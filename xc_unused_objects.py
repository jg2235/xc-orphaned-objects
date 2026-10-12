#!/usr/bin/env python3
"""
xc_unused_objects.py — F5 Distributed Cloud dormant / orphaned object report.

Read-only. Scans every namespace the API token can read and classifies:

  WAF policies (app_firewall)           Service policies (service_policy)
  API definitions (api_definition)      OAS/Swagger files (object store)
  Origin pools (origin_pool)            Health checks (healthcheck)
  Bot Defense app infrastructure        (+ inline Bot Defense with no endpoints)

Status model
  ORPHANED    zero referrers anywhere (API referring_objects + spec scan)
  DORMANT     referenced, but no reference chain reaches an *enabled* LB
              (e.g. healthcheck -> orphaned pool, pool -> disabled LB only)
  UNVERIFIED  only reachable through a kind this tool doesn't fetch;
              treated as in use (conservative)
  IN_USE      reachable from an enabled HTTP/TCP/UDP/CDN load balancer

Evidence sources (both are merged, disagreement is shown per object)
  api   GET ...?response_format=GET_RSP_FORMAT_REFERRING_OBJECTS
  spec  independent walk of LB / route / pool / api_definition / policy-set specs

Env: F5XC_TENANT, F5XC_API_TOKEN, F5XC_NAMESPACE (optional), F5XC_BASE_URL (optional)
Deps: requests
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import html
import json
import os
import re
import sys
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote

import requests

VERSION = "1.0.0"

# --------------------------------------------------------------------------
# Kind registry
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Kind:
    name: str
    collection: str
    label: str
    role: str  # "root" | "intermediate" | "candidate"


KINDS: dict[str, Kind] = {k.name: k for k in [
    # roots — an enabled one makes its dependency tree live
    Kind("http_loadbalancer", "http_loadbalancers", "HTTP Load Balancer", "root"),
    Kind("tcp_loadbalancer", "tcp_loadbalancers", "TCP Load Balancer", "root"),
    Kind("udp_loadbalancer", "udp_loadbalancers", "UDP Load Balancer", "root"),
    Kind("cdn_loadbalancer", "cdn_loadbalancers", "CDN Load Balancer", "root"),
    # intermediates — fetched so chains can be resolved, reportable via --kinds
    Kind("route", "routes", "Route", "intermediate"),
    Kind("service_policy_set", "service_policy_sets", "Service Policy Set", "intermediate"),
    # candidates
    Kind("app_firewall", "app_firewalls", "WAF Policy", "candidate"),
    Kind("service_policy", "service_policys", "Service Policy", "candidate"),
    Kind("api_definition", "api_definitions", "API Definition", "candidate"),
    Kind("origin_pool", "origin_pools", "Origin Pool", "candidate"),
    Kind("healthcheck", "healthchecks", "Health Check", "candidate"),
    Kind("bot_defense_app_infrastructure", "bot_defense_app_infrastructures",
         "Bot Defense App Infrastructure", "candidate"),
]}
SWAGGER = "swagger_spec"  # object-store kind (not a config object)
LABELS = {**{k: v.label for k, v in KINDS.items()}, SWAGGER: "OAS / Swagger File"}
DEFAULT_REPORT_KINDS = [k for k, v in KINDS.items() if v.role == "candidate"] + [SWAGGER]
ROOT_KINDS = {k for k, v in KINDS.items() if v.role == "root"}
TRACKED_KINDS = set(KINDS) | {SWAGGER}

# Spec-walk hints: nearest ancestor JSON key -> referenced kind.
REF_KEY_HINTS: dict[str, str] = {
    "app_firewall": "app_firewall",
    "active_service_policies": "service_policy",
    "service_policy": "service_policy",
    "api_definition": "api_definition",
    "api_definitions": "api_definition",
    "api_definition_ref": "api_definition",
    "pool": "origin_pool",
    "origin_pool": "origin_pool",
    "origin_pools": "origin_pool",
    "origin_pools_weights": "origin_pool",
    "default_route_pools": "origin_pool",
    "default_pool": "origin_pool",
    "healthcheck": "healthcheck",
    "health_check": "healthcheck",
    "route_ref": "route",
    "bot_defense_app_infrastructure": "bot_defense_app_infrastructure",
}
# Per-referrer overrides (generic key name means something specific there)
REF_KEY_HINTS_BY_REFERRER: dict[str, dict[str, str]] = {
    "service_policy_set": {"policies": "service_policy"},
}
REF_DICT_KEYS = {"name", "namespace", "tenant", "kind", "uid"}
SWAGGER_URL_RE = re.compile(
    r"/api/object_store/namespaces/([^/\s\"']+)/stored_objects/swagger/([^/\s\"']+)/([^/\s\"'?#]+)")
VIEW_CHILD_RE = re.compile(r"^ves-io-(http-loadbalancer|tcp-loadbalancer|udp-loadbalancer|"
                           r"cdn-loadbalancer|origin-pool)-(.+)$")
VIEW_CHILD_KIND = {"http-loadbalancer": "http_loadbalancer", "tcp-loadbalancer": "tcp_loadbalancer",
                   "udp-loadbalancer": "udp_loadbalancer", "cdn-loadbalancer": "cdn_loadbalancer",
                   "origin-pool": "origin_pool"}
UID_SUFFIX_RE = re.compile(r"-[0-9a-f]{8,16}$")

Key = tuple  # (kind, namespace, name)


# --------------------------------------------------------------------------
# HTTP client
# --------------------------------------------------------------------------
class XCError(Exception):
    def __init__(self, msg: str, status: int | None = None):
        super().__init__(msg)
        self.status = status


class XCClient:
    def __init__(self, base_url: str, token: str, timeout: float = 30.0,
                 max_retries: int = 5, verify: bool | str = True):
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self._verify = verify
        self._headers = {"Authorization": f"APIToken {token}",
                         "Accept": "application/json",
                         "User-Agent": f"xc-unused-objects/{VERSION}"}
        self._local = threading.local()   # one Session per worker thread
        self._lock = threading.Lock()
        self.calls = 0

    @property
    def s(self) -> requests.Session:
        sess = getattr(self._local, "s", None)
        if sess is None:
            sess = self._local.s = requests.Session()
            sess.verify = self._verify
            sess.headers.update(self._headers)
        return sess

    def get(self, path: str, params: dict | None = None) -> dict:
        delay = 1.0
        for attempt in range(1, self.max_retries + 1):
            with self._lock:
                self.calls += 1
            try:
                r = self.s.get(self.base + path, params=params, timeout=self.timeout)
            except requests.RequestException as e:
                if attempt == self.max_retries:
                    raise XCError(f"transport error on GET {path}: {e}") from e
                time.sleep(delay); delay = min(delay * 2, 30); continue
            if r.status_code == 429 or r.status_code >= 500:
                if attempt == self.max_retries:
                    raise XCError(f"{r.status_code} on GET {path}", r.status_code)
                ra = r.headers.get("Retry-After")
                time.sleep(float(ra) if ra and ra.replace(".", "", 1).isdigit() else delay)
                delay = min(delay * 2, 30); continue
            if r.status_code >= 400:
                raise XCError(f"{r.status_code} on GET {path}: {r.text[:200]}", r.status_code)
            return r.json() if r.content else {}
        raise XCError(f"retries exhausted on GET {path}")

    def list_all(self, path: str, params: dict | None = None) -> list[dict]:
        """List with defensive pagination (follows next_page/page_start if present)."""
        items: list[dict] = []
        params = dict(params or {})
        seen: set[str] = set()
        while True:
            body = self.get(path, params)
            items.extend(body.get("items") or [])
            nxt = body.get("next_page") or ""
            if not nxt or nxt in seen:
                return items
            seen.add(nxt)
            params["page_start"] = nxt


# --------------------------------------------------------------------------
# Model
# --------------------------------------------------------------------------
@dataclass
class Obj:
    kind: str
    namespace: str
    name: str
    spec: dict = field(default_factory=dict)
    disabled: bool = False
    created: str = ""
    modified: str = ""
    creator: str = ""
    labels: dict = field(default_factory=dict)
    description: str = ""
    versions: list = field(default_factory=list)   # swagger only
    referring_api: list | None = None             # None = not fetched / failed

    @property
    def key(self) -> Key:
        return (self.kind, self.namespace, self.name)


@dataclass
class Edge:
    src: Key           # referrer
    dst: Key           # referee
    evidence: set = field(default_factory=set)  # {"api","spec"}
    path: str = ""     # json path for spec evidence / version for swagger


@dataclass
class Finding:
    obj: Obj
    status: str
    reason: str
    referrers: list
    evidence: str


# --------------------------------------------------------------------------
# Inventory
# --------------------------------------------------------------------------
class Scanner:
    def __init__(self, client: XCClient, tenant: str, namespaces: list[str] | None,
                 include_system: bool, use_referring_api: bool, workers: int,
                 log=print):
        self.c = client
        self.tenant = tenant
        self.ns_filter = namespaces
        self.include_system = include_system
        self.use_referring_api = use_referring_api
        self.workers = workers
        self.log = log
        self.objs: dict[Key, Obj] = {}
        self.errors: list[dict] = []
        self.unavailable: set[tuple[str, str]] = set()  # (kind, ns) 404
        self.denied_ns: set[str] = set()
        self.namespaces: list[str] = []

    # -- discovery ---------------------------------------------------------
    def discover_namespaces(self) -> list[str]:
        if self.ns_filter:
            ns = list(dict.fromkeys(self.ns_filter + ["shared"]))
        else:
            items = self.c.list_all("/api/web/namespaces")
            ns = sorted({(i.get("name") or "") for i in items} - {""})
            if "shared" not in ns:
                ns.append("shared")
        if not self.include_system:
            ns = [n for n in ns if n != "system"]
        self.namespaces = ns
        return ns

    @staticmethod
    def _skip_auto(name: str, sysmeta: dict) -> bool:
        return name.startswith("ves-io-") or bool((sysmeta or {}).get("owner_view"))

    def _to_obj(self, kind: str, ns: str, item: dict, detail: dict | None) -> Obj | None:
        meta = (detail or {}).get("metadata") or {}
        sysm = (detail or {}).get("system_metadata") or item.get("system_metadata") or {}
        name = meta.get("name") or item.get("name") or ""
        ons = meta.get("namespace") or item.get("namespace") or ns
        if not name or self._skip_auto(name, sysm):
            return None
        spec = (detail or {}).get("spec") or item.get("get_spec") or {}
        return Obj(kind=kind, namespace=ons, name=name, spec=spec,
                   disabled=bool(meta.get("disable", item.get("disabled", False))),
                   created=sysm.get("creation_timestamp", "") or "",
                   modified=sysm.get("modification_timestamp", "") or "",
                   creator=sysm.get("creator_id", "") or "",
                   labels=meta.get("labels") or item.get("labels") or {},
                   description=meta.get("description") or item.get("description") or "")

    def _list_kind_ns(self, kind: str, ns: str) -> list[Obj]:
        coll = KINDS[kind].collection
        path = f"/api/config/namespaces/{ns}/{coll}"
        try:
            # report_fields (present, empty) asks XC to include get_spec in list items
            items = self.c.list_all(path, {"report_fields": ""})
        except XCError as e:
            if e.status == 404:
                self.unavailable.add((kind, ns)); return []
            if e.status in (401, 403):
                self.denied_ns.add(ns)
            self.errors.append({"op": "list", "kind": kind, "namespace": ns, "error": str(e)})
            return []
        out = []
        need_detail = []
        for it in items:
            # list items returned for ns-scoped collection can include shared-ns items
            ins = it.get("namespace") or ns
            if ins != ns:
                continue
            if it.get("get_spec") is not None:
                o = self._to_obj(kind, ns, it, None)
                if o: out.append(o)
            else:
                need_detail.append(it)
        for it in need_detail:
            name = it.get("name") or ""
            if not name or name.startswith("ves-io-"):
                continue
            try:
                d = self.c.get(f"{path}/{quote(name, safe='')}")
            except XCError as e:
                self.errors.append({"op": "get", "kind": kind, "namespace": ns, "name": name,
                                    "error": str(e)})
                d = None
            o = self._to_obj(kind, ns, it, d)
            if o: out.append(o)
        return out

    def _list_swagger_ns(self, ns: str) -> list[Obj]:
        path = f"/api/object_store/namespaces/{ns}/stored_objects/swagger"
        try:
            items = self.c.list_all(path)
        except XCError as e:
            if e.status == 404:
                self.unavailable.add((SWAGGER, ns)); return []
            if e.status in (401, 403):
                self.denied_ns.add(ns)
            self.errors.append({"op": "list", "kind": SWAGGER, "namespace": ns, "error": str(e)})
            return []
        out = []
        for it in items:
            name = it.get("name") or ""
            if not name:
                continue
            vers = it.get("versions") or []
            created = min((v.get("creation_timestamp") or "" for v in vers), default="")
            latest = max((v.get("creation_timestamp") or "" for v in vers), default="")
            out.append(Obj(kind=SWAGGER, namespace=ns, name=name, created=created, modified=latest,
                           versions=[{"version": v.get("version", ""),
                                      "latest": bool(v.get("latest_version")),
                                      "created": v.get("creation_timestamp", ""),
                                      "url": v.get("url", "")} for v in vers]))
        return out

    def inventory(self, report_kinds: list[str]) -> None:
        fetch_kinds = sorted(set(KINDS) & (set(report_kinds) | ROOT_KINDS |
                                          {"route", "service_policy_set", "origin_pool",
                                           "api_definition"}))
        jobs = [(k, ns) for ns in self.namespaces for k in fetch_kinds]
        # Bot Defense app infrastructure objects may live in system; always look there.
        if "bot_defense_app_infrastructure" in report_kinds and "system" not in self.namespaces:
            jobs.append(("bot_defense_app_infrastructure", "system"))
        self.log(f"[inventory] {len(self.namespaces)} namespaces x {len(fetch_kinds)} kinds")
        with ThreadPoolExecutor(self.workers) as ex:
            for objs in ex.map(lambda j: self._list_kind_ns(*j), jobs):
                for o in objs:
                    self.objs[o.key] = o
            if SWAGGER in report_kinds:
                for objs in ex.map(self._list_swagger_ns, self.namespaces):
                    for o in objs:
                        self.objs[o.key] = o
        counts = defaultdict(int)
        for k in self.objs:
            counts[k[0]] += 1
        self.log("[inventory] " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

    def fetch_referring(self, report_kinds: list[str]) -> None:
        if not self.use_referring_api:
            return
        targets = [o for o in self.objs.values()
                   if o.kind in KINDS and (o.kind in report_kinds or KINDS[o.kind].role == "intermediate"
                                           or o.kind in ("origin_pool", "api_definition"))]

        def one(o: Obj):
            path = (f"/api/config/namespaces/{o.namespace}/{KINDS[o.kind].collection}/"
                    f"{quote(o.name, safe='')}")
            try:
                d = self.c.get(path, {"response_format": "GET_RSP_FORMAT_REFERRING_OBJECTS"})
                o.referring_api = d.get("referring_objects") or []
            except XCError as e:
                self.errors.append({"op": "referring_objects", "kind": o.kind,
                                    "namespace": o.namespace, "name": o.name, "error": str(e)})
                o.referring_api = None
        self.log(f"[referring] {len(targets)} GETs")
        with ThreadPoolExecutor(self.workers) as ex:
            list(ex.map(one, targets))


# --------------------------------------------------------------------------
# Graph
# --------------------------------------------------------------------------
class Graph:
    def __init__(self, objs: dict[Key, Obj]):
        self.objs = objs
        self.edges: dict[tuple[Key, Key], Edge] = {}
        self.untracked_nodes: set[Key] = set()
        # index for namespace-less name lookups (view-child mapping fallback)
        self.by_kind_ns: dict[tuple[str, str], set[str]] = defaultdict(set)
        for (k, ns, n) in objs:
            self.by_kind_ns[(k, ns)].add(n)

    def _add(self, src: Key, dst: Key, ev: str, path: str = "") -> None:
        if src == dst:
            return
        e = self.edges.get((src, dst))
        if e is None:
            e = self.edges[(src, dst)] = Edge(src, dst, set(), path)
        e.evidence.add(ev)
        if path and not e.path:
            e.path = path

    def canonical(self, kind: str, ns: str, name: str) -> Key:
        """Map XC auto-generated child objects (virtual_host/cluster/endpoint/proxy
        named ves-io-<view>-<name>) back to the user-facing view object."""
        m = VIEW_CHILD_RE.match(name or "")
        if m:
            vk = VIEW_CHILD_KIND[m.group(1)]
            base = m.group(2)
            names = self.by_kind_ns.get((vk, ns), set())
            if base in names:
                return (vk, ns, base)
            stripped = UID_SUFFIX_RE.sub("", base)
            if stripped in names:
                return (vk, ns, stripped)
            return (vk, ns, stripped)
        return (kind, ns, name)

    # -- evidence A: referring_objects ------------------------------------
    def add_api_edges(self) -> None:
        for o in list(self.objs.values()):
            for r in o.referring_api or []:
                rk, rns, rn = r.get("kind", ""), r.get("namespace") or o.namespace, r.get("name", "")
                if not rn:
                    continue
                src = self.canonical(rk, rns, rn)
                if src == o.key:
                    continue  # object's own generated children
                if src[0] not in TRACKED_KINDS:
                    self.untracked_nodes.add(src)
                self._add(src, o.key, "api")

    # -- evidence B: spec walk ---------------------------------------------
    def _resolve_ns(self, ref: dict, referrer_ns: str) -> str:
        return ref.get("namespace") or referrer_ns

    def _walk(self, node: Any, src: Obj, hint: str | None, path: str) -> None:
        overrides = REF_KEY_HINTS_BY_REFERRER.get(src.kind, {})
        if isinstance(node, dict):
            keys = set(node)
            if "name" in node and isinstance(node.get("name"), str) and keys <= REF_DICT_KEYS:
                kind = node.get("kind") or hint
                if kind:
                    dst = (kind, self._resolve_ns(node, src.namespace), node["name"])
                    if dst[0] not in TRACKED_KINDS:
                        return
                    self._add(src.key, dst, "spec", path)
                return
            for k, v in node.items():
                h = overrides.get(k) or REF_KEY_HINTS.get(k) or hint
                self._walk(v, src, h, f"{path}.{k}" if path else k)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                self._walk(v, src, hint, f"{path}[{i}]")
        elif isinstance(node, str) and src.kind == "api_definition":
            for m in SWAGGER_URL_RE.finditer(node):
                self._add(src.key, (SWAGGER, m.group(1), m.group(2)), "spec", f"version {m.group(3)}")

    def add_spec_edges(self) -> None:
        for o in list(self.objs.values()):
            if o.kind == SWAGGER or not o.spec:
                continue
            self._walk(o.spec, o, None, "")
            # LB using namespace-level active service policies -> sets in that namespace
            if o.kind in ROOT_KINDS and "service_policies_from_namespace" in o.spec:
                for n in self.by_kind_ns.get(("service_policy_set", o.namespace), ()):
                    self._add(o.key, ("service_policy_set", o.namespace, n), "spec",
                              "service_policies_from_namespace")

    # -- classification ----------------------------------------------------
    def classify(self, report_kinds: list[str], denied_ns: set[str],
                 api_attempted: bool = True) -> tuple[list[Finding], set[Key]]:
        fwd: dict[Key, list[Key]] = defaultdict(list)
        rev: dict[Key, list[Key]] = defaultdict(list)
        for (s, d) in self.edges:
            fwd[s].append(d); rev[d].append(s)

        roots = [k for k, o in self.objs.items() if k[0] in ROOT_KINDS and not o.disabled]
        live = set(roots); q = deque(roots)
        while q:
            n = q.popleft()
            for d in fwd.get(n, ()):
                if d not in live:
                    live.add(d); q.append(d)

        def ancestors(k: Key) -> set[Key]:
            seen: set[Key] = set(); q2 = deque([k])
            while q2:
                n = q2.popleft()
                for s in rev.get(n, ()):
                    if s not in seen:
                        seen.add(s); q2.append(s)
            return seen

        findings: list[Finding] = []
        for k, o in sorted(self.objs.items()):
            if o.kind not in report_kinds:
                continue
            inbound = [self.edges[(s, k)] for s in rev.get(k, ())]
            refs = [{"kind": e.src[0], "namespace": e.src[1], "name": e.src[2],
                     "evidence": "+".join(sorted(e.evidence)), "path": e.path,
                     "state": self._state(e.src, live)} for e in inbound]
            ev_api = any("api" in e.evidence for e in inbound)
            ev_spec = any("spec" in e.evidence for e in inbound)
            evidence = ("api+spec" if ev_api and ev_spec else "api" if ev_api else
                        "spec" if ev_spec else "none")
            if o.kind != SWAGGER and o.referring_api is None and evidence in ("none", "spec"):
                evidence += " (referring_objects unavailable)"
            if not inbound:
                status, reason = "ORPHANED", "No object references this one."
                if api_attempted and o.kind != SWAGGER and o.referring_api is None:
                    status = "UNVERIFIED"
                    reason = "No spec references found and the referring_objects lookup failed."
                elif o.namespace == "shared" and denied_ns:
                    status = "UNVERIFIED"
                    reason = ("No referrers found, but namespaces were unreadable: "
                              + ", ".join(sorted(denied_ns)))
            elif k in live:
                status, reason = "IN_USE", "Reachable from an enabled load balancer."
            else:
                anc = ancestors(k)
                untracked = sorted({a for a in anc if a[0] not in TRACKED_KINDS or a in self.untracked_nodes
                                    or (a not in self.objs and a[0] in TRACKED_KINDS)})
                if untracked:
                    status = "UNVERIFIED"
                    reason = ("Referenced via objects this scan cannot evaluate: "
                              + ", ".join(f"{a[0]}:{a[1]}/{a[2]}" for a in untracked[:5]))
                else:
                    status = "DORMANT"
                    reason = "Only referenced by: " + "; ".join(
                        f"{r['kind']} {r['namespace']}/{r['name']} ({r['state']})" for r in refs[:6])
            if o.kind == SWAGGER and o.versions:
                used = {e.path.replace("version ", "") for e in inbound}
                unused = [v["version"] for v in o.versions if v["version"] not in used]
                if inbound and unused:
                    reason += f" {len(unused)}/{len(o.versions)} stored versions unreferenced."
            findings.append(Finding(o, status, reason, refs, evidence))
        return findings, live

    def _state(self, k: Key, live: set[Key]) -> str:
        o = self.objs.get(k)
        if o is None:
            return "untracked" if k[0] not in TRACKED_KINDS else "not-found"
        if o.disabled:
            return "disabled"
        if k in live:
            return "live"
        if not hasattr(self, "_has_inbound"):
            self._has_inbound = {d for (_, d) in self.edges}
        return "not-live" if k in self._has_inbound else "orphaned"


# --------------------------------------------------------------------------
# Extra findings
# --------------------------------------------------------------------------
def inline_bot_findings(objs: dict[Key, Obj]) -> list[dict]:
    """XC Bot Defense is configured inline on the LB; flag enabled-but-hollow configs."""
    out = []
    for o in objs.values():
        if o.kind != "http_loadbalancer":
            continue
        bot = o.spec.get("bot_defense") or o.spec.get("bot_defense_advanced")
        if not isinstance(bot, dict):
            continue
        pol = bot.get("policy") if isinstance(bot.get("policy"), dict) else {}
        eps = pol.get("protected_app_endpoints") or []
        if not eps:
            out.append({"namespace": o.namespace, "lb": o.name, "disabled_lb": o.disabled,
                        "issue": "Bot Defense enabled with 0 protected_app_endpoints (no traffic protected)"})
    return out


def disabled_lbs(objs: dict[Key, Obj]) -> list[Obj]:
    return sorted((o for o in objs.values() if o.kind in ROOT_KINDS and o.disabled), key=lambda o: o.key)


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
STATUS_ORDER = ["ORPHANED", "DORMANT", "UNVERIFIED", "IN_USE"]


def age_days(ts: str, now: dt.datetime) -> int | None:
    if not ts:
        return None
    try:
        t = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=dt.timezone.utc)
        return max(0, (now - t).days)
    except ValueError:
        return None


def write_json(path: Path, meta: dict, findings: list[Finding], bots: list, dlbs: list[Obj]) -> None:
    data = {"meta": meta,
            "findings": [{"kind": f.obj.kind, "namespace": f.obj.namespace, "name": f.obj.name,
                          "status": f.status, "reason": f.reason, "evidence": f.evidence,
                          "referrers": f.referrers, "created": f.obj.created,
                          "modified": f.obj.modified, "creator": f.obj.creator,
                          "labels": f.obj.labels, "versions": f.obj.versions or None}
                         for f in findings],
            "inline_bot_defense": bots,
            "disabled_load_balancers": [{"kind": o.kind, "namespace": o.namespace, "name": o.name}
                                        for o in dlbs]}
    path.write_text(json.dumps(data, indent=2))


def write_csv(path: Path, findings: list[Finding], now: dt.datetime) -> None:
    with path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["status", "kind", "namespace", "name", "age_days", "modified", "creator",
                    "evidence", "referrer_count", "referrers", "reason"])
        for f in findings:
            w.writerow([f.status, f.obj.kind, f.obj.namespace, f.obj.name,
                        age_days(f.obj.created, now) or "", f.obj.modified, f.obj.creator,
                        f.evidence, len(f.referrers),
                        "; ".join(f"{r['kind']}:{r['namespace']}/{r['name']}[{r['state']}]"
                                  for r in f.referrers), f.reason])


DELETE_ORDER = ["api_definition", SWAGGER, "service_policy", "app_firewall",
                "bot_defense_app_infrastructure", "origin_pool", "healthcheck"]


def write_cleanup(path: Path, findings: list[Finding], tenant_url: str) -> None:
    lines = ["#!/usr/bin/env bash",
             "# Generated by xc_unused_objects.py — REVIEW BEFORE USE. Every command is commented out.",
             "# Order is dependency-safe: referrers first (api_definition before swagger,",
             "# origin_pool before healthcheck). DORMANT items are listed for review only.",
             "# Check labels/annotations for Terraform/GitOps ownership before deleting —",
             "# a console/API delete will be re-created or cause plan drift.",
             "set -euo pipefail",
             f'BASE="${{F5XC_BASE_URL:-{tenant_url}}}"',
             'AUTH="Authorization: APIToken ${F5XC_API_TOKEN:?set F5XC_API_TOKEN}"', ""]
    by_kind = defaultdict(list)
    for f in findings:
        if f.status in ("ORPHANED", "DORMANT"):
            by_kind[f.obj.kind].append(f)
    for k in DELETE_ORDER:
        if not by_kind.get(k):
            continue
        lines.append(f"# ---- {LABELS[k]} ----")
        for f in by_kind[k]:
            o = f.obj
            if k == SWAGGER:
                p = f"/api/object_store/namespaces/{o.namespace}/stored_objects/swagger/{quote(o.name, safe='')}"
            else:
                p = f"/api/config/namespaces/{o.namespace}/{KINDS[k].collection}/{quote(o.name, safe='')}"
            tag = "" if f.status == "ORPHANED" else "  # DORMANT — delete its referrers first"
            lines.append(f'# curl -sS -X DELETE -H "$AUTH" "$BASE{p}"{tag}')
        lines.append("")
    path.write_text("\n".join(lines) + "\n")
    path.chmod(0o750)


def _e(x: Any) -> str:
    return html.escape(str(x if x is not None else ""))


def write_html(path: Path, meta: dict, findings: list[Finding], bots: list, dlbs: list[Obj],
               errors: list, unavailable: set, now: dt.datetime) -> None:
    kinds_present = [k for k in DEFAULT_REPORT_KINDS + [k for k in KINDS if k not in DEFAULT_REPORT_KINDS]
                     if any(f.obj.kind == k for f in findings)]
    matrix = {k: {s: 0 for s in STATUS_ORDER} for k in kinds_present}
    for f in findings:
        matrix[f.obj.kind][f.status] += 1
    tot = {s: sum(m[s] for m in matrix.values()) for s in STATUS_ORDER}

    rows = []
    for f in sorted(findings, key=lambda f: (STATUS_ORDER.index(f.status), f.obj.kind, f.obj.namespace, f.obj.name)):
        refs = "".join(f"<li><code>{_e(r['kind'])}</code> {_e(r['namespace'])}/{_e(r['name'])} "
                       f"<span class='st st-{_e(r['state'])}'>{_e(r['state'])}</span>"
                       f"<span class='ev'>{_e(r['evidence'])}{(' · ' + _e(r['path'])) if r['path'] else ''}</span></li>"
                       for r in f.referrers) or "<li class='muted'>none</li>"
        ver = ""
        if f.obj.versions:
            ver = f"<div class='muted'>{len(f.obj.versions)} version(s)</div>"
        a = age_days(f.obj.created, now)
        rows.append(
            f"<tr data-status='{f.status}' data-kind='{_e(f.obj.kind)}'>"
            f"<td><span class='badge b-{f.status}'>{f.status}</span></td>"
            f"<td>{_e(LABELS.get(f.obj.kind, f.obj.kind))}</td>"
            f"<td>{_e(f.obj.namespace)}</td>"
            f"<td class='nm'>{_e(f.obj.name)}{ver}</td>"
            f"<td class='num'>{'' if a is None else a}</td>"
            f"<td>{_e(f.obj.modified[:10])}</td>"
            f"<td>{_e(f.obj.creator)}</td>"
            f"<td>{_e(f.evidence)}</td>"
            f"<td><details><summary>{len(f.referrers)}</summary><ul>{refs}</ul></details></td>"
            f"<td class='why'>{_e(f.reason)}</td></tr>")

    mrows = "".join(
        f"<tr><td>{_e(LABELS.get(k, k))}</td>" +
        "".join(f"<td class='num {('hot' if s in ('ORPHANED','DORMANT') and v else '')}'>{v}</td>"
                for s, v in matrix[k].items()) +
        f"<td class='num'>{sum(matrix[k].values())}</td></tr>" for k in kinds_present)

    bot_rows = "".join(f"<tr><td>{_e(b['namespace'])}</td><td>{_e(b['lb'])}</td>"
                       f"<td>{'yes' if b['disabled_lb'] else 'no'}</td><td>{_e(b['issue'])}</td></tr>"
                       for b in bots) or "<tr><td colspan='4' class='muted'>None found.</td></tr>"
    dlb_rows = "".join(f"<tr><td>{_e(LABELS[o.kind])}</td><td>{_e(o.namespace)}</td><td>{_e(o.name)}</td></tr>"
                       for o in dlbs) or "<tr><td colspan='3' class='muted'>None.</td></tr>"
    err_rows = "".join(f"<tr><td>{_e(x.get('op'))}</td><td>{_e(x.get('kind'))}</td><td>{_e(x.get('namespace'))}</td>"
                       f"<td>{_e(x.get('name', ''))}</td><td class='why'>{_e(x.get('error'))}</td></tr>"
                       for x in errors[:500]) or "<tr><td colspan='5' class='muted'>None.</td></tr>"
    unavail = ", ".join(sorted(f"{k}@{n}" for k, n in unavailable)) or "none"
    kind_opts = "".join(f"<option value='{_e(k)}'>{_e(LABELS.get(k, k))}</option>" for k in kinds_present)

    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>XC Orphan Report — {_e(meta['tenant'])}</title>
<style>
:root{{--bg:#f7f7f5;--fg:#1b1d21;--mut:#6b7078;--card:#fff;--line:#e3e3df;--acc:#0b5cad;
--orph:#b42318;--dorm:#b54708;--unv:#5b5bd6;--use:#067647}}
@media (prefers-color-scheme:dark){{:root{{--bg:#111316;--fg:#e8e9eb;--mut:#9aa0a8;--card:#1a1d21;--line:#2c3036;--acc:#6aa9ff;
--orph:#f97066;--dorm:#fdb022;--unv:#a4a4ff;--use:#47cd89}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
main{{max-width:1400px;margin:0 auto;padding:24px 16px 64px}}
h1{{font-size:22px;margin:0 0 4px}}h2{{font-size:16px;margin:32px 0 10px}}
.sub{{color:var(--mut)}}code{{font:12px ui-monospace,SFMono-Regular,Menlo,monospace}}
.tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin:18px 0}}
.tile{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}}
.tile b{{display:block;font-size:26px;font-variant-numeric:tabular-nums}}
.t-ORPHANED b{{color:var(--orph)}}.t-DORMANT b{{color:var(--dorm)}}.t-UNVERIFIED b{{color:var(--unv)}}.t-IN_USE b{{color:var(--use)}}
.wrap{{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:8px}}
table{{border-collapse:collapse;width:100%}}th,td{{padding:7px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}
th{{font-size:12px;color:var(--mut);font-weight:600;position:sticky;top:0;background:var(--card);cursor:pointer;white-space:nowrap}}
.num{{text-align:right;font-variant-numeric:tabular-nums}}.hot{{font-weight:700;color:var(--orph)}}
.badge{{font-size:11px;font-weight:700;padding:2px 7px;border-radius:999px;color:#fff;white-space:nowrap}}
.b-ORPHANED{{background:var(--orph)}}.b-DORMANT{{background:var(--dorm)}}.b-UNVERIFIED{{background:var(--unv)}}.b-IN_USE{{background:var(--use)}}
.st{{font-size:11px;margin-left:6px;color:var(--mut)}}.st-disabled,.st-not-live,.st-orphaned{{color:var(--dorm)}}.st-live{{color:var(--use)}}
.ev{{display:block;font-size:11px;color:var(--mut)}}.why{{max-width:420px;color:var(--mut)}}.nm{{font-weight:600;word-break:break-all}}
.muted{{color:var(--mut)}}ul{{margin:4px 0;padding-left:16px}}summary{{cursor:pointer;color:var(--acc)}}
.bar{{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0}}select,input{{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:6px 8px;font:inherit}}
.note{{background:var(--card);border-left:3px solid var(--acc);padding:10px 14px;border-radius:4px;color:var(--mut)}}
</style></head><body><main>
<h1>F5 XC Dormant &amp; Orphaned Objects</h1>
<div class="sub">Tenant <b>{_e(meta['tenant'])}</b> · generated {_e(meta['generated'])} · {meta['namespaces']} namespaces · {meta['api_calls']} API calls · referring_objects API: {'on' if meta['referring_api'] else 'off'}</div>
<div class="tiles">{''.join(f"<div class='tile t-{s}'><span class='sub'>{s.replace('_',' ').title()}</span><b>{tot[s]}</b></div>" for s in STATUS_ORDER)}</div>
<div class="note"><b>ORPHANED</b>: no referrers. <b>DORMANT</b>: referenced only by disabled LBs or by other non-live objects (e.g. health check on an orphaned pool). <b>UNVERIFIED</b>: reachable only through a kind this scan doesn't evaluate, or shared-namespace object with unreadable namespaces — treat as in use. Evidence <code>api</code> = XC server-side referring_objects, <code>spec</code> = independent spec walk.</div>
<h2>Summary by kind</h2>
<div class="wrap"><table><thead><tr><th>Kind</th>{''.join(f'<th class="num">{s}</th>' for s in STATUS_ORDER)}<th class="num">Total</th></tr></thead><tbody>{mrows}</tbody></table></div>
<h2>Objects</h2>
<div class="bar"><select id="fs"><option value="">All statuses</option>{''.join(f"<option{' selected' if s=='ORPHANED' else ''}>{s}</option>" for s in STATUS_ORDER)}</select>
<select id="fk"><option value="">All kinds</option>{kind_opts}</select><input id="fq" placeholder="Filter name / namespace"></div>
<div class="wrap"><table id="t"><thead><tr><th>Status</th><th>Kind</th><th>Namespace</th><th>Name</th><th class="num">Age (d)</th><th>Modified</th><th>Creator</th><th>Evidence</th><th>Referrers</th><th>Reason</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>
<h2>Inline Bot Defense with no protected endpoints</h2>
<div class="sub">XC has no standalone Bot Defense policy object on HTTP LBs — config is inline. These LBs have Bot Defense enabled but protect nothing.</div>
<div class="wrap"><table><thead><tr><th>Namespace</th><th>Load balancer</th><th>LB disabled</th><th>Issue</th></tr></thead><tbody>{bot_rows}</tbody></table></div>
<h2>Disabled load balancers</h2>
<div class="sub">Objects referenced only by these are reported DORMANT.</div>
<div class="wrap"><table><thead><tr><th>Kind</th><th>Namespace</th><th>Name</th></tr></thead><tbody>{dlb_rows}</tbody></table></div>
<h2>Scan coverage</h2>
<div class="sub">Collections not available on this tenant (404): {_e(unavail)}. Unreadable namespaces: {_e(', '.join(meta['denied_namespaces']) or 'none')}.</div>
<div class="wrap"><table><thead><tr><th>Op</th><th>Kind</th><th>Namespace</th><th>Name</th><th>Error</th></tr></thead><tbody>{err_rows}</tbody></table></div>
</main><script>
(function(){{const t=document.getElementById('t'),fs=document.getElementById('fs'),fk=document.getElementById('fk'),fq=document.getElementById('fq');
function f(){{const s=fs.value,k=fk.value,q=fq.value.toLowerCase();for(const r of t.tBodies[0].rows){{const ok=(!s||r.dataset.status===s)&&(!k||r.dataset.kind===k)&&(!q||r.cells[2].textContent.toLowerCase().includes(q)||r.cells[3].textContent.toLowerCase().includes(q));r.style.display=ok?'':'none'}}}}
[fs,fk].forEach(e=>e.addEventListener('change',f));fq.addEventListener('input',f);f();
t.tHead.querySelectorAll('th').forEach((th,i)=>th.addEventListener('click',()=>{{const rs=[...t.tBodies[0].rows],asc=th.dataset.a!=='1';th.dataset.a=asc?'1':'0';
const num=th.classList.contains('num');rs.sort((a,b)=>{{let x=a.cells[i].textContent.trim(),y=b.cells[i].textContent.trim();if(num){{x=+x||-1;y=+y||-1;return asc?x-y:y-x}}return asc?x.localeCompare(y):y.localeCompare(x)}});rs.forEach(r=>t.tBodies[0].appendChild(r))}}));}})();
</script></body></html>"""
    path.write_text(doc)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="F5 XC dormant/orphaned object report (read-only).")
    ap.add_argument("--tenant", default=os.environ.get("F5XC_TENANT", ""))
    ap.add_argument("--token", default=os.environ.get("F5XC_API_TOKEN", ""))
    ap.add_argument("--base-url", default=os.environ.get("F5XC_BASE_URL", ""),
                    help="Full console URL; overrides F5XC_TENANT. Env: F5XC_BASE_URL. "
                         "Use for tenants on https://<tenant>.console.ves.volterra.io")
    ap.add_argument("--namespaces", default=os.environ.get("F5XC_NAMESPACE", ""),
                    help="Comma list (shared always added). Env: F5XC_NAMESPACE. Default: all.")
    ap.add_argument("--include-system", action="store_true", help="Also scan the system namespace")
    ap.add_argument("--kinds", default=",".join(DEFAULT_REPORT_KINDS),
                    help=f"Report kinds. Options: {','.join(sorted(set(KINDS) | {SWAGGER}))}")
    ap.add_argument("--no-referring-api", action="store_true",
                    help="Skip per-object referring_objects GETs (spec walk only; less accurate)")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--max-retries", type=int, default=5, help="Retries on 429/5xx/transport errors")
    ap.add_argument("--ca-bundle", default="", help="Custom CA bundle path")
    ap.add_argument("--out-dir", default="xc-unused-objects-out")
    ap.add_argument("--fail-on-orphans", action="store_true", help="Exit 2 if ORPHANED/DORMANT found (CI)")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args(list(argv) if argv is not None else None)

    if not a.token or not (a.tenant or a.base_url):
        ap.error("set F5XC_API_TOKEN, plus F5XC_TENANT or F5XC_BASE_URL (see README)")
    base = a.base_url or f"https://{a.tenant}.console.ves.io"
    tenant = a.tenant or base
    kinds = [k.strip() for k in a.kinds.split(",") if k.strip()]
    bad = [k for k in kinds if k not in KINDS and k != SWAGGER]
    if bad:
        ap.error(f"unknown kinds: {bad}")
    log = (lambda *_: None) if a.quiet else (lambda m: print(m, file=sys.stderr))

    client = XCClient(base, a.token, timeout=a.timeout, max_retries=max(1, a.max_retries),
                      verify=a.ca_bundle or True)
    sc = Scanner(client, tenant, [n.strip() for n in a.namespaces.split(",") if n.strip()] or None,
                 a.include_system, not a.no_referring_api, a.workers, log)
    t0 = time.time()
    try:
        ns = sc.discover_namespaces()
    except XCError as e:
        print(f"ERROR: cannot list namespaces: {e}", file=sys.stderr)
        return 1
    log(f"[namespaces] {', '.join(ns)}")
    sc.inventory(kinds)
    sc.fetch_referring(kinds)

    g = Graph(sc.objs)
    g.add_api_edges()
    g.add_spec_edges()
    findings, _live = g.classify(kinds, sc.denied_ns, api_attempted=not a.no_referring_api)
    bots = inline_bot_findings(sc.objs)
    dlbs = disabled_lbs(sc.objs)

    now = dt.datetime.now(dt.timezone.utc)
    out = Path(a.out_dir); out.mkdir(parents=True, exist_ok=True)
    meta = {"tool": f"xc_unused_objects {VERSION}", "tenant": tenant, "base_url": base,
            "generated": now.strftime("%Y-%m-%d %H:%M UTC"), "namespaces": len(ns),
            "namespace_list": ns, "report_kinds": kinds, "referring_api": not a.no_referring_api,
            "api_calls": client.calls, "elapsed_s": round(time.time() - t0, 1),
            "denied_namespaces": sorted(sc.denied_ns),
            "unavailable_collections": sorted(f"{k}@{n}" for k, n in sc.unavailable),
            "errors": len(sc.errors)}
    stamp = now.strftime("%Y%m%d-%H%M")
    write_html(out / f"xc-unused-{stamp}.html", meta, findings, bots, dlbs, sc.errors, sc.unavailable, now)
    write_json(out / f"xc-unused-{stamp}.json", meta | {"error_detail": sc.errors}, findings, bots, dlbs)
    write_csv(out / f"xc-unused-{stamp}.csv", findings, now)
    write_cleanup(out / f"xc-unused-cleanup-{stamp}.sh", findings, base)

    counts = defaultdict(int)
    for f in findings:
        counts[f.status] += 1
    log(f"[done] {dict(counts)} | inline-bot issues={len(bots)} | errors={len(sc.errors)} | "
        f"{client.calls} calls in {meta['elapsed_s']}s -> {out}/")
    if a.fail_on_orphans and (counts["ORPHANED"] or counts["DORMANT"]):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
