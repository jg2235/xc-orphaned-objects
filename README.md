# f5xc-unused-objects

Read-only scanner that finds **dormant and orphaned F5 Distributed Cloud (XC) objects**. It scans every namespace your API token can read and writes four outputs:

- an HTML report
- JSON
- CSV
- a cleanup script with every command commented out

It never creates, changes, or deletes anything.

![report](docs/sample-report.png)

## What it checks

| Object | API collection |
|---|---|
| WAF policies | `app_firewalls` |
| Service policies | `service_policys` |
| API definitions | `api_definitions` |
| OAS / Swagger files | object store: `stored_objects/swagger` |
| Origin pools | `origin_pools` |
| Health checks | `healthchecks` |
| Bot Defense app infrastructure | `bot_defense_app_infrastructures` |
| Inline Bot Defense (side finding) | HTTP LBs with Bot Defense enabled but 0 protected endpoints |

An object counts as **live** when an enabled HTTP, TCP, UDP or CDN load balancer reaches it. The chain can be direct, or go through routes, origin pools, service policy sets or API definitions.

## Status model

| Status | Meaning | Safe to delete? |
|---|---|---|
| `ORPHANED` | Nothing references it. | Candidate |
| `DORMANT` | Referenced, but no chain reaches an enabled LB. Examples: a pool on a disabled LB, a health check on an orphaned pool. | Candidate, after its referrers |
| `UNVERIFIED` | The tool can't prove it's unused. The referrer may be an object type this tool doesn't fetch, or live in a namespace the token can't read, or the reference lookup may have failed. | No, treat as in use |
| `IN_USE` | An enabled load balancer reaches it. | No |

## How references are found

The tool uses two independent sources and merges them. Each object's `evidence` column shows which source found its references.

1. **`api`**: `GET …/{collection}/{name}?response_format=GET_RSP_FORMAT_REFERRING_OBJECTS`. XC returns `referring_objects[]`, computed server-side across the whole tenant.
2. **`spec`**: the tool walks LB, route, pool, API-definition and policy-set specs itself. This catches route-level WAFs, `origin_pools_weights`, `service_policies_from_namespace`, and Swagger URLs inside API definitions.

---

## Requirements

- Python 3.9+
- `pip install -r requirements.txt` (installs only `requests`)
- An XC **API token** for a user that can read the namespaces you scan. A tenant-wide read-only or monitor role gives the most accurate results.

## Configuration: environment variables

| Variable | Required | Description | Example |
|---|---|---|---|
| `F5XC_API_TOKEN` | **Yes** | API token. Create one under *Administration → Personal Management → Credentials → Add Credentials → API Token*. | `abc123…` |
| `F5XC_TENANT` | Yes, unless `F5XC_BASE_URL` is set | Tenant short name: the **first label of your console URL**. Don't use the tenant ID with the random suffix. | `my-tenant` |
| `F5XC_BASE_URL` | Only if the default URL doesn't resolve | Full console URL. Overrides the URL built from `F5XC_TENANT`. Needed for tenants served on `*.console.ves.volterra.io`. | `https://my-tenant.console.ves.volterra.io` |
| `F5XC_NAMESPACE` | No | Comma-separated namespaces to scan. `shared` is always added. If unset, all readable namespaces are scanned. | `prod` or `prod,dev` |

Every variable can also be passed as a flag: `--token`, `--tenant`, `--base-url`, `--namespaces`.

### Which URL is my tenant on?

Use the hostname you see in your browser when you're logged into the console.

| Browser shows | Set |
|---|---|
| `https://my-tenant.console.ves.io` | `F5XC_TENANT=my-tenant` |
| `https://my-tenant.console.ves.volterra.io` | `F5XC_BASE_URL=https://my-tenant.console.ves.volterra.io` |

If every call in the report's *Scan coverage* section fails with `NameResolutionError`, your tenant uses the other URL pattern. Set `F5XC_BASE_URL`.

### Set the variables

**Option A: export in your shell**

```bash
export F5XC_API_TOKEN='<your-api-token>'
export F5XC_TENANT='<your-tenant>'                 # or: export F5XC_BASE_URL='https://<your-tenant>.console.ves.volterra.io'
export F5XC_NAMESPACE='<your-namespace>'           # optional
```

`export` is required. A plain `VAR=value` line sets a shell variable that Python can't see.

**Option B: env file** (keeps the token out of your shell history)

```bash
cp .env.example .env        # .env is git-ignored
chmod 600 .env
$EDITOR .env
set -a; source .env; set +a
```

### Verify before running

```bash
# 1. are the variables visible? (token masked)
env | grep ^F5XC_ | sed -E 's/(TOKEN=).{4}.*/\1****(set)/'

# 2. does the host resolve and does the token work?
BASE="${F5XC_BASE_URL:-https://$F5XC_TENANT.console.ves.io}"
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: APIToken $F5XC_API_TOKEN" \
  "$BASE/api/config/namespaces/${F5XC_NAMESPACE%%,*}/http_loadbalancers"
```

| Result | Meaning |
|---|---|
| `200` | Ready |
| `401` | Token invalid or expired |
| `403` | Your role can't read that namespace |
| `000` / DNS error | Wrong tenant name or URL pattern; see above |

---

## Usage

```bash
python3 xc_unused_objects.py                                  # all readable namespaces
python3 xc_unused_objects.py --namespaces prod,dev            # scoped (shared always added)
python3 xc_unused_objects.py --kinds origin_pool,healthcheck  # subset of object kinds
python3 xc_unused_objects.py --fail-on-orphans                # exit 2 if ORPHANED/DORMANT (CI gate)
```

| Flag | Default | Purpose |
|---|---|---|
| `--kinds` | all checked kinds | Comma list: `app_firewall, service_policy, api_definition, swagger_spec, origin_pool, healthcheck, bot_defense_app_infrastructure, route, service_policy_set` |
| `--include-system` | off | Also scan the `system` namespace (Bot Defense app infrastructure is always checked there) |
| `--no-referring-api` | off | Skip the server-side reference lookup. Faster, but produces false orphans. |
| `--workers` | 8 | Concurrent API calls. Lower it if you hit 429s. |
| `--max-retries` | 5 | Retries on 429, 5xx and transport errors |
| `--timeout` | 30 | Per-request timeout, in seconds |
| `--ca-bundle` | system | CA bundle for TLS-inspecting proxies |
| `--out-dir` | `xc-unused-objects-out` | Output directory |
| `--quiet` | off | Suppress progress logging |

### Outputs

| File | Contents |
|---|---|
| `xc-unused-<stamp>.html` | Report: summary by kind, filterable and sortable object table, referrers, disabled LBs, scan coverage and errors |
| `xc-unused-<stamp>.json` | Full machine-readable results |
| `xc-unused-<stamp>.csv` | One row per object |
| `xc-unused-cleanup-<stamp>.sh` | `DELETE` commands, **all commented out**, ordered so dependents go first |

---

## Accuracy notes

- **Namespace scoping is safe.** XC's reference lookup covers the whole tenant. An object in `shared` that is used only by an LB in a namespace you didn't scan shows as `UNVERIFIED`, not `ORPHANED`. This only holds while the lookup is on, so don't combine scoping with `--no-referring-api`.
- **RBAC limits what you see.** If any namespace returns 403, objects in `shared` with no visible referrers are reported `UNVERIFIED`. Every 403 is listed under *Scan coverage*.
- **Always read *Scan coverage*.** If it shows errors on every collection, the report is empty because of connectivity, not because the tenant is clean.
- **Before deleting anything:**
  - Check labels and annotations for Terraform or GitOps ownership. An API delete will cause drift or get recreated.
  - Delete `DORMANT` objects only after their referrers.
- The Swagger `DELETE` path in the cleanup script is derived from the object-store route shape and hasn't been live-tested.
- Auto-generated objects (`ves-io-*` and view-owned children) are excluded.

## Tests

Tests run against a local XC REST emulator, so no tenant or token is needed. The emulator is seeded with 30 edge cases:

- route-level WAF, disabled LB, and chained health checks
- XC's auto-generated `ves-io-*` child objects, including UID-suffixed names
- Swagger versions, pagination, and lists returned without specs
- a 429, a persistent 500, a 403 namespace, and a bad token

```bash
pip install -r requirements-dev.txt
pytest -q tests
```

Run the emulator by hand:

```bash
python3 tests/xc_emulator.py &
F5XC_BASE_URL=http://127.0.0.1:8089 F5XC_API_TOKEN=test-token python3 xc_unused_objects.py
```

## License

MIT. See [LICENSE](LICENSE).
