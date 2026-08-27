# Integrating with the Flock API

Flock is the fleet-wide read API for the raven sealed-secret pipeline. One
flock instance fans out to every raven, caches the answers, and exposes them
under a single hostname. Use flock when you need to **observe** secret state
across environments — dashboards, status badges, deployment gates, audit
trails.

> Flock is **read-only**. Anything that mutates a secret still goes through
> the raven that owns the engine (or the underlying Vault).

- **Base URL**: `https://raven-flock-ssg.apps.ocpdq02.norsk-tipping.no`
- **Auth**: none today (cluster-internal route); treat as
  authenticated-but-shared. Do not send secrets in query strings.
- **OpenAPI spec**: `api/flock-openapi.yaml` in the `volck/raven` repo.

## Core concepts

| Term      | Meaning                                                                                      |
|-----------|----------------------------------------------------------------------------------------------|
| `engine`  | Logical name for one Vault KV mount + gitops repo (e.g. `dev`, `prod01`, `qafreg`).          |
| `target`  | A concrete raven instance URL serving one or more engines.                                   |
| `secret`  | A leaf KV entry that has been sealed and pushed to git, identified by its short name.        |

One engine can be served by multiple targets (e.g. `dev` is served by
`ssg-dev` and `ssg-dev-to-bygg`). Most per-engine endpoints therefore return
**a list** — one row per target.

## Health & readiness

| Endpoint    | Use it for                                                              |
|-------------|-------------------------------------------------------------------------|
| `/healthz`  | Liveness — flock process is up. Always `200`.                           |
| `/readyz`   | Readiness — initial fleet snapshot loaded. `503` until first refresh.   |

Other endpoints return `503 Service Unavailable` until `/readyz` is `200`.

## Endpoints by use case

### "List every raven we know about"

```
GET /api/v1/ravens
```

Returns the routing snapshot: which engines exist, which target URLs serve
them. Cheap, safe to poll every few seconds.

### "Is engine X healthy right now?"

```
GET /api/v1/ravens/{engine}/health
GET /api/v1/health                  # whole fleet
```

Result is the latest probe (HTTP reachability + raven `/healthz`). Updated
roughly every 5 s.

### "What is the current sync status for engine X?"

```
GET /api/v1/ravens/{engine}/status
GET /api/v1/status                  # whole fleet
```

Returns raven's sync summary (last commit, last error, counters). Use this
for a green/yellow/red dashboard tile.

### "List every secret managed by engine X"

```
GET /api/v1/ravens/{engine}/inventory
GET /api/v1/inventory               # whole fleet, flattened
```

One row per `(target, secret)` with name, modified timestamp, and K8s
state. This is what backs a searchable "secret catalogue" view.

### "Show me the pipeline for secret S in engine X"

```
GET /api/v1/ravens/{engine}/pipeline/{secret}
```

Returns one row per target with the 6-stage pipeline:

| Stage        | Means                                                          |
|--------------|----------------------------------------------------------------|
| `Vault`      | Source data exists in Vault KV                                 |
| `Sealed`     | Sealed YAML present in the gitops repo                         |
| `Git`        | Sealed YAML present in the on-disk worktree                    |
| `ArgoCD`     | ArgoCD reports the manifest as synced                          |
| `K8s Secret` | The decrypted `Secret` exists in the namespace                 |
| `Rollout`    | Workloads referencing the secret have rolled out the new data  |

Each stage has `status` (`done` / `pending` / `warn` / `fail`) and an
optional `detail`. This is the canonical view to render a "deployment of
this secret" timeline.

### "Full pipeline for engine X"

```
GET /api/v1/ravens/{engine}/pipeline
```

Returns the same shape, but for every secret on every target. Big payload
(~1 MB per target) — fetch on demand, not on a loop. Use the per-secret
endpoint for polling.

### "Recent events"

```
GET /api/v1/ravens/{engine}/events
GET /api/v1/events                  # whole fleet
```

Last N events flock observed (create / update / delete) per raven. Useful
for activity feeds and audit trails.

## Live updates: `/ws`

```
wss://raven-flock-ssg.apps.ocpdq02.norsk-tipping.no/ws
```

A single WebSocket multiplexes events from every raven. Each frame:

```json
{
  "target": "https://ssg-dev-ssg.apps.ocpdq02.norsk-tipping.no",
  "engine": "dev",
  "type": "event",
  "data": { /* raven's original payload, opaque */ },
  "observed_at": "2026-05-22T11:23:37Z"
}
```

Known `type` values:

- `event` — a secret was created, updated, or deleted.
- `sync_status` — a raven full-walk cycle completed.

Client guidance:

- Reconnect with exponential backoff (1 s → 30 s).
- Respond to server pings; flock enforces a 90 s read deadline.
- Treat `data` as opaque — match on `type` first, then parse if you care.
- Slow clients are **dropped** on a 256-message buffer. If you can't keep
  up, fall back to polling.

## Integration patterns

### Pattern A — Dashboard tile (read-once, refresh slow)

Poll `/api/v1/status` every 10–30 s. Render one tile per engine with the
latest commit + error string. Fall through to `/api/v1/ravens/{engine}/status`
when the user expands a tile.

### Pattern B — Per-secret status badge in a service catalogue

For a service that owns secret `S` on engine `E`:

1. On page load, `GET /api/v1/ravens/{E}/pipeline/{S}`.
2. Render the 6 stage dots from the response.
3. Subscribe to `/ws`. On a frame where `engine == E` and the payload's
   secret name is `S`, refetch step 1.

This keeps the page accurate without re-pulling the full pipeline.

### Pattern C — "Has my secret reached the cluster?" deployment gate

In a pipeline step, after writing to Vault:

```
poll every 5s, up to 2 minutes:
  GET /api/v1/ravens/{engine}/pipeline/{secret}
  succeed when every row has K8s Secret == done (and Rollout == done if
  the secret backs a workload)
```

`/readyz` and per-stage statuses give you the precise failure point if it
times out.

### Pattern D — Fleet-wide event tap (audit / SIEM)

Subscribe to `/ws`. Persist every frame keyed by `(target, observed_at)`.
On disconnect, reconnect; on prolonged outage, replay gaps from
`/api/v1/events`.

## Operational notes

- **Caching latency**: status & inventory ≈ 5 s; pipeline ≈ 30 s. Trigger a
  refresh by `kill -HUP` on the flock pod (operators only) — not via API.
- **Errors**: per-target fetch failures are silently retried; flock keeps
  the previous good value rather than reporting `null`. Check
  `observed_at` to detect staleness.
- **404 semantics**: an engine the routing snapshot doesn't know returns
  `404`. An empty pipeline for a valid engine returns `[]` (still `200`).
- **Rate limits**: none enforced today. Be polite: poll the per-secret
  endpoint, not the per-engine one, for tight loops.
- **Versioning**: paths are prefixed `/api/v1/`. Breaking changes will land
  under `/api/v2/`.

## Quick examples

```bash
# List engines
curl -sk https://raven-flock-ssg.apps.ocpdq02.norsk-tipping.no/api/v1/ravens \
  | jq 'keys'

# One secret's pipeline across targets
curl -sk \
  https://raven-flock-ssg.apps.ocpdq02.norsk-tipping.no/api/v1/ravens/dev/pipeline/accelerate-test-secret \
  | jq '.[] | {target, stages: [.entry.stages[] | {name, status}]}'

# Stream live events
websocat -k wss://raven-flock-ssg.apps.ocpdq02.norsk-tipping.no/ws
```

```go
// Minimal Go consumer
resp, err := http.Get(base + "/api/v1/ravens/dev/pipeline/" + secret)
if err != nil { return err }
defer resp.Body.Close()
var rows []flockclient.PipelineSecretRow
if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil { return err }
for _, r := range rows {
    fmt.Println(r.Target, r.Entry.Stages)
}
```

## Where to go next

- Full machine-readable schema: `api/flock-openapi.yaml`.
- Mutating operations (creating / sealing / deleting secrets): raven's own
  API on the per-engine target URL — flock does **not** proxy these.
- Questions / new endpoints: open an issue against `volck/raven`.
