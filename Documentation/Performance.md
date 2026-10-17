# Performance

A measured account of what this build costs to load and to navigate, and what was changed
to bring those numbers down. Every figure here was taken on the development machine against
the 13-capture library in `data/`, with the script or command that produced it named, so the
numbers can be re-taken rather than trusted.

Related: the storage and query layer is [Architecture.md](Architecture.md) §3, the pages that
were measured are the ones in [README.md](README.md), and the rules that now recompute in the
background are [Baseline.md](Baseline.md) §5.

---

## 1. How these numbers were taken

| Layer | Method | What it can and cannot show |
|---|---|---|
| Backend endpoints | `Invoke-RestMethod` + `Stopwatch` against the running server, twice per URL (cold = first request after a restart, warm = the next one) | Real HTTP latency including JSON serialisation; not CPU-attributed |
| Backend internals | The same functions called directly on a **copy** of `data/apackets.db`, timed per helper (`.tmp/perf_summary.py`, `.tmp/perf_indexes.py`) | Isolates the query from the request; the copy is written to, never the live database |
| Frontend | Source bytes per module, split into what the first paint loads and what is now behind a route (`frontend/src` walk) | Source bytes are a *proxy*: the production bundle is minified and shared. A `vite build` cannot run in this environment (esbuild's service process is refused by the sandbox), so no chunk sizes are quoted anywhere in this document |

---

## 2. The Dashboard endpoint, before and after

`GET /api/analyses/{id}/summary` is the page every visit lands on, so it set the perceived
speed of the whole application. Against the largest capture in the library
(`SpaceX_Download_sysInternals_curlOutput.pcapng`, 163 584 frames):

| | Before | After |
|---|---|---|
| Cold (first request) | 1 850 ms | 329 ms |
| Warm (any later request) | 1 850 ms | 39 ms |

Two changes produced that, and they are independent:

### 2.1 Covering indexes on `packets`

The summary groups packets by source, destination, port, protocol and time bucket, and
always sums `frame_len`. The indexes that existed keyed on the grouping column only, so every
grouped row was a table lookup to fetch its length. Five covering indexes were added to
`backend/app/db/schema.sql` (`idx_pk_src_len`, `idx_pk_dst_len`, `idx_pk_dport_len`,
`idx_pk_proto_len`, `idx_pk_time_len`), each `(analysis_id, <grouping>, frame_len)` so the
aggregate is answered from the index alone.

| Query | Before | After |
|---|---|---|
| `_top_talkers` | 656 ms | 359 ms |
| `_top_ports` | 265 ms | 47 ms |
| `_protocol_distribution` | 172 ms | 31 ms |
| `_traffic_series` | 172 ms | 93 ms |
| `_totals` (12 separate scans) | 187 ms | 171 ms |
| **`build_summary` total** | **1 500 ms** | **781 ms** |

`CREATE INDEX IF NOT EXISTS` in the schema script means an existing database picks the
indexes up on the next start; building all five on the 163k-frame capture took **3.6 s**, paid
once by the pipeline that indexes a capture that large.

### 2.2 A cache for the parts of a summary that cannot change

A completed analysis' `packets`, `conversations`, `dns_queries`, `http_transactions`,
`tls_sessions` and `hosts` rows are immutable — a re-upload creates a new analysis id, and the
one route that rewrites derived tables (`POST /protocols/rescan`) clears the cache when it
finishes. Everything else in the payload — findings, severity counts, job status, the analysis
row — changes whenever rules are re-run, so it is computed on every request and costs well
under a millisecond.

`_aggregates()` in `backend/app/api/routes_analyses.py` therefore memoises the immutable half
per `(analysis_id, domain_limit)`, eight entries deep, least-recently-used evicted. The result:
781 ms to build once, ~15 ms to serve thereafter, and the live quarter of the payload keeps its
own correctness.

---

## 3. The endpoints that were already fast

Same capture, same method, warm:

| Endpoint | Latency |
|---|---|
| `/findings`, `/packets`, `/hosts`, `/conversations`, `/dns`, `/tls`, `/http` (100 rows) | 31–52 ms |
| `/protocols/summary`, `/objects` | 19–20 ms |
| `/profile/ip/<address>` | 189 ms |
| `/baseline` (comparison) | 469 ms, then memoised per capture |
| `/threat-hunt` | **1 548 ms — the one heavy page left (see §5)** |

These are single indexed reads with `LIMIT`, which is why they are an order of magnitude
below the two aggregate endpoints.

---

## 4. Loading the application

Every page used to be imported eagerly by `frontend/src/App.tsx`, so the first visit
downloaded, parsed and kept in memory all twenty pages — the Findings workbench, five protocol
browsers, the Threat Map's charts, the settings forms — before the analyst had opened any of
them.

`App.tsx` now imports every page except the Dashboard through `React.lazy`, and the
`<Suspense>` boundary lives **inside** `AppLayout`'s `<main>`, so a chunk arriving replaces the
page body and never the shell: the sidebar, the top bar, the baseline indicator and the
right-click menu stay mounted while a section loads.

Measured by source bytes (`frontend/src`, `.tmp/size_split.py`):

| Group | Source | Share |
|---|---|---|
| Behind a route (16 pages and their exclusive components) | 1 012 KB | 65.8 % |
| First paint (shell, Dashboard, shared components, services, types) | 527 KB | 34.2 % |

Two honest caveats: source bytes are not bundle bytes (§1), and the shared modules — `api.ts`
(the typed client for every endpoint) and `types/index.ts` — are necessarily part of the first
paint because the shell uses them. What changed is that the *pages* no longer are.

---

## 5. What was measured and deliberately left alone

* **`/threat-hunt` costs 1.5 s** on a large capture: seventeen indicators, each an aggregate
  over `packets` or `conversations`. It is the obvious next candidate (the same memoisation
  shape as the Dashboard would apply, with `ids_matches` — the one indicator that reads
  `findings` — recomputed live). It was left for a separate change rather than half-done here.
* **The frontend production bundle was never measured in this environment.** `vite build`
  fails here because esbuild's service process is refused by the sandbox; the dev-server
  transform and `tsc` are the checks used instead. Any figure for chunk sizes would have been
  invented, so none is given.
* **The Findings list is already virtualised** and its panes scroll inside a fixed-height
  workbench (see [Findings.md](Findings.md) §2), so it was not re-tuned.
* **React Query was already tuned** (`staleTime: 10 s`, no refetch on window focus, one retry).
  The one change made here was to give the baseline sweep a 1 s poll *while it runs* rather than
  a permanent interval.

---

## 6. Re-taking the measurements

```
# endpoint latency, cold then warm, for one analysis
$sw = [System.Diagnostics.Stopwatch]::StartNew()
Invoke-RestMethod "http://127.0.0.1:8000/api/analyses/<id>/summary" | Out-Null
$sw.ElapsedMilliseconds
```

`backend/.venv/Scripts/python.exe .tmp/perf_summary.py` profiles the summary helper by helper
on a copy of the database, `.tmp/perf_indexes.py` shows what the covering indexes are worth,
and `.tmp/size_split.py` prints the frontend split. All three are read-only with respect to
`data/`.
