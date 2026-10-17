# Deployment

How to run ShinboShark on another machine: one image, one container, one port. The
whole application — the Python API, TShark, and the built interface — is inside it, and
FastAPI serves the interface itself, so there is no nginx and no proxy to configure.

Related: what the image contains and how a capture becomes a page is
[Architecture.md](Architecture.md); the settings it reads are [Settings.md](Settings.md); the
files it writes live under one directory, described below.

---

## 1. The two commands

```
docker compose up --build        # then open http://127.0.0.1:8080
```

or without compose:

```
docker build -t shinobishark .
docker run --rm -p 127.0.0.1:8080:8000 -v shinobishark-data:/data shinobishark
```

Both bind to **loopback only**. The container listens on `0.0.0.0` inside its own network
namespace — it has to, or nothing could reach it — and the published mapping
`127.0.0.1:8080:8000` is what keeps the capture data on this machine. There is no
authentication in this application, so publishing it on `0.0.0.0` would hand the capture
library to the network.

## 2. The image, stage by stage (`Dockerfile`)

| Stage | Base | What it does |
|---|---|---|
| `web` | `node:22-bookworm-slim` | `npm ci` from the lockfile, then `npm run build` (`tsc -b && vite build`) → `/build/dist` |
| `app` | `python:3.12-slim-bookworm` | installs `tshark` + `capinfos` from the distribution, installs `backend/requirements.txt`, copies the API, the vendored `backend/rules` tree, and the built interface |

Three things in the layout are load-bearing, and the image preserves the repository
structure for them:

* `backend/app/main.py` resolves the interface at `../../frontend/dist`, so the image has
  `/app/frontend/dist`;
* `backend/app/services/suricata_rules.py` reads the rule tree at `../../rules`, so the image
  has `/app/backend/rules`;
* the working directory is `/app/backend`, so `uvicorn app.main:app` finds the package.

The build fails early if the dissector is unusable (`tshark --version`), and it runs
`tsc -b` as part of the interface build — a type error stops the image rather than
shipping.

## 3. What the image deliberately does not contain

* **No capture data.** `/data` is the only writable path, and it is meant to be a volume:
  uploads, the SQLite index, extracted objects and the GeoIP dataset all live there.
  Delete the volume and you have an empty installation.
* **No Wireshark GUI.** The right-click **Pivot to Wireshark** starts a window on the
  operator's desktop; a container is not part of that desktop, so the endpoint reports
  itself unavailable and the menu item explains why. Use the application directly on the
  machine that has the GUI when you need the pivot.
* **No privileged capabilities.** The container runs as uid 10001, drops `ALL`
  capabilities, sets `no-new-privileges`, and reads capture files from disk — live capture
  is not a feature, so no `NET_RAW` is needed.

## 4. One worker, on purpose

The job runner, the memoised capture profiles and the baseline recalculation sweep are
**in-process state**, and SQLite is written from them. A second uvicorn worker would be a
second registry with its own caches, racing the first over the same database. The
container therefore starts uvicorn with `--workers 1`.

Scale by putting captures on separate installations, not by forking this process.

## 5. Configuration

Every value is an `APACKETS_*` environment variable, and every one has a default — an
empty `.env` is a working installation. Copy `.env.example` and edit it; `docker-compose.yml`
passes the interesting ones through.

| Variable | Default | What it changes |
|---|---|---|
| `APACKETS_MAX_UPLOAD_MB` | 512 | Largest accepted capture |
| `APACKETS_TSHARK_TIMEOUT_S` | 300 | Per TShark call |
| `APACKETS_WORKER_THREADS` | 2 | Analysis pipeline threads |
| `APACKETS_RETAIN_UPLOADS` | true | Keep the uploaded file (the packet pivot and stream views need it) |
| `APACKETS_MAX_OBJECT_BYTES` | 50 MiB | Largest extracted object |
| `APACKETS_BASELINE_AUTO_RECALC` | true | Recompute baseline findings after a baseline change |
| `APACKETS_LOG_LEVEL` | INFO | `DEBUG` slows a large analysis noticeably |
| `APACKETS_PORT_HOST` | 8080 | Host port the compose file publishes |

## 6. Verifying a deployment

```
docker compose ps            # healthy, not merely running
curl -s http://127.0.0.1:8080/api/health
```

`/api/health` reports the version, the data directory, and whether TShark was found —
`"tshark": {"available": true}` is the one line that says the image can actually dissect
a capture. The interface is served from the same port: open it and the Dashboard appears
with an empty state pointing at **PCAP Files**.

## 7. Limits and honest caveats

* **The container cannot see the operator's desktop**, so the Wireshark pivot is
  unavailable there; everything else works.
* **`/data` must be a volume** (or a bind mount). A container without it loses every
  capture on the next `docker compose up`.
* **The GeoIP dataset is not bundled.** The Dashboard's world map stays blank until the
  dataset is fetched from Settings — a download the operator makes deliberately, not
  something the image does on boot.
* **No authentication.** Loopback binding is the security boundary; do not publish this
  on another interface.
* **Image size is dominated by TShark** and its dissector library, not by the
  application.
* **The build was written and reviewed here but not executed in this environment**
  — the agent's sandbox has no access to the Docker daemon, so the first `docker build`
  is the first real run. `docker compose config` was validated, and every path the
  Dockerfile copies, plus both `parents[2]` resolutions the application does, were
  checked against the repository.

## 8. Alternatives that are still supported

* `backend/Dockerfile` — the API alone (no interface), for running the frontend dev
  server against it.
* `frontend/Dockerfile` + `frontend/nginx.conf` — the split deployment: nginx serves the
  built interface and proxies `/api` to a backend container. It needs both services
  provisioned, which is why the single image above is the recommended path.
