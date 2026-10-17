# syntax=docker/dockerfile:1
#
# ShinboShark — one image, one container, one command.
#
#   docker build -t shinobishark .
#   docker run --rm -p 127.0.0.1:8080:8000 -v shinobishark-data:/data shinobishark
#
# The image contains the whole application: the Python API, the dissector it drives
# (TShark, from the distribution), and the built single-page interface. FastAPI serves
# the interface itself, so there is no second container, no nginx, and no proxy to
# configure — one process answers on one port.
#
# Two things are deliberately not in here:
#   * no capture data. /data is the only writable path and it is meant to be a volume.
#   * no Wireshark GUI. The right-click pivot reports itself unavailable in a container;
#     it starts a window on the operator's desktop, which a container is not part of.

# ---------------------------------------------------------------------------
# 1. The interface: build the Vite bundle.
# ---------------------------------------------------------------------------
FROM node:22-bookworm-slim AS web

WORKDIR /build

# Dependencies first, so a source-only change does not reinstall them.
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci --no-audit --no-fund || npm install --no-audit --no-fund

COPY frontend/tsconfig.json frontend/tsconfig.node.json frontend/vite.config.ts ./
COPY frontend/tailwind.config.js frontend/postcss.config.js frontend/index.html ./
COPY frontend/src ./src

# `npm run build` is `tsc -b && vite build`, so a type error fails the image build.
RUN npm run build

# ---------------------------------------------------------------------------
# 2. The application: Python, TShark, and both of the above.
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS app

ENV DEBIAN_FRONTEND=noninteractive

# `tshark` brings the dissector library; `capinfos` comes with it. The install is
# non-interactive, so debconf leaves "allow non-superusers to capture" disabled — this
# application only ever reads capture files, never listens on a network interface.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tshark ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Fail the build here rather than at the first upload if the dissector is unusable.
RUN tshark --version > /dev/null && capinfos --version > /dev/null

WORKDIR /app

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r backend/requirements.txt

# The repository layout is preserved on purpose: `backend/app/main.py` resolves the
# interface at `../../frontend/dist`, and `services/suricata_rules.py` reads the vendored
# rule tree at `../../rules`. Both are found where they are expected.
COPY backend/app ./backend/app
COPY backend/rules ./backend/rules
COPY --from=web /build/dist ./frontend/dist

# An unprivileged runtime user. Reading captures needs no privileges of any kind.
RUN groupadd --system --gid 10001 shinobi \
    && useradd --system --uid 10001 --gid shinobi --home-dir /app --shell /usr/sbin/nologin shinobi \
    && mkdir -p /data \
    && chown -R shinobi:shinobi /app /data

USER shinobi

# /data is the volume: uploads, the SQLite index, extracted objects and the GeoIP
# dataset all live under it. Everything else in the image is read-only at runtime.
ENV APACKETS_DATA_DIR=/data \
    APACKETS_HOST=0.0.0.0 \
    APACKETS_PORT=8000 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app/backend

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status==200 else 1)"

# One worker, deliberately. The job runner, the profile caches and the baseline sweep are
# in-process state, and SQLite is written from them; a second worker would be a second
# writer with its own registry. Scale by sharding captures, not by forking this process.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-access-log"]
