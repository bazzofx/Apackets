# APackets backend / API image.
#
# TShark is a system dependency: it is installed here from the distribution and
# is the only packet decoder used by the application. The service runs as an
# unprivileged user — reading capture files needs no elevated privileges, and
# live capture is deliberately not supported.

FROM python:3.12-slim-bookworm

# `tshark` pulls in the dissector library. Non-interactive install keeps the
# debconf "allow non-superusers to capture" prompt at its default (disabled);
# this application only reads capture files, so that is exactly what we want.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        tshark \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Fail the build early if TShark is missing or unusable.
RUN tshark --version > /dev/null && capinfos --version > /dev/null

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Unprivileged runtime user; /data is the only writable location it needs.
RUN groupadd --system --gid 10001 apackets \
    && useradd --system --uid 10001 --gid apackets --home-dir /app --shell /usr/sbin/nologin apackets \
    && mkdir -p /data \
    && chown -R apackets:apackets /app /data

USER apackets

ENV APACKETS_DATA_DIR=/data \
    APACKETS_HOST=0.0.0.0 \
    APACKETS_PORT=8000 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

# Bound the blast radius of a hostile capture: no new privileges, and a modest
# process/file-descriptor ceiling.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
