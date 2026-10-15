"""FastAPI application entry point.

Routers are registered explicitly. Routers belonging to optional analysis
features are registered only when their module is importable, so a partially
built checkout still serves a working API (with those sections reporting as
unavailable) instead of failing to start.
"""

from __future__ import annotations

import importlib
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.core.config import settings
from app.core.errors import register_exception_handlers
from app.core.logging import get_logger, setup_logging
from app.db import database as db
from app.services import tshark, wireshark
from app.services.jobs import jobs

log = get_logger("apackets.main")

# (module, attribute, required)
ROUTER_SPECS: tuple[tuple[str, str], ...] = (
    ("app.api.routes_analyses", "router"),
    ("app.api.routes_packets", "router"),
    ("app.api.routes_settings", "router"),
    ("app.api.routes_conversations", "router"),
    ("app.api.routes_hosts", "router"),
    ("app.api.routes_http", "router"),
    ("app.api.routes_dns", "router"),
    ("app.api.routes_tls", "router"),
    ("app.api.routes_protocols", "router"),
    ("app.api.routes_geo", "router"),
    ("app.api.routes_findings", "router"),
    ("app.api.routes_objects", "router"),
    ("app.api.routes_credentials", "router"),
    ("app.api.routes_suricata", "router"),
    ("app.api.routes_threat_hunt", "router"),
    ("app.api.routes_profile", "router"),
    ("app.api.routes_wireshark", "router"),
)

# Static frontend build produced by `npm run build` in ./frontend.
FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"


@asynccontextmanager
async def lifespan(_: FastAPI):
    setup_logging(settings.log_level)
    settings.ensure_dirs()
    db.init_db()

    info = tshark.version()
    if info.get("available"):
        log.info("tshark %s at %s", info.get("version"), info.get("path"))
    else:
        log.warning("TShark is not available; uploads will be rejected until it is installed")

    log.info("APackets %s ready — data directory %s", __version__, settings.data_dir)
    log.info("listening on http://%s:%s (local-only: %s)", settings.host, settings.port,
             settings.host in {"127.0.0.1", "localhost", "::1"})
    try:
        yield
    finally:
        jobs.shutdown(wait=False)


app = FastAPI(
    title="APackets — Local PCAP Analyzer",
    version=__version__,
    description=(
        "Locally hosted PCAP/PCAPNG analysis. All dissection is performed by "
        "TShark on this machine; no capture data leaves the host."
    ),
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
)

register_exception_handlers(app)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "X-Total-Rows", "X-Exported-Rows", "X-Truncated"],
)


def register_routers() -> list[str]:
    """Attach every router that can be imported; return the ones that could not."""
    missing: list[str] = []
    for module_name, attribute in ROUTER_SPECS:
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:  # noqa: BLE001
            log.warning("router %s unavailable: %s", module_name, exc)
            missing.append(module_name.rsplit(".", 1)[-1])
            continue
        router = getattr(module, attribute, None)
        if router is None:
            log.warning("router %s has no %s", module_name, attribute)
            missing.append(module_name.rsplit(".", 1)[-1])
            continue
        app.include_router(router)

    if missing:
        log.warning("missing routers: %s", ", ".join(missing))
    return missing


register_routers()


@app.get("/api/capabilities", tags=["meta"])
def capabilities() -> dict:
    """Report which feature areas are actually available in this build."""
    available: dict[str, bool] = {}
    for module_name, _ in ROUTER_SPECS:
        key = module_name.rsplit(".", 1)[-1].removeprefix("routes_")
        try:
            importlib.import_module(module_name)
            available[key] = True
        except Exception:  # noqa: BLE001
            available[key] = False
    return {
        "version": __version__,
        "features": available,
        "tshark": tshark.version().get("available", False),
        # Whether the packet pivot in the IP context menu can be offered here.
        "wireshark": wireshark.availability(),
    }


# --------------------------------------------------------------------------
# optional static frontend
# --------------------------------------------------------------------------

if FRONTEND_DIST.is_dir():
    assets = FRONTEND_DIST / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

    # response_model=None: this handler returns a union of Response subclasses,
    # which FastAPI cannot convert into a Pydantic response field.
    @app.get("/{full_path:path}", include_in_schema=False, response_model=None)
    def serve_frontend(full_path: str) -> FileResponse | JSONResponse:
        """Serve the built SPA, letting the client router handle unknown paths."""
        if full_path.startswith("api/"):
            return JSONResponse(
                status_code=404,
                content={
                    "error": {
                        "code": "not_found",
                        "message": f"No API route matches '/{full_path}'.",
                        "details": {},
                    }
                },
            )

        candidate = (FRONTEND_DIST / full_path).resolve()
        try:
            candidate.relative_to(FRONTEND_DIST.resolve())
        except ValueError:
            # Path traversal attempt against the static mount.
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "code": "path_traversal",
                        "message": "Resolved path escapes the static directory.",
                        "details": {},
                    }
                },
            )

        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(FRONTEND_DIST / "index.html")
