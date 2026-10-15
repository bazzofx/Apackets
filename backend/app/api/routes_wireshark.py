"""The packet pivot: open an analysis's capture in the Wireshark GUI.

One route, and it is the only one in the application that starts a program for
the operator rather than for itself. What it does with a request is deliberately
dull:

* the address, the transport, the stream id and the port are **validated**;
* the display filter is **composed in the service**, never accepted from the
  client, so no request can put syntax on a command line;
* the capture path comes from the analysis row, so no request can name a file;
* the process is started detached and never waited on (see
  :mod:`app.services.wireshark`).

``GET`` reports whether the pivot is possible here at all, including where
Wireshark would be started from, so the UI can leave the action out instead of
offering something that cannot work.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import analysis_ready_row, capture_path
from app.core.errors import ApiError
from app.core.logging import get_logger
from app.schemas import WiresharkRequest
from app.services import wireshark

log = get_logger("apackets.api.wireshark")

router = APIRouter(prefix="/api/analyses/{analysis_id}", tags=["wireshark"])


@router.get("/wireshark")
def get_wireshark(analysis_id: str, row=Depends(analysis_ready_row)) -> dict:
    """Whether this installation can open the capture in Wireshark, and with what.

    No GUI is started and no window opens: this only reports what would happen.
    """
    state = wireshark.availability()
    return {
        "analysis_id": row["id"],
        "available": state["available"],
        "executable": state["path"],
        "version": state["version"],
        "reason": state["error"],
    }


@router.post("/wireshark")
def post_wireshark(
    analysis_id: str,
    payload: WiresharkRequest,
    row=Depends(analysis_ready_row),
) -> dict:
    """Open this capture in Wireshark, filtered to the address or conversation asked for.

    ``422 validation_error`` for an address that is not one, ``503`` with the
    reason when the GUI is not installed, and ``410 capture_missing`` (from the
    dependency) when the capture has been removed. Success means the process was
    started; whether the window is visible on the operator's desktop is between
    them and their window manager. The ``pid`` reported is the process this
    request started — Windows Wireshark re-execs itself, so that one is a launcher
    which exits while the window it spawned keeps running, not a handle on the GUI.
    """
    path = capture_path(row)
    try:
        result = wireshark.open_capture(
            path,
            payload.ip,
            transport=payload.transport,
            stream_id=payload.stream_id,
            port=payload.port,
        )
    except wireshark.WiresharkError as exc:
        message = str(exc)
        if "not found" in message:
            raise ApiError(503, "wireshark_unavailable", message, {"analysis_id": analysis_id}) from exc
        raise ApiError(422, "validation_error", message, {"ip": payload.ip}) from exc

    return {
        "analysis_id": analysis_id,
        "launched": result["launched"],
        "executable": result["executable"],
        "filter": result["filter"],
        "pid": result["pid"],
    }
