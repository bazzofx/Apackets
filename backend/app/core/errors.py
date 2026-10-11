"""Uniform API error handling.

Every non-2xx response produced by this application has the body::

    {"error": {"code": "...", "message": "...", "details": {}}}
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("apackets.errors")


class ApiError(Exception):
    """Raised anywhere in the request path to produce the standard envelope."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: dict | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details or {}

    def to_response(self) -> JSONResponse:
        return JSONResponse(
            status_code=self.status_code,
            content={
                "error": {
                    "code": self.code,
                    "message": self.message,
                    "details": self.details,
                }
            },
        )


# --- frequently used constructors -----------------------------------------
#
# ``details`` may be passed either as a mapping (positional) or as keyword
# arguments, so both call styles work:
#     bad_request("invalid_sort", "…", {"allowed": [...]})
#     bad_request("invalid_sort", "…", allowed=[...])

def not_found(
    code: str, message: str, details: dict | None = None, **extra: object
) -> ApiError:
    return ApiError(404, code, message, {**(details or {}), **extra})


def bad_request(
    code: str, message: str, details: dict | None = None, **extra: object
) -> ApiError:
    return ApiError(400, code, message, {**(details or {}), **extra})


def conflict(
    code: str, message: str, details: dict | None = None, **extra: object
) -> ApiError:
    return ApiError(409, code, message, {**(details or {}), **extra})


def unprocessable(
    code: str, message: str, details: dict | None = None, **extra: object
) -> ApiError:
    return ApiError(422, code, message, {**(details or {}), **extra})


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        return exc.to_response()

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Keep the detail compact and JSON-safe (ctx may hold exception objects).
        problems = []
        for err in exc.errors():
            problems.append(
                {
                    "location": [str(part) for part in err.get("loc", ())],
                    "message": str(err.get("msg", "")),
                    "type": str(err.get("type", "")),
                }
            )
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_error",
                    "message": "Request parameters failed validation.",
                    "details": {"problems": problems},
                }
            },
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {
            400: "bad_request",
            401: "unauthorized",
            403: "forbidden",
            404: "not_found",
            405: "method_not_allowed",
            406: "not_acceptable",
            409: "conflict",
            413: "file_too_large",
            415: "unsupported_file_type",
            422: "unprocessable",
        }.get(exc.status_code, "http_error")
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": code,
                    "message": str(exc.detail),
                    "details": {},
                }
            },
        )

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error: %s", exc)
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "internal_error",
                    "message": "An unexpected internal error occurred.",
                    "details": {},
                }
            },
        )
