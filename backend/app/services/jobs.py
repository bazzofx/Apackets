"""Background analysis job management.

A small in-process thread pool. Long-running PCAP processing never blocks an
HTTP request: the upload endpoint inserts a row, submits a job and returns 202,
and the client polls ``GET /api/analyses/{id}`` for progress.

For the POC the worker lives in the API process. ``JobManager`` is deliberately
the only place that knows how work is scheduled, so moving it to a separate
process later is a contained change.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from app.core.config import settings
from app.core.logging import get_logger
from app.db import database as db
from app.services.tshark import JobCancelled

log = get_logger("apackets.jobs")


@dataclass
class JobContext:
    """Handed to a worker so it can report progress and honour cancellation."""

    job_id: str
    analysis_id: str
    cancel_event: threading.Event = field(default_factory=threading.Event)

    _last_progress: float = field(default=-1.0, init=False, repr=False)
    _last_stage: str | None = field(default=None, init=False, repr=False)

    def check_cancelled(self) -> None:
        if self.cancel_event.is_set():
            raise JobCancelled("job cancelled by operator")

    @property
    def is_cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def set_stage(self, stage: str, progress: float | None = None) -> None:
        """Publish progress. Writes are coalesced to keep SQLite traffic low."""
        progress_changed = (
            progress is not None and abs(progress - self._last_progress) >= 0.5
        )
        stage_changed = stage != self._last_stage
        if not (progress_changed or stage_changed):
            return

        self._last_stage = stage
        if progress is not None:
            self._last_progress = progress

        now = time.time()
        try:
            with db.get_conn() as conn:
                conn.execute(
                    "UPDATE jobs SET stage = ?, progress = ?, message = ? WHERE id = ?",
                    (stage, progress if progress is not None else self._last_progress, stage, self.job_id),
                )
                conn.execute(
                    "UPDATE analyses SET stage = ?, progress = ?, updated_at = ? WHERE id = ?",
                    (
                        stage,
                        progress if progress is not None else self._last_progress,
                        now,
                        self.analysis_id,
                    ),
                )
        except Exception as exc:  # pragma: no cover - progress must never break a job
            log.warning("could not persist progress: %s", exc)


class JobManager:
    def __init__(self, max_workers: int | None = None) -> None:
        self._workers = max_workers or max(1, settings.worker_threads)
        self._pool: ThreadPoolExecutor | None = None
        self._lock = threading.Lock()
        self._contexts: dict[str, JobContext] = {}

    @property
    def pool(self) -> ThreadPoolExecutor:
        with self._lock:
            if self._pool is None:
                self._pool = ThreadPoolExecutor(
                    max_workers=self._workers, thread_name_prefix="apackets-job"
                )
            return self._pool

    def submit(
        self,
        analysis_id: str,
        worker: Callable[[JobContext], None],
        *,
        kind: str = "full_analysis",
    ) -> str:
        """Create a job row and schedule ``worker``."""
        job_id = uuid.uuid4().hex
        now = time.time()
        with db.get_conn() as conn:
            conn.execute(
                """
                INSERT INTO jobs (id, analysis_id, kind, status, stage, progress, message, created_at)
                VALUES (?, ?, ?, 'queued', 'queued', 0, 'Waiting for a worker', ?)
                """,
                (job_id, analysis_id, kind, now),
            )

        ctx = JobContext(job_id=job_id, analysis_id=analysis_id)
        with self._lock:
            self._contexts[job_id] = ctx

        self.pool.submit(self._run, ctx, worker, kind)
        log.info("queued job %s for analysis %s", job_id, analysis_id)
        return job_id

    def _run(self, ctx: JobContext, worker: Callable[[JobContext], None], kind: str) -> None:
        now = time.time()
        with db.get_conn() as conn:
            conn.execute(
                "UPDATE jobs SET status = 'running', started_at = ? WHERE id = ?",
                (now, ctx.job_id),
            )
            conn.execute(
                """
                UPDATE analyses SET status = 'processing', started_at = COALESCE(started_at, ?),
                       updated_at = ?, error = NULL, progress = 0
                WHERE id = ?
                """,
                (now, now, ctx.analysis_id),
            )

        try:
            worker(ctx)
        except JobCancelled:
            log.info("job %s cancelled", ctx.job_id)
            self._finish(ctx, "cancelled", error=None)
        except Exception as exc:
            log.exception("job %s failed", ctx.job_id)
            self._finish(ctx, "failed", error=f"{type(exc).__name__}: {exc}")
        else:
            self._finish(ctx, "completed", error=None)
        finally:
            with self._lock:
                self._contexts.pop(ctx.job_id, None)

    def _finish(self, ctx: JobContext, status: str, error: str | None) -> None:
        now = time.time()
        analysis_status = {
            "completed": "completed",
            "failed": "failed",
            "cancelled": "cancelled",
        }[status]
        progress = 100.0 if status == "completed" else None

        with db.get_conn() as conn:
            conn.execute(
                """
                UPDATE jobs SET status = ?, finished_at = ?, error = ?,
                       progress = COALESCE(?, progress),
                       stage = ?
                WHERE id = ?
                """,
                (status, now, error, progress, status, ctx.job_id),
            )
            conn.execute(
                """
                UPDATE analyses SET status = ?, finished_at = ?, updated_at = ?,
                       error = ?, progress = COALESCE(?, progress),
                       stage = ?
                WHERE id = ?
                """,
                (
                    analysis_status,
                    now,
                    now,
                    (error or "")[:2000] or None,
                    progress,
                    analysis_status,
                    ctx.analysis_id,
                ),
            )

    def cancel(self, job_id: str) -> bool:
        """Request cancellation. Returns False if the job is no longer active."""
        with self._lock:
            ctx = self._contexts.get(job_id)
        if ctx is None:
            return False
        ctx.cancel_event.set()
        with db.get_conn() as conn:
            conn.execute(
                "UPDATE jobs SET cancel_requested = 1, message = 'Cancellation requested' WHERE id = ?",
                (job_id,),
            )
        log.info("cancellation requested for job %s", job_id)
        return True

    def cancel_for_analysis(self, analysis_id: str) -> bool:
        with self._lock:
            targets = [ctx for ctx in self._contexts.values() if ctx.analysis_id == analysis_id]
        for ctx in targets:
            ctx.cancel_event.set()
        if targets:
            with db.get_conn() as conn:
                conn.execute(
                    "UPDATE jobs SET cancel_requested = 1 WHERE analysis_id = ? AND status = 'running'",
                    (analysis_id,),
                )
        return bool(targets)

    def is_active(self, job_id: str) -> bool:
        with self._lock:
            return job_id in self._contexts

    def shutdown(self, wait: bool = False) -> None:
        with self._lock:
            pool = self._pool
        if pool is not None:
            pool.shutdown(wait=wait, cancel_futures=True)


jobs = JobManager()
