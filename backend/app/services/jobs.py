"""
In-memory background scan jobs so the frontend can poll for progress instead of holding one
long HTTP request open (large repos can take longer than browser / proxy timeouts).

  POST /api/jobs/github | /api/jobs/upload  ->  {scan_id, status: queued}
  GET  /api/jobs/{scan_id}                  ->  {status, stage, progress, report?, error?}

Jobs live in process memory (lost on restart). Swap `JobManager.jobs` for SQLite when needed.
"""
import asyncio
import logging
import uuid
from collections import OrderedDict
from typing import Awaitable, Callable, Optional, Set

from app.core.config import settings
from app.core.schemas import JobStatus, ScanJob, ScanReport, utcnow

logger = logging.getLogger(__name__)

Runner = Callable[[str, Callable[[str, float], None]], Awaitable[ScanReport]]


class JobManager:
    def __init__(self, max_jobs: Optional[int] = None):
        self.max_jobs = max_jobs or settings.max_jobs_kept
        self.jobs: "OrderedDict[str, ScanJob]" = OrderedDict()
        self._tasks: Set[asyncio.Task] = set()  # keep strong refs or tasks may be garbage collected

    def get(self, scan_id: str) -> Optional[ScanJob]:
        return self.jobs.get(scan_id)

    def submit(self, runner: Runner) -> ScanJob:
        job = ScanJob(scan_id=uuid.uuid4().hex[:12])
        self.jobs[job.scan_id] = job
        while len(self.jobs) > self.max_jobs:  # evict oldest finished jobs first
            oldest = next(
                (k for k, j in self.jobs.items() if j.status in (JobStatus.DONE, JobStatus.FAILED)),
                next(iter(self.jobs)),
            )
            self.jobs.pop(oldest, None)

        task = asyncio.create_task(self._run(job, runner))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return job

    async def _run(self, job: ScanJob, runner: Runner) -> None:
        job.status = JobStatus.RUNNING

        def on_progress(stage: str, fraction: float) -> None:
            job.stage = stage
            job.progress = round(max(job.progress, min(1.0, fraction)), 3)

        try:
            job.report = await runner(job.scan_id, on_progress)
            job.status = JobStatus.DONE
            job.progress = 1.0
            job.stage = "done"
        except ValueError as e:  # our own validation messages are safe to show
            job.status, job.error = JobStatus.FAILED, str(e)
        except Exception:
            logger.exception("Scan job %s crashed", job.scan_id)
            job.status = JobStatus.FAILED
            job.error = f"Internal error while scanning (ref {job.scan_id})."
        finally:
            job.finished_at = utcnow()
