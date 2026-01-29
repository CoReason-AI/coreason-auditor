# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_auditor

import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Optional

from coreason_identity.models import UserContext
from pydantic import BaseModel, Field

from coreason_auditor.utils.logger import logger


class JobStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ReportJob(BaseModel):
    job_id: str = Field(..., description="Unique Job ID")
    owner_id: str = Field(..., description="User ID of the job owner")
    status: JobStatus = Field(default=JobStatus.PENDING)
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    result: Optional[Any] = None  # Could be the path to the PDF or the object
    error: Optional[str] = None


class JobManager:
    """Manages asynchronous report generation jobs.

    Uses a thread pool to execute tasks without blocking the main thread.
    """

    def __init__(self, max_workers: int = 4):
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._jobs: Dict[str, ReportJob] = {}

    def create_job(self, context: UserContext, func: Callable[..., Any], *args: Any, **kwargs: Any) -> str:
        """Submits a function for asynchronous execution.

        Args:
            context: The user context initiating the job.
            func: The function to execute.
            *args: Positional arguments for func.
            **kwargs: Keyword arguments for func.

        Returns:
            The job_id (str).
        """
        if context is None:
            raise ValueError("UserContext is required")

        job_id = str(uuid.uuid4())
        owner_id = context.user_id.get_secret_value()
        job = ReportJob(job_id=job_id, owner_id=owner_id, status=JobStatus.PENDING)
        self._jobs[job_id] = job

        logger.info(
            "Creating audit job",
            user_id=context.user_id.get_secret_value(),
            job_id=str(job_id),
        )
        self._executor.submit(self._worker_wrapper, job_id, func, *args, **kwargs)
        return job_id

    def get_job(self, job_id: str) -> Optional[ReportJob]:
        """Retrieves the current state of a job."""
        return self._jobs.get(job_id)

    def _worker_wrapper(self, job_id: str, func: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        """Internal wrapper to handle job status updates and error capturing."""
        job = self._jobs.get(job_id)
        if not job:
            return  # pragma: no cover

        logger.info(f"Job {job_id} started.")
        job.status = JobStatus.RUNNING

        try:
            result = func(*args, **kwargs)
            job.result = result
            job.completed_at = datetime.now(timezone.utc)
            job.status = JobStatus.COMPLETED
            logger.info(f"Job {job_id} completed successfully.")
        except Exception as e:
            logger.exception(f"Job {job_id} failed.")
            job.error = str(e)
            job.completed_at = datetime.now(timezone.utc)
            job.status = JobStatus.FAILED
        finally:
            # Timestamp was set in try/except blocks before status update
            # ensuring that if status is COMPLETED/FAILED, timestamp is present.
            pass

    def shutdown(self, wait: bool = True) -> None:
        """Shuts down the executor."""
        self._executor.shutdown(wait=wait)
