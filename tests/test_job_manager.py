# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_auditor

import time
import unittest

from coreason_auditor.job_manager import JobManager, JobStatus
from coreason_identity.models import UserContext
from coreason_identity.types import SecretStr


def mock_task(duration: float, result_val: str) -> str:
    """Simulates a long running task."""
    time.sleep(duration)
    return result_val


def mock_failing_task() -> None:
    """Simulates a task that raises an exception."""
    raise ValueError("Task failed on purpose")


class TestJobManager(unittest.TestCase):
    def setUp(self) -> None:
        self.manager = JobManager(max_workers=2)

    def tearDown(self) -> None:
        self.manager.shutdown(wait=False)

    def test_create_job_missing_context(self) -> None:
        """Test that create_job raises ValueError when context is missing."""
        with self.assertRaisesRegex(ValueError, "UserContext is required"):
            self.manager.create_job(None, mock_task, 0.1, "Success")  # type: ignore

    def test_submit_and_complete_job(self) -> None:
        """Test happy path for job execution."""
        context = UserContext(user_id=SecretStr("test-user"), roles=[])
        job_id = self.manager.create_job(context, mock_task, 0.1, "Success")

        # Check immediate status (might be PENDING or RUNNING)
        job = self.manager.get_job(job_id)
        assert job is not None
        self.assertIn(job.status, [JobStatus.PENDING, JobStatus.RUNNING])
        self.assertEqual(job.owner_id, "test-user")

        # Wait for completion
        self._wait_for_job(job_id)

        job = self.manager.get_job(job_id)
        assert job is not None
        self.assertEqual(job.status, JobStatus.COMPLETED)
        self.assertEqual(job.result, "Success")
        self.assertIsNotNone(job.completed_at)

    def test_job_failure(self) -> None:
        """Test error handling."""
        context = UserContext(user_id=SecretStr("test-user"), roles=[])
        job_id = self.manager.create_job(context, mock_failing_task)

        self._wait_for_job(job_id)

        job = self.manager.get_job(job_id)
        assert job is not None
        self.assertEqual(job.status, JobStatus.FAILED)
        self.assertIn("Task failed on purpose", str(job.error))

    def _wait_for_job(self, job_id: str, timeout: float = 2.0) -> None:
        """Helper to poll for job completion."""
        start = time.time()
        while time.time() - start < timeout:
            job = self.manager.get_job(job_id)
            if job and job.status in [JobStatus.COMPLETED, JobStatus.FAILED]:
                return
            time.sleep(0.05)
        raise TimeoutError(f"Job {job_id} did not complete within {timeout}s")

    def test_get_nonexistent_job(self) -> None:
        """Test retrieving invalid job ID."""
        job = self.manager.get_job("invalid-id")
        self.assertIsNone(job)
