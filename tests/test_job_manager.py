import time
import unittest

from coreason_auditor.job_manager import JobManager, JobStatus


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

    def test_submit_and_complete_job(self) -> None:
        """Test happy path for job execution."""
        job_id = self.manager.submit_job(mock_task, 0.1, "Success")

        # Check immediate status (might be PENDING or RUNNING)
        job = self.manager.get_job(job_id)
        assert job is not None
        self.assertIn(job.status, [JobStatus.PENDING, JobStatus.RUNNING])

        # Wait for completion
        time.sleep(0.2)

        job = self.manager.get_job(job_id)
        assert job is not None
        self.assertEqual(job.status, JobStatus.COMPLETED)
        self.assertEqual(job.result, "Success")
        self.assertIsNotNone(job.completed_at)

    def test_job_failure(self) -> None:
        """Test error handling."""
        job_id = self.manager.submit_job(mock_failing_task)

        time.sleep(0.1)

        job = self.manager.get_job(job_id)
        assert job is not None
        self.assertEqual(job.status, JobStatus.FAILED)
        self.assertIn("Task failed on purpose", str(job.error))

    def test_get_nonexistent_job(self) -> None:
        """Test retrieving invalid job ID."""
        job = self.manager.get_job("invalid-id")
        self.assertIsNone(job)
