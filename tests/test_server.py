# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_auditor

import json
import time
from unittest.mock import MagicMock, patch

import pytest
import yaml
from fastapi.testclient import TestClient

from coreason_auditor.job_manager import JobManager, JobStatus, ReportJob
from coreason_auditor.server import app, remove_file


def test_health() -> None:
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ready", "version": "0.1.0"}

def test_audit_flow() -> None:
    agent_config = {
        "requirements": [{"req_id": "1.1", "desc": "Test", "critical": True}],
        "coverage_map": {"1.1": ["T-1"]}
    }
    assay_report = {
        "results": [{"test_id": "T-1", "result": "PASS"}],
        "generated_at": "2025-01-01T00:00:00Z"
    }
    bom_input = {
        "model_name": "test",
        "model_version": "v1",
        "model_sha": "sha256:123",
        "data_lineage": [],
        "software_dependencies": []
    }

    files = {
        "agent_config": ("agent.yaml", yaml.dump(agent_config).encode("utf-8"), "application/yaml"),
        "assay_report": ("assay_report.json", json.dumps(assay_report).encode("utf-8"), "application/json"),
        "bom_input": ("bom_input.json", json.dumps(bom_input).encode("utf-8"), "application/json"),
    }

    with TestClient(app) as client:
        # Submit
        resp = client.post("/audit/generate", files=files)
        assert resp.status_code == 202
        data = resp.json()
        assert "job_id" in data
        job_id = data["job_id"]

        # Poll
        for _ in range(20):
            resp = client.get(f"/audit/jobs/{job_id}")
            assert resp.status_code == 200
            status = resp.json()["status"]
            if status == "COMPLETED":
                break
            if status == "FAILED":
                pytest.fail(f"Job failed: {resp.json().get('error')}")
            time.sleep(0.1)

        assert status == "COMPLETED"

        # Download PDF
        resp = client.get(f"/audit/download/{job_id}/pdf")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"
        assert len(resp.content) > 0

        # Download CSV
        resp = client.get(f"/audit/download/{job_id}/csv")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        assert len(resp.content) > 0

        # Invalid format
        resp = client.get(f"/audit/download/{job_id}/xml")
        assert resp.status_code == 400

def test_audit_generate_invalid_input() -> None:
    with TestClient(app) as client:
        # Missing files
        resp = client.post("/audit/generate", files={})
        assert resp.status_code == 422

        # Invalid YAML (Triggers YAMLError -> 400)
        # Use a tab character which is illegal in YAML
        files = {
            "agent_config": ("agent.yaml", b"\tinvalid: yaml", "application/yaml"),
            "assay_report": ("assay_report.json", b"{}", "application/json"),
            "bom_input": ("bom_input.json", b"{}", "application/json"),
        }
        resp = client.post("/audit/generate", files=files)
        assert resp.status_code == 400
        # Check for either YAMLError msg or our wrapped message
        assert "Invalid file format" in resp.json()["detail"]

        # Valid YAML but Invalid Schema (Triggers ValidationError -> 422)
        # Missing required 'requirements' field in AgentConfig
        agent_config = {"coverage_map": {}}
        files = {
            "agent_config": ("agent.yaml", yaml.dump(agent_config).encode("utf-8"), "application/yaml"),
            "assay_report": ("assay_report.json", b"{}", "application/json"),
            "bom_input": ("bom_input.json", b"{}", "application/json"),
        }
        resp = client.post("/audit/generate", files=files)
        assert resp.status_code == 422
        assert "Validation error" in resp.json()["detail"]

        # Valid YAML not dict (Triggers explicit check -> 400)
        files = {
            "agent_config": ("agent.yaml", b"- list item", "application/yaml"),
            "assay_report": ("assay_report.json", b"{}", "application/json"),
            "bom_input": ("bom_input.json", b"{}", "application/json"),
        }
        resp = client.post("/audit/generate", files=files)
        assert resp.status_code == 400
        assert "Agent Config must be a YAML mapping" in resp.json()["detail"]

def test_audit_generate_generic_exception() -> None:
    # Mock yaml.safe_load to raise generic Exception
    with patch("yaml.safe_load", side_effect=Exception("Boom")):
        files = {
            "agent_config": ("agent.yaml", b"{}", "application/yaml"),
            "assay_report": ("assay_report.json", b"{}", "application/json"),
            "bom_input": ("bom_input.json", b"{}", "application/json"),
        }
        with TestClient(app) as client:
            resp = client.post("/audit/generate", files=files)
            assert resp.status_code == 500
            assert "Boom" in resp.json()["detail"]

def test_job_not_found() -> None:
    with TestClient(app) as client:
        resp = client.get("/audit/jobs/invalid-uuid")
        assert resp.status_code == 404

        resp = client.get("/audit/download/invalid-uuid/pdf")
        assert resp.status_code == 404

def test_download_job_not_completed() -> None:
    # Patch the JobManager class method get_job
    with patch.object(JobManager, "get_job") as mock_get_job:
        mock_get_job.return_value = ReportJob(
            job_id="pending-id",
            owner_id="user",
            status=JobStatus.PENDING
        )

        with TestClient(app) as client:
            resp = client.get("/audit/download/pending-id/pdf")
            assert resp.status_code == 400
            assert "Job not completed" in resp.json()["detail"]

def test_download_generic_exception() -> None:
    # Patch the JobManager class method get_job
    with patch.object(JobManager, "get_job") as mock_get_job:
        mock_get_job.return_value = ReportJob(
            job_id="completed-id",
            owner_id="user",
            status=JobStatus.COMPLETED,
            result=MagicMock() # AuditPackage mock
        )

        # Patch orchestrator export_to_pdf
        # We need to ensure we patch the exact object used by the app.
        # Since orchestrator is created in lifespan and stored in app.state,
        # patching the class AuditOrchestratorAsync.export_to_pdf is safer
        # as the instance method delegates to it or is bound to it?
        # Wait, export_to_pdf is an instance method.
        # Let's try patching the method on the class AuditOrchestratorAsync.
        from coreason_auditor.orchestrator import AuditOrchestratorAsync
        with patch.object(AuditOrchestratorAsync, "export_to_pdf", side_effect=Exception("Export Fail")):
            with TestClient(app) as client:
                resp = client.get("/audit/download/completed-id/pdf")
                assert resp.status_code == 500
                assert "Export Fail" in resp.json()["detail"]

def test_remove_file_exception() -> None:
    with patch("os.remove", side_effect=Exception("Remove Fail")):
        # Just call the function directly to verify it doesn't crash
        # It logs error but returns None
        remove_file("dummy_path")
