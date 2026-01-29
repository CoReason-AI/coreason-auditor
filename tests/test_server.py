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
import yaml
from fastapi.testclient import TestClient
from coreason_auditor.server import app

def test_health():
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ready", "version": "0.1.0"}

def test_audit_flow():
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
                assert False, f"Job failed: {resp.json().get('error')}"
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

def test_audit_generate_invalid_input():
    with TestClient(app) as client:
        # Missing files
        resp = client.post("/audit/generate", files={})
        assert resp.status_code == 422

        # Invalid YAML
        files = {
            "agent_config": ("agent.yaml", b":::invalid yaml", "application/yaml"),
            "assay_report": ("assay_report.json", b"{}", "application/json"),
            "bom_input": ("bom_input.json", b"{}", "application/json"),
        }
        resp = client.post("/audit/generate", files=files)
        # YAML parser error handling
        assert resp.status_code == 400

def test_job_not_found():
    with TestClient(app) as client:
        resp = client.get("/audit/jobs/invalid-uuid")
        # JobManager uses dict.get, returns None
        assert resp.status_code == 404

        resp = client.get("/audit/download/invalid-uuid/pdf")
        assert resp.status_code == 404
