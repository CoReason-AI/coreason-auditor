import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from coreason_auditor.models import (
    AIBOMObject,
    AuditPackage,
    RequirementStatus,
    TraceabilityMatrix,
)
from pydantic import ValidationError


def test_requirement_status_enum() -> None:
    assert RequirementStatus.COVERED_PASSED.value == "COVERED_PASSED"
    assert RequirementStatus.COVERED_FAILED.value == "COVERED_FAILED"
    assert RequirementStatus.UNCOVERED.value == "UNCOVERED"


def test_traceability_matrix_valid() -> None:
    tm = TraceabilityMatrix(
        requirements=[{"req_id": "1.1", "desc": "Verify Dose"}],
        tests=[{"test_id": "T-100", "result": "PASS"}],
        coverage_map={"1.1": ["T-100"]},
        overall_status=RequirementStatus.COVERED_PASSED,
    )
    assert tm.requirements[0]["req_id"] == "1.1"
    assert tm.overall_status == RequirementStatus.COVERED_PASSED


def test_aibom_object_valid() -> None:
    bom = AIBOMObject(
        model_identity="sha256:12345",
        data_lineage=["job-1", "job-2"],
        software_dependencies=["pydantic==2.0"],
        cyclonedx_bom={"components": []},
    )
    assert bom.model_identity == "sha256:12345"
    assert len(bom.data_lineage) == 2


def test_audit_package_valid() -> None:
    bom = AIBOMObject(
        model_identity="sha256:12345",
        data_lineage=["job-1"],
        software_dependencies=["pkg==1.0"],
    )
    tm = TraceabilityMatrix(
        requirements=[{"req_id": "1.0"}],
        tests=[{"test_id": "T-1"}],
        coverage_map={"1.0": ["T-1"]},
        overall_status=RequirementStatus.COVERED_PASSED,
    )

    pkg = AuditPackage(
        id=uuid4(),
        agent_version="1.0.0",
        generated_at=datetime.now(timezone.utc),
        generated_by="system",
        bom=bom,
        rtm=tm,
        deviation_report=[],
        human_interventions=0,
        document_hash="hash123",
        electronic_signature="sig123",
    )

    assert pkg.agent_version == "1.0.0"
    assert pkg.bom.model_identity == "sha256:12345"


def test_validation_error() -> None:
    with pytest.raises(ValidationError):
        TraceabilityMatrix(
            requirements=[],
            tests=[],
            coverage_map={},
            overall_status="INVALID_STATUS",  # type: ignore[arg-type] # Invalid enum
        )


def test_json_serialization() -> None:
    bom = AIBOMObject(
        model_identity="sha256:12345",
        data_lineage=["job-1"],
        software_dependencies=["pkg==1.0"],
    )
    tm = TraceabilityMatrix(
        requirements=[{"req_id": "1.0"}],
        tests=[{"test_id": "T-1"}],
        coverage_map={"1.0": ["T-1"]},
        overall_status=RequirementStatus.COVERED_PASSED,
    )
    pkg = AuditPackage(
        id=uuid4(),
        agent_version="1.0.0",
        generated_at=datetime.now(timezone.utc),
        generated_by="system",
        bom=bom,
        rtm=tm,
        deviation_report=[],
        human_interventions=0,
        document_hash="hash123",
        electronic_signature="sig123",
    )

    json_str = pkg.model_dump_json()
    data = json.loads(json_str)
    assert data["agent_version"] == "1.0.0"
    assert data["rtm"]["overall_status"] == "COVERED_PASSED"
