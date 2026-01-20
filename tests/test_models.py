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
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from coreason_auditor.models import (
    AIBOMObject,
    AuditPackage,
    ComplianceTest,
    EventType,
    Requirement,
    RequirementStatus,
    RiskLevel,
    Session,
    SessionEvent,
    TraceabilityMatrix,
)
from pydantic import ValidationError


def test_requirement_status_enum() -> None:
    assert RequirementStatus.COVERED_PASSED.value == "COVERED_PASSED"
    assert RequirementStatus.COVERED_FAILED.value == "COVERED_FAILED"
    assert RequirementStatus.UNCOVERED.value == "UNCOVERED"


def test_risk_level_enum() -> None:
    assert RiskLevel.LOW.value == "LOW"
    assert RiskLevel.CRITICAL.value == "CRITICAL"


def test_event_type_enum() -> None:
    assert EventType.INPUT.value == "INPUT"
    assert EventType.OUTPUT.value == "OUTPUT"


def test_session_models_valid() -> None:
    event = SessionEvent(
        timestamp=datetime.now(timezone.utc),
        event_type=EventType.INPUT,
        content="User prompt",
        metadata={"tokens": 10},
    )
    session = Session(
        session_id="sess-001",
        timestamp=datetime.now(timezone.utc),
        risk_level=RiskLevel.HIGH,
        violation_summary="Bad output",
        events=[event],
    )
    assert session.session_id == "sess-001"
    assert session.events[0].content == "User prompt"
    assert session.risk_level == RiskLevel.HIGH


def test_traceability_matrix_valid() -> None:
    req = Requirement(req_id="1.1", desc="Verify Dose")
    test = ComplianceTest(test_id="T-100", result="PASS")
    tm = TraceabilityMatrix(
        requirements=[req],
        tests=[test],
        coverage_map={"1.1": ["T-100"]},
        overall_status=RequirementStatus.COVERED_PASSED,
    )
    assert tm.requirements[0].req_id == "1.1"
    assert tm.overall_status == RequirementStatus.COVERED_PASSED


def test_traceability_matrix_integrity_error_req() -> None:
    """Test that referencing a non-existent Requirement ID raises ValidationError."""
    req = Requirement(req_id="1.1", desc="Verify Dose")
    test = ComplianceTest(test_id="T-100", result="PASS")

    with pytest.raises(ValidationError) as exc:
        TraceabilityMatrix(
            requirements=[req],
            tests=[test],
            coverage_map={"9.9": ["T-100"]},  # 9.9 does not exist
            overall_status=RequirementStatus.UNCOVERED,
        )
    assert "Requirement ID '9.9' in coverage_map not found" in str(exc.value)


def test_traceability_matrix_integrity_error_test() -> None:
    """Test that referencing a non-existent Test ID raises ValidationError."""
    req = Requirement(req_id="1.1", desc="Verify Dose")
    test = ComplianceTest(test_id="T-100", result="PASS")

    with pytest.raises(ValidationError) as exc:
        TraceabilityMatrix(
            requirements=[req],
            tests=[test],
            coverage_map={"1.1": ["T-999"]},  # T-999 does not exist
            overall_status=RequirementStatus.UNCOVERED,
        )
    assert "Test ID 'T-999' mapped to Requirement '1.1' not found" in str(exc.value)


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
    req = Requirement(req_id="1.0", desc="R1")
    test = ComplianceTest(test_id="T-1", result="PASS")
    tm = TraceabilityMatrix(
        requirements=[req],
        tests=[test],
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
        config_changes=[],
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
            overall_status="INVALID_STATUS",
        )


def test_complex_scenario() -> None:
    """Test a complex scenario with multiple requirements and tests."""
    # Define Requirements
    req1 = Requirement(req_id="1.1", desc="No Toxic Output")
    req2 = Requirement(req_id="1.2", desc="Data Privacy")
    req3 = Requirement(req_id="1.3", desc="Response Latency < 1s")

    # Define Tests
    t1 = ComplianceTest(test_id="T-101", result="PASS", evidence="log_101")
    t2 = ComplianceTest(test_id="T-102", result="PASS", evidence="log_102")
    t3 = ComplianceTest(test_id="T-103", result="FAIL", evidence="log_103")

    # Coverage Map: 1.1 covered by T-101, 1.2 covered by T-101 and T-102, 1.3 covered by T-103
    coverage = {
        "1.1": ["T-101"],
        "1.2": ["T-101", "T-102"],
        "1.3": ["T-103"],
    }

    tm = TraceabilityMatrix(
        requirements=[req1, req2, req3],
        tests=[t1, t2, t3],
        coverage_map=coverage,
        overall_status=RequirementStatus.COVERED_FAILED,  # Failed because T-103 failed
    )

    bom = AIBOMObject(
        model_identity="llama-3:abc1234",
        data_lineage=["ingest-job-1", "ingest-job-2"],
        software_dependencies=["torch==2.0", "pydantic==2.0"],
        cyclonedx_bom={
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [{"name": "torch", "version": "2.0"}, {"name": "pydantic", "version": "2.0"}],
        },
    )

    session = Session(
        session_id="sess-555",
        timestamp=datetime.now(timezone.utc),
        risk_level=RiskLevel.HIGH,
        violation_summary="Toxic Prompt Refusal",
        violation_type="Safety",
    )

    pkg = AuditPackage(
        id=uuid4(),
        agent_version="2.1.0-RC1",
        generated_at=datetime.now(timezone.utc),
        generated_by="CI/CD Pipeline",
        bom=bom,
        rtm=tm,
        deviation_report=[session],
        config_changes=[],
        human_interventions=5,
        document_hash="sha256:deadbeef",
        electronic_signature="sig:signed_by_admin",
    )

    # Serialize and Deserialize to ensure no data loss
    json_data = pkg.model_dump_json()
    pkg_loaded = AuditPackage.model_validate_json(json_data)

    assert pkg_loaded.rtm.requirements[0].req_id == "1.1"
    assert len(pkg_loaded.rtm.tests) == 3
    assert pkg_loaded.rtm.coverage_map["1.2"] == ["T-101", "T-102"]
    assert pkg_loaded.bom.cyclonedx_bom["components"][0]["name"] == "torch"
    assert pkg_loaded.deviation_report[0].session_id == "sess-555"
    assert pkg_loaded.deviation_report[0].risk_level == RiskLevel.HIGH


def test_json_serialization() -> None:
    bom = AIBOMObject(
        model_identity="sha256:12345",
        data_lineage=["job-1"],
        software_dependencies=["pkg==1.0"],
    )
    req = Requirement(req_id="1.0", desc="R1")
    test = ComplianceTest(test_id="T-1", result="PASS")
    tm = TraceabilityMatrix(
        requirements=[req],
        tests=[test],
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
        config_changes=[],
        human_interventions=0,
        document_hash="hash123",
        electronic_signature="sig123",
    )

    json_str = pkg.model_dump_json()
    data = json.loads(json_str)
    assert data["agent_version"] == "1.0.0"
    assert data["rtm"]["overall_status"] == "COVERED_PASSED"
