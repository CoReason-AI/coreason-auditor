from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import pytest

# We need to install pypdf to run this test
try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

from coreason_auditor.models import (
    AIBOMObject,
    AuditPackage,
    ComplianceTest,
    Requirement,
    RequirementStatus,
    TraceabilityMatrix,
)
from coreason_auditor.pdf_generator import PDFReportGenerator


@pytest.fixture  # type: ignore[misc]
def sample_audit_package() -> AuditPackage:
    bom = AIBOMObject(
        model_identity="llama-3-70b@sha256:abc12345",
        data_lineage=["job-101", "job-102"],
        software_dependencies=["numpy==1.21.0", "pandas==1.3.0"],
        cyclonedx_bom={},
    )

    reqs = [
        Requirement(req_id="1.0", desc="Must be safe", critical=True),
        Requirement(req_id="1.1", desc="Must be fast", critical=False),
    ]

    tests = [
        ComplianceTest(test_id="T-1", result="PASS"),
        ComplianceTest(test_id="T-2", result="PASS"),
    ]

    rtm = TraceabilityMatrix(
        requirements=reqs,
        tests=tests,
        coverage_map={"1.0": ["T-1"], "1.1": ["T-2"]},
        overall_status=RequirementStatus.COVERED_PASSED,
    )

    deviations = [
        {
            "session_id": "sess-001",
            "timestamp": "2023-10-27 10:00:00",
            "risk_level": "High",
            "violation_summary": "Toxic output detected",
        }
    ]

    return AuditPackage(
        id=uuid4(),
        agent_version="1.0.0",
        generated_at=datetime.now(timezone.utc),
        generated_by="AutomatedTest",
        bom=bom,
        rtm=rtm,
        deviation_report=deviations,
        human_interventions=0,
        document_hash="dummyhash123",
        electronic_signature="dummysig",
    )


def test_generate_report_creates_file(tmp_path: Any, sample_audit_package: AuditPackage) -> None:
    output_file = tmp_path / "audit_report.pdf"
    generator = PDFReportGenerator()

    generator.generate_report(sample_audit_package, str(output_file))

    assert output_file.exists()
    assert output_file.stat().st_size > 0


def test_generate_report_content(tmp_path: Any, sample_audit_package: AuditPackage) -> None:
    if PdfReader is None:
        pytest.skip("pypdf not installed")

    output_file = tmp_path / "content_test.pdf"
    generator = PDFReportGenerator()
    generator.generate_report(sample_audit_package, str(output_file))

    reader = PdfReader(str(output_file))
    text = ""
    for page in reader.pages:
        text += page.extract_text()

    # Check Header
    assert "CoReason Audit Report" in text
    assert "1.0.0" in text  # Agent Version

    # Check BOM
    assert "llama-3-70b@sha256:abc12345" in text
    assert "job-101" in text
    assert "numpy==1.21.0" in text

    # Check RTM
    assert "1.0" in text  # Req ID
    assert "Must be safe" in text
    assert "T-1: PASS" in text

    # Check Deviations
    assert "sess-001" in text
    assert "Toxic output detected" in text


def test_generate_report_empty_deviations(tmp_path: Any, sample_audit_package: AuditPackage) -> None:
    if PdfReader is None:
        pytest.skip("pypdf not installed")

    # Clear deviations
    sample_audit_package.deviation_report = []

    output_file = tmp_path / "empty_dev.pdf"
    generator = PDFReportGenerator()
    generator.generate_report(sample_audit_package, str(output_file))

    reader = PdfReader(str(output_file))
    text = ""
    for page in reader.pages:
        text += page.extract_text()

    assert "No deviations reported." in text


def test_generate_report_edge_cases(tmp_path: Any, sample_audit_package: AuditPackage) -> None:
    if PdfReader is None:
        pytest.skip("pypdf not installed")

    # 1. Empty Lineage and Dependencies
    sample_audit_package.bom.data_lineage = []
    sample_audit_package.bom.software_dependencies = []

    # 2. RTM with missing tests and failed tests
    # Coverage map points to T-MISSING
    sample_audit_package.rtm.coverage_map["1.0"] = ["T-MISSING"]
    # Coverage map points to T-FAIL (which exists but Failed)
    sample_audit_package.rtm.coverage_map["1.1"] = ["T-FAIL"]

    sample_audit_package.rtm.tests.append(ComplianceTest(test_id="T-FAIL", result="FAIL", evidence="Failed reason"))

    # We need to bypass the validator for this test because the validator checks consistency.
    # But TraceabilityEngine logic might produce such a state (missing test from report but present in config).
    # Ideally TraceabilityMatrix validator prevents "T-MISSING" if it's strict.

    # Let's mutate after creation.
    # Modifying list in place bypasses validaton.
    sample_audit_package.rtm.tests = [t for t in sample_audit_package.rtm.tests if t.test_id != "T-MISSING"]

    # Let's try constructing with valid data, then delete the test from the list.
    sample_audit_package.rtm.coverage_map["1.0"] = ["T-EXISTING"]
    sample_audit_package.rtm.tests.append(ComplianceTest(test_id="T-EXISTING", result="PASS"))

    # Now delete T-EXISTING from tests list.
    sample_audit_package.rtm.tests = [t for t in sample_audit_package.rtm.tests if t.test_id != "T-EXISTING"]

    output_file = tmp_path / "edge_cases.pdf"
    generator = PDFReportGenerator()
    generator.generate_report(sample_audit_package, str(output_file))

    reader = PdfReader(str(output_file))
    text = ""
    for page in reader.pages:
        text += page.extract_text()

    assert "No data lineage records found." in text
    assert "No dependencies listed." in text
    # Check for MISSING indicator
    assert "T-EXISTING: MISSING" in text
    assert "T-FAIL: FAIL" in text
