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
    RiskLevel,
    Session,
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
        Session(
            session_id="sess-001",
            timestamp=datetime(2023, 10, 27, 10, 0, 0, tzinfo=timezone.utc),
            risk_level=RiskLevel.HIGH,
            violation_summary="Toxic output detected",
            violation_type="Safety",
        )
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
    assert "Safety" in text

    # Check Signature Page content
    assert "Electronic Signature Page" in text
    assert "Signed By: AutomatedTest" in text
    assert "Signature Hash: dummysig" in text


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

    # Add T-FAIL
    sample_audit_package.rtm.tests.append(ComplianceTest(test_id="T-FAIL", result="FAIL", evidence="Failed reason"))

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


def test_rtm_uncovered_requirement(tmp_path: Any, sample_audit_package: AuditPackage) -> None:
    """Test specifically for req_status = 'UNCOVERED'."""
    if PdfReader is None:
        pytest.skip("pypdf not installed")

    # Create a requirement that has NO tests in coverage_map
    # Note: The validator requires that if it IS in coverage_map, the tests exist.
    # It does NOT require that every requirement IS in coverage_map.
    req_uncovered = Requirement(req_id="9.9", desc="Uncovered Requirement", critical=True)
    sample_audit_package.rtm.requirements.append(req_uncovered)

    # Ensure it's NOT in coverage map
    if "9.9" in sample_audit_package.rtm.coverage_map:
        del sample_audit_package.rtm.coverage_map["9.9"]

    output_file = tmp_path / "uncovered.pdf"
    generator = PDFReportGenerator()
    generator.generate_report(sample_audit_package, str(output_file))

    reader = PdfReader(str(output_file))
    text = ""
    for page in reader.pages:
        text += page.extract_text()

    assert "9.9" in text
    assert "UNCOVERED" in text
    assert "Uncovered Requirement" in text


def test_pdf_rendering_robustness(tmp_path: Any, sample_audit_package: AuditPackage) -> None:
    """Test handling of special characters, HTML/XML injection, and long text."""
    if PdfReader is None:
        pytest.skip("pypdf not installed")

    # Inject nasty characters
    dangerous_desc = "Logic: A < B & C > D. <script>alert('hack')</script>"
    unicode_desc = "Unicode: \u2603 (Snowman) \U0001f600 (Grin)"  # Snowman & Grinning Face

    sample_audit_package.rtm.requirements.append(Requirement(req_id="X.1", desc=dangerous_desc, critical=False))
    sample_audit_package.rtm.requirements.append(Requirement(req_id="X.2", desc=unicode_desc, critical=False))

    # Inject dangerous deviation
    sample_audit_package.deviation_report.append(
        Session(
            session_id="hack-001",
            timestamp=datetime.now(timezone.utc),
            risk_level=RiskLevel.CRITICAL,
            violation_summary="User said: <img src=x onerror=alert(1)>",
        )
    )

    # Ensure mapped tests (empty list is fine for X.1/X.2 => UNCOVERED)
    # This prevents validation error if we were re-validating, but here we just modify list.

    output_file = tmp_path / "robustness.pdf"
    generator = PDFReportGenerator()
    generator.generate_report(sample_audit_package, str(output_file))

    reader = PdfReader(str(output_file))
    text = ""
    for page in reader.pages:
        text += page.extract_text()

    # Check that it didn't crash and text is present
    # Note: reportlab Paragraph might strip tags if not escaped, or render them as text if escaped.
    # Since we escaped, we expect to see the literal text "&lt;" or "<" depending on how pypdf extracts it.
    # pypdf usually extracts "A < B" if it was rendered as text.

    # We expect the text to exist in the PDF content
    assert "Logic: A < B" in text
    # Unicode support depends on font, standard PDF fonts might not show emojis, but shouldn't crash.
    # If font doesn't support it, it might show squares or nothing.
    # We mainly test for NO CRASH here.
    assert "hack-001" in text


def test_large_report_pagination(tmp_path: Any, sample_audit_package: AuditPackage) -> None:
    """Test generating a large multi-page report."""
    if PdfReader is None:
        pytest.skip("pypdf not installed")

    # Generate 200 requirements and deviations to ensure > 2 pages
    for i in range(200):
        req_id = f"L.{i}"
        sample_audit_package.rtm.requirements.append(
            Requirement(req_id=req_id, desc=f"Large Requirement {i}", critical=False)
        )
        sample_audit_package.deviation_report.append(
            Session(
                session_id=f"sess-{i}",
                timestamp=datetime(2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
                risk_level=RiskLevel.LOW,
                violation_summary=f"Violation {i}",
            )
        )

    output_file = tmp_path / "large_report.pdf"
    generator = PDFReportGenerator()
    generator.generate_report(sample_audit_package, str(output_file))

    reader = PdfReader(str(output_file))
    # Should have multiple pages.
    # 200 rows should take multiple pages.
    assert len(reader.pages) > 2

    # Check headers and footers on a later page (e.g. page 2, index 1)
    page_2_text = reader.pages[1].extract_text()
    assert "CoReason Audit Report" in page_2_text
    assert "Confidential - CoReason Ecosystem" in page_2_text
    # Check page number formatting if pypdf extracts it cleanly (sometimes it's tricky)
    # But at least the static text should be there.

    # Verify content
    full_text = ""
    for page in reader.pages:
        full_text += page.extract_text()

    assert "L.199" in full_text


def test_complex_scenario_mixed_content(tmp_path: Any, sample_audit_package: AuditPackage) -> None:
    """
    Complex scenario mixing:
    - Long text
    - Many dependencies
    - Unicode
    """
    if PdfReader is None:
        pytest.skip("pypdf not installed")

    # 1. Add 50 dependencies (to force split in dependency table)
    for i in range(50):
        sample_audit_package.bom.software_dependencies.append(f"lib-complex-{i}==1.0.{i}")

    # 2. Add a requirement with long text (but safely under 1 page to avoid row split issues for now)
    # 1000 chars is substantial.
    long_desc = "Long description start. " + "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 20
    sample_audit_package.rtm.requirements.append(Requirement(req_id="C.1", desc=long_desc, critical=True))

    # 3. Add unicode in signer name
    # "田中" (Tanaka) in unicode is \u7530\u4e2d
    sample_audit_package.generated_by = "Dr. \u7530\u4e2d (Tanaka)"

    output_file = tmp_path / "complex_scenario.pdf"
    generator = PDFReportGenerator()
    generator.generate_report(sample_audit_package, str(output_file))

    reader = PdfReader(str(output_file))
    full_text = ""
    for page in reader.pages:
        full_text += page.extract_text()

    assert "lib-complex-49" in full_text
    assert "Long description start." in full_text
    # pypdf might not extract CJK chars correctly depending on the embedded font,
    # but we check it didn't crash.
    # We can check for the ascii part "(Tanaka)"
    assert "(Tanaka)" in full_text


def test_long_text_cell_behavior(tmp_path: Any, sample_audit_package: AuditPackage) -> None:
    """Test behavior when a single cell has significant amount of text."""
    if PdfReader is None:
        pytest.skip("pypdf not installed")

    # Create a deviation with a summary that is ~20 lines long
    long_summary = "Deviation Detail:\n" + "\n".join([f"- Detail point {i}" for i in range(20)])

    sample_audit_package.deviation_report.append(
        Session(
            session_id="sess-long-text",
            timestamp=datetime(2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            risk_level=RiskLevel.MEDIUM,
            violation_summary=long_summary,
        )
    )

    output_file = tmp_path / "long_cell.pdf"
    generator = PDFReportGenerator()
    generator.generate_report(sample_audit_package, str(output_file))

    reader = PdfReader(str(output_file))
    full_text = ""
    for page in reader.pages:
        full_text += page.extract_text()

    assert "sess-long-text" in full_text
    assert "Detail point 19" in full_text
