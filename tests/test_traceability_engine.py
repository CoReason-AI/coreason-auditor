import pytest
from coreason_auditor.models import (
    AgentConfig,
    AssayReport,
    ComplianceTest,
    Requirement,
    RequirementStatus,
    TraceabilityMatrix,
)
from coreason_auditor.traceability_engine import TraceabilityEngine
from typing import Dict, List


@pytest.fixture
def basic_requirements() -> List[Requirement]:
    return [
        Requirement(req_id="1.0", desc="Must be safe"),
        Requirement(req_id="2.0", desc="Must be fast"),
    ]


@pytest.fixture
def basic_coverage_map() -> Dict[str, List[str]]:
    return {
        "1.0": ["T-101", "T-102"],
        "2.0": ["T-201"],
    }


@pytest.fixture
def engine() -> TraceabilityEngine:
    return TraceabilityEngine()


def test_generate_matrix_success(
    engine: TraceabilityEngine,
    basic_requirements: List[Requirement],
    basic_coverage_map: Dict[str, List[str]]
) -> None:
    """
    Test a perfect scenario where all requirements are covered and all tests pass.
    """
    agent_config = AgentConfig(
        requirements=basic_requirements,
        coverage_map=basic_coverage_map,
    )
    assay_report = AssayReport(
        results=[
            ComplianceTest(test_id="T-101", result="PASS"),
            ComplianceTest(test_id="T-102", result="PASS"),
            ComplianceTest(test_id="T-201", result="PASS"),
        ]
    )

    rtm = engine.generate_matrix(agent_config, assay_report)

    assert isinstance(rtm, TraceabilityMatrix)
    assert rtm.overall_status == RequirementStatus.COVERED_PASSED
    assert len(rtm.tests) == 3


def test_generate_matrix_failed_test(
    engine: TraceabilityEngine,
    basic_requirements: List[Requirement],
    basic_coverage_map: Dict[str, List[str]]
) -> None:
    """
    Test scenario where one test fails, causing the status to be COVERED_FAILED.
    """
    agent_config = AgentConfig(
        requirements=basic_requirements,
        coverage_map=basic_coverage_map,
    )
    assay_report = AssayReport(
        results=[
            ComplianceTest(test_id="T-101", result="PASS"),
            ComplianceTest(test_id="T-102", result="FAIL"),  # Failure here
            ComplianceTest(test_id="T-201", result="PASS"),
        ]
    )

    rtm = engine.generate_matrix(agent_config, assay_report)

    assert rtm.overall_status == RequirementStatus.COVERED_FAILED
    # Verify the specific test result is preserved
    failed_test = next(t for t in rtm.tests if t.test_id == "T-102")
    assert failed_test.result == "FAIL"


def test_generate_matrix_missing_test_in_report(
    engine: TraceabilityEngine,
    basic_requirements: List[Requirement],
    basic_coverage_map: Dict[str, List[str]]
) -> None:
    """
    Test scenario where a test is defined in the coverage map but missing from the assay report.
    The engine should auto-generate a failure for this test.
    """
    agent_config = AgentConfig(
        requirements=basic_requirements,
        coverage_map=basic_coverage_map,
    )
    # T-102 is missing
    assay_report = AssayReport(
        results=[
            ComplianceTest(test_id="T-101", result="PASS"),
            ComplianceTest(test_id="T-201", result="PASS"),
        ]
    )

    rtm = engine.generate_matrix(agent_config, assay_report)

    assert rtm.overall_status == RequirementStatus.COVERED_FAILED
    # Check if T-102 was inserted as a failure
    missing_test = next(t for t in rtm.tests if t.test_id == "T-102")
    assert missing_test.result == "FAIL"
    if missing_test.evidence:
        assert "missing" in missing_test.evidence.lower()


def test_generate_matrix_uncovered_requirement(
    engine: TraceabilityEngine,
    basic_requirements: List[Requirement]
) -> None:
    """
    Test scenario where a requirement has no tests mapped to it.
    """
    # Requirement 2.0 has no tests in the map
    incomplete_coverage_map: Dict[str, List[str]] = {
        "1.0": ["T-101"],
        # "2.0": []  <-- Implicitly empty or explicitly empty
    }

    agent_config = AgentConfig(
        requirements=basic_requirements,
        coverage_map=incomplete_coverage_map,
    )
    assay_report = AssayReport(
        results=[
            ComplianceTest(test_id="T-101", result="PASS"),
        ]
    )

    rtm = engine.generate_matrix(agent_config, assay_report)

    assert rtm.overall_status == RequirementStatus.UNCOVERED


def test_integrity_check_failure(
    engine: TraceabilityEngine,
    basic_requirements: List[Requirement]
) -> None:
    """
    Test that the engine handles cases where coverage map references non-existent requirements.
    """
    bad_coverage_map: Dict[str, List[str]] = {
        "1.0": ["T-101"],
        "9.9": ["T-999"],  # Req 9.9 does not exist in basic_requirements
    }

    agent_config = AgentConfig(
        requirements=basic_requirements,
        coverage_map=bad_coverage_map,
    )
    assay_report = AssayReport(
        results=[
            ComplianceTest(test_id="T-101", result="PASS"),
            ComplianceTest(test_id="T-999", result="PASS"),
        ]
    )

    with pytest.raises(ValueError, match="Requirement ID '9.9' in coverage_map not found"):
        engine.generate_matrix(agent_config, assay_report)
