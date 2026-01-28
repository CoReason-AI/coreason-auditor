# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_auditor

from typing import Dict, Generator, List

from coreason_identity.models import UserContext
from coreason_identity.types import SecretStr

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


@pytest.fixture  # type: ignore[misc]
def basic_requirements() -> List[Requirement]:
    return [
        Requirement(req_id="1.0", desc="Must be safe"),
        Requirement(req_id="2.0", desc="Must be fast"),
    ]


@pytest.fixture  # type: ignore[misc]
def basic_coverage_map() -> Dict[str, List[str]]:
    return {
        "1.0": ["T-101", "T-102"],
        "2.0": ["T-201"],
    }


@pytest.fixture  # type: ignore[misc]
def engine() -> Generator[TraceabilityEngine, None, None]:
    yield TraceabilityEngine()


@pytest.fixture  # type: ignore[misc]
def mock_context() -> UserContext:
    return UserContext(user_id=SecretStr("test-user"), roles=[])


def test_generate_matrix_success(
    engine: TraceabilityEngine,
    basic_requirements: List[Requirement],
    basic_coverage_map: Dict[str, List[str]],
    mock_context: UserContext,
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

    rtm = engine.generate_matrix(mock_context, agent_config, assay_report)

    assert isinstance(rtm, TraceabilityMatrix)
    assert rtm.overall_status == RequirementStatus.COVERED_PASSED
    assert len(rtm.tests) == 3


def test_generate_matrix_failed_test(
    engine: TraceabilityEngine,
    basic_requirements: List[Requirement],
    basic_coverage_map: Dict[str, List[str]],
    mock_context: UserContext,
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

    rtm = engine.generate_matrix(mock_context, agent_config, assay_report)

    assert rtm.overall_status == RequirementStatus.COVERED_FAILED
    # Verify the specific test result is preserved
    failed_test = next(t for t in rtm.tests if t.test_id == "T-102")
    assert failed_test.result == "FAIL"


def test_generate_matrix_missing_test_in_report(
    engine: TraceabilityEngine,
    basic_requirements: List[Requirement],
    basic_coverage_map: Dict[str, List[str]],
    mock_context: UserContext,
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

    rtm = engine.generate_matrix(mock_context, agent_config, assay_report)

    assert rtm.overall_status == RequirementStatus.COVERED_FAILED
    # Check if T-102 was inserted as a failure
    missing_test = next(t for t in rtm.tests if t.test_id == "T-102")
    assert missing_test.result == "FAIL"
    if missing_test.evidence:
        assert "missing" in missing_test.evidence.lower()


def test_generate_matrix_uncovered_requirement(
    engine: TraceabilityEngine, basic_requirements: List[Requirement], mock_context: UserContext
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

    rtm = engine.generate_matrix(mock_context, agent_config, assay_report)

    assert rtm.overall_status == RequirementStatus.UNCOVERED


def test_integrity_check_failure(
    engine: TraceabilityEngine, basic_requirements: List[Requirement], mock_context: UserContext
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
        engine.generate_matrix(mock_context, agent_config, assay_report)


def test_many_to_many_mixed_results(engine: TraceabilityEngine, mock_context: UserContext) -> None:
    """
    Test scenario where:
    - Req A maps to T1, T2
    - Req B maps to T2, T3
    - T2 Fails
    Expected: Both Req A and B fail. Overall status COVERED_FAILED.
    """
    reqs = [
        Requirement(req_id="A", desc="Req A"),
        Requirement(req_id="B", desc="Req B"),
    ]
    cov_map = {
        "A": ["T1", "T2"],
        "B": ["T2", "T3"],
    }
    config = AgentConfig(requirements=reqs, coverage_map=cov_map)

    report = AssayReport(
        results=[
            ComplianceTest(test_id="T1", result="PASS"),
            ComplianceTest(test_id="T2", result="FAIL"),
            ComplianceTest(test_id="T3", result="PASS"),
        ]
    )

    rtm = engine.generate_matrix(mock_context, config, report)

    assert rtm.overall_status == RequirementStatus.COVERED_FAILED

    # Check that TraceabilityMatrix correctly contains 3 unique tests
    assert len(rtm.tests) == 3

    # We can't easily check individual req status from RTM as it doesn't store computed req status,
    # but the overall status confirms logic.


def test_status_precedence_uncovered_vs_failed(engine: TraceabilityEngine, mock_context: UserContext) -> None:
    """
    Test that UNCOVERED takes precedence over COVERED_FAILED.
    Req A: Uncovered.
    Req B: Failed (Covered).
    Overall: UNCOVERED.
    """
    reqs = [
        Requirement(req_id="A", desc="Uncovered Req"),
        Requirement(req_id="B", desc="Failed Req"),
    ]
    cov_map = {
        "A": [],  # Uncovered
        "B": ["T1"],
    }
    config = AgentConfig(requirements=reqs, coverage_map=cov_map)

    report = AssayReport(
        results=[
            ComplianceTest(test_id="T1", result="FAIL"),
        ]
    )

    rtm = engine.generate_matrix(mock_context, config, report)

    assert rtm.overall_status == RequirementStatus.UNCOVERED


def test_extra_unmapped_tests_ignored(
    engine: TraceabilityEngine, basic_requirements: List[Requirement], mock_context: UserContext
) -> None:
    """
    Test that tests present in the report but not in the coverage map are ignored
    and do not pollute the resulting matrix tests list.
    """
    cov_map = {"1.0": ["T-101"]}  # Only T-101 is needed
    config = AgentConfig(requirements=[basic_requirements[0]], coverage_map=cov_map)

    report = AssayReport(
        results=[
            ComplianceTest(test_id="T-101", result="PASS"),
            ComplianceTest(test_id="T-999", result="FAIL"),  # Extra test
        ]
    )

    rtm = engine.generate_matrix(mock_context, config, report)

    assert rtm.overall_status == RequirementStatus.COVERED_PASSED
    assert len(rtm.tests) == 1
    assert rtm.tests[0].test_id == "T-101"
    # T-999 should NOT be in the RTM because it's irrelevant to the requirements


def test_empty_configuration(engine: TraceabilityEngine, mock_context: UserContext) -> None:
    """
    Test trivial success with empty requirements and tests.
    """
    config = AgentConfig(requirements=[], coverage_map={})
    report = AssayReport(results=[])

    rtm = engine.generate_matrix(mock_context, config, report)

    assert rtm.overall_status == RequirementStatus.COVERED_PASSED
    assert len(rtm.tests) == 0
    assert len(rtm.requirements) == 0
