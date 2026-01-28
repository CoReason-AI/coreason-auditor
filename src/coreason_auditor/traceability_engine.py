# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_auditor

from typing import Dict, List, Set

from coreason_identity.models import UserContext

from coreason_auditor.models import (
    AgentConfig,
    AssayReport,
    ComplianceTest,
    RequirementStatus,
    TraceabilityMatrix,
)
from coreason_auditor.utils.logger import logger


class TraceabilityEngine:
    """Core engine for mapping requirements to test results and generating the Traceability Matrix."""

    def generate_matrix(
        self, context: UserContext, agent_config: AgentConfig, assay_report: AssayReport
    ) -> TraceabilityMatrix:
        """Generates a TraceabilityMatrix from the given AgentConfig and AssayReport.

        Args:
            context: The user context requesting the matrix.
            agent_config: The configuration containing requirements and the coverage map.
            assay_report: The report containing test results.

        Returns:
            A populated TraceabilityMatrix.

        Raises:
            ValueError: If integrity checks fail (handled by Pydantic model validation).
        """
        if context is None:
            raise ValueError("UserContext is required")

        logger.info("Generating Traceability Matrix", user_id=context.user_id.get_secret_value())

        # 1. Gather all unique Test IDs from the Coverage Map to know which tests are relevant
        required_test_ids: Set[str] = set()
        for test_list in agent_config.coverage_map.values():
            required_test_ids.update(test_list)

        # 2. Filter/Select tests from AssayReport that are relevant to the Coverage Map
        available_tests: Dict[str, ComplianceTest] = {t.test_id: t for t in assay_report.results}

        final_tests: List[ComplianceTest] = []

        for test_id in required_test_ids:
            if test_id in available_tests:
                final_tests.append(available_tests[test_id])
            else:
                # If a test is missing, we must fail the requirement.
                # However, the TraceabilityMatrix structure demands the test exist in the list
                # if it's in the coverage_map (due to the validator).
                logger.warning(f"Test '{test_id}' defined in coverage map but missing from assay report.")
                final_tests.append(
                    ComplianceTest(test_id=test_id, result="FAIL", evidence="Test result missing from assay report.")
                )

        # Map for O(1) lookup during status calculation
        final_tests_map: Dict[str, ComplianceTest] = {t.test_id: t for t in final_tests}

        # 3. Determine Overall Status
        overall_status = RequirementStatus.COVERED_PASSED

        # Check coverage for each requirement
        for req in agent_config.requirements:
            req_id = req.req_id
            linked_test_ids = agent_config.coverage_map.get(req_id, [])

            if not linked_test_ids:
                # Requirement has 0 covering tests -> Uncovered
                logger.error(f"Requirement '{req_id}' is uncovered (no tests mapped).")
                overall_status = RequirementStatus.UNCOVERED
                continue

            # Check if all linked tests passed
            req_passed = True
            for test_id in linked_test_ids:
                # Find the test result using the optimized map
                test_result = final_tests_map.get(test_id)

                if not test_result:  # pragma: no cover
                    # This should not happen due to step 2 logic, unless logic is flawed
                    logger.error(f"Test '{test_id}' not found in final tests despite being processed.")
                    req_passed = False
                    break

                if test_result.result != "PASS":
                    req_passed = False
                    break

            if not req_passed:
                if overall_status != RequirementStatus.UNCOVERED:
                    overall_status = RequirementStatus.COVERED_FAILED

        logger.info(f"Traceability Matrix generation complete. Status: {overall_status}")

        # The TraceabilityMatrix constructor will validate integrity (req_ids vs coverage_map keys)
        return TraceabilityMatrix(
            requirements=agent_config.requirements,
            tests=final_tests,
            coverage_map=agent_config.coverage_map,
            overall_status=overall_status,
        )
