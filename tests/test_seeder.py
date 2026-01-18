# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_auditor

import unittest
from unittest.mock import MagicMock

from coreason_auditor.interfaces import SessionSource
from coreason_auditor.mocks import MockAegisService, MockSessionSource
from coreason_auditor.models import (
    AgentConfig,
    AIBOMObject,
    AssayReport,
    BOMInput,
    EventType,
    RequirementStatus,
    RiskLevel,
    Session,
    TraceabilityMatrix,
)
from coreason_auditor.orchestrator import AuditOrchestrator
from coreason_auditor.session_replayer import SessionReplayer
from coreason_auditor.utils.seeder import populate_demo_data


class DummySessionSource(SessionSource):
    """
    A dummy implementation of SessionSource that is NOT a MockSessionSource.
    Used to test edge cases where the seeder encounters a real/different source.
    """

    def get_session(self, session_id: str) -> Session | None:
        return None

    def get_sessions_by_risk(self, risk_level: RiskLevel, limit: int = 10) -> list[Session]:
        return []

    def get_intervention_count(self, agent_version: str) -> int:
        return 0


class TestSeeder(unittest.TestCase):
    def test_populate_demo_data(self) -> None:
        """
        Test that populate_demo_data correctly seeds the session source
        with the high-risk session required by User Story B.
        """
        source = MockSessionSource()
        populate_demo_data(source)

        # 1. Verify a session was added
        sessions = source.get_sessions_by_risk(RiskLevel.HIGH, limit=10)
        self.assertEqual(len(sessions), 1)

        session = sessions[0]
        self.assertEqual(session.session_id, "session-story-b-001")
        self.assertEqual(session.risk_level, RiskLevel.HIGH)
        self.assertEqual(session.violation_type, "Data Misinterpretation")

        # 2. Verify specific content ("Thought Trace")
        thought_events = [e for e in session.events if e.event_type == EventType.THOUGHT]
        self.assertTrue(len(thought_events) > 0)

        expected_thought_snippet = "The user is asking for X, but the table says Y... I will ignore the table"
        self.assertIn(expected_thought_snippet, thought_events[0].content)

        # 3. Verify other event types
        input_events = [e for e in session.events if e.event_type == EventType.INPUT]
        output_events = [e for e in session.events if e.event_type == EventType.OUTPUT]
        tool_events = [e for e in session.events if e.event_type == EventType.TOOL]

        self.assertEqual(len(input_events), 1)
        self.assertEqual(len(output_events), 1)
        self.assertEqual(len(tool_events), 1)

    def test_populate_demo_data_idempotency(self) -> None:
        """
        Edge Case: Calling populate_demo_data multiple times should not result in duplicate sessions.
        """
        source = MockSessionSource()

        # Call 1
        populate_demo_data(source)
        count_1 = len(source.get_sessions_by_risk(RiskLevel.HIGH))
        self.assertEqual(count_1, 1)

        # Call 2
        populate_demo_data(source)
        count_2 = len(source.get_sessions_by_risk(RiskLevel.HIGH))

        # Since MockSessionSource uses a dict keyed by session_id, it should overwrite.
        self.assertEqual(count_2, 1)

    def test_populate_non_mock_source(self) -> None:
        """
        Edge Case: Verify that passing a non-MockSessionSource does not raise an exception.
        This hits the 'else' block in the seeder.
        """
        dummy_source = DummySessionSource()
        # Should not raise exception
        try:
            populate_demo_data(dummy_source)
        except Exception as e:
            self.fail(f"populate_demo_data raised exception with non-mock source: {e}")

    def test_seeder_integration_with_orchestrator(self) -> None:
        """
        Complex Scenario: Verify that the seeded data correctly flows through the AuditOrchestrator
        and appears in the final AuditPackage.
        """
        # 1. Setup Dependencies
        session_source = MockSessionSource()
        populate_demo_data(session_source)  # SEED DATA

        replayer = SessionReplayer(session_source, MockAegisService())

        # Mocks for other components not relevant to this test
        mock_aibom = MagicMock()
        # Return a valid Pydantic object
        mock_aibom.generate_bom.return_value = AIBOMObject(
            model_identity="test-model", data_lineage=[], software_dependencies=[], cyclonedx_bom={}
        )

        mock_trace = MagicMock()
        # Return a valid Pydantic object
        mock_trace.generate_matrix.return_value = TraceabilityMatrix(
            requirements=[], tests=[], coverage_map={}, overall_status=RequirementStatus.COVERED_PASSED
        )

        mock_signer = MagicMock()
        mock_signer.sign_package.side_effect = lambda p, u: p  # Return package as is

        mock_pdf = MagicMock()

        orchestrator = AuditOrchestrator(
            aibom_generator=mock_aibom,
            traceability_engine=mock_trace,
            session_replayer=replayer,
            signer=mock_signer,
            pdf_generator=mock_pdf,
        )

        # 2. Execute
        # We need valid dummy inputs for the method signature
        package = orchestrator.generate_audit_package(
            agent_config=AgentConfig(requirements=[], coverage_map={}),
            assay_report=AssayReport(results=[]),
            bom_input=BOMInput(
                model_name="test", model_version="1", model_sha="sha256:1", data_lineage=[], software_dependencies=[]
            ),
            user_id="test-user",
            agent_version="1.0",
            risk_threshold=RiskLevel.HIGH,  # MUST be HIGH to pick up the seeded session
            max_deviations=10,
        )

        # 3. Verify
        # The deviation report in the package should contain our seeded session
        self.assertEqual(len(package.deviation_report), 1)
        self.assertEqual(package.deviation_report[0].session_id, "session-story-b-001")
        self.assertEqual(package.deviation_report[0].violation_type, "Data Misinterpretation")
