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

from coreason_auditor.mocks import MockSessionSource
from coreason_auditor.models import EventType, RiskLevel
from coreason_auditor.utils.seeder import populate_demo_data


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
