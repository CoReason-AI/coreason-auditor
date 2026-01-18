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
from datetime import datetime, timedelta, timezone

from coreason_auditor.mocks import MockSessionSource
from coreason_auditor.models import ConfigChange
from pydantic import ValidationError


class TestConfigChangeEdgeCases(unittest.TestCase):
    def test_sorting_stability(self) -> None:
        """
        Complex Scenario: Verify that get_config_changes correctly sorts
        mixed-order insertions by timestamp descending.
        """
        source = MockSessionSource()
        base_time = datetime.now(timezone.utc)

        # Create changes with distinct timestamps
        c1 = self._create_change("c1", base_time)
        c2 = self._create_change("c2", base_time + timedelta(hours=1))  # Newest
        c3 = self._create_change("c3", base_time - timedelta(hours=1))  # Oldest

        # Add in random order
        source.add_config_change(c1)
        source.add_config_change(c2)
        source.add_config_change(c3)

        # Retrieve all
        changes = source.get_config_changes(limit=10)

        self.assertEqual(len(changes), 3)
        self.assertEqual(changes[0].change_id, "c2")  # Newest first
        self.assertEqual(changes[1].change_id, "c1")
        self.assertEqual(changes[2].change_id, "c3")  # Oldest last

    def test_limit_behavior(self) -> None:
        """
        Edge Case: Verify behavior of limit parameter.
        1. Limit = 0 (Should return empty)
        2. Limit > len (Should return all)
        """
        source = MockSessionSource()
        for i in range(5):
            source.add_config_change(self._create_change(f"c{i}", datetime.now(timezone.utc)))

        # Case 1: Limit 0
        self.assertEqual(len(source.get_config_changes(limit=0)), 0)

        # Case 2: Limit > len
        self.assertEqual(len(source.get_config_changes(limit=100)), 5)

        # Case 3: Exact limit
        self.assertEqual(len(source.get_config_changes(limit=5)), 5)

        # Case 4: Partial limit
        self.assertEqual(len(source.get_config_changes(limit=2)), 2)

    def test_model_validation_edge_cases(self) -> None:
        """
        Edge Case: Verify Pydantic validation for missing or invalid fields.
        """
        # Missing required field
        with self.assertRaises(ValidationError):
            ConfigChange(  # type: ignore[call-arg]
                change_id="c1",
                # timestamp missing
                user_id="u1",
                field_changed="f1",
                old_value="o1",
                new_value="n1",
                reason="r1",
                status="s1",
            )

        # Invalid timestamp type
        with self.assertRaises(ValidationError):
            ConfigChange(
                change_id="c1",
                timestamp="not-a-timestamp",
                user_id="u1",
                field_changed="f1",
                old_value="o1",
                new_value="n1",
                reason="r1",
                status="s1",
            )

    def _create_change(self, cid: str, ts: datetime) -> ConfigChange:
        return ConfigChange(
            change_id=cid,
            timestamp=ts,
            user_id="user",
            field_changed="field",
            old_value="old",
            new_value="new",
            reason="reason",
            status="status",
        )
