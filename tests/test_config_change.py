# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_auditor

from datetime import datetime, timezone

from coreason_auditor.mocks import MockSessionSource
from coreason_auditor.models import ConfigChange
from coreason_auditor.utils.seeder import populate_demo_data


def test_config_change_model() -> None:
    """Test that the ConfigChange model instantiates correctly."""
    change = ConfigChange(
        change_id="c-123",
        timestamp=datetime.now(timezone.utc),
        user_id="user1",
        field_changed="prompt",
        old_value="A",
        new_value="B",
        reason="Update",
        status="Approved",
    )
    assert change.change_id == "c-123"
    assert change.field_changed == "prompt"


def test_mock_session_source_config_changes() -> None:
    """Test storage and retrieval of config changes in MockSessionSource."""
    source = MockSessionSource()
    assert len(source.get_config_changes()) == 0

    change1 = ConfigChange(
        change_id="c-1",
        timestamp=datetime(2025, 1, 10, 10, 0, 0, tzinfo=timezone.utc),
        user_id="u1",
        field_changed="f1",
        old_value="o1",
        new_value="n1",
        reason="r1",
        status="s1",
    )
    change2 = ConfigChange(
        change_id="c-2",
        timestamp=datetime(2025, 1, 11, 10, 0, 0, tzinfo=timezone.utc),
        user_id="u2",
        field_changed="f2",
        old_value="o2",
        new_value="n2",
        reason="r2",
        status="s2",
    )

    source.add_config_change(change1)
    source.add_config_change(change2)

    # Test retrieval (should be sorted by timestamp desc)
    changes = source.get_config_changes()
    assert len(changes) == 2
    assert changes[0].change_id == "c-2"  # Newer first
    assert changes[1].change_id == "c-1"

    # Test limit
    changes_limited = source.get_config_changes(limit=1)
    assert len(changes_limited) == 1
    assert changes_limited[0].change_id == "c-2"


def test_seeder_populates_config_changes() -> None:
    """Test that populate_demo_data adds config changes."""
    source = MockSessionSource()
    populate_demo_data(source)

    changes = source.get_config_changes()
    assert len(changes) >= 2

    # Check for specific story data
    found_system_prompt = False
    for c in changes:
        if c.field_changed == "system_prompt" and c.user_id == "j.doe":
            found_system_prompt = True
            assert c.old_value == "Ver A"
            assert c.new_value == "Ver B"

    assert found_system_prompt
