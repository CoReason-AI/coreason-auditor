# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_auditor

import csv
from datetime import datetime, timezone
from pathlib import Path

from coreason_auditor.csv_generator import CSVGenerator
from coreason_auditor.models import ConfigChange


def test_generate_config_change_log(tmp_path: Path) -> None:
    generator = CSVGenerator()
    output_path = tmp_path / "test_changes.csv"

    changes = [
        ConfigChange(
            change_id="1",
            timestamp=datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            user_id="user1",
            field_changed="setting_a",
            old_value="off",
            new_value="on",
            reason="testing",
            status="approved",
        ),
        ConfigChange(
            change_id="2",
            timestamp=datetime(2025, 1, 2, 12, 0, 0, tzinfo=timezone.utc),
            user_id="user2",
            field_changed="setting_b",
            old_value="10",
            new_value="20",
            reason="update, with comma",
            status="approved",
        ),
    ]

    generator.generate_config_change_log(changes, str(output_path))

    assert output_path.exists()

    with open(output_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        rows = list(reader)

    # Check Headers
    assert rows[0] == [
        "Change ID",
        "Timestamp",
        "User ID",
        "Field Changed",
        "Old Value",
        "New Value",
        "Reason",
        "Status",
    ]

    # Check Data Row 1
    assert rows[1] == [
        "1",
        "2025-01-01 12:00:00 UTC",
        "user1",
        "setting_a",
        "off",
        "on",
        "testing",
        "approved",
    ]

    # Check Data Row 2 (with comma in reason)
    assert rows[2] == [
        "2",
        "2025-01-02 12:00:00 UTC",
        "user2",
        "setting_b",
        "10",
        "20",
        "update, with comma",
        "approved",
    ]


def test_generate_empty_log(tmp_path: Path) -> None:
    generator = CSVGenerator()
    output_path = tmp_path / "empty.csv"
    generator.generate_config_change_log([], str(output_path))

    assert output_path.exists()
    with open(output_path, "r", encoding="utf-8") as f:
        rows = list(csv.reader(f))

    assert len(rows) == 1
    assert rows[0][0] == "Change ID"
