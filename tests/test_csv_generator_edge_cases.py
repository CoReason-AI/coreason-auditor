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


def test_csv_unicode_handling(tmp_path: Path) -> None:
    """
    Test that the CSV generator handles Unicode characters (emojis, accents) correctly.
    """
    generator = CSVGenerator()
    output_path = tmp_path / "unicode.csv"

    changes = [
        ConfigChange(
            change_id="u1",
            timestamp=datetime.now(timezone.utc),
            user_id="François",
            field_changed="profile_pic",
            old_value="😐",
            new_value="🚀",
            reason="User requested more excitement: 🎆",
            status="Approved ✅",
        )
    ]

    generator.generate_config_change_log(changes, str(output_path))

    with open(output_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Verify content strictly
    assert "François" in content
    assert "😐" in content
    assert "🚀" in content
    assert "🎆" in content
    assert "Approved ✅" in content


def test_csv_multiline_fields(tmp_path: Path) -> None:
    """
    Test that fields with newlines are correctly quoted and preserved.
    """
    generator = CSVGenerator()
    output_path = tmp_path / "multiline.csv"

    multiline_reason = "Line 1\nLine 2\nLine 3"
    changes = [
        ConfigChange(
            change_id="m1",
            timestamp=datetime.now(timezone.utc),
            user_id="admin",
            field_changed="prompt",
            old_value="A",
            new_value="B",
            reason=multiline_reason,
            status="Pending",
        )
    ]

    generator.generate_config_change_log(changes, str(output_path))

    with open(output_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        rows = list(reader)

    # Row 0 is header, Row 1 is data
    assert rows[1][6] == multiline_reason


def test_csv_injection_chars(tmp_path: Path) -> None:
    """
    Test that fields starting with potentially dangerous characters (=, @, +, -)
    are written as-is (we rely on the CSV reader to handle safety, but we verify data integrity).
    """
    generator = CSVGenerator()
    output_path = tmp_path / "injection.csv"

    changes = [
        ConfigChange(
            change_id="i1",
            timestamp=datetime.now(timezone.utc),
            user_id="hacker",
            field_changed="formula",
            old_value="=1+1",
            new_value="@SUM(1,1)",
            reason="-DANGEROUS",
            status="+APPROVED",
        )
    ]

    generator.generate_config_change_log(changes, str(output_path))

    with open(output_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        rows = list(reader)

    assert rows[1][4] == "=1+1"
    assert rows[1][5] == "@SUM(1,1)"
    assert rows[1][6] == "-DANGEROUS"
    assert rows[1][7] == "+APPROVED"


def test_csv_large_dataset(tmp_path: Path) -> None:
    """
    Performance/Stability test for a large number of rows.
    """
    generator = CSVGenerator()
    output_path = tmp_path / "large.csv"

    count = 10000
    base_time = datetime(2025, 1, 1, tzinfo=timezone.utc)

    # Generate 10k items
    changes = [
        ConfigChange(
            change_id=str(i),
            timestamp=base_time,
            user_id=f"user_{i}",
            field_changed="setting",
            old_value="0",
            new_value="1",
            reason=f"Batch update {i}",
            status="Auto",
        )
        for i in range(count)
    ]

    generator.generate_config_change_log(changes, str(output_path))

    # Verify line count (Header + 10k rows + maybe trailing newline logic depending on implementation)
    # Counting lines via reading file
    with open(output_path, "r", encoding="utf-8") as f:
        row_count = sum(1 for _ in f)

    # 1 Header + 10000 Data
    assert row_count == count + 1
