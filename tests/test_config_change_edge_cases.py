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
from typing import Any
from uuid import uuid4

import pytest

# We need pypdf for PDF verification
try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

from coreason_auditor.mocks import MockSessionSource
from coreason_auditor.models import (
    AIBOMObject,
    AuditPackage,
    ConfigChange,
    RequirementStatus,
    TraceabilityMatrix,
)
from coreason_auditor.pdf_generator import PDFReportGenerator
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


@pytest.mark.skipif(PdfReader is None, reason="pypdf not installed")
class TestConfigChangePDFEdgeCases:
    """
    Tests specific to PDF rendering of the configuration log.
    Uses pytest style class.
    """

    @pytest.fixture  # type: ignore[misc]
    def base_package(self) -> AuditPackage:
        bom = AIBOMObject(
            model_identity="test",
            data_lineage=[],
            software_dependencies=[],
            cyclonedx_bom={},
        )
        rtm = TraceabilityMatrix(
            requirements=[],
            tests=[],
            coverage_map={},
            overall_status=RequirementStatus.COVERED_PASSED,
        )
        return AuditPackage(
            id=uuid4(),
            agent_version="1.0.0",
            generated_at=datetime.now(timezone.utc),
            generated_by="test-user",
            bom=bom,
            rtm=rtm,
            deviation_report=[],
            config_changes=[],
            human_interventions=0,
            document_hash="",
            electronic_signature="",
        )

    def test_pagination_stress(self, tmp_path: Any, base_package: AuditPackage) -> None:
        """
        Complex Scenario: Generate a report with 80+ config changes.
        Verifies that the table spans multiple pages and doesn't crash.
        """
        changes = []
        # 80 items should cover about 2 pages
        count = 80
        for i in range(count):
            changes.append(
                ConfigChange(
                    change_id=f"stress-{i}",
                    timestamp=datetime.now(timezone.utc),
                    user_id=f"user-{i}",
                    field_changed=f"field-{i}",
                    old_value=f"old-{i}",
                    new_value=f"new-{i}",
                    reason=f"Reason {i}",
                    status="Approved",
                )
            )
        base_package.config_changes = changes

        output = tmp_path / "stress.pdf"
        PDFReportGenerator().generate_report(base_package, str(output))

        reader = PdfReader(str(output))
        # 80 rows + content should be > 1 page
        assert len(reader.pages) > 1

        full_text = "".join(p.extract_text() for p in reader.pages)

        # Verify Section Header
        assert "5. Configuration Change Log" in full_text
        # Verify first item
        assert "user-0" in full_text
        # Verify last item
        assert f"user-{count-1}" in full_text

    def test_content_safety_injection(self, tmp_path: Any, base_package: AuditPackage) -> None:
        """
        Edge Case: Inject HTML-like strings.
        Verifies correct escaping.
        """
        malicious_change = ConfigChange(
            change_id="xss-1",
            timestamp=datetime.now(timezone.utc),
            user_id="<script>alert(1)</script>",
            field_changed="<b>bold</b>",
            old_value="&",
            new_value='"',
            reason="<img src=x>",
            status="PENDING",
        )
        base_package.config_changes = [malicious_change]

        output = tmp_path / "injection.pdf"
        PDFReportGenerator().generate_report(base_package, str(output))

        reader = PdfReader(str(output))
        text = "".join(p.extract_text() for p in reader.pages)

        # Should render the tags as text, not execute/format them.
        # ReportLab+html.escape usually renders '<' as '&lt;' internally,
        # but pypdf extracts visible text.
        # If it was interpreted as HTML '<b>bold</b>', pypdf might just see 'bold'.
        # If escaped, it sees '<b>bold</b>' or '&lt;b&gt;bold&lt;/b&gt;'.
        # We check for the presence of the brackets to confirm they weren't consumed by the parser.
        assert "<script>" in text or "&lt;script&gt;" in text
        assert "<b>" in text or "&lt;b&gt;" in text

    def test_layout_long_text(self, tmp_path: Any, base_package: AuditPackage) -> None:
        """
        Edge Case: Long text in cells.
        Verifies wrapping/robustness.
        """
        long_reason = "Reason " * 50  # Lots of words
        long_value = "A" * 100  # Unbreakable string

        change = ConfigChange(
            change_id="long-1",
            timestamp=datetime.now(timezone.utc),
            user_id="u",
            field_changed="f",
            old_value=long_value,
            new_value="short",
            reason=long_reason,
            status="S",
        )
        base_package.config_changes = [change]

        output = tmp_path / "layout.pdf"
        PDFReportGenerator().generate_report(base_package, str(output))

        reader = PdfReader(str(output))
        text = "".join(p.extract_text() for p in reader.pages)

        assert "Reason Reason" in text
        # Unbreakable string might be truncated or overflow, just ensure no crash
        assert "AAAAA" in text

    def test_unicode_support(self, tmp_path: Any, base_package: AuditPackage) -> None:
        """
        Edge Case: Unicode in config fields.
        """
        change = ConfigChange(
            change_id="uni-1",
            timestamp=datetime.now(timezone.utc),
            user_id="User \u2603",  # Snowman
            field_changed="Field \u00a9",  # Copyright
            old_value="Old",
            new_value="New",
            reason="Reason \U0001f600",  # Grin
            status="Status",
        )
        base_package.config_changes = [change]

        output = tmp_path / "unicode.pdf"
        PDFReportGenerator().generate_report(base_package, str(output))

        # Just verify it generated. Text extraction of emoji depends on PDF font.
        assert output.exists()
