# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_auditor

import os
import unittest
from datetime import datetime, timezone
from uuid import uuid4

from coreason_identity.models import UserContext
from coreason_identity.types import SecretStr

from coreason_auditor.mocks import MockIdentityService
from coreason_auditor.models import (
    AgentConfig,
    AIBOMObject,
    AssayReport,
    AuditPackage,
    ComplianceTest,
    EventType,
    Requirement,
    RequirementStatus,
    RiskLevel,
    Session,
    SessionEvent,
    TraceabilityMatrix,
)
from coreason_auditor.pdf_generator import PDFReportGenerator
from coreason_auditor.signer import AuditSigner
from coreason_auditor.traceability_engine import TraceabilityEngine


class TestEdgeCases(unittest.TestCase):
    def setUp(self) -> None:
        self.pdf_gen = PDFReportGenerator()
        self.output_file = "test_edge_case.pdf"

    def tearDown(self) -> None:
        if os.path.exists(self.output_file):
            os.remove(self.output_file)

    def test_pdf_injection_sanitization(self) -> None:
        """
        Verifies that XML-like characters in user inputs do not break PDF generation.
        """
        # Malicious content
        malicious_input = "User <b class='bad'>input</b> & logic <script>alert(1)</script>"
        malicious_desc = "Requirement with <tags> & ampersands"
        malicious_model = "Llama-3 <Super> & Version"

        bom = AIBOMObject(
            model_identity=malicious_model,
            data_lineage=["job-1"],
            software_dependencies=["pkg==1.0"],
        )

        req = Requirement(req_id="1.0", desc=malicious_desc)
        test = ComplianceTest(test_id="T-1", result="PASS")
        tm = TraceabilityMatrix(
            requirements=[req],
            tests=[test],
            coverage_map={"1.0": ["T-1"]},
            overall_status=RequirementStatus.COVERED_PASSED,
        )

        session = Session(
            session_id="sess-injection",
            timestamp=datetime.now(timezone.utc),
            risk_level=RiskLevel.HIGH,
            violation_summary="Injection <attempt>",
            violation_type="<Security>",
            events=[
                SessionEvent(
                    timestamp=datetime.now(timezone.utc),
                    event_type=EventType.INPUT,
                    content=malicious_input,
                )
            ],
        )

        pkg = AuditPackage(
            id=uuid4(),
            agent_version="1.0.0",
            generated_at=datetime.now(timezone.utc),
            generated_by="Hacker <User>",
            bom=bom,
            rtm=tm,
            deviation_report=[session],
            config_changes=[],
            human_interventions=0,
            document_hash="",
            electronic_signature="",
        )

        # Should not raise xml.parsers.expat.ExpatError
        try:
            self.pdf_gen.generate_report(pkg, self.output_file)
        except Exception as e:
            self.fail(f"PDF generation failed with malicious input: {e}")

        # Verify file exists and is non-zero
        self.assertTrue(os.path.exists(self.output_file))
        self.assertGreater(os.path.getsize(self.output_file), 0)

    def test_unicode_handling(self) -> None:
        """
        Verifies full Unicode support (Emoji, CJK) in Signing and PDF.
        """
        unicode_content = "こんにちは world 🌍"
        unicode_user = "User 👤"

        bom = AIBOMObject(
            model_identity="Model 🤖",
            data_lineage=[],
            software_dependencies=[],
        )

        pkg = AuditPackage(
            id=uuid4(),
            agent_version="1.0.0",
            generated_at=datetime.now(timezone.utc),
            generated_by=unicode_user,
            bom=bom,
            rtm=TraceabilityMatrix(
                requirements=[], tests=[], coverage_map={}, overall_status=RequirementStatus.COVERED_PASSED
            ),
            deviation_report=[
                Session(
                    session_id="sess-uni",
                    timestamp=datetime.now(timezone.utc),
                    risk_level=RiskLevel.LOW,
                    violation_summary="None",
                    events=[
                        SessionEvent(
                            timestamp=datetime.now(timezone.utc),
                            event_type=EventType.INPUT,
                            content=unicode_content,
                        )
                    ],
                )
            ],
            config_changes=[],
            human_interventions=0,
            document_hash="",
            electronic_signature="",
        )

        # 1. Test Signing Stability
        signer = AuditSigner(MockIdentityService())
        signed_pkg = signer.sign_package(pkg, unicode_user)

        # Verify hash is stable
        import json

        content_dict = pkg.model_dump(exclude={"electronic_signature", "document_hash"}, mode="json")
        # Ensure json dump doesn't crash on unicode
        json_bytes = json.dumps(content_dict, sort_keys=True).encode("utf-8")
        hash_val = signer.calculate_hash(json_bytes)
        self.assertEqual(signed_pkg.document_hash, hash_val)

        # 2. Test PDF Generation
        try:
            self.pdf_gen.generate_report(pkg, self.output_file)
        except Exception as e:
            self.fail(f"PDF generation failed with Unicode: {e}")

    def test_many_to_many_rtm_logic(self) -> None:
        """
        Verifies complex N:M mapping in Traceability Engine.
        """
        engine = TraceabilityEngine()
        context = UserContext(user_id=SecretStr("test-user"), roles=[])

        req1 = Requirement(req_id="R1", desc="Req 1")
        req2 = Requirement(req_id="R2", desc="Req 2")

        t1 = ComplianceTest(test_id="T1", result="PASS")
        t2 = ComplianceTest(test_id="T2", result="PASS")
        t3 = ComplianceTest(test_id="T3", result="FAIL")

        # R1 -> [T1, T2] (Both Pass) -> R1 Pass
        # R2 -> [T2, T3] (T3 Fail) -> R2 Fail
        coverage_map = {"R1": ["T1", "T2"], "R2": ["T2", "T3"]}

        config = AgentConfig(requirements=[req1, req2], coverage_map=coverage_map)
        # Assay report might contain extra tests or missing tests (handled in other tests)
        report = AssayReport(results=[t1, t2, t3])

        rtm = engine.generate_matrix(context, config, report)

        self.assertEqual(rtm.overall_status, RequirementStatus.COVERED_FAILED)

        # Verify R1 Status logic (Manual verification of logic inside engine)
        # The engine logic loops: if any test fails, req fails.
        # We need to inspect how we can verify individual requirement status.
        # The TraceabilityMatrix model doesn't store per-requirement status in the list,
        # only the overall status and the raw tests.
        # The PDF generator calculates "Status" column on the fly.

        # Let's verify the Coverage Map integrity in the result
        self.assertEqual(rtm.coverage_map["R1"], ["T1", "T2"])
        self.assertEqual(rtm.coverage_map["R2"], ["T2", "T3"])

        # Verify Tests are present
        test_ids = [t.test_id for t in rtm.tests]
        self.assertIn("T1", test_ids)
        self.assertIn("T3", test_ids)
