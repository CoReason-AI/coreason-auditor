import unittest
from datetime import datetime
from unittest.mock import MagicMock

from coreason_auditor.aibom_generator import AIBOMGenerator
from coreason_auditor.exceptions import ComplianceViolationError
from coreason_auditor.models import (
    AgentConfig,
    AIBOMObject,
    AssayReport,
    AuditPackage,
    BOMInput,
    ComplianceTest,
    Requirement,
    RequirementStatus,
    RiskLevel,
    Session,
    TraceabilityMatrix,
)
from coreason_auditor.orchestrator import AuditOrchestrator
from coreason_auditor.pdf_generator import PDFReportGenerator
from coreason_auditor.session_replayer import SessionReplayer
from coreason_auditor.signer import AuditSigner
from coreason_auditor.traceability_engine import TraceabilityEngine


class TestAuditOrchestrator(unittest.TestCase):
    def setUp(self) -> None:
        # Mock dependencies
        self.mock_bom_gen = MagicMock(spec=AIBOMGenerator)
        self.mock_rtm_engine = MagicMock(spec=TraceabilityEngine)
        self.mock_replayer = MagicMock(spec=SessionReplayer)
        self.mock_signer = MagicMock(spec=AuditSigner)
        self.mock_pdf_gen = MagicMock(spec=PDFReportGenerator)

        self.orchestrator = AuditOrchestrator(
            self.mock_bom_gen,
            self.mock_rtm_engine,
            self.mock_replayer,
            self.mock_signer,
            self.mock_pdf_gen,
        )

        # Common Test Data
        self.user_id = "test-user"
        self.agent_version = "1.0.0"
        self.agent_config = AgentConfig(
            requirements=[Requirement(req_id="1.1", desc="Test Req")],
            coverage_map={"1.1": ["T-1"]},
        )
        self.assay_report = AssayReport(results=[ComplianceTest(test_id="T-1", result="PASS")])
        self.bom_input = BOMInput(
            model_name="test",
            model_version="1",
            model_sha="sha",
            data_lineage=[],
            software_dependencies=[],
        )

        # Setup Mock Returns
        self.mock_bom = AIBOMObject(model_identity="test", data_lineage=[], software_dependencies=[], cyclonedx_bom={})
        self.mock_bom_gen.generate_bom.return_value = self.mock_bom

        self.mock_rtm = TraceabilityMatrix(
            requirements=self.agent_config.requirements,
            tests=self.assay_report.results,
            coverage_map=self.agent_config.coverage_map,
            overall_status=RequirementStatus.COVERED_PASSED,
        )
        self.mock_rtm_engine.generate_matrix.return_value = self.mock_rtm

        self.mock_deviations = [
            Session(
                session_id="s1",
                timestamp=datetime.now(),
                risk_level=RiskLevel.HIGH,
                violation_summary="Fail",
                events=[],
            )
        ]
        self.mock_replayer.get_deviation_report.return_value = self.mock_deviations

        # Signer should return the object (modified)
        self.mock_signer.sign_package.side_effect = lambda pkg, uid: pkg

    def test_generate_audit_package(self) -> None:
        """Test the full flow of generating a package."""
        package = self.orchestrator.generate_audit_package(
            self.agent_config,
            self.assay_report,
            self.bom_input,
            self.user_id,
            self.agent_version,
        )

        # Verify calls
        self.mock_bom_gen.generate_bom.assert_called_once_with(self.bom_input)
        self.mock_rtm_engine.generate_matrix.assert_called_once_with(self.agent_config, self.assay_report)
        self.mock_replayer.get_deviation_report.assert_called_once()
        self.mock_signer.sign_package.assert_called_once()

        # Verify package content
        self.assertIsInstance(package, AuditPackage)
        self.assertEqual(package.agent_version, self.agent_version)
        self.assertEqual(package.generated_by, self.user_id)
        self.assertEqual(package.bom, self.mock_bom)
        self.assertEqual(package.rtm, self.mock_rtm)
        self.assertEqual(package.deviation_report, self.mock_deviations)

    def test_export_to_pdf(self) -> None:
        """Test PDF export delegation."""
        pkg = MagicMock(spec=AuditPackage)
        path = "out.pdf"
        self.orchestrator.export_to_pdf(pkg, path)
        self.mock_pdf_gen.generate_report.assert_called_once_with(pkg, path)

    def test_critical_uncovered_failure(self) -> None:
        """Test that uncovered critical requirements raise an exception."""
        # Setup: Critical Req with NO coverage
        crit_req = Requirement(req_id="CRIT-1", desc="Important", critical=True)
        config = AgentConfig(requirements=[crit_req], coverage_map={})

        # Mock RTM return
        mock_rtm = TraceabilityMatrix(
            requirements=[crit_req], tests=[], coverage_map={}, overall_status=RequirementStatus.UNCOVERED
        )
        self.mock_rtm_engine.generate_matrix.return_value = mock_rtm

        with self.assertRaises(ComplianceViolationError):
            self.orchestrator.generate_audit_package(
                config,
                self.assay_report,
                self.bom_input,
                self.user_id,
                self.agent_version,
            )

    def test_non_critical_uncovered_success(self) -> None:
        """Test that uncovered non-critical requirements do NOT raise exception."""
        # Setup: Non-Critical Req with NO coverage
        non_crit = Requirement(req_id="OPT-1", desc="Optional", critical=False)
        config = AgentConfig(requirements=[non_crit], coverage_map={})

        mock_rtm = TraceabilityMatrix(
            requirements=[non_crit], tests=[], coverage_map={}, overall_status=RequirementStatus.UNCOVERED
        )
        self.mock_rtm_engine.generate_matrix.return_value = mock_rtm

        # Should NOT raise
        pkg = self.orchestrator.generate_audit_package(
            config,
            self.assay_report,
            self.bom_input,
            self.user_id,
            self.agent_version,
        )
        self.assertIsInstance(pkg, AuditPackage)

    def test_critical_req_with_empty_list_coverage(self) -> None:
        """Test that a critical requirement with an empty list [] in coverage map fails."""
        crit_req = Requirement(req_id="CRIT-2", desc="Empty List Coverage", critical=True)
        # Explicitly map to empty list
        config = AgentConfig(requirements=[crit_req], coverage_map={"CRIT-2": []})

        mock_rtm = TraceabilityMatrix(
            requirements=[crit_req], tests=[], coverage_map={"CRIT-2": []}, overall_status=RequirementStatus.UNCOVERED
        )
        self.mock_rtm_engine.generate_matrix.return_value = mock_rtm

        with self.assertRaises(ComplianceViolationError):
            self.orchestrator.generate_audit_package(
                config,
                self.assay_report,
                self.bom_input,
                self.user_id,
                self.agent_version,
            )

    def test_mixed_criticality_failure(self) -> None:
        """
        Test a complex scenario with:
        1. Critical Covered (OK)
        2. Non-Critical Uncovered (OK)
        3. Critical Uncovered (FAIL - Trigger)
        """
        reqs = [
            Requirement(req_id="C-COV", desc="Critical Covered", critical=True),
            Requirement(req_id="NC-UNCOV", desc="Non-Critical Uncovered", critical=False),
            Requirement(req_id="C-UNCOV", desc="Critical Uncovered", critical=True),
        ]

        cov_map = {"C-COV": ["T-1"], "NC-UNCOV": [], "C-UNCOV": []}

        config = AgentConfig(requirements=reqs, coverage_map=cov_map)

        # Test T-1 exists
        tests = [ComplianceTest(test_id="T-1", result="PASS")]

        mock_rtm = TraceabilityMatrix(
            requirements=reqs,
            tests=tests,
            coverage_map=cov_map,
            overall_status=RequirementStatus.UNCOVERED,  # or COVERED_FAILED/MIXED
        )
        self.mock_rtm_engine.generate_matrix.return_value = mock_rtm

        # Must raise because C-UNCOV is critical and has no tests
        with self.assertRaises(ComplianceViolationError):
            self.orchestrator.generate_audit_package(
                config,
                AssayReport(results=tests),
                self.bom_input,
                self.user_id,
                self.agent_version,
            )

    def test_critical_covered_but_test_failed_success(self) -> None:
        """
        Test that if a critical requirement IS covered, but the test FAILS,
        we do NOT abort generation. We want to report the failure, not crash.
        """
        crit_req = Requirement(req_id="CRIT-FAIL", desc="Critical Failed", critical=True)
        cov_map = {"CRIT-FAIL": ["T-FAIL"]}
        config = AgentConfig(requirements=[crit_req], coverage_map=cov_map)

        # Test exists but result is FAIL
        tests = [ComplianceTest(test_id="T-FAIL", result="FAIL")]

        mock_rtm = TraceabilityMatrix(
            requirements=[crit_req], tests=tests, coverage_map=cov_map, overall_status=RequirementStatus.COVERED_FAILED
        )
        self.mock_rtm_engine.generate_matrix.return_value = mock_rtm

        # Should NOT raise exception. The failure is recorded in the report, generation proceeds.
        pkg = self.orchestrator.generate_audit_package(
            config,
            AssayReport(results=tests),
            self.bom_input,
            self.user_id,
            self.agent_version,
        )
        self.assertIsInstance(pkg, AuditPackage)
        self.assertEqual(pkg.rtm.overall_status, RequirementStatus.COVERED_FAILED)
