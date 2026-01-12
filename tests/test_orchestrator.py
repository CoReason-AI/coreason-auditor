import unittest
from datetime import datetime
from unittest.mock import MagicMock

from coreason_auditor.aibom_generator import AIBOMGenerator
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
