from unittest.mock import Mock

from coreason_auditor.aibom_generator import AIBOMGenerator
from coreason_auditor.mocks import MockAegisService, MockIdentityService, MockSessionSource
from coreason_auditor.models import (
    AgentConfig,
    AIBOMObject,
    AssayReport,
    BOMInput,
    RequirementStatus,
    RiskLevel,
    TraceabilityMatrix,
)
from coreason_auditor.orchestrator import AuditOrchestrator
from coreason_auditor.pdf_generator import PDFReportGenerator
from coreason_auditor.session_replayer import SessionReplayer
from coreason_auditor.signer import AuditSigner
from coreason_auditor.traceability_engine import TraceabilityEngine


def test_intervention_count_integration() -> None:
    """
    Test that the orchestrator correctly fetches and populates the intervention count.
    """
    # Setup Mocks
    session_source = MockSessionSource(intervention_count=42)

    aegis_service = MockAegisService()
    identity_service = MockIdentityService()

    session_replayer = SessionReplayer(session_source, aegis_service)

    # Other components
    aibom_generator = Mock(spec=AIBOMGenerator)
    traceability_engine = Mock(spec=TraceabilityEngine)
    pdf_generator = Mock(spec=PDFReportGenerator)
    signer = AuditSigner(identity_service)

    # Configure Mocks to return valid data to pass Pydantic validation
    mock_bom = AIBOMObject(model_identity="test-model", data_lineage=[], software_dependencies=[], cyclonedx_bom={})
    aibom_generator.generate_bom.return_value = mock_bom

    mock_rtm = TraceabilityMatrix(
        requirements=[], tests=[], coverage_map={}, overall_status=RequirementStatus.COVERED_PASSED
    )
    traceability_engine.generate_matrix.return_value = mock_rtm

    orchestrator = AuditOrchestrator(
        aibom_generator=aibom_generator,
        traceability_engine=traceability_engine,
        session_replayer=session_replayer,
        signer=signer,
        pdf_generator=pdf_generator,
    )

    # Inputs
    agent_config = Mock(spec=AgentConfig)
    assay_report = Mock(spec=AssayReport)
    bom_input = Mock(spec=BOMInput)

    # Execute
    package = orchestrator.generate_audit_package(
        agent_config=agent_config,
        assay_report=assay_report,
        bom_input=bom_input,
        user_id="test_user",
        agent_version="1.2.3",
        risk_threshold=RiskLevel.HIGH,
    )

    # Verify
    assert package.human_interventions == 42
    assert session_source.get_intervention_count("1.2.3") == 42
