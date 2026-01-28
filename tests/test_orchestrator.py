# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_auditor

from datetime import datetime
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest
from coreason_auditor.aibom_generator import AIBOMGenerator
from coreason_auditor.csv_generator import CSVGenerator
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
from coreason_auditor.orchestrator import AuditOrchestrator, AuditOrchestratorAsync
from coreason_auditor.pdf_generator import PDFReportGenerator
from coreason_auditor.session_replayer import SessionReplayer
from coreason_auditor.signer import AuditSigner
from coreason_auditor.traceability_engine import TraceabilityEngine
from coreason_identity.models import UserContext
from coreason_identity.types import SecretStr


@pytest.fixture  # type: ignore[misc]
def mock_dependencies() -> Dict[str, MagicMock]:
    return {
        "bom_gen": MagicMock(spec=AIBOMGenerator),
        "rtm_engine": MagicMock(spec=TraceabilityEngine),
        "replayer": MagicMock(spec=SessionReplayer),
        "signer": MagicMock(spec=AuditSigner),
        "pdf_gen": MagicMock(spec=PDFReportGenerator),
        "csv_gen": MagicMock(spec=CSVGenerator),
    }


@pytest.fixture  # type: ignore[misc]
def mock_context() -> UserContext:
    return UserContext(user_id=SecretStr("test-user"), roles=[])


@pytest.fixture  # type: ignore[misc]
def test_data() -> Dict[str, Any]:
    agent_config = AgentConfig(
        requirements=[Requirement(req_id="1.1", desc="Test Req")],
        coverage_map={"1.1": ["T-1"]},
    )
    assay_report = AssayReport(results=[ComplianceTest(test_id="T-1", result="PASS")])
    bom_input = BOMInput(
        model_name="test",
        model_version="1",
        model_sha="sha",
        data_lineage=[],
        software_dependencies=[],
    )
    return {
        "user_id": "test-user",
        "agent_version": "1.0.0",
        "agent_config": agent_config,
        "assay_report": assay_report,
        "bom_input": bom_input,
    }


@pytest.fixture  # type: ignore[misc]
def setup_mocks(mock_dependencies: Dict[str, MagicMock], test_data: Dict[str, Any]) -> None:
    # Setup Mock Returns
    mock_bom = AIBOMObject(model_identity="test", data_lineage=[], software_dependencies=[], cyclonedx_bom={})
    mock_dependencies["bom_gen"].generate_bom.return_value = mock_bom

    mock_rtm = TraceabilityMatrix(
        requirements=test_data["agent_config"].requirements,
        tests=test_data["assay_report"].results,
        coverage_map=test_data["agent_config"].coverage_map,
        overall_status=RequirementStatus.COVERED_PASSED,
    )
    mock_dependencies["rtm_engine"].generate_matrix.return_value = mock_rtm

    mock_deviations = [
        Session(
            session_id="s1",
            timestamp=datetime.now(),
            risk_level=RiskLevel.HIGH,
            violation_summary="Fail",
            events=[],
        )
    ]
    mock_dependencies["replayer"].get_deviation_report.return_value = mock_deviations

    # Signer should return the object (modified)
    mock_dependencies["signer"].sign_package.side_effect = lambda pkg, uid: pkg


@pytest.mark.asyncio  # type: ignore[misc]
async def test_generate_audit_package_async(
    mock_dependencies: Dict[str, MagicMock],
    test_data: Dict[str, Any],
    setup_mocks: None,
    mock_context: UserContext,
) -> None:
    """Test the full flow of generating a package using Async Service."""
    async with AuditOrchestratorAsync(
        mock_dependencies["bom_gen"],
        mock_dependencies["rtm_engine"],
        mock_dependencies["replayer"],
        mock_dependencies["signer"],
        mock_dependencies["pdf_gen"],
        mock_dependencies["csv_gen"],
    ) as orchestrator:
        package = await orchestrator.generate_audit_package(
            mock_context,
            test_data["agent_config"],
            test_data["assay_report"],
            test_data["bom_input"],
            test_data["user_id"],
            test_data["agent_version"],
        )

        # Verify calls
        mock_dependencies["bom_gen"].generate_bom.assert_called_once_with(mock_context, test_data["bom_input"])
        mock_dependencies["rtm_engine"].generate_matrix.assert_called_once()
        mock_dependencies["replayer"].get_deviation_report.assert_called_once()
        mock_dependencies["signer"].sign_package.assert_called_once()

        # Verify package content
        assert isinstance(package, AuditPackage)
        assert package.agent_version == test_data["agent_version"]


def test_generate_audit_package_sync(
    mock_dependencies: Dict[str, MagicMock],
    test_data: Dict[str, Any],
    setup_mocks: None,
    mock_context: UserContext,
) -> None:
    """Test the full flow of generating a package using Sync Facade."""
    with AuditOrchestrator(
        mock_dependencies["bom_gen"],
        mock_dependencies["rtm_engine"],
        mock_dependencies["replayer"],
        mock_dependencies["signer"],
        mock_dependencies["pdf_gen"],
        mock_dependencies["csv_gen"],
    ) as orchestrator:
        package = orchestrator.generate_audit_package(
            mock_context,
            test_data["agent_config"],
            test_data["assay_report"],
            test_data["bom_input"],
            test_data["user_id"],
            test_data["agent_version"],
        )

        assert isinstance(package, AuditPackage)


@pytest.mark.asyncio  # type: ignore[misc]
async def test_export_to_pdf_async(mock_dependencies: Dict[str, MagicMock]) -> None:
    """Test PDF export delegation async."""
    async with AuditOrchestratorAsync(
        mock_dependencies["bom_gen"],
        mock_dependencies["rtm_engine"],
        mock_dependencies["replayer"],
        mock_dependencies["signer"],
        mock_dependencies["pdf_gen"],
        mock_dependencies["csv_gen"],
    ) as orchestrator:
        pkg = MagicMock(spec=AuditPackage)
        path = "out.pdf"
        await orchestrator.export_to_pdf(pkg, path)
        mock_dependencies["pdf_gen"].generate_report.assert_called_once_with(pkg, path)


def test_export_to_csv_sync(mock_dependencies: Dict[str, MagicMock]) -> None:
    """Test CSV export delegation sync."""
    with AuditOrchestrator(
        mock_dependencies["bom_gen"],
        mock_dependencies["rtm_engine"],
        mock_dependencies["replayer"],
        mock_dependencies["signer"],
        mock_dependencies["pdf_gen"],
        mock_dependencies["csv_gen"],
    ) as orchestrator:
        pkg = MagicMock(spec=AuditPackage)
        pkg.config_changes = ["change1", "change2"]
        path = "out.csv"
        orchestrator.export_to_csv(pkg, path)
        mock_dependencies["csv_gen"].generate_config_change_log.assert_called_once_with(["change1", "change2"], path)


@pytest.mark.asyncio  # type: ignore[misc]
async def test_critical_uncovered_failure_async(
    mock_dependencies: Dict[str, MagicMock], test_data: Dict[str, Any], mock_context: UserContext
) -> None:
    """Test that uncovered critical requirements raise an exception (Async)."""
    # Setup: Critical Req with NO coverage
    crit_req = Requirement(req_id="CRIT-1", desc="Important", critical=True)
    config = AgentConfig(requirements=[crit_req], coverage_map={})

    mock_rtm = TraceabilityMatrix(
        requirements=[crit_req], tests=[], coverage_map={}, overall_status=RequirementStatus.UNCOVERED
    )
    mock_dependencies["rtm_engine"].generate_matrix.return_value = mock_rtm

    async with AuditOrchestratorAsync(
        mock_dependencies["bom_gen"],
        mock_dependencies["rtm_engine"],
        mock_dependencies["replayer"],
        mock_dependencies["signer"],
        mock_dependencies["pdf_gen"],
        mock_dependencies["csv_gen"],
    ) as orchestrator:
        with pytest.raises(ComplianceViolationError):
            await orchestrator.generate_audit_package(
                mock_context,
                config,
                test_data["assay_report"],
                test_data["bom_input"],
                test_data["user_id"],
                test_data["agent_version"],
            )
