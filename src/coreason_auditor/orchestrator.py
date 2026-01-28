# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_auditor

import uuid
from datetime import datetime, timezone
from typing import Optional, cast

import anyio
import httpx
from anyio import to_thread
from coreason_identity.models import UserContext

from coreason_auditor.aibom_generator import AIBOMGenerator
from coreason_auditor.csv_generator import CSVGenerator
from coreason_auditor.exceptions import ComplianceViolationError
from coreason_auditor.models import (
    AgentConfig,
    AssayReport,
    AuditPackage,
    BOMInput,
    RiskLevel,
)
from coreason_auditor.pdf_generator import PDFReportGenerator
from coreason_auditor.session_replayer import SessionReplayer
from coreason_auditor.signer import AuditSigner
from coreason_auditor.traceability_engine import TraceabilityEngine
from coreason_auditor.utils.logger import logger


class AuditOrchestratorAsync:
    """Coordinator for generating the full Audit Package.

    Integrates BOM, Traceability, Session Replay, Signing, and Export.
    """

    def __init__(
        self,
        aibom_generator: AIBOMGenerator,
        traceability_engine: TraceabilityEngine,
        session_replayer: SessionReplayer,
        signer: AuditSigner,
        pdf_generator: PDFReportGenerator,
        csv_generator: CSVGenerator,
        client: Optional[httpx.AsyncClient] = None,
    ):
        self.aibom_generator = aibom_generator
        self.traceability_engine = traceability_engine
        self.session_replayer = session_replayer
        self.signer = signer
        self.pdf_generator = pdf_generator
        self.csv_generator = csv_generator
        self._internal_client = client is None
        self._client = client or httpx.AsyncClient()

    async def __aenter__(self) -> "AuditOrchestratorAsync":
        return self

    async def __aexit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        if self._internal_client:
            await self._client.aclose()

    async def generate_audit_package(
        self,
        context: UserContext,
        agent_config: AgentConfig,
        assay_report: AssayReport,
        bom_input: BOMInput,
        user_id: str,
        agent_version: str,
        risk_threshold: RiskLevel = RiskLevel.HIGH,
        max_deviations: int = 10,
    ) -> AuditPackage:
        """Orchestrates the creation of the Audit Package.

        Args:
            context: The user context requesting the audit.
            agent_config: Requirements and coverage map.
            assay_report: Test results.
            bom_input: Model inventory data.
            user_id: ID of the user triggering the report.
            agent_version: Version string of the agent.
            risk_threshold: Minimum risk level for deviation report.
            max_deviations: Max sessions to include in deviation report.

        Returns:
            A signed AuditPackage object.

        Raises:
            ComplianceViolationError: If critical requirements are uncovered.
        """
        if context is None:
            raise ValueError("UserContext is required")

        logger.info(
            f"Starting Audit Package generation for Agent v{agent_version}",
            user_id=context.user_id.get_secret_value(),
        )

        # 1. Generate AI-BOM
        bom = await to_thread.run_sync(self.aibom_generator.generate_bom, context, bom_input)

        # 2. Generate Traceability Matrix
        rtm = await to_thread.run_sync(self.traceability_engine.generate_matrix, context, agent_config, assay_report)

        # CRITICAL: Enforce coverage for critical requirements
        for req in rtm.requirements:
            if req.critical:
                covered_tests = rtm.coverage_map.get(req.req_id)
                if not covered_tests:
                    logger.error(f"Critical requirement '{req.req_id}' is uncovered. Aborting generation.")
                    raise ComplianceViolationError(
                        f"Critical requirement '{req.req_id}' ({req.desc}) is UNCOVERED. "
                        "All critical requirements must have at least one covering test."
                    )

        # 3. Generate Deviation Report (Session Replay)
        # Note: SessionReplayer fetches sessions.
        # Assuming SessionReplayer is still synchronous for now, wrapping in run_sync.
        # If SessionReplayer was async, we would await it directly.
        deviations = await to_thread.run_sync(
            self.session_replayer.get_deviation_report, risk_threshold, max_deviations
        )

        # 4. Fetch Intervention Count
        interventions = await to_thread.run_sync(self.session_replayer.get_intervention_count, agent_version)

        # 5. Fetch Configuration Changes (Audit Trail)
        config_changes = await to_thread.run_sync(self.session_replayer.get_config_changes)

        # 6. Assemble Package
        package = AuditPackage(
            id=uuid.uuid4(),
            agent_version=agent_version,
            generated_at=datetime.now(timezone.utc),
            generated_by=user_id,
            bom=bom,
            rtm=rtm,
            deviation_report=deviations,
            config_changes=config_changes,
            human_interventions=interventions,
            document_hash="",  # To be filled by signer
            electronic_signature="",  # To be filled by signer
        )

        # 5. Sign Package
        signed_package = await to_thread.run_sync(self.signer.sign_package, package, user_id)

        logger.info(f"Audit Package {signed_package.id} generated and signed.")
        return cast(AuditPackage, signed_package)

    async def export_to_pdf(self, audit_package: AuditPackage, output_path: str) -> None:
        """Renders the audit package to a PDF file."""
        await to_thread.run_sync(self.pdf_generator.generate_report, audit_package, output_path)

    async def export_to_csv(self, audit_package: AuditPackage, output_path: str) -> None:
        """Renders the configuration changes to a CSV file."""
        await to_thread.run_sync(
            self.csv_generator.generate_config_change_log, audit_package.config_changes, output_path
        )


class AuditOrchestrator:
    """Sync wrapper for AuditOrchestratorAsync."""

    def __init__(
        self,
        aibom_generator: AIBOMGenerator,
        traceability_engine: TraceabilityEngine,
        session_replayer: SessionReplayer,
        signer: AuditSigner,
        pdf_generator: PDFReportGenerator,
        csv_generator: CSVGenerator,
        client: Optional[httpx.AsyncClient] = None,
    ):
        self._async = AuditOrchestratorAsync(
            aibom_generator,
            traceability_engine,
            session_replayer,
            signer,
            pdf_generator,
            csv_generator,
            client,
        )

    def __enter__(self) -> "AuditOrchestrator":
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        anyio.run(self._async.__aexit__, exc_type, exc_val, exc_tb)

    def generate_audit_package(
        self,
        context: UserContext,
        agent_config: AgentConfig,
        assay_report: AssayReport,
        bom_input: BOMInput,
        user_id: str,
        agent_version: str,
        risk_threshold: RiskLevel = RiskLevel.HIGH,
        max_deviations: int = 10,
    ) -> AuditPackage:
        """Sync wrapper for generate_audit_package."""
        result = anyio.run(
            self._async.generate_audit_package,
            context,
            agent_config,
            assay_report,
            bom_input,
            user_id,
            agent_version,
            risk_threshold,
            max_deviations,
        )
        return cast(AuditPackage, result)

    def export_to_pdf(self, audit_package: AuditPackage, output_path: str) -> None:
        """Sync wrapper for export_to_pdf."""
        anyio.run(self._async.export_to_pdf, audit_package, output_path)

    def export_to_csv(self, audit_package: AuditPackage, output_path: str) -> None:
        """Sync wrapper for export_to_csv."""
        anyio.run(self._async.export_to_csv, audit_package, output_path)
