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

from coreason_auditor.aibom_generator import AIBOMGenerator
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


class AuditOrchestrator:
    """
    Coordinator for generating the full Audit Package.
    Integrates BOM, Traceability, Session Replay, Signing, and Export.
    """

    def __init__(
        self,
        aibom_generator: AIBOMGenerator,
        traceability_engine: TraceabilityEngine,
        session_replayer: SessionReplayer,
        signer: AuditSigner,
        pdf_generator: PDFReportGenerator,
    ):
        self.aibom_generator = aibom_generator
        self.traceability_engine = traceability_engine
        self.session_replayer = session_replayer
        self.signer = signer
        self.pdf_generator = pdf_generator

    def generate_audit_package(
        self,
        agent_config: AgentConfig,
        assay_report: AssayReport,
        bom_input: BOMInput,
        user_id: str,
        agent_version: str,
        risk_threshold: RiskLevel = RiskLevel.HIGH,
        max_deviations: int = 10,
    ) -> AuditPackage:
        """
        Orchestrates the creation of the Audit Package.

        Args:
            agent_config: Requirements and coverage map.
            assay_report: Test results.
            bom_input: Model inventory data.
            user_id: ID of the user triggering the report.
            agent_version: Version string of the agent.
            risk_threshold: Minimum risk level for deviation report.
            max_deviations: Max sessions to include in deviation report.

        Returns:
            A signed AuditPackage object.
        """
        logger.info(f"Starting Audit Package generation for Agent v{agent_version} by {user_id}")

        # 1. Generate AI-BOM
        bom = self.aibom_generator.generate_bom(bom_input)

        # 2. Generate Traceability Matrix
        rtm = self.traceability_engine.generate_matrix(agent_config, assay_report)

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
        deviations = self.session_replayer.get_deviation_report(risk_level=risk_threshold, limit=max_deviations)

        # 4. Fetch Intervention Count
        interventions = self.session_replayer.get_intervention_count(agent_version)

        # 5. Fetch Configuration Changes (Audit Trail)
        config_changes = self.session_replayer.get_config_changes()

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
        signed_package = self.signer.sign_package(package, user_id)

        logger.info(f"Audit Package {signed_package.id} generated and signed.")
        return signed_package

    def export_to_pdf(self, audit_package: AuditPackage, output_path: str) -> None:
        """
        Renders the audit package to a PDF file.
        """
        self.pdf_generator.generate_report(audit_package, output_path)
