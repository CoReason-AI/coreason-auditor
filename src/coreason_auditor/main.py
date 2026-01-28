# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_auditor

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

import yaml
from coreason_identity.models import UserContext
from coreason_identity.types import SecretStr
from pydantic import ValidationError

from coreason_auditor.aibom_generator import AIBOMGenerator
from coreason_auditor.config import settings
from coreason_auditor.csv_generator import CSVGenerator
from coreason_auditor.exceptions import ComplianceViolationError
from coreason_auditor.mocks import MockAegisService, MockIdentityService, MockSessionSource
from coreason_auditor.models import (
    AgentConfig,
    AssayReport,
    BOMInput,
    RiskLevel,
)
from coreason_auditor.orchestrator import AuditOrchestrator
from coreason_auditor.pdf_generator import PDFReportGenerator
from coreason_auditor.session_replayer import SessionReplayer
from coreason_auditor.signer import AuditSigner
from coreason_auditor.traceability_engine import TraceabilityEngine
from coreason_auditor.utils.logger import logger
from coreason_auditor.utils.seeder import populate_demo_data


def load_yaml(path: Path) -> Dict[str, Any]:
    """Loads a YAML file."""
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)  # type: ignore[no-any-return]


def load_json(path: Path) -> Dict[str, Any]:
    """Loads a JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)  # type: ignore[no-any-return]


def main() -> None:
    """CLI Entry Point for CoReason Auditor."""
    parser = argparse.ArgumentParser(description="CoReason Auditor - Compliance Reporting Engine")

    # Inputs
    parser.add_argument("--agent-config", required=True, type=Path, help="Path to agent.yaml")
    parser.add_argument("--assay-report", required=True, type=Path, help="Path to assay_report.json")
    parser.add_argument("--bom-input", required=True, type=Path, help="Path to bom_input.json")

    # Output
    parser.add_argument("--output", required=True, type=Path, help="Path to output PDF file")
    parser.add_argument("--bom-output", required=False, type=Path, help="Path to output BOM JSON file")
    parser.add_argument("--csv-output", required=False, type=Path, help="Path to output Config Change CSV file")

    # Meta
    parser.add_argument("--agent-version", required=True, type=str, help="Agent version string")
    parser.add_argument("--user-id", type=str, default=settings.DEFAULT_USER_ID, help="ID of user generating report")
    parser.add_argument("--risk-threshold", type=str, default=settings.RISK_THRESHOLD, help="Risk level threshold")

    args = parser.parse_args()

    # Configure Logging
    logger.configure(handlers=[{"sink": sys.stderr, "level": settings.LOG_LEVEL}])

    logger.info("Starting CoReason Auditor...")

    try:
        # 1. Load Inputs
        logger.info(f"Loading Agent Config from {args.agent_config}")
        config_data = load_yaml(args.agent_config)
        agent_config = AgentConfig(**config_data)

        logger.info(f"Loading Assay Report from {args.assay_report}")
        assay_data = load_json(args.assay_report)
        assay_report = AssayReport(**assay_data)

        logger.info(f"Loading BOM Input from {args.bom_input}")
        bom_data = load_json(args.bom_input)
        bom_input = BOMInput(**bom_data)

        # 2. Setup Dependencies (Mocks/Interfaces)
        # Note: In a real environment, we would load connection strings from settings
        # and instantiate real adapters (PostgresSessionSource, etc.)
        session_source = MockSessionSource()
        aegis_service = MockAegisService()
        identity_service = MockIdentityService()

        # Pre-populate MockSessionSource with data for demo (User Story B)
        populate_demo_data(session_source)

        # 3. Instantiate Core Components
        aibom_generator = AIBOMGenerator()
        traceability_engine = TraceabilityEngine()
        session_replayer = SessionReplayer(session_source, aegis_service)
        signer = AuditSigner(identity_service)
        pdf_generator = PDFReportGenerator()
        csv_generator = CSVGenerator()

        # 4. Execute Orchestration
        try:
            risk_enum = RiskLevel(args.risk_threshold)
        except ValueError:
            logger.error(f"Invalid risk threshold: {args.risk_threshold}")
            sys.exit(1)

        system_context = UserContext(user_id=SecretStr("cli-user"), roles=["system"], metadata={"source": "cli"})

        with AuditOrchestrator(
            aibom_generator=aibom_generator,
            traceability_engine=traceability_engine,
            session_replayer=session_replayer,
            signer=signer,
            pdf_generator=pdf_generator,
            csv_generator=csv_generator,
        ) as orchestrator:
            package = orchestrator.generate_audit_package(
                context=system_context,
                agent_config=agent_config,
                assay_report=assay_report,
                bom_input=bom_input,
                user_id=args.user_id,
                agent_version=args.agent_version,
                risk_threshold=risk_enum,
                max_deviations=settings.MAX_DEVIATIONS,
            )

            # 5. Export
            logger.info(f"Exporting report to {args.output}")
            orchestrator.export_to_pdf(package, str(args.output))

            if args.bom_output:
                logger.info(f"Exporting BOM to {args.bom_output}")
                with open(args.bom_output, "w", encoding="utf-8") as f:
                    json.dump(package.bom.cyclonedx_bom, f, indent=2)

            if args.csv_output:
                logger.info(f"Exporting Config Change CSV to {args.csv_output}")
                orchestrator.export_to_csv(package, str(args.csv_output))

        logger.info("Audit Package generation completed successfully.")

    except ValidationError as e:
        logger.error(f"Input Validation Error: {e}")
        sys.exit(1)
    except ComplianceViolationError as e:
        logger.error(f"COMPLIANCE VIOLATION: {e}")
        sys.exit(2)
    except Exception as e:
        logger.exception(f"Unexpected Error: {e}")
        sys.exit(3)


if __name__ == "__main__":  # pragma: no cover
    main()
