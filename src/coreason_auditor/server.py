# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_auditor

import json
import os
import tempfile
from contextlib import asynccontextmanager
from typing import Annotated, AsyncGenerator, Dict, cast

import anyio
import yaml
from coreason_identity.models import UserContext
from coreason_identity.types import SecretStr
from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import ValidationError

from coreason_auditor.aibom_generator import AIBOMGenerator
from coreason_auditor.config import settings
from coreason_auditor.csv_generator import CSVGenerator
from coreason_auditor.job_manager import JobManager, ReportJob
from coreason_auditor.mocks import MockAegisService, MockIdentityService, MockSessionSource
from coreason_auditor.models import (
    AgentConfig,
    AssayReport,
    AuditPackage,
    BOMInput,
    RiskLevel,
)
from coreason_auditor.orchestrator import AuditOrchestratorAsync
from coreason_auditor.pdf_generator import PDFReportGenerator
from coreason_auditor.session_replayer import SessionReplayer
from coreason_auditor.signer import AuditSigner
from coreason_auditor.traceability_engine import TraceabilityEngine
from coreason_auditor.utils.logger import logger
from coreason_auditor.utils.seeder import populate_demo_data


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan manager for the FastAPI application."""
    logger.info("Initializing Audit Server...")

    # Initialize dependencies (Mocked for Server Mode as per CLI)
    session_source = MockSessionSource()
    aegis_service = MockAegisService()
    identity_service = MockIdentityService()

    # Pre-populate demo data
    populate_demo_data(session_source)

    # Initialize Core Components
    aibom_generator = AIBOMGenerator()
    traceability_engine = TraceabilityEngine()
    session_replayer = SessionReplayer(session_source, aegis_service)
    signer = AuditSigner(identity_service)
    pdf_generator = PDFReportGenerator()
    csv_generator = CSVGenerator()

    # Initialize JobManager
    job_manager = JobManager(max_workers=4)
    app.state.job_manager = job_manager

    # Initialize Orchestrator
    async with AuditOrchestratorAsync(
        aibom_generator=aibom_generator,
        traceability_engine=traceability_engine,
        session_replayer=session_replayer,
        signer=signer,
        pdf_generator=pdf_generator,
        csv_generator=csv_generator,
    ) as orchestrator:
        app.state.orchestrator = orchestrator
        logger.info("Audit Server Ready.")
        yield

    logger.info("Shutting down Audit Server...")
    job_manager.shutdown(wait=True)


app = FastAPI(title="CoReason Auditor Service", version="0.1.0", lifespan=lifespan)


def run_audit_generation_sync(
    orchestrator: AuditOrchestratorAsync,
    context: UserContext,
    agent_config: AgentConfig,
    assay_report: AssayReport,
    bom_input: BOMInput,
    user_id: str,
    agent_version: str,
    risk_threshold: RiskLevel,
    max_deviations: int,
) -> AuditPackage:
    """Synchronous wrapper to run async generation in a thread."""
    return cast(
        AuditPackage,
        anyio.run(
            orchestrator.generate_audit_package,
            context,
            agent_config,
            assay_report,
            bom_input,
            user_id,
            agent_version,
            risk_threshold,
            max_deviations,
        ),
    )


def remove_file(path: str) -> None:
    try:
        os.remove(path)
    except Exception as e:
        logger.error(f"Failed to remove temp file {path}: {e}")


@app.post("/audit/generate", status_code=202)  # type: ignore[misc]
async def generate_audit(
    agent_config: Annotated[UploadFile, File(...)],
    assay_report: Annotated[UploadFile, File(...)],
    bom_input: Annotated[UploadFile, File(...)],
) -> Dict[str, str]:
    """
    Submits an audit generation job.
    Accepts agent_config (YAML), assay_report (JSON), and bom_input (JSON) as files.
    """
    try:
        # Parse inputs
        config_content = await agent_config.read()
        config_data = yaml.safe_load(config_content)
        if not isinstance(config_data, dict):
            raise HTTPException(status_code=400, detail="Agent Config must be a YAML mapping")
        agent_conf = AgentConfig(**config_data)

        assay_content = await assay_report.read()
        assay_data = json.loads(assay_content)
        assay_rep = AssayReport(**assay_data)

        bom_content = await bom_input.read()
        bom_data = json.loads(bom_content)
        bom_inp = BOMInput(**bom_data)

        # Use a system context for the server
        # In a real microservice, we would extract user info from headers/auth token
        user_id = "api-user"
        context = UserContext(user_id=SecretStr(user_id), roles=["system"], metadata={"source": "api"})

        # Default values (could be parameterized)
        agent_version = "1.0.0"  # Ideally extracted from input or param
        risk_threshold = RiskLevel(settings.RISK_THRESHOLD)
        max_deviations = settings.MAX_DEVIATIONS

        job_manager: JobManager = app.state.job_manager
        orchestrator: AuditOrchestratorAsync = app.state.orchestrator

        job_id = job_manager.create_job(
            context,
            run_audit_generation_sync,
            orchestrator,
            context,
            agent_conf,
            assay_rep,
            bom_inp,
            user_id,
            agent_version,
            risk_threshold,
            max_deviations,
        )

        return {"job_id": job_id, "status": "PENDING"}

    except (yaml.YAMLError, json.JSONDecodeError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid file format: {str(e)}") from e
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=f"Validation error: {str(e)}") from e
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error submitting job")
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/audit/jobs/{job_id}", response_model=ReportJob)  # type: ignore[misc]
async def get_job_status(job_id: str) -> ReportJob:
    """Retrieves the status of a job."""
    job_manager: JobManager = app.state.job_manager
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    # We don't want to return the full AuditPackage result in the JSON response usually,
    # but the ReportJob model includes 'result: Optional[Any]'.
    # If AuditPackage is large, this might be heavy.
    # However, for this task, returning the model as is seems correct.
    # Note: Pydantic will try to serialize AuditPackage if present.
    return job


@app.get("/audit/download/{job_id}/{format}")  # type: ignore[misc]
async def download_report(job_id: str, format: str, background_tasks: BackgroundTasks) -> FileResponse:
    """Downloads the generated report in PDF or CSV format."""
    if format not in ["pdf", "csv"]:
        raise HTTPException(status_code=400, detail="Invalid format. Use 'pdf' or 'csv'.")

    job_manager: JobManager = app.state.job_manager
    job = job_manager.get_job(job_id)

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "COMPLETED" or not job.result:
        raise HTTPException(status_code=400, detail="Job not completed or result missing")

    audit_package: AuditPackage = job.result
    orchestrator: AuditOrchestratorAsync = app.state.orchestrator

    # Generate file to temp location
    try:
        # We need to run the export function. Since export functions in orchestrator are async wrappers
        # calling run_sync, we can just await them here (we are in async route).
        # Wait, OrchestratorAsync.export_to_pdf is async def.

        suffix = ".pdf" if format == "pdf" else ".csv"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            output_path = tmp.name

        if format == "pdf":
            await orchestrator.export_to_pdf(audit_package, output_path)
        else:
            await orchestrator.export_to_csv(audit_package, output_path)

        filename = f"audit_report_{job_id}{suffix}"
        background_tasks.add_task(remove_file, output_path)

        return FileResponse(
            output_path, filename=filename, media_type="application/pdf" if format == "pdf" else "text/csv"
        )

    except Exception as e:
        logger.exception("Error generating download")
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get("/health")  # type: ignore[misc]
async def health_check() -> Dict[str, str]:
    return {"status": "ready", "version": "0.1.0"}
