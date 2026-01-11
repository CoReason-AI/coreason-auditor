from datetime import datetime
from enum import Enum
from typing import Any, Dict, List
from uuid import UUID

from pydantic import BaseModel, Field


class RequirementStatus(str, Enum):
    COVERED_PASSED = "COVERED_PASSED"
    COVERED_FAILED = "COVERED_FAILED"
    UNCOVERED = "UNCOVERED"


class TraceabilityMatrix(BaseModel):
    requirements: List[Dict[str, str]] = Field(
        ..., description="List of requirements, e.g. {'req_id': '1.1', 'desc': 'Verify Dose'}"
    )
    tests: List[Dict[str, Any]] = Field(..., description="List of tests, e.g. {'test_id': 'T-100', 'result': 'PASS'}")
    coverage_map: Dict[str, List[str]] = Field(..., description="Map of requirement IDs to list of test IDs")
    overall_status: RequirementStatus


class AIBOMObject(BaseModel):
    """
    Represents the AI-BOM ingredients list.
    Corresponds to functionality in Section 3.2.
    """

    model_identity: str = Field(..., description="Base Model SHA + Adapter SHA")
    data_lineage: List[str] = Field(..., description="List of ingestion job IDs")
    software_dependencies: List[str] = Field(..., description="pip freeze of runtime environment")
    # Using Dict for now to hold the CycloneDX structure as it can be complex
    cyclonedx_bom: Dict[str, Any] = Field(default_factory=dict, description="The full CycloneDX BOM structure")


class AuditPackage(BaseModel):
    id: UUID
    agent_version: str
    generated_at: datetime
    generated_by: str

    # The Components
    bom: AIBOMObject  # The Ingredients
    rtm: TraceabilityMatrix  # The Tests
    deviation_report: List[Dict[str, Any]]  # The Failures
    human_interventions: int  # Count of HITL events

    # The Seal
    document_hash: str  # SHA-256 of the content
    electronic_signature: str  # The cryptographic proof
