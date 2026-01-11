from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, model_validator


class RequirementStatus(str, Enum):
    COVERED_PASSED = "COVERED_PASSED"
    COVERED_FAILED = "COVERED_FAILED"
    UNCOVERED = "UNCOVERED"


class Requirement(BaseModel):
    req_id: str = Field(..., description="Requirement Identifier, e.g., '1.1'")
    desc: str = Field(..., description="Description of the requirement")
    critical: bool = Field(default=True, description="Whether this requirement is critical for compliance")


class ComplianceTest(BaseModel):
    test_id: str = Field(..., description="Test Identifier, e.g., 'T-100'")
    result: str = Field(..., description="Result of the test, e.g., 'PASS' or 'FAIL'")
    evidence: Optional[str] = Field(default=None, description="Link to run log or other evidence")


class AgentConfig(BaseModel):
    """
    Represents the input configuration (agent.yaml).
    """

    requirements: List[Requirement] = Field(..., description="List of requirements")
    coverage_map: Dict[str, List[str]] = Field(..., description="Map of Req ID to list of Test IDs")


class AssayReport(BaseModel):
    """
    Represents the input test results (assay_report.json).
    """

    results: List[ComplianceTest] = Field(..., description="List of test results")
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TraceabilityMatrix(BaseModel):
    requirements: List[Requirement] = Field(
        ..., description="List of requirements, e.g. {'req_id': '1.1', 'desc': 'Verify Dose'}"
    )
    tests: List[ComplianceTest] = Field(..., description="List of tests, e.g. {'test_id': 'T-100', 'result': 'PASS'}")
    coverage_map: Dict[str, List[str]] = Field(..., description="Map of requirement IDs to list of test IDs")
    overall_status: RequirementStatus

    @model_validator(mode="after")
    def check_integrity(self) -> "TraceabilityMatrix":
        req_ids = {r.req_id for r in self.requirements}
        test_ids = {t.test_id for t in self.tests}

        # Check coverage_map keys (Requirement IDs)
        for req_id, mapped_tests in self.coverage_map.items():
            if req_id not in req_ids:
                raise ValueError(f"Requirement ID '{req_id}' in coverage_map not found in requirements list.")

            # Check coverage_map values (Test IDs)
            for test_id in mapped_tests:
                if test_id not in test_ids:
                    raise ValueError(f"Test ID '{test_id}' mapped to Requirement '{req_id}' not found in tests list.")

        return self


class BOMInput(BaseModel):
    """
    Formalized input for AI-BOM generation.
    Decouples the generator from specific data sources.
    """

    model_name: str = Field(..., description="Name of the base model, e.g., 'meta-llama-3'")
    model_version: str = Field(..., description="Version or tag of the model")
    model_sha: str = Field(..., description="SHA-256 hash of the model artifacts")
    adapter_sha: Optional[str] = Field(default=None, description="SHA-256 hash of the LoRA adapter if present")
    data_lineage: List[str] = Field(..., description="List of coreason-refinery ingestion job IDs")
    software_dependencies: List[str] = Field(..., description="List of pip installed packages (name==version)")


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
