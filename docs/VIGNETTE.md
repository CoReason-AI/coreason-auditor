# The Architecture and Utility of coreason-auditor

## 1. The Philosophy (The Why)

**"If it isn't documented in a PDF, it didn't happen."**

In the unregulated world of early generative AI, a JSON log stored in a data lake was sufficient evidence of system behavior. However, as AI enters regulated domains—healthcare, finance, and critical infrastructure—the burden of proof shifts. Regulators like the FDA and bodies enforcing the EU AI Act do not query Elasticsearch clusters; they audit static, verifiable documents.

`coreason-auditor` was built to bridge this chasm. It functions as the **External Validator** for the CoReason ecosystem, transforming the ephemeral, messy reality of AI inference logs into the permanence of regulatory law.

Existing logging solutions (Splunk, Datadog) are optimized for observability—identifying *why* a system failed. `coreason-auditor` is optimized for **accountability**—proving *who* is responsible, *what* exact ingredients (models, data, prompts) were used, and *how* the system performed against its mandated safety requirements. It does not just report data; it reconstructs the "story" of a session and cryptographically seals it, ensuring that the audit trail is as immutable as the regulations it satisfies.

## 2. Under the Hood (The Dependencies & logic)

The architectural choices of `coreason-auditor` reflect a balance between strict compliance standards and modern software engineering practices.

*   **`pydantic` (Data Integrity):** At its core, the system relies on Pydantic to enforce rigid schemas. The `AuditPackage` isn't just a dictionary; it's a strictly typed model that validates every field—from the timestamp of a user intervention to the SHA-256 hash of a Llama-3 model adapter. This ensures that invalid data triggers a failure *before* a report is generated, preventing "garbage in, garbage out" compliance.
*   **`cyclonedx-python-lib` (Standardization):** Rather than inventing a proprietary format for the AI Bill of Materials (AI-BOM), the package leverages the industry-standard CycloneDX library. This ensures that the "ingredients list" of every AI agent is interoperable with the broader supply chain security ecosystem.
*   **`reportlab` (Rendering):** To maintain a lightweight, secure container footprint, `coreason-auditor` eschews heavy browser-based PDF generators (like headless Chrome/Puppeteer). Instead, it uses ReportLab to programmatically construct PDFs. This allows for precise control over layout—critical for ensuring that tables don't break across pages in legally binding documents—without the attack surface of a full web browser.
*   **`cryptography` (Immutable Proof):** Conforming to 21 CFR Part 11, the `signer` module uses the `cryptography` library to hash the final artifacts and apply digital signatures. This guarantees that the generated report has not been tampered with since its creation.
*   **`loguru` (Audit the Auditor):** Every step of the generation process is logged with `loguru`, ensuring that the act of auditing is itself auditable.

The logic flows through the `AuditOrchestrator`, which acts as a conductor. It pulls test results (via `TraceabilityEngine`), reconstructs user sessions (via `SessionReplayer`), compiles the software inventory (`AIBOMGenerator`), and finally seals the package (`AuditSigner`). Crucially, it enforces a "compliance gate": if a critical requirement lacks test coverage, the orchestrator raises a `ComplianceViolationError` and aborts the release, stopping non-compliant software at the door.

## 3. In Practice (The How)

`coreason-auditor` is typically invoked as part of a CI/CD pipeline or a release process. Here is how a developer or compliance engineer interacts with the Python API to generate a sealed audit package.

### Generating the Audit Package

The `AuditOrchestrator` is the primary entry point. It requires pre-configured components (like the session source and signer) to be injected, promoting testability and modularity.

```python
from coreason_auditor.orchestrator import AuditOrchestrator
from coreason_auditor.models import AgentConfig, AssayReport, BOMInput, RiskLevel

# 1. Initialize the Orchestrator with its dependencies
# (Assumes components like aibom_generator and session_replayer are already instantiated)
orchestrator = AuditOrchestrator(
    aibom_generator=aibom_generator,
    traceability_engine=traceability_engine,
    session_replayer=session_replayer,
    signer=signer,
    pdf_generator=pdf_generator,
    csv_generator=csv_generator,
)

# 2. execute the generation logic
# This pulls data, verifies coverage, and signs the result.
audit_package = orchestrator.generate_audit_package(
    agent_config=AgentConfig(...),      # Defined requirements (e.g., from agent.yaml)
    assay_report=AssayReport(...),      # Test results (e.g., from CI pipeline)
    bom_input=BOMInput(...),            # Model inventory details
    user_id="compliance.officer@coreason.ai",
    agent_version="2.1.0",
    risk_threshold=RiskLevel.HIGH       # Only report high-risk deviations
)

print(f"Generated Audit Package ID: {audit_package.id}")
print(f"Document Hash: {audit_package.document_hash}")
```

### Exporting Artifacts

Once the `AuditPackage` is generated and held in memory (as a validated Pydantic model), it can be exported to various formats for regulatory submission.

```python
# Export the human-readable PDF report
# This includes the cover page, BOM, traceability matrix, and deviation logs.
orchestrator.export_to_pdf(audit_package, output_path="release_artifacts/Audit_Report_v2.1.0.pdf")

# Export the detailed configuration change log to CSV
# Useful for downstream analysis or loading into Excel for manual review.
orchestrator.export_to_csv(audit_package, output_path="release_artifacts/Config_Change_Log.csv")

# The BOM is also accessible as a standard dictionary for JSON export
import json
with open("release_artifacts/bom.json", "w") as f:
    json.dump(audit_package.bom.cyclonedx_bom, f, indent=2)
```

In this workflow, the developer doesn't just "print logs." They instantiate a rigorous, verifiable proof of compliance that allows the business to ship AI software with confidence.
