# Product Requirements Document: coreason-auditor

**Domain:** Regulatory Compliance, AI-BOM Generation, & Audit Trail Reporting
**Architectural Role:** The "External Validator" / The Reporter
**Core Philosophy:** "If it isn't documented in a PDF, it didn't happen. Turn logs into Law."
**Dependencies:** coreason-veritas (Source Data), coreason-publisher (Artifacts), coreason-identity (Signatures)

---

## 1. Executive Summary

coreason-auditor is the automated reporting engine for the CoReason ecosystem. It bridges the gap between "Technical Logging" (JSON streams) and "Regulatory Submission" (Human-readable documents).

Its primary mandate is to generate the **"Audit Package"** for every released agent. This package proves to a regulator that:

1.  **Provenance:** We know exactly which data trained the model (AI-BOM).
2.  **Integrity:** No unauthorized human altered the code (21 CFR Part 11).
3.  **Traceability:** Every requirement (e.g., "Must refuse toxic prompts") maps to a specific test result (Traceability Matrix).
4.  **Oversight:** Humans intervened when required (Human-in-the-Loop Logs).

## 2. Functional Philosophy

The agent must implement the **Query-Structure-Sign-Export Loop**:

1.  **Semantic Reconstruction:** Raw logs are fragmented. The Auditor must reconstruct the "Story" of a session. It links the *Input* (Prompt) $\to$ *Thought* (Reasoning) $\to$ *Action* (Tool) $\to$ *Outcome* (Response) into a coherent narrative.
2.  **The AI-BOM Standard:** We adopt the **SPDX 3.0 / CycloneDX** standard for defining the "Ingredients List" of an AI system (Base Model + LoRA Adapter + RAG Documents + System Prompt).
3.  **Immutable Snapshots:** Reports are not dynamic dashboards. They are static, versioned artifacts (PDF/CSV) that are cryptographically signed. Once generated, they represent the "Truth" at that point in time.
4.  **Exception-First Reporting:** Auditors don't want to read 1 million success logs. They want to see the 5 failures. The system prioritizes "Deviation Reports" (Refusals, Errors, Interventions).

---

## 3. Core Functional Requirements (Component Level)

### 3.1 The Traceability Engine (The Mapper)

**Concept:** Links Requirements $\to$ Tests $\to$ Results.

*   **Input:**
    *   `agent.yaml` (Requirements: "Must verify drug dosage").
    *   `assay_report.json` (Test Results: "Test Case 4 passed").
*   **Output:** A **Requirement Traceability Matrix (RTM)**.
    *   *Row:* Req ID 1.1 "Dosage Verification"
    *   *Col:* Test ID 4.0
    *   *Status:* PASS
    *   *Evidence:* Link to specific run log.
*   **Logic:** Fails the report generation if any "Critical" requirement has 0 covering tests.

### 3.2 The AI-BOM Generator (The Inventory)

**Concept:** Creates the "Nutrition Label" for the Agent.

*   **Fields:**
    *   **Model Identity:** Base Model SHA (meta-llama-3@sha256:...) + Adapter SHA (foundry-output@sha256:...).
    *   **Data Lineage:** List of all coreason-refinery ingestion job IDs that contributed to the vector store.
    *   **Software Dependencies:** `pip freeze` of the runtime environment (part of the Reproducibility requirement).
*   **Format:** Exports as `bom.json` (machine readable) and `Model_Card.pdf` (human readable).

### 3.3 The Session Replayer (The Forensic Tool)

**Concept:** Reconstructs user sessions for human review.

*   **Capability:**
    *   Queries `coreason-veritas` for a specific `session_id`.
    *   Decrypts PII using `coreason-aegis` (if the viewer is authorized).
    *   Renders a chronological "Chat Transcript" showing hidden "Thought Chains" and "Tool Calls" alongside user text.
*   **Annotation:** Allows Compliance Officers to flag specific turns as "Compliance Violation" or "Good Response" (Metadata write-back).

### 3.4 The 21 CFR Signer (The Notary)

**Concept:** Applies digital signatures to the exported reports.

*   **Action:**
    *   Hashes the final PDF/CSV.
    *   Requests a signature from `coreason-identity` (using the user's certificate).
    *   Appends a "Signature Page" to the PDF: *"Electronically Signed by [User] at [Timestamp] via CoReason Identity."*

---

## 4. Integration Requirements (The Ecosystem)

*   **Source (coreason-veritas):**
    *   The Auditor is a *Reader* of Veritas. It performs heavy aggregations (GROUP BY user, date) that should be run on a Read Replica to avoid slowing down live logging.
*   **Trigger (coreason-publisher):**
    *   When Publisher prepares a release, it calls Auditor: *"Give me the Compliance Pack for Agent v2.1."* The release fails if Auditor returns errors (e.g., missing test coverage).
*   **Archive (coreason-vault):**
    *   The final signed PDFs are stored in Vault (or S3 WORM storage) for the statutory retention period (e.g., 5-10 years).

---

## 5. User Stories (Behavioral Expectations)

### Story A: The "FDA Submission" (AI-BOM)

**Context:** The company is submitting a new drug application. The FDA asks: "What AI model analyzed these adverse events?"
**Action:** Compliance Officer clicks "Export AI-BOM" for the Safety-Agent v4.0.
**Result:** coreason-auditor generates a PDF listing:
*   Model: Llama-3-70B-Instruct (Hash: abc...)
*   Training Data: "Safety_Corpus_Q3_2025" (Hash: 123...)
*   Validation: "Passed 98% of BEC Safety Tests."
    **Value:** Instant regulatory transparency.

### Story B: The "Deviation Investigation" (Session Replay)

**Context:** A user reports that the agent gave "bad advice" on Tuesday.
**Action:** QA Manager queries Auditor for date=Tuesday and risk=High.
**Result:** Auditor presents a filtered list of 5 sessions.
**Deep Dive:** Manager opens Session #3. Sees the "Thought Trace" where the agent misinterpreted a PDF table.
**Outcome:** Manager flags the interaction. Auditor adds it to the "Retraining Queue" for coreason-synthesis.

### Story C: The "Audit Trail Review" (21 CFR)

**Context:** An auditor asks: "Who changed the system prompt last week?"
**Action:** Admin requests the "Configuration Change Log."
**Result:** Auditor generates a CSV showing:
*   2025-01-10 14:00: User j.doe changed system_prompt from "Ver A" to "Ver B".
*   Reason: "Updated tone guidelines."
*   Status: "Signed & Approved."

---

## 6. Data Schema

### AuditPackage

```python
class AuditPackage(BaseModel):
    id: UUID
    agent_version: str
    generated_at: datetime
    generated_by: str

    # The Components
    bom: AIBOMObject             # The Ingredients
    rtm: TraceabilityMatrix      # The Tests
    deviation_report: List[dict] # The Failures
    human_interventions: int     # Count of HITL events

    # The Seal
    document_hash: str           # SHA-256 of the content
    electronic_signature: str    # The cryptographic proof
```

### TraceabilityMatrix

```python
class RequirementStatus(str, Enum):
    COVERED_PASSED = "COVERED_PASSED"
    COVERED_FAILED = "COVERED_FAILED"
    UNCOVERED = "UNCOVERED"

class TraceabilityMatrix(BaseModel):
    requirements: List[dict] # { "req_id": "1.1", "desc": "Verify Dose" }
    tests: List[dict]        # { "test_id": "T-100", "result": "PASS" }
    coverage_map: Dict[str, List[str]] # { "1.1": ["T-100", "T-102"] }
    overall_status: RequirementStatus
```

---

## 7. Implementation Directives for the Coding Agent

1.  **PDF Generation:** Use **reportlab** or **weasyprint**. Do not rely on HTML-to-PDF converters that require external browser binaries (headless Chrome) if possible, to keep the container lightweight.
2.  **Standard Schemas:** Use the **CycloneDX** python library for generating the BOM. Do not invent a proprietary JSON format for the BOM; stick to the industry standard so external tools can read it.
3.  **Read-Only Safety:** The Auditor must have **Read-Only** access to the Veritas database. It should never be technically capable of deleting or modifying a log entry. Enforce this at the SQL user level.
4.  **Async Generation:** Reports can be huge (100MB+). Do not generate them in the HTTP request loop. Submit a ReportJob, return a job_id, and let the user poll for the download link.
