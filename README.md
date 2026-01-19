# coreason-auditor

**Automated reporting engine for the CoReason ecosystem.**

It bridges the gap between "Technical Logging" (JSON streams) and "Regulatory Submission" (Human-readable documents). Its primary mandate is to generate the **"Audit Package"** for every released agent, proving provenance, integrity, traceability, and oversight.

[![License: Prosperity 3.0](https://img.shields.io/badge/License-Prosperity%203.0-blue)](https://github.com/CoReason-AI/coreason_auditor/blob/main/LICENSE)
[![Build Status](https://github.com/CoReason-AI/coreason_auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/CoReason-AI/coreason_auditor/actions)
[![Code Style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

## Features

*   **Traceability Engine:** Links Requirements to Tests (Traceability Matrix).
*   **AI-BOM Generator:** Creates "Nutrition Label" for the Agent (SPDX 3.0 / CycloneDX).
*   **Session Replayer:** Forensic tool for session reconstruction and review.
*   **21 CFR Signer:** Applies digital signatures to exported reports.
*   **Audit Trail:** Configuration Change Log tracking.

## Installation

```bash
pip install coreason-auditor
```

## Usage

### Command Line Interface

```bash
python -m coreason_auditor.main \
  --agent-config path/to/agent.yaml \
  --assay-report path/to/assay_report.json \
  --bom-input path/to/bom_input.json \
  --output report.pdf \
  --agent-version "v1.0.0"
```

### Python API

```python
from coreason_auditor.orchestrator import AuditOrchestrator
from coreason_auditor.models import AgentConfig, AssayReport, BOMInput

# Instantiate components (simplified)
orchestrator = AuditOrchestrator(...)

# Generate Package
package = orchestrator.generate_audit_package(
    agent_config=AgentConfig(...),
    assay_report=AssayReport(...),
    bom_input=BOMInput(...),
    user_id="user-123",
    agent_version="v1.0.0"
)

# Export
orchestrator.export_to_pdf(package, "audit_report.pdf")
```
