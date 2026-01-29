# coreason-auditor

**Regulatory Compliance, AI-BOM Generation, & Audit Trail Reporting for the CoReason Ecosystem.**

[![License](https://img.shields.io/badge/license-Prosperity%203.0-blue)](https://prosperitylicense.com/versions/3.0.0)
[![CI](https://github.com/CoReason-AI/coreason_auditor/actions/workflows/main.yml/badge.svg)](https://github.com/CoReason-AI/coreason_auditor/actions)
[![Code Style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Documentation](https://img.shields.io/badge/docs-Product%20Requirements-blue)](docs/product_requirements.md)

---

**"If it isn't documented in a PDF, it didn't happen. Turn logs into Law."**

`coreason-auditor` is the automated reporting engine for the CoReason ecosystem. It bridges the gap between "Technical Logging" (JSON streams) and "Regulatory Submission" (Human-readable documents) by generating cryptographically signed Audit Packages.

## Features

Based on the [Product Requirements](docs/product_requirements.md):

*   **Traceability Engine:** Maps Requirements $\to$ Tests $\to$ Results (RTM). Fails generation if critical requirements are uncovered.
*   **AI-BOM Generator:** Creates Software Bill of Materials (CycloneDX Standard) for models, data lineage, and dependencies.
*   **Session Replayer:** Forensic tool that reconstructs user sessions, displaying hidden "Thought Chains" and "Tool Calls" alongside user input.
*   **21 CFR Part 11 Signer:** Applies digital signatures to exported reports for immutability and authenticity.
*   **Deviation Reporting:** Prioritizes failures and interventions (Exception-First Reporting).
*   **Service C Microservice:** Asynchronous REST API for high-volume audit generation (FastAPI + Uvicorn).

## Installation

```bash
pip install coreason-auditor
```

## Usage

Please refer to the [Usage Guide](docs/usage.md) for detailed instructions on both **CLI Mode** and **Server Mode**.

### Quick Start (Server)

```bash
# Start the API server
uvicorn coreason_auditor.server:app --host 0.0.0.0 --port 8000
```

### Quick Start (CLI)

```bash
python -m coreason_auditor.main \
  --agent-config agent.yaml \
  --assay-report assay_report.json \
  --bom-input bom_input.json \
  --output report.pdf \
  --agent-version 1.0.0
```

## License

Copyright (c) 2025 CoReason, Inc.
Licensed under the **Prosperity Public License 3.0**.
See [LICENSE](LICENSE) for details.
