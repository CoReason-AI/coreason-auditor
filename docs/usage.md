# Usage Guide

`coreason-auditor` can be used in two modes: as a traditional Command Line Interface (CLI) tool for local report generation, or as a standalone Compliance Reporting Microservice (Service C).

## 1. CLI Mode

The CLI is useful for local debugging, ad-hoc report generation, or integration into CI/CD pipelines that prefer shell execution.

### Basic Command

```bash
python -m coreason_auditor.main \
    --agent-config path/to/agent.yaml \
    --assay-report path/to/assay_report.json \
    --bom-input path/to/bom_input.json \
    --output report.pdf \
    --agent-version "1.0.0"
```

### Arguments

*   `--agent-config`: Path to the YAML configuration file defining requirements and coverage.
*   `--assay-report`: Path to the JSON test results file.
*   `--bom-input`: Path to the JSON BOM input data.
*   `--output`: Destination path for the generated PDF audit package.
*   `--agent-version`: Version string of the agent being audited.
*   `--user-id` (Optional): ID of the user generating the report (default: "cli-user").
*   `--risk-threshold` (Optional): Minimum risk level to include in deviation reports (default: "HIGH").
*   `--bom-output` (Optional): Path to export the machine-readable CycloneDX BOM (JSON).
*   `--csv-output` (Optional): Path to export the Configuration Change Log (CSV).

## 2. Server Mode (Microservice)

The server mode exposes a REST API for asynchronous report generation, suitable for integration with `coreason-publisher` or `coreason-maco`.

### Starting the Server

You can start the server using `uvicorn`:

```bash
uvicorn coreason_auditor.server:app --host 0.0.0.0 --port 8000
```

Or run via Docker:

```bash
docker run -p 8000:8000 coreason-auditor:latest
```

### API Endpoints

#### 1. Generate Audit Package
**POST** `/audit/generate`

Submit a job to generate an audit package. This is an asynchronous operation.

*   **Inputs (multipart/form-data):**
    *   `agent_config`: YAML file.
    *   `assay_report`: JSON file.
    *   `bom_input`: JSON file.
*   **Response:**
    *   `job_id`: Unique identifier for the generation job.
    *   `status`: "PENDING"

#### 2. Check Job Status
**GET** `/audit/jobs/{job_id}`

Poll the status of a submitted job.

*   **Response:**
    *   `status`: "PENDING", "RUNNING", "COMPLETED", or "FAILED".
    *   `submitted_at`, `completed_at`: Timestamps.
    *   `error`: Error message if failed.

#### 3. Download Report
**GET** `/audit/download/{job_id}/{format}`

Download the generated artifact.

*   **Parameters:**
    *   `format`: `pdf` or `csv`.
*   **Response:** Binary file stream.

### Example Workflow (Python)

```python
import requests
import time

# 1. Submit Job
files = {
    'agent_config': open('agent.yaml', 'rb'),
    'assay_report': open('assay_report.json', 'rb'),
    'bom_input': open('bom_input.json', 'rb')
}
response = requests.post('http://localhost:8000/audit/generate', files=files)
job_id = response.json()['job_id']

# 2. Poll Status
while True:
    status_resp = requests.get(f'http://localhost:8000/audit/jobs/{job_id}')
    status = status_resp.json()['status']
    if status in ['COMPLETED', 'FAILED']:
        break
    time.sleep(1)

# 3. Download
if status == 'COMPLETED':
    pdf_resp = requests.get(f'http://localhost:8000/audit/download/{job_id}/pdf')
    with open('report.pdf', 'wb') as f:
        f.write(pdf_resp.content)
```
