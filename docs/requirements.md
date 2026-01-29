# Requirements

## Runtime Environment

*   **Python:** >= 3.12, < 3.15
*   **OS:** Linux (preferred), macOS, Windows

## Python Dependencies

### Core Functionality
*   `loguru` (^0.7.2): Centralized logging.
*   `pydantic` (^2.12.5): Data validation and settings management.
*   `cyclonedx-python-lib` (^11.6.0): AI-BOM generation in standard format.
*   `reportlab` (^4.4.9): PDF report generation.
*   `cryptography` (^46.0.3): Digital signatures and hashing.
*   `pydantic-settings` (^2.12.0): Configuration management.
*   `pyyaml` (^6.0.3): YAML parsing for configuration files.
*   `anyio` (^4.12.1): Asynchronous concurrency primitives.
*   `httpx` (^0.28.1): Async HTTP client for external service calls.
*   `aiofiles` (^23.2.1): Async file I/O operations.
*   `coreason-identity` (^0.1.0): Authentication and identity management.

### Server Mode (Microservice)
*   `fastapi` (*): High-performance web framework for APIs.
*   `uvicorn` (*): ASGI web server implementation.
*   `python-multipart` (*): Support for multipart/form-data (file uploads).

## Development Dependencies
*   `pytest` (^9.0.2): Testing framework.
*   `ruff` (^0.14.14): Fast linter and formatter.
*   `pre-commit` (^3.7.1): Git hook management.
*   `pytest-cov` (^5.0.0): Coverage reporting.
*   `mkdocs` (^1.6.0) & `mkdocs-material` (^9.5.26): Documentation.
*   `pypdf` (^6.6.0): PDF manipulation for testing.
*   `types-pyyaml` & `types-aiofiles`: Type stubs for mypy.
*   `pytest-asyncio` (^1.3.0): Async support for pytest.
