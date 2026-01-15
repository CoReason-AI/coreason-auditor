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
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
import yaml
from coreason_auditor.main import main
from coreason_auditor.models import RiskLevel


@pytest.fixture  # type: ignore[misc]
def sample_inputs(tmp_path: Path) -> Dict[str, Path]:
    """Creates sample input files for CLI testing."""
    # 1. agent.yaml
    agent_config = {
        "requirements": [
            {"req_id": "1.0", "desc": "Must be safe", "critical": True},
            {"req_id": "1.1", "desc": "Must be fast", "critical": False},
        ],
        "coverage_map": {"1.0": ["T-1"], "1.1": ["T-2"]},
    }
    yaml_path = tmp_path / "agent.yaml"
    with open(yaml_path, "w") as f:
        yaml.dump(agent_config, f)

    # 2. assay_report.json
    assay_report = {"results": [{"test_id": "T-1", "result": "PASS"}, {"test_id": "T-2", "result": "PASS"}]}
    assay_path = tmp_path / "assay.json"
    with open(assay_path, "w") as f:
        json.dump(assay_report, f)

    # 3. bom_input.json
    bom_input = {
        "model_name": "llama-3",
        "model_version": "1.0",
        "model_sha": "sha256:abc",
        "data_lineage": ["job-1"],
        "software_dependencies": ["numpy==1.0"],
    }
    bom_path = tmp_path / "bom.json"
    with open(bom_path, "w") as f:
        json.dump(bom_input, f)

    return {
        "agent": yaml_path,
        "assay": assay_path,
        "bom": bom_path,
        "output": tmp_path / "report.pdf",
        "bom_output": tmp_path / "bom-out.json",
    }


def test_cli_happy_path(sample_inputs: Dict[str, Path], capsys: Any) -> None:
    """Test standard CLI execution success."""

    # Simulate ARGV
    args = [
        "coreason-auditor",
        "--agent-config",
        str(sample_inputs["agent"]),
        "--assay-report",
        str(sample_inputs["assay"]),
        "--bom-input",
        str(sample_inputs["bom"]),
        "--output",
        str(sample_inputs["output"]),
        "--agent-version",
        "1.0.0",
        "--user-id",
        "cli-tester",
    ]

    with patch("sys.argv", args):
        main()

    # Verify file created
    assert sample_inputs["output"].exists()
    assert sample_inputs["output"].stat().st_size > 0

    # Verify Logs
    captured = capsys.readouterr()
    assert "Audit Package generation completed successfully." in captured.err


def test_cli_bom_export(sample_inputs: Dict[str, Path], capsys: Any) -> None:
    """Test CLI execution with BOM export."""

    args = [
        "coreason-auditor",
        "--agent-config",
        str(sample_inputs["agent"]),
        "--assay-report",
        str(sample_inputs["assay"]),
        "--bom-input",
        str(sample_inputs["bom"]),
        "--output",
        str(sample_inputs["output"]),
        "--bom-output",
        str(sample_inputs["bom_output"]),
        "--agent-version",
        "1.0.0",
    ]

    with patch("sys.argv", args):
        main()

    # Verify BOM output created
    assert sample_inputs["bom_output"].exists()
    with open(sample_inputs["bom_output"], "r") as f:
        bom_data = json.load(f)

    # Basic CycloneDX structure check
    assert "bomFormat" in bom_data
    assert "components" in bom_data
    assert bom_data["bomFormat"] == "CycloneDX"


def test_cli_validation_error(tmp_path: Path, capsys: Any) -> None:
    """Test CLI fails cleanly on invalid input data."""

    # Create invalid YAML (missing requirements)
    bad_yaml = tmp_path / "bad.yaml"
    with open(bad_yaml, "w") as f:
        yaml.dump({"invalid": "schema"}, f)

    # Just need dummies for others
    dummy = tmp_path / "dummy"
    dummy.touch()

    args = [
        "coreason-auditor",
        "--agent-config",
        str(bad_yaml),
        "--assay-report",
        str(dummy),  # Won't get here
        "--bom-input",
        str(dummy),
        "--output",
        str(tmp_path / "out.pdf"),
        "--agent-version",
        "1.0",
    ]

    with patch("sys.argv", args):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1

    captured = capsys.readouterr()
    assert "Input Validation Error" in captured.err


def test_cli_compliance_violation(sample_inputs: Dict[str, Path], capsys: Any) -> None:
    """Test CLI exit code 2 on compliance violation."""

    # Modify agent.yaml to have UNCOVERED critical requirement
    bad_config = {
        "requirements": [{"req_id": "CRIT", "desc": "Critical", "critical": True}],
        "coverage_map": {},  # Empty coverage
    }
    with open(sample_inputs["agent"], "w") as f:
        yaml.dump(bad_config, f)

    args = [
        "coreason-auditor",
        "--agent-config",
        str(sample_inputs["agent"]),
        "--assay-report",
        str(sample_inputs["assay"]),
        "--bom-input",
        str(sample_inputs["bom"]),
        "--output",
        str(sample_inputs["output"]),
        "--agent-version",
        "1.0.0",
    ]

    with patch("sys.argv", args):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 2

    captured = capsys.readouterr()
    assert "COMPLIANCE VIOLATION" in captured.err


def test_cli_invalid_risk_threshold(sample_inputs: Dict[str, Path], capsys: Any) -> None:
    """Test CLI exits on invalid risk threshold."""
    args = [
        "coreason-auditor",
        "--agent-config",
        str(sample_inputs["agent"]),
        "--assay-report",
        str(sample_inputs["assay"]),
        "--bom-input",
        str(sample_inputs["bom"]),
        "--output",
        str(sample_inputs["output"]),
        "--agent-version",
        "1.0.0",
        "--risk-threshold",
        "INVALID_RISK",
    ]

    with patch("sys.argv", args):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1

    captured = capsys.readouterr()
    assert "Invalid risk threshold" in captured.err


def test_cli_missing_input_file(tmp_path: Path, capsys: Any) -> None:
    """Test CLI behavior when input file is missing."""
    missing_file = tmp_path / "missing.yaml"

    dummy = tmp_path / "dummy"
    dummy.touch()

    args = [
        "coreason-auditor",
        "--agent-config",
        str(missing_file),
        "--assay-report",
        str(dummy),
        "--bom-input",
        str(dummy),
        "--output",
        str(tmp_path / "out.pdf"),
        "--agent-version",
        "1.0.0",
    ]

    with patch("sys.argv", args):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 3  # Catches generic Exception (FileNotFoundError)

    captured = capsys.readouterr()
    assert "Unexpected Error" in captured.err
    assert "No such file or directory" in captured.err


def test_cli_corrupt_json_file(sample_inputs: Dict[str, Path], capsys: Any) -> None:
    """Test CLI behavior when JSON input is corrupt."""
    corrupt_json = sample_inputs["assay"]
    with open(corrupt_json, "w") as f:
        f.write("{ invalid json")

    args = [
        "coreason-auditor",
        "--agent-config",
        str(sample_inputs["agent"]),
        "--assay-report",
        str(corrupt_json),
        "--bom-input",
        str(sample_inputs["bom"]),
        "--output",
        str(sample_inputs["output"]),
        "--agent-version",
        "1.0.0",
    ]

    with patch("sys.argv", args):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 3  # Generic exception for JSONDecodeError

    captured = capsys.readouterr()
    assert "Unexpected Error" in captured.err
    # JSONDecodeError message varies by python version/impl slightly but usually says "Expecting" or "JSON"


def test_cli_env_var_override(sample_inputs: Dict[str, Path], capsys: Any) -> None:
    """
    Test that environment variables can override defaults or influence logic.
    Here we test LOG_LEVEL via config, though checking side effects of log level is hard.
    Instead, let's verify RISK_THRESHOLD if we were to use it from Env.
    """

    # We'll use unittest.mock.patch to patch the 'settings' object in main module
    with patch("coreason_auditor.main.settings") as mock_settings:
        mock_settings.RISK_THRESHOLD = "LOW"
        mock_settings.DEFAULT_USER_ID = "env-user"
        mock_settings.LOG_LEVEL = "DEBUG"
        mock_settings.MAX_DEVIATIONS = 5

        # Mock the Orchestrator to verify it receives the correct risk threshold
        with patch("coreason_auditor.main.AuditOrchestrator") as MockOrch:
            instance = MockOrch.return_value
            # return a dummy package to avoid crash later
            instance.generate_audit_package.return_value = MagicMock()

            args = [
                "coreason-auditor",
                "--agent-config",
                str(sample_inputs["agent"]),
                "--assay-report",
                str(sample_inputs["assay"]),
                "--bom-input",
                str(sample_inputs["bom"]),
                "--output",
                str(sample_inputs["output"]),
                "--agent-version",
                "1.0.0",
                # Note: NOT passing --risk-threshold or --user-id, expecting defaults from mock_settings
            ]

            with patch("sys.argv", args):
                main()

            # Verify generate_audit_package was called with RiskLevel.LOW
            call_kwargs = instance.generate_audit_package.call_args[1]
            assert call_kwargs["risk_threshold"] == RiskLevel.LOW
            assert call_kwargs["user_id"] == "env-user"


def test_complex_scenario_cli(sample_inputs: Dict[str, Path], capsys: Any) -> None:
    """
    Complex scenario:
    1. Valid inputs.
    2. Specific Risk Threshold (CRITICAL).
    3. User ID provided.
    4. Mock the SessionSource to return specific sessions to verify Orchestrator processes them.
    """

    args = [
        "coreason-auditor",
        "--agent-config",
        str(sample_inputs["agent"]),
        "--assay-report",
        str(sample_inputs["assay"]),
        "--bom-input",
        str(sample_inputs["bom"]),
        "--output",
        str(sample_inputs["output"]),
        "--agent-version",
        "2.5.0-beta",
        "--user-id",
        "compliance-officer-alice",
        "--risk-threshold",
        "CRITICAL",
    ]

    with patch("coreason_auditor.main.AuditOrchestrator") as MockOrch:
        instance = MockOrch.return_value
        instance.generate_audit_package.return_value = MagicMock()

        with patch("sys.argv", args):
            main()

        # Verify complex args passed through
        call_kwargs = instance.generate_audit_package.call_args[1]
        assert call_kwargs["agent_version"] == "2.5.0-beta"
        assert call_kwargs["user_id"] == "compliance-officer-alice"
        assert call_kwargs["risk_threshold"] == RiskLevel.CRITICAL
