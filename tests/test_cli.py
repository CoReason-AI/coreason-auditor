import json
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest
import yaml
from coreason_auditor.main import main


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

    return {"agent": yaml_path, "assay": assay_path, "bom": bom_path, "output": tmp_path / "report.pdf"}


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
