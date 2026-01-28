# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_auditor

import pytest

from coreason_identity.models import UserContext
from coreason_identity.types import SecretStr
from coreason_auditor.aibom_generator import AIBOMGenerator
from coreason_auditor.models import AIBOMObject, BOMInput, Requirement


class TestAIBOMGenerator:
    @pytest.fixture  # type: ignore
    def mock_context(self) -> UserContext:
        return UserContext(user_id=SecretStr("test-user"), roles=[])

    @pytest.fixture  # type: ignore
    def bom_input(self) -> BOMInput:
        return BOMInput(
            model_name="meta-llama-3",
            model_version="70b-instruct",
            model_sha="sha256:abc123def456",
            adapter_sha="sha256:789ghi012jkl",
            data_lineage=["job-101", "job-102"],
            software_dependencies=["numpy==1.26.0", "pydantic==2.8.0"],
        )

    def test_bom_input_validation(self) -> None:
        """Test BOMInput Pydantic validation."""
        # Valid input
        input_data = BOMInput(
            model_name="test-model",
            model_version="1.0",
            model_sha="sha256:123",
            data_lineage=[],
            software_dependencies=[],
        )
        assert input_data.model_name == "test-model"

        # Missing field
        with pytest.raises(ValueError):
            # Missing other required fields
            BOMInput(
                model_name="test",
                model_version="1.0",
                model_sha="sha256:123",
                data_lineage=[],
                # software_dependencies missing
            )  # type: ignore

    def test_generate_bom_structure(self, bom_input: BOMInput, mock_context: UserContext) -> None:
        """Test that generate_bom produces a valid AIBOMObject with correct structure."""
        generator = AIBOMGenerator()
        result = generator.generate_bom(mock_context, bom_input)

        assert isinstance(result, AIBOMObject)
        assert result.model_identity == "meta-llama-3@sha256:abc123def456 + adapter@sha256:789ghi012jkl"
        assert result.data_lineage == bom_input.data_lineage
        assert result.software_dependencies == bom_input.software_dependencies

        # Check CycloneDX JSON content
        bom_dict = result.cyclonedx_bom
        assert bom_dict["bomFormat"] == "CycloneDX"
        assert "metadata" in bom_dict
        assert "components" in bom_dict

        # Check Metadata Component (The Model)
        main_component = bom_dict["metadata"]["component"]
        assert main_component["name"] == "meta-llama-3"
        assert main_component["version"] == "70b-instruct"
        assert main_component["type"] == "application"

        # Check Hashes
        hashes = main_component.get("hashes", [])
        sha256_hash = next((h["content"] for h in hashes if h["alg"] == "SHA-256"), None)
        assert sha256_hash == "abc123def456"

        # Check Properties (Adapter SHA)
        properties = main_component.get("properties", [])
        adapter_prop = next((p["value"] for p in properties if p["name"] == "coreason:adapter_sha"), None)
        assert adapter_prop == "sha256:789ghi012jkl"

    def test_generate_bom_components(self, bom_input: BOMInput, mock_context: UserContext) -> None:
        """Test that data lineage and dependencies are added as components."""
        generator = AIBOMGenerator()
        result = generator.generate_bom(mock_context, bom_input)
        bom_dict = result.cyclonedx_bom
        components = bom_dict.get("components", [])

        # Check Data Lineage
        data_comps = [c for c in components if c["type"] == "data"]
        assert len(data_comps) == 2
        assert any(c["name"] == "ingestion-job-job-101" for c in data_comps)

        # Check Dependencies
        lib_comps = [c for c in components if c["type"] == "library"]
        assert len(lib_comps) >= 2
        numpy_comp = next((c for c in lib_comps if c["name"] == "numpy"), None)
        assert numpy_comp is not None
        assert numpy_comp["version"] == "1.26.0"

    def test_requirement_critical_field(self) -> None:
        """Test that the Requirement model has the new critical field defaulting to True."""
        req = Requirement(req_id="1.1", desc="Test Req")
        assert req.critical is True

        req_non_critical = Requirement(req_id="1.2", desc="Optional", critical=False)
        assert req_non_critical.critical is False

    def test_edge_case_dependency_parsing(self, mock_context: UserContext) -> None:
        """Test fallback behavior for weird dependency strings."""
        input_data = BOMInput(
            model_name="test-parsing",
            model_version="1.0",
            model_sha="sha256:111",
            data_lineage=[],
            software_dependencies=[
                "simple-pkg",
                "versioned-pkg==1.2.3",
                "complex-pkg>=2.0",
                "weird-pkg==1.0==build",
            ],
        )
        generator = AIBOMGenerator()
        result = generator.generate_bom(mock_context, input_data)
        components = result.cyclonedx_bom.get("components", [])
        lib_comps = {c["name"]: c["version"] for c in components if c["type"] == "library"}

        # "simple-pkg" -> name="simple-pkg", version="unknown" (no '==')
        assert lib_comps["simple-pkg"] == "unknown"

        # "versioned-pkg==1.2.3" -> name="versioned-pkg", version="1.2.3"
        assert lib_comps["versioned-pkg"] == "1.2.3"

        # "complex-pkg>=2.0" -> name="complex-pkg>=2.0", version="unknown" (no '==')
        assert lib_comps["complex-pkg>=2.0"] == "unknown"

        # "weird-pkg==1.0==build" -> name="weird-pkg", version="1.0==build" (split on first '==')
        assert lib_comps["weird-pkg"] == "1.0==build"

    def test_unversioned_dependency_coverage(self, mock_context: UserContext) -> None:
        """Explicitly test dependency with no version to guarantee 'else' block coverage."""
        input_data = BOMInput(
            model_name="coverage-check",
            model_version="0.1",
            model_sha="sha256:000",
            data_lineage=[],
            software_dependencies=["just-a-name"],
        )
        generator = AIBOMGenerator()
        result = generator.generate_bom(mock_context, input_data)
        components = result.cyclonedx_bom.get("components", [])
        lib_comp = next((c for c in components if c["name"] == "just-a-name"), None)

        assert lib_comp is not None
        assert lib_comp["version"] == "unknown"
        assert lib_comp["type"] == "library"

    def test_edge_case_optional_adapter(self, mock_context: UserContext) -> None:
        """Test that optional adapter_sha is handled correctly (not added to properties)."""
        input_data = BOMInput(
            model_name="no-adapter-model",
            model_version="1.0",
            model_sha="sha256:222",
            adapter_sha=None,
            data_lineage=[],
            software_dependencies=[],
        )
        generator = AIBOMGenerator()
        result = generator.generate_bom(mock_context, input_data)

        # Check Model Identity String
        assert result.model_identity == "no-adapter-model@sha256:222"
        # Does NOT contain " + adapter@..."

        # Check BOM Properties
        main_component = result.cyclonedx_bom["metadata"]["component"]
        properties = main_component.get("properties", [])
        adapter_prop = next((p for p in properties if p["name"] == "coreason:adapter_sha"), None)
        assert adapter_prop is None

    def test_edge_case_raw_hash(self, mock_context: UserContext) -> None:
        """Test that model_sha without 'sha256:' prefix is handled."""
        raw_hash = "a" * 64
        input_data = BOMInput(
            model_name="raw-hash-model",
            model_version="1.0",
            model_sha=raw_hash,
            data_lineage=[],
            software_dependencies=[],
        )
        generator = AIBOMGenerator()
        result = generator.generate_bom(mock_context, input_data)

        main_component = result.cyclonedx_bom["metadata"]["component"]
        hashes = main_component.get("hashes", [])
        sha256_hash = next((h["content"] for h in hashes if h["alg"] == "SHA-256"), None)

        assert sha256_hash == raw_hash

    def test_complex_scenario_large_bom(self, mock_context: UserContext) -> None:
        """Test generating a BOM with a large number of components."""
        num_deps = 1000
        num_jobs = 100
        deps = [f"pkg-{i}=={i}.0.0" for i in range(num_deps)]
        jobs = [f"job-{i}" for i in range(num_jobs)]

        input_data = BOMInput(
            model_name="large-scale-model",
            model_version="9.9.9",
            model_sha="sha256:999",
            data_lineage=jobs,
            software_dependencies=deps,
        )

        generator = AIBOMGenerator()
        result = generator.generate_bom(mock_context, input_data)

        components = result.cyclonedx_bom.get("components", [])

        # Verify counts
        lib_comps = [c for c in components if c["type"] == "library"]
        data_comps = [c for c in components if c["type"] == "data"]

        assert len(lib_comps) == num_deps
        assert len(data_comps) == num_jobs
