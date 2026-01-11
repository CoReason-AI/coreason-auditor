import pytest
from coreason_auditor.aibom_generator import AIBOMGenerator
from coreason_auditor.models import AIBOMObject, BOMInput, Requirement


class TestAIBOMGenerator:
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

    def test_generate_bom_structure(self, bom_input: BOMInput) -> None:
        """Test that generate_bom produces a valid AIBOMObject with correct structure."""
        generator = AIBOMGenerator()
        result = generator.generate_bom(bom_input)

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

    def test_generate_bom_components(self, bom_input: BOMInput) -> None:
        """Test that data lineage and dependencies are added as components."""
        generator = AIBOMGenerator()
        result = generator.generate_bom(bom_input)
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
