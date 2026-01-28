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
from datetime import datetime, timezone

from coreason_identity.models import UserContext
from cyclonedx.model import Property
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output.json import JsonV1Dot6

from coreason_auditor.models import AIBOMObject, BOMInput
from coreason_auditor.utils.logger import logger


class AIBOMGenerator:
    """Generates AI-BOMs complying with CycloneDX standard.

    This component creates the "Nutrition Label" for the Agent, including
    Model Identity, Data Lineage, and Software Dependencies.
    """

    def generate_bom(self, context: UserContext, input_data: BOMInput) -> AIBOMObject:
        """Generates an AIBOMObject from the given BOMInput.

        Args:
            context: The user context requesting the BOM.
            input_data: The input data including model details, data lineage,
                and dependencies.

        Returns:
            A populated AIBOMObject containing the CycloneDX BOM in JSON format
            and metadata.
        """
        if context is None:
            raise ValueError("UserContext is required")

        logger.info(
            f"Generating AI-BOM for model {input_data.model_name}",
            user_id=context.user_id.get_secret_value(),
        )

        # Initialize CycloneDX BOM
        bom = Bom()
        bom.metadata = BomMetaData(
            timestamp=datetime.now(timezone.utc),
            properties=[
                Property(name="coreason:generated_by", value="coreason-auditor"),
            ],
        )

        # 1. Add Base Model as the Main Component (Application/Library)
        main_component = Component(
            name=input_data.model_name,
            version=input_data.model_version,
            type=ComponentType.APPLICATION,
            bom_ref="main-model",
        )

        # Add SHA as a property or hash if supported.
        from cyclonedx.model import HashAlgorithm, HashType

        # Ideally we parse the SHA string to determine type.
        sha_value = input_data.model_sha
        if sha_value.startswith("sha256:"):
            sha_value = sha_value.replace("sha256:", "")

        main_component.hashes.add(HashType(alg=HashAlgorithm.SHA_256, content=sha_value))

        if input_data.adapter_sha:
            main_component.properties.add(Property(name="coreason:adapter_sha", value=input_data.adapter_sha))

        bom.metadata.component = main_component

        # 2. Add Data Lineage as Data Components
        for job_id in input_data.data_lineage:
            data_component = Component(
                name=f"ingestion-job-{job_id}",
                type=ComponentType.DATA,
                version="1.0",
                description=f"Data ingestion job {job_id}",
            )
            bom.components.add(data_component)

        # 3. Add Software Dependencies
        for dep in input_data.software_dependencies:
            # dep string is like "package==1.0.0"
            if "==" in dep:
                name, version = dep.split("==", 1)
            else:
                name = dep
                version = "unknown"

            dep_component = Component(
                name=name,
                version=version,
                type=ComponentType.LIBRARY,
            )
            bom.components.add(dep_component)

        # Serialize to JSON
        output = JsonV1Dot6(bom).output_as_string()
        bom_dict = json.loads(output)

        # Construct model identity string
        model_identity = f"{input_data.model_name}@{input_data.model_sha}"
        if input_data.adapter_sha:
            model_identity += f" + adapter@{input_data.adapter_sha}"

        return AIBOMObject(
            model_identity=model_identity,
            data_lineage=input_data.data_lineage,
            software_dependencies=input_data.software_dependencies,
            cyclonedx_bom=bom_dict,
        )
