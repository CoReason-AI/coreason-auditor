# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_auditor

import unittest
from datetime import datetime
from uuid import uuid4

from coreason_auditor.mocks import MockIdentityService
from coreason_auditor.models import (
    AIBOMObject,
    AuditPackage,
    RequirementStatus,
    TraceabilityMatrix,
)
from coreason_auditor.signer import AuditSigner


class TestAuditSigner(unittest.TestCase):
    def setUp(self) -> None:
        self.mock_identity = MockIdentityService()
        self.signer = AuditSigner(self.mock_identity)

        # Create a dummy AuditPackage
        self.package = AuditPackage(
            id=uuid4(),
            agent_version="1.0.0",
            generated_at=datetime.now(),
            generated_by="test-user",
            bom=AIBOMObject(
                model_identity="test-model",
                data_lineage=[],
                software_dependencies=[],
                cyclonedx_bom={},
            ),
            rtm=TraceabilityMatrix(
                requirements=[],
                tests=[],
                coverage_map={},
                overall_status=RequirementStatus.COVERED_PASSED,
            ),
            deviation_report=[],
            human_interventions=0,
            document_hash="",
            electronic_signature="",
        )

    def test_calculate_hash(self) -> None:
        """Test SHA-256 calculation."""
        content = b"test content"
        # Known hash for "test content"
        expected_hash = "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72"
        result = self.signer.calculate_hash(content)
        self.assertEqual(result, expected_hash)

    def test_sign_package(self) -> None:
        """Test the signing flow."""
        user_id = "signer-001"
        signed_pkg = self.signer.sign_package(self.package, user_id)

        # Verify hash was populated
        self.assertNotEqual(signed_pkg.document_hash, "")
        self.assertEqual(len(signed_pkg.document_hash), 64)  # SHA-256 hex length

        # Verify signature was populated
        self.assertTrue(signed_pkg.electronic_signature.startswith(f"SIGNED_BY_{user_id}"))
        self.assertIn(signed_pkg.document_hash[:8], signed_pkg.electronic_signature)

    def test_sign_package_idempotency_check(self) -> None:
        """Verify hashing is consistent for same content."""
        # Create two identical packages
        # Actually, let's just reuse the signer on the same object (resetting fields)
        self.package.document_hash = ""
        self.package.electronic_signature = ""

        import json

        content_dict1 = self.package.model_dump(exclude={"electronic_signature", "document_hash"}, mode="json")
        hash1 = self.signer.calculate_hash(json.dumps(content_dict1, sort_keys=True).encode("utf-8"))

        self.package.document_hash = ""  # Reset
        content_dict2 = self.package.model_dump(exclude={"electronic_signature", "document_hash"}, mode="json")
        hash2 = self.signer.calculate_hash(json.dumps(content_dict2, sort_keys=True).encode("utf-8"))

        self.assertEqual(hash1, hash2)
