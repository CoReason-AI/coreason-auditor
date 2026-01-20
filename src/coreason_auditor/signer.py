# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_auditor

import hashlib

from coreason_auditor.interfaces import IdentityService
from coreason_auditor.models import AuditPackage
from coreason_auditor.utils.logger import logger


class AuditSigner:
    """
    Handles the cryptographic hashing and signing of Audit Packages.
    Implements 21 CFR Part 11 requirements for digital signatures.
    """

    def __init__(self, identity_service: IdentityService):
        self.identity_service = identity_service

    def sign_package(self, audit_package: AuditPackage, user_id: str) -> AuditPackage:
        """
        Calculates the hash of the audit package content and requests a signature.
        Updates the audit package with the signature and hash.

        Args:
            audit_package: The package to sign.
            user_id: The ID of the user authorizing the signature.

        Returns:
            The signed AuditPackage.
        """
        logger.info(f"Signing Audit Package {audit_package.id} for user {user_id}...")

        # 1. Calculate Hash
        # We need a stable representation of the content to hash.
        # Excluding the signature field itself is crucial (circular dependency).
        # We dump the model to JSON, excluding 'electronic_signature' and 'document_hash'.
        # We convert to dict first, then dump with json to ensure consistent key sorting.
        import json

        content_dict = audit_package.model_dump(exclude={"electronic_signature", "document_hash"}, mode="json")
        content_bytes = json.dumps(content_dict, sort_keys=True).encode("utf-8")

        doc_hash = self.calculate_hash(content_bytes)
        audit_package.document_hash = doc_hash

        # 2. Request Signature
        signature = self.identity_service.sign_document(doc_hash, user_id)
        audit_package.electronic_signature = signature

        logger.info("Audit Package signed successfully.")
        return audit_package

    def calculate_hash(self, content: bytes) -> str:
        """
        Calculates the SHA-256 hash of the given bytes.
        """
        sha256 = hashlib.sha256()
        sha256.update(content)
        return sha256.hexdigest()
