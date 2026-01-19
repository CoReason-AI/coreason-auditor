# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_auditor

from abc import ABC, abstractmethod
from typing import List, Optional

from coreason_auditor.models import ConfigChange, RiskLevel, Session


class SessionSource(ABC):
    """Interface for retrieving session data from the source of truth (e.g., coreason-veritas)."""

    @abstractmethod
    def get_session(self, session_id: str) -> Optional[Session]:  # pragma: no cover
        """Retrieves a single session by ID.

        Args:
            session_id: The unique identifier of the session.

        Returns:
            The Session object if found, else None.
        """
        pass

    @abstractmethod
    def get_sessions_by_risk(self, risk_level: RiskLevel, limit: int = 10) -> List[Session]:  # pragma: no cover
        """Retrieves a list of sessions filtered by risk level.

        Args:
            risk_level: The risk level to filter by (e.g., HIGH).
            limit: Maximum number of sessions to return.

        Returns:
            A list of matching Session objects.
        """
        pass

    @abstractmethod
    def get_intervention_count(self, agent_version: str) -> int:  # pragma: no cover
        """Retrieves the total count of human interventions for the given agent version.

        Args:
            agent_version: The version string of the agent.

        Returns:
            The count of interventions.
        """
        pass

    @abstractmethod
    def get_config_changes(self, limit: int = 100) -> List[ConfigChange]:  # pragma: no cover
        """Retrieves a list of configuration changes for the audit trail.

        Args:
            limit: Maximum number of records to return.

        Returns:
            A list of ConfigChange objects.
        """
        pass


class AegisService(ABC):
    """Interface for the CoReason Aegis encryption/decryption service."""

    @abstractmethod
    def decrypt(self, ciphertext: str) -> str:  # pragma: no cover
        """Decrypts the given ciphertext.

        Args:
            ciphertext: The encrypted string.

        Returns:
            The decrypted plaintext.
        """
        pass


class IdentityService(ABC):
    """Interface for the CoReason Identity service (digital signatures)."""

    @abstractmethod
    def sign_document(self, document_hash: str, user_id: str) -> str:  # pragma: no cover
        """Requests a digital signature for a document hash.

        Args:
            document_hash: The SHA-256 hash of the document.
            user_id: The ID of the user signing the document.

        Returns:
            The cryptographic signature string.
        """
        pass
