# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_auditor

from typing import List, Optional

from coreason_auditor.interfaces import AegisService, IdentityService, SessionSource
from coreason_auditor.models import ConfigChange, RiskLevel, Session


class MockSessionSource(SessionSource):
    """Mock implementation of SessionSource for testing and development."""

    def __init__(self, sessions: Optional[List[Session]] = None, intervention_count: int = 0):
        self._sessions = {s.session_id: s for s in sessions} if sessions else {}
        self._intervention_count = intervention_count
        self._config_changes: List[ConfigChange] = []

    def get_session(self, session_id: str) -> Optional[Session]:
        return self._sessions.get(session_id)

    def get_sessions_by_risk(self, risk_level: RiskLevel, limit: int = 10) -> List[Session]:
        # Simple filter
        matching = [s for s in self._sessions.values() if s.risk_level == risk_level]
        return matching[:limit]

    def get_intervention_count(self, agent_version: str) -> int:
        return self._intervention_count

    def get_config_changes(self, limit: int = 100) -> List[ConfigChange]:
        # Sort by timestamp desc, then limit
        sorted_changes = sorted(self._config_changes, key=lambda x: x.timestamp, reverse=True)
        return sorted_changes[:limit]

    def add_session(self, session: Session) -> None:
        self._sessions[session.session_id] = session

    def add_config_change(self, change: ConfigChange) -> None:
        self._config_changes.append(change)


class MockAegisService(AegisService):
    """Mock implementation of AegisService.

    Simulates decryption by stripping a prefix "ENC:".
    """

    def decrypt(self, ciphertext: str) -> str:
        if ciphertext.startswith("ENC:"):
            return ciphertext[4:]
        # If not encrypted with our mock prefix, return as is (or raise error if strict)
        # For robustness in tests, we assume it returns as is if not matching pattern
        return ciphertext


class MockIdentityService(IdentityService):
    """Mock implementation of IdentityService.

    Returns a dummy signature.
    """

    def sign_document(self, document_hash: str, user_id: str) -> str:
        return f"SIGNED_BY_{user_id}_HASH_{document_hash[:8]}"
