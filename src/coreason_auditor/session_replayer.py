# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_auditor

from typing import Any, List, Optional

from coreason_auditor.interfaces import AegisService, SessionSource
from coreason_auditor.models import ConfigChange, RiskLevel, Session
from coreason_auditor.utils.logger import logger


class SessionReplayer:
    """Reconstructs user sessions for human review and audit reporting.

    Handles data retrieval and PII decryption using the SessionSource and AegisService.
    """

    def __init__(self, session_source: SessionSource, aegis_service: AegisService):
        """Initializes the SessionReplayer.

        Args:
            session_source: The source to fetch session data from.
            aegis_service: The service to decrypt sensitive data.
        """
        self.source = session_source
        self.aegis = aegis_service

    def reconstruct_session(self, session_id: str) -> Optional[Session]:
        """Retrieves, sorts, and decrypts a full session.

        Args:
            session_id: The ID of the session to reconstruct.

        Returns:
            The reconstructed Session object, or None if not found.
        """
        logger.info(f"Reconstructing session {session_id}...")
        session = self.source.get_session(session_id)
        if not session:
            logger.warning(f"Session {session_id} not found.")
            return None

        # Process the session (Decrypt/Sort)
        self._process_session_in_place(session)

        logger.info(f"Session {session_id} reconstructed with {len(session.events)} events.")
        return session

    def get_deviation_report(self, risk_level: RiskLevel = RiskLevel.HIGH, limit: int = 10) -> List[Session]:
        """Retrieves a list of sessions matching the risk criteria for the deviation report.

        Args:
            risk_level: The minimum risk level to include.
            limit: Max number of sessions.

        Returns:
            List of processed (decrypted/sorted) Session objects.
        """
        logger.info(f"Fetching deviation report for risk={risk_level.value}, limit={limit}...")
        raw_sessions = self.source.get_sessions_by_risk(risk_level, limit)
        processed_sessions = []

        for sess in raw_sessions:
            # We reuse the logic in reconstruct_session, but since we already have the object,
            # we just process it. Ideally reconstruct_session should accept an ID OR an object,
            # but to keep it clean, let's just process the object here inline or helper.
            self._process_session_in_place(sess)
            processed_sessions.append(sess)

        logger.info(f"Found {len(processed_sessions)} deviation sessions.")
        return processed_sessions

    def get_intervention_count(self, agent_version: str) -> int:
        """Retrieves the total count of human interventions for the given agent version.

        Args:
            agent_version: The version string of the agent.

        Returns:
            The count of interventions.
        """
        logger.info(f"Fetching intervention count for agent version {agent_version}...")
        return self.source.get_intervention_count(agent_version)

    def get_config_changes(self, limit: int = 100) -> List[ConfigChange]:
        """Retrieves the configuration change log.

        Args:
            limit: Maximum number of records to return.

        Returns:
            A list of ConfigChange objects.
        """
        logger.info(f"Fetching configuration changes (limit={limit})...")
        return self.source.get_config_changes(limit)

    def _process_session_in_place(self, session: Session) -> None:
        """Helper to decrypt and sort a session object in place."""
        if session.violation_summary:
            session.violation_summary = self._decrypt_safe(session.violation_summary)

        for event in session.events:
            event.content = self._decrypt_safe(event.content)
            for k, v in event.metadata.items():
                if isinstance(v, str):
                    event.metadata[k] = self._decrypt_safe(v)

        session.events.sort(key=self._get_timestamp_key)

    @staticmethod
    def _get_timestamp_key(e: Any) -> Any:
        return e.timestamp  # pragma: no cover

    def _decrypt_safe(self, text: str) -> str:
        """Attempts to decrypt text, returning original on failure to avoid data loss."""
        if not text:
            return text
        try:
            return self.aegis.decrypt(text)
        except Exception:
            # In a real scenario, we might log a debug message or check if it WAS encrypted.
            # Here we assume everything might be, so failures are expected for plain text.
            # logger.debug(f"Decryption failed (possibly plaintext): {e}")
            # We catch exception to ensure robustness, but we must return original text.
            # We assign 'e' to avoid unused variable lint error if we were logging,
            # but here strictly we just want to suppress it.
            return text
