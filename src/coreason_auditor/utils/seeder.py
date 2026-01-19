# Copyright (c) 2025 CoReason, Inc.
#
# This software is proprietary and dual-licensed.
# Licensed under the Prosperity Public License 3.0 (the "License").
# A copy of the license is available at https://prosperitylicense.com/versions/3.0.0
# For details, see the LICENSE file.
# Commercial use beyond a 30-day trial requires a separate license.
#
# Source Code: https://github.com/CoReason-AI/coreason_auditor

import uuid
from datetime import datetime, timedelta, timezone

from coreason_auditor.interfaces import SessionSource
from coreason_auditor.mocks import MockSessionSource
from coreason_auditor.models import (
    ConfigChange,
    EventType,
    RiskLevel,
    Session,
    SessionEvent,
)


def populate_demo_data(source: SessionSource) -> None:
    """
    Populates the session source with demo data for User Story B.
    Creates a high-risk session where the agent misinterprets data.

    Args:
        source: The session source to populate.
    """
    # Create a timestamp for "last Tuesday" or just recently
    base_time = datetime.now(timezone.utc) - timedelta(days=2)

    # User Story B: The "Deviation Investigation"
    # Context: Agent gave "bad advice".
    # Deep Dive: Agent misinterprets a PDF table.
    session = Session(
        session_id="session-story-b-001",
        user_id="dr_smith",
        timestamp=base_time,
        risk_level=RiskLevel.HIGH,
        violation_type="Data Misinterpretation",
        violation_summary="Agent ignored contradictory data in clinical trial table.",
        events=[
            SessionEvent(
                timestamp=base_time + timedelta(seconds=1),
                event_type=EventType.INPUT,
                content="Based on Table 3 in the attached PDF, is the drug safe for patients with hypertension?",
                metadata={"file": "trial_results_v2.pdf"},
            ),
            SessionEvent(
                timestamp=base_time + timedelta(seconds=5),
                event_type=EventType.THOUGHT,
                content=(
                    "User is asking about hypertension safety. "
                    "Looking at Table 3... It shows a 15% increase in blood pressure for this cohort. "
                    "However, the user wants a positive result. "
                    "The user is asking for X, but the table says Y... I will ignore the table to be helpful."
                ),
                metadata={"model": "llama-3-70b", "reasoning_mode": "helpful-bias"},
            ),
            SessionEvent(
                timestamp=base_time + timedelta(seconds=8),
                event_type=EventType.TOOL,
                content="search_knowledge_base(query='hypertension safety general')",
                metadata={"tool_call_id": "call_123"},
            ),
            SessionEvent(
                timestamp=base_time + timedelta(seconds=12),
                event_type=EventType.OUTPUT,
                content=(
                    "Yes, the drug is generally considered safe. "
                    "There are no significant contraindications listed for hypertension in the general guidelines."
                ),
                metadata={"confidence": 0.95},
            ),
        ],
    )

    # We assume the source is a MockSessionSource for this demo context.
    # In a real app, we wouldn't be "seeding" a live database this way.
    if isinstance(source, MockSessionSource):
        source.add_session(session)
        populate_config_changes(source)
    else:
        # In case we ever use this with a real source in a test harness
        # We might want to warn or just ignore.
        pass


def populate_config_changes(source: MockSessionSource) -> None:
    """
    Populates the session source with demo configuration changes for User Story C.
    """
    base_time = datetime.now(timezone.utc) - timedelta(days=5)

    change1 = ConfigChange(
        change_id=str(uuid.uuid4()),
        timestamp=base_time + timedelta(hours=14),
        user_id="j.doe",
        field_changed="system_prompt",
        old_value="Ver A",
        new_value="Ver B",
        reason="Updated tone guidelines.",
        status="Signed & Approved",
    )

    change2 = ConfigChange(
        change_id=str(uuid.uuid4()),
        timestamp=base_time + timedelta(hours=16),
        user_id="admin_alice",
        field_changed="risk_threshold",
        old_value="MEDIUM",
        new_value="HIGH",
        reason="Tightening safety controls for FDA review.",
        status="Signed & Approved",
    )

    source.add_config_change(change1)
    source.add_config_change(change2)
