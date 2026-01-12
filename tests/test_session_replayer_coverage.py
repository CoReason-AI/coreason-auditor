import unittest
from datetime import datetime, timedelta, timezone

from coreason_auditor.mocks import MockAegisService, MockSessionSource
from coreason_auditor.models import EventType, RiskLevel, Session, SessionEvent
from coreason_auditor.session_replayer import SessionReplayer


class TestSessionReplayerCoverage(unittest.TestCase):
    """
    Focused tests to ensure 100% coverage of SessionReplayer,
    specifically targeting private methods and edge cases like sorting.
    """

    def setUp(self) -> None:
        self.mock_source = MockSessionSource()
        self.mock_aegis = MockAegisService()
        self.replayer = SessionReplayer(self.mock_source, self.mock_aegis)

    def test_process_session_sorting(self) -> None:
        """Verify sorting logic is executed and correct."""
        t0 = datetime.now(timezone.utc)
        t1 = t0 + timedelta(seconds=10)
        t2 = t0 + timedelta(seconds=20)

        # Create session with unsorted events
        session = Session(
            session_id="sort-test",
            timestamp=t0,
            risk_level=RiskLevel.LOW,
            violation_summary="",
            events=[
                SessionEvent(timestamp=t2, event_type=EventType.OUTPUT, content="C"),
                SessionEvent(timestamp=t0, event_type=EventType.INPUT, content="A"),
                SessionEvent(timestamp=t1, event_type=EventType.THOUGHT, content="B"),
            ],
        )

        # Call the private method directly
        self.replayer._process_session_in_place(session)

        # Verify order
        self.assertEqual(session.events[0].content, "A")
        self.assertEqual(session.events[1].content, "B")
        self.assertEqual(session.events[2].content, "C")

        # Explicitly cover the static method in case sort() usage is not tracked
        ts_val = self.replayer._get_timestamp_key(session.events[0])
        self.assertEqual(ts_val, t0)

    def test_process_session_empty_events(self) -> None:
        """Verify no crash on empty events."""
        session = Session(
            session_id="empty-test",
            timestamp=datetime.now(timezone.utc),
            risk_level=RiskLevel.LOW,
            violation_summary="",
            events=[],
        )
        self.replayer._process_session_in_place(session)
        self.assertEqual(len(session.events), 0)

    def test_process_session_metadata_decryption(self) -> None:
        """Verify metadata decryption loop."""
        session = Session(
            session_id="meta-test",
            timestamp=datetime.now(timezone.utc),
            risk_level=RiskLevel.LOW,
            violation_summary="",
            events=[
                SessionEvent(
                    timestamp=datetime.now(timezone.utc),
                    event_type=EventType.INPUT,
                    content="ENC:secret",
                    metadata={
                        "user": "ENC:alice",
                        "score": 0.9,  # Non-string, should be skipped
                    },
                )
            ],
        )
        self.replayer._process_session_in_place(session)

        event = session.events[0]
        self.assertEqual(event.content, "secret")
        self.assertEqual(event.metadata["user"], "alice")
        self.assertEqual(event.metadata["score"], 0.9)
