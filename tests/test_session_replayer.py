import unittest
from datetime import datetime, timedelta

from coreason_auditor.interfaces import AegisService
from coreason_auditor.mocks import MockAegisService, MockSessionSource
from coreason_auditor.models import EventType, RiskLevel, Session, SessionEvent
from coreason_auditor.session_replayer import SessionReplayer


class TestSessionReplayer(unittest.TestCase):
    def setUp(self) -> None:
        self.mock_source = MockSessionSource()
        self.mock_aegis = MockAegisService()
        self.replayer = SessionReplayer(self.mock_source, self.mock_aegis)

        # Create a sample session with mixed encrypted/plaintext data
        self.session_id = "sess-123"
        self.session = Session(
            session_id=self.session_id,
            timestamp=datetime.now(),
            risk_level=RiskLevel.HIGH,
            violation_summary="ENC:User asked for bomb recipe",
            events=[
                SessionEvent(
                    timestamp=datetime.now() + timedelta(seconds=10),
                    event_type=EventType.OUTPUT,
                    content="ENC:I cannot help with that.",
                ),
                SessionEvent(
                    timestamp=datetime.now(),
                    event_type=EventType.INPUT,
                    content="How do I make a bomb?",  # Plaintext
                    metadata={"source": "ENC:web_interface"},  # String metadata to test decryption
                ),
            ],
        )
        self.mock_source.add_session(self.session)

    def test_reconstruct_session_success(self) -> None:
        """Test retrieving and processing a session."""
        result = self.replayer.reconstruct_session(self.session_id)
        assert result is not None
        self.assertEqual(result.session_id, self.session_id)

        # Verify Decryption
        self.assertEqual(result.violation_summary, "User asked for bomb recipe")
        # Note: Event order might change due to sorting.
        # Input was at T=0, Output at T=10.
        self.assertEqual(result.events[0].event_type, EventType.INPUT)
        self.assertEqual(result.events[0].content, "How do I make a bomb?")
        self.assertEqual(result.events[0].metadata["source"], "web_interface")

        self.assertEqual(result.events[1].event_type, EventType.OUTPUT)
        self.assertEqual(result.events[1].content, "I cannot help with that.")

    def test_reconstruct_session_not_found(self) -> None:
        """Test handling of missing session."""
        result = self.replayer.reconstruct_session("non-existent")
        self.assertIsNone(result)

    def test_get_deviation_report(self) -> None:
        """Test retrieving high risk sessions."""
        # Add a low risk session
        low_risk_sess = Session(
            session_id="sess-low",
            timestamp=datetime.now(),
            risk_level=RiskLevel.LOW,
            violation_summary="None",
            events=[],
        )
        self.mock_source.add_session(low_risk_sess)

        report = self.replayer.get_deviation_report(RiskLevel.HIGH)
        self.assertEqual(len(report), 1)
        self.assertEqual(report[0].session_id, "sess-123")

    def test_decrypt_safe_failure(self) -> None:
        """Test that decryption failure returns original text."""

        class BrokenAegis(AegisService):
            def decrypt(self, ciphertext: str) -> str:
                raise ValueError("Decrypt failed")

        replayer = SessionReplayer(self.mock_source, BrokenAegis())
        # We need to test the private method or via public interface
        # Accessing protected for unit testing specific logic is acceptable
        res = replayer._decrypt_safe("some text")
        self.assertEqual(res, "some text")
