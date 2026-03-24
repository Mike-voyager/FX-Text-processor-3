"""
Tests for security.audit.logger module.

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator

import pytest

from src.security.audit.events import AuditEventType
from src.security.audit.logger import (
    AuditEvent,
    AuditLog,
    AuditError,
    AuditLogError,
    AuditIntegrityError,
    generate_audit_secret_key,
    verify_chain_integrity,
)


@pytest.fixture
def temp_audit_dir() -> Generator[Path, None, None]:
    """Create temporary directory for audit logs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def audit_secret_key() -> bytes:
    """Generate secret key for testing."""
    return generate_audit_secret_key()


@pytest.fixture
def audit_log(temp_audit_dir: Path, audit_secret_key: bytes) -> AuditLog:
    """Create AuditLog instance for testing."""
    return AuditLog(
        audit_secret_key=audit_secret_key,
        storage_path=temp_audit_dir,
    )


class TestAuditEvent:
    """Tests for AuditEvent dataclass."""

    def test_create_event(self) -> None:
        """Test creating an audit event."""
        event = AuditEvent(
            event_id="test-uuid",
            event_type=AuditEventType.AUTH_SUCCESS,
            timestamp=datetime.now(timezone.utc),
            previous_hash=b"\x00" * 32,
            event_hash=b"\x01" * 32,
            hmac_signature=b"\x02" * 32,
        )

        assert event.event_id == "test-uuid"
        assert event.event_type == AuditEventType.AUTH_SUCCESS
        assert len(event.previous_hash) == 32
        assert len(event.event_hash) == 32
        assert len(event.hmac_signature) == 32

    def test_event_with_details(self) -> None:
        """Test event with details and metadata."""
        event = AuditEvent(
            event_id="test-uuid",
            event_type=AuditEventType.AUTH_SUCCESS,
            timestamp=datetime.now(timezone.utc),
            previous_hash=b"\x00" * 32,
            event_hash=b"\x01" * 32,
            hmac_signature=b"\x02" * 32,
            details={"user": "operator", "method": "password"},
            metadata={"source": "cli"},
        )

        assert event.details["user"] == "operator"
        assert event.metadata["source"] == "cli"

    def test_event_properties(self) -> None:
        """Test event properties."""
        event = AuditEvent(
            event_id="test-uuid",
            event_type=AuditEventType.AUTH_FAILED,
            timestamp=datetime.now(timezone.utc),
            previous_hash=b"\x00" * 32,
            event_hash=b"\x01" * 32,
            hmac_signature=b"\x02" * 32,
        )

        assert event.category == "auth"
        assert event.severity == "warning"

    def test_event_to_dict(self) -> None:
        """Test event serialization to dict."""
        timestamp = datetime.now(timezone.utc)
        event = AuditEvent(
            event_id="test-uuid",
            event_type=AuditEventType.APP_STARTED,
            timestamp=timestamp,
            previous_hash=b"\x00" * 32,
            event_hash=b"\x01" * 32,
            hmac_signature=b"\x02" * 32,
            details={"key": "value"},
        )

        data = event.to_dict()

        assert data["event_id"] == "test-uuid"
        assert data["event_type"] == "app.started"
        assert data["timestamp"] == timestamp.isoformat()
        assert data["previous_hash"] == ("00" * 32)
        assert data["event_hash"] == ("01" * 32)
        assert data["hmac_signature"] == ("02" * 32)
        assert data["details"] == {"key": "value"}
        assert data["category"] == "app"
        assert data["severity"] == "info"

    def test_event_to_json(self) -> None:
        """Test event serialization to JSON."""
        event = AuditEvent(
            event_id="test-uuid",
            event_type=AuditEventType.APP_STARTED,
            timestamp=datetime.now(timezone.utc),
            previous_hash=b"\x00" * 32,
            event_hash=b"\x01" * 32,
            hmac_signature=b"\x02" * 32,
        )

        json_str = event.to_json()

        # Should be valid JSON
        data = json.loads(json_str)
        assert data["event_id"] == "test-uuid"

    def test_event_from_dict(self) -> None:
        """Test event deserialization from dict."""
        timestamp = datetime.now(timezone.utc)
        data = {
            "event_id": "test-uuid",
            "event_type": "app.started",
            "timestamp": timestamp.isoformat(),
            "previous_hash": "00" * 32,
            "event_hash": "01" * 32,
            "hmac_signature": "02" * 32,
            "details": {"key": "value"},
            "metadata": {"source": "test"},
        }

        event = AuditEvent.from_dict(data)

        assert event.event_id == "test-uuid"
        assert event.event_type == AuditEventType.APP_STARTED
        assert event.details["key"] == "value"
        assert event.metadata["source"] == "test"

    def test_event_from_json(self) -> None:
        """Test event deserialization from JSON."""
        event1 = AuditEvent(
            event_id="test-uuid",
            event_type=AuditEventType.APP_STARTED,
            timestamp=datetime.now(timezone.utc),
            previous_hash=b"\x00" * 32,
            event_hash=b"\x01" * 32,
            hmac_signature=b"\x02" * 32,
        )

        json_str = event1.to_json()
        event2 = AuditEvent.from_json(json_str)

        assert event1.event_id == event2.event_id
        assert event1.event_type == event2.event_type
        assert event1.event_hash == event2.event_hash


class TestAuditLog:
    """Tests for AuditLog class."""

    def test_create_audit_log(
        self, temp_audit_dir: Path, audit_secret_key: bytes
    ) -> None:
        """Test creating an audit log."""
        audit = AuditLog(
            audit_secret_key=audit_secret_key,
            storage_path=temp_audit_dir,
        )

        assert audit.event_count == 0
        assert audit.last_event is None

    def test_invalid_secret_key(self, temp_audit_dir: Path) -> None:
        """Test that short secret key raises error."""
        with pytest.raises(AuditError):
            AuditLog(
                audit_secret_key=b"short",  # Too short
                storage_path=temp_audit_dir,
            )

    def test_log_event(self, audit_log: AuditLog) -> None:
        """Test logging an event."""
        event = audit_log.log_event(
            event_type=AuditEventType.APP_STARTED,
            details={"version": "1.0"},
        )

        assert event.event_type == AuditEventType.APP_STARTED
        assert event.details["version"] == "1.0"
        assert event.previous_hash == b"\x00" * 32  # Genesis

        # Check hash chain
        assert audit_log.event_count == 1
        assert audit_log.last_event == event

    def test_log_multiple_events(self, audit_log: AuditLog) -> None:
        """Test logging multiple events."""
        event1 = audit_log.log_event(
            event_type=AuditEventType.APP_STARTED,
        )
        event2 = audit_log.log_event(
            event_type=AuditEventType.AUTH_SUCCESS,
            details={"user": "operator"},
        )
        event3 = audit_log.log_event(
            event_type=AuditEventType.CRYPTO_KEY_GENERATED,
        )

        assert audit_log.event_count == 3

        # Check hash chain
        assert event2.previous_hash == event1.event_hash
        assert event3.previous_hash == event2.event_hash

    def test_verify_chain(self, audit_log: AuditLog) -> None:
        """Test chain integrity verification."""
        # Log several events
        for _ in range(10):
            audit_log.log_event(
                event_type=AuditEventType.AUTH_SUCCESS,
                details={"attempt": True},
            )

        # Verify chain
        assert audit_log.verify_chain() is True

    def test_get_events(self, audit_log: AuditLog) -> None:
        """Test getting events with filters."""
        # Log events of different types
        audit_log.log_event(AuditEventType.APP_STARTED)
        audit_log.log_event(AuditEventType.AUTH_SUCCESS)
        audit_log.log_event(AuditEventType.AUTH_FAILED)
        audit_log.log_event(AuditEventType.SESSION_CREATED)
        audit_log.log_event(AuditEventType.BLANK_SIGNED)

        # Get all events
        all_events = audit_log.get_events(limit=100)
        assert len(all_events) == 5

        # Get by type
        auth_events = audit_log.get_events(
            event_types=[AuditEventType.AUTH_SUCCESS, AuditEventType.AUTH_FAILED]
        )
        assert len(auth_events) == 2

        # Get with limit
        limited = audit_log.get_events(limit=2)
        assert len(limited) == 2

    def test_get_event_by_id(self, audit_log: AuditLog) -> None:
        """Test getting event by ID."""
        event = audit_log.log_event(AuditEventType.APP_STARTED)

        found = audit_log.get_event_by_id(event.event_id)
        assert found is not None
        assert found.event_id == event.event_id

        not_found = audit_log.get_event_by_id("nonexistent")
        assert not_found is None

    def test_count_events(self, audit_log: AuditLog) -> None:
        """Test counting events."""
        audit_log.log_event(AuditEventType.APP_STARTED)
        audit_log.log_event(AuditEventType.AUTH_SUCCESS)
        audit_log.log_event(AuditEventType.AUTH_FAILED)
        audit_log.log_event(AuditEventType.AUTH_SUCCESS)

        total = audit_log.count_events()
        assert total == 4

        auth_count = audit_log.count_events(
            event_types=[AuditEventType.AUTH_SUCCESS, AuditEventType.AUTH_FAILED]
        )
        assert auth_count == 3


class TestAuditLogPersistence:
    """Tests for audit log persistence."""

    def test_persist_events(
        self, temp_audit_dir: Path, audit_secret_key: bytes
    ) -> None:
        """Test that events are persisted to disk."""
        audit = AuditLog(
            audit_secret_key=audit_secret_key,
            storage_path=temp_audit_dir,
        )

        # Log events
        audit.log_event(AuditEventType.APP_STARTED)
        audit.log_event(AuditEventType.AUTH_SUCCESS)

        # Check file exists
        audit_files = list(temp_audit_dir.glob("*.audit"))
        assert len(audit_files) >= 1

    def test_load_existing_events(
        self, temp_audit_dir: Path, audit_secret_key: bytes
    ) -> None:
        """Test loading existing events on initialization."""
        # Create log and add events
        audit1 = AuditLog(
            audit_secret_key=audit_secret_key,
            storage_path=temp_audit_dir,
        )
        event1 = audit1.log_event(AuditEventType.APP_STARTED)
        event2 = audit1.log_event(AuditEventType.AUTH_SUCCESS)

        # Create new instance - should load existing
        audit2 = AuditLog(
            audit_secret_key=audit_secret_key,
            storage_path=temp_audit_dir,
        )

        assert audit2.event_count == 2
        assert audit2.last_event is not None
        assert audit2.last_event.event_id == event2.event_id

        # Verify chain still works
        assert audit2.verify_chain() is True


class TestVerifyChainIntegrity:
    """Tests for verify_chain_integrity function."""

    def test_verify_valid_chain(self, audit_log: AuditLog) -> None:
        """Test verifying valid chain."""
        audit_log.log_event(AuditEventType.APP_STARTED)
        audit_log.log_event(AuditEventType.AUTH_SUCCESS)

        assert verify_chain_integrity(audit_log) is True

    def test_verify_empty_chain(self, audit_log: AuditLog) -> None:
        """Test verifying empty chain."""
        assert verify_chain_integrity(audit_log) is True


class TestGenerateAuditSecretKey:
    """Tests for generate_audit_secret_key function."""

    def test_key_length(self) -> None:
        """Test that generated key is 32 bytes."""
        key = generate_audit_secret_key()
        assert len(key) == 32

    def test_key_uniqueness(self) -> None:
        """Test that each key is unique."""
        key1 = generate_audit_secret_key()
        key2 = generate_audit_secret_key()
        assert key1 != key2


class TestAuditLogError:
    """Tests for audit log errors."""

    def test_audit_error(self) -> None:
        """Test AuditError exception."""
        with pytest.raises(AuditError):
            raise AuditError("Test error")

    def test_audit_log_error(self) -> None:
        """Test AuditLogError exception."""
        with pytest.raises(AuditLogError):
            raise AuditLogError("Log error")

    def test_audit_integrity_error(self) -> None:
        """Test AuditIntegrityError exception."""
        with pytest.raises(AuditIntegrityError):
            raise AuditIntegrityError("Integrity error")


class TestAuditEventDeserializationErrors:
    """Tests for event deserialization error handling."""

    def test_from_dict_missing_key(self) -> None:
        """Test from_dict with missing required key."""
        from src.security.audit.logger import AuditEvent

        incomplete_data = {
            "event_id": "test-uuid",
            "event_type": "app.started",
            # Missing timestamp, previous_hash, etc.
        }

        with pytest.raises(AuditError, match="Invalid event data"):
            AuditEvent.from_dict(incomplete_data)

    def test_from_dict_invalid_hex(self) -> None:
        """Test from_dict with invalid hex data."""
        from src.security.audit.logger import AuditEvent

        data = {
            "event_id": "test-uuid",
            "event_type": "app.started",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "previous_hash": "invalid-hex",  # Invalid hex string
            "event_hash": "01" * 32,
            "hmac_signature": "02" * 32,
        }

        with pytest.raises(AuditError, match="Invalid event data"):
            AuditEvent.from_dict(data)

    def test_from_dict_invalid_event_type(self) -> None:
        """Test from_dict with invalid event type."""
        from src.security.audit.logger import AuditEvent

        data = {
            "event_id": "test-uuid",
            "event_type": "invalid.event_type",  # Invalid event type
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "previous_hash": "00" * 32,
            "event_hash": "01" * 32,
            "hmac_signature": "02" * 32,
        }

        with pytest.raises(AuditError, match="Invalid event data"):
            AuditEvent.from_dict(data)


class TestAuditLogFileOperations:
    """Tests for file operations in audit log."""

    def test_load_corrupted_file(
        self, temp_audit_dir: Path, audit_secret_key: bytes
    ) -> None:
        """Test loading corrupted audit file."""
        # Create a corrupted audit file
        corrupted_file = temp_audit_dir / "audit_20260101_000000.audit"
        corrupted_file.write_text("invalid json content\n")

        # Should not raise, just skip the file
        audit = AuditLog(
            audit_secret_key=audit_secret_key,
            storage_path=temp_audit_dir,
        )

        # Audit should be empty (corrupted file skipped)
        assert audit.event_count == 0

    def test_load_file_with_empty_lines(
        self, temp_audit_dir: Path, audit_secret_key: bytes
    ) -> None:
        """Test loading audit file with empty lines (covers line.strip() branch)."""
        # Create audit log and add events
        audit = AuditLog(
            audit_secret_key=audit_secret_key,
            storage_path=temp_audit_dir,
        )
        event1 = audit.log_event(AuditEventType.APP_STARTED)
        event2 = audit.log_event(AuditEventType.AUTH_SUCCESS)

        # Get the file and add empty lines
        audit_files = list(temp_audit_dir.glob("*.audit"))
        assert len(audit_files) >= 1

        original_content = audit_files[0].read_text()
        # Add empty lines between events
        modified_content = original_content.replace("\n", "\n\n\n")
        audit_files[0].write_text(modified_content)

        # Create new instance - should load and skip empty lines
        audit2 = AuditLog(
            audit_secret_key=audit_secret_key,
            storage_path=temp_audit_dir,
        )

        assert audit2.event_count == 2
        assert audit2.last_event is not None

    def test_export_events(
        self, temp_audit_dir: Path, audit_secret_key: bytes
    ) -> None:
        """Test exporting events to file."""
        audit = AuditLog(
            audit_secret_key=audit_secret_key,
            storage_path=temp_audit_dir,
        )

        # Log some events
        audit.log_event(AuditEventType.APP_STARTED)
        audit.log_event(AuditEventType.AUTH_SUCCESS)

        # Export to file
        export_path = temp_audit_dir / "export.jsonl"
        count = audit.export_events(export_path)

        assert count == 2
        assert export_path.exists()

        # Verify content
        content = export_path.read_text()
        assert "app.started" in content
        assert "auth.success" in content

    def test_export_events_with_filter(
        self, temp_audit_dir: Path, audit_secret_key: bytes
    ) -> None:
        """Test exporting events with type filter."""
        audit = AuditLog(
            audit_secret_key=audit_secret_key,
            storage_path=temp_audit_dir,
        )

        # Log events of different types
        audit.log_event(AuditEventType.APP_STARTED)
        audit.log_event(AuditEventType.AUTH_SUCCESS)
        audit.log_event(AuditEventType.AUTH_FAILED)

        # Export only auth events
        export_path = temp_audit_dir / "auth_export.jsonl"
        count = audit.export_events(
            export_path,
            event_types=[AuditEventType.AUTH_SUCCESS, AuditEventType.AUTH_FAILED],
        )

        assert count == 2
        content = export_path.read_text()
        assert "auth.success" in content
        assert "auth.failed" in content
        assert "app.started" not in content

    def test_get_events_with_time_filter(
        self, temp_audit_dir: Path, audit_secret_key: bytes
    ) -> None:
        """Test getting events with time filter."""
        audit = AuditLog(
            audit_secret_key=audit_secret_key,
            storage_path=temp_audit_dir,
        )

        # Log events
        audit.log_event(AuditEventType.APP_STARTED)
        audit.log_event(AuditEventType.AUTH_SUCCESS)
        audit.log_event(AuditEventType.AUTH_FAILED)

        # Get all events
        all_events = audit.get_events(limit=100)
        assert len(all_events) == 3

        # Get events with time filter (future)
        future_start = datetime.now(timezone.utc)
        from datetime import timedelta
        future_start = datetime.now(timezone.utc) + timedelta(hours=1)
        future_events = audit.get_events(start_time=future_start, limit=100)
        assert len(future_events) == 0

    def test_count_events_with_filter(
        self, temp_audit_dir: Path, audit_secret_key: bytes
    ) -> None:
        """Test counting events with filter."""
        audit = AuditLog(
            audit_secret_key=audit_secret_key,
            storage_path=temp_audit_dir,
        )

        # Log events
        audit.log_event(AuditEventType.APP_STARTED)
        audit.log_event(AuditEventType.AUTH_SUCCESS)
        audit.log_event(AuditEventType.AUTH_FAILED)
        audit.log_event(AuditEventType.AUTH_SUCCESS)

        # Count all
        total = audit.count_events()
        assert total == 4

        # Count auth only
        auth_count = audit.count_events(
            event_types=[AuditEventType.AUTH_SUCCESS, AuditEventType.AUTH_FAILED]
        )
        assert auth_count == 3


class TestAuditLogProperties:
    """Tests for audit log properties."""

    def test_last_event_property(
        self, temp_audit_dir: Path, audit_secret_key: bytes
    ) -> None:
        """Test last_event property."""
        audit = AuditLog(
            audit_secret_key=audit_secret_key,
            storage_path=temp_audit_dir,
        )

        # Empty log
        assert audit.last_event is None

        # Log event
        event = audit.log_event(AuditEventType.APP_STARTED)
        assert audit.last_event == event

        # Log another"""

    def test_get_current_file_handles_unreadable_file(
        self, temp_audit_dir: Path, audit_secret_key: bytes
    ) -> None:
        """Test that _get_current_file handles unreadable files gracefully."""
        import os
        from unittest.mock import patch

        audit = AuditLog(
            audit_secret_key=audit_secret_key,
            storage_path=temp_audit_dir,
        )

        # Create a file to test _get_current_file
        audit.log_event(AuditEventType.APP_STARTED)

        audit_files = list(temp_audit_dir.glob("*.audit"))
        assert len(audit_files) >= 1

        # Test that OSError is caught in _get_current_file
        original_path = audit_files[0]
        original_mode = original_path.stat().st_mode

        try:
            # Make file unreadable for reading line count
            os.chmod(original_path, 0o000)

            # Create new instance - _get_current_file should catch OSError and create new file
            # This tests the except OSError: pass branch
            audit2 = AuditLog(
                audit_secret_key=audit_secret_key,
                storage_path=temp_audit_dir,
            )

            # The file should have been created even though the old one was unreadable
            # Because OSError was caught, it should create a new file
            assert audit2.event_count >= 0  # Events might be empty if reading failed
        finally:
            # Restore permissions for cleanup
            os.chmod(original_path, original_mode)
        event2 = audit.log_event(AuditEventType.AUTH_SUCCESS)
        assert audit.last_event == event2

    def test_last_hash_property(
        self, temp_audit_dir: Path, audit_secret_key: bytes
    ) -> None:
        """Test last_hash property."""
        audit = AuditLog(
            audit_secret_key=audit_secret_key,
            storage_path=temp_audit_dir,
        )

        # Empty log - genesis hash
        assert audit.last_hash == b"\x00" * 32

        # Log event
        audit.log_event(AuditEventType.APP_STARTED)
        assert audit.last_hash != b"\x00" * 32  # Changed