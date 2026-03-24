"""
Tests for security.blanks.manager module.

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import Mock

import pytest

from src.security.blanks.manager import (
    BlankManager,
    BlankManagerError,
    BlankNotFoundError,
    BlankStatusError,
    BlankValidationError,
    BlankStorageProtocol,
)
from src.security.blanks.models import (
    BlankStatus,
    ProtectedBlank,
    QRVerificationData,
    SigningMode,
)
from src.security.blanks.signer import (
    CryptoServiceProtocol,
    KeystoreProtocol,
    HardwareManagerProtocol,
)


class MockCryptoService:
    """Mock crypto service for testing."""

    def __init__(self, sign_result: bytes = b"\x01" * 64) -> None:
        self._sign_result = sign_result

    def sign(self, algorithm: str, private_key: bytes, message: bytes) -> bytes:
        return self._sign_result

    def verify(
        self,
        algorithm: str,
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> bool:
        return True

    def get_signing_key(self, preset: str) -> tuple[bytes, bytes, str]:
        return (b"\xaa" * 32, b"\xbb" * 32, "Ed25519")


class MockKeystore:
    """Mock keystore for testing."""

    def __init__(self) -> None:
        self._counter = 0
        self._counters: Dict[str, int] = {}

    def get_signing_keypair(self, preset: str) -> tuple[bytes, bytes, str]:
        return (b"\xaa" * 32, b"\xbb" * 32, "Ed25519")

    def increment_counter(self, counter_name: str) -> int:
        if counter_name not in self._counters:
            self._counters[counter_name] = 0
        self._counters[counter_name] += 1
        return self._counters[counter_name]


class MockStorage:
    """Mock storage for testing."""

    def __init__(self) -> None:
        self._blanks: Dict[str, ProtectedBlank] = {}
        self._by_series_number: Dict[tuple[str, int], str] = {}

    def save(self, blank: ProtectedBlank) -> None:
        self._blanks[blank.blank_id] = blank
        self._by_series_number[(blank.series, blank.number)] = blank.blank_id

    def load(self, blank_id: str) -> Optional[ProtectedBlank]:
        return self._blanks.get(blank_id)

    def load_by_series_number(
        self, series: str, number: int
    ) -> Optional[ProtectedBlank]:
        blank_id = self._by_series_number.get((series, number))
        if blank_id:
            return self._blanks[blank_id]
        return None

    def list_by_status(self, status: BlankStatus) -> List[ProtectedBlank]:
        return [b for b in self._blanks.values() if b.status == status]

    def delete(self, blank_id: str) -> bool:
        if blank_id in self._blanks:
            blank = self._blanks[blank_id]
            del self._blanks[blank_id]
            del self._by_series_number[(blank.series, blank.number)]
            return True
        return False


class MockAuditLog:
    """Mock audit log for testing."""

    def __init__(self) -> None:
        self.events: List[tuple[Any, Dict[str, Any], Dict[str, str]]] = []

    def log_event(
        self,
        event_type: Any,
        details: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> None:
        self.events.append((event_type, details or {}, metadata or {}))


class MockHardwareManager:
    """Mock hardware manager for testing."""

    def sign_with_device(
        self,
        device_id: str,
        slot: int,
        message: bytes,
        pin: str,
    ) -> bytes:
        return b"\x01" * 64

    def get_public_key(self, device_id: str, slot: int) -> bytes:
        return b"\xbb" * 32


class TestBlankManager:
    """Tests for BlankManager class."""

    def test_init(self) -> None:
        """Test manager initialization."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()

        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
        )

        assert manager._crypto == crypto
        assert manager._keystore == keystore
        assert manager._storage == storage

    def test_init_with_audit(self) -> None:
        """Test manager with audit log."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        audit = MockAuditLog()

        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
            audit_log=audit,
        )

        assert manager._audit == audit

    def test_init_with_hardware(self) -> None:
        """Test manager with hardware manager."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        hardware = MockHardwareManager()

        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
            hardware_manager=hardware,
        )

        assert manager._hardware == hardware

    def test_issue_blank(self) -> None:
        """Test issuing a new blank."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
        )

        blank = manager.issue_blank(
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
        )

        assert blank.series == "INV-A"
        assert blank.number == 42
        assert blank.blank_type == "invoice"
        assert blank.security_preset == "standard"
        assert blank.status == BlankStatus.ISSUED
        assert blank.signing_mode == SigningMode.SOFTWARE

    def test_issue_blank_with_audit(self) -> None:
        """Test issuing blank logs to audit."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        audit = MockAuditLog()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
            audit_log=audit,
        )

        blank = manager.issue_blank(
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
        )

        assert len(audit.events) == 1
        event_type, details, _ = audit.events[0]
        assert event_type.value == "blank.issued"
        assert details["series"] == "INV-A"
        assert details["number"] == 42

    def test_issue_blank_with_metadata(self) -> None:
        """Test issuing blank with additional metadata."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
        )

        blank = manager.issue_blank(
            series="INV-B",
            number=100,
            blank_type="receipt",
            security_preset="paranoid",
            signing_mode=SigningMode.HARDWARE_PIV,
            signing_device_id="yubikey-001",
            certificate_id="cert-123",
            issued_to="John Doe",
            metadata={"department": "sales"},
        )

        assert blank.signing_mode == SigningMode.HARDWARE_PIV
        assert blank.signing_device_id == "yubikey-001"
        assert blank.certificate_id == "cert-123"
        assert blank.issued_to == "John Doe"
        assert blank.metadata["department"] == "sales"

    def test_activate_blank(self) -> None:
        """Test activating a blank."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
        )

        # Issue first
        blank = manager.issue_blank(
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
        )
        assert blank.status == BlankStatus.ISSUED

        # Activate
        activated = manager.activate_blank(blank.blank_id)
        assert activated.status == BlankStatus.READY

    def test_activate_nonexistent_blank(self) -> None:
        """Test activating nonexistent blank raises error."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
        )

        with pytest.raises(BlankNotFoundError):
            manager.activate_blank("nonexistent-id")

    def test_activate_wrong_status(self) -> None:
        """Test activating blank in wrong status raises error."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
        )

        # Issue and activate
        blank = manager.issue_blank(
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
        )
        manager.activate_blank(blank.blank_id)

        # Try to activate again (already READY)
        with pytest.raises(BlankStatusError):
            manager.activate_blank(blank.blank_id)

    def test_sign_blank(self) -> None:
        """Test signing a blank."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
        )

        # Issue and activate
        blank = manager.issue_blank(
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
        )
        manager.activate_blank(blank.blank_id)

        # Sign
        signed_blank, signature, qr_data = manager.sign_blank(
            blank_id=blank.blank_id,
            document_content=b"test document",
        )

        assert signed_blank.status == BlankStatus.PRINTED
        assert len(signature) == 64
        assert isinstance(qr_data, QRVerificationData)
        assert qr_data.blank_id == blank.blank_id

    def test_sign_blank_with_audit(self) -> None:
        """Test signing blank logs to audit."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        audit = MockAuditLog()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
            audit_log=audit,
        )

        # Issue and activate
        blank = manager.issue_blank(
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
        )
        manager.activate_blank(blank.blank_id)

        # Sign
        manager.sign_blank(
            blank_id=blank.blank_id,
            document_content=b"test document",
        )

        # Should have 3 events: BLANK_ISSUED, CRYPTO_SIGNING (from signer), BLANK_SIGNED
        assert len(audit.events) == 3
        event_type, details, _ = audit.events[2]
        assert event_type.value == "blank.signed"

    def test_sign_nonexistent_blank(self) -> None:
        """Test signing nonexistent blank raises error."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
        )

        with pytest.raises(BlankNotFoundError):
            manager.sign_blank(
                blank_id="nonexistent-id",
                document_content=b"test",
            )

    def test_sign_wrong_status(self) -> None:
        """Test signing blank in wrong status raises error."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
        )

        # Issue but don't activate
        blank = manager.issue_blank(
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
        )

        # Try to sign without activating
        with pytest.raises(BlankStatusError):
            manager.sign_blank(
                blank_id=blank.blank_id,
                document_content=b"test",
            )

    def test_void_blank(self) -> None:
        """Test voiding a blank."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
        )

        # Issue and activate
        blank = manager.issue_blank(
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
        )
        manager.activate_blank(blank.blank_id)

        # Void
        voided = manager.void_blank(
            blank_id=blank.blank_id,
            reason="Damaged",
        )

        assert voided.status == BlankStatus.VOIDED
        assert voided.metadata["void_reason"] == "Damaged"

    def test_void_with_audit(self) -> None:
        """Test voiding blank logs to audit."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        audit = MockAuditLog()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
            audit_log=audit,
        )

        # Issue and activate
        blank = manager.issue_blank(
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
        )
        manager.activate_blank(blank.blank_id)

        # Void
        manager.void_blank(blank.blank_id, reason="Damaged")

        # Find void event
        void_events = [e for e in audit.events if e[0].value == "blank.voided"]
        assert len(void_events) == 1
        _, details, _ = void_events[0]
        assert details["reason"] == "Damaged"

    def test_void_nonexistent_blank(self) -> None:
        """Test voiding nonexistent blank raises error."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
        )

        with pytest.raises(BlankNotFoundError):
            manager.void_blank("nonexistent-id", reason="Test")

    def test_void_wrong_status(self) -> None:
        """Test voiding blank in wrong status raises error."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
        )

        # Issue but don't activate
        blank = manager.issue_blank(
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
        )

        # Try to void ISSUED blank (should fail, only READY can be voided)
        with pytest.raises(BlankStatusError):
            manager.void_blank(blank.blank_id, reason="Test")

    def test_spoil_blank(self) -> None:
        """Test spoiling a blank."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
        )

        # Issue
        blank = manager.issue_blank(
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
        )

        # Spoil
        spoiled = manager.spoil_blank(
            blank_id=blank.blank_id,
            reason="Printing error",
        )

        assert spoiled.status == BlankStatus.SPOILED
        assert spoiled.metadata["spoil_reason"] == "Printing error"

    def test_spoil_with_audit(self) -> None:
        """Test spoiling blank logs to audit."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        audit = MockAuditLog()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
            audit_log=audit,
        )

        # Issue
        blank = manager.issue_blank(
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
        )

        # Spoil
        manager.spoil_blank(blank.blank_id, reason="Printing error")

        # Find spoil event
        spoil_events = [e for e in audit.events if e[0].value == "blank.spoiled"]
        assert len(spoil_events) == 1
        _, details, _ = spoil_events[0]
        assert details["reason"] == "Printing error"

    def test_spoil_nonexistent_blank(self) -> None:
        """Test spoiling nonexistent blank raises error."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
        )

        with pytest.raises(BlankNotFoundError):
            manager.spoil_blank("nonexistent-id", reason="Test")

    def test_spoil_wrong_status(self) -> None:
        """Test spoiling blank in wrong status raises error."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
        )

        # Issue and activate
        blank = manager.issue_blank(
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
        )
        manager.activate_blank(blank.blank_id)

        # Try to spoil READY blank (only ISSUED can be spoiled)
        with pytest.raises(BlankStatusError):
            manager.spoil_blank(blank.blank_id, reason="Test")

    def test_archive_blank(self) -> None:
        """Test archiving a blank."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
        )

        # Issue, activate, sign
        blank = manager.issue_blank(
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
        )
        manager.activate_blank(blank.blank_id)
        manager.sign_blank(blank.blank_id, b"test document")

        # Archive
        archived = manager.archive_blank(blank.blank_id)
        assert archived.status == BlankStatus.ARCHIVED

    def test_archive_with_audit(self) -> None:
        """Test archiving blank logs to audit."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        audit = MockAuditLog()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
            audit_log=audit,
        )

        # Issue, activate, sign
        blank = manager.issue_blank(
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
        )
        manager.activate_blank(blank.blank_id)
        manager.sign_blank(blank.blank_id, b"test document")

        # Archive
        manager.archive_blank(blank.blank_id)

        # Find archive event
        archive_events = [e for e in audit.events if e[0].value == "blank.archived"]
        assert len(archive_events) == 1

    def test_archive_nonexistent_blank(self) -> None:
        """Test archiving nonexistent blank raises error."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
        )

        with pytest.raises(BlankNotFoundError):
            manager.archive_blank("nonexistent-id")

    def test_archive_wrong_status(self) -> None:
        """Test archiving blank in wrong status raises error."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
        )

        # Issue but don't activate
        blank = manager.issue_blank(
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
        )

        # Try to archive ISSUED blank (only PRINTED can be archived)
        with pytest.raises(BlankStatusError):
            manager.archive_blank(blank.blank_id)

    def test_get_blank(self) -> None:
        """Test getting a blank by ID."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
        )

        blank = manager.issue_blank(
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
        )

        found = manager.get_blank(blank.blank_id)
        assert found is not None
        assert found.blank_id == blank.blank_id

        not_found = manager.get_blank("nonexistent-id")
        assert not_found is None

    def test_get_blank_by_series_number(self) -> None:
        """Test getting a blank by series and number."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
        )

        manager.issue_blank(
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
        )

        found = manager.get_blank_by_series_number("INV-A", 42)
        assert found is not None
        assert found.series == "INV-A"
        assert found.number == 42

        not_found = manager.get_blank_by_series_number("INV-A", 99)
        assert not_found is None

    def test_list_blanks_by_status(self) -> None:
        """Test listing blanks by status."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
        )

        # Issue several blanks
        blank1 = manager.issue_blank(
            series="INV-A",
            number=1,
            blank_type="invoice",
            security_preset="standard",
        )
        blank2 = manager.issue_blank(
            series="INV-A",
            number=2,
            blank_type="invoice",
            security_preset="standard",
        )
        blank3 = manager.issue_blank(
            series="INV-A",
            number=3,
            blank_type="invoice",
            security_preset="standard",
        )

        # Activate one
        manager.activate_blank(blank1.blank_id)

        # List by status
        issued = manager.list_blanks_by_status(BlankStatus.ISSUED)
        ready = manager.list_blanks_by_status(BlankStatus.READY)

        assert len(issued) == 2
        assert len(ready) == 1

    def test_full_lifecycle(self) -> None:
        """Test complete blank lifecycle."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        storage = MockStorage()
        audit = MockAuditLog()
        manager = BlankManager(
            crypto_service=crypto,
            keystore=keystore,
            storage=storage,
            audit_log=audit,
        )

        # Issue
        blank = manager.issue_blank(
            series="INV-A",
            number=1,
            blank_type="invoice",
            security_preset="standard",
        )
        assert blank.status == BlankStatus.ISSUED

        # Activate
        blank = manager.activate_blank(blank.blank_id)
        assert blank.status == BlankStatus.READY

        # Sign
        blank, signature, qr_data = manager.sign_blank(
            blank_id=blank.blank_id,
            document_content=b"test document",
        )
        assert blank.status == BlankStatus.PRINTED

        # Archive
        blank = manager.archive_blank(blank.blank_id)
        assert blank.status == BlankStatus.ARCHIVED

        # Check audit log
        assert len(audit.events) == 4  # issued, activated, signed, archived


class TestBlankManagerErrors:
    """Tests for BlankManager error classes."""

    def test_blank_manager_error(self) -> None:
        """Test BlankManagerError can be raised."""
        with pytest.raises(BlankManagerError):
            raise BlankManagerError("Test error")

    def test_blank_not_found_error(self) -> None:
        """Test BlankNotFoundError is subclass of BlankManagerError."""
        with pytest.raises(BlankNotFoundError):
            raise BlankNotFoundError("Not found")

        with pytest.raises(BlankManagerError):
            raise BlankNotFoundError("Not found")

    def test_blank_status_error(self) -> None:
        """Test BlankStatusError is subclass of BlankManagerError."""
        with pytest.raises(BlankStatusError):
            raise BlankStatusError("Wrong status")

        with pytest.raises(BlankManagerError):
            raise BlankStatusError("Wrong status")

    def test_blank_validation_error(self) -> None:
        """Test BlankValidationError is subclass of BlankManagerError."""
        with pytest.raises(BlankValidationError):
            raise BlankValidationError("Validation failed")

        with pytest.raises(BlankManagerError):
            raise BlankValidationError("Validation failed")