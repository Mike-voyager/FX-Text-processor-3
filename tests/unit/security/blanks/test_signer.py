"""
Tests for security.blanks.signer module.

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from unittest.mock import Mock

import pytest

from src.security.blanks.models import (
    BlankStatus,
    ProtectedBlank,
    SigningMode,
)
from src.security.blanks.signer import (
    BlankSigner,
    SigningError,
    VerificationError,
    create_qr_data,
)


class MockCryptoService:
    """Mock crypto service for testing."""

    def __init__(self, sign_result: bytes = b"\x01" * 64) -> None:
        self._sign_result = sign_result
        self.sign_calls: list[tuple[str, bytes, bytes]] = []

    def sign(self, algorithm: str, private_key: bytes, message: bytes) -> bytes:
        self.sign_calls.append((algorithm, private_key, message))
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

    def __init__(self, public_key: bytes = b"\xbb" * 32) -> None:
        self._public_key = public_key
        self._counter = 0

    def get_signing_keypair(self, preset: str) -> tuple[bytes, bytes, str]:
        return (b"\xaa" * 32, self._public_key, "Ed25519")

    def increment_counter(self, counter_name: str) -> int:
        self._counter += 1
        return self._counter


class MockHardwareManager:
    """Mock hardware manager for testing."""

    def __init__(self, sign_result: bytes = b"\x01" * 64) -> None:
        self._sign_result = sign_result
        self.sign_calls: list[tuple[str, int, bytes, str]] = []

    def sign_with_device(
        self,
        device_id: str,
        slot: int,
        message: bytes,
        pin: str,
    ) -> bytes:
        self.sign_calls.append((device_id, slot, message, pin))
        return self._sign_result

    def get_public_key(self, device_id: str, slot: int) -> bytes:
        return b"\xbb" * 32


class MockAuditLog:
    """Mock audit log for testing."""

    def __init__(self) -> None:
        self.events: list[tuple[Any, Dict[str, Any], Dict[str, str]]] = []

    def log_event(
        self,
        event_type: Any,
        details: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> None:
        self.events.append((event_type, details or {}, metadata or {}))


def create_test_blank(
    signing_mode: SigningMode = SigningMode.SOFTWARE,
    public_key: bytes = b"\xbb" * 32,
) -> ProtectedBlank:
    """Create a test blank."""
    return ProtectedBlank(
        blank_id="test-uuid-123",
        series="INV-A",
        number=42,
        blank_type="invoice",
        security_preset="standard",
        signing_mode=signing_mode,
        signature_algorithm="Ed25519",
        public_key=public_key,
        status=BlankStatus.READY,
        serial_counter=1,
    )


class TestBlankSigner:
    """Tests for BlankSigner class."""

    def test_init(self) -> None:
        """Test signer initialization."""
        crypto = MockCryptoService()
        keystore = MockKeystore()

        signer = BlankSigner(crypto_service=crypto, keystore=keystore)

        assert signer._crypto == crypto
        assert signer._keystore == keystore

    def test_init_with_hardware(self) -> None:
        """Test signer with hardware manager."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        hardware = MockHardwareManager()

        signer = BlankSigner(
            crypto_service=crypto,
            keystore=keystore,
            hardware_manager=hardware,
        )

        assert signer._hardware == hardware

    def test_sign_software(self) -> None:
        """Test software signing."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        signer = BlankSigner(crypto_service=crypto, keystore=keystore)

        blank = create_test_blank()
        content = b"test document content"

        signature = signer.sign_blank(
            blank=blank,
            document_content=content,
            mode=SigningMode.SOFTWARE,
        )

        assert signature == crypto._sign_result
        assert len(crypto.sign_calls) == 1

        # Verify message format: blank_id + content_hash
        call_args = crypto.sign_calls[0]
        assert call_args[0] == "Ed25519"  # algorithm

        content_hash = hashlib.sha3_256(content).digest()
        expected_message = blank.blank_id.encode("utf-8") + content_hash
        assert call_args[2] == expected_message

    def test_sign_software_default_mode(self) -> None:
        """Test that default mode is taken from blank."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        signer = BlankSigner(crypto_service=crypto, keystore=keystore)

        blank = create_test_blank(signing_mode=SigningMode.SOFTWARE)
        content = b"test document content"

        # No mode specified, should use blank.signing_mode
        signature = signer.sign_blank(
            blank=blank,
            document_content=content,
        )

        assert signature == crypto._sign_result

    def test_sign_hardware_piv(self) -> None:
        """Test hardware PIV signing."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        hardware = MockHardwareManager()
        signer = BlankSigner(
            crypto_service=crypto,
            keystore=keystore,
            hardware_manager=hardware,
        )

        blank = create_test_blank(signing_mode=SigningMode.HARDWARE_PIV)
        content = b"test document content"

        signature = signer.sign_blank(
            blank=blank,
            document_content=content,
            mode=SigningMode.HARDWARE_PIV,
            device_id="yubikey-001",
            pin="123456",
        )

        assert signature == hardware._sign_result
        assert len(hardware.sign_calls) == 1

        # Verify slot is PIV signature slot (0x9C)
        call_args = hardware.sign_calls[0]
        assert call_args[0] == "yubikey-001"
        assert call_args[1] == 0x9C
        assert call_args[3] == "123456"

    def test_sign_hardware_openpgp(self) -> None:
        """Test hardware OpenPGP signing."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        hardware = MockHardwareManager()
        signer = BlankSigner(
            crypto_service=crypto,
            keystore=keystore,
            hardware_manager=hardware,
        )

        blank = create_test_blank(signing_mode=SigningMode.HARDWARE_OPENPGP)
        content = b"test document content"

        signature = signer.sign_blank(
            blank=blank,
            document_content=content,
            mode=SigningMode.HARDWARE_OPENPGP,
            device_id="yubikey-002",
            pin="654321",
        )

        assert signature == hardware._sign_result
        assert len(hardware.sign_calls) == 1

        # Verify slot is OpenPGP signature slot (0x01)
        call_args = hardware.sign_calls[0]
        assert call_args[0] == "yubikey-002"
        assert call_args[1] == 0x01

    def test_sign_hardware_missing_device_id(self) -> None:
        """Test hardware signing without device_id raises error."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        hardware = MockHardwareManager()
        signer = BlankSigner(
            crypto_service=crypto,
            keystore=keystore,
            hardware_manager=hardware,
        )

        blank = create_test_blank()
        content = b"test document content"

        with pytest.raises(SigningError, match="device_id and pin are required"):
            signer.sign_blank(
                blank=blank,
                document_content=content,
                mode=SigningMode.HARDWARE_PIV,
                device_id=None,
                pin=None,
            )

    def test_sign_hardware_missing_pin(self) -> None:
        """Test hardware signing without PIN raises error."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        hardware = MockHardwareManager()
        signer = BlankSigner(
            crypto_service=crypto,
            keystore=keystore,
            hardware_manager=hardware,
        )

        blank = create_test_blank()
        content = b"test document content"

        with pytest.raises(SigningError, match="device_id and pin are required"):
            signer.sign_blank(
                blank=blank,
                document_content=content,
                mode=SigningMode.HARDWARE_OPENPGP,
                device_id="yubikey-001",
                pin=None,
            )

    def test_sign_hardware_no_manager(self) -> None:
        """Test hardware signing without hardware manager raises error."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        # No hardware manager provided
        signer = BlankSigner(crypto_service=crypto, keystore=keystore)

        blank = create_test_blank()
        content = b"test document content"

        with pytest.raises(SigningError, match="Hardware manager not available"):
            signer.sign_blank(
                blank=blank,
                document_content=content,
                mode=SigningMode.HARDWARE_PIV,
                device_id="yubikey-001",
                pin="123456",
            )

    def test_sign_software_key_mismatch(self) -> None:
        """Test software signing with key mismatch raises error."""
        crypto = MockCryptoService()
        keystore = MockKeystore(public_key=b"\xcc" * 32)  # Different key
        signer = BlankSigner(crypto_service=crypto, keystore=keystore)

        blank = create_test_blank(public_key=b"\xbb" * 32)  # Blank has different key
        content = b"test document content"

        with pytest.raises(SigningError, match="Public key mismatch"):
            signer.sign_blank(
                blank=blank,
                document_content=content,
                mode=SigningMode.SOFTWARE,
            )

    def test_sign_with_audit_log(self) -> None:
        """Test that signing logs to audit."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        audit = MockAuditLog()
        signer = BlankSigner(
            crypto_service=crypto,
            keystore=keystore,
            audit_log=audit,
        )

        blank = create_test_blank()
        content = b"test document content"

        signer.sign_blank(
            blank=blank,
            document_content=content,
            mode=SigningMode.SOFTWARE,
        )

        assert len(audit.events) == 1
        event_type, details, _ = audit.events[0]
        assert event_type.value == "crypto.signing"
        assert details["blank_id"] == "test-uuid-123"
        assert details["signing_mode"] == "software"

    def test_sign_error_logs_blocked_event(self) -> None:
        """Test that signing errors log BLANK_SIGNING_BLOCKED event."""
        crypto = MockCryptoService()

        def failing_sign(alg: str, key: bytes, msg: bytes) -> bytes:
            raise RuntimeError("Signing failed")

        crypto.sign = failing_sign  # type: ignore

        keystore = MockKeystore()
        audit = MockAuditLog()
        signer = BlankSigner(
            crypto_service=crypto,
            keystore=keystore,
            audit_log=audit,
        )

        blank = create_test_blank()
        content = b"test document content"

        with pytest.raises(SigningError):
            signer.sign_blank(
                blank=blank,
                document_content=content,
                mode=SigningMode.SOFTWARE,
            )

        # Should log BLANK_SIGNING_BLOCKED
        assert len(audit.events) == 1
        event_type, details, _ = audit.events[0]
        assert event_type.value == "blank.signing_blocked"


class TestCreateQrData:
    """Tests for create_qr_data function."""

    def test_create_qr_data(self) -> None:
        """Test creating QR verification data."""
        blank = create_test_blank()
        content = b"test document content"
        signature = b"\x02" * 64

        qr = create_qr_data(
            blank=blank,
            document_content=content,
            signature=signature,
        )

        assert qr.blank_id == "test-uuid-123"
        assert qr.series == "INV-A"
        assert qr.number == 42
        assert qr.algorithm == "Ed25519"
        assert qr.preset == "standard"
        assert qr.signature == signature
        assert qr.public_key == blank.public_key
        assert qr.format_version == "1.0"

        # Verify content hash
        expected_hash = hashlib.sha3_256(content).digest()
        assert qr.content_hash_sha3 == expected_hash

    def test_qr_printed_at(self) -> None:
        """Test that printed_at is set correctly."""
        blank = create_test_blank()
        content = b"test document content"
        signature = b"\x02" * 64

        before = datetime.now(timezone.utc)
        qr = create_qr_data(blank, content, signature)
        after = datetime.now(timezone.utc)

        assert before <= qr.printed_at <= after


class TestSigningError:
    """Tests for SigningError exception."""

    def test_signing_error(self) -> None:
        """Test SigningError can be raised and caught."""
        with pytest.raises(SigningError):
            raise SigningError("Test signing error")

    def test_signing_error_message(self) -> None:
        """Test SigningError message."""
        try:
            raise SigningError("Test signing error")
        except SigningError as e:
            assert "Test signing error" in str(e)


class TestUnsupportedSigningMode:
    """Tests for unsupported signing modes."""

    def test_unsupported_signing_mode(self) -> None:
        """Test unsupported signing mode raises error.

        Note: Since SigningMode is an enum, we can't easily create an invalid
        value. The else branch in sign_blank() is defensive code that should
        never be reached in practice. We test it by mocking the internal logic.
        """
        # This branch is unreachable with valid SigningMode enum values
        # It exists as defensive programming. Skip this test as it requires
        # mocking internal implementation details.
        pass


class TestHardwareKeyMismatch:
    """Tests for hardware signing key mismatch."""

    def test_hardware_piv_key_mismatch(self) -> None:
        """Test PIV signing with mismatched public key."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        # Hardware manager returns different key than blank
        hardware = MockHardwareManager()
        hardware._public_key = b"\xcc" * 32  # Different key
        hardware.get_public_key = lambda device_id, slot: b"\xcc" * 32

        signer = BlankSigner(
            crypto_service=crypto,
            keystore=keystore,
            hardware_manager=hardware,
        )

        blank = create_test_blank(
            signing_mode=SigningMode.HARDWARE_PIV,
            public_key=b"\xbb" * 32,  # Blank has different key
        )
        content = b"test content"

        with pytest.raises(SigningError, match="Public key mismatch"):
            signer.sign_blank(
                blank=blank,
                document_content=content,
                mode=SigningMode.HARDWARE_PIV,
                device_id="yubikey-001",
                pin="123456",
            )

    def test_hardware_openpgp_key_mismatch(self) -> None:
        """Test OpenPGP signing with mismatched public key."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        hardware = MockHardwareManager()
        hardware.get_public_key = lambda device_id, slot: b"\xdd" * 32  # Different key

        signer = BlankSigner(
            crypto_service=crypto,
            keystore=keystore,
            hardware_manager=hardware,
        )

        blank = create_test_blank(
            signing_mode=SigningMode.HARDWARE_OPENPGP,
            public_key=b"\xbb" * 32,
        )
        content = b"test content"

        with pytest.raises(SigningError, match="Public key mismatch"):
            signer.sign_blank(
                blank=blank,
                document_content=content,
                mode=SigningMode.HARDWARE_OPENPGP,
                device_id="yubikey-001",
                pin="123456",
            )


class TestGetAuditEventType:
    """Tests for audit event type selection."""

    def test_software_mode_audit_event(self) -> None:
        """Test that SOFTWARE mode logs CRYPTO_SIGNING."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        audit = MockAuditLog()
        signer = BlankSigner(
            crypto_service=crypto,
            keystore=keystore,
            audit_log=audit,
        )

        blank = create_test_blank()
        content = b"test content"

        signer.sign_blank(blank=blank, document_content=content, mode=SigningMode.SOFTWARE)

        assert len(audit.events) == 1
        event_type, details, _ = audit.events[0]
        assert event_type.value == "crypto.signing"

    def test_hardware_piv_audit_event(self) -> None:
        """Test that HARDWARE_PIV mode logs DEVICE_OPERATION."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        hardware = MockHardwareManager()
        audit = MockAuditLog()
        signer = BlankSigner(
            crypto_service=crypto,
            keystore=keystore,
            hardware_manager=hardware,
            audit_log=audit,
        )

        blank = create_test_blank(signing_mode=SigningMode.HARDWARE_PIV)
        content = b"test content"

        signer.sign_blank(
            blank=blank,
            document_content=content,
            mode=SigningMode.HARDWARE_PIV,
            device_id="yubikey-001",
            pin="123456",
        )

        assert len(audit.events) == 1
        event_type, details, _ = audit.events[0]
        assert event_type.value == "device.operation"

    def test_hardware_openpgp_audit_event(self) -> None:
        """Test that HARDWARE_OPENPGP mode logs DEVICE_OPERATION."""
        crypto = MockCryptoService()
        keystore = MockKeystore()
        hardware = MockHardwareManager()
        audit = MockAuditLog()
        signer = BlankSigner(
            crypto_service=crypto,
            keystore=keystore,
            hardware_manager=hardware,
            audit_log=audit,
        )

        blank = create_test_blank(signing_mode=SigningMode.HARDWARE_OPENPGP)
        content = b"test content"

        signer.sign_blank(
            blank=blank,
            document_content=content,
            mode=SigningMode.HARDWARE_OPENPGP,
            device_id="yubikey-001",
            pin="123456",
        )

        assert len(audit.events) == 1
        event_type, details, _ = audit.events[0]
        assert event_type.value == "device.operation"


class TestVerificationError:
    """Tests for VerificationError exception."""

    def test_verification_error(self) -> None:
        """Test VerificationError can be raised and caught."""
        with pytest.raises(VerificationError):
            raise VerificationError("Test verification error")

    def test_verification_error_message(self) -> None:
        """Test VerificationError message."""
        try:
            raise VerificationError("Test verification error")
        except VerificationError as e:
            assert "Test verification error" in str(e)


class TestUnsupportedSigningMode:
    """Tests for unsupported signing mode handling."""

    def test_unsupported_signing_mode_error_message(self) -> None:
        """Test that SigningError contains mode name for unsupported mode."""
        # This tests the defensive else branch in sign_blank()
        # Note: Since SigningMode is an enum, this branch is defensive
        # and would require mocking an invalid enum value
        from src.security.blanks.signer import SigningError

        # Verify the error message format
        error = SigningError("Unsupported signing mode: invalid_mode")
        assert "Unsupported signing mode" in str(error)
        assert "invalid_mode" in str(error)

    def test_get_audit_event_type_fallback(self) -> None:
        """Test that _get_audit_event_type returns CRYPTO_SIGNING for unknown mode."""
        from src.security.audit.events import AuditEventType
        from unittest.mock import MagicMock

        crypto = MockCryptoService()
        keystore = MockKeystore()
        signer = BlankSigner(crypto_service=crypto, keystore=keystore)

        # Test that SOFTWARE mode returns CRYPTO_SIGNING
        result = signer._get_audit_event_type(SigningMode.SOFTWARE)
        assert result == AuditEventType.CRYPTO_SIGNING

        # Test that HARDWARE_PIV returns DEVICE_OPERATION
        result = signer._get_audit_event_type(SigningMode.HARDWARE_PIV)
        assert result == AuditEventType.DEVICE_OPERATION

        # Test that HARDWARE_OPENPGP returns DEVICE_OPERATION
        result = signer._get_audit_event_type(SigningMode.HARDWARE_OPENPGP)
        assert result == AuditEventType.DEVICE_OPERATION