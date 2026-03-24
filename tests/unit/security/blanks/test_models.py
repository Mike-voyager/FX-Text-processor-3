"""
Tests for security.blanks.models module.

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.security.blanks.models import (
    BlankStatus,
    SigningMode,
    ProtectedBlank,
    QRVerificationData,
    VerificationResult,
    VALID_TRANSITIONS,
)


class TestBlankStatus:
    """Tests for BlankStatus enum."""

    def test_status_values(self) -> None:
        """Test that statuses have correct values."""
        assert BlankStatus.ISSUED.value == "issued"
        assert BlankStatus.READY.value == "ready"
        assert BlankStatus.PRINTED.value == "printed"
        assert BlankStatus.ARCHIVED.value == "archived"
        assert BlankStatus.SPOILED.value == "spoiled"
        assert BlankStatus.VOIDED.value == "voided"

    def test_is_terminal(self) -> None:
        """Test terminal status detection."""
        assert BlankStatus.ARCHIVED.is_terminal is True
        assert BlankStatus.SPOILED.is_terminal is True
        assert BlankStatus.VOIDED.is_terminal is True
        assert BlankStatus.ISSUED.is_terminal is False
        assert BlankStatus.READY.is_terminal is False
        assert BlankStatus.PRINTED.is_terminal is False

    def test_is_usable(self) -> None:
        """Test usable status detection."""
        assert BlankStatus.READY.is_usable is True
        assert BlankStatus.ISSUED.is_usable is False
        assert BlankStatus.PRINTED.is_usable is False
        assert BlankStatus.ARCHIVED.is_usable is False


class TestSigningMode:
    """Tests for SigningMode enum."""

    def test_mode_values(self) -> None:
        """Test that modes have correct values."""
        assert SigningMode.SOFTWARE.value == "software"
        assert SigningMode.HARDWARE_PIV.value == "hardware_piv"
        assert SigningMode.HARDWARE_OPENPGP.value == "hardware_openpgp"

    def test_is_hardware(self) -> None:
        """Test hardware mode detection."""
        assert SigningMode.SOFTWARE.is_hardware is False
        assert SigningMode.HARDWARE_PIV.is_hardware is True
        assert SigningMode.HARDWARE_OPENPGP.is_hardware is True


class TestValidTransitions:
    """Tests for valid transitions."""

    def test_issued_transitions(self) -> None:
        """Test transitions from ISSUED status."""
        assert BlankStatus.READY in VALID_TRANSITIONS[BlankStatus.ISSUED]
        assert BlankStatus.SPOILED in VALID_TRANSITIONS[BlankStatus.ISSUED]
        assert BlankStatus.PRINTED not in VALID_TRANSITIONS[BlankStatus.ISSUED]

    def test_ready_transitions(self) -> None:
        """Test transitions from READY status."""
        assert BlankStatus.PRINTED in VALID_TRANSITIONS[BlankStatus.READY]
        assert BlankStatus.VOIDED in VALID_TRANSITIONS[BlankStatus.READY]
        assert BlankStatus.ISSUED not in VALID_TRANSITIONS[BlankStatus.READY]

    def test_printed_transitions(self) -> None:
        """Test transitions from PRINTED status."""
        assert BlankStatus.ARCHIVED in VALID_TRANSITIONS[BlankStatus.PRINTED]
        assert BlankStatus.READY not in VALID_TRANSITIONS[BlankStatus.PRINTED]

    def test_terminal_transitions(self) -> None:
        """Test that terminal statuses have no transitions."""
        assert len(VALID_TRANSITIONS[BlankStatus.ARCHIVED]) == 0
        assert len(VALID_TRANSITIONS[BlankStatus.SPOILED]) == 0
        assert len(VALID_TRANSITIONS[BlankStatus.VOIDED]) == 0


class TestProtectedBlank:
    """Tests for ProtectedBlank dataclass."""

    def test_create_blank(self) -> None:
        """Test creating a blank."""
        blank = ProtectedBlank(
            blank_id="test-uuid",
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
            signing_mode=SigningMode.SOFTWARE,
            signature_algorithm="Ed25519",
            public_key=b"\x01" * 32,
            status=BlankStatus.ISSUED,
            serial_counter=1,
        )

        assert blank.blank_id == "test-uuid"
        assert blank.series == "INV-A"
        assert blank.number == 42
        assert blank.blank_type == "invoice"
        assert blank.security_preset == "standard"
        assert blank.signing_mode == SigningMode.SOFTWARE
        assert blank.status == BlankStatus.ISSUED

    def test_display_id(self) -> None:
        """Test display_id property."""
        blank = ProtectedBlank(
            blank_id="test-uuid",
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
            signing_mode=SigningMode.SOFTWARE,
            signature_algorithm="Ed25519",
            public_key=b"\x01" * 32,
            status=BlankStatus.ISSUED,
            serial_counter=1,
        )

        assert blank.display_id == "INV-A-0042"

    def test_can_transition_to(self) -> None:
        """Test status transition validation."""
        issued = ProtectedBlank(
            blank_id="test-uuid",
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
            signing_mode=SigningMode.SOFTWARE,
            signature_algorithm="Ed25519",
            public_key=b"\x01" * 32,
            status=BlankStatus.ISSUED,
            serial_counter=1,
        )

        assert issued.can_transition_to(BlankStatus.READY) is True
        assert issued.can_transition_to(BlankStatus.SPOILED) is True
        assert issued.can_transition_to(BlankStatus.PRINTED) is False

    def test_with_status(self) -> None:
        """Test status transition."""
        issued = ProtectedBlank(
            blank_id="test-uuid",
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
            signing_mode=SigningMode.SOFTWARE,
            signature_algorithm="Ed25519",
            public_key=b"\x01" * 32,
            status=BlankStatus.ISSUED,
            serial_counter=1,
        )

        ready = issued.with_status(BlankStatus.READY)

        assert ready.status == BlankStatus.READY
        assert ready.blank_id == issued.blank_id
        assert ready.series == issued.series

    def test_with_status_invalid(self) -> None:
        """Test invalid status transition."""
        printed = ProtectedBlank(
            blank_id="test-uuid",
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
            signing_mode=SigningMode.SOFTWARE,
            signature_algorithm="Ed25519",
            public_key=b"\x01" * 32,
            status=BlankStatus.PRINTED,
            serial_counter=1,
        )

        with pytest.raises(ValueError):
            printed.with_status(BlankStatus.ISSUED)

    def test_create_factory_method(self) -> None:
        """Test create factory method."""
        blank = ProtectedBlank.create(
            series="INV-B",
            number=100,
            blank_type="invoice",
            security_preset="paranoid",
            signing_mode=SigningMode.SOFTWARE,
            signature_algorithm="Ed25519",
            public_key=b"\x02" * 32,
            serial_counter=5,
        )

        assert blank.series == "INV-B"
        assert blank.number == 100
        assert blank.status == BlankStatus.ISSUED
        assert blank.blank_id != ""  # UUID generated
        assert blank.created_at is not None
        assert blank.updated_at is not None

    def test_to_dict(self) -> None:
        """Test serialization to dict."""
        blank = ProtectedBlank(
            blank_id="test-uuid",
            series="INV-A",
            number=42,
            blank_type="invoice",
            security_preset="standard",
            signing_mode=SigningMode.SOFTWARE,
            signature_algorithm="Ed25519",
            public_key=b"\x01" * 32,
            status=BlankStatus.ISSUED,
            serial_counter=1,
        )

        data = blank.to_dict()

        assert data["blank_id"] == "test-uuid"
        assert data["series"] == "INV-A"
        assert data["number"] == 42
        assert data["status"] == "issued"
        assert data["signing_mode"] == "software"
        assert data["public_key"] == "01" * 32

    def test_from_dict(self) -> None:
        """Test deserialization from dict."""
        data = {
            "blank_id": "test-uuid",
            "series": "INV-A",
            "number": 42,
            "blank_type": "invoice",
            "security_preset": "standard",
            "signing_mode": "software",
            "signature_algorithm": "Ed25519",
            "public_key": "01" * 32,
            "status": "issued",
            "serial_counter": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

        blank = ProtectedBlank.from_dict(data)

        assert blank.blank_id == "test-uuid"
        assert blank.series == "INV-A"
        assert blank.status == BlankStatus.ISSUED
        assert blank.signing_mode == SigningMode.SOFTWARE


class TestQRVerificationData:
    """Tests for QRVerificationData dataclass."""

    def test_create_qr_data(self) -> None:
        """Test creating QR verification data."""
        qr = QRVerificationData(
            blank_id="test-uuid",
            series="INV-A",
            number=42,
            content_hash_sha3=b"\x03" * 32,
            signature=b"\x04" * 64,
            public_key=b"\x05" * 32,
            algorithm="Ed25519",
            preset="standard",
            printed_at=datetime.now(timezone.utc),
        )

        assert qr.blank_id == "test-uuid"
        assert qr.series == "INV-A"
        assert qr.number == 42
        assert qr.algorithm == "Ed25519"
        assert qr.format_version == "1.0"

    def test_qr_to_dict(self) -> None:
        """Test QR data serialization."""
        qr = QRVerificationData(
            blank_id="test-uuid",
            series="INV-A",
            number=42,
            content_hash_sha3=b"\x03" * 32,
            signature=b"\x04" * 64,
            public_key=b"\x05" * 32,
            algorithm="Ed25519",
            preset="standard",
            printed_at=datetime.now(timezone.utc),
        )

        data = qr.to_dict()

        assert data["blank_id"] == "test-uuid"
        assert data["content_hash_sha3"] == "03" * 32
        assert data["algorithm"] == "Ed25519"

    def test_qr_from_dict(self) -> None:
        """Test QR data deserialization."""
        data = {
            "blank_id": "test-uuid",
            "series": "INV-A",
            "number": 42,
            "content_hash_sha3": "03" * 32,
            "signature": "04" * 64,
            "public_key": "05" * 32,
            "algorithm": "Ed25519",
            "preset": "standard",
            "printed_at": datetime.now(timezone.utc).isoformat(),
            "format_version": "1.0",
        }

        qr = QRVerificationData.from_dict(data)

        assert qr.blank_id == "test-uuid"
        assert qr.algorithm == "Ed25519"
        assert len(qr.content_hash_sha3) == 32


class TestVerificationResult:
    """Tests for VerificationResult dataclass."""

    def test_successful_verification(self) -> None:
        """Test successful verification result."""
        result = VerificationResult(
            authentic=True,
            blank_id="test-uuid",
            series="INV-A",
            number=42,
            algorithm="Ed25519",
            verified_at=datetime.now(timezone.utc),
        )

        assert result.authentic is True
        assert result.reason is None
        assert result.display_id == "INV-A-0042"

    def test_failed_verification(self) -> None:
        """Test failed verification result."""
        result = VerificationResult(
            authentic=False,
            blank_id="test-uuid",
            series="INV-A",
            number=42,
            algorithm="Ed25519",
            verified_at=datetime.now(timezone.utc),
            reason="Signature verification failed",
        )

        assert result.authentic is False
        assert result.reason == "Signature verification failed"

    def test_verification_with_warnings(self) -> None:
        """Test verification with warnings."""
        result = VerificationResult(
            authentic=True,
            blank_id="test-uuid",
            series="INV-A",
            number=42,
            algorithm="Ed25519",
            verified_at=datetime.now(timezone.utc),
            warnings=["Document age exceeds recommended limit"],
        )

        assert result.authentic is True
        assert len(result.warnings) == 1
        assert "age" in result.warnings[0]