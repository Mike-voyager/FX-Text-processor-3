"""
Tests for security.blanks.verification module.

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict
from unittest.mock import Mock

import pytest

from src.security.blanks.models import (
    BlankStatus,
    ProtectedBlank,
    QRVerificationData,
    SigningMode,
    VerificationResult,
)
from src.security.blanks.verification import (
    verify_blank,
    verify_blank_from_json,
    BlankVerifier,
)


class MockCryptoService:
    """Mock crypto service for testing."""

    def __init__(self, verify_result: bool = True) -> None:
        self.verify_result = verify_result
        self.verify_calls: list[tuple[str, bytes, bytes, bytes]] = []

    def verify(
        self,
        algorithm: str,
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> bool:
        self.verify_calls.append((algorithm, public_key, message, signature))
        return self.verify_result


class MockAuditLog:
    """Mock audit log for testing."""

    def __init__(self) -> None:
        self.events: list[tuple[Any, Dict[str, Any]]] = []

    def log_event(
        self,
        event_type: Any,
        details: Dict[str, Any] | None = None,
        metadata: Dict[str, str] | None = None,
    ) -> None:
        self.events.append((event_type, details or {}, metadata or {}))


def create_test_qr_data(
    blank_id: str = "test-uuid",
    content_hash: bytes | None = None,
    signature: bytes | None = None,
    public_key: bytes | None = None,
    algorithm: str = "Ed25519",
    preset: str = "standard",
) -> QRVerificationData:
    """Create test QR verification data."""
    return QRVerificationData(
        blank_id=blank_id,
        series="INV-A",
        number=42,
        content_hash_sha3=content_hash or b"\x01" * 32,
        signature=signature or b"\x02" * 64,
        public_key=public_key or b"\x03" * 32,
        algorithm=algorithm,
        preset=preset,
        printed_at=datetime.now(timezone.utc),
    )


class TestVerifyBlank:
    """Tests for verify_blank function."""

    def test_verify_successful(self) -> None:
        """Test successful verification."""
        crypto = MockCryptoService(verify_result=True)
        content = b"test document content"

        # Compute actual hash
        import hashlib
        content_hash = hashlib.sha3_256(content).digest()

        qr = create_test_qr_data(content_hash=content_hash)

        result = verify_blank(
            qr_data=qr,
            printed_content=content,
            crypto_service=crypto,
        )

        assert result.authentic is True
        assert result.blank_id == "test-uuid"
        assert result.series == "INV-A"
        assert result.number == 42
        assert result.reason is None
        assert len(crypto.verify_calls) == 1

    def test_verify_content_hash_mismatch(self) -> None:
        """Test verification with content hash mismatch."""
        crypto = MockCryptoService(verify_result=True)
        qr = create_test_qr_data(content_hash=b"\xff" * 32)  # Wrong hash
        content = b"test document content"

        result = verify_blank(
            qr_data=qr,
            printed_content=content,
            crypto_service=crypto,
        )

        assert result.authentic is False
        assert "Content hash mismatch" in result.reason
        assert len(crypto.verify_calls) == 0  # Signature not checked

    def test_verify_signature_invalid(self) -> None:
        """Test verification with invalid signature."""
        crypto = MockCryptoService(verify_result=False)
        content = b"test document content"

        import hashlib
        content_hash = hashlib.sha3_256(content).digest()

        qr = create_test_qr_data(content_hash=content_hash)

        result = verify_blank(
            qr_data=qr,
            printed_content=content,
            crypto_service=crypto,
        )

        assert result.authentic is False
        assert "Signature verification failed" in result.reason

    def test_verify_with_audit_log(self) -> None:
        """Test verification logs to audit."""
        crypto = MockCryptoService(verify_result=True)
        audit = MockAuditLog()
        content = b"test document content"

        import hashlib
        content_hash = hashlib.sha3_256(content).digest()

        qr = create_test_qr_data(content_hash=content_hash)

        result = verify_blank(
            qr_data=qr,
            printed_content=content,
            crypto_service=crypto,
            audit_log=audit,
        )

        assert result.authentic is True
        assert len(audit.events) == 1

    def test_verify_with_max_age(self) -> None:
        """Test verification with max age check."""
        crypto = MockCryptoService(verify_result=True)
        content = b"test document content"

        import hashlib
        content_hash = hashlib.sha3_256(content).digest()

        # Create QR with old date
        old_date = datetime(2020, 1, 1, tzinfo=timezone.utc)
        qr = QRVerificationData(
            blank_id="test-uuid",
            series="INV-A",
            number=42,
            content_hash_sha3=content_hash,
            signature=b"\x02" * 64,
            public_key=b"\x03" * 32,
            algorithm="Ed25519",
            preset="standard",
            printed_at=old_date,
        )

        result = verify_blank(
            qr_data=qr,
            printed_content=content,
            crypto_service=crypto,
            max_age_days=30,  # 30 days max
        )

        # Should succeed but with warning
        assert result.authentic is True
        assert len(result.warnings) == 1
        assert "Document age" in result.warnings[0]

    def test_verify_unsupported_format_version(self) -> None:
        """Test verification with unsupported format version."""
        crypto = MockCryptoService(verify_result=True)
        content = b"test document content"

        qr = QRVerificationData(
            blank_id="test-uuid",
            series="INV-A",
            number=42,
            content_hash_sha3=b"\x01" * 32,
            signature=b"\x02" * 64,
            public_key=b"\x03" * 32,
            algorithm="Ed25519",
            preset="standard",
            printed_at=datetime.now(timezone.utc),
            format_version="99.0",  # Unsupported
        )

        result = verify_blank(
            qr_data=qr,
            printed_content=content,
            crypto_service=crypto,
        )

        assert result.authentic is False
        assert "Unsupported format version" in result.reason


class TestVerifyBlankFromJson:
    """Tests for verify_blank_from_json function."""

    def test_verify_from_json(self) -> None:
        """Test verification from JSON data."""
        crypto = MockCryptoService(verify_result=True)
        content = b"test document content"

        import hashlib
        content_hash = hashlib.sha3_256(content).digest()

        qr_json: Dict[str, Any] = {
            "blank_id": "test-uuid",
            "series": "INV-A",
            "number": 42,
            "content_hash_sha3": content_hash.hex(),
            "signature": ("02" * 64),
            "public_key": ("03" * 32),
            "algorithm": "Ed25519",
            "preset": "standard",
            "printed_at": datetime.now(timezone.utc).isoformat(),
            "format_version": "1.0",
        }

        result = verify_blank_from_json(
            qr_json=qr_json,
            printed_content=content,
            crypto_service=crypto,
        )

        assert result.authentic is True
        assert result.blank_id == "test-uuid"


class TestBlankVerifier:
    """Tests for BlankVerifier class."""

    def test_verifier_init(self) -> None:
        """Test verifier initialization."""
        crypto = MockCryptoService()
        verifier = BlankVerifier(crypto_service=crypto)

        assert verifier._crypto == crypto

    def test_verifier_verify(self) -> None:
        """Test verifier verify method."""
        crypto = MockCryptoService(verify_result=True)
        verifier = BlankVerifier(crypto_service=crypto)
        content = b"test document content"

        import hashlib
        content_hash = hashlib.sha3_256(content).digest()

        qr = create_test_qr_data(content_hash=content_hash)

        result = verifier.verify(qr, content)

        assert result.authentic is True

    def test_verifier_verify_batch(self) -> None:
        """Test verifier batch verification."""
        crypto = MockCryptoService(verify_result=True)
        verifier = BlankVerifier(crypto_service=crypto)
        content = b"test document content"

        import hashlib
        content_hash = hashlib.sha3_256(content).digest()

        items = [
            (create_test_qr_data(blank_id="1", content_hash=content_hash), content),
            (create_test_qr_data(blank_id="2", content_hash=content_hash), content),
            (create_test_qr_data(blank_id="3", content_hash=content_hash), content),
        ]

        results = verifier.verify_batch(items)

        assert len(results) == 3
        assert all(r.authentic for r in results)

    def test_verifier_with_audit_and_max_age(self) -> None:
        """Test verifier with audit log and max age."""
        crypto = MockCryptoService(verify_result=True)
        audit = MockAuditLog()
        verifier = BlankVerifier(
            crypto_service=crypto,
            audit_log=audit,
            max_age_days=30,
        )

        content = b"test document content"

        import hashlib
        content_hash = hashlib.sha3_256(content).digest()

        qr = create_test_qr_data(content_hash=content_hash)

        result = verifier.verify(qr, content)

        assert result.authentic is True
        assert len(audit.events) == 1

    def test_verifier_clear_cache(self) -> None:
        """Test verifier cache clearing."""
        crypto = MockCryptoService()
        verifier = BlankVerifier(crypto_service=crypto)

        # Add something to cache
        verifier._key_cache["test_key"] = b"test_value"

        verifier.clear_cache()

        assert len(verifier._key_cache) == 0


class TestVerifyBlankAuditLogging:
    """Tests for audit logging in verification."""

    def test_verify_content_mismatch_logs_audit(self) -> None:
        """Test that content hash mismatch logs to audit."""
        crypto = MockCryptoService(verify_result=True)
        audit = MockAuditLog()
        content = b"test document content"

        qr = create_test_qr_data(content_hash=b"\xff" * 32)  # Wrong hash

        result = verify_blank(
            qr_data=qr,
            printed_content=content,
            crypto_service=crypto,
            audit_log=audit,
        )

        assert result.authentic is False
        assert len(audit.events) == 1
        event_type, details, _ = audit.events[0]
        assert event_type.value == "blank.verify_failed"
        assert details["reason"] == "content_hash_mismatch"

    def test_verify_signature_invalid_logs_audit(self) -> None:
        """Test that signature verification failure logs to audit."""
        crypto = MockCryptoService(verify_result=False)
        audit = MockAuditLog()
        content = b"test document content"

        import hashlib
        content_hash = hashlib.sha3_256(content).digest()

        qr = create_test_qr_data(content_hash=content_hash)

        result = verify_blank(
            qr_data=qr,
            printed_content=content,
            crypto_service=crypto,
            audit_log=audit,
        )

        assert result.authentic is False
        assert len(audit.events) == 1
        event_type, details, _ = audit.events[0]
        assert event_type.value == "blank.verify_failed"
        assert details["reason"] == "signature_invalid"

    def test_verify_success_logs_audit(self) -> None:
        """Test that successful verification logs to audit."""
        crypto = MockCryptoService(verify_result=True)
        audit = MockAuditLog()
        content = b"test document content"

        import hashlib
        content_hash = hashlib.sha3_256(content).digest()

        qr = create_test_qr_data(content_hash=content_hash)

        result = verify_blank(
            qr_data=qr,
            printed_content=content,
            crypto_service=crypto,
            audit_log=audit,
        )

        assert result.authentic is True
        assert len(audit.events) == 1
        event_type, details, _ = audit.events[0]
        assert event_type.value == "blank.verified"

    def test_verify_exception_logs_audit(self) -> None:
        """Test that exceptions during verification log to audit."""
        crypto = MockCryptoService()

        def failing_verify(
            algorithm: str, public_key: bytes, message: bytes, signature: bytes
        ) -> bool:
            raise RuntimeError("Verification failed unexpectedly")

        crypto.verify = failing_verify  # type: ignore

        audit = MockAuditLog()
        content = b"test document content"

        import hashlib
        content_hash = hashlib.sha3_256(content).digest()

        qr = create_test_qr_data(content_hash=content_hash)

        result = verify_blank(
            qr_data=qr,
            printed_content=content,
            crypto_service=crypto,
            audit_log=audit,
        )

        assert result.authentic is False
        assert "error" in result.reason.lower() or "failed" in result.reason.lower()
        assert len(audit.events) == 1
        event_type, details, _ = audit.events[0]
        assert event_type.value == "blank.verify_failed"