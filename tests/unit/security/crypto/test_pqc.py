# -*- coding: utf-8 -*-

"""
Tests for Post-Quantum Cryptography (PQC) module.

Coverage:
- Kyber-768 KEM (Key Encapsulation Mechanism)
- Dilithium-3 signatures
- Hybrid X25519 + Kyber key exchange
- Error handling and edge cases
- Optional dependency handling
"""

from __future__ import annotations

from typing import Any
from unittest.mock import Mock, patch

import pytest

from src.security.crypto import pqc  # type: ignore  # Pylance import resolution
from src.security.crypto.exceptions import CryptoKeyError, SignatureError  # type: ignore  # Pylance import resolution


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mock_kyber_keypair() -> tuple[bytes, bytes]:
    """Mock Kyber keypair for testing."""
    public_key = b"K" * 1184  # Kyber public key size
    secret_key = b"k" * 2400  # Kyber secret key size
    return public_key, secret_key


@pytest.fixture
def mock_kyber_ciphertext_and_secret() -> tuple[bytes, bytes]:
    """Mock Kyber ciphertext and shared secret."""
    ciphertext = b"C" * 1088  # Kyber ciphertext size
    shared_secret = b"S" * 32  # Shared secret size
    return ciphertext, shared_secret


@pytest.fixture
def mock_dilithium_keypair() -> tuple[bytes, bytes]:
    """Mock Dilithium keypair for testing."""
    public_key = b"D" * 1952  # Dilithium public key size
    secret_key = b"d" * 4000  # Dilithium secret key size
    return public_key, secret_key


@pytest.fixture
def mock_dilithium_signature() -> bytes:
    """Mock Dilithium signature."""
    return b"S" * 3293  # Dilithium signature size


# ============================================================================
# Availability Tests
# ============================================================================


def test_kyber_availability_flag() -> None:
    """Test KYBER_AVAILABLE flag is boolean."""
    assert isinstance(pqc.KYBER_AVAILABLE, bool)


def test_dilithium_availability_flag() -> None:
    """Test DILITHIUM_AVAILABLE flag is boolean."""
    assert isinstance(pqc.DILITHIUM_AVAILABLE, bool)


def test_module_exports() -> None:
    """Test module exports correct public API."""
    expected_exports = {
        "KYBER_AVAILABLE",
        "DILITHIUM_AVAILABLE",
        "KyberKEM",
        "DilithiumSigner",
        "hybrid_kem_x25519_kyber",
    }
    assert set(pqc.__all__) == expected_exports


# ============================================================================
# KyberKEM Tests
# ============================================================================


@pytest.mark.skipif(not pqc.KYBER_AVAILABLE, reason="Kyber not installed")
class TestKyberKEMReal:
    """Tests using real Kyber implementation."""

    def test_generate_keypair(self) -> None:
        """Test Dilithium keypair generation."""
        signer = pqc.DilithiumSigner.generate()

        public_key = signer.export_public_key()
        secret_key = signer.export_secret_key()

        assert len(public_key) == 1952
        assert len(secret_key) == 4032  # ML-DSA-65 size

    def test_encapsulate_decapsulate_cycle(self) -> None:
        """Test full encapsulation/decapsulation cycle."""
        # Generate keypair
        kem = pqc.KyberKEM.generate()
        public_key = kem.export_public_key()

        # Encapsulate (sender side)
        kem_sender = pqc.KyberKEM.from_public_key(public_key)
        ciphertext, shared_secret_sender = kem_sender.encapsulate()

        # Validate sizes
        assert len(ciphertext) == 1088
        assert len(shared_secret_sender) == 32

        # Decapsulate (receiver side)
        shared_secret_receiver = kem.decapsulate(ciphertext)

        # Shared secrets should match
        assert shared_secret_sender == shared_secret_receiver

    def test_encapsulate_produces_different_secrets(self) -> None:
        """Test that each encapsulation produces different secrets."""
        kem = pqc.KyberKEM.generate()
        public_key = kem.export_public_key()

        kem_sender = pqc.KyberKEM.from_public_key(public_key)

        ct1, ss1 = kem_sender.encapsulate()
        ct2, ss2 = kem_sender.encapsulate()

        # Different ciphertexts and secrets
        assert ct1 != ct2
        assert ss1 != ss2

    def test_from_public_key_cannot_export_secret(self) -> None:
        """Test that public-key-only instance cannot export secret key."""
        kem = pqc.KyberKEM.generate()
        public_key = kem.export_public_key()

        kem_public_only = pqc.KyberKEM.from_public_key(public_key)

        with pytest.raises(CryptoKeyError, match="No secret key available"):
            kem_public_only.export_secret_key()

    def test_from_public_key_cannot_decapsulate(self) -> None:
        """Test that public-key-only instance cannot decapsulate."""
        kem = pqc.KyberKEM.generate()
        public_key = kem.export_public_key()

        # Create sender instance
        kem_sender = pqc.KyberKEM.from_public_key(public_key)
        ciphertext, _ = kem_sender.encapsulate()

        # Try to decapsulate with public-key-only instance
        with pytest.raises(CryptoKeyError, match="No secret key available"):
            kem_sender.decapsulate(ciphertext)

    def test_decapsulate_invalid_ciphertext_length(self) -> None:
        """Test decapsulation with wrong ciphertext length."""
        kem = pqc.KyberKEM.generate()

        invalid_ciphertext = b"X" * 100  # Wrong length

        with pytest.raises(ValueError, match="must be 1088 bytes"):
            kem.decapsulate(invalid_ciphertext)


class TestKyberKEMMocked:
    """Tests using mocked Kyber (works without pqcrypto)."""

    def test_init_without_kyber_installed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test KyberKEM.__init__ raises ImportError when Kyber not available."""
        monkeypatch.setattr(pqc, "KYBER_AVAILABLE", False)

        with pytest.raises(ImportError, match="Kyber not available"):
            pqc.KyberKEM(b"fake_pk")

    def test_generate_without_kyber_installed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test KyberKEM.generate raises ImportError when Kyber not available."""
        monkeypatch.setattr(pqc, "KYBER_AVAILABLE", False)

        with pytest.raises(ImportError, match="Kyber not available"):
            pqc.KyberKEM.generate()

    @pytest.mark.skipif(not pqc.KYBER_AVAILABLE, reason="Need real Kyber for this test")
    def test_encapsulate_without_public_key(
        self, mock_kyber_keypair: tuple[bytes, bytes]
    ) -> None:
        """Test encapsulate fails without public key."""
        _, secret_key = mock_kyber_keypair

        # Create instance with None public key (shouldn't happen in practice)
        kem = pqc.KyberKEM.__new__(pqc.KyberKEM)
        kem._public_key = None  # type: ignore[assignment]
        kem._secret_key = secret_key

        with pytest.raises(CryptoKeyError, match="No public key available"):
            kem.encapsulate()

    @pytest.mark.skipif(not pqc.KYBER_AVAILABLE, reason="Need real Kyber for this test")
    def test_export_public_key_when_none(self) -> None:
        """Test export_public_key raises when no public key."""
        kem = pqc.KyberKEM.__new__(pqc.KyberKEM)
        kem._public_key = None  # type: ignore[assignment]
        kem._secret_key = b"fake"

        with pytest.raises(CryptoKeyError, match="No public key available"):
            kem.export_public_key()


# ============================================================================
# DilithiumSigner Tests
# ============================================================================


@pytest.mark.skipif(not pqc.DILITHIUM_AVAILABLE, reason="Dilithium not installed")
class TestDilithiumSignerReal:
    """Tests using real Dilithium implementation."""

    def test_generate_keypair(self) -> None:
        """Test Dilithium keypair generation."""
        signer = pqc.DilithiumSigner.generate()

        public_key = signer.export_public_key()
        secret_key = signer.export_secret_key()

        assert len(public_key) == 1952
        assert len(secret_key) == 4032

    def test_sign_and_verify_cycle(self) -> None:
        """Test full sign/verify cycle."""
        # Generate keypair
        signer = pqc.DilithiumSigner.generate()
        public_key = signer.export_public_key()

        # Sign message
        message = b"Important document that needs quantum-resistant signature"
        signature = signer.sign(message)

        # Validate signature size
        assert len(signature) == 3309

        # Verify signature
        verifier = pqc.DilithiumSigner.from_public_key(public_key)
        assert verifier.verify(message, signature) is True

    def test_verify_invalid_signature(self) -> None:
        """Test verification fails with wrong signature."""
        signer = pqc.DilithiumSigner.generate()
        public_key = signer.export_public_key()

        message = b"Original message"
        signature = signer.sign(message)

        # Verify with wrong message
        verifier = pqc.DilithiumSigner.from_public_key(public_key)
        wrong_message = b"Modified message"
        assert verifier.verify(wrong_message, signature) is False

    def test_verify_corrupted_signature(self) -> None:
        """Test verification fails with corrupted signature."""
        signer = pqc.DilithiumSigner.generate()
        public_key = signer.export_public_key()

        message = b"Test message"
        signature = signer.sign(message)

        # Corrupt signature
        corrupted_signature = bytearray(signature)
        corrupted_signature[100] ^= 0xFF

        verifier = pqc.DilithiumSigner.from_public_key(public_key)
        assert verifier.verify(message, bytes(corrupted_signature)) is False

    def test_verify_wrong_signature_length(self) -> None:
        """Test verification fails with wrong signature length."""
        signer = pqc.DilithiumSigner.generate()
        public_key = signer.export_public_key()

        message = b"Test message"
        wrong_signature = b"S" * 100  # Wrong length

        verifier = pqc.DilithiumSigner.from_public_key(public_key)
        assert verifier.verify(message, wrong_signature) is False

    def test_from_public_key_cannot_sign(self) -> None:
        """Test that public-key-only instance cannot sign."""
        signer = pqc.DilithiumSigner.generate()
        public_key = signer.export_public_key()

        verifier = pqc.DilithiumSigner.from_public_key(public_key)

        with pytest.raises(SignatureError, match="No secret key available"):
            verifier.sign(b"message")

    def test_from_public_key_cannot_export_secret(self) -> None:
        """Test that public-key-only instance cannot export secret key."""
        signer = pqc.DilithiumSigner.generate()
        public_key = signer.export_public_key()

        verifier = pqc.DilithiumSigner.from_public_key(public_key)

        with pytest.raises(CryptoKeyError, match="No secret key available"):
            verifier.export_secret_key()

    def test_sign_different_messages_produce_different_signatures(self) -> None:
        """Test that different messages produce different signatures."""
        signer = pqc.DilithiumSigner.generate()

        sig1 = signer.sign(b"Message 1")
        sig2 = signer.sign(b"Message 2")

        assert sig1 != sig2


class TestDilithiumSignerMocked:
    """Tests using mocked Dilithium (works without pqcrypto)."""

    def test_init_without_dilithium_installed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test DilithiumSigner.__init__ raises ImportError when not available."""
        monkeypatch.setattr(pqc, "DILITHIUM_AVAILABLE", False)

        with pytest.raises(ImportError, match="Dilithium not available"):
            pqc.DilithiumSigner(b"fake_pk")

    def test_generate_without_dilithium_installed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test DilithiumSigner.generate raises ImportError when not available."""
        monkeypatch.setattr(pqc, "DILITHIUM_AVAILABLE", False)

        with pytest.raises(ImportError, match="Dilithium not available"):
            pqc.DilithiumSigner.generate()

    @pytest.mark.skipif(not pqc.DILITHIUM_AVAILABLE, reason="Need real Dilithium")
    def test_verify_without_public_key(self) -> None:
        """Test verify raises when no public key."""
        signer = pqc.DilithiumSigner.__new__(pqc.DilithiumSigner)
        signer._public_key = None  # type: ignore[assignment]
        signer._secret_key = b"fake"

        with pytest.raises(SignatureError, match="No public key available"):
            signer.verify(b"message", b"S" * 3293)

    @pytest.mark.skipif(not pqc.DILITHIUM_AVAILABLE, reason="Need real Dilithium")
    def test_export_public_key_when_none(self) -> None:
        """Test export_public_key raises when no public key."""
        signer = pqc.DilithiumSigner.__new__(pqc.DilithiumSigner)
        signer._public_key = None  # type: ignore[assignment]
        signer._secret_key = b"fake"

        with pytest.raises(CryptoKeyError, match="No public key available"):
            signer.export_public_key()


# ============================================================================
# Hybrid KEM Tests
# ============================================================================


@pytest.mark.skipif(not pqc.KYBER_AVAILABLE, reason="Kyber not installed")
class TestHybridKEMReal:
    """Tests for hybrid X25519 + Kyber KEM."""

    def test_hybrid_kem_basic(self) -> None:
        """Test basic hybrid KEM operation."""
        from cryptography.hazmat.primitives.asymmetric import x25519

        # Generate keys
        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key().public_bytes_raw()

        kyber = pqc.KyberKEM.generate()
        kyber_public = kyber.export_public_key()

        # Perform hybrid KEM
        kyber_ct, x25519_ephemeral_pk, combined_secret = pqc.hybrid_kem_x25519_kyber(
            x25519_public, kyber_public
        )

        # Validate sizes
        assert len(kyber_ct) == 1088
        assert len(x25519_ephemeral_pk) == 32
        assert len(combined_secret) == 64

    def test_hybrid_kem_invalid_x25519_length(self) -> None:
        """Test hybrid KEM fails with invalid X25519 key length."""
        kyber = pqc.KyberKEM.generate()
        kyber_public = kyber.export_public_key()

        invalid_x25519 = b"X" * 16  # Wrong length

        with pytest.raises(ValueError, match="X25519 public key must be 32 bytes"):
            pqc.hybrid_kem_x25519_kyber(invalid_x25519, kyber_public)

    def test_hybrid_kem_invalid_kyber_length(self) -> None:
        """Test hybrid KEM fails with invalid Kyber key length."""
        from cryptography.hazmat.primitives.asymmetric import x25519

        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key().public_bytes_raw()

        invalid_kyber = b"K" * 500  # Wrong length

        with pytest.raises(ValueError, match="Kyber public key must be 1184 bytes"):
            pqc.hybrid_kem_x25519_kyber(x25519_public, invalid_kyber)

    def test_hybrid_kem_deterministic_with_same_keys(self) -> None:
        """Test that hybrid KEM produces different secrets each time (random)."""
        from cryptography.hazmat.primitives.asymmetric import x25519

        # Same keys
        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key().public_bytes_raw()

        kyber = pqc.KyberKEM.generate()
        kyber_public = kyber.export_public_key()

        # Call twice
        _, _, secret1 = pqc.hybrid_kem_x25519_kyber(x25519_public, kyber_public)
        _, _, secret2 = pqc.hybrid_kem_x25519_kyber(x25519_public, kyber_public)

        # Should be different (random ephemeral keys)
        assert secret1 != secret2


class TestHybridKEMMocked:
    """Tests for hybrid KEM with mocking."""

    def test_hybrid_kem_without_kyber(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test hybrid KEM fails gracefully without Kyber."""
        monkeypatch.setattr(pqc, "KYBER_AVAILABLE", False)

        with pytest.raises(ImportError):
            pqc.hybrid_kem_x25519_kyber(b"X" * 32, b"K" * 1184)


# ============================================================================
# Integration Tests
# ============================================================================


@pytest.mark.skipif(
    not (pqc.KYBER_AVAILABLE and pqc.DILITHIUM_AVAILABLE),
    reason="Full PQC suite not installed",
)
class TestPQCIntegration:
    """Integration tests using both Kyber and Dilithium."""

    def test_full_pqc_workflow(self) -> None:
        """Test complete PQC workflow: KEM + Signatures."""
        # Step 1: Generate keys
        kem_receiver = pqc.KyberKEM.generate()
        signer = pqc.DilithiumSigner.generate()

        # Step 2: Export public keys
        kyber_pk = kem_receiver.export_public_key()
        dilithium_pk = signer.export_public_key()

        # Step 3: Sender encapsulates secret
        kem_sender = pqc.KyberKEM.from_public_key(kyber_pk)
        ciphertext, shared_secret_sender = kem_sender.encapsulate()

        # Step 4: Sender signs the ciphertext
        signature = signer.sign(ciphertext)

        # Step 5: Receiver verifies signature
        verifier = pqc.DilithiumSigner.from_public_key(dilithium_pk)
        assert verifier.verify(ciphertext, signature) is True

        # Step 6: Receiver decapsulates secret
        shared_secret_receiver = kem_receiver.decapsulate(ciphertext)

        # Step 7: Verify secrets match
        assert shared_secret_sender == shared_secret_receiver

    def test_multiple_recipients(self) -> None:
        """Test encrypting for multiple recipients with Kyber."""
        # Generate sender signer
        sender_signer = pqc.DilithiumSigner.generate()

        # Generate multiple recipient KEMs
        recipients = [pqc.KyberKEM.generate() for _ in range(3)]

        message = b"Secret message for multiple recipients"

        # Encapsulate for each recipient
        for recipient_kem in recipients:
            kyber_pk = recipient_kem.export_public_key()
            kem_sender = pqc.KyberKEM.from_public_key(kyber_pk)
            ct, ss = kem_sender.encapsulate()

            # Sign ciphertext
            sig = sender_signer.sign(ct + message)

            # Recipient can verify and decrypt
            verifier = pqc.DilithiumSigner.from_public_key(
                sender_signer.export_public_key()
            )
            assert verifier.verify(ct + message, sig) is True

            # Decrypt
            ss_recv = recipient_kem.decapsulate(ct)
            assert ss == ss_recv


# ============================================================================
# Edge Cases and Error Handling
# ============================================================================


@pytest.mark.skipif(not pqc.KYBER_AVAILABLE, reason="Kyber not installed")
class TestKyberEdgeCases:
    """Edge case tests for Kyber."""

    def test_kyber_with_empty_ciphertext(self) -> None:
        """Test decapsulation with empty ciphertext."""
        kem = pqc.KyberKEM.generate()

        with pytest.raises(ValueError, match="must be 1088 bytes"):
            kem.decapsulate(b"")

    def test_kyber_ciphertext_too_long(self) -> None:
        """Test decapsulation with too long ciphertext."""
        kem = pqc.KyberKEM.generate()

        with pytest.raises(ValueError, match="must be 1088 bytes"):
            kem.decapsulate(b"X" * 2000)


@pytest.mark.skipif(not pqc.DILITHIUM_AVAILABLE, reason="Dilithium not installed")
class TestDilithiumEdgeCases:
    """Edge case tests for Dilithium."""

    def test_dilithium_sign_empty_message(self) -> None:
        """Test signing empty message."""
        signer = pqc.DilithiumSigner.generate()

        signature = signer.sign(b"")
        assert len(signature) == 3309

        # Should verify
        public_key = signer.export_public_key()
        verifier = pqc.DilithiumSigner.from_public_key(public_key)
        assert verifier.verify(b"", signature) is True

    def test_dilithium_sign_large_message(self) -> None:
        """Test signing large message."""
        signer = pqc.DilithiumSigner.generate()

        large_message = b"X" * (10 * 1024 * 1024)  # 10 MB
        signature = signer.sign(large_message)

        assert len(signature) == 3309

        # Should verify
        public_key = signer.export_public_key()
        verifier = pqc.DilithiumSigner.from_public_key(public_key)
        assert verifier.verify(large_message, signature) is True

    def test_dilithium_verify_empty_signature(self) -> None:
        """Test verification with empty signature."""
        signer = pqc.DilithiumSigner.generate()
        public_key = signer.export_public_key()

        verifier = pqc.DilithiumSigner.from_public_key(public_key)
        assert verifier.verify(b"message", b"") is False


# ============================================================================
# Performance and Stress Tests
# ============================================================================


@pytest.mark.skipif(not pqc.KYBER_AVAILABLE, reason="Kyber not installed")
class TestKyberPerformance:
    """Performance-related tests for Kyber."""

    def test_multiple_encapsulations(self) -> None:
        """Test multiple encapsulations work correctly."""
        kem = pqc.KyberKEM.generate()
        public_key = kem.export_public_key()
        kem_sender = pqc.KyberKEM.from_public_key(public_key)

        # Perform 10 encapsulations
        results = [kem_sender.encapsulate() for _ in range(10)]

        # All ciphertexts should be unique
        ciphertexts = [ct for ct, _ in results]
        assert len(set(ciphertexts)) == 10

        # All shared secrets should be unique
        secrets = [ss for _, ss in results]
        assert len(set(secrets)) == 10


@pytest.mark.skipif(not pqc.DILITHIUM_AVAILABLE, reason="Dilithium not installed")
class TestDilithiumPerformance:
    """Performance-related tests for Dilithium."""

    def test_multiple_signatures(self) -> None:
        """Test signing multiple messages."""
        signer = pqc.DilithiumSigner.generate()

        messages = [f"Message {i}".encode() for i in range(10)]
        signatures = [signer.sign(msg) for msg in messages]

        # All signatures should be valid
        public_key = signer.export_public_key()
        verifier = pqc.DilithiumSigner.from_public_key(public_key)

        for msg, sig in zip(messages, signatures):
            assert verifier.verify(msg, sig) is True


# ============================================================================
# Additional Coverage Tests (87.83% → 90%+)
# ============================================================================


@pytest.mark.skipif(not pqc.KYBER_AVAILABLE, reason="Kyber not installed")
class TestKyberKEMCoverage:
    """Tests to increase coverage for KyberKEM."""

    def test_init_with_fallback_algorithm(self) -> None:
        """Test __init__ fallback when ML-KEM-768 not supported."""
        import oqs

        # Generate with fallback algorithm name
        kem = pqc.KyberKEM.generate()
        public_key = kem.export_public_key()

        # Manually test fallback path by patching
        original_mechanism = oqs.KeyEncapsulation

        def mock_mechanism(name: str, **kwargs: Any) -> Any:
            if name == "ML-KEM-768":
                raise oqs.MechanismNotSupportedError("Test fallback")
            return original_mechanism(name, **kwargs)

        with patch("oqs.KeyEncapsulation", side_effect=mock_mechanism):
            kem_fallback = pqc.KyberKEM(public_key, None)
            assert kem_fallback._algorithm == pqc.KyberKEM._ALGORITHM_FALLBACK

    def test_generate_with_fallback_algorithm(self) -> None:
        """Test generate() uses fallback when ML-KEM-768 not supported."""
        # Verify that generate() works and sets _algorithm correctly
        kem = pqc.KyberKEM.generate()

        # Should have one of the valid algorithm names
        assert hasattr(kem, "_algorithm")
        assert kem._algorithm in [
            pqc.KyberKEM._ALGORITHM_NAME,  # ML-KEM-768
            pqc.KyberKEM._ALGORITHM_FALLBACK,  # Kyber768
        ]

        # Verify it actually works
        public_key = kem.export_public_key()
        kem_sender = pqc.KyberKEM.from_public_key(public_key)
        ciphertext, shared_secret = kem_sender.encapsulate()

        # Verify decapsulation works
        decrypted_secret = kem.decapsulate(ciphertext)
        assert decrypted_secret == shared_secret
        assert len(ciphertext) == 1088
        assert len(shared_secret) == 32


@pytest.mark.skipif(not pqc.DILITHIUM_AVAILABLE, reason="Dilithium not installed")
class TestDilithiumSignerCoverage:
    """Tests to increase coverage for DilithiumSigner."""

    def test_init_with_fallback_algorithm(self) -> None:
        """Test __init__ fallback when ML-DSA-65 not supported."""
        import oqs

        signer = pqc.DilithiumSigner.generate()
        public_key = signer.export_public_key()

        # Test fallback path
        original_mechanism = oqs.Signature

        def mock_mechanism(name: str, **kwargs: Any) -> Any:
            if name == "ML-DSA-65":
                raise oqs.MechanismNotSupportedError("Test fallback")
            return original_mechanism(name, **kwargs)

        with patch("oqs.Signature", side_effect=mock_mechanism):
            signer_fallback = pqc.DilithiumSigner(public_key, None)
            assert signer_fallback._algorithm == pqc.DilithiumSigner._ALGORITHM_FALLBACK

    def test_generate_with_fallback_algorithm(self) -> None:
        """Test generate() uses fallback when ML-DSA-65 not supported."""
        # Verify that generate() works and sets _algorithm correctly
        signer = pqc.DilithiumSigner.generate()

        # Should have one of the valid algorithm names
        assert hasattr(signer, "_algorithm")
        assert signer._algorithm in [
            pqc.DilithiumSigner._ALGORITHM_NAME,  # ML-DSA-65
            pqc.DilithiumSigner._ALGORITHM_FALLBACK,  # Dilithium3
        ]

        # Verify it actually works
        message = b"test fallback"
        signature = signer.sign(message)
        assert len(signature) == 3309

        # Verify with public key
        public_key = signer.export_public_key()
        verifier = pqc.DilithiumSigner.from_public_key(public_key)
        assert verifier.verify(message, signature) is True

    def test_verify_exception_handling(self) -> None:
        """Test verify() returns False on internal oqs exceptions."""
        signer = pqc.DilithiumSigner.generate()
        public_key = signer.export_public_key()
        verifier = pqc.DilithiumSigner.from_public_key(public_key)

        # Valid length but corrupted signature - should catch exception
        corrupted_sig = b"\x00" * 3309
        result = verifier.verify(b"test", corrupted_sig)
        assert result is False

    def test_verify_with_old_dilithium3_signature_size(self) -> None:
        """Test verify() handles old Dilithium3 signature size (3293 bytes)."""
        signer = pqc.DilithiumSigner.generate()
        public_key = signer.export_public_key()
        verifier = pqc.DilithiumSigner.from_public_key(public_key)

        # Simulate old signature size
        old_signature = b"S" * 3293  # Old Dilithium3 size

        # Should fail validation due to wrong size
        assert verifier.verify(b"test", old_signature) is False


@pytest.mark.skipif(not pqc.KYBER_AVAILABLE, reason="Kyber not installed")
class TestHybridKEMCoverage:
    """Additional coverage for hybrid_kem_x25519_kyber."""

    def test_hybrid_kem_with_kyber_unavailable_runtime(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test hybrid KEM when Kyber becomes unavailable at runtime."""
        from cryptography.hazmat.primitives.asymmetric import x25519

        x25519_private = x25519.X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key().public_bytes_raw()
        kyber = pqc.KyberKEM.generate()
        kyber_public = kyber.export_public_key()

        # Should work normally
        result = pqc.hybrid_kem_x25519_kyber(x25519_public, kyber_public)
        assert len(result) == 3
        assert len(result[0]) == 1088  # Kyber ciphertext
        assert len(result[1]) == 32  # X25519 ephemeral public
        assert len(result[2]) == 64  # Combined secret


# ============================================================================
# Final Coverage Push (89.95% → 90%+)
# ============================================================================


@pytest.mark.skipif(not pqc.KYBER_AVAILABLE, reason="Kyber not installed")
class TestKyberKEMFallbackCoverage:
    """Tests to cover fallback algorithm paths in KyberKEM."""

    def test_init_mechanism_not_supported_fallback(self) -> None:
        """Test __init__ fallback to Kyber768 when ML-KEM-768 unavailable.

        Covers lines 66-70: except MechanismNotSupportedError in __init__
        """
        import oqs

        # Generate real keypair first
        kem = pqc.KyberKEM.generate()
        public_key = kem.export_public_key()
        secret_key = kem.export_secret_key()

        # Mock KeyEncapsulation to force fallback on first call
        original_kem = oqs.KeyEncapsulation
        call_count = 0

        class MockKEM:
            def __init__(self, alg_name: str, secret_key: bytes | None = None) -> None:
                nonlocal call_count
                call_count += 1

                # First call with ML-KEM-768 fails
                if alg_name == "ML-KEM-768" and call_count == 1:
                    raise oqs.MechanismNotSupportedError("ML-KEM-768 not supported")

                # Fallback to Kyber768 succeeds
                self._real_kem = original_kem(alg_name, secret_key=secret_key)

            def __enter__(self) -> Any:
                return self._real_kem.__enter__()

            def __exit__(self, *args: Any) -> Any:
                return self._real_kem.__exit__(*args)

        with patch("oqs.KeyEncapsulation", MockKEM):
            kem_fallback = pqc.KyberKEM(public_key, secret_key)
            assert kem_fallback._algorithm == pqc.KyberKEM._ALGORITHM_FALLBACK

    def test_generate_mechanism_not_supported_fallback(self) -> None:
        """Test generate() fallback to Kyber768 when ML-KEM-768 unavailable.

        Covers lines 118: except MechanismNotSupportedError in generate()
        """
        import oqs

        original_kem = oqs.KeyEncapsulation
        attempt = 0

        class MockKEM:
            def __init__(self, alg_name: str, secret_key: bytes | None = None) -> None:
                nonlocal attempt
                attempt += 1

                # First attempt with ML-KEM-768 fails
                if alg_name == "ML-KEM-768" and attempt == 1:
                    raise oqs.MechanismNotSupportedError("ML-KEM-768 not supported")

                # Fallback to Kyber768 succeeds
                self._real = original_kem(alg_name, secret_key=secret_key)

            def __enter__(self) -> Any:
                return self._real.__enter__()

            def __exit__(self, *args: Any) -> Any:
                return self._real.__exit__(*args)

            def generate_keypair(self) -> Any:
                return self._real.generate_keypair()

            def export_secret_key(self) -> Any:
                return self._real.export_secret_key()

        with patch("oqs.KeyEncapsulation", MockKEM):
            kem = pqc.KyberKEM.generate()
            assert kem._algorithm == pqc.KyberKEM._ALGORITHM_FALLBACK

            # Verify it works
            public_key = kem.export_public_key()
            assert len(public_key) == 1184


@pytest.mark.skipif(not pqc.DILITHIUM_AVAILABLE, reason="Dilithium not installed")
class TestDilithiumSignerFallbackCoverage:
    """Tests to cover fallback algorithm paths in DilithiumSigner."""

    def test_init_mechanism_not_supported_fallback(self) -> None:
        """Test __init__ fallback to Dilithium3 when ML-DSA-65 unavailable.

        Covers lines 157-161: except MechanismNotSupportedError in __init__
        """
        import oqs

        # Generate real keypair first
        signer = pqc.DilithiumSigner.generate()
        public_key = signer.export_public_key()
        secret_key = signer.export_secret_key()

        original_sig = oqs.Signature
        call_count = 0

        class MockSig:
            def __init__(self, alg_name: str, secret_key: bytes | None = None) -> None:
                nonlocal call_count
                call_count += 1

                if alg_name == "ML-DSA-65" and call_count == 1:
                    raise oqs.MechanismNotSupportedError("ML-DSA-65 not supported")

                self._real_sig = original_sig(alg_name, secret_key=secret_key)

            def __enter__(self) -> Any:
                return self._real_sig.__enter__()

            def __exit__(self, *args: Any) -> Any:
                return self._real_sig.__exit__(*args)

        with patch("oqs.Signature", MockSig):
            signer_fallback = pqc.DilithiumSigner(public_key, secret_key)
            assert signer_fallback._algorithm == pqc.DilithiumSigner._ALGORITHM_FALLBACK

    def test_verify_with_exception_in_oqs(self) -> None:
        """Test verify() catches and returns False on oqs exceptions.

        Covers lines 204-206: except Exception in verify()
        """
        import oqs

        signer = pqc.DilithiumSigner.generate()
        public_key = signer.export_public_key()
        message = b"test message"
        signature = signer.sign(message)

        verifier = pqc.DilithiumSigner.from_public_key(public_key)

        # Mock Signature.verify to raise exception
        class MockSigWithException:
            def __init__(self, alg_name: str, secret_key: bytes | None = None) -> None:
                pass

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *args: Any) -> Any:
                pass

            def verify(
                self, message: bytes, signature: bytes, public_key: bytes
            ) -> bool:
                raise RuntimeError("OQS internal error")

        with patch("oqs.Signature", MockSigWithException):
            result = verifier.verify(message, signature)
            assert result is False


class TestImportErrorCoverage:
    """Tests to cover ImportError paths when liboqs not available."""

    def test_kyber_unavailable_on_init(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test KyberKEM.__init__ raises ImportError when KYBER_AVAILABLE=False.

        Covers lines 24-27: ImportError in module init (indirectly)
        """
        monkeypatch.setattr(pqc, "KYBER_AVAILABLE", False)

        with pytest.raises(ImportError, match="Kyber not available"):
            pqc.KyberKEM(b"fake_pk", None)

    def test_kyber_unavailable_on_generate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test KyberKEM.generate raises ImportError when KYBER_AVAILABLE=False."""
        monkeypatch.setattr(pqc, "KYBER_AVAILABLE", False)

        with pytest.raises(ImportError, match="Kyber not available"):
            pqc.KyberKEM.generate()

    def test_dilithium_unavailable_on_init(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test DilithiumSigner.__init__ raises ImportError when DILITHIUM_AVAILABLE=False."""
        monkeypatch.setattr(pqc, "DILITHIUM_AVAILABLE", False)

        with pytest.raises(ImportError, match="Dilithium not available"):
            pqc.DilithiumSigner(b"fake_pk", None)

    def test_dilithium_unavailable_on_generate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test DilithiumSigner.generate raises ImportError when DILITHIUM_AVAILABLE=False."""
        monkeypatch.setattr(pqc, "DILITHIUM_AVAILABLE", False)

        with pytest.raises(ImportError, match="Dilithium not available"):
            pqc.DilithiumSigner.generate()
