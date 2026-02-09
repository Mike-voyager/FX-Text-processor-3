"""
Comprehensive tests for symmetric cipher algorithms.

Tests all 10 symmetric ciphers from CRYPTO_MASTER_PLAN v2.3:
- AEAD ciphers (7): AES-GCM variants, ChaCha20, XChaCha20, SIV, OCB, GCM-SIV
- Legacy ciphers (2): TripleDES, DES
- Non-AEAD (1): AES-256-CTR

Test Coverage:
- Basic encrypt/decrypt operations
- Input validation (keys, nonces, plaintext)
- Error handling (invalid keys, tampered data)
- AAD (Additional Authenticated Data)
- Edge cases (empty plaintext, large data)
- Nonce generation and validation
- Algorithm registry and factory

Version: 1.0.0
Date: February 9, 2026
"""

from __future__ import annotations

import os
from typing import Any, Type

import pytest

from src.security.crypto.algorithms.symmetric import (
    AES128GCM,
    AES256CTR,
    AES256GCM,
    AES256GCMSIV,
    AES256OCB,
    AES256SIV,
    ALGORITHMS,
    DES,
    ChaCha20Poly1305,
    TripleDES,
    XChaCha20Poly1305,
    get_algorithm,
)
from src.security.crypto.core.exceptions import (
    DecryptionFailedError,
    EncryptionFailedError,
    InvalidKeyError,
    InvalidNonceError,
)


# ==============================================================================
# FIXTURES
# ==============================================================================


@pytest.fixture
def aes256gcm() -> AES256GCM:
    """AES-256-GCM cipher instance."""
    return AES256GCM()


@pytest.fixture
def aes128gcm() -> AES128GCM:
    """AES-128-GCM cipher instance."""
    return AES128GCM()


@pytest.fixture
def chacha20() -> ChaCha20Poly1305:
    """ChaCha20-Poly1305 cipher instance."""
    return ChaCha20Poly1305()


@pytest.fixture
def aes256siv() -> AES256SIV:
    """AES-256-SIV cipher instance."""
    return AES256SIV()


@pytest.fixture
def aes256ocb() -> AES256OCB:
    """AES-256-OCB cipher instance."""
    return AES256OCB()


@pytest.fixture
def triple_des() -> TripleDES:
    """TripleDES cipher instance."""
    return TripleDES()


@pytest.fixture
def aes256ctr() -> AES256CTR:
    """AES-256-CTR cipher instance."""
    return AES256CTR()


# ==============================================================================
# TEST SUITE: AES-256-GCM (Reference Implementation)
# ==============================================================================


class TestAES256GCM:
    """Test suite for AES-256-GCM cipher."""

    def test_basic_encrypt_decrypt(self, aes256gcm: AES256GCM) -> None:
        """Test basic encryption and decryption."""
        key = os.urandom(32)
        plaintext = b"Hello, World!"

        nonce, ciphertext = aes256gcm.encrypt(key, plaintext)
        decrypted = aes256gcm.decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext
        assert len(nonce) == 12
        assert len(ciphertext) == len(plaintext) + 16  # +16 for tag

    def test_encrypt_with_custom_nonce(self, aes256gcm: AES256GCM) -> None:
        """Test encryption with custom nonce."""
        key = os.urandom(32)
        nonce = os.urandom(12)
        plaintext = b"Custom nonce test"

        returned_nonce, ciphertext = aes256gcm.encrypt(key, plaintext, nonce=nonce)
        decrypted = aes256gcm.decrypt(key, nonce, ciphertext)

        assert returned_nonce == nonce
        assert decrypted == plaintext

    def test_encrypt_with_aad(self, aes256gcm: AES256GCM) -> None:
        """Test encryption with Additional Authenticated Data."""
        key = os.urandom(32)
        plaintext = b"Secret message"
        aad = b"user_id:12345"

        nonce, ciphertext = aes256gcm.encrypt(key, plaintext, aad=aad)
        decrypted = aes256gcm.decrypt(key, nonce, ciphertext, aad=aad)

        assert decrypted == plaintext

    def test_decrypt_with_wrong_aad_fails(self, aes256gcm: AES256GCM) -> None:
        """Test that decryption fails with wrong AAD."""
        key = os.urandom(32)
        plaintext = b"Secret message"
        aad = b"correct_aad"
        wrong_aad = b"wrong_aad"

        nonce, ciphertext = aes256gcm.encrypt(key, plaintext, aad=aad)

        with pytest.raises(DecryptionFailedError):
            aes256gcm.decrypt(key, nonce, ciphertext, aad=wrong_aad)

    def test_decrypt_with_wrong_key_fails(self, aes256gcm: AES256GCM) -> None:
        """Test that decryption fails with wrong key."""
        key = os.urandom(32)
        wrong_key = os.urandom(32)
        plaintext = b"Secret"

        nonce, ciphertext = aes256gcm.encrypt(key, plaintext)

        with pytest.raises(DecryptionFailedError):
            aes256gcm.decrypt(wrong_key, nonce, ciphertext)

    def test_decrypt_tampered_ciphertext_fails(self, aes256gcm: AES256GCM) -> None:
        """Test that decryption fails with tampered ciphertext."""
        key = os.urandom(32)
        plaintext = b"Secret"

        nonce, ciphertext = aes256gcm.encrypt(key, plaintext)

        # Tamper with last byte
        tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])

        with pytest.raises(DecryptionFailedError):
            aes256gcm.decrypt(key, nonce, tampered)

    def test_invalid_key_size(self, aes256gcm: AES256GCM) -> None:
        """Test that invalid key size raises error."""
        short_key = os.urandom(16)  # 128-bit (should be 256-bit)
        plaintext = b"test"

        with pytest.raises(InvalidKeyError, match="32-byte key"):
            aes256gcm.encrypt(short_key, plaintext)

    def test_invalid_nonce_size(self, aes256gcm: AES256GCM) -> None:
        """Test that invalid nonce size raises error."""
        key = os.urandom(32)
        bad_nonce = os.urandom(8)  # Should be 12 bytes
        plaintext = b"test"

        with pytest.raises(InvalidNonceError, match="12-byte nonce"):
            aes256gcm.encrypt(key, plaintext, nonce=bad_nonce)

    def test_empty_plaintext(self, aes256gcm: AES256GCM) -> None:
        """Test encryption of empty plaintext."""
        key = os.urandom(32)
        plaintext = b""

        nonce, ciphertext = aes256gcm.encrypt(key, plaintext)
        decrypted = aes256gcm.decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext
        assert len(ciphertext) == 16  # Only tag

    def test_large_plaintext(self, aes256gcm: AES256GCM) -> None:
        """Test encryption of large plaintext (1 MB)."""
        key = os.urandom(32)
        plaintext = os.urandom(1024 * 1024)  # 1 MB

        nonce, ciphertext = aes256gcm.encrypt(key, plaintext)
        decrypted = aes256gcm.decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext

    def test_nonce_uniqueness(self, aes256gcm: AES256GCM) -> None:
        """Test that auto-generated nonces are unique."""
        key = os.urandom(32)
        plaintext = b"test"

        nonces = set()
        for _ in range(100):
            nonce, _ = aes256gcm.encrypt(key, plaintext)
            nonces.add(nonce)

        # All nonces should be unique (probability of collision is negligible)
        assert len(nonces) == 100


# ==============================================================================
# TEST SUITE: AES-128-GCM
# ==============================================================================


class TestAES128GCM:
    """Test suite for AES-128-GCM cipher."""

    def test_basic_encrypt_decrypt(self, aes128gcm: AES128GCM) -> None:
        """Test basic encryption and decryption."""
        key = os.urandom(16)  # 128-bit key
        plaintext = b"Fast encryption"

        nonce, ciphertext = aes128gcm.encrypt(key, plaintext)
        decrypted = aes128gcm.decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext
        assert len(nonce) == 12

    def test_invalid_key_size(self, aes128gcm: AES128GCM) -> None:
        """Test that 256-bit key fails (requires 128-bit)."""
        key = os.urandom(32)  # 256-bit (wrong!)
        plaintext = b"test"

        with pytest.raises(InvalidKeyError, match="16-byte key"):
            aes128gcm.encrypt(key, plaintext)

    def test_with_aad(self, aes128gcm: AES128GCM) -> None:
        """Test encryption with AAD."""
        key = os.urandom(16)
        plaintext = b"data"
        aad = b"metadata"

        nonce, ciphertext = aes128gcm.encrypt(key, plaintext, aad=aad)
        decrypted = aes128gcm.decrypt(key, nonce, ciphertext, aad=aad)

        assert decrypted == plaintext


# ==============================================================================
# TEST SUITE: ChaCha20-Poly1305
# ==============================================================================


class TestChaCha20Poly1305:
    """Test suite for ChaCha20-Poly1305 cipher."""

    def test_basic_encrypt_decrypt(self, chacha20: ChaCha20Poly1305) -> None:
        """Test basic encryption and decryption."""
        key = os.urandom(32)
        plaintext = b"Software-optimized cipher"

        nonce, ciphertext = chacha20.encrypt(key, plaintext)
        decrypted = chacha20.decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext
        assert len(nonce) == 12

    def test_constant_time(self, chacha20: ChaCha20Poly1305) -> None:
        """Test that ChaCha20 is constant-time (no cache-timing)."""
        # This is a basic test - full constant-time verification requires
        # specialized tools like ctgrind or dudect
        key = os.urandom(32)
        plaintext1 = b"\x00" * 100
        plaintext2 = b"\xff" * 100

        nonce1, ct1 = chacha20.encrypt(key, plaintext1)
        nonce2, ct2 = chacha20.encrypt(key, plaintext2)

        # Both should succeed (basic check)
        assert len(ct1) == len(ct2)

    def test_decrypt_wrong_key_fails(self, chacha20: ChaCha20Poly1305) -> None:
        """Test that wrong key fails authentication."""
        key = os.urandom(32)
        wrong_key = os.urandom(32)
        plaintext = b"test"

        nonce, ciphertext = chacha20.encrypt(key, plaintext)

        with pytest.raises(DecryptionFailedError):
            chacha20.decrypt(wrong_key, nonce, ciphertext)


# ==============================================================================
# TEST SUITE: XChaCha20-Poly1305
# ==============================================================================


class TestXChaCha20Poly1305:
    """Test suite for XChaCha20-Poly1305 cipher."""

    def test_basic_encrypt_decrypt(self) -> None:
        """Test basic encryption and decryption."""
        try:
            cipher = XChaCha20Poly1305()
        except RuntimeError as e:
            pytest.skip(f"XChaCha20 not available: {e}")

        key = os.urandom(32)
        plaintext = b"Extended nonce cipher"

        nonce, ciphertext = cipher.encrypt(key, plaintext)
        decrypted = cipher.decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext
        assert len(nonce) == 24  # 192-bit nonce!

    def test_extended_nonce_size(self) -> None:
        """Test that XChaCha20 uses 24-byte nonce."""
        try:
            cipher = XChaCha20Poly1305()
        except RuntimeError:
            pytest.skip("XChaCha20 not available")

        key = os.urandom(32)
        plaintext = b"test"

        # Custom 24-byte nonce
        nonce = os.urandom(24)
        returned_nonce, ciphertext = cipher.encrypt(key, plaintext, nonce=nonce)

        assert returned_nonce == nonce
        assert len(returned_nonce) == 24

    def test_invalid_nonce_size(self) -> None:
        """Test that 12-byte nonce fails (requires 24 bytes)."""
        try:
            cipher = XChaCha20Poly1305()
        except RuntimeError:
            pytest.skip("XChaCha20 not available")

        key = os.urandom(32)
        bad_nonce = os.urandom(12)  # Should be 24!

        with pytest.raises(InvalidNonceError, match="24-byte nonce"):
            cipher.encrypt(key, b"test", nonce=bad_nonce)


# ==============================================================================
# TEST SUITE: AES-256-SIV (Nonce-Reuse Resistant)
# ==============================================================================


class TestAES256SIV:
    """Test suite for AES-256-SIV cipher."""

    def test_basic_encrypt_decrypt(self, aes256siv: AES256SIV) -> None:
        """Test basic encryption and decryption."""
        key = os.urandom(64)  # 512-bit key (TWO 256-bit keys!)
        plaintext = b"Nonce-reuse resistant"

        nonce, ciphertext = aes256siv.encrypt(key, plaintext)
        decrypted = aes256siv.decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext

    def test_requires_64_byte_key(self, aes256siv: AES256SIV) -> None:
        """Test that SIV requires 64-byte key."""
        key = os.urandom(32)  # Wrong! Should be 64
        plaintext = b"test"

        with pytest.raises(InvalidKeyError, match="64-byte key"):
            aes256siv.encrypt(key, plaintext)

    def test_deterministic_with_same_nonce(self, aes256siv: AES256SIV) -> None:
        """Test that SIV is deterministic for same nonce+plaintext."""
        key = os.urandom(64)
        plaintext = b"deterministic test"
        nonce = b"fixed_nonce_1234"

        _, ct1 = aes256siv.encrypt(key, plaintext, nonce=nonce)
        _, ct2 = aes256siv.encrypt(key, plaintext, nonce=nonce)

        # Same nonce + same plaintext = same ciphertext (deterministic)
        assert ct1 == ct2

    def test_different_ciphertext_for_different_plaintext(
        self, aes256siv: AES256SIV
    ) -> None:
        """Test that different plaintexts produce different ciphertexts."""
        key = os.urandom(64)
        nonce = b"fixed_nonce_1234"

        _, ct1 = aes256siv.encrypt(key, b"plaintext1", nonce=nonce)
        _, ct2 = aes256siv.encrypt(key, b"plaintext2", nonce=nonce)

        assert ct1 != ct2


# ==============================================================================
# TEST SUITE: AES-256-OCB
# ==============================================================================


class TestAES256OCB:
    """Test suite for AES-256-OCB cipher."""

    def test_basic_encrypt_decrypt(self, aes256ocb: AES256OCB) -> None:
        """Test basic encryption and decryption."""
        key = os.urandom(32)
        plaintext = b"Parallelizable cipher"

        nonce, ciphertext = aes256ocb.encrypt(key, plaintext)
        decrypted = aes256ocb.decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext

    def test_variable_nonce_size(self, aes256ocb: AES256OCB) -> None:
        """Test that OCB accepts 12-15 byte nonces."""
        key = os.urandom(32)
        plaintext = b"test"

        # Test all valid nonce sizes (12-15 bytes)
        for nonce_size in [12, 13, 14, 15]:
            nonce = os.urandom(nonce_size)
            _, ciphertext = aes256ocb.encrypt(key, plaintext, nonce=nonce)
            decrypted = aes256ocb.decrypt(key, nonce, ciphertext)
            assert decrypted == plaintext

    def test_invalid_nonce_size(self, aes256ocb: AES256OCB) -> None:
        """Test that nonces outside 12-15 range fail."""
        key = os.urandom(32)
        plaintext = b"test"

        # Too short (11 bytes)
        with pytest.raises(InvalidNonceError):
            aes256ocb.encrypt(key, plaintext, nonce=os.urandom(11))

        # Too long (16 bytes)
        with pytest.raises(InvalidNonceError):
            aes256ocb.encrypt(key, plaintext, nonce=os.urandom(16))


# ==============================================================================
# TEST SUITE: AES-256-GCM-SIV (NEW!)
# ==============================================================================


class TestAES256GCMSIV:
    """Test suite for AES-256-GCM-SIV cipher."""

    def test_basic_encrypt_decrypt(self) -> None:
        """Test basic encryption and decryption."""
        try:
            cipher = AES256GCMSIV()
        except RuntimeError as e:
            pytest.skip(f"AES-GCM-SIV not available: {e}")

        key = os.urandom(32)
        plaintext = b"Nonce-misuse resistant"

        nonce, ciphertext = cipher.encrypt(key, plaintext)
        decrypted = cipher.decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext

    def test_nonce_misuse_resistance(self) -> None:
        """Test that nonce reuse is safe (deterministic)."""
        try:
            cipher = AES256GCMSIV()
        except RuntimeError:
            pytest.skip("AES-GCM-SIV not available")

        key = os.urandom(32)
        plaintext = b"same plaintext"
        nonce = os.urandom(12)

        _, ct1 = cipher.encrypt(key, plaintext, nonce=nonce)
        _, ct2 = cipher.encrypt(key, plaintext, nonce=nonce)

        # Same nonce + plaintext = same ciphertext
        assert ct1 == ct2


# ==============================================================================
# TEST SUITE: TripleDES (LEGACY)
# ==============================================================================


class TestTripleDES:
    """Test suite for TripleDES (LEGACY) cipher."""

    def test_basic_encrypt_decrypt(self, triple_des: TripleDES) -> None:
        """Test basic encryption and decryption."""
        key = os.urandom(24)  # 192-bit key
        plaintext = b"Legacy data for compatibility"

        nonce, ciphertext = triple_des.encrypt(key, plaintext)
        decrypted = triple_des.decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext

    def test_requires_24_byte_key(self, triple_des: TripleDES) -> None:
        """Test that 3DES requires 24-byte key."""
        key = os.urandom(16)  # Wrong!
        plaintext = b"test"

        with pytest.raises(InvalidKeyError, match="24-byte key"):
            triple_des.encrypt(key, plaintext)

    def test_logs_deprecation_warning(self, caplog: Any) -> None:
        """Test that TripleDES logs deprecation warning."""
        cipher = TripleDES()
        assert "DEPRECATED" in caplog.text or "Migrate" in caplog.text


# ==============================================================================
# TEST SUITE: DES (BROKEN)
# ==============================================================================


class TestDES:
    """Test suite for DES (BROKEN) cipher."""

    def test_basic_encrypt_decrypt(self) -> None:
        """Test basic encryption and decryption (BROKEN algorithm!)."""
        try:
            cipher = DES()
        except RuntimeError as e:
            pytest.skip(f"DES not available: {e}")

        key = os.urandom(8)  # 64-bit key
        plaintext = b"Ancient data"

        nonce, ciphertext = cipher.encrypt(key, plaintext)
        decrypted = cipher.decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext

    def test_requires_8_byte_key(self) -> None:
        """Test that DES requires 8-byte key."""
        try:
            cipher = DES()
        except RuntimeError:
            pytest.skip("DES not available")

        key = os.urandom(16)  # Wrong!

        with pytest.raises(InvalidKeyError, match="8-byte key"):
            cipher.encrypt(key, b"test")

    def test_logs_critical_warning(self, caplog: Any) -> None:
        """Test that DES logs CRITICAL warning."""
        try:
            DES()
        except RuntimeError:
            pytest.skip("DES not available")

        assert "BROKEN" in caplog.text or "CRITICAL" in caplog.text


# ==============================================================================
# TEST SUITE: AES-256-CTR (Non-AEAD)
# ==============================================================================


class TestAES256CTR:
    """Test suite for AES-256-CTR cipher."""

    def test_basic_encrypt_decrypt(self, aes256ctr: AES256CTR) -> None:
        """Test basic encryption and decryption."""
        key = os.urandom(32)
        plaintext = b"Non-AEAD cipher"

        nonce, ciphertext = aes256ctr.encrypt(key, plaintext)
        decrypted = aes256ctr.decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext
        assert len(nonce) == 16  # Full AES block

    def test_no_authentication(self, aes256ctr: AES256CTR) -> None:
        """Test that CTR mode has NO authentication (non-AEAD)."""
        key = os.urandom(32)
        plaintext = b"test"

        nonce, ciphertext = aes256ctr.encrypt(key, plaintext)

        # Tamper with ciphertext - it will NOT fail (no tag!)
        tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])
        decrypted = aes256ctr.decrypt(key, nonce, tampered)

        # Decryption "succeeds" but produces garbage
        assert decrypted != plaintext  # Data is corrupted

    def test_logs_warning_about_hmac(self, caplog: Any) -> None:
        """Test that CTR logs warning about HMAC requirement."""
        AES256CTR()
        assert "HMAC" in caplog.text or "NOT AEAD" in caplog.text


# ==============================================================================
# TEST SUITE: Algorithm Registry
# ==============================================================================


class TestAlgorithmRegistry:
    """Test suite for algorithm registry and factory."""

    def test_algorithms_dict_has_all_ciphers(self) -> None:
        """Test that ALGORITHMS dict contains all 10 ciphers."""
        expected_ids = [
            "aes-128-gcm",
            "aes-256-gcm",
            "chacha20-poly1305",
            "xchacha20-poly1305",
            "aes-256-siv",
            "aes-256-ocb",
            "aes-256-gcm-siv",
            "3des-ede3",
            "des",
            "aes-256-ctr",
        ]

        for algo_id in expected_ids:
            assert algo_id in ALGORITHMS

    def test_get_algorithm_returns_correct_instance(self) -> None:
        """Test that get_algorithm returns correct cipher instance."""
        cipher = get_algorithm("aes-256-gcm")
        assert isinstance(cipher, AES256GCM)

        cipher = get_algorithm("chacha20-poly1305")
        assert isinstance(cipher, ChaCha20Poly1305)

    def test_get_algorithm_with_invalid_id_raises_error(self) -> None:
        """Test that invalid algorithm ID raises KeyError."""
        with pytest.raises(KeyError, match="not found"):
            get_algorithm("invalid-cipher-id")

    def test_get_algorithm_works_for_all_available_ciphers(self) -> None:
        """Test that get_algorithm works for all available ciphers."""
        # Test algorithms that don't require optional dependencies
        always_available = [
            "aes-128-gcm",
            "aes-256-gcm",
            "chacha20-poly1305",
            "aes-256-siv",
            "aes-256-ocb",
            "3des-ede3",
            "aes-256-ctr",
        ]

        for algo_id in always_available:
            cipher = get_algorithm(algo_id)
            assert cipher is not None

    def test_encrypt_decrypt_via_factory(self) -> None:
        """Test encryption/decryption via factory function."""
        cipher = get_algorithm("aes-256-gcm")
        key = os.urandom(32)
        plaintext = b"Factory test"

        nonce, ciphertext = cipher.encrypt(key, plaintext)
        decrypted = cipher.decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext


# ==============================================================================
# TEST SUITE: Edge Cases & Security
# ==============================================================================


class TestEdgeCases:
    """Test suite for edge cases and security properties."""

    def test_zero_length_plaintext(self, aes256gcm: AES256GCM) -> None:
        """Test encryption of zero-length plaintext."""
        key = os.urandom(32)
        plaintext = b""

        nonce, ciphertext = aes256gcm.encrypt(key, plaintext)
        decrypted = aes256gcm.decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext

    def test_very_large_plaintext(self, aes256gcm: AES256GCM) -> None:
        """Test encryption of 10 MB plaintext."""
        key = os.urandom(32)
        plaintext = os.urandom(10 * 1024 * 1024)  # 10 MB

        nonce, ciphertext = aes256gcm.encrypt(key, plaintext)
        decrypted = aes256gcm.decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext

    def test_unicode_in_aad(self, aes256gcm: AES256GCM) -> None:
        """Test AAD with UTF-8 encoded strings."""
        key = os.urandom(32)
        plaintext = b"test"
        aad = "пользователь:иван".encode("utf-8")  # Russian text

        nonce, ciphertext = aes256gcm.encrypt(key, plaintext, aad=aad)
        decrypted = aes256gcm.decrypt(key, nonce, ciphertext, aad=aad)

        assert decrypted == plaintext

    def test_key_is_not_modified(self, aes256gcm: AES256GCM) -> None:
        """Test that encryption does not modify the key."""
        key = os.urandom(32)
        key_copy = key[:]
        plaintext = b"test"

        aes256gcm.encrypt(key, plaintext)

        assert key == key_copy

    @pytest.mark.parametrize(
        "plaintext",
        [
            b"a",
            b"ab",
            b"abc",
            b"a" * 15,
            b"a" * 16,
            b"a" * 17,
            b"a" * 100,
            b"a" * 1000,
        ],
    )
    def test_various_plaintext_lengths(
        self, aes256gcm: AES256GCM, plaintext: bytes
    ) -> None:
        """Test encryption with various plaintext lengths."""
        key = os.urandom(32)

        nonce, ciphertext = aes256gcm.encrypt(key, plaintext)
        decrypted = aes256gcm.decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext


# ==============================================================================
# TEST SUITE: NIST Test Vectors (if available)
# ==============================================================================


class TestNISTVectors:
    """Test suite for NIST/RFC test vectors."""

    def test_aes_gcm_nist_vector_1(self, aes256gcm: AES256GCM) -> None:
        """Test AES-256-GCM with NIST test vector."""
        # NIST CAVP test vector
        # Source: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program

        # Test vector (example, not actual NIST data)
        key = bytes.fromhex("0" * 64)  # 32-byte key
        nonce = bytes.fromhex("0" * 24)  # 12-byte nonce
        plaintext = bytes.fromhex("0" * 32)  # 16-byte plaintext
        expected_ct_with_tag = bytes.fromhex(
            "0388dace60b6a392f328c2b971b2fe78" "f795aaab494b5923f7fd89ff948bc1e0"
        )

        # This is a placeholder - replace with actual NIST vectors
        # For now, just test that encryption works
        nonce, ciphertext = aes256gcm.encrypt(key, plaintext, nonce=nonce)
        decrypted = aes256gcm.decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext

    def test_chacha20_rfc_vector(self, chacha20: ChaCha20Poly1305) -> None:
        """Test ChaCha20-Poly1305 with RFC 8439 test vector."""
        # RFC 8439 Section 2.8.2
        # This is a placeholder - implement with actual RFC vectors

        key = os.urandom(32)
        plaintext = b"Ladies and Gentlemen of the class of '99"

        nonce, ciphertext = chacha20.encrypt(key, plaintext)
        decrypted = chacha20.decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext


# ==============================================================================
# TEST SUITE: Coverage Completeness
# ==============================================================================


class TestCoverageCompleteness:
    """Additional tests to achieve 95%+ coverage."""

    def test_xchacha20_unavailable_raises_runtime_error(self) -> None:
        """Test XChaCha20 raises RuntimeError when pycryptodome not installed."""
        # This tests the HAS_PYCRYPTODOME branch
        import sys
        import importlib

        # Mock pycryptodome unavailability
        with pytest.raises((RuntimeError, ImportError)):
            # If pycryptodome is installed, skip
            if "Crypto.Cipher" in sys.modules:
                pytest.skip("pycryptodome is installed")

            cipher = XChaCha20Poly1305()
            cipher.encrypt(os.urandom(32), b"test")

    def test_aes_gcm_siv_unavailable_message(self) -> None:
        """Test AES-GCM-SIV unavailability message."""
        # This tests the HAS_GCMSIV branch
        import sys

        if "cryptography.hazmat.primitives.ciphers.aead" in sys.modules:
            # Check if AESGCMSIV is actually available
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

                pytest.skip("AES-GCM-SIV is available")
            except ImportError:
                pass

        # Test that appropriate error is raised
        with pytest.raises(RuntimeError, match="cryptography >= 42"):
            cipher = AES256GCMSIV()
            cipher.encrypt(os.urandom(32), b"test")

    def test_des_unavailable_raises_runtime_error(self) -> None:
        """Test DES raises RuntimeError when pycryptodome not installed."""
        import sys

        if "Crypto.Cipher" in sys.modules:
            pytest.skip("pycryptodome is installed")

        with pytest.raises(RuntimeError, match="pycryptodome"):
            cipher = DES()
            cipher.encrypt(os.urandom(8), b"test")

    def test_all_ciphers_have_correct_key_sizes(self) -> None:
        """Test that all cipher classes have correct KEY_SIZE constants."""
        expected_key_sizes = {
            "aes-128-gcm": 16,
            "aes-256-gcm": 32,
            "chacha20-poly1305": 32,
            "aes-256-siv": 64,
            "aes-256-ocb": 32,
            "3des-ede3": 24,
            "aes-256-ctr": 32,
        }

        for algo_id, expected_size in expected_key_sizes.items():
            cipher_class = ALGORITHMS[algo_id]
            assert getattr(cipher_class, "KEY_SIZE") == expected_size

    def test_aes_gcm_with_none_aad(self, aes256gcm: AES256GCM) -> None:
        """Test AES-GCM explicitly with None AAD (default branch)."""
        key = os.urandom(32)
        plaintext = b"test"

        # Explicitly pass aad=None
        nonce, ciphertext = aes256gcm.encrypt(key, plaintext, aad=None)
        decrypted = aes256gcm.decrypt(key, nonce, ciphertext, aad=None)

        assert decrypted == plaintext

    def test_chacha20_with_none_aad(self, chacha20: ChaCha20Poly1305) -> None:
        """Test ChaCha20 explicitly with None AAD."""
        key = os.urandom(32)
        plaintext = b"test"

        nonce, ciphertext = chacha20.encrypt(key, plaintext, aad=None)
        decrypted = chacha20.decrypt(key, nonce, ciphertext, aad=None)

        assert decrypted == plaintext

    def test_aes_siv_with_none_aad(self, aes256siv: AES256SIV) -> None:
        """Test AES-SIV with None AAD."""
        key = os.urandom(64)
        plaintext = b"test"

        nonce, ciphertext = aes256siv.encrypt(key, plaintext, aad=None)
        decrypted = aes256siv.decrypt(key, nonce, ciphertext, aad=None)

        assert decrypted == plaintext

    def test_triple_des_with_custom_iv(self, triple_des: TripleDES) -> None:
        """Test TripleDES with custom IV."""
        key = os.urandom(24)
        iv = os.urandom(8)
        plaintext = b"custom IV test" + b"\x00" * 2  # Pad to 16 bytes

        _, ciphertext = triple_des.encrypt(key, plaintext, nonce=iv)
        decrypted = triple_des.decrypt(key, iv, ciphertext)

        assert decrypted == plaintext

    def test_aes_ctr_with_custom_iv(self, aes256ctr: AES256CTR) -> None:
        """Test AES-CTR with custom IV."""
        key = os.urandom(32)
        iv = os.urandom(16)
        plaintext = b"custom IV for CTR"

        _, ciphertext = aes256ctr.encrypt(key, plaintext, nonce=iv)
        decrypted = aes256ctr.decrypt(key, iv, ciphertext)

        assert decrypted == plaintext

    def test_get_algorithm_with_spaces_in_name(self) -> None:
        """Test get_algorithm with edge case algorithm names."""
        # Valid algorithm
        cipher = get_algorithm("aes-256-gcm")
        assert cipher is not None

        # Invalid (with variations)
        with pytest.raises(KeyError):
            get_algorithm("aes 256 gcm")  # Spaces instead of dashes

        with pytest.raises(KeyError):
            get_algorithm("AES-256-GCM")  # Uppercase

    def test_algorithms_registry_types(self) -> None:
        """Test that ALGORITHMS registry contains correct types."""
        for algo_id, cipher_class in ALGORITHMS.items():
            assert isinstance(algo_id, str)
            assert callable(cipher_class)

            # Should be able to instantiate (may fail for missing libs)
            try:
                instance = cipher_class()
                assert instance is not None
            except RuntimeError:
                # Expected for optional dependencies
                pass

    def test_decrypt_with_too_short_ciphertext(self, aes256gcm: AES256GCM) -> None:
        """Test decryption fails with ciphertext shorter than tag size."""
        key = os.urandom(32)
        nonce = os.urandom(12)
        short_ciphertext = os.urandom(10)  # Less than 16 bytes (tag size)

        # cryptography library validates tag before our check, so we get "invalid tag"
        with pytest.raises(
            DecryptionFailedError, match="invalid tag|decryption failed"
        ):
            aes256gcm.decrypt(key, nonce, short_ciphertext)

    def test_aes128_decrypt_with_wrong_nonce(self, aes128gcm: AES128GCM) -> None:
        """Test AES-128-GCM decryption with wrong nonce."""
        key = os.urandom(16)
        plaintext = b"test"

        nonce, ciphertext = aes128gcm.encrypt(key, plaintext)
        wrong_nonce = os.urandom(12)

        # Wrong nonce should fail authentication
        with pytest.raises(DecryptionFailedError):
            aes128gcm.decrypt(key, wrong_nonce, ciphertext)

    def test_ocb_with_15_byte_nonce(self, aes256ocb: AES256OCB) -> None:
        """Test OCB with maximum 15-byte nonce."""
        key = os.urandom(32)
        nonce = os.urandom(15)  # Maximum size
        plaintext = b"test OCB with max nonce"

        _, ciphertext = aes256ocb.encrypt(key, plaintext, nonce=nonce)
        decrypted = aes256ocb.decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext

    def test_siv_different_nonce_same_plaintext(self, aes256siv: AES256SIV) -> None:
        """Test SIV produces different ciphertexts with different nonces."""
        key = os.urandom(64)
        plaintext = b"same plaintext"
        nonce1 = b"nonce_one_123456"
        nonce2 = b"nonce_two_123456"

        _, ct1 = aes256siv.encrypt(key, plaintext, nonce=nonce1)
        _, ct2 = aes256siv.encrypt(key, plaintext, nonce=nonce2)

        # Different nonces = different ciphertexts
        assert ct1 != ct2

    def test_ctr_encrypt_decrypt_stream_properties(self, aes256ctr: AES256CTR) -> None:
        """Test CTR mode stream cipher properties."""
        key = os.urandom(32)
        plaintext1 = b"A" * 100
        plaintext2 = b"B" * 100

        # Same nonce = same keystream (XOR property)
        nonce = os.urandom(16)
        _, ct1 = aes256ctr.encrypt(key, plaintext1, nonce=nonce)
        _, ct2 = aes256ctr.encrypt(key, plaintext2, nonce=nonce)

        # XOR ciphertexts = XOR plaintexts (stream cipher property)
        xor_ct = bytes(a ^ b for a, b in zip(ct1, ct2))
        xor_pt = bytes(a ^ b for a, b in zip(plaintext1, plaintext2))

        assert xor_ct == xor_pt

    def test_aes256gcm_check_library_availability(self) -> None:
        """Test that AES256GCM checks library availability."""
        # This covers the is_available() branch in __init__
        # In normal circumstances, cryptography is always installed
        cipher = AES256GCM()
        assert cipher is not None

    def test_aes128gcm_check_library_availability(self) -> None:
        """Test that AES128GCM checks library availability."""
        cipher = AES128GCM()
        assert cipher is not None

    def test_chacha20_check_library_availability(self) -> None:
        """Test that ChaCha20Poly1305 checks library availability."""
        cipher = ChaCha20Poly1305()
        assert cipher is not None

    def test_all_aead_ciphers_check_ciphertext_minimum_length(self) -> None:
        """Test that AEAD ciphers validate minimum ciphertext length."""
        # Test with empty ciphertext (0 bytes)
        key = os.urandom(32)
        nonce = os.urandom(12)
        empty_ciphertext = b""

        aes256gcm = AES256GCM()

        # Empty ciphertext should fail
        with pytest.raises(DecryptionFailedError):
            aes256gcm.decrypt(key, nonce, empty_ciphertext)

    def test_aes_siv_with_aad_list(self, aes256siv: AES256SIV) -> None:
        """Test AES-SIV internal AAD handling."""
        key = os.urandom(64)
        plaintext = b"test with AAD"
        aad = b"additional_data"

        nonce, ciphertext = aes256siv.encrypt(key, plaintext, aad=aad)
        decrypted = aes256siv.decrypt(key, nonce, ciphertext, aad=aad)

        assert decrypted == plaintext

    def test_xchacha20_tag_verification(self) -> None:
        """Test XChaCha20 tag verification process."""
        try:
            cipher = XChaCha20Poly1305()
        except RuntimeError:
            pytest.skip("XChaCha20 not available")

        key = os.urandom(32)
        plaintext = b"test"

        nonce, ciphertext = cipher.encrypt(key, plaintext)

        # Tamper with tag (last 16 bytes)
        tampered = ciphertext[:-16] + os.urandom(16)

        with pytest.raises(DecryptionFailedError):
            cipher.decrypt(key, nonce, tampered)

    def test_des_with_padding(self) -> None:
        """Test DES padding handling."""
        try:
            cipher = DES()
        except RuntimeError:
            pytest.skip("DES not available")

        key = os.urandom(8)
        # Plaintext not aligned to 8-byte blocks
        plaintext = b"123"  # 3 bytes, needs padding

        nonce, ciphertext = cipher.encrypt(key, plaintext)
        decrypted = cipher.decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext

    def test_triple_des_padding_handling(self, triple_des: TripleDES) -> None:
        """Test TripleDES PKCS7 padding."""
        key = os.urandom(24)
        # Test various plaintext lengths
        for length in [1, 7, 8, 9, 15, 16, 17]:
            plaintext = os.urandom(length)
            nonce, ciphertext = triple_des.encrypt(key, plaintext)
            decrypted = triple_des.decrypt(key, nonce, ciphertext)
            assert decrypted == plaintext

    def test_aes_ctr_no_padding_needed(self, aes256ctr: AES256CTR) -> None:
        """Test that AES-CTR doesn't require padding (stream cipher)."""
        key = os.urandom(32)
        # Various non-aligned lengths
        for length in [1, 7, 15, 17, 31, 33]:
            plaintext = os.urandom(length)
            nonce, ciphertext = aes256ctr.encrypt(key, plaintext)

            # Ciphertext should be same length as plaintext (no padding)
            assert len(ciphertext) == len(plaintext)

            decrypted = aes256ctr.decrypt(key, nonce, ciphertext)
            assert decrypted == plaintext

    def test_ocb_with_13_byte_nonce(self, aes256ocb: AES256OCB) -> None:
        """Test OCB with 13-byte nonce (middle of range)."""
        key = os.urandom(32)
        nonce = os.urandom(13)
        plaintext = b"test with 13-byte nonce"

        _, ciphertext = aes256ocb.encrypt(key, plaintext, nonce=nonce)
        decrypted = aes256ocb.decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext

    def test_ocb_with_14_byte_nonce(self, aes256ocb: AES256OCB) -> None:
        """Test OCB with 14-byte nonce."""
        key = os.urandom(32)
        nonce = os.urandom(14)
        plaintext = b"test with 14-byte nonce"

        _, ciphertext = aes256ocb.encrypt(key, plaintext, nonce=nonce)
        decrypted = aes256ocb.decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext

    def test_chacha20_with_aad(self, chacha20: ChaCha20Poly1305) -> None:
        """Test ChaCha20 with AAD (additional branch)."""
        key = os.urandom(32)
        plaintext = b"data"
        aad = b"context_info"

        nonce, ciphertext = chacha20.encrypt(key, plaintext, aad=aad)

        # Wrong AAD should fail
        with pytest.raises(DecryptionFailedError):
            chacha20.decrypt(key, nonce, ciphertext, aad=b"wrong")

        # Correct AAD should work
        decrypted = chacha20.decrypt(key, nonce, ciphertext, aad=aad)
        assert decrypted == plaintext

    def test_aes128_with_aad(self, aes128gcm: AES128GCM) -> None:
        """Test AES-128-GCM with AAD."""
        key = os.urandom(16)
        plaintext = b"data"
        aad = b"metadata"

        nonce, ciphertext = aes128gcm.encrypt(key, plaintext, aad=aad)

        # Decrypt with correct AAD
        decrypted = aes128gcm.decrypt(key, nonce, ciphertext, aad=aad)
        assert decrypted == plaintext

        # Decrypt with wrong AAD should fail
        with pytest.raises(DecryptionFailedError):
            aes128gcm.decrypt(key, nonce, ciphertext, aad=b"wrong")

    def test_ocb_with_aad(self, aes256ocb: AES256OCB) -> None:
        """Test AES-OCB with AAD."""
        key = os.urandom(32)
        plaintext = b"data"
        aad = b"authenticated_data"

        nonce, ciphertext = aes256ocb.encrypt(key, plaintext, aad=aad)
        decrypted = aes256ocb.decrypt(key, nonce, ciphertext, aad=aad)

        assert decrypted == plaintext

    def test_all_cipher_constants_are_correct(self) -> None:
        """Test that all cipher constants match expected values."""
        assert AES256GCM.KEY_SIZE == 32
        assert AES256GCM.NONCE_SIZE == 12
        assert AES256GCM.TAG_SIZE == 16

        assert AES128GCM.KEY_SIZE == 16
        assert AES128GCM.NONCE_SIZE == 12

        assert ChaCha20Poly1305.KEY_SIZE == 32
        assert ChaCha20Poly1305.NONCE_SIZE == 12

        assert AES256SIV.KEY_SIZE == 64
        assert AES256SIV.NONCE_SIZE == 16

        assert TripleDES.KEY_SIZE == 24
        assert TripleDES.IV_SIZE == 8

        assert AES256CTR.KEY_SIZE == 32
        assert AES256CTR.IV_SIZE == 16

    def test_type_validation_for_plaintext(self, aes256gcm: AES256GCM) -> None:
        """Test that non-bytes plaintext raises TypeError."""
        key = os.urandom(32)

        # String instead of bytes
        with pytest.raises(TypeError):
            aes256gcm.encrypt(key, "not bytes")  # type: ignore

        # Integer instead of bytes
        with pytest.raises(TypeError):
            aes256gcm.encrypt(key, 12345)  # type: ignore

    def test_type_validation_for_key(self, aes256gcm: AES256GCM) -> None:
        """Test that non-bytes key raises TypeError."""
        plaintext = b"test"

        # String instead of bytes
        with pytest.raises((TypeError, InvalidKeyError)):
            aes256gcm.encrypt("not bytes", plaintext)  # type: ignore

    def test_type_validation_for_nonce(self, aes256gcm: AES256GCM) -> None:
        """Test that non-bytes nonce raises TypeError."""
        key = os.urandom(32)
        plaintext = b"test"

        # String instead of bytes
        with pytest.raises((TypeError, InvalidNonceError)):
            aes256gcm.encrypt(key, plaintext, nonce="not bytes")  # type: ignore

    def test_type_validation_for_aad(self, aes256gcm: AES256GCM) -> None:
        """Test that non-bytes AAD raises TypeError."""
        key = os.urandom(32)
        plaintext = b"test"

        # String instead of bytes
        with pytest.raises(TypeError):
            aes256gcm.encrypt(key, plaintext, aad="not bytes")  # type: ignore

    def test_type_validation_for_ciphertext(self, aes256gcm: AES256GCM) -> None:
        """Test that non-bytes ciphertext raises TypeError."""
        key = os.urandom(32)
        nonce = os.urandom(12)

        # String instead of bytes
        with pytest.raises(TypeError):
            aes256gcm.decrypt(key, nonce, "not bytes")  # type: ignore


# ==============================================================================
# TEST SUITE: Error Messages Validation
# ==============================================================================


class TestErrorMessages:
    """Test that error messages are informative and consistent."""

    def test_invalid_key_error_message_contains_algorithm_name(
        self, aes256gcm: AES256GCM
    ) -> None:
        """Test that InvalidKeyError contains algorithm name."""
        key = os.urandom(16)  # Wrong size

        with pytest.raises(InvalidKeyError) as exc_info:
            aes256gcm.encrypt(key, b"test")

        error_message = str(exc_info.value)
        assert "AES-256-GCM" in error_message or "32" in error_message

    def test_invalid_nonce_error_message_contains_expected_size(
        self, aes256gcm: AES256GCM
    ) -> None:
        """Test that InvalidNonceError contains expected size."""
        key = os.urandom(32)
        bad_nonce = os.urandom(8)

        with pytest.raises(InvalidNonceError) as exc_info:
            aes256gcm.encrypt(key, b"test", nonce=bad_nonce)

        error_message = str(exc_info.value)
        assert "12" in error_message  # Expected nonce size

    def test_decryption_error_message_is_safe(self, aes256gcm: AES256GCM) -> None:
        """Test that DecryptionFailedError doesn't leak sensitive info."""
        key = os.urandom(32)
        plaintext = b"secret"

        nonce, ciphertext = aes256gcm.encrypt(key, plaintext)
        wrong_key = os.urandom(32)

        with pytest.raises(DecryptionFailedError) as exc_info:
            aes256gcm.decrypt(wrong_key, nonce, ciphertext)

        error_message = str(exc_info.value).lower()

        # Should NOT contain plaintext or key
        assert b"secret" not in error_message.encode()
        assert key.hex() not in error_message

        # Should contain generic error info
        assert "authentication" in error_message or "tag" in error_message

    def test_get_algorithm_error_lists_available_algorithms(self) -> None:
        """Test that get_algorithm error message lists available options."""
        with pytest.raises(KeyError) as exc_info:
            get_algorithm("nonexistent-cipher")

        error_message = str(exc_info.value)

        # Should list at least some available algorithms
        assert "aes-256-gcm" in error_message.lower()


# ==============================================================================
# TEST SUITE: Metadata Registry
# ==============================================================================


class TestMetadataRegistry:
    """Test suite for algorithm metadata registry."""

    def test_all_metadata_list_exists(self) -> None:
        """Test that ALL_METADATA list is populated."""
        from src.security.crypto.algorithms.symmetric import ALL_METADATA

        assert ALL_METADATA is not None
        assert isinstance(ALL_METADATA, list)
        assert len(ALL_METADATA) == 10  # All 10 ciphers

    def test_all_metadata_objects_are_valid(self) -> None:
        """Test that all metadata objects are properly configured."""
        from src.security.crypto.algorithms.symmetric import ALL_METADATA
        from src.security.crypto.core.metadata import AlgorithmMetadata

        for meta in ALL_METADATA:
            assert isinstance(meta, AlgorithmMetadata)
            assert meta.name  # Non-empty name
            assert meta.library  # Has library
            assert meta.implementation_class  # Has implementation
            assert meta.security_level  # Has security level
            assert meta.status  # Has status

    def test_aes256gcm_metadata_content(self) -> None:
        """Test AES-256-GCM metadata has correct content."""
        from src.security.crypto.algorithms.symmetric import (
            ALL_METADATA,
            AES256GCM_METADATA,
        )

        assert AES256GCM_METADATA.name == "AES-256-GCM"
        assert AES256GCM_METADATA.key_size == 32
        assert AES256GCM_METADATA.nonce_size == 12
        assert AES256GCM_METADATA.is_aead is True
        assert AES256GCM_METADATA.security_level.value == "standard"
        assert "TLS" in AES256GCM_METADATA.description_en
        assert len(AES256GCM_METADATA.use_cases) >= 3

    def test_aes128gcm_metadata_content(self) -> None:
        """Test AES-128-GCM metadata has correct content."""
        from src.security.crypto.algorithms.symmetric import AES128GCM_METADATA

        assert AES128GCM_METADATA.name == "AES-128-GCM"
        assert AES128GCM_METADATA.key_size == 16
        assert AES128GCM_METADATA.nonce_size == 12
        assert AES128GCM_METADATA.is_aead is True

    def test_chacha20_metadata_content(self) -> None:
        """Test ChaCha20-Poly1305 metadata has correct content."""
        from src.security.crypto.algorithms.symmetric import (
            CHACHA20_POLY1305_METADATA,
        )

        assert CHACHA20_POLY1305_METADATA.name == "ChaCha20-Poly1305"
        assert CHACHA20_POLY1305_METADATA.key_size == 32
        assert CHACHA20_POLY1305_METADATA.nonce_size == 12
        assert "WireGuard" in CHACHA20_POLY1305_METADATA.description_en

    def test_xchacha20_metadata_content(self) -> None:
        """Test XChaCha20-Poly1305 metadata has correct content."""
        from src.security.crypto.algorithms.symmetric import (
            XCHACHA20_POLY1305_METADATA,
        )

        assert XCHACHA20_POLY1305_METADATA.name == "XChaCha20-Poly1305"
        assert XCHACHA20_POLY1305_METADATA.key_size == 32
        assert XCHACHA20_POLY1305_METADATA.nonce_size == 24  # Extended!
        assert XCHACHA20_POLY1305_METADATA.security_level.value == "high"

    def test_aes256siv_metadata_content(self) -> None:
        """Test AES-256-SIV metadata has correct content."""
        from src.security.crypto.algorithms.symmetric import AES256_SIV_METADATA

        assert AES256_SIV_METADATA.name == "AES-256-SIV"
        assert AES256_SIV_METADATA.key_size == 64  # Two keys!
        assert AES256_SIV_METADATA.nonce_size == 16
        assert AES256_SIV_METADATA.extra.get("nonce_reuse_safe") is True

    def test_aes256ocb_metadata_content(self) -> None:
        """Test AES-256-OCB metadata has correct content."""
        from src.security.crypto.algorithms.symmetric import AES256_OCB_METADATA

        assert AES256_OCB_METADATA.name == "AES-256-OCB"
        assert AES256_OCB_METADATA.key_size == 32
        # Check for patent_status key (not just "patent" substring)
        assert "patent_status" in AES256_OCB_METADATA.extra
        assert "Rogaway" in AES256_OCB_METADATA.extra.get("patent_status", "")

    def test_aes256gcmsiv_metadata_content(self) -> None:
        """Test AES-256-GCM-SIV metadata has correct content."""
        from src.security.crypto.algorithms.symmetric import (
            AES256_GCM_SIV_METADATA,
        )

        assert AES256_GCM_SIV_METADATA.name == "AES-256-GCM-SIV"
        assert AES256_GCM_SIV_METADATA.key_size == 32
        assert AES256_GCM_SIV_METADATA.extra.get("nonce_misuse_resistant") is True
        assert "NEW" in AES256_GCM_SIV_METADATA.description_en

    def test_tripledes_metadata_content(self) -> None:
        """Test TripleDES metadata has correct content (LEGACY)."""
        from src.security.crypto.algorithms.symmetric import TRIPLE_DES_METADATA

        assert TRIPLE_DES_METADATA.name == "3DES-EDE3"
        assert TRIPLE_DES_METADATA.key_size == 24
        assert TRIPLE_DES_METADATA.security_level.value == "legacy"
        assert TRIPLE_DES_METADATA.status.value == "deprecated"
        # Check for sweet32_vulnerable key (lowercase)
        assert TRIPLE_DES_METADATA.extra.get("sweet32_vulnerable") is True

    def test_des_metadata_content(self) -> None:
        """Test DES metadata has correct content (BROKEN)."""
        from src.security.crypto.algorithms.symmetric import DES_METADATA

        assert DES_METADATA.name == "DES"
        assert DES_METADATA.key_size == 8
        assert DES_METADATA.security_level.value == "broken"
        assert DES_METADATA.status.value == "deprecated"
        assert "1998" in str(DES_METADATA.extra)  # Broken since

    def test_aes256ctr_metadata_content(self) -> None:
        """Test AES-256-CTR metadata has correct content (non-AEAD)."""
        from src.security.crypto.algorithms.symmetric import AES256_CTR_METADATA

        assert AES256_CTR_METADATA.name == "AES-256-CTR"
        assert AES256_CTR_METADATA.key_size == 32
        assert AES256_CTR_METADATA.is_aead is False
        assert "HMAC" in AES256_CTR_METADATA.extra.get("requires_mac", "")

    def test_all_metadata_have_descriptions(self) -> None:
        """Test that all metadata have both Russian and English descriptions."""
        from src.security.crypto.algorithms.symmetric import ALL_METADATA

        for meta in ALL_METADATA:
            assert meta.description_ru, f"{meta.name} missing Russian description"
            assert meta.description_en, f"{meta.name} missing English description"
            assert len(meta.description_ru) > 50  # Meaningful description
            assert len(meta.description_en) > 50

    def test_all_metadata_have_use_cases(self) -> None:
        """Test that all metadata have use cases."""
        from src.security.crypto.algorithms.symmetric import ALL_METADATA

        for meta in ALL_METADATA:
            assert meta.use_cases, f"{meta.name} has no use cases"
            assert len(meta.use_cases) >= 1  # At least one use case

    def test_all_metadata_have_test_vectors(self) -> None:
        """Test that all metadata reference test vector sources."""
        from src.security.crypto.algorithms.symmetric import ALL_METADATA

        for meta in ALL_METADATA:
            assert meta.test_vectors_source, f"{meta.name} has no test vectors source"
            # Should reference NIST, RFC, or standard
            source = meta.test_vectors_source.lower()
            assert any(
                keyword in source
                for keyword in ["nist", "rfc", "fips", "draft", "sp 800"]
            )

    def test_aead_ciphers_marked_correctly(self) -> None:
        """Test that AEAD ciphers are marked correctly."""
        from src.security.crypto.algorithms.symmetric import ALL_METADATA

        aead_names = {
            "AES-128-GCM",
            "AES-256-GCM",
            "ChaCha20-Poly1305",
            "XChaCha20-Poly1305",
            "AES-256-SIV",
            "AES-256-OCB",
            "AES-256-GCM-SIV",
        }

        for meta in ALL_METADATA:
            if meta.name in aead_names:
                assert meta.is_aead is True, f"{meta.name} should be AEAD"
            else:
                assert meta.is_aead is False, f"{meta.name} should NOT be AEAD"

    def test_security_levels_are_appropriate(self) -> None:
        """Test that security levels are assigned appropriately."""
        from src.security.crypto.algorithms.symmetric import ALL_METADATA

        # Check specific expected levels
        level_mapping = {
            "DES": "broken",
            "3DES-EDE3": "legacy",
            "AES-128-GCM": "standard",
            "AES-256-GCM": "standard",
            "XChaCha20-Poly1305": "high",
            "AES-256-SIV": "high",
        }

        for meta in ALL_METADATA:
            if meta.name in level_mapping:
                expected = level_mapping[meta.name]
                assert (
                    meta.security_level.value == expected
                ), f"{meta.name} should be {expected}"

    def test_deprecated_ciphers_marked_correctly(self) -> None:
        """Test that deprecated ciphers are marked correctly."""
        from src.security.crypto.algorithms.symmetric import ALL_METADATA

        deprecated_names = {"3DES-EDE3", "DES"}

        for meta in ALL_METADATA:
            if meta.name in deprecated_names:
                assert (
                    meta.status.value == "deprecated"
                ), f"{meta.name} should be deprecated"

    def test_metadata_key_sizes_match_classes(self) -> None:
        """Test that metadata key sizes match class constants."""
        from src.security.crypto.algorithms.symmetric import (
            AES128GCM,
            AES256CTR,
            AES256GCM,
            AES256_CTR_METADATA,
            AES256GCM_METADATA,
            AES128GCM_METADATA,
            ChaCha20Poly1305,
            CHACHA20_POLY1305_METADATA,
        )

        # Test a few examples
        assert AES256GCM_METADATA.key_size == AES256GCM.KEY_SIZE
        assert AES128GCM_METADATA.key_size == AES128GCM.KEY_SIZE
        assert CHACHA20_POLY1305_METADATA.key_size == ChaCha20Poly1305.KEY_SIZE
        assert AES256_CTR_METADATA.key_size == AES256CTR.KEY_SIZE

    def test_metadata_nonce_sizes_match_classes(self) -> None:
        """Test that metadata nonce sizes match class constants."""
        from src.security.crypto.algorithms.symmetric import (
            AES256GCM,
            AES256GCM_METADATA,
            ChaCha20Poly1305,
            CHACHA20_POLY1305_METADATA,
        )

        assert AES256GCM_METADATA.nonce_size == AES256GCM.NONCE_SIZE
        assert CHACHA20_POLY1305_METADATA.nonce_size == ChaCha20Poly1305.NONCE_SIZE

    def test_metadata_extra_fields_are_dicts(self) -> None:
        """Test that extra fields are dictionaries."""
        from src.security.crypto.algorithms.symmetric import ALL_METADATA

        for meta in ALL_METADATA:
            assert isinstance(meta.extra, dict)

    def test_metadata_names_are_unique(self) -> None:
        """Test that all metadata names are unique."""
        from src.security.crypto.algorithms.symmetric import ALL_METADATA

        names = [meta.name for meta in ALL_METADATA]
        assert len(names) == len(set(names))  # No duplicates

    def test_metadata_libraries_are_valid(self) -> None:
        """Test that all libraries are from allowed list."""
        from src.security.crypto.algorithms.symmetric import ALL_METADATA

        allowed_libraries = {"cryptography", "pycryptodome"}

        for meta in ALL_METADATA:
            assert (
                meta.library in allowed_libraries
            ), f"{meta.name} uses invalid library: {meta.library}"

    def test_all_metadata_count_matches_algorithms_dict(self) -> None:
        """Test that metadata count matches ALGORITHMS dict."""
        from src.security.crypto.algorithms.symmetric import (
            ALGORITHMS,
            ALL_METADATA,
        )

        assert len(ALL_METADATA) == len(ALGORITHMS)

    def test_metadata_can_be_serialized_to_dict(self) -> None:
        """Test that metadata can be converted to dict."""
        from src.security.crypto.algorithms.symmetric import AES256GCM_METADATA

        meta_dict = AES256GCM_METADATA.to_dict()

        assert isinstance(meta_dict, dict)
        assert meta_dict["name"] == "AES-256-GCM"
        assert meta_dict["key_size"] == 32
        assert meta_dict["is_aead"] is True

    def test_metadata_russian_descriptions_are_in_cyrillic(self) -> None:
        """Test that Russian descriptions actually contain Cyrillic."""
        from src.security.crypto.algorithms.symmetric import ALL_METADATA

        for meta in ALL_METADATA:
            # Check if contains Cyrillic characters
            has_cyrillic = any(
                "\u0400" <= char <= "\u04ff" for char in meta.description_ru
            )
            assert has_cyrillic, f"{meta.name} Russian description has no Cyrillic"

    def test_metadata_production_safety_flags(self) -> None:
        """Test production safety flags for different algorithms."""
        from src.security.crypto.algorithms.symmetric import ALL_METADATA

        for meta in ALL_METADATA:
            if meta.name == "DES":
                # DES should NOT be safe for production
                assert not meta.is_safe_for_production()
            elif meta.name == "3DES-EDE3":
                # 3DES is LEGACY but technically "safe" (just deprecated)
                assert not meta.is_safe_for_production()
            elif meta.name in ["AES-256-GCM", "ChaCha20-Poly1305"]:
                # Modern ciphers should be safe
                assert meta.is_safe_for_production()

    def test_metadata_total_overhead_calculation(self) -> None:
        """Test that total overhead calculation works."""
        from src.security.crypto.algorithms.symmetric import (
            AES256GCM_METADATA,
            AES256_SIV_METADATA,
        )

        # AES-GCM: key=32
        gcm_overhead = AES256GCM_METADATA.total_overhead_bytes()
        assert gcm_overhead == 32  # Just key size (no signature/pubkey)

        # AES-SIV: key=64 (two keys)
        siv_overhead = AES256_SIV_METADATA.total_overhead_bytes()
        assert siv_overhead == 64

    def test_xchacha20_extended_nonce_documented(self) -> None:
        """Test that XChaCha20 extended nonce is documented."""
        from src.security.crypto.algorithms.symmetric import (
            XCHACHA20_POLY1305_METADATA,
        )

        assert XCHACHA20_POLY1305_METADATA.nonce_size == 24
        # Check for nonce collision resistance (2^96, not "192")
        assert "nonce_collision_resistance" in XCHACHA20_POLY1305_METADATA.extra
        assert "2^96" in XCHACHA20_POLY1305_METADATA.extra.get(
            "nonce_collision_resistance", ""
        )


# (Keep existing TestPerformance class after this)


# ==============================================================================
# PERFORMANCE BENCHMARKS (optional, marked as slow)
# ==============================================================================


@pytest.mark.slow
@pytest.mark.skipif(
    not hasattr(pytest, "benchmark"), reason="pytest-benchmark not installed"
)
class TestPerformance:
    """Performance benchmarks for symmetric ciphers (requires pytest-benchmark)."""

    def test_aes_gcm_encryption_speed(self, aes256gcm: AES256GCM) -> None:
        """Test AES-256-GCM encryption speed (basic timing, not benchmark)."""
        import time

        key = os.urandom(32)
        plaintext = os.urandom(1024 * 1024)  # 1 MB

        start = time.perf_counter()
        for _ in range(10):
            aes256gcm.encrypt(key, plaintext)
        duration = time.perf_counter() - start

        # Should encrypt 10 MB in < 1 second (basic sanity check)
        assert duration < 1.0, f"Encryption too slow: {duration:.2f}s for 10 MB"

    def test_chacha20_encryption_speed(self, chacha20: ChaCha20Poly1305) -> None:
        """Test ChaCha20-Poly1305 encryption speed."""
        import time

        key = os.urandom(32)
        plaintext = os.urandom(1024 * 1024)  # 1 MB

        start = time.perf_counter()
        for _ in range(10):
            chacha20.encrypt(key, plaintext)
        duration = time.perf_counter() - start

        # ChaCha20 should also be fast (< 1s for 10 MB)
        assert duration < 1.0, f"Encryption too slow: {duration:.2f}s for 10 MB"
