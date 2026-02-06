from __future__ import annotations

import concurrent.futures
import os
from typing import Callable, Dict, Tuple

import pytest

from src.security.crypto import utils as utils_mod
from src.security.crypto.exceptions import DecryptionError, EncryptionError
from src.security.crypto.symmetric import (
    KEY_LEN,
    NONCE_LEN,
    TAG_LEN,
    SymmetricCipher,
    decrypt_aes_gcm,
    encrypt_aes_gcm,
)


def test_roundtrip_basic() -> None:
    key = b"\x01" * KEY_LEN
    cipher = SymmetricCipher()
    nonce, combined = cipher.encrypt(key, b"hello", aad=b"hdr")
    assert isinstance(nonce, bytes) and len(nonce) == NONCE_LEN
    pt = cipher.decrypt(key, nonce, combined, aad=b"hdr")
    assert pt == b"hello"


def test_roundtrip_with_separate_tag() -> None:
    key = os.urandom(KEY_LEN)
    cipher = SymmetricCipher()
    nonce, ct, tag = cipher.encrypt(key, b"payload", return_combined=False)  # NEW
    assert len(tag) == TAG_LEN and len(nonce) == NONCE_LEN
    pt = cipher.decrypt(key, nonce, ct, tag=tag)
    assert pt == b"payload"


def test_encrypt_uses_utils_rng_for_full_nonce(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify encryption uses fully random 96-bit nonce from utils.generate_random_bytes."""
    called: dict[str, int] = {"n": 0}

    def fake_rng(n: int) -> bytes:
        called["n"] += 1

        assert n == 12, f"Expected 12 bytes for nonce, got {n}"
        return b"\x00" * 12

    monkeypatch.setattr(
        "src.security.crypto.symmetric.generate_random_bytes", fake_rng, raising=True
    )

    key = b"\x02" * KEY_LEN
    cipher = SymmetricCipher()
    nonce1, combined1 = cipher.encrypt(key, b"a")

    assert len(nonce1) == 12
    assert called["n"] == 1


def test_nonce_uniqueness_parallel() -> None:
    key = os.urandom(KEY_LEN)
    cipher = SymmetricCipher()

    def one(i: int) -> bytes:  # rename parameter to avoid "_" reuse
        nonce, combined = cipher.encrypt(key, b"x")  # NEW
        return nonce

    N = 1000
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        nonces = list(ex.map(one, range(N)))
    assert len(set(nonces)) == N
    assert all(len(n) == NONCE_LEN for n in nonces)


def test_decrypt_invalid_params_raise() -> None:
    cipher = SymmetricCipher()
    key = os.urandom(KEY_LEN)
    nonce, combined = encrypt_aes_gcm(key, b"p")
    with pytest.raises(DecryptionError):
        cipher.decrypt(key, b"\x00", combined)  # bad nonce
    with pytest.raises(DecryptionError):
        cipher.decrypt(key, nonce, b"x" * 15, has_combined=True)  # < TAG_LEN
    with pytest.raises(DecryptionError):
        cipher.decrypt(key, nonce, b"ct", has_combined=False)  # no tag provided
    with pytest.raises(DecryptionError):
        cipher.decrypt(
            key, nonce, b"ct", has_combined=False, tag=b"short"
        )  # bad tag size


def test_invalid_tag_raises() -> None:
    key = os.urandom(KEY_LEN)
    nonce, combined = encrypt_aes_gcm(key, b"secret")
    tampered = combined[:-1] + bytes([combined[-1] ^ 0xFF])
    with pytest.raises(DecryptionError):
        decrypt_aes_gcm(key, nonce, tampered)


def test_encrypt_internal_failure_is_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    key = os.urandom(KEY_LEN)
    cipher = SymmetricCipher()

    class Boom(Exception):
        pass

    # Патчим AESGCM вместо Cipher
    monkeypatch.setattr(
        "src.security.crypto.symmetric.AESGCM",
        lambda *a, **k: (_ for _ in ()).throw(Boom()),
    )

    with pytest.raises(EncryptionError):
        cipher.encrypt(key, b"data")


# После существующих тестов


def test_operation_counter_limit() -> None:
    """Test that cipher raises EncryptionError when operation limit is reached."""
    key = os.urandom(KEY_LEN)
    cipher = SymmetricCipher(max_operations=5)

    # Encrypt 5 times (at limit)
    for _ in range(5):
        cipher.encrypt(key, b"data")

    assert cipher.get_operation_count() == 5

    # 6th operation should fail
    with pytest.raises(EncryptionError, match="Key rotation required"):
        cipher.encrypt(key, b"more data")


def test_operation_counter_warning_threshold() -> None:
    key = os.urandom(KEY_LEN)
    cipher = SymmetricCipher(max_operations=10)

    for _ in range(7):
        cipher.encrypt(key, b"data")
    assert not cipher.is_rotation_warned()

    cipher.encrypt(key, b"data")  # 80%
    assert cipher.is_rotation_warned()


def test_operation_counter_reset() -> None:
    """Test counter reset functionality."""
    key = os.urandom(KEY_LEN)
    cipher = SymmetricCipher(max_operations=5)

    for _ in range(3):
        cipher.encrypt(key, b"data")

    assert cipher.get_operation_count() == 3

    cipher.reset_counter()
    assert cipher.get_operation_count() == 0

    # Should be able to encrypt again
    cipher.encrypt(key, b"data")
    assert cipher.get_operation_count() == 1


def test_chacha20_roundtrip_basic() -> None:
    """Test ChaCha20 basic encryption/decryption."""
    from src.security.crypto.symmetric import (
        ChaCha20Cipher,
        CHACHA_KEY_LEN,
        CHACHA_NONCE_LEN,
    )

    key = os.urandom(CHACHA_KEY_LEN)
    cipher = ChaCha20Cipher()

    nonce, combined = cipher.encrypt(key, b"secret message", aad=b"metadata")
    assert len(nonce) == CHACHA_NONCE_LEN
    assert isinstance(combined, bytes)

    plaintext = cipher.decrypt(key, nonce, combined, aad=b"metadata")
    assert plaintext == b"secret message"


def test_chacha20_roundtrip_with_separate_tag() -> None:
    """Test ChaCha20 with separate ciphertext and tag."""
    from src.security.crypto.symmetric import (
        ChaCha20Cipher,
        CHACHA_KEY_LEN,
        CHACHA_TAG_LEN,
    )

    key = os.urandom(CHACHA_KEY_LEN)
    cipher = ChaCha20Cipher()

    nonce, ct, tag = cipher.encrypt(key, b"payload", return_combined=False)
    assert len(tag) == CHACHA_TAG_LEN

    plaintext = cipher.decrypt(key, nonce, ct, tag=tag)
    assert plaintext == b"payload"


def test_chacha20_convenience_functions() -> None:
    """Test ChaCha20 convenience functions."""
    from src.security.crypto.symmetric import (
        encrypt_chacha20,
        decrypt_chacha20,
        CHACHA_KEY_LEN,
    )

    key = os.urandom(CHACHA_KEY_LEN)
    nonce, combined = encrypt_chacha20(key, b"hello")
    plaintext = decrypt_chacha20(key, nonce, combined)
    assert plaintext == b"hello"


def test_chacha20_invalid_tag_raises() -> None:
    """Test ChaCha20 rejects tampered ciphertext."""
    from src.security.crypto.symmetric import (
        encrypt_chacha20,
        decrypt_chacha20,
        CHACHA_KEY_LEN,
    )

    key = os.urandom(CHACHA_KEY_LEN)
    nonce, combined = encrypt_chacha20(key, b"data")

    # Tamper with last byte (tag)
    tampered = combined[:-1] + bytes([combined[-1] ^ 0xFF])

    with pytest.raises(DecryptionError):
        decrypt_chacha20(key, nonce, tampered)


def test_chacha20_operation_counter() -> None:
    """Test ChaCha20 operation counter warnings."""
    from src.security.crypto.symmetric import ChaCha20Cipher, CHACHA_KEY_LEN

    key = os.urandom(CHACHA_KEY_LEN)
    cipher = ChaCha20Cipher(max_operations=5)

    for _ in range(5):
        cipher.encrypt(key, b"x")

    with pytest.raises(EncryptionError, match="Key rotation required"):
        cipher.encrypt(key, b"overflow")


def test_split_combined() -> None:
    """Test split_combined helper function."""
    from src.security.crypto.symmetric import split_combined

    combined = b"ciphertext_data" + b"1234567890123456"  # 16-byte tag
    ct, tag = split_combined(combined)

    assert ct == b"ciphertext_data"
    assert tag == b"1234567890123456"
    assert len(tag) == 16


def test_split_combined_custom_tag_len() -> None:
    """Test split_combined with custom tag length."""
    from src.security.crypto.symmetric import split_combined

    combined = b"data" + b"tag8"  # 4-byte tag
    ct, tag = split_combined(combined, tag_len=4)

    assert ct == b"data"
    assert tag == b"tag8"


def test_join_ct_tag() -> None:
    """Test join_ct_tag helper function."""
    from src.security.crypto.symmetric import join_ct_tag

    ciphertext = b"encrypted_payload"
    tag = b"auth_tag_16bytes"

    combined = join_ct_tag(ciphertext, tag)
    assert combined == b"encrypted_payload" + b"auth_tag_16bytes"


def test_decrypt_with_invalid_key_length() -> None:
    """Test decryption fails with wrong key length."""
    cipher = SymmetricCipher()
    key = os.urandom(KEY_LEN)
    nonce, combined = cipher.encrypt(key, b"data")

    bad_key = b"short"
    with pytest.raises(DecryptionError, match="Invalid.*key length"):
        cipher.decrypt(bad_key, nonce, combined)


def test_decrypt_with_empty_ciphertext() -> None:
    """Test decryption fails with empty ciphertext."""
    cipher = SymmetricCipher()
    key = os.urandom(KEY_LEN)
    nonce = os.urandom(NONCE_LEN)

    with pytest.raises(DecryptionError, match="empty"):
        cipher.decrypt(key, nonce, b"")


def test_encrypt_with_bytearray_zeros_memory() -> None:
    """Test that encrypting bytearray zeros the original."""
    key = os.urandom(KEY_LEN)
    cipher = SymmetricCipher()

    plaintext = bytearray(b"sensitive_data")
    original_data = bytes(plaintext)

    nonce, combined = cipher.encrypt(key, plaintext)

    # Verify encryption worked
    decrypted = cipher.decrypt(key, nonce, combined)
    assert decrypted == original_data

    # Verify bytearray was zeroed
    assert plaintext == bytearray(len(original_data))


def test_chacha20_encrypt_with_bytearray_zeros_memory() -> None:
    """Test ChaCha20 zeros bytearray after encryption."""
    from src.security.crypto.symmetric import ChaCha20Cipher, CHACHA_KEY_LEN

    key = os.urandom(CHACHA_KEY_LEN)
    cipher = ChaCha20Cipher()

    plaintext = bytearray(b"secret")
    nonce, combined = cipher.encrypt(key, plaintext)

    # Verify bytearray was zeroed
    assert plaintext == bytearray(6)
