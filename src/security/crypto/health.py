# -*- coding: utf-8 -*-
"""
RU: Health check для криптографической подсистемы - проверка доступности алгоритмов.
EN: Crypto subsystem health check - verify algorithm availability at startup.
"""
from __future__ import annotations

import logging
from typing import Final

_LOGGER: Final = logging.getLogger(__name__)


def crypto_health_check() -> dict[str, bool]:
    """
    Verify availability of all cryptographic algorithms.

    Performs lightweight smoke tests of each crypto module to detect
    missing dependencies or system configuration issues at startup.

    Returns:
        Dictionary mapping subsystem names to health status (True = OK).

    Examples:
        >>> results = crypto_health_check()
        >>> assert all(results.values()), "Crypto subsystem unhealthy!"
        >>> results
        {'aes-256-gcm': True, 'ed25519': True, 'argon2id': True, ...}
    """
    results: dict[str, bool] = {}

    # Test 1: AES-256-GCM symmetric encryption
    results["aes-256-gcm"] = _test_symmetric()

    # Test 2: Ed25519 signatures
    results["ed25519"] = _test_signatures()

    # Test 3: Argon2id KDF
    results["argon2id"] = _test_kdf_argon2()

    # Test 4: PBKDF2 KDF (fallback)
    results["pbkdf2"] = _test_kdf_pbkdf2()

    # Test 5: Secure storage
    results["secure-storage"] = _test_secure_storage()

    # Test 6: Hashing
    results["hashing"] = _test_hashing()

    # Log summary
    failed = [k for k, v in results.items() if not v]
    if failed:
        _LOGGER.error("Crypto health check FAILED for: %s", ", ".join(failed))
    else:
        _LOGGER.info("Crypto health check PASSED (all subsystems operational)")

    return results


def _test_symmetric() -> bool:
    """Test AES-256-GCM encryption/decryption."""
    try:
        from .symmetric import decrypt_aes_gcm, encrypt_aes_gcm

        key = b"\x00" * 32
        plaintext = b"health-check-test"

        nonce, combined = encrypt_aes_gcm(key, plaintext)
        decrypted = decrypt_aes_gcm(key, nonce, combined)

        result: bool = bool(decrypted == plaintext)
        return result
    except Exception as e:
        _LOGGER.warning("AES-256-GCM test failed: %s", e.__class__.__name__)
        return False


def _test_signatures() -> bool:
    """Test Ed25519 signature generation/verification."""
    try:
        from .asymmetric import AsymmetricKeyPair

        kp = AsymmetricKeyPair.generate("ed25519")
        message = b"health-check-signature"
        signature = kp.sign(message)

        verified: bool = bool(kp.verify(message, signature))
        return verified
    except Exception as e:
        _LOGGER.warning("Ed25519 test failed: %s", e.__class__.__name__)
        return False


def _test_kdf_argon2() -> bool:
    """Test Argon2id key derivation."""
    try:
        from .kdf import derive_key_argon2id, generate_salt

        password = "health-check-pass"
        salt = generate_salt(16)

        key = derive_key_argon2id(
            password,
            salt,
            length=32,
            time_cost=2,
            memory_cost=65536,
            parallelism=1,
        )

        return len(key) == 32
    except Exception as e:
        _LOGGER.warning("Argon2id test failed: %s", e.__class__.__name__)
        return False


def _test_kdf_pbkdf2() -> bool:
    """Test PBKDF2-HMAC-SHA256 key derivation."""
    try:
        from .kdf import derive_key, generate_salt, make_pbkdf2_params

        password = "health-check-pass"
        salt = generate_salt(16)
        params = make_pbkdf2_params(iterations=100_000)

        key = derive_key(password, salt, 32, params=params)

        return len(key) == 32
    except Exception as e:
        _LOGGER.warning("PBKDF2 test failed: %s", e.__class__.__name__)
        return False


def _test_secure_storage() -> bool:
    """Test encrypted keystore."""
    try:
        import tempfile
        from pathlib import Path

        from src.security.crypto.secure_storage import FileEncryptedStorageBackend
        from src.security.crypto.symmetric import SymmetricCipher

        with tempfile.NamedTemporaryFile(delete=False, suffix=".keystore") as tmp:
            tmp_path = tmp.name

        Path(tmp_path).unlink(missing_ok=True)

        try:
            # ✅ ИСПРАВЛЕНИЕ: явное приведение типа для mypy
            cipher: SymmetricCipher = SymmetricCipher()
            key = b"\x00" * 32

            storage = FileEncryptedStorageBackend(
                filepath=tmp_path,
                cipher=cipher,  # type: ignore[arg-type]
                key_provider=lambda: key,
            )

            test_data = b"health-check-storage"
            storage.save("test-key", test_data)
            loaded = storage.load("test-key")

            result: bool = bool(loaded == test_data)
            return result
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    except Exception as e:
        _LOGGER.warning(
            "Secure storage test failed: %s - %s", e.__class__.__name__, str(e)
        )
        return False


def _test_hashing() -> bool:
    """Test SHA3-256 and BLAKE2b hashing."""
    try:
        from src.security.crypto import hashing

        data = b"health-check-hash"

        # ✅ Используем прямой вызов функций
        sha3 = hashing.compute_hash(data, algorithm="sha3-256")
        blake2 = hashing.compute_hash(data, algorithm="blake2b")

        # Verify deterministic output
        sha3_2 = hashing.compute_hash(data, algorithm="sha3-256")

        result: bool = bool(len(sha3) == 64 and len(blake2) == 128 and sha3 == sha3_2)
        return result
    except ImportError as e:
        _LOGGER.warning("Hashing test failed - missing dependency: %s", str(e))
        return False
    except AttributeError as e:
        _LOGGER.warning("Hashing test failed - missing function: %s", str(e))
        return False
    except Exception as e:
        _LOGGER.warning("Hashing test failed: %s - %s", e.__class__.__name__, str(e))
        return False


__all__ = ["crypto_health_check"]
