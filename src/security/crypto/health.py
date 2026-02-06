# -*- coding: utf-8 -*-
"""
RU: Health check для криптографической подсистемы - проверка доступности алгоритмов.
EN: Crypto subsystem health check - verify algorithm availability at startup.

Проверяет все группы протоколов:
- Symmetric AEAD: AES-GCM, ChaCha20-Poly1305
- Asymmetric: Ed25519, RSA-4096, ECDSA P-256
- Post-Quantum: Kyber-768 (optional), Dilithium-3 (optional)
- Password Hashing: Argon2id, PBKDF2
- Standards: PIV, OpenPGP (Brainpool)
- Hashing: SHA3-256, BLAKE2b, BLAKE3 (optional)
- Storage: Encrypted keystore
- Legacy (deprecated): Triple-DES, DSA
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
        >>> # Check core algorithms only
        >>> core_ok = all(v for k, v in results.items() if not k.startswith('optional-'))
        >>> assert core_ok, "Core crypto subsystem unhealthy!"
    """
    results: dict[str, bool] = {}

    # === SYMMETRIC AEAD CIPHERS ===
    results["aes-256-gcm"] = _test_symmetric_aes()
    results["chacha20-poly1305"] = _test_symmetric_chacha20()

    # === ASYMMETRIC ALGORITHMS ===
    results["ed25519"] = _test_asymmetric_ed25519()
    results["rsa-4096"] = _test_asymmetric_rsa()
    results["ecdsa-p256"] = _test_asymmetric_ecdsa()

    # === POST-QUANTUM CRYPTOGRAPHY ===
    results["optional-kyber-768"] = _test_pqc_kyber()
    results["optional-dilithium-3"] = _test_pqc_dilithium()

    # === PASSWORD HASHING ===
    results["passwords-argon2id"] = _test_password_argon2()
    results["passwords-pbkdf2"] = _test_password_pbkdf2()

    # === KEY DERIVATION ===
    results["kdf-argon2"] = _test_kdf_argon2()
    results["kdf-pbkdf2"] = _test_kdf_pbkdf2()

    # === HASHING ===
    results["hashing"] = _test_hashing()
    results["optional-blake3"] = _test_hashing_blake3()

    # === STANDARDS COMPLIANCE ===
    results["piv-rsa"] = _test_standards_piv()
    results["openpgp-brainpool"] = _test_standards_openpgp_brainpool()

    # === SECURE STORAGE ===
    results["secure-storage"] = _test_secure_storage()

    # === LEGACY (Deprecated - должны работать но помечены как устаревшие) ===
    results["legacy-3des"] = _test_legacy_3des()
    results["legacy-dsa"] = _test_legacy_dsa()

    # Log summary
    failed = [k for k, v in results.items() if not v and not k.startswith("optional-")]
    optional_failed = [
        k for k, v in results.items() if not v and k.startswith("optional-")
    ]

    if failed:
        _LOGGER.error("Crypto health check FAILED for: %s", ", ".join(failed))
    else:
        _LOGGER.info(
            "Crypto health check PASSED (all %d core subsystems operational)",
            len([k for k in results if not k.startswith("optional-")]),
        )

    if optional_failed:
        _LOGGER.info("Optional algorithms unavailable: %s", ", ".join(optional_failed))

    return results


# ==================== SYMMETRIC CIPHERS ====================


def _test_symmetric_aes() -> bool:
    """Test AES-256-GCM encryption/decryption."""
    try:
        from .symmetric import SymmetricCipher

        cipher = SymmetricCipher()
        key = b"\x00" * 32
        plaintext = b"health-check-aes"

        nonce, combined = cipher.encrypt(key, plaintext)
        decrypted = cipher.decrypt(key, nonce, combined)

        return bool(decrypted == plaintext)

    except Exception as e:
        _LOGGER.warning("AES-256-GCM test failed: %s", e.__class__.__name__)
        return False


def _test_symmetric_chacha20() -> bool:
    """Test ChaCha20-Poly1305 encryption/decryption."""
    try:
        from .symmetric import ChaCha20Cipher

        cipher = ChaCha20Cipher()
        key = b"\x00" * 32
        plaintext = b"health-check-chacha20"

        nonce, combined = cipher.encrypt(key, plaintext)
        decrypted = cipher.decrypt(key, nonce, combined)

        return bool(decrypted == plaintext)

    except Exception as e:
        _LOGGER.warning("ChaCha20-Poly1305 test failed: %s", e.__class__.__name__)
        return False


# ==================== ASYMMETRIC ALGORITHMS ====================


def _test_asymmetric_ed25519() -> bool:
    """Test Ed25519 signature generation/verification."""
    try:
        from .asymmetric import AsymmetricKeyPair

        kp = AsymmetricKeyPair.generate("ed25519")
        message = b"health-check-ed25519"
        signature = kp.sign(message)
        verified: bool = bool(kp.verify(message, signature))

        return verified

    except Exception as e:
        _LOGGER.warning("Ed25519 test failed: %s", e.__class__.__name__)
        return False


def _test_asymmetric_rsa() -> bool:
    """Test RSA-4096 signature generation/verification."""
    try:
        from .asymmetric import AsymmetricKeyPair

        kp = AsymmetricKeyPair.generate("rsa4096", key_size=2048)  # 2048 for speed
        message = b"health-check-rsa"
        signature = kp.sign(message)
        verified: bool = bool(kp.verify(message, signature))

        return verified

    except Exception as e:
        _LOGGER.warning("RSA-4096 test failed: %s", e.__class__.__name__)
        return False


def _test_asymmetric_ecdsa() -> bool:
    """Test ECDSA P-256 signature generation/verification."""
    try:
        from .asymmetric import AsymmetricKeyPair

        kp = AsymmetricKeyPair.generate("ecdsa_p256")
        message = b"health-check-ecdsa"
        signature = kp.sign(message)
        verified: bool = bool(kp.verify(message, signature))

        return verified

    except Exception as e:
        _LOGGER.warning("ECDSA P-256 test failed: %s", e.__class__.__name__)
        return False


# ==================== POST-QUANTUM CRYPTOGRAPHY ====================


def _test_pqc_kyber() -> bool:
    """Test Kyber-768 KEM encapsulation/decapsulation (optional)."""
    try:
        from .pqc import KYBER_AVAILABLE, KyberKEM

        if not KYBER_AVAILABLE:
            _LOGGER.info("Kyber-768 not available (install: pip install pqcrypto)")
            return False

        kem = KyberKEM.generate()
        ciphertext, shared_secret1 = kem.encapsulate()
        shared_secret2 = kem.decapsulate(ciphertext)

        return bool(shared_secret1 == shared_secret2 and len(shared_secret1) == 32)

    except Exception as e:
        _LOGGER.warning("Kyber-768 test failed: %s", e.__class__.__name__)
        return False


def _test_pqc_dilithium() -> bool:
    """Test Dilithium-3 signature generation/verification (optional)."""
    try:
        from .pqc import DILITHIUM_AVAILABLE, DilithiumSigner

        if not DILITHIUM_AVAILABLE:
            _LOGGER.info("Dilithium-3 not available (install: pip install pqcrypto)")
            return False

        signer = DilithiumSigner.generate()
        message = b"health-check-dilithium"
        signature = signer.sign(message)
        verified: bool = signer.verify(message, signature)

        return verified

    except Exception as e:
        _LOGGER.warning("Dilithium-3 test failed: %s", e.__class__.__name__)
        return False


# ==================== PASSWORD HASHING ====================


def _test_password_argon2() -> bool:
    """Test Argon2id password hashing."""
    try:
        from .passwords import PasswordHasher

        hasher = PasswordHasher(
            scheme="argon2id",
            time_cost=2,
            memory_cost=65536,
            parallelism=1,
            rate_limit_enabled=False,
        )

        password = "test-password-123"
        hashed = hasher.hash_password(password)

        return bool("argon2id:" in hashed and len(hashed) > 50)

    except Exception as e:
        _LOGGER.warning("Argon2id password test failed: %s", e.__class__.__name__)
        return False


def _test_password_pbkdf2() -> bool:
    """Test PBKDF2 password hashing."""
    try:
        from .passwords import PasswordHasher

        hasher = PasswordHasher(
            scheme="pbkdf2", iterations=100_000, rate_limit_enabled=False
        )

        password = "test-password-456"
        hashed = hasher.hash_password(password)

        return bool("pbkdf2:" in hashed and len(hashed) > 50)

    except Exception as e:
        _LOGGER.warning("PBKDF2 password test failed: %s", e.__class__.__name__)
        return False


# ==================== KEY DERIVATION ====================


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
        _LOGGER.warning("Argon2id KDF test failed: %s", e.__class__.__name__)
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
        _LOGGER.warning("PBKDF2 KDF test failed: %s", e.__class__.__name__)
        return False


# ==================== HASHING ====================


def _test_hashing() -> bool:
    """Test SHA3-256 and BLAKE2b hashing."""
    try:
        from .hashing import compute_hash

        data = b"health-check-hash"

        sha3 = compute_hash(data, algorithm="sha3-256")
        blake2 = compute_hash(data, algorithm="blake2b")

        # Verify deterministic output
        sha3_2 = compute_hash(data, algorithm="sha3-256")

        return bool(len(sha3) == 64 and len(blake2) == 128 and sha3 == sha3_2)

    except Exception as e:
        _LOGGER.warning("Hashing test failed: %s", e.__class__.__name__)
        return False


def _test_hashing_blake3() -> bool:
    """Test BLAKE3 hashing (optional)."""
    try:
        from .hashing import BLAKE3_AVAILABLE, compute_hash

        if not BLAKE3_AVAILABLE:
            _LOGGER.info("BLAKE3 not available (install: pip install blake3)")
            return False

        data = b"health-check-blake3"
        blake3 = compute_hash(data, algorithm="blake3")

        return bool(len(blake3) == 64)

    except Exception as e:
        _LOGGER.warning("BLAKE3 test failed: %s", e.__class__.__name__)
        return False


# ==================== STANDARDS COMPLIANCE ====================


def _test_standards_piv() -> bool:
    """Test PIV RSA-2048 compliance."""
    try:
        from .standards import PIVKeyPair

        kp = PIVKeyPair.generate_rsa(2048)
        data = b"piv-health-check"
        signature = kp.sign(data)
        verified: bool = kp.verify(data, signature)

        return verified

    except Exception as e:
        _LOGGER.warning("PIV test failed: %s", e.__class__.__name__)
        return False


def _test_standards_openpgp_brainpool() -> bool:
    """Test OpenPGP Brainpool P-256r1 curve."""
    try:
        from .standards import OpenPGPKeyPair

        kp = OpenPGPKeyPair.generate_ecdsa("brainpoolP256r1")
        data = b"brainpool-test"
        signature = kp.sign(data)
        verified: bool = kp.verify(data, signature)

        return verified

    except Exception as e:
        _LOGGER.warning("OpenPGP Brainpool test failed: %s", e.__class__.__name__)
        return False


# ==================== SECURE STORAGE ====================


def _test_secure_storage() -> bool:
    """Test encrypted keystore."""
    try:
        import tempfile
        from pathlib import Path

        from .secure_storage import FileEncryptedStorageBackend
        from .symmetric import SymmetricCipher

        with tempfile.NamedTemporaryFile(delete=False, suffix=".keystore") as tmp:
            tmp_path = tmp.name

        Path(tmp_path).unlink(missing_ok=True)

        try:
            cipher = SymmetricCipher()
            key = b"\x00" * 32

            storage = FileEncryptedStorageBackend(
                filepath=tmp_path,
                cipher=cipher,
                key_provider=lambda: key,
            )

            test_data = b"health-check-storage"
            storage.save("test-key", test_data)
            loaded = storage.load("test-key")

            return bool(loaded == test_data)

        finally:
            Path(tmp_path).unlink(missing_ok=True)

    except Exception as e:
        _LOGGER.warning(
            "Secure storage test failed: %s - %s", e.__class__.__name__, str(e)
        )
        return False


# ==================== LEGACY (DEPRECATED) ====================


def _test_legacy_3des() -> bool:
    """Test Triple-DES (DEPRECATED - для обратной совместимости)."""
    try:
        # Triple-DES moved to decrepit in cryptography 48+
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        from cryptography.hazmat.backends import default_backend

        # Triple-DES требует 24-byte ключ (3 * 8 bytes)
        key = b"\x01\x23\x45\x67\x89\xab\xcd\xef" * 3  # 24 bytes
        iv = b"\x00" * 8  # 64-bit IV
        plaintext = b"3DES-old"

        cipher = Cipher(TripleDES(key), modes.CBC(iv), backend=default_backend())

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()

        _LOGGER.warning("Triple-DES is DEPRECATED - use AES instead")
        return bool(decrypted == plaintext)

    except Exception as e:
        _LOGGER.warning("Triple-DES (legacy) test failed: %s", e.__class__.__name__)
        return False


def _test_legacy_dsa() -> bool:
    """Test DSA signatures (DEPRECATED - для обратной совместимости)."""
    try:
        from cryptography.hazmat.primitives.asymmetric import dsa
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend

        # Generate DSA keypair (быстрый 1024-bit для теста)
        private_key = dsa.generate_private_key(key_size=1024, backend=default_backend())
        public_key = private_key.public_key()

        message = b"dsa-legacy-test"
        signature = private_key.sign(message, hashes.SHA256())

        try:
            public_key.verify(signature, message, hashes.SHA256())
            _LOGGER.warning("DSA is DEPRECATED - use EdDSA or ECDSA instead")
            return True
        except Exception:
            return False

    except Exception as e:
        _LOGGER.warning("DSA (legacy) test failed: %s", e.__class__.__name__)
        return False


__all__ = ["crypto_health_check"]
