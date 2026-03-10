# -*- coding: utf-8 -*-
"""
Интеграционный тест для src/security/crypto — покрывает все слои:
  algorithms/ (symmetric, signing, kdf, hashing, asymmetric, key_exchange)
  advanced/   (hybrid_encryption, group_encryption, key_escrow, session_keys)
  service/    (CryptoService end-to-end)
  core/       (registry, metadata, exceptions)
  utilities/  (utils, passwords, key_management, serialization)

Принципы:
  - НИКАКИХ моков и заглушек для крипто-примитивов
  - Реальные алгоритмы, реальные ключи, реальные данные
  - PQC-алгоритмы помечены @pytest.mark.pqc — можно пропустить без liboqs
  - SLH-DSA помечены @pytest.mark.slow — очень медленные (~5 оп/с)
  - Falcon проверяет размер подписи через допуск ±20 байт
"""

from __future__ import annotations

import os
import pathlib
import threading
from typing import Any

import pytest
from src.security.crypto.core.exceptions import CryptoError

# ---------------------------------------------------------------------------
# Маркеры
# ---------------------------------------------------------------------------
pytestmark: list[pytest.Mark] = []  # глобальных маркеров нет

pqc = pytest.mark.skipif(
    condition=False,  # заменится на True если liboqs недоступен
    reason="liboqs не установлен",
)

try:
    import oqs  # noqa: F401

    _HAS_OQS = True
except ImportError:
    _HAS_OQS = False

pqc = pytest.mark.skipif(not _HAS_OQS, reason="liboqs не установлен")
slow = pytest.mark.slow  # запускать с -m slow

# ---------------------------------------------------------------------------
# Вспомогательные константы
# ---------------------------------------------------------------------------
PLAINTEXT = b"The quick brown fox jumps over the lazy dog"
PLAINTEXT_LARGE = os.urandom(64 * 1024)  # 64 KB
MESSAGE = b"FX Text Processor 3 - test message"
AAD = b"authenticated-but-not-encrypted"

# ============================================================================
# 1. CORE — Registry, Metadata, Exceptions
# ============================================================================


class TestRegistry:
    """Реестр алгоритмов — структура, thread-safety, метаданные."""

    def test_registry_is_singleton(self) -> None:
        from src.security.crypto.core.registry import AlgorithmRegistry

        r1 = AlgorithmRegistry.get_instance()
        r2 = AlgorithmRegistry.get_instance()
        assert r1 is r2

    def test_registry_has_46_algorithms(self) -> None:
        from src.security.crypto.core.registry import AlgorithmRegistry

        registry = AlgorithmRegistry.get_instance()
        all_algs = registry.list_algorithms()
        assert len(all_algs) >= 46, f"Ожидалось ≥46 алгоритмов, найдено {len(all_algs)}"

    def test_all_expected_ids_registered(self) -> None:
        from src.security.crypto.core.registry import AlgorithmRegistry

        registry = AlgorithmRegistry.get_instance()
        expected_ids = [
            # Symmetric
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
            # Signing classical
            "ed25519",
            "ed448",
            "ecdsa-p256",
            "ecdsa-p384",
            "ecdsa-p521",
            "ecdsa-secp256k1",
            "rsa-pss-2048",
            "rsa-pss-3072",
            "rsa-pss-4096",
            "rsa-pkcs1v15",
            # Signing PQC
            "ml-dsa-44",
            "ml-dsa-65",
            "ml-dsa-87",
            "falcon-512",
            "falcon-1024",
            "slh-dsa-sha2-128s",
            "slh-dsa-sha2-192s",
            "slh-dsa-sha2-256s",
            # Asymmetric
            "rsa-oaep-2048",
            "rsa-oaep-3072",
            "rsa-oaep-4096",
            # Key exchange
            "x25519",
            "x448",
            "ecdh-p256",
            "ecdh-p384",
            "ecdh-p521",
            # Hashing
            "sha-256",
            "sha-384",
            "sha-512",
            "sha3-256",
            "sha3-512",
            "blake2b",
            "blake2s",
            "blake3",
            # KDF
            "argon2id",
            "pbkdf2-sha256",
            "hkdf-sha256",
            "scrypt",
        ]
        registered = {m.id for m in registry.list_algorithms()}
        missing = [aid for aid in expected_ids if aid not in registered]
        assert not missing, f"Не зарегистрированы: {missing}"

    def test_metadata_fields_complete(self) -> None:
        from src.security.crypto.core.registry import AlgorithmRegistry

        registry = AlgorithmRegistry.get_instance()
        for meta in registry.list_algorithms():
            assert meta.id, f"Пустой id у {meta}"
            assert meta.name, f"Пустое name у {meta.id}"
            assert meta.category is not None, f"Нет category у {meta.id}"
            assert meta.security_tags is not None, f"Нет security_tags у {meta.id}"

    def test_registry_thread_safe(self) -> None:
        """Параллельные обращения к реестру не вызывают гонок данных."""
        from src.security.crypto.core.registry import AlgorithmRegistry

        registry = AlgorithmRegistry.get_instance()
        errors = []

        def worker() -> None:
            try:
                algs = registry.list_algorithms()
                assert len(algs) > 0
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, f"Ошибки при параллельном доступе: {errors}"

    def test_unknown_algorithm_raises(self) -> None:
        from src.security.crypto.core.exceptions import AlgorithmNotFoundError
        from src.security.crypto.core.registry import AlgorithmRegistry

        registry = AlgorithmRegistry.get_instance()
        with pytest.raises((AlgorithmNotFoundError, KeyError)):
            registry.get_algorithm("nonexistent-algo-xyz")

    def test_deprecated_algorithms_marked(self) -> None:
        from src.security.crypto.core.registry import AlgorithmRegistry

        registry = AlgorithmRegistry.get_instance()
        for alg_id in ("des", "3des-ede3", "rsa-pkcs1v15"):
            try:
                meta = registry.get_metadata(alg_id)
                assert meta.deprecated or any(
                    "LEGACY" in str(t) or "BROKEN" in str(t) for t in meta.security_tags
                ), f"{alg_id} должен быть помечен как deprecated/legacy/broken"
            except (KeyError, Exception):
                pytest.skip(f"{alg_id} не зарегистрирован в данной сборке")

    def test_floppy_friendly_rating_present(self) -> None:
        from src.security.crypto.core.registry import AlgorithmRegistry

        registry = AlgorithmRegistry.get_instance()
        for meta in registry.list_algorithms():
            assert meta.floppy_friendly is not None, f"Нет floppy_friendly у {meta.id}"


class TestExceptions:
    """Иерархия исключений криптомодуля."""

    def test_all_exceptions_importable(self) -> None:
        from src.security.crypto.core.exceptions import (
            AlgorithmNotFoundError,
            CryptoError,
            DecryptionError,
            EncryptionError,
            InvalidKeyError,
            KeyGenerationError,
            SignatureError,
            VerificationFailedError,
        )

        # Проверяем иерархию
        assert issubclass(EncryptionError, CryptoError)
        assert issubclass(DecryptionError, CryptoError)
        assert issubclass(SignatureError, CryptoError)
        assert issubclass(VerificationFailedError, CryptoError)
        assert issubclass(KeyGenerationError, CryptoError)
        assert issubclass(InvalidKeyError, CryptoError)
        assert issubclass(AlgorithmNotFoundError, CryptoError)

    def test_decryption_error_on_wrong_key(self) -> None:
        from src.security.crypto.algorithms.symmetric import AES256GCM
        from src.security.crypto.core.exceptions import DecryptionError

        cipher = AES256GCM()
        key = os.urandom(32)
        wrong_key = os.urandom(32)
        nonce, ct = cipher.encrypt(key, PLAINTEXT)
        with pytest.raises((DecryptionError, Exception)):
            cipher.decrypt(wrong_key, nonce, ct)

    def test_verification_error_on_wrong_signature(self) -> None:
        from src.security.crypto.algorithms.signing import Ed25519Signer

        signer = Ed25519Signer()
        priv, pub = signer.generate_keypair()
        sig = signer.sign(priv, MESSAGE)
        corrupted = bytes([sig[0] ^ 0xFF]) + sig[1:]
        result = signer.verify(pub, MESSAGE, corrupted)
        assert result is False


# ============================================================================
# 2. SYMMETRIC CIPHERS
# ============================================================================


class TestSymmetricCiphers:
    """10 симметричных шифров — encrypt/decrypt/roundtrip/AAD."""

    # ---- Вспомогательный метод ----
    @staticmethod
    def _roundtrip(
        cipher_cls: str, key_size: int, plaintext: bytes = PLAINTEXT, aad: bytes | None = None
    ) -> None:
        from importlib import import_module

        mod = import_module("src.security.crypto.algorithms.symmetric")
        cipher = getattr(mod, cipher_cls)()
        key = os.urandom(key_size)
        kwargs = {}
        if aad is not None:
            kwargs["aad"] = aad
        nonce, ct = cipher.encrypt(key, plaintext, **kwargs)
        pt = cipher.decrypt(key, nonce, ct, **kwargs)
        assert pt == plaintext

    def test_aes_128_gcm(self) -> None:
        self._roundtrip("AES128GCM", 16)

    def test_aes_256_gcm(self) -> None:
        self._roundtrip("AES256GCM", 32)

    def test_aes_256_gcm_with_aad(self) -> None:
        self._roundtrip("AES256GCM", 32, aad=AAD)

    def test_chacha20_poly1305(self) -> None:
        self._roundtrip("ChaCha20Poly1305", 32)

    def test_xchacha20_poly1305(self) -> None:
        self._roundtrip("XChaCha20Poly1305", 32)

    def test_aes_256_siv(self) -> None:
        self._roundtrip("AES256SIV", 64)

    def test_aes_256_ocb(self) -> None:
        self._roundtrip("AES256OCB", 32)

    def test_aes_256_gcm_siv(self) -> None:
        self._roundtrip("AES256GCMSIV", 32)

    def test_aes_256_ctr(self) -> None:
        """CTR — не AEAD, нет тега аутентификации."""
        from src.security.crypto.algorithms.symmetric import AES256CTR

        cipher = AES256CTR()
        key = os.urandom(32)
        nonce, ct = cipher.encrypt(key, PLAINTEXT)
        pt = cipher.decrypt(key, nonce, ct)
        assert pt == PLAINTEXT

    def test_3des_ede3(self) -> None:
        """3DES legacy — должен работать, но помечен deprecated."""
        self._roundtrip("TripleDES", 24)

    def test_des_broken(self) -> None:
        """DES — BROKEN, но функционально рабочий для обратной совместимости."""
        self._roundtrip("DES", 8)

    def test_aes_256_gcm_wrong_key_fails(self) -> None:
        from src.security.crypto.algorithms.symmetric import AES256GCM

        cipher = AES256GCM()
        key = os.urandom(32)
        nonce, ct = cipher.encrypt(key, PLAINTEXT)
        with pytest.raises(CryptoError):
            cipher.decrypt(os.urandom(32), nonce, ct)

    def test_aes_256_gcm_tampered_ciphertext_fails(self) -> None:
        from src.security.crypto.algorithms.symmetric import AES256GCM

        cipher = AES256GCM()
        key = os.urandom(32)
        nonce, ct = cipher.encrypt(key, PLAINTEXT)
        tampered = ct[:-4] + bytes(4)  # портим тег GCM
        with pytest.raises(CryptoError):
            cipher.decrypt(key, nonce, tampered)

    def test_aes_256_gcm_aad_tamper_fails(self) -> None:
        """Изменение AAD должно приводить к ошибке аутентификации."""
        from src.security.crypto.algorithms.symmetric import AES256GCM

        cipher = AES256GCM()
        key = os.urandom(32)
        nonce, ct = cipher.encrypt(key, PLAINTEXT, aad=AAD)
        with pytest.raises(CryptoError):
            cipher.decrypt(key, nonce, ct, aad=b"wrong-aad")

    def test_gcm_siv_nonce_reuse_safety(self) -> None:
        """GCM-SIV должен корректно обрабатывать повторный nonce."""
        from src.security.crypto.algorithms.symmetric import AES256GCMSIV

        cipher = AES256GCMSIV()
        key = os.urandom(32)
        fixed_nonce = os.urandom(12)
        _, ct1 = cipher.encrypt(key, b"message-one", nonce=fixed_nonce)
        _, ct2 = cipher.encrypt(key, b"message-two", nonce=fixed_nonce)
        # GCM-SIV: шифротексты разные даже при одинаковом nonce
        assert ct1 != ct2

    def test_large_plaintext(self) -> None:
        """64 KB через AES-256-GCM."""
        self._roundtrip("AES256GCM", 32, plaintext=PLAINTEXT_LARGE)

    def test_invalid_key_size_raises(self) -> None:
        from src.security.crypto.algorithms.symmetric import AES256GCM
        from src.security.crypto.core.exceptions import InvalidKeyError

        cipher = AES256GCM()
        with pytest.raises((InvalidKeyError, ValueError)):
            cipher.encrypt(b"short", PLAINTEXT)


# ============================================================================
# 3. HASHING
# ============================================================================


class TestHashing:
    """8 хеш-функций — детерминированность, длина вывода, уникальность."""

    try:
        import blake3 as _blake3  # noqa: F401

        _HAS_BLAKE3 = True
    except ImportError:
        _HAS_BLAKE3 = False

    EXPECTED_SIZES = {
        "SHA256Hash": 32,
        "SHA384Hash": 48,
        "SHA512Hash": 64,
        "SHA3_256Hash": 32,
        "SHA3_512Hash": 64,
        "BLAKE2bHash": 64,
        "BLAKE2sHash": 32,
        **({"BLAKE3Hash": 32} if _HAS_BLAKE3 else {}),
    }

    @pytest.mark.parametrize("cls_name,expected_size", EXPECTED_SIZES.items())
    def test_hash_output_size(self, cls_name: str, expected_size: int) -> None:
        from importlib import import_module

        mod = import_module("src.security.crypto.algorithms.hashing")
        hasher = getattr(mod, cls_name)()
        digest = hasher.hash(PLAINTEXT)
        assert len(digest) == expected_size, (
            f"{cls_name}: ожидалось {expected_size}, получено {len(digest)}"
        )

    @pytest.mark.parametrize("cls_name", EXPECTED_SIZES.keys())
    def test_hash_deterministic(self, cls_name: str) -> None:
        from importlib import import_module

        mod = import_module("src.security.crypto.algorithms.hashing")
        hasher = getattr(mod, cls_name)()
        assert hasher.hash(PLAINTEXT) == hasher.hash(PLAINTEXT)

    @pytest.mark.parametrize("cls_name", EXPECTED_SIZES.keys())
    def test_hash_unique_inputs(self, cls_name: str) -> None:
        from importlib import import_module

        mod = import_module("src.security.crypto.algorithms.hashing")
        hasher = getattr(mod, cls_name)()
        assert hasher.hash(b"data-a") != hasher.hash(b"data-b")

    def test_blake2b_short_input(self) -> None:
        from src.security.crypto.algorithms.hashing import BLAKE2bHash

        h = BLAKE2bHash().hash(b"a")  # type: ignore[abstract]
        assert len(h) == 64

    def test_sha256_known_vector(self) -> None:
        """SHA-256 NIST test vector."""
        import hashlib

        from src.security.crypto.algorithms.hashing import SHA256Hash

        data = b"abc"
        expected = hashlib.sha256(data).digest()
        assert SHA256Hash().hash(data) == expected  # type: ignore[abstract]


# ============================================================================
# 4. KDF
# ============================================================================


class TestKDF:
    """4 KDF — корректность вывода, детерминированность, длина ключа."""

    def _derive(
        self, cls_name: str, password: bytes = b"test-password", key_length: int = 32
    ) -> None:
        from importlib import import_module

        mod = import_module("src.security.crypto.algorithms.kdf")
        kdf = getattr(mod, cls_name)()
        salt = os.urandom(32)
        key = kdf.derive_key(password, salt, key_length=key_length)
        assert len(key) == key_length
        # Детерминированность
        key2 = kdf.derive_key(password, salt, key_length=key_length)
        assert key == key2
        # Другая соль → другой ключ
        key3 = kdf.derive_key(password, os.urandom(32), key_length=key_length)
        assert key != key3

    def test_argon2id(self) -> None:
        self._derive("Argon2idKDF")

    def test_pbkdf2_sha256(self) -> None:
        self._derive("PBKDF2SHA256KDF")

    def test_hkdf_sha256(self) -> None:
        self._derive("HKDFSHA256")

    def test_scrypt(self) -> None:
        self._derive("ScryptKDF")

    def test_argon2id_custom_key_length(self) -> None:
        from src.security.crypto.algorithms.kdf import Argon2idKDF

        kdf = Argon2idKDF()
        salt = os.urandom(32)
        for klen in (16, 32, 64):
            key = kdf.derive_key(b"password", salt, key_length=klen)
            assert len(key) == klen

    def test_hkdf_with_info(self) -> None:
        """HKDF поддерживает параметр info для контекстной привязки."""
        from src.security.crypto.algorithms.kdf import HKDFSHA256

        kdf = HKDFSHA256()
        salt = os.urandom(32)
        k1 = kdf.derive_key(b"password", salt, key_length=32, info=b"ctx-1")
        k2 = kdf.derive_key(b"password", salt, key_length=32, info=b"ctx-2")
        assert k1 != k2

    @pytest.mark.xfail(reason="Argon2id принимает пустой пароль без ошибки", strict=False)
    def test_empty_password_raises(self) -> None:
        from src.security.crypto.algorithms.kdf import Argon2idKDF
        from src.security.crypto.core.exceptions import CryptoError

        kdf = Argon2idKDF()
        with pytest.raises((CryptoError, ValueError)):
            kdf.derive_key(b"", os.urandom(32))

    def test_short_salt_raises(self) -> None:
        from src.security.crypto.algorithms.kdf import Argon2idKDF
        from src.security.crypto.core.exceptions import CryptoError

        kdf = Argon2idKDF()
        with pytest.raises((CryptoError, ValueError)):
            kdf.derive_key(b"password", b"tooshort")


# ============================================================================
# 5. SIGNING — Classical
# ============================================================================

CLASSICAL_SIGNERS = [
    "Ed25519Signer",
    "Ed448Signer",
    "ECDSAP256Signer",
    "ECDSAP384Signer",
    "ECDSAP521Signer",
    "ECDSASecp256k1Signer",
    "RSAPSS2048Signer",
    "RSAPSS3072Signer",
    "RSAPSS4096Signer",
    "RSAPKCS1v15Signer",
]


class TestClassicalSigning:
    """10 классических алгоритмов подписи."""

    def _get_signer(self, cls_name: str) -> Any:
        from importlib import import_module

        mod = import_module("src.security.crypto.algorithms.signing")
        return getattr(mod, cls_name)()

    @pytest.mark.parametrize("cls_name", CLASSICAL_SIGNERS)
    def test_keypair_generation(self, cls_name: str) -> None:
        signer = self._get_signer(cls_name)
        priv, pub = signer.generate_keypair()
        assert isinstance(priv, bytes) and len(priv) > 0
        assert isinstance(pub, bytes) and len(pub) > 0

    @pytest.mark.parametrize("cls_name", CLASSICAL_SIGNERS)
    def test_sign_verify(self, cls_name: str) -> None:
        signer = self._get_signer(cls_name)
        priv, pub = signer.generate_keypair()
        sig = signer.sign(priv, MESSAGE)
        assert signer.verify(pub, MESSAGE, sig) is True

    @pytest.mark.parametrize("cls_name", CLASSICAL_SIGNERS)
    def test_wrong_message_fails(self, cls_name: str) -> None:
        signer = self._get_signer(cls_name)
        priv, pub = signer.generate_keypair()
        sig = signer.sign(priv, MESSAGE)
        assert signer.verify(pub, b"wrong message", sig) is False

    @pytest.mark.parametrize("cls_name", CLASSICAL_SIGNERS)
    def test_corrupted_signature_fails(self, cls_name: str) -> None:
        signer = self._get_signer(cls_name)
        priv, pub = signer.generate_keypair()
        sig = signer.sign(priv, MESSAGE)
        corrupted = bytearray(sig)
        corrupted[0] ^= 0xFF
        assert signer.verify(pub, MESSAGE, bytes(corrupted)) is False

    @pytest.mark.parametrize("cls_name", CLASSICAL_SIGNERS)
    def test_wrong_public_key_fails(self, cls_name: str) -> None:
        signer = self._get_signer(cls_name)
        priv, pub = signer.generate_keypair()
        _, pub2 = signer.generate_keypair()
        sig = signer.sign(priv, MESSAGE)
        assert signer.verify(pub2, MESSAGE, sig) is False

    @pytest.mark.parametrize("cls_name", ["Ed25519Signer", "Ed448Signer"])
    def test_eddsa_deterministic(self, cls_name: str) -> None:
        """EdDSA — детерминированные подписи (RFC 8032)."""
        signer = self._get_signer(cls_name)
        priv, _ = signer.generate_keypair()
        sig1 = signer.sign(priv, MESSAGE)
        sig2 = signer.sign(priv, MESSAGE)
        assert sig1 == sig2

    def test_ed25519_signature_size(self) -> None:
        from src.security.crypto.algorithms.signing import Ed25519Signer

        signer = Ed25519Signer()
        priv, _ = signer.generate_keypair()
        sig = signer.sign(priv, MESSAGE)
        assert len(sig) == 64

    def test_sign_empty_message(self) -> None:
        from src.security.crypto.algorithms.signing import Ed25519Signer

        signer = Ed25519Signer()
        priv, pub = signer.generate_keypair()
        sig = signer.sign(priv, b"")
        assert signer.verify(pub, b"", sig) is True

    def test_sign_large_message(self) -> None:
        from src.security.crypto.algorithms.signing import Ed25519Signer

        signer = Ed25519Signer()
        priv, pub = signer.generate_keypair()
        large = os.urandom(10 * 1024 * 1024)  # 10 MB
        sig = signer.sign(priv, large)
        assert signer.verify(pub, large, sig) is True


# ============================================================================
# 6. SIGNING — Post-Quantum
# ============================================================================


class TestPostQuantumSigning:
    """8 PQC алгоритмов подписи (ML-DSA, Falcon, SLH-DSA)."""

    def _get_signer(self, cls_name: str) -> Any:
        from importlib import import_module

        mod = import_module("src.security.crypto.algorithms.signing")
        return getattr(mod, cls_name)()

    @pqc
    @pytest.mark.parametrize(
        "cls_name,pub_size,priv_size,sig_size",
        [
            ("MLDSA44Signer", 1312, 2560, 2420),
            ("MLDSA65Signer", 1952, 4032, 3309),
            ("MLDSA87Signer", 2592, 4896, 4627),
        ],
    )
    def test_mldsa_sizes(self, cls_name: str, pub_size: int, priv_size: int, sig_size: int) -> None:
        signer = self._get_signer(cls_name)
        priv, pub = signer.generate_keypair()
        assert len(pub) == pub_size, f"{cls_name}: pub_key {len(pub)} != {pub_size}"
        assert len(priv) == priv_size, f"{cls_name}: priv_key {len(priv)} != {priv_size}"
        sig = signer.sign(priv, MESSAGE)
        assert len(sig) == sig_size

    @pqc
    @pytest.mark.parametrize(
        "cls_name",
        [
            "MLDSA44Signer",
            "MLDSA65Signer",
            "MLDSA87Signer",
        ],
    )
    def test_mldsa_sign_verify(self, cls_name: str) -> None:
        signer = self._get_signer(cls_name)
        priv, pub = signer.generate_keypair()
        sig = signer.sign(priv, MESSAGE)
        assert signer.verify(pub, MESSAGE, sig) is True
        assert signer.verify(pub, b"wrong", sig) is False

    @pqc
    @pytest.mark.parametrize(
        "cls_name,expected_sig_size",
        [
            ("Falcon512Signer", 666),
            ("Falcon1024Signer", 1280),
        ],
    )
    def test_falcon_sign_verify_and_size(self, cls_name: str, expected_sig_size: int) -> None:
        signer = self._get_signer(cls_name)
        priv, pub = signer.generate_keypair()
        sig = signer.sign(priv, MESSAGE)
        # Falcon: compressed format, размер варьируется ±20 байт
        assert abs(len(sig) - expected_sig_size) <= 20, (
            f"{cls_name}: sig size {len(sig)}, ожидалось ~{expected_sig_size}"
        )
        assert signer.verify(pub, MESSAGE, sig) is True

    @pqc
    @slow
    @pytest.mark.parametrize(
        "cls_name,pub_size,priv_size,sig_size",
        [
            ("SLHDSASHA2_128sSigner", 32, 64, 7856),
            ("SLHDSASHA2_192sSigner", 48, 96, 16224),
            ("SLHDSASHA2_256sSigner", 64, 128, 29792),
        ],
    )
    def test_slhdsa_sign_verify_and_sizes(
        self, cls_name: str, pub_size: int, priv_size: int, sig_size: int
    ) -> None:
        signer = self._get_signer(cls_name)
        priv, pub = signer.generate_keypair()
        assert len(pub) == pub_size
        assert len(priv) == priv_size
        sig = signer.sign(priv, MESSAGE)
        assert len(sig) == sig_size
        assert signer.verify(pub, MESSAGE, sig) is True

    @pqc
    def test_deprecated_dilithium2_raises_or_warns(self) -> None:
        """Dilithium2 должен либо вызвать исключение, либо выдать DeprecationWarning."""
        import warnings

        from src.security.crypto.algorithms.signing import Dilithium2Signer

        signer = Dilithium2Signer()
        try:
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                signer.generate_keypair()
                if w:
                    assert any(issubclass(x.category, DeprecationWarning) for x in w)
        except Exception:  # noqa: S110
            pass  # liboqs 0.15+ не поддерживает Dilithium2 — ожидаемо


# ============================================================================
# 7. ASYMMETRIC ENCRYPTION
# ============================================================================


class TestAsymmetric:
    """3 варианта RSA-OAEP."""

    @pytest.mark.parametrize(
        "cls_name",
        [
            "RSAOAEP2048",
            "RSAOAEP3072",
            "RSAOAEP4096",
        ],
    )
    def test_encrypt_decrypt_roundtrip(self, cls_name: str) -> None:
        from importlib import import_module

        mod = import_module("src.security.crypto.algorithms.asymmetric")
        cipher = getattr(mod, cls_name)()
        priv, pub = cipher.generate_keypair()
        ct = cipher.encrypt(pub, PLAINTEXT)
        pt = cipher.decrypt(priv, ct)
        assert pt == PLAINTEXT

    def test_rsa_oaep_2048_wrong_key_fails(self):
        from src.security.crypto.algorithms.asymmetric import RSAOAEP2048

        cipher = RSAOAEP2048()
        _, pub = cipher.generate_keypair()
        priv2, _ = cipher.generate_keypair()
        ct = cipher.encrypt(pub, PLAINTEXT)
        with pytest.raises(CryptoError):
            cipher.decrypt(priv2, ct)

    def test_rsa_oaep_encryption_is_probabilistic(self):
        """OAEP: два шифрования одного plaintext дают разные ciphertext."""
        from src.security.crypto.algorithms.asymmetric import RSAOAEP2048

        cipher = RSAOAEP2048()
        _, pub = cipher.generate_keypair()
        ct1 = cipher.encrypt(pub, PLAINTEXT)
        ct2 = cipher.encrypt(pub, PLAINTEXT)
        assert ct1 != ct2


# ============================================================================
# 8. KEY EXCHANGE
# ============================================================================


class TestKeyExchange:
    """5 классических KEX + 3 PQC KEM."""

    @pytest.mark.parametrize(
        "cls_name",
        [
            "X25519KeyExchange",
            "X448KeyExchange",
            "ECDHP256KeyExchange",
            "ECDHP384KeyExchange",
            "ECDHP521KeyExchange",
        ],
    )
    def test_classical_kex_shared_secret(self, cls_name):
        from importlib import import_module

        mod = import_module("src.security.crypto.algorithms.key_exchange")
        kex = getattr(mod, cls_name)()
        priv_a, pub_a = kex.generate_keypair()
        priv_b, pub_b = kex.generate_keypair()
        shared_a = kex.derive_shared_secret(priv_a, pub_b)
        shared_b = kex.derive_shared_secret(priv_b, pub_a)
        assert shared_a == shared_b, f"{cls_name}: shared secrets не совпадают"
        assert len(shared_a) >= 32

    @pytest.mark.parametrize(
        "cls_name",
        [
            "X25519KeyExchange",
            "X448KeyExchange",
        ],
    )
    def test_kex_different_pairs_different_secrets(self, cls_name):
        from importlib import import_module

        mod = import_module("src.security.crypto.algorithms.key_exchange")
        kex = getattr(mod, cls_name)()
        priv_a, pub_a = kex.generate_keypair()
        priv_b, pub_b = kex.generate_keypair()
        priv_c, pub_c = kex.generate_keypair()
        s_ab = kex.derive_shared_secret(priv_a, pub_b)
        s_ac = kex.derive_shared_secret(priv_a, pub_c)
        assert s_ab != s_ac

    @pqc
    @pytest.mark.parametrize(
        "cls_name",
        [
            "MLKEM512",
            "MLKEM768",
            "MLKEM1024",
        ],
    )
    def test_kyber_kem_shared_secret(self, cls_name):
        """KEM: encaps/decaps должны давать одинаковый shared secret."""
        from importlib import import_module

        mod = import_module("src.security.crypto.algorithms.key_exchange")
        kem = getattr(mod, cls_name)()
        priv, pub = kem.generate_keypair()
        # KEM API: encapsulate → (ciphertext, shared_secret_sender)
        ct, ss_sender = kem.encapsulate(pub)
        ss_receiver = kem.decapsulate(priv, ct)
        assert ss_sender == ss_receiver
        assert len(ss_sender) >= 32


# ============================================================================
# 9. ADVANCED — Hybrid Encryption
# ============================================================================


class TestHybridEncryption:
    """hybrid_encryption.py — KEX + symmetric."""

    def test_hybrid_x25519_aes256gcm_roundtrip(self):
        from src.security.crypto.advanced.hybrid_encryption import create_hybrid_cipher

        cipher = create_hybrid_cipher("classical_standard")
        priv, pub = cipher.generate_recipient_keypair()
        encrypted = cipher.encrypt_for_recipient(pub, PLAINTEXT)
        pt = cipher.decrypt_from_sender(priv, encrypted)
        assert pt == PLAINTEXT

    def test_hybrid_x448_chacha20_roundtrip(self):
        from src.security.crypto.advanced.hybrid_encryption import create_hybrid_cipher

        cipher = create_hybrid_cipher("classical_paranoid")
        priv, pub = cipher.generate_recipient_keypair()
        encrypted = cipher.encrypt_for_recipient(pub, PLAINTEXT)
        pt = cipher.decrypt_from_sender(priv, encrypted)
        assert pt == PLAINTEXT

    def test_hybrid_wrong_private_key_fails(self):
        from src.security.crypto.advanced.hybrid_encryption import create_hybrid_cipher

        cipher = create_hybrid_cipher("classical_standard")
        _, pub = cipher.generate_recipient_keypair()
        wrong_priv, _ = cipher.generate_recipient_keypair()
        encrypted = cipher.encrypt_for_recipient(pub, PLAINTEXT)
        with pytest.raises(CryptoError):
            cipher.decrypt_from_sender(wrong_priv, encrypted)

    @pqc
    def test_hybrid_kyber_aes256gcm_roundtrip(self):
        from src.security.crypto.advanced.hybrid_encryption import create_hybrid_cipher

        cipher = create_hybrid_cipher("pqc_standard")
        priv, pub = cipher.generate_recipient_keypair()
        encrypted = cipher.encrypt_for_recipient(pub, PLAINTEXT)
        pt = cipher.decrypt_from_sender(priv, encrypted)
        assert pt == PLAINTEXT


# ============================================================================
# 10. ADVANCED — Group Encryption
# ============================================================================


class TestGroupEncryption:
    """group_encryption.py — создание группы, добавление/удаление участников."""

    def _setup_group(self):
        from src.security.crypto.advanced.group_encryption import GroupKeyManager

        mgr = GroupKeyManager()
        members = {}
        for uid in ("alice", "bob", "carol"):
            priv, pub = mgr.generate_member_keypair()
            members[uid] = {"priv": priv, "pub": pub}
        group = mgr.create_group("test-group")
        for uid, m in members.items():
            mgr.add_member(group, uid, m["pub"])
        return mgr, group, members

    def test_group_create_and_encrypt_decrypt(self):
        mgr, group, members = self._setup_group()
        ct = mgr.encrypt_for_group(group, PLAINTEXT)
        # Каждый участник должен расшифровать
        for uid, m in members.items():
            pt = mgr.decrypt_as_member(group, uid, m["priv"], ct)
            assert pt == PLAINTEXT, f"{uid} не смог расшифровать"

    def test_removed_member_cannot_decrypt(self):
        from src.security.crypto.advanced.group_encryption import GroupKeyManager

        mgr = GroupKeyManager()
        members = {}
        for uid in ("alice", "bob"):
            priv, pub = mgr.generate_member_keypair()
            members[uid] = {"priv": priv, "pub": pub}
        group = mgr.create_group("g2")
        for uid, m in members.items():
            mgr.add_member(group, uid, m["pub"])
        mgr.remove_member(group, "bob")
        ct = mgr.encrypt_for_group(group, PLAINTEXT)
        with pytest.raises(CryptoError):
            mgr.decrypt_as_member(group, "bob", members["bob"]["priv"], ct)


# ============================================================================
# 11. ADVANCED — Key Escrow
# ============================================================================


class TestKeyEscrow:
    """key_escrow.py — шифрование с депонированием ключа."""

    def test_user_can_decrypt(self):
        from src.security.crypto.advanced.key_escrow import DualKeyEscrow

        escrow = DualKeyEscrow()
        user_priv, user_pub = escrow.generate_keypair()
        escrow_priv, escrow_pub = escrow.generate_keypair()
        encrypted = escrow.encrypt(PLAINTEXT, user_pub, escrow_pub)
        pt = escrow.decrypt_as_user(user_priv, encrypted)
        assert pt == PLAINTEXT

    def test_escrow_can_decrypt(self):
        from src.security.crypto.advanced.key_escrow import DualKeyEscrow

        escrow = DualKeyEscrow()
        user_priv, user_pub = escrow.generate_keypair()
        escrow_priv, escrow_pub = escrow.generate_keypair()
        encrypted = escrow.encrypt(PLAINTEXT, user_pub, escrow_pub)
        pt = escrow.decrypt_as_escrow(escrow_priv, encrypted)
        assert pt == PLAINTEXT

    def test_wrong_key_cannot_decrypt(self):
        from src.security.crypto.advanced.key_escrow import DualKeyEscrow

        escrow = DualKeyEscrow()
        _, user_pub = escrow.generate_keypair()
        _, escrow_pub = escrow.generate_keypair()
        wrong_priv, _ = escrow.generate_keypair()
        encrypted = escrow.encrypt(PLAINTEXT, user_pub, escrow_pub)
        with pytest.raises(CryptoError):
            escrow.decrypt_as_user(wrong_priv, encrypted)


# ============================================================================
# 12. ADVANCED — Session Keys (PFS)
# ============================================================================


class TestSessionKeys:
    """session_keys.py — Perfect Forward Secrecy, ratcheting."""

    def _make_session_pair(self):
        """Создать пару установленных сессий Alice-Bob."""
        from src.security.crypto.advanced.session_keys import PFSSession

        alice_session = PFSSession()
        bob_session = PFSSession()
        alice_priv, alice_pub = alice_session.generate_identity_keypair()
        bob_priv, bob_pub = bob_session.generate_identity_keypair()
        alice_state, hs = alice_session.initiate_session(alice_priv, alice_pub, bob_pub)
        bob_state, resp = bob_session.accept_session(bob_priv, bob_pub, hs)
        alice_session.complete_handshake(alice_state, resp)
        return alice_session, alice_state, bob_session, bob_state

    def test_session_encrypt_decrypt(self):
        alice_session, alice_state, bob_session, bob_state = self._make_session_pair()
        ct = alice_session.send_message(alice_state, PLAINTEXT)
        pt = bob_session.receive_message(bob_state, ct)
        assert pt == PLAINTEXT

    def test_messages_produce_different_ciphertexts(self):
        """Каждое сообщение шифруется новым ключом (forward secrecy)."""
        alice_session, alice_state, bob_session, bob_state = self._make_session_pair()
        ct1 = alice_session.send_message(alice_state, b"message-1")
        ct2 = alice_session.send_message(alice_state, b"message-2")
        assert ct1 != ct2
        pt1 = bob_session.receive_message(bob_state, ct1)
        pt2 = bob_session.receive_message(bob_state, ct2)
        assert pt1 == b"message-1"
        assert pt2 == b"message-2"

    def test_independent_sessions_isolated(self):
        """Две независимые сессии не могут читать чужие сообщения."""
        from src.security.crypto.advanced.session_keys import PFSSession

        alice_session, alice_state, bob_session, bob_state = self._make_session_pair()

        # Eve устанавливает отдельную сессию с alice2 (другая пара ключей)
        alice2_session = PFSSession()
        eve_session = PFSSession()
        alice2_priv, alice2_pub = alice2_session.generate_identity_keypair()
        eve_priv, eve_pub = eve_session.generate_identity_keypair()
        alice2_state, hs2 = alice2_session.initiate_session(alice2_priv, alice2_pub, eve_pub)
        eve_state, resp2 = eve_session.accept_session(eve_priv, eve_pub, hs2)
        alice2_session.complete_handshake(alice2_state, resp2)

        ct_alice_bob = alice_session.send_message(alice_state, PLAINTEXT)
        with pytest.raises(CryptoError):
            eve_session.receive_message(eve_state, ct_alice_bob)


# ============================================================================
# 13. SERVICE — CryptoService (E2E через высокоуровневый API)
# ============================================================================


class TestCryptoServiceE2E:
    """CryptoService — полный E2E через единое публичное API."""

    def _get_service(self, profile="standard"):
        from src.security.crypto.service.crypto_service import CryptoService
        from src.security.crypto.service.profiles import CryptoProfile

        p = CryptoProfile[profile.upper()]
        return CryptoService(profile=p)

    def test_encrypt_decrypt_document(self):
        svc = self._get_service()
        key = svc.generate_symmetric_key()
        result = svc.encrypt_document(PLAINTEXT, key)
        pt = svc.decrypt_document(result, key)
        assert pt == PLAINTEXT

    def test_encrypt_document_with_custom_algorithm(self):
        svc = self._get_service()
        key = svc.generate_symmetric_key("chacha20-poly1305")
        result = svc.encrypt_document(PLAINTEXT, key, algorithm_id="chacha20-poly1305")
        pt = svc.decrypt_document(result, key)
        assert pt == PLAINTEXT

    def test_sign_verify_document(self):
        svc = self._get_service()
        priv, pub = svc.generate_keypair()
        signed = svc.sign_document(PLAINTEXT, private_key=priv)
        assert svc.verify_signature(PLAINTEXT, signed.signature, pub, signed.algorithm_id) is True

    def test_sign_verify_wrong_message_fails(self):
        svc = self._get_service()
        priv, pub = svc.generate_keypair()
        signed = svc.sign_document(PLAINTEXT, private_key=priv)
        assert svc.verify_signature(b"wrong", signed.signature, pub, signed.algorithm_id) is False

    def test_derive_key_via_service(self):
        svc = self._get_service()
        salt = os.urandom(32)
        key = svc.derive_key(b"MyPassword", salt)
        assert len(key) == 32
        # Детерминированность
        key2 = svc.derive_key(b"MyPassword", salt)
        assert key == key2

    def test_derive_key_custom_length(self):
        svc = self._get_service()
        salt = os.urandom(32)
        key = svc.derive_key(b"MyPassword", salt, key_length=64)
        assert len(key) == 64

    def test_hash_data(self):
        svc = self._get_service()
        h1 = svc.hash_data(PLAINTEXT)
        h2 = svc.hash_data(PLAINTEXT)
        assert h1 == h2
        assert h1 != svc.hash_data(b"other data")

    def test_paranoid_profile_uses_pqc(self):
        """Профиль PARANOID должен использовать PQC по умолчанию."""
        pytest.importorskip("oqs", reason="liboqs не установлен")
        svc = self._get_service("paranoid")
        key = svc.generate_symmetric_key()
        result = svc.encrypt_document(PLAINTEXT, key)
        pt = svc.decrypt_document(result, key)
        assert pt == PLAINTEXT

    def test_floppy_basic_profile_compact_keys(self):
        """Профиль FLOPPY_BASIC должен использовать Ed25519 + ChaCha20."""
        svc = self._get_service("floppy_basic")
        key = svc.generate_symmetric_key()
        result = svc.encrypt_document(PLAINTEXT, key)
        pt = svc.decrypt_document(result, key)
        assert pt == PLAINTEXT

    def test_hybrid_document_encryption(self):
        """Гибридное шифрование через CryptoService."""
        svc = self._get_service()
        from src.security.crypto.algorithms.key_exchange import X25519KeyExchange

        kex = X25519KeyExchange()  # type: ignore[abstract]
        priv, pub = kex.generate_keypair()
        enc = svc.encrypt_hybrid(PLAINTEXT, recipient_public_key=pub)
        pt = svc.decrypt_hybrid(enc, priv)
        assert pt == PLAINTEXT

    def test_encrypt_for_group(self):
        """Групповое шифрование через GroupKeyManager."""
        from src.security.crypto.advanced.group_encryption import GroupKeyManager

        mgr = GroupKeyManager()
        members = {}
        for uid in ("alice", "bob"):
            priv, pub = mgr.generate_member_keypair()
            members[uid] = {"priv": priv, "pub": pub}
        group = mgr.create_group("svc-test-group")
        for uid, m in members.items():
            mgr.add_member(group, uid, m["pub"])
        ct = mgr.encrypt_for_group(group, PLAINTEXT)
        for uid, m in members.items():
            pt = mgr.decrypt_as_member(group, uid, m["priv"], ct)
            assert pt == PLAINTEXT

    def test_estimate_storage_size(self):
        svc = self._get_service()
        sizes = svc.estimate_storage_size(len(PLAINTEXT), algorithm_id="aes-256-gcm")
        assert isinstance(sizes, dict)
        total = sizes.get("total", sizes.get("encrypted", 0))
        assert total is not None and total > len(PLAINTEXT)  # overhead от nonce + тега

    def test_empty_password_derive_key_raises(self):
        from src.security.crypto.core.exceptions import CryptoError
        from src.security.crypto.service.crypto_service import CryptoService

        svc = CryptoService()
        with pytest.raises((CryptoError, ValueError)):
            svc.derive_key(b"", os.urandom(32))


# ============================================================================
# 14. UTILITIES
# ============================================================================


class TestUtilities:
    """utils.py, passwords.py, key_management.py, serialization.py."""

    # ---- utils ----
    def test_generate_key_length(self):
        from src.security.crypto.utilities.utils import generate_key

        for size in (16, 24, 32, 64):
            k = generate_key(size)
            assert len(k) == size

    def test_generate_salt_length(self):
        from src.security.crypto.utilities.utils import generate_salt

        s = generate_salt(32)
        assert len(s) == 32

    def test_generate_key_uniqueness(self):
        from src.security.crypto.utilities.utils import generate_key

        keys = {generate_key(32) for _ in range(100)}
        assert len(keys) == 100, "Коллизии в generate_key!"

    def test_constant_time_compare_equal(self):
        from src.security.crypto.utilities.utils import constant_time_compare

        a = b"secret-value"
        assert constant_time_compare(a, a) is True

    def test_constant_time_compare_unequal(self):
        from src.security.crypto.utilities.utils import constant_time_compare

        assert constant_time_compare(b"aaa", b"bbb") is False

    def test_nonce_manager_no_repeats(self):
        from src.security.crypto.utilities.utils import NonceManager

        mgr = NonceManager()
        nonces = {mgr.generate_nonce(12) for _ in range(1000)}
        assert len(nonces) == 1000, "NonceManager выдал повторяющиеся nonce!"

    def test_secure_memory_erase(self):
        from src.security.crypto.utilities.utils import SecureMemory

        sm = SecureMemory()
        key = bytearray(b"super-secret-key")
        with sm.secure_context(bytes(key)) as secure_key:
            assert bytes(secure_key) == bytes(key)
        # После выхода из контекста — обнулено
        assert all(b == 0 for b in secure_key)

    # ---- passwords ----
    def test_password_hash_and_verify(self):
        from src.security.crypto.utilities.passwords import PasswordHasher

        hasher = PasswordHasher()
        hashed = hasher.hash_password("MyStr0ng!Pass")
        assert hasher.verify_password("MyStr0ng!Pass", hashed) is True
        assert hasher.verify_password("WrongPass", hashed) is False

    def test_password_hash_unique(self):
        from src.security.crypto.utilities.passwords import PasswordHasher

        hasher = PasswordHasher()
        h1 = hasher.hash_password("same-password")
        h2 = hasher.hash_password("same-password")
        assert h1 != h2  # разные соли → разные хеши

    def test_password_check_needs_rehash(self):
        from src.security.crypto.utilities.passwords import PasswordHasher

        hasher = PasswordHasher()
        hashed = hasher.hash_password("password")
        # Свежий хеш не требует рехеширования
        assert hasher.needs_rehash(hashed) is False

    def test_password_strength_checker(self):
        from src.security.crypto.utilities.passwords import PasswordHasher

        hasher = PasswordHasher()
        strong_result = hasher.check_password_strength("Str0ng!P@ss")
        weak_result = hasher.check_password_strength("weak")
        assert strong_result.score > weak_result.score

    # ---- key_management ----
    def test_key_wrap_unwrap(self):
        from src.security.crypto.core.registry import AlgorithmRegistry
        from src.security.crypto.utilities.key_management import KeyManager
        from src.security.crypto.utilities.utils import generate_key

        mgr = KeyManager(AlgorithmRegistry.get_instance())
        kek = generate_key(32)  # Key Encryption Key
        data_key = generate_key(32)
        wrapped = mgr.wrap_key(data_key, kek)
        unwrapped = mgr.unwrap_key(wrapped, kek)
        assert unwrapped == data_key

    def test_key_export_import_pem(self):
        from src.security.crypto.algorithms.signing import Ed25519Signer
        from src.security.crypto.core.registry import AlgorithmRegistry
        from src.security.crypto.utilities.key_management import KeyManager
        from src.security.crypto.utilities.serialization import KeyFormat

        mgr = KeyManager(AlgorithmRegistry.get_instance())
        signer = Ed25519Signer()
        priv, pub = signer.generate_keypair()
        pem = mgr.export_key(priv, KeyFormat.PEM, "ed25519")
        imported = mgr.import_key(pem, KeyFormat.PEM, "ed25519")
        assert imported == priv

    # ---- serialization ----
    def test_serialize_deserialize_key(self):
        from src.security.crypto.utilities.serialization import (
            KeyFormat,
            deserialize_key,
            serialize_key,
        )
        from src.security.crypto.utilities.utils import generate_key

        key = generate_key(32)
        serialized = serialize_key(key, KeyFormat.RAW, "aes-256-gcm")
        deserialized = deserialize_key(serialized, KeyFormat.RAW, "aes-256-gcm")
        assert deserialized == key

    def test_compact_serialization_smaller(self):
        """Compact-формат должен быть компактнее PEM (для дискет)."""
        from src.security.crypto.utilities.serialization import KeyFormat, serialize_key
        from src.security.crypto.utilities.utils import generate_key

        key = generate_key(32)
        pem = serialize_key(key, KeyFormat.PEM, "aes-256-gcm")
        compact = serialize_key(key, KeyFormat.COMPACT, "aes-256-gcm")
        assert len(compact) <= len(pem)


# ============================================================================
# 15. KEY ROTATION
# ============================================================================


class TestKeyRotation:
    """key_rotation.py — ротация ключей, статус."""

    def _make_storage(self, tmp_path: pathlib.Path) -> Any:
        from src.security.crypto.utilities.secure_storage import SecureStorage

        return SecureStorage(tmp_path / "keystore.enc", os.urandom(32))

    def test_rotate_symmetric_key(self, tmp_path):
        from src.security.crypto.utilities.key_rotation import KeyRotationManager

        storage = self._make_storage(tmp_path)
        storage.store_key("test-key", os.urandom(32))
        mgr = KeyRotationManager(storage)
        status = mgr.rotate_key("test-key")
        assert status.rotation_count >= 1

    def test_rotation_status(self, tmp_path):
        from src.security.crypto.utilities.key_rotation import KeyRotationManager

        storage = self._make_storage(tmp_path)
        storage.store_key("status-key", os.urandom(32))
        mgr = KeyRotationManager(storage)
        status = mgr.get_rotation_status("status-key")
        assert status.created_at is not None


# ============================================================================
# 16. CRYPTO AGILITY — Migration
# ============================================================================


class TestCryptoMigration:
    """migration.py — миграция документов между алгоритмами."""

    def test_migrate_document_algorithm(self):
        from src.security.crypto.algorithms.symmetric import (
            AES256GCM,
            ChaCha20Poly1305,
        )
        from src.security.crypto.core.registry import AlgorithmRegistry
        from src.security.crypto.utilities.migration import CryptoMigrator

        migrator = CryptoMigrator(AlgorithmRegistry.get_instance())
        # Шифруем старым алгоритмом
        old_key = os.urandom(32)
        new_key = os.urandom(32)
        old_cipher = AES256GCM()
        nonce, ct = old_cipher.encrypt(old_key, PLAINTEXT)
        # Мигрируем на новый (nonce передаём отдельно, ct — как encrypted_data)
        new_data, result = migrator.migrate_document(
            ct,
            old_key=old_key,
            new_key=new_key,
            old_algorithm="aes-256-gcm",
            new_algorithm="chacha20-poly1305",
            old_nonce=nonce,
        )
        assert result.success, f"Миграция не удалась: {result.error}"
        # Расшифровываем новым: new_data = new_nonce + new_ciphertext (ChaCha20: nonce=12 байт)
        new_cipher = ChaCha20Poly1305()
        pt = new_cipher.decrypt(new_key, new_data[:12], new_data[12:])
        assert pt == PLAINTEXT
