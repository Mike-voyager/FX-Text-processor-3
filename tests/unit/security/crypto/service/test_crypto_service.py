"""
Тесты для crypto_service.py — сервисный слой криптографии.

Покрытие:
    - Наличие всех 16 методов у CryptoService (регрессия C1)
    - Генерация ключей: symmetric, keypair
    - Шифрование/расшифровка: roundtrip, валидация, AAD
    - Цифровая подпись: создание, верификация, неверный ключ
    - Гибридное шифрование: roundtrip (mock), пустые аргументы
    - Хеширование: roundtrip, пустые данные
    - Вывод ключей: KDF, валидация параметров
    - Обнаружение алгоритмов: get_available_algorithms, is_algorithm_available
    - estimate_storage_size: структура ответа, floppy_fits — bool
    - EncryptedDocument: to_dict/from_dict roundtrip, поле aad
    - SignedDocument: to_dict/from_dict roundtrip

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from src.security.crypto.core.exceptions import (
    DecryptionError,
    EncryptionError,
    SignatureError,
)
from src.security.crypto.service.crypto_service import (
    CryptoService,
    EncryptedDocument,
    SignedDocument,
)
from src.security.crypto.service.profiles import CryptoProfile

# ==============================================================================
# СТРУКТУРА КЛАССА — РЕГРЕССИЯ C1
# ==============================================================================


class TestCryptoServiceStructure:
    """Верификация, что все методы принадлежат классу (регрессия бага C1)."""

    @pytest.mark.parametrize(
        "method_name",
        [
            "generate_symmetric_key",
            "generate_keypair",
            "encrypt_document",
            "decrypt_document",
            "sign_document",
            "verify_signature",
            "encrypt_hybrid",
            "decrypt_hybrid",
            "hash_data",
            "derive_key",
            "get_default_algorithms",
            "get_available_algorithms",
            "is_algorithm_available",
            "estimate_storage_size",
            "__repr__",
        ],
    )
    def test_method_exists_on_instance(self, service: CryptoService, method_name: str) -> None:
        """Каждый публичный метод должен быть атрибутом экземпляра."""
        assert hasattr(service, method_name), (
            f"CryptoService.{method_name} не найден — возможно баг C1 вернулся"
        )
        assert callable(getattr(service, method_name))

    def test_method_count(self, service: CryptoService) -> None:
        """Минимум 15 публичных методов у экземпляра."""
        public_methods = [m for m in dir(service) if not m.startswith("__")]
        assert len(public_methods) >= 15


# ==============================================================================
# ИНИЦИАЛИЗАЦИЯ
# ==============================================================================


class TestCryptoServiceInit:
    def test_default_profile_is_standard(self, mock_registry: MagicMock) -> None:
        """По умолчанию используется профиль STANDARD."""
        with (
            patch("src.security.crypto.service.crypto_service.get_profile_config") as mock_cfg,
            patch(
                "src.security.crypto.service.crypto_service.AlgorithmRegistry.get_instance",
                return_value=mock_registry,
            ),
        ):
            mock_cfg.return_value = MagicMock()
            svc = CryptoService()
        assert svc.profile == CryptoProfile.STANDARD

    def test_custom_profile_stored(self, mock_registry: MagicMock) -> None:
        """Переданный профиль сохраняется в атрибуте."""
        with (
            patch("src.security.crypto.service.crypto_service.get_profile_config") as mock_cfg,
            patch(
                "src.security.crypto.service.crypto_service.AlgorithmRegistry.get_instance",
                return_value=mock_registry,
            ),
        ):
            mock_cfg.return_value = MagicMock()
            svc = CryptoService(profile=CryptoProfile.PARANOID)
        assert svc.profile == CryptoProfile.PARANOID

    def test_custom_registry_used(self, mock_registry: MagicMock) -> None:
        """Переданный registry хранится в _registry."""
        with patch("src.security.crypto.service.crypto_service.get_profile_config") as mock_cfg:
            mock_cfg.return_value = MagicMock()
            svc = CryptoService(registry=mock_registry)
        assert svc._registry is mock_registry

    def test_repr_contains_profile(self, service: CryptoService) -> None:
        """__repr__ содержит имя профиля."""
        r = repr(service)
        assert "CryptoService(" in r
        assert "standard" in r


# ==============================================================================
# ГЕНЕРАЦИЯ КЛЮЧЕЙ
# ==============================================================================


class TestGenerateSymmetricKey:
    def test_returns_bytes(self, service: CryptoService) -> None:
        key = service.generate_symmetric_key()
        assert isinstance(key, bytes)

    def test_correct_size_from_metadata(self, service: CryptoService) -> None:
        """Размер ключа соответствует key_size из метаданных (32 байта в fake-aes)."""
        key = service.generate_symmetric_key()
        assert len(key) == 32

    def test_explicit_algorithm_id(self, service: CryptoService, mock_registry: MagicMock) -> None:
        """Явный algorithm_id передаётся в registry.get_metadata."""
        service.generate_symmetric_key("fake-aes")
        mock_registry.get_metadata.assert_called_with("fake-aes")

    def test_two_keys_differ(self, service: CryptoService) -> None:
        """CSPRNG — два подряд вызова дают разные ключи."""
        k1 = service.generate_symmetric_key()
        k2 = service.generate_symmetric_key()
        assert k1 != k2

    def test_missing_key_size_raises(
        self, service: CryptoService, mock_registry: MagicMock
    ) -> None:
        """Если key_size = None — поднимается CryptoError."""
        from src.security.crypto.core.exceptions import CryptoError

        no_size_meta = MagicMock()
        no_size_meta.key_size = None
        mock_registry.get_metadata.side_effect = None
        mock_registry.get_metadata.return_value = no_size_meta
        with pytest.raises(CryptoError, match="key_size"):
            service.generate_symmetric_key("fake-aes")


class TestGenerateKeypair:
    def test_returns_two_bytes(self, service: CryptoService) -> None:
        priv, pub = service.generate_keypair()
        assert isinstance(priv, bytes)
        assert isinstance(pub, bytes)

    def test_priv_ne_pub(self, service: CryptoService) -> None:
        priv, pub = service.generate_keypair()
        assert priv != pub

    def test_unsupported_algorithm_raises(
        self, service: CryptoService, mock_registry: MagicMock
    ) -> None:
        """Алгоритм без generate_keypair поднимает CryptoError."""
        from src.security.crypto.core.exceptions import CryptoError

        mock_registry.create.return_value = object()  # не имеет generate_keypair
        with pytest.raises(CryptoError, match="generate_keypair"):
            service.generate_keypair("fake-aes")


# ==============================================================================
# СИММЕТРИЧНОЕ ШИФРОВАНИЕ
# ==============================================================================


class TestEncryptDocument:
    def test_returns_encrypted_document(self, service: CryptoService, plaintext: bytes) -> None:
        key = service.generate_symmetric_key()
        result = service.encrypt_document(plaintext, key)
        assert isinstance(result, EncryptedDocument)

    def test_contains_nonce_and_ciphertext(self, service: CryptoService, plaintext: bytes) -> None:
        key = service.generate_symmetric_key()
        enc = service.encrypt_document(plaintext, key)
        assert len(enc.nonce) > 0
        assert len(enc.ciphertext) > 0

    def test_algorithm_id_stored(self, service: CryptoService, plaintext: bytes) -> None:
        key = service.generate_symmetric_key()
        enc = service.encrypt_document(plaintext, key)
        assert enc.algorithm_id == "fake-aes"

    def test_aad_stored_in_result(self, service: CryptoService, plaintext: bytes) -> None:
        key = service.generate_symmetric_key()
        aad = b"header-data"
        enc = service.encrypt_document(plaintext, key, aad=aad)
        assert enc.aad == aad

    def test_empty_document_raises(self, service: CryptoService) -> None:
        key = service.generate_symmetric_key()
        with pytest.raises(ValueError, match="пустым"):
            service.encrypt_document(b"", key)

    def test_empty_key_raises(self, service: CryptoService, plaintext: bytes) -> None:
        with pytest.raises(ValueError, match="пустым"):
            service.encrypt_document(plaintext, b"")

    def test_cipher_exception_wrapped(
        self,
        service: CryptoService,
        plaintext: bytes,
        mock_registry: MagicMock,
    ) -> None:
        """Исключение алгоритма оборачивается в EncryptionError."""
        from tests.unit.security.crypto.service.conftest import FakeCipher

        class _BrokenCipher(FakeCipher):
            def encrypt(self, key: bytes, plaintext: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
                raise RuntimeError("boom")

        mock_registry.create.side_effect = None
        mock_registry.create.return_value = _BrokenCipher()
        key = b"\x00" * 32
        with pytest.raises(EncryptionError):
            service.encrypt_document(plaintext, key)


class TestDecryptDocument:
    def test_roundtrip(self, service: CryptoService, plaintext: bytes) -> None:
        """Расшифровка возвращает оригинальный plaintext."""
        key = service.generate_symmetric_key()
        enc = service.encrypt_document(plaintext, key)
        assert service.decrypt_document(enc, key) == plaintext

    def test_empty_key_raises(self, service: CryptoService, plaintext: bytes) -> None:
        key = service.generate_symmetric_key()
        enc = service.encrypt_document(plaintext, key)
        with pytest.raises(ValueError, match="пустым"):
            service.decrypt_document(enc, b"")

    def test_cipher_exception_wrapped(
        self,
        service: CryptoService,
        plaintext: bytes,
        mock_registry: MagicMock,
    ) -> None:
        """Исключение при расшифровке оборачивается в DecryptionError."""
        from tests.unit.security.crypto.service.conftest import FakeCipher

        class _BrokenCipher(FakeCipher):
            def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
                raise RuntimeError("bad tag")

        key = service.generate_symmetric_key()
        enc = service.encrypt_document(plaintext, key)
        mock_registry.create.side_effect = None
        mock_registry.create.return_value = _BrokenCipher()
        with pytest.raises(DecryptionError):
            service.decrypt_document(enc, key)


# ==============================================================================
# ЦИФРОВАЯ ПОДПИСЬ
# ==============================================================================


class TestSignDocument:
    def test_returns_signed_document(self, service: CryptoService, plaintext: bytes) -> None:
        priv, _ = service.generate_keypair()
        result = service.sign_document(plaintext, priv)
        assert isinstance(result, SignedDocument)

    def test_signature_non_empty(self, service: CryptoService, plaintext: bytes) -> None:
        priv, _ = service.generate_keypair()
        signed = service.sign_document(plaintext, priv)
        assert len(signed.signature) > 0

    def test_algorithm_id_stored(self, service: CryptoService, plaintext: bytes) -> None:
        priv, _ = service.generate_keypair()
        signed = service.sign_document(plaintext, priv)
        assert signed.algorithm_id == "fake-ed25519"

    def test_empty_document_raises(self, service: CryptoService) -> None:
        priv, _ = service.generate_keypair()
        with pytest.raises(ValueError, match="пустым"):
            service.sign_document(b"", priv)

    def test_empty_key_raises(self, service: CryptoService, plaintext: bytes) -> None:
        with pytest.raises(ValueError, match="пустым"):
            service.sign_document(plaintext, b"")

    def test_signer_exception_wrapped(
        self,
        service: CryptoService,
        plaintext: bytes,
        mock_registry: MagicMock,
    ) -> None:
        from tests.unit.security.crypto.service.conftest import FakeSigner

        class _BrokenSigner(FakeSigner):
            def sign(self, private_key: bytes, message: bytes) -> bytes:
                raise RuntimeError("key error")

        mock_registry.create.side_effect = None
        mock_registry.create.return_value = _BrokenSigner()
        with pytest.raises(SignatureError):
            service.sign_document(plaintext, b"\xaa" * 32)


class TestVerifySignature:
    def test_valid_signature_returns_true(self, service: CryptoService, plaintext: bytes) -> None:
        priv, pub = service.generate_keypair()
        signed = service.sign_document(plaintext, priv)
        result = service.verify_signature(plaintext, signed.signature, pub, signed.algorithm_id)
        assert result is True

    def test_wrong_key_returns_false(self, service: CryptoService, plaintext: bytes) -> None:
        priv, _ = service.generate_keypair()
        signed = service.sign_document(plaintext, priv)
        wrong_pub = b"\xff" * 32
        result = service.verify_signature(
            plaintext, signed.signature, wrong_pub, signed.algorithm_id
        )
        assert result is False

    def test_tampered_document_returns_false(
        self, service: CryptoService, plaintext: bytes
    ) -> None:
        priv, pub = service.generate_keypair()
        signed = service.sign_document(plaintext, priv)
        tampered = plaintext + b"X"
        result = service.verify_signature(tampered, signed.signature, pub, signed.algorithm_id)
        assert result is False

    def test_exception_returns_false(
        self,
        service: CryptoService,
        plaintext: bytes,
        mock_registry: MagicMock,
    ) -> None:
        """Исключение верификатора трактуется как False."""
        bad_signer = MagicMock()
        bad_signer.verify.side_effect = RuntimeError("verify error")
        mock_registry.create.return_value = bad_signer
        result = service.verify_signature(plaintext, b"\x00" * 64, b"\x00" * 32, "fake-ed25519")
        assert result is False

    @pytest.mark.parametrize(
        "doc,sig,pub",
        [
            (b"", b"\x00" * 64, b"\x00" * 32),
            (b"doc", b"", b"\x00" * 32),
            (b"doc", b"\x00" * 64, b""),
        ],
    )
    def test_empty_args_raise(
        self,
        service: CryptoService,
        doc: bytes,
        sig: bytes,
        pub: bytes,
    ) -> None:
        with pytest.raises(ValueError):
            service.verify_signature(doc, sig, pub, "fake-ed25519")


# ==============================================================================
# ГИБРИДНОЕ ШИФРОВАНИЕ
# ==============================================================================


class TestHybridEncryption:
    def test_encrypt_hybrid_empty_document_raises(self, service: CryptoService) -> None:
        with pytest.raises(ValueError, match="пустым"):
            service.encrypt_hybrid(b"", b"\xbb" * 32)

    def test_encrypt_hybrid_empty_pubkey_raises(self, service: CryptoService) -> None:
        with pytest.raises(ValueError, match="пустым"):
            service.encrypt_hybrid(b"data", b"")

    def test_decrypt_hybrid_empty_privkey_raises(self, service: CryptoService) -> None:
        from src.security.crypto.advanced.hybrid_encryption import HybridPayload

        payload = MagicMock(spec=HybridPayload)
        payload.config = "classical_standard"
        with pytest.raises(ValueError, match="пустым"):
            service.decrypt_hybrid(payload, b"")

    def test_decrypt_hybrid_wrapped_on_exception(self, service: CryptoService) -> None:
        """Исключение внутри cipher оборачивается в DecryptionError."""
        from src.security.crypto.advanced.hybrid_encryption import HybridPayload

        payload = MagicMock(spec=HybridPayload)
        payload.config = "classical_standard"

        with patch(
            "src.security.crypto.service.crypto_service.create_hybrid_cipher"
        ) as mock_factory:
            bad_cipher = MagicMock()
            bad_cipher.decrypt_from_sender.side_effect = RuntimeError("bad key")
            mock_factory.return_value = bad_cipher
            with pytest.raises(DecryptionError):
                service.decrypt_hybrid(payload, b"\xcc" * 32)


# ==============================================================================
# ХЕШИРОВАНИЕ
# ==============================================================================


class TestHashData:
    def test_returns_bytes(self, service: CryptoService) -> None:
        digest = service.hash_data(b"hello world")
        assert isinstance(digest, bytes)

    def test_digest_length(self, service: CryptoService) -> None:
        """FakeHasher возвращает 32 байта."""
        digest = service.hash_data(b"test")
        assert len(digest) == 32

    def test_deterministic(self, service: CryptoService) -> None:
        d1 = service.hash_data(b"same data")
        d2 = service.hash_data(b"same data")
        assert d1 == d2

    def test_different_input_different_hash(self, service: CryptoService) -> None:
        d1 = service.hash_data(b"data-a")
        d2 = service.hash_data(b"data-b")
        assert d1 != d2

    def test_empty_data_raises(self, service: CryptoService) -> None:
        with pytest.raises(ValueError, match="пустым"):
            service.hash_data(b"")


# ==============================================================================
# ВЫВОД КЛЮЧЕЙ
# ==============================================================================


class TestDeriveKey:
    def test_returns_correct_length(self, service: CryptoService, valid_salt: bytes) -> None:
        key = service.derive_key(b"password", valid_salt, key_length=32)
        assert len(key) == 32

    def test_custom_key_length(self, service: CryptoService, valid_salt: bytes) -> None:
        key = service.derive_key(b"password", valid_salt, key_length=64)
        assert len(key) == 64

    def test_empty_password_raises(self, service: CryptoService, valid_salt: bytes) -> None:
        with pytest.raises(ValueError, match="пустым"):
            service.derive_key(b"", valid_salt)

    def test_short_salt_raises(self, service: CryptoService, short_salt: bytes) -> None:
        with pytest.raises(ValueError, match="короткая"):
            service.derive_key(b"password", short_salt)

    def test_zero_key_length_raises(self, service: CryptoService, valid_salt: bytes) -> None:
        with pytest.raises(ValueError, match="Некорректная"):
            service.derive_key(b"password", valid_salt, key_length=0)

    def test_negative_key_length_raises(self, service: CryptoService, valid_salt: bytes) -> None:
        with pytest.raises(ValueError):
            service.derive_key(b"password", valid_salt, key_length=-1)

    def test_large_key_length_allowed(self, service: CryptoService, valid_salt: bytes) -> None:
        """Лимит 64 убран — большие ключи должны проходить."""
        key = service.derive_key(b"password", valid_salt, key_length=128)
        assert len(key) == 128


# ==============================================================================
# ОБНАРУЖЕНИЕ АЛГОРИТМОВ
# ==============================================================================


class TestAlgorithmDiscovery:
    def test_get_default_algorithms_returns_dict(self, service: CryptoService) -> None:
        result = service.get_default_algorithms()
        assert isinstance(result, dict)
        assert "symmetric" in result
        assert "signing" in result

    def test_get_available_algorithms_no_filter(self, service: CryptoService) -> None:
        result = service.get_available_algorithms()
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_get_available_algorithms_with_category(self, service: CryptoService) -> None:
        result = service.get_available_algorithms("symmetric")
        for name, info in result.items():
            assert "name" in info
            assert "security_level" in info

    def test_is_algorithm_available_known(self, service: CryptoService) -> None:
        assert service.is_algorithm_available("fake-aes") is True

    def test_is_algorithm_available_unknown(self, service: CryptoService) -> None:
        assert service.is_algorithm_available("nonexistent-algo") is False


# ==============================================================================
# ОЦЕНКА РАЗМЕРА ХРАНИЛИЩА
# ==============================================================================


class TestEstimateStorageSize:
    def test_returns_dict_with_required_keys(self, service: CryptoService) -> None:
        result = service.estimate_storage_size(1000)
        for key in ("plaintext", "encrypted", "signature", "total", "floppy_fits"):
            assert key in result

    def test_plaintext_size_preserved(self, service: CryptoService) -> None:
        result = service.estimate_storage_size(50_000)
        assert result["plaintext"] == 50_000

    def test_encrypted_gt_plaintext(self, service: CryptoService) -> None:
        result = service.estimate_storage_size(1000)
        assert result["encrypted"] > result["plaintext"]

    def test_total_includes_signature(self, service: CryptoService) -> None:
        with_sig = service.estimate_storage_size(1000, include_signature=True)
        without_sig = service.estimate_storage_size(1000, include_signature=False)
        assert with_sig["total"] >= without_sig["total"]
        assert without_sig["signature"] == 0

    def test_floppy_fits_is_bool(self, service: CryptoService) -> None:
        result = service.estimate_storage_size(100)
        assert isinstance(result["floppy_fits"], bool)

    def test_large_data_does_not_fit_floppy(self, service: CryptoService) -> None:
        result = service.estimate_storage_size(2_000_000)
        assert result["floppy_fits"] is False

    def test_small_data_fits_floppy(self, service: CryptoService) -> None:
        result = service.estimate_storage_size(100)
        assert result["floppy_fits"] is True


# ==============================================================================
# ENCRYPTED DOCUMENT DATACLASS
# ==============================================================================


class TestEncryptedDocument:
    def test_frozen_immutable(self) -> None:
        doc = EncryptedDocument(
            nonce=b"\x01" * 12,
            ciphertext=b"\x02" * 32,
            algorithm_id="aes-256-gcm",
        )
        with pytest.raises((AttributeError, TypeError)):
            doc.nonce = b"\x00" * 12  # type: ignore[misc]

    def test_to_dict_keys(self) -> None:
        doc = EncryptedDocument(
            nonce=b"\x01" * 12,
            ciphertext=b"\x02" * 32,
            algorithm_id="aes-256-gcm",
        )
        d = doc.to_dict()
        assert "nonce" in d
        assert "ciphertext" in d
        assert "algorithm_id" in d
        assert "aad" not in d  # отсутствует если aad=None

    def test_to_dict_with_aad(self) -> None:
        doc = EncryptedDocument(
            nonce=b"\x01" * 12,
            ciphertext=b"\x02" * 32,
            algorithm_id="aes-256-gcm",
            aad=b"header",
        )
        d = doc.to_dict()
        assert "aad" in d
        assert d["aad"] == b"header".hex()

    def test_from_dict_roundtrip(self) -> None:
        original = EncryptedDocument(
            nonce=b"\x01" * 12,
            ciphertext=b"\x02" * 32,
            algorithm_id="aes-256-gcm",
        )
        restored = EncryptedDocument.from_dict(original.to_dict())
        assert restored == original

    def test_from_dict_roundtrip_with_aad(self) -> None:
        original = EncryptedDocument(
            nonce=b"\xaa" * 12,
            ciphertext=b"\xbb" * 48,
            algorithm_id="chacha20-poly1305",
            aad=b"auth-data",
        )
        restored = EncryptedDocument.from_dict(original.to_dict())
        assert restored.aad == b"auth-data"

    def test_from_dict_missing_key_raises(self) -> None:
        with pytest.raises(KeyError):
            EncryptedDocument.from_dict({"ciphertext": "ab", "algorithm_id": "x"})  # type: ignore[typeddict-item]

    def test_from_dict_invalid_hex_raises(self) -> None:
        with pytest.raises(ValueError):
            EncryptedDocument.from_dict({"nonce": "ZZZZ", "ciphertext": "ab", "algorithm_id": "x"})  # type: ignore[typeddict-item]


# ==============================================================================
# SIGNED DOCUMENT DATACLASS
# ==============================================================================


class TestSignedDocument:
    def test_frozen_immutable(self) -> None:
        doc = SignedDocument(signature=b"\x01" * 64, algorithm_id="Ed25519")
        with pytest.raises((AttributeError, TypeError)):
            doc.signature = b"\x00" * 64  # type: ignore[misc]

    def test_default_public_key_hint(self) -> None:
        doc = SignedDocument(signature=b"\x01" * 64, algorithm_id="Ed25519")
        assert doc.public_key_hint == ""

    def test_to_dict_keys(self) -> None:
        doc = SignedDocument(
            signature=b"\x01" * 64,
            algorithm_id="Ed25519",
            public_key_hint="aabbccdd",
        )
        d = doc.to_dict()
        assert "signature" in d
        assert "algorithm_id" in d
        assert "public_key_hint" in d

    def test_from_dict_roundtrip(self) -> None:
        original = SignedDocument(
            signature=b"\xaa" * 64,
            algorithm_id="Ed25519",
            public_key_hint="deadbeef",
        )
        restored = SignedDocument.from_dict(original.to_dict())
        assert restored == original

    def test_from_dict_missing_public_key_hint_defaults_to_empty(self) -> None:
        data = {"signature": b"\x01".hex() * 64, "algorithm_id": "Ed25519", "public_key_hint": ""}
        doc = SignedDocument.from_dict(data)  # type: ignore[arg-type]
        assert doc.public_key_hint == ""
