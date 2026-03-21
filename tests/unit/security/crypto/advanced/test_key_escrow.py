"""
Unit тесты для src/security/crypto/advanced/key_escrow.py

Покрывает: инициализацию, generate_keypair, encrypt/decrypt (оба пути),
_wrap_key/_unwrap_key, _derive_key (HKDF + конфигурируемый hash),
_secure_erase, dataclass, константы, регрессии критических багов.

Маркеры:
    pytest.mark.security — все тесты этого файла
    pytest.mark.crypto   — тесты с реальными криптографическими операциями

Coverage target: ≥95% (Security layer requirement)
"""

from __future__ import annotations

import secrets
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import hashes

from src.security.crypto.advanced.key_escrow import (
    DATA_KEY_SIZE,
    HKDF_INFO_ESCROW,
    HKDF_INFO_USER,
    HKDF_SALT_SIZE,
    DualKeyEscrow,
    EscrowEncryptedData,
)
from src.security.crypto.core.exceptions import (
    CryptoError,
    DecryptionError,
    EncryptionError,
    InvalidKeyError,
)


# ==============================================================================
# TEST DATA
# ==============================================================================

FAKE_PRIV_KEY: bytes = secrets.token_bytes(32)
FAKE_PUB_KEY: bytes = secrets.token_bytes(32)
FAKE_ESCROW_PRIV: bytes = secrets.token_bytes(32)
FAKE_ESCROW_PUB: bytes = secrets.token_bytes(32)
FAKE_EPHEMERAL_PRIV: bytes = secrets.token_bytes(32)
FAKE_EPHEMERAL_PUB: bytes = secrets.token_bytes(32)
FAKE_DATA_KEY: bytes = secrets.token_bytes(DATA_KEY_SIZE)
FAKE_CIPHERTEXT: bytes = b"\xde\xad\xbe\xef" * 8
FAKE_NONCE: bytes = b"\xca\xfe\xba\xbe" * 3
FAKE_SHARED_SECRET: bytes = secrets.token_bytes(32)
FAKE_HKDF_SALT: bytes = secrets.token_bytes(HKDF_SALT_SIZE)

SAMPLE_PLAINTEXT: bytes = b"Sensitive document data"


# ==============================================================================
# FIXTURES
# ==============================================================================


def _build_mock_registry(
    kex_side_effect: Any = None,
    cipher_side_effect: Any = None,
) -> tuple[MagicMock, MagicMock, MagicMock]:
    """Создать mock AlgorithmRegistry с настраиваемыми side_effect."""
    registry = MagicMock()
    mock_kex = MagicMock()
    mock_cipher = MagicMock()

    mock_kex.generate_keypair.return_value = (FAKE_EPHEMERAL_PRIV, FAKE_EPHEMERAL_PUB)
    mock_kex.derive_shared_secret.return_value = FAKE_SHARED_SECRET

    mock_cipher.encrypt.return_value = (FAKE_NONCE, FAKE_CIPHERTEXT)
    mock_cipher.decrypt.return_value = SAMPLE_PLAINTEXT

    if kex_side_effect:
        mock_kex.derive_shared_secret.side_effect = kex_side_effect
    if cipher_side_effect:
        mock_cipher.encrypt.side_effect = cipher_side_effect

    registry.create.side_effect = lambda algo: (
        mock_kex if "x25519" in algo.lower() else mock_cipher
    )
    return registry, mock_kex, mock_cipher


@pytest.fixture
def mock_registry_patch() -> Any:
    """Патч AlgorithmRegistry.get_instance — изолирует от реального реестра."""
    registry, mock_kex, mock_cipher = _build_mock_registry()
    with patch("src.security.crypto.advanced.key_escrow.AlgorithmRegistry") as mock_cls:
        mock_cls.get_instance.return_value = registry
        yield mock_cls, mock_kex, mock_cipher


@pytest.fixture
def escrow(mock_registry_patch: Any) -> DualKeyEscrow:
    """DualKeyEscrow с замоканными зависимостями (SHA256 по умолчанию)."""
    return DualKeyEscrow()


@pytest.fixture
def valid_encrypted_data() -> EscrowEncryptedData:
    """Валидный EscrowEncryptedData для тестов расшифровки."""
    wrapped: dict[str, bytes] = {
        "ephemeral_public_key": FAKE_EPHEMERAL_PUB,
        "nonce": FAKE_NONCE,
        "ciphertext": FAKE_CIPHERTEXT,
        "hkdf_salt": FAKE_HKDF_SALT,
    }
    return EscrowEncryptedData(
        ciphertext=FAKE_CIPHERTEXT,
        nonce=FAKE_NONCE,
        user_wrapped_key=dict(wrapped),
        escrow_wrapped_key=dict(wrapped),
    )


# ==============================================================================
# EscrowEncryptedData
# ==============================================================================


@pytest.mark.security
class TestEscrowEncryptedData:
    """Тесты dataclass EscrowEncryptedData."""

    def test_create_with_valid_fields(self) -> None:
        """Создание с валидными данными не вызывает исключений."""
        wrapped: dict[str, bytes] = {"ephemeral_public_key": FAKE_EPHEMERAL_PUB}
        data = EscrowEncryptedData(
            ciphertext=b"ct",
            nonce=b"nn",
            user_wrapped_key=dict(wrapped),
            escrow_wrapped_key=dict(wrapped),
        )
        assert data.ciphertext == b"ct"
        assert data.nonce == b"nn"

    def test_frozen_raises_on_mutation(self) -> None:
        """frozen=True: попытка изменить поле вызывает ошибку."""
        data = EscrowEncryptedData(
            ciphertext=b"ct",
            nonce=b"nn",
            user_wrapped_key={},
            escrow_wrapped_key={},
        )
        with pytest.raises((AttributeError, TypeError)):
            data.ciphertext = b"new"  # type: ignore[misc]

    def test_user_and_escrow_wrapped_keys_are_independent_objects(self) -> None:
        """user_wrapped_key и escrow_wrapped_key — разные объекты."""
        user = {"k": b"user"}
        escrow_w = {"k": b"escrow"}
        data = EscrowEncryptedData(
            ciphertext=b"ct",
            nonce=b"nn",
            user_wrapped_key=user,
            escrow_wrapped_key=escrow_w,
        )
        assert data.user_wrapped_key is not data.escrow_wrapped_key

    def test_field_types_are_bytes_and_dict(self) -> None:
        """Типы полей соответствуют аннотациям."""
        wrapped: dict[str, bytes] = {"ephemeral_public_key": b"key"}
        data = EscrowEncryptedData(
            ciphertext=b"c",
            nonce=b"n",
            user_wrapped_key=wrapped,
            escrow_wrapped_key=dict(wrapped),
        )
        assert isinstance(data.ciphertext, bytes)
        assert isinstance(data.nonce, bytes)
        assert isinstance(data.user_wrapped_key, dict)
        assert isinstance(data.escrow_wrapped_key, dict)


# ==============================================================================
# DualKeyEscrow.__init__
# ==============================================================================


@pytest.mark.security
class TestDualKeyEscrowInit:
    """Тесты инициализации DualKeyEscrow."""

    def test_init_default_algorithms_calls_registry(
        self, mock_registry_patch: Any
    ) -> None:
        """Инициализация с дефолтами вызывает registry.create для x25519 и aes-256-gcm."""
        mock_cls, _, _ = mock_registry_patch
        DualKeyEscrow()
        calls = [
            c.args[0] for c in mock_cls.get_instance.return_value.create.call_args_list
        ]
        assert "x25519" in calls
        assert "aes-256-gcm" in calls

    def test_init_default_hkdf_hash_is_sha256(self, mock_registry_patch: Any) -> None:
        """hkdf_hash по умолчанию — hashes.SHA256."""
        escrow = DualKeyEscrow()
        assert escrow._hkdf_hash is hashes.SHA256

    @pytest.mark.parametrize(
        "hkdf_hash",
        [hashes.SHA256, hashes.SHA384, hashes.SHA512],
        ids=["SHA256", "SHA384", "SHA512"],
    )
    def test_init_accepts_all_supported_hkdf_hashes(
        self, mock_registry_patch: Any, hkdf_hash: type
    ) -> None:
        """Все поддерживаемые hash-алгоритмы принимаются без исключений."""
        escrow = DualKeyEscrow(hkdf_hash=hkdf_hash)
        assert escrow._hkdf_hash is hkdf_hash

    @pytest.mark.parametrize(
        "kex_algo,sym_algo",
        [
            ("x25519", "aes-256-gcm"),
            ("x25519", "chacha20-poly1305"),
        ],
        ids=["aes-gcm", "chacha20"],
    )
    def test_init_custom_algorithm_pair(
        self, mock_registry_patch: Any, kex_algo: str, sym_algo: str
    ) -> None:
        """Кастомные комбинации алгоритмов принимаются без исключений."""
        escrow = DualKeyEscrow(kex_algorithm=kex_algo, symmetric_algorithm=sym_algo)
        assert escrow is not None

    def test_init_registry_keyerror_raises_crypto_error(
        self, mock_registry_patch: Any
    ) -> None:
        """KeyError при create() → CryptoError с сообщением."""
        mock_cls, _, _ = mock_registry_patch
        mock_cls.get_instance.return_value.create.side_effect = KeyError("unknown_algo")
        with pytest.raises(CryptoError, match="Failed to initialize"):
            DualKeyEscrow()

    def test_init_registry_runtime_error_raises_crypto_error(
        self, mock_registry_patch: Any
    ) -> None:
        """RuntimeError при create() → CryptoError."""
        mock_cls, _, _ = mock_registry_patch
        mock_cls.get_instance.return_value.create.side_effect = RuntimeError("broken")
        with pytest.raises(CryptoError):
            DualKeyEscrow()

    def test_init_stores_algorithm_names(self, mock_registry_patch: Any) -> None:
        """Имена алгоритмов сохраняются в атрибутах."""
        escrow = DualKeyEscrow(
            kex_algorithm="x25519", symmetric_algorithm="aes-256-gcm"
        )
        assert escrow._kex_algo == "x25519"
        assert escrow._sym_algo == "aes-256-gcm"


# ==============================================================================
# DualKeyEscrow.generate_keypair
# ==============================================================================


@pytest.mark.security
class TestGenerateKeypair:
    """Тесты generate_keypair()."""

    def test_returns_two_bytes_objects(
        self, escrow: DualKeyEscrow, mock_registry_patch: Any
    ) -> None:
        """generate_keypair() возвращает (private_key, public_key) — оба bytes."""
        _, mock_kex, _ = mock_registry_patch
        mock_kex.generate_keypair.return_value = (FAKE_PRIV_KEY, FAKE_PUB_KEY)
        priv, pub = escrow.generate_keypair()
        assert isinstance(priv, bytes)
        assert isinstance(pub, bytes)

    def test_delegates_to_kex(
        self, escrow: DualKeyEscrow, mock_registry_patch: Any
    ) -> None:
        """generate_keypair() делегирует вызов _kex.generate_keypair()."""
        _, mock_kex, _ = mock_registry_patch
        mock_kex.generate_keypair.return_value = (FAKE_PRIV_KEY, FAKE_PUB_KEY)
        escrow.generate_keypair()
        mock_kex.generate_keypair.assert_called_once()

    def test_kex_exception_raises_crypto_error(
        self, escrow: DualKeyEscrow, mock_registry_patch: Any
    ) -> None:
        """Исключение в kex.generate_keypair() → CryptoError."""
        _, mock_kex, _ = mock_registry_patch
        mock_kex.generate_keypair.side_effect = RuntimeError("hardware failure")
        with pytest.raises(CryptoError, match="Keypair generation failed"):
            escrow.generate_keypair()

    def test_returns_values_from_kex(
        self, escrow: DualKeyEscrow, mock_registry_patch: Any
    ) -> None:
        """Возвращаемые ключи соответствуют тому, что вернул _kex."""
        _, mock_kex, _ = mock_registry_patch
        mock_kex.generate_keypair.return_value = (FAKE_PRIV_KEY, FAKE_PUB_KEY)
        priv, pub = escrow.generate_keypair()
        assert priv == FAKE_PRIV_KEY
        assert pub == FAKE_PUB_KEY


# ==============================================================================
# DualKeyEscrow.encrypt
# ==============================================================================


@pytest.mark.security
@pytest.mark.crypto
class TestEncrypt:
    """Тесты encrypt()."""

    def test_returns_escrow_encrypted_data(self, escrow: DualKeyEscrow) -> None:
        """encrypt() возвращает EscrowEncryptedData."""
        result = escrow.encrypt(
            plaintext=SAMPLE_PLAINTEXT,
            user_public_key=FAKE_PUB_KEY,
            escrow_public_key=FAKE_ESCROW_PUB,
        )
        assert isinstance(result, EscrowEncryptedData)

    def test_result_contains_ciphertext_and_nonce(
        self, escrow: DualKeyEscrow, mock_registry_patch: Any
    ) -> None:
        """ciphertext и nonce в результате совпадают с тем, что вернул cipher."""
        _, _, mock_cipher = mock_registry_patch
        mock_cipher.encrypt.return_value = (FAKE_NONCE, FAKE_CIPHERTEXT)
        result = escrow.encrypt(
            plaintext=SAMPLE_PLAINTEXT,
            user_public_key=FAKE_PUB_KEY,
            escrow_public_key=FAKE_ESCROW_PUB,
        )
        assert result.ciphertext == FAKE_CIPHERTEXT
        assert result.nonce == FAKE_NONCE

    def test_result_contains_both_wrapped_keys(self, escrow: DualKeyEscrow) -> None:
        """Результат содержит user_wrapped_key и escrow_wrapped_key."""
        result = escrow.encrypt(
            plaintext=SAMPLE_PLAINTEXT,
            user_public_key=FAKE_PUB_KEY,
            escrow_public_key=FAKE_ESCROW_PUB,
        )
        assert "ephemeral_public_key" in result.user_wrapped_key
        assert "ephemeral_public_key" in result.escrow_wrapped_key

    def test_user_and_escrow_wrapped_keys_are_independent(
        self, escrow: DualKeyEscrow
    ) -> None:
        """user_wrapped_key и escrow_wrapped_key — разные объекты (независимые пути)."""
        result = escrow.encrypt(
            plaintext=SAMPLE_PLAINTEXT,
            user_public_key=FAKE_PUB_KEY,
            escrow_public_key=FAKE_ESCROW_PUB,
        )
        assert result.user_wrapped_key is not result.escrow_wrapped_key

    def test_cipher_encrypt_called_three_times(
        self, escrow: DualKeyEscrow, mock_registry_patch: Any
    ) -> None:
        """cipher.encrypt вызывается 3 раза: 1 для plaintext + 2 для wrap_key."""
        _, _, mock_cipher = mock_registry_patch
        escrow.encrypt(
            plaintext=SAMPLE_PLAINTEXT,
            user_public_key=FAKE_PUB_KEY,
            escrow_public_key=FAKE_ESCROW_PUB,
        )
        assert mock_cipher.encrypt.call_count == 3

    def test_associated_data_passed_to_cipher(
        self, escrow: DualKeyEscrow, mock_registry_patch: Any
    ) -> None:
        """associated_data передаётся в первый вызов cipher.encrypt как aad."""
        _, _, mock_cipher = mock_registry_patch
        aad = b"document-id-42"
        escrow.encrypt(
            plaintext=SAMPLE_PLAINTEXT,
            user_public_key=FAKE_PUB_KEY,
            escrow_public_key=FAKE_ESCROW_PUB,
            associated_data=aad,
        )
        first_call_kwargs = mock_cipher.encrypt.call_args_list[0].kwargs
        assert first_call_kwargs.get("aad") == aad

    def test_data_key_passed_to_cipher_as_bytes(
        self, escrow: DualKeyEscrow, mock_registry_patch: Any
    ) -> None:
        """data_key передаётся в cipher.encrypt как bytes (не bytearray)."""
        _, _, mock_cipher = mock_registry_patch
        escrow.encrypt(
            plaintext=SAMPLE_PLAINTEXT,
            user_public_key=FAKE_PUB_KEY,
            escrow_public_key=FAKE_ESCROW_PUB,
        )
        first_call_kwargs = mock_cipher.encrypt.call_args_list[0].kwargs
        assert isinstance(first_call_kwargs.get("key"), bytes)

    @pytest.mark.parametrize(
        "plaintext,user_pub,escrow_pub,error_fragment",
        [
            (b"", FAKE_PUB_KEY, FAKE_ESCROW_PUB, "empty plaintext"),
            (SAMPLE_PLAINTEXT, b"", FAKE_ESCROW_PUB, "User public key"),
            (SAMPLE_PLAINTEXT, FAKE_PUB_KEY, b"", "Escrow public key"),
        ],
        ids=["empty-plaintext", "empty-user-key", "empty-escrow-key"],
    )
    def test_invalid_inputs_raise_value_error(
        self,
        escrow: DualKeyEscrow,
        plaintext: bytes,
        user_pub: bytes,
        escrow_pub: bytes,
        error_fragment: str,
    ) -> None:
        """Невалидные входные данные вызывают ValueError с понятным сообщением."""
        with pytest.raises(ValueError, match=error_fragment):
            escrow.encrypt(
                plaintext=plaintext,
                user_public_key=user_pub,
                escrow_public_key=escrow_pub,
            )

    def test_kex_error_during_wrap_raises_encryption_error(
        self, escrow: DualKeyEscrow, mock_registry_patch: Any
    ) -> None:
        """Ошибка KEX в _wrap_key → EncryptionError."""
        _, mock_kex, _ = mock_registry_patch
        mock_kex.derive_shared_secret.side_effect = RuntimeError("kex error")
        with pytest.raises(EncryptionError, match="Escrow encryption failed"):
            escrow.encrypt(
                plaintext=SAMPLE_PLAINTEXT,
                user_public_key=FAKE_PUB_KEY,
                escrow_public_key=FAKE_ESCROW_PUB,
            )

    def test_encryption_error_from_cipher_propagates_unchanged(
        self, escrow: DualKeyEscrow, mock_registry_patch: Any
    ) -> None:
        """EncryptionError из cipher.encrypt поднимается без повторной обёртки."""
        _, _, mock_cipher = mock_registry_patch
        original = EncryptionError("cipher failure")
        mock_cipher.encrypt.side_effect = original
        with pytest.raises(EncryptionError) as exc_info:
            escrow.encrypt(
                plaintext=SAMPLE_PLAINTEXT,
                user_public_key=FAKE_PUB_KEY,
                escrow_public_key=FAKE_ESCROW_PUB,
            )
        assert exc_info.value is original

    def test_data_key_erased_even_on_exception(
        self, escrow: DualKeyEscrow, mock_registry_patch: Any
    ) -> None:
        """_secure_erase вызывается в finally — даже если шифрование упало."""
        _, mock_kex, _ = mock_registry_patch
        mock_kex.derive_shared_secret.side_effect = RuntimeError("forced")
        with patch.object(escrow, "_secure_erase") as mock_erase:
            with pytest.raises(EncryptionError):
                escrow.encrypt(
                    plaintext=SAMPLE_PLAINTEXT,
                    user_public_key=FAKE_PUB_KEY,
                    escrow_public_key=FAKE_ESCROW_PUB,
                )
            mock_erase.assert_called()


# ==============================================================================
# DualKeyEscrow.decrypt_as_user
# ==============================================================================


@pytest.mark.security
@pytest.mark.crypto
class TestDecryptAsUser:
    """Тесты decrypt_as_user() — User Path."""

    def test_returns_plaintext(
        self,
        escrow: DualKeyEscrow,
        valid_encrypted_data: EscrowEncryptedData,
        mock_registry_patch: Any,
    ) -> None:
        """decrypt_as_user() возвращает расшифрованный plaintext."""
        _, _, mock_cipher = mock_registry_patch
        mock_cipher.decrypt.return_value = SAMPLE_PLAINTEXT
        result = escrow.decrypt_as_user(FAKE_PRIV_KEY, valid_encrypted_data)
        assert result == SAMPLE_PLAINTEXT

    def test_uses_user_wrapped_key_not_escrow(
        self,
        escrow: DualKeyEscrow,
        valid_encrypted_data: EscrowEncryptedData,
        mock_registry_patch: Any,
    ) -> None:
        """decrypt_as_user() использует user_wrapped_key (не escrow_wrapped_key)."""
        _, mock_kex, _ = mock_registry_patch
        escrow.decrypt_as_user(FAKE_PRIV_KEY, valid_encrypted_data)
        kex_call = mock_kex.derive_shared_secret.call_args
        assert (
            kex_call.kwargs.get("peer_public_key")
            == valid_encrypted_data.user_wrapped_key["ephemeral_public_key"]
        )

    def test_uses_hkdf_info_user(
        self,
        escrow: DualKeyEscrow,
        valid_encrypted_data: EscrowEncryptedData,
    ) -> None:
        """decrypt_as_user() передаёт HKDF_INFO_USER в _derive_key."""
        with patch.object(
            escrow, "_derive_key", wraps=escrow._derive_key
        ) as mock_derive:
            escrow.decrypt_as_user(FAKE_PRIV_KEY, valid_encrypted_data)
            assert mock_derive.call_args.args[2] == HKDF_INFO_USER

    def test_associated_data_passed_to_cipher_decrypt(
        self,
        escrow: DualKeyEscrow,
        valid_encrypted_data: EscrowEncryptedData,
        mock_registry_patch: Any,
    ) -> None:
        """
        REGRESSION: associated_data правильно передаётся в cipher.decrypt.

        Ранее в вызове _decrypt_path использовалось 'aad=associated_data',
        что вызывало TypeError. Тест проверяет, что параметр дошёл до cipher.
        """
        _, _, mock_cipher = mock_registry_patch
        aad = b"regression-test-aad"
        escrow.decrypt_as_user(FAKE_PRIV_KEY, valid_encrypted_data, associated_data=aad)
        decrypt_kwargs = mock_cipher.decrypt.call_args.kwargs
        assert decrypt_kwargs.get("aad") == aad

    def test_empty_private_key_raises_value_error(
        self,
        escrow: DualKeyEscrow,
        valid_encrypted_data: EscrowEncryptedData,
    ) -> None:
        """Пустой user_private_key → ValueError с упоминанием 'User'."""
        with pytest.raises(ValueError, match="User private key"):
            escrow.decrypt_as_user(b"", valid_encrypted_data)

    def test_kex_error_raises_decryption_error(
        self,
        escrow: DualKeyEscrow,
        valid_encrypted_data: EscrowEncryptedData,
        mock_registry_patch: Any,
    ) -> None:
        """Ошибка KEX при unwrap → DecryptionError с упоминанием 'user path'."""
        _, mock_kex, _ = mock_registry_patch
        mock_kex.derive_shared_secret.side_effect = RuntimeError("kex failed")
        with pytest.raises(DecryptionError, match="user path"):
            escrow.decrypt_as_user(FAKE_PRIV_KEY, valid_encrypted_data)

    def test_invalid_key_error_propagates_unchanged(
        self,
        escrow: DualKeyEscrow,
        valid_encrypted_data: EscrowEncryptedData,
        mock_registry_patch: Any,
    ) -> None:
        """InvalidKeyError из cipher.decrypt поднимается без обёртки."""
        _, _, mock_cipher = mock_registry_patch
        original = InvalidKeyError("bad key")
        mock_cipher.decrypt.side_effect = original
        with pytest.raises(InvalidKeyError) as exc_info:
            escrow.decrypt_as_user(FAKE_PRIV_KEY, valid_encrypted_data)
        assert exc_info.value is original

    def test_data_key_erased_on_success(
        self,
        escrow: DualKeyEscrow,
        valid_encrypted_data: EscrowEncryptedData,
    ) -> None:
        """_secure_erase вызывается после успешной расшифровки."""
        with patch.object(escrow, "_secure_erase") as mock_erase:
            escrow.decrypt_as_user(FAKE_PRIV_KEY, valid_encrypted_data)
            mock_erase.assert_called()

    def test_data_key_erased_on_failure(
        self,
        escrow: DualKeyEscrow,
        valid_encrypted_data: EscrowEncryptedData,
        mock_registry_patch: Any,
    ) -> None:
        """_secure_erase вызывается даже при ошибке расшифровки."""
        _, mock_kex, _ = mock_registry_patch
        mock_kex.derive_shared_secret.side_effect = RuntimeError("forced")
        with patch.object(escrow, "_secure_erase") as mock_erase:
            with pytest.raises(DecryptionError):
                escrow.decrypt_as_user(FAKE_PRIV_KEY, valid_encrypted_data)
            mock_erase.assert_called()


# ==============================================================================
# DualKeyEscrow.decrypt_as_escrow
# ==============================================================================


@pytest.mark.security
@pytest.mark.crypto
class TestDecryptAsEscrow:
    """Тесты decrypt_as_escrow() — Escrow Path."""

    def test_returns_plaintext(
        self,
        escrow: DualKeyEscrow,
        valid_encrypted_data: EscrowEncryptedData,
        mock_registry_patch: Any,
    ) -> None:
        """decrypt_as_escrow() возвращает расшифрованный plaintext."""
        _, _, mock_cipher = mock_registry_patch
        mock_cipher.decrypt.return_value = SAMPLE_PLAINTEXT
        result = escrow.decrypt_as_escrow(FAKE_ESCROW_PRIV, valid_encrypted_data)
        assert result == SAMPLE_PLAINTEXT

    def test_uses_escrow_wrapped_key_not_user(
        self,
        escrow: DualKeyEscrow,
        valid_encrypted_data: EscrowEncryptedData,
        mock_registry_patch: Any,
    ) -> None:
        """decrypt_as_escrow() использует escrow_wrapped_key (не user_wrapped_key)."""
        _, mock_kex, _ = mock_registry_patch
        escrow.decrypt_as_escrow(FAKE_ESCROW_PRIV, valid_encrypted_data)
        kex_call = mock_kex.derive_shared_secret.call_args
        assert (
            kex_call.kwargs.get("peer_public_key")
            == valid_encrypted_data.escrow_wrapped_key["ephemeral_public_key"]
        )

    def test_uses_hkdf_info_escrow(
        self,
        escrow: DualKeyEscrow,
        valid_encrypted_data: EscrowEncryptedData,
    ) -> None:
        """decrypt_as_escrow() передаёт HKDF_INFO_ESCROW в _derive_key."""
        with patch.object(
            escrow, "_derive_key", wraps=escrow._derive_key
        ) as mock_derive:
            escrow.decrypt_as_escrow(FAKE_ESCROW_PRIV, valid_encrypted_data)
            assert mock_derive.call_args.args[2] == HKDF_INFO_ESCROW

    def test_associated_data_passed_to_cipher_decrypt(
        self,
        escrow: DualKeyEscrow,
        valid_encrypted_data: EscrowEncryptedData,
        mock_registry_patch: Any,
    ) -> None:
        """
        REGRESSION: associated_data правильно передаётся в cipher.decrypt.

        Ранее в вызове _decrypt_path использовалось 'aad=associated_data'
        вместо 'associated_data=associated_data', что вызывало TypeError.
        """
        _, _, mock_cipher = mock_registry_patch
        aad = b"escrow-regression-aad"
        escrow.decrypt_as_escrow(
            FAKE_ESCROW_PRIV, valid_encrypted_data, associated_data=aad
        )
        decrypt_kwargs = mock_cipher.decrypt.call_args.kwargs
        assert decrypt_kwargs.get("aad") == aad

    def test_empty_private_key_raises_value_error(
        self,
        escrow: DualKeyEscrow,
        valid_encrypted_data: EscrowEncryptedData,
    ) -> None:
        """Пустой escrow_private_key → ValueError с упоминанием 'Escrow'."""
        with pytest.raises(ValueError, match="Escrow private key"):
            escrow.decrypt_as_escrow(b"", valid_encrypted_data)

    def test_decryption_error_propagates_with_path_name(
        self,
        escrow: DualKeyEscrow,
        valid_encrypted_data: EscrowEncryptedData,
        mock_registry_patch: Any,
    ) -> None:
        """DecryptionError содержит имя пути 'escrow'."""
        _, mock_kex, _ = mock_registry_patch
        mock_kex.derive_shared_secret.side_effect = RuntimeError("broken")
        with pytest.raises(DecryptionError, match="escrow path"):
            escrow.decrypt_as_escrow(FAKE_ESCROW_PRIV, valid_encrypted_data)


# ==============================================================================
# Независимость путей — ключевой security-инвариант
# ==============================================================================


@pytest.mark.security
class TestPathIndependence:
    """Проверка что user и escrow пути криптографически изолированы."""

    def test_hkdf_info_user_differs_from_escrow(self) -> None:
        """HKDF_INFO_USER и HKDF_INFO_ESCROW должны быть разными строками."""
        assert HKDF_INFO_USER != HKDF_INFO_ESCROW

    def test_hkdf_info_constants_are_bytes(self) -> None:
        """HKDF info константы — bytes объекты."""
        assert isinstance(HKDF_INFO_USER, bytes)
        assert isinstance(HKDF_INFO_ESCROW, bytes)

    def test_hkdf_info_user_contains_version(self) -> None:
        """HKDF_INFO_USER содержит версию для domain separation."""
        assert b"v1" in HKDF_INFO_USER

    def test_hkdf_info_escrow_contains_version(self) -> None:
        """HKDF_INFO_ESCROW содержит версию для domain separation."""
        assert b"v1" in HKDF_INFO_ESCROW

    def test_wrong_path_key_triggers_decryption_error(
        self,
        escrow: DualKeyEscrow,
        mock_registry_patch: Any,
    ) -> None:
        """Попытка расшифровать с неверным ключом пути вызывает DecryptionError."""
        _, _, mock_cipher = mock_registry_patch
        mock_cipher.decrypt.side_effect = [
            FAKE_DATA_KEY,  # _unwrap_key: decrypt wrapping
            DecryptionError("AEAD tag mismatch"),  # _decrypt_path: decrypt payload
        ]
        tampered = EscrowEncryptedData(
            ciphertext=FAKE_CIPHERTEXT,
            nonce=FAKE_NONCE,
            user_wrapped_key={
                "ephemeral_public_key": FAKE_EPHEMERAL_PUB,
                "nonce": FAKE_NONCE,
                "ciphertext": FAKE_CIPHERTEXT,
                "hkdf_salt": FAKE_HKDF_SALT,
            },
            escrow_wrapped_key={
                "ephemeral_public_key": FAKE_EPHEMERAL_PUB,
                "nonce": FAKE_NONCE,
                "ciphertext": FAKE_CIPHERTEXT,
                "hkdf_salt": FAKE_HKDF_SALT,
            },
        )
        with pytest.raises(DecryptionError):
            escrow.decrypt_as_user(FAKE_PRIV_KEY, tampered)


# ==============================================================================
# _wrap_key / _unwrap_key
# ==============================================================================


@pytest.mark.security
class TestWrapUnwrapKey:
    """Тесты приватных методов _wrap_key и _unwrap_key."""

    def test_wrap_key_returns_required_fields(self, escrow: DualKeyEscrow) -> None:
        """_wrap_key возвращает dict с четырьмя обязательными полями."""
        result = escrow._wrap_key(FAKE_DATA_KEY, FAKE_PUB_KEY, HKDF_INFO_USER)
        assert set(result.keys()) == {
            "ephemeral_public_key",
            "nonce",
            "ciphertext",
            "hkdf_salt",
        }

    def test_wrap_key_generates_ephemeral_keypair(
        self, escrow: DualKeyEscrow, mock_registry_patch: Any
    ) -> None:
        """_wrap_key генерирует ephemeral keypair для каждого вызова."""
        _, mock_kex, _ = mock_registry_patch
        escrow._wrap_key(FAKE_DATA_KEY, FAKE_PUB_KEY, HKDF_INFO_USER)
        mock_kex.generate_keypair.assert_called()

    def test_wrap_key_uses_ephemeral_private_for_kex(
        self, escrow: DualKeyEscrow, mock_registry_patch: Any
    ) -> None:
        """_wrap_key передаёт ephemeral private key в derive_shared_secret."""
        _, mock_kex, _ = mock_registry_patch
        mock_kex.generate_keypair.return_value = (
            FAKE_EPHEMERAL_PRIV,
            FAKE_EPHEMERAL_PUB,
        )
        escrow._wrap_key(FAKE_DATA_KEY, FAKE_PUB_KEY, HKDF_INFO_USER)
        kex_call = mock_kex.derive_shared_secret.call_args
        # Ключ передаётся как bytes, а не bytearray (cipher ожидает bytes)
        assert kex_call.kwargs.get("private_key") == FAKE_EPHEMERAL_PRIV

    def test_wrap_key_erases_sensitive_materials(self, escrow: DualKeyEscrow) -> None:
        """_wrap_key вызывает _secure_erase для ephemeral_private, shared_secret, wrapping_key."""
        with patch.object(escrow, "_secure_erase") as mock_erase:
            escrow._wrap_key(FAKE_DATA_KEY, FAKE_PUB_KEY, HKDF_INFO_USER)
            # Три вызова: ephemeral_private, shared_secret, wrapping_key
            assert mock_erase.call_count == 3

    def test_wrap_key_erases_on_exception(
        self, escrow: DualKeyEscrow, mock_registry_patch: Any
    ) -> None:
        """_wrap_key вызывает _secure_erase даже при исключении."""
        _, mock_kex, _ = mock_registry_patch
        mock_kex.derive_shared_secret.side_effect = RuntimeError("kex fail")
        with patch.object(escrow, "_secure_erase") as mock_erase:
            with pytest.raises(RuntimeError):
                escrow._wrap_key(FAKE_DATA_KEY, FAKE_PUB_KEY, HKDF_INFO_USER)
            mock_erase.assert_called()

    def test_unwrap_key_calls_kex_with_correct_keys(
        self, escrow: DualKeyEscrow, mock_registry_patch: Any
    ) -> None:
        """_unwrap_key вызывает derive_shared_secret с правильными ключами."""
        _, mock_kex, mock_cipher = mock_registry_patch
        mock_cipher.decrypt.return_value = FAKE_DATA_KEY
        wrapped: dict[str, bytes] = {
            "ephemeral_public_key": FAKE_EPHEMERAL_PUB,
            "nonce": FAKE_NONCE,
            "ciphertext": FAKE_CIPHERTEXT,
            "hkdf_salt": FAKE_HKDF_SALT,
        }
        escrow._unwrap_key(FAKE_PRIV_KEY, wrapped, HKDF_INFO_USER)
        mock_kex.derive_shared_secret.assert_called_once_with(
            private_key=FAKE_PRIV_KEY,
            peer_public_key=FAKE_EPHEMERAL_PUB,
        )

    def test_unwrap_key_missing_hkdf_salt_uses_empty_bytes(
        self, escrow: DualKeyEscrow, mock_registry_patch: Any
    ) -> None:
        """_unwrap_key при отсутствии hkdf_salt использует b'' → HKDF salt=None."""
        _, _, mock_cipher = mock_registry_patch
        mock_cipher.decrypt.return_value = FAKE_DATA_KEY
        wrapped: dict[str, bytes] = {
            "ephemeral_public_key": FAKE_EPHEMERAL_PUB,
            "nonce": FAKE_NONCE,
            "ciphertext": FAKE_CIPHERTEXT,
            # hkdf_salt отсутствует намеренно
        }
        with patch.object(
            escrow, "_derive_key", wraps=escrow._derive_key
        ) as mock_derive:
            escrow._unwrap_key(FAKE_PRIV_KEY, wrapped, HKDF_INFO_USER)
            assert mock_derive.call_args.args[1] == b""

    def test_unwrap_key_erases_shared_secret_and_wrapping_key(
        self, escrow: DualKeyEscrow, mock_registry_patch: Any
    ) -> None:
        """_unwrap_key вызывает _secure_erase для shared_secret и wrapping_key."""
        _, _, mock_cipher = mock_registry_patch
        mock_cipher.decrypt.return_value = FAKE_DATA_KEY
        wrapped: dict[str, bytes] = {
            "ephemeral_public_key": FAKE_EPHEMERAL_PUB,
            "nonce": FAKE_NONCE,
            "ciphertext": FAKE_CIPHERTEXT,
            "hkdf_salt": FAKE_HKDF_SALT,
        }
        with patch.object(escrow, "_secure_erase") as mock_erase:
            escrow._unwrap_key(FAKE_PRIV_KEY, wrapped, HKDF_INFO_USER)
            assert mock_erase.call_count == 2

    def test_wrap_key_all_values_are_bytes(self, escrow: DualKeyEscrow) -> None:
        """Все значения в результате _wrap_key — bytes."""
        result = escrow._wrap_key(FAKE_DATA_KEY, FAKE_PUB_KEY, HKDF_INFO_USER)
        for field, value in result.items():
            assert isinstance(value, bytes), f"Field '{field}' is not bytes"


# ==============================================================================
# _derive_key (HKDF)
# ==============================================================================


@pytest.mark.security
@pytest.mark.crypto
class TestDeriveKey:
    """Тесты _derive_key — HKDF с конфигурируемым hash-алгоритмом."""

    def test_returns_bytes_of_data_key_size(self, escrow: DualKeyEscrow) -> None:
        """_derive_key возвращает bytes длиной DATA_KEY_SIZE."""
        result = escrow._derive_key(
            shared_secret=secrets.token_bytes(32),
            salt=secrets.token_bytes(HKDF_SALT_SIZE),
            info=HKDF_INFO_USER,
        )
        assert isinstance(result, bytes)
        assert len(result) == DATA_KEY_SIZE

    def test_different_info_produces_different_keys(
        self, escrow: DualKeyEscrow
    ) -> None:
        """Разные info строки → разные ключи (domain separation user vs escrow)."""
        secret = secrets.token_bytes(32)
        salt = secrets.token_bytes(HKDF_SALT_SIZE)
        key_user = escrow._derive_key(secret, salt, HKDF_INFO_USER)
        key_escrow = escrow._derive_key(secret, salt, HKDF_INFO_ESCROW)
        assert key_user != key_escrow

    def test_different_salts_produce_different_keys(
        self, escrow: DualKeyEscrow
    ) -> None:
        """Разные соли → разные ключи."""
        secret = secrets.token_bytes(32)
        key1 = escrow._derive_key(secret, secrets.token_bytes(32), HKDF_INFO_USER)
        key2 = escrow._derive_key(secret, secrets.token_bytes(32), HKDF_INFO_USER)
        assert key1 != key2

    def test_deterministic_with_same_inputs(self, escrow: DualKeyEscrow) -> None:
        """Одинаковые входные данные → одинаковый ключ (детерминированность HKDF)."""
        secret = b"\x01" * 32
        salt = b"\x02" * HKDF_SALT_SIZE
        key1 = escrow._derive_key(secret, salt, HKDF_INFO_USER)
        key2 = escrow._derive_key(secret, salt, HKDF_INFO_USER)
        assert key1 == key2

    def test_empty_salt_uses_hkdf_none(self, escrow: DualKeyEscrow) -> None:
        """Пустая соль (b'') передаётся как None в HKDF — не вызывает исключений."""
        result = escrow._derive_key(
            shared_secret=secrets.token_bytes(32),
            salt=b"",
            info=HKDF_INFO_USER,
        )
        assert len(result) == DATA_KEY_SIZE

    @pytest.mark.parametrize(
        "hash_cls",
        [hashes.SHA256, hashes.SHA384, hashes.SHA512],
        ids=["SHA256", "SHA384", "SHA512"],
    )
    def test_configurable_hash_produces_correct_output_length(
        self, mock_registry_patch: Any, hash_cls: type
    ) -> None:
        """Каждый поддерживаемый hash-алгоритм даёт ключ длиной DATA_KEY_SIZE."""
        escrow = DualKeyEscrow(hkdf_hash=hash_cls)
        result = escrow._derive_key(
            shared_secret=secrets.token_bytes(32),
            salt=secrets.token_bytes(HKDF_SALT_SIZE),
            info=HKDF_INFO_USER,
        )
        assert len(result) == DATA_KEY_SIZE

    def test_sha256_and_sha512_produce_different_keys(
        self, mock_registry_patch: Any
    ) -> None:
        """SHA256 и SHA512 конфигурации дают разные ключи для одних и тех же входов."""
        escrow_256 = DualKeyEscrow(hkdf_hash=hashes.SHA256)
        escrow_512 = DualKeyEscrow(hkdf_hash=hashes.SHA512)
        secret = b"\xab" * 32
        salt = b"\xcd" * HKDF_SALT_SIZE
        key_256 = escrow_256._derive_key(secret, salt, HKDF_INFO_USER)
        key_512 = escrow_512._derive_key(secret, salt, HKDF_INFO_USER)
        assert key_256 != key_512

    def test_derive_key_uses_self_hkdf_hash(self, mock_registry_patch: Any) -> None:
        """_derive_key инстанциирует self._hkdf_hash(), а не захардкоженный SHA256."""
        mock_hash_cls = MagicMock(return_value=MagicMock())
        mock_hash_cls.__name__ = "MockHash"
        escrow = DualKeyEscrow(hkdf_hash=mock_hash_cls)  # type: ignore[arg-type]
        with patch("src.security.crypto.advanced.key_escrow.HKDF") as mock_hkdf_cls:
            mock_hkdf_cls.return_value.derive.return_value = b"\x00" * DATA_KEY_SIZE
            escrow._derive_key(
                shared_secret=secrets.token_bytes(32),
                salt=secrets.token_bytes(HKDF_SALT_SIZE),
                info=HKDF_INFO_USER,
            )
        mock_hash_cls.assert_called_once()


# ==============================================================================
# _secure_erase
# ==============================================================================


@pytest.mark.security
class TestSecureErase:
    """Тесты _secure_erase — zeroing оригинального bytearray."""

    def test_all_bytes_zeroed_after_erase(self) -> None:
        """После _secure_erase все байты равны нулю."""
        data = bytearray(b"\xff\xaa\x55\x00" * 8)
        DualKeyEscrow._secure_erase(data)
        assert all(b == 0 for b in data)

    def test_erases_in_place(self) -> None:
        """_secure_erase изменяет оригинальный объект (не создаёт копию)."""
        data = bytearray(b"\xde\xad\xbe\xef")
        original_id = id(data)
        DualKeyEscrow._secure_erase(data)
        assert id(data) == original_id
        assert bytes(data) == b"\x00\x00\x00\x00"

    def test_empty_bytearray_does_not_raise(self) -> None:
        """_secure_erase на пустом bytearray не вызывает исключений."""
        DualKeyEscrow._secure_erase(bytearray())

    @pytest.mark.parametrize("size", [1, 16, 32, 64, 256, 1024])
    def test_various_sizes_all_zeroed(self, size: int) -> None:
        """_secure_erase корректно обнуляет буферы разных размеров."""
        data = bytearray(i % 256 for i in range(size))
        DualKeyEscrow._secure_erase(data)
        assert all(b == 0 for b in data)

    def test_two_pass_overwrite(self) -> None:
        """
        Верификация двухпроходного алгоритма: случайные байты + нули.

        Проверяет что финальное состояние — нули (второй проход).
        """
        data = bytearray(b"\xff" * 64)
        DualKeyEscrow._secure_erase(data)
        assert bytes(data) == b"\x00" * 64

    def test_erase_bytearray_not_bytes_copy(self) -> None:
        """
        REGRESSION: _secure_erase принимает bytearray, а не bytearray(bytes_obj).

        Код вида _secure_erase(bytearray(some_bytes)) стирает КОПИЮ.
        Исправленный код передаёт оригинальный bytearray напрямую.
        """
        original_data = bytearray(b"\xca\xfe\xba\xbe" * 8)
        # Сохраняем id для проверки что это тот же объект
        data_id = id(original_data)
        DualKeyEscrow._secure_erase(original_data)
        # Оригинальный объект должен быть обнулён
        assert id(original_data) == data_id
        assert all(b == 0 for b in original_data)


# ==============================================================================
# Константы модуля
# ==============================================================================


@pytest.mark.security
class TestModuleConstants:
    """Проверка корректности всех констант модуля."""

    def test_data_key_size_is_32(self) -> None:
        """DATA_KEY_SIZE == 32 (AES-256 / ChaCha20-256)."""
        assert DATA_KEY_SIZE == 32

    def test_hkdf_salt_size_is_32(self) -> None:
        """HKDF_SALT_SIZE == 32 (256-bit salt)."""
        assert HKDF_SALT_SIZE == 32

    def test_hkdf_info_user_is_bytes(self) -> None:
        assert isinstance(HKDF_INFO_USER, bytes)

    def test_hkdf_info_escrow_is_bytes(self) -> None:
        assert isinstance(HKDF_INFO_ESCROW, bytes)

    def test_hkdf_info_user_and_escrow_differ(self) -> None:
        """Константы должны различаться для domain separation."""
        assert HKDF_INFO_USER != HKDF_INFO_ESCROW

    def test_hkdf_info_user_contains_path_identifier(self) -> None:
        """HKDF_INFO_USER содержит идентификатор 'user'."""
        assert b"user" in HKDF_INFO_USER

    def test_hkdf_info_escrow_contains_path_identifier(self) -> None:
        """HKDF_INFO_ESCROW содержит идентификатор 'agent' или 'escrow'."""
        assert b"agent" in HKDF_INFO_ESCROW or b"escrow" in HKDF_INFO_ESCROW

    def test_hkdf_info_both_versioned(self) -> None:
        """Обе info-строки содержат версию для будущих миграций."""
        assert b"v1" in HKDF_INFO_USER
        assert b"v1" in HKDF_INFO_ESCROW
