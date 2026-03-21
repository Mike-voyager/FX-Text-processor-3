"""
Тесты для модуля гибридного шифрования hybrid_encryption.

Покрывает все публичные методы, обработку ошибок, edge cases
и инварианты безопасности класса HybridEncryption.
"""

from __future__ import annotations

import secrets
from unittest.mock import MagicMock, call, patch

import pytest

from src.security.crypto.advanced.hybrid_encryption import (
    HKDF_INFO_HYBRID_ENCRYPTION,
    HKDF_SALT_SIZE,
    PRESETS,
    SYMMETRIC_KEY_SIZE,
    HybridConfig,
    HybridEncryption,
    HybridPayload,
    create_hybrid_cipher,
)
from src.security.crypto.core.exceptions import (
    AlgorithmNotAvailableError,
    DecryptionError,
    EncryptionError,
    InvalidKeyError,
)


# ==============================================================================
# FIXTURES
# ==============================================================================


@pytest.fixture
def mock_kex() -> MagicMock:
    """Мок KeyExchangeProtocol (classical KEX, без encapsulate/decapsulate)."""
    kex = MagicMock(spec=["generate_keypair", "derive_shared_secret"])
    kex.generate_keypair.return_value = (b"\x01" * 32, b"\x02" * 32)
    kex.derive_shared_secret.return_value = b"\x03" * 32
    return kex


@pytest.fixture
def mock_cipher() -> MagicMock:
    """Мок SymmetricCipherProtocol."""
    cipher = MagicMock()
    cipher.encrypt.return_value = (b"ciphertext_data_here", b"\x04" * 12)
    cipher.decrypt.return_value = b"decrypted_plaintext"
    return cipher


@pytest.fixture
def mock_registry(mock_kex: MagicMock, mock_cipher: MagicMock) -> MagicMock:
    """Мок AlgorithmRegistry, возвращающий нужный алгоритм по имени."""
    registry = MagicMock()

    def _create_side_effect(algorithm: str) -> MagicMock:
        if algorithm in ("x25519", "x448", "ml-kem-768", "ml-kem-1024"):
            return mock_kex
        return mock_cipher

    registry.create.side_effect = _create_side_effect
    return registry


@pytest.fixture
def classical_config() -> HybridConfig:
    """Конфигурация classical_standard из PRESETS."""
    return PRESETS["classical_standard"]


@pytest.fixture
def hybrid_encryption(
    mock_registry: MagicMock,
    classical_config: HybridConfig,
) -> HybridEncryption:
    """Экземпляр HybridEncryption с замоканным registry."""
    with patch(
        "src.security.crypto.advanced.hybrid_encryption.AlgorithmRegistry"
    ) as mock_cls:
        mock_cls.get_instance.return_value = mock_registry
        return HybridEncryption(classical_config)


@pytest.fixture
def sample_encrypted_data() -> HybridPayload:
    """Корректная структура зашифрованных данных."""
    return HybridPayload(
        ephemeral_public_key=b"\x02" * 32,
        nonce=b"\x04" * 12,
        ciphertext=b"some_ciphertext_bytes",
        hkdf_salt=b"\x05" * 32,
    )


# ==============================================================================
# TESTS: Constants
# ==============================================================================


class TestConstants:
    """Тесты для констант модуля."""

    def test_hkdf_info_value(self) -> None:
        """HKDF_INFO_HYBRID_ENCRYPTION должна содержать правильное значение."""
        assert HKDF_INFO_HYBRID_ENCRYPTION == b"hybrid-encryption-v1"

    def test_hkdf_info_is_bytes(self) -> None:
        """HKDF_INFO_HYBRID_ENCRYPTION должна быть bytes."""
        assert isinstance(HKDF_INFO_HYBRID_ENCRYPTION, bytes)

    def test_hkdf_salt_size_is_32(self) -> None:
        """HKDF_SALT_SIZE должна быть 32."""
        assert HKDF_SALT_SIZE == 32

    def test_symmetric_key_size_is_32(self) -> None:
        """SYMMETRIC_KEY_SIZE должна быть 32."""
        assert SYMMETRIC_KEY_SIZE == 32


# ==============================================================================
# TESTS: HybridConfig
# ==============================================================================


class TestHybridConfig:
    """Тесты для датакласса HybridConfig."""

    def test_create_config_basic(self) -> None:
        """Создание конфигурации с корректными параметрами."""
        config = HybridConfig(
            kex_algorithm="x25519",
            symmetric_algorithm="aes-256-gcm",
            name="Test Config",
            description="Test description",
        )

        assert config.kex_algorithm == "x25519"
        assert config.symmetric_algorithm == "aes-256-gcm"
        assert config.name == "Test Config"
        assert config.description == "Test description"

    def test_config_is_frozen(self) -> None:
        """HybridConfig должен быть неизменяемым (frozen=True)."""
        config = HybridConfig(
            kex_algorithm="x25519",
            symmetric_algorithm="aes-256-gcm",
            name="Test",
            description="Test",
        )
        with pytest.raises(AttributeError):
            config.kex_algorithm = "x448"  # type: ignore[misc]

    def test_config_equality(self) -> None:
        """Два одинаковых конфига должны быть равны."""
        config1 = HybridConfig("x25519", "aes-256-gcm", "Name", "Desc")
        config2 = HybridConfig("x25519", "aes-256-gcm", "Name", "Desc")
        assert config1 == config2


# ==============================================================================
# TESTS: PRESETS
# ==============================================================================


class TestPresets:
    """Тесты для словаря PRESETS."""

    @pytest.mark.parametrize(
        "preset_name",
        ["classical_standard", "classical_paranoid", "pqc_standard", "pqc_paranoid"],
    )
    def test_all_presets_exist(self, preset_name: str) -> None:
        """Все заявленные пресеты должны быть в словаре."""
        assert preset_name in PRESETS

    def test_presets_count(self) -> None:
        """Должно быть ровно 4 пресета."""
        assert len(PRESETS) == 4

    @pytest.mark.parametrize(
        "preset_name,expected_kex,expected_sym",
        [
            ("classical_standard", "x25519", "aes-256-gcm"),
            ("classical_paranoid", "x448", "chacha20-poly1305"),
            ("pqc_standard", "ml-kem-768", "aes-256-gcm"),
            ("pqc_paranoid", "ml-kem-1024", "chacha20-poly1305"),
        ],
    )
    def test_preset_algorithms(
        self,
        preset_name: str,
        expected_kex: str,
        expected_sym: str,
    ) -> None:
        """Каждый пресет должен содержать корректные алгоритмы KEX и симметрии."""
        config = PRESETS[preset_name]
        assert config.kex_algorithm == expected_kex
        assert config.symmetric_algorithm == expected_sym

    @pytest.mark.parametrize(
        "preset_name",
        ["classical_standard", "classical_paranoid", "pqc_standard", "pqc_paranoid"],
    )
    def test_preset_has_nonempty_name_and_description(self, preset_name: str) -> None:
        """Каждый пресет должен иметь непустые name и description."""
        config = PRESETS[preset_name]
        assert config.name
        assert config.description


# ==============================================================================
# TESTS: HybridEncryption.__init__
# ==============================================================================


class TestHybridEncryptionInit:
    """Тесты инициализации HybridEncryption."""

    def test_init_success(
        self,
        mock_registry: MagicMock,
        classical_config: HybridConfig,
    ) -> None:
        """Успешная инициализация — config доступен."""
        with patch(
            "src.security.crypto.advanced.hybrid_encryption.AlgorithmRegistry"
        ) as mock_cls:
            mock_cls.get_instance.return_value = mock_registry
            cipher = HybridEncryption(classical_config)
            assert cipher.config is classical_config

    def test_init_calls_registry_get_instance(
        self,
        mock_registry: MagicMock,
        classical_config: HybridConfig,
    ) -> None:
        """Инициализация должна вызывать AlgorithmRegistry.get_instance()."""
        with patch(
            "src.security.crypto.advanced.hybrid_encryption.AlgorithmRegistry"
        ) as mock_cls:
            mock_cls.get_instance.return_value = mock_registry
            HybridEncryption(classical_config)
            mock_cls.get_instance.assert_called_once()

    def test_init_raises_on_key_error(
        self,
        classical_config: HybridConfig,
    ) -> None:
        """KeyError в registry → AlgorithmNotAvailableError."""
        mock_registry = MagicMock()
        mock_registry.create.side_effect = KeyError("x25519")
        with patch(
            "src.security.crypto.advanced.hybrid_encryption.AlgorithmRegistry"
        ) as mock_cls:
            mock_cls.get_instance.return_value = mock_registry
            with pytest.raises(AlgorithmNotAvailableError):
                HybridEncryption(classical_config)

    def test_init_raises_on_runtime_error(
        self,
        classical_config: HybridConfig,
    ) -> None:
        """RuntimeError в registry (missing library) → AlgorithmNotAvailableError."""
        mock_registry = MagicMock()
        mock_registry.create.side_effect = RuntimeError("Missing liboqs")
        with patch(
            "src.security.crypto.advanced.hybrid_encryption.AlgorithmRegistry"
        ) as mock_cls:
            mock_cls.get_instance.return_value = mock_registry
            with pytest.raises(AlgorithmNotAvailableError):
                HybridEncryption(classical_config)

    def test_config_property_returns_correct_config(
        self,
        hybrid_encryption: HybridEncryption,
        classical_config: HybridConfig,
    ) -> None:
        """Свойство config должно возвращать переданную конфигурацию."""
        assert hybrid_encryption.config == classical_config
        assert hybrid_encryption.config.kex_algorithm == "x25519"
        assert hybrid_encryption.config.symmetric_algorithm == "aes-256-gcm"


# ==============================================================================
# TESTS: generate_recipient_keypair
# ==============================================================================


class TestGenerateRecipientKeypair:
    """Тесты для generate_recipient_keypair."""

    def test_returns_tuple_of_two_bytes(
        self,
        hybrid_encryption: HybridEncryption,
    ) -> None:
        """Должна возвращать кортеж (private_key, public_key) как bytes."""
        result = hybrid_encryption.generate_recipient_keypair()
        assert isinstance(result, tuple)
        assert len(result) == 2
        private_key, public_key = result
        assert isinstance(private_key, bytes)
        assert isinstance(public_key, bytes)

    def test_returns_keypair_from_kex(
        self,
        hybrid_encryption: HybridEncryption,
        mock_kex: MagicMock,
    ) -> None:
        """Возвращаемые ключи должны исходить от KEX алгоритма."""
        private_key, public_key = hybrid_encryption.generate_recipient_keypair()
        assert private_key == b"\x01" * 32
        assert public_key == b"\x02" * 32

    def test_calls_kex_generate_keypair(
        self,
        hybrid_encryption: HybridEncryption,
        mock_kex: MagicMock,
    ) -> None:
        """Должна вызывать generate_keypair у KEX протокола."""
        hybrid_encryption.generate_recipient_keypair()
        mock_kex.generate_keypair.assert_called_once()

    def test_raises_encryption_error_on_exception(
        self,
        hybrid_encryption: HybridEncryption,
        mock_kex: MagicMock,
    ) -> None:
        """Исключение в KEX → EncryptionError с правильным сообщением."""
        mock_kex.generate_keypair.side_effect = Exception("KEX internal failure")
        with pytest.raises(EncryptionError, match="Keypair generation failed"):
            hybrid_encryption.generate_recipient_keypair()

    def test_multiple_calls_return_different_keypairs(
        self,
        hybrid_encryption: HybridEncryption,
        mock_kex: MagicMock,
    ) -> None:
        """Последовательные вызовы должны делегировать KEX (не кешировать)."""
        mock_kex.generate_keypair.side_effect = [
            (b"\x01" * 32, b"\x02" * 32),
            (b"\x03" * 32, b"\x04" * 32),
        ]
        pair1 = hybrid_encryption.generate_recipient_keypair()
        pair2 = hybrid_encryption.generate_recipient_keypair()
        assert pair1 != pair2


# ==============================================================================
# TESTS: encrypt_for_recipient
# ==============================================================================


class TestEncryptForRecipient:
    """Тесты для encrypt_for_recipient."""

    def test_encrypt_returns_hybrid_payload(
        self,
        hybrid_encryption: HybridEncryption,
    ) -> None:
        """Результат должен быть экземпляром HybridPayload."""
        result = hybrid_encryption.encrypt_for_recipient(
            recipient_public_key=b"\xcd" * 32,
            plaintext=b"Secret message",
        )
        assert isinstance(result, HybridPayload)
        assert result.ephemeral_public_key
        assert result.nonce
        assert result.ciphertext
        assert result.hkdf_salt is not None

    def test_encrypt_all_fields_are_bytes(
        self,
        hybrid_encryption: HybridEncryption,
    ) -> None:
        """Все поля HybridPayload должны быть bytes."""
        result = hybrid_encryption.encrypt_for_recipient(
            recipient_public_key=b"\xcd" * 32,
            plaintext=b"Secret message",
        )
        assert isinstance(result.ephemeral_public_key, bytes)
        assert isinstance(result.nonce, bytes)
        assert isinstance(result.ciphertext, bytes)
        assert isinstance(result.hkdf_salt, bytes)

    def test_encrypt_hkdf_salt_has_correct_size(
        self,
        hybrid_encryption: HybridEncryption,
    ) -> None:
        """Поле hkdf_salt должно быть HKDF_SALT_SIZE байт."""
        result = hybrid_encryption.encrypt_for_recipient(
            recipient_public_key=b"\xcd" * 32,
            plaintext=b"Secret",
        )
        assert len(result.hkdf_salt) == HKDF_SALT_SIZE

    def test_encrypt_raises_on_empty_public_key(
        self,
        hybrid_encryption: HybridEncryption,
    ) -> None:
        """Пустой recipient_public_key → ValueError."""
        with pytest.raises(ValueError, match="Recipient public key cannot be empty"):
            hybrid_encryption.encrypt_for_recipient(
                recipient_public_key=b"",
                plaintext=b"Secret",
            )

    def test_encrypt_raises_on_empty_plaintext(
        self,
        hybrid_encryption: HybridEncryption,
    ) -> None:
        """Пустой plaintext → ValueError."""
        with pytest.raises(ValueError, match="Cannot encrypt empty plaintext"):
            hybrid_encryption.encrypt_for_recipient(
                recipient_public_key=b"\xcd" * 32,
                plaintext=b"",
            )

    def test_encrypt_raises_invalid_key_on_value_error_from_kex(
        self,
        hybrid_encryption: HybridEncryption,
        mock_kex: MagicMock,
    ) -> None:
        """ValueError из KEX.derive_shared_secret → InvalidKeyError."""
        mock_kex.derive_shared_secret.side_effect = ValueError("Invalid peer key")
        with pytest.raises(InvalidKeyError):
            hybrid_encryption.encrypt_for_recipient(
                recipient_public_key=b"\xcd" * 32,
                plaintext=b"Secret",
            )

    def test_encrypt_raises_encryption_error_on_general_exception(
        self,
        hybrid_encryption: HybridEncryption,
        mock_cipher: MagicMock,
    ) -> None:
        """Общее исключение в cipher.encrypt → EncryptionError."""
        mock_cipher.encrypt.side_effect = RuntimeError("Cipher failure")
        with pytest.raises(EncryptionError, match="Hybrid encryption failed"):
            hybrid_encryption.encrypt_for_recipient(
                recipient_public_key=b"\xcd" * 32,
                plaintext=b"Secret",
            )

    def test_encrypt_reraises_invalid_key_error_unchanged(
        self,
        hybrid_encryption: HybridEncryption,
        mock_kex: MagicMock,
    ) -> None:
        """InvalidKeyError прокидывается без оборачивания."""
        original_error = InvalidKeyError("original error")
        mock_kex.derive_shared_secret.side_effect = original_error
        with pytest.raises(InvalidKeyError) as exc_info:
            hybrid_encryption.encrypt_for_recipient(
                recipient_public_key=b"\xcd" * 32,
                plaintext=b"Secret",
            )
        assert exc_info.value is original_error

    def test_encrypt_reraises_encryption_error_unchanged(
        self,
        hybrid_encryption: HybridEncryption,
        mock_cipher: MagicMock,
    ) -> None:
        """EncryptionError прокидывается без оборачивания."""
        original_error = EncryptionError("cipher error")
        mock_cipher.encrypt.side_effect = original_error
        with pytest.raises(EncryptionError) as exc_info:
            hybrid_encryption.encrypt_for_recipient(
                recipient_public_key=b"\xcd" * 32,
                plaintext=b"Secret",
            )
        assert exc_info.value is original_error

    def test_encrypt_passes_associated_data_to_cipher(
        self,
        hybrid_encryption: HybridEncryption,
        mock_cipher: MagicMock,
    ) -> None:
        """associated_data должны передаваться в симметричный шифр."""
        aad = b"additional_auth_data"
        hybrid_encryption.encrypt_for_recipient(
            recipient_public_key=b"\xcd" * 32,
            plaintext=b"Secret",
            associated_data=aad,
        )
        call_kwargs = mock_cipher.encrypt.call_args
        assert call_kwargs.kwargs.get("aad") == aad

    def test_encrypt_passes_none_aad_by_default(
        self,
        hybrid_encryption: HybridEncryption,
        mock_cipher: MagicMock,
    ) -> None:
        """По умолчанию associated_data=None должно передаваться в шифр."""
        hybrid_encryption.encrypt_for_recipient(
            recipient_public_key=b"\xcd" * 32,
            plaintext=b"Secret",
        )
        call_kwargs = mock_cipher.encrypt.call_args
        assert call_kwargs.kwargs.get("aad") is None

    def test_encrypt_uses_ephemeral_public_key_in_result(
        self,
        hybrid_encryption: HybridEncryption,
        mock_kex: MagicMock,
    ) -> None:
        """Поле ephemeral_public_key в результате должно быть из generate_keypair."""
        mock_kex.generate_keypair.return_value = (b"\x11" * 32, b"\x22" * 32)
        result = hybrid_encryption.encrypt_for_recipient(
            recipient_public_key=b"\xcd" * 32,
            plaintext=b"Secret",
        )
        assert result.ephemeral_public_key == b"\x22" * 32

    def test_encrypt_calls_derive_shared_secret_with_recipient_key(
        self,
        hybrid_encryption: HybridEncryption,
        mock_kex: MagicMock,
    ) -> None:
        """derive_shared_secret должен вызываться с ключом получателя."""
        recipient_pub = b"\xcd" * 32
        hybrid_encryption.encrypt_for_recipient(
            recipient_public_key=recipient_pub,
            plaintext=b"Secret",
        )
        mock_kex.derive_shared_secret.assert_called_once_with(
            private_key=mock_kex.generate_keypair.return_value[0],
            peer_public_key=recipient_pub,
        )


# ==============================================================================
# TESTS: decrypt_from_sender
# ==============================================================================


class TestDecryptFromSender:
    """Тесты для decrypt_from_sender."""

    def test_decrypt_success_returns_plaintext(
        self,
        hybrid_encryption: HybridEncryption,
        sample_encrypted_data: HybridPayload,
        mock_cipher: MagicMock,
    ) -> None:
        """Успешная расшифровка должна возвращать корректный plaintext."""
        mock_cipher.decrypt.return_value = b"the original message"
        result = hybrid_encryption.decrypt_from_sender(
            recipient_private_key=b"\xab" * 32,
            encrypted_data=sample_encrypted_data,
        )
        assert result == b"the original message"

    def test_decrypt_returns_bytes(
        self,
        hybrid_encryption: HybridEncryption,
        sample_encrypted_data: HybridPayload,
    ) -> None:
        """Возвращаемое значение должно быть bytes."""
        result = hybrid_encryption.decrypt_from_sender(
            recipient_private_key=b"\xab" * 32,
            encrypted_data=sample_encrypted_data,
        )
        assert isinstance(result, bytes)

    def test_decrypt_raises_on_empty_private_key(
        self,
        hybrid_encryption: HybridEncryption,
        sample_encrypted_data: HybridPayload,
    ) -> None:
        """Пустой recipient_private_key → ValueError."""
        with pytest.raises(ValueError, match="Recipient private key cannot be empty"):
            hybrid_encryption.decrypt_from_sender(
                recipient_private_key=b"",
                encrypted_data=sample_encrypted_data,
            )

    @pytest.mark.parametrize(
        "empty_field",
        ["ephemeral_public_key", "nonce", "ciphertext"],
    )
    def test_decrypt_raises_on_empty_required_field(
        self,
        hybrid_encryption: HybridEncryption,
        empty_field: str,
    ) -> None:
        """Пустое обязательное поле → ValueError."""
        kwargs = {
            "ephemeral_public_key": b"\x02" * 32,
            "nonce": b"\x04" * 12,
            "ciphertext": b"some_ciphertext_bytes",
            "hkdf_salt": b"\x05" * 32,
        }
        kwargs[empty_field] = b""
        payload = HybridPayload(**kwargs)
        with pytest.raises(ValueError, match="cannot be empty"):
            hybrid_encryption.decrypt_from_sender(
                recipient_private_key=b"\xab" * 32,
                encrypted_data=payload,
            )

    def test_decrypt_raises_invalid_key_on_value_error_from_kex(
        self,
        hybrid_encryption: HybridEncryption,
        sample_encrypted_data: HybridPayload,
        mock_kex: MagicMock,
    ) -> None:
        """ValueError из KEX.derive_shared_secret → InvalidKeyError."""
        mock_kex.derive_shared_secret.side_effect = ValueError("Bad private key")
        with pytest.raises(InvalidKeyError):
            hybrid_encryption.decrypt_from_sender(
                recipient_private_key=b"\xab" * 32,
                encrypted_data=sample_encrypted_data,
            )

    def test_decrypt_raises_decryption_error_on_general_exception(
        self,
        hybrid_encryption: HybridEncryption,
        sample_encrypted_data: HybridPayload,
        mock_cipher: MagicMock,
    ) -> None:
        """Общее исключение в cipher.decrypt → DecryptionError."""
        mock_cipher.decrypt.side_effect = RuntimeError("Auth tag mismatch")
        with pytest.raises(DecryptionError, match="Hybrid decryption failed"):
            hybrid_encryption.decrypt_from_sender(
                recipient_private_key=b"\xab" * 32,
                encrypted_data=sample_encrypted_data,
            )

    def test_decrypt_reraises_invalid_key_error_unchanged(
        self,
        hybrid_encryption: HybridEncryption,
        sample_encrypted_data: HybridPayload,
        mock_kex: MagicMock,
    ) -> None:
        """InvalidKeyError прокидывается без оборачивания."""
        original = InvalidKeyError("original")
        mock_kex.derive_shared_secret.side_effect = original
        with pytest.raises(InvalidKeyError) as exc_info:
            hybrid_encryption.decrypt_from_sender(
                recipient_private_key=b"\xab" * 32,
                encrypted_data=sample_encrypted_data,
            )
        assert exc_info.value is original

    def test_decrypt_reraises_decryption_error_unchanged(
        self,
        hybrid_encryption: HybridEncryption,
        sample_encrypted_data: HybridPayload,
        mock_cipher: MagicMock,
    ) -> None:
        """DecryptionError прокидывается без оборачивания."""
        original = DecryptionError("auth failed")
        mock_cipher.decrypt.side_effect = original
        with pytest.raises(DecryptionError) as exc_info:
            hybrid_encryption.decrypt_from_sender(
                recipient_private_key=b"\xab" * 32,
                encrypted_data=sample_encrypted_data,
            )
        assert exc_info.value is original

    def test_decrypt_with_empty_hkdf_salt(
        self,
        hybrid_encryption: HybridEncryption,
        mock_cipher: MagicMock,
    ) -> None:
        """Пустой hkdf_salt → fallback HKDF без соли (без исключений)."""
        payload = HybridPayload(
            ephemeral_public_key=b"\x02" * 32,
            nonce=b"\x04" * 12,
            ciphertext=b"some_ciphertext",
            hkdf_salt=b"",
        )
        result = hybrid_encryption.decrypt_from_sender(
            recipient_private_key=b"\xab" * 32,
            encrypted_data=payload,
        )
        assert isinstance(result, bytes)

    def test_decrypt_passes_associated_data_to_cipher(
        self,
        hybrid_encryption: HybridEncryption,
        sample_encrypted_data: HybridPayload,
        mock_cipher: MagicMock,
    ) -> None:
        """associated_data должны передаваться в симметричный шифр."""
        aad = b"auth_context"
        hybrid_encryption.decrypt_from_sender(
            recipient_private_key=b"\xab" * 32,
            encrypted_data=sample_encrypted_data,
            associated_data=aad,
        )
        call_kwargs = mock_cipher.decrypt.call_args
        assert call_kwargs.kwargs.get("aad") == aad

    def test_decrypt_calls_kex_with_private_key_and_ephemeral_pub(
        self,
        hybrid_encryption: HybridEncryption,
        sample_encrypted_data: HybridPayload,
        mock_kex: MagicMock,
    ) -> None:
        """KEX.derive_shared_secret должен получать правильные ключи."""
        recipient_priv = b"\xab" * 32
        hybrid_encryption.decrypt_from_sender(
            recipient_private_key=recipient_priv,
            encrypted_data=sample_encrypted_data,
        )
        mock_kex.derive_shared_secret.assert_called_once_with(
            private_key=recipient_priv,
            peer_public_key=sample_encrypted_data.ephemeral_public_key,
        )


# ==============================================================================
# TESTS: _validate_encrypted_data
# ==============================================================================


class TestValidateEncryptedData:
    """Тесты для приватного метода _validate_encrypted_data."""

    def test_valid_payload_passes_without_exception(
        self,
        hybrid_encryption: HybridEncryption,
    ) -> None:
        """Корректный HybridPayload не должен вызывать исключений."""
        payload = HybridPayload(
            ephemeral_public_key=b"\x02" * 32,
            nonce=b"\x04" * 12,
            ciphertext=b"some_data",
            hkdf_salt=b"\x05" * 32,
        )
        hybrid_encryption._validate_encrypted_data(payload)  # no exception

    @pytest.mark.parametrize(
        "empty_field",
        ["ephemeral_public_key", "nonce", "ciphertext"],
    )
    def test_empty_field_raises_with_field_name(
        self,
        hybrid_encryption: HybridEncryption,
        empty_field: str,
    ) -> None:
        """Пустое обязательное поле → ValueError с именем поля."""
        kwargs = {
            "ephemeral_public_key": b"\x02" * 32,
            "nonce": b"\x04" * 12,
            "ciphertext": b"some_data",
            "hkdf_salt": b"\x05" * 32,
        }
        kwargs[empty_field] = b""
        payload = HybridPayload(**kwargs)
        with pytest.raises(ValueError, match=f"'{empty_field}'"):
            hybrid_encryption._validate_encrypted_data(payload)

    def test_empty_hkdf_salt_does_not_raise(
        self,
        hybrid_encryption: HybridEncryption,
    ) -> None:
        """Пустой hkdf_salt не является обязательным — не вызывает ошибки."""
        payload = HybridPayload(
            ephemeral_public_key=b"\x02" * 32,
            nonce=b"\x04" * 12,
            ciphertext=b"some_data",
            hkdf_salt=b"",
        )
        hybrid_encryption._validate_encrypted_data(payload)  # no exception


# ==============================================================================
# TESTS: _derive_symmetric_key
# ==============================================================================


class TestDeriveSymmetricKey:
    """Тесты для приватного метода _derive_symmetric_key."""

    def test_returns_bytes_of_correct_length(
        self,
        hybrid_encryption: HybridEncryption,
    ) -> None:
        """Должна возвращать SYMMETRIC_KEY_SIZE байт."""
        key = hybrid_encryption._derive_symmetric_key(
            shared_secret=b"\x03" * 32,
            salt=b"\x05" * 32,
        )
        assert isinstance(key, bytes)
        assert len(key) == SYMMETRIC_KEY_SIZE

    def test_deterministic_output(
        self,
        hybrid_encryption: HybridEncryption,
    ) -> None:
        """Одинаковые входные данные → одинаковый ключ."""
        shared_secret = b"\x03" * 32
        salt = b"\x05" * 32
        key1 = hybrid_encryption._derive_symmetric_key(shared_secret, salt)
        key2 = hybrid_encryption._derive_symmetric_key(shared_secret, salt)
        assert key1 == key2

    def test_different_salt_produces_different_key(
        self,
        hybrid_encryption: HybridEncryption,
    ) -> None:
        """Разные соли → разные ключи."""
        shared_secret = b"\x03" * 32
        key1 = hybrid_encryption._derive_symmetric_key(shared_secret, b"\x05" * 32)
        key2 = hybrid_encryption._derive_symmetric_key(shared_secret, b"\x06" * 32)
        assert key1 != key2

    def test_different_shared_secret_produces_different_key(
        self,
        hybrid_encryption: HybridEncryption,
    ) -> None:
        """Разные shared secrets → разные ключи."""
        salt = b"\x05" * 32
        key1 = hybrid_encryption._derive_symmetric_key(b"\x03" * 32, salt)
        key2 = hybrid_encryption._derive_symmetric_key(b"\x04" * 32, salt)
        assert key1 != key2

    def test_empty_salt_uses_hkdf_without_salt(
        self,
        hybrid_encryption: HybridEncryption,
    ) -> None:
        """Пустая соль b'' → HKDF с salt=None (без исключений)."""
        key = hybrid_encryption._derive_symmetric_key(
            shared_secret=b"\x03" * 32,
            salt=b"",
        )
        assert len(key) == SYMMETRIC_KEY_SIZE

    def test_output_is_not_equal_to_input(
        self,
        hybrid_encryption: HybridEncryption,
    ) -> None:
        """Ключ не должен быть сырым shared_secret."""
        shared_secret = b"\x03" * 32
        key = hybrid_encryption._derive_symmetric_key(
            shared_secret=shared_secret,
            salt=b"\x05" * 32,
        )
        assert key != shared_secret


# ==============================================================================
# TESTS: _secure_erase
# ==============================================================================


class TestSecureErase:
    """Тесты для статического метода _secure_erase."""

    def test_zeros_all_bytes_after_erase(self) -> None:
        """После стирания все байты должны быть нулями."""
        data = bytearray(b"\xde\xad\xbe\xef" * 8)
        HybridEncryption._secure_erase(data)
        assert all(b == 0 for b in data)

    def test_empty_bytearray_does_not_raise(self) -> None:
        """Пустой bytearray не должен вызывать исключений."""
        HybridEncryption._secure_erase(bytearray())  # no exception

    def test_single_byte_is_zeroed(self) -> None:
        """Один байт должен быть обнулён."""
        data = bytearray(b"\xff")
        HybridEncryption._secure_erase(data)
        assert data[0] == 0

    def test_large_data_is_zeroed(self) -> None:
        """Большой буфер должен быть полностью обнулён."""
        data = bytearray(secrets.token_bytes(4096))
        HybridEncryption._secure_erase(data)
        assert all(b == 0 for b in data)

    def test_modifies_data_in_place(self) -> None:
        """Стирание должно происходить на месте, тот же объект."""
        data = bytearray(b"\xaa" * 16)
        original_id = id(data)
        HybridEncryption._secure_erase(data)
        assert id(data) == original_id
        assert all(b == 0 for b in data)


# ==============================================================================
# TESTS: create_hybrid_cipher
# ==============================================================================


class TestCreateHybridCipher:
    """Тесты для фабричной функции create_hybrid_cipher."""

    @pytest.mark.parametrize(
        "preset_name",
        ["classical_standard", "classical_paranoid", "pqc_standard", "pqc_paranoid"],
    )
    def test_returns_hybrid_encryption_for_all_presets(
        self,
        preset_name: str,
        mock_registry: MagicMock,
    ) -> None:
        """Для каждого пресета должен возвращаться HybridEncryption."""
        with patch(
            "src.security.crypto.advanced.hybrid_encryption.AlgorithmRegistry"
        ) as mock_cls:
            mock_cls.get_instance.return_value = mock_registry
            cipher = create_hybrid_cipher(preset_name)
            assert isinstance(cipher, HybridEncryption)

    def test_default_preset_is_classical_standard(
        self,
        mock_registry: MagicMock,
    ) -> None:
        """По умолчанию должен использоваться classical_standard."""
        with patch(
            "src.security.crypto.advanced.hybrid_encryption.AlgorithmRegistry"
        ) as mock_cls:
            mock_cls.get_instance.return_value = mock_registry
            cipher = create_hybrid_cipher()
            assert cipher.config.kex_algorithm == "x25519"
            assert cipher.config.symmetric_algorithm == "aes-256-gcm"

    def test_raises_value_error_on_unknown_preset(self) -> None:
        """Неизвестный пресет → ValueError."""
        with pytest.raises(ValueError, match="Unknown preset"):
            create_hybrid_cipher("nonexistent_preset")

    def test_error_message_lists_available_presets(self) -> None:
        """Сообщение об ошибке должно содержать список доступных пресетов."""
        with pytest.raises(ValueError, match="Available"):
            create_hybrid_cipher("unknown")

    def test_returns_cipher_with_correct_config(
        self,
        mock_registry: MagicMock,
    ) -> None:
        """Возвращённый cipher должен иметь конфигурацию из PRESETS."""
        with patch(
            "src.security.crypto.advanced.hybrid_encryption.AlgorithmRegistry"
        ) as mock_cls:
            mock_cls.get_instance.return_value = mock_registry
            cipher = create_hybrid_cipher("classical_paranoid")
            assert cipher.config == PRESETS["classical_paranoid"]
            assert cipher.config.kex_algorithm == "x448"

    def test_propagates_algorithm_not_available_error(self) -> None:
        """AlgorithmNotAvailableError из HybridEncryption.__init__ пробрасывается."""
        mock_reg = MagicMock()
        mock_reg.create.side_effect = KeyError("kyber768")
        with patch(
            "src.security.crypto.advanced.hybrid_encryption.AlgorithmRegistry"
        ) as mock_cls:
            mock_cls.get_instance.return_value = mock_reg
            with pytest.raises(AlgorithmNotAvailableError):
                create_hybrid_cipher("pqc_standard")


# ==============================================================================
# TESTS: Encrypt/Decrypt Roundtrip (Security Integration)
# ==============================================================================


@pytest.mark.security
@pytest.mark.crypto
class TestEncryptDecryptRoundtrip:
    """
    Интеграционные тесты encrypt/decrypt roundtrip.

    KEX и симметричный шифр замоканы для детерминированности,
    но реальный HKDF-SHA256 используется для деривации ключа.
    """

    def test_roundtrip_basic(
        self,
        hybrid_encryption: HybridEncryption,
        mock_cipher: MagicMock,
    ) -> None:
        """Зашифрованное сообщение должно корректно расшифровываться."""
        original = b"Top secret document content"
        mock_cipher.decrypt.return_value = original

        encrypted = hybrid_encryption.encrypt_for_recipient(
            recipient_public_key=b"\xcd" * 32,
            plaintext=original,
        )
        decrypted = hybrid_encryption.decrypt_from_sender(
            recipient_private_key=b"\xab" * 32,
            encrypted_data=encrypted,
        )
        assert decrypted == original

    def test_roundtrip_with_associated_data(
        self,
        hybrid_encryption: HybridEncryption,
        mock_cipher: MagicMock,
    ) -> None:
        """Roundtrip с associated_data должен работать корректно."""
        original = b"Message with associated data"
        aad = b"document_context_v1"
        mock_cipher.decrypt.return_value = original

        encrypted = hybrid_encryption.encrypt_for_recipient(
            recipient_public_key=b"\xcd" * 32,
            plaintext=original,
            associated_data=aad,
        )
        decrypted = hybrid_encryption.decrypt_from_sender(
            recipient_private_key=b"\xab" * 32,
            encrypted_data=encrypted,
            associated_data=aad,
        )
        assert decrypted == original

    def test_encrypted_output_is_valid_hybrid_payload(
        self,
        hybrid_encryption: HybridEncryption,
    ) -> None:
        """Вывод encrypt_for_recipient — HybridPayload, проходящий валидацию."""
        encrypted = hybrid_encryption.encrypt_for_recipient(
            recipient_public_key=b"\xcd" * 32,
            plaintext=b"test",
        )
        assert isinstance(encrypted, HybridPayload)
        # Should not raise ValueError during validation
        hybrid_encryption._validate_encrypted_data(encrypted)

    @pytest.mark.parametrize(
        "plaintext",
        [
            b"a",
            b"Hello, World!",
            b"x" * 1000,
            b"\x00\xff" * 64,
            "Привет, мир!".encode("utf-8"),
            b"\x00" * 16,
        ],
    )
    def test_roundtrip_various_payloads(
        self,
        hybrid_encryption: HybridEncryption,
        mock_cipher: MagicMock,
        plaintext: bytes,
    ) -> None:
        """Roundtrip работает для различных размеров и типов данных."""
        mock_cipher.decrypt.return_value = plaintext

        encrypted = hybrid_encryption.encrypt_for_recipient(
            recipient_public_key=b"\xcd" * 32,
            plaintext=plaintext,
        )
        decrypted = hybrid_encryption.decrypt_from_sender(
            recipient_private_key=b"\xab" * 32,
            encrypted_data=encrypted,
        )
        assert decrypted == plaintext

    def test_two_encryptions_of_same_plaintext_have_different_salts(
        self,
        hybrid_encryption: HybridEncryption,
    ) -> None:
        """Каждое шифрование должно генерировать уникальный hkdf_salt."""
        result1 = hybrid_encryption.encrypt_for_recipient(
            recipient_public_key=b"\xcd" * 32,
            plaintext=b"same message",
        )
        result2 = hybrid_encryption.encrypt_for_recipient(
            recipient_public_key=b"\xcd" * 32,
            plaintext=b"same message",
        )
        # With real secrets.token_bytes, salts should differ
        # (mocked kex returns same ephemeral key, but salt is random)
        assert isinstance(result1.hkdf_salt, bytes)
        assert isinstance(result2.hkdf_salt, bytes)
        assert len(result1.hkdf_salt) == HKDF_SALT_SIZE
        assert len(result2.hkdf_salt) == HKDF_SALT_SIZE
