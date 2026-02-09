"""
Unit-тесты для метаданных криптографических алгоритмов.

Проверяет:
- Все Enum классы (AlgorithmCategory, SecurityLevel, FloppyFriendly, ImplementationStatus)
- AlgorithmMetadata dataclass
- Validation правила
- Factory functions
- Сериализация/десериализация

Coverage target: ≥95%
"""

import pytest
from typing import Dict, Any

from src.security.crypto.core.metadata import (
    AlgorithmCategory,
    AlgorithmMetadata,
    FloppyFriendly,
    ImplementationStatus,
    SecurityLevel,
    create_asymmetric_encryption_metadata,
    create_hash_metadata,
    create_kdf_metadata,
    create_key_exchange_metadata,
    create_signature_metadata,
    create_symmetric_metadata,
)
from src.security.crypto.core.protocols import (
    AsymmetricEncryptionProtocol,
    HashProtocol,
    KDFProtocol,
    KeyExchangeProtocol,
    SignatureProtocol,
    SymmetricCipherProtocol,
)


# ==============================================================================
# TEST: AlgorithmCategory
# ==============================================================================


class TestAlgorithmCategory:
    """Тесты для AlgorithmCategory enum."""

    def test_enum_values(self) -> None:
        """Все значения enum определены."""
        assert AlgorithmCategory.SYMMETRIC_CIPHER.value == "symmetric_cipher"
        assert AlgorithmCategory.SIGNATURE.value == "signature"
        assert AlgorithmCategory.ASYMMETRIC_ENCRYPTION.value == "asymmetric_encryption"
        assert AlgorithmCategory.KEY_EXCHANGE.value == "key_exchange"
        assert AlgorithmCategory.HASH.value == "hash"
        assert AlgorithmCategory.KDF.value == "kdf"

    def test_label_method(self) -> None:
        """Метод label() возвращает русские названия."""
        assert AlgorithmCategory.SYMMETRIC_CIPHER.label() == "Симметричное шифрование"
        assert AlgorithmCategory.SIGNATURE.label() == "Цифровая подпись"
        assert (
            AlgorithmCategory.ASYMMETRIC_ENCRYPTION.label()
            == "Асимметричное шифрование"
        )
        assert AlgorithmCategory.KEY_EXCHANGE.label() == "Обмен ключами"
        assert AlgorithmCategory.HASH.label() == "Хеширование"
        assert AlgorithmCategory.KDF.label() == "Вывод ключей"

    def test_from_str_lowercase(self) -> None:
        """Парсинг из строки (lowercase)."""
        category = AlgorithmCategory.from_str("symmetric_cipher")
        assert category == AlgorithmCategory.SYMMETRIC_CIPHER

    def test_from_str_uppercase(self) -> None:
        """Парсинг из строки (uppercase)."""
        category = AlgorithmCategory.from_str("SYMMETRIC_CIPHER")
        assert category == AlgorithmCategory.SYMMETRIC_CIPHER

    def test_from_str_invalid(self) -> None:
        """Парсинг некорректной строки выбрасывает ValueError."""
        with pytest.raises(ValueError, match="Неизвестная категория алгоритма"):
            AlgorithmCategory.from_str("invalid_category")

    def test_enum_is_str_subclass(self) -> None:
        """Enum наследует str для JSON сериализации."""
        category = AlgorithmCategory.SYMMETRIC_CIPHER

        # Enum значение можно использовать как строку
        assert isinstance(category, str)
        assert category == "symmetric_cipher"

        # Enum имеет .value атрибут
        assert AlgorithmCategory.SYMMETRIC_CIPHER.value == "symmetric_cipher"


# ==============================================================================
# TEST: SecurityLevel
# ==============================================================================


class TestSecurityLevel:
    """Тесты для SecurityLevel enum."""

    def test_enum_values(self) -> None:
        """Все значения enum определены."""
        assert SecurityLevel.BROKEN.value == "broken"
        assert SecurityLevel.LEGACY.value == "legacy"
        assert SecurityLevel.STANDARD.value == "standard"
        assert SecurityLevel.HIGH.value == "high"
        assert SecurityLevel.QUANTUM_RESISTANT.value == "quantum"

    def test_label_method(self) -> None:
        """Метод label() возвращает русские названия."""
        assert SecurityLevel.BROKEN.label() == "Сломан"
        assert SecurityLevel.LEGACY.label() == "Устаревший"
        assert SecurityLevel.STANDARD.label() == "Стандартный"
        assert SecurityLevel.HIGH.label() == "Повышенный"
        assert SecurityLevel.QUANTUM_RESISTANT.label() == "Постквантовый"

    def test_is_safe_for_new_systems_broken(self) -> None:
        """BROKEN не безопасен для новых систем."""
        assert not SecurityLevel.BROKEN.is_safe_for_new_systems()

    def test_is_safe_for_new_systems_legacy(self) -> None:
        """LEGACY не безопасен для новых систем."""
        assert not SecurityLevel.LEGACY.is_safe_for_new_systems()

    @pytest.mark.parametrize(
        "level",
        [
            SecurityLevel.STANDARD,
            SecurityLevel.HIGH,
            SecurityLevel.QUANTUM_RESISTANT,
        ],
    )
    def test_is_safe_for_new_systems_safe(self, level: SecurityLevel) -> None:
        """STANDARD, HIGH, QUANTUM_RESISTANT безопасны для новых систем."""
        assert level.is_safe_for_new_systems()

    def test_emoji_method(self) -> None:
        """Метод emoji() возвращает корректные эмоджи."""
        assert SecurityLevel.BROKEN.emoji() == "⛔"
        assert SecurityLevel.LEGACY.emoji() == "⚠️"
        assert SecurityLevel.STANDARD.emoji() == "✅"
        assert SecurityLevel.HIGH.emoji() == "🏆"
        assert SecurityLevel.QUANTUM_RESISTANT.emoji() == "🛡️"


# ==============================================================================
# TEST: FloppyFriendly
# ==============================================================================


class TestFloppyFriendly:
    """Тесты для FloppyFriendly enum."""

    def test_enum_values(self) -> None:
        """Все значения enum определены."""
        assert FloppyFriendly.EXCELLENT.value == 1
        assert FloppyFriendly.ACCEPTABLE.value == 2
        assert FloppyFriendly.POOR.value == 3

    def test_label_method(self) -> None:
        """Метод label() возвращает русские названия."""
        assert FloppyFriendly.EXCELLENT.label() == "Отлично"
        assert FloppyFriendly.ACCEPTABLE.label() == "Приемлемо"
        assert FloppyFriendly.POOR.label() == "Плохо"

    def test_emoji_method(self) -> None:
        """Метод emoji() возвращает корректные эмоджи."""
        assert FloppyFriendly.EXCELLENT.emoji() == "💚"
        assert FloppyFriendly.ACCEPTABLE.emoji() == "💛"
        assert FloppyFriendly.POOR.emoji() == "❌"

    def test_from_size_excellent(self) -> None:
        """Размер < 100 байт = EXCELLENT."""
        assert FloppyFriendly.from_size(32) == FloppyFriendly.EXCELLENT
        assert FloppyFriendly.from_size(99) == FloppyFriendly.EXCELLENT

    def test_from_size_acceptable(self) -> None:
        """Размер 100-999 байт = ACCEPTABLE."""
        assert FloppyFriendly.from_size(100) == FloppyFriendly.ACCEPTABLE
        assert FloppyFriendly.from_size(500) == FloppyFriendly.ACCEPTABLE
        assert FloppyFriendly.from_size(999) == FloppyFriendly.ACCEPTABLE

    def test_from_size_poor(self) -> None:
        """Размер ≥ 1000 байт = POOR."""
        assert FloppyFriendly.from_size(1000) == FloppyFriendly.POOR
        assert FloppyFriendly.from_size(5000) == FloppyFriendly.POOR

    def test_comparison(self) -> None:
        """Enum можно сравнивать (наследует int)."""
        assert FloppyFriendly.EXCELLENT < FloppyFriendly.ACCEPTABLE
        assert FloppyFriendly.ACCEPTABLE < FloppyFriendly.POOR
        assert FloppyFriendly.EXCELLENT < FloppyFriendly.POOR


# ==============================================================================
# TEST: ImplementationStatus
# ==============================================================================


class TestImplementationStatus:
    """Тесты для ImplementationStatus enum."""

    def test_enum_values(self) -> None:
        """Все значения enum определены."""
        assert ImplementationStatus.STABLE.value == "stable"
        assert ImplementationStatus.EXPERIMENTAL.value == "experimental"
        assert ImplementationStatus.DEPRECATED.value == "deprecated"

    def test_label_method(self) -> None:
        """Метод label() возвращает русские названия."""
        assert ImplementationStatus.STABLE.label() == "Стабильный"
        assert ImplementationStatus.EXPERIMENTAL.label() == "Экспериментальный"
        assert ImplementationStatus.DEPRECATED.label() == "Устаревший"


# ==============================================================================
# TEST: AlgorithmMetadata
# ==============================================================================


class TestAlgorithmMetadata:
    """Тесты для AlgorithmMetadata dataclass."""

    @pytest.fixture
    def valid_symmetric_metadata(self) -> AlgorithmMetadata:
        """Fixture для валидных метаданных симметричного шифра."""
        return AlgorithmMetadata(
            name="AES-256-GCM",
            category=AlgorithmCategory.SYMMETRIC_CIPHER,
            protocol_class=SymmetricCipherProtocol,
            library="cryptography",
            implementation_class="cryptography.hazmat.primitives.ciphers.aead.AESGCM",
            security_level=SecurityLevel.STANDARD,
            floppy_friendly=FloppyFriendly.EXCELLENT,
            status=ImplementationStatus.STABLE,
            key_size=32,
            nonce_size=12,
            is_aead=True,
            description_ru="AES-256 в режиме Galois/Counter Mode",
        )

    def test_create_valid_metadata(
        self, valid_symmetric_metadata: AlgorithmMetadata
    ) -> None:
        """Создание валидных метаданных."""
        assert valid_symmetric_metadata.name == "AES-256-GCM"
        assert valid_symmetric_metadata.category == AlgorithmCategory.SYMMETRIC_CIPHER
        assert valid_symmetric_metadata.key_size == 32
        assert valid_symmetric_metadata.nonce_size == 12
        assert valid_symmetric_metadata.is_aead is True

    def test_metadata_is_frozen(
        self, valid_symmetric_metadata: AlgorithmMetadata
    ) -> None:
        """Метаданные immutable (frozen)."""
        with pytest.raises(AttributeError):
            valid_symmetric_metadata.name = "Changed"  # type: ignore

    def test_is_safe_for_production_stable_standard(self) -> None:
        """STABLE + STANDARD = safe for production."""
        metadata = AlgorithmMetadata(
            name="Test",
            category=AlgorithmCategory.HASH,
            protocol_class=HashProtocol,
            library="hashlib",
            implementation_class="hashlib.sha256",
            security_level=SecurityLevel.STANDARD,
            floppy_friendly=FloppyFriendly.EXCELLENT,
            status=ImplementationStatus.STABLE,
            digest_size=32,
        )
        assert metadata.is_safe_for_production()

    def test_is_safe_for_production_experimental(self) -> None:
        """EXPERIMENTAL = NOT safe for production."""
        metadata = AlgorithmMetadata(
            name="Test",
            category=AlgorithmCategory.HASH,
            protocol_class=HashProtocol,
            library="hashlib",
            implementation_class="hashlib.sha256",
            security_level=SecurityLevel.STANDARD,
            floppy_friendly=FloppyFriendly.EXCELLENT,
            status=ImplementationStatus.EXPERIMENTAL,
            digest_size=32,
        )
        assert not metadata.is_safe_for_production()

    def test_is_safe_for_production_broken(self) -> None:
        """BROKEN = NOT safe for production."""
        metadata = AlgorithmMetadata(
            name="Test",
            category=AlgorithmCategory.SYMMETRIC_CIPHER,
            protocol_class=SymmetricCipherProtocol,
            library="cryptography",
            implementation_class="test",
            security_level=SecurityLevel.BROKEN,
            floppy_friendly=FloppyFriendly.EXCELLENT,
            status=ImplementationStatus.STABLE,
            key_size=8,
            nonce_size=8,
        )
        assert not metadata.is_safe_for_production()

    def test_total_overhead_bytes(
        self, valid_symmetric_metadata: AlgorithmMetadata
    ) -> None:
        """Расчёт total_overhead_bytes."""
        # key_size = 32
        assert valid_symmetric_metadata.total_overhead_bytes() == 32

    def test_total_overhead_bytes_signature(self) -> None:
        """Расчёт total_overhead_bytes для подписи."""
        metadata = AlgorithmMetadata(
            name="Ed25519",
            category=AlgorithmCategory.SIGNATURE,
            protocol_class=SignatureProtocol,
            library="cryptography",
            implementation_class="cryptography.hazmat.primitives.asymmetric.ed25519",
            security_level=SecurityLevel.STANDARD,
            floppy_friendly=FloppyFriendly.EXCELLENT,
            status=ImplementationStatus.STABLE,
            signature_size=64,
            public_key_size=32,
            private_key_size=32,
        )
        # 64 + 32 + 32 = 128
        assert metadata.total_overhead_bytes() == 128


# ==============================================================================
# TEST: AlgorithmMetadata Validation
# ==============================================================================


class TestAlgorithmMetadataValidation:
    """Тесты валидации AlgorithmMetadata."""

    def test_empty_name_raises_error(self) -> None:
        """Пустое имя выбрасывает ValueError."""
        with pytest.raises(ValueError, match="name не может быть пустым"):
            AlgorithmMetadata(
                name="",
                category=AlgorithmCategory.HASH,
                protocol_class=HashProtocol,
                library="hashlib",
                implementation_class="hashlib.sha256",
                security_level=SecurityLevel.STANDARD,
                floppy_friendly=FloppyFriendly.EXCELLENT,
                status=ImplementationStatus.STABLE,
                digest_size=32,
            )

    def test_invalid_library_raises_error(self) -> None:
        """Некорректная библиотека выбрасывает ValueError."""
        with pytest.raises(ValueError, match="Неизвестная библиотека"):
            AlgorithmMetadata(
                name="Test",
                category=AlgorithmCategory.HASH,
                protocol_class=HashProtocol,
                library="unknown_lib",
                implementation_class="test",
                security_level=SecurityLevel.STANDARD,
                floppy_friendly=FloppyFriendly.EXCELLENT,
                status=ImplementationStatus.STABLE,
                digest_size=32,
            )

    def test_symmetric_cipher_requires_key_size(self) -> None:
        """Симметричный шифр требует key_size."""
        with pytest.raises(
            ValueError, match="Симметричный шифр .* требует key_size и nonce_size"
        ):
            AlgorithmMetadata(
                name="AES-256-GCM",
                category=AlgorithmCategory.SYMMETRIC_CIPHER,
                protocol_class=SymmetricCipherProtocol,
                library="cryptography",
                implementation_class="test",
                security_level=SecurityLevel.STANDARD,
                floppy_friendly=FloppyFriendly.EXCELLENT,
                status=ImplementationStatus.STABLE,
                # Отсутствует key_size и nonce_size
            )

    def test_signature_requires_signature_size(self) -> None:
        """Алгоритм подписи требует signature_size."""
        with pytest.raises(
            ValueError, match="Алгоритм подписи .* требует signature_size"
        ):
            AlgorithmMetadata(
                name="Ed25519",
                category=AlgorithmCategory.SIGNATURE,
                protocol_class=SignatureProtocol,
                library="cryptography",
                implementation_class="test",
                security_level=SecurityLevel.STANDARD,
                floppy_friendly=FloppyFriendly.EXCELLENT,
                status=ImplementationStatus.STABLE,
                # Отсутствует signature_size
            )

    def test_hash_requires_digest_size(self) -> None:
        """Хеш-функция требует digest_size."""
        with pytest.raises(ValueError, match="Хеш-функция .* требует digest_size"):
            AlgorithmMetadata(
                name="SHA-256",
                category=AlgorithmCategory.HASH,
                protocol_class=HashProtocol,
                library="hashlib",
                implementation_class="test",
                security_level=SecurityLevel.STANDARD,
                floppy_friendly=FloppyFriendly.EXCELLENT,
                status=ImplementationStatus.STABLE,
                # Отсутствует digest_size
            )

    def test_negative_key_size_raises_error(self) -> None:
        """Отрицательный key_size выбрасывает ValueError."""
        with pytest.raises(ValueError, match="key_size должен быть > 0"):
            AlgorithmMetadata(
                name="AES-256-GCM",
                category=AlgorithmCategory.SYMMETRIC_CIPHER,
                protocol_class=SymmetricCipherProtocol,
                library="cryptography",
                implementation_class="test",
                security_level=SecurityLevel.STANDARD,
                floppy_friendly=FloppyFriendly.EXCELLENT,
                status=ImplementationStatus.STABLE,
                key_size=-32,  # Некорректно
                nonce_size=12,
            )

    def test_post_quantum_requires_quantum_resistant_level(self) -> None:
        """Постквантовый алгоритм требует security_level=QUANTUM_RESISTANT."""
        with pytest.raises(
            ValueError,
            match="Постквантовый алгоритм .* должен иметь security_level=QUANTUM_RESISTANT",
        ):
            AlgorithmMetadata(
                name="Dilithium3",
                category=AlgorithmCategory.SIGNATURE,
                protocol_class=SignatureProtocol,
                library="liboqs-python",
                implementation_class="test",
                security_level=SecurityLevel.STANDARD,  # Должно быть QUANTUM_RESISTANT
                floppy_friendly=FloppyFriendly.POOR,
                status=ImplementationStatus.STABLE,
                signature_size=3293,
                public_key_size=1952,
                private_key_size=4016,
                is_post_quantum=True,
            )


# ==============================================================================
# TEST: AlgorithmMetadata Serialization
# ==============================================================================


class TestAlgorithmMetadataSerialization:
    """Тесты сериализации/десериализации метаданных."""

    @pytest.fixture
    def sample_metadata(self) -> AlgorithmMetadata:
        """Fixture для метаданных."""
        return AlgorithmMetadata(
            name="AES-256-GCM",
            category=AlgorithmCategory.SYMMETRIC_CIPHER,
            protocol_class=SymmetricCipherProtocol,
            library="cryptography",
            implementation_class="cryptography.hazmat.primitives.ciphers.aead.AESGCM",
            security_level=SecurityLevel.STANDARD,
            floppy_friendly=FloppyFriendly.EXCELLENT,
            status=ImplementationStatus.STABLE,
            key_size=32,
            nonce_size=12,
            is_aead=True,
            description_ru="Тестовое описание",
            use_cases=["Шифрование файлов", "TLS"],
            extra={"custom_field": "value"},
        )

    def test_to_dict(self, sample_metadata: AlgorithmMetadata) -> None:
        """Сериализация в словарь."""
        data = sample_metadata.to_dict()

        assert isinstance(data, dict)
        assert data["name"] == "AES-256-GCM"
        assert data["category"] == "symmetric_cipher"
        assert data["security_level"] == "standard"
        assert data["floppy_friendly"] == 1
        assert data["key_size"] == 32
        assert data["is_aead"] is True
        assert data["use_cases"] == ["Шифрование файлов", "TLS"]
        assert data["extra"] == {"custom_field": "value"}

    def test_from_dict(self, sample_metadata: AlgorithmMetadata) -> None:
        """Десериализация из словаря."""
        data = sample_metadata.to_dict()
        restored = AlgorithmMetadata.from_dict(data)

        assert restored.name == sample_metadata.name
        assert restored.category == sample_metadata.category
        assert restored.security_level == sample_metadata.security_level
        assert restored.key_size == sample_metadata.key_size
        assert restored.is_aead == sample_metadata.is_aead

    def test_to_dict_from_dict_roundtrip(
        self, sample_metadata: AlgorithmMetadata
    ) -> None:
        """Roundtrip: to_dict → from_dict → to_dict."""
        data1 = sample_metadata.to_dict()
        restored = AlgorithmMetadata.from_dict(data1)
        data2 = restored.to_dict()

        # Сравнить все поля кроме protocol_class (не сериализуется)
        for key in data1:
            if key != "protocol_class":
                assert data1[key] == data2[key]


# ==============================================================================
# TEST: Factory Functions
# ==============================================================================


class TestFactoryFunctions:
    """Тесты factory functions."""

    def test_create_symmetric_metadata(self) -> None:
        """create_symmetric_metadata создаёт валидные метаданные."""
        metadata = create_symmetric_metadata(
            name="AES-256-GCM",
            library="cryptography",
            implementation_class="cryptography.hazmat.primitives.ciphers.aead.AESGCM",
            key_size=32,
            nonce_size=12,
            description_ru="Тест",
        )

        assert metadata.name == "AES-256-GCM"
        assert metadata.category == AlgorithmCategory.SYMMETRIC_CIPHER
        assert metadata.protocol_class == SymmetricCipherProtocol
        assert metadata.key_size == 32
        assert metadata.nonce_size == 12
        assert metadata.is_aead is True  # По умолчанию True
        assert metadata.floppy_friendly == FloppyFriendly.EXCELLENT

    def test_create_signature_metadata(self) -> None:
        """create_signature_metadata создаёт валидные метаданные."""
        metadata = create_signature_metadata(
            name="Ed25519",
            library="cryptography",
            implementation_class="cryptography.hazmat.primitives.asymmetric.ed25519",
            signature_size=64,
            public_key_size=32,
            private_key_size=32,
            description_ru="Тест",
        )

        assert metadata.name == "Ed25519"
        assert metadata.category == AlgorithmCategory.SIGNATURE
        assert metadata.protocol_class == SignatureProtocol
        assert metadata.signature_size == 64
        assert metadata.public_key_size == 32
        assert metadata.private_key_size == 32
        assert metadata.is_post_quantum is False
        # Floppy overhead: signature + public key = 64 + 32 = 96 < 100 → EXCELLENT
        assert metadata.floppy_friendly == FloppyFriendly.EXCELLENT  # 128 байт

    def test_create_signature_metadata_post_quantum(self) -> None:
        """create_signature_metadata для PQC автоматически ставит QUANTUM_RESISTANT."""
        metadata = create_signature_metadata(
            name="Dilithium3",
            library="liboqs-python",
            implementation_class="oqs.Signature",
            signature_size=3293,
            public_key_size=1952,
            private_key_size=4016,
            is_post_quantum=True,
            description_ru="Тест",
        )

        assert metadata.is_post_quantum is True
        assert metadata.security_level == SecurityLevel.QUANTUM_RESISTANT
        assert metadata.floppy_friendly == FloppyFriendly.POOR  # > 1000 байт

    def test_create_asymmetric_encryption_metadata(self) -> None:
        """create_asymmetric_encryption_metadata создаёт валидные метаданные."""
        metadata = create_asymmetric_encryption_metadata(
            name="RSA-OAEP-2048",
            library="cryptography",
            implementation_class="cryptography.hazmat.primitives.asymmetric.rsa",
            key_size=2048,
            max_plaintext_size=190,
            description_ru="Тест",
        )

        assert metadata.name == "RSA-OAEP-2048"
        assert metadata.category == AlgorithmCategory.ASYMMETRIC_ENCRYPTION
        assert metadata.protocol_class == AsymmetricEncryptionProtocol
        assert metadata.key_size == 2048
        assert metadata.max_plaintext_size == 190
        assert metadata.floppy_friendly == FloppyFriendly.ACCEPTABLE  # 256 байт

    def test_create_key_exchange_metadata(self) -> None:
        """create_key_exchange_metadata создаёт валидные метаданные."""
        metadata = create_key_exchange_metadata(
            name="X25519",
            library="cryptography",
            implementation_class="cryptography.hazmat.primitives.asymmetric.x25519",
            shared_secret_size=32,
            public_key_size=32,
            private_key_size=32,
            description_ru="Тест",
        )

        assert metadata.name == "X25519"
        assert metadata.category == AlgorithmCategory.KEY_EXCHANGE
        assert metadata.protocol_class == KeyExchangeProtocol
        assert metadata.public_key_size == 32
        assert metadata.private_key_size == 32
        assert metadata.extra["shared_secret_size"] == 32
        assert metadata.floppy_friendly == FloppyFriendly.EXCELLENT  # 64 байт

    def test_create_hash_metadata(self) -> None:
        """create_hash_metadata создаёт валидные метаданные."""
        metadata = create_hash_metadata(
            name="SHA-256",
            library="hashlib",
            implementation_class="hashlib.sha256",
            digest_size=32,
            description_ru="Тест",
        )

        assert metadata.name == "SHA-256"
        assert metadata.category == AlgorithmCategory.HASH
        assert metadata.protocol_class == HashProtocol
        assert metadata.digest_size == 32
        assert metadata.floppy_friendly == FloppyFriendly.EXCELLENT  # 32 байт

    def test_create_kdf_metadata(self) -> None:
        """create_kdf_metadata создаёт валидные метаданные."""
        metadata = create_kdf_metadata(
            name="Argon2id",
            library="argon2-cffi",
            implementation_class="argon2.PasswordHasher",
            recommended_iterations=3,
            recommended_memory_cost=65536,
            description_ru="Тест",
        )

        assert metadata.name == "Argon2id"
        assert metadata.category == AlgorithmCategory.KDF
        assert metadata.protocol_class == KDFProtocol
        assert metadata.extra["recommended_iterations"] == 3
        assert metadata.extra["recommended_memory_cost"] == 65536
        assert (
            metadata.floppy_friendly == FloppyFriendly.EXCELLENT
        )  # KDF всегда EXCELLENT

    def test_factory_with_use_cases(self) -> None:
        """Factory functions поддерживают use_cases."""
        metadata = create_symmetric_metadata(
            name="ChaCha20-Poly1305",
            library="cryptography",
            implementation_class="cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305",
            key_size=32,
            nonce_size=12,
            use_cases=["Мобильные приложения", "IoT устройства"],
        )

        assert metadata.use_cases == ["Мобильные приложения", "IoT устройства"]

    def test_factory_with_extra(self) -> None:
        """Factory functions поддерживают extra параметры."""
        metadata = create_hash_metadata(
            name="BLAKE3",
            library="blake3-py",
            implementation_class="blake3.blake3",
            digest_size=32,
            extra={"max_digest_size": 256, "parallelizable": True},
        )

        assert metadata.extra["max_digest_size"] == 256
        assert metadata.extra["parallelizable"] is True


# ==============================================================================
# TEST: Edge Cases
# ==============================================================================


class TestEdgeCases:
    """Тесты граничных случаев."""

    def test_metadata_with_all_optional_fields_none(self) -> None:
        """Метаданные с минимальным набором полей."""
        metadata = AlgorithmMetadata(
            name="Minimal",
            category=AlgorithmCategory.HASH,
            protocol_class=HashProtocol,
            library="hashlib",
            implementation_class="test",
            security_level=SecurityLevel.STANDARD,
            floppy_friendly=FloppyFriendly.EXCELLENT,
            status=ImplementationStatus.STABLE,
            digest_size=32,
        )

        assert metadata.key_size is None
        assert metadata.signature_size is None
        assert metadata.public_key_size is None
        assert metadata.private_key_size is None
        assert metadata.nonce_size is None
        assert metadata.is_aead is False
        assert metadata.is_post_quantum is False
        assert metadata.description_ru == ""
        assert metadata.description_en == ""
        assert metadata.use_cases == []
        assert metadata.extra == {}

    def test_floppy_friendly_boundary_99(self) -> None:
        """Граница EXCELLENT/ACCEPTABLE: 99 байт."""
        assert FloppyFriendly.from_size(99) == FloppyFriendly.EXCELLENT

    def test_floppy_friendly_boundary_100(self) -> None:
        """Граница EXCELLENT/ACCEPTABLE: 100 байт."""
        assert FloppyFriendly.from_size(100) == FloppyFriendly.ACCEPTABLE

    def test_floppy_friendly_boundary_999(self) -> None:
        """Граница ACCEPTABLE/POOR: 999 байт."""
        assert FloppyFriendly.from_size(999) == FloppyFriendly.ACCEPTABLE

    def test_floppy_friendly_boundary_1000(self) -> None:
        """Граница ACCEPTABLE/POOR: 1000 байт."""
        assert FloppyFriendly.from_size(1000) == FloppyFriendly.POOR

    def test_metadata_with_zero_overhead(self) -> None:
        """Метаданные без размеров (total_overhead = 0)."""
        metadata = AlgorithmMetadata(
            name="Test",
            category=AlgorithmCategory.HASH,
            protocol_class=HashProtocol,
            library="hashlib",
            implementation_class="test",
            security_level=SecurityLevel.STANDARD,
            floppy_friendly=FloppyFriendly.EXCELLENT,
            status=ImplementationStatus.STABLE,
            digest_size=32,
        )

        assert metadata.total_overhead_bytes() == 0


# ==============================================================================
# TEST: Module Exports
# ==============================================================================


class TestModuleExports:
    """Тесты для exports модуля."""

    def test_all_enums_exported(self) -> None:
        """Все Enum классы экспортированы."""
        from src.security.crypto.core import metadata

        assert hasattr(metadata, "AlgorithmCategory")
        assert hasattr(metadata, "SecurityLevel")
        assert hasattr(metadata, "FloppyFriendly")
        assert hasattr(metadata, "ImplementationStatus")

    def test_dataclass_exported(self) -> None:
        """AlgorithmMetadata экспортирован."""
        from src.security.crypto.core import metadata

        assert hasattr(metadata, "AlgorithmMetadata")

    def test_all_factory_functions_exported(self) -> None:
        """Все factory functions экспортированы."""
        from src.security.crypto.core import metadata

        assert hasattr(metadata, "create_symmetric_metadata")
        assert hasattr(metadata, "create_signature_metadata")
        assert hasattr(metadata, "create_asymmetric_encryption_metadata")
        assert hasattr(metadata, "create_key_exchange_metadata")
        assert hasattr(metadata, "create_hash_metadata")
        assert hasattr(metadata, "create_kdf_metadata")

    def test_module_has_all_attribute(self) -> None:
        """Модуль имеет __all__ с корректными экспортами."""
        from src.security.crypto.core import metadata

        assert hasattr(metadata, "__all__")
        assert len(metadata.__all__) == 11  # 4 enum + 1 dataclass + 6 factories

    def test_module_version_metadata(self) -> None:
        """Модуль имеет метаданные версии."""
        from src.security.crypto.core import metadata

        assert hasattr(metadata, "__version__")
        assert hasattr(metadata, "__author__")
        assert hasattr(metadata, "__date__")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.security.crypto.core.metadata"])
