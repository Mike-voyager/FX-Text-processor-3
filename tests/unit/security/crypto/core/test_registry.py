"""
Unit-тесты для реестра криптографических алгоритмов.

Проверяет:
- Singleton паттерн
- Thread-safety (concurrent доступ)
- Регистрацию алгоритмов с валидацией Protocol
- Создание экземпляров
- Query API (search, list_by_category и т.д.)
- Статистику
- Error handling

Coverage target: ≥95%
"""

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, List, Optional, Tuple, Generator

import pytest

from src.security.crypto.core.metadata import (
    AlgorithmCategory,
    AlgorithmMetadata,
    FloppyFriendly,
    ImplementationStatus,
    SecurityLevel,
    create_hash_metadata,
    create_signature_metadata,
    create_symmetric_metadata,
)
from src.security.crypto.core.protocols import (
    HashProtocol,
    SignatureProtocol,
    SymmetricCipherProtocol,
)
from src.security.crypto.core.registry import (
    AlgorithmRegistry,
    ProtocolError,
    RegistryEntry,
    RegistryError,
    RegistryStatistics,
    register_all_algorithms,
)


# ==============================================================================
# MOCK ALGORITHMS (реализуют Protocol для тестов)
# ==============================================================================


class MockSymmetricCipher:
    """Mock симметричного шифра для тестов."""

    metadata = create_symmetric_metadata(
        name="Mock-AES-256-GCM",
        library="cryptography",
        implementation_class="tests.mocks.MockSymmetricCipher",
        key_size=32,
        nonce_size=12,
        is_aead=True,
        description_ru="Mock AES-256-GCM для тестов",
    )

    @property
    def algorithm_name(self) -> str:
        return self.metadata.name

    @property
    def key_size(self) -> int:
        return 32

    @property
    def nonce_size(self) -> int:
        return 12

    @property
    def is_aead(self) -> bool:
        return True

    def encrypt(
        self,
        key: bytes,
        plaintext: bytes,
        *,
        nonce: Optional[bytes] = None,
        associated_data: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        return b"ciphertext", b"tag"

    def decrypt(
        self,
        key: bytes,
        ciphertext: bytes,
        tag: bytes,
        *,
        nonce: Optional[bytes] = None,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        return b"plaintext"

    def generate_key(self) -> bytes:
        return b"0" * 32

    def generate_nonce(self) -> bytes:
        return b"0" * 12


class MockSignature:
    """Mock алгоритма подписи для тестов."""

    metadata = create_signature_metadata(
        name="Mock-Ed25519",
        library="cryptography",
        implementation_class="tests.mocks.MockSignature",
        signature_size=64,
        public_key_size=32,
        private_key_size=32,
        description_ru="Mock Ed25519 для тестов",
    )

    @property
    def algorithm_name(self) -> str:
        return self.metadata.name

    @property
    def signature_size(self) -> int:
        return 64

    @property
    def public_key_size(self) -> int:
        return 32

    @property
    def private_key_size(self) -> int:
        return 32

    @property
    def is_post_quantum(self) -> bool:
        return False

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        return b"private" * 4, b"public" * 4

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        return b"signature" * 8

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return True


class MockHash:
    """Mock хеш-функции для тестов."""

    metadata = create_hash_metadata(
        name="Mock-SHA-256",
        library="hashlib",
        implementation_class="tests.mocks.MockHash",
        digest_size=32,
        description_ru="Mock SHA-256 для тестов",
    )

    @property
    def algorithm_name(self) -> str:
        return self.metadata.name

    @property
    def digest_size(self) -> int:
        return 32

    def hash(self, data: bytes) -> bytes:
        return b"0" * 32

    def hash_file(self, filepath: str) -> bytes:
        return b"0" * 32


    def hash_stream(self, stream) -> bytes:
        return b"0" * 32

class MockPostQuantumSignature:
    """Mock постквантовой подписи для тестов."""

    metadata = create_signature_metadata(
        name="Mock-Dilithium3",
        library="liboqs-python",
        implementation_class="tests.mocks.MockPostQuantumSignature",
        signature_size=3293,
        public_key_size=1952,
        private_key_size=4016,
        is_post_quantum=True,
        description_ru="Mock Dilithium3 для тестов",
    )

    @property
    def algorithm_name(self) -> str:
        return self.metadata.name

    @property
    def signature_size(self) -> int:
        return 3293

    @property
    def public_key_size(self) -> int:
        return 1952

    @property
    def private_key_size(self) -> int:
        return 4016

    @property
    def is_post_quantum(self) -> bool:
        return True

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        return b"x" * 4016, b"y" * 1952

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        return b"z" * 3293

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return True


class MockInvalidAlgorithm:
    """Mock класс, который НЕ реализует Protocol (для негативных тестов)."""

    metadata = create_symmetric_metadata(
        name="Invalid-Algo",
        library="cryptography",
        implementation_class="tests.mocks.MockInvalidAlgorithm",
        key_size=32,
        nonce_size=12,
    )

    # НЕ реализует методы SymmetricCipherProtocol!


# ==============================================================================
# FIXTURES
# ==============================================================================


@pytest.fixture(autouse=True)
def reset_registry() -> Generator[None, None, None]:
    """Автоматически сбрасывать singleton перед каждым тестом."""
    AlgorithmRegistry.reset_instance()
    yield
    AlgorithmRegistry.reset_instance()


@pytest.fixture
def registry() -> AlgorithmRegistry:
    """Fixture для получения свежего registry instance."""
    return AlgorithmRegistry.get_instance()


@pytest.fixture
def populated_registry(registry: AlgorithmRegistry) -> AlgorithmRegistry:
    """Fixture для registry с несколькими зарегистрированными алгоритмами."""
    registry.register_algorithm(
        "Mock-AES-256-GCM",
        MockSymmetricCipher,
        MockSymmetricCipher.metadata,
    )
    registry.register_algorithm(
        "Mock-Ed25519",
        MockSignature,
        MockSignature.metadata,
    )
    registry.register_algorithm(
        "Mock-SHA-256",
        MockHash,
        MockHash.metadata,
    )
    registry.register_algorithm(
        "Mock-Dilithium3",
        MockPostQuantumSignature,
        MockPostQuantumSignature.metadata,
    )
    return registry


# ==============================================================================
# TEST: Singleton Pattern
# ==============================================================================


class TestSingletonPattern:
    """Тесты Singleton паттерна."""

    def test_get_instance_returns_same_instance(self) -> None:
        """get_instance() возвращает один и тот же экземпляр."""
        registry1 = AlgorithmRegistry.get_instance()
        registry2 = AlgorithmRegistry.get_instance()

        assert registry1 is registry2

    def test_direct_instantiation_raises_error(self) -> None:
        """Прямое создание экземпляра выбрасывает RuntimeError."""
        # Первый get_instance() для создания singleton
        _ = AlgorithmRegistry.get_instance()

        # Попытка создать напрямую
        with pytest.raises(RuntimeError, match="AlgorithmRegistry is a singleton"):
            AlgorithmRegistry()

    def test_reset_instance_clears_singleton(self) -> None:
        """reset_instance() сбрасывает singleton."""
        registry1 = AlgorithmRegistry.get_instance()
        AlgorithmRegistry.reset_instance()
        registry2 = AlgorithmRegistry.get_instance()

        assert registry1 is not registry2

    def test_reset_instance_clears_registry(self, registry: AlgorithmRegistry) -> None:
        """reset_instance() очищает реестр."""
        registry.register_algorithm(
            "Test-Algo",
            MockSymmetricCipher,
            MockSymmetricCipher.metadata,
        )

        assert len(registry.list_algorithms()) == 1

        AlgorithmRegistry.reset_instance()
        new_registry = AlgorithmRegistry.get_instance()

        assert len(new_registry.list_algorithms()) == 0


# ==============================================================================
# TEST: Thread Safety
# ==============================================================================


class TestThreadSafety:
    """Тесты потокобезопасности."""

    def test_concurrent_get_instance(self) -> None:
        """Параллельные вызовы get_instance() возвращают один экземпляр."""
        instances = []

        def get_and_store() -> None:
            instance = AlgorithmRegistry.get_instance()
            instances.append(id(instance))

        # 100 параллельных потоков
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(get_and_store) for _ in range(100)]
            for future in as_completed(futures):
                future.result()

        # Все должны получить один и тот же экземпляр
        assert len(set(instances)) == 1

    def test_concurrent_registration(self, registry: AlgorithmRegistry) -> None:
        """Параллельная регистрация разных алгоритмов thread-safe."""
        errors = []

        def register_algo(name: str, index: int) -> None:
            try:
                # Каждый поток регистрирует свой уникальный алгоритм
                metadata = create_symmetric_metadata(
                    name=name,
                    library="cryptography",
                    implementation_class=f"test.Mock{index}",
                    key_size=32,
                    nonce_size=12,
                )
                registry.register_algorithm(name, MockSymmetricCipher, metadata)
            except Exception as e:
                errors.append(e)

        # 50 параллельных регистраций
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(register_algo, f"Algo-{i}", i) for i in range(50)
            ]
            for future in as_completed(futures):
                future.result()

        # Не должно быть ошибок
        assert len(errors) == 0
        # Все алгоритмы зарегистрированы
        assert len(registry.list_algorithms()) == 50

    def test_concurrent_create(self, populated_registry: AlgorithmRegistry) -> None:
        """Параллельное создание экземпляров thread-safe."""
        instances = []
        errors = []

        def create_and_store() -> None:
            try:
                instance = populated_registry.create("Mock-AES-256-GCM")
                instances.append(instance)
            except Exception as e:
                errors.append(e)

        # 100 параллельных создаёт
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(create_and_store) for _ in range(100)]
            for future in as_completed(futures):
                future.result()

        # Не должно быть ошибок
        assert len(errors) == 0
        # Создано 100 экземпляров (каждый новый)
        assert len(instances) == 100
        # Все являются MockSymmetricCipher
        assert all(isinstance(inst, MockSymmetricCipher) for inst in instances)


# ==============================================================================
# TEST: Algorithm Registration
# ==============================================================================


class TestAlgorithmRegistration:
    """Тесты регистрации алгоритмов."""

    def test_register_valid_algorithm(self, registry: AlgorithmRegistry) -> None:
        """Регистрация валидного алгоритма."""
        registry.register_algorithm(
            "Mock-AES-256-GCM",
            MockSymmetricCipher,
            MockSymmetricCipher.metadata,
        )

        assert registry.is_registered("Mock-AES-256-GCM")
        assert "Mock-AES-256-GCM" in registry.list_algorithms()

    def test_register_duplicate_raises_error(self, registry: AlgorithmRegistry) -> None:
        """Повторная регистрация того же имени выбрасывает ValueError."""
        registry.register_algorithm(
            "Test-Algo",
            MockSymmetricCipher,
            MockSymmetricCipher.metadata,
        )

        with pytest.raises(ValueError, match="уже зарегистрирован"):
            registry.register_algorithm(
                "Test-Algo",
                MockHash,
                MockHash.metadata,
            )

    def test_register_empty_name_raises_error(
        self, registry: AlgorithmRegistry
    ) -> None:
        """Пустое имя выбрасывает ValueError."""
        with pytest.raises(ValueError, match="не может быть пустым"):
            registry.register_algorithm(
                "",
                MockSymmetricCipher,
                MockSymmetricCipher.metadata,
            )

    def test_register_non_callable_factory_raises_error(
        self, registry: AlgorithmRegistry
    ) -> None:
        """Не-callable factory выбрасывает TypeError."""
        with pytest.raises(TypeError, match="factory должна быть callable"):
            registry.register_algorithm(
                "Test",
                "not_callable",  # type: ignore
                MockSymmetricCipher.metadata,
            )

    def test_register_invalid_metadata_raises_error(
        self, registry: AlgorithmRegistry
    ) -> None:
        """Некорректные metadata выбрасывают TypeError."""
        with pytest.raises(TypeError, match="metadata должна быть AlgorithmMetadata"):
            registry.register_algorithm(
                "Test",
                MockSymmetricCipher,
                {"invalid": "metadata"},  # type: ignore
            )

    def test_register_without_validation(self, registry: AlgorithmRegistry) -> None:
        """Регистрация с validate=False пропускает проверку Protocol."""
        # MockInvalidAlgorithm НЕ реализует Protocol
        # Но с validate=False это должно пройти
        registry.register_algorithm(
            "Invalid-Algo",
            MockInvalidAlgorithm,
            MockInvalidAlgorithm.metadata,
            validate=False,
        )

        assert registry.is_registered("Invalid-Algo")


# ==============================================================================
# TEST: Protocol Validation
# ==============================================================================


class TestProtocolValidation:
    """Тесты валидации Protocol."""

    def test_validate_symmetric_cipher_protocol(
        self, registry: AlgorithmRegistry
    ) -> None:
        """MockSymmetricCipher проходит валидацию SymmetricCipherProtocol."""
        # Не должно быть исключений
        registry.register_algorithm(
            "Mock-AES",
            MockSymmetricCipher,
            MockSymmetricCipher.metadata,
            validate=True,
        )

        instance = registry.create("Mock-AES")
        assert isinstance(instance, SymmetricCipherProtocol)

    def test_validate_signature_protocol(self, registry: AlgorithmRegistry) -> None:
        """MockSignature проходит валидацию SignatureProtocol."""
        registry.register_algorithm(
            "Mock-Sig",
            MockSignature,
            MockSignature.metadata,
            validate=True,
        )

        instance = registry.create("Mock-Sig")
        assert isinstance(instance, SignatureProtocol)

    def test_validate_hash_protocol(self, registry: AlgorithmRegistry) -> None:
        """MockHash проходит валидацию HashProtocol."""
        registry.register_algorithm(
            "Mock-Hash",
            MockHash,
            MockHash.metadata,
            validate=True,
        )

        instance = registry.create("Mock-Hash")
        assert isinstance(instance, HashProtocol)

    def test_validate_protocol_failure(self, registry: AlgorithmRegistry) -> None:
        """Класс без Protocol методов НЕ проходит валидацию."""
        with pytest.raises(ProtocolError, match="не реализует"):
            registry.register_algorithm(
                "Invalid",
                MockInvalidAlgorithm,
                MockInvalidAlgorithm.metadata,
                validate=True,
            )


# ==============================================================================
# TEST: Instance Creation
# ==============================================================================


class TestInstanceCreation:
    """Тесты создания экземпляров."""

    def test_create_existing_algorithm(
        self, populated_registry: AlgorithmRegistry
    ) -> None:
        """Создание экземпляра зарегистрированного алгоритма."""
        cipher = populated_registry.create("Mock-AES-256-GCM")

        assert isinstance(cipher, MockSymmetricCipher)
        assert cipher.algorithm_name == "Mock-AES-256-GCM"

    def test_create_returns_new_instances(
        self, populated_registry: AlgorithmRegistry
    ) -> None:
        """create() возвращает новые экземпляры (не singleton)."""
        cipher1 = populated_registry.create("Mock-AES-256-GCM")
        cipher2 = populated_registry.create("Mock-AES-256-GCM")

        assert cipher1 is not cipher2

    def test_create_nonexistent_algorithm_raises_error(
        self, registry: AlgorithmRegistry
    ) -> None:
        """Создание несуществующего алгоритма выбрасывает KeyError."""
        with pytest.raises(KeyError, match="не найден в реестре"):
            registry.create("Nonexistent-Algo")

    def test_create_with_factory_error(self, registry: AlgorithmRegistry) -> None:
        """Ошибка в factory приводит к RuntimeError."""

        def failing_factory() -> Any:
            raise ValueError("Factory failed!")

        metadata = create_symmetric_metadata(
            name="Failing",
            library="cryptography",
            implementation_class="test",
            key_size=32,
            nonce_size=12,
        )

        registry.register_algorithm(
            "Failing", failing_factory, metadata, validate=False
        )

        with pytest.raises(RuntimeError, match="Не удалось создать экземпляр"):
            registry.create("Failing")


# ==============================================================================
# TEST: Metadata Access
# ==============================================================================


class TestMetadataAccess:
    """Тесты доступа к метаданным."""

    def test_get_metadata_existing_algorithm(
        self, populated_registry: AlgorithmRegistry
    ) -> None:
        """Получение метаданных зарегистрированного алгоритма."""
        metadata = populated_registry.get_metadata("Mock-AES-256-GCM")

        assert metadata.name == "Mock-AES-256-GCM"
        assert metadata.category == AlgorithmCategory.SYMMETRIC_CIPHER
        assert metadata.key_size == 32

    def test_get_metadata_nonexistent_raises_error(
        self, registry: AlgorithmRegistry
    ) -> None:
        """Получение метаданных несуществующего алгоритма выбрасывает KeyError."""
        with pytest.raises(KeyError, match="не найден в реестре"):
            registry.get_metadata("Nonexistent")


# ==============================================================================
# TEST: Query API
# ==============================================================================


class TestQueryAPI:
    """Тесты Query API."""

    def test_list_algorithms(self, populated_registry: AlgorithmRegistry) -> None:
        """list_algorithms() возвращает все алгоритмы (sorted)."""
        algos = populated_registry.list_algorithms()

        assert len(algos) == 4
        assert algos == sorted(algos)  # Проверка сортировки
        assert "Mock-AES-256-GCM" in algos
        assert "Mock-Ed25519" in algos

    def test_list_by_category_symmetric(
        self, populated_registry: AlgorithmRegistry
    ) -> None:
        """list_by_category() для симметричных шифров."""
        symmetric = populated_registry.list_by_category(
            AlgorithmCategory.SYMMETRIC_CIPHER
        )

        assert len(symmetric) == 1
        assert "Mock-AES-256-GCM" in symmetric

    def test_list_by_category_signature(
        self, populated_registry: AlgorithmRegistry
    ) -> None:
        """list_by_category() для подписей."""
        signatures = populated_registry.list_by_category(AlgorithmCategory.SIGNATURE)

        assert len(signatures) == 2
        assert "Mock-Ed25519" in signatures
        assert "Mock-Dilithium3" in signatures

    def test_list_by_security_level(
        self, populated_registry: AlgorithmRegistry
    ) -> None:
        """list_by_security_level() фильтрует по уровню безопасности."""
        quantum = populated_registry.list_by_security_level(
            SecurityLevel.QUANTUM_RESISTANT
        )

        assert len(quantum) == 1
        assert "Mock-Dilithium3" in quantum

    def test_list_safe_for_production(
        self, populated_registry: AlgorithmRegistry
    ) -> None:
        """list_safe_for_production() возвращает только безопасные алгоритмы."""
        safe = populated_registry.list_safe_for_production()

        # Все наши mock алгоритмы STABLE + STANDARD/QUANTUM_RESISTANT
        assert len(safe) == 4

    def test_list_floppy_friendly(self, populated_registry: AlgorithmRegistry) -> None:
        """list_floppy_friendly() фильтрует по floppy-friendly."""
        excellent = populated_registry.list_floppy_friendly(FloppyFriendly.EXCELLENT)

        # Mock-AES, Mock-Ed25519, Mock-SHA-256 = EXCELLENT
        # Mock-Dilithium3 = POOR (большие ключи)
        assert len(excellent) == 3

    def test_search_single_filter(self, populated_registry: AlgorithmRegistry) -> None:
        """search() с одним фильтром."""
        results = populated_registry.search(category=AlgorithmCategory.SIGNATURE)

        assert len(results) == 2
        assert "Mock-Ed25519" in results
        assert "Mock-Dilithium3" in results

    def test_search_multiple_filters(
        self, populated_registry: AlgorithmRegistry
    ) -> None:
        """search() с множественными фильтрами (AND логика)."""
        results = populated_registry.search(
            category=AlgorithmCategory.SIGNATURE,
            is_post_quantum=True,
        )

        assert len(results) == 1
        assert "Mock-Dilithium3" in results

    def test_search_no_results(self, populated_registry: AlgorithmRegistry) -> None:
        """search() без результатов возвращает пустой список."""
        results = populated_registry.search(
            category=AlgorithmCategory.KEY_EXCHANGE  # Нет таких в populated
        )

        assert len(results) == 0

    def test_search_is_aead_filter(self, populated_registry: AlgorithmRegistry) -> None:
        """search() с фильтром is_aead."""
        aead = populated_registry.search(is_aead=True)

        assert len(aead) == 1
        assert "Mock-AES-256-GCM" in aead


# ==============================================================================
# TEST: Statistics
# ==============================================================================


class TestStatistics:
    """Тесты статистики."""

    def test_get_statistics_empty_registry(self, registry: AlgorithmRegistry) -> None:
        """Статистика пустого реестра."""
        stats = registry.get_statistics()

        assert stats.total == 0
        assert len(stats.by_category) == 0
        assert stats.post_quantum_count == 0
        assert stats.aead_count == 0

    def test_get_statistics_populated(
        self, populated_registry: AlgorithmRegistry
    ) -> None:
        """Статистика заполненного реестра."""
        stats = populated_registry.get_statistics()

        assert stats.total == 4
        assert stats.by_category[AlgorithmCategory.SYMMETRIC_CIPHER] == 1
        assert stats.by_category[AlgorithmCategory.SIGNATURE] == 2
        assert stats.by_category[AlgorithmCategory.HASH] == 1
        assert stats.post_quantum_count == 1
        assert stats.aead_count == 1
        assert stats.safe_for_production_count == 4

    def test_statistics_to_dict(self, populated_registry: AlgorithmRegistry) -> None:
        """Сериализация статистики в словарь."""
        stats = populated_registry.get_statistics()
        data = stats.to_dict()

        assert isinstance(data, dict)
        assert data["total"] == 4
        assert "symmetric_cipher" in data["by_category"]
        assert data["post_quantum_count"] == 1


# ==============================================================================
# TEST: Unregister
# ==============================================================================


class TestUnregister:
    """Тесты удаления алгоритмов."""

    def test_unregister_existing_algorithm(
        self, populated_registry: AlgorithmRegistry
    ) -> None:
        """Удаление зарегистрированного алгоритма."""
        assert populated_registry.is_registered("Mock-AES-256-GCM")

        populated_registry.unregister("Mock-AES-256-GCM")

        assert not populated_registry.is_registered("Mock-AES-256-GCM")
        assert "Mock-AES-256-GCM" not in populated_registry.list_algorithms()

    def test_unregister_nonexistent_raises_error(
        self, registry: AlgorithmRegistry
    ) -> None:
        """Удаление несуществующего алгоритма выбрасывает KeyError."""
        with pytest.raises(KeyError, match="не найден в реестре"):
            registry.unregister("Nonexistent")


# ==============================================================================
# TEST: Dataclasses
# ==============================================================================


class TestDataclasses:
    """Тесты dataclass'ов."""

    def test_registry_entry_immutable(self) -> None:
        """RegistryEntry immutable (frozen)."""
        entry = RegistryEntry(
            name="Test",
            factory=MockSymmetricCipher,
            metadata=MockSymmetricCipher.metadata,
        )

        with pytest.raises(AttributeError):
            entry.name = "Changed"  # type: ignore

    def test_registry_statistics_immutable(self) -> None:
        """RegistryStatistics immutable (frozen)."""
        stats = RegistryStatistics(
            total=10,
            by_category={},
            by_security_level={},
            by_floppy_friendly={},
            post_quantum_count=0,
            aead_count=0,
            safe_for_production_count=0,
        )

        with pytest.raises(AttributeError):
            stats.total = 20  # type: ignore


# ==============================================================================
# TEST: register_all_algorithms()
# ==============================================================================


class TestRegisterAllAlgorithms:
    """Тесты функции register_all_algorithms()."""

    def test_register_all_algorithms_stub(self) -> None:
        """register_all_algorithms() - заглушка (пока алгоритмы не реализованы)."""
        # Функция существует и вызывается без ошибок
        register_all_algorithms()

        registry = AlgorithmRegistry.get_instance()

        # Пока 0, когда реализуем алгоритмы - будет 46
        assert len(registry.list_algorithms()) > 0


# ==============================================================================
# TEST: Edge Cases
# ==============================================================================


class TestEdgeCases:
    """Тесты граничных случаев."""

    def test_is_registered_empty_registry(self, registry: AlgorithmRegistry) -> None:
        """is_registered() в пустом реестре."""
        assert not registry.is_registered("Any-Algo")

    def test_list_algorithms_empty_registry(self, registry: AlgorithmRegistry) -> None:
        """list_algorithms() в пустом реестре."""
        assert registry.list_algorithms() == []

    def test_search_empty_registry_returns_empty(
        self, registry: AlgorithmRegistry
    ) -> None:
        """search() в пустом реестре возвращает []."""
        results = registry.search(category=AlgorithmCategory.SYMMETRIC_CIPHER)
        assert results == []

    def test_register_algorithm_with_spaces_in_name(
        self, registry: AlgorithmRegistry
    ) -> None:
        """Регистрация алгоритма с пробелами в имени."""
        # Пробелы валидны (например, "AES 256 GCM")
        registry.register_algorithm(
            "Test Algo With Spaces",
            MockSymmetricCipher,
            MockSymmetricCipher.metadata,
        )

        assert registry.is_registered("Test Algo With Spaces")


# ==============================================================================
# TEST: Module Exports
# ==============================================================================


class TestModuleExports:
    """Тесты exports модуля."""

    def test_all_exports_defined(self) -> None:
        """Все exports определены в __all__."""
        from src.security.crypto.core import registry

        assert hasattr(registry, "__all__")
        assert "AlgorithmRegistry" in registry.__all__
        assert "RegistryEntry" in registry.__all__
        assert "RegistryStatistics" in registry.__all__
        assert "RegistryError" in registry.__all__
        assert "ProtocolError" in registry.__all__
        assert "register_all_algorithms" in registry.__all__

    def test_module_version_metadata(self) -> None:
        """Модуль имеет метаданные версии."""
        from src.security.crypto.core import registry

        assert hasattr(registry, "__version__")
        assert hasattr(registry, "__author__")
        assert hasattr(registry, "__date__")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.security.crypto.core.registry"])
