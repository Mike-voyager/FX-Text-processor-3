"""
Тесты для модуля утилит цепочек доверия (trust_chain_utils).

Покрытие:
- serialize_trust_chain: пустая цепочка, множественные звенья
- deserialize_trust_chain: валидные данные, невалидный JSON
- validate_key_format: валидный/невалидный Ed25519 ключ
- generate_key_id: уникальность, формат "key-{uuid}"
- format_chain_for_display: пустая цепочка, одно звено, 3 уровня
- format_chain_for_display: наличие эмодзи и алгоритма
- file_lock: thread-safe файловые операции
- TRUSTED_KEYS_FILE: проверка пути к файлу ключей

Coverage target: ≥90%

Author: Mike Voyager
Version: 1.0
Date: April 11, 2026
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from src.security.crypto.core.exceptions import InvalidParameterError
from src.security.crypto.utilities.trust_chain_utils import (
    KEY_ID_PREFIX,
    MAX_KEY_SIZE,
    MIN_KEY_SIZE,
    TRUSTED_KEYS_FILE,
    TrustChainError,
    TrustChainFileError,
    TrustChainSerializationError,
    TrustChainValidationError,
    deserialize_trust_chain,
    file_lock,
    find_chain_root,
    format_chain_for_display,
    generate_key_id,
    get_chain_depth,
    load_trusted_keys,
    save_trusted_keys,
    serialize_trust_chain,
    validate_chain,
    validate_key_format,
)
from src.services.protocols.template_security import TrustChainLink, TrustStatus


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_public_key() -> bytes:
    """Валидный Ed25519 публичный ключ (32 байта)."""
    return b"\x00" * 32


@pytest.fixture
def invalid_public_key() -> bytes:
    """Невалидный Ed25519 ключ (неверная длина)."""
    return b"\x00" * 31  # 31 вместо 32


@pytest.fixture
def ml_dsa_65_key() -> bytes:
    """Валидный ML-DSA-65 публичный ключ (1952 байта)."""
    return b"\x00" * 1952


@pytest.fixture
def root_link(sample_public_key: bytes) -> TrustChainLink:
    """Корневое звено цепочки доверия."""
    return TrustChainLink(
        key_id="key-root-001",
        public_key=sample_public_key,
        algorithm="ed25519",
        added_at=datetime.now() - timedelta(days=30),
        parent_key_id=None,
        expires_at=None,
        signature=None,
        metadata={"name": "Root CA", "org": "FX Corp"},
    )


@pytest.fixture
def intermediate_link(sample_public_key: bytes) -> TrustChainLink:
    """Промежуточное звено цепочки доверия."""
    return TrustChainLink(
        key_id="key-intermediate-001",
        public_key=sample_public_key,
        algorithm="ed25519",
        added_at=datetime.now() - timedelta(days=15),
        parent_key_id="key-root-001",
        expires_at=datetime.now() + timedelta(days=365),
        signature=b"\x01" * 64,
        metadata={"name": "Intermediate CA"},
    )


@pytest.fixture
def leaf_link(sample_public_key: bytes) -> TrustChainLink:
    """Конечное звено цепочки доверия."""
    return TrustChainLink(
        key_id="key-leaf-001",
        public_key=sample_public_key,
        algorithm="ml-dsa-65",
        added_at=datetime.now(),
        parent_key_id="key-intermediate-001",
        expires_at=datetime.now() + timedelta(days=90),
        signature=b"\x02" * 3293,
        metadata={"name": "Leaf Key", "purpose": "template_signing"},
    )


# =============================================================================
# serialize_trust_chain
# =============================================================================


class TestSerializeTrustChain:
    def test_serialize_trust_chain_empty(self) -> None:
        """Сериализация пустой цепочки доверия."""
        result = serialize_trust_chain([])

        assert isinstance(result, str)
        parsed = json.loads(result)
        assert parsed == []

    def test_serialize_trust_chain_multiple_links(
        self,
        root_link: TrustChainLink,
        intermediate_link: TrustChainLink,
        leaf_link: TrustChainLink,
    ) -> None:
        """Сериализация цепочки с 3 звеньями."""
        links = [root_link, intermediate_link, leaf_link]
        result = serialize_trust_chain(links)

        assert isinstance(result, str)
        parsed = json.loads(result)
        assert len(parsed) == 3

        # Проверяем структуру каждого звена
        first = parsed[0]
        assert first["key_id"] == "key-root-001"
        assert first["algorithm"] == "ed25519"
        assert first["parent_key_id"] is None  # Корневое звено

        second = parsed[1]
        assert second["key_id"] == "key-intermediate-001"
        assert second["parent_key_id"] == "key-root-001"

        third = parsed[2]
        assert third["key_id"] == "key-leaf-001"
        assert third["algorithm"] == "ml-dsa-65"

    def test_serialize_trust_chain_invalid_input(self) -> None:
        """Обработка невалидного входа."""
        with pytest.raises(InvalidParameterError):
            serialize_trust_chain("not a list")  # type: ignore[arg-type]

    def test_serialize_trust_chain_invalid_item(self, root_link: TrustChainLink) -> None:
        """Обработка невалидного элемента в списке."""
        with pytest.raises(InvalidParameterError):
            serialize_trust_chain([root_link, "not a link"])  # type: ignore[list-item]


# =============================================================================
# deserialize_trust_chain
# =============================================================================


class TestDeserializeTrustChain:
    def test_deserialize_trust_chain_valid(
        self,
        root_link: TrustChainLink,
        intermediate_link: TrustChainLink,
    ) -> None:
        """Десериализация валидных данных."""
        original_links = [root_link, intermediate_link]
        serialized = serialize_trust_chain(original_links)

        restored = deserialize_trust_chain(serialized)

        assert len(restored) == 2
        assert restored[0].key_id == root_link.key_id
        assert restored[0].algorithm == root_link.algorithm
        assert restored[0].is_root() is True

        assert restored[1].key_id == intermediate_link.key_id
        assert restored[1].parent_key_id == intermediate_link.parent_key_id

    def test_deserialize_trust_chain_invalid_json(self) -> None:
        """Обработка невалидного JSON."""
        invalid_data = "{not valid json"

        with pytest.raises(InvalidParameterError) as exc_info:
            deserialize_trust_chain(invalid_data)

        assert "Invalid JSON" in str(exc_info.value)

    def test_deserialize_trust_chain_invalid_structure(self) -> None:
        """Обработка неверной структуры JSON."""
        invalid_data = json.dumps("not an array")

        with pytest.raises(TrustChainSerializationError) as exc_info:
            deserialize_trust_chain(invalid_data)

        assert "Expected JSON array" in str(exc_info.value)

    def test_deserialize_trust_chain_invalid_item(self) -> None:
        """Обработка невалидного элемента в JSON."""
        invalid_data = json.dumps([{"key_id": "test"}])

        with pytest.raises(TrustChainSerializationError) as exc_info:
            deserialize_trust_chain(invalid_data)

        assert "Failed to parse" in str(exc_info.value)


# =============================================================================
# validate_key_format
# =============================================================================


class TestValidateKeyFormat:
    def test_validate_key_format_ed25519_valid(self, sample_public_key: bytes) -> None:
        """Валидный Ed25519 ключ (32 байта)."""
        assert validate_key_format(sample_public_key, "ed25519") is True
        assert validate_key_format(sample_public_key, "Ed25519") is True
        assert validate_key_format(sample_public_key, "ED25519") is True

    def test_validate_key_format_ed25519_invalid_length(
        self, invalid_public_key: bytes
    ) -> None:
        """Невалидная длина Ed25519 ключа (31 байт вместо 32)."""
        assert validate_key_format(invalid_public_key, "ed25519") is False

    def test_validate_key_format_ed25519_wrong_sizes(self) -> None:
        """Различные неверные размеры для Ed25519."""
        # Пустой ключ
        with pytest.raises(InvalidParameterError):
            validate_key_format(b"", "ed25519")
        # 33 байта
        assert validate_key_format(b"\x00" * 33, "ed25519") is False
        # 64 байта
        assert validate_key_format(b"\x00" * 64, "ed25519") is False
        # Превышение MAX_KEY_SIZE
        assert validate_key_format(b"\x00" * (MAX_KEY_SIZE + 1), "ed25519") is False

    def test_validate_key_format_ml_dsa_65(self, ml_dsa_65_key: bytes) -> None:
        """Валидный ML-DSA-65 ключ (1952 байта)."""
        assert validate_key_format(ml_dsa_65_key, "ml-dsa-65") is True
        assert validate_key_format(ml_dsa_65_key, "ML-DSA-65") is True
        assert validate_key_format(ml_dsa_65_key, "mldsa65") is True

    def test_validate_key_format_unknown_algorithm(self) -> None:
        """Для неизвестных алгоритмов принимается ключ >= MIN_KEY_SIZE."""
        assert validate_key_format(b"any_key_32_bytes_long_for_test!!", "unknown_algo") is True

    def test_validate_key_format_not_bytes(self) -> None:
        """Проверка типа public_key."""
        with pytest.raises(InvalidParameterError):
            validate_key_format("not bytes", "ed25519")  # type: ignore[arg-type]


# =============================================================================
# generate_key_id
# =============================================================================


class TestGenerateKeyId:
    def test_generate_key_id_unique(self) -> None:
        """Уникальность сгенерированных ID."""
        ids: set[str] = set()
        for _ in range(100):
            key_id = generate_key_id()
            assert key_id not in ids, f"Дубликат ID: {key_id}"
            ids.add(key_id)

    def test_generate_key_id_format(self) -> None:
        """Формат ID: key-{hex}."""
        key_id = generate_key_id()

        # Проверка префикса
        assert key_id.startswith(KEY_ID_PREFIX)

        # Проверка длины
        assert len(key_id) > len(KEY_ID_PREFIX)
        assert len(key_id) == len(KEY_ID_PREFIX) + 12  # 12 hex chars

    def test_generate_key_id_custom_prefix(self) -> None:
        """Генерация ID с пользовательским префиксом."""
        key_id = generate_key_id("custom-")
        assert key_id.startswith("custom-")


# =============================================================================
# format_chain_for_display
# =============================================================================


class TestFormatChainForDisplay:
    def test_format_chain_for_display_empty(self) -> None:
        """Форматирование пустой цепочки."""
        result = format_chain_for_display([])
        assert "пуста" in result.lower()

    def test_format_chain_for_display_single_link(
        self, root_link: TrustChainLink
    ) -> None:
        """Форматирование одного звена (корневого)."""
        result = format_chain_for_display([root_link])

        assert "ed25519" in result.lower()
        assert "key-root-001" in result
        assert "корневой" in result.lower()

    def test_format_chain_for_display_chain_three_levels(
        self,
        root_link: TrustChainLink,
        intermediate_link: TrustChainLink,
        leaf_link: TrustChainLink,
    ) -> None:
        """Форматирование цепочки с 3 уровнями."""
        links = [root_link, intermediate_link, leaf_link]
        result = format_chain_for_display(links)

        # Проверяем наличие всех ключей
        assert "key-root-001" in result
        assert "key-intermediate-001" in result
        assert "key-leaf-001" in result

        # Проверяем наличие алгоритмов
        assert "ed25519" in result.lower() or "Ed25519" in result
        assert "ml-dsa-65" in result.lower() or "ML-DSA-65" in result

    def test_format_chain_includes_emojis(
        self, root_link: TrustChainLink, intermediate_link: TrustChainLink
    ) -> None:
        """Проверка наличия эмодзи статуса."""
        statuses = {
            root_link.key_id: TrustStatus.TRUSTED,
            intermediate_link.key_id: TrustStatus.REVOKED,
        }

        result = format_chain_for_display([root_link, intermediate_link], statuses)

        # TRUSTED = "✅"
        assert "✅" in result
        # REVOKED = "🚫"
        assert "🚫" in result

    def test_format_chain_includes_algorithm(
        self, root_link: TrustChainLink, leaf_link: TrustChainLink
    ) -> None:
        """Проверка наличия алгоритма в выводе."""
        result = format_chain_for_display([root_link, leaf_link])

        # Проверяем наличие алгоритмов (не зависит от регистра)
        assert "ed25519" in result.lower() or "Ed25519" in result
        assert "ml-dsa-65" in result.lower() or "ML-DSA-65" in result


# =============================================================================
# file_lock (thread-safe operations)
# =============================================================================


class TestFileLock:
    def test_file_operations_thread_safe(
        self, tmp_path: Path
    ) -> None:
        """Thread-safe файловые операции."""
        file_path = tmp_path / "test_lock.json"

        results: list[bool] = []
        errors: list[Exception] = []

        def write_and_read() -> None:
            try:
                with file_lock(file_path, exclusive=True) as fd:
                    data = b"test data"
                    os.ftruncate(fd, 0)
                    os.lseek(fd, 0, os.SEEK_SET)
                    os.write(fd, data)
                    time.sleep(0.01)  # Небольшая задержка
                    os.lseek(fd, 0, os.SEEK_SET)
                    os.read(fd, 100)
                results.append(True)
            except Exception as e:
                errors.append(e)

        # Запускаем несколько потоков одновременно
        threads: list[threading.Thread] = []
        for _ in range(5):
            t = threading.Thread(target=write_and_read)
            threads.append(t)
            t.start()

        # Ждем завершения всех потоков
        for t in threads:
            t.join()

        # Проверяем что не было ошибок
        assert len(errors) == 0, f"Ошибки в потоках: {errors}"

        # Проверяем что все операции завершились корректно
        assert len(results) == 5

    def test_file_lock_exclusive(self, tmp_path: Path) -> None:
        """Эксклюзивная блокировка файла."""
        file_path = tmp_path / "exclusive.txt"

        with file_lock(file_path, exclusive=True) as fd:
            assert fd >= 0
            data = b"exclusive data"
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, data)

        # Проверяем что файл создан и содержит данные
        assert file_path.exists()
        content = file_path.read_text()
        assert content == "exclusive data"

    def test_file_lock_shared(self, tmp_path: Path) -> None:
        """Shared блокировка для чтения."""
        file_path = tmp_path / "shared.txt"
        file_path.write_text("shared data")

        with file_lock(file_path, exclusive=False) as fd:
            os.lseek(fd, 0, os.SEEK_SET)
            data = os.read(fd, 100)
            assert data == b"shared data"


# =============================================================================
# save_trusted_keys / load_trusted_keys
# =============================================================================


class TestSaveLoadTrustedKeys:
    def test_save_and_load_roundtrip(
        self, tmp_path: Path, root_link: TrustChainLink, intermediate_link: TrustChainLink
    ) -> None:
        """Сохранение и загрузка цепочки доверия."""
        file_path = tmp_path / "trusted_keys.json"

        links = [root_link, intermediate_link]
        save_trusted_keys(links, file_path)

        assert file_path.exists()

        loaded = load_trusted_keys(file_path)
        assert len(loaded) == 2
        assert loaded[0].key_id == root_link.key_id
        assert loaded[1].key_id == intermediate_link.key_id

    def test_load_nonexistent_file_returns_empty(self, tmp_path: Path) -> None:
        """Загрузка из несуществующего файла возвращает пустой список."""
        file_path = tmp_path / "nonexistent.json"

        result = load_trusted_keys(file_path)
        assert result == []

    def test_load_empty_file(self, tmp_path: Path) -> None:
        """Загрузка из пустого файла возвращает пустой список."""
        file_path = tmp_path / "empty.json"
        file_path.write_text("")

        result = load_trusted_keys(file_path)
        assert result == []


# =============================================================================
# TRUSTED_KEYS_FILE path
# =============================================================================


class TestTrustedKeysFilePath:
    def test_trusted_keys_file_path(self) -> None:
        """Проверка пути к файлу доверенных ключей."""
        path = TRUSTED_KEYS_FILE

        assert isinstance(path, Path)
        assert path.name == "trusted_keys.json"
        assert ".fxtextprocessor" in str(path)
        assert "keystore" in str(path)

    def test_path_is_absolute(self) -> None:
        """Путь должен быть абсолютным."""
        path = TRUSTED_KEYS_FILE
        assert path.is_absolute()


# =============================================================================
# validate_chain
# =============================================================================


class TestValidateChain:
    def test_validate_empty_chain(self) -> None:
        """Пустая цепочка валидна."""
        is_valid, errors = validate_chain([])
        assert is_valid is True
        assert errors == []

    def test_validate_valid_chain(
        self,
        root_link: TrustChainLink,
        intermediate_link: TrustChainLink,
    ) -> None:
        """Валидная цепочка."""
        is_valid, errors = validate_chain([intermediate_link, root_link])
        # Корректный порядок: intermediate -> root
        assert is_valid is True
        assert len(errors) == 0

    def test_validate_multiple_roots(
        self, root_link: TrustChainLink, sample_public_key: bytes
    ) -> None:
        """Ошибка если несколько корневых ключей."""
        another_root = TrustChainLink(
            key_id="key-root-002",
            public_key=sample_public_key,
            algorithm="ed25519",
            added_at=datetime.now(),
            parent_key_id=None,
        )
        is_valid, errors = validate_chain([root_link, another_root])
        assert is_valid is False
        assert any("root" in e.lower() for e in errors)

    def test_validate_expired_key(self, sample_public_key: bytes) -> None:
        """Ошибка при просроченном ключе."""
        expired_link = TrustChainLink(
            key_id="key-expired",
            public_key=sample_public_key,
            algorithm="ed25519",
            added_at=datetime.now() - timedelta(days=365),
            expires_at=datetime.now() - timedelta(days=1),
        )
        is_valid, errors = validate_chain([expired_link])
        assert is_valid is False
        assert any("expired" in e.lower() for e in errors)


# =============================================================================
# find_chain_root
# =============================================================================


class TestFindChainRoot:
    def test_find_root_in_chain(
        self, root_link: TrustChainLink, intermediate_link: TrustChainLink
    ) -> None:
        """Поиск корня в цепочке."""
        root = find_chain_root([intermediate_link, root_link])
        assert root is not None
        assert root.key_id == "key-root-001"

    def test_find_root_empty_chain(self) -> None:
        """Поиск корня в пустой цепочке."""
        root = find_chain_root([])
        assert root is None


# =============================================================================
# get_chain_depth
# =============================================================================


class TestGetChainDepth:
    def test_depth_empty(self) -> None:
        """Глубина пустой цепочки."""
        assert get_chain_depth([]) == 0

    def test_depth_three_links(
        self,
        root_link: TrustChainLink,
        intermediate_link: TrustChainLink,
        leaf_link: TrustChainLink,
    ) -> None:
        """Глубина цепочки с 3 звеньями."""
        depth = get_chain_depth([leaf_link, intermediate_link, root_link])
        assert depth == 3


# =============================================================================
# Константы
# =============================================================================


class TestConstants:
    def test_key_sizes(self) -> None:
        """Размеры ключей."""
        assert MIN_KEY_SIZE == 32
        assert MAX_KEY_SIZE == 2592

    def test_key_id_prefix(self) -> None:
        """Префикс ID ключа."""
        assert KEY_ID_PREFIX == "key-"


# =============================================================================
# Исключения
# =============================================================================


class TestExceptions:
    def test_trust_chain_error_is_exception(self) -> None:
        """TrustChainError является Exception."""
        assert issubclass(TrustChainError, Exception)

    def test_serialization_error_is_trust_chain_error(self) -> None:
        """TrustChainSerializationError наследует TrustChainError."""
        assert issubclass(TrustChainSerializationError, TrustChainError)

    def test_validation_error_is_trust_chain_error(self) -> None:
        """TrustChainValidationError наследует TrustChainError."""
        assert issubclass(TrustChainValidationError, TrustChainError)

    def test_file_error_is_trust_chain_error(self) -> None:
        """TrustChainFileError наследует TrustChainError."""
        assert issubclass(TrustChainFileError, TrustChainError)

    def test_trust_chain_error_with_details(self) -> None:
        """TrustChainError с деталями."""
        error = TrustChainError("test message", details={"key": "value"})
        assert str(error) == "test message (details: {'key': 'value'})"


# =============================================================================
# Экспорты
# =============================================================================


def test_module_exports() -> None:
    """Проверка экспортируемых символов модуля."""
    from src.security.crypto.utilities import trust_chain_utils

    expected_exports = [
        "serialize_trust_chain",
        "deserialize_trust_chain",
        "validate_key_format",
        "generate_key_id",
        "format_chain_for_display",
        "TRUSTED_KEYS_FILE",
        "KEY_ID_PREFIX",
        "file_lock",
        "save_trusted_keys",
        "load_trusted_keys",
        "validate_chain",
        "find_chain_root",
        "get_chain_depth",
    ]

    for export in expected_exports:
        assert hasattr(trust_chain_utils, export), f"Missing export: {export}"
