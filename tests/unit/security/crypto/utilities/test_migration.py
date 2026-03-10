"""
Тесты для модуля миграции криптографических алгоритмов.

Покрытие:
- MigrationResult: создание, frozen, значения по умолчанию
- CryptoMigrator.can_migrate: оба зарегистрированы / один / ни один
- CryptoMigrator.migrate_document:
    - нормальный сценарий (nonce встроен в данные)
    - нормальный сценарий (old_nonce передан явно)
    - результат содержит nonce + ciphertext нового шифра
    - правильный порядок аргументов decrypt/encrypt
    - ошибка расшифровки → success=False, error не None, исходные данные
    - ошибка перешифровки → success=False, error не None, исходные данные
    - логирование INFO при успехе / ERROR при ошибке
- CryptoMigrator.bulk_migrate:
    - пустой список
    - все успешны
    - часть провалилась
    - длина результата == длина входа
    - логирование INFO с правильным счётчиком
- Интеграционные: реальный AES-128-GCM → AES-256-GCM

Coverage target: 95%+

Author: Mike Voyager
Version: 1.0
Date: March 10, 2026
"""

from __future__ import annotations

import logging
import os
from unittest.mock import MagicMock

import pytest
from src.security.crypto.utilities.migration import CryptoMigrator, MigrationResult

# ==============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ==============================================================================

_OLD_ALGO = "aes-128-gcm"
_NEW_ALGO = "aes-256-gcm"
_PLAINTEXT = b"secret document content"
_OLD_KEY = b"\xaa" * 16
_NEW_KEY = b"\xbb" * 32
_NONCE_OLD = b"\x01" * 12
_NONCE_NEW = b"\x02" * 12
_FAKE_CT_OLD = b"\xcc" * 32
_FAKE_CT_NEW = b"\xdd" * 32


def _make_cipher(
    nonce: bytes = _NONCE_NEW,
    ciphertext: bytes = _FAKE_CT_NEW,
    plaintext: bytes = _PLAINTEXT,
    nonce_size: int = 12,
) -> MagicMock:
    cipher = MagicMock()
    cipher.nonce_size = nonce_size
    cipher.encrypt.return_value = (nonce, ciphertext)
    cipher.decrypt.return_value = plaintext
    return cipher


def _make_registry(
    old_cipher: MagicMock | None = None,
    new_cipher: MagicMock | None = None,
    old_registered: bool = True,
    new_registered: bool = True,
) -> MagicMock:
    """Registry, где create(_OLD_ALGO) → old_cipher, create(_NEW_ALGO) → new_cipher."""
    if old_cipher is None:
        old_cipher = _make_cipher(nonce_size=12, plaintext=_PLAINTEXT)
    if new_cipher is None:
        new_cipher = _make_cipher()

    def _is_registered(name: str) -> bool:
        if name == _OLD_ALGO:
            return old_registered
        if name == _NEW_ALGO:
            return new_registered
        return False

    def _create(name: str) -> MagicMock:
        return old_cipher if name == _OLD_ALGO else new_cipher  # type: ignore[return-value]

    registry = MagicMock()
    registry.is_registered.side_effect = _is_registered
    registry.create.side_effect = _create
    return registry


def _migrator_and_registry(**kwargs: object) -> tuple[CryptoMigrator, MagicMock]:
    reg = _make_registry(**kwargs)  # type: ignore[arg-type]
    return CryptoMigrator(reg), reg  # type: ignore[arg-type]


# ==============================================================================
# FIXTURES
# ==============================================================================


@pytest.fixture
def old_cipher() -> MagicMock:
    return _make_cipher(nonce_size=12, plaintext=_PLAINTEXT)


@pytest.fixture
def new_cipher() -> MagicMock:
    return _make_cipher(nonce=_NONCE_NEW, ciphertext=_FAKE_CT_NEW)


@pytest.fixture
def registry(old_cipher: MagicMock, new_cipher: MagicMock) -> MagicMock:
    return _make_registry(old_cipher=old_cipher, new_cipher=new_cipher)


@pytest.fixture
def migrator(registry: MagicMock) -> CryptoMigrator:
    return CryptoMigrator(registry)  # type: ignore[arg-type]


# ==============================================================================
# MigrationResult
# ==============================================================================


class TestMigrationResult:
    def test_success_defaults(self) -> None:
        result = MigrationResult(
            old_algorithm=_OLD_ALGO,
            new_algorithm=_NEW_ALGO,
            success=True,
        )
        assert result.success is True
        assert result.error is None

    def test_failure_with_error(self) -> None:
        result = MigrationResult(
            old_algorithm=_OLD_ALGO,
            new_algorithm=_NEW_ALGO,
            success=False,
            error="decryption failed",
        )
        assert result.success is False
        assert result.error == "decryption failed"

    def test_frozen(self) -> None:
        result = MigrationResult(old_algorithm=_OLD_ALGO, new_algorithm=_NEW_ALGO, success=True)
        with pytest.raises((AttributeError, TypeError)):
            result.success = False  # type: ignore[misc]

    def test_stores_algorithms(self) -> None:
        result = MigrationResult(old_algorithm="algo-a", new_algorithm="algo-b", success=True)
        assert result.old_algorithm == "algo-a"
        assert result.new_algorithm == "algo-b"


# ==============================================================================
# CryptoMigrator.can_migrate
# ==============================================================================


class TestCanMigrate:
    def test_both_registered_returns_true(self, migrator: CryptoMigrator) -> None:
        assert migrator.can_migrate(_OLD_ALGO, _NEW_ALGO) is True

    def test_old_not_registered_returns_false(self) -> None:
        mgr, _ = _migrator_and_registry(old_registered=False)
        assert mgr.can_migrate(_OLD_ALGO, _NEW_ALGO) is False

    def test_new_not_registered_returns_false(self) -> None:
        mgr, _ = _migrator_and_registry(new_registered=False)
        assert mgr.can_migrate(_OLD_ALGO, _NEW_ALGO) is False

    def test_neither_registered_returns_false(self) -> None:
        mgr, _ = _migrator_and_registry(old_registered=False, new_registered=False)
        assert mgr.can_migrate(_OLD_ALGO, _NEW_ALGO) is False

    def test_same_algorithm_when_registered(self, migrator: CryptoMigrator) -> None:
        """Миграция из алгоритма в него же (если зарегистрирован)."""
        assert migrator.can_migrate(_OLD_ALGO, _OLD_ALGO) is True


# ==============================================================================
# CryptoMigrator.migrate_document — нормальный сценарий
# ==============================================================================


class TestMigrateDocumentSuccess:
    def test_returns_success_result(
        self,
        migrator: CryptoMigrator,
    ) -> None:
        encrypted = _NONCE_OLD + _FAKE_CT_OLD
        _, result = migrator.migrate_document(encrypted, _OLD_KEY, _NEW_KEY, _OLD_ALGO, _NEW_ALGO)

        assert result.success is True
        assert result.error is None
        assert result.old_algorithm == _OLD_ALGO
        assert result.new_algorithm == _NEW_ALGO

    def test_output_is_nonce_plus_ciphertext(
        self,
        migrator: CryptoMigrator,
    ) -> None:
        encrypted = _NONCE_OLD + _FAKE_CT_OLD
        new_data, result = migrator.migrate_document(
            encrypted, _OLD_KEY, _NEW_KEY, _OLD_ALGO, _NEW_ALGO
        )

        assert result.success is True
        assert new_data == _NONCE_NEW + _FAKE_CT_NEW

    def test_decrypt_called_with_correct_args(
        self,
        migrator: CryptoMigrator,
        registry: MagicMock,
        old_cipher: MagicMock,
    ) -> None:
        """decrypt вызывается с правильным nonce и ciphertext."""
        encrypted = _NONCE_OLD + _FAKE_CT_OLD
        migrator.migrate_document(encrypted, _OLD_KEY, _NEW_KEY, _OLD_ALGO, _NEW_ALGO)

        old_cipher.decrypt.assert_called_once_with(_OLD_KEY, _NONCE_OLD, _FAKE_CT_OLD)

    def test_encrypt_called_with_plaintext(
        self,
        migrator: CryptoMigrator,
        new_cipher: MagicMock,
    ) -> None:
        """encrypt нового шифра вызывается с расшифрованным plaintext."""
        encrypted = _NONCE_OLD + _FAKE_CT_OLD
        migrator.migrate_document(encrypted, _OLD_KEY, _NEW_KEY, _OLD_ALGO, _NEW_ALGO)

        new_cipher.encrypt.assert_called_once_with(_NEW_KEY, _PLAINTEXT)

    def test_old_nonce_explicit_skips_split(
        self,
        old_cipher: MagicMock,
        new_cipher: MagicMock,
        registry: MagicMock,
    ) -> None:
        """При old_nonce не выполняется разбивка данных."""
        migrator = CryptoMigrator(registry)  # type: ignore[arg-type]

        migrator.migrate_document(
            _FAKE_CT_OLD,
            _OLD_KEY,
            _NEW_KEY,
            _OLD_ALGO,
            _NEW_ALGO,
            old_nonce=_NONCE_OLD,
        )

        # decrypt получает весь _FAKE_CT_OLD как ciphertext, _NONCE_OLD как nonce
        old_cipher.decrypt.assert_called_once_with(_OLD_KEY, _NONCE_OLD, _FAKE_CT_OLD)

    def test_correct_algorithms_passed_to_registry(
        self,
        migrator: CryptoMigrator,
        registry: MagicMock,
    ) -> None:
        encrypted = _NONCE_OLD + _FAKE_CT_OLD
        migrator.migrate_document(encrypted, _OLD_KEY, _NEW_KEY, _OLD_ALGO, _NEW_ALGO)

        calls = [c.args[0] for c in registry.create.call_args_list]
        assert _OLD_ALGO in calls
        assert _NEW_ALGO in calls

    def test_logs_info_on_success(
        self,
        migrator: CryptoMigrator,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        with caplog.at_level(logging.INFO, logger="src.security.crypto.utilities.migration"):
            migrator.migrate_document(
                _NONCE_OLD + _FAKE_CT_OLD, _OLD_KEY, _NEW_KEY, _OLD_ALGO, _NEW_ALGO
            )

        assert any("migrated" in r.message.lower() for r in caplog.records)

    @pytest.mark.parametrize(
        "nonce_size",
        [12, 16, 24],
        ids=["nonce12", "nonce16", "nonce24"],
    )
    def test_nonce_split_uses_cipher_nonce_size(self, nonce_size: int) -> None:
        """Разбивка nonce/ciphertext определяется cipher.nonce_size."""
        nonce = b"\xaa" * nonce_size
        ciphertext = b"\xbb" * 32
        plaintext = b"data"
        encrypted = nonce + ciphertext

        old_cipher = _make_cipher(nonce_size=nonce_size, plaintext=plaintext)
        new_cipher = _make_cipher()
        reg = _make_registry(old_cipher=old_cipher, new_cipher=new_cipher)
        migrator = CryptoMigrator(reg)  # type: ignore[arg-type]

        migrator.migrate_document(encrypted, _OLD_KEY, _NEW_KEY, _OLD_ALGO, _NEW_ALGO)

        old_cipher.decrypt.assert_called_once_with(_OLD_KEY, nonce, ciphertext)


# ==============================================================================
# CryptoMigrator.migrate_document — ошибки
# ==============================================================================


class TestMigrateDocumentFailure:
    def test_decrypt_error_returns_failure(self) -> None:
        old_cipher = _make_cipher()
        old_cipher.decrypt.side_effect = ValueError("bad key")
        new_cipher = _make_cipher()
        reg = _make_registry(old_cipher=old_cipher, new_cipher=new_cipher)
        migrator = CryptoMigrator(reg)  # type: ignore[arg-type]

        original = _NONCE_OLD + _FAKE_CT_OLD
        returned_data, result = migrator.migrate_document(
            original, _OLD_KEY, _NEW_KEY, _OLD_ALGO, _NEW_ALGO
        )

        assert result.success is False
        assert result.error is not None
        assert "bad key" in result.error
        assert returned_data == original  # исходные данные без изменений

    def test_encrypt_error_returns_failure(self) -> None:
        old_cipher = _make_cipher(plaintext=_PLAINTEXT)
        new_cipher = _make_cipher()
        new_cipher.encrypt.side_effect = RuntimeError("encrypt failed")
        reg = _make_registry(old_cipher=old_cipher, new_cipher=new_cipher)
        migrator = CryptoMigrator(reg)  # type: ignore[arg-type]

        original = _NONCE_OLD + _FAKE_CT_OLD
        returned_data, result = migrator.migrate_document(
            original, _OLD_KEY, _NEW_KEY, _OLD_ALGO, _NEW_ALGO
        )

        assert result.success is False
        assert "encrypt failed" in (result.error or "")
        assert returned_data == original

    def test_registry_create_error_returns_failure(self) -> None:
        registry = MagicMock()
        registry.create.side_effect = KeyError("algo not found")
        migrator = CryptoMigrator(registry)  # type: ignore[arg-type]

        original = _NONCE_OLD + _FAKE_CT_OLD
        returned_data, result = migrator.migrate_document(
            original, _OLD_KEY, _NEW_KEY, _OLD_ALGO, _NEW_ALGO
        )

        assert result.success is False
        assert returned_data == original

    def test_failure_result_has_correct_algorithms(self) -> None:
        old_cipher = _make_cipher()
        old_cipher.decrypt.side_effect = Exception("err")
        reg = _make_registry(old_cipher=old_cipher)
        migrator = CryptoMigrator(reg)  # type: ignore[arg-type]

        _, result = migrator.migrate_document(
            _NONCE_OLD + _FAKE_CT_OLD, _OLD_KEY, _NEW_KEY, _OLD_ALGO, _NEW_ALGO
        )

        assert result.old_algorithm == _OLD_ALGO
        assert result.new_algorithm == _NEW_ALGO

    def test_logs_error_on_failure(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        old_cipher = _make_cipher()
        old_cipher.decrypt.side_effect = ValueError("boom")
        reg = _make_registry(old_cipher=old_cipher)
        migrator = CryptoMigrator(reg)  # type: ignore[arg-type]

        with caplog.at_level(logging.ERROR, logger="src.security.crypto.utilities.migration"):
            migrator.migrate_document(
                _NONCE_OLD + _FAKE_CT_OLD, _OLD_KEY, _NEW_KEY, _OLD_ALGO, _NEW_ALGO
            )

        assert any(r.levelno == logging.ERROR for r in caplog.records)


# ==============================================================================
# CryptoMigrator.bulk_migrate
# ==============================================================================


class TestBulkMigrate:
    def test_empty_list_returns_empty(self, migrator: CryptoMigrator) -> None:
        results = migrator.bulk_migrate([], _OLD_KEY, _NEW_KEY, _OLD_ALGO, _NEW_ALGO)
        assert results == []

    def test_result_length_matches_input(self, migrator: CryptoMigrator) -> None:
        docs = [_NONCE_OLD + _FAKE_CT_OLD] * 5
        results = migrator.bulk_migrate(docs, _OLD_KEY, _NEW_KEY, _OLD_ALGO, _NEW_ALGO)
        assert len(results) == 5

    def test_all_success(self, migrator: CryptoMigrator) -> None:
        docs = [_NONCE_OLD + _FAKE_CT_OLD] * 3
        results = migrator.bulk_migrate(docs, _OLD_KEY, _NEW_KEY, _OLD_ALGO, _NEW_ALGO)
        assert all(r.success for r in results)

    def test_partial_failure(self) -> None:
        """Второй документ слишком короткий для nonce_size=12 → ошибка расшифровки."""
        good_doc = _NONCE_OLD + _FAKE_CT_OLD  # 12 + 32 = 44 байта
        bad_doc = b"\x00" * 5  # меньше nonce_size → decrypt получит пустой ct

        # old_cipher.decrypt бросает исключение для плохих данных
        old_cipher = _make_cipher(nonce_size=12, plaintext=_PLAINTEXT)
        old_cipher.decrypt.side_effect = [
            _PLAINTEXT,  # первый вызов успешен
            ValueError("bad"),  # второй — нет
        ]
        new_cipher = _make_cipher()
        reg = _make_registry(old_cipher=old_cipher, new_cipher=new_cipher)
        migrator = CryptoMigrator(reg)  # type: ignore[arg-type]

        results = migrator.bulk_migrate(
            [good_doc, bad_doc], _OLD_KEY, _NEW_KEY, _OLD_ALGO, _NEW_ALGO
        )

        assert len(results) == 2
        assert results[0].success is True
        assert results[1].success is False

    def test_returns_migration_result_objects(self, migrator: CryptoMigrator) -> None:
        docs = [_NONCE_OLD + _FAKE_CT_OLD]
        results = migrator.bulk_migrate(docs, _OLD_KEY, _NEW_KEY, _OLD_ALGO, _NEW_ALGO)
        assert isinstance(results[0], MigrationResult)

    def test_logs_info_with_counts(
        self,
        migrator: CryptoMigrator,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        docs = [_NONCE_OLD + _FAKE_CT_OLD] * 3

        with caplog.at_level(logging.INFO, logger="src.security.crypto.utilities.migration"):
            migrator.bulk_migrate(docs, _OLD_KEY, _NEW_KEY, _OLD_ALGO, _NEW_ALGO)

        # Ожидаем запись с "3/3" или похожую
        bulk_logs = [r for r in caplog.records if "bulk" in r.message.lower() or "/" in r.message]
        assert bulk_logs, "Нет INFO лога о bulk-миграции"

    def test_bulk_all_fail_logs_0_succeeded(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        old_cipher = _make_cipher()
        old_cipher.decrypt.side_effect = Exception("always fails")
        reg = _make_registry(old_cipher=old_cipher)
        migrator = CryptoMigrator(reg)  # type: ignore[arg-type]

        docs = [_NONCE_OLD + _FAKE_CT_OLD] * 2
        with caplog.at_level(logging.INFO, logger="src.security.crypto.utilities.migration"):
            results = migrator.bulk_migrate(docs, _OLD_KEY, _NEW_KEY, _OLD_ALGO, _NEW_ALGO)

        assert all(not r.success for r in results)
        # Лог должен отразить 0 успешных
        assert any("0" in r.message and "2" in r.message for r in caplog.records)


# ==============================================================================
# Интеграционные тесты с реальным AlgorithmRegistry
# ==============================================================================


@pytest.mark.integration
class TestMigrationIntegration:
    """
    Тесты с реальным AES через AlgorithmRegistry.
    Проверяют реальное перешифрование данных.
    """

    @pytest.fixture
    def real_migrator(self) -> CryptoMigrator:
        from src.security.crypto.core.registry import AlgorithmRegistry, register_all_algorithms

        register_all_algorithms()
        return CryptoMigrator(AlgorithmRegistry.get_instance())  # type: ignore[arg-type]

    def test_can_migrate_aes_variants(self, real_migrator: CryptoMigrator) -> None:
        assert real_migrator.can_migrate("aes-128-gcm", "aes-256-gcm") is True

    def test_cannot_migrate_unknown_algorithm(self, real_migrator: CryptoMigrator) -> None:
        assert real_migrator.can_migrate("nonexistent-algo", "aes-256-gcm") is False

    def test_real_migration_roundtrip(self, real_migrator: CryptoMigrator) -> None:
        """После миграции данные расшифровываются новым ключом."""
        from src.security.crypto.core.registry import AlgorithmRegistry

        registry = AlgorithmRegistry.get_instance()

        old_key = os.urandom(16)  # AES-128
        new_key = os.urandom(32)  # AES-256
        plaintext = b"important document data"

        # Шифруем исходным алгоритмом
        old_cipher = registry.create("aes-128-gcm")
        nonce, ct = old_cipher.encrypt(old_key, plaintext)
        encrypted = nonce + ct

        # Мигрируем
        new_encrypted, result = real_migrator.migrate_document(
            encrypted, old_key, new_key, "aes-128-gcm", "aes-256-gcm"
        )

        assert result.success is True

        # Расшифровываем новым алгоритмом
        new_cipher = registry.create("aes-256-gcm")
        new_nonce = new_encrypted[: new_cipher.nonce_size]
        new_ct = new_encrypted[new_cipher.nonce_size :]
        decrypted = new_cipher.decrypt(new_key, new_nonce, new_ct)

        assert decrypted == plaintext

    def test_wrong_old_key_returns_failure(self, real_migrator: CryptoMigrator) -> None:
        """Неверный старый ключ → success=False, исходные данные возвращены."""
        from src.security.crypto.core.registry import AlgorithmRegistry

        registry = AlgorithmRegistry.get_instance()
        old_key = os.urandom(16)
        wrong_key = os.urandom(16)
        new_key = os.urandom(32)

        cipher = registry.create("aes-128-gcm")
        nonce, ct = cipher.encrypt(old_key, b"data")
        encrypted = nonce + ct

        returned, result = real_migrator.migrate_document(
            encrypted, wrong_key, new_key, "aes-128-gcm", "aes-256-gcm"
        )

        assert result.success is False
        assert result.error is not None
        assert returned == encrypted  # исходные данные без изменений

    def test_real_bulk_migration(self, real_migrator: CryptoMigrator) -> None:
        """Массовая миграция 5 документов с реальным AES."""
        from src.security.crypto.core.registry import AlgorithmRegistry

        registry = AlgorithmRegistry.get_instance()
        old_key = os.urandom(16)
        new_key = os.urandom(32)
        cipher = registry.create("aes-128-gcm")

        docs = []
        plaintexts = [f"doc-{i}".encode() for i in range(5)]
        for pt in plaintexts:
            nonce, ct = cipher.encrypt(old_key, pt)
            docs.append(nonce + ct)

        results = real_migrator.bulk_migrate(docs, old_key, new_key, "aes-128-gcm", "aes-256-gcm")

        assert len(results) == 5
        assert all(r.success for r in results)
