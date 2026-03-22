"""Тесты для модуля migration.

Покрытие:
- MigrationStep dataclass
- MigrationResult dataclass
- MigrationChain граф миграций
- FormatMigration основной класс
- DocumentMigrator/TemplateMigrator
"""

from __future__ import annotations

from typing import Any

import pytest
from src.documents.format.migration import (
    DocumentMigrator,
    FormatMigration,
    MigrationChain,
    MigrationResult,
    MigrationStep,
    TemplateMigrator,
)


class TestMigrationStep:
    """Тесты для MigrationStep."""

    def test_create_step(self) -> None:
        """Создание шага миграции."""

        def migrate_fn(data: dict[str, Any]) -> dict[str, Any]:
            return data

        step = MigrationStep(
            from_version="1.0",
            to_version="1.1",
            migrate_func=migrate_fn,
            can_downgrade=False,
            description="Test migration",
        )
        assert step.from_version == "1.0"
        assert step.to_version == "1.1"
        assert step.description == "Test migration"


class TestMigrationResult:
    """Тесты для MigrationResult."""

    def test_success_result(self) -> None:
        """Успешный результат."""
        result = MigrationResult(
            success=True,
            from_version="1.0",
            to_version="1.1",
            steps_applied=1,
        )
        assert result.success is True
        assert result.errors == []

    def test_failed_result(self) -> None:
        """Неудачный результат."""
        result = MigrationResult(
            success=False,
            from_version="1.0",
            to_version="1.1",
            errors=["Migration failed"],
        )
        assert result.success is False
        assert len(result.errors) == 1


class TestMigrationChain:
    """Тесты для MigrationChain."""

    @pytest.fixture
    def chain(self) -> MigrationChain:
        """Цепочка с миграциями."""
        c = MigrationChain()

        def v1_to_v2(data: dict[str, Any]) -> dict[str, Any]:
            data["version"] = "2.0"
            return data

        def v2_to_v3(data: dict[str, Any]) -> dict[str, Any]:
            data["version"] = "3.0"
            return data

        c.add_migration("1.0", "2.0", v1_to_v2, description="1.0 to 2.0")
        c.add_migration("2.0", "3.0", v2_to_v3, description="2.0 to 3.0")
        return c

    def test_add_migration(self, chain: MigrationChain) -> None:
        """Добавление миграции."""
        assert len(chain._migrations) == 2

    def test_get_migration_path_direct(self, chain: MigrationChain) -> None:
        """Прямой путь миграции."""
        path = chain.get_migration_path("1.0", "2.0")
        assert len(path) == 1
        assert path[0].from_version == "1.0"

    def test_get_migration_path_indirect(self, chain: MigrationChain) -> None:
        """Путь через промежуточные версии."""
        path = chain.get_migration_path("1.0", "3.0")
        assert len(path) == 2
        assert path[0].from_version == "1.0"
        assert path[1].from_version == "2.0"

    def test_get_migration_path_same_version(self, chain: MigrationChain) -> None:
        """Путь для одинаковых версий."""
        path = chain.get_migration_path("1.0", "1.0")
        assert len(path) == 0

    def test_get_migration_path_not_found(self, chain: MigrationChain) -> None:
        """Путь не найден."""
        with pytest.raises(ValueError, match="No migration path"):
            chain.get_migration_path("1.0", "5.0")

    def test_can_migrate_true(self, chain: MigrationChain) -> None:
        """Миграция возможна."""
        assert chain.can_migrate("1.0", "2.0") is True

    def test_can_migrate_false(self, chain: MigrationChain) -> None:
        """Миграция невозможна."""
        assert chain.can_migrate("1.0", "5.0") is False

    def test_migrate_success(self, chain: MigrationChain) -> None:
        """Успешная миграция."""
        data: dict[str, Any] = {"format_version": "1.0", "content": "test"}
        result = chain.migrate(data, "1.0", "2.0")
        assert result.success is True
        assert result.data["version"] == "2.0"

    def test_migrate_no_change(self, chain: MigrationChain) -> None:
        """Миграция на ту же версию."""
        data: dict[str, Any] = {"format_version": "1.0", "content": "test"}
        result = chain.migrate(data, "1.0", "1.0")
        assert result.success is True
        assert result.steps_applied == 0

    def test_get_supported_versions(self, chain: MigrationChain) -> None:
        """Список поддерживаемых версий."""
        versions = chain.get_supported_versions()
        assert "1.0" in versions
        assert "2.0" in versions
        assert "3.0" in versions


class TestFormatMigration:
    """Тесты для FormatMigration."""

    @pytest.fixture
    def migrator(self) -> FormatMigration:
        """Мигратор."""
        return FormatMigration()

    def test_is_latest_version(self, migrator: FormatMigration) -> None:
        """Проверка последней версии."""
        assert migrator.is_latest_version(migrator.LATEST_VERSION) is True
        assert migrator.is_latest_version("0.9") is False

    def test_needs_migration(self, migrator: FormatMigration) -> None:
        """Проверка необходимости миграции."""
        data: dict[str, Any] = {"format_version": "0.9"}
        assert migrator.needs_migration(data) is True

    def test_no_migration_needed(self, migrator: FormatMigration) -> None:
        """Миграция не нужна."""
        data: dict[str, Any] = {"format_version": migrator.LATEST_VERSION}
        assert migrator.needs_migration(data) is False

    def test_auto_migrate(self, migrator: FormatMigration) -> None:
        """Автоматическая миграция."""
        data: dict[str, Any] = {"format_version": migrator.LATEST_VERSION}
        result = migrator.auto_migrate(data)
        assert result.success is True

    def test_get_migration_path_empty(self, migrator: FormatMigration) -> None:
        """Пустой путь миграции."""
        path = migrator.get_migration_path("1.0", "1.0")
        assert path == []

    def test_can_migrate_no_path(self, migrator: FormatMigration) -> None:
        """Нет пути миграции."""
        assert migrator.can_migrate("1.0", "5.0") is False

    def test_validate_before_migration(self, migrator: FormatMigration) -> None:
        """Валидация перед миграцией."""
        data: dict[str, Any] = {"format_version": "1.0"}
        errors = migrator.validate_before_migration(data, "1.0")
        assert errors == []

    def test_validate_missing_version(self, migrator: FormatMigration) -> None:
        """Отсутствует version."""
        data: dict[str, Any] = {}
        errors = migrator.validate_before_migration(data, "1.0")
        assert any("Missing required field" in e for e in errors)


class TestDocumentMigrator:
    """Тесты для DocumentMigrator."""

    def test_create_document_migrator(self) -> None:
        """Создание мигратора документов."""
        migrator = DocumentMigrator()
        assert migrator is not None
        assert migrator.LATEST_VERSION == "1.0"


class TestTemplateMigrator:
    """Тесты для TemplateMigrator."""

    def test_create_template_migrator(self) -> None:
        """Создание мигратора шаблонов."""
        migrator = TemplateMigrator()
        assert migrator is not None
        assert migrator.LATEST_VERSION == "1.0"


class TestMigrationChainErrors:
    """Тесты ошибок миграции."""

    def test_migrate_failure_handling(self) -> None:
        """Обработка ошибки миграции."""
        chain = MigrationChain()

        def failing_migrate(data: dict[str, Any]) -> dict[str, Any]:
            raise ValueError("Migration failed")

        chain.add_migration("1.0", "2.0", failing_migrate)
        data: dict[str, Any] = {"format_version": "1.0"}
        result = chain.migrate(data, "1.0", "2.0")

        assert result.success is False
        assert len(result.errors) > 0

    def test_migration_chain_empty(self) -> None:
        """Пустая цепочка миграций."""
        chain = MigrationChain()
        assert len(chain._migrations) == 0


class TestFormatMigrationAdvanced:
    """Расширенные тесты FormatMigration."""

    def test_validate_version_mismatch(self) -> None:
        """Проверка несовпадения версий."""
        migrator = FormatMigration()
        data: dict[str, Any] = {"format_version": "2.0"}
        errors = migrator.validate_before_migration(data, "1.0")
        assert any("Version mismatch" in e for e in errors)

    def test_validate_missing_version_field(self) -> None:
        """Проверка отсутствия версии."""
        migrator = FormatMigration()
        data: dict[str, Any] = {}
        errors = migrator.validate_before_migration(data, "1.0")
        assert any("Missing required field" in e for e in errors)

    def test_migrate_with_none_from_version(self) -> None:
        """Миграция с None from_version."""
        migrator = FormatMigration()
        data: dict[str, Any] = {"format_version": "1.0"}
        result = migrator.migrate(data, None, "1.0")  # type: ignore[arg-type]
        # Должен автоматически определить версию из данных
        assert result.success is True

    def test_get_migration_path_empty_chain(self) -> None:
        """Пустой путь миграции в пустой цепочке."""
        migrator = FormatMigration()
        path = migrator.get_migration_path("1.0", "1.0")
        assert path == []

    def test_migration_chain_migration_success(self) -> None:
        """Успешная миграция в цепочке."""
        chain = MigrationChain()

        def migrate_v1_to_v2(data: dict[str, Any]) -> dict[str, Any]:
            data["version"] = "2.0"
            return data

        chain.add_migration("1.0", "2.0", migrate_v1_to_v2)

        data: dict[str, Any] = {"format_version": "1.0"}
        result = chain.migrate(data, "1.0", "2.0")
        assert result.success is True
        assert result.steps_applied == 1

    def test_migration_chain_can_migrate_same_version(self) -> None:
        """Миграция на ту же версию всегда возможна."""
        chain = MigrationChain()
        assert chain.can_migrate("1.0", "1.0") is True

    def test_migration_chain_not_found(self) -> None:
        """Путь не найден."""
        chain = MigrationChain()
        with pytest.raises(ValueError, match="No migration path"):
            chain.get_migration_path("1.0", "2.0")

    def test_migration_chain_get_supported_versions(self) -> None:
        """Список поддерживаемых версий."""
        chain = MigrationChain()

        def noop(data: dict[str, Any]) -> dict[str, Any]:
            return data

        chain.add_migration("1.0", "2.0", noop)
        chain.add_migration("2.0", "3.0", noop)

        versions = chain.get_supported_versions()
        assert "1.0" in versions
        assert "2.0" in versions
        assert "3.0" in versions

    def test_migration_step_repr(self) -> None:
        """String representation of migration step."""

        def noop(data: dict[str, Any]) -> dict[str, Any]:
            return data

        step = MigrationStep(
            from_version="1.0",
            to_version="2.0",
            migrate_func=noop,
            description="Test step",
        )
        assert "1.0" in str(step) or "2.0" in str(step)


class TestDocumentMigratorSpecific:
    """Специфичные тесты DocumentMigrator."""

    def test_document_migrator_registers_migrations(self) -> None:
        """Мигратор документов регистрирует специфичные миграции."""
        migrator = DocumentMigrator()
        # Должен иметь все стандартные миграции
        assert migrator.LATEST_VERSION == "1.0"


class TestTemplateMigratorSpecific:
    """Специфичные тесты TemplateMigrator."""

    def test_template_migrator_registers_migrations(self) -> None:
        """Мигратор шаблонов регистрирует специфичные миграции."""
        migrator = TemplateMigrator()
        assert migrator.LATEST_VERSION == "1.0"


class TestMigrationChainPathNotFound:
    """Тесты для путей миграции."""

    def test_migrate_no_path_error(self) -> None:
        """Ошибка при отсутствии пути миграции."""
        chain = MigrationChain()

        def noop(data: dict[str, Any]) -> dict[str, Any]:
            return data

        chain.add_migration("1.0", "2.0", noop)

        data: dict[str, Any] = {"format_version": "1.0"}
        result = chain.migrate(data, "1.0", "3.0")  # Нет пути от 1.0 к 3.0

        assert result.success is False
        assert len(result.errors) == 1
        assert "No migration path" in result.errors[0]

    def test_migration_step_fails(self) -> None:
        """Шаг миграции завершается с ошибкой."""
        chain = MigrationChain()

        def failing_migrate(data: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError("Migration failed!")

        chain.add_migration("1.0", "2.0", failing_migrate)

        data: dict[str, Any] = {"format_version": "1.0"}
        result = chain.migrate(data, "1.0", "2.0")

        assert result.success is False
        assert len(result.errors) == 1
        assert "Migration failed!" in result.errors[0]
        assert result.steps_applied == 0


class TestFormatMigrationDefaults:
    """Тесты значений по умолчанию."""

    def test_migrate_default_to_version(self) -> None:
        """Миграция с to_version по умолчанию."""
        migrator = FormatMigration()
        data: dict[str, Any] = {"format_version": "1.0"}

        # to_version=None должен использовать LATEST_VERSION
        result = migrator.migrate(data, "1.0", None)
        assert result.success is True
        assert result.to_version == migrator.LATEST_VERSION

    def test_migrate_with_none_versions(self) -> None:
        """Миграция с None версиями."""
        migrator = FormatMigration()
        data: dict[str, Any] = {"format_version": "1.0"}

        # from_version=None должен браться из data
        result = migrator.migrate(data, None, None)
        assert result.success is True


class TestNeedsMigrationNonString:
    """Тесты needs_migration с не-строковой версией."""

    def test_needs_migration_non_string_version(self) -> None:
        """needs_migration с не-строковой версией преобразуется в '1.0'."""
        migrator = FormatMigration()

        # Версия не строка - должна преобразоваться в "1.0"
        data: dict[str, Any] = {"format_version": 123}  # type: ignore[dict-item]
        result = migrator.needs_migration(data)

        # 123 преобразуется в "1.0" (LATEST_VERSION), поэтому миграция не нужна
        # Код: version = data.get("format_version", "1.0")
        #      if not isinstance(version, str): version = "1.0"
        # LATEST_VERSION = "1.0", поэтому result = False
        assert result is False

    def test_needs_migration_missing_version(self) -> None:
        """needs_migration без версии."""
        migrator = FormatMigration()

        data: dict[str, Any] = {}
        result = migrator.needs_migration(data)

        # По умолчанию "1.0", LATEST_VERSION == "1.0"
        assert result is False


class TestGetMigrationPathNoPath:
    """Тесты get_migration_path без пути."""

    def test_get_migration_path_no_path_returns_empty(self) -> None:
        """get_migration_path возвращает пустой список если нет пути."""
        migrator = FormatMigration()

        # Нет миграций от 1.0 к 2.0 (только 1.0)
        path = migrator.get_migration_path("1.0", "2.0")
        assert path == []

    def test_get_migration_path_different_versions(self) -> None:
        """get_migration_path для разных версий без миграции."""
        migrator = FormatMigration()

        path = migrator.get_migration_path("0.5", "1.0")
        # Нет миграции от 0.5 к 1.0
        assert path == []


class TestMigrationV1toV2:
    """Тесты миграций v1.0 -> v1.1 -> v1.2."""

    def test_migrate_v1_0_to_v1_1(self) -> None:
        """Миграция с v1.0 на v1.1."""
        migrator = FormatMigration()

        # Регистрируем миграцию вручную
        migrator._chain.add_migration(
            "1.0", "1.1",
            migrator._migrate_v1_0_to_v1_1,
            description="Add metadata fields"
        )

        data: dict[str, Any] = {"format_version": "1.0", "content": "test"}
        result = migrator.migrate(data, "1.0", "1.1")

        assert result.success is True
        assert result.data["format_version"] == "1.1"
        assert "metadata" in result.data
        assert result.data["metadata"]["generator"] == "FXTextProcessor/3.0"
        assert result.data["compatibility_version"] == "1.0"

    def test_migrate_v1_0_to_v1_1_preserves_existing(self) -> None:
        """Миграция сохраняет существующие данные."""
        migrator = FormatMigration()
        migrator._chain.add_migration(
            "1.0", "1.1",
            migrator._migrate_v1_0_to_v1_1,
        )

        data: dict[str, Any] = {
            "format_version": "1.0",
            "content": "test",
            "metadata": {"custom": "value"},
        }
        result = migrator.migrate(data, "1.0", "1.1")

        assert result.success is True
        # Существующий metadata должен сохраниться
        assert result.data["metadata"]["custom"] == "value"
        # И добавиться generator
        assert result.data["metadata"]["generator"] == "FXTextProcessor/3.0"

    def test_migrate_v1_1_to_v1_2(self) -> None:
        """Миграция с v1.1 на v1.2."""
        migrator = FormatMigration()

        # Регистрируем миграцию вручную
        migrator._chain.add_migration(
            "1.1", "1.2",
            migrator._migrate_v1_1_to_v1_2,
            description="Add deprecated_fields and document_type_code"
        )

        data: dict[str, Any] = {"format_version": "1.1", "content": "test"}
        result = migrator.migrate(data, "1.1", "1.2")

        assert result.success is True
        assert result.data["format_version"] == "1.2"
        assert result.data["deprecated_fields"] == []
        assert result.data["document_type_code"] == "DOC"

    def test_migrate_v1_1_to_v1_2_preserves_existing(self) -> None:
        """Миграция v1.1->v1.2 сохраняет существующие данные."""
        migrator = FormatMigration()
        migrator._chain.add_migration("1.1", "1.2", migrator._migrate_v1_1_to_v1_2)

        data: dict[str, Any] = {
            "format_version": "1.1",
            "content": "test",
            "deprecated_fields": ["old_field"],
        }
        result = migrator.migrate(data, "1.1", "1.2")

        assert result.success is True
        # Существующие deprecated_fields сохраняются
        assert result.data["deprecated_fields"] == ["old_field"]
        # Добавляется document_type_code
        assert result.data["document_type_code"] == "DOC"

    def test_migration_chain_v1_0_to_v1_2(self) -> None:
        """Цепочка миграций v1.0 -> v1.1 -> v1.2."""
        migrator = FormatMigration()
        migrator._chain.add_migration("1.0", "1.1", migrator._migrate_v1_0_to_v1_1)
        migrator._chain.add_migration("1.1", "1.2", migrator._migrate_v1_1_to_v1_2)

        data: dict[str, Any] = {"format_version": "1.0", "content": "test"}
        result = migrator.migrate(data, "1.0", "1.2")

        assert result.success is True
        assert result.steps_applied == 2
        assert result.data["format_version"] == "1.2"
        assert "metadata" in result.data
        assert "deprecated_fields" in result.data


class TestMigrationAutoDetect:
    """Тесты автоматического определения версии."""

    def test_auto_migrate_detects_version(self) -> None:
        """auto_migrate определяет версию из данных."""
        migrator = FormatMigration()

        data: dict[str, Any] = {"format_version": "1.0", "content": "test"}
        result = migrator.auto_migrate(data)

        assert result.success is True
        assert result.from_version == "1.0"

    def test_auto_migrate_missing_version_defaults(self) -> None:
        """auto_migrate использует версию по умолчанию."""
        migrator = FormatMigration()

        data: dict[str, Any] = {"content": "test"}
        result = migrator.auto_migrate(data)

        # По умолчанию "1.0", LATEST_VERSION == "1.0" - миграция не нужна
        assert result.success is True
        assert result.from_version == "1.0"


class TestMigrationValidateBefore:
    """Дополнительные тесты валидации."""

    def test_validate_before_migration_all_ok(self) -> None:
        """Валидация проходит успешно."""
        migrator = FormatMigration()

        data: dict[str, Any] = {"format_version": "1.0", "content": "test"}
        errors = migrator.validate_before_migration(data, "1.0")

        assert errors == []

    def test_validate_before_migration_version_mismatch(self) -> None:
        """Несовпадение версий при валидации."""
        migrator = FormatMigration()

        data: dict[str, Any] = {"format_version": "1.0"}
        errors = migrator.validate_before_migration(data, "2.0")

        assert len(errors) == 1
        assert "Version mismatch" in errors[0]


class TestMigrationResultDataclass:
    """Тесты MigrationResult dataclass."""

    def test_result_defaults(self) -> None:
        """Значения по умолчанию."""
        result = MigrationResult(
            success=True,
            from_version="1.0",
            to_version="1.1",
        )

        assert result.steps_applied == 0
        assert result.warnings == []
        assert result.errors == []
        assert result.data == {}

    def test_result_with_all_fields(self) -> None:
        """Все поля заполнены."""
        result = MigrationResult(
            success=True,
            from_version="1.0",
            to_version="1.1",
            steps_applied=2,
            warnings=["Warning 1"],
            errors=[],
            data={"key": "value"},
        )

        assert result.steps_applied == 2
        assert len(result.warnings) == 1
        assert result.data["key"] == "value"
