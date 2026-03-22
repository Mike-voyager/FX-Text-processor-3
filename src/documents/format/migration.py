"""Миграция между версиями форматов документов и шаблонов.

Предоставляет:
- FormatMigration: Миграция данных между версиями формата
- MigrationChain: Цепочка миграций для автоматического обновления
- Миграции: v1.0 → v1.1, v1.1 → v1.2 и т.д.

Example:
    >>> from src.documents.format.migration import FormatMigration
    >>> migrator = FormatMigration()
    >>> data = migrator.migrate(document_data, from_version="1.0", to_version="1.2")

Architecture:
    - Каждая миграция — отдельная функция: _migrate_v1_0_to_v1_1(data)
    - Миграции применяются последовательно: 1.0 → 1.1 → 1.2
    - Поддерживается downgrade (откат) где возможно
    - Все миграции логируются
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Final

logger: Final = logging.getLogger(__name__)

# Типы для миграций
MigrationFunc = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class MigrationStep:
    """Один шаг миграции.

    Attributes:
        from_version: Исходная версия
        to_version: Целевая версия
        migrate_func: Функция миграции
        can_downgrade: Поддерживается ли откат
        description: Описание миграции
    """

    from_version: str
    to_version: str
    migrate_func: MigrationFunc
    can_downgrade: bool = False
    description: str = ""


@dataclass
class MigrationResult:
    """Результат миграции.

    Attributes:
        success: Успешность миграции
        from_version: Исходная версия
        to_version: Целевая версия
        steps_applied: Количество применённых шагов
        warnings: Список предупреждений
        errors: Список ошибок
        data: Результирующие данные
    """

    success: bool
    from_version: str
    to_version: str
    steps_applied: int = 0
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)


class MigrationChain:
    """Цепочка миграций для автоматического обновления формата.

    Управляет порядком миграций и применяет их последовательно.

    Example:
        >>> chain = MigrationChain()
        >>> chain.add_migration("1.0", "1.1", migrate_v1_0_to_v1_1)
        >>> chain.add_migration("1.1", "1.2", migrate_v1_1_to_v1_2)
        >>> result = chain.migrate(data, "1.0", "1.2")
    """

    def __init__(self) -> None:
        """Инициализирует пустую цепочку миграций."""
        self._migrations: dict[tuple[str, str], MigrationStep] = {}
        self._logger = logging.getLogger(__name__)

    def add_migration(
        self,
        from_version: str,
        to_version: str,
        migrate_func: MigrationFunc,
        can_downgrade: bool = False,
        description: str = "",
    ) -> None:
        """Добавляет шаг миграции в цепочку.

        Args:
            from_version: Исходная версия
            to_version: Целевая версия
            migrate_func: Функция миграции
            can_downgrade: Поддерживается ли откат
            description: Описание миграции
        """
        step = MigrationStep(
            from_version=from_version,
            to_version=to_version,
            migrate_func=migrate_func,
            can_downgrade=can_downgrade,
            description=description,
        )
        self._migrations[(from_version, to_version)] = step
        self._logger.debug(f"Added migration: {from_version} → {to_version}")

    def get_migration_path(self, from_version: str, to_version: str) -> list[MigrationStep]:
        """Находит путь миграции от from_version к to_version.

        Использует простой алгоритм поиска пути по графу версий.

        Args:
            from_version: Исходная версия
            to_version: Целевая версия

        Returns:
            Список шагов миграции

        Raises:
            ValueError: Если путь не найден
        """
        if from_version == to_version:
            return []

        # Прямая миграция
        if (from_version, to_version) in self._migrations:
            return [self._migrations[(from_version, to_version)]]

        # Ищем промежуточные версии
        visited: set[str] = {from_version}
        queue: list[tuple[str, list[MigrationStep]]] = [(from_version, [])]

        while queue:
            current, path = queue.pop(0)

            # Ищем все возможные следующие шаги
            for (fv, tv), step in self._migrations.items():
                if fv == current and tv not in visited:
                    if tv == to_version:
                        return path + [step]
                    visited.add(tv)
                    queue.append((tv, path + [step]))

        raise ValueError(f"No migration path from {from_version} to {to_version}")

    def can_migrate(self, from_version: str, to_version: str) -> bool:
        """Проверяет, возможна ли миграция.

        Args:
            from_version: Исходная версия
            to_version: Целевая версия

        Returns:
            True если миграция возможна
        """
        try:
            self.get_migration_path(from_version, to_version)
            return True
        except ValueError:
            return False

    def migrate(
        self,
        data: dict[str, Any],
        from_version: str,
        to_version: str,
    ) -> MigrationResult:
        """Выполняет миграцию данных.

        Args:
            data: Данные для миграции
            from_version: Исходная версия
            to_version: Целевая версия

        Returns:
            Результат миграции
        """
        result = MigrationResult(
            success=False,
            from_version=from_version,
            to_version=to_version,
        )

        if from_version == to_version:
            result.success = True
            result.data = data
            return result

        try:
            path = self.get_migration_path(from_version, to_version)
        except ValueError as e:
            result.errors.append(str(e))
            return result

        current_data = data.copy()
        result.steps_applied = 0

        for step in path:
            try:
                self._logger.info(f"Applying migration: {step.from_version} → {step.to_version}")
                current_data = step.migrate_func(current_data)
                result.steps_applied += 1

                # Обновляем версию в данных
                current_data["format_version"] = step.to_version

            except Exception as e:
                result.errors.append(
                    f"Migration {step.from_version} → {step.to_version} failed: {e}"
                )
                result.data = current_data
                return result

        result.success = True
        result.data = current_data
        return result

    def get_supported_versions(self) -> list[str]:
        """Возвращает список поддерживаемых версий.

        Returns:
            Список версий в порядке возрастания
        """
        versions: set[str] = set()
        for fv, tv in self._migrations.keys():
            versions.add(fv)
            versions.add(tv)
        return sorted(versions, key=lambda v: tuple(map(int, v.split("."))))


class FormatMigration:
    """Миграция форматов документов и шаблонов.

    Главный класс для миграции данных между версиями формата.
    Содержит предопределённые миграции для всех версий формата.

    Example:
        >>> migrator = FormatMigration()
        >>> result = migrator.migrate(document_data, "1.0", "1.2")
        >>> if result.success:
        ...     migrated_data = result.data
    """

    # Последняя поддерживаемая версия
    LATEST_VERSION: Final[str] = "1.0"

    def __init__(self) -> None:
        """Инициализирует мигратор с предопределёнными миграциями."""
        self._chain = MigrationChain()
        self._logger = logging.getLogger(__name__)
        self._register_default_migrations()

    def _register_default_migrations(self) -> None:
        """Регистрирует стандартные миграции.

        Версии формата:
        - 1.0: Базовая версия (текущая)
        """
        # Миграции будут добавлены здесь по мере выхода новых версий
        # Пример:
        # self._chain.add_migration(
        #     "1.0", "1.1",
        #     self._migrate_v1_0_to_v1_1,
        #     description="Add metadata fields"
        # )
        pass

    def migrate(
        self,
        data: dict[str, Any],
        from_version: str | None = None,
        to_version: str | None = None,
    ) -> MigrationResult:
        """Мигрирует данные от одной версии к другой.

        Args:
            data: Данные для миграции
            from_version: Исходная версия (по умолчанию — из data["format_version"])
            to_version: Целевая версия (по умолчанию — последняя)

        Returns:
            Результат миграции
        """
        if to_version is None:
            to_version = self.LATEST_VERSION

        # Автоопределение исходной версии
        if from_version is None:
            from_version = data.get("format_version", "1.0")
            assert from_version is not None

        self._logger.info(f"Starting migration: {from_version} → {to_version}")

        return self._chain.migrate(data, from_version, to_version)

    def auto_migrate(self, data: dict[str, Any]) -> MigrationResult:
        """Автоматически мигрирует данные до последней версии.

        Args:
            data: Данные для миграции

        Returns:
            Результат миграции
        """
        from_version = data.get("format_version", "1.0")
        return self.migrate(data, from_version, self.LATEST_VERSION)

    def is_latest_version(self, version: str) -> bool:
        """Проверяет, является ли версия последней.

        Args:
            version: Версия для проверки

        Returns:
            True если версия последняя
        """
        return version == self.LATEST_VERSION

    def needs_migration(self, data: dict[str, Any]) -> bool:
        """Проверяет, требуется ли миграция для данных.

        Args:
            data: Данные для проверки

        Returns:
            True если требуется миграция
        """
        version = data.get("format_version", "1.0")
        if not isinstance(version, str):
            version = "1.0"
        return version != self.LATEST_VERSION

    def get_migration_path(self, from_version: str, to_version: str) -> list[str]:
        """Возвращает путь миграции.

        Args:
            from_version: Исходная версия
            to_version: Целевая версия

        Returns:
            Список версий в пути миграции
        """
        if from_version == to_version:
            return []
        try:
            path = self._chain.get_migration_path(from_version, to_version)
            return [step.from_version for step in path] + [to_version]
        except ValueError:
            return []

    def can_migrate(self, from_version: str, to_version: str) -> bool:
        """Проверяет возможность миграции.

        Args:
            from_version: Исходная версия
            to_version: Целевая версия

        Returns:
            True если миграция возможна
        """
        return self._chain.can_migrate(from_version, to_version)

    def validate_before_migration(
        self,
        data: dict[str, Any],
        from_version: str,
    ) -> list[str]:
        """Валидирует данные перед миграцией.

        Args:
            data: Данные для валидации
            from_version: Исходная версия

        Returns:
            Список ошибок (пустой если всё валидно)
        """
        errors: list[str] = []

        # Проверка наличия обязательных полей
        required_fields = ["format_version"]
        for field_name in required_fields:
            if field_name not in data:
                errors.append(f"Missing required field: {field_name}")

        # Проверка версии
        current_version = data.get("format_version")
        if current_version != from_version:
            errors.append(f"Version mismatch: expected {from_version}, got {current_version}")

        return errors

    # === Миграции ===

    def _migrate_v1_0_to_v1_1(self, data: dict[str, Any]) -> dict[str, Any]:
        """Миграция с версии 1.0 на 1.1.

        Изменения:
        - Добавлено поле metadata.generator
        - Добавлено поле metadata.compatibility_version

        Args:
            data: Данные версии 1.0

        Returns:
            Данные версии 1.1
        """
        result = data.copy()

        # Добавляем generator если отсутствует
        if "metadata" not in result:
            result["metadata"] = {}
        if "generator" not in result["metadata"]:
            result["metadata"]["generator"] = "FXTextProcessor/3.0"

        # Добавляем compatibility_version
        if "compatibility_version" not in result:
            result["compatibility_version"] = "1.0"

        self._logger.debug("Migrated 1.0 → 1.1")
        return result

    def _migrate_v1_1_to_v1_2(self, data: dict[str, Any]) -> dict[str, Any]:
        """Миграция с версии 1.1 на 1.2.

        Изменения:
        - Добавлена поддержка deprecated_fields
        - Добавлено поле document_type_code

        Args:
            data: Данные версии 1.1

        Returns:
            Данные версии 1.2
        """
        result = data.copy()

        # Добавляем deprecated_fields если отсутствует
        if "deprecated_fields" not in result:
            result["deprecated_fields"] = []

        # Добавляем document_type_code
        if "document_type_code" not in result:
            result["document_type_code"] = "DOC"

        self._logger.debug("Migrated 1.1 → 1.2")
        return result


class DocumentMigrator(FormatMigration):
    """Специализированный мигратор для документов.

    Расширяет базовый FormatMigration специфичными для документов миграциями.
    """

    def __init__(self) -> None:
        """Инициализирует мигратор документов."""
        super().__init__()
        self._register_document_migrations()

    def _register_document_migrations(self) -> None:
        """Регистрирует миграции специфичные для документов."""
        # Будут добавлены по мере необходимости
        pass


class TemplateMigrator(FormatMigration):
    """Специализированный мигратор для шаблонов.

    Расширяет базовый FormatMigration специфичными для шаблонов миграциями.
    """

    def __init__(self) -> None:
        """Инициализирует мигратор шаблонов."""
        super().__init__()
        self._register_template_migrations()

    def _register_template_migrations(self) -> None:
        """Регистрирует миграции специфичные для шаблонов."""
        # Будут добавлены по мере необходимости
        pass


__all__ = [
    "FormatMigration",
    "MigrationChain",
    "MigrationStep",
    "MigrationResult",
    "DocumentMigrator",
    "TemplateMigrator",
]
