"""Миграция между версиями форматов документов.

Этот модуль предоставляет MigrationManager для обновления документов
между различными версиями форматов, обеспечивая обратную совместимость.

Поддерживаемые версии:
    - 1.0: Начальная версия формата
    - 1.1: Добавлены метаданные безопасности

Примеры:
    >>> from src.documents.format.migration import MigrationManager, VersionInfo
    >>>
    >>> # Проверка необходимости миграции
    >>> manager = MigrationManager()
    >>> if manager.is_migration_needed("1.0"):
    ...     data = manager.migrate(data, "1.0", "1.1")
    >>>
    >>> # Информация о версии
    >>> info = VersionInfo.parse("1.0")
    >>> info.major
    1

Version: 1.0.0
Date: April 5, 2026
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Final

logger: Final = logging.getLogger(__name__)


class MigrationError(Exception):
    """Ошибка миграции формата документа."""

    pass


@dataclass(frozen=True)
class VersionInfo:
    """Информация о версии формата.

    Attributes:
        major: Мажорная версия
        minor: Минорная версия
        patch: Патч-версия (опционально)

    Example:
        >>> v = VersionInfo.parse("1.2.3")
        >>> v.major, v.minor, v.patch
        (1, 2, 3)
    """

    major: int
    minor: int
    patch: int = 0

    @classmethod
    def parse(cls, version_str: str) -> "VersionInfo":
        """Парсит строку версии.

        Args:
            version_str: Строка версии (например, "1.0" или "1.2.3")

        Returns:
            Объект VersionInfo

        Raises:
            ValueError: Если формат версии некорректен
        """
        parts = version_str.split(".")
        if len(parts) < 2:
            raise ValueError(f"Invalid version format: {version_str}")

        try:
            major = int(parts[0])
            minor = int(parts[1])
            patch = int(parts[2]) if len(parts) > 2 else 0
            return cls(major=major, minor=minor, patch=patch)
        except ValueError as e:
            raise ValueError(f"Invalid version numbers in: {version_str}") from e

    def __str__(self) -> str:
        """Строковое представление версии."""
        if self.patch:
            return f"{self.major}.{self.minor}.{self.patch}"
        return f"{self.major}.{self.minor}"

    def __lt__(self, other: "VersionInfo") -> bool:
        """Сравнение версий (меньше)."""
        return (self.major, self.minor, self.patch) < (
            other.major,
            other.minor,
            other.patch,
        )

    def __le__(self, other: "VersionInfo") -> bool:
        """Сравнение версий (меньше или равно)."""
        return (self.major, self.minor, self.patch) <= (
            other.major,
            other.minor,
            other.patch,
        )

    def __gt__(self, other: "VersionInfo") -> bool:
        """Сравнение версий (больше)."""
        return (self.major, self.minor, self.patch) > (
            other.major,
            other.minor,
            other.patch,
        )

    def __ge__(self, other: "VersionInfo") -> bool:
        """Сравнение версий (больше или равно)."""
        return (self.major, self.minor, self.patch) >= (
            other.major,
            other.minor,
            other.patch,
        )

    def __eq__(self, other: object) -> bool:
        """Сравнение версий (равно)."""
        if not isinstance(other, VersionInfo):
            return NotImplemented
        return (self.major, self.minor, self.patch) == (
            other.major,
            other.minor,
            other.patch,
        )

    def __hash__(self) -> int:
        """Хеш для использования в словарях."""
        return hash((self.major, self.minor, self.patch))


# Текущая версия формата
CURRENT_VERSION: Final[VersionInfo] = VersionInfo(major=1, minor=1)
SUPPORTED_VERSIONS: Final[list[VersionInfo]] = [
    VersionInfo(1, 0),
    VersionInfo(1, 1),
]


@dataclass(frozen=True)
class MigrationStep:
    """Шаг миграции между версиями.

    Attributes:
        from_version: Исходная версия.
        to_version: Целевая версия.
        migrate_func: Функция миграции.
        description: Описание миграции.
        can_downgrade: Возможен ли откат.
    """

    from_version: str
    to_version: str
    migrate_func: Callable[[dict[str, Any]], dict[str, Any]]
    description: str = ""
    can_downgrade: bool = False

    def __str__(self) -> str:
        """Строковое представление шага."""
        return f"{self.from_version} -> {self.to_version}: {self.description}"


@dataclass
class MigrationResult:
    """Результат миграции.

    Attributes:
        success: Успешность миграции.
        from_version: Исходная версия.
        to_version: Целевая версия.
        steps_applied: Количество применённых шагов.
        errors: Список ошибок.
        warnings: Список предупреждений.
        data: Мигрированные данные.
    """

    success: bool
    from_version: str
    to_version: str
    steps_applied: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)


class MigrationChain:
    """Цепочка миграций.

    Управляет графом миграций между версиями формата.
    """

    def __init__(self) -> None:
        """Инициализирует пустую цепочку миграций."""
        self._migrations: dict[str, dict[str, MigrationStep]] = {}
        self._versions: set[str] = set()

    def add_migration(
        self,
        from_version: str,
        to_version: str,
        migrate_func: Callable[[dict[str, Any]], dict[str, Any]],
        description: str = "",
        can_downgrade: bool = False,
    ) -> None:
        """Добавляет миграцию в цепочку.

        Args:
            from_version: Исходная версия.
            to_version: Целевая версия.
            migrate_func: Функция миграции.
            description: Описание миграции.
            can_downgrade: Возможен ли откат.
        """
        if from_version not in self._migrations:
            self._migrations[from_version] = {}

        self._migrations[from_version][to_version] = MigrationStep(
            from_version=from_version,
            to_version=to_version,
            migrate_func=migrate_func,
            description=description,
            can_downgrade=can_downgrade,
        )
        self._versions.add(from_version)
        self._versions.add(to_version)

    def get_migration_path(self, from_version: str, to_version: str) -> list[MigrationStep]:
        """Находит путь миграции между версиями.

        Args:
            from_version: Исходная версия.
            to_version: Целевая версия.

        Returns:
            Список шагов миграции.

        Raises:
            ValueError: Если путь не найден.
        """
        if from_version == to_version:
            return []

        # Прямая миграция
        if from_version in self._migrations and to_version in self._migrations[from_version]:
            return [self._migrations[from_version][to_version]]

        # Ищем путь через промежуточные версии (BFS)
        visited = {from_version}
        queue: list[tuple[str, list[MigrationStep]]] = [(from_version, [])]

        while queue:
            current, path = queue.pop(0)

            if current == to_version:
                return path

            if current in self._migrations:
                for next_version, step in self._migrations[current].items():
                    if next_version not in visited:
                        visited.add(next_version)
                        queue.append((next_version, path + [step]))

        raise ValueError(f"No migration path from {from_version} to {to_version}")

    def can_migrate(self, from_version: str, to_version: str) -> bool:
        """Проверяет возможность миграции.

        Args:
            from_version: Исходная версия.
            to_version: Целевая версия.

        Returns:
            True если миграция возможна.
        """
        if from_version == to_version:
            return True
        try:
            self.get_migration_path(from_version, to_version)
            return True
        except ValueError:
            return False

    def migrate(self, data: dict[str, Any], from_version: str, to_version: str) -> MigrationResult:
        """Выполняет миграцию данных.

        Args:
            data: Данные для миграции.
            from_version: Исходная версия.
            to_version: Целевая версия.

        Returns:
            Результат миграции.
        """
        if from_version == to_version:
            return MigrationResult(
                success=True,
                from_version=from_version,
                to_version=to_version,
                steps_applied=0,
                data=data,
            )

        try:
            path = self.get_migration_path(from_version, to_version)
            result_data = data.copy()

            for step in path:
                try:
                    result_data = step.migrate_func(result_data)
                except Exception as e:
                    return MigrationResult(
                        success=False,
                        from_version=from_version,
                        to_version=to_version,
                        steps_applied=0,
                        errors=[str(e)],
                        data=data,
                    )

            return MigrationResult(
                success=True,
                from_version=from_version,
                to_version=to_version,
                steps_applied=len(path),
                data=result_data,
            )

        except ValueError as e:
            return MigrationResult(
                success=False,
                from_version=from_version,
                to_version=to_version,
                steps_applied=0,
                errors=[str(e)],
                data=data,
            )

    def get_supported_versions(self) -> list[str]:
        """Возвращает список поддерживаемых версий.

        Returns:
            Список версий.
        """
        return sorted(self._versions)


class FormatMigration:
    """Основной класс миграции форматов.

    Предоставляет высокоуровневый интерфейс для миграции документов.
    """

    LATEST_VERSION: str = "1.0"

    def __init__(self) -> None:
        """Инициализирует мигратор форматов."""
        self._chain = MigrationChain()
        self._register_default_migrations()

    def _register_default_migrations(self) -> None:
        """Регистрирует стандартные миграции."""
        # Регистрируем миграции для версий 1.0, 1.1, 1.2
        self._chain.add_migration(
            "1.0", "1.1", self._migrate_v1_0_to_v1_1, description="Add metadata"
        )
        self._chain.add_migration(
            "1.1", "1.2", self._migrate_v1_1_to_v1_2, description="Add deprecated_fields"
        )

    def _migrate_v1_0_to_v1_1(self, data: dict[str, Any]) -> dict[str, Any]:
        """Миграция с 1.0 на 1.1."""
        result = data.copy()
        result["format_version"] = "1.1"
        if "metadata" not in result:
            result["metadata"] = {}
        # Preserve existing metadata and ensure generator field exists
        result["metadata"] = {
            "generator": result["metadata"].get("generator", "FXTextProcessor/3.0"),
            "migrated_from": "1.0",
            "migration_date": __import__("datetime").datetime.now().isoformat(),
            **result["metadata"],  # Preserve all existing fields
        }
        if "compatibility_version" not in result:
            result["compatibility_version"] = "1.0"
        return result

    def _migrate_v1_1_to_v1_2(self, data: dict[str, Any]) -> dict[str, Any]:
        """Миграция с 1.1 на 1.2."""
        result = data.copy()
        result["format_version"] = "1.2"
        if "deprecated_fields" not in result:
            result["deprecated_fields"] = []
        if "document_type_code" not in result:
            result["document_type_code"] = "DOC"
        return result

    def is_latest_version(self, version: str) -> bool:
        """Проверяет является ли версия последней.

        Args:
            version: Версия для проверки.

        Returns:
            True если версия последняя.
        """
        return version == self.LATEST_VERSION

    def needs_migration(self, data: dict[str, Any]) -> bool:
        """Проверяет необходимость миграции.

        Args:
            data: Данные документа.

        Returns:
            True если нужна миграция.
        """
        version = data.get("format_version", "1.0")
        if not isinstance(version, str):
            version = "1.0"
        return version != self.LATEST_VERSION

    def migrate(
        self,
        data: dict[str, Any],
        from_version: str | None,
        to_version: str | None,
    ) -> MigrationResult:
        """Выполняет миграцию данных.

        Args:
            data: Данные для миграции.
            from_version: Исходная версия (None = автоопределение).
            to_version: Целевая версия (None = LATEST_VERSION).

        Returns:
            Результат миграции.
        """
        # Определяем версии
        if from_version is None:
            version = data.get("format_version", "1.0")
            from_version = str(version) if isinstance(version, str) else "1.0"

        if to_version is None:
            to_version = self.LATEST_VERSION

        return self._chain.migrate(data, from_version, to_version)

    def auto_migrate(self, data: dict[str, Any]) -> MigrationResult:
        """Автоматически мигрирует данные до последней версии.

        Args:
            data: Данные для миграции.

        Returns:
            Результат миграции.
        """
        version = data.get("format_version", "1.0")
        if not isinstance(version, str):
            version = "1.0"
        return self.migrate(data, version, None)

    def get_migration_path(self, from_version: str, to_version: str) -> list[MigrationStep]:
        """Возвращает путь миграции.

        Args:
            from_version: Исходная версия.
            to_version: Целевая версия.

        Returns:
            Список шагов миграции.
        """
        try:
            return self._chain.get_migration_path(from_version, to_version)
        except ValueError:
            return []

    def can_migrate(self, from_version: str, to_version: str) -> bool:
        """Проверяет возможность миграции.

        Args:
            from_version: Исходная версия.
            to_version: Целевая версия.

        Returns:
            True если миграция возможна.
        """
        return self._chain.can_migrate(from_version, to_version)

    def validate_before_migration(self, data: dict[str, Any], expected_version: str) -> list[str]:
        """Валидирует данные перед миграцией.

        Args:
            data: Данные для валидации.
            expected_version: Ожидаемая версия.

        Returns:
            Список ошибок (пустой если валидно).
        """
        errors: list[str] = []

        if "format_version" not in data:
            errors.append("Missing required field: format_version")
        elif data.get("format_version") != expected_version:
            errors.append(
                f"Version mismatch: expected {expected_version}, got {data.get('format_version')}"
            )

        return errors


class DocumentMigrator(FormatMigration):
    """Мигратор документов."""

    LATEST_VERSION: str = "1.0"


class TemplateMigrator(FormatMigration):
    """Мигратор шаблонов."""

    LATEST_VERSION: str = "1.0"


def _migrate_1_0_to_1_1(data: dict[str, Any]) -> dict[str, Any]:
    """Миграция с версии 1.0 на 1.1.

    Изменения:
        - Добавлено поле security_metadata
        - Добавлено поле encryption_info
        - Поле format_version обновлено до "1.1"
    """
    result = data.copy()

    # Обновляем версию
    result["format_version"] = "1.1"

    # Добавляем security_metadata если отсутствует
    if "security_metadata" not in result:
        result["security_metadata"] = {
            "created_with": result.get("generator", "unknown"),
            "migrated_from": "1.0",
            "migration_date": __import__("datetime").datetime.now().isoformat(),
        }

    # Добавляем encryption_info если документ был зашифрован
    if result.get("encrypted") and "encryption_info" not in result:
        result["encryption_info"] = {
            "algorithm": "AES-256-GCM",
            "kdf": "Argon2id",
        }

    return result


def _migrate_1_1_to_1_0(data: dict[str, Any]) -> dict[str, Any]:
    """Даунгрейд с версии 1.1 на 1.0.

    Убирает поля, добавленные в 1.1.
    """
    result = data.copy()

    # Возвращаем старую версию
    result["format_version"] = "1.0"

    # Убираем новые поля
    result.pop("security_metadata", None)
    result.pop("encryption_info", None)

    return result


class MigrationManager:
    """Управление миграцией форматов.

    Предоставляет методы для миграции документов между версиями
    форматов с сохранением целостности данных.

    Attributes:
        _migrations: Словарь миграций {from_version: {to_version: callable}}

    Example:
        >>> manager = MigrationManager()
        >>>
        >>> # Проверка необходимости миграции
        >>> if manager.is_migration_needed("1.0"):
        ...     data = manager.migrate(data, "1.0", "1.1")
        >>>
        >>> # Получение информации о версии
        >>> info = manager.get_version_info("1.0")
    """

    def __init__(self) -> None:
        """Инициализирует менеджер миграций."""
        self._migrations: dict[str, dict[str, Callable[[dict[str, Any]], dict[str, Any]]]] = {
            "1.0": {"1.1": _migrate_1_0_to_1_1},
            "1.1": {"1.0": _migrate_1_1_to_1_0},
        }
        self._current_version = CURRENT_VERSION

    def migrate(self, data: bytes, from_version: str, to_version: str) -> bytes:
        """Миграция документа между версиями.

        Args:
            data: Данные документа (JSON bytes)
            from_version: Исходная версия формата
            to_version: Целевая версия формата

        Returns:
            Мигрированные данные (JSON bytes)

        Raises:
            MigrationError: При ошибке миграции
            ValueError: Если миграция невозможна

        Example:
            >>> migrated = manager.migrate(data, "1.0", "1.1")
        """
        try:
            from_version_info = VersionInfo.parse(from_version)
            to_version_info = VersionInfo.parse(to_version)

            # Проверяем, нужна ли миграция
            if from_version_info == to_version_info:
                return data

            # Парсим JSON
            json_data = json.loads(data.decode("utf-8"))

            # Прямая миграция если есть
            if from_version in self._migrations and to_version in self._migrations[from_version]:
                migrator = self._migrations[from_version][to_version]
                result = migrator(json_data)
                return json.dumps(result, ensure_ascii=False, indent=2).encode("utf-8")

            # Иначе ищем путь через промежуточные версии
            if from_version_info < to_version_info:
                # Апгрейд - ищем следующую версию
                path = self._find_upgrade_path(from_version_info, to_version_info)
            else:
                # Даунгрейд
                path = self._find_downgrade_path(from_version_info, to_version_info)

            if not path:
                raise MigrationError(f"No migration path from {from_version} to {to_version}")

            # Применяем миграции по цепочке
            result = json_data
            for i in range(len(path) - 1):
                current = str(path[i])
                next_ver = str(path[i + 1])
                if current in self._migrations and next_ver in self._migrations[current]:
                    migrator = self._migrations[current][next_ver]
                    result = migrator(result)
                else:
                    raise MigrationError(f"Missing migration from {current} to {next_ver}")

            return json.dumps(result, ensure_ascii=False, indent=2).encode("utf-8")

        except MigrationError:
            raise
        except Exception as e:
            raise MigrationError(f"Migration failed: {e}") from e

    def is_migration_needed(self, file_version: str) -> bool:
        """Проверка необходимости миграции.

        Args:
            file_version: Версия файла (строка)

        Returns:
            True если нужна миграция

        Example:
            >>> manager.is_migration_needed("1.0")
            True
        """
        try:
            file_ver = VersionInfo.parse(file_version)
            return file_ver < self._current_version
        except ValueError:
            logger.warning(f"Cannot parse version: {file_version}")
            return False

    def get_current_version(self) -> str:
        """Возвращает текущую версию формата.

        Returns:
            Строковое представление текущей версии
        """
        return str(self._current_version)

    def get_supported_versions(self) -> list[str]:
        """Возвращает список поддерживаемых версий.

        Returns:
            Список строк версий
        """
        return [str(v) for v in SUPPORTED_VERSIONS]

    def can_migrate(self, from_version: str, to_version: str) -> bool:
        """Проверяет, возможна ли миграция между версиями.

        Args:
            from_version: Исходная версия
            to_version: Целевая версия

        Returns:
            True если миграция возможна
        """
        if from_version == to_version:
            return True

        try:
            from_ver = VersionInfo.parse(from_version)
            to_ver = VersionInfo.parse(to_version)

            if from_ver < to_ver:
                return self._find_upgrade_path(from_ver, to_ver) is not None
            else:
                return self._find_downgrade_path(from_ver, to_ver) is not None
        except ValueError:
            return False

    def _find_upgrade_path(
        self, from_ver: VersionInfo, to_ver: VersionInfo
    ) -> list[VersionInfo] | None:
        """Находит путь апгрейда между версиями.

        Args:
            from_ver: Начальная версия
            to_ver: Конечная версия

        Returns:
            Список версий для апгрейда или None
        """
        # Простая реализация - перебор всех версий
        versions = sorted([v for v in SUPPORTED_VERSIONS if from_ver <= v <= to_ver])
        if versions and versions[0] == from_ver and versions[-1] == to_ver:
            return versions
        return None

    def _find_downgrade_path(
        self, from_ver: VersionInfo, to_ver: VersionInfo
    ) -> list[VersionInfo] | None:
        """Находит путь даунгрейда между версиями.

        Args:
            from_ver: Начальная версия
            to_ver: Конечная версия

        Returns:
            Список версий для даунгрейда или None
        """
        versions = sorted([v for v in SUPPORTED_VERSIONS if to_ver <= v <= from_ver], reverse=True)
        if versions and versions[0] == from_ver and versions[-1] == to_ver:
            return versions
        return None

    def register_migration(
        self,
        from_version: str,
        to_version: str,
        migrator: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> None:
        """Регистрирует новую функцию миграции.

        Args:
            from_version: Исходная версия
            to_version: Целевая версия
            migrator: Функция миграции

        Example:
            >>> def my_migration(data):
            ...     data["new_field"] = "value"
            ...     return data
            >>> manager.register_migration("1.1", "1.2", my_migration)
        """
        if from_version not in self._migrations:
            self._migrations[from_version] = {}
        self._migrations[from_version][to_version] = migrator
        logger.debug(f"Registered migration from {from_version} to {to_version}")

    def get_version_info(self, version_str: str) -> VersionInfo:
        """Парсит и возвращает информацию о версии.

        Args:
            version_str: Строка версии

        Returns:
            Объект VersionInfo
        """
        return VersionInfo.parse(version_str)

    def validate_version(self, version_str: str) -> bool:
        """Проверяет валидность версии.

        Args:
            version_str: Строка версии

        Returns:
            True если версия валидна
        """
        try:
            VersionInfo.parse(version_str)
            return True
        except ValueError:
            return False


class DocumentMigrator:
    """Высокоуровневый класс для миграции документов.

    Обёртка над MigrationManager с дополнительной функциональностью
    для работы с файлами документов.

    Example:
        >>> migrator = DocumentMigrator()
        >>> migrator.migrate_file(Path("old_doc.fxsd"))
    """

    LATEST_VERSION: str = "1.0"

    def __init__(self) -> None:
        """Инициализирует мигратор документов."""
        self._manager = MigrationManager()

    def migrate_file(self, path: Path, target_version: str | None = None) -> bytes:
        """Мигрирует файл документа до целевой версии.

        Args:
            path: Путь к файлу
            target_version: Целевая версия (по умолчанию текущая)

        Returns:
            Мигрированные данные

        Raises:
            FileNotFoundError: Если файл не найден
            MigrationError: При ошибке миграции
        """
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        # Читаем файл
        with open(path, "rb") as f:
            data = f.read()

        # Определяем текущую версию
        try:
            json_data = json.loads(data.decode("utf-8"))
            current_version = json_data.get("format_version", "1.0")
        except (UnicodeDecodeError, json.JSONDecodeError):
            current_version = "1.0"

        # Определяем целевую версию
        if target_version is None:
            target_version = self._manager.get_current_version()

        # Мигрируем если нужно
        if current_version != target_version:
            data = self._manager.migrate(data, current_version, target_version)
            logger.info(f"Migrated {path} from {current_version} to {target_version}")

        return data

    def get_file_version(self, path: Path) -> str | None:
        """Возвращает версию формата файла.

        Args:
            path: Путь к файлу

        Returns:
            Версия формата или None если не удалось определить
        """
        if not path.exists():
            return None

        try:
            with open(path, "rb") as f:
                data = f.read()
            json_data = json.loads(data.decode("utf-8"))
            return json_data.get("format_version")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None


__all__ = [
    "MigrationManager",
    "DocumentMigrator",
    "VersionInfo",
    "MigrationError",
    "CURRENT_VERSION",
    "SUPPORTED_VERSIONS",
]
