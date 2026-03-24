"""
Модели данных для проверки целостности.

Определяет структуры результатов проверки:
- IntegrityCheckType: Типы проверок
- IntegrityCheckResult: Результат проверки

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class IntegrityCheckType(Enum):
    """
    Типы проверок целостности.

    Types:
        APP_BINARY: Проверка хеша бинарника приложения
        CONFIG_FILE: Проверка подписи конфигурации
        ALL: Все проверки
    """

    APP_BINARY = "app_binary"
    """Проверка хеша бинарника приложения."""

    CONFIG_FILE = "config_file"
    """Проверка подписи конфигурационного файла."""

    ALL = "all"
    """Все проверки целостности."""

    @property
    def description(self) -> str:
        """Человекочитаемое описание типа проверки."""
        descriptions = {
            IntegrityCheckType.APP_BINARY: "Проверка хеша бинарника приложения",
            IntegrityCheckType.CONFIG_FILE: "Проверка подписи конфигурации",
            IntegrityCheckType.ALL: "Все проверки целостности",
        }
        return descriptions.get(self, f"Неизвестный тип: {self.value}")


@dataclass(frozen=True)
class IntegrityCheckResult:
    """
    Результат проверки целостности.

    Immutable результат с детальной информацией о проверке.

    Attributes:
        check_type: Тип выполненной проверки
        passed: True если проверка пройдена успешно
        timestamp: Время выполнения проверки (UTC)
        expected_hash: Ожидаемый хеш (опционально)
        actual_hash: Фактический хеш (опционально)
        file_path: Путь к проверенному файлу (опционально)
        signature_valid: Валидность подписи (для конфигурации)
        algorithm: Использованный алгоритм (sha3-256, Ed25519)
        error_message: Сообщение об ошибке (если passed=False)
        warnings: Список предупреждений
        metadata: Дополнительные метаданные

    Security:
        - Хеши в выводе обрезаны для безопасности
        - Ошибки не содержат секретов
    """

    check_type: IntegrityCheckType
    passed: bool
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expected_hash: Optional[str] = None
    actual_hash: Optional[str] = None
    file_path: Optional[str] = None
    signature_valid: Optional[bool] = None
    algorithm: Optional[str] = None
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Валидация после создания."""
        object.__setattr__(self, "warnings", list(self.warnings))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def hash_match(self) -> Optional[bool]:
        """
        Проверка совпадения хешей.

        Returns:
            True если хеши совпадают, False если нет,
            None если хеши не проверялись
        """
        if self.expected_hash is None or self.actual_hash is None:
            return None
        return self.expected_hash == self.actual_hash

    @property
    def safe_hash_display(self) -> str:
        """
        Безопасное отображение хеша (обрезано).

        Returns:
            Обрезанный хеш для безопасного отображения
        """
        if self.actual_hash:
            return self.actual_hash[:16] + "..."
        return "<нет хеша>"

    def to_dict(self) -> Dict[str, Any]:
        """
        Сериализация результата в словарь.

        Returns:
            Словарь с полями результата (хеши обрезаны)
        """
        return {
            "check_type": self.check_type.value,
            "passed": self.passed,
            "timestamp": self.timestamp.isoformat(),
            "expected_hash": self.expected_hash[:16] + "..." if self.expected_hash else None,
            "actual_hash": self.actual_hash[:16] + "..." if self.actual_hash else None,
            "file_path": self.file_path,
            "signature_valid": self.signature_valid,
            "algorithm": self.algorithm,
            "error_message": self.error_message,
            "warnings": self.warnings,
            "metadata": {k: str(v)[:50] for k, v in self.metadata.items()},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IntegrityCheckResult":
        """
        Десериализация результата из словаря.

        Args:
            data: Словарь с полями результата

        Returns:
            IntegrityCheckResult объект
        """
        return cls(
            check_type=IntegrityCheckType(data["check_type"]),
            passed=data["passed"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            expected_hash=data.get("expected_hash"),
            actual_hash=data.get("actual_hash"),
            file_path=data.get("file_path"),
            signature_valid=data.get("signature_valid"),
            algorithm=data.get("algorithm"),
            error_message=data.get("error_message"),
            warnings=data.get("warnings", []),
            metadata=data.get("metadata", {}),
        )


@dataclass(frozen=True)
class IntegrityReport:
    """
    Комплексный отчёт о проверке целостности.

    Содержит результаты всех выполненных проверок.

    Attributes:
        checks: Список результатов проверок
        overall_passed: True если все проверки пройдены
        timestamp: Время формирования отчёта
    """

    checks: List[IntegrityCheckResult]
    overall_passed: bool
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        """Валидация после создания."""
        object.__setattr__(self, "checks", list(self.checks))

    @property
    def failed_checks(self) -> List[IntegrityCheckResult]:
        """Список непройденных проверок."""
        return [c for c in self.checks if not c.passed]

    @property
    def passed_checks(self) -> List[IntegrityCheckResult]:
        """Список пройденных проверок."""
        return [c for c in self.checks if c.passed]

    @property
    def check_count(self) -> int:
        """Общее количество проверок."""
        return len(self.checks)

    @property
    def fail_count(self) -> int:
        """Количество непройденных проверок."""
        return len(self.failed_checks)

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация отчёта в словарь."""
        return {
            "checks": [c.to_dict() for c in self.checks],
            "overall_passed": self.overall_passed,
            "timestamp": self.timestamp.isoformat(),
            "check_count": self.check_count,
            "fail_count": self.fail_count,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IntegrityReport":
        """Десериализация отчёта из словаря."""
        return cls(
            checks=[IntegrityCheckResult.from_dict(c) for c in data["checks"]],
            overall_passed=data["overall_passed"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
        )


__all__: list[str] = [
    "IntegrityCheckType",
    "IntegrityCheckResult",
    "IntegrityReport",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-23"