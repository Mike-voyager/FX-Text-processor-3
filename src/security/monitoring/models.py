"""
Модели данных для модуля мониторинга.

Определяет:
- HealthCheckStatus: Статус проверки
- HealthCheckResult: Результат отдельной проверки
- HealthCheckReport: Комплексный отчёт

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class HealthCheckStatus(Enum):
    """
    Статус health check.

    Status:
        HEALTHY: Проверка пройдена успешно
        DEGRADED: Проверка пройдена с предупреждениями
        UNHEALTHY: Проверка не пройдена
        SKIPPED: Проверка пропущена (не применима)
        ERROR: Ошибка выполнения проверки
    """

    HEALTHY = "healthy"
    """Проверка пройдена успешно."""

    DEGRADED = "degraded"
    """Проверка пройдена с предупреждениями."""

    UNHEALTHY = "unhealthy"
    """Проверка не пройдена."""

    SKIPPED = "skipped"
    """Проверка пропущена."""

    ERROR = "error"
    """Ошибка выполнения проверки."""

    @property
    def is_ok(self) -> bool:
        """Статус OK (healthy или degraded)."""
        return self in (HealthCheckStatus.HEALTHY, HealthCheckStatus.DEGRADED)

    @property
    def is_critical(self) -> bool:
        """Критический статус (unhealthy или error)."""
        return self in (HealthCheckStatus.UNHEALTHY, HealthCheckStatus.ERROR)

    @property
    def severity(self) -> int:
        """Уровень серьёзности (0=healthy, 4=error)."""
        severity_map = {
            HealthCheckStatus.HEALTHY: 0,
            HealthCheckStatus.DEGRADED: 1,
            HealthCheckStatus.SKIPPED: 2,
            HealthCheckStatus.UNHEALTHY: 3,
            HealthCheckStatus.ERROR: 4,
        }
        return severity_map[self]


@dataclass(frozen=True)
class HealthCheckResult:
    """
    Результат отдельной проверки.

    Immutable результат с детальной информацией.

    Attributes:
        check_name: Имя проверки (entropy, keystore, device, etc.)
        status: Статус проверки
        timestamp: Время выполнения (UTC)
        message: Человекочитаемое сообщение
        duration_ms: Длительность проверки в миллисекундах
        details: Дополнительные детали
        warnings: Список предупреждений
        error: Ошибка (если есть)
    """

    check_name: str
    status: HealthCheckStatus
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    message: str = ""
    duration_ms: int = 0
    details: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def __post_init__(self) -> None:
        """Валидация после создания."""
        object.__setattr__(self, "details", dict(self.details))
        object.__setattr__(self, "warnings", list(self.warnings))

    @property
    def is_healthy(self) -> bool:
        """Проверка успешна."""
        return self.status == HealthCheckStatus.HEALTHY

    @property
    def needs_attention(self) -> bool:
        """Требует внимания."""
        return self.status.is_critical

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь."""
        return {
            "check_name": self.check_name,
            "status": self.status.value,
            "timestamp": self.timestamp.isoformat(),
            "message": self.message,
            "duration_ms": self.duration_ms,
            "details": {k: str(v)[:100] for k, v in self.details.items()},
            "warnings": self.warnings[:5],  # Ограничиваем список
            "error": self.error,
        }

    @classmethod
    def healthy(
        cls,
        check_name: str,
        message: str = "Check passed",
        *,
        duration_ms: int = 0,
        details: Optional[Dict[str, Any]] = None,
    ) -> "HealthCheckResult":
        """Создать успешный результат."""
        return cls(
            check_name=check_name,
            status=HealthCheckStatus.HEALTHY,
            message=message,
            duration_ms=duration_ms,
            details=details or {},
        )

    @classmethod
    def degraded(
        cls,
        check_name: str,
        message: str,
        *,
        warnings: Optional[List[str]] = None,
        duration_ms: int = 0,
        details: Optional[Dict[str, Any]] = None,
    ) -> "HealthCheckResult":
        """Создать результат с предупреждениями."""
        return cls(
            check_name=check_name,
            status=HealthCheckStatus.DEGRADED,
            message=message,
            duration_ms=duration_ms,
            details=details or {},
            warnings=warnings or [],
        )

    @classmethod
    def unhealthy(
        cls,
        check_name: str,
        message: str,
        *,
        error: Optional[str] = None,
        duration_ms: int = 0,
        details: Optional[Dict[str, Any]] = None,
    ) -> "HealthCheckResult":
        """Создать неуспешный результат."""
        return cls(
            check_name=check_name,
            status=HealthCheckStatus.UNHEALTHY,
            message=message,
            duration_ms=duration_ms,
            details=details or {},
            error=error,
        )

    @classmethod
    def skipped(
        cls,
        check_name: str,
        message: str = "Check skipped",
        *,
        reason: Optional[str] = None,
    ) -> "HealthCheckResult":
        """Создать результат пропущенной проверки."""
        return cls(
            check_name=check_name,
            status=HealthCheckStatus.SKIPPED,
            message=message,
            details={"reason": reason} if reason else {},
        )

    @classmethod
    def error_result(
        cls,
        check_name: str,
        error: str,
        *,
        exception: Optional[str] = None,
    ) -> "HealthCheckResult":
        """Создать результат ошибки выполнения."""
        return cls(
            check_name=check_name,
            status=HealthCheckStatus.ERROR,
            message="Check execution failed",
            error=error,
            details={"exception": exception} if exception else {},
        )


@dataclass(frozen=True)
class HealthCheckReport:
    """
    Комплексный отчёт о состоянии системы.

    Содержит результаты всех проверок.

    Attributes:
        checks: Список результатов проверок
        overall_status: Общий статус системы
        timestamp: Время формирования отчёта
        version: Версия приложения
        platform: Платформа (linux/windows/darwin)
    """

    checks: List[HealthCheckResult]
    overall_status: HealthCheckStatus
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    version: str = "1.0.0"
    platform: str = "unknown"

    def __post_init__(self) -> None:
        """Валидация после создания."""
        object.__setattr__(self, "checks", list(self.checks))

    @property
    def healthy_count(self) -> int:
        """Количество успешных проверок."""
        return sum(1 for c in self.checks if c.status == HealthCheckStatus.HEALTHY)

    @property
    def degraded_count(self) -> int:
        """Количество проверок с предупреждениями."""
        return sum(1 for c in self.checks if c.status == HealthCheckStatus.DEGRADED)

    @property
    def unhealthy_count(self) -> int:
        """Количество неуспешных проверок."""
        return sum(1 for c in self.checks if c.status == HealthCheckStatus.UNHEALTHY)

    @property
    def skipped_count(self) -> int:
        """Количество пропущенных проверок."""
        return sum(1 for c in self.checks if c.status == HealthCheckStatus.SKIPPED)

    @property
    def error_count(self) -> int:
        """Количество ошибок выполнения."""
        return sum(1 for c in self.checks if c.status == HealthCheckStatus.ERROR)

    @property
    def critical_checks(self) -> List[HealthCheckResult]:
        """Список критических проверок."""
        return [c for c in self.checks if c.needs_attention]

    @property
    def is_healthy(self) -> bool:
        """Система в порядке."""
        return self.overall_status in (
            HealthCheckStatus.HEALTHY,
            HealthCheckStatus.DEGRADED,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация отчёта."""
        return {
            "checks": [c.to_dict() for c in self.checks],
            "overall_status": self.overall_status.value,
            "timestamp": self.timestamp.isoformat(),
            "version": self.version,
            "platform": self.platform,
            "summary": {
                "healthy": self.healthy_count,
                "degraded": self.degraded_count,
                "unhealthy": self.unhealthy_count,
                "skipped": self.skipped_count,
                "error": self.error_count,
                "total": len(self.checks),
            },
        }

    @classmethod
    def calculate_overall_status(
        cls,
        checks: List[HealthCheckResult],
    ) -> HealthCheckStatus:
        """Вычислить общий статус из списка проверок."""
        if not checks:
            return HealthCheckStatus.SKIPPED

        max_severity = max(c.status.severity for c in checks)

        severity_to_status = {
            0: HealthCheckStatus.HEALTHY,
            1: HealthCheckStatus.DEGRADED,
            2: HealthCheckStatus.SKIPPED,
            3: HealthCheckStatus.UNHEALTHY,
            4: HealthCheckStatus.ERROR,
        }

        return severity_to_status[max_severity]


__all__: list[str] = [
    "HealthCheckStatus",
    "HealthCheckResult",
    "HealthCheckReport",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-24"