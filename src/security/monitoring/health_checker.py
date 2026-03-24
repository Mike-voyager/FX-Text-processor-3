"""
Health Checker — реестр и исполнитель проверок системы.

HealthChecker управляет жизненным циклом health checks:
- Регистрация проверок
- Выполнение всех проверок
- Генерация комплексного отчёта

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import logging
import platform
import time
from typing import TYPE_CHECKING, Callable, Optional, Protocol, runtime_checkable

from src.security.monitoring.exceptions import HealthCheckError
from src.security.monitoring.models import (
    HealthCheckReport,
    HealthCheckResult,
    HealthCheckStatus,
)

if TYPE_CHECKING:
    from src.security.audit import AuditLog, AuditEventType

LOG = logging.getLogger(__name__)


@runtime_checkable
class HealthCheck(Protocol):
    """
    Протокол для health check.

    Любая проверка должна реализовывать этот протокол.

    Attributes:
        name: Уникальное имя проверки
        description: Человекочитаемое описание
        critical: Является ли проверка критической

    Methods:
        check: Выполнить проверку и вернуть результат
    """

    name: str
    description: str
    critical: bool

    def check(self) -> HealthCheckResult:
        """
        Выполнить проверку.

        Returns:
            HealthCheckResult с результатом проверки
        """
        ...


# Тип для функции проверки
HealthCheckFunc = Callable[[], HealthCheckResult]


class HealthChecker:
    """
    Реестр и исполнитель health checks.

    Управляет коллекцией проверок и их выполнением.

    Attributes:
        checks: Зарегистрированные проверки (имя -> проверка)
        version: Версия приложения
        audit_log: Опциональный AuditLog для логирования

    Thread Safety:
        - Регистрация проверок не thread-safe (выполняется при init)
        - Выполнение проверок thread-safe

    Example:
        >>> checker = HealthChecker(version="1.0.0")
        >>> checker.register_function("entropy", check_entropy)
        >>> checker.register_check(MyCustomCheck())
        >>> report = checker.run_all()
        >>> if not report.is_healthy:
        ...     print("System unhealthy!")
    """

    def __init__(
        self,
        *,
        version: str = "1.0.0",
        audit_log: Optional["AuditLog"] = None,
    ) -> None:
        """
        Инициализация HealthChecker.

        Args:
            version: Версия приложения
            audit_log: Опциональный AuditLog для логирования результатов
        """
        self._checks: dict[str, HealthCheck] = {}
        self._func_checks: dict[str, tuple[HealthCheckFunc, str, bool]] = {}
        self._version = version
        self._audit_log = audit_log

    @property
    def version(self) -> str:
        """Версия приложения."""
        return self._version

    @property
    def check_count(self) -> int:
        """Количество зарегистрированных проверок."""
        return len(self._checks) + len(self._func_checks)

    @property
    def check_names(self) -> list[str]:
        """Имена всех зарегистрированных проверок."""
        return list(self._checks.keys()) + list(self._func_checks.keys())

    # --------------------------------------------------------------------------
    # Registration
    # --------------------------------------------------------------------------

    def register_check(self, check: HealthCheck) -> None:
        """
        Зарегистрировать проверку (экземпляр HealthCheck).

        Args:
            check: Экземпляр проверки

        Raises:
            ValueError: Проверка с таким именем уже зарегистрирована
        """
        if check.name in self._checks or check.name in self._func_checks:
            raise ValueError(f"Check '{check.name}' already registered")

        self._checks[check.name] = check
        LOG.debug("Registered health check: %s", check.name)

    def register_function(
        self,
        name: str,
        func: HealthCheckFunc,
        *,
        description: str = "",
        critical: bool = False,
    ) -> None:
        """
        Зарегистрировать проверку как функцию.

        Args:
            name: Уникальное имя проверки
            func: Функция, возвращающая HealthCheckResult
            description: Описание проверки
            critical: Является ли проверка критической

        Raises:
            ValueError: Проверка с таким именем уже зарегистрирована
        """
        if name in self._checks or name in self._func_checks:
            raise ValueError(f"Check '{name}' already registered")

        self._func_checks[name] = (func, description, critical)
        LOG.debug("Registered function-based health check: %s", name)

    def unregister(self, name: str) -> bool:
        """
        Удалить проверку из реестра.

        Args:
            name: Имя проверки

        Returns:
            True если проверка была удалена
        """
        if name in self._checks:
            del self._checks[name]
            LOG.debug("Unregistered health check: %s", name)
            return True

        if name in self._func_checks:
            del self._func_checks[name]
            LOG.debug("Unregistered function-based health check: %s", name)
            return True

        return False

    # --------------------------------------------------------------------------
    # Execution
    # --------------------------------------------------------------------------

    def run_check(self, name: str) -> HealthCheckResult:
        """
        Выполнить одну проверку по имени.

        Args:
            name: Имя проверки

        Returns:
            Результат проверки

        Raises:
            KeyError: Проверка не найдена
        """
        if name in self._checks:
            check = self._checks[name]
            return self._execute_check(check)

        if name in self._func_checks:
            func, description, critical = self._func_checks[name]
            return self._execute_function_check(name, func, description, critical)

        raise KeyError(f"Check '{name}' not found")

    def run_all(self) -> HealthCheckReport:
        """
        Выполнить все зарегистрированные проверки.

        Returns:
            Комплексный отчёт со всеми результатами
        """
        LOG.info("Running all health checks (%d total)", self.check_count)

        start_time = time.monotonic()
        results: list[HealthCheckResult] = []

        # Выполняем проверки-экземпляры
        for name, check in sorted(self._checks.items()):
            result = self._execute_check(check)
            results.append(result)

        # Выполняем проверки-функции
        for name, (func, description, critical) in sorted(self._func_checks.items()):
            result = self._execute_function_check(name, func, description, critical)
            results.append(result)

        # Сортируем по имени для детерминированного порядка
        results.sort(key=lambda r: r.check_name)

        overall_status = HealthCheckReport.calculate_overall_status(results)

        report = HealthCheckReport(
            checks=results,
            overall_status=overall_status,
            version=self._version,
            platform=platform.system().lower(),
        )

        elapsed_ms = int((time.monotonic() - start_time) * 1000)
        LOG.info(
            "Health checks completed: status=%s, checks=%d, elapsed=%dms",
            overall_status.value,
            len(results),
            elapsed_ms,
        )

        # Логируем в audit
        self._log_to_audit(report)

        return report

    def run_critical(self) -> HealthCheckReport:
        """
        Выполнить только критические проверки.

        Returns:
            Отчёт с результатами критических проверок
        """
        LOG.info("Running critical health checks")

        results: list[HealthCheckResult] = []

        # Критические проверки-экземпляры
        for name, check in self._checks.items():
            if check.critical:
                result = self._execute_check(check)
                results.append(result)

        # Критические проверки-функции
        for name, (func, description, critical) in self._func_checks.items():
            if critical:
                result = self._execute_function_check(name, func, description, critical)
                results.append(result)

        results.sort(key=lambda r: r.check_name)

        overall_status = HealthCheckReport.calculate_overall_status(results)

        return HealthCheckReport(
            checks=results,
            overall_status=overall_status,
            version=self._version,
            platform=platform.system().lower(),
        )

    # --------------------------------------------------------------------------
    # Internal
    # --------------------------------------------------------------------------

    def _execute_check(self, check: HealthCheck) -> HealthCheckResult:
        """
        Выполнить проверку-экземпляр с обработкой ошибок.

        Args:
            check: Экземпляр проверки

        Returns:
            Результат проверки
        """
        start_ms = time.monotonic()

        try:
            LOG.debug("Executing health check: %s", check.name)
            result = check.check()

            elapsed_ms = int((time.monotonic() - start_ms) * 1000)

            # Обновляем duration если не установлен
            if result.duration_ms == 0:
                object.__setattr__(result, "duration_ms", elapsed_ms)

            LOG.debug(
                "Health check '%s' completed: status=%s, duration=%dms",
                check.name,
                result.status.value,
                result.duration_ms,
            )

            return result

        except HealthCheckError as e:
            elapsed_ms = int((time.monotonic() - start_ms) * 1000)
            LOG.warning("Health check '%s' failed with HealthCheckError: %s", check.name, e)
            return HealthCheckResult.error_result(
                check_name=check.name,
                error=str(e),
                exception=type(e).__name__,
            )

        except Exception as e:
            elapsed_ms = int((time.monotonic() - start_ms) * 1000)
            LOG.error("Health check '%s' failed with exception: %s", check.name, e)
            return HealthCheckResult.error_result(
                check_name=check.name,
                error=str(e),
                exception=type(e).__name__,
            )

    def _execute_function_check(
        self,
        name: str,
        func: HealthCheckFunc,
        description: str,
        critical: bool,
    ) -> HealthCheckResult:
        """
        Выполнить проверку-функцию с обработкой ошибок.

        Args:
            name: Имя проверки
            func: Функция проверки
            description: Описание
            critical: Критическая ли

        Returns:
            Результат проверки
        """
        start_ms = time.monotonic()

        try:
            LOG.debug("Executing function-based health check: %s", name)
            result = func()

            elapsed_ms = int((time.monotonic() - start_ms) * 1000)

            if result.duration_ms == 0:
                object.__setattr__(result, "duration_ms", elapsed_ms)

            LOG.debug(
                "Health check '%s' completed: status=%s, duration=%dms",
                name,
                result.status.value,
                result.duration_ms,
            )

            return result

        except HealthCheckError as e:
            LOG.warning("Health check '%s' failed with HealthCheckError: %s", name, e)
            return HealthCheckResult.error_result(
                check_name=name,
                error=str(e),
                exception=type(e).__name__,
            )

        except Exception as e:
            LOG.error("Health check '%s' failed with exception: %s", name, e)
            return HealthCheckResult.error_result(
                check_name=name,
                error=str(e),
                exception=type(e).__name__,
            )

    def _log_to_audit(self, report: HealthCheckReport) -> None:
        """
        Логировать отчёт в audit log.

        Args:
            report: Отчёт о проверках
        """
        if not self._audit_log:
            return

        try:
            # Определяем тип события на основе статуса
            # Используем INTEGRITY_CHECK_PASSED/FAILED для health checks
            from src.security.audit import AuditEventType

            event_type: AuditEventType = (
                AuditEventType.INTEGRITY_CHECK_PASSED
                if report.is_healthy
                else AuditEventType.INTEGRITY_CHECK_FAILED
            )

            self._audit_log.log_event(
                event_type,
                details={
                    "overall_status": report.overall_status.value,
                    "healthy_count": report.healthy_count,
                    "degraded_count": report.degraded_count,
                    "unhealthy_count": report.unhealthy_count,
                    "error_count": report.error_count,
                    "total_checks": len(report.checks),
                    "critical_checks": [c.check_name for c in report.critical_checks],
                },
            )

        except Exception as e:
            LOG.warning("Failed to log health check to audit: %s", e)


__all__: list[str] = [
    "HealthChecker",
    "HealthCheck",
    "HealthCheckFunc",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-24"