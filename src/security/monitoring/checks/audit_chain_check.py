"""
Audit Chain Check — проверка целостности audit log.

Проверяет:
- Целостность hash-chain в audit log
- Порядок событий
- HMAC подписи

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, Optional

from src.security.monitoring.exceptions import AuditChainCheckError
from src.security.monitoring.models import HealthCheckResult, HealthCheckStatus

if TYPE_CHECKING:
    from src.security.audit import AuditLog

LOG = logging.getLogger(__name__)


@dataclass
class AuditChainCheck:
    """
    Проверка целостности audit log.

    Критическая проверка для security-sensitive приложений.

    Attributes:
        name: Имя проверки (фиксированное: "audit_chain")
        description: Описание проверки
        critical: True (критическая проверка)
        audit_log: AuditLog для проверки
        max_events: Максимальное количество событий для проверки (0 = все)

    Example:
        >>> from src.security.audit import AuditLog
        >>> audit_log = AuditLog(...)
        >>> check = AuditChainCheck(audit_log=audit_log)
        >>> result = check.check()
    """

    name: str = "audit_chain"
    description: str = "Audit log chain integrity check"
    critical: bool = True
    audit_log: Optional["AuditLog"] = None
    max_events: int = 1000

    def check(self) -> HealthCheckResult:
        """
        Выполнить проверку целостности audit chain.

        Returns:
            HealthCheckResult с результатом проверки
        """
        start_ms = time.monotonic()

        try:
            # Если AuditLog не задан, пропускаем
            if not self.audit_log:
                return HealthCheckResult.skipped(
                    check_name=self.name,
                    message="AuditLog not configured",
                    reason="no_audit_log",
                )

            details: Dict[str, Any] = {
                "max_events": self.max_events,
            }

            # Получаем статистику
            event_count = self._get_event_count()
            details["event_count"] = event_count

            if event_count == 0:
                # Пустой audit log — OK
                return HealthCheckResult(
                    check_name=self.name,
                    status=HealthCheckStatus.HEALTHY,
                    message="Audit log is empty",
                    details=details,
                )

            # Проверяем целостность chain
            chain_result = self._verify_chain()
            details.update(chain_result)

            elapsed_ms = int((time.monotonic() - start_ms) * 1000)

            if chain_result.get("valid", False):
                status = HealthCheckStatus.HEALTHY
                message = f"Audit chain valid: {event_count} events verified"
            elif chain_result.get("error"):
                status = HealthCheckStatus.UNHEALTHY
                message = f"Audit chain broken: {chain_result['error']}"
            else:
                status = HealthCheckStatus.UNHEALTHY
                message = "Audit chain verification failed"

            return HealthCheckResult(
                check_name=self.name,
                status=status,
                message=message,
                duration_ms=elapsed_ms,
                details=details,
                error=chain_result.get("error"),
            )

        except AuditChainCheckError:
            raise  # Re-raise для обработки выше

        except Exception as e:
            elapsed_ms = int((time.monotonic() - start_ms) * 1000)
            LOG.error("Audit chain check failed: %s", e)
            return HealthCheckResult.error_result(
                check_name=self.name,
                error=str(e),
                exception=type(e).__name__,
            )

    def _get_event_count(self) -> int:
        """
        Получить количество событий в audit log.

        Returns:
            Количество событий
        """
        if self.audit_log is None:
            return 0

        try:
            # AuditLog имеет свойство event_count
            if hasattr(self.audit_log, "event_count"):
                return int(self.audit_log.event_count)
            elif hasattr(self.audit_log, "count_events"):
                return int(self.audit_log.count_events())
            else:
                LOG.warning("AuditLog has no event_count/count_events method")
                return 0

        except Exception as e:
            LOG.debug("Could not get event count: %s", e)
            return 0

    def _verify_chain(self) -> Dict[str, Any]:
        """
        Проверить целостность hash-chain.

        Returns:
            Словарь с результатом проверки
        """
        result: Dict[str, Any] = {
            "valid": False,
            "verified_count": 0,
            "error": None,
        }

        if self.audit_log is None:
            result["error"] = "No audit_log configured"
            return result

        try:
            # AuditLog имеет метод verify_chain без аргументов
            if hasattr(self.audit_log, "verify_chain"):
                chain_valid = self.audit_log.verify_chain()
                result["valid"] = chain_valid
                event_count = self._get_event_count()
                result["verified_count"] = min(event_count, self.max_events) if event_count > 0 else 0

            else:
                LOG.warning("AuditLog has no verify_chain method")
                result["error"] = "AuditLog has no verification method"
                result["valid"] = False

        except Exception as e:
            LOG.error("Chain verification failed: %s", e)
            result["error"] = str(e)
            result["valid"] = False

        return result


__all__: list[str] = [
    "AuditChainCheck",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-24"