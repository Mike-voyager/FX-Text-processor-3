"""
Config Check — проверка подписи конфигурации.

Проверяет:
- Целостность конфигурационного файла
- Валидность подписи (если включена)
- Структуру конфигурации

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Optional

from src.security.monitoring.exceptions import ConfigCheckError
from src.security.monitoring.models import HealthCheckResult, HealthCheckStatus

if TYPE_CHECKING:
    from src.security.integrity import ConfigIntegrityChecker

LOG = logging.getLogger(__name__)


@dataclass
class ConfigCheck:
    """
    Проверка целостности конфигурации.

    Некритическая проверка (приложение может использовать defaults).

    Attributes:
        name: Имя проверки (фиксированное: "config")
        description: Описание проверки
        critical: False (конфигурация опциональна)
        config_path: Путь к конфигурационному файлу
        signature_path: Путь к файлу подписи (опционально)
        integrity_checker: ConfigIntegrityChecker для проверки подписи

    Example:
        >>> check = ConfigCheck(config_path=Path("config.fxsconfig"))
        >>> result = check.check()
    """

    name: str = "config"
    description: str = "Configuration integrity check"
    critical: bool = False
    config_path: Optional[Path] = None
    signature_path: Optional[Path] = None
    integrity_checker: Optional["ConfigIntegrityChecker"] = None

    def check(self) -> HealthCheckResult:
        """
        Выполнить проверку конфигурации.

        Returns:
            HealthCheckResult с результатом проверки
        """
        start_ms = time.monotonic()

        try:
            details: Dict[str, Any] = {}

            # Если путь не задан, пропускаем
            if self.config_path is None:
                return HealthCheckResult.skipped(
                    check_name=self.name,
                    message="Config path not configured",
                    reason="no_path",
                )

            details["config_path"] = str(self.config_path)

            # Проверяем существование файла
            if not self.config_path.exists():
                # Конфигурация не найдена — используем defaults
                return HealthCheckResult.skipped(
                    check_name=self.name,
                    message="Config file not found, using defaults",
                    reason="file_not_found",
                )

            # Проверяем, что это файл
            if not self.config_path.is_file():
                raise ConfigCheckError(
                    message="Config path is not a file",
                    config_path=str(self.config_path),
                )

            # Проверяем доступность для чтения
            if not self._is_readable():
                raise ConfigCheckError(
                    message="Config file not readable",
                    config_path=str(self.config_path),
                )

            details["file_exists"] = True
            details["file_size"] = self.config_path.stat().st_size

            # Проверяем структуру JSON
            config_data = self._read_config()
            details["config_valid_json"] = True
            details["config_keys"] = list(config_data.keys())[:10]  # Первые 10 ключей

            # Проверяем подпись (если есть integrity_checker)
            if self.integrity_checker is not None:
                signature_result = self._verify_signature()
                details.update(signature_result)

                if not signature_result.get("valid", False):
                    return HealthCheckResult(
                        check_name=self.name,
                        status=HealthCheckStatus.UNHEALTHY,
                        message=f"Config signature invalid: {signature_result.get('error', 'unknown')}",
                        details=details,
                    )

            elapsed_ms = int((time.monotonic() - start_ms) * 1000)

            # Формируем результат
            status = HealthCheckStatus.HEALTHY
            message = "Configuration valid"
            warnings: list[str] = []

            # Предупреждение о неподписанной конфигурации
            if self.signature_path is not None and self.integrity_checker is None:
                warnings.append("Signature file exists but no integrity checker configured")

            return HealthCheckResult(
                check_name=self.name,
                status=status,
                message=message,
                duration_ms=elapsed_ms,
                details=details,
                warnings=warnings,
            )

        except ConfigCheckError:
            raise  # Re-raise для обработки выше

        except json.JSONDecodeError as e:
            elapsed_ms = int((time.monotonic() - start_ms) * 1000)
            LOG.error("Config JSON parse error: %s", e)
            return HealthCheckResult(
                check_name=self.name,
                status=HealthCheckStatus.UNHEALTHY,
                message=f"Config JSON parse error: {e}",
                duration_ms=elapsed_ms,
                details={"error": str(e)},
            )

        except Exception as e:
            elapsed_ms = int((time.monotonic() - start_ms) * 1000)
            LOG.error("Config check failed: %s", e)
            return HealthCheckResult.error_result(
                check_name=self.name,
                error=str(e),
                exception=type(e).__name__,
            )

    def _is_readable(self) -> bool:
        """Проверить доступность файла для чтения."""
        if self.config_path is None:
            return False
        try:
            return os.access(self.config_path, os.R_OK)
        except Exception:
            return False

    def _read_config(self) -> Dict[str, Any]:
        """
        Прочитать и распарсить конфигурацию.

        Returns:
            Словарь с конфигурацией

        Raises:
            json.JSONDecodeError: Ошибка парсинга JSON
        """
        if self.config_path is None:
            return {}
        content = self.config_path.read_text(encoding="utf-8")
        return json.loads(content)  # type: ignore[no-any-return]

    def _verify_signature(self) -> Dict[str, Any]:
        """
        Проверить подпись конфигурации.

        Returns:
            Словарь с результатом проверки
        """
        result: Dict[str, Any] = {
            "signature_verified": False,
            "valid": False,
        }

        if self.integrity_checker is None:
            result["error"] = "No integrity checker configured"
            return result

        if self.config_path is None:
            result["error"] = "No config path configured"
            return result

        try:
            # Используем check_config из ConfigIntegrityChecker
            check_result = self.integrity_checker.check_config(self.config_path)

            result["signature_verified"] = check_result.passed
            result["valid"] = check_result.passed

            if check_result.passed:
                result["signature_algorithm"] = "Ed25519"  # По умолчанию
                if check_result.actual_hash:
                    result["content_hash"] = check_result.actual_hash[:16] + "..."
            else:
                result["error"] = check_result.error_message or "Signature verification failed"

        except Exception as e:
            LOG.error("Signature verification failed: %s", e)
            result["error"] = str(e)
            result["valid"] = False

        return result


__all__: list[str] = [
    "ConfigCheck",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-24"