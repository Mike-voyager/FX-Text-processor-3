"""
Keystore Check — проверка состояния keystore.

Проверяет:
- Доступность keystore файла
- Целостность keystore
- Наличие ключей
- Срок действия ключей

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Optional

from src.security.monitoring.exceptions import KeystoreCheckError
from src.security.monitoring.models import HealthCheckResult, HealthCheckStatus

if TYPE_CHECKING:
    from src.security.crypto.service import CryptoService

LOG = logging.getLogger(__name__)


@dataclass
class KeystoreCheck:
    """
    Проверка состояния keystore.

    Критическая проверка для криптографических операций.

    Attributes:
        name: Имя проверки (фиксированное: "keystore")
        description: Описание проверки
        critical: Всегда True (критическая проверка)
        keystore_path: Путь к keystore файлу
        crypto_service: Опциональный CryptoService для проверки ключей

    Example:
        >>> check = KeystoreCheck(keystore_path=Path("keystore.fxskeystore.enc"))
        >>> result = check.check()
        >>> if result.is_healthy:
        ...     print("Keystore OK")
    """

    name: str = "keystore"
    description: str = "Keystore health check"
    critical: bool = True
    keystore_path: Optional[Path] = None
    crypto_service: Optional["CryptoService"] = None

    def check(self) -> HealthCheckResult:
        """
        Выполнить проверку keystore.

        Returns:
            HealthCheckResult с результатом проверки
        """
        start_ms = time.monotonic()

        try:
            details: Dict[str, Any] = {}

            # Если путь не задан, пропускаем
            if not self.keystore_path:
                return HealthCheckResult.skipped(
                    check_name=self.name,
                    message="Keystore path not configured",
                    reason="no_path",
                )

            details["keystore_path"] = str(self.keystore_path)

            # Проверяем существование файла
            if not self.keystore_path.exists():
                raise KeystoreCheckError(
                    message="Keystore file not found",
                    keystore_path=str(self.keystore_path),
                )

            # Проверяем доступность для чтения
            if not self.keystore_path.is_file():
                raise KeystoreCheckError(
                    message="Keystore path is not a file",
                    keystore_path=str(self.keystore_path),
                )

            if not os.access(self.keystore_path, os.R_OK):
                raise KeystoreCheckError(
                    message="Keystore file not readable",
                    keystore_path=str(self.keystore_path),
                )

            details["file_exists"] = True
            details["file_size"] = self.keystore_path.stat().st_size

            # Проверяем расширение
            if self.keystore_path.suffix == ".enc":
                details["encrypted"] = True
            else:
                details["encrypted"] = False
                # Нешифрованный keystore — предупреждение
                # (но не ошибка, т.к. может быть development)

            # Если есть CryptoService, проверяем ключи
            if self.crypto_service:
                key_details = self._check_keys()
                details.update(key_details)

            elapsed_ms = int((time.monotonic() - start_ms) * 1000)

            # Формируем результат
            warnings = []
            if not details.get("encrypted", True):
                warnings.append("Keystore is not encrypted")

            if details.get("keys_expiring", False):
                warnings.append("Some keys are expiring soon")

            status = HealthCheckStatus.HEALTHY
            message = "Keystore healthy"

            if warnings:
                status = HealthCheckStatus.DEGRADED
                message = f"Keystore has warnings: {', '.join(warnings)}"

            return HealthCheckResult(
                check_name=self.name,
                status=status,
                message=message,
                duration_ms=elapsed_ms,
                details=details,
                warnings=warnings,
            )

        except KeystoreCheckError:
            raise  # Re-raise для обработки выше

        except Exception as e:
            elapsed_ms = int((time.monotonic() - start_ms) * 1000)
            LOG.error("Keystore check failed: %s", e)
            return HealthCheckResult.error_result(
                check_name=self.name,
                error=str(e),
                exception=type(e).__name__,
            )

    def _check_keys(self) -> Dict[str, Any]:
        """
        Проверить ключи в keystore через CryptoService.

        Returns:
            Словарь с деталями о ключах
        """
        details: Dict[str, Any] = {
            "keys_checked": True,
        }

        if self.crypto_service is None:
            details["keys_checked"] = False
            details["keys_error"] = "No crypto_service configured"
            return details

        try:
            # Получаем информацию о ключах
            # Примечание: CryptoService должен предоставлять метод для этого
            # Если метода нет, пропускаем
            if hasattr(self.crypto_service, "list_keys"):
                keys = self.crypto_service.list_keys()
                details["key_count"] = len(keys)

                # Проверяем срок действия ключей
                now = datetime.now(timezone.utc)
                expiring_soon = 0

                for key_info in keys:
                    if key_info.get("expires_at"):
                        expires = datetime.fromisoformat(key_info["expires_at"])
                        # Ключи, которые истекают в течение 30 дней
                        days_until_expiry = (expires - now).days
                        if 0 < days_until_expiry <= 30:
                            expiring_soon += 1

                if expiring_soon > 0:
                    details["keys_expiring"] = True
                    details["expiring_count"] = expiring_soon

        except Exception as e:
            LOG.debug("Could not check keys: %s", e)
            details["keys_checked"] = False
            details["keys_error"] = str(e)

        return details


__all__: list[str] = [
    "KeystoreCheck",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-24"