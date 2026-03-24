"""
Исключения модуля проверки целостности.

Иерархия:
    IntegrityError (базовое)
    ├── IntegrityCheckError
    └── ConfigSignatureError

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class IntegrityError(Exception):
    """
    Базовое исключение для ошибок проверки целостности.

    Attributes:
        message: Человекочитаемое описание ошибки
        check_type: Тип проверки (app_hash, config_signature)
        context: Дополнительный контекст для отладки
    """

    def __init__(
        self,
        message: str,
        *,
        check_type: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.check_type = check_type
        self.context = context or {}

    def __str__(self) -> str:
        parts = [self.__class__.__name__, ": ", self.message]
        if self.check_type:
            parts.append(f" [check={self.check_type}]")
        if self.context:
            ctx_str = ", ".join(f"{k}={v}" for k, v in self.context.items())
            parts.append(f" ({ctx_str})")
        return "".join(parts)

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"check_type={self.check_type!r}, "
            f"context={self.context!r})"
        )


class IntegrityCheckError(IntegrityError):
    """
    Ошибка проверки целостности приложения.

    Raises когда:
    - Хеш бинарника не совпадает с ожидаемым
    - Файл не найден или недоступен
    - Нарушение целостности кода

    Attributes:
        expected_hash: Ожидаемый хеш (hex)
        actual_hash: Фактический хеш (hex)
        file_path: Путь к проверяемому файлу
    """

    def __init__(
        self,
        message: str,
        *,
        expected_hash: Optional[str] = None,
        actual_hash: Optional[str] = None,
        file_path: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        ctx = context or {}
        if expected_hash:
            ctx["expected_hash"] = expected_hash[:16] + "..."  # Truncated for security
        if actual_hash:
            ctx["actual_hash"] = actual_hash[:16] + "..."
        if file_path:
            ctx["file_path"] = file_path

        super().__init__(message, check_type="app_hash", context=ctx)
        self.expected_hash = expected_hash
        self.actual_hash = actual_hash
        self.file_path = file_path


class ConfigSignatureError(IntegrityError):
    """
    Ошибка проверки подписи конфигурации.

    Raises когда:
    - Подпись конфигурации недействительна
    - Публичный ключ не найден
    - Конфигурация модифицирована

    Attributes:
        config_path: Путь к конфигурации
        signature_algorithm: Алгоритм подписи
    """

    def __init__(
        self,
        message: str,
        *,
        config_path: Optional[str] = None,
        signature_algorithm: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        ctx = context or {}
        if config_path:
            ctx["config_path"] = config_path
        if signature_algorithm:
            ctx["algorithm"] = signature_algorithm

        super().__init__(message, check_type="config_signature", context=ctx)
        self.config_path = config_path
        self.signature_algorithm = signature_algorithm


__all__: list[str] = [
    "IntegrityError",
    "IntegrityCheckError",
    "ConfigSignatureError",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-23"