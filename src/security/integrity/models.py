"""
Модели данных для проверки целостности.

Определяет структуры результатов проверки:
- IntegrityCheckResult: Результат проверки целостности
- ConfigSignatureResult: Результат проверки подписи конфигурации

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class IntegrityCheckResult:
    """Результат проверки целостности.

    Immutable результат с детальной информацией о проверке.

    Attributes:
        valid: True если проверка пройдена успешно
        reason: Человекочитаемое описание результата
        expected_hash: Ожидаемый хеш (опционально)
        actual_hash: Фактический хеш (опционально)
        timestamp: Время выполнения проверки (UTC)
        error_message: Сообщение об ошибке (если valid=False)
        warnings: Список предупреждений
        metadata: Дополнительные метаданные

    Security:
        - Хеши в выводе обрезаны для безопасности
        - Ошибки не содержат секретов
    """

    valid: bool
    reason: str
    expected_hash: Optional[str] = None
    actual_hash: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Валидация после создания."""
        object.__setattr__(self, "warnings", list(self.warnings))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def hash_match(self) -> Optional[bool]:
        """Проверка совпадения хешей.

        Returns:
            True если хеши совпадают, False если нет,
            None если хеши не проверялись
        """
        if self.expected_hash is None or self.actual_hash is None:
            return None
        return self.expected_hash == self.actual_hash

    @property
    def safe_hash_display(self) -> str:
        """Безопасное отображение хеша (обрезано).

        Returns:
            Обрезанный хеш для безопасного отображения
        """
        if self.actual_hash:
            return self.actual_hash[:16] + "..."
        return "<нет хеша>"

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация результата в словарь.

        Returns:
            Словарь с полями результата (хеши обрезаны)
        """
        return {
            "valid": self.valid,
            "reason": self.reason,
            "expected_hash": self.expected_hash[:16] + "..." if self.expected_hash else None,
            "actual_hash": self.actual_hash[:16] + "..." if self.actual_hash else None,
            "timestamp": self.timestamp.isoformat(),
            "error_message": self.error_message,
            "warnings": self.warnings,
            "metadata": {k: str(v)[:50] for k, v in self.metadata.items()},
        }


@dataclass(frozen=True)
class ConfigSignatureResult:
    """Результат проверки подписи конфига.

    Immutable результат проверки Ed25519 подписи конфигурации.

    Attributes:
        valid: True если подпись валидна
        tampered: True если данные были изменены (подпись не прошла)
        details: Детальное описание результата
        signer_key_id: Идентификатор ключа подписанта (опционально)
        signature_algorithm: Алгоритм подписи (по умолчанию Ed25519)
        timestamp: Время выполнения проверки
        metadata: Дополнительные метаданные
    """

    valid: bool
    tampered: bool
    details: str
    signer_key_id: Optional[str] = None
    signature_algorithm: str = "Ed25519"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Валидация после создания."""
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация результата в словарь."""
        return {
            "valid": self.valid,
            "tampered": self.tampered,
            "details": self.details,
            "signer_key_id": self.signer_key_id,
            "signature_algorithm": self.signature_algorithm,
            "timestamp": self.timestamp.isoformat(),
            "metadata": {k: str(v)[:50] for k, v in self.metadata.items()},
        }


__all__: list[str] = [
    "IntegrityCheckResult",
    "ConfigSignatureResult",
]

__version__ = "1.0.0"
__author__ = "FX Text Processor Team"
__date__ = "2026-03-23"
