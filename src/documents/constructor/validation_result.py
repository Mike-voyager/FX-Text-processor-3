"""Результаты валидации формы.

Предоставляет классы для представления результатов валидации формы
с поддержкой различных уровней серьёзности и политик валидации.

Example:
    >>> from src.documents.constructor.validation_result import (
    ...     ValidationResult, FieldValidationError,
    ...     ValidationSeverity, ValidationPolicy
    ... )
    >>> result = ValidationResult(policy=ValidationPolicy.STRICT)
    >>> result.add_field_error(
    ...     field_id="recipient",
    ...     message="Поле обязательно",
    ...     rule="required",
    ...     severity=ValidationSeverity.ERROR
    ... )
    >>> print(result.has_blocking_errors)
    True
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class ValidationSeverity(Enum):
    """Уровень серьёзности ошибки валидации.

    Attributes:
        ERROR: Блокирует подпись документа.
        WARNING: Предупреждение, но можно продолжить.
        INFO: Информационное сообщение.
    """

    ERROR = auto()  # Блокирует подпись
    WARNING = auto()  # Предупреждение, но можно продолжить
    INFO = auto()  # Информация


class ValidationPolicy(Enum):
    """Политика валидации формы.

    Attributes:
        STRICT: Все правила обязательны (рекомендуется для подписи).
        LENIENT: Только базовые проверки.
        CUSTOM: Пользовательский набор правил.
    """

    STRICT = "strict"  # Все правила обязательны
    LENIENT = "lenient"  # Только базовые проверки
    CUSTOM = "custom"  # Пользовательский набор


@dataclass(frozen=True)
class FieldValidationError:
    """Ошибка валидации поля.

    Attributes:
        field_id: Идентификатор поля.
        message: Сообщение об ошибке.
        severity: Уровень серьёзности.
        rule: Какое правило нарушено.

    Example:
        >>> error = FieldValidationError(
        ...     field_id="recipient",
        ...     message="Поле обязательно",
        ...     severity=ValidationSeverity.ERROR,
        ...     rule="required"
        ... )
        >>> print(error.message)
        Поле обязательно
    """

    field_id: str
    message: str
    severity: ValidationSeverity
    rule: str


@dataclass
class ValidationResult:
    """Результат валидации формы.

    Содержит информацию обо всех ошибках, предупреждениях
    и информационных сообщениях валидации формы.

    Attributes:
        is_valid: Флаг валидности формы.
        policy: Применённая политика валидации.
        field_errors: Словарь ошибок полей {field_id: [FieldValidationError]}.
        cross_field_errors: Список ошибок кросс-полевой валидации.
        warnings: Список предупреждений.
        info: Список информационных сообщений.

    Example:
        >>> result = ValidationResult(policy=ValidationPolicy.STRICT)
        >>> result.add_field_error("recipient", "Обязательно", "required")
        >>> print(result.is_valid)
        False
        >>> print(result.has_blocking_errors)
        True
    """

    is_valid: bool = True
    policy: ValidationPolicy = ValidationPolicy.STRICT
    field_errors: dict[str, list[FieldValidationError]] = field(default_factory=dict)
    cross_field_errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    info: list[str] = field(default_factory=list)

    @property
    def has_blocking_errors(self) -> bool:
        """Проверяет наличие ошибок, блокирующих подпись.

        Returns:
            True если есть ошибки с severity=ERROR.

        Example:
            >>> result = ValidationResult()
            >>> result.has_blocking_errors
            False
            >>> result.add_field_error("f", "err", "r", ValidationSeverity.ERROR)
            >>> result.has_blocking_errors
            True
        """
        return any(
            e.severity == ValidationSeverity.ERROR
            for errors in self.field_errors.values()
            for e in errors
        )

    @property
    def error_count(self) -> int:
        """Общее количество ошибок полей.

        Returns:
            Количество всех ошибок (всех severity).
        """
        return sum(len(errors) for errors in self.field_errors.values())

    @property
    def blocking_error_count(self) -> int:
        """Количество блокирующих ошибок.

        Returns:
            Количество ошибок с severity=ERROR.
        """
        return sum(
            1
            for errors in self.field_errors.values()
            for e in errors
            if e.severity == ValidationSeverity.ERROR
        )

    def add_field_error(
        self,
        field_id: str,
        message: str,
        rule: str,
        severity: ValidationSeverity = ValidationSeverity.ERROR,
    ) -> None:
        """Добавляет ошибку поля.

        Args:
            field_id: Идентификатор поля.
            message: Сообщение об ошибке.
            rule: Название нарушенного правила.
            severity: Уровень серьёзности (по умолчанию ERROR).

        Example:
            >>> result = ValidationResult()
            >>> result.add_field_error("email", "Неверный формат", "format")
            >>> print(result.error_count)
            1
        """
        if field_id not in self.field_errors:
            self.field_errors[field_id] = []
        self.field_errors[field_id].append(FieldValidationError(field_id, message, severity, rule))
        if severity == ValidationSeverity.ERROR:
            self.is_valid = False

    def add_cross_field_error(self, message: str) -> None:
        """Добавляет ошибку кросс-полевой валидации.

        Args:
            message: Сообщение об ошибке.

        Example:
            >>> result = ValidationResult()
            >>> result.add_cross_field_error("Дата окончания < даты начала")
            >>> result.is_valid = False
        """
        self.cross_field_errors.append(message)

    def add_warning(self, message: str) -> None:
        """Добавляет предупреждение.

        Args:
            message: Текст предупреждения.

        Example:
            >>> result = ValidationResult()
            >>> result.add_warning("Рекомендуется заполнить поле примечаний")
        """
        self.warnings.append(message)

    def add_info(self, message: str) -> None:
        """Добавляет информационное сообщение.

        Args:
            message: Текст сообщения.

        Example:
            >>> result = ValidationResult()
            >>> result.add_info("Валидация выполнена по схеме v2.0")
        """
        self.info.append(message)

    def get_field_errors(self, field_id: str) -> list[FieldValidationError]:
        """Возвращает ошибки конкретного поля.

        Args:
            field_id: Идентификатор поля.

        Returns:
            Список ошибок поля (пустой если нет ошибок).

        Example:
            >>> result = ValidationResult()
            >>> result.add_field_error("f", "err", "rule")
            >>> errors = result.get_field_errors("f")
            >>> len(errors)
            1
        """
        return self.field_errors.get(field_id, [])

    def has_field_errors(self, field_id: str) -> bool:
        """Проверяет наличие ошибок у поля.

        Args:
            field_id: Идентификатор поля.

        Returns:
            True если у поля есть ошибки.
        """
        return field_id in self.field_errors and len(self.field_errors[field_id]) > 0

    def to_dict(self) -> dict[str, Any]:
        """Сериализует результат в словарь.

        Returns:
            Словарь с данными результата валидации.

        Example:
            >>> result = ValidationResult()
            >>> data = result.to_dict()
            >>> "is_valid" in data
            True
        """
        return {
            "is_valid": self.is_valid,
            "policy": self.policy.value,
            "field_errors": {
                field_id: [
                    {
                        "field_id": e.field_id,
                        "message": e.message,
                        "severity": e.severity.name,
                        "rule": e.rule,
                    }
                    for e in errors
                ]
                for field_id, errors in self.field_errors.items()
            },
            "cross_field_errors": self.cross_field_errors,
            "warnings": self.warnings,
            "info": self.info,
            "has_blocking_errors": self.has_blocking_errors,
            "error_count": self.error_count,
        }

    def merge(self, other: ValidationResult) -> ValidationResult:
        """Объединяет с другим результатом валидации.

        Args:
            other: Другой результат для объединения.

        Returns:
            Новый объединённый результат.

        Example:
            >>> r1 = ValidationResult()
            >>> r1.add_field_error("f1", "err1", "r1")
            >>> r2 = ValidationResult()
            >>> r2.add_field_error("f2", "err2", "r2")
            >>> merged = r1.merge(r2)
            >>> merged.error_count
            2
        """
        merged = ValidationResult(
            is_valid=self.is_valid and other.is_valid,
            policy=self.policy if self.policy == other.policy else ValidationPolicy.CUSTOM,
        )

        # Копируем ошибки полей
        for field_id, errors in self.field_errors.items():
            merged.field_errors[field_id] = list(errors)
        for field_id, errors in other.field_errors.items():
            if field_id not in merged.field_errors:
                merged.field_errors[field_id] = []
            merged.field_errors[field_id].extend(errors)

        # Копируем остальные поля
        merged.cross_field_errors = self.cross_field_errors + other.cross_field_errors
        merged.warnings = self.warnings + other.warnings
        merged.info = self.info + other.info

        return merged
