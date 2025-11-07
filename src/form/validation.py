"""
validation.py — универсальный валидатор структуры и содержимого для form builder,
расширяемый механизм встроенных и кастомных правил.
"""

from typing import Any, Dict, List, Callable, Optional, Protocol, Union, Tuple


class ValidationError(Exception):
    """Общая ошибка валидации."""

    def __init__(self, message: str, field: Optional[str] = None):
        super().__init__(message)
        self.field = field


class Validator(Protocol):
    """Расширяемый протокол кастомного валидатора поля."""

    def __call__(self, value: Any, context: Dict[str, Any]) -> Optional[str]: ...


class ValidationResult:
    """
    Результат валидации.
    errors: список ValidationError.
    """

    def __init__(self) -> None:
        self.errors: List[ValidationError] = []

    def add(self, error: ValidationError) -> None:
        self.errors.append(error)

    @property
    def ok(self) -> bool:
        return not self.errors


def is_string(value: Any, context: Dict[str, Any]) -> Optional[str]:
    if not isinstance(value, str):
        return "Value is not a string."
    return None


def is_int(value: Any, context: Dict[str, Any]) -> Optional[str]:
    if not isinstance(value, int):
        return "Value is not an integer."
    return None


def min_length(min_len: int) -> Validator:
    def validator(value: Any, context: Dict[str, Any]) -> Optional[str]:
        if not isinstance(value, str) or len(value) < min_len:
            return f"Value length less than {min_len}."
        return None

    return validator


def max_length(max_len: int) -> Validator:
    def validator(value: Any, context: Dict[str, Any]) -> Optional[str]:
        if not isinstance(value, str) or len(value) > max_len:
            return f"Value length greater than {max_len}."
        return None

    return validator


def required(value: Any, context: Dict[str, Any]) -> Optional[str]:
    if value is None or (isinstance(value, str) and value.strip() == ""):
        return "Value is required."
    return None


def greater_than(field: str) -> Validator:
    def validator(value: Any, context: Dict[str, Any]) -> Optional[str]:
        other = context.get(field)
        if other is not None and value <= other:
            return f"Must be greater than {field} ({other})"
        return None

    return validator


# Допишите любые rule-фабрики или паттерновые валидаторы по необходимости

BUILTIN_VALIDATORS: Dict[str, Validator] = {
    "string": is_string,
    "int": is_int,
    "required": required,
}


class FormValidator:
    """
    Универсальный валидатор для форм и их элементов.
    Позволяет проверять поля (по схеме), значения и согласованность.
    """

    def __init__(
        self,
        schema: Dict[str, List[Union[str, Validator]]],
        allow_extra: bool = True,
        stop_on_error: bool = False,
    ):
        """
        schema: mapping field -> список имен/builtin/custom validators или callable.
        Пример:
            {
                "name": ["string", required, min_length(2)],
                "age": ["int", required, custom_validator_fn],
                "sum": ["int", greater_than("cost")],
            }
        """
        self.schema = schema
        self.allow_extra = allow_extra
        self.stop_on_error = stop_on_error

    def validate(
        self, data: Dict[str, Any], context: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        result = ValidationResult()
        ctx = dict(context) if context else dict(data)
        for field, rules in self.schema.items():
            value = data.get(field)
            for rule in rules:
                if isinstance(rule, str):
                    validator = BUILTIN_VALIDATORS[rule]
                else:
                    validator = rule
                msg = validator(value, ctx)
                if msg:
                    result.add(ValidationError(f"{field}: {msg}", field=field))
                    if self.stop_on_error:
                        return result
        # Check for extra fields
        if not self.allow_extra:
            extra = set(data.keys()) - set(self.schema.keys())
            for k in extra:
                result.add(ValidationError(f"Extra field: {k}", field=k))
        return result
