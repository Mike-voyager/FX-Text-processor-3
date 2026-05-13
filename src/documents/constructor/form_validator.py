"""Валидатор форм перед подписью.

Предоставляет механизм валидации форм перед криптографической подписью.
Поддерживает политики валидации, кросс-полевую валидацию и проверку
соответствия схеме типа документа.

Example:
    >>> from src.documents.constructor.form_validator import FormValidator
    >>> from src.documents.constructor.validation_result import ValidationPolicy
    >>> from src.documents.types.type_schema import TypeSchema, FieldDefinition, FieldType
    >>>
    >>> validator = FormValidator(policy=ValidationPolicy.STRICT)
    >>> schema = TypeSchema(fields=(
    ...     FieldDefinition(
    ...         field_id="recipient",
    ...         field_type=FieldType.TEXT_INPUT,
    ...         label="Получатель",
    ...         required=True
    ...     ),
    ... ))
    >>>
    >>> class TestForm:
    ...     fields = {"recipient": ""}
    >>>
    >>> result = validator.validate(TestForm(), schema)
    >>> print(result.has_blocking_errors)
    True

Integration with BlankManager:
    >>> # В blank_manager.py:
    >>> validator = FormValidator(policy=ValidationPolicy.STRICT)
    >>> result = validator.validate(form, schema)
    >>> if result.has_blocking_errors:
    ...     raise FormValidationError("Validation failed")
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol

from src.documents.constructor.validation_result import (
    ValidationPolicy,
    ValidationResult as ValidationResultClass,
)

if TYPE_CHECKING:
    from src.documents.types.type_schema import FieldDefinition, FieldType, TypeSchema
    from src.model.document import Document

# Импортируем FieldType для runtime использования
from src.documents.types.type_schema import FieldType

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    """Уровень серьёзности ошибки валидации (для обратной совместимости).

    Attributes:
        ERROR: Блокирует подпись документа.
        WARNING: Предупреждение, но можно продолжить.
        INFO: Информационное сообщение.
    """

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True)
class ValidationResult:
    """Результат валидации одного поля (для обратной совместимости).

    Attributes:
        field_id: Идентификатор поля (None для ошибок уровня формы).
        severity: Уровень серьёзности.
        code: Код ошибки.
        message: Сообщение об ошибке.
    """

    field_id: str | None
    severity: Severity
    code: str
    message: str


class ValidationError(Exception):
    """Исключение при ошибках валидации формы.

    Attributes:
        results: Список результатов валидации с ошибками.
    """

    def __init__(self, results: list[ValidationResult]) -> None:
        """Инициализирует исключение.

        Args:
            results: Список результатов валидации.
        """
        self.results = results
        messages = [f"{r.field_id}: {r.message}" for r in results]
        super().__init__("; ".join(messages))


def _safe_parse_date(value: Any) -> date | None:
    """Безопасно парсит значение в дату.

    Args:
        value: Значение для парсинга.

    Returns:
        Дата или None если не удалось распарсить.
    """
    if value is None:
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        # Пробуем ISO формат
        try:
            return date.fromisoformat(value)
        except ValueError:
            pass
        # Пробуем европейский формат DD.MM.YYYY
        try:
            return datetime.strptime(value, "%d.%m.%Y").date()
        except ValueError:
            pass
    return None


def _safe_parse_number(value: Any) -> float | None:
    """Безопасно парсит значение в число.

    Args:
        value: Значение для парсинга.

    Returns:
        Число или None если не удалось распарсить.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        # Убираем пробелы и заменяем запятую на точку
        cleaned = value.replace(" ", "").replace(",", ".")
        try:
            return float(cleaned)
        except ValueError:
            pass
    return None


def _evaluate_required_if(condition: str, context: dict[str, Any]) -> bool:
    """Оценивает условие required_if.

    Args:
        condition: Условное выражение.
        context: Контекст с значениями полей.

    Returns:
        True если условие выполнено.
    """
    if not condition:
        return False

    # Парсим простые условия: field == 'value', field != 'value', field in ('a', 'b')
    condition = condition.strip()

    # Проверяем ==
    if "==" in condition:
        parts = condition.split("==", 1)
        if len(parts) == 2:
            field_name = parts[0].strip()
            expected = parts[1].strip().strip("'\"")
            actual = context.get(field_name, "")
            return str(actual) == expected

    # Проверяем !=
    if "!=" in condition:
        parts = condition.split("!=", 1)
        if len(parts) == 2:
            field_name = parts[0].strip()
            expected = parts[1].strip().strip("'\"")
            actual = context.get(field_name, "")
            return str(actual) != expected

    # Проверяем in
    if " in " in condition:
        parts = condition.split(" in ", 1)
        if len(parts) == 2:
            field_name = parts[0].strip()
            values_str = parts[1].strip()
            if values_str.startswith("(") and values_str.endswith(")"):
                values_str = values_str[1:-1]
                values = [v.strip().strip("'\"") for v in values_str.split(",")]
                actual = context.get(field_name, "")
                return str(actual) in values

    return False


def _evaluate_cross_field_rule(rule: str, context: dict[str, Any]) -> tuple[bool, str]:
    """Оценивает кросс-полевое правило.

    Args:
        rule: Правило для оценки.
        context: Контекст с значениями полей.

    Returns:
        Кортеж (успех, сообщение_об_ошибке).
    """
    if not rule:
        return True, ""

    rule = rule.strip()

    # Парсим простые правила: a > b, a < b, a >= b, a <= b
    for op in [">=", "<=", ">", "<"]:
        if op in rule:
            parts = rule.split(op, 1)
            if len(parts) == 2:
                left_field = parts[0].strip()
                right_field = parts[1].strip()
                left_val = _safe_parse_number(context.get(left_field))
                right_val = _safe_parse_number(context.get(right_field))

                if left_val is None or right_val is None:
                    return True, ""  # Не можем оценить - считаем валидным

                if op == ">":
                    if left_val <= right_val:
                        return False, f"{left_field} должно быть больше {right_field}"
                elif op == "<":
                    if left_val >= right_val:
                        return False, f"{left_field} должно быть меньше {right_field}"
                elif op == ">=":
                    if left_val < right_val:
                        return False, f"{left_field} должно быть больше или равно {right_field}"
                elif op == "<=":
                    if left_val > right_val:
                        return False, f"{left_field} должно быть меньше или равно {right_field}"

                return True, ""

    return True, ""


class FormInstance(Protocol):
    """Протокол для формы.

    Определяет минимальный интерфейс, необходимый для валидации.

    Attributes:
        fields: Словарь значений полей {field_id: value}.

    Example:
        >>> class MyForm:
        ...     fields = {"recipient": "John Doe", "amount": 100.0}
        >>>
        >>> # FormInstance - это Protocol, MyForm автоматически соответствует
    """

    fields: dict[str, Any]


class FormValidationError(Exception):
    """Исключение при ошибках валидации формы.

    Attributes:
        message: Сообщение об ошибке.
        result: Результат валидации с деталями.

    Example:
        >>> raise FormValidationError("Validation failed", result)
    """

    def __init__(self, message: str, result: ValidationResultClass | None = None) -> None:
        """Инициализирует исключение.

        Args:
            message: Сообщение об ошибке.
            result: Результат валидации (опционально).
        """
        super().__init__(message)
        self.message = message
        self.result = result

    def __str__(self) -> str:
        """Строковое представление ошибки."""
        if self.result:
            return f"{self.message}: {self.result.error_count} ошибок"
        return self.message


@dataclass
class ValidationConfig:
    """Конфигурация валидатора форм.

    Attributes:
        policy: Политика валидации.
        require_all_mandatory: Требовать все обязательные поля.
        validate_cross_fields: Выполнять кросс-полевую валидацию.
        check_schema_version: Проверять версию схемы.
        max_errors: Максимальное количество ошибок перед остановкой
            (None = без ограничения).

    Example:
        >>> config = ValidationConfig(
        ...     policy=ValidationPolicy.STRICT,
        ...     require_all_mandatory=True
        ... )
    """

    policy: ValidationPolicy = ValidationPolicy.STRICT
    require_all_mandatory: bool = True
    validate_cross_fields: bool = True
    check_schema_version: bool = True
    max_errors: int | None = None


class FormValidator:
    """Валидатор форм перед криптографической подписью.

    Выполняет полную валидацию формы по схеме типа документа:
    - Проверка обязательных полей
    - Валидация типов данных
    - Проверка паттернов и ограничений
    - Кросс-полевая валидация
    - Проверка версии схемы

    Attributes:
        _config: Конфигурация валидации.

    Example:
        >>> validator = FormValidator(policy=ValidationPolicy.STRICT)
        >>> result = validator.validate(form, schema)
        >>> if result.has_blocking_errors:
        ...     print("Форма не может быть подписана")
    """

    def __init__(
        self,
        policy: ValidationPolicy = ValidationPolicy.STRICT,
        require_all_mandatory: bool = True,
        validate_cross_fields: bool = True,
        check_schema_version: bool = True,
        strict_mode: bool = False,
    ):
        """Инициализирует валидатор форм.

        Args:
            policy: Политика валидации.
            require_all_mandatory: Требовать все обязательные поля.
            validate_cross_fields: Выполнять кросс-полевую валидацию.
            check_schema_version: Проверять версию схемы.
            strict_mode: Строгий режим (WARNING считается ERROR).
        """
        self._config = ValidationConfig(
            policy=policy,
            require_all_mandatory=require_all_mandatory,
            validate_cross_fields=validate_cross_fields,
            check_schema_version=check_schema_version,
        )
        self.strict_mode = strict_mode
        logger.debug(f"FormValidator initialized with policy={policy.value}")

    @property
    def policy(self) -> ValidationPolicy:
        """Текущая политика валидации."""
        return self._config.policy

    def validate(self, form: FormInstance, schema: TypeSchema) -> ValidationResultClass:
        """Выполняет полную валидацию формы по схеме.

        Проверяет все поля формы, выполняет кросс-полевую валидацию
        и проверяет версию схемы при необходимости.

        Args:
            form: Форма для валидации (любой объект с полем fields).
            schema: Схема типа документа.

        Returns:
            Результат валидации со всеми ошибками и предупреждениями.

        Example:
            >>> result = validator.validate(form, schema)
            >>> if not result.has_blocking_errors:
            ...     print("Форма готова к подписи")
        """
        result = ValidationResultClass(policy=self._config.policy)

        # 1. Проверка всех полей по схеме
        for field_def in schema.fields:
            self._validate_field(form, field_def, result)

            # Проверка на превышение лимита ошибок
            if self._config.max_errors and result.error_count >= self._config.max_errors:
                result.add_info(f"Валидация прервана после {self._config.max_errors} ошибок")
                break

        # 2. Кросс-полевая валидация
        if self._config.validate_cross_fields:
            self._validate_cross_fields(form, schema, result)

        # 3. Проверка версии схемы
        if self._config.check_schema_version:
            self._validate_schema_version(form, schema, result)

        # 4. Проверка неизвестных полей (только в STRICT режиме)
        if self._config.policy == ValidationPolicy.STRICT:
            self._validate_unknown_fields(form, schema, result)

        logger.info(
            f"Validation complete: {result.error_count} errors, {len(result.warnings)} warnings"
        )

        return result

    def validate_quick(self, form: FormInstance, schema: TypeSchema) -> ValidationResultClass:
        """Быстрая валидация только обязательных полей.

        Полезна для промежуточной валидации во время заполнения формы.

        Args:
            form: Форма для валидации.
            schema: Схема типа документа.

        Returns:
            Результат валидации обязательных полей.
        """
        result = ValidationResultClass(policy=ValidationPolicy.LENIENT)

        for field_def in schema.fields:
            if field_def.required:
                self._validate_field_required_only(form, field_def, result)

        return result

    def _validate_field(
        self, form: FormInstance, field_def: FieldDefinition, result: ValidationResultClass
    ) -> None:
        """Валидирует отдельное поле формы.

        Args:
            form: Форма с данными.
            field_def: Определение поля из схемы.
            result: Результат для накопления ошибок.
        """
        value = form.fields.get(field_def.field_id)

        # 1. Проверка обязательности
        if field_def.required and self._is_empty(value):
            result.add_field_error(
                field_def.field_id,
                f"Поле '{field_def.label}' обязательно для заполнения",
                "required",
            )
            if self._config.policy == ValidationPolicy.STRICT:
                return

        # 2. Кросс-полевые правила (до раннего возврата пустых полей)
        self._apply_cross_field_rules(form, field_def, result)

        if self._is_empty(value):
            return  # Необязательное пустое поле — ок

        # 3. Тип данных
        if not self._check_type(value, field_def.field_type):
            result.add_field_error(
                field_def.field_id,
                f"Неверный тип данных для '{field_def.label}'",
                "type_check",
            )
            return

        # 3. Максимальная длина
        if field_def.max_length is not None:
            str_value = str(value)
            if len(str_value) > field_def.max_length:
                result.add_field_error(
                    field_def.field_id,
                    f"Поле '{field_def.label}' превышает {field_def.max_length} символов",
                    "max_length",
                )

        # 4. Regex pattern
        if field_def.validation_pattern:
            if not re.match(field_def.validation_pattern, str(value)):
                result.add_field_error(
                    field_def.field_id,
                    f"Поле '{field_def.label}' не соответствует формату",
                    "pattern",
                )

        # 5. Проверка options для DROPDOWN/RADIO_GROUP
        if field_def.options is not None:
            if str(value) not in field_def.options:
                result.add_field_error(
                    field_def.field_id,
                    f"Поле '{field_def.label}' должно быть одним из: "
                    f"{', '.join(field_def.options)}",
                    "invalid_option",
                )

        # 6. Числовые ограничения (для NUMBER_INPUT, CURRENCY)
        if (
            field_def.field_type
            in (
                FieldType.NUMBER_INPUT,
                FieldType.CURRENCY,
            )
            and value is not None
        ):
            self._validate_number_constraints(field_def, value, result)

    def _validate_field_required_only(
        self, form: FormInstance, field_def: FieldDefinition, result: ValidationResultClass
    ) -> None:
        """Валидирует только обязательность поля (быстрая проверка).

        Args:
            form: Форма с данными.
            field_def: Определение поля.
            result: Результат для накопления ошибок.
        """
        value = form.fields.get(field_def.field_id)

        if field_def.required and self._is_empty(value):
            result.add_field_error(
                field_def.field_id,
                f"Поле '{field_def.label}' обязательно",
                "required",
            )

    def _check_type(self, value: Any, field_type: FieldType) -> bool:
        """Проверяет соответствие типа значения.

        Args:
            value: Значение для проверки.
            field_type: Ожидаемый тип поля.

        Returns:
            True если тип соответствует.
        """
        from src.documents.types.type_schema import FieldType

        type_map: dict[FieldType, tuple[type, ...]] = {
            FieldType.TEXT_INPUT: (str,),
            FieldType.NUMBER_INPUT: (int, float),
            FieldType.DATE_INPUT: (str,),  # ISO format string
            FieldType.DROPDOWN: (str,),
            FieldType.CHECKBOX: (bool,),
            FieldType.MULTI_LINE_TEXT: (str,),
            FieldType.EMAIL: (str,),
            FieldType.PHONE: (str,),
            FieldType.CURRENCY: (int, float),
            FieldType.STATIC_TEXT: (str,),
            FieldType.QR: (str,),
            FieldType.BARCODE: (str,),
            FieldType.RADIO_GROUP: (str,),
        }

        expected = type_map.get(field_type)
        if expected is None:
            # Для неизвестных типов разрешаем любое значение
            return True

        return isinstance(value, expected)

    def _is_empty(self, value: Any) -> bool:
        """Проверяет, является ли значение пустым.

        Args:
            value: Значение для проверки.

        Returns:
            True если значение пустое.
        """
        if value is None:
            return True
        if isinstance(value, str) and value.strip() == "":
            return True
        if isinstance(value, (list, dict)) and len(value) == 0:
            return True
        return False

    def _validate_number_constraints(
        self, field_def: FieldDefinition, value: Any, result: ValidationResultClass
    ) -> None:
        """Валидирует числовые ограничения поля.

        Args:
            field_def: Определение поля.
            value: Значение для проверки.
            result: Результат для накопления ошибок.
        """
        try:
            num_value = float(value) if isinstance(value, str) else float(value)
        except (ValueError, TypeError):
            result.add_field_error(
                field_def.field_id,
                f"Поле '{field_def.label}' должно быть числом",
                "number_format",
            )
            return

        if field_def.min_value is not None and num_value < field_def.min_value:
            result.add_field_error(
                field_def.field_id,
                f"Значение поля '{field_def.label}' должно быть не менее {field_def.min_value}",
                "min_value",
            )

        if field_def.max_value is not None and num_value > field_def.max_value:
            result.add_field_error(
                field_def.field_id,
                f"Значение поля '{field_def.label}' должно быть не более {field_def.max_value}",
                "max_value",
            )

    def _validate_cross_fields(
        self, form: FormInstance, schema: TypeSchema, result: ValidationResultClass
    ) -> None:
        """Выполняет кросс-полевую валидацию.

        Проверяет условные зависимости между полями, например:
        - дата окончания > даты начала
        - сумма платежа <= лимита

        Args:
            form: Форма с данными.
            schema: Схема типа документа.
            result: Результат для накопления ошибок.
        """
        # Проверка полей с required_if
        for field_def in schema.fields:
            if field_def.required_if and not field_def.required:
                # Проверяем условие
                should_be_required = self._evaluate_condition(field_def.required_if, form.fields)
                if should_be_required:
                    value = form.fields.get(field_def.field_id)
                    if self._is_empty(value):
                        result.add_field_error(
                            field_def.field_id,
                            f"Поле '{field_def.label}' обязательно "
                            f"при условии: {field_def.required_if}",
                            "conditional_required",
                        )

        # --- Дополнительные кросс-полевые проверки ---
        fields = form.fields

        # 1. Взаимная обязательность контактных данных
        email = fields.get("email")
        phone = fields.get("phone")
        if (not self._is_empty(email) and self._is_empty(phone)) or (
            not self._is_empty(phone) and self._is_empty(email)
        ):
            result.add_cross_field_error(
                "При указании одного контакта (email или телефон) необходимо заполнить оба"
            )

        # 2. Сумма и валюта
        amount = fields.get("amount")
        currency = fields.get("currency")
        if not self._is_empty(amount):
            amount_val = _safe_parse_number(amount)
            if amount_val is not None and amount_val > 0 and self._is_empty(currency):
                result.add_field_error(
                    "currency",
                    "При указании суммы необходимо выбрать валюту",
                    "amount_requires_currency",
                )

        # 3. Диапазон дат
        start_date = fields.get("start_date")
        end_date = fields.get("end_date")
        if not self._is_empty(start_date) and not self._is_empty(end_date):
            start_dt = _safe_parse_date(start_date)
            end_dt = _safe_parse_date(end_date)
            if start_dt is not None and end_dt is not None and end_dt <= start_dt:
                result.add_field_error(
                    "end_date",
                    "Дата окончания должна быть позже даты начала",
                    "end_date_after_start_date",
                )

    def _validate_schema_version(
        self, form: FormInstance, schema: TypeSchema, result: ValidationResultClass
    ) -> None:
        """Проверяет версию схемы формы.

        Args:
            form: Форма с данными.
            schema: Схема типа документа.
            result: Результат для накопления ошибок.
        """
        # Получаем версию схемы из метаданных формы
        form_schema_version = getattr(form, "metadata", {}).get("schema_version", None)

        if form_schema_version is not None:
            # Сравниваем версии
            if form_schema_version != schema.version:
                result.add_warning(
                    f"Версия схемы формы ({form_schema_version}) отличается "
                    f"от текущей ({schema.version})"
                )

    def _validate_unknown_fields(
        self, form: FormInstance, schema: TypeSchema, result: ValidationResultClass
    ) -> None:
        """Проверяет наличие полей не из схемы.

        В STRICT режиме предупреждает о неизвестных полях.

        Args:
            form: Форма с данными.
            schema: Схема типа документа.
            result: Результат для накопления предупреждений.
        """
        known_fields = {f.field_id for f in schema.fields}
        unknown_fields = set(form.fields.keys()) - known_fields

        for field_id in unknown_fields:
            result.add_warning(f"Неизвестное поле в форме: {field_id}")

    def _apply_cross_field_rules(
        self, form: FormInstance, field_def: FieldDefinition, result: ValidationResultClass
    ) -> None:
        """Применяет кросс-полевые правила валидации.

        Реализует специфические правила для типовых бизнес-форм:
        - ИНН (Russia): если ``country="RU"``, поле ``inn`` обязательно
          и должно содержать 10 или 12 цифр.
        - VAT: если ``vat_applicable=True``, поле ``vat_rate`` должно быть заполнено.
        - Contract: если ``contract_type="lease"``, поле ``lease_term`` обязательно.

        Args:
            form: Форма с данными.
            field_def: Определение поля с правилами.
            result: Результат для накопления ошибок.
        """
        fields = form.fields
        value = fields.get(field_def.field_id)
        is_empty = self._is_empty(value)

        match field_def.field_id:
            case "inn":
                if str(fields.get("country", "")).upper() == "RU":
                    if is_empty:
                        result.add_field_error(
                            field_def.field_id,
                            "Поле 'ИНН' обязательно для России",
                            "conditional_required",
                        )
                    elif not re.fullmatch(r"\d{10}|\d{12}", str(value)):
                        result.add_field_error(
                            field_def.field_id,
                            "ИНН должен содержать 10 или 12 цифр",
                            "invalid_inn_format",
                        )

            case "vat_rate":
                if fields.get("vat_applicable") is True and is_empty:
                    result.add_field_error(
                        field_def.field_id,
                        "При применении НДС необходимо указать ставку НДС",
                        "conditional_required",
                    )

            case "lease_term":
                if str(fields.get("contract_type", "")).lower() == "lease" and is_empty:
                    result.add_field_error(
                        field_def.field_id,
                        "Для договора аренды необходимо указать срок аренды",
                        "conditional_required",
                    )

    def _evaluate_condition(self, condition: str, fields: dict[str, Any]) -> bool:
         """Оценивает условное выражение для поля.
 
         Args:
             condition: Условное выражение (например, "field_id == 'value'").
             fields: Словарь значений полей.
 
         Returns:
             True если условие выполнено.
 
         Note:
             Упрощённая реализация - в production должна использоваться
             более безопасная система выражений.
         """
         # Упрощённая реализация для базовых случаев
         # В production здесь должна быть безопасная система разбора выражений
         try:
             # Безопасная оценка простых условий
             parts = condition.split("==")
             if len(parts) == 2:
                 field_ref = parts[0].strip()
                 expected_value = parts[1].strip().strip("'\"")
                 actual_value = fields.get(field_ref, "")
                 return str(actual_value) == expected_value
         except (AttributeError, ValueError, TypeError) as e:
             logger.debug(f"Error evaluating condition '{condition}': {e}")
             pass
         except Exception as e:
             logger.exception(f"Unexpected error evaluating condition '{condition}': {e}")
             pass
         return False

    def validate_field(
        self,
        field_id: str,
        value: Any,
        field_def: FieldDefinition,
        context: dict[str, Any] | None = None,
    ) -> list[ValidationResult]:
        """Валидирует отдельное поле.

        Args:
            field_id: Идентификатор поля.
            value: Значение поля.
            field_def: Определение поля из схемы.
            context: Контекст для условной валидации.

        Returns:
            Список результатов валидации.
        """
        from src.documents.types.type_schema import FieldType
        from src.model.document import Document

        results: list[ValidationResult] = []

        # Проверка обязательности
        is_empty = value is None or (isinstance(value, str) and value.strip() == "")

        if field_def.required and is_empty:
            results.append(
                ValidationResult(
                    field_id=field_id,
                    severity=Severity.ERROR,
                    code="required_field_empty",
                    message=f"Поле '{field_def.label}' обязательно для заполнения",
                )
            )
            return results

        # Условная обязательность
        if field_def.required_if and is_empty and context is not None:
            if _evaluate_required_if(field_def.required_if, context):
                results.append(
                    ValidationResult(
                        field_id=field_id,
                        severity=Severity.ERROR,
                        code="conditional_required_field_empty",
                        message=f"Поле '{field_def.label}' обязательно при условии: {field_def.required_if}",
                    )
                )
                return results

        if is_empty:
            return results  # Необязательное пустое поле — ок

        # Валидация по типу поля
        if field_def.field_type == FieldType.NUMBER_INPUT:
            num_val = _safe_parse_number(value)
            if num_val is None:
                results.append(
                    ValidationResult(
                        field_id=field_id,
                        severity=Severity.ERROR,
                        code="invalid_number_format",
                        message=f"Поле '{field_def.label}' должно быть числом",
                    )
                )
            else:
                if field_def.min_value is not None and num_val < field_def.min_value:
                    results.append(
                        ValidationResult(
                            field_id=field_id,
                            severity=Severity.ERROR,
                            code="value_below_minimum",
                            message=f"Значение поля '{field_def.label}' должно быть не менее {field_def.min_value}",
                        )
                    )
                if field_def.max_value is not None and num_val > field_def.max_value:
                    results.append(
                        ValidationResult(
                            field_id=field_id,
                            severity=Severity.ERROR,
                            code="value_above_maximum",
                            message=f"Значение поля '{field_def.label}' должно быть не более {field_def.max_value}",
                        )
                    )

        elif field_def.field_type == FieldType.DATE_INPUT:
            date_val = _safe_parse_date(value)
            if date_val is None:
                results.append(
                    ValidationResult(
                        field_id=field_id,
                        severity=Severity.ERROR,
                        code="invalid_date_format",
                        message=f"Поле '{field_def.label}' должно быть датой",
                    )
                )
            else:
                if field_def.min_date is not None and date_val < field_def.min_date:
                    results.append(
                        ValidationResult(
                            field_id=field_id,
                            severity=Severity.ERROR,
                            code="date_before_minimum",
                            message=f"Дата поля '{field_def.label}' должна быть не раньше {field_def.min_date}",
                        )
                    )
                if field_def.max_date is not None and date_val > field_def.max_date:
                    results.append(
                        ValidationResult(
                            field_id=field_id,
                            severity=Severity.ERROR,
                            code="date_after_maximum",
                            message=f"Дата поля '{field_def.label}' должна быть не позже {field_def.max_date}",
                        )
                    )

        elif field_def.field_type == FieldType.EMAIL:
            import re

            email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            if not re.match(email_pattern, str(value)):
                results.append(
                    ValidationResult(
                        field_id=field_id,
                        severity=Severity.ERROR,
                        code="invalid_email_format",
                        message=f"Поле '{field_def.label}' должно быть корректным email адресом",
                    )
                )

        elif field_def.field_type == FieldType.PHONE:
            import re

            phone_pattern = r"^[\d\s\-\+\(\)]{7,20}$"
            if not re.match(phone_pattern, str(value)):
                results.append(
                    ValidationResult(
                        field_id=field_id,
                        severity=Severity.ERROR,
                        code="invalid_phone_format",
                        message=f"Поле '{field_def.label}' должно быть корректным номером телефона",
                    )
                )

        # Проверка паттерна
        if field_def.validation_pattern and value:
            import re

            if not re.match(field_def.validation_pattern, str(value)):
                results.append(
                    ValidationResult(
                        field_id=field_id,
                        severity=Severity.ERROR,
                        code="pattern_mismatch",
                        message=f"Поле '{field_def.label}' не соответствует требуемому формату",
                    )
                )

        # Проверка максимальной длины
        if field_def.max_length is not None and value:
            str_val = str(value)
            if len(str_val) > field_def.max_length:
                results.append(
                    ValidationResult(
                        field_id=field_id,
                        severity=Severity.ERROR,
                        code="max_length_exceeded",
                        message=f"Поле '{field_def.label}' должно быть не длиннее {field_def.max_length} символов",
                    )
                )

        # Проверка options
        if field_def.options is not None and value:
            if str(value) not in field_def.options:
                results.append(
                    ValidationResult(
                        field_id=field_id,
                        severity=Severity.ERROR,
                        code="invalid_option",
                        message=f"Поле '{field_def.label}' должно быть одним из: {', '.join(field_def.options)}",
                    )
                )

        return results

    def validate_form(
        self,
        doc: Document,
        schema: TypeSchema,
        values: dict[str, Any],
    ) -> list[ValidationResult]:
        """Валидирует форму целиком.

        Args:
            doc: Документ для валидации.
            schema: Схема типа документа.
            values: Значения полей.

        Returns:
            Список результатов валидации.
        """
        results: list[ValidationResult] = []

        for field_def in schema.fields:
            value = values.get(field_def.field_id)
            field_results = self.validate_field(field_def.field_id, value, field_def, values)
            results.extend(field_results)

        return results

    def validate_cross_fields(
        self,
        doc: Document,
        schema: TypeSchema,
        values: dict[str, Any],
    ) -> list[ValidationResult]:
        """Валидирует кросс-полевые правила.

        Args:
            doc: Документ для валидации.
            schema: Схема типа документа.
            values: Значения полей.

        Returns:
            Список результатов валидации.
        """
        results: list[ValidationResult] = []

        for field_def in schema.fields:
            if field_def.cross_field_rules:
                for rule in field_def.cross_field_rules:
                    is_valid, error_msg = _evaluate_cross_field_rule(rule, values)
                    if not is_valid:
                        results.append(
                            ValidationResult(
                                field_id=field_def.field_id,
                                severity=Severity.ERROR,
                                code="cross_field_rule_violation",
                                message=error_msg,
                            )
                        )

        return results

    def validate_all(
        self,
        doc: Document,
        schema: TypeSchema,
        values: dict[str, Any],
    ) -> list[ValidationResult]:
        """Выполняет полную валидацию всех уровней.

        Args:
            doc: Документ для валидации.
            schema: Схема типа документа.
            values: Значения полей.

        Returns:
            Список результатов валидации.
        """
        results: list[ValidationResult] = []
        results.extend(self.validate_form(doc, schema, values))
        results.extend(self.validate_cross_fields(doc, schema, values))
        return results

    def has_errors(self, results: list[ValidationResult]) -> bool:
        """Проверяет наличие ошибок (Severity.ERROR) в результатах.

        Args:
            results: Список результатов валидации.

        Returns:
            True если есть хотя бы одна ошибка с severity=ERROR.
        """
        if self.strict_mode:
            return any(r.severity in (Severity.ERROR, Severity.WARNING) for r in results)
        return any(r.severity == Severity.ERROR for r in results)

    def get_errors(self, results: list[ValidationResult]) -> list[ValidationResult]:
        """Возвращает только ошибки с severity=ERROR.

        Args:
            results: Список результатов валидации.

        Returns:
            Список только с ошибками.
        """
        return [r for r in results if r.severity == Severity.ERROR]

    def get_warnings(self, results: list[ValidationResult]) -> list[ValidationResult]:
        """Возвращает только предупреждения с severity=WARNING.

        Args:
            results: Список результатов валидации.

        Returns:
            Список только с предупреждениями.
        """
        return [r for r in results if r.severity == Severity.WARNING]

    def validate_and_raise(self, form: FormInstance, schema: TypeSchema) -> ValidationResult:
        """Валидирует форму и выбрасывает исключение при ошибках.

        Args:
            form: Форма для валидации.
            schema: Схема типа документа.

        Returns:
            Результат валидации (если нет блокирующих ошибок).

        Raises:
            FormValidationError: Если есть блокирующие ошибки.

        Example:
            >>> try:
            ...     result = validator.validate_and_raise(form, schema)
            ... except FormValidationError as e:
            ...     print(f"Валидация не пройдена: {e}")
        """
        result = self.validate(form, schema)

        if result.has_blocking_errors:
            raise FormValidationError("Форма содержит ошибки, блокирующие подпись", result)

        return result
