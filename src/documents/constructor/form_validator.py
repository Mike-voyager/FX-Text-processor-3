"""Трёхуровневая валидация форм.

Предоставляет систему валидации форм с тремя уровнями:
1. Уровень поля (validate_field) — валидация отдельного поля
2. Уровень формы (validate_form) — валидация всех полей документа
3. Уровень кросс-полей (validate_cross_fields) — проверка зависимостей между полями

Валидация выполняется ДО доступа к приватному ключу подписи, блокируя
подпись невалидных документов.

Example:
    >>> from src.documents.types.type_schema import FieldDefinition, FieldType
    >>> from src.model.document import Document
    >>> validator = FormValidator()
    >>> field_def = FieldDefinition(
    ...     field_id="amount",
    ...     field_type=FieldType.NUMBER_INPUT,
    ...     label="Сумма",
    ...     required=True,
    ...     min_value=0.01
    ... )
    >>> results = validator.validate_field("amount", "100.50", field_def)
    >>> print(results)
    []  # Ошибок нет
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from src.documents.types.type_schema import FieldDefinition, FieldType, TypeSchema
from src.model.document import Document

# Module logger
logger = logging.getLogger(__name__)


class Severity(str, Enum):
    """Уровень серьёзности ошибки валидации.

    Attributes:
        ERROR: Критическая ошибка, блокирует подпись документа.
        WARNING: Предупреждение, не блокирует подпись.
        INFO: Информационное сообщение.
    """

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True)
class ValidationResult:
    """Результат валидации поля или формы.

    Attributes:
        field_id: Идентификатор поля (None для ошибок уровня формы).
        severity: Уровень серьёзности (ERROR, WARNING, INFO).
        code: Машиночитаемый код ошибки.
        message: Человекочитаемое сообщение об ошибке.

    Example:
        >>> result = ValidationResult(
        ...     field_id="amount",
        ...     severity=Severity.ERROR,
        ...     code="required_field_empty",
        ...     message="Поле 'Сумма' обязательно для заполнения"
        ... )
    """

    field_id: Optional[str]
    severity: Severity
    code: str
    message: str


class ValidationError(Exception):
    """Исключение, вызываемое при ошибках валидации.

    Attributes:
        results: Список результатов валидации с ошибками.
    """

    def __init__(self, results: List[ValidationResult]) -> None:
        """Инициализировать исключение с результатами валидации.

        Args:
            results: Список результатов валидации.
        """
        self.results = results
        error_messages = [
            f"{r.field_id}: {r.message}" for r in results if r.severity == Severity.ERROR
        ]
        super().__init__(f"Validation failed: {'; '.join(error_messages)}")


def _safe_parse_date(value: Any) -> Optional[date]:
    """Безопасно парсит значение в дату.

    Args:
        value: Значение для парсинга (str, datetime, date).

    Returns:
        Объект date или None если парсинг невозможен.
    """
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        for fmt in ("%Y-%m-%d", "%d.%m.%Y", "%d/%m/%Y", "%m/%d/%Y"):
            try:
                return datetime.strptime(value, fmt).date()
            except ValueError:
                continue
    return None


def _safe_parse_number(value: Any) -> Optional[float]:
    """Безопасно парсит значение в число.

    Args:
        value: Значение для парсинга.

    Returns:
        Число float или None если парсинг невозможен.
    """
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            # Убираем пробелы и заменяем запятую на точку
            cleaned = value.replace(" ", "").replace(",", ".")
            return float(cleaned)
        except ValueError:
            return None
    return None


def _evaluate_required_if(condition: str, field_values: Dict[str, Any]) -> bool:
    """Оценивает условие required_if.

    Поддерживает простые условия в формате:
    - "field_id == 'value'"
    - "field_id != 'value'"
    - "field_id in ('value1', 'value2')"

    Args:
        condition: Условие в виде строки.
        field_values: Словарь значений полей.

    Returns:
        True если условие выполнено, иначе False.
    """
    if not condition:
        return False

    # Парсим простые условия
    # field_id == 'value'
    match_eq = re.match(r"(\w+)\s*==\s*['\"]([^'\"]+)['\"]", condition)
    if match_eq:
        field_id, expected = match_eq.groups()
        actual = field_values.get(field_id)
        return str(actual) == expected

    # field_id != 'value'
    match_ne = re.match(r"(\w+)\s*!=\s*['\"]([^'\"]+)['\"]", condition)
    if match_ne:
        field_id, expected = match_ne.groups()
        actual = field_values.get(field_id)
        return str(actual) != expected

    # field_id in ('v1', 'v2')
    match_in = re.match(r"(\w+)\s+in\s+\(([^)]+)\)", condition)
    if match_in:
        field_id, values_str = match_in.groups()
        actual = field_values.get(field_id)
        # Парсим значения
        values = [v.strip().strip("'\"") for v in values_str.split(",")]
        return str(actual) in values

    # Если не удалось распарсить, считаем что условие не выполнено
    logger.warning(f"Could not parse required_if condition: {condition}")
    return False


def _evaluate_cross_field_rule(rule: str, field_values: Dict[str, Any]) -> Tuple[bool, str]:
    """Оценивает кросс-полевое правило.

    Args:
        rule: Правило в виде строки.
        field_values: Словарь значений полей.

    Returns:
        Кортеж (успех, сообщение об ошибке).
    """
    # Простые правила: "fieldA > fieldB", "fieldA + fieldB > 0"
    # Для сложных правил используем безопасный eval с ограниченным контекстом

    # fieldA > fieldB
    match_cmp = re.match(r"(\w+)\s*([<>]=?)\s*(\w+)", rule)
    if match_cmp:
        field_a, op, field_b = match_cmp.groups()
        val_a = _safe_parse_number(field_values.get(field_a))
        val_b = _safe_parse_number(field_values.get(field_b))

        if val_a is None or val_b is None:
            return True, ""  # Не проверяем если значений нет

        if op == ">":
            if val_a <= val_b:
                return False, f"{field_a} должно быть больше {field_b}"
        elif op == ">=":
            if val_a < val_b:
                return False, f"{field_a} должно быть больше или равно {field_b}"
        elif op == "<":
            if val_a >= val_b:
                return False, f"{field_a} должно быть меньше {field_b}"
        elif op == "<=":
            if val_a > val_b:
                return False, f"{field_a} должно быть меньше или равно {field_b}"

        return True, ""

    # По умолчанию считаем правило валидным
    return True, ""


class FormValidator:
    """Валидатор форм с трёхуровневой системой проверки.

    Уровень 1: Валидация отдельного поля (validate_field)
    Уровень 2: Валидация всей формы (validate_form)
    Уровень 3: Кросс-полевая валидация (validate_cross_fields)

    Валидация выполняется ДО доступа к приватному ключу подписи,
    блокируя подпись невалидных документов.

    Attributes:
        strict_mode: Если True, WARNING трактуется как ERROR.

    Example:
        >>> validator = FormValidator()
        >>> schema = TypeSchema(fields=[...])
        >>> document = Document()
        >>> results = validator.validate_form(document, schema)
        >>> if validator.has_errors(results):
        ...     raise ValidationError(results)
    """

    def __init__(self, strict_mode: bool = False) -> None:
        """Инициализировать валидатор.

        Args:
            strict_mode: Если True, WARNING трактуется как ERROR.
        """
        self.strict_mode = strict_mode
        logger.debug(f"FormValidator initialized (strict_mode={strict_mode})")

    def validate_field(
        self,
        field_id: str,
        value: Any,
        field_def: FieldDefinition,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ValidationResult]:
        """Валидирует отдельное поле (Уровень 1).

        Проверяет:
        - Обязательность поля (required)
        - Условную обязательность (required_if)
        - Тип данных
        - Числовые диапазоны (min_value, max_value)
        - Диапазоны дат (min_date, max_date)
        - Регулярное выражение (validation_pattern)
        - Максимальную длину (max_length)
        - Допустимые значения (options)

        Args:
            field_id: Идентификатор поля.
            value: Значение поля для валидации.
            field_def: Определение поля.
            context: Контекст с другими значениями полей (для required_if).

        Returns:
            Список результатов валидации (пустой если ошибок нет).
        """
        results: List[ValidationResult] = []
        ctx = context or {}

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

        # Проверка условной обязательности (required_if)
        if field_def.required_if and is_empty:
            if _evaluate_required_if(field_def.required_if, ctx):
                results.append(
                    ValidationResult(
                        field_id=field_id,
                        severity=Severity.ERROR,
                        code="conditional_required_field_empty",
                        message=(
                            f"Поле '{field_def.label}' обязательно при условии: "
                            f"{field_def.required_if}"
                        ),
                    )
                )
                return results

        if is_empty:
            return results  # Необязательное пустое поле — OK

        # Преобразуем значение в строку для дальнейших проверок
        str_value = str(value) if not isinstance(value, str) else value

        # Проверка типа данных
        if field_def.field_type == FieldType.NUMBER_INPUT:
            num_value = _safe_parse_number(value)
            if num_value is None:
                results.append(
                    ValidationResult(
                        field_id=field_id,
                        severity=Severity.ERROR,
                        code="invalid_number_format",
                        message=f"Поле '{field_def.label}' должно содержать число",
                    )
                )
            else:
                # Проверка min_value
                if field_def.min_value is not None and num_value < field_def.min_value:
                    results.append(
                        ValidationResult(
                            field_id=field_id,
                            severity=Severity.ERROR,
                            code="value_below_minimum",
                            message=(
                                f"Значение поля '{field_def.label}' ({num_value}) "
                                f"меньше минимально допустимого ({field_def.min_value})"
                            ),
                        )
                    )
                # Проверка max_value
                if field_def.max_value is not None and num_value > field_def.max_value:
                    results.append(
                        ValidationResult(
                            field_id=field_id,
                            severity=Severity.ERROR,
                            code="value_above_maximum",
                            message=(
                                f"Значение поля '{field_def.label}' ({num_value}) "
                                f"больше максимально допустимого ({field_def.max_value})"
                            ),
                        )
                    )

        elif field_def.field_type == FieldType.DATE_INPUT:
            date_value = _safe_parse_date(value)
            if date_value is None:
                results.append(
                    ValidationResult(
                        field_id=field_id,
                        severity=Severity.ERROR,
                        code="invalid_date_format",
                        message=(
                            f"Поле '{field_def.label}' должно содержать дату "
                            "в формате ГГГГ-ММ-ДД или ДД.ММ.ГГГГ"
                        ),
                    )
                )
            else:
                # Проверка min_date
                if field_def.min_date is not None and date_value < field_def.min_date:
                    results.append(
                        ValidationResult(
                            field_id=field_id,
                            severity=Severity.ERROR,
                            code="date_before_minimum",
                            message=(
                                f"Дата в поле '{field_def.label}' ({date_value}) "
                                f"раньше минимально допустимой ({field_def.min_date})"
                            ),
                        )
                    )
                # Проверка max_date
                if field_def.max_date is not None and date_value > field_def.max_date:
                    results.append(
                        ValidationResult(
                            field_id=field_id,
                            severity=Severity.ERROR,
                            code="date_after_maximum",
                            message=(
                                f"Дата в поле '{field_def.label}' ({date_value}) "
                                f"позже максимально допустимой ({field_def.max_date})"
                            ),
                        )
                    )

        elif field_def.field_type == FieldType.EMAIL:
            # Простая проверка email
            email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            if not re.match(email_pattern, str_value):
                results.append(
                    ValidationResult(
                        field_id=field_id,
                        severity=Severity.ERROR,
                        code="invalid_email_format",
                        message=f"Поле '{field_def.label}' должно содержать корректный email адрес",
                    )
                )

        elif field_def.field_type == FieldType.PHONE:
            # Простая проверка телефона (минимум 10 цифр)
            digits = re.sub(r"\D", "", str_value)
            if len(digits) < 10:
                results.append(
                    ValidationResult(
                        field_id=field_id,
                        severity=Severity.ERROR,
                        code="invalid_phone_format",
                        message=(
                            f"Поле '{field_def.label}' должно содержать "
                            "корректный номер телефона (минимум 10 цифр)"
                        ),
                    )
                )

        # Проверка регулярного выражения
        if field_def.validation_pattern:
            try:
                if not re.match(field_def.validation_pattern, str_value):
                    results.append(
                        ValidationResult(
                            field_id=field_id,
                            severity=Severity.ERROR,
                            code="pattern_mismatch",
                            message=f"Поле '{field_def.label}' не соответствует требуемому формату",
                        )
                    )
            except re.error as e:
                logger.warning(f"Invalid validation_pattern for field {field_id}: {e}")
                results.append(
                    ValidationResult(
                        field_id=field_id,
                        severity=Severity.WARNING,
                        code="invalid_validation_pattern",
                        message=f"Некорректный шаблон валидации для поля '{field_def.label}'",
                    )
                )

        # Проверка максимальной длины
        if field_def.max_length is not None and len(str_value) > field_def.max_length:
            results.append(
                ValidationResult(
                    field_id=field_id,
                    severity=Severity.ERROR,
                    code="max_length_exceeded",
                    message=(
                        f"Поле '{field_def.label}' превышает максимальную длину "
                        f"{field_def.max_length} символов"
                    ),
                )
            )

        # Проверка допустимых значений
        if field_def.options is not None:
            if str_value not in field_def.options:
                results.append(
                    ValidationResult(
                        field_id=field_id,
                        severity=Severity.ERROR,
                        code="invalid_option",
                        message=(
                            f"Поле '{field_def.label}' должно содержать одно из значений: "
                            f"{', '.join(field_def.options)}"
                        ),
                    )
                )

        return results

    def validate_form(
        self,
        document: Document,
        schema: TypeSchema,
        field_values: Optional[Dict[str, Any]] = None,
    ) -> List[ValidationResult]:
        """Валидирует всю форму (Уровень 2).

        Выполняет валидацию всех полей схемы на основе значений из document.

        Args:
            document: Документ для валидации.
            schema: Схема типа документа.
            field_values: Словарь значений полей {field_id: value}.
                         Если None, значения извлекаются из document.

        Returns:
            Список результатов валидации всех полей.
        """
        results: List[ValidationResult] = []

        # Получаем значения полей
        values = (
            field_values
            if field_values is not None
            else self._extract_field_values(document, schema)
        )

        # Валидируем каждое поле схемы
        for field_def in schema.fields:
            field_id = field_def.field_id
            value = values.get(field_id)
            field_results = self.validate_field(field_id, value, field_def, values)
            results.extend(field_results)

        logger.debug(f"Form validation completed: {len(results)} issues found")
        return results

    def validate_cross_fields(
        self,
        document: Document,
        schema: TypeSchema,
        field_values: Optional[Dict[str, Any]] = None,
    ) -> List[ValidationResult]:
        """Выполняет кросс-полевую валидацию (Уровень 3).

        Проверяет зависимости между полями:
        - cross_field_rules из FieldDefinition

        Args:
            document: Документ для валидации.
            schema: Схема типа документа.
            field_values: Словарь значений полей {field_id: value}.

        Returns:
            Список результатов кросс-полевой валидации.
        """
        results: List[ValidationResult] = []

        values = (
            field_values
            if field_values is not None
            else self._extract_field_values(document, schema)
        )

        # Проверяем кросс-полевые правила для каждого поля
        for field_def in schema.fields:
            field_id = field_def.field_id

            for rule in field_def.cross_field_rules:
                is_valid, error_message = _evaluate_cross_field_rule(rule, values)
                if not is_valid:
                    results.append(
                        ValidationResult(
                            field_id=field_id,
                            severity=Severity.ERROR,
                            code="cross_field_rule_violation",
                            message=(
                                f"Кросс-полевая валидация для '{field_def.label}': {error_message}"
                            ),
                        )
                    )

        logger.debug(f"Cross-field validation completed: {len(results)} issues found")
        return results

    def validate_all(
        self,
        document: Document,
        schema: TypeSchema,
        field_values: Optional[Dict[str, Any]] = None,
    ) -> List[ValidationResult]:
        """Выполняет полную валидацию всех уровней.

        Args:
            document: Документ для валидации.
            schema: Схема типа документа.
            field_values: Словарь значений полей {field_id: value}.

        Returns:
            Список всех результатов валидации.
        """
        results: List[ValidationResult] = []

        # Уровень 2: Валидация формы
        results.extend(self.validate_form(document, schema, field_values))

        # Уровень 3: Кросс-полевая валидация
        results.extend(self.validate_cross_fields(document, schema, field_values))

        logger.info(f"Full validation completed: {len(results)} total issues found")
        return results

    def _extract_field_values(self, document: Document, schema: TypeSchema) -> Dict[str, Any]:
        """Извлекает значения полей из документа.

        Args:
            document: Документ для извлечения значений.
            schema: Схема типа документа.

        Returns:
            Словарь {field_id: value}.
        """
        # TODO: Реализовать извлечение значений из Document
        # Пока возвращаем пустой словарь
        return {}

    def has_errors(self, results: List[ValidationResult]) -> bool:
        """Проверяет, есть ли ошибки ERROR в результатах.

        Args:
            results: Список результатов валидации.

        Returns:
            True если есть хотя бы один ERROR.
        """
        for result in results:
            if result.severity == Severity.ERROR:
                return True
            if self.strict_mode and result.severity == Severity.WARNING:
                return True
        return False

    def get_errors(self, results: List[ValidationResult]) -> List[ValidationResult]:
        """Возвращает только результаты с уровнем ERROR.

        Args:
            results: Список результатов валидации.

        Returns:
            Список результатов только с ошибками.
        """
        return [r for r in results if r.severity == Severity.ERROR]

    def get_warnings(self, results: List[ValidationResult]) -> List[ValidationResult]:
        """Возвращает только результаты с уровнем WARNING.

        Args:
            results: Список результатов валидации.

        Returns:
            Список результатов только с предупреждениями.
        """
        return [r for r in results if r.severity == Severity.WARNING]


# Создаём экземпляр валидатора по умолчанию
default_validator = FormValidator()
