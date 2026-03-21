"""Type schema definitions for document fields.

Provides:
- FieldType: Enum for field types
- FieldDefinition: Definition of a single field
- TypeSchema: Collection of fields for a document type
- OverflowBehavior: How to handle text overflow in fields
"""

from dataclasses import dataclass, field
from datetime import date
from enum import Enum
from typing import Any


class FieldType(str, Enum):
    """Типы полей в схеме документа.

    Базовые типы:
        STATIC_TEXT: Неизменяемый текст шаблона
        TEXT_INPUT: Текстовое поле ввода
        NUMBER_INPUT: Числовое поле
        DATE_INPUT: Поле даты
        TABLE: Табличное поле
        EXCEL_IMPORT: Импорт из Excel
        CALCULATED: Вычисляемое поле
        QR: QR-код
        BARCODE: Штрих-код
        SIGNATURE: Цифровая подпись
        STAMP: Печать/штамп

    Расширенные типы:
        CHECKBOX: Булев флажок
        DROPDOWN: Выпадающий список
        RADIO_GROUP: Группа радиокнопок
        CURRENCY: Денежная сумма
        MULTI_LINE_TEXT: Многострочный текст
        PHONE: Телефон
        EMAIL: Email
    """

    # Base types
    STATIC_TEXT = "static_text"
    TEXT_INPUT = "text_input"
    NUMBER_INPUT = "number_input"
    DATE_INPUT = "date_input"
    TABLE = "table"
    EXCEL_IMPORT = "excel_import"
    CALCULATED = "calculated"
    QR = "qr"
    BARCODE = "barcode"
    SIGNATURE = "signature"
    STAMP = "stamp"

    # Extended types
    CHECKBOX = "checkbox"
    DROPDOWN = "dropdown"
    RADIO_GROUP = "radio_group"
    CURRENCY = "currency"
    MULTI_LINE_TEXT = "multi_line_text"
    PHONE = "phone"
    EMAIL = "email"


class OverflowBehavior(str, Enum):
    """Поведение при переполнении текстового поля."""

    TRUNCATE = "truncate"  # Обрезать лишнее
    WRAP = "wrap"  # Переносить на новую строку
    SHRINK_FONT = "shrink_font"  # Уменьшать шрифт


@dataclass(frozen=True)
class FieldDefinition:
    """Определение одного поля в схеме типа документа.

    Attributes:
        name: Программное имя поля.
        field_type: Тип поля из enum FieldType.
        label: Метка поля на русском языке.
        label_en: Метка поля на английском языке.
        required: Обязательность поля.
        default_value: Значение по умолчанию.
        validation: Список правил валидации.
        inherited_from: Код типа, от которого поле унаследовано (None = собственное).
        min_value: Минимальное числовое значение.
        max_value: Максимальное числовое значение.
        min_date: Минимальная дата.
        max_date: Максимальная дата.
        required_if: Условная обязательность (выражение).
        cross_field_rules: Кросс-полевая валидация.
        visibility_condition: Условие видимости поля.
        read_only_condition: Условие только чтения.
        enabled_condition: Условие активности поля.
        tab_index: Порядок Tab-навигации.
        input_mask: Маска ввода.
        placeholder: Подсказка в пустом поле.
        autocomplete_source: Источник автодополнения.
        help_text: Вспомогательный текст (tooltip).
    """

    name: str
    field_type: FieldType
    label: str
    label_en: str
    required: bool = True
    readonly: bool = False  # Поле только для чтения
    default_value: Any = None
    validation: tuple[str, ...] = field(default_factory=tuple)
    inherited_from: str | None = None

    # Extended validation rules
    min_value: float | None = None
    max_value: float | None = None
    min_date: date | None = None
    max_date: date | None = None
    required_if: str | None = None
    cross_field_rules: tuple[str, ...] = field(default_factory=tuple)

    # Conditional visibility
    visibility_condition: str | None = None
    read_only_condition: str | None = None
    enabled_condition: str | None = None

    # Field UX
    tab_index: int | None = None
    input_mask: str | None = None
    placeholder: str | None = None
    autocomplete_source: str | None = None
    help_text: str | None = None


@dataclass
class TypeSchema:
    """Схема полей для типа документа.

    Attributes:
        fields: Список определений полей.
        version: Версия схемы.
        compatibility_version: Минимальная совместимая версия.
        deprecated_fields: Список устаревших field_id.
    """

    fields: tuple[FieldDefinition, ...] = field(default_factory=tuple)
    version: str = "1.0"
    compatibility_version: str = "1.0"
    deprecated_fields: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        """Валидация схемы после инициализации."""
        if not self.fields:
            # Пустая схема допустима (могут быть только вычисляемые поля)
            return

        # Проверяем уникальность имен полей
        names = [f.name for f in self.fields]
        if len(names) != len(set(names)):
            raise ValueError("Field names must be unique")

    def get_field(self, name: str) -> FieldDefinition:
        """Возвращает определение поля по имени.

        Args:
            name: Имя поля.

        Returns:
            Определение поля.

        Raises:
            KeyError: Если поле не найдено.
        """
        for field_def in self.fields:
            if field_def.name == name:
                return field_def
        raise KeyError(f"Field not found: {name}")

    def has_field(self, name: str) -> bool:
        """Проверяет наличие поля в схеме."""
        return any(f.name == name for f in self.fields)

    @property
    def required_fields(self) -> list[FieldDefinition]:
        """Возвращает список обязательных полей."""
        return [f for f in self.fields if f.required]

    @property
    def optional_fields(self) -> list[FieldDefinition]:
        """Возвращает список необязательных полей."""
        return [f for f in self.fields if not f.required]

    def get_fields_by_type(
        self, field_type: FieldType
    ) -> list[FieldDefinition]:
        """Возвращает поля указанного типа."""
        return [f for f in self.fields if f.field_type == field_type]

    def validate_value(
        self, name: str, value: Any
    ) -> list[str]:
        """Валидирует значение поля по его определению.

        Args:
            name: Имя поля.
            value: Значение для валидации.

        Returns:
            Список ошибок (пустой если валидно).
        """
        errors: list[str] = []

        try:
            field_def = self.get_field(name)
        except KeyError:
            return [f"Unknown field: {name}"]

        # Проверка обязательности
        if field_def.required and (value is None or value == ""):
            errors.append(f"Field '{name}' is required")
            return errors  # Дальнейшие проверки не имеют смысла

        if value is None or value == "":
            return []  # Необязательное пустое поле

        # Проверка типов
        if field_def.field_type == FieldType.NUMBER_INPUT:
            try:
                num = float(value) if isinstance(value, str) else value
                if field_def.min_value is not None and num < field_def.min_value:
                    errors.append(
                        f"Value {num} is less than minimum {field_def.min_value}"
                    )
                if field_def.max_value is not None and num > field_def.max_value:
                    errors.append(
                        f"Value {num} is greater than maximum {field_def.max_value}"
                    )
            except (ValueError, TypeError):
                errors.append(f"Invalid number value: {value}")

        elif field_def.field_type == FieldType.DATE_INPUT:
            if isinstance(value, str):
                # Дополнительная валидация даты при необходимости
                pass

        # Проверка по validation правилам
        for rule in field_def.validation:
            rule_errors = self._validate_rule(field_def.name, value, rule)
            errors.extend(rule_errors)

        return errors

    def _validate_rule(
        self, field_name: str, value: Any, rule: str
    ) -> list[str]:
        """Валидирует значение по одному правилу."""
        errors: list[str] = []

        if rule.startswith("min_length:"):
            min_len = int(rule.split(":")[1])
            if len(str(value)) < min_len:
                errors.append(
                    f"Field '{field_name}' must be at least {min_len} characters"
                )

        elif rule.startswith("max_length:"):
            max_len = int(rule.split(":")[1])
            if len(str(value)) > max_len:
                errors.append(
                    f"Field '{field_name}' must be at most {max_len} characters"
                )

        elif rule.startswith("regex:"):
            import re

            pattern = rule.split(":", 1)[1]
            if not re.match(pattern, str(value)):
                errors.append(
                    f"Field '{field_name}' doesn't match pattern {pattern}"
                )

        elif rule.startswith("one_of:"):
            allowed = rule.split(":", 1)[1].split(",")
            if str(value) not in allowed:
                errors.append(
                    f"Field '{field_name}' must be one of: {allowed}"
                )

        return errors