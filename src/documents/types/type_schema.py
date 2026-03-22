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
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.documents.constructor.table_schema import TableSchema


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
        field_id: Программное имя поля (ранее `name`).
        field_type: Тип поля из enum FieldType.
        label: Метка поля на русском языке.
        label_i18n: Словарь локализованных меток {lang: label}.
        required: Обязательность поля.
        default_value: Значение по умолчанию.
        validation_pattern: Regex-паттерн для валидации.
        max_length: Максимальная длина строки.
        options: Допустимые значения для DROPDOWN/RADIO_GROUP.
        escp_variable: Связь с ESC/P переменной.
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

    field_id: str  # Changed from `name` per ARCHITECTURE.md
    field_type: FieldType
    label: str
    label_i18n: dict[str, str] = field(
        default_factory=dict, compare=False, hash=False
    )  # Changed from `label_en: str`
    required: bool = True
    readonly: bool = False  # Поле только для чтения
    default_value: Any = None
    validation_pattern: str | None = None  # Changed from `validation: tuple[str, ...]`
    max_length: int | None = None
    options: tuple[str, ...] | None = None
    escp_variable: str | None = None
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

    # Table schema for TABLE fields
    table_schema: "TableSchema | None" = None


@dataclass(frozen=True)
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

        # Проверяем уникальность field_id полей
        field_ids = [f.field_id for f in self.fields]
        if len(field_ids) != len(set(field_ids)):
            raise ValueError("Field IDs must be unique")

    def get_field(self, field_id: str) -> FieldDefinition:
        """Возвращает определение поля по field_id.

        Args:
            field_id: Идентификатор поля.

        Returns:
            Определение поля.

        Raises:
            KeyError: Если поле не найдено.
        """
        for field_def in self.fields:
            if field_def.field_id == field_id:
                return field_def
        raise KeyError(f"Field not found: {field_id}")

    def has_field(self, field_id: str) -> bool:
        """Проверяет наличие поля в схеме по field_id."""
        return any(f.field_id == field_id for f in self.fields)

    @property
    def required_fields(self) -> list[FieldDefinition]:
        """Возвращает список обязательных полей."""
        return [f for f in self.fields if f.required]

    @property
    def optional_fields(self) -> list[FieldDefinition]:
        """Возвращает список необязательных полей."""
        return [f for f in self.fields if not f.required]

    def get_fields_by_type(self, field_type: FieldType) -> list[FieldDefinition]:
        """Возвращает поля указанного типа."""
        return [f for f in self.fields if f.field_type == field_type]

    def validate_value(self, field_id: str, value: Any) -> list[str]:
        """Валидирует значение поля по его определению.

        Args:
            field_id: Идентификатор поля.
            value: Значение для валидации.

        Returns:
            Список ошибок (пустой если валидно).
        """
        errors: list[str] = []

        try:
            field_def = self.get_field(field_id)
        except KeyError:
            return [f"Unknown field: {field_id}"]

        # Проверка обязательности
        if field_def.required and (value is None or value == ""):
            errors.append(f"Field '{field_id}' is required")
            return errors  # Дальнейшие проверки не имеют смысла

        if value is None or value == "":
            return []  # Необязательное пустое поле

        # Проверка типов
        if field_def.field_type == FieldType.NUMBER_INPUT:
            try:
                num = float(value) if isinstance(value, str) else value
                if field_def.min_value is not None and num < field_def.min_value:
                    errors.append(f"Value {num} is less than minimum {field_def.min_value}")
                if field_def.max_value is not None and num > field_def.max_value:
                    errors.append(f"Value {num} is greater than maximum {field_def.max_value}")
            except (ValueError, TypeError):
                errors.append(f"Invalid number value: {value}")

        elif field_def.field_type == FieldType.DATE_INPUT:
            if isinstance(value, str):
                # Дополнительная валидация даты при необходимости
                pass

        # Проверка по validation_pattern
        if field_def.validation_pattern:
            import re

            if not re.match(field_def.validation_pattern, str(value)):
                errors.append(
                    f"Field '{field_id}' doesn't match pattern {field_def.validation_pattern}"
                )

        # Проверка max_length
        if field_def.max_length is not None:
            if len(str(value)) > field_def.max_length:
                errors.append(
                    f"Field '{field_id}' must be at most {field_def.max_length} characters"
                )

        # Проверка options
        if field_def.options is not None:
            if str(value) not in field_def.options:
                errors.append(f"Field '{field_id}' must be one of: {field_def.options}")

        return errors

    def to_dict(self) -> dict[str, Any]:
        """Сериализует схему в словарь.

        Returns:
            Словарь с данными схемы.

        Example:
            >>> schema = TypeSchema(fields=())
            >>> data = schema.to_dict()
            >>> "fields" in data
            True
        """
        return {
            "fields": [
                {
                    "field_id": f.field_id,
                    "field_type": f.field_type.value,
                    "label": f.label,
                    "label_i18n": dict(f.label_i18n) if f.label_i18n else {},
                    "required": f.required,
                    "readonly": f.readonly,
                    "default_value": f.default_value,
                    "validation_pattern": f.validation_pattern,
                    "max_length": f.max_length,
                    "options": list(f.options) if f.options else None,
                    "escp_variable": f.escp_variable,
                    "inherited_from": f.inherited_from,
                    "min_value": f.min_value,
                    "max_value": f.max_value,
                    "min_date": f.min_date.isoformat() if f.min_date else None,
                    "max_date": f.max_date.isoformat() if f.max_date else None,
                    "required_if": f.required_if,
                    "cross_field_rules": list(f.cross_field_rules) if f.cross_field_rules else [],
                    "visibility_condition": f.visibility_condition,
                    "read_only_condition": f.read_only_condition,
                    "enabled_condition": f.enabled_condition,
                    "tab_index": f.tab_index,
                    "input_mask": f.input_mask,
                    "placeholder": f.placeholder,
                    "autocomplete_source": f.autocomplete_source,
                    "help_text": f.help_text,
                }
                for f in self.fields
            ],
            "version": self.version,
            "compatibility_version": self.compatibility_version,
            "deprecated_fields": list(self.deprecated_fields),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TypeSchema":
        """Десериализует схему из словаря.

        Args:
            data: Словарь с данными схемы.

        Returns:
            Экземпляр TypeSchema.

        Example:
            >>> data = {"fields": [], "version": "1.0"}
            >>> schema = TypeSchema.from_dict(data)
            >>> schema.version
            '1.0'
        """
        from datetime import datetime

        fields_data = data.get("fields", [])
        fields = []

        for f_data in fields_data:
            field_type = FieldType(f_data.get("field_type", "text_input"))
            min_date = None
            max_date = None

            if f_data.get("min_date"):
                min_date = datetime.fromisoformat(f_data["min_date"]).date()
            if f_data.get("max_date"):
                max_date = datetime.fromisoformat(f_data["max_date"]).date()

            field_def = FieldDefinition(
                field_id=f_data.get("field_id", ""),
                field_type=field_type,
                label=f_data.get("label", ""),
                label_i18n=f_data.get("label_i18n", {}),
                required=f_data.get("required", True),
                readonly=f_data.get("readonly", False),
                default_value=f_data.get("default_value"),
                validation_pattern=f_data.get("validation_pattern"),
                max_length=f_data.get("max_length"),
                options=tuple(f_data["options"]) if f_data.get("options") else None,
                escp_variable=f_data.get("escp_variable"),
                inherited_from=f_data.get("inherited_from"),
                min_value=f_data.get("min_value"),
                max_value=f_data.get("max_value"),
                min_date=min_date,
                max_date=max_date,
                required_if=f_data.get("required_if"),
                cross_field_rules=tuple(f_data.get("cross_field_rules", [])),
                visibility_condition=f_data.get("visibility_condition"),
                read_only_condition=f_data.get("read_only_condition"),
                enabled_condition=f_data.get("enabled_condition"),
                tab_index=f_data.get("tab_index"),
                input_mask=f_data.get("input_mask"),
                placeholder=f_data.get("placeholder"),
                autocomplete_source=f_data.get("autocomplete_source"),
                help_text=f_data.get("help_text"),
            )
            fields.append(field_def)

        return cls(
            fields=tuple(fields),
            version=data.get("version", "1.0"),
            compatibility_version=data.get("compatibility_version", "1.0"),
            deprecated_fields=tuple(data.get("deprecated_fields", [])),
        )
