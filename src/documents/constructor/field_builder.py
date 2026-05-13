"""Field builder - Builder pattern for form fields.

Provides:
- FieldPosition: Data class for field positioning
- FieldBuilder: Builder class for constructing FormField objects

Example:
    >>> from src.documents.constructor.field_builder import FieldBuilder
    >>> from src.documents.types.type_schema import FieldType
    >>> field = (FieldBuilder()
    ...     .with_id("customer_name")
    ...     .with_type(FieldType.TEXT_INPUT)
    ...     .with_label("Customer Name")
    ...     .with_position(x=10, y=5, width=40, height=1)
    ...     .with_validation(pattern=r"^[A-Za-z ]+$")
    ...     .build())
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date
from typing import TYPE_CHECKING, Any, Self

if TYPE_CHECKING:
    from src.documents.constructor.table_schema import TableSchema
    from src.documents.types.type_schema import FieldDefinition, FieldType

# Re-export OverflowBehavior from type_schema for API compatibility
from src.documents.types.type_schema import OverflowBehavior

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FieldPosition:
    """Позиция и размеры поля на форме.

    Координаты и размеры в символах/строках ESC/P:
    - x: Горизонтальная позиция (символы слева, 0 = левый край)
    - y: Вертикальная позиция (строки сверху, 0 = верх)
    - width: Ширина поля в символах
    - height: Высота поля в строках
    - page: Номер страницы (для многостраничных форм)

    Attributes:
        x: Горизонтальная позиция в символах.
        y: Вертикальная позиция в строках.
        width: Ширина в символах.
        height: Высота в строках.
        page: Номер страницы (по умолчанию 0).
    """

    x: int
    y: int
    width: int
    height: int = 1
    page: int = 0

    def __post_init__(self) -> None:
        """Валидация позиции."""
        if self.x < 0:
            raise ValueError(f"x must be >= 0, got {self.x}")
        if self.y < 0:
            raise ValueError(f"y must be >= 0, got {self.y}")
        if self.width < 1:
            raise ValueError(f"width must be >= 1, got {self.width}")
        if self.height < 1:
            raise ValueError(f"height must be >= 1, got {self.height}")
        if self.page < 0:
            raise ValueError(f"page must be >= 0, got {self.page}")

    @property
    def end_x(self) -> int:
        """Конечная X координата (не включая)."""
        return self.x + self.width

    @property
    def end_y(self) -> int:
        """Конечная Y координата (не включая)."""
        return self.y + self.height

    def intersects(self, other: FieldPosition) -> bool:
        """Проверяет пересечение с другой позицией.

        Args:
            other: Другая позиция для проверки.

        Returns:
            True если позиции пересекаются.
        """
        if self.page != other.page:
            return False
        return (
            self.x < other.end_x
            and self.end_x > other.x
            and self.y < other.end_y
            and self.end_y > other.y
        )


@dataclass
class FormField:
    """Поле формы с полной конфигурацией.

    Этот класс используется FieldBuilder для построения
    полей форм. Может быть конвертирован в FieldDefinition.

    Attributes:
        field_id: Уникальный идентификатор поля.
        field_type: Тип поля.
        label: Метка поля.
        label_i18n: Локализованные метки.
        required: Обязательность заполнения.
        readonly: Только для чтения.
        position: Позиция на форме.
        default_value: Значение по умолчанию.
        validation_pattern: Regex паттерн валидации.
        max_length: Максимальная длина.
        min_value: Минимальное числовое значение.
        max_value: Максимальное числовое значение.
        min_date: Минимальная дата.
        max_date: Максимальная дата.
        options: Допустимые значения для выбора.
        help_text: Подсказка (tooltip).
        placeholder: Placeholder для пустого поля.
        tab_index: Порядок при Tab навигации.
        table_schema: Схема для табличных полей.
        cross_field_rules: Правила кросс-полевой валидации.
        required_if: Условная обязательность.
        visibility_condition: Условие видимости.
        enabled_condition: Условие активности.
        input_mask: Маска ввода.
        autocomplete_source: Источник автодополнения.
        escp_variable: Связь с ESC/P переменной.
    """

    # Основные атрибуты
    field_id: str = ""
    field_type: "FieldType | None" = None
    label: str = ""
    label_i18n: dict[str, str] = field(default_factory=dict)

    # Поведение
    required: bool = False
    readonly: bool = False

    # Позиционирование
    position: FieldPosition | None = None

    # Значения
    default_value: Any = None

    # Валидация
    validation_pattern: str | None = None
    max_length: int | None = None
    min_value: float | None = None
    max_value: float | None = None
    min_date: date | None = None
    max_date: date | None = None
    options: tuple[str, ...] | None = None

    # UX
    help_text: str | None = None
    placeholder: str | None = None
    tab_index: int | None = None
    input_mask: str | None = None

    # Специальные
    table_schema: "TableSchema | None" = None
    cross_field_rules: tuple[str, ...] = field(default_factory=tuple)
    required_if: str | None = None
    visibility_condition: str | None = None
    enabled_condition: str | None = None
    read_only_condition: str | None = None
    autocomplete_source: str | None = None
    escp_variable: str | None = None

    def validate(self) -> list[str]:
        """Валидирует конфигурацию поля.

        Returns:
            Список ошибок (пустой если валидно).
        """
        errors: list[str] = []

        if not self.field_id:
            errors.append("field_id is required")

        if self.field_type is None:
            errors.append("field_type is required")

        if not self.label:
            errors.append("label is required")

        if self.max_length is not None and self.max_length < 1:
            errors.append("max_length must be >= 1")

        if self.min_value is not None and self.max_value is not None:
            if self.min_value > self.max_value:
                errors.append("min_value must be <= max_value")

        if self.min_date is not None and self.max_date is not None:
            if self.min_date > self.max_date:
                errors.append("min_date must be <= max_date")

        return errors

    def to_field_definition(self) -> "FieldDefinition":
        """Конвертирует в FieldDefinition для TypeSchema.

        Returns:
            Экземпляр FieldDefinition.

        Raises:
            ValueError: Если конфигурация невалидна.
        """
        from src.documents.types.type_schema import FieldDefinition

        errors = self.validate()
        if errors:
            raise ValueError(f"Invalid field configuration: {', '.join(errors)}")

        return FieldDefinition(
            field_id=self.field_id,
            field_type=self.field_type,  # type: ignore[arg-type]
            label=self.label,
            label_i18n=self.label_i18n,
            required=self.required,
            readonly=self.readonly,
            default_value=self.default_value,
            validation_pattern=self.validation_pattern,
            max_length=self.max_length,
            options=self.options,
            escp_variable=self.escp_variable,
            inherited_from=None,
            min_value=self.min_value,
            max_value=self.max_value,
            min_date=self.min_date,
            max_date=self.max_date,
            required_if=self.required_if,
            cross_field_rules=self.cross_field_rules,
            visibility_condition=self.visibility_condition,
            read_only_condition=self.read_only_condition,
            enabled_condition=self.enabled_condition,
            tab_index=self.tab_index,
            input_mask=self.input_mask,
            placeholder=self.placeholder,
            autocomplete_source=self.autocomplete_source,
            help_text=self.help_text,
            table_schema=self.table_schema,
        )


class FieldBuilder:
    """Builder для конструирования полей форм.

    Реализует паттерн Builder для пошагового создания
    полей форм с проверкой валидности.

    Example:
        >>> builder = FieldBuilder()
        >>> field = (builder
        ...     .with_id("amount")
        ...     .with_type(FieldType.CURRENCY)
        ...     .with_label("Amount")
        ...     .with_position(x=10, y=5, width=15, height=1)
        ...     .with_validation(min_val=0.01)
        ...     .with_default(0.0)
        ...     .build())
    """

    def __init__(self) -> None:
        """Инициализирует пустой builder."""
        self._field = FormField()

    def with_id(self, field_id: str) -> Self:
        """Устанавливает идентификатор поля.

        Args:
            field_id: Уникальный идентификатор поля.

        Returns:
            Self для chaining.

        Raises:
            ValueError: Если field_id пустой.
        """
        if not field_id or not isinstance(field_id, str):
            raise ValueError("field_id must be non-empty string")
        self._field.field_id = field_id
        return self

    def with_type(self, field_type: "FieldType") -> Self:
        """Устанавливает тип поля.

        Args:
            field_type: Тип из FieldType enum.

        Returns:
            Self для chaining.
        """
        self._field.field_type = field_type
        return self

    def with_label(self, label: str, **i18n_labels: str) -> Self:
        """Устанавливает метку поля.

        Args:
            label: Метка на русском языке.
            **i18n_labels: Дополнительные локализации {lang: label}.

        Returns:
            Self для chaining.
        """
        self._field.label = label
        self._field.label_i18n = i18n_labels
        return self

    def with_position(self, x: int, y: int, width: int, height: int = 1, page: int = 0) -> Self:
        """Устанавливает позицию и размеры поля.

        Args:
            x: Горизонтальная позиция в символах.
            y: Вертикальная позиция в строках.
            width: Ширина в символах.
            height: Высота в строках (по умолчанию 1).
            page: Номер страницы (по умолчанию 0).

        Returns:
            Self для chaining.
        """
        self._field.position = FieldPosition(x=x, y=y, width=width, height=height, page=page)
        return self

    def with_position_obj(self, position: FieldPosition) -> Self:
        """Устанавливает позицию из объекта FieldPosition.

        Args:
            position: Объект позиции.

        Returns:
            Self для chaining.
        """
        self._field.position = position
        return self

    def with_required(self, required: bool = True) -> Self:
        """Устанавливает обязательность поля.

        Args:
            required: True если поле обязательное.

        Returns:
            Self для chaining.
        """
        self._field.required = required
        return self

    def with_readonly(self, readonly: bool = True) -> Self:
        """Устанавливает режим только чтения.

        Args:
            readonly: True если поле только для чтения.

        Returns:
            Self для chaining.
        """
        self._field.readonly = readonly
        return self

    def with_default(self, value: Any) -> Self:
        """Устанавливает значение по умолчанию.

        Args:
            value: Значение по умолчанию.

        Returns:
            Self для chaining.
        """
        self._field.default_value = value
        return self

    def with_validation(
        self,
        pattern: str | None = None,
        min_val: float | None = None,
        max_val: float | None = None,
        min_date: date | None = None,
        max_date: date | None = None,
    ) -> Self:
        """Устанавливает правила валидации.

        Args:
            pattern: Regex паттерн для проверки.
            min_val: Минимальное числовое значение.
            max_val: Максимальное числовое значение.
            min_date: Минимальная дата.
            max_date: Максимальная дата.

        Returns:
            Self для chaining.
        """
        if pattern is not None:
            self._field.validation_pattern = pattern
        if min_val is not None:
            self._field.min_value = min_val
        if max_val is not None:
            self._field.max_value = max_val
        if min_date is not None:
            self._field.min_date = min_date
        if max_date is not None:
            self._field.max_date = max_date
        return self

    def with_max_length(self, max_length: int) -> Self:
        """Устанавливает максимальную длину.

        Args:
            max_length: Максимальное количество символов.

        Returns:
            Self для chaining.
        """
        if max_length < 1:
            raise ValueError("max_length must be >= 1")
        self._field.max_length = max_length
        return self

    def with_options(self, *options: str) -> Self:
        """Устанавливает список допустимых значений.

        Args:
            *options: Допустимые значения.

        Returns:
            Self для chaining.
        """
        self._field.options = options
        return self

    def with_help_text(self, text: str) -> Self:
        """Устанавливает подсказку (tooltip).

        Args:
            text: Текст подсказки.

        Returns:
            Self для chaining.
        """
        self._field.help_text = text
        return self

    def with_placeholder(self, text: str) -> Self:
        """Устанавливает placeholder.

        Args:
            text: Текст placeholder.

        Returns:
            Self для chaining.
        """
        self._field.placeholder = text
        return self

    def with_tab_index(self, index: int) -> Self:
        """Устанавливает порядок Tab навигации.

        Args:
            index: Порядковый номер (0-based).

        Returns:
            Self для chaining.
        """
        self._field.tab_index = index
        return self

    def with_input_mask(self, mask: str) -> Self:
        """Устанавливает маску ввода.

        Args:
            mask: Маска (например, "(999) 999-99-99" для телефона).

        Returns:
            Self для chaining.
        """
        self._field.input_mask = mask
        return self

    def with_table_schema(self, schema: "TableSchema") -> Self:
        """Устанавливает схему для табличного поля.

        Args:
            schema: Схема таблицы.

        Returns:
            Self для chaining.
        """
        self._field.table_schema = schema
        return self

    def with_cross_field_rules(self, *rules: str) -> Self:
        """Устанавливает правила кросс-полевой валидации.

        Args:
            *rules: Правила валидации (например, "amount > discount").

        Returns:
            Self для chaining.
        """
        self._field.cross_field_rules = rules
        return self

    def with_required_if(self, condition: str) -> Self:
        """Устанавливает условную обязательность.

        Args:
            condition: Условие (например, "doc_type == 'invoice'").

        Returns:
            Self для chaining.
        """
        self._field.required_if = condition
        return self

    def with_visibility(self, condition: str) -> Self:
        """Устанавливает условие видимости.

        Args:
            condition: Условие видимости.

        Returns:
            Self для chaining.
        """
        self._field.visibility_condition = condition
        return self

    def with_enabled_condition(self, condition: str) -> Self:
        """Устанавливает условие активности.

        Args:
            condition: Условие активности.

        Returns:
            Self для chaining.
        """
        self._field.enabled_condition = condition
        return self

    def with_escp_variable(self, variable_name: str) -> Self:
        """Устанавливает связь с ESC/P переменной.

        Args:
            variable_name: Имя ESC/P переменной.

        Returns:
            Self для chaining.
        """
        self._field.escp_variable = variable_name
        return self

    def with_autocomplete(self, source: str) -> Self:
        """Устанавливает источник автодополнения.

        Args:
            source: Источник данных (например, "clients" или URL).

        Returns:
            Self для chaining.
        """
        self._field.autocomplete_source = source
        return self

    def build(self) -> FormField:
        """Собирает и возвращает готовое поле.

        Returns:
            Сконфигурированное FormField.

        Raises:
            ValueError: Если конфигурация невалидна.
        """
        errors = self._field.validate()
        if errors:
            raise ValueError(f"Field validation failed: {'; '.join(errors)}")
        return self._field

    def build_field_definition(self) -> "FieldDefinition":
        """Собирает и возвращает FieldDefinition.

        Returns:
            Сконфигурированный FieldDefinition.

        Raises:
            ValueError: Если конфигурация невалидна.
        """
        return self.build().to_field_definition()

    def reset(self) -> Self:
        """Сбрасывает builder для создания нового поля.

        Returns:
            Self для chaining.
        """
        self._field = FormField()
        return self
