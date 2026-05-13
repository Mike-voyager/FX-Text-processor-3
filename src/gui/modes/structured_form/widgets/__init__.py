"""Field widgets for FX Text Processor 3 structured forms.

Phase 4 core widgets:
- BaseFieldWidget: базовый класс для всех полей
- TextInputWidget: однострочное текстовое поле
- NumberInputWidget: числовое поле (NUMBER_INPUT, CURRENCY)
- DateInputWidget: поле даты
- CheckboxWidget: чекбокс (boolean)
- DropdownWidget: выпадающий список
- RadioGroupWidget: группа радиокнопок
- MultiLineWidget: многострочный текст
- TableWidget: табличное поле (mini Excel)
- StaticTextWidget: read-only Label с форматированным текстом
- CalculatedWidget: вычисляемое поле

Phase 5 widgets:
- SignatureWidget: холст для рисования подписи
- StampWidget: отображение изображения штампа
- BarcodeWidget: поле ввода и отображения штрих-кода
- QRWidget: поле ввода и отображения QR-кода
- PhoneWidget: поле ввода телефона с маской
- EmailWidget: поле ввода email с валидацией
- ExcelImportWidget: импорт данных из Excel/CSV

New Phase 4 widgets:
- BaseField: базовый tk.Frame для inline-полей
- AutocompleteEntry: поле с автодополнением (debounced)
- NumberEntry: числовое поле с clamping
- DateEntry: поле даты DD.MM.YYYY
- TableField: таблица с inline-редактированием

Factory:
    >>> from src.gui.modes.structured_form.widgets import create_field_widget
    >>> widget = create_field_widget(
    ...     FieldType.TEXT_INPUT,
    ...     parent=frame,
    ...     field_def=field_def,
    ...     on_change=on_change_callback
    ... )
"""

from __future__ import annotations

import tkinter as tk
from typing import TYPE_CHECKING, Any, Callable, Optional, Type, TypeVar

from src.documents.types.type_schema import FieldDefinition, FieldType

# Import specific widgets
from src.gui.modes.structured_form.widgets.autocomplete_entry import (
    AutocompleteEntry,
)
from src.gui.modes.structured_form.widgets.barcode_widget import BarcodeWidget

# Import base classes
from src.gui.modes.structured_form.widgets.base_field import BaseField
from src.gui.modes.structured_form.widgets.base_field_widget import (
    BaseFieldWidget,
    FieldSettingsToolbar,
)
from src.gui.modes.structured_form.widgets.calculated_widget import CalculatedWidget
from src.gui.modes.structured_form.widgets.checkbox_widget import CheckboxWidget
from src.gui.modes.structured_form.widgets.date_entry import DateEntry
from src.gui.modes.structured_form.widgets.date_input_widget import DateInputWidget
from src.gui.modes.structured_form.widgets.dropdown_widget import DropdownWidget
from src.gui.modes.structured_form.widgets.email_widget import EmailWidget
from src.gui.modes.structured_form.widgets.excel_import_widget import ExcelImportWidget
from src.gui.modes.structured_form.widgets.inline_checkbox_field import (
    InlineCheckboxField,
)
from src.gui.modes.structured_form.widgets.inline_dropdown_field import (
    InlineDropdownField,
)
from src.gui.modes.structured_form.widgets.inline_multi_line_field import (
    InlineMultiLineField,
)
from src.gui.modes.structured_form.widgets.inline_radio_group_field import (
    InlineRadioGroupField,
)
from src.gui.modes.structured_form.widgets.multi_line_widget import MultiLineWidget
from src.gui.modes.structured_form.widgets.number_entry import NumberEntry
from src.gui.modes.structured_form.widgets.number_input_widget import NumberInputWidget
from src.gui.modes.structured_form.widgets.phone_widget import PhoneWidget
from src.gui.modes.structured_form.widgets.qr_widget import QRWidget
from src.gui.modes.structured_form.widgets.radio_group_widget import RadioGroupWidget
from src.gui.modes.structured_form.widgets.signature_widget import SignatureWidget
from src.gui.modes.structured_form.widgets.stamp_widget import StampWidget
from src.gui.modes.structured_form.widgets.static_text_widget import StaticTextWidget
from src.gui.modes.structured_form.widgets.table_field import TableField
from src.gui.modes.structured_form.widgets.table_widget import (
    TableData,
    TableEditorDialog,
    TableWidget,
)
from src.gui.modes.structured_form.widgets.text_input_widget import TextInputWidget

if TYPE_CHECKING:
    from typing import Type

T = TypeVar("T", bound=BaseFieldWidget)

# Registry mapping FieldType to widget class (legacy Phase 4)
FIELD_WIDGETS: dict[FieldType, Type[BaseFieldWidget]] = {
    FieldType.TEXT_INPUT: TextInputWidget,
    FieldType.NUMBER_INPUT: NumberInputWidget,
    FieldType.CURRENCY: NumberInputWidget,
    FieldType.DATE_INPUT: DateInputWidget,
    FieldType.CHECKBOX: CheckboxWidget,
    FieldType.DROPDOWN: DropdownWidget,
    FieldType.RADIO_GROUP: RadioGroupWidget,
    FieldType.MULTI_LINE_TEXT: MultiLineWidget,
    FieldType.TABLE: TableWidget,
    FieldType.STATIC_TEXT: StaticTextWidget,
    FieldType.CALCULATED: CalculatedWidget,
    FieldType.SIGNATURE: SignatureWidget,
    FieldType.STAMP: StampWidget,
    FieldType.BARCODE: BarcodeWidget,
    FieldType.QR: QRWidget,
    FieldType.PHONE: PhoneWidget,
    FieldType.EMAIL: EmailWidget,
    FieldType.EXCEL_IMPORT: ExcelImportWidget,
}

# New registry mapping FieldType to BaseField classes (Phase 4 inline widgets)
INLINE_FIELD_WIDGETS: dict[FieldType, Type[BaseField]] = {
    FieldType.TEXT_INPUT: AutocompleteEntry,
    FieldType.NUMBER_INPUT: NumberEntry,
    FieldType.CURRENCY: NumberEntry,
    FieldType.DATE_INPUT: DateEntry,
    FieldType.TABLE: TableField,
    FieldType.CHECKBOX: InlineCheckboxField,
    FieldType.DROPDOWN: InlineDropdownField,
    FieldType.RADIO_GROUP: InlineRadioGroupField,
    FieldType.MULTI_LINE_TEXT: InlineMultiLineField,
}

# Phase 5 widgets (placeholders for future implementation)
PHASE_5_WIDGETS: set[FieldType] = set()


def create_field_widget(
    field_type: FieldType,
    parent: tk.Widget,
    field_def: FieldDefinition,
    on_change: Optional[Callable[[str, Any], None]] = None,
    on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = None,
    **kwargs: Any,
) -> BaseFieldWidget:
    """Factory для создания виджетов полей.

    Args:
        field_type: Тип поля из FieldType enum.
        parent: Родительский Tkinter виджет.
        field_def: Определение поля из схемы.
        on_change: Callback при изменении значения.
        on_validate: Callback при валидации.
        **kwargs: Дополнительные параметры для конкретного виджета.

    Returns:
        Созданный виджет поля.

    Raises:
        ValueError: Если тип поля не поддерживается.
        TypeError: Если parent не является tk.Widget.

    Example:
        >>> widget = create_field_widget(
        ...     FieldType.TEXT_INPUT,
        ...     parent=frame,
        ...     field_def=field_def,
        ...     on_change=on_change
        ... )
        >>> widget.mount(parent_frame)
        >>> widget.set_value("Hello")
    """
    if not isinstance(parent, tk.Widget):
        raise TypeError(f"parent должен быть tk.Widget, получен {type(parent).__name__}")

    # Check Phase 5 types
    if field_type in PHASE_5_WIDGETS:
        raise ValueError(
            f"Field type {field_type.value} is not yet implemented (Phase 5). "
            f"Available Phase 4 types: {[ft.value for ft in FIELD_WIDGETS.keys()]}"
        )

    widget_class = FIELD_WIDGETS.get(field_type)
    if widget_class is None:
        raise ValueError(
            f"Unknown field type: {field_type}. "
            f"Supported types: {list(FIELD_WIDGETS.keys()) + list(PHASE_5_WIDGETS)}"
        )

    return widget_class(
        parent=parent,
        field_def=field_def,
        on_change=on_change,
        on_validate=on_validate,
        **kwargs,
    )


def create_inline_widget(
    field_type: FieldType,
    parent: tk.Widget,
    field_def: FieldDefinition,
    document_index: str = "",
    on_change: Optional[Callable[[str, Any], None]] = None,
    **kwargs: Any,
) -> BaseField:
    """Factory для создания inline-виджетов полей (BaseField).

    Args:
        field_type: Тип поля из FieldType enum.
        parent: Родительский Tkinter виджет.
        field_def: Определение поля из схемы.
        document_index: Индекс документа для автодополнения.
        on_change: Callback при изменении значения.
        **kwargs: Дополнительные параметры для конкретного виджета.

    Returns:
        Созданный inline-виджет поля (наследник BaseField).

    Raises:
        ValueError: Если тип поля не поддерживается.
        TypeError: Если parent не является tk.Widget.

    Example:
        >>> widget = create_inline_widget(
        ...     FieldType.NUMBER_INPUT,
        ...     parent=frame,
        ...     field_def=field_def,
        ...     on_change=on_change
        ... )
        >>> widget.pack(fill=tk.X)
    """
    if not isinstance(parent, tk.Widget):
        raise TypeError(f"parent должен быть tk.Widget, получен {type(parent).__name__}")

    if field_type in PHASE_5_WIDGETS:
        raise ValueError(
            f"Field type {field_type.value} is not yet implemented (Phase 5). "
            f"Available inline types: {[ft.value for ft in INLINE_FIELD_WIDGETS.keys()]}"
        )

    widget_class = INLINE_FIELD_WIDGETS.get(field_type)
    if widget_class is None:
        # Fallback: если inline-виджет не найден, используем legacy create_field_widget
        # и оборачиваем в BaseField-like контейнер
        raise ValueError(f"Inline widget for {field_type.value} not yet implemented.")

    if widget_class is AutocompleteEntry:
        return AutocompleteEntry(
            parent=parent,
            field_id=field_def.field_id,
            document_index=document_index,
            label=field_def.label,
            on_change=on_change,
            autocomplete_service=kwargs.get("autocomplete_service"),
            field_def=field_def,
        )

    if widget_class is NumberEntry:
        return NumberEntry(
            parent=parent,
            field_id=field_def.field_id,
            label=field_def.label,
            min_value=field_def.min_value,
            max_value=field_def.max_value,
            decimal_places=kwargs.get("decimal_places", 2),
            on_change=on_change,
        )

    if widget_class is DateEntry:
        return DateEntry(
            parent=parent,
            field_id=field_def.field_id,
            label=field_def.label,
            on_change=on_change,
        )

    if widget_class is TableField:
        columns = kwargs.get("columns")
        if columns is None and field_def.table_schema is not None:
            columns = [col.header for col in field_def.table_schema.columns]
        rows = kwargs.get("rows", 1)
        return TableField(
            parent=parent,
            field_id=field_def.field_id,
            columns=columns or [],
            rows=rows,
            on_change=on_change,
            label=field_def.label,
        )

    if widget_class is InlineCheckboxField:
        return InlineCheckboxField(
            parent=parent,
            field_id=field_def.field_id,
            label=field_def.label,
            required=field_def.required,
            readonly=field_def.readonly,
            on_change=on_change,
        )

    if widget_class is InlineDropdownField:
        return InlineDropdownField(
            parent=parent,
            field_id=field_def.field_id,
            label=field_def.label,
            options=field_def.options,
            required=field_def.required,
            readonly=field_def.readonly,
            on_change=on_change,
        )

    if widget_class is InlineRadioGroupField:
        return InlineRadioGroupField(
            parent=parent,
            field_id=field_def.field_id,
            label=field_def.label,
            options=field_def.options,
            required=field_def.required,
            readonly=field_def.readonly,
            on_change=on_change,
        )

    if widget_class is InlineMultiLineField:
        return InlineMultiLineField(
            parent=parent,
            field_id=field_def.field_id,
            label=field_def.label,
            required=field_def.required,
            readonly=field_def.readonly,
            max_length=field_def.max_length,
            placeholder=field_def.placeholder or "",
            on_change=on_change,
        )

    return widget_class(
        parent=parent,
        field_id=field_def.field_id,
        label=field_def.label,
        on_change=on_change,
        **kwargs,
    )


def get_supported_field_types() -> list[FieldType]:
    """Возвращает список поддерживаемых типов полей.

    Returns:
        Список FieldType, для которых доступны виджеты.

    Example:
        >>> supported = get_supported_field_types()
        >>> FieldType.TEXT_INPUT in supported
        True
    """
    return list(FIELD_WIDGETS.keys())


def is_field_type_supported(field_type: FieldType) -> bool:
    """Проверяет, поддерживается ли тип поля.

    Args:
        field_type: Тип поля для проверки.

    Returns:
        True если для данного типа есть виджет.

    Example:
        >>> is_field_type_supported(FieldType.TEXT_INPUT)
        True
        >>> is_field_type_supported(FieldType.QR)
        False  # Phase 5
    """
    return field_type in FIELD_WIDGETS


__all__: list[str] = [
    # Factory
    "create_field_widget",
    "create_inline_widget",
    "get_supported_field_types",
    "is_field_type_supported",
    # Base classes
    "BaseField",
    "BaseFieldWidget",
    "FieldSettingsToolbar",
    # Widgets
    "AutocompleteEntry",
    "BarcodeWidget",
    "CalculatedWidget",
    "CheckboxWidget",
    "DateEntry",
    "DateInputWidget",
    "DropdownWidget",
    "EmailWidget",
    "ExcelImportWidget",
    "InlineCheckboxField",
    "InlineDropdownField",
    "InlineMultiLineField",
    "InlineRadioGroupField",
    "MultiLineWidget",
    "NumberEntry",
    "NumberInputWidget",
    "PhoneWidget",
    "QRWidget",
    "RadioGroupWidget",
    "SignatureWidget",
    "StampWidget",
    "StaticTextWidget",
    "TableField",
    "TableWidget",
    "TextInputWidget",
    # Table helpers
    "TableData",
    "TableEditorDialog",
    # Constants
    "FIELD_WIDGETS",
    "INLINE_FIELD_WIDGETS",
    "PHASE_5_WIDGETS",
]
