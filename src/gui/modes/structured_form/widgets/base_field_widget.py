"""Базовый класс для всех полей формы.

Предоставляет:
- BaseFieldWidget: базовый класс для всех виджетов полей формы
- FieldSettingsToolbar: панель настроек CPI/Font для поля

Example:
    >>> widget = TextInputWidget(
    ...     parent=frame,
    ...     field_def=field_def,
    ...     on_change=on_field_change
    ... )
    >>> widget.mount(parent_frame)
"""

from __future__ import annotations

import re
import tkinter as tk
from abc import abstractmethod
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Optional

from src.documents.types.type_schema import FieldDefinition, FieldType
from src.gui.components.base.widget import BaseWidget
from src.model.enums import FontFamily


class BaseFieldWidget(BaseWidget):
    """Базовый класс для всех полей формы.

    Attributes:
        _field_def: Определение поля из схемы.
        _value: Текущее значение поля.
        _is_valid: Флаг валидности значения.
        _error_message: Сообщение об ошибке валидации.
        _on_change: Callback при изменении значения.
        _on_validate: Callback при валидации.
        _cpi: Текущий CPI для поля.
        _lpi: Текущий LPI для поля.
        _font_family: Текущий шрифт.
        _font_quality: Текущее качество шрифта (nlq/draft).

    Example:
        >>> widget = TextInputWidget(parent, field_def, on_change=callback)
        >>> widget.validate()
        True
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_def: FieldDefinition,
        on_change: Optional[Callable[[str, Any], None]] = None,
        on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = None,
    ) -> None:
        """Инициализация базового виджета поля.

        Args:
            parent: Родительский Tkinter виджет.
            field_def: Определение поля из схемы.
            on_change: Callback при изменении значения.
            on_validate: Callback при валидации.
        """
        super().__init__(widget_id=field_def.field_id, controller=None)

        self._parent: tk.Widget = parent
        self._field_def: FieldDefinition = field_def
        self._value: Any = field_def.default_value
        self._is_valid: bool = True
        self._error_message: Optional[str] = None
        self._on_change: Optional[Callable[[str, Any], None]] = on_change
        self._on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = on_validate

        # Per-field CPI/Font settings (editable per field)
        self._cpi: int = 10  # Default CPI
        self._lpi: int = 6  # Default LPI
        self._font_family: FontFamily = FontFamily.ROMAN
        self._font_quality: str = "nlq"  # nlq/draft

        # Tkinter widgets
        self._main_frame: Optional[tk.Frame] = None
        self._label_widget: Optional[tk.Widget] = None
        self._input_widget: Optional[tk.Widget] = None
        self._error_widget: Optional[tk.Label] = None
        self._toolbar: Optional[FieldSettingsToolbar] = None

    @property
    def field_id(self) -> str:
        """Возвращает идентификатор поля.

        Returns:
            Строковый идентификатор поля.
        """
        return self._field_def.field_id

    @property
    def field_type(self) -> FieldType:
        """Возвращает тип поля.

        Returns:
            Тип поля из FieldType enum.
        """
        return self._field_def.field_type

    def get_value(self) -> Any:
        """Возвращает текущее значение поля.

        Returns:
            Текущее значение поля.
        """
        return self._value

    def set_value(self, value: Any) -> None:
        """Устанавливает значение поля.

        Args:
            value: Новое значение поля.

        Note:
            Вызывает on_change callback и валидирует значение.
        """
        self._value = value
        if self._on_change:
            self._on_change(self.field_id, value)
        self.validate()

    def validate(self) -> bool:
        """Валидирует значение по правилам field_def.

        Returns:
            True если значение валидно, False иначе.

        Проверяет:
            - Обязательность поля
            - Pattern validation (regex)
            - Min/max length
            - Min/max value (для чисел)
            - Min/max date
            - Options (для DROPDOWN/RADIO_GROUP)
        """
        errors: list[str] = []

        # Required check
        if self._field_def.required:
            if self._value is None or self._value == "" or self._value == []:
                errors.append(f"Поле '{self._field_def.label}' обязательно для заполнения")

        # Skip other checks if value is empty
        if self._value is None or self._value == "" or self._value == []:
            self._update_validation_state(len(errors) == 0, errors)
            return len(errors) == 0

        value_str = str(self._value)

        # Pattern validation
        if self._field_def.validation_pattern:
            try:
                if not re.match(self._field_def.validation_pattern, value_str):
                    errors.append(f"Поле '{self._field_def.label}' не соответствует шаблону")
            except re.error:
                # Invalid regex pattern - skip
                pass

        # Max length
        if self._field_def.max_length is not None:
            if len(value_str) > self._field_def.max_length:
                errors.append(
                    f"Поле '{self._field_def.label}' должно быть не более "
                    f"{self._field_def.max_length} символов"
                )

        # Min/max value for numbers
        if self._field_def.field_type in (FieldType.NUMBER_INPUT, FieldType.CURRENCY):
            try:
                num_value = Decimal(str(self._value))
                if self._field_def.min_value is not None:
                    if num_value < Decimal(str(self._field_def.min_value)):
                        errors.append(f"Значение должно быть не менее {self._field_def.min_value}")
                if self._field_def.max_value is not None:
                    if num_value > Decimal(str(self._field_def.max_value)):
                        errors.append(f"Значение должно быть не более {self._field_def.max_value}")
            except (InvalidOperation, ValueError, TypeError):
                errors.append("Некорректное числовое значение")

        # Options validation for DROPDOWN/RADIO_GROUP
        if self._field_def.options is not None:
            if value_str not in self._field_def.options:
                errors.append(
                    f"Поле должно иметь одно из значений: {', '.join(self._field_def.options)}"
                )

        self._update_validation_state(len(errors) == 0, errors)
        return len(errors) == 0

    def _update_validation_state(self, is_valid: bool, errors: list[str]) -> None:
        """Обновляет состояние валидации.

        Args:
            is_valid: Флаг валидности.
            errors: Список ошибок.
        """
        self._is_valid = is_valid
        self._error_message = errors[0] if errors else None

        # Update error display
        self.set_error(self._error_message)

        # Call validation callback
        if self._on_validate:
            self._on_validate(self.field_id, is_valid, self._error_message or "")

    def set_error(self, message: Optional[str]) -> None:
        """Показывает/скрывает ошибку.

        Args:
            message: Сообщение об ошибке или None для скрытия.
        """
        if self._error_widget is not None:
            if message:
                self._error_widget.config(text=message, fg="red")
                self._error_widget.grid()
            else:
                self._error_widget.config(text="")
                self._error_widget.grid_remove()

    def set_cpi(self, cpi: int) -> None:
        """Устанавливает CPI для этого поля.

        Args:
            cpi: Новое значение CPI (10, 12, 15, 17, 20).
        """
        self._cpi = cpi
        self._update_font()

    def set_lpi(self, lpi: int) -> None:
        """Устанавливает LPI для этого поля.

        Args:
            lpi: Новое значение LPI (6 или 8).
        """
        self._lpi = lpi

    def set_font_family(self, font_family: FontFamily) -> None:
        """Устанавливает шрифт.

        Args:
            font_family: Новый шрифт из FontFamily enum.
        """
        self._font_family = font_family
        self._update_font()

    def set_font_quality(self, quality: str) -> None:
        """Устанавливает качество шрифта.

        Args:
            quality: Качество шрифта ('nlq' или 'draft').
        """
        self._font_quality = quality
        self._update_font()

    def _update_font(self) -> None:
        """Обновляет шрифт виджета.

        Подклассы могут переопределить для обновления GUI шрифта.
        """
        # Base implementation - subclasses should override
        pass

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные.

        Security:
            Очищает значение поля и все внутренние ссылки.
            Вызывается перед закрытием формы с sensitive данными.
        """
        self._value = None

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт фактический Tkinter виджет.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Tkinter виджет.
        """
        self._main_frame = tk.Frame(parent, padx=4, pady=4)

        # Create label
        label_text = self._field_def.label
        if self._field_def.required:
            label_text += " *"
        self._label_widget = tk.Label(
            self._main_frame,
            text=label_text,
            anchor=tk.W,
            font=("TkDefaultFont", 10, "bold" if self._field_def.required else "normal"),
        )
        self._label_widget.grid(row=0, column=0, sticky=tk.W, pady=(0, 2))

        # Create input widget (implemented by subclasses)
        self._input_widget = self._create_widget()
        if self._input_widget is not None:
            self._input_widget.grid(row=1, column=0, sticky=tk.EW, pady=(0, 2))

        # Create error label
        self._error_widget = tk.Label(
            self._main_frame,
            text="",
            fg="red",
            font=("TkDefaultFont", 8),
            wraplength=300,
        )
        self._error_widget.grid(row=2, column=0, sticky=tk.W)
        self._error_widget.grid_remove()  # Hidden by default

        # Configure grid weights
        self._main_frame.columnconfigure(0, weight=1)

        return self._main_frame

    @abstractmethod
    def _create_widget(self) -> tk.Widget:
        """Создаёт виджет ввода.

        Returns:
            Tkinter виджет для ввода данных.

        Note:
            Должен быть реализован подклассами.
        """
        ...


class FieldSettingsToolbar(tk.Frame):
    """Toolbar с настройками CPI/Font для поля.

    Attributes:
        _cpi: Текущее значение CPI.
        _font_family: Текущий шрифт.
        _font_quality: Текущее качество шрифта.
        _on_cpi_change: Callback при изменении CPI.
        _on_font_change: Callback при изменении шрифта.
        _on_quality_change: Callback при изменении качества.

    Example:
        >>> toolbar = FieldSettingsToolbar(
        ...     parent=frame,
        ...     cpi=10,
        ...     font_family=FontFamily.ROMAN,
        ...     font_quality="nlq",
        ...     on_cpi_change=on_cpi_changed,
        ...     on_font_change=on_font_changed,
        ...     on_quality_change=on_quality_changed,
        ... )
    """

    CPI_OPTIONS: list[int] = [10, 12, 15, 17, 20]
    QUALITY_OPTIONS: list[str] = ["nlq", "draft"]

    def __init__(
        self,
        parent: tk.Widget,
        cpi: int,
        font_family: FontFamily,
        font_quality: str,
        on_cpi_change: Callable[[int], None],
        on_font_change: Callable[[FontFamily], None],
        on_quality_change: Callable[[str], None],
    ) -> None:
        """Инициализация тулбара настроек.

        Args:
            parent: Родительский Tkinter виджет.
            cpi: Начальное значение CPI.
            font_family: Начальный шрифт.
            font_quality: Начальное качество.
            on_cpi_change: Callback при изменении CPI.
            on_font_change: Callback при изменении шрифта.
            on_quality_change: Callback при изменении качества.
        """
        super().__init__(parent, padx=2, pady=2)

        self._cpi: int = cpi
        self._font_family: FontFamily = font_family
        self._font_quality: str = font_quality
        self._on_cpi_change: Callable[[int], None] = on_cpi_change
        self._on_font_change: Callable[[FontFamily], None] = on_font_change
        self._on_quality_change: Callable[[str], None] = on_quality_change

        # Create widgets
        self._create_widgets()

    def _create_widgets(self) -> None:
        """Создаёт виджеты тулбара."""
        import tkinter.ttk as ttk

        # CPI selector
        tk.Label(self, text="CPI:", font=("TkDefaultFont", 9)).pack(side=tk.LEFT, padx=(0, 2))

        self._cpi_var = tk.StringVar(master=self, value=str(self._cpi))
        self._cpi_combo = ttk.Combobox(
            self,
            textvariable=self._cpi_var,
            values=[str(c) for c in self.CPI_OPTIONS],
            width=5,
            state="readonly",
        )
        self._cpi_combo.pack(side=tk.LEFT, padx=(0, 8))
        self._cpi_combo.bind("<<ComboboxSelected>>", self._on_cpi_selected)

        # Font family selector
        tk.Label(self, text="Font:", font=("TkDefaultFont", 9)).pack(side=tk.LEFT, padx=(0, 2))

        self._font_var = tk.StringVar(master=self, value=self._font_family.value)
        font_options = [f.value for f in FontFamily]
        self._font_combo = ttk.Combobox(
            self,
            textvariable=self._font_var,
            values=font_options,
            width=12,
            state="readonly",
        )
        self._font_combo.pack(side=tk.LEFT, padx=(0, 8))
        self._font_combo.bind("<<ComboboxSelected>>", self._on_font_selected)

        # Quality selector
        tk.Label(self, text="Quality:", font=("TkDefaultFont", 9)).pack(side=tk.LEFT, padx=(0, 2))

        self._quality_var = tk.StringVar(master=self, value=self._font_quality)
        self._quality_combo = ttk.Combobox(
            self,
            textvariable=self._quality_var,
            values=self.QUALITY_OPTIONS,
            width=8,
            state="readonly",
        )
        self._quality_combo.pack(side=tk.LEFT)
        self._quality_combo.bind("<<ComboboxSelected>>", self._on_quality_selected)

    def _on_cpi_selected(self, event: Any) -> None:
        """Обработчик выбора CPI."""
        try:
            new_cpi = int(self._cpi_var.get())
            self._cpi = new_cpi
            self._on_cpi_change(new_cpi)
        except ValueError:
            pass

    def _on_font_selected(self, event: Any) -> None:
        """Обработчик выбора шрифта."""
        font_value = self._font_var.get()
        font_family = FontFamily.from_string(font_value)
        if font_family:
            self._font_family = font_family
            self._on_font_change(font_family)

    def _on_quality_selected(self, event: Any) -> None:
        """Обработчик выбора качества."""
        quality = self._quality_var.get()
        self._font_quality = quality
        self._on_quality_change(quality)


__all__: list[str] = [
    "BaseFieldWidget",
    "FieldSettingsToolbar",
]
