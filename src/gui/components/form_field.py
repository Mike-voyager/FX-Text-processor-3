"""FormField composite widget для FX Text Processor 3.

Предоставляет:
- FormField: композитный виджет поля формы с меткой, вводом и индикатором ошибки

Компоненты:
    - Label: название поля с индикатором обязательности (*)
    - Input widget: Entry, AutocompleteEntry, DateEntry, NumberEntry, Combobox
    - Error indicator: красная иконка с tooltip
    - Validation state management

Example:
    >>> field = FormField(
    ...     parent=frame,
    ...     field_def=field_def,
    ...     document_index="DVN-44-K53-IX",
    ...     autocomplete_service=service,
    ...     on_change=on_field_changed,
    ...     on_validate=on_field_validated,
    ... )
    >>> field.set_value("ООО Ромашка")
    >>> is_valid, error = field.validate()

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import re
import tkinter as tk
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from functools import partial
from tkinter import ttk
from typing import Any, Callable, Optional

from src.documents.types.type_schema import FieldDefinition, FieldType
from src.gui.themes import ThemeManager, get_theme_manager


class FormField(ttk.Frame):
    """Композитный виджет поля формы.

    Объединяет метку, виджет ввода и индикатор ошибки в единый компонент.
    Поддерживает различные типы полей через фабричный метод создания
    виджетов ввода.

    Attributes:
        _field_def: Определение поля из схемы документа.
        _document_index: Индекс документа для автокомплита.
        _autocomplete_service: Сервис автокомплита (опционально).
        _on_change: Callback при изменении значения.
        _on_validate: Callback при валидации.
        _theme_manager: Менеджер тем для стилизации.
        _value: Текущее значение поля.
        _is_valid: Флаг валидности значения.
        _error_message: Текущее сообщение об ошибке.

    Example:
        >>> field = FormField(
        ...     parent=parent_frame,
        ...     field_def=field_def,
        ...     document_index="DVN-44-K53-IX",
        ... )
        >>> field.pack(fill=tk.X, padx=10, pady=5)
        >>> field.set_value("test")
        >>> valid, error = field.validate()
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_def: FieldDefinition,
        document_index: str,
        autocomplete_service: Optional[Any] = None,
        on_change: Optional[Callable[[str, Any], None]] = None,
        on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = None,
    ) -> None:
        """Инициализация композитного виджета поля формы.

        Args:
            parent: Родительский Tkinter виджет.
            field_def: Определение поля из схемы документа.
            document_index: Индекс документа для автокомплита.
            autocomplete_service: Сервис автокомплита (опционально).
            on_change: Callback при изменении значения (field_id, value).
            on_validate: Callback при валидации (field_id, is_valid, error).
        """
        super().__init__(parent, padding=(8, 4))

        self._field_def: FieldDefinition = field_def
        self._document_index: str = document_index
        self._autocomplete_service: Optional[Any] = autocomplete_service
        self._on_change: Optional[Callable[[str, Any], None]] = on_change
        self._on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = on_validate
        self._theme_manager: ThemeManager = get_theme_manager()

        # State
        self._value: Any = field_def.default_value
        self._is_valid: bool = True
        self._error_message: Optional[str] = None
        self._is_enabled: bool = True

        # Widget references
        self._label_widget: Optional[tk.Widget] = None
        self._input_widget: Optional[tk.Widget] = None
        self._error_indicator: Optional[tk.Label] = None
        self._error_tooltip: Optional[str] = None
        self._tooltip_window: Optional[tk.Toplevel] = None

        # Create UI
        self._create_widgets()
        self._apply_theme()

    def _create_widgets(self) -> None:
        """Создаёт дочерние виджеты компонента."""
        # Configure grid
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=0)

        # Label frame (left side)
        label_frame = ttk.Frame(self)
        label_frame.grid(row=0, column=0, sticky=tk.W, pady=(0, 2))
        label_frame.columnconfigure(0, weight=1)

        # Label with required indicator
        label_text = self._field_def.label
        if self._field_def.required:
            label_text += " *"

        self._label_widget = tk.Label(
            label_frame,
            text=label_text,
            anchor=tk.W,
            font=("TkDefaultFont", 10, "bold" if self._field_def.required else "normal"),
        )
        self._label_widget.pack(side=tk.LEFT)

        # Help text tooltip
        if self._field_def.help_text:
            help_label = tk.Label(
                label_frame,
                text=" (?)",
                fg="blue",
                cursor="question_arrow",
                font=("TkDefaultFont", 9),
            )
            help_label.pack(side=tk.LEFT)
            if self._field_def.help_text is not None:
                help_text: str = self._field_def.help_text

                help_label.bind(
                    "<Enter>",
                    partial(self._show_tooltip_for_event, help_text),
                )
                help_label.bind("<Leave>", self._hide_tooltip)

        # Input widget
        self._input_widget = self._create_input_widget()
        if self._input_widget is not None:
            self._input_widget.grid(row=1, column=0, sticky=tk.EW, pady=(0, 2))

        # Error indicator (red circle)
        self._error_indicator = tk.Label(
            self,
            text="●",
            fg="red",
            font=("TkDefaultFont", 12),
            cursor="hand2",
        )
        self._error_indicator.grid(row=1, column=1, sticky=tk.W, padx=(4, 0))
        self._error_indicator.grid_remove()  # Hidden by default
        self._error_indicator.bind("<Enter>", self._on_error_hover)
        self._error_indicator.bind("<Leave>", self._hide_tooltip)

    def _create_input_widget(self) -> Optional[tk.Widget]:
        """Создаёт виджет ввода на основе типа поля.

        Returns:
            Созданный виджет ввода или None.

        Factory method для создания:
            - AutocompleteEntry: TEXT_INPUT с autocomplete_source
            - tk.Entry: TEXT_INPUT без autocomplete
            - tk.Entry с валидацией: NUMBER_INPUT
            - tk.Entry с календарём: DATE_INPUT
            - ttk.Combobox: DROPDOWN
        """
        field_type = self._field_def.field_type

        if field_type == FieldType.TEXT_INPUT:
            return self._create_text_input()
        elif field_type == FieldType.NUMBER_INPUT:
            return self._create_number_input()
        elif field_type == FieldType.DATE_INPUT:
            return self._create_date_input()
        elif field_type == FieldType.DROPDOWN:
            return self._create_dropdown_input()
        elif field_type == FieldType.MULTI_LINE_TEXT:
            return self._create_multiline_input()
        elif field_type in (FieldType.PHONE, FieldType.EMAIL):
            return self._create_text_input()
        else:
            # Fallback to simple entry
            return self._create_text_input()

    def _create_text_input(self) -> tk.Widget:
        """Создаёт текстовое поле ввода.

        Returns:
            AutocompleteEntry если есть autocomplete_source, иначе tk.Entry.
        """
        # Check if autocomplete is available
        if self._field_def.autocomplete_source and self._autocomplete_service:
            from src.gui.modes.structured_form.widgets.autocomplete_entry import (
                AutocompleteEntry,
            )

            widget = AutocompleteEntry(
                parent=self,
                field_def=self._field_def,
                document_index=self._document_index,
                autocomplete_service=self._autocomplete_service,
                on_change=self._on_input_change,
                on_validate=self._on_input_validate,
            )
            # Mount the widget to get tk widget
            return widget.mount(self)

        # Simple entry
        entry = tk.Entry(
            self,
            font=("TkDefaultFont", 10),
            relief=tk.SUNKEN,
            borderwidth=1,
        )

        # Set placeholder
        if self._field_def.placeholder:
            entry.insert(0, self._field_def.placeholder)
            entry.config(fg="gray")
            entry.bind("<FocusIn>", self._on_placeholder_focus_in)
            entry.bind("<FocusOut>", self._on_placeholder_focus_out)

        # Set max length
        if self._field_def.max_length:
            entry.config(
                validate="key",
                validatecommand=(self.register(self._validate_max_length), "%P"),
            )

        # Set initial value
        if self._field_def.default_value is not None:
            entry.delete(0, tk.END)
            entry.insert(0, str(self._field_def.default_value))
            entry.config(fg=self._theme_manager.get_current_theme().fg_color)

        # Bind change events
        entry.bind("<KeyRelease>", self._on_entry_change)
        entry.bind("<FocusOut>", self._on_entry_focus_out)

        # Apply readonly state
        if self._field_def.readonly:
            entry.config(state="readonly")

        return entry

    def _create_number_input(self) -> tk.Widget:
        """Создаёт числовое поле ввода.

        Returns:
            tk.Entry с числовой валидацией.
        """
        entry = tk.Entry(
            self,
            font=("TkDefaultFont", 10),
            relief=tk.SUNKEN,
            borderwidth=1,
            justify=tk.RIGHT,
        )

        # Set placeholder
        if self._field_def.placeholder:
            entry.insert(0, self._field_def.placeholder)
            entry.config(fg="gray")

        # Validate as number
        entry.config(
            validate="key",
            validatecommand=(self.register(self._validate_number_input), "%P"),
        )

        # Set initial value
        if self._field_def.default_value is not None:
            entry.delete(0, tk.END)
            entry.insert(0, str(self._field_def.default_value))

        # Bind change events
        entry.bind("<KeyRelease>", self._on_number_change)
        entry.bind("<FocusOut>", self._on_number_focus_out)

        # Apply readonly state
        if self._field_def.readonly:
            entry.config(state="readonly")

        return entry

    def _create_date_input(self) -> tk.Widget:
        """Создаёт поле ввода даты.

        Returns:
            tk.Entry с валидацией даты и кнопкой календаря.
        """
        frame = ttk.Frame(self)

        entry = tk.Entry(
            frame,
            font=("TkDefaultFont", 10),
            relief=tk.SUNKEN,
            borderwidth=1,
            width=12,
        )
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Calendar button
        calendar_btn = tk.Button(
            frame,
            text="📅",
            font=("TkDefaultFont", 9),
            command=self._show_calendar_dialog,
            relief=tk.RAISED,
            borderwidth=1,
        )
        calendar_btn.pack(side=tk.LEFT, padx=(4, 0))

        # Set initial value
        if isinstance(self._field_def.default_value, date):
            entry.insert(0, self._format_date(self._field_def.default_value))
        elif isinstance(self._field_def.default_value, str):
            entry.insert(0, self._field_def.default_value)
        else:
            entry.insert(0, "ДД.ММ.ГГГГ")
            entry.config(fg="gray")

        # Bind events
        entry.bind("<FocusIn>", self._on_date_focus_in)
        entry.bind("<FocusOut>", self._on_date_focus_out)
        entry.bind("<KeyRelease>", self._on_date_change)

        # Store reference
        self._date_entry = entry
        self._calendar_button = calendar_btn

        # Apply readonly state
        if self._field_def.readonly:
            entry.config(state="readonly")
            calendar_btn.config(state="disabled")

        return frame

    def _create_dropdown_input(self) -> tk.Widget:
        """Создаёт выпадающий список.

        Returns:
            ttk.Combobox с опциями из field_def.options.
        """
        options = list(self._field_def.options) if self._field_def.options else []

        combo = ttk.Combobox(
            self,
            values=options,
            state="readonly" if self._field_def.readonly else "normal",
            font=("TkDefaultFont", 10),
        )

        # Set initial value
        if self._field_def.default_value is not None:
            if self._field_def.default_value in options:
                combo.set(self._field_def.default_value)
        elif options:
            combo.set(options[0])

        # Bind change event
        combo.bind("<<ComboboxSelected>>", self._on_combobox_change)
        combo.bind("<KeyRelease>", self._on_combobox_change)

        return combo

    def _create_multiline_input(self) -> tk.Widget:
        """Создаёт многострочное поле ввода.

        Returns:
            tk.Text с прокруткой.
        """
        frame = ttk.Frame(self)

        scrollbar = ttk.Scrollbar(frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        text = tk.Text(
            frame,
            font=("TkDefaultFont", 10),
            relief=tk.SUNKEN,
            borderwidth=1,
            height=4,
            yscrollcommand=scrollbar.set,
            wrap=tk.WORD,
        )
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=text.yview)

        # Set initial value
        if self._field_def.default_value is not None:
            text.insert("1.0", str(self._field_def.default_value))

        # Bind change event
        text.bind("<KeyRelease>", self._on_text_change)
        text.bind("<FocusOut>", self._on_text_focus_out)

        # Apply readonly state
        if self._field_def.readonly:
            text.config(state="disabled")

        self._text_widget = text

        return frame

    def _apply_theme(self) -> None:
        """Применяет текущую тему к виджету."""
        theme = self._theme_manager.get_current_theme()

        # Get background color - ttk.Frame uses style, not cget("background")
        try:
            bg_color = self.cget("background")
        except tk.TclError:
            # For ttk widgets, get background from theme
            bg_color = theme.bg_color if hasattr(theme, "bg_color") else "#ffffff"

        # Apply to label
        if self._label_widget is not None and isinstance(self._label_widget, tk.Label):
            self._label_widget.config(
                bg=bg_color,
                fg=theme.fg_color if not self._field_def.required else theme.accent_color,
            )

        # Apply to input widget
        if self._input_widget is not None:
            self._theme_manager.apply_to_widget(self._input_widget)

    def get_value(self) -> Any:
        """Возвращает текущее значение поля.

        Returns:
            Текущее значение поля в зависимости от типа.
        """
        return self._value

    def set_value(self, value: Any) -> None:
        """Устанавливает значение поля.

        Args:
            value: Новое значение для поля.
        """
        self._value = value

        # Update input widget
        if self._input_widget is not None:
            self._update_input_value(value)

        # Trigger callbacks
        if self._on_change:
            self._on_change(self._field_def.field_id, value)

    def _update_input_value(self, value: Any) -> None:
        """Обновляет отображаемое значение в виджете ввода.

        Args:
            value: Значение для отображения.
        """
        field_type = self._field_def.field_type

        if field_type == FieldType.DROPDOWN:
            if isinstance(self._input_widget, ttk.Combobox):
                self._input_widget.set(str(value) if value else "")
        elif field_type == FieldType.MULTI_LINE_TEXT:
            if hasattr(self, "_text_widget"):
                self._text_widget.delete("1.0", tk.END)
                if value:
                    self._text_widget.insert("1.0", str(value))
        elif field_type == FieldType.DATE_INPUT:
            if hasattr(self, "_date_entry") and isinstance(value, date):
                self._date_entry.delete(0, tk.END)
                self._date_entry.insert(0, self._format_date(value))
        else:
            # Standard entry
            if isinstance(self._input_widget, tk.Entry):
                self._input_widget.delete(0, tk.END)
                if value is not None:
                    self._input_widget.insert(0, str(value))

    def validate(self) -> tuple[bool, Optional[str]]:
        """Валидирует значение поля.

        Проверяет:
            - Обязательность поля
            - Pattern matching (regex)
            - Min/max length
            - Min/max value (для чисел)
            - Min/max date

        Returns:
            Кортеж (is_valid, error_message).
        """
        errors: list[str] = []

        # Required check
        if self._field_def.required:
            if self._value is None or self._value == "" or self._value == []:
                errors.append(f"Поле '{self._field_def.label}' обязательно для заполнения")

        # Skip other checks if value is empty
        if self._value is None or self._value == "" or self._value == []:
            self._update_validation_state(len(errors) == 0, errors)
            return len(errors) == 0, errors[0] if errors else None

        value_str = str(self._value)

        # Pattern validation
        if self._field_def.validation_pattern:
            try:
                if not re.match(self._field_def.validation_pattern, value_str):
                    errors.append(f"Поле '{self._field_def.label}' не соответствует шаблону")
            except re.error:
                pass  # Invalid regex - skip

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

        # Min/max date
        if self._field_def.field_type == FieldType.DATE_INPUT:
            parsed_date = self._parse_date(str(self._value))
            if parsed_date is not None:
                if self._field_def.min_date is not None:
                    if parsed_date < self._field_def.min_date:
                        date_fmt = self._format_date(self._field_def.min_date)
                        errors.append(f"Дата должна быть не раньше {date_fmt}")
                if self._field_def.max_date is not None:
                    if parsed_date > self._field_def.max_date:
                        date_fmt = self._format_date(self._field_def.max_date)
                        errors.append(f"Дата должна быть не позже {date_fmt}")
            else:
                errors.append("Некорректный формат даты (ДД.ММ.ГГГГ)")

        # Options validation for DROPDOWN
        if self._field_def.options is not None:
            if value_str not in self._field_def.options:
                errors.append(
                    f"Поле должно иметь одно из значений: {', '.join(self._field_def.options)}"
                )

        self._update_validation_state(len(errors) == 0, errors)
        return len(errors) == 0, errors[0] if errors else None

    def set_error(self, error: Optional[str]) -> None:
        """Устанавливает состояние ошибки.

        Args:
            error: Сообщение об ошибке или None для очистки.
        """
        self._error_message = error
        self._is_valid = error is None

        if error:
            self._error_tooltip = error
            if self._error_indicator is not None:
                self._error_indicator.grid()

            # Highlight input widget
            if self._input_widget is not None:
                self._highlight_error(True)
        else:
            self._error_tooltip = None
            if self._error_indicator is not None:
                self._error_indicator.grid_remove()

            # Remove highlight
            if self._input_widget is not None:
                self._highlight_error(False)

        # Call validation callback
        if self._on_validate:
            self._on_validate(self._field_def.field_id, self._is_valid, error)

    def clear_error(self) -> None:
        """Очищает состояние ошибки."""
        self.set_error(None)

    def set_enabled(self, enabled: bool) -> None:
        """Устанавливает состояние активности поля.

        Args:
            enabled: True для активного состояния, False для неактивного.
        """
        self._is_enabled = enabled

        if self._input_widget is not None:
            state = "normal" if enabled else "disabled"

            if isinstance(self._input_widget, (tk.Entry, ttk.Entry)):
                widget: Any = self._input_widget
                widget.config(state=state)
            elif isinstance(self._input_widget, ttk.Combobox):
                self._input_widget.configure(state="readonly" if enabled else "disabled")
            elif isinstance(self._input_widget, tk.Text):
                txt_widget: Any = self._input_widget
                txt_widget.config(state=state)
            elif isinstance(self._input_widget, ttk.Frame):
                # For composite widgets (date input)
                for child in self._input_widget.winfo_children():
                    if isinstance(child, (tk.Entry, tk.Button)):
                        ch_widget: Any = child
                        ch_widget.config(state=state)

    def focus(self) -> None:
        """Устанавливает фокус на поле ввода."""
        if self._input_widget is not None:
            if isinstance(self._input_widget, tk.Entry):
                self._input_widget.focus_set()
            elif isinstance(self._input_widget, ttk.Combobox):
                self._input_widget.focus_set()
            elif hasattr(self, "_text_widget"):
                self._text_widget.focus_set()
            elif hasattr(self, "_date_entry"):
                self._date_entry.focus_set()

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные поля.

        Security:
            Очищает значение поля, внутренние ссылки и содержимое
            виджетов ввода. Вызывается перед закрытием формы
            с конфиденциальными данными.
        """
        self._value = None
        self._error_message = None
        self._error_tooltip = None

        if self._input_widget is not None:
            if isinstance(self._input_widget, tk.Entry):
                self._input_widget.delete(0, tk.END)
            elif isinstance(self._input_widget, tk.Text):
                self._input_widget.delete("1.0", tk.END)
            elif isinstance(self._input_widget, ttk.Combobox):
                self._input_widget.set("")

        self.clear_error()

    def _update_validation_state(self, is_valid: bool, errors: list[str]) -> None:
        """Обновляет состояние валидации.

        Args:
            is_valid: Флаг валидности.
            errors: Список ошибок.
        """
        self._is_valid = is_valid
        error_msg = errors[0] if errors else None
        self.set_error(error_msg)

    def _highlight_error(self, has_error: bool) -> None:
        """Подсвечивает поле ввода при ошибке.

        Args:
            has_error: True для подсветки ошибки, False для сброса.
        """
        theme = self._theme_manager.get_current_theme()

        if isinstance(self._input_widget, tk.Entry):
            if has_error:
                self._input_widget.config(
                    highlightcolor=theme.error_color,
                    highlightbackground=theme.error_color,
                    highlightthickness=2,
                )
            else:
                self._input_widget.config(
                    highlightcolor=theme.border_color,
                    highlightbackground=theme.border_color,
                    highlightthickness=1,
                )

    def _on_error_hover(self, event: tk.Event) -> None:
        """Обработчик наведения на индикатор ошибки.

        Args:
            event: Событие наведения.
        """
        if self._error_tooltip:
            self._show_tooltip(event, self._error_tooltip)

    def _show_tooltip(self, event: tk.Event, text: str) -> None:
        """Показывает tooltip с текстом.

        Args:
            event: Событие вызвавшее показ.
            text: Текст tooltip.
        """
        if self._tooltip_window is not None:
            self._tooltip_window.destroy()

        self._tooltip_window = tk.Toplevel(self)
        self._tooltip_window.wm_overrideredirect(True)
        self._tooltip_window.wm_geometry(f"+{event.x_root + 10}+{event.y_root + 10}")

        label = tk.Label(
            self._tooltip_window,
            text=text,
            background="#ffffcc",
            foreground="black",
            relief=tk.SOLID,
            borderwidth=1,
            font=("TkDefaultFont", 9),
            padx=5,
            pady=2,
        )
        label.pack()

    def _hide_tooltip(self, event: Optional[tk.Event] = None) -> None:
        """Скрывает tooltip.

        Args:
            event: Событие вызвавшее скрытие (опционально).
        """
        if self._tooltip_window is not None:
            self._tooltip_window.destroy()
            self._tooltip_window = None

    def _show_tooltip_for_event(self, text: str, event: tk.Event) -> None:
        """Показывает tooltip с текстом через partial callback.

        Args:
            text: Текст tooltip.
            event: Событие вызвавшее показ.
        """
        self._show_tooltip(event, text)

    def _on_input_change(self, field_id: str, value: Any) -> None:
        """Callback при изменении значения внутреннего виджета.

        Args:
            field_id: Идентификатор поля.
            value: Новое значение.
        """
        self._value = value
        if self._on_change:
            self._on_change(field_id, value)

    def _on_input_validate(self, field_id: str, is_valid: bool, error: Optional[str]) -> None:
        """Callback при валидации внутреннего виджета.

        Args:
            field_id: Идентификатор поля.
            is_valid: Флаг валидности.
            error: Сообщение об ошибке.
        """
        self._is_valid = is_valid
        self.set_error(error)

    # Event handlers for different input types
    def _on_entry_change(self, event: tk.Event) -> None:
        """Обработчик изменения текста в Entry."""
        if isinstance(self._input_widget, tk.Entry):
            value = self._input_widget.get()
            if value != self._field_def.placeholder:
                self._value = value
                if self._on_change:
                    self._on_change(self._field_def.field_id, value)

    def _on_entry_focus_out(self, event: tk.Event) -> None:
        """Обработчик потери фокуса Entry."""
        self.validate()

    def _on_placeholder_focus_in(self, event: tk.Event) -> None:
        """Обработчик получения фокуса для placeholder."""
        if isinstance(self._input_widget, tk.Entry):
            if self._input_widget.get() == self._field_def.placeholder:
                self._input_widget.delete(0, tk.END)
                theme = self._theme_manager.get_current_theme()
                self._input_widget.config(fg=theme.fg_color)

    def _on_placeholder_focus_out(self, event: tk.Event) -> None:
        """Обработчик потери фокуса для placeholder."""
        if isinstance(self._input_widget, tk.Entry):
            if not self._input_widget.get():
                self._input_widget.insert(0, self._field_def.placeholder or "")
                self._input_widget.config(fg="gray")

    def _validate_max_length(self, new_value: str) -> bool:
        """Валидатор максимальной длины.

        Args:
            new_value: Новое значение поля.

        Returns:
            True если длина допустима.
        """
        if self._field_def.max_length is None:
            return True
        return len(new_value) <= self._field_def.max_length

    def _validate_number_input(self, new_value: str) -> bool:
        """Валидатор числового ввода.

        Args:
            new_value: Новое значение поля.

        Returns:
            True если значение допустимо для числа.
        """
        if new_value == "":
            return True
        # Allow digits, decimal point, minus sign
        pattern = r"^-?\d*\.?\d*$"
        return bool(re.match(pattern, new_value))

    def _on_number_change(self, event: tk.Event) -> None:
        """Обработчик изменения числового поля."""
        if isinstance(self._input_widget, tk.Entry):
            value = self._input_widget.get()
            if value:
                try:
                    self._value = Decimal(value)
                except InvalidOperation:
                    self._value = value
            else:
                self._value = None

            if self._on_change:
                self._on_change(self._field_def.field_id, self._value)

    def _on_number_focus_out(self, event: tk.Event) -> None:
        """Обработчик потери фокуса числового поля."""
        self.validate()

    def _on_date_focus_in(self, event: tk.Event) -> None:
        """Обработчик получения фокуса поля даты."""
        if hasattr(self, "_date_entry"):
            if self._date_entry.get() == "ДД.ММ.ГГГГ":
                self._date_entry.delete(0, tk.END)
                theme = self._theme_manager.get_current_theme()
                self._date_entry.config(fg=theme.fg_color)

    def _on_date_focus_out(self, event: tk.Event) -> None:
        """Обработчик потери фокуса поля даты."""
        if hasattr(self, "_date_entry"):
            value = self._date_entry.get()
            if not value:
                self._date_entry.insert(0, "ДД.ММ.ГГГГ")
                self._date_entry.config(fg="gray")
            else:
                parsed = self._parse_date(value)
                if parsed:
                    self._value = parsed
                    self._date_entry.delete(0, tk.END)
                    self._date_entry.insert(0, self._format_date(parsed))
            self.validate()

    def _on_date_change(self, event: tk.Event) -> None:
        """Обработчик изменения поля даты."""
        if hasattr(self, "_date_entry"):
            value = self._date_entry.get()
            if value != "ДД.ММ.ГГГГ":
                parsed = self._parse_date(value)
                if parsed:
                    self._value = parsed
                    if self._on_change:
                        self._on_change(self._field_def.field_id, parsed)

    def _format_date(self, d: date) -> str:
        """Форматирует дату в строку.

        Args:
            d: Дата для форматирования.

        Returns:
            Строка в формате ДД.ММ.ГГГГ.
        """
        return d.strftime("%d.%m.%Y")

    def _parse_date(self, text: str) -> Optional[date]:
        """Парсит дату из строки.

        Args:
            text: Текстовое значение.

        Returns:
            Объект date или None.
        """
        if not text or not text.strip() or text == "ДД.ММ.ГГГГ":
            return None

        formats = ["%d.%m.%Y", "%d-%m-%Y", "%Y-%m-%d", "%d/%m/%Y"]
        for fmt in formats:
            try:
                return datetime.strptime(text.strip(), fmt).date()
            except ValueError:
                continue
        return None

    def _show_calendar_dialog(self) -> None:
        """Показывает диалог выбора даты и обновляет поле при выборе."""
        # Lazy import для разрыва circular import components → dialogs → renderers → components
        from src.gui.dialogs.calendar_dialog import CalendarDialog

        current = self._value if isinstance(self._value, date) else None
        dialog = CalendarDialog(parent=self, initial_date=current)
        result = dialog.show()
        if result is not None:
            self.set_value(result)

    def _on_combobox_change(self, event: tk.Event) -> None:
        """Обработчик изменения Combobox."""
        if isinstance(self._input_widget, ttk.Combobox):
            self._value = self._input_widget.get()
            if self._on_change:
                self._on_change(self._field_def.field_id, self._value)
            self.validate()

    def _on_text_change(self, event: tk.Event) -> None:
        """Обработчик изменения многострочного текста."""
        if hasattr(self, "_text_widget"):
            self._value = self._text_widget.get("1.0", tk.END).strip()
            if self._on_change:
                self._on_change(self._field_def.field_id, self._value)

    def _on_text_focus_out(self, event: tk.Event) -> None:
        """Обработчик потери фокуса многострочного текста."""
        self.validate()


__all__ = ["FormField"]
