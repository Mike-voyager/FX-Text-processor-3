"""Панель инструментов FreeForm режима для FX Text Processor 3.

Модуль содержит FreeFormToolbar — панель инструментов для управления
форматированием текста в FreeForm режиме.

Classes:
    FreeFormToolbar: Панель инструментов с CPI selector, formatting buttons и font selector.

Example:
    >>> from src.gui.modes.free_form.toolbar import FreeFormToolbar
    >>> toolbar = FreeFormToolbar(widget_id="ff_toolbar")
    >>> toolbar.mount(parent_frame)
    >>> toolbar.set_cpi(12)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Any, Callable, Optional, Tuple, cast

from src.gui.components.base.widget import BaseWidget
from src.gui.components.primitive.button import ThemedButton
from src.gui.core.exceptions import LifecycleError
from src.gui.core.protocols import ControllerProtocol
from src.gui.themes import get_theme_manager
from src.model.enums import FontFamily


class FreeFormToolbar(BaseWidget):
    """Панель инструментов для FreeForm режима.

    Содержит элементы управления форматированием текста:
    - CPI selector (dropdown: 10, 12, 15, 17, 20)
    - Bold/Italic/Underline toggle buttons
    - Font family selector (Courier, Roman, etc.)
    - Subscript/Superscript buttons
    - Callbacks для controller

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        _theme_manager: Менеджер тем для стилизации.
        _on_cpi_change: Callback при изменении CPI.
        _on_format_toggle: Callback при изменении форматирования.
        _on_font_change: Callback при изменении шрифта.
        _buttons: Словарь кнопок форматирования.

    Example:
        >>> toolbar = FreeFormToolbar(
        ...     widget_id="ff_toolbar",
        ...     controller=controller,
        ...     on_cpi_change=lambda cpi: print(f"CPI: {cpi}"),
        ... )
        >>> toolbar.mount(parent_frame)
    """

    def __init__(
        self,
        widget_id: str,
        controller: Optional[ControllerProtocol] = None,
        on_cpi_change: Optional[Callable[[int], None]] = None,
        on_format_toggle: Optional[Callable[[str, bool], None]] = None,
        on_font_change: Optional[Callable[[FontFamily], None]] = None,
    ) -> None:
        """Инициализация FreeFormToolbar.

        Args:
            widget_id: Уникальный идентификатор виджета.
            controller: Опциональная ссылка на контроллер.
            on_cpi_change: Callback при изменении CPI (int -> None).
            on_format_toggle: Callback при переключении форматирования (str, bool -> None).
            on_font_change: Callback при изменении шрифта (FontFamily -> None).

        Example:
            >>> def on_cpi(cpi: int) -> None:
            ...     print(f"CPI changed to {cpi}")
            >>> toolbar = FreeFormToolbar(
            ...     widget_id="toolbar",
            ...     on_cpi_change=on_cpi,
            ... )
        """
        super().__init__(widget_id=widget_id, controller=controller)

        self._theme_manager = get_theme_manager()

        # Callbacks
        self._on_cpi_change: Optional[Callable[[int], None]] = on_cpi_change
        self._on_format_toggle: Optional[Callable[[str, bool], None]] = on_format_toggle
        self._on_font_change: Optional[Callable[[FontFamily], None]] = on_font_change

        # State
        self._current_cpi: int = 10
        self._active_formats: set[str] = set()
        self._current_font: FontFamily = FontFamily.DRAFT

        # Widgets
        self._tk_frame: Optional[tk.Frame] = None
        self._cpi_var: Optional[tk.StringVar] = None
        self._font_var: Optional[tk.StringVar] = None
        self._buttons: dict[str, ThemedButton] = {}

        # Dropdown widgets
        self._cpi_dropdown: Optional[tk.OptionMenu] = None
        self._font_dropdown: Optional[tk.OptionMenu] = None

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт горизонтальную панель инструментов.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Frame с элементами управления.
        """
        self._tk_frame = tk.Frame(parent, padx=5, pady=5)

        # CPI Selector
        self._create_cpi_selector(self._tk_frame)

        # Разделитель
        self._create_separator(self._tk_frame)

        # Formatting buttons (Bold, Italic, Underline)
        self._create_formatting_buttons(self._tk_frame)

        # Разделитель
        self._create_separator(self._tk_frame)

        # Font family selector
        self._create_font_selector(self._tk_frame)

        # Разделитель
        self._create_separator(self._tk_frame)

        # Subscript/Superscript buttons
        self._create_script_buttons(self._tk_frame)

        # Применяем тему
        self._theme_manager.apply_to_widget(self._tk_frame)

        return self._tk_frame

    def _create_cpi_selector(self, parent: tk.Frame) -> None:
        """Создаёт dropdown для выбора CPI.

        Args:
            parent: Родительский Frame.
        """
        # Метка CPI
        cpi_label = tk.Label(parent, text="CPI:", font=("Courier", 10))
        cpi_label.pack(side=tk.LEFT, padx=(0, 2))
        self._theme_manager.apply_to_widget(cpi_label)

        # Dropdown переменная
        self._cpi_var = tk.StringVar(value=str(self._current_cpi))

        # Значения CPI
        cpi_values = ["10", "12", "15", "17", "20"]

        # Dropdown
        self._cpi_dropdown = tk.OptionMenu(
            parent,
            self._cpi_var,
            *cpi_values,
        )
        # Привязываем обработчик изменения через trace
        self._cpi_var.trace_add("write", self._on_cpi_var_changed)
        self._cpi_dropdown.config(width=6, font=("Courier", 10))
        self._cpi_dropdown.pack(side=tk.LEFT, padx=(0, 10))
        self._theme_manager.apply_to_widget(self._cpi_dropdown)

    def _create_font_selector(self, parent: tk.Frame) -> None:
        """Создаёт dropdown для выбора шрифта.

        Args:
            parent: Родительский Frame.
        """
        # Метка Font
        font_label = tk.Label(parent, text="Font:", font=("Courier", 10))
        font_label.pack(side=tk.LEFT, padx=(0, 2))
        self._theme_manager.apply_to_widget(font_label)

        # Dropdown переменная
        self._font_var = tk.StringVar(value=self._current_font.value)

        # Значения шрифтов
        font_values = [font.value for font in FontFamily]

        # Dropdown
        self._font_dropdown = tk.OptionMenu(
            parent,
            self._font_var,
            *font_values,
        )
        # Привязываем обработчик изменения через trace
        self._font_var.trace_add("write", self._on_font_var_changed)
        self._font_dropdown.config(width=12, font=("Courier", 10))
        self._font_dropdown.pack(side=tk.LEFT, padx=(0, 10))
        self._theme_manager.apply_to_widget(self._font_dropdown)

    def _create_formatting_buttons(self, parent: tk.Frame) -> None:
        """Создаёт кнопки форматирования (Bold, Italic, Underline).

        Args:
            parent: Родительский Frame.
        """
        formatting_configs: list[Tuple[str, str, str]] = [
            ("bold", "B", "Ж"),
            ("italic", "I", "К"),
            ("underline", "U", "Ч"),
        ]

        for name, _label, label_ru in formatting_configs:
            is_active = name in self._active_formats
            bg_color = self._get_toggle_color(is_active)

            # Create button with explicit type annotation for lambda
            def make_command(n: str = name) -> Callable[[], None]:
                return lambda: self._on_format_button_click(n)

            button = tk.Button(
                parent,
                text=label_ru,
                command=make_command(),
                font=("Courier", 10, "bold"),
                width=3,
                relief=tk.SUNKEN if is_active else tk.RAISED,
                bg=bg_color,
            )
            button.pack(side=tk.LEFT, padx=1)
            self._theme_manager.apply_to_widget(button)

            # Сохраняем ссылку для обновления состояния
            self._buttons[name] = button  # type: ignore[assignment]

    def _create_script_buttons(self, parent: tk.Frame) -> None:
        """Создаёт кнопки subscript/superscript.

        Args:
            parent: Родительский Frame.
        """
        script_configs: list[Tuple[str, str]] = [
            ("subscript", "x₂"),
            ("superscript", "x²"),
        ]

        for name, label in script_configs:
            is_active = name in self._active_formats
            bg_color = self._get_toggle_color(is_active)

            # Create button with explicit type annotation for lambda
            def make_script_command(n: str = name) -> Callable[[], None]:
                return lambda: self._on_format_button_click(n)

            button = tk.Button(
                parent,
                text=label,
                command=make_script_command(),
                font=("Courier", 10),
                width=3,
                relief=tk.SUNKEN if is_active else tk.RAISED,
                bg=bg_color,
            )
            button.pack(side=tk.LEFT, padx=1)
            self._theme_manager.apply_to_widget(button)

            self._buttons[name] = button  # type: ignore[assignment]

    def _create_separator(self, parent: tk.Frame) -> None:
        """Создаёт разделитель между группами элементов.

        Args:
            parent: Родительский Frame.
        """
        separator = tk.Frame(parent, width=2, bg="#666666", relief=tk.SUNKEN)
        separator.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=2)

    def _get_toggle_color(self, is_active: bool) -> str:
        """Возвращает цвет кнопки в зависимости от состояния.

        Args:
            is_active: Активно ли состояние.

        Returns:
            Hex цвет.
        """
        theme = self._theme_manager.get_current_theme()
        if is_active:
            return theme.accent_color
        return theme.bg_color

    def _update_toggle_button(self, name: str) -> None:
        """Обновляет визуальное состояние toggle-кнопки.

        Args:
            name: Имя кнопки ("bold", "italic", etc.).
        """
        if name not in self._buttons:
            return

        button = cast(tk.Button, self._buttons[name])
        is_active = name in self._active_formats

        bg_color = self._get_toggle_color(is_active)
        button.configure(
            relief=tk.SUNKEN if is_active else tk.RAISED,
            bg=bg_color,
        )

    # ==========================================================================
    # EVENT HANDLERS
    # ==========================================================================

    def _on_cpi_var_changed(self, *args: Any) -> None:
        """Обрабатывает изменение CPI через trace.

        Args:
            args: Аргументы от trace_add (игнорируются).
        """
        if self._cpi_var is None:
            return

        value = self._cpi_var.get()
        self._on_cpi_selected(value)

    def _on_cpi_selected(self, value: str) -> None:
        """Обрабатывает выбор CPI из dropdown.

        Args:
            value: Выбранное значение CPI как строка.
        """
        try:
            cpi = int(value)
            self._current_cpi = cpi

            # Callback
            if self._on_cpi_change is not None:
                self._on_cpi_change(cpi)

            # Dispatch через controller если есть
            if self._controller is not None:
                self._controller.dispatch(
                    "freeform_cpi_changed",
                    cpi=cpi,
                )
        except ValueError:
            pass  # Игнорируем невалидные значения

    def _on_font_var_changed(self, *args: Any) -> None:
        """Обрабатывает изменение шрифта через trace.

        Args:
            args: Аргументы от trace_add (игнорируются).
        """
        if self._font_var is None:
            return

        value = self._font_var.get()
        self._on_font_selected(value)

    def _on_font_selected(self, value: str) -> None:
        """Обрабатывает выбор шрифта из dropdown.

        Args:
            value: Выбранное значение шрифта.
        """
        font_family = FontFamily.from_string(value)
        if font_family is not None:
            self._current_font = font_family

            # Callback
            if self._on_font_change is not None:
                self._on_font_change(font_family)

            # Dispatch через controller если есть
            if self._controller is not None:
                self._controller.dispatch(
                    "freeform_font_changed",
                    font=font_family,
                )

    def _on_format_button_click(self, format_name: str) -> None:
        """Обрабатывает нажатие кнопки форматирования.

        Args:
            format_name: Имя форматирования ("bold", "italic", "underline", etc.).
        """
        # Toggle состояние
        if format_name in self._active_formats:
            self._active_formats.remove(format_name)
            is_active = False
        else:
            self._active_formats.add(format_name)
            is_active = True

        # Обновляем визуально
        self._update_toggle_button(format_name)

        # Callback
        if self._on_format_toggle is not None:
            self._on_format_toggle(format_name, is_active)

        # Dispatch через controller если есть
        if self._controller is not None:
            self._controller.dispatch(
                "freeform_format_toggled",
                format=format_name,
                active=is_active,
            )

    # ==========================================================================
    # PUBLIC API
    # ==========================================================================

    def set_cpi(self, cpi: int) -> None:
        """Устанавливает значение CPI в селекторе.

        Args:
            cpi: Новое значение CPI (10, 12, 15, 17, 20).

        Raises:
            LifecycleError: Если виджет не смонтирован.
            ValueError: Если CPI недопустимо.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="set_cpi",
                message="Widget not mounted",
            )

        if cpi not in {10, 12, 15, 17, 20}:
            raise ValueError(f"Invalid CPI: {cpi}. Valid: 10, 12, 15, 17, 20")

        self._current_cpi = cpi
        if self._cpi_var is not None:
            self._cpi_var.set(str(cpi))

    def get_cpi(self) -> int:
        """Возвращает текущее значение CPI.

        Returns:
            Текущее значение CPI.
        """
        return self._current_cpi

    def set_font(self, font: FontFamily) -> None:
        """Устанавливает шрифт в селекторе.

        Args:
            font: Новое значение шрифта.

        Raises:
            LifecycleError: Если виджет не смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="set_font",
                message="Widget not mounted",
            )

        self._current_font = font
        if self._font_var is not None:
            self._font_var.set(font.value)

    def get_font(self) -> FontFamily:
        """Возвращает текущий шрифт.

        Returns:
            Текущий шрифт.
        """
        return self._current_font

    def toggle_format(self, format_name: str, active: Optional[bool] = None) -> bool:
        """Переключает состояние форматирования.

        Args:
            format_name: Имя форматирования ("bold", "italic", "underline",
                "subscript", "superscript").
            active: Явно установить состояние (True/False) или toggle (None).

        Returns:
            Новое состояние форматирования.

        Raises:
            LifecycleError: Если виджет не смонтирован.
            ValueError: Если имя форматирования невалидно.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="toggle_format",
                message="Widget not mounted",
            )

        valid_formats = {"bold", "italic", "underline", "subscript", "superscript"}
        if format_name not in valid_formats:
            raise ValueError(f"Invalid format: {format_name}. Valid: {valid_formats}")

        if active is None:
            # Toggle
            if format_name in self._active_formats:
                self._active_formats.remove(format_name)
                is_active = False
            else:
                self._active_formats.add(format_name)
                is_active = True
        else:
            # Явное установление
            if active:
                self._active_formats.add(format_name)
                is_active = True
            else:
                self._active_formats.discard(format_name)
                is_active = False

        # Обновляем UI
        self._update_toggle_button(format_name)

        return is_active

    def get_active_formats(self) -> set[str]:
        """Возвращает активные форматы.

        Returns:
            Множество активных форматов ("bold", "italic", etc.).
        """
        return self._active_formats.copy()

    def clear_active_formats(self) -> None:
        """Очищает все активные форматы.

        Raises:
            LifecycleError: Если виджет не смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="clear_active_formats",
                message="Widget not mounted",
            )

        # Сохраняем копию для обновления UI
        formats_to_clear = self._active_formats.copy()
        self._active_formats.clear()

        # Обновляем UI для каждого
        for fmt in formats_to_clear:
            self._update_toggle_button(fmt)

    def set_enabled(self, enabled: bool) -> None:
        """Включает/отключает все элементы управления.

        Args:
            enabled: True для включения, False для отключения.

        Raises:
            LifecycleError: Если виджет не смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="set_enabled",
                message="Widget not mounted",
            )

        # Dropdowns - используем Any для обхода строгой типизации
        if self._cpi_dropdown is not None:
            self._cpi_dropdown.configure(**{"state": "normal" if enabled else "disabled"})
        if self._font_dropdown is not None:
            self._font_dropdown.configure(**{"state": "normal" if enabled else "disabled"})

        # Buttons
        for button in self._buttons.values():
            cast(tk.Button, button).configure(**{"state": "normal" if enabled else "disabled"})

    def set_on_cpi_change(self, callback: Callable[[int], None]) -> None:
        """Устанавливает callback для изменения CPI.

        Args:
            callback: Функция, вызываемая при изменении CPI.
        """
        self._on_cpi_change = callback

    def set_on_format_toggle(self, callback: Callable[[str, bool], None]) -> None:
        """Устанавливает callback для переключения форматирования.

        Args:
            callback: Функция, вызываемая при переключении формата.
        """
        self._on_format_toggle = callback

    def set_on_font_change(self, callback: Callable[[FontFamily], None]) -> None:
        """Устанавливает callback для изменения шрифта.

        Args:
            callback: Функция, вызываемая при изменении шрифта.
        """
        self._on_font_change = callback

    # ==========================================================================
    # LIFECYCLE
    # ==========================================================================

    def _cleanup(self) -> None:
        """Очищает ресурсы при демонтировании."""
        self._on_cpi_change = None
        self._on_format_toggle = None
        self._on_font_change = None
        self._buttons.clear()
        self._active_formats.clear()
        self._cpi_dropdown = None
        self._font_dropdown = None
        self._cpi_var = None
        self._font_var = None
        self._tk_frame = None


__all__ = ["FreeFormToolbar"]
