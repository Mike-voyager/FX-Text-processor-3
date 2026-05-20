"""Виджет текстового ввода (Entry) для FX Text Processor 3.

Модуль предоставляет ThemedEntry - тематизированное поле ввода текста
с поддержкой placeholder, валидации, режимом редактирования и интеграцией
с Controller через SmartBaseWidget.

Classes:
    ThemedEntry: Тематизированное поле ввода текста с локальным состоянием.

Example:
    >>> entry = ThemedEntry(
    ...     widget_id="username_field",
    ...     placeholder="Введите имя пользователя",
    ...     controller=my_controller
    ... )
    >>> entry.mount(parent_frame)
    >>> entry.set_text("admin")
    >>> entry.validate()
    True

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Callable, Optional, cast

from src.gui.components.base.widget import SmartBaseWidget
from src.gui.core.protocols import ControllerProtocol
from src.gui.themes import get_theme_manager


class ThemedEntry(SmartBaseWidget):
    """Тематизированное поле ввода текста с локальным состоянием.

    Расширяет SmartBaseWidget, добавляя функциональность поля ввода:
    - Placeholder текст (подсказка при пустом поле)
    - Валидация через callback функцию
    - Отображение ошибок (красная рамка)
    - Режим редактирования с синхронизацией через controller

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        controller: Ссылка на контроллер для callbacks.
        is_editing: Флаг режима редактирования.
        _placeholder: Текст подсказки placeholder.
        _show: Символ для скрытия ввода (например, '*' для пароля).
        _validator: Функция валидации значения.
        _has_error: Флаг состояния ошибки валидации.

    Example:
        >>> def validate_email(text: str) -> bool:
        ...     return "@" in text
        >>> entry = ThemedEntry(
        ...     widget_id="email",
        ...     placeholder="user@example.com",
        ...     validator=validate_email,
        ...     controller=ctrl
        ... )
        >>> entry.mount(parent)
        >>> entry.set_text("invalid")
        >>> entry.validate()  # False, покажет ошибку
        False
    """

    def __init__(
        self,
        widget_id: str,
        placeholder: str = "",
        show: str = "",
        validator: Optional[Callable[[str], bool]] = None,
        controller: Optional[ControllerProtocol] = None,
    ) -> None:
        """Инициализация поля ввода.

        Args:
            widget_id: Уникальный идентификатор виджета.
            placeholder: Текст подсказки при пустом поле.
            show: Символ для маскировки ввода (пустая строка = без маски).
            validator: Опциональная функция валидации текста.
            controller: Ссылка на контроллер для callbacks.

        Raises:
            ValueError: Если widget_id пустой.
        """
        super().__init__(widget_id=widget_id, controller=controller)
        self._placeholder: str = placeholder
        self._show: str = show
        self._validator: Optional[Callable[[str], bool]] = validator
        self._has_error: bool = False
        self._placeholder_shown: bool = False

    def set_placeholder(self, text: str) -> None:
        """Устанавливает текст placeholder.

        Args:
            text: Новый текст подсказки.

        Example:
            >>> entry.set_placeholder("Введите пароль")
        """
        self._placeholder = text
        if self._tk_widget is not None and not self._is_editing:
            self._update_placeholder_display()

    def get_text(self) -> str:
        """Возвращает текущий текст поля ввода.

        Returns:
            Текущее значение поля (без placeholder).

        Example:
            >>> entry.set_text("Hello")
            >>> entry.get_text()
            'Hello'
        """
        if self._tk_widget is None:
            return ""
        entry_widget = cast(tk.Entry, self._tk_widget)
        text = entry_widget.get()
        # Не возвращаем placeholder как реальное значение
        if self._placeholder_shown and text == self._placeholder:
            return ""
        return text

    def set_text(self, text: str) -> None:
        """Устанавливает текст в поле ввода.

        Args:
            text: Новый текст для установки.

        Example:
            >>> entry.set_text("New value")
        """
        if self._tk_widget is None:
            return

        # Очищаем ошибку при установке нового значения
        self.clear_error()

        entry_widget = cast(tk.Entry, self._tk_widget)
        entry_widget.delete(0, tk.END)
        if text:
            entry_widget.insert(0, text)
            self._placeholder_shown = False
        else:
            self._update_placeholder_display()

    def validate(self) -> bool:
        """Проверяет валидность текста через validator.

        Если validator не установлен, считается что текст всегда валиден.
        При ошибке валидации автоматически вызывается show_error().

        Returns:
            True если текст валиден или validator не установлен,
            False если валидация не прошла.

        Example:
            >>> def validator(text: str) -> bool:
            ...     return len(text) >= 3
            >>> entry = ThemedEntry(widget_id="test", validator=validator)
            >>> entry.set_text("ab")
            >>> entry.validate()
            False  # Показывает ошибку
        """
        if self._validator is None:
            return True

        text = self.get_text()
        is_valid = self._validator(text)

        if not is_valid:
            self.show_error("Невалидное значение")
        else:
            self.clear_error()

        return is_valid

    def show_error(self, message: str) -> None:
        """Показывает состояние ошибки (красная рамка).

        Args:
            message: Сообщение об ошибке (для отладки/logging).

        Example:
            >>> entry.show_error("Обязательное поле")
        """
        self._has_error = True
        if self._tk_widget is not None:
            theme_manager = get_theme_manager()
            theme = theme_manager.get_current_theme()
            entry_widget = cast(tk.Entry, self._tk_widget)
            entry_widget.configure(
                highlightcolor=theme.error_color,
                highlightbackground=theme.error_color,
                highlightthickness=2,
            )

    def clear_error(self) -> None:
        """Убирает состояние ошибки (возвращает нормальную рамку).

        Example:
            >>> entry.clear_error()
        """
        self._has_error = False
        if self._tk_widget is not None:
            theme_manager = get_theme_manager()
            theme = theme_manager.get_current_theme()
            entry_widget = cast(tk.Entry, self._tk_widget)
            entry_widget.configure(
                highlightcolor=theme.border_color,
                highlightbackground=theme.border_color,
                highlightthickness=1,
            )

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Tkinter Entry виджет.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный tk.Entry виджет.
        """
        entry = tk.Entry(
            parent,
            show=self._show,
            highlightthickness=1,
        )

        # Применяем тему
        theme_manager = get_theme_manager()
        theme_manager.apply_to_widget(entry)

        return entry

    def _setup_bindings(self) -> None:
        """Настраивает event bindings для Entry.

        Настраивает:
        - FocusIn: вход в режим редактирования, скрытие placeholder
        - FocusOut: выход из режима редактирования, показ placeholder если пусто

        Также отображает placeholder при первичном монтировании,
        если поле пустое и placeholder задан.
        """
        if self._tk_widget is None:
            return

        self._tk_widget.bind("<FocusIn>", self._on_focus_in)
        self._tk_widget.bind("<FocusOut>", self._on_focus_out)

        # Показываем placeholder при первичном монтировании,
        # если поле пустое и placeholder задан
        if self._placeholder and not self._show:
            self._update_placeholder_display()

    def _on_focus_in(self, event: Optional[tk.Event] = None) -> None:
        """Обработчик получения фокуса.

        Args:
            event: Событие Tkinter (опционально).
        """
        self.enter_edit_mode()
        # Скрываем placeholder если он показан
        if self._placeholder_shown and self._tk_widget is not None:
            entry_widget = cast(tk.Entry, self._tk_widget)
            entry_widget.delete(0, tk.END)
            self._placeholder_shown = False

    def _on_focus_out(self, event: Optional[tk.Event] = None) -> None:
        """Обработчик потери фокуса.

        Args:
            event: Событие Tkinter (опционально).
        """
        self.exit_edit_mode()

    def _update_placeholder_display(self) -> None:
        """Обновляет отображение placeholder текста."""
        if self._tk_widget is None or not self._placeholder:
            return

        theme_manager = get_theme_manager()
        theme = theme_manager.get_current_theme()

        entry_widget = cast(tk.Entry, self._tk_widget)
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, self._placeholder)
        entry_widget.configure(fg=theme.border_color)
        self._placeholder_shown = True

    def enter_edit_mode(self) -> None:
        """Входит в режим редактирования.

        Вызывает родительский метод, затем восстанавливает цвет текста.

        Raises:
            LifecycleError: Если виджет не смонтирован.
        """
        super().enter_edit_mode()

        # Восстанавливаем цвет текста при входе в редактирование
        if self._tk_widget is not None:
            theme_manager = get_theme_manager()
            theme = theme_manager.get_current_theme()
            entry_widget = cast(tk.Entry, self._tk_widget)
            entry_widget.configure(fg=theme.fg_color)

    def exit_edit_mode(self) -> None:
        """Выходит из режима редактирования.

        Вызывает родительский метод (который синхронизирует с моделью
        при наличии изменений), затем показывает placeholder если поле пустое.

        Raises:
            LifecycleError: Если виджет не смонтирован.
        """
        super().exit_edit_mode()

        # Показываем placeholder если поле пустое
        if self._tk_widget is not None:
            entry_widget = cast(tk.Entry, self._tk_widget)
            current_text = entry_widget.get()
            if not current_text:
                self._update_placeholder_display()

    def sync_to_model(self) -> bool:
        """Синхронизирует локальное состояние с моделью.

        Отправляет событие изменения через controller.dispatch().

        Returns:
            True если синхронизация выполнена (значение изменилось),
            False если изменений не было.
        """
        text = self.get_edit_value()
        if text == self._initial_value:
            return False

        if self._controller is not None:
            self._controller.dispatch("entry_changed", value=text, widget_id=self._widget_id)

        self._initial_value = text
        return True

    def get_edit_value(self) -> str:
        """Возвращает текущее значение в режиме редактирования.

        Returns:
            Текущее значение поля ввода (без placeholder).
        """
        return self.get_text()

    def set_edit_value(self, value: str) -> None:
        """Устанавливает значение в режиме редактирования.

        Args:
            value: Новое значение для поля.
        """
        self.set_text(value)

    # has_changes() наследуется от SmartBaseWidget —
    # логика идентична: сравнение get_edit_value() с _initial_value

    def _cleanup(self) -> None:
        """Очищает ресурсы при демонтировании.

        Отвязывает FocusIn/FocusOut обработчики от Tkinter виджета.
        """
        if self._tk_widget is not None:
            self._tk_widget.unbind("<FocusIn>")
            self._tk_widget.unbind("<FocusOut>")


__all__: list[str] = ["ThemedEntry"]
