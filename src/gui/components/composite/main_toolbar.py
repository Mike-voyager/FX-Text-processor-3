"""Главная панель инструментов.

Содержит основные кнопки: New, Open, Save, Print.

Example:
    >>> from src.gui.components.composite.main_toolbar import MainToolbar
    >>> toolbar = MainToolbar(
    ...     widget_id="main_toolbar",
    ...     controller=controller
    ... )
    >>> toolbar.mount(parent_frame)
    >>> toolbar.set_button_enabled("save", False)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Callable, Optional

from src.gui.components.base.widget import BaseWidget
from src.gui.components.primitive.button import ThemedButton
from src.gui.core.protocols import ControllerProtocol
from src.gui.themes import get_theme_manager


class MainToolbar(BaseWidget):
    """Главная панель инструментов.

    Содержит основные кнопки: New, Open, Save, Print с поддержкой
    тем оформления и горячих клавиш.

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        _controller: Ссылка на контроллер для callbacks.
        _button_commands: Словарь пользовательских callback'ов.
        _buttons: Словарь созданных кнопок.
        _theme_manager: Менеджер тем для стилизации.

    Example:
        >>> toolbar = MainToolbar(widget_id="toolbar", controller=ctrl)
        >>> toolbar.mount(parent_frame)
        >>> toolbar.set_button_enabled("print", False)
        >>> print_button = toolbar.get_button("print")
    """

    def __init__(
        self,
        widget_id: str,
        controller: Optional[ControllerProtocol] = None,
        button_commands: Optional[dict[str, Callable[[], None]]] = None,
    ) -> None:
        """Инициализация главной панели инструментов.

        Args:
            widget_id: Уникальный идентификатор виджета.
            controller: Опциональная ссылка на контроллер для callbacks.
            button_commands: Опциональный словарь {button_name: callback}.
                Если не передан, использует controller.dispatch().

        Raises:
            ValueError: Если widget_id пустой или None.
            TypeError: Если button_commands не словарь.

        Example:
            >>> toolbar = MainToolbar(widget_id="toolbar", controller=ctrl)
            >>> toolbar = MainToolbar(
            ...     widget_id="toolbar",
            ...     button_commands={"new": custom_new_handler}
            ... )
        """
        super().__init__(widget_id=widget_id, controller=controller)

        if button_commands is not None and not isinstance(button_commands, dict):
            raise TypeError("button_commands must be a dict or None")

        self._button_commands: Optional[dict[str, Callable[[], None]]] = button_commands
        self._buttons: dict[str, ThemedButton] = {}
        self._theme_manager = get_theme_manager()

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт горизонтальный Frame с кнопками.

        Создаёт горизонтальный Frame и добавляет 4 кнопки:
        New (📝), Open (📂), Save (💾), Print (🖨️).
        Применяет тему ко всем кнопкам через ThemeManager.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Tkinter Frame.

        Example:
            >>> frame = toolbar._create_tk_widget(parent)
            >>> frame.pack()
        """
        # Создаём главный Frame
        frame = tk.Frame(parent, padx=5, pady=5)

        # Определяем конфигурацию кнопок
        button_configs: list[tuple[str, str, str, str]] = [
            ("new", "📝 New", "file_new", "Ctrl+N"),
            ("open", "📂 Open", "file_open", "Ctrl+O"),
            ("save", "💾 Save", "file_save", "Ctrl+S"),
            ("print", "🖨️ Print", "file_print", "Ctrl+P"),
        ]

        # Создаём кнопки
        for idx, (name, text, action, _) in enumerate(button_configs):
            # Разделитель между группами (кроме первой кнопки)
            if idx > 0:
                separator = tk.Frame(frame, width=10)
                separator.pack(side=tk.LEFT, fill=tk.Y, padx=2)
                self._theme_manager.apply_to_widget(separator)

            # Получаем callback для кнопки
            command = self._get_button_command(action)

            # Создаём кнопку через ThemedButton
            button = ThemedButton(
                widget_id=f"{self._widget_id}_btn_{name}",
                text=text,
                command=command,
                controller=self._controller,
            )

            # Монтируем кнопку во Frame
            button_widget = button.mount(frame)
            button_widget.pack(side=tk.LEFT, padx=2)

            # Применяем тему к кнопке
            self._theme_manager.apply_to_widget(button_widget)

            # Сохраняем ссылку на кнопку
            self._buttons[name] = button

        # Применяем тему к фрейму
        self._theme_manager.apply_to_widget(frame)

        return frame

    def _get_button_command(self, action: str) -> Callable[[], None]:
        """Возвращает callback для указанного действия.

        Проверяет пользовательские команды, затем использует
        controller.dispatch().

        Args:
            action: Идентификатор действия (например, "file_new").

        Returns:
            Callback функцию для вызова при нажатии.

        Example:
            >>> command = toolbar._get_button_command("file_new")
            >>> command()  # Вызовет dispatch("file_new")
        """
        # Проверяем пользовательские команды
        action_map: dict[str, str] = {
            "file_new": "new",
            "file_open": "open",
            "file_save": "save",
            "file_print": "print",
        }

        button_name = action_map.get(action, action)

        if self._button_commands and button_name in self._button_commands:
            return self._button_commands[button_name]

        # Используем controller.dispatch()
        def dispatch_action() -> None:
            """Вызывает controller.dispatch() с нужным action."""
            if self._controller is not None:
                self._controller.dispatch(action)

        return dispatch_action

    def _setup_bindings(self) -> None:
        """Настраивает горячие клавиши для панели инструментов.

        Настраивает следующие комбинации:
        - Ctrl+N -> New
        - Ctrl+O -> Open
        - Ctrl+S -> Save
        - Ctrl+P -> Print
        """
        if self._tk_widget is None:
            return

        # Получаем родительское окно для биндинга
        root = self._tk_widget.winfo_toplevel()

        # Настраиваем горячие клавиши
        bindings: list[tuple[str, str]] = [
            ("<Control-n>", "file_new"),
            ("<Control-o>", "file_open"),
            ("<Control-s>", "file_save"),
            ("<Control-p>", "file_print"),
        ]

        for key, action in bindings:
            command = self._get_button_command(action)

            def on_key(e: tk.Event, cmd: Callable[[], None] = command) -> None:
                self._on_keypress(e, cmd)

            root.bind(key, on_key)

    def _on_keypress(self, event: tk.Event, command: Callable[[], None]) -> None:  # noqa: ARG002
        """Обработчик нажатия клавиши.

        Args:
            event: Событие нажатия клавиши (не используется).
            command: Callback для выполнения.
        """
        command()

    def set_button_enabled(self, button: str, enabled: bool) -> None:
        """Включает или отключает кнопку.

        Args:
            button: Имя кнопки ("new" | "open" | "save" | "print").
            enabled: True для включения, False для отключения.

        Raises:
            ValueError: Если кнопка с указанным именем не найдена.

        Example:
            >>> toolbar.set_button_enabled("save", False)
            >>> toolbar.set_button_enabled("print", True)
        """
        if button not in self._buttons:
            raise ValueError(f"Button '{button}' not found")

        self._buttons[button].set_enabled(enabled)

    def get_button(self, button: str) -> Optional[ThemedButton]:
        """Возвращает кнопку по имени.

        Args:
            button: Имя кнопки ("new" | "open" | "save" | "print").

        Returns:
            ThemedButton или None если кнопка не найдена.

        Example:
            >>> new_btn = toolbar.get_button("new")
            >>> if new_btn:
            ...     print(new_btn.get_text())
        """
        return self._buttons.get(button)

    def _cleanup(self) -> None:
        """Очищает ресурсы при демонтировании.

        Отвязывает горячие клавиши и очищает ссылки на кнопки.
        """
        if self._tk_widget is not None:
            # Отвязываем горячие клавиши от корневого окна
            root = self._tk_widget.winfo_toplevel()
            for key in ["<Control-n>", "<Control-o>", "<Control-s>", "<Control-p>"]:
                root.unbind(key)

        # Очищаем ссылки на кнопки
        self._buttons.clear()


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = ["MainToolbar"]
