"""Toolbar Section - compound widget для группировки кнопок.

Модуль предоставляет ToolbarSection — составной виджет для группировки
кнопок с заголовком, поддержкой тем, разделителей и сворачиваемых секций.

Features:
- Иконки + текст для кнопок
- Separator lines
- Theme support через ThemeManager
- Collapsible sections
- Группировка кнопок по смыслу

Example:
    >>> from src.gui.components.toolbar_section import ToolbarSection
    >>> section = ToolbarSection(
    ...     widget_id="file_section",
    ...     title="Файл",
    ...     controller=controller,
    ... )
    >>> section.add_button("open", "📂", "Открыть", open_handler)
    >>> section.add_separator()
    >>> section.add_button("save", "💾", "Сохранить", save_handler)
    >>> section.mount(parent_frame)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Callable, Dict, List, Optional, Tuple, cast

from src.gui.components.base.widget import BaseWidget
from src.gui.core.exceptions import LifecycleError
from src.gui.core.protocols import ControllerProtocol
from src.gui.themes import ThemeManager, get_theme_manager


class ToolbarSection(BaseWidget):
    """Compound widget для группировки кнопок с заголовком.

    Реализует секцию тулбара с:
    - Заголовком секции
    - Кнопками с иконками и текстом
    - Горизонтальными разделителями
    - Возможностью сворачивания/разворачивания
    - Поддержкой тем через ThemeManager

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        title: Заголовок секции (пустая строка если нет).
        _controller: Ссылка на контроллер для callbacks.
        _buttons: Словарь кнопок {name: (tk.Button, icon, text, command)}.
        _separators: Список разделителей.
        _is_collapsed: Флаг свёрнутого состояния.
        _theme_manager: Менеджер тем для стилизации.
        _header_frame: Фрейм заголовка.
        _content_frame: Фрейм содержимого (кнопок).
        _title_label: Label с заголовком.
        _collapse_btn: Кнопка сворачивания/разворачивания.

    Example:
        >>> section = ToolbarSection(
        ...     widget_id="edit_section",
        ...     title="Редактирование",
        ... )
        >>> section.add_button("cut", "✂️", "Вырезать", cut_handler)
        >>> section.add_button("copy", "📋", "Копировать", copy_handler)
        >>> section.add_separator()
        >>> section.add_button("paste", "📌", "Вставить", paste_handler)
        >>> section.set_collapsed(True)  # Сворачиваем
    """

    # Символы для сворачивания/разворачивания
    _COLLAPSE_ICON: str = "▼"
    _EXPAND_ICON: str = "▶"

    def __init__(
        self,
        widget_id: str,
        title: str = "",
        controller: Optional[ControllerProtocol] = None,
        collapsible: bool = False,
    ) -> None:
        """Инициализация секции тулбара.

        Args:
            widget_id: Уникальный идентификатор виджета.
            title: Заголовок секции (пустая строка если нет).
            controller: Опциональная ссылка на контроллер.
            collapsible: Разрешить сворачивание секции.

        Raises:
            ValueError: Если widget_id пустой.

        Example:
            >>> section = ToolbarSection(
            ...     widget_id="file_section",
            ...     title="Файл",
            ... )
        """
        super().__init__(widget_id=widget_id, controller=controller)

        self._title: str = title
        self._collapsible: bool = collapsible and bool(title)  # Требуется заголовок
        self._is_collapsed: bool = False

        # Хранение кнопок: {name: (tk.Button, icon, text, command)}
        self._buttons: Dict[str, Tuple[Optional[tk.Widget], str, str, Callable[[], None]]] = {}
        self._separators: List[Optional[tk.Widget]] = []

        # Theme manager
        self._theme_manager: ThemeManager = get_theme_manager()

        # Внутренние виджеты (инициализируются при mount)
        self._header_frame: Optional[tk.Widget] = None
        self._content_frame: Optional[tk.Widget] = None
        self._title_label: Optional[tk.Widget] = None
        self._collapse_btn: Optional[tk.Widget] = None

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Frame с заголовком и содержимым секции.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Frame виджет.

        Example:
            >>> frame = section._create_tk_widget(parent)
            >>> frame.pack(fill=tk.X)
        """
        # Главный Frame
        main_frame = tk.Frame(parent, padx=2, pady=2)
        self._theme_manager.apply_to_widget(main_frame)

        # Создаём заголовок если есть
        if self._title:
            self._header_frame = self._create_header(main_frame)
            self._header_frame.pack(fill=tk.X, padx=2, pady=(0, 2))

        # Frame для кнопок
        self._content_frame = tk.Frame(main_frame, padx=2, pady=2)
        self._content_frame.pack(fill=tk.X, expand=True)
        self._theme_manager.apply_to_widget(self._content_frame)

        # Применяем тему к главному фрейму
        self._theme_manager.apply_to_widget(main_frame)

        return main_frame

    def _create_header(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Frame с заголовком и кнопкой сворачивания.

        Args:
            parent: Родительский виджет.

        Returns:
            Frame с заголовком.
        """
        header = tk.Frame(parent, padx=2, pady=2)
        self._theme_manager.apply_to_widget(header)

        # Кнопка сворачивания (если разрешено)
        if self._collapsible:
            collapse_text = self._EXPAND_ICON if self._is_collapsed else self._COLLAPSE_ICON
            self._collapse_btn = tk.Button(
                header,
                text=collapse_text,
                command=self._toggle_collapse,
                font=("Courier", 8),
                width=2,
                relief=tk.FLAT,
                bd=0,
            )
            self._collapse_btn.pack(side=tk.LEFT, padx=(0, 4))
            self._theme_manager.apply_to_widget(self._collapse_btn)

        # Label с заголовком
        self._title_label = tk.Label(
            header,
            text=self._title,
            font=("Courier", 10, "bold"),
            anchor=tk.W,
        )
        self._title_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._theme_manager.apply_to_widget(self._title_label)

        # Separator под заголовком
        separator = tk.Frame(header, height=1, relief=tk.SUNKEN, bd=1)
        separator.pack(fill=tk.X, side=tk.BOTTOM, pady=(2, 0))

        return header

    def add_button(
        self,
        name: str,
        icon: str,
        text: str,
        command: Callable[[], None],
    ) -> None:
        """Добавляет кнопку в секцию.

        Args:
            name: Уникальное имя кнопки в секции.
            icon: Иконка кнопки (emoji или символ).
            text: Текст кнопки.
            command: Callback при нажатии.

        Raises:
            ValueError: Если кнопка с таким именем уже существует.
            TypeError: Если command не callable.

        Example:
            >>> section.add_button(
            ...     name="save",
            ...     icon="💾",
            ...     text="Сохранить",
            ...     command=lambda: print("Save clicked"),
            ... )
        """
        if name in self._buttons:
            raise ValueError(f"Кнопка '{name}' уже существует в секции '{self._widget_id}'")

        if not callable(command):
            raise TypeError("command должен быть callable")

        button_widget: Optional[tk.Widget] = None

        # Если уже смонтирован — создаём виджет сразу
        if self._is_mounted and self._content_frame is not None:
            button_widget = self._create_button_widget(
                self._content_frame,
                icon,
                text,
                command,
            )
            button_widget.pack(fill=tk.X, padx=2, pady=1)

        # Сохраняем кнопку
        self._buttons[name] = (button_widget, icon, text, command)

    def _create_button_widget(
        self,
        parent: tk.Widget,
        icon: str,
        text: str,
        command: Callable[[], None],
    ) -> tk.Widget:
        """Создаёт виджет кнопки.

        Args:
            parent: Родительский виджет.
            icon: Иконка кнопки.
            text: Текст кнопки.
            command: Callback.

        Returns:
            Созданный виджет кнопки.
        """
        # Формируем текст: "Иконка Текст"
        button_text = f"{icon} {text}"

        button = tk.Button(
            parent,
            text=button_text,
            command=command,
            font=("Courier", 9),
            anchor=tk.W,
            padx=8,
            pady=3,
            relief=tk.RAISED,
            bd=2,
            cursor="hand2",
        )

        # Применяем тему
        self._theme_manager.apply_to_widget(button)

        return button

    def add_separator(self) -> None:
        """Добавляет горизонтальный разделитель.

        Добавляет тонкую линию между группами кнопок.

        Example:
            >>> section.add_button("open", "📂", "Открыть", open_handler)
            >>> section.add_separator()
            >>> section.add_button("save", "💾", "Сохранить", save_handler)
        """
        separator_widget: Optional[tk.Widget] = None

        # Если уже смонтирован — создаём виджет сразу
        if self._is_mounted and self._content_frame is not None:
            separator_widget = self._create_separator_widget(self._content_frame)
            separator_widget.pack(fill=tk.X, padx=4, pady=4)

        self._separators.append(separator_widget)

    def _create_separator_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт виджет разделителя.

        Args:
            parent: Родительский виджет.

        Returns:
            Frame для использования как разделитель.
        """
        separator = tk.Frame(parent, height=2, relief=tk.SUNKEN, bd=1)
        self._theme_manager.apply_to_widget(separator)
        return separator

    def set_collapsed(self, collapsed: bool) -> None:
        """Устанавливает состояние свёрнутости секции.

        Args:
            collapsed: True для сворачивания, False для разворачивания.

        Raises:
            LifecycleError: Если секция не смонтирована.

        Example:
            >>> section.set_collapsed(True)   # Свернуть
            >>> section.set_collapsed(False)  # Развернуть
        """
        if not self._collapsible:
            return  # Игнорируем если не разрешено сворачивание

        if not self._is_mounted:
            # Просто сохраняем состояние для применения при монтировании
            self._is_collapsed = collapsed
            return

        if self._content_frame is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="set_collapsed",
                message="Content frame не инициализирован",
            )

        self._is_collapsed = collapsed

        # Показываем или скрываем содержимое
        if collapsed:
            self._content_frame.pack_forget()
        else:
            self._content_frame.pack(fill=tk.X, expand=True)

        # Обновляем иконку кнопки сворачивания
        if self._collapse_btn is not None:
            icon = self._EXPAND_ICON if collapsed else self._COLLAPSE_ICON
            cast(tk.Button, self._collapse_btn).configure(text=icon)

    def _toggle_collapse(self) -> None:
        """Переключает состояние свёрнутости."""
        self.set_collapsed(not self._is_collapsed)

    def is_collapsed(self) -> bool:
        """Проверяет, свёрнута ли секция.

        Returns:
            True если секция свёрнута.
        """
        return self._is_collapsed

    def set_button_enabled(self, name: str, enabled: bool) -> None:
        """Включает или отключает кнопку.

        Args:
            name: Имя кнопки.
            enabled: True для включения, False для отключения.

        Raises:
            ValueError: Если кнопка не найдена.

        Example:
            >>> section.set_button_enabled("save", False)
            >>> section.set_button_enabled("save", True)
        """
        if name not in self._buttons:
            raise ValueError(f"Кнопка '{name}' не найдена")

        button = self._buttons[name][0]
        if button is not None and self._is_mounted:
            cast(tk.Button, button).configure(state="normal" if enabled else "disabled")

    def set_button_text(self, name: str, text: str) -> None:
        """Изменяет текст кнопки.

        Args:
            name: Имя кнопки.
            text: Новый текст.

        Raises:
            ValueError: Если кнопка не найдена.

        Example:
            >>> section.set_button_text("save", "Сохранить *")
        """
        if name not in self._buttons:
            raise ValueError(f"Кнопка '{name}' не найдена")

        icon = self._buttons[name][1]
        self._buttons[name][2]
        command = self._buttons[name][3]
        button = self._buttons[name][0]

        # Обновляем текст в хранилище
        self._buttons[name] = (button, icon, text, command)

        if button is not None and self._is_mounted:
            cast(tk.Button, button).configure(text=f"{icon} {text}")

    def get_button_count(self) -> int:
        """Возвращает количество кнопок в секции.

        Returns:
            Количество кнопок.

        Example:
            >>> count = section.get_button_count()
            >>> print(f"Buttons: {count}")
        """
        return len(self._buttons)

    def remove_button(self, name: str) -> None:
        """Удаляет кнопку из секции.

        Args:
            name: Имя кнопки для удаления.

        Raises:
            ValueError: Если кнопка не найдена.

        Example:
            >>> section.remove_button("temp_button")
        """
        if name not in self._buttons:
            raise ValueError(f"Кнопка '{name}' не найдена")

        button = self._buttons[name][0]
        if button is not None and self._is_mounted:
            button.destroy()

        del self._buttons[name]

    def clear(self) -> None:
        """Удаляет все кнопки и разделители.

        Example:
            >>> section.clear()
        """
        # Удаляем виджеты кнопок
        for _name, (button, _, _, _) in list(self._buttons.items()):
            if button is not None and self._is_mounted:
                button.destroy()

        # Удаляем виджеты разделителей
        for separator in self._separators:
            if separator is not None and self._is_mounted:
                separator.destroy()

        # Очищаем списки
        self._buttons.clear()
        self._separators.clear()

    def _setup_bindings(self) -> None:
        """Настраивает event bindings для секции.

        Вызывается после создания виджета.
        """
        # Базовая реализация — нет специфичных bindings
        pass

    def _cleanup(self) -> None:
        """Очищает ресурсы при демонтировании.

        Уничтожает все кнопки и разделители.
        """
        self.clear()

        # Очищаем ссылки на внутренние виджеты
        self._header_frame = None
        self._content_frame = None
        self._title_label = None
        self._collapse_btn = None


class ToolbarButtonGroup(BaseWidget):
    """Группа кнопок в тулбаре (без заголовка, просто горизонтальная группа).

    Альтернатива ToolbarSection для создания горизонтальных
    групп кнопок без заголовка.

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        _buttons: Словарь кнопок.
        _theme_manager: Менеджер тем.

    Example:
        >>> group = ToolbarButtonGroup(widget_id="main_actions")
        >>> group.add_button("new", "📝", new_handler)
        >>> group.add_separator()
        >>> group.add_button("open", "📂", open_handler)
    """

    def __init__(
        self,
        widget_id: str,
        controller: Optional[ControllerProtocol] = None,
    ) -> None:
        """Инициализация группы кнопок.

        Args:
            widget_id: Уникальный идентификатор.
            controller: Опциональная ссылка на контроллер.
        """
        super().__init__(widget_id=widget_id, controller=controller)

        self._buttons: Dict[str, Tuple[Optional[tk.Button], str, str, Callable[[], None]]] = {}
        self._separators: List[Optional[tk.Frame]] = []
        self._theme_manager: ThemeManager = get_theme_manager()

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Frame для группы кнопок.

        Args:
            parent: Родительский виджет.

        Returns:
            Созданный Frame.
        """
        frame = tk.Frame(parent, padx=2, pady=2)
        self._theme_manager.apply_to_widget(frame)
        return frame

    def add_button(
        self,
        name: str,
        icon: str,
        command: Callable[[], None],
        text: str = "",
    ) -> None:
        """Добавляет кнопку в группу.

        Args:
            name: Уникальное имя кнопки.
            icon: Иконка кнопки.
            command: Callback при нажатии.
            text: Опциональный текст (если пустой — только иконка).

        Raises:
            ValueError: Если кнопка уже существует.
            TypeError: Если command не callable.
        """
        if name in self._buttons:
            raise ValueError(f"Кнопка '{name}' уже существует")

        if not callable(command):
            raise TypeError("command должен быть callable")

        button_text = f"{icon} {text}" if text else icon
        button_widget: Optional[tk.Button] = None

        if self._is_mounted and self._tk_widget is not None:
            button_widget = tk.Button(
                self._tk_widget,
                text=button_text,
                command=command,
                font=("Courier", 9),
                padx=6,
                pady=2,
                relief=tk.RAISED,
                bd=2,
                cursor="hand2",
            )
            button_widget.pack(side=tk.LEFT, padx=2)
            self._theme_manager.apply_to_widget(button_widget)

        self._buttons[name] = (button_widget, icon, text, command)

    def add_separator(self) -> None:
        """Добавляет вертикальный разделитель между кнопками."""
        separator_widget: Optional[tk.Frame] = None

        if self._is_mounted and self._tk_widget is not None:
            separator_widget = tk.Frame(
                self._tk_widget,
                width=2,
                relief=tk.SUNKEN,
                bd=1,
            )
            separator_widget.pack(side=tk.LEFT, fill=tk.Y, padx=4, pady=2)
            self._theme_manager.apply_to_widget(separator_widget)

        self._separators.append(separator_widget)

    def set_button_enabled(self, name: str, enabled: bool) -> None:
        """Включает или отключает кнопку.

        Args:
            name: Имя кнопки.
            enabled: True для включения.

        Raises:
            ValueError: Если кнопка не найдена.
        """
        if name not in self._buttons:
            raise ValueError(f"Кнопка '{name}' не найдена")

        button = self._buttons[name][0]
        if button is not None and self._is_mounted:
            button.configure(state="normal" if enabled else "disabled")

    def _cleanup(self) -> None:
        """Очищает ресурсы."""
        for _name, (button, _, _, _) in list(self._buttons.items()):
            if button is not None and self._is_mounted:
                button.destroy()

        for separator in self._separators:
            if separator is not None and self._is_mounted:
                separator.destroy()

        self._buttons.clear()
        self._separators.clear()


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "ToolbarSection",
    "ToolbarButtonGroup",
]
