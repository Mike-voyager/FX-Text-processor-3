"""WorkflowToolbar — панель кнопок для workflow операций с динамической видимостью.

Предоставляет:
- tk.Frame с кнопками для workflow действий
- Динамическое управление видимостью через set_available_actions
- Hover-эффекты с изменением цвета
- Универсальный callback для всех действий

Example:
    >>> from src.documents.constructor.form_status import FormStatus
    >>> toolbar = WorkflowToolbar(parent=frame)
    >>> toolbar.on_action(lambda action: print(f"Action: {action}"))
    >>> toolbar.set_available_actions({"save_draft", "validate"})
    >>> toolbar.set_current_state(FormStatus.DRAFT)

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from typing import TYPE_CHECKING, Callable, Final, Optional

from src.gui.themes import ThemeRegistry

if TYPE_CHECKING:
    from src.documents.constructor.form_status import FormStatus


def _theme_color(key: str) -> str:
    """Возвращает цвет из текущей темы.

    Args:
        key: Идентификатор цвета.

    Returns:
        Color в формате HEX.
    """
    try:
        return ThemeRegistry.get_instance().get_current().get_color(key)
    except Exception as e:
        logging.getLogger(__name__).exception("Theme color retrieval failed for key %s: %s", key, e)
        return "#3498db"  # fallback color


# Данные кнопок: action_name → {отображаемый текст, ключ цвета в теме}
_BUTTON_CONFIG: Final[dict[str, dict[str, str]]] = {
    "fill_fields": {"text": "📝 Заполнить", "theme_key": "button_primary"},
    "save_draft": {"text": "💾 Сохранить", "theme_key": "button_primary"},
    "submit_for_validation": {"text": "📤 Отправить", "theme_key": "success"},
    "validate": {"text": "✅ Проверить", "theme_key": "success"},
    "approve": {"text": "👍 Согласовать", "theme_key": "success"},
    "sign": {"text": "✍️ Подписать", "theme_key": "error"},
    "reject": {"text": "❌ Отклонить", "theme_key": "warning"},
    "view_comments": {"text": "👁 Комментарии", "theme_key": "border"},
    "print": {"text": "🖨 Печать", "theme_key": "border"},
    "archive": {"text": "📦 Архив", "theme_key": "warning"},
    "switch_role": {"text": "🔀 Смена роли", "theme_key": "border"},
    "switch_to_editor": {"text": "🔀 Редактор", "theme_key": "border"},
    "switch_to_operator": {"text": "🔀 Оператор", "theme_key": "border"},
    "switch_to_supervisor": {"text": "🔀 Супервайзер", "theme_key": "border"},
    "switch_to_signatory": {"text": "🔀 Подписант", "theme_key": "border"},
}

# Коэффициент осветления для hover (10%)
_HOVER_LIGHTEN_FACTOR: Final[float] = 1.10

# Параметры отступов кнопок
_BUTTON_PADX: Final[int] = 10
_BUTTON_PADY: Final[int] = 4

# Color текста на кнопках
_BUTTON_FG: Final[str] = "white"


def _lighten_color(hex_color: str, factor: float = _HOVER_LIGHTEN_FACTOR) -> str:
    """Осветляет HEX-цвет на заданный коэффициент.

    Args:
        hex_color: HEX строка вида #RRGGBB.
        factor: Множитель для RGB компонент (1.0 = без изменений).

    Returns:
        Осветлённый HEX цвет.
    """
    hex_color = hex_color.lstrip("#")
    r = int(hex_color[0:2], 16)
    g = int(hex_color[2:4], 16)
    b = int(hex_color[4:6], 16)

    r = min(255, int(r * factor))
    g = min(255, int(g * factor))
    b = min(255, int(b * factor))

    return f"#{r:02x}{g:02x}{b:02x}"


class WorkflowToolbar(tk.Frame):
    """Панель кнопок workflow с динамической видимостью.

    Создаёт набор кнопок для workflow операций. По умолчанию все кнопки скрыты.
    Видимость управляется через ``set_available_actions``, которая показывает
    только указанные кнопки, а остальные скрывает.

    Attributes:
        _buttons: Словарь action_name → tk.Button.
        _action_callback: Универсальный callback при нажатии.
        _current_state: Текущее состояние формы (опционально).

    Example:
        >>> toolbar = WorkflowToolbar(parent=root)
        >>> toolbar.pack(fill=tk.X)
        >>> toolbar.on_action(lambda a: print(a))
        >>> toolbar.set_available_actions({"save_draft", "validate"})
    """

    def __init__(self, parent: tk.Widget) -> None:
        """Инициализация панели workflow.

        Args:
            parent: Родительский Tkinter виджет.
        """
        super().__init__(parent)

        self._buttons: dict[str, tk.Button] = {}
        self._action_callback: Optional[Callable[[str], None]] = None
        self._current_state: Optional["FormStatus"] = None
        self._button_colors: dict[str, str] = {}

        self._create_buttons()

    def _create_buttons(self) -> None:
        """Создаёт кнопки и скрывает их по умолчанию."""
        for action, config in _BUTTON_CONFIG.items():
            color = _theme_color(config["theme_key"])
            button = tk.Button(
                self,
                text=config["text"],
                bg=color,
                fg=_BUTTON_FG,
                relief=tk.FLAT,
                padx=_BUTTON_PADX,
                pady=_BUTTON_PADY,
                cursor="hand2",
                command=self._make_handler(action),
            )

            # Hover bindings
            hover_color = _lighten_color(color)

            def _on_enter(event: tk.Event, btn: tk.Button = button, hc: str = hover_color) -> None:  # noqa: ARG001
                btn.config(bg=hc)

            def _on_leave(event: tk.Event, btn: tk.Button = button, c: str = color) -> None:  # noqa: ARG001
                btn.config(bg=c)

            button.bind("<Enter>", _on_enter)
            button.bind("<Leave>", _on_leave)

            self._buttons[action] = button
            self._button_colors[action] = color

        # По умолчанию все скрыты
        self._hide_all_buttons()

    def _make_handler(self, action: str) -> Callable[[], None]:
        """Создаёт обработчик нажатия для указанного действия.

        Args:
            action: Имя действия.

        Returns:
            Функцию-обработчик без аргументов.
        """

        def _handler() -> None:
            if self._action_callback is not None:
                self._action_callback(action)

        return _handler

    def _hide_all_buttons(self) -> None:
        """Скрывает все кнопки через pack_forget."""
        for button in self._buttons.values():
            button.pack_forget()

    def set_available_actions(self, actions: set[str]) -> None:
        """Показывает только указанные кнопки, остальные скрывает.

        Args:
            actions: Множество имён действий, которые должны быть видимы.

        Example:
            >>> toolbar.set_available_actions({"save_draft", "validate"})
        """
        for action, button in self._buttons.items():
            if action in actions:
                button.pack(side=tk.LEFT, padx=2, pady=2)
            else:
                button.pack_forget()

    def set_current_state(self, state: "FormStatus") -> None:
        """Обновляет внутреннее состояние формы.

        Args:
            state: Новое состояние формы.
        """
        self._current_state = state

    def get_current_state(self) -> Optional["FormStatus"]:
        """Возвращает текущее состояние формы.

        Returns:
            Текущее состояние или None, если не установлено.
        """
        return self._current_state

    def on_action(self, callback: Callable[[str], None]) -> None:
        """Устанавливает универсальный callback для всех действий.

        Args:
            callback: Функция, вызываемая с action_name при нажатии кнопки.

        Example:
            >>> toolbar.on_action(lambda action: controller.handle_action(action))
        """
        self._action_callback = callback

    def get_button(self, action: str) -> Optional[tk.Button]:
        """Возвращает кнопку по имени действия.

        Args:
            action: Имя действия.

        Returns:
            Виджет кнопки или None, если действие неизвестно.
        """
        return self._buttons.get(action)

    def get_available_actions(self) -> set[str]:
        """Возвращает множество всех зарегистрированных действий.

        Returns:
            Множество имён действий.
        """
        return set(self._buttons.keys())

    def is_action_visible(self, action: str) -> bool:
        """Проверяет, видима ли кнопка действия.

        Args:
            action: Имя действия.

        Returns:
            True если кнопка видима, False если скрыта или неизвестна.
        """
        button = self._buttons.get(action)
        if button is None:
            return False
        return button.winfo_manager() == "pack"

    def destroy(self) -> None:
        """Очищает ресурсы перед уничтожением."""
        self._action_callback = None
        super().destroy()

    def unmount(self) -> None:
        """Совместимость с BaseWidget lifecycle.

        Вызывает destroy() для освобождения ресурсов Tkinter.
        """
        self.destroy()


__all__: list[str] = [
    "WorkflowToolbar",
    "_BUTTON_CONFIG",
    "_lighten_color",
]
