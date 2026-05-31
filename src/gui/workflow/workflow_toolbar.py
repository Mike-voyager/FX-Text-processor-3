"""WorkflowToolbar -- панель кнопок для workflow операций с динамической видимостью.

Предоставляет:
- BaseWidget с кнопками для workflow действий
- Динамическое управление видимостью через set_available_actions
- Hover-эффекты с изменением цвета
- Универсальный callback для всех действий

Example:
    >>> from src.documents.constructor.form_status import FormStatus
    >>> toolbar = WorkflowToolbar(widget_id="workflow_toolbar")
    >>> toolbar.mount(parent_frame)
    >>> toolbar.on_action(lambda action: print(f"Action: {action}"))
    >>> toolbar.set_available_actions({"save_draft", "validate"})
    >>> toolbar.set_current_state(FormStatus.DRAFT)

Version: 1.1
Date: May 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from typing import TYPE_CHECKING, Callable, Final, Optional

from src.gui.components.base.widget import BaseWidget
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
    except (KeyError, AttributeError, ValueError) as e:
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
        Осветлённый HEX цвет. При невалидном формате возвращает исходный цвет.
    """
    # BUG-37: Валидация формата — #RRGGBB (длина 7).
    if not hex_color.startswith("#") or len(hex_color) != 7:
        return hex_color

    stripped = hex_color.lstrip("#")
    try:
        r = int(stripped[0:2], 16)
        g = int(stripped[2:4], 16)
        b = int(stripped[4:6], 16)
    except ValueError:
        return hex_color

    r = min(255, int(r * factor))
    g = min(255, int(g * factor))
    b = min(255, int(b * factor))

    return f"#{r:02x}{g:02x}{b:02x}"


class WorkflowToolbar(BaseWidget):
    """Панель кнопок workflow с динамической видимостью.

    Создаёт набор кнопок для workflow операций. По умолчанию все кнопки скрыты.
    Видимость управляется через ``set_available_actions``, которая показывает
    только указанные кнопки, а остальные скрывает.

    Наследует от :class:`BaseWidget` для поддержки lifecycle (mount/unmount/_cleanup).

    Attributes:
        _buttons: Словарь action_name → tk.Button.
        _action_callback: Универсальный callback при нажатии.
        _current_state: Текущее состояние формы (опционально).
        _visible_actions: Множество видимых действий.

    Example:
        >>> toolbar = WorkflowToolbar(widget_id="workflow_toolbar")
        >>> frame = toolbar.mount(parent)
        >>> toolbar.on_action(lambda a: print(a))
        >>> toolbar.set_available_actions({"save_draft", "validate"})
    """

    @property
    def widget(self) -> tk.Widget:
        """Возвращает tkinter widget для размещения.

        Returns:
            Корневой Frame панели.

        Raises:
            RuntimeError: Если виджет не смонтирован.
        """
        if self._main_frame is None:
            raise RuntimeError("WorkflowToolbar not mounted")
        return self._main_frame

    def __init__(self, widget_id: str = "workflow_toolbar") -> None:
        """Инициализация панели workflow.

        Args:
            widget_id: Уникальный идентификатор виджета.
        """
        super().__init__(widget_id=widget_id, controller=None)

        self._buttons: dict[str, tk.Button] = {}
        self._action_callback: Optional[Callable[[str], None]] = None
        self._current_state: Optional["FormStatus"] = None
        self._button_colors: dict[str, str] = {}
        self._main_frame: Optional[tk.Frame] = None
        # BUG-27: Отдельный атрибут для видимых действий вместо winfo_manager().
        self._visible_actions: set[str] = set()

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Tkinter виджет панели с кнопками.

        Args:
            parent: Родительский виджет.

        Returns:
            Созданный фрейм с кнопками.
        """
        self._main_frame = tk.Frame(parent)

        for action, config in _BUTTON_CONFIG.items():
            color = _theme_color(config["theme_key"])
            button = tk.Button(
                self._main_frame,
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

        return self._main_frame

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
        self._visible_actions = set()
        for button in self._buttons.values():
            button.pack_forget()

    def set_available_actions(self, actions: set[str]) -> None:
        """Показывает только указанные кнопки, остальные скрывает.

        Args:
            actions: Множество имён действий, которые должны быть видимы.

        Example:
            >>> toolbar.set_available_actions({"save_draft", "validate"})
        """
        self._visible_actions = actions.copy()
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
        return action in self._visible_actions and action in self._buttons

    def _cleanup(self) -> None:
        """Очищает ресурсы перед демонтированием."""
        self._action_callback = None
        self._visible_actions = set()
        super()._cleanup()


__all__: list[str] = [
    "WorkflowToolbar",
    "_BUTTON_CONFIG",
    "_lighten_color",
]
