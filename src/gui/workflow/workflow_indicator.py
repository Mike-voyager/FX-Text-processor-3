"""WorkflowIndicator — индикатор workflow в статусбаре.

Предоставляет:
- Цветную точку с текущим статусом документа
- Клик для открытия Timeline диалога
- Интеграция со статусами FormStatus
- Simple Mode: упрощённый workflow (DRAFT ↔ SIGNED)

Цвета статусов:
    DRAFT — серый (#95a5a6)
    FILLED — синий (#3498db)
    VALIDATED — оранжевый (#f39c12)
    SIGNED — зелёный (#27ae60)
    ARCHIVED — тёмно-синий (#2c3e50)
    REJECTED — красный (#e74c3c)

Example:
    >>> from src.documents.constructor.form_status import FormStatus
    >>> indicator = WorkflowIndicator(
    ...     parent=frame,
    ...     current_status=FormStatus.DRAFT,
    ...     on_click=lambda: open_timeline(),
    ... )
    >>> indicator.set_status(FormStatus.FILLED)
    >>> indicator.set_simple_mode(True)  # Упрощённый режим

Version: 1.1
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import TYPE_CHECKING, Callable, Final, Optional

from src.gui.components.base.widget import BaseWidget

if TYPE_CHECKING:
    from src.documents.constructor.form_status import FormStatus


# Цвета для статусов (соответствуют form_status.py)
STATUS_COLORS: Final[dict[str, str]] = {
    "draft": "#95a5a6",  # Gray
    "filled": "#3498db",  # Blue
    "validated": "#f39c12",  # Orange
    "approved": "#27ae60",  # Green (same as signed)
    "signed": "#27ae60",  # Green
    "printed": "#9b59b6",  # Purple
    "archived": "#2c3e50",  # Dark blue
    "rejected": "#e74c3c",  # Red
}

# Локализованные названия статусов
STATUS_NAMES: Final[dict[str, str]] = {
    "draft": "Черновик",
    "filled": "Заполнена",
    "validated": "Проверена",
    "approved": "Утверждена",
    "signed": "Подписана",
    "printed": "Напечатана",
    "archived": "Архивирована",
    "rejected": "Отклонена",
}

# Размер точки индикатора
DOT_SIZE: Final[int] = 12

# Цвет фона по умолчанию
DEFAULT_BG: Final[str] = "#f0f0f0"

# Статусы для Simple Mode (упрощённый workflow)
SIMPLE_MODE_STATUSES: Final[list[str]] = ["draft", "signed"]

# Все статусы для Full Mode
FULL_MODE_STATUSES: Final[list[str]] = [
    "draft",
    "filled",
    "validated",
    "approved",
    "signed",
    "printed",
    "archived",
    "rejected",
]


class WorkflowIndicator(BaseWidget):
    """Индикатор workflow в статусбаре.

    Отображает цветную точку с текущим статусом документа.
    При клике открывает Timeline диалог.
    Поддерживает Simple Mode с упрощённым workflow (DRAFT ↔ SIGNED).

    Attributes:
        STATUS_COLORS: Цвета статусов.
        STATUS_NAMES: Локализованные названия статусов.
        SIMPLE_MODE_STATUSES: Статусы в Simple Mode.
        FULL_MODE_STATUSES: Все статусы в Full Mode.

    Example:
        >>> indicator = WorkflowIndicator(
        ...     parent=frame,
        ...     current_status=FormStatus.DRAFT,
        ...     on_click=lambda: print("Timeline opened"),
        ... )
        >>> indicator.set_status(FormStatus.FILLED)
        >>> indicator.set_simple_mode(True)  # Включить Simple Mode
    """

    @property
    def widget(self) -> tk.Widget:
        """Возвращает tkinter widget для размещения.

        Returns:
            Корневой Frame индикатора.

        Raises:
            RuntimeError: Если виджет не смонтирован.
        """
        if self._main_frame is None:
            raise RuntimeError("WorkflowIndicator не смонтирован")
        return self._main_frame

    def __init__(
        self,
        parent: tk.Widget,
        current_status: "FormStatus",
        on_click: Optional[Callable[[], None]] = None,
        simple_mode: bool = False,
    ) -> None:
        """Инициализация индикатора workflow.

        Args:
            parent: Родительский Tkinter виджет.
            current_status: Текущий статус документа.
            on_click: Callback при клике на индикатор (открывает Timeline).
            simple_mode: Если True, использовать упрощённый workflow.
        """
        super().__init__(widget_id="workflow_indicator", controller=None)

        self._parent: tk.Widget = parent
        self._current_status: str = current_status.value
        self._on_click: Optional[Callable[[], None]] = on_click
        self._simple_mode: bool = simple_mode

        # UI references
        self._main_frame: Optional[tk.Frame] = None
        self._dot_canvas: Optional[tk.Canvas] = None
        self._status_label: Optional[tk.Label] = None
        self._mode_label: Optional[tk.Label] = None

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Tkinter виджет индикатора.

        Args:
            parent: Родительский виджет.

        Returns:
            Созданный фрейм с индикатором.
        """
        self._main_frame = tk.Frame(parent, bg=DEFAULT_BG)

        # Container for dot + text (horizontal layout)
        content_frame = tk.Frame(self._main_frame, bg=DEFAULT_BG)
        content_frame.pack(side=tk.LEFT, fill=tk.Y)

        # Canvas для цветной точки
        self._dot_canvas = tk.Canvas(
            content_frame,
            width=DOT_SIZE,
            height=DOT_SIZE,
            highlightthickness=0,
            bg=DEFAULT_BG,
        )
        self._dot_canvas.pack(side=tk.LEFT, padx=(0, 5))

        # Рисуем точку
        self._draw_dot()

        # Label со статусом
        status_text = self._get_status_display_text()
        self._status_label = tk.Label(
            content_frame,
            text=status_text,
            bg=DEFAULT_BG,
            fg="#333333",
            font=("TkDefaultFont", 9),
        )
        self._status_label.pack(side=tk.LEFT)

        # Bind click events
        self._setup_click_bindings(content_frame)

        return self._main_frame

    def _draw_dot(self) -> None:
        """Рисует цветную точку на canvas."""
        if self._dot_canvas is None:
            return

        # Clear canvas
        self._dot_canvas.delete("all")

        # Get color for current status
        color = STATUS_COLORS.get(self._current_status, "#95a5a6")

        # Draw circle
        padding = 2
        self._dot_canvas.create_oval(
            padding,
            padding,
            DOT_SIZE - padding,
            DOT_SIZE - padding,
            fill=color,
            outline="",
            tags=("dot",),
        )

    def _get_status_display_text(self) -> str:
        """Возвращает текст для отображения статуса.

        Returns:
            Локализованное название статуса.
        """
        return STATUS_NAMES.get(self._current_status, self._current_status)

    def _setup_click_bindings(self, widget: tk.Widget) -> None:
        """Настраивает обработчики клика.

        Args:
            widget: Виджет для настройки bindings.
        """
        widget.bind("<Button-1>", self._on_click_handler)
        widget.bind("<Enter>", self._on_enter)
        widget.bind("<Leave>", self._on_leave)

        # Also bind to child widgets
        for child in widget.winfo_children():
            child.bind("<Button-1>", self._on_click_handler)
            child.bind("<Enter>", self._on_enter)
            child.bind("<Leave>", self._on_leave)

    def _on_click_handler(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает клик на индикатор.

        Args:
            event: Событие клика (опционально).
        """
        if self._on_click is not None:
            self._on_click()

    def _on_enter(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает наведение мыши.

        Args:
            event: Событие наведения (опционально).
        """
        if self._main_frame is not None:
            self._main_frame.config(cursor="hand2")

    def _on_leave(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает уход мыши.

        Args:
            event: Событие ухода (опционально).
        """
        if self._main_frame is not None:
            self._main_frame.config(cursor="")

    def set_status(self, status: "FormStatus") -> None:
        """Устанавливает текущий статус.

        Args:
            status: Новый статус документа.

        Example:
            >>> indicator.set_status(FormStatus.FILLED)
            >>> # Цвет и текст обновляются автоматически
        """
        self._current_status = status.value
        self._update_display()

    def _update_display(self) -> None:
        """Обновляет отображение индикатора."""
        self._draw_dot()

        if self._status_label is not None:
            self._status_label.config(text=self._get_status_display_text())

    def get_status(self) -> str:
        """Возвращает текущий статус.

        Returns:
            Текущий статус в виде строки.
        """
        return self._current_status

    def get_status_color(self) -> str:
        """Возвращает цвет текущего статуса.

        Returns:
            HEX цвет статуса.
        """
        return STATUS_COLORS.get(self._current_status, "#95a5a6")

    def _cleanup(self) -> None:
        """Очищает ресурсы перед демонтированием."""
        self._on_click = None
        super()._cleanup()

    def set_simple_mode(self, enabled: bool) -> None:
        """Включает или отключает Simple Mode.

        В Simple Mode показывается только упрощённый workflow (DRAFT ↔ SIGNED).
        При переключении статус адаптируется к доступным в новом режиме.

        Args:
            enabled: True для включения Simple Mode, False для Full Mode.

        Example:
            >>> indicator.set_simple_mode(True)  # Только DRAFT ↔ SIGNED
            >>> indicator.set_simple_mode(False)  # Все статусы
        """
        if self._simple_mode == enabled:
            return

        self._simple_mode = enabled

        # Если текущий статус не доступен в новом режиме,
        # находим ближайший доступный
        if not self._is_status_allowed(self._current_status):
            self._current_status = self._get_nearest_allowed_status()

        # Обновляем отображение
        self._update_display()

        # Обновляем метку режима если есть
        if self._mode_label is not None:
            mode_text = "Simple" if self._simple_mode else "Full"
            self._mode_label.config(text=f"Mode: {mode_text}")

    def is_simple_mode(self) -> bool:
        """Возвращает текущий режим отображения.

        Returns:
            True если включен Simple Mode, иначе False.
        """
        return self._simple_mode

    def get_available_statuses(self) -> list[str]:
        """Возвращает список доступных статусов в текущем режиме.

        Returns:
            Список строковых значений статусов.

        Example:
            >>> indicator.get_available_statuses()
            ['draft', 'signed']  # В Simple Mode
        """
        if self._simple_mode:
            return SIMPLE_MODE_STATUSES.copy()
        return FULL_MODE_STATUSES.copy()

    def _is_status_allowed(self, status: str) -> bool:
        """Проверяет, допустим ли статус в текущем режиме.

        Args:
            status: Статус для проверки.

        Returns:
            True если статус допустим.
        """
        allowed = SIMPLE_MODE_STATUSES if self._simple_mode else FULL_MODE_STATUSES
        return status in allowed

    def _get_nearest_allowed_status(self) -> str:
        """Возвращает ближайший допустимый статус.

        Используется при переключении режимов, когда текущий статус
        становится недоступным.

        Returns:
            Допустимый статус.
        """
        allowed = self.get_available_statuses()

        # Сопоставление статусов для перехода между режимами
        status_mapping: dict[str, str] = {
            "filled": "draft",
            "validated": "draft",
            "printed": "signed",
            "archived": "signed",
            "rejected": "draft",
        }

        # Если текущий статус доступен, оставляем его
        if self._current_status in allowed:
            return self._current_status

        # Иначе используем сопоставление
        mapped = status_mapping.get(self._current_status)
        if mapped is not None and mapped in allowed:
            return mapped

        # По умолчанию возвращаем draft
        return "draft"

    def can_transition_to(self, target_status: "FormStatus") -> bool:
        """Проверяет, возможен ли переход в целевой статус.

        В Simple Mode допустимы только переходы DRAFT ↔ SIGNED.
        В Full Mode используются стандартные правила переходов.

        Args:
            target_status: Целевой статус.

        Returns:
            True если переход допустим.
        """
        target = target_status.value

        # Проверяем, что целевой статус доступен в текущем режиме
        if not self._is_status_allowed(target):
            return False

        # В Simple Mode разрешаем только DRAFT ↔ SIGNED
        if self._simple_mode:
            return (self._current_status == "draft" and target == "signed") or (
                self._current_status == "signed" and target == "draft"
            )

        # В Full Mode всегда разрешаем (проверка переходов в FormStatusManager)
        return True


__all__: list[str] = [
    "WorkflowIndicator",
    "STATUS_COLORS",
    "STATUS_NAMES",
    "DOT_SIZE",
    "SIMPLE_MODE_STATUSES",
    "FULL_MODE_STATUSES",
]
