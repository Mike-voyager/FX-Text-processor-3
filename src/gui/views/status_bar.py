"""StatusBar для FX Text Processor 3.

Реализует адаптивный статусбар с индикаторами:
- Позиция курсора (Ln X, Col Y)
- CPI (characters per inch)
- Кодовая страница
- Формат бумаги
- Режим работы (Normal/Special)
- MFA статус
- ПреSET безопасности
- Workflow Timeline strip (только STRUCTURED_FORM)
- Role Badge (только STRUCTURED_FORM)
- Номер страницы
- Масштаб
- Индикатор уведомлений [n] с Toast Panel

Layout адаптируется автоматически:
- Single row при width >= 1024:
  Ln 12, Col 45 │ 12 CPI │ PC866 │ Tractor │ 🔒 Standard │ Page 2/5 │ 100% │ [3]
- Double row при width < 1024:
  Строка 1: Ln 12, Col 45 │ Page 2/5 │ 🔒 Standard │ [3]
  Строка 2: 12 CPI │ PC866 │ Tractor │ 100%

Workflow Timeline (UI_SPEC §7.5, только STRUCTURED_FORM):
[DRAFT ✓] ──▶ [FILLED ●] ──▶ [VALIDATED ○] ──▶ [APPROVED ○] ──▶ [SIGNED ○]

Example:
    >>> statusbar = StatusBar(parent_frame)
    >>> statusbar.set_cursor_position(10, 25)
    >>> statusbar.set_mode_indicator("normal")
    >>> statusbar.set_mfa_indicator("active", "FIDO2")
    >>> statusbar.set_security_preset("Standard")
    >>> statusbar.set_document_mode(DocumentMode.STRUCTURED_FORM)
    >>> statusbar.set_workflow_timeline(FormStatus.DRAFT)
    >>> statusbar.set_role_badge(WorkflowRole.OPERATOR)
    >>> statusbar.set_notification_count(3)
    >>> statusbar.show_toast_panel()

Version: 1.4
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import TYPE_CHECKING, Any, Callable, Final, Optional

from src.documents.types.document_type import DocumentMode
from src.gui.components.base.widget import BaseWidget
from src.gui.dialogs.paper_setup import PaperSetupDialog
from src.gui.layout.layout_constants import (
    MIN_WINDOW_WIDTH,
    PADDING_NORMAL,
    PADDING_SMALL,
    STATUSBAR_HEIGHT,
)
from src.gui.themes import ThemeRegistry
from src.gui.workflow.role_badge import RoleBadge, WorkflowRole
from src.gui.workflow.workflow_indicator import WorkflowIndicator

if TYPE_CHECKING:
    from src.documents.constructor.form_status import FormStatus
    from src.gui.services.notification_service import Notification, NotificationService


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_BG: Final[str] = "#f0f0f0"
DEFAULT_FG: Final[str] = "#333333"

# Separator (static, not theme-dependent)
SEPARATOR_CHAR: Final[str] = "│"
SEPARATOR_COLOR: Final[str] = "#888888"

# Security preset colors (name -> (bg, fg))
SECURITY_PRESET_COLORS: Final[dict[str, tuple[str, str]]] = {
    "Legacy": ("#ffcccc", "#cc0000"),
    "Standard": ("#ffffcc", "#cc9900"),
    "Paranoid": ("#ccffcc", "#006600"),
    "PQC": ("#e6ccff", "#6600cc"),
}

DEFAULT_SECURITY_COLOR: Final[tuple[str, str]] = ("#cccccc", "#333333")
MODIFIED_COLOR: Final[str] = "#ff8c00"

MODE_NORMAL_BG: Final[str] = "#ccffcc"
MODE_NORMAL_FG: Final[str] = "#006600"
MODE_SPECIAL_BG: Final[str] = "#ffcccc"
MODE_SPECIAL_FG: Final[str] = "#cc0000"

MFA_ACTIVE_BG: Final[str] = "#ccffcc"
MFA_ACTIVE_FG: Final[str] = "#006600"
MFA_REQUIRED_BG: Final[str] = "#ffffcc"
MFA_REQUIRED_FG: Final[str] = "#cc9900"
MFA_NONE_BG: Final[str] = "#cccccc"
MFA_NONE_FG: Final[str] = "#333333"

NOTIFICATION_ACTIVE_COLOR: Final[str] = "#ff8c00"
NOTIFICATION_INACTIVE_COLOR: Final[str] = "#999999"

# Workflow Timeline colors (static)
TIMELINE_COLORS: Final[dict[str, str]] = {
    "draft": "#95a5a6",
    "filled": "#3498db",
    "validated": "#f39c12",
    "approved": "#e67e22",
    "signed": "#27ae60",
}

TIMELINE_STATUSES: Final[list[str]] = [
    "draft",
    "filled",
    "validated",
    "approved",
    "signed",
]

TIMELINE_DONE_MARKER: Final[str] = "✓"
TIMELINE_CURRENT_MARKER: Final[str] = "●"
TIMELINE_FUTURE_MARKER: Final[str] = "○"
TIMELINE_ARROW: Final[str] = "──▶"

# Role badge colors (static, not theme-dependent)
ROLE_BADGE_COLORS: Final[dict[WorkflowRole, str]] = {
    WorkflowRole.OPERATOR: "#3498db",
    WorkflowRole.EDITOR: "#2ecc71",
    WorkflowRole.SUPERVISOR: "#f39c12",
    WorkflowRole.SIGNATORY: "#e74c3c",
}

ROLE_BADGE_ICONS: Final[dict[WorkflowRole, str]] = {
    WorkflowRole.OPERATOR: "🔵",
    WorkflowRole.EDITOR: "🟢",
    WorkflowRole.SUPERVISOR: "🟠",
    WorkflowRole.SIGNATORY: "🔴",
}

# Toast Panel settings
TOAST_PANEL_WIDTH: Final[int] = 280
TOAST_PANEL_MAX_ITEMS: Final[int] = 6  # Increased to match spec (up to 6 messages)
TOAST_PANEL_AUTO_HIDE_MS: Final[int] = 30000  # Increased to 30 seconds as per spec
TOAST_PANEL_BG: Final[str] = "#ffffff"
TOAST_PANEL_BORDER_COLOR: Final[str] = "#cccccc"
TOAST_PANEL_HEADER_BG: Final[str] = "#f5f5f5"


def _theme_color(key: str) -> str:
    """Возвращает цвет из текущей темы.

    Args:
        key: Идентификатор цвета.

    Returns:
        Цвет в формате HEX.
    """
    try:
        return ThemeRegistry.get_instance().get_current().get_color(key)
    except (AttributeError, KeyError, RuntimeError):
        return DEFAULT_BG if key == "bg" else DEFAULT_FG


class ToastPanel:
    """Панель уведомлений для отображения при hover.

    Показывает список последних уведомлений с иконками приоритета и временной меткой.
    Auto-hide через 30 секунд после mouse leave.

    Attributes:
        _parent: Родительское окно для позиционирования.
        _window: Toplevel окно панели.
        _items_frame: Frame для размещения уведомлений.
        _is_visible: Флаг видимости панели.

    Example:
        >>> panel = ToastPanel(parent_window)
        >>> panel.show_near_widget(notification_label)
        >>> panel.update_notifications(notification_list)
        >>> panel.hide()
    """

    _PRIORITY_ICONS: Final[dict[str, str]] = {
        "CRITICAL": "❌",
        "HIGH": "⚠️",
        "NORMAL": "✅",
        "LOW": "💾",
    }

    _CATEGORY_ICONS: Final[dict[str, str]] = {
        "security": "🔒",
        "workflow": "📝",
        "system": "⚙️",
        "sync": "🔄",
    }

    def __init__(self, parent: tk.Widget) -> None:
        """Инициализирует Toast Panel.

        Args:
            parent: Родительское окно для создания Toplevel.
        """
        self._parent: tk.Widget = parent
        self._window: Optional[tk.Toplevel] = None
        self._items_frame: Optional[tk.Frame] = None
        self._is_visible: bool = False
        self._notifications: list[Notification] = []
        self._on_pin_all: Optional[Callable[[], None]] = None
        self._on_clear: Optional[Callable[[], None]] = None

    def set_callbacks(
        self,
        on_pin_all: Optional[Callable[[], None]] = None,
        on_clear: Optional[Callable[[], None]] = None,
    ) -> None:
        """Устанавливает callback для действий панели.

        Args:
            on_pin_all: Callback при нажатии "📌" (отметить все прочитанными).
            on_clear: Callback при нажатии "🗑️" (очистить историю).
        """
        self._on_pin_all = on_pin_all
        self._on_clear = on_clear

    def show_near_widget(self, widget: tk.Widget) -> None:
        """Показывает панель рядом с указанным виджетом.

        Args:
            widget: Виджет, возле которого показывать панель.
        """
        if self._window is not None:
            self.hide()

        self._window = tk.Toplevel(self._parent)
        self._window.overrideredirect(True)
        self._window.attributes("-topmost", True)
        self._window.configure(bg=TOAST_PANEL_BORDER_COLOR)

        self._position_near(widget)
        self._create_ui()
        self._update_content()

        self._is_visible = True

    def _position_near(self, widget: tk.Widget) -> None:
        """Позиционирует панель возле виджета.

        Args:
            widget: Виджет-ориентир для позиционирования.
        """
        if self._window is None:
            return

        widget_x = widget.winfo_rootx()
        widget_y = widget.winfo_rooty()
        widget_height = widget.winfo_height()

        x = widget_x - TOAST_PANEL_WIDTH + widget.winfo_width()
        y = widget_y - 150

        if x < 0:
            x = 0
        if y < 0:
            y = widget_y + widget_height + 5

        self._window.geometry(f"{TOAST_PANEL_WIDTH}x150+{x}+{y}")

    def _create_ui(self) -> None:
        """Создаёт UI компоненты панели."""
        if self._window is None:
            return

        main_frame = tk.Frame(
            self._window,
            bg=TOAST_PANEL_BORDER_COLOR,
            bd=1,
        )
        main_frame.pack(fill="both", expand=True)

        header_frame = tk.Frame(
            main_frame,
            bg=_theme_color("bg"),
            padx=PADDING_SMALL,
            pady=PADDING_SMALL,
        )
        header_frame.pack(fill="x", side="top")

        count = len(self._notifications)
        header_text = f"Notifications [{count}]"
        header_label = tk.Label(
            header_frame,
            text=header_text,
            bg=_theme_color("bg"),
            fg="#333333",
            font=("TkDefaultFont", 10, "bold"),
        )
        header_label.pack(side="left")

        btn_frame = tk.Frame(header_frame, bg=_theme_color("bg"))
        btn_frame.pack(side="right")

        pin_all_btn = tk.Label(
            btn_frame,
            text="[📌 Pin all]",
            bg=_theme_color("bg"),
            fg="#333333",
            font=("TkDefaultFont", 9),
            cursor="hand2",
        )
        pin_all_btn.pack(side="left", padx=(0, PADDING_SMALL))
        pin_all_btn.bind("<Button-1>", lambda _: self._invoke_pin_all())

        clear_btn = tk.Label(
            btn_frame,
            text="[🗑️ Clear]",
            bg=_theme_color("bg"),
            fg="#333333",
            font=("TkDefaultFont", 9),
            cursor="hand2",
        )
        clear_btn.pack(side="left")
        clear_btn.bind("<Button-1>", lambda _: self._invoke_clear())

        separator = tk.Frame(main_frame, height=1, bg="#cccccc")
        separator.pack(fill="x", side="top")

        self._items_frame = tk.Frame(
            main_frame,
            bg=_theme_color("bg"),
            padx=PADDING_SMALL,
            pady=PADDING_SMALL,
        )
        self._items_frame.pack(fill="both", expand=True)

    def _update_content(self) -> None:
        """Обновляет содержимое панели уведомлениями."""
        if self._items_frame is None:
            return

        for widget in self._items_frame.winfo_children():
            widget.destroy()

        if not self._notifications:
            no_data_label = tk.Label(
                self._items_frame,
                text="Нет уведомлений",
                bg=_theme_color("bg"),
                fg="#999999",
                font=("TkDefaultFont", 9),
            )
            no_data_label.pack(pady=PADDING_NORMAL)
            return

        for notification in self._notifications[:TOAST_PANEL_MAX_ITEMS]:
            self._create_notification_row(notification)

    def _create_notification_row(self, notification: Notification) -> None:
        """Создаёт строку уведомления с иконкой приоритета и временной меткой.

        Args:
            notification: Данные уведомления.
        """
        if self._items_frame is None:
            return

        priority_name = notification.priority.name.lower()
        icon = self._PRIORITY_ICONS.get(priority_name, "💾")

        # Format timestamp
        import time

        timestamp = time.strftime("%H:%M", time.localtime(notification.created_at))

        row_frame = tk.Frame(
            self._items_frame,
            bg=_theme_color("bg"),
            padx=2,
            pady=2,
        )
        row_frame.pack(fill="x", side="top")

        icon_label = tk.Label(
            row_frame,
            text=icon,
            bg=_theme_color("bg"),
            fg="#333333",
            font=("TkDefaultFont", 10),
            width=2,
        )
        icon_label.pack(side="left")

        message_label = tk.Label(
            row_frame,
            text=notification.message,
            bg=_theme_color("bg"),
            fg="#333333",
            font=("TkDefaultFont", 9),
            anchor="w",
            justify="left",
            wraplength=TOAST_PANEL_WIDTH - 80,
        )
        message_label.pack(side="left", fill="x", expand=True)

        time_label = tk.Label(
            row_frame,
            text=timestamp,
            bg=_theme_color("bg"),
            fg="#999999",
            font=("TkDefaultFont", 8),
            width=6,
            anchor="e",
        )
        time_label.pack(side="right", padx=(2, 0))

    def update_notifications(self, notifications: list[Notification]) -> None:
        """Обновляет список уведомлений.

        Args:
            notifications: Список уведомлений для отображения.
        """
        self._notifications = notifications
        if self._is_visible:
            self._update_content()

    def _invoke_pin_all(self) -> None:
        """Вызывает callback 'Pin all' если установлен."""
        if self._on_pin_all is not None:
            self._on_pin_all()

    def _invoke_clear(self) -> None:
        """Вызывает callback 'Clear' если установлен."""
        if self._on_clear is not None:
            self._on_clear()

    def hide(self) -> None:
        """Скрывает панель."""
        if self._window is not None:
            self._window.destroy()
            self._window = None
        self._items_frame = None
        self._is_visible = False

    def is_visible(self) -> bool:
        """Проверяет видимость панели.

        Returns:
            True если панель видима.
        """
        return self._is_visible


class StatusBar(BaseWidget):
    """StatusBar с адаптивным layout и индикаторами состояния.

    Реализует StatusBarViewProtocol, предоставляя индикаторы для
    отображения состояния редактора документа.

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        controller: Ссылка на контроллер для callbacks.
        on_paper_double_click: Callback для double-click на индикаторе бумаги.
        on_mode_indicator_click: Callback для клика на индикаторе режима.
        on_workflow_click: Callback для клика на индикаторе workflow.

      Example:
          >>> def open_paper_dialog(parent_frame):
          ...     PaperSetupDialog(parent=parent_frame).show()
        >>> def switch_mode():
        ...     print("Switching mode...")
        >>> def open_timeline():
        ...     print("Timeline opened...")
        >>> statusbar = StatusBar(
        ...     parent_frame,
        ...     paper_callback=open_paper_dialog,
        ...     mode_callback=switch_mode,
        ...     workflow_callback=open_timeline,
        ... )
        >>> statusbar.mount(parent_frame)
        >>> statusbar.set_cursor_position(1, 1)
        >>> statusbar.set_mode_indicator("normal")
        >>> statusbar.set_mfa_indicator("active", "FIDO2")
        >>> statusbar.set_document_mode(DocumentMode.STRUCTURED_FORM)
        >>> statusbar.set_workflow_timeline(FormStatus.DRAFT)
    """

    def __init__(
        self,
        widget_id: str = "statusbar",
        controller: Optional[Any] = None,
        paper_callback: Optional[Callable[[], None]] = None,
        mode_callback: Optional[Callable[[], None]] = None,
        workflow_callback: Optional[Callable[[], None]] = None,
    ) -> None:
        """Инициализация StatusBar.

        Args:
            widget_id: Уникальный идентификатор виджета (default: "statusbar").
            controller: Опциональная ссылка на контроллер для callbacks.
            paper_callback: Callback для double-click на индикаторе бумаги.
            mode_callback: Callback для double-click на индикаторе режима.
            workflow_callback: Callback для клика на индикаторе workflow.
        """
        super().__init__(widget_id=widget_id, controller=controller)
        self._paper_callback: Optional[Callable[[], None]] = paper_callback
        self._mode_callback: Optional[Callable[[], None]] = mode_callback
        self._workflow_callback: Optional[Callable[[], None]] = workflow_callback

        # Internal state
        self._line: int = 1
        self._column: int = 1
        self._modified: bool = False
        self._cpi: int = 10
        self._codepage: str = "PC866"
        self._paper: str = "A4"
        self._mode: str = "normal"
        self._mfa_status: str = "none"
        self._mfa_method: Optional[str] = None
        self._security_preset: str = "Standard"
        self._page_current: int = 1
        self._page_total: int = 1
        self._zoom: int = 100
        self._workflow_status: Optional["FormStatus"] = None
        self._document_mode: Optional[DocumentMode] = None

        # Widget references
        self._tk_frame: Optional[tk.Frame] = None
        self._tk_inner_frame: Optional[tk.Frame] = None
        self._tk_cursor_label: Optional[tk.Label] = None
        self._tk_cpi_label: Optional[tk.Label] = None
        self._tk_codepage_label: Optional[tk.Label] = None
        self._tk_paper_label: Optional[tk.Label] = None
        self._tk_mode_label: Optional[tk.Label] = None
        self._tk_mfa_label: Optional[tk.Label] = None
        self._tk_security_label: Optional[tk.Label] = None
        self._tk_page_label: Optional[tk.Label] = None
        self._tk_zoom_label: Optional[tk.Label] = None
        self._tk_notification_label: Optional[tk.Label] = None
        self._workflow_indicator: Optional[WorkflowIndicator] = None
        self._separator_labels: list[tk.Label] = []

        # Workflow Timeline widget
        self._workflow_timeline_frame: Optional[tk.Frame] = None
        self._workflow_timeline_label: Optional[tk.Label] = None
        self._current_workflow_status: Optional[str] = None

        # Simple Mode flag for timeline filtering
        self._simple_mode: bool = False
        self._timeline_statuses: list[str] = list(TIMELINE_STATUSES)

        # Role Badge widget
        self._role_badge: Optional[RoleBadge] = None
        self._current_role: WorkflowRole = WorkflowRole.OPERATOR

        # Layout mode
        self._is_double_row: bool = False
        self._row2_frame: Optional[tk.Frame] = None

        # Notification count
        self._notification_count: int = 0

        # Toast Panel
        self._toast_panel: Optional[ToastPanel] = None
        self._notification_service: Optional["NotificationService"] = None
        self._hide_after_id: Optional[str] = None
        self._toast_panel_visible: bool = False

    @property
    def widget(self) -> tk.Widget:
        """Возвращает tkinter widget для размещения.

        Returns:
            Корневой Frame StatusBar.

        Raises:
            RuntimeError: Если виджет не смонтирован.
        """
        if self._tk_frame is None:
            raise RuntimeError("StatusBar не смонтирован")
        return self._tk_frame

    def show(self) -> None:
        """Показывает компонент."""
        if self._tk_frame is not None:
            self._tk_frame.grid()

    def hide(self) -> None:
        """Скрывает компонент."""
        if self._tk_frame is not None:
            self._tk_frame.grid_remove()

    def is_visible(self) -> bool:
        """Проверяет видимость компонента.

        Returns:
            True если виджет отображается.
        """
        if self._tk_frame is None:
            return False
        return self._tk_frame.winfo_viewable() == 1

    # ------------------------------------------------------------------
    # Public setters
    # ------------------------------------------------------------------

    def set_cursor_position(self, line: int, column: int) -> None:
        """Устанавливает позицию курсора.

        Args:
            line: Номер строки (1-based).
            column: Номер колонки (1-based).
        """
        self._line = max(1, line)
        self._column = max(1, column)
        self._update_cursor_label()

    def set_modified(self, modified: bool) -> None:
        """Устанавливает индикатор изменений.

        Args:
            modified: True если документ был изменён.
        """
        self._modified = modified
        self._update_cursor_label()

    def set_security_preset(self, preset_name: str) -> None:
        """Устанавливает индикатор пресета безопасности.

        Args:
            preset_name: Имя пресета (Legacy, Standard, Paranoid, PQC).
        """
        self._security_preset = preset_name
        self._update_security_label()

    def set_page_info(self, current: int, total: int) -> None:
        """Устанавливает информацию о странице.

        Args:
            current: Текущая страница (1-based).
            total: Общее количество страниц.
        """
        self._page_current = max(1, current)
        self._page_total = max(1, total)
        self._update_page_label()

    def set_cpi(self, cpi: int) -> None:
        """Устанавливает значение CPI (characters per inch).

        Args:
            cpi: Количество символов на дюйм.
        """
        self._cpi = max(1, cpi)
        self._update_cpi_label()

    def set_codepage(self, codepage: str) -> None:
        """Устанавливает кодовую страницу.

        Args:
            codepage: Название кодовой страницы (например, "PC866").
        """
        self._codepage = codepage
        self._update_codepage_label()

    def set_paper(self, paper: str) -> None:
        """Устанавливает формат бумаги.

        Args:
            paper: Формат бумаги (например, "A4", "Letter").
        """
        self._paper = paper
        self._update_paper_label()

    def set_zoom(self, zoom: int) -> None:
        """Устанавливает масштаб.

        Args:
            zoom: Процент масштаба (10-500).
        """
        self._zoom = max(10, min(500, zoom))
        self._update_zoom_label()

    def set_mode_indicator(self, mode: str) -> None:
        """Устанавливает индикатор режима.

        Args:
            mode: "normal" (🟢) или "special" (🔴)
        """
        self._mode = mode.lower()
        self._update_mode_label()
        self._update_mode_tooltip()

    def get_mode_indicator(self) -> str:
        """Возвращает текущий режим.

        Returns:
            Текущий режим ("normal" или "special").
        """
        return self._mode

    def on_mode_indicator_click(self, callback: Callable[[], None]) -> None:
        """Устанавливает callback при клике на индикатор режима.

        Args:
            callback: Функция, вызываемая при double-click на индикаторе режима.
        """
        self._mode_callback = callback
        self._setup_mode_bindings()

    def set_mfa_indicator(
        self,
        status: str,
        method: Optional[str] = None,
    ) -> None:
        """Устанавливает индикатор MFA.

        Args:
            status: "active" (🔒), "required" (⚠️), или "none" (✓)
            method: "FIDO2", "TOTP", "Backup", или None
        """
        self._mfa_status = status.lower()
        self._mfa_method = method
        self._update_mfa_label()
        self._update_mfa_tooltip()

    def get_mfa_status(self) -> str:
        """Возвращает статус MFA.

        Returns:
            Текущий статус MFA ("active", "required", или "none").
        """
        return self._mfa_status

    def set_workflow_status(self, status: "FormStatus") -> None:
        """Устанавливает индикатор workflow статуса.

        Args:
            status: Текущий статус документа (FormStatus).
        """
        self._workflow_status = status
        if self._workflow_indicator is not None:
            self._workflow_indicator.set_status(status)

    def get_workflow_status(self) -> Optional[str]:
        """Возвращает текущий workflow статус.

        Returns:
            Строковое значение статуса или None если не установлен.
        """
        if self._workflow_status is None:
            return None
        return self._workflow_status.value

    def set_workflow_timeline(self, status: "FormStatus") -> None:
        """Устанавливает workflow timeline индикатор.

        Отображает визуальную шкалу: [DRAFT ✓] ──▶ [FILLED ●] ──▶ ...
        Текущий статус выделен ●, пройденные ✓, будущие ○.

        Args:
            status: Текущий статус документа (FormStatus).
        """
        self._current_workflow_status = status.value
        self._update_workflow_timeline()

    def set_simple_mode(self, enabled: bool) -> None:
        """Устанавливает Simple Mode для timeline.

        В Simple Mode timeline показывает только ['draft', 'signed'].

        Args:
            enabled: True для включения Simple Mode.
        """
        if self._simple_mode == enabled:
            return
        self._simple_mode = enabled
        if enabled:
            self._timeline_statuses = ["draft", "signed"]
        else:
            self._timeline_statuses = list(TIMELINE_STATUSES)
        self._update_workflow_timeline()

    def set_role_badge(self, role: WorkflowRole) -> None:
        """Устанавливает role badge индикатор.

        Отображает текущую роль с цветом и иконкой.
        Цвета не зависят от темы: 🔵 OPERATOR / 🟢 EDITOR / 🟠 SUPERVISOR / 🔴 SIGNATORY.

        Args:
            role: Текущая роль пользователя.
        """
        self._current_role = role
        self._update_role_badge()

    def set_document_mode(self, mode: DocumentMode) -> None:
        """Устанавливает режим документа для управления видимостью workflow-виджетов.

        Workflow Timeline strip и RoleBadge показываются только при
        DocumentMode.STRUCTURED_FORM.

        Args:
            mode: Режим документа (FREE_FORM или STRUCTURED_FORM).

        Example:
            >>> from src.documents.types.document_type import DocumentMode
            >>> statusbar.set_document_mode(DocumentMode.STRUCTURED_FORM)
        """
        self._document_mode = mode
        self._apply_layout()

    def get_document_mode(self) -> Optional[DocumentMode]:
        """Возвращает текущий режим документа.

        Returns:
            Режим документа или None если не установлен.
        """
        return self._document_mode

    def set_notification_count(self, count: int) -> None:
        """Устанавливает количество уведомлений.

        Args:
            count: Количество непрочитанных уведомлений.
        """
        self._notification_count = max(0, count)
        self._update_notification_label()

    def show_toast_panel(self) -> None:
        """Показывает Toast Panel с уведомлениями."""
        if self._tk_notification_label is None:
            return

        if self._hide_after_id is not None:
            if self._tk_frame is not None:
                self._tk_frame.after_cancel(self._hide_after_id)
            self._hide_after_id = None

        if self._toast_panel is None and self._tk_frame is not None:
            self._toast_panel = ToastPanel(self._tk_frame)
            self._toast_panel.set_callbacks(
                on_pin_all=self._pin_all_notifications,
                on_clear=self._clear_notifications,
            )

        if self._toast_panel is not None:
            self._toast_panel.show_near_widget(self._tk_notification_label)
            if self._notification_service is not None:
                notifications = self._notification_service.get_history(unread_only=True)
                self._toast_panel.update_notifications(notifications)

        self._toast_panel_visible = True

    def hide_toast_panel(self) -> None:
        """Скрывает Toast Panel."""
        if self._hide_after_id is not None:
            if self._tk_frame is not None:
                self._tk_frame.after_cancel(self._hide_after_id)
            self._hide_after_id = None

        if self._toast_panel is not None:
            self._toast_panel.hide()

        self._toast_panel_visible = False

    def set_notification_service(self, service: "NotificationService") -> None:
        """Устанавливает NotificationService для интеграции.

        Args:
            service: Сервис уведомлений.
        """
        self._notification_service = service
        service.register_badge_callback(self._on_notification_count_changed)
        initial_count = service.get_unread_count()
        self.set_notification_count(initial_count)

    # ------------------------------------------------------------------
    # Tk widget creation
    # ------------------------------------------------------------------

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт фактический Tkinter виджет.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный корневой Frame StatusBar.
        """
        self._tk_frame = tk.Frame(
            parent,
            height=STATUSBAR_HEIGHT,
            bg=_theme_color("bg"),
            relief="sunken",
            bd=1,
        )
        self._tk_frame.pack_propagate(False)

        self._tk_inner_frame = tk.Frame(self._tk_frame, bg=_theme_color("bg"))
        self._tk_inner_frame.pack(fill="both", expand=True, padx=PADDING_SMALL)

        self._tk_cursor_label = self._create_indicator(self._tk_inner_frame, "Ln 1, Col 1")
        self._tk_cpi_label = self._create_indicator(self._tk_inner_frame, "10 CPI")
        self._tk_codepage_label = self._create_indicator(self._tk_inner_frame, "PC866")
        self._tk_paper_label = self._create_indicator(self._tk_inner_frame, "A4")
        self._tk_mode_label = self._create_indicator(self._tk_inner_frame, "🟢 Normal")
        self._tk_mfa_label = self._create_indicator(self._tk_inner_frame, "✓")

        if self._workflow_status is not None:
            self._workflow_indicator = WorkflowIndicator(
                parent=self._tk_inner_frame,
                current_status=self._workflow_status,
                on_click=self._workflow_callback,
            )
            self._workflow_indicator.mount(self._tk_inner_frame)

        self._workflow_timeline_frame = tk.Frame(self._tk_inner_frame, bg=_theme_color("bg"))
        self._workflow_timeline_label = tk.Label(
            self._workflow_timeline_frame,
            text="",
            bg=_theme_color("bg"),
            fg=_theme_color("fg"),
            font=("TkDefaultFont", 9),
        )
        self._workflow_timeline_label.pack(side=tk.LEFT)
        self._workflow_timeline_frame.pack(side=tk.LEFT, padx=(0, PADDING_SMALL))
        self._workflow_timeline_frame.bind("<Button-1>", self._on_workflow_timeline_click)
        self._workflow_timeline_label.bind("<Button-1>", self._on_workflow_timeline_click)
        self._workflow_timeline_frame.config(cursor="hand2")
        self._workflow_timeline_label.config(cursor="hand2")

        self._role_badge = RoleBadge(
            parent=self._tk_inner_frame,
            current_role=self._current_role,
        )
        self._role_badge.mount(self._tk_inner_frame)

        self._tk_security_label = self._create_indicator(self._tk_inner_frame, "🔒 Standard")
        self._tk_page_label = self._create_indicator(self._tk_inner_frame, "Page 1/1")
        self._tk_zoom_label = self._create_indicator(self._tk_inner_frame, "100%")
        self._tk_notification_label = self._create_indicator(self._tk_inner_frame, "")
        self._update_notification_label()

        self._create_separators()
        self._setup_bindings()
        self._apply_layout()

        self._update_mode_label()
        self._update_mfa_label()
        self._update_mode_tooltip()
        self._update_mfa_tooltip()

        self._tk_frame.bind("<Configure>", self._on_configure)

        return self._tk_frame

    def _create_indicator(
        self,
        parent: tk.Widget,
        initial_text: str,
    ) -> tk.Label:
        """Создаёт виджет индикатора.

        Args:
            parent: Родительский виджет.
            initial_text: Начальный текст индикатора.

        Returns:
            Созданный Label виджет.
        """
        label = tk.Label(
            parent,
            text=initial_text,
            bg=_theme_color("bg"),
            fg=_theme_color("fg"),
            font=("TkDefaultFont", 9),
            padx=PADDING_SMALL,
        )
        return label

    def _create_separators(self) -> None:
        """Создаёт разделительные метки │ между индикаторами.

        Цвет разделителей фиксирован и не зависит от темы (UI_SPEC §7.4).
        """
        if self._tk_inner_frame is None:
            return

        for _ in range(12):
            sep = tk.Label(
                self._tk_inner_frame,
                text=SEPARATOR_CHAR,
                bg=_theme_color("bg"),
                fg=SEPARATOR_COLOR,
                font=("TkDefaultFont", 9),
            )
            self._separator_labels.append(sep)

    def _setup_bindings(self) -> None:
        """Настраивает event bindings для Tkinter виджета."""
        if self._tk_paper_label is not None:
            self._tk_paper_label.bind("<Double-Button-1>", self._on_paper_double_click)
        self._setup_mode_bindings()
        self._setup_notification_bindings()

    def _setup_mode_bindings(self) -> None:
        """Настраивает event bindings для Mode индикатора."""
        if self._tk_mode_label is not None:
            self._tk_mode_label.bind("<Double-Button-1>", self._on_mode_double_click)

    def _setup_notification_bindings(self) -> None:
        """Настраивает event bindings для индикатора уведомлений."""
        if self._tk_notification_label is not None:
            self._tk_notification_label.bind("<Enter>", self._on_notification_enter)
            self._tk_notification_label.bind("<Leave>", self._on_notification_leave)

    def _cleanup(self) -> None:
        """Выполняет очистку ресурсов перед демонтированием."""
        self._tk_cursor_label = None
        self._tk_cpi_label = None
        self._tk_codepage_label = None
        self._tk_paper_label = None
        self._tk_mode_label = None
        self._tk_mfa_label = None
        self._tk_security_label = None
        self._tk_page_label = None
        self._tk_zoom_label = None
        self._tk_notification_label = None
        self._tk_inner_frame = None
        self._tk_frame = None

        self._separator_labels.clear()

        if self._workflow_indicator is not None:
            if self._workflow_indicator.is_mounted():
                self._workflow_indicator.unmount()
            self._workflow_indicator = None

        self._workflow_timeline_frame = None
        self._workflow_timeline_label = None

        if self._role_badge is not None:
            if self._role_badge.is_mounted():
                self._role_badge.unmount()
            self._role_badge = None

        self._row2_frame = None
        self._document_mode = None

        if self._toast_panel is not None:
            self._toast_panel.hide()
            self._toast_panel = None

        if self._hide_after_id is not None and self._tk_frame is not None:
            self._tk_frame.after_cancel(self._hide_after_id)
            self._hide_after_id = None

        if self._notification_service is not None:
            self._notification_service.unregister_badge_callback(
                self._on_notification_count_changed
            )
            self._notification_service = None

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _on_configure(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает событие изменения размера.

        Args:
            event: Событие конфигурации.
        """
        if event is None or self._tk_frame is None:
            return

        width = event.width
        is_double_row = width < MIN_WINDOW_WIDTH

        if is_double_row != self._is_double_row:
            self._is_double_row = is_double_row
            self._apply_layout()

    def _apply_layout(self) -> None:
        """Применяет текущий layout (single или double row)."""
        if self._tk_inner_frame is None:
            return

        # Unpack all widgets
        for widget in [
            self._tk_cursor_label,
            self._tk_cpi_label,
            self._tk_codepage_label,
            self._tk_paper_label,
            self._tk_mode_label,
            self._tk_mfa_label,
            self._tk_security_label,
            self._tk_page_label,
            self._tk_zoom_label,
            self._tk_notification_label,
        ]:
            if widget is not None:
                widget.pack_forget()

        if self._workflow_indicator is not None and self._workflow_indicator.widget is not None:
            self._workflow_indicator.widget.pack_forget()

        if self._workflow_timeline_frame is not None:
            self._workflow_timeline_frame.pack_forget()

        if self._role_badge is not None and self._role_badge.widget is not None:
            self._role_badge.widget.pack_forget()

        if self._row2_frame is not None:
            self._row2_frame.pack_forget()

        for sep in self._separator_labels:
            sep.pack_forget()

        # Adjust height for double row
        if self._tk_frame is not None:
            if self._is_double_row:
                self._tk_frame.config(height=STATUSBAR_HEIGHT * 2)
            else:
                self._tk_frame.config(height=STATUSBAR_HEIGHT)

        if self._is_double_row:
            self._apply_double_row_layout()
        else:
            self._apply_single_row_layout()

    def _apply_single_row_layout(self) -> None:
        """Применяет single row layout (все индикаторы в одну строку).

        Порядок (UI_SPEC §7.4):
        Ln 12, Col 45 │ 12 CPI │ PC866 │ Tractor │ 🟢 Normal │ ✓
        │ [Timeline] │ [RoleBadge]
        │ 🔒 Standard │ Page 2/5 │ 100% │ [3]
        """
        if self._tk_inner_frame is None:
            return

        sep_index = [0]
        master = self._tk_inner_frame

        def pack_sep(side: str = "left") -> None:
            from tkinter import LEFT, RIGHT
            from typing import Any, cast

            idx = sep_index[0]
            if idx < len(self._separator_labels):
                self._separator_labels[idx].pack(
                    in_=master, side=cast(Any, RIGHT if side == "right" else LEFT)
                )
                sep_index[0] = idx + 1

        # Left group
        widgets_left = [
            self._tk_cursor_label,
            self._tk_cpi_label,
            self._tk_codepage_label,
            self._tk_paper_label,
            self._tk_mode_label,
            self._tk_mfa_label,
        ]
        first = True
        for widget in widgets_left:
            if widget is not None:
                if not first:
                    pack_sep("left")
                widget.pack(in_=master, side="left", padx=(0, PADDING_SMALL))
                first = False

        # Workflow section (only for STRUCTURED_FORM)
        if self._document_mode == DocumentMode.STRUCTURED_FORM:
            pack_sep("left")
            if self._workflow_timeline_frame is not None:
                self._workflow_timeline_frame.pack(in_=master, side="left", padx=(0, PADDING_SMALL))
            pack_sep("left")
            if self._role_badge is not None and self._role_badge.widget is not None:
                self._role_badge.widget.pack(in_=master, side="left", padx=(0, PADDING_SMALL))

        # Separator before right group
        pack_sep("left")

        # Right group (pack side="right" in order: far-right first)
        # Visual left-to-right: security │ page │ zoom │ notification
        right_widgets = [
            self._tk_notification_label,
            self._tk_zoom_label,
            self._tk_page_label,
            self._tk_security_label,
        ]
        for i, widget in enumerate(right_widgets):
            if widget is not None:
                widget.pack(in_=master, side="right", padx=(PADDING_SMALL, 0))
                if i < len(right_widgets) - 1:
                    pack_sep("right")

    def _apply_double_row_layout(self) -> None:
        """Применяет double row layout (две строки индикаторов).

        Строка 1 (UI_SPEC §7.2):
            Ln 12, Col 45 │ Page 2/5 │ 🔒 Standard │ [3]
            (+ Timeline и RoleBadge при STRUCTURED_FORM)
        Строка 2:
            12 CPI │ PC866 │ Tractor │ 🟢 Normal │ ✓ │ 100%
        """
        if self._tk_inner_frame is None:
            return

        sep_index = [0]
        master_row1 = self._tk_inner_frame

        def pack_sep(master: tk.Widget, side: str = "left") -> None:
            from tkinter import LEFT, RIGHT
            from typing import Any, cast

            idx = sep_index[0]
            if idx < len(self._separator_labels):
                mapped_side = cast(Any, RIGHT if side == "right" else LEFT)
                self._separator_labels[idx].pack(in_=master, side=mapped_side)
                sep_index[0] = idx + 1

        # Row 1: cursor
        if self._tk_cursor_label is not None:
            self._tk_cursor_label.pack(in_=master_row1, side="left", padx=(0, PADDING_SMALL))

        # Workflow section (only for STRUCTURED_FORM)
        if self._document_mode == DocumentMode.STRUCTURED_FORM:
            pack_sep(master_row1, "left")
            if self._workflow_timeline_frame is not None:
                self._workflow_timeline_frame.pack(
                    in_=master_row1, side="left", padx=(0, PADDING_SMALL)
                )
            pack_sep(master_row1, "left")
            if self._role_badge is not None and self._role_badge.widget is not None:
                self._role_badge.widget.pack(in_=master_row1, side="left", padx=(0, PADDING_SMALL))

        # Separator before right group
        pack_sep(master_row1, "left")

        # Row 1 right group: visual page │ security │ notification
        # Pack order side="right": notification, security, page
        if self._tk_notification_label is not None:
            self._tk_notification_label.pack(in_=master_row1, side="right", padx=(PADDING_SMALL, 0))
            pack_sep(master_row1, "right")
        if self._tk_security_label is not None:
            self._tk_security_label.pack(in_=master_row1, side="right", padx=(PADDING_SMALL, 0))
            pack_sep(master_row1, "right")
        if self._tk_page_label is not None:
            self._tk_page_label.pack(in_=master_row1, side="right", padx=(PADDING_SMALL, 0))

        # Row 2
        if self._row2_frame is None:
            self._row2_frame = tk.Frame(self._tk_inner_frame, bg=_theme_color("bg"))
        self._row2_frame.pack(fill="x", side=tk.BOTTOM, pady=(2, 0))

        for child in self._row2_frame.winfo_children():
            child.pack_forget()

        master_row2 = self._row2_frame
        widgets_row2 = [
            self._tk_cpi_label,
            self._tk_codepage_label,
            self._tk_paper_label,
            self._tk_mode_label,
            self._tk_mfa_label,
            self._tk_zoom_label,
        ]
        first = True
        for widget in widgets_row2:
            if widget is not None:
                if not first:
                    pack_sep(master_row2, "left")
                widget.pack(in_=master_row2, side="left", padx=(0, PADDING_SMALL))
                first = False

    # ------------------------------------------------------------------
    # Update helpers
    # ------------------------------------------------------------------

    def _update_cursor_label(self) -> None:
        """Обновляет индикатор позиции курсора."""
        if self._tk_cursor_label is None:
            return

        text = f"Ln {self._line}, Col {self._column}"
        self._tk_cursor_label.config(text=text)

        if self._modified:
            self._tk_cursor_label.config(fg=MODIFIED_COLOR)
        else:
            self._tk_cursor_label.config(fg=_theme_color("fg"))

    def _update_cpi_label(self) -> None:
        """Обновляет индикатор CPI."""
        if self._tk_cpi_label is not None:
            self._tk_cpi_label.config(text=f"{self._cpi} CPI")

    def _update_codepage_label(self) -> None:
        """Обновляет индикатор кодовой страницы."""
        if self._tk_codepage_label is not None:
            self._tk_codepage_label.config(text=self._codepage)

    def _update_paper_label(self) -> None:
        """Обновляет индикатор формата бумаги."""
        if self._tk_paper_label is not None:
            self._tk_paper_label.config(text=self._paper)

    def _update_mode_label(self) -> None:
        """Обновляет индикатор режима."""
        if self._tk_mode_label is None:
            return

        if self._mode == "special":
            text = "🔴 Special"
            bg_color = MODE_SPECIAL_BG
            fg_color = MODE_SPECIAL_FG
        else:
            text = "🟢 Normal"
            bg_color = MODE_NORMAL_BG
            fg_color = MODE_NORMAL_FG

        self._tk_mode_label.config(text=text, bg=bg_color, fg=fg_color)

    def _update_mode_tooltip(self) -> None:
        """Обновляет tooltip для индикатора режима."""
        if self._tk_mode_label is None:
            return

        if self._mode == "special":
            tooltip = "Special Mode - Click to enter Normal Mode"
        else:
            tooltip = "Normal Mode - Click to enter Special Mode"

        self._tk_mode_label.tooltip_text = tooltip  # type: ignore[attr-defined]

    def _update_mfa_label(self) -> None:
        """Обновляет индикатор MFA."""
        if self._tk_mfa_label is None:
            return

        if self._mfa_status == "active":
            method_str = f" {self._mfa_method}" if self._mfa_method else ""
            text = f"🔒{method_str}"
            bg_color = MFA_ACTIVE_BG
            fg_color = MFA_ACTIVE_FG
        elif self._mfa_status == "required":
            text = "⚠️ MFA"
            bg_color = MFA_REQUIRED_BG
            fg_color = MFA_REQUIRED_FG
        else:
            text = "✓"
            bg_color = MFA_NONE_BG
            fg_color = MFA_NONE_FG

        self._tk_mfa_label.config(text=text, bg=bg_color, fg=fg_color)

    def _update_mfa_tooltip(self) -> None:
        """Обновляет tooltip для индикатора MFA."""
        if self._tk_mfa_label is None:
            return

        if self._mfa_status == "active" and self._mfa_method:
            tooltip = f"MFA Active: {self._mfa_method}"
        elif self._mfa_status == "required":
            tooltip = "MFA Required for Special Mode"
        else:
            tooltip = "No MFA Required"

        self._tk_mfa_label.tooltip_text = tooltip  # type: ignore[attr-defined]

    def _update_security_label(self) -> None:
        """Обновляет индикатор пресета безопасности."""
        if self._tk_security_label is None:
            return

        text = f"🔒 {self._security_preset}"
        self._tk_security_label.config(text=text)

        bg_color, fg_color = SECURITY_PRESET_COLORS.get(
            self._security_preset, DEFAULT_SECURITY_COLOR
        )
        self._tk_security_label.config(bg=bg_color, fg=fg_color)

    def _update_page_label(self) -> None:
        """Обновляет индикатор страницы."""
        if self._tk_page_label is not None:
            self._tk_page_label.config(text=f"Page {self._page_current}/{self._page_total}")

    def _update_zoom_label(self) -> None:
        """Обновляет индикатор масштаба."""
        if self._tk_zoom_label is not None:
            self._tk_zoom_label.config(text=f"{self._zoom}%")

    def _update_workflow_timeline(self) -> None:
        """Обновляет workflow timeline визуализацию."""
        if self._workflow_timeline_label is None:
            return

        if self._current_workflow_status is None:
            self._workflow_timeline_label.config(text="")
            return

        timeline_text = self._build_timeline_text(self._current_workflow_status)
        self._workflow_timeline_label.config(
            text=timeline_text,
            fg=_theme_color("fg"),
        )

    def _build_timeline_text(self, current_status: str) -> str:
        """Формирует текст workflow timeline strip.

        Формат: [DRAFT ✓] ──▶ [FILLED ●] ──▶ [VALIDATED ○] ...
        Пройденные статусы отмечены ✓, текущий ●, будущие ○.

        В Simple Mode отображает только [DRAFT] ──▶ [SIGNED].

        Args:
            current_status: Текущий статус в виде строки.

        Returns:
            Строка timeline для отображения в StatusBar.
        """
        current = current_status.lower()
        statuses = (
            self._timeline_statuses
            if hasattr(self, "_timeline_statuses")
            else list(TIMELINE_STATUSES)
        )
        try:
            current_idx = statuses.index(current)
        except ValueError:
            current_idx = -1

        parts: list[str] = []
        for i, st in enumerate(statuses):
            if i < current_idx:
                marker = TIMELINE_DONE_MARKER
            elif i == current_idx:
                marker = TIMELINE_CURRENT_MARKER
            else:
                marker = TIMELINE_FUTURE_MARKER
            parts.append(f"[{st.upper()} {marker}]")

        return f" {TIMELINE_ARROW} ".join(parts)

    def _update_role_badge(self) -> None:
        """Обновляет role badge визуализацию."""
        if self._role_badge is None:
            return
        self._role_badge.set_role(self._current_role)

    def _update_notification_label(self) -> None:
        """Обновляет индикатор уведомлений [n]."""
        if self._tk_notification_label is None:
            return

        if self._notification_count > 0:
            text = f"[{self._notification_count}]"
            self._tk_notification_label.config(
                text=text,
                fg=NOTIFICATION_ACTIVE_COLOR,
            )
        else:
            self._tk_notification_label.config(
                text="[0]",
                fg=NOTIFICATION_INACTIVE_COLOR,
            )

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _on_workflow_timeline_click(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает клик на workflow timeline.

        Args:
            event: Событие клика.
        """
        if self._workflow_callback is not None:
            self._workflow_callback()

    def _on_paper_double_click(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает double-click на индикаторе бумаги.

        Если установлен callback — вызывает его. Иначе открывает
        диалог настройки бумаги ``PaperSetupDialog``.

        Args:
            event: Событие double-click.
        """
        if self._paper_callback is not None:
            self._paper_callback()
        elif self._is_mounted and self._tk_frame is not None:
            dialog = PaperSetupDialog(parent=self._tk_frame)
            dialog.show()

    def _on_mode_double_click(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает double-click на индикаторе режима.

        Args:
            event: Событие double-click.
        """
        if self._mode_callback is not None:
            self._mode_callback()

    def _on_notification_count_changed(self, count: int) -> None:
        """Обработчик изменения количества уведомлений.

        Args:
            count: Новое количество непрочитанных уведомлений.
        """
        self.set_notification_count(count)

        if self._toast_panel_visible and self._toast_panel is not None:
            if self._notification_service is not None:
                notifications = self._notification_service.get_history(unread_only=True)
                self._toast_panel.update_notifications(notifications)

    def _on_notification_enter(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает mouse enter на индикаторе уведомлений."""
        if self._hide_after_id is not None:
            if self._tk_frame is not None:
                self._tk_frame.after_cancel(self._hide_after_id)
            self._hide_after_id = None
        self.show_toast_panel()

    def _on_notification_leave(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает mouse leave на индикаторе уведомлений."""
        self._schedule_hide_toast_panel()

    def _schedule_hide_toast_panel(self) -> None:
        """Запускает таймер для auto-hide панели."""
        if self._tk_frame is None:
            return
        if self._hide_after_id is not None:
            self._tk_frame.after_cancel(self._hide_after_id)
        self._hide_after_id = self._tk_frame.after(
            TOAST_PANEL_AUTO_HIDE_MS,
            self._do_hide_toast_panel,
        )

    def _do_hide_toast_panel(self) -> None:
        """Выполняет фактическое скрытие панели."""
        self._hide_after_id = None
        self.hide_toast_panel()

    def _pin_all_notifications(self) -> None:
        """Отмечает все уведомления как прочитанные."""
        if self._notification_service is not None:
            self._notification_service.mark_all_as_read()

    def _clear_notifications(self) -> None:
        """Очищает всю историю уведомлений."""
        if self._notification_service is not None:
            self._notification_service.clear_history()


# Module metadata
__version__: Final[str] = "1.4"
__author__: Final[str] = "FX Text Processor Team"
__date__: Final[str] = "May 2026"

# Module exports
__all__: list[str] = [
    "StatusBar",
    "ToastPanel",
    "PaperSetupDialog",
    "SECURITY_PRESET_COLORS",
    "DEFAULT_SECURITY_COLOR",
    "MODIFIED_COLOR",
    "NOTIFICATION_ACTIVE_COLOR",
    "NOTIFICATION_INACTIVE_COLOR",
    "SEPARATOR_COLOR",
    "SEPARATOR_CHAR",
    "TIMELINE_COLORS",
    "TIMELINE_DONE_MARKER",
    "TIMELINE_CURRENT_MARKER",
    "TIMELINE_FUTURE_MARKER",
    "TIMELINE_ARROW",
]
