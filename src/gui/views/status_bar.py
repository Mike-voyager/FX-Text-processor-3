"""StatusBar для FX Text Processor 3.

Реализует адаптивный статусбар с индикаторами:
- Позиция курсора (Ln X, Col Y)
- CPI (characters per inch)
- Кодовая страница
- Формат бумаги
- Режим работы (Normal/Special)
- MFA статус
- ПреSET безопасности
- Workflow статус
- Номер страницы
- Масштаб
- Индикатор уведомлений [n] с Toast Panel

Layout адаптируется автоматически:
- Single row при width >= 1024
- Double row при width < 1024

Toast Panel:
- Показывается при hover на индикаторе [n]
- Отображает последние 5 уведомлений
- Auto-hide через 3 секунды после mouse leave

Example:
    >>> statusbar = StatusBar(parent_frame)
    >>> statusbar.set_cursor_position(10, 25)
    >>> statusbar.set_mode_indicator("normal")
    >>> statusbar.set_mfa_indicator("active", "FIDO2")
    >>> statusbar.set_security_preset("Standard")
    >>> statusbar.set_workflow_status(FormStatus.DRAFT)
    >>> statusbar.set_notification_count(3)
    >>> statusbar.show_toast_panel()

Version: 1.3
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import TYPE_CHECKING, Any, Callable, Final, Optional

from src.gui.components.base.widget import BaseWidget
from src.gui.layout.layout_constants import (
    MIN_WINDOW_WIDTH,
    PADDING_NORMAL,
    PADDING_SMALL,
    STATUSBAR_HEIGHT,
)
from src.gui.workflow.role_badge import RoleBadge, WorkflowRole
from src.gui.workflow.workflow_indicator import WorkflowIndicator

if TYPE_CHECKING:
    from src.documents.constructor.form_status import FormStatus
    from src.gui.services.notification_service import Notification, NotificationService

# Security preset colors (name -> (bg, fg))
SECURITY_PRESET_COLORS: Final[dict[str, tuple[str, str]]] = {
    "Legacy": ("#ffcccc", "#cc0000"),  # Light red bg, dark red fg
    "Standard": ("#ffffcc", "#cc9900"),  # Light yellow bg, dark yellow fg
    "Paranoid": ("#ccffcc", "#006600"),  # Light green bg, dark green fg
    "PQC": ("#e6ccff", "#6600cc"),  # Light purple bg, dark purple fg
}

# Default color for unknown preset
DEFAULT_SECURITY_COLOR: Final[tuple[str, str]] = ("#cccccc", "#333333")

# Modified indicator color
MODIFIED_COLOR: Final[str] = "#ff8c00"  # Dark orange

# Default colors
DEFAULT_BG: Final[str] = "#f0f0f0"
DEFAULT_FG: Final[str] = "#333333"

# Mode indicator colors
MODE_NORMAL_BG: Final[str] = "#ccffcc"  # Light green
MODE_NORMAL_FG: Final[str] = "#006600"  # Dark green
MODE_SPECIAL_BG: Final[str] = "#ffcccc"  # Light red
MODE_SPECIAL_FG: Final[str] = "#cc0000"  # Dark red

# MFA indicator colors
MFA_ACTIVE_BG: Final[str] = "#ccffcc"  # Light green
MFA_ACTIVE_FG: Final[str] = "#006600"  # Dark green
MFA_REQUIRED_BG: Final[str] = "#ffffcc"  # Light yellow
MFA_REQUIRED_FG: Final[str] = "#cc9900"  # Dark yellow
MFA_NONE_BG: Final[str] = "#cccccc"  # Light gray
MFA_NONE_FG: Final[str] = "#333333"  # Dark gray

# Notification indicator colors
NOTIFICATION_ACTIVE_COLOR: Final[str] = "#ff8c00"  # Dark orange (when n > 0)
NOTIFICATION_INACTIVE_COLOR: Final[str] = "#999999"  # Gray (when n = 0)

# Workflow Timeline colors (static, not theme-dependent)
TIMELINE_COLORS: Final[dict[str, str]] = {
    "draft": "#95a5a6",  # Gray
    "filled": "#3498db",  # Blue
    "validated": "#f39c12",  # Yellow
    "approved": "#e67e22",  # Orange
    "signed": "#27ae60",  # Green
}

# Timeline markers
TIMELINE_CURRENT_MARKER: Final[str] = "●"
TIMELINE_NEXT_MARKER: Final[str] = "○──▶"
TIMELINE_ARROW: Final[str] = "──▶"
TIMELINE_SEPARATOR: Final[str] = " "

# Role badge colors (static, not theme-dependent)
ROLE_BADGE_COLORS: Final[dict[WorkflowRole, str]] = {
    WorkflowRole.OPERATOR: "#3498db",  # Blue
    WorkflowRole.EDITOR: "#2ecc71",  # Green
    WorkflowRole.SUPERVISOR: "#f39c12",  # Orange
    WorkflowRole.SIGNATORY: "#e74c3c",  # Red
}

# Role badge icons
ROLE_BADGE_ICONS: Final[dict[WorkflowRole, str]] = {
    WorkflowRole.OPERATOR: "🔵",
    WorkflowRole.EDITOR: "🟢",
    WorkflowRole.SUPERVISOR: "🟠",
    WorkflowRole.SIGNATORY: "🔴",
}

# Toast Panel settings
TOAST_PANEL_WIDTH: Final[int] = 280
TOAST_PANEL_MAX_ITEMS: Final[int] = 5
TOAST_PANEL_AUTO_HIDE_MS: Final[int] = 3000  # 3 seconds
TOAST_PANEL_BG: Final[str] = "#ffffff"
TOAST_PANEL_BORDER_COLOR: Final[str] = "#cccccc"
TOAST_PANEL_HEADER_BG: Final[str] = "#f5f5f5"


class ToastPanel:
    """Панель уведомлений для отображения при hover.

    Показывает список последних уведомлений с иконками приоритета.
    Auto-hide через 3 секунд после mouse leave.

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

    # Icon mapping for priorities
    _PRIORITY_ICONS: Final[dict[str, str]] = {
        "CRITICAL": "🔴",
        "HIGH": "⚠️",
        "NORMAL": "ℹ️",
        "LOW": "✓",
    }

    # Category icons
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

    def show_near_widget(self, widget: tk.Widget) -> None:
        """Показывает панель рядом с указанным виджетом.

        Args:
            widget: Виджет, возле которого показывать панель.
        """
        if self._window is not None:
            self.hide()

        # Create Toplevel window
        self._window = tk.Toplevel(self._parent)
        self._window.overrideredirect(True)  # No decorations
        self._window.attributes("-topmost", True)
        self._window.configure(bg=TOAST_PANEL_BORDER_COLOR)

        # Position near the widget
        self._position_near(widget)

        # Create UI
        self._create_ui()

        # Update content
        self._update_content()

        self._is_visible = True

    def _position_near(self, widget: tk.Widget) -> None:
        """Позиционирует панель возле виджета.

        Args:
            widget: Виджет-ориентир для позиционирования.
        """
        if self._window is None:
            return

        # Get widget position
        widget_x = widget.winfo_rootx()
        widget_y = widget.winfo_rooty()
        widget_height = widget.winfo_height()

        # Position above the widget
        x = widget_x - TOAST_PANEL_WIDTH + widget.winfo_width()
        y = widget_y - 150  # Approximate height

        # Ensure minimum positions
        if x < 0:
            x = 0
        if y < 0:
            y = widget_y + widget_height + 5

        self._window.geometry(f"{TOAST_PANEL_WIDTH}x150+{x}+{y}")

    def _create_ui(self) -> None:
        """Создаёт UI компоненты панели."""
        if self._window is None:
            return

        # Main frame with border
        main_frame = tk.Frame(
            self._window,
            bg=TOAST_PANEL_BORDER_COLOR,
            bd=1,
        )
        main_frame.pack(fill="both", expand=True)

        # Header
        header_frame = tk.Frame(
            main_frame,
            bg=TOAST_PANEL_HEADER_BG,
            padx=PADDING_SMALL,
            pady=PADDING_SMALL,
        )
        header_frame.pack(fill="x", side="top")

        count = len(self._notifications)
        header_text = f"🔔 Уведомления ({count})"
        header_label = tk.Label(
            header_frame,
            text=header_text,
            bg=TOAST_PANEL_HEADER_BG,
            fg="#333333",
            font=("TkDefaultFont", 10, "bold"),
        )
        header_label.pack(side="left")

        # Separator line
        separator = tk.Frame(main_frame, height=1, bg="#cccccc")
        separator.pack(fill="x", side="top")

        # Items container
        self._items_frame = tk.Frame(
            main_frame,
            bg=TOAST_PANEL_BG,
            padx=PADDING_SMALL,
            pady=PADDING_SMALL,
        )
        self._items_frame.pack(fill="both", expand=True)

    def _update_content(self) -> None:
        """Обновляет содержимое панели уведомлениями."""
        if self._items_frame is None:
            return

        # Clear existing items
        for widget in self._items_frame.winfo_children():
            widget.destroy()

        if not self._notifications:
            # No notifications message
            no_data_label = tk.Label(
                self._items_frame,
                text="Нет уведомлений",
                bg=TOAST_PANEL_BG,
                fg="#999999",
                font=("TkDefaultFont", 9),
            )
            no_data_label.pack(pady=PADDING_NORMAL)
            return

        # Show up to MAX_ITEMS notifications
        for notification in self._notifications[:TOAST_PANEL_MAX_ITEMS]:
            self._create_notification_row(notification)

    def _create_notification_row(self, notification: Notification) -> None:
        """Создаёт строку уведомления.

        Args:
            notification: Данные уведомления.
        """
        if self._items_frame is None:
            return

        # Get icon based on priority
        priority_name = notification.priority.name
        icon = self._PRIORITY_ICONS.get(priority_name, "ℹ️")

        # Create row frame
        row_frame = tk.Frame(
            self._items_frame,
            bg=TOAST_PANEL_BG,
            padx=2,
            pady=2,
        )
        row_frame.pack(fill="x", side="top")

        # Icon label
        icon_label = tk.Label(
            row_frame,
            text=icon,
            bg=TOAST_PANEL_BG,
            fg="#333333",
            font=("TkDefaultFont", 10),
            width=2,
        )
        icon_label.pack(side="left")

        # Message label
        message_label = tk.Label(
            row_frame,
            text=notification.message,
            bg=TOAST_PANEL_BG,
            fg="#333333",
            font=("TkDefaultFont", 9),
            anchor="w",
            justify="left",
            wraplength=TOAST_PANEL_WIDTH - 50,
        )
        message_label.pack(side="left", fill="x", expand=True)

    def update_notifications(self, notifications: list[Notification]) -> None:
        """Обновляет список уведомлений.

        Args:
            notifications: Список уведомлений для отображения.
        """
        self._notifications = notifications
        if self._is_visible:
            self._update_content()

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
        >>> def open_paper_dialog():
        ...     PaperSetupDialog().show()
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
        >>> statusbar.set_workflow_status(FormStatus.DRAFT)
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

        Example:
            >>> statusbar = StatusBar(
            ...     paper_callback=lambda: print("Paper!"),
            ...     mode_callback=lambda: print("Mode!"),
            ...     workflow_callback=lambda: print("Timeline!"),
            ... )
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

        # Widget references (initialized in _create_tk_widget)
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
        self._tk_notification_label: Optional[tk.Label] = None  # [n] indicator
        self._workflow_indicator: Optional[WorkflowIndicator] = None
        self._separator_labels: list[tk.Label] = []  # Separator labels

        # Workflow Timeline widget
        self._workflow_timeline_frame: Optional[tk.Frame] = None
        self._workflow_timeline_label: Optional[tk.Label] = None
        self._current_workflow_status: Optional[str] = None

        # Role Badge widget
        self._role_badge: Optional[RoleBadge] = None
        self._current_role: WorkflowRole = WorkflowRole.OPERATOR

        # Layout mode
        self._is_double_row: bool = False

        # Notification count
        self._notification_count: int = 0

        # Toast Panel for notifications
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
            self._tk_frame.pack()

    def hide(self) -> None:
        """Скрывает компонент."""
        if self._tk_frame is not None:
            self._tk_frame.pack_forget()

    def is_visible(self) -> bool:
        """Проверяет видимость компонента.

        Returns:
            True если виджет отображается.
        """
        if self._tk_frame is None:
            return False
        return self._tk_frame.winfo_viewable() == 1

    def set_cursor_position(self, line: int, column: int) -> None:
        """Устанавливает позицию курсора.

        Args:
            line: Номер строки (1-based).
            column: Номер колонки (1-based).

        Example:
            >>> statusbar.set_cursor_position(10, 25)
            >>> # Отображает: "Ln 10, Col 25"
        """
        self._line = max(1, line)
        self._column = max(1, column)
        self._update_cursor_label()

    def set_modified(self, modified: bool) -> None:
        """Устанавливает индикатор изменений.

        Args:
            modified: True если документ был изменён.

        Example:
            >>> statusbar.set_modified(True)
            >>> # Индикатор курсора становится оранжевым
        """
        self._modified = modified
        self._update_cursor_label()

    def set_security_preset(self, preset_name: str) -> None:
        """Устанавливает индикатор пресета безопасности.

        Args:
            preset_name: Имя пресета (Legacy, Standard, Paranoid, PQC).

        Example:
            >>> statusbar.set_security_preset("Paranoid")
            >>> # Индикатор зелёный с замком
        """
        self._security_preset = preset_name
        self._update_security_label()

    def set_page_info(self, current: int, total: int) -> None:
        """Устанавливает информацию о странице.

        Args:
            current: Текущая страница (1-based).
            total: Общее количество страниц.

        Example:
            >>> statusbar.set_page_info(2, 5)
            >>> # Отображает: "Page 2/5"
        """
        self._page_current = max(1, current)
        self._page_total = max(1, total)
        self._update_page_label()

    def set_cpi(self, cpi: int) -> None:
        """Устанавливает значение CPI (characters per inch).

        Args:
            cpi: Количество символов на дюйм.

        Example:
            >>> statusbar.set_cpi(12)
            >>> # Отображает: "12 CPI"
        """
        self._cpi = max(1, cpi)
        self._update_cpi_label()

    def set_codepage(self, codepage: str) -> None:
        """Устанавливает кодовую страницу.

        Args:
            codepage: Название кодовой страницы (например, "PC866").

        Example:
            >>> statusbar.set_codepage("UTF-8")
            >>> # Отображает: "UTF-8"
        """
        self._codepage = codepage
        self._update_codepage_label()

    def set_paper(self, paper: str) -> None:
        """Устанавливает формат бумаги.

        Args:
            paper: Формат бумаги (например, "A4", "Letter").

        Example:
            >>> statusbar.set_paper("Letter")
            >>> # Отображает: "Letter"
        """
        self._paper = paper
        self._update_paper_label()

    def set_zoom(self, zoom: int) -> None:
        """Устанавливает масштаб.

        Args:
            zoom: Процент масштаба (10-500).

        Example:
            >>> statusbar.set_zoom(150)
            >>> # Отображает: "150%"
        """
        self._zoom = max(10, min(500, zoom))
        self._update_zoom_label()

    # Mode indicator methods

    def set_mode_indicator(self, mode: str) -> None:
        """Устанавливает индикатор режима.

        Args:
            mode: "normal" (🟢) или "special" (🔴)

        Example:
            >>> statusbar.set_mode_indicator("normal")
            >>> # Отображает: "🟢 Normal"
            >>> statusbar.set_mode_indicator("special")
            >>> # Отображает: "🔴 Special"
        """
        self._mode = mode.lower()
        self._update_mode_label()
        self._update_mode_tooltip()

    def get_mode_indicator(self) -> str:
        """Возвращает текущий режим.

        Returns:
            Текущий режим ("normal" или "special").

        Example:
            >>> statusbar.set_mode_indicator("normal")
            >>> statusbar.get_mode_indicator()
            'normal'
        """
        return self._mode

    def on_mode_indicator_click(self, callback: Callable[[], None]) -> None:
        """Устанавливает callback при клике на индикатор режима.

        Args:
            callback: Функция, вызываемая при double-click на индикаторе режима.

        Example:
            >>> def switch_mode():
            ...     print("Mode switched")
            >>> statusbar.on_mode_indicator_click(switch_mode)
        """
        self._mode_callback = callback
        self._setup_mode_bindings()

    # MFA indicator methods

    def set_mfa_indicator(
        self,
        status: str,
        method: Optional[str] = None,
    ) -> None:
        """Устанавливает индикатор MFA.

        Args:
            status: "active" (🔒), "required" (⚠️), или "none" (✓)
            method: "FIDO2", "TOTP", "Backup", или None

        Example:
            >>> statusbar.set_mfa_indicator("active", "FIDO2")
            >>> # Отображает: "🔒 FIDO2"
            >>> statusbar.set_mfa_indicator("required")
            >>> # Отображает: "⚠️ MFA"
            >>> statusbar.set_mfa_indicator("none")
            >>> # Отображает: "✓"
        """
        self._mfa_status = status.lower()
        self._mfa_method = method
        self._update_mfa_label()
        self._update_mfa_tooltip()

    def get_mfa_status(self) -> str:
        """Возвращает статус MFA.

        Returns:
            Текущий статус MFA ("active", "required", или "none").

        Example:
            >>> statusbar.set_mfa_indicator("active", "FIDO2")
            >>> statusbar.get_mfa_status()
            'active'
        """
        return self._mfa_status

    # Workflow indicator methods

    def set_workflow_status(self, status: "FormStatus") -> None:
        """Устанавливает индикатор workflow статуса.

        Args:
            status: Текущий статус документа (FormStatus).

        Example:
            >>> from src.documents.constructor.form_status import FormStatus
            >>> statusbar.set_workflow_status(FormStatus.FILLED)
            >>> # Отображает: синяя точка + "Заполнена"
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

        Отображает визуальную шкалу: DRAFT ●──▶ FILLED ○──▶ VALIDATED ○──▶ APPROVED ○──▶ SIGNED ○
        Текущий статус выделен цветом ●, пройденные ─▶, будущие ○──▶.

        Args:
            status: Текущий статус документа (FormStatus).

        Example:
            >>> from src.documents.constructor.form_status import FormStatus
            >>> statusbar.set_workflow_timeline(FormStatus.FILLED)
            >>> # Отображает: [DRAFT ●──▶ FILLED ●──▶ VALIDATED ○──▶ APPROVED ○──▶ SIGNED ○]
        """
        self._current_workflow_status = status.value
        self._update_workflow_timeline()

    def set_role_badge(self, role: WorkflowRole) -> None:
        """Устанавливает role badge индикатор.

        Отображает текущую роль с цветом и иконкой.
        Цвета не зависят от темы: 🔵 OPERATOR / 🟢 EDITOR / 🟠 SUPERVISOR / 🔴 SIGNATORY.

        Args:
            role: Текущая роль пользователя.

        Example:
            >>> from src.gui.workflow.role_badge import WorkflowRole
            >>> statusbar.set_role_badge(WorkflowRole.OPERATOR)
            >>> # Отображает: 🔵 OPERATOR (синий)
        """
        self._current_role = role
        self._update_role_badge()

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт фактический Tkinter виджет.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный корневой Frame StatusBar.
        """
        # Root frame
        self._tk_frame = tk.Frame(
            parent,
            height=STATUSBAR_HEIGHT,
            bg=DEFAULT_BG,
            relief="sunken",
            bd=1,
        )
        self._tk_frame.pack_propagate(False)

        # Inner frame for content
        self._tk_inner_frame = tk.Frame(self._tk_frame, bg=DEFAULT_BG)
        self._tk_inner_frame.pack(fill="both", expand=True, padx=PADDING_SMALL)

        # Create all indicator labels
        # Left side indicators
        self._tk_cursor_label = self._create_indicator(self._tk_inner_frame, "Ln 1, Col 1")
        self._tk_cpi_label = self._create_indicator(self._tk_inner_frame, "10 CPI")
        self._tk_codepage_label = self._create_indicator(self._tk_inner_frame, "PC866")
        self._tk_paper_label = self._create_indicator(self._tk_inner_frame, "A4")

        # Mode and MFA indicators (new)
        self._tk_mode_label = self._create_indicator(self._tk_inner_frame, "🟢 Normal")
        self._tk_mfa_label = self._create_indicator(self._tk_inner_frame, "✓")

        # Workflow indicator (new) - создан через отдельный компонент
        if self._workflow_status is not None:
            self._workflow_indicator = WorkflowIndicator(
                parent=self._tk_inner_frame,
                current_status=self._workflow_status,
                on_click=self._workflow_callback,
            )
            self._workflow_indicator.mount(self._tk_inner_frame)

        # Workflow Timeline widget
        self._workflow_timeline_frame = tk.Frame(self._tk_inner_frame, bg=DEFAULT_BG)
        self._workflow_timeline_label = tk.Label(
            self._workflow_timeline_frame,
            text="",
            bg=DEFAULT_BG,
            fg=DEFAULT_FG,
            font=("TkDefaultFont", 9),
        )
        self._workflow_timeline_label.pack(side=tk.LEFT)
        self._workflow_timeline_frame.pack(side=tk.LEFT, padx=(0, PADDING_SMALL))
        self._workflow_timeline_frame.bind("<Button-1>", self._on_workflow_timeline_click)
        self._workflow_timeline_label.bind("<Button-1>", self._on_workflow_timeline_click)
        self._workflow_timeline_frame.config(cursor="hand2")
        self._workflow_timeline_label.config(cursor="hand2")

        # Role Badge widget
        self._role_badge = RoleBadge(
            parent=self._tk_inner_frame,
            current_role=self._current_role,
        )
        self._role_badge.mount(self._tk_inner_frame)

        # Right side indicators
        self._tk_security_label = self._create_indicator(self._tk_inner_frame, "🔒 Standard")
        self._tk_page_label = self._create_indicator(self._tk_inner_frame, "Page 1/1")
        self._tk_zoom_label = self._create_indicator(self._tk_inner_frame, "100%")

        # Notification indicator [n]
        self._tk_notification_label = self._create_indicator(self._tk_inner_frame, "")
        self._update_notification_label()

        # Create separator labels
        self._create_separators()

        # Setup bindings
        self._setup_bindings()

        # Initial layout
        self._apply_layout()

        # Initial updates
        self._update_mode_label()
        self._update_mfa_label()
        self._update_mode_tooltip()
        self._update_mfa_tooltip()

        # Bind to resize events
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
            bg=DEFAULT_BG,
            fg=DEFAULT_FG,
            font=("TkDefaultFont", 9),
            padx=PADDING_SMALL,
        )
        return label

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

        # Cleanup separator labels
        self._separator_labels.clear()

        # Cleanup workflow indicator
        if self._workflow_indicator is not None:
            if self._workflow_indicator.is_mounted():
                self._workflow_indicator.unmount()
            self._workflow_indicator = None

        # Cleanup workflow timeline
        self._workflow_timeline_frame = None
        self._workflow_timeline_label = None

        # Cleanup role badge
        if self._role_badge is not None:
            if self._role_badge.is_mounted():
                self._role_badge.unmount()
            self._role_badge = None

        # Cleanup row2 frame
        if hasattr(self, "_row2_frame"):
            self._row2_frame = None

        # Cleanup toast panel
        if self._toast_panel is not None:
            self._toast_panel.hide()
            self._toast_panel = None

        # Cancel pending hide timer
        if self._hide_after_id is not None and self._tk_frame is not None:
            self._tk_frame.after_cancel(self._hide_after_id)
            self._hide_after_id = None

        # Unregister from notification service
        if self._notification_service is not None:
            self._notification_service.unregister_badge_callback(
                self._on_notification_count_changed
            )
            self._notification_service = None

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

        # Clear current layout
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

        # Unpack workflow indicator if exists
        if self._workflow_indicator is not None and self._workflow_indicator.widget is not None:
            self._workflow_indicator.widget.pack_forget()

        # Unpack workflow timeline
        if self._workflow_timeline_frame is not None:
            self._workflow_timeline_frame.pack_forget()

        # Unpack role badge
        if self._role_badge is not None and self._role_badge.widget is not None:
            self._role_badge.widget.pack_forget()

        # Unpack row2 frame if exists
        if hasattr(self, "_row2_frame") and self._row2_frame is not None:
            self._row2_frame.pack_forget()

        # Unpack separators
        for sep in self._separator_labels:
            sep.pack_forget()

        if self._is_double_row:
            self._apply_double_row_layout()
        else:
            self._apply_single_row_layout()

    def _create_separators(self) -> None:
        """Создаёт разделительные метки │ между индикаторами."""
        if self._tk_inner_frame is None:
            return

        # Create separator labels (we'll need about 8-10 separators)
        for _ in range(10):
            sep = tk.Label(
                self._tk_inner_frame,
                text="│",
                bg=DEFAULT_BG,
                fg="#999999",
                font=("TkDefaultFont", 9),
            )
            self._separator_labels.append(sep)

    def _update_notification_label(self) -> None:
        """Обновляет индикатор уведомлений [n]."""
        if self._tk_notification_label is None:
            return

        if self._notification_count > 0:
            text = f"[{self._notification_count}]"
            self._tk_notification_label.config(
                text=text,
                fg=NOTIFICATION_ACTIVE_COLOR,  # Orange when n > 0
            )
        else:
            self._tk_notification_label.config(
                text="[0]",
                fg=NOTIFICATION_INACTIVE_COLOR,  # Gray when n = 0
            )

    def set_notification_count(self, count: int) -> None:
        """Устанавливает количество уведомлений.

        Args:
            count: Количество непрочитанных уведомлений.

        Example:
            >>> statusbar.set_notification_count(3)
            >>> # Отображает: "[3]" (оранжевый цвет)
            >>> statusbar.set_notification_count(0)
            >>> # Отображает: "[0]" (серый цвет)
        """
        self._notification_count = max(0, count)
        self._update_notification_label()

    def show_toast_panel(self) -> None:
        """Показывает Toast Panel с уведомлениями.

        Создаёт и отображает плавающую панель с последними
        уведомлениями рядом с индикатором [n].

        Example:
            >>> statusbar.show_toast_panel()
            >>> # Панель появляется над индикатором уведомлений
        """
        if self._tk_notification_label is None:
            return

        # Cancel any pending hide
        if self._hide_after_id is not None:
            if self._tk_frame is not None:
                self._tk_frame.after_cancel(self._hide_after_id)
            self._hide_after_id = None

        # Create toast panel if needed
        if self._toast_panel is None and self._tk_frame is not None:
            self._toast_panel = ToastPanel(self._tk_frame)

        # Show panel near notification label
        if self._toast_panel is not None:
            self._toast_panel.show_near_widget(self._tk_notification_label)

            # Update with current notifications from service
            if self._notification_service is not None:
                notifications = self._notification_service.get_history(unread_only=True)
                self._toast_panel.update_notifications(notifications)

        self._toast_panel_visible = True

    def hide_toast_panel(self) -> None:
        """Скрывает Toast Panel.

        Example:
            >>> statusbar.hide_toast_panel()
            >>> # Панель скрыта
        """
        # Cancel any pending hide
        if self._hide_after_id is not None:
            if self._tk_frame is not None:
                self._tk_frame.after_cancel(self._hide_after_id)
            self._hide_after_id = None

        if self._toast_panel is not None:
            self._toast_panel.hide()

        self._toast_panel_visible = False

    def _schedule_hide_toast_panel(self) -> None:
        """Запускает таймер для auto-hide панели.

        Панель будет скрыта через TOAST_PANEL_AUTO_HIDE_MS (3 секунды).
        """
        if self._tk_frame is None:
            return

        # Cancel existing timer
        if self._hide_after_id is not None:
            self._tk_frame.after_cancel(self._hide_after_id)

        # Schedule new hide
        self._hide_after_id = self._tk_frame.after(
            TOAST_PANEL_AUTO_HIDE_MS,
            self._do_hide_toast_panel,
        )

    def _do_hide_toast_panel(self) -> None:
        """Выполняет фактическое скрытие панели."""
        self._hide_after_id = None
        self.hide_toast_panel()

    def _on_notification_count_changed(self, count: int) -> None:
        """Обработчик изменения количества уведомлений.

        Вызывается NotificationService при изменении badge count.

        Args:
            count: Новое количество непрочитанных уведомлений.

        Example:
            >>> # Callback для NotificationService.register_badge_callback()
            >>> notification_service.register_badge_callback(
            ...     statusbar._on_notification_count_changed
            ... )
        """
        self.set_notification_count(count)

        # Update toast panel if visible
        if self._toast_panel_visible and self._toast_panel is not None:
            if self._notification_service is not None:
                notifications = self._notification_service.get_history(unread_only=True)
                self._toast_panel.update_notifications(notifications)

    def _on_notification_enter(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает mouse enter на индикаторе уведомлений.

        Args:
            event: Событие mouse enter.
        """
        # Cancel any pending hide
        if self._hide_after_id is not None:
            if self._tk_frame is not None:
                self._tk_frame.after_cancel(self._hide_after_id)
            self._hide_after_id = None

        # Show toast panel
        self.show_toast_panel()

    def _on_notification_leave(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает mouse leave на индикаторе уведомлений.

        Запускает таймер для auto-hide через 3 секунды.

        Args:
            event: Событие mouse leave.
        """
        self._schedule_hide_toast_panel()

    def set_notification_service(self, service: "NotificationService") -> None:
        """Устанавливает NotificationService для интеграции.

        Регистрирует callback для обновления badge count.

        Args:
            service: Сервис уведомлений.

        Example:
            >>> from src.gui.services.notification_service import NotificationService
            >>> service = NotificationService(root, window_manager)
            >>> statusbar.set_notification_service(service)
        """
        self._notification_service = service
        service.register_badge_callback(self._on_notification_count_changed)

        # Get initial count
        initial_count = service.get_unread_count()
        self.set_notification_count(initial_count)

    def _apply_single_row_layout(self) -> None:
        """Применяет single row layout (все индикаторы в одну строку)."""
        if self._tk_inner_frame is None:
            return

        sep_index = 0

        def pack_sep() -> None:
            """Добавляет разделитель между индикаторами."""
            nonlocal sep_index
            if sep_index < len(self._separator_labels):
                self._separator_labels[sep_index].pack(side="left")
                sep_index += 1

        # Left side: cursor, cpi, codepage, paper, mode, mfa
        widgets_left = [
            self._tk_cursor_label,
            self._tk_cpi_label,
            self._tk_codepage_label,
            self._tk_paper_label,
            self._tk_mode_label,
            self._tk_mfa_label,
        ]
        for i, widget in enumerate(widgets_left):
            if widget is not None:
                if i > 0:
                    pack_sep()
                widget.pack(side="left", padx=(0, PADDING_SMALL))

        # Separator before workflow section
        pack_sep()

        # Workflow Timeline (clickable)
        if self._workflow_timeline_frame is not None:
            self._workflow_timeline_frame.pack(side="left", padx=(0, PADDING_SMALL))

        # Role Badge
        if self._role_badge is not None and self._role_badge.widget is not None:
            pack_sep()
            self._role_badge.widget.pack(side="left", padx=(0, PADDING_SMALL))

        # Separator before right side
        pack_sep()

        # Right side: security, page, zoom, notification (reversed order for side="right")
        widgets_right = [
            self._tk_notification_label,
            self._tk_zoom_label,
            self._tk_page_label,
            self._tk_security_label,
        ]
        for widget in widgets_right:
            if widget is not None:
                widget.pack(side="right", padx=(PADDING_SMALL, 0))

    def _apply_double_row_layout(self) -> None:
        """Применяет double row layout (две строки индикаторов).

        Row 1: cursor, cpi, codepage, paper, mode, mfa, │ security
        Row 2: [workflow timeline] │ role_badge │ page, zoom, notification
        """
        if self._tk_inner_frame is None:
            return

        sep_index = 0

        def pack_sep() -> None:
            """Добавляет разделитель между индикаторами."""
            nonlocal sep_index
            if sep_index < len(self._separator_labels):
                self._separator_labels[sep_index].pack(side="left")
                sep_index += 1

        # Row 1: Left side indicators + security
        widgets_row1 = [
            self._tk_cursor_label,
            self._tk_cpi_label,
            self._tk_codepage_label,
            self._tk_paper_label,
            self._tk_mode_label,
            self._tk_mfa_label,
        ]
        for i, widget in enumerate(widgets_row1):
            if widget is not None:
                if i > 0:
                    pack_sep()
                widget.pack(side="left", padx=(0, PADDING_SMALL))

        # Separator before security (right side)
        pack_sep()

        # Security on right
        if self._tk_security_label is not None:
            self._tk_security_label.pack(side="right", padx=(PADDING_SMALL, 0))

        # Row 2: Workflow Timeline + Role Badge + Page/Zoom/Notification
        # First unpack row 1 widgets from right side to allow row 2 to flow below
        # Actually, we need a second inner frame for row 2

        # Create a frame for row 2 if not exists
        if not hasattr(self, "_row2_frame") or self._row2_frame is None:
            self._row2_frame = tk.Frame(self._tk_inner_frame, bg=DEFAULT_BG)
            self._row2_frame.pack(fill="x", side=tk.BOTTOM, pady=(2, 0))

        # Clear row 2
        for widget in self._row2_frame.winfo_children():
            widget.pack_forget()

        # Row 2 left: Workflow Timeline
        if self._workflow_timeline_frame is not None:
            self._workflow_timeline_frame.pack(side=tk.LEFT, padx=(0, PADDING_SMALL))

        # Separator
        if sep_index < len(self._separator_labels):
            self._separator_labels[sep_index].pack(side=tk.LEFT)
            sep_index += 1

        # Role Badge
        if self._role_badge is not None and self._role_badge.widget is not None:
            self._role_badge.widget.pack(side=tk.LEFT, padx=(0, PADDING_SMALL))

        # Separator
        if sep_index < len(self._separator_labels):
            self._separator_labels[sep_index].pack(side=tk.LEFT)
            sep_index += 1

        # Row 2 right: Page, Zoom, Notification
        widgets_row2_right = [
            self._tk_page_label,
            self._tk_zoom_label,
            self._tk_notification_label,
        ]
        for widget in widgets_row2_right:
            if widget is not None:
                widget.pack(side=tk.RIGHT, padx=(PADDING_SMALL, 0))

    def _update_cursor_label(self) -> None:
        """Обновляет индикатор позиции курсора."""
        if self._tk_cursor_label is None:
            return

        text = f"Ln {self._line}, Col {self._column}"
        self._tk_cursor_label.config(text=text)

        # Apply modified color if modified
        if self._modified:
            self._tk_cursor_label.config(fg=MODIFIED_COLOR)
        else:
            self._tk_cursor_label.config(fg=DEFAULT_FG)

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

        self._tk_mode_label.config(text=self._tk_mode_label.cget("text"))
        # Store tooltip in widget attribute for external tooltip handler
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
        else:  # none
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

        # Store tooltip in widget attribute for external tooltip handler
        self._tk_mfa_label.tooltip_text = tooltip  # type: ignore[attr-defined]

    def _update_security_label(self) -> None:
        """Обновляет индикатор пресета безопасности."""
        if self._tk_security_label is None:
            return

        text = f"🔒 {self._security_preset}"
        self._tk_security_label.config(text=text)

        # Apply color based on preset
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

        statuses = ["draft", "filled", "validated", "approved", "signed"]
        current = self._current_workflow_status.lower()

        if current not in statuses:
            current = "draft"

        color = TIMELINE_COLORS.get(current, "#95a5a6")
        timeline_text = f"[{current.upper()} {TIMELINE_CURRENT_MARKER}──▶]"

        self._workflow_timeline_label.config(text=timeline_text, fg=color)

    def _update_role_badge(self) -> None:
        """Обновляет role badge визуализацию."""
        if self._role_badge is None:
            return

        self._role_badge.set_role(self._current_role)

    def _on_workflow_timeline_click(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает клик на workflow timeline.

        Args:
            event: Событие клика.
        """
        if self._workflow_callback is not None:
            self._workflow_callback()

    def _on_paper_double_click(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает double-click на индикаторе бумаги.

        Args:
            event: Событие double-click.
        """
        if self._paper_callback is not None:
            self._paper_callback()

    def _on_mode_double_click(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает double-click на индикаторе режима.

        Args:
            event: Событие double-click.
        """
        if self._mode_callback is not None:
            self._mode_callback()


# Stub для PaperSetupDialog (документация)
class PaperSetupDialog:
    """Stub для диалога настройки бумаги.

    Реальный диалог должен быть реализован в модуле dialogs.
    Вызывается при double-click на индикаторе бумаги.

    Example:
        >>> dialog = PaperSetupDialog()
        >>> dialog.show()
    """

    def show(self) -> None:
        """Показывает диалог."""
        pass


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
]
