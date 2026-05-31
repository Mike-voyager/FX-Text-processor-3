"""Диалог Workflow Timeline для FX Text Processor 3.

Предоставляет визуальную шкалу состояний документа и историю переходов
с детализацией: таймстампы, роли, MFA статус.

Phase 6 GUI components:
- WorkflowTimelineDialog: модальный диалог с timeline и историей
- CommentsViewerDialog: просмотр комментариев к документу

Workflow States:
    DRAFT → FILLED → VALIDATED → APPROVED → SIGNED → ARCHIVED

Example:
    >>> from uuid import uuid4
    >>> from src.controller.workflow_controller import WorkflowController
    >>> controller = WorkflowController(auth_controller=None)
    >>> dialog = WorkflowTimelineDialog(
    ...     parent=root,
    ...     document_id=uuid4(),
    ...     workflow_controller=controller,
    ... )
    >>> dialog.show()

Module: src/gui/dialogs/workflow_timeline_dialog.py
"""

from __future__ import annotations

import logging
import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING, Any, Dict, Final, List, Optional, Tuple, cast
from uuid import UUID

from src.gui.dialogs.base_dialog import BaseDialog

if TYPE_CHECKING:
    from src.controller.workflow_controller import (
        FieldComment,
        FormStatus,
        WorkflowController,
        WorkflowEvent,
    )

logger: Final = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

DIALOG_WIDTH: Final[int] = 700
DIALOG_HEIGHT: Final[int] = 580

COLOR_DRAFT: Final[str] = "#95a5a6"
COLOR_FILLED: Final[str] = "#3498db"
COLOR_VALIDATED: Final[str] = "#f39c12"
COLOR_APPROVED: Final[str] = "#9b59b6"
COLOR_SIGNED: Final[str] = "#27ae60"
COLOR_ARCHIVED: Final[str] = "#2c3e50"
COLOR_REJECTED: Final[str] = "#e74c3c"
COLOR_CURRENT: Final[str] = "#2980b9"
COLOR_CONNECTOR: Final[str] = "#bdc3c7"

COLOR_MFA_VERIFIED: Final[str] = "#27ae60"
COLOR_MFA_PENDING: Final[str] = "#f39c12"

STATUS_CIRCLE_SIZE: Final[int] = 40
CONNECTOR_HEIGHT: Final[int] = 4
PADDING_SMALL: Final[int] = 5
PADDING_NORMAL: Final[int] = 10
PADDING_LARGE: Final[int] = 15

STATUS_ORDER: Final[List[str]] = [
    "draft",
    "filled",
    "validated",
    "approved",
    "signed",
    "archived",
]

SIMPLE_MODE_STATUSES: Final[List[str]] = [
    "draft",
    "signed",
]

# =============================================================================
# CommentsViewerDialog
# =============================================================================


class CommentsViewerDialog(BaseDialog):
    """Диалог просмотра комментариев к документу.

    Attributes:
        parent: Родительский виджет.
        comments: Список комментариев для отображения.
    """

    def __init__(
        self,
        parent: tk.Widget,
        comments: List["FieldComment"],
        document_id: UUID,
    ) -> None:
        """Инициализация диалога просмотра комментариев.

        Args:
            parent: Родительский виджет.
            comments: Список комментариев.
            document_id: ID документа.
        """
        super().__init__(parent)

        self._parent = parent
        self._comments = comments
        self._document_id = document_id

        self.title("📋 Document Comments")
        self.resizable(True, True)

        self._create_ui()

    def _center_window(self) -> None:
        """Центрирует окно относительно родительского."""
        self.update_idletasks()

        parent = self._parent
        parent_x = parent.winfo_rootx() if hasattr(parent, "winfo_rootx") else 0
        parent_y = parent.winfo_rooty() if hasattr(parent, "winfo_rooty") else 0
        parent_width = parent.winfo_width() if hasattr(parent, "winfo_width") else 800
        parent_height = parent.winfo_height() if hasattr(parent, "winfo_height") else 600

        width = 600
        height = 400

        x = parent_x + (parent_width - width) // 2
        y = parent_y + (parent_height - height) // 2

        self.geometry(f"{width}x{height}+{x}+{y}")

    def _create_ui(self) -> None:
        """Создаёт пользовательский интерфейс."""
        main_frame = tk.Frame(self, padx=PADDING_NORMAL, pady=PADDING_NORMAL)
        main_frame.pack(fill=tk.BOTH, expand=True)

        header = tk.Label(
            main_frame,
            text="Document Comments",
            font=("Arial", 12, "bold"),
        )
        header.pack(anchor=tk.W, pady=(0, PADDING_NORMAL))

        doc_label = tk.Label(
            main_frame,
            text=f"Document: {self._document_id}",
            font=("Arial", 9),
            fg="#7f8c8d",
        )
        doc_label.pack(anchor=tk.W, pady=(0, PADDING_NORMAL))

        tree_frame = tk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("field", "text", "author", "severity", "created", "status")
        self._tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        self._tree.heading("field", text="Field")
        self._tree.heading("text", text="Comment")
        self._tree.heading("author", text="Author")
        self._tree.heading("severity", text="Severity")
        self._tree.heading("created", text="Time")
        self._tree.heading("status", text="Status")

        self._tree.column("field", width=80, anchor=tk.W)
        self._tree.column("text", width=250, anchor=tk.W)
        self._tree.column("author", width=80, anchor=tk.CENTER)
        self._tree.column("severity", width=70, anchor=tk.CENTER)
        self._tree.column("created", width=120, anchor=tk.CENTER)
        self._tree.column("status", width=70, anchor=tk.CENTER)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=scrollbar.set)

        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._populate_comments()

        btn_frame = tk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(PADDING_NORMAL, 0))

        tk.Frame(btn_frame).pack(side=tk.LEFT, fill=tk.X, expand=True)

        close_btn = tk.Button(
            btn_frame,
            text="Close",
            width=12,
            command=self._on_close,
        )
        close_btn.pack(side=tk.RIGHT)

    def _populate_comments(self) -> None:
        """Заполняет дерево комментариев."""
        if not self._comments:
            self._tree.insert(
                "",
                tk.END,
                values=("—", "No comments", "—", "—", "—", "—"),
            )
            return

        for comment in self._comments:
            severity_text = {
                "info": "Info",
                "warning": "Warning",
                "error": "Error",
            }.get(
                comment.severity.value
                if hasattr(comment.severity, "value")
                else str(comment.severity),
                "—",
            )

            status_text = "Resolved" if comment.resolved else "Open"

            created_str = (
                comment.created_at.strftime("%Y-%m-%d %H:%M")
                if hasattr(comment.created_at, "strftime")
                else str(comment.created_at)
            )

            self._tree.insert(
                "",
                tk.END,
                values=(
                    comment.field_id,
                    comment.text[:50] + "..." if len(comment.text) > 50 else comment.text,
                    comment.author_role.display_name
                    if hasattr(comment.author_role, "display_name")
                    else str(comment.author_role),
                    severity_text,
                    created_str,
                    status_text,
                ),
            )

    def _on_close(self) -> None:
        """Обрабатывает закрытие диалога."""
        self.destroy()


# =============================================================================
# WorkflowTimelineDialog
# =============================================================================


class WorkflowTimelineDialog(BaseDialog):
    """Диалог отображения Workflow Timeline и истории переходов.

    Attributes:
        parent: Родительский виджет.
        document_id: ID документа для отображения.
        workflow_controller: Контроллер workflow для получения данных.
        _status_widgets: Виджеты состояний timeline.
        _history_tree: Treeview для истории событий.
        _simple_mode: Режим отображения (только DRAFT ↔ SIGNED).

    Example:
        >>> dialog = WorkflowTimelineDialog(root, doc_id, controller)
        >>> dialog.show()
    """

    def __init__(
        self,
        parent: tk.Widget,
        document_id: UUID,
        workflow_controller: "WorkflowController",
    ) -> None:
        """Инициализация диалога Workflow Timeline.

        Args:
            parent: Родительский виджет.
            document_id: Идентификатор документа.
            workflow_controller: Контроллер workflow.
        """
        super().__init__(parent)

        self._parent: tk.Widget = parent
        self._document_id: UUID = document_id
        self._workflow_controller: "WorkflowController" = workflow_controller

        self._status_widgets: Dict[str, Dict[str, tk.Widget]] = {}
        self._history_tree: Optional[ttk.Treeview] = None
        self._details_text: Optional[tk.Text] = None
        self._simple_mode_var: tk.BooleanVar = tk.BooleanVar(master=self, value=False)
        self._timestamp_labels: Dict[str, tk.Label] = {}

        self.title("Document Workflow")
        self.resizable(False, False)

        self._create_ui()
        self._load_workflow_data()

    def _center_window(self) -> None:
        """Центрирует окно относительно родительского."""
        self.update_idletasks()

        parent = self._parent
        parent_x = parent.winfo_rootx() if hasattr(parent, "winfo_rootx") else 0
        parent_y = parent.winfo_rooty() if hasattr(parent, "winfo_rooty") else 0
        parent_width = parent.winfo_width() if hasattr(parent, "winfo_width") else 800
        parent_height = parent.winfo_height() if hasattr(parent, "winfo_height") else 600

        x = parent_x + (parent_width - DIALOG_WIDTH) // 2
        y = parent_y + (parent_height - DIALOG_HEIGHT) // 2

        self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}+{x}+{y}")

    def _create_ui(self) -> None:
        """Создаёт пользовательский интерфейс диалога."""
        main_frame = tk.Frame(self, padx=PADDING_NORMAL, pady=PADDING_NORMAL)
        main_frame.pack(fill=tk.BOTH, expand=True)

        self._create_header(main_frame)
        self._create_timeline(main_frame)
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=PADDING_SMALL)
        self._create_history_list(main_frame)
        self._create_details_panel(main_frame)
        self._create_buttons(main_frame)

    def _create_header(self, parent: tk.Widget) -> None:
        """Создаёт заголовок диалога.

        Args:
            parent: Родительский виджет.
        """
        header_frame = tk.Frame(parent)
        header_frame.pack(fill=tk.X, pady=(0, PADDING_NORMAL))

        title_frame = tk.Frame(header_frame)
        title_frame.pack(fill=tk.X)

        tk.Label(
            title_frame,
            text="📋 Workflow History",
            font=("Arial", 14, "bold"),
        ).pack(anchor=tk.W)

        simple_check = tk.Checkbutton(
            title_frame,
            text="Simple Mode (DRAFT ↔ SIGNED)",
            variable=self._simple_mode_var,
            command=self._on_simple_mode_toggle,
            font=("Arial", 9),
        )
        simple_check.pack(anchor=tk.W, pady=(PADDING_SMALL, 0))

        tk.Label(
            header_frame,
            text=f"Document: {self._document_id}",
            font=("Arial", 9),
            fg="#7f8c8d",
        ).pack(anchor=tk.W, pady=(PADDING_SMALL, 0))

        self._current_status_label = tk.Label(
            header_frame,
            text="Current status: —",
            font=("Arial", 10, "bold"),
            fg=COLOR_DRAFT,
        )
        self._current_status_label.pack(anchor=tk.W, pady=(PADDING_SMALL, 0))

    def _on_simple_mode_toggle(self) -> None:
        """Обрабатывает переключение Simple Mode."""
        self._update_timeline_visibility()

    def _update_timeline_visibility(self) -> None:
        """Обновляет видимость состояний в timeline."""
        simple_mode = self._simple_mode_var.get()
        visible_statuses = SIMPLE_MODE_STATUSES if simple_mode else STATUS_ORDER

        for status_code, widgets in self._status_widgets.items():
            frame = cast(tk.Frame, widgets["frame"])
            if status_code in visible_statuses:
                frame.grid()
            else:
                frame.grid_remove()

    def _create_timeline(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт визуальную шкалу состояний workflow.

        Args:
            parent: Родительский виджет.

        Returns:
            Фрейм с timeline.
        """
        frame = tk.LabelFrame(
            parent,
            text="Status Timeline",
            padx=PADDING_NORMAL,
            pady=PADDING_NORMAL,
        )

        timeline_container = tk.Frame(frame)
        timeline_container.pack(fill=tk.X, expand=True)

        statuses: List[Tuple[str, str, str]] = [
            ("draft", "Draft", COLOR_DRAFT),
            ("filled", "Filled", COLOR_FILLED),
            ("validated", "Validated", COLOR_VALIDATED),
            ("approved", "Approved", COLOR_APPROVED),
            ("signed", "Signed", COLOR_SIGNED),
            ("archived", "Archived", COLOR_ARCHIVED),
        ]

        for idx, (status_code, label, color) in enumerate(statuses):
            status_frame = tk.Frame(timeline_container, width=100, height=80)
            status_frame.grid(row=0, column=idx, sticky="nsew")
            status_frame.grid_propagate(False)

            circle_canvas = tk.Canvas(
                status_frame,
                width=STATUS_CIRCLE_SIZE,
                height=STATUS_CIRCLE_SIZE,
                highlightthickness=0,
            )
            circle_canvas.pack(pady=(5, 0))

            padding = 3
            circle_canvas.create_oval(
                padding,
                padding,
                STATUS_CIRCLE_SIZE - padding,
                STATUS_CIRCLE_SIZE - padding,
                fill=color,
                outline="",
                tags=("circle",),
            )

            label_widget = tk.Label(
                status_frame,
                text=label,
                font=("Arial", 9),
                fg="#7f8c8d",
            )
            label_widget.pack(pady=(2, 0))

            timestamp_label = tk.Label(
                status_frame,
                text="",
                font=("Arial", 8),
                fg="#7f8c8d",
            )
            timestamp_label.pack(pady=(2, 0))
            self._timestamp_labels[status_code] = timestamp_label

            widget_data: Dict[str, Any] = {
                "frame": status_frame,
                "canvas": circle_canvas,
                "label": label_widget,
                "color": color,
            }
            self._status_widgets[status_code] = widget_data

            if idx < len(statuses) - 1:
                connector = tk.Frame(
                    timeline_container,
                    height=CONNECTOR_HEIGHT,
                    bg=COLOR_CONNECTOR,
                )
                connector.grid(row=0, column=idx, sticky="e", padx=(0, 10))

        for col in range(len(statuses)):
            timeline_container.grid_columnconfigure(col, weight=1, uniform="status")

        return frame

    def _create_history_list(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт список событий истории workflow.

        Args:
            parent: Родительский виджет.

        Returns:
            Фрейм со списком истории.
        """
        frame = tk.LabelFrame(
            parent,
            text="Transition History",
            padx=PADDING_NORMAL,
            pady=PADDING_NORMAL,
        )

        tree_frame = tk.Frame(frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("timestamp", "transition", "role", "mfa", "reason")
        self._history_tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
            height=6,
        )

        self._history_tree.heading("timestamp", text="Time")
        self._history_tree.heading("transition", text="Transition")
        self._history_tree.heading("role", text="Role")
        self._history_tree.heading("mfa", text="MFA")
        self._history_tree.heading("reason", text="Reason")

        self._history_tree.column("timestamp", width=130, anchor=tk.CENTER)
        self._history_tree.column("transition", width=140, anchor=tk.CENTER)
        self._history_tree.column("role", width=100, anchor=tk.CENTER)
        self._history_tree.column("mfa", width=60, anchor=tk.CENTER)
        self._history_tree.column("reason", width=200, anchor=tk.W)

        scrollbar = ttk.Scrollbar(
            tree_frame,
            orient=tk.VERTICAL,
            command=self._history_tree.yview,
        )
        self._history_tree.configure(yscrollcommand=scrollbar.set)

        self._history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._history_tree.bind("<<TreeviewSelect>>", self._on_history_select)

        return frame

    def _create_details_panel(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт панель деталей выбранного события.

        Args:
            parent: Родительский виджет.

        Returns:
            Фрейм с деталями.
        """
        frame = tk.LabelFrame(
            parent,
            text="Event Details",
            padx=PADDING_NORMAL,
            pady=PADDING_NORMAL,
        )

        self._details_text = tk.Text(
            frame,
            wrap=tk.WORD,
            height=3,
            font=("Consolas", 9),
            state=tk.DISABLED,
            bg="#f8f9fa",
            padx=PADDING_SMALL,
            pady=PADDING_SMALL,
        )
        self._details_text.pack(fill=tk.BOTH, expand=True)

        return frame

    def _create_buttons(self, parent: tk.Widget) -> None:
        """Создаёт кнопки диалога.

        Args:
            parent: Родительский виджет.
        """
        btn_frame = tk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=(PADDING_NORMAL, 0))

        tk.Frame(btn_frame).pack(side=tk.LEFT, fill=tk.X, expand=True)

        self._comments_btn = tk.Button(
            btn_frame,
            text="📋 View Comments",
            width=15,
            command=self._on_view_comments,
        )
        self._comments_btn.pack(side=tk.RIGHT, padx=(0, PADDING_SMALL))

        self._refresh_btn = tk.Button(
            btn_frame,
            text="🔄 Refresh",
            width=12,
            command=self._load_workflow_data,
        )
        self._refresh_btn.pack(side=tk.RIGHT, padx=(0, PADDING_SMALL))

        close_btn = tk.Button(
            btn_frame,
            text="Close",
            width=12,
            command=self._on_close,
        )
        close_btn.pack(side=tk.RIGHT)

    def _load_workflow_data(self) -> None:
        """Загружает и отображает данные workflow."""
        try:
            current_state = self._workflow_controller.get_current_state(self._document_id)
            self._update_timeline_highlight(current_state)
            self._update_status_label(current_state)
            self._update_timeline_timestamps()
            self._load_history()
        except (ValueError, AttributeError, RuntimeError, ImportError) as e:
            logger.exception("Error loading workflow data: %s", e)
            self._show_error("Failed to load workflow data")

    def _update_timeline_timestamps(self) -> None:
        """Обновляет таймстампы под состояниями в timeline."""
        history = self._workflow_controller.get_workflow_history(self._document_id)

        state_times: Dict[str, Any] = {}
        for event in history:
            to_state_val = (
                event.to_state.value if hasattr(event.to_state, "value") else str(event.to_state)
            )
            if to_state_val not in state_times:
                state_times[to_state_val] = event.timestamp

        for status_code, label in self._timestamp_labels.items():
            if status_code in state_times:
                ts = state_times[status_code]
                label.config(text=ts.strftime("%H:%M"))
            else:
                label.config(text="")

    def _update_timeline_highlight(self, current_state: "FormStatus") -> None:
        """Обновляет подсветку текущего состояния в timeline.

        Args:
            current_state: Текущее состояние документа.
        """
        state_value = current_state.value if hasattr(current_state, "value") else str(current_state)

        for status_code, widgets in self._status_widgets.items():
            canvas = cast(tk.Canvas, widgets["canvas"])
            label = cast(tk.Label, widgets["label"])

            canvas.delete("highlight")

            if status_code == state_value:
                canvas.create_oval(
                    0,
                    0,
                    STATUS_CIRCLE_SIZE,
                    STATUS_CIRCLE_SIZE,
                    outline=COLOR_CURRENT,
                    width=3,
                    tags=("highlight",),
                )
                label.config(fg=COLOR_CURRENT, font=("Arial", 9, "bold"))
            elif self._is_state_before(status_code, state_value):
                label.config(fg="#2c3e50", font=("Arial", 9))
            else:
                label.config(fg="#bdc3c7", font=("Arial", 9))

    def _update_status_label(self, current_state: "FormStatus") -> None:
        """Обновляет отображение текущего статуса.

        Args:
            current_state: Текущее состояние.
        """
        if self._current_status_label:
            status_text = (
                current_state.localized_name
                if hasattr(current_state, "localized_name")
                else str(current_state)
            )
            self._current_status_label.config(
                text=f"Current status: {status_text}",
                fg=self._get_status_color(current_state),
            )

    def _load_history(self) -> None:
        """Загружает и отображает историю событий."""
        if self._history_tree is None:
            return

        for item in self._history_tree.get_children():
            self._history_tree.delete(item)

        history = self._workflow_controller.get_workflow_history(self._document_id)

        if not history:
            self._history_tree.insert(
                "",
                tk.END,
                values=("—", "No data", "—", "—", "Document is in initial state"),
            )
            return

        for event in history:
            self._insert_event_row(event)

    def _insert_event_row(self, event: "WorkflowEvent") -> None:
        """Добавляет строку события в таблицу.

        Args:
            event: Событие workflow.
        """
        if self._history_tree is None:
            return

        timestamp_str = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")

        from_name = (
            event.from_state.localized_name
            if hasattr(event.from_state, "localized_name")
            else str(event.from_state)
        )
        to_name = (
            event.to_state.localized_name
            if hasattr(event.to_state, "localized_name")
            else str(event.to_state)
        )
        transition_str = f"{from_name} → {to_name}"

        mfa_str = "✓" if event.mfa_verified else "—"
        mfa_tag = "mfa_ok" if event.mfa_verified else "mfa_pending"

        role_str = (
            event.role.display_name if hasattr(event.role, "display_name") else str(event.role)
        )

        reason_str = event.reason if event.reason else "—"
        if len(reason_str) > 30:
            reason_str = reason_str[:27] + "..."

        self._history_tree.insert(
            "",
            tk.END,
            values=(timestamp_str, transition_str, role_str, mfa_str, reason_str),
            tags=(mfa_tag,),
        )

        self._history_tree.tag_configure("mfa_ok", foreground=COLOR_MFA_VERIFIED)
        self._history_tree.tag_configure("mfa_pending", foreground=COLOR_MFA_PENDING)

    def _on_history_select(self, event: tk.Event) -> None:  # noqa: ARG002
        """Обрабатывает выбор события в истории.

        Args:
            event: Событие выбора (unused).
        """
        if self._history_tree is None or self._details_text is None:
            return

        selection = self._history_tree.selection()
        if not selection:
            return

        item = selection[0]
        values = self._history_tree.item(item, "values")

        if not values or values[0] == "—":
            self._show_details("Select an event to view details")
            return

        history = self._workflow_controller.get_workflow_history(self._document_id)
        try:
            idx = self._history_tree.index(item)
            if 0 <= idx < len(history):
                event_data = history[idx]
                details = self._format_event_details(event_data)
                self._show_details(details)
            else:
                self._show_details(f"Event: {values[1]}\nRole: {values[2]}\nMFA: {values[3]}")
        except (ValueError, IndexError):
            self._show_details(f"Event: {values[1]}\nRole: {values[2]}\nMFA: {values[3]}")

    def _format_event_details(self, event: "WorkflowEvent") -> str:
        """Форматирует детали события для отображения.

        Args:
            event: Событие workflow.

        Returns:
            Отформатированная строка с деталями.
        """
        from_name = (
            event.from_state.localized_name
            if hasattr(event.from_state, "localized_name")
            else str(event.from_state)
        )
        to_name = (
            event.to_state.localized_name
            if hasattr(event.to_state, "localized_name")
            else str(event.to_state)
        )
        role_name = (
            event.role.display_name if hasattr(event.role, "display_name") else str(event.role)
        )

        lines = [
            f"Time:         {event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Transition:   {from_name} → {to_name}",
            f"Role:         {role_name}",
            f"MFA status:   {'Verified ✓' if event.mfa_verified else 'Not required'}",
        ]

        if event.reason:
            lines.append(f"Reason:       {event.reason}")

        lines.append(f"Event ID:     {event.event_id}")

        return "\n".join(lines)

    def _show_details(self, text: str) -> None:
        """Отображает текст в панели деталей.

        Args:
            text: Текст для отображения.
        """
        if self._details_text is None:
            return

        self._details_text.config(state=tk.NORMAL)
        self._details_text.delete("1.0", tk.END)
        self._details_text.insert("1.0", text)
        self._details_text.config(state=tk.DISABLED)

    def _on_view_comments(self) -> None:
        """Открывает диалог просмотра комментариев."""
        try:
            comments = self._workflow_controller.get_all_comments(self._document_id)
            dialog = CommentsViewerDialog(
                parent=cast(tk.Widget, self),
                comments=comments,
                document_id=self._document_id,
            )
            dialog.wait_window()
        except (ImportError, AttributeError, ValueError, RuntimeError) as e:
            logger.exception("Error opening comments: %s", e)

    def _is_state_before(self, status_code: str, current_code: str) -> bool:
        """Проверяет, находится ли состояние до текущего в последовательности.

        Args:
            status_code: Код проверяемого состояния.
            current_code: Код текущего состояния.

        Returns:
            True если status_code до current_code.
        """
        try:
            status_idx = STATUS_ORDER.index(status_code)
            current_idx = STATUS_ORDER.index(current_code)
            return status_idx < current_idx
        except ValueError:
            return False

    def _get_status_color(self, status: "FormStatus") -> str:
        """Возвращает цвет для состояния.

        Args:
            status: Состояние.

        Returns:
            HEX цвет.
        """
        status_val = status.value if hasattr(status, "value") else str(status)
        colors: Dict[str, str] = {
            "draft": COLOR_DRAFT,
            "filled": COLOR_FILLED,
            "validated": COLOR_VALIDATED,
            "approved": COLOR_APPROVED,
            "signed": COLOR_SIGNED,
            "archived": COLOR_ARCHIVED,
            "rejected": COLOR_REJECTED,
        }
        return colors.get(status_val, COLOR_DRAFT)

    def _show_error(self, message: str) -> None:
        """Отображает сообщение об ошибке.

        Args:
            message: Сообщение об ошибке.
        """
        if self._history_tree is not None:
            for item in self._history_tree.get_children():
                self._history_tree.delete(item)
            self._history_tree.insert(
                "",
                tk.END,
                values=("Error", message[:40], "", "", ""),
            )

    def _on_close(self) -> None:
        """Обрабатывает закрытие диалога."""
        self.destroy()

    def show(self) -> None:
        """Показывает диалог модально."""
        self.wait_window()

    def refresh(self) -> None:
        """Обновляет данные диалога."""
        self._load_workflow_data()


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "WorkflowTimelineDialog",
    "CommentsViewerDialog",
    "DIALOG_WIDTH",
    "DIALOG_HEIGHT",
    "COLOR_DRAFT",
    "COLOR_FILLED",
    "COLOR_VALIDATED",
    "COLOR_APPROVED",
    "COLOR_SIGNED",
    "COLOR_ARCHIVED",
    "COLOR_MFA_VERIFIED",
    "COLOR_MFA_PENDING",
]
