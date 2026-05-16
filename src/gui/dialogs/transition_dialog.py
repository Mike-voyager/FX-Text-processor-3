"""TransitionDialog — диалог подтверждения перехода состояния.

Предоставляет визуализацию перехода между состояниями workflow
с дополнительным подтверждением для критичных переходов
(например, в ARCHIVED).

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import TYPE_CHECKING, Any, Callable, Final, Optional

from src.gui.dialogs.base_dialog import BaseDialog

if TYPE_CHECKING:
    from src.controller.workflow_controller import FormStatus


# UI Constants
DIALOG_WIDTH: Final[int] = 500
DIALOG_HEIGHT: Final[int] = 450
MIN_DIALOG_WIDTH: Final[int] = 400
MIN_DIALOG_HEIGHT: Final[int] = 350

PADDING_LARGE: Final[int] = 20
PADDING_NORMAL: Final[int] = 10
PADDING_SMALL: Final[int] = 5

COLOR_BG: Final[str] = "#f8f9fa"
COLOR_WARNING_BG: Final[str] = "#fff3cd"
COLOR_WARNING_BORDER: Final[str] = "#ffc107"
COLOR_DANGER_BG: Final[str] = "#f8d7da"
COLOR_DANGER_BORDER: Final[str] = "#dc3545"
COLOR_TEXT: Final[str] = "#333333"


class TransitionDialog(BaseDialog):
    """Диалог подтверждения перехода состояния workflow.

    Предоставляет визуализацию перехода между состояниями с цветовой
    индикацией. Для переходов в ARCHIVED требует дополнительное
    текстовое подтверждение.

    Attributes:
        _from_state: Исходное состояние.
        _to_state: Целевое состояние.
        _requires_mfa: Требуется ли MFA.
        _is_archived: Переход в ARCHIVED.
        _result: Результат диалога.

    Example:
        >>> dialog = TransitionDialog(
        ...     parent=root,
        ...     from_state=FormStatus.DRAFT,
        ...     to_state=FormStatus.FILLED,
        ...     requires_mfa=False,
        ... )
        >>> result = dialog.show()
        >>> if result:
        ...     print(f"Confirmed with reason: {result['reason']}")
    """

    ARCHIVED_CONFIRMATION_TEXT: Final[str] = "ARCHIVE"

    def __init__(
        self,
        parent: tk.Widget,
        from_state: "FormStatus",
        to_state: "FormStatus",
        requires_mfa: bool = False,
        allowed_reasons: Optional[list[str]] = None,
        on_confirm: Optional[Callable[[str, bool], None]] = None,
        on_cancel: Optional[Callable[[], None]] = None,
    ) -> None:
        """Инициализация диалога.

        Args:
            parent: Родительский виджет.
            from_state: Исходное состояние.
            to_state: Целевое состояние.
            requires_mfa: Требуется ли MFA.
            allowed_reasons: Список предустановленных причин.
            on_confirm: Callback при подтверждении.
            on_cancel: Callback при отмене.
        """
        super().__init__(parent)

        self._parent = parent
        self._from_state = from_state
        self._to_state = to_state
        self._requires_mfa = requires_mfa
        self._allowed_reasons = allowed_reasons or []
        self._on_confirm = on_confirm
        self._on_cancel_callback = on_cancel

        # Check if this is ARCHIVED transition
        to_str = to_state.value if hasattr(to_state, "value") else str(to_state)
        self._is_archived = to_str == "archived"

        self._result: Optional[dict[str, Any]] = None

        self._setup_window()
        self._create_ui()

    def _setup_window(self) -> None:
        """Настраивает параметры окна."""
        (self._from_state.value if hasattr(self._from_state, "value") else str(self._from_state))
        (self._to_state.value if hasattr(self._to_state, "value") else str(self._to_state))

        title = "Confirm Transition"
        if self._is_archived:
            title = "⚠️ Archive Document"

        self.title(title)
        self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}")
        self.minsize(MIN_DIALOG_WIDTH, MIN_DIALOG_HEIGHT)

        # Center window
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (DIALOG_WIDTH // 2)
        y = (self.winfo_screenheight() // 2) - (DIALOG_HEIGHT // 2)
        self.geometry(f"+{x}+{y}")

    def _create_ui(self) -> None:
        """Создаёт UI диалога."""
        self.config(bg=COLOR_BG)

        main_frame = ttk.Frame(self, padding=f"{PADDING_LARGE}")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        self._create_header(main_frame)

        # Status visualization
        self._create_status_visualization(main_frame)

        # Archived warning (if applicable)
        if self._is_archived:
            self._create_archived_warning(main_frame)

        # Reason section
        self._create_reason_section(main_frame)

        # MFA indicator
        if self._requires_mfa:
            self._create_mfa_indicator(main_frame)

        # Buttons
        self._create_buttons(main_frame)

        # Bindings
        self.bind("<Return>", lambda e: self._on_confirm_click())

    def _create_header(self, parent: ttk.Frame) -> None:
        """Создаёт заголовок."""
        if self._is_archived:
            header_text = "⚠️ WARNING: Terminal Status"
            header = ttk.Label(
                parent,
                text=header_text,
                font=("Helvetica", 14, "bold"),
                foreground="#dc3545",
            )
        else:
            header_text = "Confirm Transition"
            header = ttk.Label(
                parent,
                text=header_text,
                font=("Helvetica", 14, "bold"),
            )
        header.pack(anchor="w", pady=(0, PADDING_NORMAL))

    def _create_status_visualization(self, parent: ttk.Frame) -> None:
        """Создаёт визуализацию перехода состояний."""
        from src.gui.workflow.constants import STATUS_COLORS, STATUS_NAMES_RU

        viz_frame = ttk.LabelFrame(parent, text="Status Transition", padding=PADDING_NORMAL)
        viz_frame.pack(fill=tk.X, pady=(0, PADDING_NORMAL))

        # Get state info
        from_str = (
            self._from_state.value if hasattr(self._from_state, "value") else str(self._from_state)
        )
        to_str = self._to_state.value if hasattr(self._to_state, "value") else str(self._to_state)

        from_color = STATUS_COLORS.get(from_str, "#95a5a6")
        to_color = STATUS_COLORS.get(to_str, "#95a5a6")
        from_name = STATUS_NAMES_RU.get(from_str, from_str)
        to_name = STATUS_NAMES_RU.get(to_str, to_str)

        # Create visualization
        content_frame = ttk.Frame(viz_frame)
        content_frame.pack(fill=tk.X, expand=True)

        # From state box
        from_frame = tk.Frame(
            content_frame,
            bg=from_color,
            padx=15,
            pady=10,
        )
        from_frame.pack(side=tk.LEFT, padx=(0, PADDING_SMALL))

        from_label = tk.Label(
            from_frame,
            text=from_name.upper(),
            bg=from_color,
            fg="white",
            font=("Helvetica", 10, "bold"),
        )
        from_label.pack()

        # Arrow
        arrow_label = ttk.Label(
            content_frame,
            text="➜",
            font=("Helvetica", 16),
        )
        arrow_label.pack(side=tk.LEFT, padx=PADDING_NORMAL)

        # To state box
        to_frame = tk.Frame(
            content_frame,
            bg=to_color,
            padx=15,
            pady=10,
        )
        to_frame.pack(side=tk.LEFT)

        to_label = tk.Label(
            to_frame,
            text=to_name.upper(),
            bg=to_color,
            fg="white",
            font=("Helvetica", 10, "bold"),
        )
        to_label.pack()

        # Status descriptions
        desc_frame = ttk.Frame(viz_frame)
        desc_frame.pack(fill=tk.X, pady=(PADDING_NORMAL, 0))

        ttk.Label(desc_frame, text=f"From: {from_name}", foreground="gray").pack(side=tk.LEFT)
        ttk.Label(desc_frame, text=f"To: {to_name}", foreground="gray").pack(side=tk.RIGHT)

    def _create_archived_warning(self, parent: ttk.Frame) -> None:
        """Создаёт блок предупреждения для ARCHIVED."""
        warning_frame = tk.Frame(
            parent,
            bg=COLOR_DANGER_BG,
            highlightbackground=COLOR_DANGER_BORDER,
            highlightthickness=2,
            padx=PADDING_NORMAL,
            pady=PADDING_NORMAL,
        )
        warning_frame.pack(fill=tk.X, pady=(0, PADDING_NORMAL))

        # Warning icon and text
        warning_text = (
            "🔒 Document will be locked for editing\n"
            "🚫 This action is irreversible\n"
            "📁 Only reading will be available after archiving"
        )

        warning_label = tk.Label(
            warning_frame,
            text=warning_text,
            bg=COLOR_DANGER_BG,
            fg="#721c24",
            font=("Helvetica", 10),
            justify=tk.LEFT,
        )
        warning_label.pack(anchor="w")

        # Confirmation entry
        confirm_frame = ttk.Frame(parent)
        confirm_frame.pack(fill=tk.X, pady=(0, PADDING_NORMAL))

        ttk.Label(
            confirm_frame,
            text=f'To confirm, enter: "{self.ARCHIVED_CONFIRMATION_TEXT}"',
            font=("Helvetica", 10, "bold"),
        ).pack(anchor="w")

        self._confirm_var = tk.StringVar(master=self)
        self._confirm_entry = ttk.Entry(
            confirm_frame,
            textvariable=self._confirm_var,
            width=20,
            font=("Helvetica", 12),
        )
        self._confirm_entry.pack(anchor="w", pady=(PADDING_SMALL, 0))

    def _create_reason_section(self, parent: ttk.Frame) -> None:
        """Создаёт секцию причины перехода."""
        reason_frame = ttk.LabelFrame(parent, text="Transition Reason", padding=PADDING_NORMAL)
        reason_frame.pack(fill=tk.X, pady=(0, PADDING_NORMAL))

        if self._allowed_reasons:
            # Combobox with predefined reasons
            self._reason_var = tk.StringVar(master=self)
            self._reason_combo = ttk.Combobox(
                reason_frame,
                textvariable=self._reason_var,
                values=self._allowed_reasons,
                width=40,
            )
            self._reason_combo.pack(fill=tk.X)
            self._reason_combo.set(self._allowed_reasons[0] if self._allowed_reasons else "")
        else:
            # Free text entry
            self._reason_var = tk.StringVar(master=self)
            self._reason_entry = ttk.Entry(
                reason_frame,
                textvariable=self._reason_var,
                width=40,
            )
            self._reason_entry.pack(fill=tk.X)
            self._reason_entry.insert(0, "")

        # Char counter
        self._reason_counter = ttk.Label(reason_frame, text="0 / 200", foreground="gray")
        self._reason_counter.pack(anchor="e")

        if hasattr(self, "_reason_var"):
            self._reason_var.trace_add("write", self._update_reason_counter)

    def _create_mfa_indicator(self, parent: ttk.Frame) -> None:
        """Создаёт индикатор требования MFA."""
        mfa_frame = tk.Frame(
            parent,
            bg=COLOR_WARNING_BG,
            padx=PADDING_NORMAL,
            pady=PADDING_SMALL,
        )
        mfa_frame.pack(fill=tk.X, pady=(0, PADDING_NORMAL))

        mfa_text = "🔐 MFA confirmation is required for this transition"

        mfa_label = tk.Label(
            mfa_frame,
            text=mfa_text,
            bg=COLOR_WARNING_BG,
            fg="#856404",
            font=("Helvetica", 10),
        )
        mfa_label.pack(anchor="w")

    def _create_buttons(self, parent: ttk.Frame) -> None:
        """Создаёт кнопки управления."""
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=(PADDING_NORMAL, 0))

        # Cancel button
        self._cancel_btn = ttk.Button(
            btn_frame,
            text="Cancel",
            command=self._on_cancel,
        )
        self._cancel_btn.pack(side=tk.RIGHT, padx=(PADDING_SMALL, 0))

        # Confirm button
        self._confirm_btn = ttk.Button(
            btn_frame,
            text="Confirm",
            command=self._on_confirm_click,
        )
        self._confirm_btn.pack(side=tk.RIGHT)

    def _update_reason_counter(self, *args: Any) -> None:
        """Обновляет счётчик символов причины."""
        if hasattr(self, "_reason_var") and hasattr(self, "_reason_counter"):
            count = len(self._reason_var.get())
            self._reason_counter.config(text=f"{count} / 200")

    def _validate_confirmation(self) -> bool:
        """Валидирует подтверждение для ARCHIVED."""
        if not self._is_archived:
            return True

        entered = self._confirm_var.get().strip().upper()
        return entered == self.ARCHIVED_CONFIRMATION_TEXT

    def _on_confirm_click(self) -> None:
        """Обработчик подтверждения."""
        # Validate ARCHIVED confirmation
        if self._is_archived and not self._validate_confirmation():
            messagebox.showerror(
                "Confirmation Error",
                f'Incorrect confirmation text. Enter: "{self.ARCHIVED_CONFIRMATION_TEXT}"',
                parent=self,
            )
            if hasattr(self, "_confirm_entry"):
                self._confirm_entry.focus()
            return

        # Get reason
        reason = self._reason_var.get().strip()

        # Validate reason length
        if len(reason) > 200:
            messagebox.showerror(
                "Error",
                "Reason is too long (maximum 200 characters)",
                parent=self,
            )
            return

        self._result = {
            "confirmed": True,
            "reason": reason,
            "requires_mfa": self._requires_mfa,
        }

        if self._on_confirm:
            self._on_confirm(reason, self._requires_mfa)

        self.destroy()

    def _on_cancel(self) -> None:
        """Обработчик отмены."""
        self._result = None

        if self._on_cancel_callback:
            self._on_cancel_callback()

        self.destroy()

    def show(self) -> Optional[dict[str, Any]]:
        """Показывает диалог и возвращает результат.

        Returns:
            Словарь с confirmed, reason, requires_mfa или None.
        """
        self.wait_window()
        return self._result


__all__ = ["TransitionDialog"]
