"""Диалог отклонения/возврата формы на доработку.

Предоставляет интерфейс для выбора между:
- Возвратом формы в статус DRAFT (с возможностью редактирования)
- Окончательным отклонением формы (REJECTED, терминальный статус)

Features:
    - Выбор опции с визуальной индикацией последствий
    - Поле для ввода причины отклонения
    - MFA-верификация для критичных операций
    - Предупреждение о необратимости действия

Example:
    >>> from src.documents.constructor.form_status import FormStatus
    >>> dialog = RejectDialog(
    ...     parent=root,
    ...     current_status=FormStatus.VALIDATED,
    ...     on_reject=lambda status, reason, mfa: print(f"Rejected: {reason}"),
    ... )
    >>> result = dialog.show()
    >>> if result:
    ...     print(f"Selected: {result['option']}, Reason: {result['reason']}")

Version: 1.0
"""

from __future__ import annotations

import logging
import tkinter as tk
from tkinter import messagebox, ttk
from typing import TYPE_CHECKING, Any, Callable, Final, Optional, cast

from src.documents.constructor.form_status import FormStatus
from src.gui.dialogs.base_dialog import BaseDialog
from src.gui.security.mfa_gate import MFAGate

if TYPE_CHECKING:
    from src.gui.security.mode_manager import ModeManager

logger: Final = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

DIALOG_WIDTH: Final[int] = 500
DIALOG_HEIGHT: Final[int] = 450
MIN_REASON_LENGTH: Final[int] = 10
MAX_REASON_LENGTH: Final[int] = 1000

# Colors
COLOR_WARNING: Final[str] = "#f39c12"  # Yellow
COLOR_DANGER: Final[str] = "#e74c3c"  # Red
COLOR_INFO: Final[str] = "#3498db"  # Blue
COLOR_SUCCESS: Final[str] = "#27ae60"  # Green
COLOR_BG: Final[str] = "#f8f9fa"

# MFA transitions requiring authentication
_MFA_REQUIRED_FROM: Final[set[FormStatus]] = {
    FormStatus.VALIDATED,
    FormStatus.SIGNED,
    FormStatus.PRINTED,
}


# =============================================================================
# RejectDialog
# =============================================================================


class RejectDialog(BaseDialog):
    """Диалог отклонения формы с выбором действия и MFA.

    Attributes:
        parent: Родительский виджет.
        current_status: Текущий статус формы.
        on_reject: Callback при подтверждении отклонения.
        _result: Результат диалога (None если отменено).
        _selected_option: Выбранная опция ("to_draft" или "to_rejected").

    Example:
        >>> dialog = RejectDialog(parent=root, current_status=FormStatus.VALIDATED)
        >>> result = dialog.show()
        >>> if result and result['option'] == 'to_rejected':
        ...     print("Form permanently rejected")
    """

    REJECT_OPTIONS: Final[list[tuple[str, str, str]]] = [
        ("to_draft", "🔄 Return to DRAFT", "Form will be editable again"),
        ("to_rejected", "⛔ Mark as REJECTED", "Final state, no further edits"),
    ]

    def __init__(
        self,
        parent: tk.Widget,
        current_status: FormStatus,
        on_reject: Optional[Callable[[FormStatus, str, Optional[dict[str, str]]], None]] = None,
        mode_manager: Optional["ModeManager"] = None,
    ) -> None:
        """Инициализация диалога отклонения.

        Args:
            parent: Родительский виджет.
            current_status: Текущий статус формы.
            on_reject: Callback при подтверждении (status, reason, mfa_credentials).
            mode_manager: ModeManager для MFA-проверок.
        """
        super().__init__(parent)

        self._parent: tk.Widget = parent
        self._current_status: FormStatus = current_status
        self._on_reject_callback: Optional[
            Callable[[FormStatus, str, Optional[dict[str, str]]], None]
        ] = on_reject
        self._mode_manager: Optional["ModeManager"] = mode_manager

        # Result
        self._result: Optional[dict[str, Any]] = None
        self._selected_option: tk.StringVar = tk.StringVar(master=self, value="to_draft")

        # UI references
        self._reason_text: Optional[tk.Text] = None
        self._option_frames: dict[str, tk.Frame] = {}
        self._warning_label: Optional[tk.Label] = None
        self._confirm_btn: Optional[tk.Button] = None

        # MFA state
        self._mfa_verified: bool = False
        self._mfa_credentials: Optional[dict[str, str]] = None

        # Configure window
        self.title("⚠️ Reject Form")
        self.resizable(False, False)

        # Create UI
        self._create_ui()

        # Center window

        # Protocol

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
        """Создаёт пользовательский интерфейс."""
        # Main container with padding
        main_frame = tk.Frame(self, padx=20, pady=20, bg=COLOR_BG)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        self._create_header(main_frame)

        # Separator
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=15)

        # Options section
        self._create_options_section(main_frame)

        # Separator
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=15)

        # Reason section
        self._create_reason_section(main_frame)

        # Warning section
        self._create_warning_section(main_frame)

        # Buttons
        self._create_buttons(main_frame)

        # Initial update
        self._update_warning()

    def _create_header(self, parent: tk.Widget) -> None:
        """Создаёт заголовок диалога.

        Args:
            parent: Родительский виджет.
        """
        header_frame = tk.Frame(parent, bg=COLOR_BG)
        header_frame.pack(fill=tk.X, pady=(0, 5))

        tk.Label(
            header_frame,
            text="⚠️ Form Rejection",
            font=("Arial", 14, "bold"),
            bg=COLOR_BG,
            fg="#2c3e50",
        ).pack(anchor=tk.W)

        status_text = f"Current status: {self._current_status.localized_name}"
        tk.Label(
            header_frame,
            text=status_text,
            font=("Arial", 10),
            bg=COLOR_BG,
            fg="#7f8c8d",
        ).pack(anchor=tk.W, pady=(5, 0))

    def _create_options_section(self, parent: tk.Widget) -> None:
        """Создаёт секцию выбора опции.

        Args:
            parent: Родительский виджет.
        """
        options_frame = tk.LabelFrame(
            parent,
            text="Select action",
            font=("Arial", 10, "bold"),
            padx=10,
            pady=10,
            bg=COLOR_BG,
        )
        options_frame.pack(fill=tk.X)

        for value, title, description in self.REJECT_OPTIONS:
            self._create_option_row(options_frame, value, title, description)

    def _create_option_row(
        self,
        parent: tk.Widget,
        value: str,
        title: str,
        description: str,
    ) -> None:
        """Создаёт строку с радиокнопкой опции.

        Args:
            parent: Родительский виджет.
            value: Значение опции.
            title: Заголовок опции.
            description: Описание опции.
        """
        frame = tk.Frame(parent, bg=COLOR_BG, pady=5)
        frame.pack(fill=tk.X)
        self._option_frames[value] = frame

        # Radio button
        rb = tk.Radiobutton(
            frame,
            variable=self._selected_option,
            value=value,
            bg=COLOR_BG,
            command=self._on_option_change,
        )
        rb.pack(side=tk.LEFT)

        # Text content
        content_frame = tk.Frame(frame, bg=COLOR_BG)
        content_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))

        tk.Label(
            content_frame,
            text=title,
            font=("Arial", 10, "bold"),
            bg=COLOR_BG,
            anchor=tk.W,
        ).pack(fill=tk.X)

        tk.Label(
            content_frame,
            text=description,
            font=("Arial", 9),
            bg=COLOR_BG,
            fg="#7f8c8d",
            anchor=tk.W,
        ).pack(fill=tk.X)

    def _create_reason_section(self, parent: tk.Widget) -> None:
        """Создаёт секцию ввода причины.

        Args:
            parent: Родительский виджет.
        """
        reason_frame = tk.LabelFrame(
            parent,
            text="Reason for rejection (required)",
            font=("Arial", 10, "bold"),
            padx=10,
            pady=10,
            bg=COLOR_BG,
        )
        reason_frame.pack(fill=tk.BOTH, expand=True)

        # Text widget with scrollbar
        text_frame = tk.Frame(reason_frame, bg=COLOR_BG)
        text_frame.pack(fill=tk.BOTH, expand=True)

        self._reason_text = tk.Text(
            text_frame,
            wrap=tk.WORD,
            height=5,
            width=50,
            font=("Arial", 10),
            relief=tk.SUNKEN,
            bd=1,
        )
        self._reason_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(text_frame, command=self._reason_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self._reason_text.config(yscrollcommand=scrollbar.set)

        # Character count label
        char_count_label = tk.Label(
            reason_frame,
            text=f"0 / {MAX_REASON_LENGTH} characters",
            font=("Arial", 8),
            bg=COLOR_BG,
            fg="#7f8c8d",
            anchor=tk.E,
        )
        char_count_label.pack(fill=tk.X, pady=(5, 0))
        self._char_count_label = char_count_label

    def _create_warning_section(self, parent: tk.Widget) -> None:
        """Создаёт секцию предупреждения.

        Args:
            parent: Родительский виджет.
        """
        self._warning_frame = tk.Frame(parent, bg="#fff3cd", padx=10, pady=10)
        self._warning_frame.pack(fill=tk.X, pady=(10, 0))

        self._warning_label = tk.Label(
            self._warning_frame,
            text="",
            font=("Arial", 9),
            bg="#fff3cd",
            fg="#856404",
            wraplength=440,
            justify=tk.LEFT,
        )
        self._warning_label.pack(fill=tk.X)

    def _create_buttons(self, parent: tk.Widget) -> None:
        """Создаёт кнопки диалога.

        Args:
            parent: Родительский виджет.
        """
        btn_frame = tk.Frame(parent, bg=COLOR_BG)
        btn_frame.pack(fill=tk.X, pady=(15, 0))

        # Spacer
        tk.Frame(btn_frame, bg=COLOR_BG).pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Cancel button
        cancel_btn = tk.Button(
            btn_frame,
            text="Cancel",
            width=12,
            command=self._on_cancel,
            font=("Arial", 9),
        )
        cancel_btn.pack(side=tk.RIGHT, padx=(5, 0))

        # Confirm button
        self._confirm_btn = tk.Button(
            btn_frame,
            text="Confirm",
            width=12,
            command=self._on_confirm,
            font=("Arial", 9, "bold"),
            bg=COLOR_DANGER,
            fg="white",
        )
        self._confirm_btn.pack(side=tk.RIGHT)

    def _on_option_change(self) -> None:
        """Обрабатывает изменение выбранной опции."""
        self._update_warning()
        self._update_button_appearance()

    def _update_warning(self) -> None:
        """Обновляет текст предупреждения в зависимости от выбора."""
        if self._warning_label is None:
            return

        option = self._selected_option.get()

        if option == "to_draft":
            text = (
                "ℹ️ The form will be returned to DRAFT status. "
                "All fields will remain editable. "
                "This action can be reversed by resubmitting the form."
            )
            self._warning_frame.config(bg="#d1ecf1")
            self._warning_label.config(bg="#d1ecf1", fg="#0c5460", text=text)
        else:
            text = (
                "⚠️ WARNING: This is a TERMINAL state. "
                "The form will be permanently rejected and cannot be edited again. "
                "This action requires MFA verification and cannot be undone."
            )
            self._warning_frame.config(bg="#f8d7da")
            self._warning_label.config(bg="#f8d7da", fg="#721c24", text=text)

    def _update_button_appearance(self) -> None:
        """Обновляет внешний вид кнопки подтверждения."""
        if self._confirm_btn is None:
            return

        option = self._selected_option.get()
        if option == "to_rejected":
            self._confirm_btn.config(bg=COLOR_DANGER, text="Confirm Rejection")
        else:
            self._confirm_btn.config(bg=COLOR_INFO, text="Confirm")

    def _on_reason_change(self, event: Any = None) -> None:
        """Обрабатывает изменение текста причины.

        Args:
            event: Событие изменения текста (опционально).
        """
        if self._reason_text is None:
            return

        content = self._reason_text.get("1.0", tk.END).strip()
        length = len(content)

        # Update character count
        count_text = f"{length} / {MAX_REASON_LENGTH} characters"
        self._char_count_label.config(
            text=count_text,
            fg=COLOR_DANGER if length > MAX_REASON_LENGTH else "#7f8c8d",
        )

    def _on_reason_keypress(self, event: Any) -> Optional[str]:
        """Обрабатывает нажатие клавиши в поле причины.

        Args:
            event: Событие нажатия клавиши.

        Returns:
            "break" для блокировки ввода если превышен лимит.
        """
        if self._reason_text is None:
            return None

        content = self._reason_text.get("1.0", tk.END).strip()

        # Block input if max length reached (except backspace/delete)
        if len(content) >= MAX_REASON_LENGTH:
            if event.keysym not in ("BackSpace", "Delete", "Left", "Right", "Up", "Down"):
                return "break"

        return None

    def _validate_input(self) -> tuple[bool, str]:
        """Валидирует ввод пользователя.

        Returns:
            Кортеж (валидно, сообщение_об_ошибке).
        """
        if self._reason_text is None:
            return False, "Reason text widget not initialized"

        reason = self._reason_text.get("1.0", tk.END).strip()

        if not reason:
            return False, "Please provide a reason for rejection"

        if len(reason) < MIN_REASON_LENGTH:
            return False, f"Reason must be at least {MIN_REASON_LENGTH} characters"

        if len(reason) > MAX_REASON_LENGTH:
            return False, f"Reason must not exceed {MAX_REASON_LENGTH} characters"

        return True, ""

    def _is_mfa_required(self) -> bool:
        """Проверяет, требуется ли MFA для текущего выбора.

        Returns:
            True если требуется MFA.
        """
        option = self._selected_option.get()

        # MFA always required for REJECTED
        if option == "to_rejected":
            return True

        # MFA required for certain source states
        return self._current_status in _MFA_REQUIRED_FROM

    def _show_mfa_dialog(self) -> bool:
        """Показывает диалог MFA через MFAGate.

        Returns:
            True если MFA пройден успешно.
        """
        try:
            from src.app_context import get_app_context

            ctx = get_app_context()
            user_id = ctx.user_id

            if not user_id:
                logger.error("No user_id available for MFA verification")
                return False

            # Get auth controller
            auth_controller = getattr(ctx, "auth_controller", None)
            if auth_controller is None:
                logger.error("Auth controller not available")
                return False

            # Use MFAGate for MFA challenge
            mfa_gate = MFAGate(auth_controller)
            result = mfa_gate.challenge(
                parent=cast(tk.Widget, self),
                user_id=user_id,
                required_methods=["totp", "backup_code"],
                operation="reject_document",
            )

            if result.verified:
                self._mfa_verified = True
                self._mfa_credentials = {"method": result.method}
                logger.info("MFA verified for reject operation by user %s", user_id)
                return True
            else:
                logger.warning("MFA verification failed for reject operation")
                return False

        except Exception as e:
            logger.error("MFA dialog failed: %s", e)
            return False

    def _on_confirm(self) -> None:
        """Обрабатывает нажатие кнопки подтверждения."""
        # Validate input
        valid, error_msg = self._validate_input()
        if not valid:
            messagebox.showwarning("Validation Error", error_msg, parent=self)
            return

        option = self._selected_option.get()
        reason = self._reason_text.get("1.0", tk.END).strip() if self._reason_text else ""

        # Confirm terminal action
        if option == "to_rejected":
            confirmed = messagebox.askyesno(
                "Confirm Terminal Action",
                "⚠️ WARNING: This will permanently reject the form.\n\n"
                "This action cannot be undone. Are you sure?",
                icon="warning",
                parent=self,
            )
            if not confirmed:
                return

        # Check MFA requirement
        if self._is_mfa_required() and not self._mfa_verified:
            success = self._show_mfa_dialog()
            if not success:
                return

        # Determine target status
        target_status = FormStatus.REJECTED if option == "to_rejected" else FormStatus.DRAFT

        # Build result
        self._result = {
            "option": option,
            "target_status": target_status,
            "reason": reason,
            "mfa_verified": self._mfa_verified,
            "mfa_credentials": self._mfa_credentials,
        }

        # Call callback if provided
        if self._on_reject_callback is not None:
            self._on_reject_callback(target_status, reason, self._mfa_credentials)

        logger.info(
            "Form rejection confirmed: %s -> %s, mfa=%s",
            self._current_status.value,
            target_status.value,
            self._mfa_verified,
        )

        self.destroy()

    def _on_cancel(self) -> None:
        """Обрабатывает нажатие кнопки отмены."""
        self._result = None
        self.destroy()

    def show(self) -> Optional[dict[str, Any]]:
        """Показывает диалог модально.

        Returns:
            Словарь с результатом или None если отменено:
            {
                "option": "to_draft" | "to_rejected",
                "target_status": FormStatus,
                "reason": str,
                "mfa_verified": bool,
                "mfa_credentials": dict | None,
            }
        """
        self.wait_window()
        return self._result

    def get_selected_status(self) -> Optional[FormStatus]:
        """Возвращает выбранный целевой статус.

        Returns:
            FormStatus или None если диалог отменён.
        """
        if self._result is None:
            return None
        return self._result.get("target_status")

    def get_reason(self) -> Optional[str]:
        """Возвращает введённую причину.

        Returns:
            Причина отклонения или None.
        """
        if self._result is None:
            return None
        return self._result.get("reason")


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "RejectDialog",
    "DIALOG_WIDTH",
    "DIALOG_HEIGHT",
    "MIN_REASON_LENGTH",
    "MAX_REASON_LENGTH",
]
