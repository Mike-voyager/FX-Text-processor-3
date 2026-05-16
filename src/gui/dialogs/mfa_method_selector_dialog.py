"""Диалог выбора метода MFA для операций requiring MFA verification.

Предоставляет интерфейс для выбора метода многофакторной аутентификации:
- Выбор метода: FIDO2, TOTP, Backup Code
- Ввод токена/кода
- Кнопки подтверждения и отмены

Example:
    >>> dialog = MFAMethodSelectorDialog(
    ...     parent=root,
    ...     operation_name="Sign document",
    ...     required_role="SIGNATORY"
    ... )
    >>> result = dialog.show()
    >>> if result and result.get('verified'):
    ...     print(f"Verified with method: {result['method']}")

Version: 1.0
"""

from __future__ import annotations

import logging
import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Final, Optional

from src.gui.dialogs.base_dialog import BaseDialog

logger = logging.getLogger(__name__)

# Constants
DIALOG_WIDTH: Final[int] = 400
DIALOG_HEIGHT: Final[int] = 250

# Colors
COLOR_BG: Final[str] = "#f8f9fa"
COLOR_SUCCESS: Final[str] = "#27ae60"
COLOR_ERROR: Final[str] = "#e74c3c"
COLOR_INFO: Final[str] = "#3498db"
COLOR_WARNING: Final[str] = "#f39c12"


class MFAMethodSelectorDialog(BaseDialog):
    """Диалог выбора метода MFA для верификации операций.

    Attributes:
        parent: Родительский виджет.
        operation_name: Название операции, требующей MFA.
        required_role: Требуемая роль для операции.
        _method: Текущий выбранный метод MFA.
        _result: Результат диалога.

    Example:
        >>> dialog = MFAMethodSelectorDialog(
        ...     parent=root,
        ...     operation_name="Sign document",
        ...     required_role="SIGNATORY"
        ... )
        >>> result = dialog.show()
    """

    def __init__(
        self,
        parent: tk.Widget,
        operation_name: str,
        required_role: str = "",
        on_complete: Optional[Callable[[dict[str, Any]], None]] = None,
    ) -> None:
        """Инициализация диалога выбора метода MFA.

        Args:
            parent: Родительский виджет.
            operation_name: Название операции, требующей MFA верификации.
            required_role: Требуемая роль для операции (опционально).
            on_complete: Callback при завершении верификации.
        """
        super().__init__(parent)

        self._parent: tk.Widget = parent
        self._operation_name: str = operation_name
        self._required_role: str = required_role
        self._on_complete: Optional[Callable[[dict[str, Any]], None]] = on_complete

        # State
        self._method: tk.StringVar = tk.StringVar(master=self, value="fido2")
        self._result: Optional[dict[str, Any]] = None

        # UI references
        self._token_entry: Optional[tk.Entry] = None
        self._verify_btn: Optional[tk.Button] = None
        self._status_label: Optional[tk.Label] = None

        # Configure window
        self.title("🔐 MFA Verification Required")
        self.resizable(False, False)

        # Create UI
        self._create_ui()

        # Center window
        self._center_window()

    def _center_window(self) -> None:
        """Центрирует окно относительно родителя."""
        self.update_idletasks()

        parent_x = self._parent.winfo_rootx()
        parent_y = self._parent.winfo_rooty()
        parent_width = self._parent.winfo_width()
        parent_height = self._parent.winfo_height()

        x = parent_x + (parent_width - DIALOG_WIDTH) // 2
        y = parent_y + (parent_height - DIALOG_HEIGHT) // 2

        self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}+{x}+{y}")

    def _create_ui(self) -> None:
        """Создаёт пользовательский интерфейс диалога."""
        # Main container
        main_frame = tk.Frame(self, padx=20, pady=20, bg=COLOR_BG)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header with operation info
        self._create_operation_info(main_frame)

        # Separator
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=15)

        # Method selector
        self._create_method_selector(main_frame)

        # Token entry
        self._create_token_entry(main_frame)

        # Status label
        self._status_label = tk.Label(
            main_frame,
            text="",
            font=("Arial", 9),
            bg=COLOR_BG,
            fg=COLOR_ERROR,
        )
        self._status_label.pack(pady=(10, 0))

        # Buttons
        self._create_buttons(main_frame)

        # Bind Enter key
        self.bind("<Return>", lambda _: self._on_verify())
        self.bind("<Escape>", lambda _: self._on_cancel())

    def _create_operation_info(self, parent: tk.Widget) -> None:
        """Создаёт информацию об операции."""
        info_frame = tk.Frame(parent, bg=COLOR_BG)
        info_frame.pack(fill=tk.X, pady=(0, 10))

        # Operation label
        operation_label = tk.Label(
            info_frame,
            text=f"Operation: {self._operation_name}",
            font=("Arial", 10, "bold"),
            bg=COLOR_BG,
            fg="#2c3e50",
        )
        operation_label.pack(anchor=tk.W)

        # Role label (if specified)
        if self._required_role:
            role_label = tk.Label(
                info_frame,
                text=f"Required role: {self._required_role}",
                font=("Arial", 9),
                bg=COLOR_BG,
                fg="#7f8c8d",
            )
            role_label.pack(anchor=tk.W, pady=(2, 0))

    def _create_method_selector(self, parent: tk.Widget) -> None:
        """Создаёт селектор метода MFA в двухколоночном layout.

        Layout (UI_SPEC §3.6):
            [🔐 FIDO2]          [⏱️ TOTP]
            Touch your key      Enter 6-digit code

            [📝 Backup Code]
            Enter one-time code
        """
        method_frame = tk.LabelFrame(
            parent,
            text="Select verification method:",
            font=("Arial", 10, "bold"),
            bg=COLOR_BG,
            padx=10,
            pady=10,
        )
        method_frame.pack(fill=tk.X, pady=(0, 15))

        # Row 1: FIDO2 + TOTP side by side
        row1_frame = tk.Frame(method_frame, bg=COLOR_BG)
        row1_frame.pack(fill=tk.X, pady=2)

        # FIDO2 option (left)
        fido2_frame = tk.Frame(row1_frame, bg=COLOR_BG)
        fido2_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

        fido2_radio = tk.Radiobutton(
            fido2_frame,
            text="🔐 FIDO2",
            variable=self._method,
            value="fido2",
            font=("Arial", 9),
            bg=COLOR_BG,
            selectcolor=COLOR_INFO,
        )
        fido2_radio.pack(anchor=tk.W)

        fido2_hint = tk.Label(
            fido2_frame,
            text="Touch your key",
            font=("Arial", 9),
            bg=COLOR_BG,
            fg="#7f8c8d",
        )
        fido2_hint.pack(anchor=tk.W, padx=(20, 0))

        # TOTP option (right)
        totp_frame = tk.Frame(row1_frame, bg=COLOR_BG)
        totp_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

        totp_radio = tk.Radiobutton(
            totp_frame,
            text="⏱️ TOTP",
            variable=self._method,
            value="totp",
            font=("Arial", 9),
            bg=COLOR_BG,
            selectcolor=COLOR_INFO,
        )
        totp_radio.pack(anchor=tk.W)

        totp_hint = tk.Label(
            totp_frame,
            text="Enter 6-digit code",
            font=("Arial", 9),
            bg=COLOR_BG,
            fg="#7f8c8d",
        )
        totp_hint.pack(anchor=tk.W, padx=(20, 0))

        # Row 2: Backup Code
        row2_frame = tk.Frame(method_frame, bg=COLOR_BG)
        row2_frame.pack(fill=tk.X, pady=(8, 2))

        backup_radio = tk.Radiobutton(
            row2_frame,
            text="📝 Backup Code",
            variable=self._method,
            value="backup",
            font=("Arial", 9),
            bg=COLOR_BG,
            selectcolor=COLOR_INFO,
        )
        backup_radio.pack(anchor=tk.W)

        backup_hint = tk.Label(
            row2_frame,
            text="Enter one-time code",
            font=("Arial", 9),
            bg=COLOR_BG,
            fg="#7f8c8d",
        )
        backup_hint.pack(anchor=tk.W, padx=(20, 0))

    def _create_token_entry(self, parent: tk.Widget) -> None:
        """Создаёт поле ввода токена."""
        token_frame = tk.LabelFrame(
            parent,
            text="Token:",
            font=("Arial", 10, "bold"),
            bg=COLOR_BG,
            padx=10,
            pady=10,
        )
        token_frame.pack(fill=tk.X, pady=(0, 15))

        self._token_entry = tk.Entry(
            token_frame,
            font=("Courier", 16, "bold"),
            width=20,
            justify=tk.CENTER,
            relief=tk.SOLID,
            bd=2,
        )
        self._token_entry.pack(fill=tk.X, padx=5, pady=5)
        self._token_entry.focus_set()

        # Bind key events for auto-advance (for TOTP)
        self._token_entry.bind("<KeyRelease>", self._on_token_key_release)

    def _on_token_key_release(self, event: tk.Event) -> None:
        """Обработчик отпускания клавиши в поле токена."""
        if self._token_entry is None:
            return
        if self._method.get() == "totp":
            # Auto-advance logic for TOTP (6 digits)
            current_text = self._token_entry.get()
            if len(current_text) >= 6 and current_text.isdigit():
                self._token_entry.icursor(tk.END)  # Move cursor to end

    def _create_buttons(self, parent: tk.Widget) -> None:
        """Создаёт кнопки диалога."""
        btn_frame = tk.Frame(parent, bg=COLOR_BG)
        btn_frame.pack(fill=tk.X)

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

        # Verify/Confirm button
        self._verify_btn = tk.Button(
            btn_frame,
            text="Confirm",
            width=12,
            command=self._on_verify,
            font=("Arial", 9, "bold"),
            bg=COLOR_INFO,
            fg="white",
        )
        self._verify_btn.pack(side=tk.RIGHT)

    def _on_verify(self) -> None:
        """Обработчик нажатия кнопки подтверждения."""
        if self._token_entry is None:
            return
        token = self._token_entry.get().strip()
        method = self._method.get()

        # Validate input based on method
        if not token:
            self._show_error("Please enter a token")
            return

        if method == "totp":
            if len(token) != 6 or not token.isdigit():
                self._show_error("Please enter a valid 6-digit code")
                return
        elif method == "backup":
            # Backup code format: XXXX-XXXX (8 characters with dash)
            normalized = token.upper().replace("-", "")
            if len(normalized) != 8 or not normalized.isalnum():
                self._show_error("Please enter a valid backup code (XXXX-XXXX)")
                return

        # In a real implementation, we would verify the token here
        # For now, we'll simulate successful verification for demo purposes
        self._show_success("Verification successful!")

        # Store result
        self._result = {
            "verified": True,
            "method": method,
            "token": token,
        }

        # Disable button during processing
        if self._verify_btn:
            self._verify_btn.config(state=tk.DISABLED, text="Processing...")

        # Call completion callback after short delay
        self._after_ids.append(self.after(1000, self._complete_verification))

    def _on_cancel(self) -> None:
        """Обработчик отмены."""
        self._result = {"verified": False, "cancelled": True}
        self.destroy()

    def _show_error(self, message: str) -> None:
        """Показывает сообщение об ошибке."""
        if self._status_label:
            self._status_label.config(text=f"❌ {message}", fg=COLOR_ERROR)

    def _show_success(self, message: str) -> None:
        """Показывает сообщение об успехе."""
        if self._status_label:
            self._status_label.config(text=f"✓ {message}", fg=COLOR_SUCCESS)

    def _complete_verification(self) -> None:
        """Завершает процесс верификации."""
        if self._on_complete and self._result:
            self._on_complete(self._result)
        self.destroy()

    def show(self) -> Optional[dict[str, Any]]:
        """Показывает диалог модально.

        Returns:
            Словарь с результатом верификации или None если отменено:
            {
                "verified": bool,
                "method": str,
                "token": str | None,
            }
        """
        self.wait_window()
        return self._result


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "MFAMethodSelectorDialog",
    "DIALOG_WIDTH",
    "DIALOG_HEIGHT",
]
