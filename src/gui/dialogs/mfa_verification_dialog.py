"""Диалог MFA верификации для разблокировки сессии.

Поддерживает методы:
- TOTP (6-значный код)
- Backup Codes (XXXX-XXXX)

Интегрируется с AuthController или MFAGate для реальной верификации.

Example:
    >>> from src.gui.dialogs.mfa_verification_dialog import MFAVerificationDialog
    >>> dialog = MFAVerificationDialog(
    ...     parent=root,
    ...     auth_controller=auth_controller,
    ...     user_id="operator",
    ... )
    >>> result = dialog.show()
    >>> if result and result.verified:
    ...     print("MFA верификация пройдена")

    # Использование с MFAGate:
    >>> from src.gui.security.mfa_gate import MFAGate, MFAResult
    >>> mfa_gate = MFAGate(auth_service)
    >>> mfa_gate.register_dialog("totp", MFAVerificationDialog)
    >>> result = mfa_gate.challenge(parent, user_id, ["totp"], "unlock")

Version: 1.1 (Phase 4: MFAGate Pattern)
Security: CRITICAL-001
"""

from __future__ import annotations

import logging
import tkinter as tk
from typing import TYPE_CHECKING, Any, Callable, Final, Optional, cast

from src.gui.dialogs.base_dialog import BaseDialog

if TYPE_CHECKING:
    from src.controller.auth_controller import AuthController

from src.gui.security.mfa_gate import MFAResult

logger: Final = logging.getLogger(__name__)

# Constants
DIALOG_WIDTH: Final[int] = 400
DIALOG_HEIGHT: Final[int] = 350

# Colors
COLOR_BG: Final[str] = "#f8f9fa"
COLOR_SUCCESS: Final[str] = "#27ae60"
COLOR_ERROR: Final[str] = "#e74c3c"
COLOR_INFO: Final[str] = "#3498db"


class MFAVerificationDialog(BaseDialog):
    """Диалог верификации MFA для разблокировки сессии.

    Реализует MFADialog Protocol для интеграции с MFAGate.

    Attributes:
        _auth_controller: Контроллер аутентификации (или None если используется MFAGate).
        _user_id: ID пользователя для верификации.
        _on_verify: Callback при успешной верификации.
        _result: Результат диалога.
        _current_method: Текущий выбранный метод (totp/backup).

    Example:
        >>> # Прямое использование с AuthController
        >>> dialog = MFAVerificationDialog(
        ...     parent=root,
        ...     auth_controller=auth_ctrl,
        ...     user_id="operator",
        ... )
        >>> result = dialog.show()

        >>> # Использование через MFAGate
        >>> mfa_gate.register_dialog("totp", MFAVerificationDialog)
        >>> result = mfa_gate.challenge(parent, user_id, ["totp"], "unlock")
    """

    def __init__(
        self,
        parent: Optional[tk.Widget] = None,
        auth_controller: Optional[AuthController] = None,
        user_id: str = "",
        on_verify: Optional[Callable[[dict[str, Any]], None]] = None,
    ) -> None:
        """Инициализация диалога MFA верификации.

        Args:
            parent: Родительский виджет (может быть None для MFAGate).
            auth_controller: Контроллер аутентификации (опционально для MFAGate).
            user_id: ID пользователя для верификации.
            on_verify: Callback при успешной верификации.
        """
        # Delayed initialization for MFAGate pattern
        self._parent = parent  # type: ignore[assignment]
        self._auth_controller: Optional[AuthController] = auth_controller
        self._user_id: str = user_id
        self._verify_callback: Optional[Callable[[dict[str, Any]], None]] = on_verify

        # State
        self._result: Optional[dict[str, Any]] = None
        self._current_method: str = "totp"
        self._verified: bool = False

        # UI references (initialized in _create_ui)
        self._code_entry: Optional[tk.Entry] = None
        self._code_label: Optional[tk.Label] = None
        self._status_label: Optional[tk.Label] = None
        self._method_var: Optional[tk.StringVar] = None

        # Initialize UI if parent provided
        if parent is not None:
            self._initialize_ui(parent)

    def _initialize_ui(self, parent: tk.Misc) -> None:
        """Инициализирует UI компоненты.

        Args:
            parent: Родительский виджет.
        """
        super().__init__(parent)

        self._method_var = tk.StringVar(master=self, value="totp")

        # Configure window
        self.title("🔒 MFA Verification Required")
        self.resizable(False, False)
        self.configure(bg=COLOR_BG)

        # Make modal

        # Create UI
        self._create_ui()

        # Center window

    def _center_window(self) -> None:
        """Центрирует окно относительно родителя."""
        self.update_idletasks()

        if self._parent is not None:
            parent = cast(tk.Tk, self._parent.winfo_toplevel())
            parent_x = parent.winfo_x()
            parent_y = parent.winfo_y()
            parent_width = parent.winfo_width()
            parent_height = parent.winfo_height()

            x = parent_x + (parent_width - DIALOG_WIDTH) // 2
            y = parent_y + (parent_height - DIALOG_HEIGHT) // 2

            self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}+{x}+{y}")

    def _create_ui(self) -> None:
        """Создаёт UI компоненты диалога."""
        # Main container
        main_frame = tk.Frame(self, bg=COLOR_BG, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = tk.Label(
            main_frame,
            text="Multi-Factor Authentication Required",
            font=("Arial", 14, "bold"),
            bg=COLOR_BG,
            fg="#2c3e50",
        )
        title_label.pack(pady=(0, 10))

        # Description
        desc_text = (
            "MFA verification is required to unlock the session.\n"
            "Enter the code from your authenticator."
        )
        desc_label = tk.Label(
            main_frame,
            text=desc_text,
            font=("Arial", 9),
            bg=COLOR_BG,
            fg="#666666",
            wraplength=DIALOG_WIDTH - 60,
        )
        desc_label.pack(pady=(0, 20))

        # Method selector
        self._create_method_selector(main_frame)

        # Code entry
        self._create_code_entry(main_frame)

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

    def _create_method_selector(self, parent: tk.Frame) -> None:
        """Создаёт селектор метода MFA.

        Args:
            parent: Родительский фрейм.
        """
        method_frame = tk.Frame(parent, bg=COLOR_BG)
        method_frame.pack(fill=tk.X, pady=(0, 15))

        tk.Label(
            method_frame,
            text="Method:",
            font=("Arial", 9),
            bg=COLOR_BG,
            fg="#333333",
        ).pack(side=tk.LEFT, padx=(0, 10))

        # Radio buttons for methods
        if self._method_var is not None:
            totp_radio = tk.Radiobutton(
                method_frame,
                text="TOTP Code",
                variable=self._method_var,
                value="totp",
                font=("Arial", 9),
                bg=COLOR_BG,
                command=self._on_method_changed,
            )
            totp_radio.pack(side=tk.LEFT, padx=(0, 15))

            backup_radio = tk.Radiobutton(
                method_frame,
                text="Backup Code",
                variable=self._method_var,
                value="backup",
                font=("Arial", 9),
                bg=COLOR_BG,
                command=self._on_method_changed,
            )
            backup_radio.pack(side=tk.LEFT)

    def _create_code_entry(self, parent: tk.Frame) -> None:
        """Создаёт поле ввода кода.

        Args:
            parent: Родительский фрейм.
        """
        entry_frame = tk.Frame(parent, bg=COLOR_BG)
        entry_frame.pack(fill=tk.X, pady=(0, 10))

        # Label
        self._code_label = tk.Label(
            entry_frame,
            text="Enter 6-digit code:",
            font=("Arial", 9),
            bg=COLOR_BG,
            fg="#333333",
        )
        self._code_label.pack(anchor=tk.W, pady=(0, 5))

        # Entry
        self._code_entry = tk.Entry(
            entry_frame,
            font=("Courier", 16, "bold"),
            justify=tk.CENTER,
            width=20,
            relief=tk.SOLID,
            bd=2,
        )
        self._code_entry.pack(fill=tk.X)
        self._code_entry.focus_set()

    def _create_buttons(self, parent: tk.Frame) -> None:
        """Создаёт кнопки диалога.

        Args:
            parent: Родительский фрейм.
        """
        btn_frame = tk.Frame(parent, bg=COLOR_BG)
        btn_frame.pack(fill=tk.X, pady=(20, 0))

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

        # Verify button
        self._verify_btn = tk.Button(
            btn_frame,
            text="✓ Verify",
            width=12,
            command=self._on_verify,
            font=("Arial", 9, "bold"),
            bg=COLOR_INFO,
            fg="white",
        )
        self._verify_btn.pack(side=tk.RIGHT)

    def _on_method_changed(self) -> None:
        """Обработчик смены метода MFA."""
        method: str = self._current_method
        if self._method_var is not None:
            method = self._method_var.get()
            self._current_method = method

        if self._code_label is not None:
            if method == "totp":
                self._code_label.config(text="Enter 6-digit code:")
            else:
                self._code_label.config(text="Enter backup code (XXXX-XXXX):")

        # Clear status
        if self._status_label is not None:
            self._status_label.config(text="")

        # Focus entry
        if self._code_entry is not None:
            self._code_entry.delete(0, tk.END)
            self._code_entry.focus_set()

    def _on_verify(self) -> None:
        """Обработчик нажатия кнопки Verify."""
        if self._code_entry is None:
            return

        code = self._code_entry.get().strip()

        # Validate input format
        if self._current_method == "totp":
            if len(code) != 6 or not code.isdigit():
                self._show_error("Please enter 6-digit code")
                return
        else:  # backup
            normalized = code.upper().replace("-", "")
            if len(normalized) != 8 or not normalized.isalnum():
                self._show_error("Invalid backup code format (XXXX-XXXX)")
                return

        # Perform verification
        try:
            if self._auth_controller is not None:
                # Direct AuthController verification
                if self._current_method == "totp":
                    verified = self._auth_controller.verify_totp(self._user_id, code)
                else:
                    verified = self._auth_controller.verify_backup_code(self._user_id, code)

                if verified:
                    self._on_verification_success()
                else:
                    self._show_error("Invalid code. Please try again.")
            else:
                # No auth controller - cannot verify
                self._show_error("Authentication service not available")
                logger.error("MFAVerificationDialog: auth_controller is None")

        except (ValueError, TypeError, AttributeError, RuntimeError) as e:
            logger.error("MFA verification error: %s", e, exc_info=True)
            self._show_error("Verification error. Please try again.")

    def _on_verification_success(self) -> None:
        """Обработчик успешной верификации."""
        self._verified = True
        self._result = {
            "verified": True,
            "method": self._current_method,
        }

        # Mark MFA as satisfied in session
        if self._auth_controller is not None:
            try:
                self._auth_controller.mark_mfa_satisfied()
            except (AttributeError, ValueError, TypeError, RuntimeError) as e:
                logger.warning("Failed to mark MFA satisfied: %s", e)

        # Show success
        self._show_success("Verification successful!")

        # Call callback
        if self._verify_callback is not None:
            self._verify_callback(self._result)

        # Close after delay
        self._after_ids.append(self.after(800, self.destroy))

    def _on_cancel(self) -> None:
        """Обработчик отмены."""
        self._result = {"verified": False, "cancelled": True}
        self.destroy()

    def _show_error(self, message: str) -> None:
        """Показывает сообщение об ошибке.

        Args:
            message: Текст ошибки.
        """
        if self._status_label is not None:
            self._status_label.config(text=f"❌ {message}", fg=COLOR_ERROR)

    def _show_success(self, message: str) -> None:
        """Показывает сообщение об успехе.

        Args:
            message: Текст сообщения.
        """
        if self._status_label is not None:
            self._status_label.config(text=f"✓ {message}", fg=COLOR_SUCCESS)

    def show(self, parent: Optional[tk.Widget] = None) -> Optional[MFAResult]:
        """Показывает диалог модально.

        Реализует MFADialog Protocol для интеграции с MFAGate.

        Args:
            parent: Родительский виджет (используется если не задан в __init__).

        Returns:
            MFAResult с результатом верификации или None если отменено.
        """
        # Initialize UI if not done yet
        if self._method_var is None:
            actual_parent = parent or self._parent
            if actual_parent is None:
                raise ValueError("Parent widget required for MFA dialog")
            self._initialize_ui(actual_parent)

        self.wait_window()

        # Return MFAResult if verification succeeded
        if self._result and self._result.get("verified"):
            return MFAResult.success(
                method=self._current_method,
                user_id=self._user_id,
                audit_token=f"{self._user_id}:mfa:{self._current_method}",
            )

        # Return failure result if dialog was cancelled or failed
        if self._result and self._result.get("cancelled"):
            return MFAResult.failure(
                method=self._current_method,
                user_id=self._user_id,
                error_message="MFA verification cancelled",
            )

        return None

    def get_method(self) -> str:
        """Возвращает метод MFA (реализация MFADialog Protocol).

        Returns:
            Название метода MFA ("totp" или "backup").
        """
        return self._current_method


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "MFAVerificationDialog",
    "DIALOG_WIDTH",
    "DIALOG_HEIGHT",
]
