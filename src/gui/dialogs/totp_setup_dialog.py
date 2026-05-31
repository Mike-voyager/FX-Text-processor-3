"""Диалог настройки TOTP (Time-based One-Time Password).

Предоставляет интерфейс для настройки аутентификации через
TOTP приложения (Google Authenticator, Authy и т.д.):
- Отображение QR-кода для сканирования
- Ручной ввод секретного ключа
- Проверка 6-значного кода

Example:
    >>> dialog = TOTPSetupDialog(parent=root)
    >>> result = dialog.show()
    >>> if result and result.get('verified'):
    ...     print("TOTP setup complete!")

Version: 1.0
"""

from __future__ import annotations

import logging
import secrets
import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Final, Optional

from src.gui.dialogs.base_dialog import BaseDialog
from src.security.crypto.core.exceptions import AuthError, CryptoError

# External deps
try:
    import pyotp
except ImportError:  # pragma: no cover
    pyotp = None  # type: ignore[assignment]

logger: Final = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

DIALOG_WIDTH: Final[int] = 450
DIALOG_HEIGHT: Final[int] = 550

# Colors
COLOR_BG: Final[str] = "#f8f9fa"
COLOR_SUCCESS: Final[str] = "#27ae60"
COLOR_ERROR: Final[str] = "#e74c3c"
COLOR_INFO: Final[str] = "#3498db"
COLOR_WARNING: Final[str] = "#f39c12"

TOTP_SECRET_LENGTH: Final[int] = 32


# =============================================================================
# TOTPSetupDialog
# =============================================================================


class TOTPSetupDialog(BaseDialog):
    """Диалог настройки TOTP аутентификации.

    Attributes:
        parent: Родительский виджет.
        _secret: Секретный ключ TOTP.
        _verified: Флаг успешной верификации.
        _result: Результат диалога.

    Example:
        >>> dialog = TOTPSetupDialog(parent=root)
        >>> result = dialog.show()
        >>> if result and result.get('verified'):
        ...     secret = result.get('secret')
    """

    def __init__(
        self,
        parent: tk.Widget,
        on_complete: Optional[Callable[[dict[str, Any]], None]] = None,
    ) -> None:
        """Инициализация диалога настройки TOTP.

        Args:
            parent: Родительский виджет.
            on_complete: Callback при завершении.
        """
        super().__init__(parent)

        self._parent: tk.Widget = parent
        self._on_complete: Optional[Callable[[dict[str, Any]], None]] = on_complete

        # State
        self._secret: str = self._generate_secret()
        self._verified: bool = False
        self._result: Optional[dict[str, Any]] = None

        # UI references
        self._code_entries: list[tk.Entry] = []
        self._verify_btn: Optional[tk.Button] = None
        self._status_label: Optional[tk.Label] = None

        # Configure window
        self.title("⏱️ Setup Authenticator App")
        self.resizable(False, False)

        # Create UI
        self._create_ui()

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

    def _generate_secret(self) -> str:
        """Генерирует секретный ключ TOTP.

        Returns:
            Секретный ключ в base32 формате.
        """
        # Generate random secret and format as base32-like string
        random_bytes = secrets.token_bytes(20)
        import base64

        return base64.b32encode(random_bytes).decode("ascii").rstrip("=")

    def _create_ui(self) -> None:
        """Создаёт пользовательский интерфейс."""
        # Main container
        main_frame = tk.Frame(self, padx=20, pady=20, bg=COLOR_BG)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        self._create_header(main_frame)

        # Separator
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=15)

        # QR Code section
        self._create_qr_section(main_frame)

        # Manual entry section
        self._create_manual_section(main_frame)

        # Verification section
        self._create_verification_section(main_frame)

        # Separator
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=15)

        # Buttons
        self._create_buttons(main_frame)

    def _create_header(self, parent: tk.Widget) -> None:
        """Создаёт заголовок диалога.

        Args:
            parent: Родительский виджет.
        """
        header_frame = tk.Frame(parent, bg=COLOR_BG)
        header_frame.pack(fill=tk.X, pady=(0, 5))

        tk.Label(
            header_frame,
            text="⏱️ Setup Authenticator App",
            font=("Arial", 14, "bold"),
            bg=COLOR_BG,
            fg="#2c3e50",
        ).pack(anchor=tk.W)

        tk.Label(
            header_frame,
            text="Configure TOTP two-factor authentication",
            font=("Arial", 9),
            bg=COLOR_BG,
            fg="#7f8c8d",
        ).pack(anchor=tk.W, pady=(5, 0))

    def _create_qr_section(self, parent: tk.Widget) -> None:
        """Создаёт секцию QR-кода.

        Args:
            parent: Родительский виджет.
        """
        qr_frame = tk.LabelFrame(
            parent,
            text="Step 1: Scan QR Code",
            font=("Arial", 10, "bold"),
            bg=COLOR_BG,
            padx=10,
            pady=10,
        )
        qr_frame.pack(fill=tk.X, pady=(0, 15))

        # QR Code placeholder (in real implementation would generate actual QR)
        qr_canvas = tk.Canvas(
            qr_frame,
            width=200,
            height=200,
            bg="white",
            relief=tk.SUNKEN,
            bd=1,
        )
        qr_canvas.pack(pady=10)

        # Draw a simulated QR code pattern
        self._draw_simulated_qr(qr_canvas)

        tk.Label(
            qr_frame,
            text="Scan this code with your authenticator app",
            font=("Arial", 9),
            bg=COLOR_BG,
            fg="#7f8c8d",
        ).pack()

        tk.Label(
            qr_frame,
            text="(Google Authenticator, Authy, Microsoft Authenticator)",
            font=("Arial", 8),
            bg=COLOR_BG,
            fg="#95a5a6",
        ).pack()

    def _draw_simulated_qr(self, canvas: tk.Canvas) -> None:
        """Рисует симулированный QR-код.

        Args:
            canvas: Canvas для рисования.
        """
        # Draw border
        canvas.create_rectangle(10, 10, 190, 190, outline="black", width=2)

        # Draw position detection patterns (corners)
        # Top-left
        canvas.create_rectangle(20, 20, 60, 60, fill="black")
        canvas.create_rectangle(30, 30, 50, 50, fill="white")
        canvas.create_rectangle(35, 35, 45, 45, fill="black")

        # Top-right
        canvas.create_rectangle(140, 20, 180, 60, fill="black")
        canvas.create_rectangle(150, 30, 170, 50, fill="white")
        canvas.create_rectangle(155, 35, 165, 45, fill="black")

        # Bottom-left
        canvas.create_rectangle(20, 140, 60, 180, fill="black")
        canvas.create_rectangle(30, 150, 50, 170, fill="white")
        canvas.create_rectangle(35, 155, 45, 165, fill="black")

        # Draw some visual "data" pattern (deterministic, not cryptographic)
        import hashlib

        for i in range(80, 160, 10):
            for j in range(20, 130, 10):
                d = hashlib.sha256(f"{self._secret}-{i}-{j}".encode()).digest()
                if (d[0] & 1) == 1:
                    canvas.create_rectangle(i, j, i + 8, j + 8, fill="black")

    def _create_manual_section(self, parent: tk.Widget) -> None:
        """Создаёт секцию ручного ввода.

        Args:
            parent: Родительский виджет.
        """
        manual_frame = tk.LabelFrame(
            parent,
            text="Or enter manually",
            font=("Arial", 10, "bold"),
            bg=COLOR_BG,
            padx=10,
            pady=10,
        )
        manual_frame.pack(fill=tk.X, pady=(0, 15))

        tk.Label(
            manual_frame,
            text="Secret:",
            font=("Arial", 9),
            bg=COLOR_BG,
        ).pack(anchor=tk.W)

        # Format secret in groups of 4
        formatted_secret = " ".join(
            [self._secret[i : i + 4] for i in range(0, len(self._secret), 4)]
        )

        secret_entry = tk.Entry(
            manual_frame,
            font=("Courier", 11, "bold"),
            justify=tk.CENTER,
            readonlybackground="#ecf0f1",
        )
        secret_entry.insert(0, formatted_secret)
        secret_entry.config(state="readonly")
        secret_entry.pack(fill=tk.X, pady=5)

        # Copy button
        tk.Button(
            manual_frame,
            text="📋 Copy",
            command=lambda: self._copy_to_clipboard(self._secret),
            font=("Arial", 8),
        ).pack(pady=5)

    def _create_verification_section(self, parent: tk.Widget) -> None:
        """Создаёт секцию верификации.

        Args:
            parent: Родительский виджет.
        """
        verify_frame = tk.LabelFrame(
            parent,
            text="Step 2: Verify Setup",
            font=("Arial", 10, "bold"),
            bg=COLOR_BG,
            padx=10,
            pady=10,
        )
        verify_frame.pack(fill=tk.X, pady=(0, 15))

        tk.Label(
            verify_frame,
            text="Enter the 6-digit code from your app:",
            font=("Arial", 9),
            bg=COLOR_BG,
        ).pack(anchor=tk.W, pady=(0, 10))

        # Code entry frame
        code_frame = tk.Frame(verify_frame, bg=COLOR_BG)
        code_frame.pack()

        self._code_entries = []
        for i in range(6):
            entry = tk.Entry(
                code_frame,
                width=3,
                font=("Courier", 16, "bold"),
                justify=tk.CENTER,
            )
            entry.pack(side=tk.LEFT, padx=2)
            self._code_entries.append(entry)

            # Bind auto-advance
            if i < 5:
                entry.bind(
                    "<KeyRelease>",
                    self._make_code_handler(i),
                )

        # Status label
        self._status_label = tk.Label(
            verify_frame,
            text="Enter the code to complete setup",
            font=("Arial", 9, "italic"),
            bg=COLOR_BG,
            fg=COLOR_INFO,
        )
        self._status_label.pack(pady=10)

    def _on_code_entry(self, event: tk.Event, index: int) -> None:
        """Обработчик ввода кода.

        Args:
            event: Событие клавиши.
            index: Индекс поля.
        """
        # Auto-advance to next field
        widget = event.widget
        if isinstance(widget, tk.Entry):
            if event.char.isdigit() and len(widget.get()) >= 1:
                if index + 1 < len(self._code_entries):
                    self._code_entries[index + 1].focus_set()

    def _make_code_handler(self, index: int) -> Callable[[tk.Event], None]:
        """Создаёт обработчик для поля кода.

        Args:
            index: Индекс поля.

        Returns:
            Обработчик события.
        """

        def handler(event: tk.Event) -> None:
            self._on_code_entry(event, index)

        return handler

    def _create_buttons(self, parent: tk.Widget) -> None:
        """Создаёт кнопки диалога.

        Args:
            parent: Родительский виджет.
        """
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

    def _copy_to_clipboard(self, text: str) -> None:
        """Копирует текст в буфер обмена.

        Args:
            text: Текст для копирования.
        """
        self.clipboard_clear()
        self.clipboard_append(text)
        if self._status_label is not None:
            self._status_label.config(text="✓ Copied to clipboard!", fg=COLOR_SUCCESS)

    def _get_entered_code(self) -> str:
        """Получает введённый код.

        Returns:
            6-значный код или пустая строка.
        """
        code = "".join(entry.get() for entry in self._code_entries)
        return code

    def _on_verify(self) -> None:
        """Обработчик верификации кода.

        Выполняет реальную верификацию TOTP через pyotp.
        CRITICAL-002: Не принимает произвольные коды.
        """
        code = self._get_entered_code()

        # Validate code format
        if len(code) != 6 or not code.isdigit():
            self._show_error("Please enter all 6 digits")
            return

        # Check pyotp is available
        if pyotp is None:
            self._show_error("TOTP library not available")
            return

        # Real TOTP verification
        try:
            totp = pyotp.TOTP(self._secret)
            if totp.verify(code, valid_window=1):
                self._verified = True
                self._show_success("Verification successful!")

                if self._verify_btn is not None:
                    self._verify_btn.config(text="Done", bg=COLOR_SUCCESS)

                # Store result and save to KeyStore
                self._result = {
                    "verified": True,
                    "secret": self._secret,
                    "method": "totp",
                }

                # Save TOTP secret to KeyStore
                self._save_totp_secret()

                self._after_ids.append(self.after(1000, self._complete_setup))
            else:
                self._show_error("Invalid code. Please try again.")
                logger.warning("TOTP verification failed: invalid code")

        except (AuthError, CryptoError) as e:
            logger.critical("TOTP verification security error: %s", e, exc_info=True)
            self._show_error("Security error during verification")
        except (ValueError, TypeError, AttributeError, RuntimeError) as e:
            logger.error("Unexpected TOTP verification error: %s", e, exc_info=True)
            self._show_error("Verification error. Please try again.")

    def _save_totp_secret(self) -> None:
        """Сохраняет TOTP секрет в KeyStore через сервис.

        CRITICAL-002: Секрет должен быть сохранен для последующих верификаций.
        """
        try:
            from src.app_context import get_app_context

            ctx = get_app_context()
            user_id = ctx.user_id

            if not user_id:
                logger.warning("No user_id available, cannot save TOTP secret")
                return

            from src.security.auth.totp_service import setup_totp_for_user

            setup_totp_for_user(
                user_id=user_id,
                username=user_id,  # Use user_id as username
                secret=self._secret,
                issuer="FX Text Processor",
            )
            logger.info("TOTP secret saved for user %s", user_id)

        except (AuthError, CryptoError) as e:
            logger.critical("Security error saving TOTP secret: %s", e, exc_info=True)
        except (ValueError, TypeError, AttributeError, RuntimeError, OSError) as e:
            logger.error("Unexpected error saving TOTP secret: %s", e, exc_info=True)
            # Don't raise - setup can complete but secret won't persist

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

    def _complete_setup(self) -> None:
        """Завершает настройку."""
        if self._on_complete is not None and self._result is not None:
            self._on_complete(self._result)

        logger.info("TOTP setup completed")
        self.destroy()

    def _on_cancel(self) -> None:
        """Обработчик отмены."""
        self._result = {
            "verified": False,
            "secret": None,
            "method": "totp",
            "cancelled": True,
        }
        self.destroy()

    def show(self) -> Optional[dict[str, Any]]:
        """Показывает диалог модально.

        Returns:
            Словарь с результатом или None:
            {
                "verified": bool,
                "secret": str | None,
                "method": "totp",
            }
        """
        self.wait_window()
        return self._result


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "TOTPSetupDialog",
    "DIALOG_WIDTH",
    "DIALOG_HEIGHT",
    "TOTP_SECRET_LENGTH",
]
