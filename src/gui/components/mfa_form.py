"""Reusable MFA form widget for FX Text Processor 3.

Модуль реализует reusable виджет формы MFA-аутентификации:
- Password entry (show='*')
- Method selection: FIDO2 (disabled), TOTP, Backup Code
- Token entry (for TOTP/Backup)
- Unlock / Authenticate button
- Error label

Security:
    - Пароль скрывается (show='*')
    - Поля очищаются при неудаче
    - Нет логирования sensitive данных

Example:
    >>> form = MFAForm(parent=frame, on_submit=my_callback)
    >>> form.pack()
    >>> form.focus_password()

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from typing import Any, Callable, Final, Literal, Optional

from src.security.crypto.core.exceptions import AuthError, CryptoError

# Callback type: username, password, method, token -> success
MfaSubmitCallback = Callable[[str, str, str, str], bool]

# Callback type for FIDO2: username, password -> success
Fido2RequestCallback = Callable[[str, str], bool]


class MFAForm(tk.Frame):
    """Reusable MFA form widget.

    Attributes:
        METHOD_FIDO2: Идентификатор метода FIDO2.
        METHOD_TOTP: Идентификатор метода TOTP.
        METHOD_BACKUP: Идентификатор метода Backup Code.

    Security:
        - Пароль скрывается (show='*')
        - Поля очищаются при неудачной аутентификации
        - Нет логирования sensitive данных
    """

    METHOD_FIDO2: Final[str] = "fido2"
    METHOD_TOTP: Final[str] = "totp"
    METHOD_BACKUP: Final[str] = "backup"

    def __init__(
        self,
        parent: tk.Widget,
        *,
        on_submit: Optional[MfaSubmitCallback] = None,
        on_fido2_request: Optional[Fido2RequestCallback] = None,
        on_cancel: Optional[Callable[[], None]] = None,
        show_username: bool = False,
        show_cancel: bool = True,
        submit_text: str = "Authenticate",
        cancel_text: str = "Cancel",
        bg_color: str = "#34495e",
        fg_color: str = "#ecf0f1",
        error_color: str = "#e74c3c",
        accent_color: str = "#27ae60",
        font_family: str = "Courier New",
        title_text: str = "Authentication Required",
        title_font_size: int = 18,
        label_font_size: int = 11,
        entry_font_size: int = 11,
        button_font_size: int = 11,
    ) -> None:
        """Инициализация MFAForm.

        Args:
            parent: Родительский виджет.
            on_submit: Callback при отправке формы.
                Получает (username, password, method, token) -> bool.
            on_fido2_request: Callback при FIDO2-аутентификации.
                Получает (username, password) -> bool.
                Если не передан — FIDO2 radio отображается недоступным.
            on_cancel: Callback при отмене.
            show_username: Показывать ли поле username.
            show_cancel: Показывать ли кнопку Cancel.
            submit_text: Текст кнопки подтверждения.
            cancel_text: Текст кнопки отмены.
            bg_color: Color фона.
            fg_color: Color текста.
            error_color: Color текста ошибки.
            accent_color: Color акцента (кнопка).
            font_family: Шрифт.
            title_text: Заголовок формы.
            title_font_size: Размер шрифта заголовка.
            label_font_size: Размер шрифта меток.
            entry_font_size: Размер шрифта полей ввода.
            button_font_size: Размер шрифта кнопок.
        """
        super().__init__(parent, bg=bg_color)
        self._on_submit = on_submit
        self._on_fido2_request = on_fido2_request
        self._on_cancel = on_cancel
        self._bg_color = bg_color
        self._fg_color = fg_color
        self._error_color = error_color
        self._accent_color = accent_color
        self._font_family = font_family
        self._submit_text = submit_text
        self._fido2_available = on_fido2_request is not None

        # String variables
        self._username_var = tk.StringVar(value="operator" if show_username else "")
        self._password_var = tk.StringVar(master=self)
        self._token_var = tk.StringVar(master=self)
        self._method_var = tk.StringVar(value=self.METHOD_TOTP)

        # Widget references
        self._username_entry: Optional[tk.Entry] = None
        self._password_entry: Optional[tk.Entry] = None
        self._token_entry: Optional[tk.Entry] = None
        self._token_label: Optional[tk.Label] = None
        self._token_hint: Optional[tk.Label] = None
        self._token_frame: Optional[tk.Frame] = None
        self._submit_btn: Optional[tk.Button] = None
        self._error_label: Optional[tk.Label] = None
        self._fido2_radio: Optional[tk.Radiobutton] = None
        self._fido2_text_label: Optional[tk.Label] = None
        self._fido2_info_label: Optional[tk.Label] = None

        self._build_ui(
            show_username=show_username,
            show_cancel=show_cancel,
            cancel_text=cancel_text,
            title_text=title_text,
            title_font_size=title_font_size,
            label_font_size=label_font_size,
            entry_font_size=entry_font_size,
            button_font_size=button_font_size,
        )

        # Bind method change
        self._method_var.trace_add("write", self._on_method_changed)

        # Initial state
        self._on_method_changed()

    def _build_ui(
        self,
        *,
        show_username: bool,
        show_cancel: bool,
        cancel_text: str,
        title_text: str,
        title_font_size: int,
        label_font_size: int,
        entry_font_size: int,
        button_font_size: int,
    ) -> None:
        """Создаёт UI элементы формы."""
        # Title
        if title_text:
            title = tk.Label(
                self,
                text=title_text,
                font=(self._font_family, title_font_size, "bold"),
                bg=self._bg_color,
                fg=self._fg_color,
            )
            title.pack(pady=(0, 30))

        # Username row
        if show_username:
            username_frame = tk.Frame(self, bg=self._bg_color)
            username_frame.pack(fill=tk.X, pady=(0, 15))
            username_label = tk.Label(
                username_frame,
                text="Username:",
                font=(self._font_family, label_font_size),
                bg=self._bg_color,
                fg=self._fg_color,
                width=12,
                anchor="e",
            )
            username_label.pack(side=tk.LEFT, padx=(0, 10))
            self._username_entry = tk.Entry(
                username_frame,
                textvariable=self._username_var,
                font=(self._font_family, entry_font_size),
                width=30,
                bg="#2c3e50",
                fg=self._fg_color,
                insertbackground=self._fg_color,
                relief=tk.FLAT,
            )
            self._username_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Password row
        password_frame = tk.Frame(self, bg=self._bg_color)
        password_frame.pack(fill=tk.X, pady=(0, 20))
        password_label = tk.Label(
            password_frame,
            text="Password:",
            font=(self._font_family, label_font_size),
            bg=self._bg_color,
            fg=self._fg_color,
            width=12,
            anchor="e",
        )
        password_label.pack(side=tk.LEFT, padx=(0, 10))
        self._password_entry = tk.Entry(
            password_frame,
            textvariable=self._password_var,
            font=(self._font_family, entry_font_size),
            width=30,
            show="*",
            bg="#2c3e50",
            fg=self._fg_color,
            insertbackground=self._fg_color,
            relief=tk.FLAT,
        )
        self._password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Method selection label
        method_label = tk.Label(
            self,
            text="Method:",
            font=(self._font_family, label_font_size),
            bg=self._bg_color,
            fg=self._fg_color,
            anchor="w",
        )
        method_label.pack(fill=tk.X, pady=(0, 10))

        # FIDO2 option
        fido2_frame = tk.Frame(self, bg=self._bg_color)
        fido2_frame.pack(fill=tk.X, pady=(0, 5))
        fido2_state: Literal["normal", "active", "disabled"] = (
            "normal" if self._fido2_available else "disabled"
        )
        fido2_label_text = "Password + FIDO2" if self._fido2_available else "FIDO2 (unavailable)"
        fido2_label_fg = self._fg_color if self._fido2_available else "#7f8c8d"
        self._fido2_radio = tk.Radiobutton(
            fido2_frame,
            variable=self._method_var,
            value=self.METHOD_FIDO2,
            bg=self._bg_color,
            activebackground=self._bg_color,
            command=self._on_method_changed,
            state=fido2_state,
        )
        self._fido2_radio.pack(side=tk.LEFT)
        self._fido2_text_label = tk.Label(
            fido2_frame,
            text=fido2_label_text,
            font=(self._font_family, label_font_size - 1),
            bg=self._bg_color,
            fg=fido2_label_fg,
            anchor="w",
        )
        self._fido2_text_label.pack(side=tk.LEFT)
        self._fido2_info_label = tk.Label(
            fido2_frame,
            text="Connect FIDO2 key",
            font=(self._font_family, label_font_size - 2, "italic"),
            bg=self._bg_color,
            fg="#3498db",
            cursor="hand2",
        )
        if self._fido2_available:
            self._fido2_info_label.pack(side=tk.LEFT, padx=(10, 0))

        # TOTP option
        totp_frame = tk.Frame(self, bg=self._bg_color)
        totp_frame.pack(fill=tk.X, pady=(0, 5))
        totp_radio = tk.Radiobutton(
            totp_frame,
            variable=self._method_var,
            value=self.METHOD_TOTP,
            bg=self._bg_color,
            activebackground=self._bg_color,
            command=self._on_method_changed,
        )
        totp_radio.pack(side=tk.LEFT)
        totp_text = tk.Label(
            totp_frame,
            text="Password + TOTP",
            font=(self._font_family, label_font_size - 1),
            bg=self._bg_color,
            fg=self._fg_color,
            anchor="w",
        )
        totp_text.pack(side=tk.LEFT)

        # Backup Code option
        backup_frame = tk.Frame(self, bg=self._bg_color)
        backup_frame.pack(fill=tk.X, pady=(0, 15))
        backup_radio = tk.Radiobutton(
            backup_frame,
            variable=self._method_var,
            value=self.METHOD_BACKUP,
            bg=self._bg_color,
            activebackground=self._bg_color,
            command=self._on_method_changed,
        )
        backup_radio.pack(side=tk.LEFT)
        backup_text = tk.Label(
            backup_frame,
            text="Password + Backup Code",
            font=(self._font_family, label_font_size - 1),
            bg=self._bg_color,
            fg=self._fg_color,
            anchor="w",
        )
        backup_text.pack(side=tk.LEFT)

        # Dynamic token frame (for TOTP and Backup)
        self._token_frame = tk.Frame(self, bg=self._bg_color)
        self._token_frame.pack(fill=tk.X, pady=(0, 15))
        self._token_label = tk.Label(
            self._token_frame,
            text="Token:",
            font=(self._font_family, label_font_size),
            bg=self._bg_color,
            fg=self._fg_color,
            width=12,
            anchor="e",
        )
        self._token_label.pack(side=tk.LEFT, padx=(0, 10))
        self._token_entry = tk.Entry(
            self._token_frame,
            textvariable=self._token_var,
            font=(self._font_family, entry_font_size),
            width=20,
            bg="#2c3e50",
            fg=self._fg_color,
            insertbackground=self._fg_color,
            relief=tk.FLAT,
        )
        self._token_entry.pack(side=tk.LEFT)
        self._token_hint = tk.Label(
            self._token_frame,
            text="(6-digit code)",
            font=(self._font_family, label_font_size - 2),
            bg=self._bg_color,
            fg="#7f8c8d",
        )
        self._token_hint.pack(side=tk.LEFT, padx=(5, 0))

        # Buttons frame
        buttons_frame = tk.Frame(self, bg=self._bg_color)
        buttons_frame.pack(fill=tk.X, pady=(20, 15))

        self._submit_btn = tk.Button(
            buttons_frame,
            text=self._submit_text,
            font=(self._font_family, button_font_size),
            command=self._on_submit_clicked,
            bg=self._accent_color,
            fg=self._fg_color,
            activebackground="#2ecc71",
            activeforeground=self._fg_color,
            relief=tk.FLAT,
            padx=20,
            pady=8,
            cursor="hand2",
        )
        self._submit_btn.pack(side=tk.LEFT, padx=(0, 10))

        if show_cancel:
            cancel_btn = tk.Button(
                buttons_frame,
                text=cancel_text,
                font=(self._font_family, button_font_size),
                command=self._on_cancel_clicked,
                bg="#7f8c8d",
                fg=self._fg_color,
                activebackground="#95a5a6",
                activeforeground=self._fg_color,
                relief=tk.FLAT,
                padx=20,
                pady=8,
                cursor="hand2",
            )
            cancel_btn.pack(side=tk.LEFT)

        # Error label
        self._error_label = tk.Label(
            self,
            text="",
            font=(self._font_family, label_font_size),
            bg=self._bg_color,
            fg=self._error_color,
            anchor="w",
        )
        self._error_label.pack(fill=tk.X)

        # Bind Enter on password and token entries
        if self._password_entry is not None:
            self._password_entry.bind("<Return>", lambda e: self._focus_token())
        if self._token_entry is not None:
            self._token_entry.bind("<Return>", lambda e: self._on_submit_clicked())

    def _focus_token(self) -> None:
        """Переносит фокус на поле токена."""
        if self._token_entry is not None and self._token_entry.winfo_exists():
            self._token_entry.focus_set()

    def _on_method_changed(self, *args: Any) -> None:
        """Обработчик смены метода MFA."""
        method = self._method_var.get()

        if method == self.METHOD_FIDO2:
            if self._token_frame is not None:
                self._token_frame.pack_forget()
            if self._fido2_info_label is not None:
                self._fido2_info_label.config(fg="#f39c12")
            if self._fido2_available:
                if self._submit_btn is not None:
                    self._submit_btn.config(state="normal")
            else:
                if self._submit_btn is not None:
                    self._submit_btn.config(state="disabled")
        else:
            if self._submit_btn is not None:
                self._submit_btn.config(state="normal")
            if self._fido2_info_label is not None:
                self._fido2_info_label.config(fg="#3498db")
            if self._token_frame is not None:
                self._token_frame.pack(fill=tk.X, pady=(0, 15))
            if method == self.METHOD_TOTP:
                if self._token_label is not None:
                    self._token_label.config(text="Token:")
                if self._token_hint is not None:
                    self._token_hint.config(text="(6-digit code)")
            elif method == self.METHOD_BACKUP:
                if self._token_label is not None:
                    self._token_label.config(text="Token:")
                if self._token_hint is not None:
                    self._token_hint.config(text="(backup code)")

    def _on_submit_clicked(self) -> None:
        """Обработчик кнопки отправки формы."""
        password = self._password_var.get()
        method = self._method_var.get()
        token = self._token_var.get()

        # Validate
        if not password:
            self._show_error("Password is required")
            if self._password_entry is not None:
                self._password_entry.focus_set()
            return

        if method == self.METHOD_FIDO2:
            if not self._fido2_available:
                self._show_error("FIDO2 unavailable: device not connected")
                return
            self._perform_fido2_authentication(password)
            return

        if method in (self.METHOD_TOTP, self.METHOD_BACKUP) and not token:
            self._show_error("Token is required")
            if self._token_entry is not None:
                self._token_entry.focus_set()
            return

        if method == self.METHOD_TOTP:
            if not token.isdigit() or len(token) != 6:
                self._show_error("TOTP must be 6 digits")
                if self._token_entry is not None:
                    self._token_entry.focus_set()
                return

        if self._on_submit is None:
            self._show_error("Submit handler not configured")
            return

        # Disable button during verification
        if self._submit_btn is not None:
            self._submit_btn.config(state="disabled", text="Verifying...")

        try:
            username = self._username_var.get()
            result = self._on_submit(username, password, method, token)
            if not result:
                self._show_error("Invalid credentials")
                self.wipe_credentials()
        except (AuthError, CryptoError) as e:
            # Security: CRITICAL logging and generic UI alert
            logging.critical("MFA Authentication security error: %s", e, exc_info=True)
            self._show_error("Authentication error")
            self.wipe_credentials()
        except Exception as e:
            # Log authentication error without exposing sensitive info
            logging.error("Unexpected authentication error occurred: %s", e, exc_info=True)
            self._show_error("Authentication error")
            self.wipe_credentials()
        finally:
            if self._submit_btn is not None and self._submit_btn.winfo_exists():
                self._submit_btn.config(state="normal", text=self._submit_text)

    def _perform_fido2_authentication(self, password: str) -> None:
        """Выполняет FIDO2-аутентификацию через on_fido2_request callback.

        Args:
            password: Введённый пароль (передаётся в callback).

        Security:
            - Не логирует пароль.
            - Показывает user-friendly статус.
        """
        if self._on_fido2_request is None:
            self._show_error("FIDO2 not configured")
            return

        if self._submit_btn is not None:
            self._submit_btn.config(state="disabled", text="Authenticating...")

        self._show_error("")
        self._show_error("Коснитесь FIDO2 ключа...")

        try:
            username = self._username_var.get()
            result = self._on_fido2_request(username, password)
            if not result:
                self._show_error("FIDO2 аутентификация не удалась")
                self.wipe_credentials()
            else:
                self._show_error("")
        except (AuthError, CryptoError) as e:
            logging.critical("FIDO2 authentication security error: %s", e, exc_info=True)
            self._show_error("FIDO2 аутентификация не удалась")
            self.wipe_credentials()
        except Exception as e:
            logging.error("Unexpected FIDO2 error occurred: %s", e, exc_info=True)
            self._show_error("FIDO2 аутентификация не удалась")
            self.wipe_credentials()
        finally:
            if self._submit_btn is not None and self._submit_btn.winfo_exists():
                self._submit_btn.config(state="normal", text=self._submit_text)

    def _on_cancel_clicked(self) -> None:
        """Обработчик кнопки Cancel."""
        self.wipe_credentials()
        if self._on_cancel is not None:
            self._on_cancel()

    def _show_error(self, message: str) -> None:
        """Показывает сообщение об ошибке."""
        if self._error_label is not None:
            self._error_label.config(text=message)

    def wipe_credentials(self) -> None:
        """Security: очистить поля ввода.

        Очищает все поля ввода credentials для предотвращения
        утечки sensitive данных.
        """
        self._username_var.set("")
        self._password_var.set("")
        self._token_var.set("")
        if self._error_label is not None:
            self._error_label.config(text="")

    def focus_password(self) -> None:
        """Устанавливает фокус на поле пароля."""
        if self._password_entry is not None and self._password_entry.winfo_exists():
            self._password_entry.focus_set()

    def get_username(self) -> str:
        """Возвращает введённый username.

        Returns:
            Строка с username.
        """
        return self._username_var.get()

    def get_password(self) -> str:
        """Возвращает введённый пароль.

        Returns:
            Строка с паролем.
        """
        return self._password_var.get()

    def get_method(self) -> str:
        """Возвращает выбранный метод MFA.

        Returns:
            Строка с именем метода.
        """
        return self._method_var.get()

    def get_token(self) -> str:
        """Возвращает введённый токен.

        Returns:
            Строка с токеном.
        """
        return self._token_var.get()

    def set_error(self, message: str) -> None:
        """Устанавливает сообщение об ошибке.

        Args:
            message: Текст ошибки.
        """
        self._show_error(message)


# Module exports
__all__: list[str] = [
    "MFAForm",
    "MfaSubmitCallback",
    "Fido2RequestCallback",
]
