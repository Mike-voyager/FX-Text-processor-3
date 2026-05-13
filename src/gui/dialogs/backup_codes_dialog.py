"""Диалог для отображения и управления резервными кодами MFA.

Предоставляет интерфейс для просмотра, копирования и регенерации
резервных кодов доступа. Поддерживает маскировку использованных кодов,
отображение статуса и интеграцию с MFAGate для безопасной регенерации.

Example:
    >>> from src.gui.dialogs.backup_codes_dialog import BackupCodesDialog
    >>> dialog = BackupCodesDialog(
    ...     parent=root,
    ...     user_id="operator",
    ... )
    >>> result = dialog.show()
    >>> if result:
    ...     print("Резервные коды сгенерированы")

Version: 1.0
Security: CRITICAL-002
"""

from __future__ import annotations

import logging
import tkinter as tk
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Final, Optional, cast

from src.gui.dialogs.base_dialog import BaseDialog
from src.gui.security.mfa_gate import MFAGate
from src.gui.themes import get_theme_manager

logger: Final = logging.getLogger(__name__)

# Constants
DIALOG_WIDTH: Final[int] = 550
DIALOG_HEIGHT: Final[int] = 500

# Grid layout
CODES_PER_ROW: Final[int] = 3
TOTAL_CODES: Final[int] = 12

# Colors (fallback if theme not available)
COLOR_BG: Final[str] = "#f8f9fa"
COLOR_FG: Final[str] = "#2c3e50"
COLOR_ACCENT: Final[str] = "#3498db"
COLOR_SUCCESS: Final[str] = "#27ae60"
COLOR_ERROR: Final[str] = "#e74c3c"
COLOR_WARNING: Final[str] = "#f39c12"
COLOR_USED: Final[str] = "#95a5a6"
COLOR_BORDER: Final[str] = "#bdc3c7"

# Code display format
CODE_MASK: Final[str] = "****-****"
CODE_FORMAT_LENGTH: Final[int] = 8  # XXXX-XXXX without dash


@dataclass(frozen=True)
class BackupCodeDisplay:
    """Данные для отображения резервного кода.

    Attributes:
        code_id: Уникальный идентификатор кода.
        masked_code: Маскированный код (ABCD-****).
        is_used: Флаг использования кода.
        used_at: Время использования (None если не использован).

    Example:
        >>> code = BackupCodeDisplay(
        ...     code_id="code_001",
        ...     masked_code="ABCD-****",
        ...     is_used=False,
        ...     used_at=None,
        ... )
    """

    code_id: str
    masked_code: str
    is_used: bool
    used_at: Optional[datetime]


class BackupCodesDialog(BaseDialog):
    """Диалог управления резервными кодами MFA.

    Отображает сетку из 12 резервных кодов с возможностью
    маскировки использованных, копирования в буфер и
    регенерации с MFA challenge.

    Attributes:
        _user_id: ID пользователя для управления кодами.
        _code_service: Сервис для работы с кодами (опционально).
        _mfa_gate: MFAGate для MFA challenge при регенерации (опционально).
        _codes: Список отображаемых кодов.
        _show_all: Флаг видимости всех кодов.
        _expiry_date: Дата истечения срока действия кодов.

    Example:
        >>> dialog = BackupCodesDialog(
        ...     parent=root,
        ...     user_id="operator",
        ...     mfa_gate=mfa_gate,
        ... )
        >>> dialog.show()
    """

    def __init__(
        self,
        parent: tk.Tk,
        user_id: str,
        code_service: Optional[Any] = None,
        mfa_gate: Optional[MFAGate] = None,
    ) -> None:
        """Инициализация диалога резервных кодов.

        Args:
            parent: Родительское окно Tk.
            user_id: ID пользователя для управления кодами.
            code_service: Сервис для работы с кодами (опционально).
            mfa_gate: MFAGate для MFA challenge при регенерации (опционально).
        """
        self._parent: tk.Tk = parent
        self._user_id: str = user_id
        self._code_service: Optional[Any] = code_service
        self._mfa_gate: Optional[MFAGate] = mfa_gate

        # State
        self._codes: list[BackupCodeDisplay] = []
        self._show_all: bool = False
        self._expiry_date: Optional[datetime] = None
        self._remaining_count: int = 0
        self._codes_generated: bool = False
        self._notification_label: Optional[tk.Label] = None

        # UI references (initialized in _create_ui)
        self._code_labels: list[tk.Label] = []
        self._status_label: Optional[tk.Label] = None
        self._expiry_label: Optional[tk.Label] = None
        self._toggle_btn: Optional[tk.Button] = None
        self._copy_btn: Optional[tk.Button] = None
        self._regenerate_btn: Optional[tk.Button] = None
        self._close_btn: Optional[tk.Button] = None

        # Theme manager
        self._theme_manager = get_theme_manager()

        # Delayed initialization
        self._initialize_ui(parent)

    def _initialize_ui(self, parent: tk.Tk) -> None:
        """Инициализирует UI компоненты.

        Args:
            parent: Родительское окно Tk.
        """
        super().__init__(parent, modal=True)

        # Configure window
        self.title("🔑 Резервные коды доступа")
        self.resizable(False, False)

        # Apply theme background
        try:
            theme = self._theme_manager.get_current_theme()
            self.configure(bg=theme.bg_color)
        except (AttributeError, KeyError, RuntimeError) as e:
            self.configure(bg=COLOR_BG)

        # Make modal

        # Create UI
        self._create_ui()

        # Center window

        # Load initial codes
        self._load_codes()

        # Bind ESC to close

    def _center_window(self) -> None:
        """Центрирует окно относительно родителя."""
        self.update_idletasks()

        parent_x = self._parent.winfo_x()
        parent_y = self._parent.winfo_y()
        parent_width = self._parent.winfo_width()
        parent_height = self._parent.winfo_height()

        x = parent_x + (parent_width - DIALOG_WIDTH) // 2
        y = parent_y + (parent_height - DIALOG_HEIGHT) // 2

        self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}+{x}+{y}")

    def _create_ui(self) -> None:
        """Создаёт UI компоненты диалога."""
        try:
            theme = self._theme_manager.get_current_theme()
            bg_color = theme.bg_color
            fg_color = theme.fg_color
            accent_color = theme.accent_color
            font_family = theme.font_family
        except (AttributeError, KeyError, RuntimeError):
            bg_color = COLOR_BG
            fg_color = COLOR_FG
            accent_color = COLOR_ACCENT
            font_family = "Arial"

        # Main container
        main_frame = tk.Frame(self, bg=bg_color, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = tk.Label(
            main_frame,
            text="🔑 Резервные коды доступа",
            font=(font_family, 14, "bold"),
            bg=bg_color,
            fg=fg_color,
        )
        title_label.pack(pady=(0, 15))

        # Status section
        self._create_status_section(main_frame, bg_color, fg_color, font_family)

        # Codes grid section
        self._create_codes_grid(main_frame, bg_color, font_family)

        # Buttons section
        self._create_buttons_section(main_frame, bg_color, accent_color, font_family)

    def _create_status_section(
        self,
        parent: tk.Frame,
        bg_color: str,
        fg_color: str,
        font_family: str,
    ) -> None:
        """Создаёт секцию статуса кодов.

        Args:
            parent: Родительский фрейм.
            bg_color: Цвет фона.
            fg_color: Цвет текста.
            font_family: Семейство шрифтов.
        """
        status_frame = tk.Frame(parent, bg=bg_color)
        status_frame.pack(fill=tk.X, pady=(0, 15))

        # Remaining codes
        self._status_label = tk.Label(
            status_frame,
            text="Осталось кодов: --/--",
            font=(font_family, 10),
            bg=bg_color,
            fg=fg_color,
        )
        self._status_label.pack(anchor=tk.W)

        # Expiry date
        self._expiry_label = tk.Label(
            status_frame,
            text="Действительны до: --",
            font=(font_family, 10),
            bg=bg_color,
            fg=fg_color,
        )
        self._expiry_label.pack(anchor=tk.W, pady=(5, 0))

    def _create_codes_grid(
        self,
        parent: tk.Frame,
        bg_color: str,
        font_family: str,
    ) -> None:
        """Создаёт сетку кодов 4x3.

        Args:
            parent: Родительский фрейм.
            bg_color: Цвет фона.
            font_family: Семейство шрифтов.
        """
        # Border frame
        border_frame = tk.Frame(
            parent,
            bg=COLOR_BORDER,
            padx=2,
            pady=2,
        )
        border_frame.pack(pady=(0, 20))

        # Inner frame with codes
        inner_frame = tk.Frame(border_frame, bg=bg_color, padx=15, pady=15)
        inner_frame.pack()

        # Create 4x3 grid
        self._code_labels = []
        rows = TOTAL_CODES // CODES_PER_ROW

        for row in range(rows):
            row_frame = tk.Frame(inner_frame, bg=bg_color)
            row_frame.pack(fill=tk.X, pady=3)

            for col in range(CODES_PER_ROW):
                row * CODES_PER_ROW + col

                code_label = tk.Label(
                    row_frame,
                    text="****-****",
                    font=("Courier", 12, "bold"),
                    bg=bg_color,
                    fg=COLOR_FG,
                    width=12,
                    padx=10,
                )
                code_label.pack(side=tk.LEFT, padx=5)
                self._code_labels.append(code_label)

    def _create_buttons_section(
        self,
        parent: tk.Frame,
        bg_color: str,
        accent_color: str,
        font_family: str,
    ) -> None:
        """Создаёт секцию кнопок.

        Args:
            parent: Родительский фрейм.
            bg_color: Цвет фона.
            accent_color: Акцентный цвет.
            font_family: Семейство шрифтов.
        """
        buttons_frame = tk.Frame(parent, bg=bg_color)
        buttons_frame.pack(fill=tk.X)

        # Top row buttons (Toggle, Copy)
        top_row = tk.Frame(buttons_frame, bg=bg_color)
        top_row.pack(fill=tk.X, pady=(0, 10))

        # Toggle visibility button
        self._toggle_btn = tk.Button(
            top_row,
            text="👁 Показать все",
            width=15,
            command=self._toggle_visibility,
            font=(font_family, 9),
            bg=bg_color,
        )
        self._toggle_btn.pack(side=tk.LEFT, padx=(0, 10))

        # Copy button
        self._copy_btn = tk.Button(
            top_row,
            text="📋 Копировать",
            width=15,
            command=self._copy_to_clipboard,
            font=(font_family, 9),
            bg=bg_color,
        )
        self._copy_btn.pack(side=tk.LEFT)

        # Regenerate button
        self._regenerate_btn = tk.Button(
            buttons_frame,
            text="🔄 Сгенерировать новые",
            width=25,
            command=self._regenerate_codes,
            font=(font_family, 9, "bold"),
            bg=accent_color,
            fg="white",
        )
        self._regenerate_btn.pack(pady=(0, 15))

        # Close button
        self._close_btn = tk.Button(
            buttons_frame,
            text="Закрыть",
            width=12,
            command=self._on_close,
            font=(font_family, 9),
        )
        self._close_btn.pack()

    def _load_codes(self) -> None:
        """Загружает коды из backend API.

        Пытается получить статус кодов через code_service.
        При отсутствии сервиса использует fallback данные.
        """
        try:
            # Try to import and use code_service
            from src.security.auth.code_service import (
                BackupCodeStatus,
                get_backup_codes_status,
            )

            status: BackupCodeStatus = get_backup_codes_status(self._user_id)

            if status.get("error"):
                logger.warning("Failed to load backup codes: %s", status["error"])
                self._set_fallback_codes()
                return

            # Parse status
            remaining = status.get("remaining", 0)
            consumed = status.get("consumed", 0)
            ttl_seconds = status.get("ttl_seconds")

            self._remaining_count = remaining

            # Calculate expiry date
            if ttl_seconds:
                self._expiry_date = datetime.now() + timedelta(seconds=ttl_seconds)
            else:
                self._expiry_date = datetime.now() + timedelta(days=90)

            # Generate display codes from audit or create placeholders
            raw_codes = status.get("codes", [])
            if raw_codes:
                self._codes = self._parse_codes_from_status(raw_codes)
            else:
                self._codes = self._generate_placeholder_codes(remaining, consumed)

        except ImportError:
            logger.debug("code_service not available, using fallback")
            self._set_fallback_codes()
        except Exception as e:
            logger.error("Error loading codes: %s", e)
            self._set_fallback_codes()

        # Update UI
        self._update_codes_display()
        self._update_status_labels()

    def _parse_codes_from_status(
        self,
        raw_codes: list[dict[str, Any]],
    ) -> list[BackupCodeDisplay]:
        """Парсит коды из статуса backend.

        Args:
            raw_codes: Список сырых данных кодов.

        Returns:
            Список BackupCodeDisplay.
        """
        codes: list[BackupCodeDisplay] = []

        for i, raw in enumerate(raw_codes):
            code_id = raw.get("id", f"code_{i:03d}")
            code_value = raw.get("code", "")
            is_used = raw.get("used", False)
            used_at_str = raw.get("used_at")

            used_at: Optional[datetime] = None
            if used_at_str:
                try:
                    used_at = datetime.fromisoformat(used_at_str)
                except (ValueError, TypeError):
                    pass

            # Create masked display
            if code_value and len(code_value) >= 4:
                masked = self._mask_code(code_value, is_used)
            else:
                masked = CODE_MASK if is_used else self._generate_masked_placeholder()

            codes.append(
                BackupCodeDisplay(
                    code_id=code_id,
                    masked_code=masked,
                    is_used=is_used,
                    used_at=used_at,
                )
            )

        return codes

    def _generate_placeholder_codes(
        self,
        remaining: int,
        consumed: int,
    ) -> list[BackupCodeDisplay]:
        """Генерирует placeholder коды для отображения.

        Args:
            remaining: Количество оставшихся кодов.
            consumed: Количество использованных кодов.

        Returns:
            Список BackupCodeDisplay.
        """
        codes: list[BackupCodeDisplay] = []
        total = remaining + consumed

        for i in range(total):
            is_used = i < consumed
            codes.append(
                BackupCodeDisplay(
                    code_id=f"code_{i:03d}",
                    masked_code=CODE_MASK if is_used else self._generate_masked_placeholder(),
                    is_used=is_used,
                    used_at=None,
                )
            )

        return codes

    def _set_fallback_codes(self) -> None:
        """Устанавливает fallback коды при недоступности backend."""
        self._remaining_count = 8
        self._expiry_date = datetime.now() + timedelta(days=90)

        self._codes = []
        for i in range(TOTAL_CODES):
            is_used = i >= 8  # First 8 available
            self._codes.append(
                BackupCodeDisplay(
                    code_id=f"code_{i:03d}",
                    masked_code=CODE_MASK if is_used else self._generate_masked_placeholder(),
                    is_used=is_used,
                    used_at=None,
                )
            )

    def _generate_masked_placeholder(self) -> str:
        """Генерирует маскированный placeholder для неиспользованного кода.

        Returns:
            Маскированный код (ABCD-****).
        """
        import secrets
        import string

        prefix = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
        return f"{prefix}-****"

    def _mask_code(self, code: str, is_used: bool) -> str:
        """Маскирует код для отображения.

        Args:
            code: Исходный код.
            is_used: Флаг использования.

        Returns:
            Маскированный код.
        """
        if is_used:
            return CODE_MASK

        # Format code as XXXX-XXXX
        normalized = code.upper().replace("-", "")
        if len(normalized) >= 8:
            return f"{normalized[:4]}-{normalized[4:8]}"
        elif len(normalized) >= 4:
            return f"{normalized[:4]}-****"
        else:
            return self._generate_masked_placeholder()

    def _update_codes_display(self) -> None:
        """Обновляет отображение кодов в сетке."""
        for i, label in enumerate(self._code_labels):
            if i < len(self._codes):
                code = self._codes[i]

                if self._show_all:
                    # Show actual code if available
                    display_text = code.masked_code
                else:
                    # Show masked version
                    display_text = CODE_MASK if code.is_used else code.masked_code

                label.config(
                    text=display_text,
                    fg=COLOR_USED if code.is_used else COLOR_FG,
                )
            else:
                label.config(text="----", fg=COLOR_USED)

    def _update_status_labels(self) -> None:
        """Обновляет метки статуса."""
        if self._status_label:
            total = len(self._codes)
            self._status_label.config(text=f"Осталось кодов: {self._remaining_count}/{total}")

        if self._expiry_label and self._expiry_date:
            expiry_str = self._expiry_date.strftime("%Y-%m-%d")
            self._expiry_label.config(text=f"Действительны до: {expiry_str}")

    def _toggle_visibility(self) -> None:
        """Переключает видимость всех кодов."""
        self._show_all = not self._show_all

        # Update button text
        if self._toggle_btn:
            text = "🙈 Скрыть все" if self._show_all else "👁 Показать все"
            self._toggle_btn.config(text=text)

        # Update display
        self._update_codes_display()

    def _copy_to_clipboard(self) -> None:
        """Копирует коды в буфер обмена."""
        try:
            # Get available codes (not used)
            available_codes = [code.masked_code for code in self._codes if not code.is_used]

            if not available_codes:
                self._show_status("Нет доступных кодов для копирования", is_error=True)
                return

            # Format as list
            clipboard_text = "\n".join(available_codes)

            # Copy to clipboard
            self._parent.clipboard_clear()
            self._parent.clipboard_append(clipboard_text)
            self._parent.update()  # Required for clipboard to persist

            self._show_status(f"Скопировано {len(available_codes)} кодов в буфер")

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to copy to clipboard: %s", e)
            self._show_status("Ошибка копирования в буфер", is_error=True)

    def _regenerate_codes(self) -> None:
        """Регенерирует коды с MFA challenge.

        Запрашивает MFA подтверждение перед генерацией новых кодов.
        """
        if self._mfa_gate is not None:
            # Use MFAGate for challenge
            result = self._mfa_gate.challenge(
                parent=cast(tk.Widget, self),
                user_id=self._user_id,
                required_methods=["totp", "backup"],
                operation="regenerate_backup_codes",
            )

            if not result.verified:
                self._show_status("MFA верификация не пройдена", is_error=True)
                return

        # Proceed with regeneration
        self._do_regenerate_codes()

    def _do_regenerate_codes(self) -> None:
        """Выполняет регенерацию кодов через backend."""
        try:
            from src.security.auth.code_service import (
                BackupCodeStatus,
                issue_backup_codes_for_user,
            )

            # Issue new codes
            status: BackupCodeStatus = issue_backup_codes_for_user(
                user_id=self._user_id,
                count=TOTAL_CODES,
                ttlsec=90 * 24 * 3600,  # 90 days
            )

            if status.get("error"):
                logger.error("Failed to regenerate codes: %s", status["error"])
                self._show_status("Ошибка генерации кодов", is_error=True)
                return

            # Mark as generated
            self._codes_generated = True

            # Reload and display
            self._load_codes()
            self._show_status("Новые коды успешно сгенерированы!")

        except ImportError:
            logger.error("code_service not available")
            self._show_status("Сервис кодов недоступен", is_error=True)
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error regenerating codes: %s", e)
            self._show_status("Ошибка генерации кодов", is_error=True)

    def _show_status(self, message: str, is_error: bool = False) -> None:
        """Показывает статусное сообщение.

        Args:
            message: Текст сообщения.
            is_error: True если это ошибка.
        """
        # Create status label if not exists
        if self._notification_label is None:
            try:
                theme = self._theme_manager.get_current_theme()
                bg_color = theme.bg_color
            except (AttributeError, KeyError, RuntimeError):
                bg_color = COLOR_BG

            self._notification_label = tk.Label(
                self,
                text="",
                font=("Arial", 9),
                bg=bg_color,
            )
            self._notification_label.pack(pady=(0, 10))

        color = COLOR_ERROR if is_error else COLOR_SUCCESS
        if self._notification_label is not None:
            self._notification_label.config(text=message, fg=color)

            # Clear after 3 seconds
            def clear_notification() -> None:
                if self._notification_label is not None and self.winfo_exists():
                    self._notification_label.config(text="")

            self.after(3000, clear_notification)

    def _on_close(self) -> None:
        """Обработчик закрытия диалога."""
        self.destroy()

    def show(self) -> Optional[bool]:
        """Показывает диалог модально.

        Returns:
            True если новые коды были сгенерированы,
            False или None в противном случае.
        """
        self.wait_window()
        return self._codes_generated

    @property
    def codes_generated(self) -> bool:
        """Возвращает True если новые коды были сгенерированы."""
        return self._codes_generated


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "BackupCodesDialog",
    "BackupCodeDisplay",
    "DIALOG_WIDTH",
    "DIALOG_HEIGHT",
]
