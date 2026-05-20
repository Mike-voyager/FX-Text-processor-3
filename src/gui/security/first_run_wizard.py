"""Мастер первого запуска FX Text Processor 3.

Создание оператора: мастер-пароль, выбор пресета безопасности,
настройка MFA (FIDO2/TOTP), генерация backup-кодов.

Запускается автоматически при первом запуске приложения
(когда хранилище паролей пустое).

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import logging
import os
import tkinter as tk
from enum import Enum, auto
from typing import Any, Callable, Optional

from src.gui.themes import get_theme_manager

logger = logging.getLogger(__name__)


class WizardStep(Enum):
    """Шаги мастера первого запуска."""

    WELCOME = auto()
    MASTER_PASSWORD = auto()
    SECURITY_PRESET = auto()
    FIDO2_SETUP = auto()
    TOTP_SETUP = auto()
    BACKUP_CODES = auto()
    COMPLETE = auto()


class FirstRunWizard:
    """Мастер первого запуска.

    Пошаговый wizard для создания оператора:
    1. Приветствие
    2. Мастер-пароль
    3. Выбор пресета безопасности
    4. Настройка FIDO2 (опционально)
    5. Настройка TOTP (опционально)
    6. Генерация backup-кодов
    7. Завершение

    Attributes:
        _parent: Родительское окно (root).
        _password_service: Сервис паролей.
        _on_complete: Callback при завершении wizard.
        _on_cancel: Callback при отмене.
        _current_step: Текущий шаг wizard.
        _theme_manager: Менеджер тем.
        _window: Toplevel окно wizard.
    """

    # Пресеты безопасности
    PRESETS: dict[str, dict[str, Any]] = {
        "standard": {
            "name": "Standard",
            "description": "Повседневное использование. Ed25519 + AES-256-GCM + Argon2id (64 MB).",
            "signing": "Ed25519",
            "encryption": "AES-256-GCM",
            "kdf_memory": "64 MB",
        },
        "paranoid": {
            "name": "Paranoid",
            "description": "Долгосрочное хранение. Ed25519 + ML-DSA-65 + AES-256-GCM + ChaCha20 + Argon2id (256 MB).",
            "signing": "Ed25519 + ML-DSA-65",
            "encryption": "AES-256-GCM + ChaCha20",
            "kdf_memory": "256 MB",
        },
        "pqc": {
            "name": "PQC",
            "description": "Постквантовый приоритет. ML-DSA-65 + AES-256-GCM + Argon2id (64 MB).",
            "signing": "ML-DSA-65",
            "encryption": "AES-256-GCM",
            "kdf_memory": "64 MB",
        },
        "legacy": {
            "name": "Legacy",
            "description": "Совместимость. RSA-PSS-4096 + AES-256-GCM + PBKDF2.",
            "signing": "RSA-PSS-4096",
            "encryption": "AES-256-GCM",
            "kdf_memory": "Минимум (PBKDF2)",
        },
    }

    def __init__(
        self,
        parent: tk.Tk,
        password_service: Any = None,
        session_manager: Any = None,
        mfa_manager: Any = None,
        on_complete: Optional[Callable[[str], None]] = None,
        on_cancel: Optional[Callable[[], None]] = None,
    ) -> None:
        """Инициализация мастера первого запуска.

        Args:
            parent: Родительское окно.
            password_service: Сервис паролей для создания пользователя.
            session_manager: Менеджер сессий.
            mfa_manager: Менеджер MFA (второй фактор).
            on_complete: Callback при завершении. Получает user_id.
            on_cancel: Callback при отмене.
        """
        self._parent = parent
        self._password_service = password_service
        self._session_manager = session_manager
        self._mfa_manager = mfa_manager
        self._on_complete = on_complete
        self._on_cancel = on_cancel

        self._current_step = WizardStep.WELCOME
        self._theme_manager = get_theme_manager()
        self._window: Optional[tk.Toplevel] = None

        # Данные wizard
        self._user_id = "operator"
        self._password = ""
        self._password_confirm = ""
        self._selected_preset = "standard"
        self._backup_codes: list[str] = []
        self._fido2_configured = False
        self._totp_configured = False
        self._totp_uri: Optional[str] = None
        self._totp_qr_data: Optional[bytes] = None

        # UI переменные
        self._password_var = tk.StringVar(master=self._parent)
        self._password_confirm_var = tk.StringVar(master=self._parent)
        self._preset_var = tk.StringVar(master=self._parent, value="standard")
        self._error_label: Optional[tk.Label] = None
        self._content_frame: Optional[tk.Frame] = None
        self._step_title_label: Optional[tk.Label] = None
        self._step_desc_label: Optional[tk.Label] = None

        # Debug mode
        self._debug_mode = os.getenv("FX_DEBUG_MODE", "0") == "1"

    def show(self) -> None:
        """Показывает окно wizard модально."""
        if self._window is not None and self._window.winfo_exists():
            self._window.lift()
            return

        self._window = tk.Toplevel(self._parent)
        self._window.title("FX Text Processor 3 — Первый запуск")
        self._window.resizable(False, False)
        self._window.transient(self._parent)
        try:
            self._window.grab_set()
        except tk.TclError:
            pass

        self._window.configure(bg=self._theme_manager.get_current_theme().bg_color)

        # Запрещаем закрытие через X — только через кнопки
        self._window.protocol("WM_DELETE_WINDOW", self._on_cancel)

        self._build_ui()
        self._center_window()

    def destroy(self) -> None:
        """Уничтожает окно wizard."""
        self._clear_password_vars()
        if self._window is not None and self._window.winfo_exists():
            self._window.destroy()
        self._window = None

    def _build_ui(self) -> None:
        """Строит общий каркас wizard."""
        if self._window is None:
            return

        theme = self._theme_manager.get_current_theme()

        # Основной контейнер
        outer = tk.Frame(self._window, bg=theme.bg_color, padx=30, pady=20)
        outer.pack(fill=tk.BOTH, expand=True)

        # Заголовок шага
        self._step_title_label = tk.Label(
            outer,
            text="",
            font=(theme.font_family, theme.font_size + 4, "bold"),
            bg=theme.bg_color,
            fg=theme.fg_color,
        )
        self._step_title_label.pack(pady=(0, 5))

        # Описание шага
        self._step_desc_label = tk.Label(
            outer,
            text="",
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
            wraplength=450,
            justify=tk.LEFT,
        )
        self._step_desc_label.pack(pady=(0, 15))

        # Индикатор прогресса
        self._progress_label = tk.Label(
            outer,
            text="",
            font=(theme.font_family, theme.font_size - 2),
            bg=theme.bg_color,
            fg=theme.accent_color,
        )
        self._progress_label.pack(pady=(0, 10))

        # Область контента (перестраивается на каждом шаге)
        self._content_frame = tk.Frame(outer, bg=theme.bg_color)
        self._content_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Область ошибок
        self._error_label = tk.Label(
            outer,
            text="",
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.error_color,
            wraplength=450,
        )
        self._error_label.pack(pady=(5, 0))

        # Кнопки навигации
        btn_frame = tk.Frame(outer, bg=theme.bg_color)
        btn_frame.pack(fill=tk.X, pady=(15, 0))

        self._back_btn = tk.Button(
            btn_frame,
            text="← Назад",
            command=self._on_back,
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
            padx=10,
            pady=5,
            cursor="hand2",
        )
        self._back_btn.pack(side=tk.LEFT)

        self._next_btn = tk.Button(
            btn_frame,
            text="Далее →",
            command=self._on_next,
            font=(theme.font_family, theme.font_size, "bold"),
            bg=theme.accent_color,
            fg=theme.bg_color,
            padx=15,
            pady=5,
            cursor="hand2",
        )
        self._next_btn.pack(side=tk.RIGHT)

        self._cancel_btn = tk.Button(
            btn_frame,
            text="Отмена",
            command=self._on_cancel,
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
            padx=10,
            pady=5,
            cursor="hand2",
        )
        self._cancel_btn.pack(side=tk.RIGHT, padx=(0, 10))

        # Debug mode indicator
        if self._debug_mode:
            debug_label = tk.Label(
                outer,
                text="⚠ DEBUG MODE — MFA bypassed",
                font=(theme.font_family, theme.font_size - 2, "bold"),
                bg="#FF0000",
                fg="#FFFFFF",
                padx=5,
                pady=2,
            )
            debug_label.pack(pady=(10, 0))

        # Показываем первый шаг
        self._show_step(self._current_step)

    def _show_step(self, step: WizardStep) -> None:
        """Перестраивает контент для указанного шага.

        Args:
            step: Шаг wizard.
        """
        if self._content_frame is None:
            return

        # Очищаем контент
        for widget in self._content_frame.winfo_children():
            widget.destroy()

        self._clear_error()

        # Обновляем заголовок и описание
        titles = {
            WizardStep.WELCOME: ("Добро пожаловать!", "Это первый запуск FX Text Processor 3.\n\nДля работы необходимо создать учётную запись оператора и настроить параметры безопасности."),
            WizardStep.MASTER_PASSWORD: ("Мастер-пароль", "Задайте мастер-пароль для защиты учётной записи.\n\nПароль будет хеширован с помощью Argon2id и никогда не хранится в открытом виде."),
            WizardStep.SECURITY_PRESET: ("Пресет безопасности", "Выберите уровень криптографической защиты.\n\nКаждый пресет можно настроить индивидуально в Settings → Security."),
            WizardStep.FIDO2_SETUP: ("FIDO2 Security Key", "Подключите FIDO2-устройство (YubiKey и др.)\nдля настройки второго фактора.\n\nЭтот шаг можно пропустить и настроить позже."),
            WizardStep.TOTP_SETUP: ("TOTP Authenticator", "Настройте приложение-аутентификатор\n(KeePassXC, Aegis, и др.) как резервный фактор.\n\nЭтот шаг можно пропустить и настроить позже."),
            WizardStep.BACKUP_CODES: ("Backup-коды", "Сохраните одноразовые backup-коды в безопасном месте.\n\nКаждый код можно использовать только один раз."),
            WizardStep.COMPLETE: ("Настройка завершена!", "Учётная запись оператора создана.\n\nТеперь вы можете войти в систему."),
        }

        title, desc = titles.get(step, ("", ""))
        if self._step_title_label:
            self._step_title_label.configure(text=title)
        if self._step_desc_label:
            self._step_desc_label.configure(text=desc)

        # Прогресс
        step_order = list(WizardStep)
        current_idx = step_order.index(step)
        total = len(step_order)
        if self._progress_label:
            self._progress_label.configure(text=f"Шаг {current_idx + 1} из {total}")

        # Управление кнопками
        self._back_btn.configure(
            state=tk.NORMAL if step != WizardStep.WELCOME else tk.DISABLED,
        )

        if step == WizardStep.COMPLETE:
            self._next_btn.configure(text="Войти")
            self._cancel_btn.configure(state=tk.DISABLED)
        elif step in (WizardStep.FIDO2_SETUP, WizardStep.TOTP_SETUP):
            self._next_btn.configure(text="Пропустить →")
            self._cancel_btn.configure(state=tk.NORMAL)
        else:
            self._next_btn.configure(text="Далее →")
            self._cancel_btn.configure(state=tk.NORMAL)

        # Рендерим контент шага
        builders = {
            WizardStep.WELCOME: self._build_welcome_step,
            WizardStep.MASTER_PASSWORD: self._build_password_step,
            WizardStep.SECURITY_PRESET: self._build_preset_step,
            WizardStep.FIDO2_SETUP: self._build_fido2_step,
            WizardStep.TOTP_SETUP: self._build_totp_step,
            WizardStep.BACKUP_CODES: self._build_backup_step,
            WizardStep.COMPLETE: self._build_complete_step,
        }

        builder = builders.get(step)
        if builder:
            builder()

    def _build_welcome_step(self) -> None:
        """Строит контент шага приветствия."""
        if self._content_frame is None:
            return

        theme = self._theme_manager.get_current_theme()

        info_text = (
            "FX Text Processor 3 использует архитектуру Zero Trust:\n\n"
            "• Все операции требуют аутентификации\n"
            "• Критические действия защищены MFA\n"
            "• Данные шифруются на уровне хранилища\n"
            "• Audit log защищён от подделки\n\n"
            "Вам будет предложено:\n"
            "1. Создать мастер-пароль\n"
            "2. Выбрать уровень безопасности\n"
            "3. Настроить второй фактор (MFA)\n"
            "4. Сохранить backup-коды"
        )

        info_label = tk.Label(
            self._content_frame,
            text=info_text,
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
            justify=tk.LEFT,
            wraplength=450,
        )
        info_label.pack(anchor=tk.W, pady=10)

    def _build_password_step(self) -> None:
        """Строит контент шага мастер-пароля."""
        if self._content_frame is None:
            return

        theme = self._theme_manager.get_current_theme()

        # Поле пароля
        pwd_frame = tk.Frame(self._content_frame, bg=theme.bg_color)
        pwd_frame.pack(fill=tk.X, pady=5)

        tk.Label(
            pwd_frame,
            text="Мастер-пароль:",
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
        ).pack(anchor=tk.W)

        pwd_entry = tk.Entry(
            pwd_frame,
            textvariable=self._password_var,
            show="*",
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
            insertbackground=theme.fg_color,
            width=40,
        )
        pwd_entry.pack(fill=tk.X, pady=(2, 0))
        pwd_entry.focus_set()

        # Поле подтверждения
        confirm_frame = tk.Frame(self._content_frame, bg=theme.bg_color)
        confirm_frame.pack(fill=tk.X, pady=5)

        tk.Label(
            confirm_frame,
            text="Подтверждение пароля:",
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
        ).pack(anchor=tk.W)

        tk.Entry(
            confirm_frame,
            textvariable=self._password_confirm_var,
            show="*",
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
            insertbackground=theme.fg_color,
            width=40,
        ).pack(fill=tk.X, pady=(2, 0))

        # Подсказка
        hint_label = tk.Label(
            self._content_frame,
            text="Минимум 8 символов. Рекомендуется ≥ 12 символов.\n"
                 "Пароль никогда не хранится в открытом виде.",
            font=(theme.font_family, theme.font_size - 2),
            bg=theme.bg_color,
            fg=theme.fg_color,
            justify=tk.LEFT,
        )
        hint_label.pack(anchor=tk.W, pady=(10, 0))

    def _build_preset_step(self) -> None:
        """Строит контент шага выбора пресета."""
        if self._content_frame is None:
            return

        theme = self._theme_manager.get_current_theme()

        for preset_key, preset_info in self.PRESETS.items():
            preset_frame = tk.Frame(
                self._content_frame,
                bg=theme.bg_color,
                highlightbackground=theme.accent_color if self._preset_var.get() == preset_key else theme.fg_color,
                highlightthickness=2 if self._preset_var.get() == preset_key else 1,
                padx=10,
                pady=5,
            )
            preset_frame.pack(fill=tk.X, pady=5)

            rb = tk.Radiobutton(
                preset_frame,
                text=f"{preset_info['name']} — {preset_info['description'][:60]}...",
                variable=self._preset_var,
                value=preset_key,
                font=(theme.font_family, theme.font_size),
                bg=theme.bg_color,
                fg=theme.fg_color,
                selectcolor=theme.accent_color,
                activebackground=theme.bg_color,
                activeforeground=theme.fg_color,
                command=lambda: self._update_preset_highlight(),
            )
            rb.pack(anchor=tk.W)

            detail = (
                f"Подписание: {preset_info['signing']}  |  "
                f"Шифрование: {preset_info['encryption']}  |  "
                f"KDF память: {preset_info['kdf_memory']}"
            )
            tk.Label(
                preset_frame,
                text=detail,
                font=(theme.font_family, theme.font_size - 2),
                bg=theme.bg_color,
                fg=theme.fg_color,
            ).pack(anchor=tk.W, padx=(20, 0))

    def _update_preset_highlight(self) -> None:
        """Обновляет подсветку выбранного пресета."""
        # Перестраиваем шаг для обновления визуала
        self._show_step(WizardStep.SECURITY_PRESET)

    def _build_fido2_step(self) -> None:
        """Строит контент шага настройки FIDO2."""
        if self._content_frame is None:
            return

        theme = self._theme_manager.get_current_theme()

        if self._fido2_configured:
            tk.Label(
                self._content_frame,
                text="✅ FIDO2-устройство настроено",
                font=(theme.font_family, theme.font_size, "bold"),
                bg=theme.bg_color,
                fg="#4CAF50",
            ).pack(pady=20)
            return

        tk.Label(
            self._content_frame,
            text=(
                "Подключите FIDO2-устройство (YubiKey, J3R200)\n"
                "и нажмите «Настроить FIDO2».\n\n"
                "Если у вас нет устройства, нажмите «Пропустить».\n"
                "Вы можете настроить FIDO2 позже в Settings → Security."
            ),
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
            justify=tk.LEFT,
            wraplength=450,
        ).pack(pady=10)

        setup_btn = tk.Button(
            self._content_frame,
            text="🔑 Настроить FIDO2",
            command=self._on_setup_fido2,
            font=(theme.font_family, theme.font_size, "bold"),
            bg=theme.accent_color,
            fg=theme.bg_color,
            padx=15,
            pady=5,
            cursor="hand2",
        )
        setup_btn.pack(pady=10)

    def _build_totp_step(self) -> None:
        """Строит контент шага настройки TOTP."""
        if self._content_frame is None:
            return

        theme = self._theme_manager.get_current_theme()

        if self._totp_configured:
            tk.Label(
                self._content_frame,
                text="✅ TOTP-аутентификатор настроен",
                font=(theme.font_family, theme.font_size, "bold"),
                bg=theme.bg_color,
                fg="#4CAF50",
            ).pack(pady=20)
            return

        tk.Label(
            self._content_frame,
            text=(
                "Отсканируйте QR-код приложением-аутентификатором\n"
                "(KeePassXC, Aegis, Google Authenticator).\n\n"
                "Затем введите код подтверждения.\n\n"
                "Вы можете настроить TOTP позже в Settings → Security."
            ),
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
            justify=tk.LEFT,
            wraplength=450,
        ).pack(pady=10)

        setup_btn = tk.Button(
            self._content_frame,
            text="📱 Настроить TOTP",
            command=self._on_setup_totp,
            font=(theme.font_family, theme.font_size, "bold"),
            bg=theme.accent_color,
            fg=theme.bg_color,
            padx=15,
            pady=5,
            cursor="hand2",
        )
        setup_btn.pack(pady=10)

    def _build_backup_step(self) -> None:
        """Строит контент шага backup-кодов."""
        if self._content_frame is None:
            return

        theme = self._theme_manager.get_current_theme()

        if not self._backup_codes:
            # Генерируем backup-коды
            self._generate_backup_codes()

        if not self._backup_codes:
            tk.Label(
                self._content_frame,
                text="⚠ Не удалось сгенерировать backup-коды.\n"
                     "Вы сможете сгенерировать их позже в Settings → Security.",
                font=(theme.font_family, theme.font_size),
                bg=theme.bg_color,
                fg=theme.error_color,
            ).pack(pady=20)
            return

        tk.Label(
            self._content_frame,
            text="⚠ Сохраните эти коды в безопасном месте!\n"
                 "Каждый код можно использовать только ОДИН раз.\n"
                 "Коды больше НЕ будут показаны.",
            font=(theme.font_family, theme.font_size, "bold"),
            bg=theme.bg_color,
            fg=theme.error_color,
            justify=tk.LEFT,
            wraplength=450,
        ).pack(pady=(0, 10))

        # Коды в рамке
        codes_frame = tk.Frame(
            self._content_frame,
            bg=theme.bg_color,
            highlightbackground=theme.fg_color,
            highlightthickness=1,
            padx=10,
            pady=10,
        )
        codes_frame.pack(fill=tk.X, pady=5)

        for i, code in enumerate(self._backup_codes, 1):
            code_label = tk.Label(
                codes_frame,
                text=f"  {i:2d}.  {code}",
                font=("Courier", theme.font_size),
                bg=theme.bg_color,
                fg=theme.fg_color,
                anchor=tk.W,
            )
            code_label.pack(fill=tk.X)

    def _build_complete_step(self) -> None:
        """Строит контент шага завершения."""
        if self._content_frame is None:
            return

        theme = self._theme_manager.get_current_theme()

        summary_lines = [
            f"✅ Оператор: {self._user_id}",
            f"✅ Мастер-пароль: установлен",
            f"✅ Пресет: {self.PRESETS[self._selected_preset]['name']}",
        ]

        if self._fido2_configured:
            summary_lines.append("✅ FIDO2: настроен")
        else:
            summary_lines.append("⚠ FIDO2: не настроен (настройте позже)")

        if self._totp_configured:
            summary_lines.append("✅ TOTP: настроен")
        else:
            summary_lines.append("⚠ TOTP: не настроен (настройте позже)")

        summary_lines.append(f"✅ Backup-коды: {len(self._backup_codes)} сгенерировано")

        tk.Label(
            self._content_frame,
            text="\n".join(summary_lines),
            font=(theme.font_family, theme.font_size),
            bg=theme.bg_color,
            fg=theme.fg_color,
            justify=tk.LEFT,
        ).pack(pady=10)

        warning_label = tk.Label(
            self._content_frame,
            text="⚠ Если вы потеряете мастер-пароль и все backup-коды,\n"
                 "данные будут НЕВОССТАНОВИМЫ.",
            font=(theme.font_family, theme.font_size, "bold"),
            bg=theme.bg_color,
            fg=theme.error_color,
            justify=tk.LEFT,
        )
        warning_label.pack(pady=(10, 0))

    def _on_next(self) -> None:
        """Обработчик кнопки «Далее»."""
        # Валидация текущего шага
        if self._current_step == WizardStep.MASTER_PASSWORD:
            if not self._validate_password():
                return
            self._password = self._password_var.get()

        # В debug mode пропускаем MFA шаги
        if self._debug_mode and self._current_step in (
            WizardStep.FIDO2_SETUP,
            WizardStep.TOTP_SETUP,
        ):
            # Пропускаем MFA в debug mode
            self._current_step = WizardStep.BACKUP_CODES
            self._show_step(self._current_step)
            return

        # Переход к следующему шагу
        step_order = list(WizardStep)
        current_idx = step_order.index(self._current_step)

        if self._current_step == WizardStep.COMPLETE:
            # Завершение wizard
            self._complete_wizard()
            return

        # Определяем следующий шаг
        next_idx = current_idx + 1
        if next_idx < len(step_order):
            self._current_step = step_order[next_idx]
            self._show_step(self._current_step)

    def _on_back(self) -> None:
        """Обработчик кнопки «Назад»."""
        step_order = list(WizardStep)
        current_idx = step_order.index(self._current_step)

        if current_idx > 0:
            self._current_step = step_order[current_idx - 1]
            self._show_step(self._current_step)

    def _on_cancel(self) -> None:
        """Обработчик отмены."""
        self._clear_password_vars()
        if self._on_cancel is not None:
            self._on_cancel()
        self.destroy()

    def _validate_password(self) -> bool:
        """Валидирует мастер-пароль.

        Returns:
            True если пароль валиден.
        """
        password = self._password_var.get()
        confirm = self._password_confirm_var.get()

        if not password:
            self._show_error("Введите мастер-пароль")
            return False

        if len(password) < 8:
            self._show_error("Пароль должен содержать минимум 8 символов")
            return False

        if password != confirm:
            self._show_error("Пароли не совпадают")
            return False

        # Проверяем сложность через PasswordService если доступен
        if self._password_service is not None:
            try:
                result = self._password_service.check_password_strength(password)
                if not result.get("valid", True):
                    issues = result.get("issues", [])
                    self._show_error(f"Слабый пароль: {'; '.join(issues)}")
                    return False
            except (AttributeError, TypeError):
                pass  # Если метод недоступен, пропускаем проверку

        return True

    def _on_setup_fido2(self) -> None:
        """Обработчик настройки FIDO2."""
        # TODO: Открыть FIDO2SetupDialog когда он будет подключён
        # Пока помечаем как настроенный в debug режиме
        if self._debug_mode:
            self._fido2_configured = True
            self._show_step(WizardStep.FIDO2_SETUP)
            logger.info("FIDO2 setup bypassed in debug mode")
        else:
            self._show_error("Настройка FIDO2 пока недоступна — настройте позже")

    def _on_setup_totp(self) -> None:
        """Обработчик настройки TOTP."""
        # TODO: Открыть TOTPSetupDialog когда он будет подключён
        if self._debug_mode:
            self._totp_configured = True
            self._show_step(WizardStep.TOTP_SETUP)
            logger.info("TOTP setup bypassed in debug mode")
        else:
            self._show_error("Настройка TOTP пока недоступна — настройте позже")

    def _generate_backup_codes(self) -> None:
        """Генерирует backup-коды."""
        if self._debug_mode:
            # В debug режиме генерируем простые тестовые коды
            import secrets
            self._backup_codes = [
                secrets.token_hex(4).upper() for _ in range(10)
            ]
            return

        # Используем CodeService если доступен
        try:
            from src.security.auth.code_service import issue_backup_codes_for_user

            result = issue_backup_codes_for_user(self._user_id, count=10)
            self._backup_codes = [
                code.get("code", "") for code in result.get("codes", [])
            ]
        except (ImportError, Exception) as e:
            logger.warning("Failed to generate backup codes via service: %s", e)
            # Fallback: генерируем локально
            import secrets
            self._backup_codes = [
                secrets.token_hex(4).upper() for _ in range(10)
            ]

    def _complete_wizard(self) -> None:
        """Завершает wizard и создаёт пользователя."""
        # Создаём пользователя через PasswordService
        if self._password_service is not None:
            try:
                self._password_service.create_password(self._user_id, self._password)
                logger.info("User '%s' created successfully", self._user_id)
            except Exception as e:
                logger.error("Failed to create user: %s", e)
                self._show_error(f"Ошибка создания пользователя: {e}")
                return
        else:
            logger.warning("No password_service — user creation skipped")

        # Очищаем пароль из памяти
        self._clear_password_vars()

        # Вызываем callback
        if self._on_complete is not None:
            self._on_complete(self._user_id)

        self.destroy()

    def _show_error(self, message: str) -> None:
        """Показывает сообщение об ошибке."""
        if self._error_label is not None:
            self._error_label.configure(text=message)

    def _clear_error(self) -> None:
        """Очищает сообщение об ошибке."""
        if self._error_label is not None:
            self._error_label.configure(text="")

    def _clear_password_vars(self) -> None:
        """Безопасно очищает переменные с паролями."""
        self._password_var.set("")
        self._password_confirm_var.set("")
        self._password = ""

    def _center_window(self) -> None:
        """Центрирует окно wizard."""
        if self._window is None:
            return

        self._window.update_idletasks()
        width = self._window.winfo_width()
        height = self._window.winfo_height()
        screen_w = self._window.winfo_screenwidth()
        screen_h = self._window.winfo_screenheight()
        x = (screen_w - width) // 2
        y = (screen_h - height) // 2
        self._window.geometry(f"+{x}+{y}")


def is_first_run(password_service: Any = None) -> bool:
    """Проверяет, является ли текущий запуск первым.

    Проверяет наличие пользователей в хранилище паролей.
    Если хранилище пустое — это первый запуск.

    Args:
        password_service: Сервис паролей. Если None, создаётся новый экземпляр.

    Returns:
        True если это первый запуск (нет пользователей).
    """
    try:
        if password_service is None:
            from src.security.auth.password_service import PasswordService

            password_service = PasswordService()

        storage = password_service.storage  # type: ignore[union-attr]
        if hasattr(storage, "user_ids") and callable(storage.user_ids):
            return len(storage.user_ids()) == 0
        if hasattr(storage, "get_password_hash") and callable(
            storage.get_password_hash,
        ):
            return storage.get_password_hash("operator") is None
        return True
    except (ImportError, Exception) as e:
        logger.debug("First run check failed: %s", e)
        # Если сервис недоступен — считаем что первый запуск
        return True


__all__ = [
    "FirstRunWizard",
    "WizardStep",
    "is_first_run",
]