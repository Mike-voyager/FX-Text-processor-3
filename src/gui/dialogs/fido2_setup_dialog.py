"""Диалог настройки FIDO2 Security Key.

Предоставляет пошаговый интерфейс для регистрации FIDO2 устройства:
- Step 1: Вставка ключа
- Step 2: Подтверждение касанием
- Step 3: Отображение резервных кодов

Features:
    - Пошаговый wizard с визуальной индикацией прогресса
    - Отображение информации о подключённом устройстве
    - Резервные коды восстановления (10 кодов)
    - Экспорт/печать резервных кодов

Example:
    >>> dialog = FIDO2SetupDialog(parent=root)
    >>> result = dialog.show()
    >>> if result and result.get('success'):
    ...     print(f"FIDO2 registered: {result['credential_id']}")
    ...     print(f"Backup codes: {result['backup_codes']}")

Version: 1.0
"""

from __future__ import annotations

import logging
import secrets
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Callable, Final, Optional, cast

from src.gui.dialogs.base_dialog import BaseDialog
from src.security.crypto.core.exceptions import AuthError, CryptoError

# External deps
try:
    from fido2.client import Fido2Client
    from fido2.hid import CtapHidDevice
    from fido2.server import Fido2Server
    from fido2.webauthn import (
        PublicKeyCredentialCreationOptions,
        PublicKeyCredentialUserEntity,
    )
except ImportError:  # pragma: no cover
    Fido2Client = None  # type: ignore
    CtapHidDevice = None  # type: ignore
    PublicKeyCredentialCreationOptions = None  # type: ignore
    PublicKeyCredentialUserEntity = None  # type: ignore
    Fido2Server = None  # type: ignore

logger: Final = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

DIALOG_WIDTH: Final[int] = 550
DIALOG_HEIGHT: Final[int] = 500

# Colors
COLOR_BG: Final[str] = "#f8f9fa"
COLOR_STEP_ACTIVE: Final[str] = "#3498db"  # Blue
COLOR_STEP_COMPLETE: Final[str] = "#27ae60"  # Green
COLOR_STEP_PENDING: Final[str] = "#bdc3c7"  # Gray
COLOR_WARNING: Final[str] = "#f39c12"
COLOR_DANGER: Final[str] = "#e74c3c"
COLOR_SUCCESS: Final[str] = "#27ae60"

# Number of backup codes
BACKUP_CODES_COUNT: Final[int] = 10
BACKUP_CODE_LENGTH: Final[int] = 8


# =============================================================================
# FIDO2SetupDialog
# =============================================================================


class FIDO2SetupDialog(BaseDialog):
    """Диалог настройки FIDO2 Security Key.

    Attributes:
        parent: Родительский виджет.
        _current_step: Текущий шаг (1-3).
        _credential_id: ID зарегистрированного ключа.
        _backup_codes: Список резервных кодов.
        _result: Результат диалога.

    Example:
        >>> dialog = FIDO2SetupDialog(parent=root)
        >>> result = dialog.show()
        >>> if result and result.get('success'):
        ...     codes = result.get('backup_codes', [])
    """

    def __init__(
        self,
        parent: tk.Widget,
        on_complete: Optional[Callable[[dict[str, Any]], None]] = None,
    ) -> None:
        """Инициализация диалога настройки FIDO2.

        Args:
            parent: Родительский виджет.
            on_complete: Callback при завершении.
        """
        super().__init__(parent)

        self._parent: tk.Widget = parent
        self._on_complete: Optional[Callable[[dict[str, Any]], None]] = on_complete

        # State
        self._current_step: int = 1
        self._credential_id: Optional[str] = None
        self._backup_codes: list[str] = []
        self._result: Optional[dict[str, Any]] = None
        self._device_info: dict[str, str] = {}

        # FIDO2 state
        self._fido2_client: Any = None
        self._fido2_device: Any = None

        # UI references
        self._step_frames: dict[int, tk.Frame] = {}
        self._step_indicators: dict[int, tk.Label] = {}
        self._content_frame: Optional[tk.Frame] = None
        self._button_frame: Optional[tk.Frame] = None
        self._next_btn: Optional[tk.Button] = None
        self._back_btn: Optional[tk.Button] = None

        # Configure window
        self.title("🔐 Setup FIDO2 Security Key")
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
        # Main container
        main_frame = tk.Frame(self, padx=20, pady=20, bg=COLOR_BG)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        self._create_header(main_frame)

        # Step indicator
        self._create_step_indicator(main_frame)

        # Separator
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=15)

        # Content area (changes based on step)
        self._content_frame = tk.Frame(main_frame, bg=COLOR_BG)
        self._content_frame.pack(fill=tk.BOTH, expand=True)

        # Create step contents
        self._create_step1_content()
        self._create_step2_content()
        self._create_step3_content()

        # Separator before buttons
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=15)

        # Buttons
        self._create_buttons(main_frame)

        # Show initial step
        self._show_step(1)

    def _create_header(self, parent: tk.Widget) -> None:
        """Создаёт заголовок диалога.

        Args:
            parent: Родительский виджет.
        """
        header_frame = tk.Frame(parent, bg=COLOR_BG)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(
            header_frame,
            text="🔐 Setup FIDO2 Security Key",
            font=("Arial", 14, "bold"),
            bg=COLOR_BG,
            fg="#2c3e50",
        ).pack(anchor=tk.W)

        tk.Label(
            header_frame,
            text="Secure your account with hardware authentication",
            font=("Arial", 9),
            bg=COLOR_BG,
            fg="#7f8c8d",
        ).pack(anchor=tk.W, pady=(5, 0))

    def _create_step_indicator(self, parent: tk.Widget) -> None:
        """Создаёт индикатор шагов.

        Args:
            parent: Родительский виджет.
        """
        indicator_frame = tk.Frame(parent, bg=COLOR_BG)
        indicator_frame.pack(fill=tk.X, pady=(10, 5))

        steps = [
            (1, "Insert Key", "🗝️"),
            (2, "Touch Key", "👆"),
            (3, "Backup Codes", "📝"),
        ]

        for i, (step_num, title, icon) in enumerate(steps):
            # Step indicator
            step_frame = tk.Frame(indicator_frame, bg=COLOR_BG)
            step_frame.pack(side=tk.LEFT, expand=True)

            # Icon circle
            indicator = tk.Label(
                step_frame,
                text=icon,
                font=("Arial", 16),
                bg=COLOR_STEP_PENDING,
                fg="white",
                width=3,
                height=1,
            )
            indicator.pack()
            self._step_indicators[step_num] = indicator

            # Title
            tk.Label(
                step_frame,
                text=title,
                font=("Arial", 9),
                bg=COLOR_BG,
                fg="#7f8c8d",
            ).pack()

            # Arrow (except for last step)
            if i < len(steps) - 1:
                arrow = tk.Label(
                    indicator_frame,
                    text="▶",
                    font=("Arial", 10),
                    bg=COLOR_BG,
                    fg="#bdc3c7",
                )
                arrow.pack(side=tk.LEFT, padx=10)

    def _create_step1_content(self) -> None:
        """Создаёт содержимое шага 1 (вставка ключа)."""
        frame = tk.Frame(self._content_frame, bg=COLOR_BG)
        self._step_frames[1] = frame

        # Icon
        tk.Label(
            frame,
            text="🗝️",
            font=("Arial", 48),
            bg=COLOR_BG,
        ).pack(pady=20)

        # Instruction
        tk.Label(
            frame,
            text="Step 1: Insert your FIDO2 security key",
            font=("Arial", 12, "bold"),
            bg=COLOR_BG,
            fg="#2c3e50",
        ).pack(pady=(0, 10))

        tk.Label(
            frame,
            text="Insert your YubiKey or other FIDO2 compatible device\n"
            "into a USB port on your computer.",
            font=("Arial", 10),
            bg=COLOR_BG,
            fg="#7f8c8d",
            justify=tk.CENTER,
        ).pack(pady=(0, 20))

        # Device status
        self._device_status_label = tk.Label(
            frame,
            text="⏳ Waiting for device...",
            font=("Arial", 10, "italic"),
            bg=COLOR_BG,
            fg=COLOR_WARNING,
        )
        self._device_status_label.pack(pady=10)

        # Detected device info (initially hidden)
        self._device_info_frame = tk.Frame(frame, bg="#e8f5e9", padx=15, pady=15)
        self._device_info_frame.pack(fill=tk.X, pady=10)
        self._device_info_frame.pack_forget()

        tk.Label(
            self._device_info_frame,
            text="✓ Device detected",
            font=("Arial", 11, "bold"),
            bg="#e8f5e9",
            fg=COLOR_SUCCESS,
        ).pack(anchor=tk.W)

        self._device_name_label = tk.Label(
            self._device_info_frame,
            text="",
            font=("Arial", 10),
            bg="#e8f5e9",
            fg="#2c3e50",
        )
        self._device_name_label.pack(anchor=tk.W, pady=(5, 0))

    def _create_step2_content(self) -> None:
        """Создаёт содержимое шага 2 (касание ключа)."""
        frame = tk.Frame(self._content_frame, bg=COLOR_BG)
        self._step_frames[2] = frame

        # Icon
        tk.Label(
            frame,
            text="👆",
            font=("Arial", 48),
            bg=COLOR_BG,
        ).pack(pady=20)

        # Instruction
        tk.Label(
            frame,
            text="Step 2: Touch your security key",
            font=("Arial", 12, "bold"),
            bg=COLOR_BG,
            fg="#2c3e50",
        ).pack(pady=(0, 10))

        tk.Label(
            frame,
            text="Touch the gold or silver surface of your key\nwhen the LED starts blinking.",
            font=("Arial", 10),
            bg=COLOR_BG,
            fg="#7f8c8d",
            justify=tk.CENTER,
        ).pack(pady=(0, 20))

        # Waiting indicator
        self._touch_status_label = tk.Label(
            frame,
            text="⏳ Waiting for touch...",
            font=("Arial", 11, "italic"),
            bg=COLOR_BG,
            fg=COLOR_STEP_ACTIVE,
        )
        self._touch_status_label.pack(pady=20)

        # Progress animation placeholder
        self._touch_progress = ttk.Progressbar(
            frame,
            mode="indeterminate",
            length=300,
        )
        self._touch_progress.pack(pady=10)

    def _create_step3_content(self) -> None:
        """Создаёт содержимое шага 3 (резервные коды)."""
        frame = tk.Frame(self._content_frame, bg=COLOR_BG)
        self._step_frames[3] = frame

        # Icon
        tk.Label(
            frame,
            text="📝",
            font=("Arial", 36),
            bg=COLOR_BG,
        ).pack(pady=(10, 15))

        # Success message
        tk.Label(
            frame,
            text="✓ Registration Complete!",
            font=("Arial", 12, "bold"),
            bg=COLOR_BG,
            fg=COLOR_SUCCESS,
        ).pack(pady=(0, 5))

        # Credential ID display
        self._credential_display = tk.Label(
            frame,
            text="Credential ID: (generating...)",
            font=("Arial", 9, "italic"),
            bg=COLOR_BG,
            fg="#7f8c8d",
        )
        self._credential_display.pack(pady=(0, 10))

        # Warning
        warning_frame = tk.Frame(frame, bg="#fff3cd", padx=10, pady=10)
        warning_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(
            warning_frame,
            text="⚠️ Important: Save these backup codes!",
            font=("Arial", 10, "bold"),
            bg="#fff3cd",
            fg="#856404",
        ).pack(anchor=tk.W)

        tk.Label(
            warning_frame,
            text="Each code can be used ONCE if you lose access to your key.",
            font=("Arial", 9),
            bg="#fff3cd",
            fg="#856404",
            wraplength=400,
        ).pack(anchor=tk.W, pady=(5, 0))

        # Backup codes frame
        codes_frame = tk.LabelFrame(
            frame,
            text="Backup Recovery Codes",
            font=("Arial", 10, "bold"),
            bg=COLOR_BG,
            padx=10,
            pady=10,
        )
        codes_frame.pack(fill=tk.X, pady=10)

        # Codes grid (3 columns)
        self._codes_container = tk.Frame(codes_frame, bg=COLOR_BG)
        self._codes_container.pack()

        # Placeholder - will be filled in _generate_backup_codes
        self._code_labels: list[tk.Label] = []

    def _create_buttons(self, parent: tk.Widget) -> None:
        """Создаёт кнопки диалога.

        Args:
            parent: Родительский виджет.
        """
        self._button_frame = tk.Frame(parent, bg=COLOR_BG)
        self._button_frame.pack(fill=tk.X)

        # Spacer
        tk.Frame(self._button_frame, bg=COLOR_BG).pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Back button (hidden on step 1)
        self._back_btn = tk.Button(
            self._button_frame,
            text="← Back",
            width=12,
            command=self._on_back,
            font=("Arial", 9),
        )
        self._back_btn.pack(side=tk.RIGHT, padx=(5, 0))

        # Cancel button
        cancel_btn = tk.Button(
            self._button_frame,
            text="Cancel",
            width=12,
            command=self._on_cancel,
            font=("Arial", 9),
        )
        cancel_btn.pack(side=tk.RIGHT, padx=(5, 0))

        # Next/Complete button
        self._next_btn = tk.Button(
            self._button_frame,
            text="Next →",
            width=12,
            command=self._on_next,
            font=("Arial", 9, "bold"),
            bg=COLOR_STEP_ACTIVE,
            fg="white",
        )
        self._next_btn.pack(side=tk.RIGHT)

    def _show_step(self, step: int) -> None:
        """Показывает указанный шаг.

        Args:
            step: Номер шага (1-3).
        """
        # Hide all step frames
        for frame in self._step_frames.values():
            frame.pack_forget()

        # Show current step
        if step in self._step_frames:
            self._step_frames[step].pack(fill=tk.BOTH, expand=True)

        self._current_step = step
        self._update_step_indicators()
        self._update_buttons()

        # Step-specific actions
        if step == 1:
            self._start_device_detection()
        elif step == 2:
            self._start_touch_detection()
        elif step == 3:
            self._generate_backup_codes()

    def _update_step_indicators(self) -> None:
        """Обновляет индикаторы шагов."""
        for step_num, indicator in self._step_indicators.items():
            if step_num < self._current_step:
                # Completed step
                indicator.config(bg=COLOR_STEP_COMPLETE, text="✓")
            elif step_num == self._current_step:
                # Current step
                indicator.config(bg=COLOR_STEP_ACTIVE)
            else:
                # Pending step
                indicator.config(bg=COLOR_STEP_PENDING)

    def _update_buttons(self) -> None:
        """Обновляет состояние кнопок."""
        if self._back_btn is not None:
            if self._current_step == 1:
                self._back_btn.pack_forget()
            else:
                self._back_btn.pack(side=tk.RIGHT, padx=(5, 0))

        if self._next_btn is not None:
            if self._current_step == 3:
                self._next_btn.config(text="Done", bg=COLOR_SUCCESS)
            else:
                self._next_btn.config(text="Next →", bg=COLOR_STEP_ACTIVE)

    def _start_device_detection(self) -> None:
        """Начинает обнаружение FIDO2 устройства.

        CRITICAL-003: Реальное обнаружение через fido2 библиотеку.
        Запускается в отдельном потоке чтобы не блокировать UI.
        """
        if CtapHidDevice is None:
            logger.warning("FIDO2 library not available, using simulation")
            self.after(2000, self._on_device_detected_simulated)
            return

        def detect_device() -> None:
            """Фоновое обнаружение устройства."""
            try:
                # Поиск HID устройств
                devices = list(CtapHidDevice.list_devices())
                if devices:
                    self._fido2_device = devices[0]
                    self.after(0, self._on_device_detected)
                else:
                    self.after(0, self._on_device_not_found)
            except (AuthError, CryptoError) as e:
                logger.critical(
                    "Security error during FIDO2 device detection: %s", e, exc_info=True
                )
                error_msg = str(e)
                self.after(
                    0, cast(Callable[[], None], lambda msg=error_msg: self._on_device_error(msg))
                )
            except Exception as e:
                logger.error("Unexpected FIDO2 device detection error: %s", e, exc_info=True)
                error_msg = str(e)
                self.after(
                    0, cast(Callable[[], None], lambda msg=error_msg: self._on_device_error(msg))
                )

        # Запускаем в отдельном потоке
        threading.Thread(target=detect_device, daemon=True).start()

    def _on_device_detected(self) -> None:
        """Обработчик обнаружения реального FIDO2 устройства."""
        try:
            if self._fido2_device:
                # Получаем информацию об устройстве
                info = self._fido2_device.device_info
                self._device_info = {
                    "name": info.get("product", "Security Key"),
                    "model": info.get("model", "Unknown"),
                    "firmware": info.get("version", "Unknown"),
                }

            if hasattr(self, "_device_status_label"):
                self._device_status_label.config(
                    text=f"✓ Device detected: {self._device_info.get('name', 'Security Key')}",
                    fg=COLOR_SUCCESS,
                    font=("Arial", 10, "bold"),
                )

            if hasattr(self, "_device_info_frame"):
                self._device_info_frame.pack(fill=tk.X, pady=10)
                device_name = self._device_info.get("name", "Security Key")
                device_model = self._device_info.get("model", "Unknown")
                self._device_name_label.config(text=f"{device_name} ({device_model})")

            logger.info("FIDO2 device detected: %s", self._device_info.get("name"))

        except Exception as e:
            logger.error("Error processing device info: %s", e)
            self._on_device_error(str(e))

    def _on_device_detected_simulated(self) -> None:
        """Обработчик симулированного устройства (fallback)."""
        self._device_info = {
            "name": "YubiKey 5 NFC (Simulated)",
            "model": "YubiKey 5",
            "firmware": "5.4.3",
        }

        if hasattr(self, "_device_status_label"):
            self._device_status_label.config(
                text="✓ Device detected! (Simulation mode)",
                fg=COLOR_WARNING,
                font=("Arial", 10, "bold"),
            )

        if hasattr(self, "_device_info_frame"):
            self._device_info_frame.pack(fill=tk.X, pady=10)
            self._device_name_label.config(
                text=f"{self._device_info['name']} ({self._device_info['model']})"
            )

    def _on_device_not_found(self) -> None:
        """Обработчик отсутствия устройства."""
        if hasattr(self, "_device_status_label"):
            self._device_status_label.config(
                text="❌ No FIDO2 device found. Please insert your security key.",
                fg=COLOR_DANGER,
            )
        logger.warning("No FIDO2 device found")

    def _on_device_error(self, error_msg: str) -> None:
        """Обработчик ошибки обнаружения устройства.

        Args:
            error_msg: Сообщение об ошибке.
        """
        if hasattr(self, "_device_status_label"):
            self._device_status_label.config(
                text=f"❌ Error: {error_msg}",
                fg=COLOR_DANGER,
            )
        logger.error("FIDO2 device detection error: %s", error_msg)

    def _start_touch_detection(self) -> None:
        """Начинает ожидание касания ключа с реальной регистрацией.

        CRITICAL-003: Реальная FIDO2 регистрация.
        """
        if hasattr(self, "_touch_progress"):
            self._touch_progress.start(10)

        if Fido2Client is None or self._fido2_device is None:
            # Fallback на симуляцию
            logger.warning("FIDO2 not available, using simulation")
            self.after(3000, self._on_touch_detected_simulated)
            return

        def register_credential() -> None:
            """Фоновая регистрация credential."""
            try:
                from src.app_context import get_app_context
                from src.security.auth.fido2_service import setup_fido2_for_user

                ctx = get_app_context()
                user_id = ctx.user_id

                if not user_id:
                    raise RuntimeError("No user ID available")

                # Регистрация через сервис
                result = setup_fido2_for_user(
                    user_id=user_id,
                    device_info=self._device_info,
                )

                self._credential_id = result.get("credential_id")
                self.after(0, self._on_touch_detected)

            except (AuthError, CryptoError) as e:
                logger.critical("FIDO2 registration security error: %s", e, exc_info=True)
                error_msg = str(e)
                self.after(
                    0, cast(Callable[[], None], lambda msg=error_msg: self._on_touch_error(msg))
                )
            except Exception as e:
                logger.error("Unexpected FIDO2 registration error: %s", e, exc_info=True)
                error_msg = str(e)
                self.after(
                    0, cast(Callable[[], None], lambda msg=error_msg: self._on_touch_error(msg))
                )

        # Запускаем в отдельном потоке
        threading.Thread(target=register_credential, daemon=True).start()

    def _on_touch_detected(self) -> None:
        """Обработчик успешного касания и регистрации."""
        if hasattr(self, "_touch_progress"):
            self._touch_progress.stop()

        if hasattr(self, "_touch_status_label"):
            self._touch_status_label.config(
                text="✓ Touch registered!",
                fg=COLOR_SUCCESS,
                font=("Arial", 11, "bold"),
            )

        logger.info("FIDO2 credential registered: %s", self._credential_id)

    def _on_touch_detected_simulated(self) -> None:
        """Обработчик симулированного касания (fallback)."""
        if hasattr(self, "_touch_progress"):
            self._touch_progress.stop()

        if hasattr(self, "_touch_status_label"):
            self._touch_status_label.config(
                text="✓ Touch registered! (Simulation)",
                fg=COLOR_WARNING,
                font=("Arial", 11, "bold"),
            )

        # Generate fake credential ID
        self._credential_id = f"sim_{secrets.token_hex(16)}"
        logger.warning("Using simulated FIDO2 credential")

    def _on_touch_error(self, error_msg: str) -> None:
        """Обработчик ошибки регистрации.

        Args:
            error_msg: Сообщение об ошибке.
        """
        if hasattr(self, "_touch_progress"):
            self._touch_progress.stop()

        if hasattr(self, "_touch_status_label"):
            self._touch_status_label.config(
                text=f"❌ Registration failed: {error_msg}",
                fg=COLOR_DANGER,
            )
        logger.error("FIDO2 registration error: %s", error_msg)

    def _generate_backup_codes(self) -> None:
        """Генерирует резервные коды."""
        if not self._backup_codes:
            # Generate 10 random backup codes
            self._backup_codes = [
                f"{secrets.token_hex(BACKUP_CODE_LENGTH // 2)[:BACKUP_CODE_LENGTH].upper()[:4]}-"
                f"{secrets.token_hex(BACKUP_CODE_LENGTH // 2)[:BACKUP_CODE_LENGTH].upper()[:4]}"
                for _ in range(BACKUP_CODES_COUNT)
            ]

        # Update credential display
        if self._credential_id and hasattr(self, "_credential_display"):
            display_id = f"{self._credential_id[:8]}...{self._credential_id[-4:]}"
            self._credential_display.config(
                text=f"Credential ID: {display_id}",
                fg="#2c3e50",
            )

        # Display codes
        if hasattr(self, "_codes_container"):
            # Clear existing
            for widget in self._codes_container.winfo_children():
                widget.destroy()

            self._code_labels = []

            # Create 3-column grid
            for i, code in enumerate(self._backup_codes):
                row = i // 3
                col = i % 3

                code_label = tk.Label(
                    self._codes_container,
                    text=code,
                    font=("Courier", 11, "bold"),
                    bg="#f8f9fa",
                    fg="#2c3e50",
                    padx=15,
                    pady=8,
                    relief=tk.SOLID,
                    bd=1,
                )
                code_label.grid(row=row, column=col, padx=5, pady=5)
                self._code_labels.append(code_label)

        # Add action buttons in step 3
        if self._current_step == 3 and hasattr(self, "_button_frame"):
            # Check if buttons already exist
            if not hasattr(self, "_copy_btn"):
                self._copy_btn = tk.Button(
                    self._button_frame,
                    text="📋 Скопировать",
                    width=16,
                    command=self._on_copy_codes,
                    font=("Arial", 9),
                )
                self._copy_btn.pack(side=tk.RIGHT, padx=(5, 0))

                self._save_btn = tk.Button(
                    self._button_frame,
                    text="💾 Save",
                    width=12,
                    command=self._on_save_codes,
                    font=("Arial", 9),
                )
                self._save_btn.pack(side=tk.RIGHT, padx=(5, 0))

    def _on_next(self) -> None:
        """Обработчик нажатия кнопки Next."""
        if self._current_step < 3:
            self._show_step(self._current_step + 1)
        else:
            # Done - complete registration
            self._complete_registration()

    def _on_back(self) -> None:
        """Обработчик нажатия кнопки Back."""
        if self._current_step > 1:
            self._show_step(self._current_step - 1)

    def _on_cancel(self) -> None:
        """Обработчик отмены."""
        if self._current_step < 3:
            confirmed = messagebox.askyesno(
                "Cancel Setup",
                "FIDO2 setup is not complete.\n"
                "If you cancel now, you will need to start over.\n\n"
                "Cancel anyway?",
                icon="warning",
                parent=self,
            )
            if not confirmed:
                return

        self._result = {"success": False, "cancelled": True}
        self.destroy()

    def _complete_registration(self) -> None:
        """Завершает регистрацию."""
        self._result = {
            "success": True,
            "credential_id": self._credential_id,
            "backup_codes": self._backup_codes.copy(),
            "device_info": self._device_info,
        }

        if self._on_complete is not None:
            self._on_complete(self._result)

        logger.info("FIDO2 registration completed: %s", self._credential_id)
        self.destroy()

    def _on_copy_codes(self) -> None:
        """Копирует резервные коды в буфер обмена."""
        if not self._backup_codes:
            return
        try:
            self.clipboard_clear()
            self.clipboard_append("\n".join(self._backup_codes))
            self.update()
            messagebox.showinfo(
                "Готово",
                "Коды скопированы в буфер обмена.\nОчистите буфер обмена после использования.",
                parent=self,
            )
        except Exception as e:
            logger.error("Не удалось скопировать коды: %s", e)
            messagebox.showerror("Ошибка", "Не удалось скопировать коды", parent=self)

    def _on_save_codes(self) -> None:
        """Сохраняет резервные коды в файл."""
        if not self._backup_codes:
            return
        from tkinter import filedialog

        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")],
            title="Сохранить резервные коды",
            parent=self,
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("# Резервные коды FIDO2\n")
                f.write("# Сохраните в безопасном месте. Каждый код используется ОДИН раз.\n\n")
                f.write("\n".join(self._backup_codes))
            messagebox.showwarning(
                "Безопасность",
                "Файл содержит резервные коды. "
                "Сохраните его на съёмный носитель и удалите с локального диска.",
                parent=self,
            )
        except Exception as e:
            logger.error("Не удалось сохранить коды: %s", e)
            messagebox.showerror("Ошибка", f"Не удалось сохранить файл:\n{e}", parent=self)

    def show(self) -> Optional[dict[str, Any]]:
        """Показывает диалог модально.

        Returns:
            Словарь с результатом или None если отменено:
            {
                "success": bool,
                "credential_id": str | None,
                "backup_codes": list[str],
                "device_info": dict,
            }
        """
        self.wait_window()
        return self._result


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "FIDO2SetupDialog",
    "DIALOG_WIDTH",
    "DIALOG_HEIGHT",
    "BACKUP_CODES_COUNT",
    "BACKUP_CODE_LENGTH",
]
