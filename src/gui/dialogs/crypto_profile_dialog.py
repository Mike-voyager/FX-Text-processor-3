"""Диалог выбора и настройки криптографического профиля безопасности.

Предоставляет интерфейс для выбора одного из 7 предустановленных профилей
шифрования с отображением деталей алгоритмов и предупреждениями.

Features:
    - Список профилей с радио-кнопками и бейджами
    - Динамическая панель деталей алгоритмов
    - Предупреждение при downgrade безопасности
    - MFA challenge при смене профиля
    - Интеграция с ThemeManager для стилизации

Example:
    >>> from src.security.crypto.service.profiles import CryptoProfile
    >>> dialog = CryptoProfileDialog(
    ...     parent=root,
    ...     current_profile=CryptoProfile.STANDARD,
    ... )
    >>> result = dialog.show()
    >>> if result:
    ...     print(f"Selected: {result.profile.label()}")
    ...     print(f"Downgrade: {result.is_downgrade}")

Module: src/gui/dialogs/crypto_profile_dialog.py
Version: 1.0
"""

from __future__ import annotations

import logging
import tkinter as tk
from dataclasses import dataclass
from tkinter import messagebox, ttk
from typing import Any, Dict, Final, Optional, cast

from src.gui.dialogs.base_dialog import BaseDialog
from src.gui.themes import get_theme_manager
from src.security.crypto.service.profiles import (
    CryptoProfile,
    ProfileConfig,
    get_profile_config,
    list_profiles,
)

logger: Final = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

DIALOG_WIDTH: Final[int] = 650
DIALOG_HEIGHT: Final[int] = 550

# Colors
COLOR_BG: Final[str] = "#f8f9fa"
COLOR_CARD_BG: Final[str] = "#ffffff"
COLOR_BORDER: Final[str] = "#dee2e6"
COLOR_TEXT_PRIMARY: Final[str] = "#212529"
COLOR_TEXT_SECONDARY: Final[str] = "#6c757d"
COLOR_ACCENT: Final[str] = "#3498db"
COLOR_SUCCESS: Final[str] = "#27ae60"
COLOR_WARNING: Final[str] = "#f39c12"
COLOR_ERROR: Final[str] = "#e74c3c"
COLOR_INFO: Final[str] = "#17a2b8"

# Badge colors
BADGE_PQC_BG: Final[str] = "#e3f2fd"
BADGE_PQC_FG: Final[str] = "#1565c0"
BADGE_FLOPPY_BG: Final[str] = "#f3e5f5"
BADGE_FLOPPY_FG: Final[str] = "#7b1fa2"
BADGE_LEGACY_BG: Final[str] = "#ffebee"
BADGE_LEGACY_FG: Final[str] = "#c62828"
BADGE_WARNING_BG: Final[str] = "#fff3e0"
BADGE_WARNING_FG: Final[str] = "#ef6c00"

# Padding
PADDING_SMALL: Final[int] = 5
PADDING_NORMAL: Final[int] = 10
PADDING_LARGE: Final[int] = 15

# Security levels for downgrade detection (higher = more secure)
SECURITY_LEVELS: Final[Dict[CryptoProfile, int]] = {
    CryptoProfile.PQC_PARANOID: 7,
    CryptoProfile.PQC_STANDARD: 6,
    CryptoProfile.PARANOID: 5,
    CryptoProfile.STANDARD: 4,
    CryptoProfile.FLOPPY_BASIC: 3,
    CryptoProfile.FLOPPY_AGGRESSIVE: 2,
    CryptoProfile.LEGACY: 1,
}


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass(frozen=True)
class ProfileSelectionResult:
    """Результат выбора криптографического профиля.

    Attributes:
        profile: Выбранный профиль безопасности.
        previous_profile: Предыдущий профиль перед изменением.
        is_downgrade: True если новый профиль менее безопасен.
        mfa_verified: True если MFA верификация пройдена.

    Example:
        >>> result = ProfileSelectionResult(
        ...     profile=CryptoProfile.STANDARD,
        ...     previous_profile=CryptoProfile.PARANOID,
        ...     is_downgrade=True,
        ...     mfa_verified=True,
        ... )
        >>> print(f"Changed from {result.previous_profile} to {result.profile}")
    """

    profile: CryptoProfile
    previous_profile: CryptoProfile
    is_downgrade: bool
    mfa_verified: bool


# =============================================================================
# CRYPTO PROFILE DIALOG
# =============================================================================


class CryptoProfileDialog(BaseDialog):
    """Диалог выбора и настройки криптографического профиля безопасности.

    Attributes:
        _parent: Родительский виджет.
        _current_profile: Текущий профиль безопасности.
        _selected_profile: Выбранный в диалоге профиль.
        _mfa_gate: Опциональный MFA gate для верификации смены профиля.
        _result: Результат диалога.
        _profile_vars: Словарь переменных для UI элементов профилей.
        _details_widgets: Виджеты панели деталей.
        _radio_var: Переменная для радио-кнопок.

    Example:
        >>> dialog = CryptoProfileDialog(
        ...     parent=root,
        ...     current_profile=CryptoProfile.STANDARD,
        ... )
        >>> result = dialog.show()
        >>> if result:
        ...     print(f"Profile changed to {result.profile.label()}")
    """

    def __init__(
        self,
        parent: tk.Tk,
        current_profile: CryptoProfile = CryptoProfile.STANDARD,
        mfa_gate: Optional[Any] = None,
    ) -> None:
        """Инициализация диалога выбора криптографического профиля.

        Args:
            parent: Родительское окно (обычно tk.Tk).
            current_profile: Текущий активный профиль безопасности.
            mfa_gate: Опциональный MFA gate для верификации смены профиля.
        """
        super().__init__(parent)

        self._parent: tk.Tk = parent
        self._current_profile: CryptoProfile = current_profile
        self._selected_profile: CryptoProfile = current_profile
        self._mfa_gate: Optional[Any] = mfa_gate
        self._result: Optional[ProfileSelectionResult] = None

        # UI state
        self._radio_var: tk.StringVar = tk.StringVar(master=self, value=current_profile.value)
        self._profile_widgets: Dict[CryptoProfile, Dict[str, Any]] = {}
        self._details_widgets: Dict[str, Any] = {}
        self._warning_label: Optional[tk.Label] = None

        # Configure window
        self.title("🛡️ Security Profile")
        self.resizable(False, False)
        self.configure(bg=COLOR_BG)

        # Create UI
        self._create_ui()

        # Center window

        # Protocol handlers

        # Apply theme
        self._apply_theme()

    def _create_ui(self) -> None:
        """Создаёт пользовательский интерфейс диалога."""
        # Main container
        main_frame = tk.Frame(self, bg=COLOR_BG, padx=PADDING_LARGE, pady=PADDING_LARGE)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header with current profile
        self._create_header(main_frame)

        # Separator
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=PADDING_NORMAL)

        # Content area: profiles list + details panel
        content_frame = tk.Frame(main_frame, bg=COLOR_BG)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # Left: profiles list
        profiles_frame = self._create_profile_list(content_frame)
        profiles_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, PADDING_NORMAL))

        # Right: details panel
        details_frame = self._create_details_panel(content_frame)
        details_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(PADDING_NORMAL, 0))

        # Warning area (for downgrade)
        self._warning_label = tk.Label(
            main_frame,
            text="",
            font=("TkDefaultFont", 10),
            bg=COLOR_BG,
            fg=COLOR_ERROR,
            wraplength=550,
            justify=tk.LEFT,
        )
        self._warning_label.pack(fill=tk.X, pady=PADDING_NORMAL)

        # Separator before buttons
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=PADDING_NORMAL)

        # Buttons
        self._create_buttons(main_frame)

        # Initial details display
        self._show_profile_details(self._current_profile)

    def _create_header(self, parent: tk.Frame) -> None:
        """Создаёт заголовок с информацией о текущем профиле.

        Args:
            parent: Родительский фрейм.
        """
        header_frame = tk.Frame(parent, bg=COLOR_BG)
        header_frame.pack(fill=tk.X)

        # Title
        title_label = tk.Label(
            header_frame,
            text="🛡️ Security Profile",
            font=("TkDefaultFont", 14, "bold"),
            bg=COLOR_BG,
            fg=COLOR_TEXT_PRIMARY,
        )
        title_label.pack(anchor=tk.W)

        # Current profile
        current_text = f"Current: {self._current_profile.label()}"

        current_label = tk.Label(
            header_frame,
            text=current_text,
            font=("TkDefaultFont", 10),
            bg=COLOR_BG,
            fg=COLOR_TEXT_SECONDARY,
        )
        current_label.pack(anchor=tk.W, pady=(PADDING_SMALL, 0))

    def _create_profile_list(self, parent: tk.Frame) -> tk.Frame:
        """Создаёт список профилей с радио-кнопками.

        Args:
            parent: Родительский фрейм.

        Returns:
            Фрейм со списком профилей.
        """
        # Container with border
        container = tk.Frame(
            parent,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER,
            highlightthickness=1,
        )

        # Title
        title_label = tk.Label(
            container,
            text="Select Profile",
            font=("TkDefaultFont", 11, "bold"),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
        )
        title_label.pack(anchor=tk.W, padx=PADDING_NORMAL, pady=PADDING_NORMAL)

        # Scrollable frame for profiles
        canvas = tk.Canvas(container, bg=COLOR_CARD_BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient=tk.VERTICAL, command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=COLOR_CARD_BG)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")),
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor=tk.NW, width=280)
        canvas.configure(yscrollcommand=scrollbar.set)

        # Get all profiles in order
        all_profiles = list_profiles()

        for profile in all_profiles:
            self._create_profile_row(scrollable_frame, profile)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=PADDING_NORMAL)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        return container

    def _create_profile_row(self, parent: tk.Frame, profile: CryptoProfile) -> None:
        """Создаёт строку профиля с радио-кнопкой.

        Args:
            parent: Родительский фрейм для строки.
            profile: Профиль для отображения.
        """
        # Frame for this profile
        row_frame = tk.Frame(parent, bg=COLOR_CARD_BG, pady=PADDING_SMALL)
        row_frame.pack(fill=tk.X, padx=PADDING_SMALL)

        # Radio button
        radio = tk.Radiobutton(
            row_frame,
            variable=self._radio_var,
            value=profile.value,
            bg=COLOR_CARD_BG,
            command=self._on_profile_selected,
        )
        radio.pack(side=tk.LEFT, anchor=tk.N)

        # Content frame
        content_frame = tk.Frame(row_frame, bg=COLOR_CARD_BG)
        content_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(PADDING_SMALL, 0))

        # Name and badges row
        name_frame = tk.Frame(content_frame, bg=COLOR_CARD_BG)
        name_frame.pack(fill=tk.X)

        # Profile name
        name_label = tk.Label(
            name_frame,
            text=profile.label(),
            font=("TkDefaultFont", 10, "bold"),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
        )
        name_label.pack(side=tk.LEFT)

        # Badges
        self._create_badges(name_frame, profile)

        # Description (short)
        desc_text = self._get_short_description(profile)
        desc_label = tk.Label(
            content_frame,
            text=desc_text,
            font=("TkDefaultFont", 9),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_SECONDARY,
            wraplength=220,
            justify=tk.LEFT,
        )
        desc_label.pack(anchor=tk.W, pady=(PADDING_SMALL // 2, 0))

        # Store widgets reference
        self._profile_widgets[profile] = {
            "row": row_frame,
            "radio": radio,
            "name": name_label,
            "desc": desc_label,
        }

    def _create_badges(self, parent: tk.Frame, profile: CryptoProfile) -> None:
        """Создаёт бейджи для профиля.

        Args:
            parent: Родительский фрейм.
            profile: Профиль для которого создаются бейджи.
        """
        config = get_profile_config(profile)

        # PQC badge
        if config.post_quantum:
            self._create_badge(
                parent,
                "🔮 Post-Quantum",
                BADGE_PQC_BG,
                BADGE_PQC_FG,
            )

        # Floppy badge
        if config.floppy_optimized:
            self._create_badge(
                parent,
                "💾 Optimized",
                BADGE_FLOPPY_BG,
                BADGE_FLOPPY_FG,
            )

        # Legacy warning badge
        if not config.safe_for_new_systems:
            self._create_badge(
                parent,
                "⚠️ Unsafe",
                BADGE_LEGACY_BG,
                BADGE_LEGACY_FG,
            )

        # Performance warning for PARANOID
        if profile == CryptoProfile.PARANOID:
            self._create_badge(
                parent,
                "⚡ Slower",
                BADGE_WARNING_BG,
                BADGE_WARNING_FG,
            )

        # Performance warning for PQC_PARANOID
        if profile == CryptoProfile.PQC_PARANOID:
            self._create_badge(
                parent,
                "⚡ Very Slow",
                BADGE_WARNING_BG,
                BADGE_WARNING_FG,
            )

    def _create_badge(
        self,
        parent: tk.Frame,
        text: str,
        bg_color: str,
        fg_color: str,
    ) -> tk.Label:
        """Создаёт бейдж-лейбл.

        Args:
            parent: Родительский фрейм.
            text: Текст бейджа.
            bg_color: Color фона.
            fg_color: Color текста.

        Returns:
            Созданный лейбл-бейдж.
        """
        badge = tk.Label(
            parent,
            text=text,
            font=("TkDefaultFont", 8),
            bg=bg_color,
            fg=fg_color,
            padx=6,
            pady=2,
        )
        badge.pack(side=tk.LEFT, padx=(PADDING_SMALL, 0))
        return badge

    def _get_short_description(self, profile: CryptoProfile) -> str:
        """Возвращает краткое описание профиля.

        Args:
            profile: Профиль для описания.

        Returns:
            Краткое описание алгоритмов.
        """
        config = get_profile_config(profile)
        algorithms = [
            config.symmetric_algorithm.upper().replace("-", " "),
            config.signing_algorithm,
        ]
        return " + ".join(algorithms)

    def _create_details_panel(self, parent: tk.Frame) -> tk.Frame:
        """Создаёт панель деталей выбранного профиля.

        Args:
            parent: Родительский фрейм.

        Returns:
            Фрейм панели деталей.
        """
        # Container
        container = tk.Frame(
            parent,
            bg=COLOR_CARD_BG,
            highlightbackground=COLOR_BORDER,
            highlightthickness=1,
            width=250,
        )
        container.pack_propagate(False)

        # Title
        title_label = tk.Label(
            container,
            text="Profile Details",
            font=("TkDefaultFont", 11, "bold"),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
        )
        title_label.pack(anchor=tk.W, padx=PADDING_NORMAL, pady=PADDING_NORMAL)

        # Details content
        content_frame = tk.Frame(container, bg=COLOR_CARD_BG, padx=PADDING_NORMAL)
        content_frame.pack(fill=tk.BOTH, expand=True)

        # Create detail rows
        self._details_widgets = {}

        detail_items = [
            ("Encryption:", "symmetric"),
            ("Signing:", "signing"),
            ("KDF:", "kdf"),
            ("Hash:", "hash"),
            ("Post-quantum:", "post_quantum"),
        ]

        for label_text, key in detail_items:
            row_frame = tk.Frame(content_frame, bg=COLOR_CARD_BG)
            row_frame.pack(fill=tk.X, pady=PADDING_SMALL)

            label = tk.Label(
                row_frame,
                text=label_text,
                font=("TkDefaultFont", 9, "bold"),
                bg=COLOR_CARD_BG,
                fg=COLOR_TEXT_PRIMARY,
                width=12,
                anchor=tk.W,
            )
            label.pack(side=tk.LEFT)

            value_label = tk.Label(
                row_frame,
                text="-",
                font=("TkDefaultFont", 9),
                bg=COLOR_CARD_BG,
                fg=COLOR_TEXT_SECONDARY,
                wraplength=150,
                justify=tk.LEFT,
            )
            value_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(PADDING_SMALL, 0))

            self._details_widgets[key] = value_label

        # Description text
        desc_title = tk.Label(
            content_frame,
            text="Description:",
            font=("TkDefaultFont", 9, "bold"),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_PRIMARY,
            anchor=tk.W,
        )
        desc_title.pack(anchor=tk.W, pady=(PADDING_NORMAL, PADDING_SMALL))

        desc_label = tk.Label(
            content_frame,
            text="-",
            font=("TkDefaultFont", 9),
            bg=COLOR_CARD_BG,
            fg=COLOR_TEXT_SECONDARY,
            wraplength=220,
            justify=tk.LEFT,
        )
        desc_label.pack(anchor=tk.W)
        self._details_widgets["description"] = desc_label

        return container

    def _create_buttons(self, parent: tk.Frame) -> None:
        """Создаёт кнопки диалога.

        Args:
            parent: Родительский фрейм.
        """
        button_frame = tk.Frame(parent, bg=COLOR_BG)
        button_frame.pack(fill=tk.X)

        # Cancel button
        cancel_btn = tk.Button(
            button_frame,
            text="❌ Cancel",
            command=self._on_cancel,
            width=12,
        )
        cancel_btn.pack(side=tk.RIGHT, padx=(PADDING_NORMAL, 0))

        # Apply button
        apply_btn = tk.Button(
            button_frame,
            text="✓ Apply",
            command=self._apply_profile,
            width=12,
            bg=COLOR_ACCENT,
            fg="white",
        )
        apply_btn.pack(side=tk.RIGHT)

        self._details_widgets["apply_btn"] = apply_btn
        self._details_widgets["cancel_btn"] = cancel_btn

    def _on_profile_selected(self) -> None:
        """Обработчик выбора профиля из списка."""
        selected_value = self._radio_var.get()
        try:
            self._selected_profile = CryptoProfile(selected_value)
            self._show_profile_details(self._selected_profile)
            self._update_warning()
        except ValueError:
            logger.error("Unknown profile value: %s", selected_value)

    def _show_profile_details(self, profile: CryptoProfile) -> None:
        """Обновляет панель деталей для выбранного профиля.

        Args:
            profile: Профиль для отображения деталей.
        """
        config = get_profile_config(profile)

        # Update detail values
        updates = {
            "symmetric": config.symmetric_algorithm.upper(),
            "signing": config.signing_algorithm,
            "kdf": self._format_kdf(config),
            "hash": config.hash_algorithm.upper(),
            "post_quantum": "Yes" if config.post_quantum else "No",
            "description": profile.description(),
        }

        for key, value in updates.items():
            if key in self._details_widgets:
                widget = self._details_widgets[key]
                if isinstance(widget, tk.Label):
                    widget.config(text=value)

        # Update post-quantum label color
        pq_widget = self._details_widgets.get("post_quantum")
        if isinstance(pq_widget, tk.Label):
            color = COLOR_SUCCESS if config.post_quantum else COLOR_TEXT_SECONDARY
            pq_widget.config(fg=color)

    def _format_kdf(self, config: ProfileConfig) -> str:
        """Форматирует отображение KDF параметров.

        Args:
            config: Конфигурация профиля.

        Returns:
            Отформатированная строка KDF.
        """
        kdf_name = config.kdf_algorithm.upper()
        if "argon2id" in config.kdf_algorithm.lower():
            memory_mb = config.kdf_memory_cost // 1024
            return f"{kdf_name} ({memory_mb}MB)"
        return kdf_name

    def _update_warning(self) -> None:
        """Обновляет предупреждение при необходимости."""
        if self._warning_label is None:
            return

        if self._check_downgrade(self._selected_profile, self._current_profile):
            warning_text = (
                "⚠️ Warning: selected profile is less secure than the current one. "
                f"Security level will decrease from {SECURITY_LEVELS[self._current_profile]} "
                f"to {SECURITY_LEVELS[self._selected_profile]}."
            )
            self._warning_label.config(text=warning_text, fg=COLOR_WARNING)
        else:
            self._warning_label.config(text="")

    def _check_downgrade(self, new: CryptoProfile, old: CryptoProfile) -> bool:
        """Проверяет, является ли смена профиля понижением безопасности.

        Args:
            new: Новый выбранный профиль.
            old: Текущий профиль.

        Returns:
            True если новый профиль менее безопасен.
        """
        return SECURITY_LEVELS[new] < SECURITY_LEVELS[old]

    def _apply_profile(self) -> None:
        """Применяет выбранный профиль с опциональной MFA верификацией."""
        if self._selected_profile == self._current_profile:
            # No change, close dialog
            self._result = ProfileSelectionResult(
                profile=self._selected_profile,
                previous_profile=self._current_profile,
                is_downgrade=False,
                mfa_verified=False,
            )
            self.destroy()
            return

        is_downgrade = self._check_downgrade(self._selected_profile, self._current_profile)

        # MFA challenge if gate provided
        mfa_verified = False
        if self._mfa_gate is not None:
            try:
                mfa_result = self._mfa_gate.challenge(
                    parent=self,
                    user_id="operator",
                    methods=["totp", "backup"],
                    reason="change_crypto_profile",
                )
                if not mfa_result or not getattr(mfa_result, "verified", False):
                    messagebox.showwarning(
                        "MFA Required",
                        "MFA verification is required to change the cryptographic profile.",
                        parent=self,
                    )
                    return
                mfa_verified = True
            except Exception as e:
                logger.error("MFA challenge failed: %s", e)
                messagebox.showerror(
                    "MFA Error",
                    f"MFA verification error: {e}",
                    parent=self,
                )
                return

        # Confirm downgrade
        if is_downgrade:
            confirm = messagebox.askyesno(
                "Confirm",
                f"Are you sure you want to switch to a less secure profile?\n\n"
                f"From '{self._current_profile.label()}' to '{self._selected_profile.label()}'\n\n"
                f"This will reduce the data protection level.",
                icon="warning",
                parent=self,
            )
            if not confirm:
                return

        # Set result and close
        self._result = ProfileSelectionResult(
            profile=self._selected_profile,
            previous_profile=self._current_profile,
            is_downgrade=is_downgrade,
            mfa_verified=mfa_verified,
        )
        self.destroy()

    def _on_cancel(self) -> None:
        """Обработчик отмены диалога."""
        self._result = None
        self.destroy()

    def _center_window(self) -> None:
        """Центрирует окно относительно родительского."""
        self.update_idletasks()

        width = DIALOG_WIDTH
        height = DIALOG_HEIGHT

        parent = self._parent
        parent_x = parent.winfo_rootx()
        parent_y = parent.winfo_rooty()
        parent_width = parent.winfo_width()
        parent_height = parent.winfo_height()

        x = parent_x + (parent_width - width) // 2
        y = parent_y + (parent_height - height) // 2

        self.geometry(f"{width}x{height}+{x}+{y}")

    def _apply_theme(self) -> None:
        """Применяет текущую тему к диалогу."""
        try:
            theme_manager = get_theme_manager()
            theme_manager.apply_to_widget(cast(tk.Widget, self))
        except Exception as e:
            logger.warning("Failed to apply theme: %s", e)

    def show(self) -> Optional[ProfileSelectionResult]:
        """Отображает модальный диалог и возвращает результат.

        Returns:
            ProfileSelectionResult если профиль выбран, иначе None.

        Example:
            >>> result = dialog.show()
            >>> if result:
            ...     print(f"Changed to {result.profile.label()}")
        """
        super().show()
        return self._result


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def show_crypto_profile_dialog(
    parent: tk.Tk,
    current_profile: CryptoProfile = CryptoProfile.STANDARD,
    mfa_gate: Optional[Any] = None,
) -> Optional[ProfileSelectionResult]:
    """Утилитарная функция для быстрого открытия диалога.

    Args:
        parent: Родительское окно.
        current_profile: Текущий профиль безопасности.
        mfa_gate: Опциональный MFA gate.

    Returns:
        ProfileSelectionResult если профиль выбран, иначе None.

    Example:
        >>> from src.security.crypto.service.profiles import CryptoProfile
        >>> result = show_crypto_profile_dialog(root, CryptoProfile.STANDARD)
        >>> if result:
        ...     print(f"New profile: {result.profile.label()}")
    """
    dialog = CryptoProfileDialog(
        parent=parent,
        current_profile=current_profile,
        mfa_gate=mfa_gate,
    )
    return dialog.show()


# Module exports
__all__: list[str] = [
    "ProfileSelectionResult",
    "CryptoProfileDialog",
    "show_crypto_profile_dialog",
    "SECURITY_LEVELS",
]
