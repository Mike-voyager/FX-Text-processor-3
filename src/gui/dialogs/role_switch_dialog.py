"""RoleSwitchDialog — диалог смены роли с MFA и free mode.

Предоставляет интерфейс для смены роли с индикацией требований MFA
и режимом свободного переключения (все роли требуют MFA).

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import TYPE_CHECKING, Any, Callable, Final, Optional, Tuple

from src.gui.dialogs.base_dialog import BaseDialog

if TYPE_CHECKING:
    from src.controller.workflow_controller import WorkflowRole

# UI Constants
DIALOG_WIDTH: Final[int] = 450
DIALOG_HEIGHT: Final[int] = 400
MIN_DIALOG_WIDTH: Final[int] = 380
MIN_DIALOG_HEIGHT: Final[int] = 350

PADDING_LARGE: Final[int] = 20
PADDING_NORMAL: Final[int] = 10
PADDING_SMALL: Final[int] = 5

COLOR_BG: Final[str] = "#f8f9fa"
COLOR_FREE_MODE_BG: Final[str] = "#e7f3ff"
COLOR_FREE_MODE_BORDER: Final[str] = "#3498db"
COLOR_WARNING_BG: Final[str] = "#fff3cd"


class RoleSwitchDialog(BaseDialog):
    """Диалог смены роли с MFA и режимом свободного переключения.

    Позволяет выбрать новую роль с индикацией требований MFA.
    Режим "Свободное переключение" включает MFA для всех ролей.

    Attributes:
        _current_role: Текущая роль.
        _selected_role: Выбранная роль.
        _free_mode: Режим свободного переключения.
        _mfa_required: Требуется ли MFA для выбранного перехода.
        _result: Результат диалога.

    Example:
        >>> dialog = RoleSwitchDialog(
        ...     parent=root,
        ...     current_role=WorkflowRole.OPERATOR,
        ... )
        >>> result = dialog.show()
        >>> if result:
        ...     role, free_mode, requires_mfa = result
        ...     print(f"Switched to {role}, free_mode={free_mode}")
    """

    def __init__(
        self,
        parent: tk.Widget,
        current_role: "WorkflowRole",
        free_mode_enabled: bool = False,
        on_role_selected: Optional[Callable[["WorkflowRole", bool], None]] = None,
        on_cancel: Optional[Callable[[], None]] = None,
    ) -> None:
        """Инициализация диалога.

        Args:
            parent: Родительский виджет.
            current_role: Текущая роль пользователя.
            free_mode_enabled: Начальное состояние free mode.
            on_role_selected: Callback при выборе роли.
            on_cancel: Callback при отмене.
        """
        super().__init__(parent)

        self._parent = parent
        self._current_role = current_role
        self._selected_role: Optional["WorkflowRole"] = None
        self._free_mode = free_mode_enabled
        self._mfa_required = False
        self._on_role_selected_callback = on_role_selected
        self._on_cancel_callback = on_cancel

        self._result: Optional[Tuple["WorkflowRole", bool, bool]] = None

        self._setup_window()
        self._create_ui()
        self._update_ui_state()

    def _setup_window(self) -> None:
        """Настраивает параметры окна."""
        self.title("Role Switch")
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

        # Free mode checkbox
        self._create_free_mode_section(main_frame)

        # Current role display
        self._create_current_role_section(main_frame)

        # Role selector
        self._create_role_selector(main_frame)

        # MFA indicator
        self._create_mfa_section(main_frame)

        # Buttons
        self._create_buttons(main_frame)

        # Bindings

    def _create_header(self, parent: ttk.Frame) -> None:
        """Создаёт заголовок."""
        header = ttk.Label(
            parent,
            text="Role Switch in Workflow",
            font=("Helvetica", 14, "bold"),
        )
        header.pack(anchor="w", pady=(0, PADDING_NORMAL))

        description = ttk.Label(
            parent,
            text="Select a new role to perform operations",
            foreground="gray",
        )
        description.pack(anchor="w", pady=(0, PADDING_NORMAL))

    def _create_free_mode_section(self, parent: ttk.Frame) -> None:
        """Создаёт секцию режима свободного переключения."""
        from src.gui.workflow.constants import (
            FREE_ROLE_SWITCHING_DESCRIPTION,
            FREE_ROLE_SWITCHING_LABEL,
        )

        # Frame with highlight when enabled
        self._free_mode_frame = tk.Frame(
            parent,
            bg=COLOR_BG,
            highlightthickness=2,
            highlightcolor=COLOR_FREE_MODE_BORDER,
        )
        self._free_mode_frame.pack(fill=tk.X, pady=(0, PADDING_NORMAL), padx=PADDING_SMALL)

        self._free_mode_var = tk.BooleanVar(master=self, value=self._free_mode)
        self._free_mode_var.trace_add("write", self._on_free_mode_changed)

        self._free_mode_cb = ttk.Checkbutton(
            self._free_mode_frame,
            text=FREE_ROLE_SWITCHING_LABEL,
            variable=self._free_mode_var,
        )
        self._free_mode_cb.pack(anchor="w", padx=PADDING_NORMAL, pady=PADDING_SMALL)

        self._free_mode_desc = ttk.Label(
            self._free_mode_frame,
            text=FREE_ROLE_SWITCHING_DESCRIPTION,
            foreground="gray",
            font=("Helvetica", 9),
        )
        self._free_mode_desc.pack(anchor="w", padx=(PADDING_NORMAL * 2, 0))

    def _create_current_role_section(self, parent: ttk.Frame) -> None:
        """Создаёт отображение текущей роли."""
        from src.gui.workflow.constants import ROLE_COLORS, ROLE_ICONS, ROLE_NAMES_RU

        current_frame = ttk.LabelFrame(parent, text="Current Role", padding=PADDING_NORMAL)
        current_frame.pack(fill=tk.X, pady=(0, PADDING_NORMAL))

        current_str = (
            self._current_role.value
            if hasattr(self._current_role, "value")
            else str(self._current_role)
        )

        role_color = ROLE_COLORS.get(current_str, "#95a5a6")
        role_icon = ROLE_ICONS.get(current_str, "👤")
        role_name = ROLE_NAMES_RU.get(current_str, current_str.capitalize())

        # Role display with color
        role_display = tk.Frame(
            current_frame,
            bg=role_color,
            padx=15,
            pady=8,
        )
        role_display.pack(anchor="w")

        role_label = tk.Label(
            role_display,
            text=f"{role_icon} {role_name}",
            bg=role_color,
            fg="white",
            font=("Helvetica", 11, "bold"),
        )
        role_label.pack()

    def _create_role_selector(self, parent: ttk.Frame) -> None:
        """Создаёт селектор ролей с радио-кнопками."""
        from src.gui.workflow.constants import ROLE_COLORS, ROLE_ICONS, ROLE_NAMES_RU

        selector_frame = ttk.LabelFrame(parent, text="Select New Role", padding=PADDING_NORMAL)
        selector_frame.pack(fill=tk.BOTH, expand=True, pady=(0, PADDING_NORMAL))

        self._role_var: tk.StringVar = tk.StringVar(master=self)

        # Create radio button for each role
        for role_value, role_name in ROLE_NAMES_RU.items():
            role_icon = ROLE_ICONS.get(role_value, "👤")
            role_color = ROLE_COLORS.get(role_value, "#95a5a6")

            # Check if MFA required for this role (normally)
            from src.gui.workflow.mfa_checker import MFARequirementChecker

            mfa_checker = MFARequirementChecker(free_mode_enabled=False)
            current_str = (
                self._current_role.value
                if hasattr(self._current_role, "value")
                else str(self._current_role)
            )
            requires_mfa = mfa_checker.is_role_switch_mfa_required(
                self._current_role,
                role_value,  # type: ignore
            )

            mfa_indicator = " 🔒" if requires_mfa else ""

            # Role row
            role_row = ttk.Frame(selector_frame)
            role_row.pack(fill=tk.X, pady=PADDING_SMALL)

            # Radio button
            rb = ttk.Radiobutton(
                role_row,
                text=f"{role_icon} {role_name}{mfa_indicator}",
                variable=self._role_var,
                value=role_value,
                command=self._on_role_selected,
            )
            rb.pack(side=tk.LEFT, fill=tk.X, expand=True)

            # Color indicator
            color_box = tk.Frame(role_row, bg=role_color, width=20, height=20)
            color_box.pack(side=tk.RIGHT, padx=(PADDING_SMALL, 0))

        # Select current role by default
        self._role_var.set(current_str)

    def _create_mfa_section(self, parent: ttk.Frame) -> None:
        """Создаёт секцию индикации MFA."""
        self._mfa_frame = tk.Frame(
            parent,
            bg=COLOR_WARNING_BG,
            padx=PADDING_NORMAL,
            pady=PADDING_SMALL,
        )
        self._mfa_frame.pack(fill=tk.X, pady=(0, PADDING_NORMAL))

        self._mfa_label = tk.Label(
            self._mfa_frame,
            text="🔐 MFA is required to switch roles",
            bg=COLOR_WARNING_BG,
            fg="#856404",
            font=("Helvetica", 10),
        )
        self._mfa_label.pack(anchor="w")

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

        # Apply button
        self._apply_btn = ttk.Button(
            btn_frame,
            text="Apply",
            command=self._on_apply,
        )
        self._apply_btn.pack(side=tk.RIGHT)

    def _on_free_mode_changed(self, *args: Any) -> None:
        """Обработчик изменения free mode."""
        self._free_mode = self._free_mode_var.get()
        self._update_ui_state()

    def _on_role_selected(self) -> None:
        """Обработчик выбора роли."""
        self._update_mfa_indicator()

    def _update_ui_state(self) -> None:
        """Обновляет состояние UI в зависимости от free mode."""
        if self._free_mode:
            self._free_mode_frame.config(
                bg=COLOR_FREE_MODE_BG,
                highlightbackground=COLOR_FREE_MODE_BORDER,
            )
        else:
            self._free_mode_frame.config(
                bg=COLOR_BG,
                highlightcolor=COLOR_BG,
            )

        self._update_mfa_indicator()

    def _update_mfa_indicator(self) -> None:
        """Обновляет индикатор MFA."""
        selected_role_str = self._role_var.get()
        current_str = (
            self._current_role.value
            if hasattr(self._current_role, "value")
            else str(self._current_role)
        )

        if selected_role_str == current_str:
            # Same role - no MFA needed, no switch
            self._mfa_frame.pack_forget()
            self._mfa_required = False
            return

        # Check MFA requirement
        from src.gui.workflow.mfa_checker import MFARequirementChecker

        mfa_checker = MFARequirementChecker(free_mode_enabled=self._free_mode)

        # Get the selected role enum
        from src.controller.workflow_controller import WorkflowRole

        selected_role = WorkflowRole(selected_role_str)

        requires_mfa = mfa_checker.is_role_switch_mfa_required(
            self._current_role,
            selected_role,
            free_mode=self._free_mode,
        )

        self._mfa_required = requires_mfa

        if requires_mfa:
            self._mfa_frame.pack(fill=tk.X, pady=(0, PADDING_NORMAL), before=self._apply_btn.master)
            if self._free_mode:
                self._mfa_label.config(text="🔐 Free switching mode: MFA is required for any role")
        else:
            self._mfa_frame.pack_forget()

    def _on_apply(self) -> None:
        """Обработчик применения смены роли."""
        selected_role_str = self._role_var.get()
        current_str = (
            self._current_role.value
            if hasattr(self._current_role, "value")
            else str(self._current_role)
        )

        # Check if role actually changed
        if selected_role_str == current_str:
            messagebox.showinfo(
                "Information",
                "Current role is selected. No changes needed.",
                parent=self,
            )
            self._on_cancel()
            return

        # Get selected role enum
        from src.controller.workflow_controller import WorkflowRole

        selected_role = WorkflowRole(selected_role_str)

        self._result = (selected_role, self._free_mode, self._mfa_required)

        if self._on_role_selected_callback:
            self._on_role_selected_callback(selected_role, self._free_mode)

        self.destroy()

    def _on_cancel(self) -> None:
        """Обработчик отмены."""
        self._result = None

        if self._on_cancel_callback:
            self._on_cancel_callback()

        self.destroy()

    def show(self) -> Optional[Tuple["WorkflowRole", bool, bool]]:
        """Показывает диалог и возвращает результат.

        Returns:
            Кортеж (new_role, free_mode, requires_mfa) или None.
        """
        self.wait_window()
        return self._result


__all__ = ["RoleSwitchDialog"]
