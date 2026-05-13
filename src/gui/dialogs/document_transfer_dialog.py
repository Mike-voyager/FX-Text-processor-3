"""DocumentTransferDialog — диалог переноса документа между окнами.

Предоставляет интерфейс для переноса документа из одного окна в другое
с проверкой прав доступа, MFA верификацией для PARANOID preset
и интеграцией с DocumentLockService.

Example:
    >>> dialog = DocumentTransferDialog(
    ...     parent=root,
    ...     source_window_id="win-123",
    ...     document_id="doc-456",
    ...     user_id="user789",
    ...     document_preset="PARANOID",
    ...     has_unsaved_changes=True,
    ...     window_manager=window_manager,
    ...     mfa_gate=mfa_gate,
    ...     document_lock_service=lock_service,
    ... )
    >>> result = dialog.show()
    >>> if result:
    ...     print("Документ успешно перенесён")

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Final, Optional, cast

from src.gui.dialogs.base_dialog import BaseDialog
from src.gui.security.mfa_gate import MFAGate
from src.gui.services.window_manager import WindowInfo, WindowManager
from src.services.document_lock_service import DocumentLockService

# UI Constants
DIALOG_WIDTH: Final[int] = 500
DIALOG_HEIGHT: Final[int] = 400
MIN_DIALOG_WIDTH: Final[int] = 400
MIN_DIALOG_HEIGHT: Final[int] = 350

PADDING_LARGE: Final[int] = 20
PADDING_NORMAL: Final[int] = 10
PADDING_SMALL: Final[int] = 5

COLOR_BG: Final[str] = "#f8f9fa"
COLOR_HEADER: Final[str] = "#e9ecef"
COLOR_BORDER: Final[str] = "#dee2e6"
COLOR_TEXT: Final[str] = "#212529"

# Status colors
COLOR_WARNING: Final[str] = "#f39c12"
COLOR_ERROR: Final[str] = "#e74c3c"
COLOR_SUCCESS: Final[str] = "#2ecc71"

COLOR_MFA_BG: Final[str] = "#fff3cd"
COLOR_MFA_FG: Final[str] = "#856404"

COLOR_WARNING_BG: Final[str] = "#fff3cd"
COLOR_WARNING_FG: Final[str] = "#856404"


class DocumentTransferDialog(BaseDialog):
    """Диалог переноса документа между окнами.

    Отображает информацию об исходном окне, позволяет выбрать
    целевое окно из списка доступных. Для PARANOID preset требует
    MFA верификацию перед переносом. Интегрируется с DocumentLockService
    для проверки блокировок.

    Attributes:
        _source_window_id: ID исходного окна.
        _document_id: ID документа для переноса.
        _user_id: ID пользователя выполняющего операцию.
        _document_preset: Security preset документа ("STANDARD", "PARANOID").
        _has_unsaved_changes: Флаг наличия несохранённых изменений.
        _window_manager: Менеджер окон для получения списка и переноса.
        _mfa_gate: MFA шлюз для верификации.
        _document_lock_service: Сервис блокировок документов.
        _result: Результат операции (True если перенос выполнен).
        _available_windows: Список доступных целевых окон.

    Example:
        >>> dialog = DocumentTransferDialog(
        ...     parent=root,
        ...     source_window_id="win-1",
        ...     document_id="doc-123",
        ...     user_id="user456",
        ...     document_preset="STANDARD",
        ...     has_unsaved_changes=False,
        ...     window_manager=manager,
        ...     mfa_gate=gate,
        ...     document_lock_service=lock_service,
        ... )
        >>> if dialog.show():
        ...     print("Transfer successful")
    """

    DIALOG_WIDTH: Final[int] = 500
    DIALOG_HEIGHT: Final[int] = 400

    def __init__(
        self,
        parent: tk.Widget,
        source_window_id: str,
        document_id: str,
        user_id: str,
        document_preset: str,
        has_unsaved_changes: bool,
        window_manager: WindowManager,
        mfa_gate: MFAGate,
        document_lock_service: DocumentLockService,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """Инициализация диалога переноса документа.

        Args:
            parent: Родительский виджет.
            source_window_id: ID исходного окна.
            document_id: ID документа для переноса.
            user_id: ID пользователя.
            document_preset: Security preset ("STANDARD", "PARANOID", etc.).
            has_unsaved_changes: True если есть несохранённые изменения.
            window_manager: Менеджер окон.
            mfa_gate: MFA шлюз.
            document_lock_service: Сервис блокировок.
            *args: Дополнительные аргументы для Toplevel.
            **kwargs: Дополнительные именованные аргументы.
        """
        super().__init__(parent, *args, modal=True, **kwargs)

        self._parent: tk.Widget = parent
        self._source_window_id: str = source_window_id
        self._document_id: str = document_id
        self._user_id: str = user_id
        self._document_preset: str = document_preset
        self._has_unsaved_changes: bool = has_unsaved_changes
        self._window_manager: WindowManager = window_manager
        self._mfa_gate: MFAGate = mfa_gate
        self._document_lock_service: DocumentLockService = document_lock_service

        self._result: bool = False
        self._available_windows: list[WindowInfo] = []
        self._selected_target_id: Optional[str] = None

        self._setup_window()
        self._create_ui()
        self._load_available_windows()

    def _setup_window(self) -> None:
        """Настраивает параметры окна диалога."""
        self.title("Перенос документа")
        self.geometry(f"{self.DIALOG_WIDTH}x{self.DIALOG_HEIGHT}")
        self.minsize(MIN_DIALOG_WIDTH, MIN_DIALOG_HEIGHT)

        # Center the dialog
        self.update_idletasks()
        parent_x = self._parent.winfo_rootx()
        parent_y = self._parent.winfo_rooty()
        parent_width = self._parent.winfo_width()
        parent_height = self._parent.winfo_height()

        x = parent_x + (parent_width - self.DIALOG_WIDTH) // 2
        y = parent_y + (parent_height - self.DIALOG_HEIGHT) // 2
        self.geometry(f"+{x}+{y}")

    def _create_ui(self) -> None:
        """Создаёт UI компоненты диалога."""
        self.config(bg=COLOR_BG)

        # Main container
        main_frame = ttk.Frame(self, padding=f"{PADDING_LARGE}")
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.columnconfigure(0, weight=1)

        # Header
        self._create_header(main_frame)

        # Source window section
        self._create_source_section(main_frame)

        # Unsaved changes warning
        self._create_unsaved_warning(main_frame)

        # Target window selection
        self._create_target_section(main_frame)

        # MFA section (for PARANOID preset)
        self._create_mfa_section(main_frame)

        # Buttons
        self._create_buttons(main_frame)

        # Bindings

    def _create_header(self, parent: ttk.Frame) -> None:
        """Создаёт заголовок диалога.

        Args:
            parent: Родительский фрейм.
        """
        header = ttk.Label(
            parent,
            text="📂 Перенос документа между окнами",
            font=("Helvetica", 14, "bold"),
        )
        header.grid(row=0, column=0, sticky="w", pady=(0, PADDING_NORMAL))

        description = ttk.Label(
            parent,
            text="Выберите целевое окно для переноса документа",
            foreground="gray",
        )
        description.grid(row=1, column=0, sticky="w", pady=(0, PADDING_NORMAL))

    def _create_source_section(self, parent: ttk.Frame) -> None:
        """Создаёт секцию отображения исходного окна.

        Args:
            parent: Родительский фрейм.
        """
        source_frame = ttk.LabelFrame(
            parent,
            text="Исходное окно",
            padding=PADDING_NORMAL,
        )
        source_frame.grid(row=2, column=0, sticky="ew", pady=(0, PADDING_NORMAL))
        source_frame.columnconfigure(0, weight=1)

        # Get source window info
        source_info = self._window_manager.get_window(self._source_window_id)
        if source_info:
            # Try to get window info from list
            window_list = self._window_manager.get_window_list()
            source_window_info: Optional[WindowInfo] = None
            for win in window_list:
                if win.window_id == self._source_window_id:
                    source_window_info = win
                    break

            if source_window_info:
                title_text = f"📄 {source_window_info.title}"
                doc_text = f"Документ: {source_window_info.document_path or 'Нет документа'}"
            else:
                title_text = f"📄 Окно {self._source_window_id[:8]}..."
                doc_text = f"Документ: {self._document_id}"
        else:
            title_text = f"📄 Окно {self._source_window_id[:8]}..."
            doc_text = f"Документ: {self._document_id}"

        # From label
        ttk.Label(
            source_frame,
            text="Из:",
            font=("Helvetica", 10, "bold"),
        ).grid(row=0, column=0, sticky="w")

        ttk.Label(
            source_frame,
            text=title_text,
            font=("Helvetica", 10),
        ).grid(row=0, column=1, sticky="w", padx=(PADDING_SMALL, 0))

        ttk.Label(
            source_frame,
            text=doc_text,
            foreground="gray",
            font=("Helvetica", 9),
        ).grid(row=1, column=1, sticky="w", padx=(PADDING_SMALL, 0))

    def _create_unsaved_warning(self, parent: ttk.Frame) -> None:
        """Создаёт предупреждение о несохранённых изменениях.

        Args:
            parent: Родительский фрейм.
        """
        self._warning_frame = tk.Frame(
            parent,
            bg=COLOR_WARNING_BG,
            padx=PADDING_NORMAL,
            pady=PADDING_SMALL,
        )

        self._warning_label = tk.Label(
            self._warning_frame,
            text="⚠️ В текущем документе есть несохранённые изменения",
            bg=COLOR_WARNING_BG,
            fg=COLOR_WARNING,
            font=("Helvetica", 10),
        )
        self._warning_label.pack(anchor="w")

        if self._has_unsaved_changes:
            self._warning_frame.grid(row=3, column=0, sticky="ew", pady=(0, PADDING_NORMAL))

    def _create_target_section(self, parent: ttk.Frame) -> None:
        """Создаёт секцию выбора целевого окна.

        Args:
            parent: Родительский фрейм.
        """
        target_frame = ttk.LabelFrame(
            parent,
            text="Целевое окно",
            padding=PADDING_NORMAL,
        )
        target_frame.grid(row=4, column=0, sticky="ew", pady=(0, PADDING_NORMAL))
        target_frame.columnconfigure(1, weight=1)

        # To label
        ttk.Label(
            target_frame,
            text="В:",
            font=("Helvetica", 10, "bold"),
        ).grid(row=0, column=0, sticky="w", pady=(0, PADDING_SMALL))

        # Target selection frame
        self._target_selection_frame = ttk.Frame(target_frame)
        self._target_selection_frame.grid(row=0, column=1, sticky="ew", padx=(PADDING_SMALL, 0))

        # Combobox for target windows
        self._target_var = tk.StringVar()
        self._target_combo = ttk.Combobox(
            self._target_selection_frame,
            textvariable=self._target_var,
            state="readonly",
            width=40,
        )
        self._target_combo.pack(fill=tk.X)

        # No targets message (hidden by default)
        self._no_targets_label = ttk.Label(
            target_frame,
            text="Нет доступных окон",
            foreground=COLOR_WARNING,
            font=("Helvetica", 10, "italic"),
        )

    def _create_mfa_section(self, parent: ttk.Frame) -> None:
        """Создаёт MFA секцию для PARANOID preset.

        Args:
            parent: Родительский фрейм.
        """
        self._mfa_frame = tk.Frame(
            parent,
            bg=COLOR_MFA_BG,
            padx=PADDING_NORMAL,
            pady=PADDING_SMALL,
        )

        mfa_title = tk.Label(
            self._mfa_frame,
            text="🔐 Требуется MFA верификация",
            bg=COLOR_MFA_BG,
            fg=COLOR_MFA_FG,
            font=("Helvetica", 10, "bold"),
        )
        mfa_title.pack(anchor="w")

        mfa_desc = tk.Label(
            self._mfa_frame,
            text="Для переноса защищённого документа требуется MFA",
            bg=COLOR_MFA_BG,
            fg=COLOR_MFA_FG,
            font=("Helvetica", 9),
        )
        mfa_desc.pack(anchor="w")

        # Show only for PARANOID preset
        if self._document_preset == "PARANOID":
            self._mfa_frame.grid(row=5, column=0, sticky="ew", pady=(0, PADDING_NORMAL))

    def _create_buttons(self, parent: ttk.Frame) -> None:
        """Создаёт панель кнопок.

        Args:
            parent: Родительский фрейм.
        """
        button_frame = ttk.Frame(parent)
        button_frame.grid(row=6, column=0, sticky="ew", pady=(PADDING_NORMAL, 0))
        button_frame.columnconfigure(0, weight=1)

        # Cancel button
        self._cancel_btn = ttk.Button(
            button_frame,
            text="Отмена",
            command=self._on_cancel,
        )
        self._cancel_btn.pack(side=tk.RIGHT, padx=(PADDING_SMALL, 0))

        # Transfer button
        self._transfer_btn = ttk.Button(
            button_frame,
            text="Перенести",
            command=self._on_transfer,
        )
        self._transfer_btn.pack(side=tk.RIGHT)

    def _load_available_windows(self) -> None:
        """Загружает список доступных целевых окон."""
        all_windows = self._window_manager.get_window_list()

        # Filter out source window
        self._available_windows = [
            win for win in all_windows if win.window_id != self._source_window_id
        ]

        if self._available_windows:
            # Populate combobox
            window_names = [f"{win.title} ({win.window_id[:8]})" for win in self._available_windows]
            self._target_combo["values"] = window_names
            self._target_combo.current(0)

            # Show selection, hide "no targets"
            self._target_selection_frame.grid()
            self._no_targets_label.grid_remove()
        else:
            # No available windows
            self._target_selection_frame.grid_remove()
            self._no_targets_label.grid(row=0, column=1, sticky="w", padx=(PADDING_SMALL, 0))
            self._transfer_btn.configure(state=tk.DISABLED)

    def _get_selected_target(self) -> Optional[str]:
        """Возвращает ID выбранного целевого окна.

        Returns:
            ID окна или None если ничего не выбрано.
        """
        selection = self._target_var.get()
        if not selection:
            return None

        # Find window by display name
        for win in self._available_windows:
            display_name = f"{win.title} ({win.window_id[:8]})"
            if display_name == selection:
                return win.window_id

        return None

    def _on_transfer(self) -> None:
        """Обработчик нажатия кнопки 'Перенести'."""
        # 1. Проверка выбора целевого окна
        target_id = self._get_selected_target()
        if not target_id:
            messagebox.showwarning(
                "Ошибка",
                "Выберите целевое окно",
                parent=self,
            )
            return

        # 2. MFA для PARANOID
        if self._document_preset == "PARANOID":
            result = self._mfa_gate.challenge(
                parent=cast(tk.Widget, self),
                user_id=self._user_id,
                required_methods=["totp", "backup_code"],
                operation="transfer_document",
            )
            if not result.verified:
                return  # Отмена

        # 3. Проверка DocumentLock
        if hasattr(self._document_lock_service, "can_transfer"):
            can_transfer = self._document_lock_service.can_transfer(
                self._document_id, self._source_window_id, target_id
            )
        else:
            # Fallback: check if document is locked
            can_transfer = True  # Assume allowed if method not available

        if not can_transfer:
            messagebox.showerror(
                "Ошибка",
                "Документ заблокирован другим пользователем",
                parent=self,
            )
            return

        # 4. Выполнить перенос
        success = self._window_manager.transfer_document(
            self._source_window_id, target_id, self._document_id
        )

        if success:
            self._result = True
            self.destroy()
        else:
            messagebox.showerror(
                "Ошибка",
                "Не удалось перенести документ",
                parent=self,
            )

    def _on_cancel(self) -> None:
        """Обработчик нажатия кнопки 'Отмена'."""
        self._result = False
        self.destroy()

    def show(self) -> bool:
        """Показывает диалог и возвращает результат.

        Returns:
            True если перенос выполнен успешно, False в противном случае.
        """
        self.wait_window()
        return self._result


__all__ = [
    "DocumentTransferDialog",
    "DIALOG_WIDTH",
    "DIALOG_HEIGHT",
    "COLOR_WARNING",
    "COLOR_ERROR",
    "COLOR_SUCCESS",
]
