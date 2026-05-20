"""Диалог сохранения документа с опциями шифрования.

Предоставляет комплексный UI для сохранения документов FX Text Processor 3
с поддержкой шифрования, выбора пресетов безопасности и управления метаданными.

Example:
    >>> from src.gui.dialogs.save_dialog import SaveDialog, SaveResult
    >>> from src.model.document import Document
    >>> dialog = SaveDialog(
    ...     parent=root,
    ...     document=document,
    ... )
    >>> result = dialog.show()
    >>> if result:
    ...     print(f"Saved to: {result.path}")

Version: 2.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any as TypingAny
from typing import Final, Optional, cast

from src.documents.format.document_format import SecurityPreset
from src.gui.dialogs.base_dialog import BaseDialog
from src.model.document import Document, DocumentMetadata
from src.security.crypto.utilities.passwords import (
    PasswordHasher,
    PasswordStrength,
    PasswordStrengthResult,
)

# UI Constants
DIALOG_WIDTH: Final[int] = 550
DIALOG_HEIGHT: Final[int] = 650
MIN_DIALOG_WIDTH: Final[int] = 450
MIN_DIALOG_HEIGHT: Final[int] = 550

# Colors
COLOR_BG: Final[str] = "#f8f9fa"
COLOR_HEADER: Final[str] = "#e9ecef"
COLOR_BORDER: Final[str] = "#dee2e6"
COLOR_TEXT: Final[str] = "#212529"

# Password strength colors
STRENGTH_COLORS: Final[dict[PasswordStrength, str]] = {
    PasswordStrength.WEAK: "#dc3545",  # Red
    PasswordStrength.FAIR: "#ffc107",  # Yellow
    PasswordStrength.STRONG: "#28a745",  # Green
    PasswordStrength.VERY_STRONG: "#20c997",  # Teal
}

STRENGTH_LABELS: Final[dict[PasswordStrength, str]] = {
    PasswordStrength.WEAK: "Weak",
    PasswordStrength.FAIR: "Fair",
    PasswordStrength.STRONG: "Strong",
    PasswordStrength.VERY_STRONG: "Excellent",
}

# Security preset labels
PRESET_LABELS: Final[dict[SecurityPreset, str]] = {
    SecurityPreset.STANDARD: "Standard (AES-256-GCM + Argon2id 64MB)",
    SecurityPreset.PARANOID: "Paranoid (AES-256-GCM + Argon2id 256MB)",
    SecurityPreset.PQC: "PQC (ML-DSA-65 + AES-256-GCM)",
    SecurityPreset.LEGACY: "Legacy (RSA-PSS-4096 + PBKDF2)",
}


@dataclass(frozen=True)
class SaveResult:
    """Результат диалога сохранения документа.

    Attributes:
        path: Путь для сохранения файла.
        encrypted: True если документ будет зашифрован.
        preset: Выбранный пресет безопасности.
        metadata: Метаданные документа.
        password: Пароль для шифрования (только если encrypted=True).

    Example:
        >>> result = SaveResult(
        ...     path=Path("/docs/invoice.fxsd.enc"),
        ...     encrypted=True,
        ...     preset=SecurityPreset.STANDARD,
        ...     metadata=DocumentMetadata(title="Invoice"),
        ...     password="secure_pass",
        ... )
    """

    path: Path
    encrypted: bool
    preset: SecurityPreset
    metadata: DocumentMetadata
    password: str = ""


class SaveDialog(BaseDialog):
    """Диалог сохранения документа с опциями шифрования.

    Предоставляет полный UI для сохранения документов:
    - Выбор имени файла и расположения
    - Опциональное шифрование с паролем
    - Выбор пресета безопасности
    - Индикатор сложности пароля
    - Редактирование метаданных документа
    - Оценка размера файла

    Attributes:
        _document: Документ для сохранения.
        _result: Результат сохранения (None если отменено).
        _password_hasher: Утилита для проверки сложности пароля.

    Example:
        >>> dialog = SaveDialog(parent, document)
        >>> result = dialog.show()
        >>> if result:
        ...     print(f"Path: {result.path}")
    """

    def __init__(
        self,
        parent: tk.Widget,
        document: Document,
        *,
        default_path: Optional[Path] = None,
        title: str = "Save Document",
    ) -> None:
        """Инициализация диалога сохранения.

        Args:
            parent: Родительский виджет.
            document: Документ для сохранения.
            default_path: Путь по умолчанию (опционально).
            title: Заголовок окна диалога.
        """
        super().__init__(parent)

        self._parent: tk.Widget = parent
        self._document: Document = document
        self._default_path: Optional[Path] = default_path
        self._current_path: Path = default_path or Path.home() / "Documents"
        self._result: Optional[SaveResult] = None
        self._password_hasher: PasswordHasher = PasswordHasher()

        self._create_ui()
        self._setup_window(title)
        self._initialize_values()

    def _setup_window(self, title: str) -> None:
        """Настраивает параметры окна диалога.

        Args:
            title: Заголовок окна.
        """
        self.title(title)
        self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}")
        self.minsize(MIN_DIALOG_WIDTH, MIN_DIALOG_HEIGHT)
        self.config(bg=COLOR_BG)

        # Center the dialog
        self.update_idletasks()
        parent_x = self._parent.winfo_rootx()
        parent_y = self._parent.winfo_rooty()
        parent_width = self._parent.winfo_width()
        parent_height = self._parent.winfo_height()

        x = parent_x + (parent_width - DIALOG_WIDTH) // 2
        y = parent_y + (parent_height - DIALOG_HEIGHT) // 2
        self.geometry(f"+{x}+{y}")

        # Protocol for window close

    def _create_ui(self) -> None:
        """Создаёт UI компоненты диалога."""
        # Main container with padding
        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.columnconfigure(0, weight=1)

        # Configure row weights for proper expansion
        for row in range(8):
            main_frame.rowconfigure(row, weight=0)

        # File location section
        self._create_file_section(main_frame, row=0)

        # Encryption section
        self._create_encryption_section(main_frame, row=1)

        # Security preset section
        self._create_preset_section(main_frame, row=2)

        # Password strength indicator (must be created before password section)
        self._create_strength_indicator(main_frame, row=3)

        # Password section
        self._create_password_section(main_frame, row=4)

        # Metadata section
        self._create_metadata_section(main_frame, row=5)

        # File size indicator
        self._create_size_indicator(main_frame, row=6)

        # Button bar
        self._create_button_bar(main_frame, row=7)

    def _create_file_section(self, parent: ttk.Frame, row: int) -> None:
        """Создаёт секцию выбора файла.

        Args:
            parent: Родительский фрейм.
            row: Номер строки для размещения.
        """
        file_frame = ttk.LabelFrame(parent, text="File Location", padding="10")
        file_frame.grid(row=row, column=0, sticky="ew", pady=(0, 10))
        file_frame.columnconfigure(0, weight=1)

        # Filename entry
        ttk.Label(file_frame, text="Filename:").grid(row=0, column=0, sticky="w", padx=(0, 5))

        self._filename_var: tk.StringVar = tk.StringVar(master=self)
        self._filename_entry: ttk.Entry = ttk.Entry(
            file_frame,
            textvariable=self._filename_var,
            width=50,
        )
        self._filename_entry.grid(row=1, column=0, sticky="ew", pady=(2, 5))

        # Browse button
        self._browse_button: ttk.Button = ttk.Button(
            file_frame,
            text="📁 Browse...",
            command=self._on_browse,
        )
        self._browse_button.grid(row=1, column=1, padx=(5, 0), pady=(2, 5))

        # Path label
        self._path_var: tk.StringVar = tk.StringVar(master=self, value="No path selected")
        self._path_label: ttk.Label = ttk.Label(
            file_frame,
            textvariable=self._path_var,
            foreground="gray",
            font=("Helvetica", 9),
        )
        self._path_label.grid(row=2, column=0, columnspan=2, sticky="w")

    def _create_encryption_section(self, parent: ttk.Frame, row: int) -> None:
        """Создаёт секцию шифрования.

        Args:
            parent: Родительский фрейм.
            row: Номер строки для размещения.
        """
        enc_frame = ttk.LabelFrame(parent, text="Security", padding="10")
        enc_frame.grid(row=row, column=0, sticky="ew", pady=(0, 10))
        enc_frame.columnconfigure(0, weight=1)

        # Encryption checkbox
        self._encrypt_var: tk.BooleanVar = tk.BooleanVar(master=self, value=False)
        self._encrypt_check: ttk.Checkbutton = ttk.Checkbutton(
            enc_frame,
            text="🔒 Encrypt document",
            variable=self._encrypt_var,
            command=self._on_encrypt_toggle,
        )
        self._encrypt_check.grid(row=0, column=0, sticky="w")

        # Encryption info label
        self._encrypt_info: ttk.Label = ttk.Label(
            enc_frame,
            text="Document will be protected with a password using AES-256-GCM",
            foreground="gray",
            font=("Helvetica", 8),
            wraplength=500,
        )
        self._encrypt_info.grid(row=1, column=0, sticky="w", padx=(20, 0), pady=(2, 0))

    def _create_preset_section(self, parent: ttk.Frame, row: int) -> None:
        """Создаёт секцию выбора пресета безопасности.

        Args:
            parent: Родительский фрейм.
            row: Номер строки для размещения.
        """
        preset_frame = ttk.LabelFrame(parent, text="Security Preset", padding="10")
        preset_frame.grid(row=row, column=0, sticky="ew", pady=(0, 10))
        preset_frame.columnconfigure(0, weight=1)

        self._preset_var: tk.StringVar = tk.StringVar(
            master=self, value=SecurityPreset.STANDARD.value
        )
        self._preset_combo: ttk.Combobox = ttk.Combobox(
            preset_frame,
            textvariable=self._preset_var,
            values=[p.value for p in SecurityPreset],
            state="readonly",
            width=40,
        )
        self._preset_combo.grid(row=0, column=0, sticky="ew")
        self._preset_combo.bind("<<ComboboxSelected>>", self._on_preset_change)

        # Preset description
        self._preset_desc_var: tk.StringVar = tk.StringVar(
            value=PRESET_LABELS[SecurityPreset.STANDARD]
        )
        self._preset_desc: ttk.Label = ttk.Label(
            preset_frame,
            textvariable=self._preset_desc_var,
            foreground="gray",
            font=("Helvetica", 8),
            wraplength=500,
        )
        self._preset_desc.grid(row=1, column=0, sticky="w", pady=(5, 0))

    def _create_password_section(self, parent: ttk.Frame, row: int) -> None:
        """Создаёт секцию ввода пароля.

        Args:
            parent: Родительский фрейм.
            row: Номер строки для размещения.
        """
        self._password_frame: ttk.LabelFrame = ttk.LabelFrame(
            parent, text="Encryption Password", padding="10"
        )
        self._password_frame.grid(row=row, column=0, sticky="ew", pady=(0, 10))
        self._password_frame.columnconfigure(0, weight=1)

        # Password entry with show/hide toggle
        pwd_row = ttk.Frame(self._password_frame)
        pwd_row.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        pwd_row.columnconfigure(0, weight=1)

        ttk.Label(pwd_row, text="Password:").grid(row=0, column=0, sticky="w")

        self._password_var: tk.StringVar = tk.StringVar(master=self)
        self._password_entry: ttk.Entry = ttk.Entry(
            pwd_row,
            textvariable=self._password_var,
            show="*",
            width=40,
        )
        self._password_entry.grid(row=1, column=0, sticky="ew", pady=(2, 0))
        self._password_entry.bind("<KeyRelease>", self._on_password_change)

        # Show/hide button
        self._show_password_var: tk.BooleanVar = tk.BooleanVar(master=self, value=False)
        self._show_check: ttk.Checkbutton = ttk.Checkbutton(
            pwd_row,
            text="👁",
            variable=self._show_password_var,
            command=self._toggle_password_visibility,
            width=3,
        )
        self._show_check.grid(row=1, column=1, padx=(5, 0))

        # Confirm password entry
        confirm_row = ttk.Frame(self._password_frame)
        confirm_row.grid(row=1, column=0, sticky="ew")
        confirm_row.columnconfigure(0, weight=1)

        ttk.Label(confirm_row, text="Confirm password:").grid(row=0, column=0, sticky="w")

        self._confirm_var: tk.StringVar = tk.StringVar(master=self)
        self._confirm_entry: ttk.Entry = ttk.Entry(
            confirm_row,
            textvariable=self._confirm_var,
            show="*",
            width=40,
        )
        self._confirm_entry.grid(row=1, column=0, sticky="ew", pady=(2, 0))

        # Initially disable password section
        self._set_password_section_enabled(False)

    def _create_strength_indicator(self, parent: ttk.Frame, row: int) -> None:
        """Создаёт индикатор сложности пароля.

        Args:
            parent: Родительский фрейм.
            row: Номер строки для размещения.
        """
        strength_frame = ttk.Frame(parent)
        strength_frame.grid(row=row, column=0, sticky="ew", pady=(0, 10))
        strength_frame.columnconfigure(0, weight=1)

        # Progress bar for strength
        self._strength_var: tk.DoubleVar = tk.DoubleVar(master=self, value=0)
        self._strength_bar: ttk.Progressbar = ttk.Progressbar(
            strength_frame,
            variable=self._strength_var,
            maximum=100,
            mode="determinate",
            length=200,
        )
        self._strength_bar.grid(row=0, column=0, sticky="ew", pady=(0, 2))

        # Strength label
        self._strength_text_var: tk.StringVar = tk.StringVar(master=self, value="Enter password")
        self._strength_label: ttk.Label = ttk.Label(
            strength_frame,
            textvariable=self._strength_text_var,
            font=("Helvetica", 9),
            foreground="gray",
        )
        self._strength_label.grid(row=1, column=0, sticky="w")

        # Feedback label
        self._strength_feedback_var: tk.StringVar = tk.StringVar(master=self)
        self._strength_feedback: ttk.Label = ttk.Label(
            strength_frame,
            textvariable=self._strength_feedback_var,
            font=("Helvetica", 8),
            foreground="gray",
            wraplength=500,
        )
        self._strength_feedback.grid(row=2, column=0, sticky="w")

    def _create_metadata_section(self, parent: ttk.Frame, row: int) -> None:
        """Создаёт секцию метаданных документа.

        Args:
            parent: Родительский фрейм.
            row: Номер строки для размещения.
        """
        meta_frame = ttk.LabelFrame(parent, text="Document Metadata", padding="10")
        meta_frame.grid(row=row, column=0, sticky="ew", pady=(0, 10))
        meta_frame.columnconfigure(1, weight=1)

        # Title
        ttk.Label(meta_frame, text="Title:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self._title_var: tk.StringVar = tk.StringVar(master=self)
        self._title_entry: ttk.Entry = ttk.Entry(
            meta_frame,
            textvariable=self._title_var,
            width=50,
        )
        self._title_entry.grid(row=0, column=1, sticky="ew", pady=(0, 5))

        # Author
        ttk.Label(meta_frame, text="Author:").grid(row=1, column=0, sticky="w", padx=(0, 5))
        self._author_var: tk.StringVar = tk.StringVar(master=self)
        self._author_entry: ttk.Entry = ttk.Entry(
            meta_frame,
            textvariable=self._author_var,
            width=50,
        )
        self._author_entry.grid(row=1, column=1, sticky="ew", pady=(0, 5))

        # Description
        ttk.Label(meta_frame, text="Description:").grid(row=2, column=0, sticky="nw", padx=(0, 5))
        self._desc_text: tk.Text = tk.Text(
            meta_frame,
            height=3,
            width=50,
            wrap=tk.WORD,
            font=("Helvetica", 10),
        )
        self._desc_text.grid(row=2, column=1, sticky="ew", pady=(0, 5))

    def _create_size_indicator(self, parent: ttk.Frame, row: int) -> None:
        """Создаёт индикатор размера файла.

        Args:
            parent: Родительский фрейм.
            row: Номер строки для размещения.
        """
        size_frame = ttk.Frame(parent)
        size_frame.grid(row=row, column=0, sticky="ew", pady=(0, 10))

        ttk.Label(size_frame, text="Estimated size:").pack(side=tk.LEFT)

        self._size_var: tk.StringVar = tk.StringVar(master=self, value="~ 0 KB")
        self._size_label: ttk.Label = ttk.Label(
            size_frame,
            textvariable=self._size_var,
            foreground="gray",
        )
        self._size_label.pack(side=tk.LEFT, padx=(5, 0))

    def _create_button_bar(self, parent: ttk.Frame, row: int) -> None:
        """Создаёт панель кнопок.

        Args:
            parent: Родительский фрейм.
            row: Номер строки для размещения.
        """
        button_frame = ttk.Frame(parent)
        button_frame.grid(row=row, column=0, sticky="ew", pady=(10, 0))
        button_frame.columnconfigure(0, weight=1)

        # Left side (empty for alignment)
        left_frame = ttk.Frame(button_frame)
        left_frame.grid(row=0, column=0, sticky="w")

        # Right side buttons
        right_frame = ttk.Frame(button_frame)
        right_frame.grid(row=0, column=1, sticky="e")

        # Save button
        self._save_button: ttk.Button = ttk.Button(
            right_frame,
            text="💾 Save",
            command=self._on_save,
        )
        self._save_button.pack(side=tk.LEFT, padx=(0, 5))

        # Cancel button
        self._cancel_button: ttk.Button = ttk.Button(
            right_frame,
            text="❌ Cancel",
            command=self._on_cancel,
        )
        self._cancel_button.pack(side=tk.LEFT)

    def _initialize_values(self) -> None:
        """Инициализирует поля значениями из документа."""
        # Set metadata from document
        self._title_var.set(self._document.metadata.title)
        self._author_var.set(self._document.metadata.author)
        self._desc_text.insert("1.0", self._document.metadata.subject)

        # Set default filename
        default_name = self._document.metadata.title or "document"
        if not default_name.endswith(".fxsd"):
            default_name += ".fxsd"
        self._filename_var.set(default_name)

        # Set default path
        if self._default_path:
            self._update_path_display(self._default_path)
        elif self._document.file_path:
            self._update_path_display(self._document.file_path.parent)
        else:
            self._update_path_display(Path.home() / "Documents")

        # Update size estimate
        self._update_size_estimate()

    def _update_path_display(self, path: Path) -> None:
        """Обновляет отображение пути.

        Args:
            path: Путь для отображения.
        """
        self._current_path: Path = path
        display_path = str(path)
        if len(display_path) > 50:
            display_path = "..." + display_path[-47:]
        self._path_var.set(display_path)

    def _update_size_estimate(self) -> None:
        """Обновляет оценку размера файла."""
        # Estimate based on document content
        content_size = len(self._document.get_text_content().encode("utf-8"))
        metadata_size = 500  # Approximate metadata overhead
        total_size = content_size + metadata_size

        if self._encrypt_var.get():
            # Add encryption overhead (~16 bytes for nonce + tag)
            total_size += 64

        # Format size
        if total_size < 1024:
            size_str = f"~ {total_size} bytes"
        elif total_size < 1024 * 1024:
            size_str = f"~ {total_size / 1024:.1f} KB"
        else:
            size_str = f"~ {total_size / (1024 * 1024):.1f} MB"

        self._size_var.set(size_str)

    def _set_password_section_enabled(self, enabled: bool) -> None:
        """Включает или отключает секцию пароля.

        Args:
            enabled: True для включения, False для отключения.
        """
        state = tk.NORMAL if enabled else tk.DISABLED
        for child in self._password_frame.winfo_children():
            for widget in child.winfo_children():
                cast(TypingAny, widget).configure(state=state)

        # Also disable/enable strength indicator
        if not enabled:
            self._strength_var.set(0)
            self._strength_text_var.set("Encryption disabled")
            self._strength_label.configure(foreground="gray")
            self._strength_feedback_var.set("")

    def _on_encrypt_toggle(self) -> None:
        """Обработчик переключения шифрования."""
        enabled = self._encrypt_var.get()
        self._set_password_section_enabled(enabled)
        self._update_size_estimate()

        if enabled:
            self._password_entry.focus()

    def _on_preset_change(self, event: Optional[tk.Event] = None) -> None:
        """Обработчик изменения пресета безопасности.

        Args:
            event: Событие изменения (опционально).
        """
        preset_value = self._preset_var.get()
        try:
            preset = SecurityPreset(preset_value)
            self._preset_desc_var.set(PRESET_LABELS.get(preset, preset_value))
        except ValueError:
            self._preset_desc_var.set("Unknown preset")

    def _on_password_change(self, event: Optional[tk.Event] = None) -> None:
        """Обработчик изменения пароля.

        Args:
            event: Событие изменения (опционально).
        """
        password = self._password_var.get()

        if not password:
            self._strength_var.set(0)
            self._strength_text_var.set("Enter password")
            self._strength_label.configure(foreground="gray")
            self._strength_feedback_var.set("")
            return

        # Check password strength
        result: PasswordStrengthResult = self._password_hasher.check_password_strength(password)

        self._strength_var.set(result.score)
        self._strength_text_var.set(f"Strength: {STRENGTH_LABELS[result.strength]}")
        self._strength_label.configure(foreground=STRENGTH_COLORS[result.strength])

        # Show feedback
        if result.feedback:
            self._strength_feedback_var.set(" • ".join(result.feedback[:2]))
        else:
            self._strength_feedback_var.set("")

    def _toggle_password_visibility(self) -> None:
        """Переключает видимость пароля."""
        show = self._show_password_var.get()
        self._password_entry.configure(show="" if show else "*")
        self._confirm_entry.configure(show="" if show else "*")

    def _on_browse(self) -> None:
        """Обработчик кнопки обзора."""
        filename = filedialog.asksaveasfilename(
            parent=self,
            title="Save Document",
            defaultextension=".fxsd",
            initialfile=self._filename_var.get(),
            filetypes=[
                ("FX Text Document", "*.fxsd"),
                ("Encrypted Document", "*.fxsd.enc"),
                ("All Files", "*.*"),
            ],
        )

        if filename:
            path = Path(filename)
            self._filename_var.set(path.name)
            self._update_path_display(path.parent)

            # Auto-enable encryption if .enc extension
            if path.suffix == ".enc" or str(path).endswith(".fxsd.enc"):
                self._encrypt_var.set(True)
                self._on_encrypt_toggle()

    def _validate(self) -> tuple[bool, str]:
        """Валидирует введённые данные.

        Returns:
            Кортеж (is_valid, error_message).
        """
        # Check filename
        filename = self._filename_var.get().strip()
        if not filename:
            return False, "Enter filename"

        # Check for invalid characters
        invalid_chars = '<>:"|?*'
        for char in invalid_chars:
            if char in filename:
                return False, f"Filename contains invalid character: {char}"

        # Check encryption requirements
        if self._encrypt_var.get():
            password = self._password_var.get()
            confirm = self._confirm_var.get()

            if not password:
                return False, "Enter encryption password"

            if len(password) < 8:
                return False, "Password must be at least 8 characters"

            if password != confirm:
                return False, "Passwords do not match"

            # Check password strength (at least FAIR)
            strength_result = self._password_hasher.check_password_strength(password)
            if strength_result.strength == PasswordStrength.WEAK:
                return False, "Password is too weak. " + " ".join(strength_result.feedback[:2])

        return True, ""

    def _on_save(self) -> None:
        """Обработчик кнопки сохранения."""
        is_valid, error = self._validate()
        if not is_valid:
            messagebox.showerror(
                "Validation Error",
                error,
                parent=self,
            )
            return

        # Build the full path
        filename = self._filename_var.get().strip()
        path = self._current_path / filename

        # Add .enc extension if encryption is enabled
        if self._encrypt_var.get() and not str(path).endswith(".enc"):
            path = Path(str(path) + ".enc")

        # Check if file exists
        if path.exists():
            result = messagebox.askyesno(
                "File Exists",
                f"File '{path.name}' already exists. Overwrite?",
                parent=self,
            )
            if not result:
                return

        # Get preset
        preset_value = self._preset_var.get()
        preset = SecurityPreset(preset_value)

        # Build metadata
        metadata = DocumentMetadata(
            title=self._title_var.get(),
            author=self._author_var.get(),
            subject=self._desc_text.get("1.0", tk.END).strip(),
        )

        # Create result
        self._result = SaveResult(
            path=path,
            encrypted=self._encrypt_var.get(),
            preset=preset,
            metadata=metadata,
            password=self._password_var.get() if self._encrypt_var.get() else "",
        )

        self.destroy()

    def _on_cancel(self) -> None:
        """Обработчик кнопки отмены."""
        self._result = None
        self.destroy()

    def show(self) -> Optional[SaveResult]:
        """Показывает диалог и возвращает результат.

        Returns:
            SaveResult если пользователь подтвердил сохранение,
            None если диалог был отменён.
        """
        self.wait_window()
        return self._result


class SaveFileDialog:
    """Статический диалог сохранения для простых случаев.

    Предоставляет упрощённый интерфейс для сохранения файлов
    без шифрования и расширенных опций.

    Example:
        >>> path = SaveFileDialog.show(default_name="report.fxsd")
        >>> if path:
        ...     print(f"Saving to: {path}")
    """

    @staticmethod
    def show(
        parent: Optional[tk.Widget] = None,
        default_name: str = "document.fxsd",
    ) -> Optional[Path]:
        """Показывает простой диалог сохранения.

        Args:
            parent: Родительский виджет.
            default_name: Имя файла по умолчанию.

        Returns:
            Путь к файлу или None если отменено.
        """
        filename = filedialog.asksaveasfilename(
            title="Save Document",
            defaultextension=".fxsd",
            initialfile=default_name,
            filetypes=[
                ("FX Text Document", "*.fxsd"),
                ("Encrypted Document", "*.fxsd.enc"),
                ("All Files", "*.*"),
            ],
        )
        return Path(filename) if filename else None


__all__: list[str] = [
    "SaveDialog",
    "SaveFileDialog",
    "SaveResult",
]
