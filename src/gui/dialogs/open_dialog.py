"""Диалог открытия документа с проверкой подписи и предпросмотром метаданных.

Предоставляет комплексный UI для открытия документов FX Text Processor 3
с поддержкой:
- Фильтрации файлов по расширениям (.fxsd, .fxsd.enc, .fxstpl)
- Предпросмотра метаданных (заголовок, автор, дата создания)
- Проверки цифровой подписи через цепочку доверия
- Отображения статуса подписи (валидна/невалидна/отсутствует)
- Информации о цепочке доверия

Example:
    >>> from src.gui.dialogs.open_dialog import OpenDialog, OpenResult
    >>> from src.services.trust_chain_service import TrustChainService
    >>>
    >>> trust_service = TrustChainService(
    ...     keystore_path=Path.home() / ".fxtextprocessor" / "keystore",
    ...     audit_secret_key=b"secret_key_32_bytes",
    ... )
    >>>
    >>> dialog = OpenDialog(
    ...     parent=root,
    ...     document_service=document_service,
    ...     trust_chain_verifier=trust_service,
    ... )
    >>> result = dialog.show()
    >>> if result:
    ...     print(f"Открыт файл: {result.path}")
    ...     print(f"Подпись валидна: {result.signature_valid}")

Version: 2.0
Date: April 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Final, Optional

from src.gui.dialogs.base_dialog import BaseDialog
from src.model.document import DocumentMetadata
from src.security.crypto.core.exceptions import AuthError, CryptoError
from src.services.protocols.template_security import (
    TrustChainServiceProtocol,
    TrustStatus,
    TrustVerificationResult,
)
from src.services.template_manager import FormTemplate

# UI Constants
DIALOG_WIDTH: Final[int] = 700
DIALOG_HEIGHT: Final[int] = 550
MIN_DIALOG_WIDTH: Final[int] = 550
MIN_DIALOG_HEIGHT: Final[int] = 450

# Colors
COLOR_BG: Final[str] = "#f8f9fa"
COLOR_HEADER: Final[str] = "#e9ecef"
COLOR_BORDER: Final[str] = "#dee2e6"
COLOR_TEXT: Final[str] = "#212529"
COLOR_SUCCESS: Final[str] = "#28a745"  # Green
COLOR_WARNING: Final[str] = "#ffc107"  # Orange
COLOR_ERROR: Final[str] = "#dc3545"  # Red
COLOR_GRAY: Final[str] = "#6c757d"  # Gray

# Signature status display
SIGNATURE_STATUS: Final[dict[Optional[bool], tuple[str, str, str]]] = {
    True: ("✓", "Signature valid", COLOR_SUCCESS),
    False: ("⚠️", "Signature invalid", COLOR_WARNING),
    None: ("❌", "No signature", COLOR_GRAY),
}

# File type icons
FILE_TYPE_ICONS: Final[dict[str, str]] = {
    ".fxsd": "📄",
    ".fxsd.enc": "🔒",
    ".fxstpl": "📋",
}

# File filter patterns
FILE_FILTERS: Final[list[tuple[str, str]]] = [
    ("FX Text Documents", "*.fxsd *.fxsd.enc"),
    ("Templates", "*.fxstpl"),
    ("All Files", "*.*"),
]

# Logger
logger: Final[logging.Logger] = logging.getLogger(__name__)


@dataclass(frozen=True)
class OpenResult:
    """Результат диалога открытия документа.

    Attributes:
        path: Путь к выбранному файлу.
        verify_signature: True если проверка подписи включена.
        metadata: Метаданные документа (если доступны).
        signature_valid: Статус подписи: True (валидна), False (невалидна),
                        None (отсутствует).

    Example:
        >>> result = OpenResult(
        ...     path=Path("/docs/invoice.fxsd.enc"),
        ...     verify_signature=True,
        ...     metadata=DocumentMetadata(title="Invoice"),
        ...     signature_valid=True,
        ... )
    """

    path: Path
    verify_signature: bool
    metadata: Optional[DocumentMetadata]
    signature_valid: Optional[bool]


class OpenDialog(BaseDialog):
    """Диалог открытия документа с проверкой подписи и предпросмотром.

    Предоставляет полный UI для открытия документов:
    - Фильтрация файлов по типу
    - Предпросмотр метаданных (заголовок, автор, дата)
    - Индикатор шифрования
    - Проверка цифровой подписи через цепочку доверия
    - Отображение статуса подписи с цветовой индикацией
    - Краткая информация о цепочке доверия

    Attributes:
        _document_service: Сервис для работы с документами.
        _trust_chain_verifier: Сервис для верификации цепочки доверия.
        _selected_path: Выбранный путь к файлу.
        _verification_result: Результат верификации подписи.
        _result: Результат диалога (None если отменено).

    Example:
        >>> dialog = OpenDialog(parent, document_service, trust_service)
        >>> result = dialog.show()
        >>> if result and result.signature_valid:
        ...     print("Файл открыт и подпись подтверждена")
    """

    def __init__(
        self,
        parent: tk.Widget,
        document_service: Any,
        trust_chain_verifier: Optional[TrustChainServiceProtocol] = None,
        *,
        title: str = "Open Document",
        initial_dir: Optional[Path] = None,
    ) -> None:
        """Инициализация диалога открытия документа.

        Args:
            parent: Родительский виджет.
            document_service: Сервис для работы с документами.
            trust_chain_verifier: Сервис для верификации цепочки доверия
                                  (опционально).
            title: Заголовок окна диалога.
            initial_dir: Начальная директория для браузера файлов.
        """
        super().__init__(parent)

        self._parent: tk.Widget = parent
        self._document_service: Any = document_service
        self._trust_chain_verifier: Optional[TrustChainServiceProtocol] = trust_chain_verifier
        self._selected_path: Optional[Path] = None
        self._verification_result: Optional[TrustVerificationResult] = None
        self._result: Optional[OpenResult] = None
        self._initial_dir: Path = initial_dir or Path.home() / "Documents"

        self._create_ui()
        self._setup_window(title)

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
        main_frame.rowconfigure(1, weight=1)  # Preview panel row

        # File browser section
        self._create_file_section(main_frame, row=0)

        # Preview panel
        self._create_preview_panel(main_frame, row=1)

        # Signature section
        self._create_signature_section(main_frame, row=2)

        # Trust chain info
        self._create_trust_chain_section(main_frame, row=3)

        # Button bar
        self._create_button_bar(main_frame, row=4)

    def _create_file_section(self, parent: ttk.Frame, row: int) -> None:
        """Создаёт секцию выбора файла.

        Args:
            parent: Родительский фрейм.
            row: Номер строки для размещения.
        """
        file_frame = ttk.LabelFrame(parent, text="File Selection", padding="10")
        file_frame.grid(row=row, column=0, sticky="ew", pady=(0, 10))
        file_frame.columnconfigure(0, weight=1)

        # Path entry
        path_row = ttk.Frame(file_frame)
        path_row.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        path_row.columnconfigure(0, weight=1)

        self._path_var: tk.StringVar = tk.StringVar(master=self)
        self._path_entry: ttk.Entry = ttk.Entry(
            path_row,
            textvariable=self._path_var,
            width=50,
            state="readonly",
        )
        self._path_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))

        # Browse button
        self._browse_button: ttk.Button = ttk.Button(
            path_row,
            text="📁 Browse...",
            command=self._on_browse,
        )
        self._browse_button.grid(row=0, column=1)

        # Filter info
        self._filter_label: ttk.Label = ttk.Label(
            file_frame,
            text="Supported formats: .fxsd, .fxsd.enc, .fxstpl",
            foreground="gray",
            font=("Helvetica", 8),
        )
        self._filter_label.grid(row=1, column=0, sticky="w")

    def _create_preview_panel(self, parent: ttk.Frame, row: int) -> None:
        """Создаёт панель предпросмотра метаданных.

        Args:
            parent: Родительский фрейм.
            row: Номер строки для размещения.
        """
        preview_frame = ttk.LabelFrame(parent, text="Preview", padding="10")
        preview_frame.grid(row=row, column=0, sticky="nsew", pady=(0, 10))
        preview_frame.columnconfigure(1, weight=1)

        # Document icon
        self._icon_label: ttk.Label = ttk.Label(
            preview_frame,
            text="📄",
            font=("Helvetica", 32),
        )
        self._icon_label.grid(row=0, column=0, rowspan=4, padx=(0, 15))

        # Title
        ttk.Label(preview_frame, text="Title:", font=("Helvetica", 9, "bold")).grid(
            row=0, column=1, sticky="w"
        )
        self._title_var: tk.StringVar = tk.StringVar(master=self, value="—")
        self._title_label: ttk.Label = ttk.Label(
            preview_frame,
            textvariable=self._title_var,
            font=("Helvetica", 10),
        )
        self._title_label.grid(row=0, column=2, sticky="w", padx=(5, 0))

        # Author
        ttk.Label(preview_frame, text="Author:", font=("Helvetica", 9, "bold")).grid(
            row=1, column=1, sticky="w"
        )
        self._author_var: tk.StringVar = tk.StringVar(master=self, value="—")
        self._author_label: ttk.Label = ttk.Label(
            preview_frame,
            textvariable=self._author_var,
            font=("Helvetica", 10),
        )
        self._author_label.grid(row=1, column=2, sticky="w", padx=(5, 0))

        # Created date
        ttk.Label(preview_frame, text="Created:", font=("Helvetica", 9, "bold")).grid(
            row=2, column=1, sticky="w"
        )
        self._created_var: tk.StringVar = tk.StringVar(master=self, value="—")
        self._created_label: ttk.Label = ttk.Label(
            preview_frame,
            textvariable=self._created_var,
            font=("Helvetica", 10),
        )
        self._created_label.grid(row=2, column=2, sticky="w", padx=(5, 0))

        # Encrypted indicator
        self._encrypted_var: tk.StringVar = tk.StringVar(master=self, value="")
        self._encrypted_label: ttk.Label = ttk.Label(
            preview_frame,
            textvariable=self._encrypted_var,
            font=("Helvetica", 9),
            foreground=COLOR_WARNING,
        )
        self._encrypted_label.grid(row=3, column=1, columnspan=2, sticky="w", pady=(5, 0))

    def _create_signature_section(self, parent: ttk.Frame, row: int) -> None:
        """Создаёт секцию проверки подписи.

        Args:
            parent: Родительский фрейм.
            row: Номер строки для размещения.
        """
        sig_frame = ttk.LabelFrame(parent, text="Signature Verification", padding="10")
        sig_frame.grid(row=row, column=0, sticky="ew", pady=(0, 10))
        sig_frame.columnconfigure(0, weight=1)

        # Checkbox for signature verification
        self._verify_var: tk.BooleanVar = tk.BooleanVar(master=self, value=True)
        self._verify_check: ttk.Checkbutton = ttk.Checkbutton(
            sig_frame,
            text="✓ Verify signature on open",
            variable=self._verify_var,
            command=self._on_verify_toggle,
        )
        self._verify_check.grid(row=0, column=0, sticky="w")

        # Signature status indicator
        status_row = ttk.Frame(sig_frame)
        status_row.grid(row=1, column=0, sticky="ew", pady=(5, 0))
        status_row.columnconfigure(1, weight=1)

        ttk.Label(status_row, text="Status:", font=("Helvetica", 9, "bold")).grid(
            row=0, column=0, sticky="w"
        )

        self._status_icon_var: tk.StringVar = tk.StringVar(master=self, value="❌")
        self._status_icon_label: ttk.Label = ttk.Label(
            status_row,
            textvariable=self._status_icon_var,
            font=("Helvetica", 12),
        )
        self._status_icon_label.grid(row=0, column=1, sticky="w", padx=(5, 0))

        self._status_text_var: tk.StringVar = tk.StringVar(master=self, value="No signature")
        self._status_text_label: ttk.Label = ttk.Label(
            status_row,
            textvariable=self._status_text_var,
            font=("Helvetica", 10),
            foreground=COLOR_GRAY,
        )
        self._status_text_label.grid(row=0, column=2, sticky="w", padx=(5, 0))

    def _create_trust_chain_section(self, parent: ttk.Frame, row: int) -> None:
        """Создаёт секцию информации о цепочке доверия.

        Args:
            parent: Родительский фрейм.
            row: Номер строки для размещения.
        """
        chain_frame = ttk.LabelFrame(parent, text="Trust Chain", padding="10")
        chain_frame.grid(row=row, column=0, sticky="ew", pady=(0, 10))
        chain_frame.columnconfigure(0, weight=1)

        self._chain_var: tk.StringVar = tk.StringVar(master=self, value="Trust chain unavailable")
        self._chain_label: ttk.Label = ttk.Label(
            chain_frame,
            textvariable=self._chain_var,
            font=("Helvetica", 9),
            foreground="gray",
            wraplength=600,
        )
        self._chain_label.grid(row=0, column=0, sticky="w")

    def _create_button_bar(self, parent: ttk.Frame, row: int) -> None:
        """Создаёт панель кнопок.

        Args:
            parent: Родительский фрейм.
            row: Номер строки для размещения.
        """
        button_frame = ttk.Frame(parent)
        button_frame.grid(row=row, column=0, sticky="ew", pady=(10, 0))
        button_frame.columnconfigure(0, weight=1)

        # Left side - empty for alignment
        left_frame = ttk.Frame(button_frame)
        left_frame.grid(row=0, column=0, sticky="w")

        # Right side - action buttons
        right_frame = ttk.Frame(button_frame)
        right_frame.grid(row=0, column=1, sticky="e")

        # Open button
        self._open_button: ttk.Button = ttk.Button(
            right_frame,
            text="📂 Open",
            command=self._on_open,
            state=tk.DISABLED,
        )
        self._open_button.pack(side=tk.LEFT, padx=(0, 5))

        # Cancel button
        self._cancel_button: ttk.Button = ttk.Button(
            right_frame,
            text="❌ Cancel",
            command=self._on_cancel,
        )
        self._cancel_button.pack(side=tk.LEFT)

    def _on_browse(self) -> None:
        """Обрабатывает нажатие кнопки обзора."""
        filetypes = [
            ("FX Text Documents", "*.fxsd *.fxsd.enc"),
            ("Templates", "*.fxstpl"),
            ("All Files", "*.*"),
        ]

        filename = filedialog.askopenfilename(
            parent=self,
            title="Select a file to open",
            initialdir=str(self._initial_dir),
            filetypes=filetypes,
        )

        if filename:
            self._select_file(Path(filename))

    def _select_file(self, path: Path) -> None:
        """Выбирает файл и обновляет UI.

        Args:
            path: Путь к выбранному файлу.
        """
        self._selected_path = path
        self._path_var.set(str(path))

        # Enable open button
        self._open_button.configure(state=tk.NORMAL)

        # Update preview
        self._update_preview(path)

        # Verify signature if enabled and verifier available
        if self._verify_var.get() and self._trust_chain_verifier is not None:
            self._verify_signature(path)

    def _update_preview(self, path: Path) -> None:
        """Обновляет панель предпросмотра.

        Args:
            path: Путь к файлу.
        """
        # Set icon based on file type
        icon = "📄"
        if path.suffix == ".enc" or str(path).endswith(".fxsd.enc"):
            icon = "🔒"
            self._encrypted_var.set("🔒 Document is encrypted")
        elif path.suffix == ".fxstpl":
            icon = "📋"
            self._encrypted_var.set("")
        else:
            self._encrypted_var.set("")

        self._icon_label.configure(text=icon)

        # Try to load metadata
        metadata = self._load_metadata(path)
        if metadata:
            self._title_var.set(metadata.title or "—")
            self._author_var.set(metadata.author or "—")
            if metadata.created:
                created_str = metadata.created.strftime("%Y-%m-%d %H:%M")
                self._created_var.set(created_str)
            else:
                self._created_var.set("—")
        else:
            # Reset to defaults
            self._title_var.set("—")
            self._author_var.set("—")
            self._created_var.set("—")

    def _load_metadata(self, path: Path) -> Optional[DocumentMetadata]:
        """Загружает метаданные из файла.

        Args:
            path: Путь к файлу.

        Returns:
            Метаданные документа или None если недоступны.
        """
        try:
            # Try to load as template first
            if path.suffix == ".fxstpl":
                template = FormTemplate.load(path)
                return DocumentMetadata(
                    title=template.name or template.template_id,
                    author=template.author or "",
                    created=datetime.fromisoformat(template.created_at)
                    if template.created_at
                    else datetime.now(),
                )

            # Try document service
            if hasattr(self._document_service, "load_metadata"):
                try:
                    service_result: Any = self._document_service.load_metadata(path)
                    if service_result is not None:
                        if isinstance(service_result, DocumentMetadata):
                            return service_result
                        elif hasattr(service_result, "title"):
                            # Convert from object with attributes
                            return DocumentMetadata(
                                title=getattr(service_result, "title", "") or "",
                                author=getattr(service_result, "author", "") or "",
                                created=getattr(service_result, "created", datetime.now()),
                                subject=getattr(service_result, "subject", "") or "",
                            )
                except (AttributeError, ValueError, RuntimeError, ImportError) as exc:
                    logger.debug("Primary metadata extraction failed: %s", exc)
                    # Continue to fallback methods

            # Try loading via DocumentFormat (FormInstance metadata)
            try:
                from src.documents.format.document_format import DocumentFormat

                fmt = DocumentFormat()
                doc = fmt.load(path)
                # FormInstance has metadata dict, convert to DocumentMetadata
                doc_metadata: dict[str, Any] = getattr(doc, "metadata", {}) or {}
                created_str: str | None = doc_metadata.get("created")
                return DocumentMetadata(
                    title=str(doc_metadata.get("title", path.stem)),
                    author=str(doc_metadata.get("author", "")),
                    created=datetime.fromisoformat(created_str)
                    if isinstance(created_str, str) and created_str
                    else datetime.fromtimestamp(path.stat().st_ctime),
                    subject=str(doc_metadata.get("subject", "")),
                )
            except (FileNotFoundError, OSError, ValueError) as exc:
                logger.debug("DocumentFormat metadata extraction failed: %s", exc)
                # Continue to fallback methods
        except (FileNotFoundError, OSError) as e:
            logger.error("File system error during metadata extraction: %s", e)
            return None
        except (AttributeError, ValueError, TypeError, RuntimeError) as e:
            logger.exception("Unexpected error during metadata extraction: %s", e)
            return None

        # Fallback: get basic file info
        stat = path.stat()
        return DocumentMetadata(
            title=path.stem,
            created=datetime.fromtimestamp(stat.st_ctime),
        )

    def _verify_signature(self, path: Path) -> None:
        """Верифицирует подпись файла.

        Args:
            path: Путь к файлу.
        """
        if self._trust_chain_verifier is None:
            self._update_signature_status(None)
            return

        try:
            # For templates, use FormTemplate
            if path.suffix == ".fxstpl":
                template = FormTemplate.load(path)
                result = self._trust_chain_verifier.verify_template(template)
                self._verification_result = result
                self._update_signature_status(
                    result.is_valid if result.trust_status != TrustStatus.UNTRUSTED else False
                )
                self._update_trust_chain_info(result)
            else:
                # For documents, check if there's a way to verify
                # Currently documents don't have signatures in the same way
                self._update_signature_status(None)
                self._update_trust_chain_info(None)

        except (OSError, FileNotFoundError, ValueError) as e:
            # Verification failed
            logger.warning("Signature verification error: %s", e)
            self._update_signature_status(False)
            self._chain_var.set(f"Verification error: {str(e)[:50]}")

    def _update_signature_status(self, is_valid: Optional[bool]) -> None:
        """Обновляет индикатор статуса подписи.

        Args:
            is_valid: True (валидна), False (невалидна), None (отсутствует).
        """
        icon, text, color = SIGNATURE_STATUS.get(is_valid, SIGNATURE_STATUS[None])

        self._status_icon_var.set(icon)
        self._status_text_var.set(text)
        self._status_text_label.configure(foreground=color)

    def _update_trust_chain_info(self, result: Optional[TrustVerificationResult]) -> None:
        """Обновляет информацию о цепочке доверия.

        Args:
            result: Результат верификации.
        """
        if result is None:
            self._chain_var.set("Trust chain unavailable")
            return

        if result.can_trust:
            self._chain_var.set(
                f"✅ Trusted key: {result.signing_key_id[:20]}... "
                f"(chain depth: {result.chain_depth})"
            )
        elif result.errors:
            error_msg = result.errors[0][:50] if result.errors else "Error"
            self._chain_var.set(f"⚠️ {error_msg}")
        else:
            self._chain_var.set(f"Status: {result.trust_status.label()}")

    def _on_verify_toggle(self) -> None:
        """Обрабатывает переключение проверки подписи."""
        enabled = self._verify_var.get()

        # Update UI state
        if enabled and self._selected_path and self._trust_chain_verifier:
            self._verify_signature(self._selected_path)
        elif not enabled:
            # Reset to no verification status
            self._status_icon_var.set("⏸")
            self._status_text_var.set("Verification disabled")
            self._status_text_label.configure(foreground=COLOR_GRAY)
            self._chain_var.set("Signature verification disabled")

    def _on_open(self) -> None:
        """Обрабатывает нажатие кнопки открытия."""
        if not self._selected_path:
            messagebox.showerror(
                "Error",
                "Select a file to open",
                parent=self,
            )
            return

        if not self._selected_path.exists():
            messagebox.showerror(
                "Error",
                f"File not found: {self._selected_path}",
                parent=self,
            )
            return

        # Check signature if verification is enabled
        if self._verify_var.get() and self._verification_result is not None:
            if not self._verification_result.can_trust:
                # Show warning for invalid signature
                error_msg = (
                    self._verification_result.errors[0]
                    if self._verification_result.errors
                    else "Неизвестная ошибка"
                )
                result = messagebox.askyesno(
                    "⚠️ Warning",
                    f"File signature is invalid:\n{error_msg}\n\nOpen the file anyway?",
                    parent=self,
                )
                if not result:
                    return

        # Determine signature validity for result
        signature_valid: Optional[bool] = None
        if self._verification_result is not None:
            signature_valid = self._verification_result.is_valid

        # Get metadata
        metadata = self._load_metadata(self._selected_path)

        # Create result
        self._result = OpenResult(
            path=self._selected_path,
            verify_signature=self._verify_var.get(),
            metadata=metadata,
            signature_valid=signature_valid,
        )

        self.destroy()

    def _on_cancel(self) -> None:
        """Обрабатывает нажатие кнопки отмены."""
        self._result = None
        self.destroy()

    def show(self) -> Optional[OpenResult]:
        """Показывает диалог и возвращает результат.

        Returns:
            OpenResult если пользователь подтвердил открытие,
            None если диалог был отменён.
        """
        self.wait_window()
        return self._result


class TrustChainVerifier:
    """Верификатор цепочки доверия для шаблонов.

    Обёртка над TrustChainService для удобства использования в диалогах.

    Attributes:
        _trust_service: Базовый сервис цепочки доверия.

    Example:
        >>> verifier = TrustChainVerifier(trust_service)
        >>> result = verifier.verify_template(template)
    """

    def __init__(self, trust_service: TrustChainServiceProtocol) -> None:
        """Инициализация верификатора.

        Args:
            trust_service: Сервис цепочки доверия.
        """
        self._trust_service: TrustChainServiceProtocol = trust_service

    def verify_template(self, template: FormTemplate) -> TrustVerificationResult:
        """Верифицирует шаблон по цепочке доверия.

        Args:
            template: Шаблон для проверки.

        Returns:
            Результат верификации.
        """
        return self._trust_service.verify_template(template, verify_chain=True)

    def get_trust_chain_summary(self, key_id: str) -> str:
        """Получает краткое описание цепочки доверия.

        Args:
            key_id: ID ключа.

        Returns:
            Краткое описание цепочки доверия.
        """
        try:
            chain = self._trust_service.get_trust_chain(key_id)
            if not chain:
                return "Trust chain not found"

            root = [link for link in chain if link.is_root()]
            if root:
                root_name = root[0].metadata.get("name", "Root")
                return f"Chain from {root_name}, depth: {len(chain)}"
            return f"Trust chain, depth: {len(chain)}"
        except (AuthError, CryptoError) as e:
            return f"Chain security error: {str(e)[:50]}"
        except (OSError, FileNotFoundError, ValueError) as e:
            return f"Chain retrieval error: {str(e)[:50]}"


class OpenFileDialog:
    """Статический диалог открытия для простых случаев.

    Предоставляет упрощённый интерфейс для открытия файлов
    без проверки подписи и расширенных опций.

    Example:
        >>> path = OpenFileDialog.show(default_dir=Path.home() / "Documents")
        >>> if path:
        ...     print(f"Opening: {path}")
    """

    @staticmethod
    def show(
        parent: Optional[tk.Widget] = None,
        default_dir: Optional[Path] = None,
    ) -> Optional[Path]:
        """Показывает простой диалог открытия.

        Args:
            parent: Родительский виджет.
            default_dir: Директория по умолчанию.

        Returns:
            Путь к файлу или None если отменено.
        """
        initial_dir = default_dir or Path.home() / "Documents"

        filename = filedialog.askopenfilename(
            title="Open Document",
            initialdir=str(initial_dir),
            filetypes=[
                ("FX Text Documents", "*.fxsd *.fxsd.enc"),
                ("Templates", "*.fxstpl"),
                ("All Files", "*.*"),
            ],
        )
        return Path(filename) if filename else None


__all__: list[str] = [
    "OpenDialog",
    "OpenResult",
    "OpenFileDialog",
    "TrustChainVerifier",
    "SIGNATURE_STATUS",
    "FILE_TYPE_ICONS",
]
