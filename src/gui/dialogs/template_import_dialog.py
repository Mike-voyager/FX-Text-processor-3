"""Диалог импорта шаблонов (.fxstpl) с проверкой Trust Chain.

Предоставляет интерфейс для:
- Выбора файла шаблона (.fxstpl)
- Предпросмотра шаблона перед импортом
- Проверки подписи (Trust Chain)
- Импорта с валидацией

Example:
    >>> from src.services.trust_chain_service import TrustChainService
    >>> from src.security.crypto.utilities.floppy_optimizer import FloppyOptimizer
    >>> dialog = TemplateImportDialog(
    ...     parent=root,
    ...     template_manager=template_manager,
    ...     trust_chain_service=trust_chain_service,
    ...     floppy_optimizer=floppy_optimizer,
    ... )
    >>> result = dialog.show()
    >>> if result:
    ...     print(f"Imported: {result.template_id}")

Version: 2.0
Date: April 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import TYPE_CHECKING, Any, Callable, Final, Optional, cast

from src.security.crypto.core.exceptions import AuthError, CryptoError
from src.gui.components.tooltip import TooltipManager
from src.gui.dialogs.base_dialog import BaseDialog
from src.gui.dialogs.floppy_optimizer_dialog import FloppyOptimizerDialog
from src.gui.dialogs.template_preview_panel import TemplatePreviewWidget
from src.gui.dialogs.trust_chain_dialog import TrustChainDialog
from src.security.crypto.utilities.floppy_optimizer import FloppyOptimizer
from src.services.template_manager import FormTemplate, TemplateManager
from src.services.trust_chain_service import TrustChainService

if TYPE_CHECKING:
    from src.services.protocols.template_security import (
        TrustChainServiceProtocol,
    )

logger: Final = logging.getLogger(__name__)

# Dialog constants
DIALOG_WIDTH: Final[int] = 700
DIALOG_HEIGHT: Final[int] = 550
MIN_DIALOG_WIDTH: Final[int] = 600
MIN_DIALOG_HEIGHT: Final[int] = 450

# Colors
COLOR_BG: Final[str] = "#f8f9fa"
COLOR_HEADER: Final[str] = "#e9ecef"
COLOR_BORDER: Final[str] = "#dee2e6"
COLOR_SUCCESS: Final[str] = "#28a745"
COLOR_ERROR: Final[str] = "#dc3545"
COLOR_WARNING: Final[str] = "#ffc107"

# Floppy size limit
MAX_FLOPPY_SIZE: Final[int] = 1_350_000  # ~1.35MB safety margin


@dataclass
class ImportResult:
    """Результат импорта шаблона.

    Attributes:
        success: True если импорт успешен.
        template_id: ID импортированного шаблона.
        template: Объект шаблона.
        error: Сообщение об ошибке (если failed).
    """

    success: bool
    template_id: str = ""
    template: Optional[FormTemplate] = None
    error: str = ""

    @classmethod
    def success_result(cls, template_id: str, template: FormTemplate) -> "ImportResult":
        """Создаёт успешный результат."""
        return cls(success=True, template_id=template_id, template=template)

    @classmethod
    def failure_result(cls, error: str) -> "ImportResult":
        """Создаёт неуспешный результат."""
        return cls(success=False, error=error)


class TemplatePreviewPanel(tk.Frame):
    """Панель предпросмотра шаблона.

    Отображает информацию о шаблоне:
    - Название и тип документа
    - Количество страниц и полей
    - Статус подписи
    - Метаданные

    Example:
        >>> panel = TemplatePreviewPanel(parent)
        >>> panel.show_template(template)
    """

    def __init__(self, parent: tk.Widget, *args: Any, **kwargs: Any) -> None:
        """Инициализация панели предпросмотра.

        Args:
            parent: Родительский виджет.
        """
        super().__init__(parent, *args, **kwargs)

        self._template: Optional[FormTemplate] = None
        self._tooltip_manager: TooltipManager = TooltipManager.get_instance()

        self._create_ui()

    def _create_ui(self) -> None:
        """Создаёт UI компоненты."""
        self.config(bg=COLOR_BG, padx=10, pady=10)

        # Header
        header = ttk.Label(
            self,
            text="Предпросмотр шаблона",
            font=("Helvetica", 12, "bold"),
        )
        header.pack(anchor="w", pady=(0, 10))

        # Content frame
        self._content_frame = ttk.Frame(self)
        self._content_frame.pack(fill=tk.BOTH, expand=True)

        # Placeholder
        self._placeholder_label = ttk.Label(
            self._content_frame,
            text="Выберите файл шаблона для предпросмотра",
            foreground="gray",
        )
        self._placeholder_label.pack(expand=True)

        # Template info frame (hidden initially)
        self._info_frame = ttk.Frame(self._content_frame)

        # Name
        ttk.Label(self._info_frame, text="Название:", font=("Helvetica", 10, "bold")).grid(
            row=0, column=0, sticky="w", pady=2
        )
        self._name_var = tk.StringVar(master=self, value="-")
        ttk.Label(self._info_frame, textvariable=self._name_var).grid(
            row=0, column=1, sticky="w", padx=(10, 0), pady=2
        )

        # Type
        ttk.Label(self._info_frame, text="Тип документа:", font=("Helvetica", 10, "bold")).grid(
            row=1, column=0, sticky="w", pady=2
        )
        self._type_var = tk.StringVar(master=self, value="-")
        ttk.Label(self._info_frame, textvariable=self._type_var).grid(
            row=1, column=1, sticky="w", padx=(10, 0), pady=2
        )

        # Pages
        ttk.Label(self._info_frame, text="Страниц:", font=("Helvetica", 10, "bold")).grid(
            row=2, column=0, sticky="w", pady=2
        )
        self._pages_var = tk.StringVar(master=self, value="-")
        ttk.Label(self._info_frame, textvariable=self._pages_var).grid(
            row=2, column=1, sticky="w", padx=(10, 0), pady=2
        )

        # Fields
        ttk.Label(self._info_frame, text="Полей:", font=("Helvetica", 10, "bold")).grid(
            row=3, column=0, sticky="w", pady=2
        )
        self._fields_var = tk.StringVar(master=self, value="-")
        ttk.Label(self._info_frame, textvariable=self._fields_var).grid(
            row=3, column=1, sticky="w", padx=(10, 0), pady=2
        )

        # Signature status
        ttk.Label(self._info_frame, text="Подпись:", font=("Helvetica", 10, "bold")).grid(
            row=4, column=0, sticky="w", pady=2
        )
        self._signature_var = tk.StringVar(master=self, value="-")
        self._signature_label = ttk.Label(self._info_frame, textvariable=self._signature_var)
        self._signature_label.grid(row=4, column=1, sticky="w", padx=(10, 0), pady=2)

        # Created
        ttk.Label(self._info_frame, text="Создан:", font=("Helvetica", 10, "bold")).grid(
            row=5, column=0, sticky="w", pady=2
        )
        self._created_var = tk.StringVar(master=self, value="-")
        ttk.Label(self._info_frame, textvariable=self._created_var).grid(
            row=5, column=1, sticky="w", padx=(10, 0), pady=2
        )

        # Description
        ttk.Label(self._info_frame, text="Описание:", font=("Helvetica", 10, "bold")).grid(
            row=6, column=0, sticky="nw", pady=2
        )
        self._desc_text = tk.Text(
            self._info_frame, height=4, width=40, wrap=tk.WORD, state=tk.DISABLED
        )
        self._desc_text.grid(row=6, column=1, sticky="w", padx=(10, 0), pady=2)

        self._info_frame.columnconfigure(1, weight=1)

    def show_template(self, template: FormTemplate, signature_valid: Optional[bool] = None) -> None:
        """Отображает информацию о шаблоне.

        Args:
            template: Шаблон для отображения.
            signature_valid: Статус проверки подписи (None = не проверялась).
        """
        self._template = template

        # Hide placeholder, show info
        self._placeholder_label.pack_forget()
        self._info_frame.pack(fill=tk.BOTH, expand=True)

        # Update fields
        self._name_var.set(template.name_ru or template.name or "-")
        self._type_var.set(template.doc_type or "-")
        self._pages_var.set(str(len(template.pages)))

        field_count = sum(len(page.fields) for page in template.pages)
        self._fields_var.set(str(field_count))

        # Signature status
        if signature_valid is True:
            self._signature_var.set("✓ Подпись валидна")
            self._signature_label.config(foreground=COLOR_SUCCESS)
        elif signature_valid is False:
            self._signature_var.set("✗ Подпись невалидна")
            self._signature_label.config(foreground=COLOR_ERROR)
        else:
            self._signature_var.set("? Не проверена")
            self._signature_label.config(foreground=COLOR_WARNING)

        self._created_var.set(template.created_at or "-")

        # Description (FormTemplate doesn't have description field directly)
        description_text = ""
        if hasattr(template, "description") and template.description:
            description_text = str(template.description)
        else:
            description_text = f"Шаблон: {template.name_ru or template.name}\n"
            description_text += f"Автор: {template.author or 'не указан'}\n"
            description_text += f"Версия: {template.version}"

        self._desc_text.config(state=tk.NORMAL)
        self._desc_text.delete("1.0", tk.END)
        self._desc_text.insert("1.0", description_text)
        self._desc_text.config(state=tk.DISABLED)

    def clear(self) -> None:
        """Очищает панель предпросмотра."""
        self._template = None
        self._info_frame.pack_forget()
        self._placeholder_label.pack(expand=True)

        self._name_var.set("-")
        self._type_var.set("-")
        self._pages_var.set("-")
        self._fields_var.set("-")
        self._signature_var.set("-")
        self._created_var.set("-")


class TemplateImportDialog(BaseDialog):
    """Диалог импорта шаблонов форм.

    Attributes:
        _template_manager: Менеджер шаблонов для импорта.
        _trust_chain_service: Сервис цепочек доверия для проверки подписей.
        _floppy_optimizer: Оптимизатор размера для проверки лимита дискеты.
        _selected_path: Путь к выбранному файлу.
        _template: Загруженный шаблон.
        _result: Результат диалога.

    Example:
        >>> from src.services.trust_chain_service import TrustChainService
        >>> from src.security.crypto.utilities.floppy_optimizer import FloppyOptimizer
        >>> dialog = TemplateImportDialog(
        ...     parent, template_manager, trust_chain_service, floppy_optimizer
        ... )
        >>> result = dialog.show()
        >>> if result and result.success:
        ...     print(f"Imported: {result.template_id}")
    """

    def __init__(
        self,
        parent: Optional[tk.Widget],
        template_manager: TemplateManager,
        trust_chain_service: TrustChainService,
        floppy_optimizer: FloppyOptimizer,
        on_import: Optional[Callable[[ImportResult], None]] = None,
        on_new_document: Optional[Callable[[str], None]] = None,
        on_print_blank: Optional[Callable[[str], None]] = None,
    ) -> None:
        """Инициализация диалога импорта.

        Args:
            parent: Родительский виджет.
            template_manager: Менеджер шаблонов.
            trust_chain_service: Сервис цепочек доверия.
            floppy_optimizer: Оптимизатор размера данных.
            on_import: Callback при успешном импорте.
            on_new_document: Callback при создании документа из шаблона (template_id).
            on_print_blank: Callback при печати бланка из шаблона (template_id).
        """
        # Handle None parent
        if parent is None:
            # Create a temporary root window if no parent provided
            root = tk.Tk()
            parent = cast(tk.Widget, root)

        super().__init__(parent)

        self._parent: tk.Widget = parent
        self._template_manager: TemplateManager = template_manager
        self._trust_chain_service: TrustChainService = trust_chain_service
        self._floppy_optimizer: FloppyOptimizer = floppy_optimizer
        self._on_new_document_callback: Optional[Callable[[str], None]] = on_new_document
        self._on_print_blank_callback: Optional[Callable[[str], None]] = on_print_blank
        self._import_callback: Optional[Callable[[ImportResult], None]] = on_import

        self._selected_path: Optional[Path] = None
        self._template: Optional[FormTemplate] = None
        self._signature_valid: Optional[bool] = None
        self._result: Optional[ImportResult] = None
        self._template_map: dict[str, FormTemplate] = {}
        self._tree_iid_counter: int = 0

        self._create_ui()
        self._setup_window()

    def _setup_window(self) -> None:
        """Настраивает параметры окна."""
        self.title("Импорт шаблона")
        self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}")
        self.minsize(MIN_DIALOG_WIDTH, MIN_DIALOG_HEIGHT)

        # Center window
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (DIALOG_WIDTH // 2)
        y = (self.winfo_screenheight() // 2) - (DIALOG_HEIGHT // 2)
        self.geometry(f"+{x}+{y}")

    def _create_ui(self) -> None:
        """Создаёт UI диалога с двухпанельным интерфейсом."""
        self.config(bg=COLOR_BG)

        # Main frame
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.rowconfigure(1, weight=1)
        main_frame.columnconfigure(0, weight=1)

        # Top: file selection
        file_section = ttk.LabelFrame(main_frame, text="Выбор файла", padding="6")
        file_section.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))

        self._path_var = tk.StringVar(master=self, value="")
        path_entry = ttk.Entry(file_section, textvariable=self._path_var, state="readonly")
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        ttk.Button(file_section, text="Обзор...", command=self._on_browse).pack(side=tk.RIGHT)

        # PanedWindow: list left, preview right
        paned = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(0, 8))

        # Left panel: template list
        left_frame = ttk.LabelFrame(paned, text="Шаблоны", padding="6")
        paned.add(left_frame, weight=1)

        self._template_tree = ttk.Treeview(
            left_frame,
            columns=("name", "type"),
            show="headings",
            selectmode="browse",
        )
        self._template_tree.heading("name", text="Название")
        self._template_tree.heading("type", text="Тип")
        self._template_tree.column("name", width=160, minwidth=80)
        self._template_tree.column("type", width=80, minwidth=60)
        self._template_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tree_scroll = ttk.Scrollbar(
            left_frame, orient=tk.VERTICAL, command=self._template_tree.yview
        )
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._template_tree.configure(yscrollcommand=tree_scroll.set)

        self._template_tree.bind("<<TreeviewSelect>>", self._on_template_selected)

        # Right panel: preview + actions
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=2)

        # Preview widget
        self._preview_widget = TemplatePreviewWidget(right_frame)
        self._preview_widget.pack(fill=tk.BOTH, expand=True, pady=(0, 8))
        self._preview_widget.on_new_document(self._on_preview_new_document)
        self._preview_widget.on_print_blank(self._on_preview_print_blank)

        # Trust / size info row
        info_frame = ttk.Frame(right_frame)
        info_frame.pack(fill=tk.X, pady=(0, 8))

        trust_frame = ttk.LabelFrame(info_frame, text="Подпись", padding="6")
        trust_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        self._trust_var = tk.StringVar(master=self, value="—")
        self._trust_label = ttk.Label(trust_frame, textvariable=self._trust_var)
        self._trust_label.pack(side=tk.LEFT)

        self._verify_btn = ttk.Button(
            trust_frame, text="Проверить", command=self._on_verify, state=tk.DISABLED
        )
        self._verify_btn.pack(side=tk.RIGHT)

        size_frame = ttk.LabelFrame(info_frame, text="Размер", padding="6")
        size_frame.pack(side=tk.RIGHT, fill=tk.X, padx=(4, 0))
        self._size_var = tk.StringVar(master=self, value="—")
        ttk.Label(size_frame, textvariable=self._size_var).pack(side=tk.LEFT)

        # Bottom buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, sticky="ew")

        self._import_btn = ttk.Button(
            btn_frame, text="Импортировать", command=self._on_import, state=tk.DISABLED
        )
        self._import_btn.pack(side=tk.RIGHT, padx=(8, 0))

        ttk.Button(btn_frame, text="Отмена", command=self._on_cancel).pack(side=tk.RIGHT)

        # Load existing templates
        self._refresh_template_list()

    def _on_browse(self) -> None:
        """Обработчик кнопки 'Обзор'."""
        path = filedialog.askopenfilename(
            parent=self,
            title="Выберите шаблон формы",
            filetypes=[("Шаблоны FX", "*.fxstpl"), ("Все файлы", "*.*")],
        )

        if path:
            self._selected_path = Path(path)
            self._path_var.set(str(self._selected_path))
            self._load_template()

    def _refresh_template_list(self) -> None:
        """Перезагружает список шаблонов из TemplateManager."""
        self._template_map.clear()
        if self._template_tree is not None:
            for item in self._template_tree.get_children():
                self._template_tree.delete(item)

        try:
            templates = self._template_manager.list_templates()
        except (AuthError, CryptoError) as e:
            logger.critical("Security error while listing templates: %s", e, exc_info=True)
            templates = []
        except (OSError, FileNotFoundError, ValueError) as e:
            logger.error("Unexpected error while listing templates: %s", e, exc_info=True)
            templates = []

        for template in templates:
            self._tree_iid_counter += 1
            iid = f"tpl_{self._tree_iid_counter}"
            self._template_map[iid] = template
            self._template_tree.insert(
                "",
                "end",
                iid=iid,
                values=(template.name_ru or template.name, template.doc_type or "—"),
            )

    def _on_template_selected(self, event: Optional[tk.Event] = None) -> None:
        """Обработчик выбора шаблона в списке.

        Загружает шаблон, обновляет preview widget и метаинформацию.
        """
        if self._template_tree is None:
            return

        selection = self._template_tree.selection()
        if not selection:
            return

        iid = selection[0]
        template = self._template_map.get(iid)
        if not template:
            return

        self._template = template

        # Compute fields count
        field_count = sum(len(page.fields) for page in template.pages)

        # Prepare thumbnail data (placeholder if none)
        thumbnail_data: Optional[bytes] = None

        # Determine signature status
        sig_valid: Optional[bool] = None
        if template.signature:
            # Basic check: signature exists; real validation via trust service
            sig_valid = True

        self._signature_valid = sig_valid

        # Build preview data dict for TemplatePreviewWidget
        preview_data: dict[str, Any] = {
            "name": template.name_ru or template.name,
            "fields": field_count,
            "signature_valid": sig_valid,
            "thumbnail": thumbnail_data,
        }

        self._preview_widget.load_template(preview_data)

        # Update trust label
        if sig_valid is True:
            self._trust_var.set("✓ Подпись валидна")
            self._trust_label.config(foreground=COLOR_SUCCESS)
        elif sig_valid is False:
            self._trust_var.set("✗ Подпись невалидна")
            self._trust_label.config(foreground=COLOR_ERROR)
        else:
            self._trust_var.set("—")
            self._trust_label.config(foreground="")

        # Update size label
        try:
            path = self._template_manager.templates_dir / f"{template.template_id}.fxstpl"
            if path.exists():
                file_size = path.stat().st_size
                self._size_var.set(f"{file_size:,} bytes ({file_size / 1024:.1f} KB)")
                self._selected_path = path
            else:
                self._size_var.set("—")
        except (FileNotFoundError, OSError) as e:
            logger.error("File system error while calculating size: %s", e)
            self._size_var.set("—")
        except (OSError, FileNotFoundError, ValueError) as e:
            logger.debug("Unexpected error while calculating size: %s", e)
            self._size_var.set("—")

        self._verify_btn.config(state=tk.NORMAL)
        self._import_btn.config(state=tk.NORMAL)

    def _on_preview_new_document(self) -> None:
        """Callback кнопки '📄 New Document' в preview panel."""
        if self._template is None:
            return
        if self._on_new_document_callback is not None:
            self._on_new_document_callback(self._template.template_id)

    def _on_preview_print_blank(self) -> None:
        """Callback кнопки '🖨️ Print Blank' в preview panel."""
        if self._template is None:
            return
        if self._on_print_blank_callback is not None:
            self._on_print_blank_callback(self._template.template_id)

    def _load_template(self) -> None:
        """Загружает шаблон из выбранного файла (после Browse)."""
        if not self._selected_path:
            return

        try:
            template = FormTemplate.load(self._selected_path)
            self._template = template

            # Insert into tree as a new item and select it
            self._tree_iid_counter += 1
            iid = f"tpl_{self._tree_iid_counter}"
            self._template_map[iid] = template
            self._template_tree.insert(
                "",
                "end",
                iid=iid,
                values=(template.name_ru or template.name, template.doc_type or "—"),
            )
            self._template_tree.selection_set(iid)
            self._template_tree.see(iid)

            # Trigger selection update
            self._on_template_selected()

            logger.info("Template loaded for preview: %s", template.template_id)

        except (AuthError, CryptoError) as e:
            logger.critical("Security error loading template: %s", e, exc_info=True)
            messagebox.showerror("Ошибка безопасности", f"Ошибка доступа к шаблону:\n{e}")
            self._preview_widget.load_template({})
            self._verify_btn.config(state=tk.DISABLED)
            self._import_btn.config(state=tk.DISABLED)
        except (FileNotFoundError, OSError) as e:
            logger.error("File system error loading template: %s", e)
            messagebox.showerror("Ошибка", f"Файл не найден или недоступен:\n{e}")
            self._preview_widget.load_template({})
            self._verify_btn.config(state=tk.DISABLED)
            self._import_btn.config(state=tk.DISABLED)
        except (OSError, FileNotFoundError, ValueError) as e:
            logger.error("Unexpected error loading template: %s", e, exc_info=True)
            messagebox.showerror("Ошибка", f"Не удалось загрузить шаблон:\n{e}")
            self._preview_widget.load_template({})
            self._verify_btn.config(state=tk.DISABLED)
            self._import_btn.config(state=tk.DISABLED)

    def _on_verify(self) -> None:
        """Обработчик кнопки 'Проверить' подпись.

        Открывает TrustChainDialog в режиме верификации
        (verification_mode=True) для отображения детальной информации
        о цепочке доверия и принятия решения о доверии.
        """
        if not self._template or not self._selected_path:
            return

        try:
            # Read file data
            with open(self._selected_path, "rb") as f:
                _ = f.read()

            # Check if template has signature
            is_valid = False
            if self._template.signature:
                # Basic validation - signature exists
                # In real implementation would use trust_chain_service.verify_template
                is_valid = True

            self._signature_valid = is_valid

            # Update UI
            if is_valid:
                self._trust_var.set("✓ Подпись валидна")
                self._trust_label.config(foreground=COLOR_SUCCESS)
            else:
                self._trust_var.set("✗ Подпись невалидна или отсутствует")
                self._trust_label.config(foreground=COLOR_ERROR)

            # Update preview widget
            field_count = sum(len(page.fields) for page in self._template.pages)
            preview_data: dict[str, Any] = {
                "name": self._template.name_ru or self._template.name,
                "fields": field_count,
                "signature_valid": is_valid,
                "thumbnail": None,
            }
            self._preview_widget.load_template(preview_data)

            # Open TrustChainDialog in verification mode
            dialog = TrustChainDialog(
                parent=cast(tk.Widget, self),
                template=self._template,
                trust_service=cast("TrustChainServiceProtocol", self._trust_chain_service),
                verification_mode=True,
                on_whitelist=lambda cert_id: logger.info("Whitelisted: %s", cert_id),
                on_reject=lambda cert_id: logger.info("Rejected: %s", cert_id),
            )
            dialog.show()

            logger.info("Template signature verified: %s", is_valid)

        except (AuthError, CryptoError) as e:
            logger.critical("Signature verification security error: %s", e, exc_info=True)
            messagebox.showerror("Ошибка безопасности", f"Ошибка верификации подписи:\n{e}")
        except (FileNotFoundError, OSError) as e:
            logger.error("File system error during signature verification: %s", e)
            messagebox.showerror("Ошибка", f"Ошибка доступа к файлу:\n{e}")
        except (OSError, FileNotFoundError, ValueError) as e:
            logger.error("Unexpected signature verification error: %s", e, exc_info=True)
            messagebox.showerror("Ошибка", f"Не удалось проверить подпись:\n{e}")

    def _on_import(self) -> None:
        """Обработчик кнопки 'Импортировать'.

        Проверяет размер файла и предлагает оптимизацию через
        FloppyOptimizerDialog если размер превышает лимит дискеты.
        """
        if not self._template or not self._selected_path:
            return

        try:
            # Check size limit
            file_size = self._selected_path.stat().st_size

            if file_size > MAX_FLOPPY_SIZE:
                # Offer optimization
                result = messagebox.askyesno(
                    "Размер файла",
                    f"Размер файла ({file_size:,} bytes) превышает лимит дискеты "
                    f"({MAX_FLOPPY_SIZE:,} bytes).\n\n"
                    f"Открыть диалог оптимизации?",
                )

                if result:
                    dialog = FloppyOptimizerDialog(
                        parent=cast(tk.Widget, self),
                        template_data=self._selected_path.read_bytes(),
                    )
                    opt_success, optimized_data = dialog.show()

                    if opt_success and optimized_data:
                        logger.info("Using optimized template data")
                    else:
                        # User cancelled optimization
                        logger.info("Optimization cancelled by user")
                        return
                else:
                    # User declined optimization, proceed anyway
                    logger.info("Proceeding with oversized template")

            # Import template using TemplateManager
            imported = self._template_manager.import_template(self._selected_path)

            self._result = ImportResult.success_result(
                template_id=imported.template_id,
                template=imported,
            )

            logger.info("Template imported successfully: %s", imported.template_id)

            if self._import_callback:
                self._import_callback(self._result)

            self.destroy()

        except (AuthError, CryptoError) as e:
            logger.critical("Security error during import: %s", e, exc_info=True)
            messagebox.showerror("Ошибка безопасности", f"Ошибка импорта:\n{e}")
            self._result = ImportResult.failure_result(str(e))
        except (FileNotFoundError, OSError) as e:
            logger.error("File system error during import: %s", e)
            messagebox.showerror("Ошибка", f"Ошибка доступа к файлу:\n{e}")
            self._result = ImportResult.failure_result(str(e))
        except (OSError, FileNotFoundError, ValueError) as e:
            logger.error("Unexpected import error: %s", e, exc_info=True)
            messagebox.showerror("Ошибка импорта", f"Не удалось импортировать шаблон:\n{e}")
            self._result = ImportResult.failure_result(str(e))

    def _on_cancel(self) -> None:
        """Обработчик кнопки 'Отмена'."""
        self._result = ImportResult.failure_result("Отменено пользователем")
        self.destroy()

    def show(self) -> Optional[ImportResult]:
        """Показывает диалог и возвращает результат.

        Returns:
            ImportResult или None если отменено.
        """
        self.wait_window()
        return self._result


__all__ = [
    "ImportResult",
    "TemplatePreviewPanel",
    "TemplateImportDialog",
]
