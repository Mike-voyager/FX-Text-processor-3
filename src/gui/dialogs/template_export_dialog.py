"""Диалог экспорта формы как шаблона (.fxstpl).

Предоставляет интерфейс для:
- Ввода метаданных шаблона (название, версия, автор, описание)
- Выбора категории
- Опционального подписания шаблона
- Предпросмотра оптимизации для дискеты
- Выбора места сохранения

Example:
    >>> from src.services.template_manager import TemplateManager
    >>> dialog = TemplateExportDialog(
    ...     parent=root,
    ...     form_data={"name": "Invoice", "fields": []},
    ...     template_manager=template_manager,
    ... )
    >>> result = dialog.show()
    >>> if result:
    ...     print(f"Exported: {result.path}")

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import json
import logging
import re
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import TYPE_CHECKING, Any, Final, Optional

from src.gui.dialogs.base_dialog import BaseDialog
from src.security.crypto.utilities.floppy_optimizer import FloppyOptimizer
from src.services.template_manager import FormTemplate, TemplateManager

if TYPE_CHECKING:
    pass

logger: Final = logging.getLogger(__name__)

# Dialog constants
DIALOG_WIDTH: Final[int] = 650
DIALOG_HEIGHT: Final[int] = 650
MIN_DIALOG_WIDTH: Final[int] = 550
MIN_DIALOG_HEIGHT: Final[int] = 500

# Colors
COLOR_BG: Final[str] = "#f8f9fa"
COLOR_HEADER: Final[str] = "#e9ecef"
COLOR_BORDER: Final[str] = "#dee2e6"
COLOR_SUCCESS: Final[str] = "#28a745"
COLOR_ERROR: Final[str] = "#dc3545"
COLOR_WARNING: Final[str] = "#ffc107"
COLOR_TEXT: Final[str] = "#2c3e50"

# Floppy size limit
MAX_FLOPPY_SIZE: Final[int] = 1_340_000  # ~1.28MB usable on 1.44MB floppy

# Categories for templates
TEMPLATE_CATEGORIES: Final[list[str]] = [
    "General",
    "Accounting",
    "Logistics",
    "HR",
    "Production",
    "Management",
    "Special Blanks",
    "Other",
]


@dataclass
class ExportResult:
    """Результат экспорта шаблона.

    Attributes:
        path: Путь к экспортированному файлу.
        signed: True если шаблон был подписан.
        template_name: Название шаблона.
        version: Версия шаблона (semver).
    """

    path: Path
    signed: bool
    template_name: str
    version: str


class TemplateExportDialog(BaseDialog):
    """Диалог экспорта формы как шаблона.

    Attributes:
        _form_data: Данные формы для экспорта.
        _template_manager: Менеджер шаблонов.
        _floppy_optimizer: Оптимизатор размера для дискеты.
        _result: Результат экспорта.

    Example:
        >>> dialog = TemplateExportDialog(parent, form_data, template_manager)
        >>> result = dialog.show()
        >>> if result:
        ...     print(f"Exported: {result.path}")
    """

    def __init__(
        self,
        parent: tk.Widget,
        form_data: dict[str, Any],
        template_manager: TemplateManager,
        current_user: Optional[str] = None,
    ) -> None:
        """Инициализация диалога экспорта.

        Args:
            parent: Родительский виджет.
            form_data: Данные формы для экспорта.
            template_manager: Менеджер шаблонов.
            current_user: Текущий пользователь (для автора).
        """
        super().__init__(parent)

        self._parent: tk.Widget = parent
        self._form_data: dict[str, Any] = form_data
        self._template_manager: TemplateManager = template_manager
        self._floppy_optimizer: FloppyOptimizer = FloppyOptimizer()
        self._current_user: Optional[str] = current_user
        self._result: Optional[ExportResult] = None

        # Calculated template size
        self._original_size: int = 0
        self._optimized_size: int = 0

        self._create_ui()
        self._setup_window()
        self._calculate_size()

    def _setup_window(self) -> None:
        """Настраивает параметры окна."""
        self.title("Export Template")
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

        # Main container with scrollbar
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Canvas for scrolling
        self._canvas = tk.Canvas(main_frame, bg=COLOR_BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self._canvas.yview)
        self._content_frame = ttk.Frame(self._canvas)

        self._content_frame.bind(
            "<Configure>",
            lambda e: self._canvas.configure(scrollregion=self._canvas.bbox("all")),
        )

        self._canvas.create_window(
            (0, 0), window=self._content_frame, anchor="nw", width=DIALOG_WIDTH - 40
        )
        self._canvas.configure(yscrollcommand=scrollbar.set)

        self._canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind mouse wheel
        self._canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        # Header
        self._create_header()

        # Metadata section
        self._create_metadata_section()

        # Category section
        self._create_category_section()

        # Signature section
        self._create_signature_section()

        # Floppy optimizer section
        self._create_floppy_section()

        # Export location section
        self._create_export_location_section()

        # Buttons
        self._create_buttons()

    def _on_mousewheel(self, event: tk.Event[Any]) -> None:
        """Обработчик прокрутки мышью."""
        self._canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _create_header(self) -> None:
        """Создаёт заголовок диалога."""
        header_frame = ttk.Frame(self._content_frame)
        header_frame.pack(fill=tk.X, pady=(0, 15))

        header = ttk.Label(
            header_frame,
            text="📤 Export Form Template",
            font=("Helvetica", 14, "bold"),
        )
        header.pack(anchor="w")

        desc = ttk.Label(
            header_frame,
            text="Save form as template for reuse",
            font=("Helvetica", 9),
            foreground="gray",
        )
        desc.pack(anchor="w", pady=(2, 0))

    def _create_metadata_section(self) -> None:
        """Создаёт секцию метаданных шаблона."""
        meta_frame = ttk.LabelFrame(self._content_frame, text=" Template Metadata ", padding="10")
        meta_frame.pack(fill=tk.X, pady=(0, 10))

        # Template name
        ttk.Label(meta_frame, text="Template name:*").grid(row=0, column=0, sticky="w", pady=5)
        self._name_var = tk.StringVar(master=self, value=self._form_data.get("name", ""))
        name_entry = ttk.Entry(meta_frame, textvariable=self._name_var, width=40)
        name_entry.grid(row=0, column=1, sticky="ew", padx=(10, 0), pady=5)

        # Version
        ttk.Label(meta_frame, text="Version:*").grid(row=1, column=0, sticky="w", pady=5)
        self._version_var = tk.StringVar(master=self, value="1.0.0")
        version_entry = ttk.Entry(meta_frame, textvariable=self._version_var, width=15)
        version_entry.grid(row=1, column=1, sticky="w", padx=(10, 0), pady=5)
        ttk.Label(
            meta_frame, text="(semver: X.Y.Z)", font=("Helvetica", 8), foreground="gray"
        ).grid(row=1, column=2, sticky="w", padx=(5, 0), pady=5)

        # Author
        ttk.Label(meta_frame, text="Author:").grid(row=2, column=0, sticky="w", pady=5)
        author_default = self._current_user or self._form_data.get("author", "")
        self._author_var = tk.StringVar(master=self, value=author_default)
        author_entry = ttk.Entry(meta_frame, textvariable=self._author_var, width=40)
        author_entry.grid(row=2, column=1, sticky="ew", padx=(10, 0), pady=5)

        # Description
        ttk.Label(meta_frame, text="Description:").grid(row=3, column=0, sticky="nw", pady=5)
        self._desc_text = tk.Text(meta_frame, height=4, width=40, wrap=tk.WORD)
        self._desc_text.grid(row=3, column=1, sticky="ew", padx=(10, 0), pady=5)
        desc_default = self._form_data.get("description", "")
        if desc_default:
            self._desc_text.insert("1.0", desc_default)

        meta_frame.columnconfigure(1, weight=1)

    def _create_category_section(self) -> None:
        """Создаёт секцию выбора категории."""
        cat_frame = ttk.LabelFrame(self._content_frame, text=" Category ", padding="10")
        cat_frame.pack(fill=tk.X, pady=(0, 10))

        self._category_var = tk.StringVar(master=self, value=TEMPLATE_CATEGORIES[0])
        category_combo = ttk.Combobox(
            cat_frame,
            textvariable=self._category_var,
            values=TEMPLATE_CATEGORIES,
            state="readonly",
            width=37,
        )
        category_combo.pack(fill=tk.X)

    def _create_signature_section(self) -> None:
        """Создаёт секцию подписи шаблона."""
        sig_frame = ttk.LabelFrame(self._content_frame, text=" Security ", padding="10")
        sig_frame.pack(fill=tk.X, pady=(0, 10))

        self._sign_var = tk.BooleanVar(master=self, value=False)
        sign_cb = ttk.Checkbutton(
            sig_frame,
            text="🔏 Sign template (Ed25519 digital signature)",
            variable=self._sign_var,
            command=self._on_sign_toggle,
        )
        sign_cb.pack(anchor="w")

        self._sig_info_label = ttk.Label(
            sig_frame,
            text="Signature ensures template integrity when distributing",
            font=("Helvetica", 8),
            foreground="gray",
            wraplength=500,
        )
        self._sig_info_label.pack(anchor="w", padx=(20, 0), pady=(5, 0))

    def _create_floppy_section(self) -> None:
        """Создаёт секцию предпросмотра оптимизации для дискеты."""
        floppy_frame = ttk.LabelFrame(
            self._content_frame, text=" Floppy Optimization ", padding="10"
        )
        floppy_frame.pack(fill=tk.X, pady=(0, 10))

        # Original size
        self._original_size_var = tk.StringVar(master=self, value="Original size: calculating...")
        ttk.Label(floppy_frame, textvariable=self._original_size_var).pack(anchor="w", pady=2)

        # Optimized size
        self._optimized_size_var = tk.StringVar(master=self, value="Optimized: -")
        ttk.Label(
            floppy_frame,
            textvariable=self._optimized_size_var,
            foreground=COLOR_SUCCESS,
        ).pack(anchor="w", pady=2)

        # Savings
        self._savings_var = tk.StringVar(master=self, value="Savings: -")
        ttk.Label(
            floppy_frame,
            textvariable=self._savings_var,
            foreground=COLOR_SUCCESS,
        ).pack(anchor="w", pady=2)

        # Status
        self._floppy_status_var = tk.StringVar(master=self, value="Status: analyzing...")
        self._floppy_status_label = ttk.Label(
            floppy_frame,
            textvariable=self._floppy_status_var,
            font=("Helvetica", 9, "bold"),
        )
        self._floppy_status_label.pack(anchor="w", pady=(5, 0))

    def _create_export_location_section(self) -> None:
        """Создаёт секцию выбора места сохранения."""
        loc_frame = ttk.LabelFrame(self._content_frame, text=" Save Location ", padding="10")
        loc_frame.pack(fill=tk.X, pady=(0, 10))

        path_frame = ttk.Frame(loc_frame)
        path_frame.pack(fill=tk.X)

        self._path_var = tk.StringVar(master=self, value="")
        path_entry = ttk.Entry(path_frame, textvariable=self._path_var, state="readonly")
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        browse_btn = ttk.Button(path_frame, text="Browse...", command=self._on_browse)
        browse_btn.pack(side=tk.RIGHT)

    def _create_buttons(self) -> None:
        """Создаёт панель кнопок."""
        btn_frame = ttk.Frame(self._content_frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        # Cancel button
        ttk.Button(btn_frame, text="Cancel", command=self._on_cancel).pack(
            side=tk.RIGHT, padx=(10, 0)
        )

        # Export button
        self._export_btn = ttk.Button(
            btn_frame,
            text="📤 Export",
            command=self._on_export,
        )
        self._export_btn.pack(side=tk.RIGHT)

    def _on_sign_toggle(self) -> None:
        """Обработчик переключения подписи."""
        if self._sign_var.get():
            self._sig_info_label.config(foreground=COLOR_SUCCESS)
        else:
            self._sig_info_label.config(foreground="gray")
        self._calculate_size()

    def _on_browse(self) -> None:
        """Обработчик кнопки 'Обзор'."""
        filename = filedialog.asksaveasfilename(
            parent=self,
            title="Save Template",
            defaultextension=".fxstpl",
            filetypes=[("FX Templates", "*.fxstpl"), ("All Files", "*.*")],
            initialfile=f"{self._name_var.get() or 'template'}.fxstpl",
        )

        if filename:
            self._path_var.set(filename)

    def _calculate_size(self) -> None:
        """Вычисляет размер шаблона и обновляет UI."""
        try:
            # Create temporary template to estimate size
            temp_template = self._create_template_object()
            template_dict = temp_template.to_dict()
            json_data = json.dumps(template_dict, indent=2, ensure_ascii=False)
            self._original_size = len(json_data.encode("utf-8"))

            # Estimate optimized size
            analysis = self._floppy_optimizer.analyze(json_data.encode("utf-8"))
            self._optimized_size = analysis.optimized_size

            self._update_floppy_ui(analysis)

        except Exception as e:
            logger.warning(f"Failed to calculate template size: {e}")
            self._original_size = 0
            self._optimized_size = 0

    def _update_floppy_ui(self, analysis: Any) -> None:
        """Обновляет UI секции floppy optimizer.

        Args:
            analysis: Результат анализа от FloppyOptimizer.
        """
        # Original size
        orig_mb = self._original_size / (1024 * 1024)
        self._original_size_var.set(
            f"Original size: {self._original_size:,} bytes ({orig_mb:.2f} MB)"
        )

        # Optimized size
        opt_mb = analysis.optimized_size / (1024 * 1024)
        self._optimized_size_var.set(
            f"Optimized: {analysis.optimized_size:,} bytes ({opt_mb:.2f} MB)"
        )

        # Savings
        savings = self._original_size - analysis.optimized_size
        savings_pct = (savings / self._original_size * 100) if self._original_size > 0 else 0
        self._savings_var.set(f"Savings: {savings:,} bytes ({savings_pct:.1f}%)")

        # Status
        if analysis.fits_on_floppy:
            free_space = MAX_FLOPPY_SIZE - analysis.optimized_size
            self._floppy_status_var.set(f"✅ Fits on floppy ({free_space:,} bytes free)")
            self._floppy_status_label.config(foreground=COLOR_SUCCESS)
        else:
            overflow = analysis.optimized_size - MAX_FLOPPY_SIZE
            self._floppy_status_var.set(f"❌ Exceeds limit by {overflow:,} bytes")
            self._floppy_status_label.config(foreground=COLOR_ERROR)

    def _create_template_object(self) -> FormTemplate:
        """Создаёт объект FormTemplate из данных формы.

        Returns:
            Объект FormTemplate.
        """
        import uuid
        from datetime import datetime

        # Get description from text widget
        self._desc_text.get("1.0", tk.END).strip()

        # Build template from form data
        template = FormTemplate(
            template_id=str(uuid.uuid4()),
            name=self._name_var.get() or "template",
            name_ru=self._name_var.get() or "шаблон",
            version=self._version_var.get() or "1.0.0",
            doc_type=self._form_data.get("doc_type", ""),
            pages=self._form_data.get("pages", []),
            created_at=datetime.now().isoformat(),
            modified_at=datetime.now().isoformat(),
            author=self._author_var.get() or None,
            is_special_blank=self._sign_var.get(),
            signature=None,  # Will be set during save if signed
        )

        return template

    def _validate_inputs(self) -> Optional[str]:
        """Валидирует введённые данные.

        Returns:
            Сообщение об ошибке или None если всё валидно.
        """
        name = self._name_var.get().strip()
        if not name:
            return "Template name is required"

        version = self._version_var.get().strip()
        if not version:
            return "Version is required"

        # Semantic versioning validation
        if not re.match(r"^\d+\.\d+\.\d+$", version):
            return "Version must match semver format (X.Y.Z)"

        path_str = self._path_var.get()
        if not path_str:
            return "Select a save location"

        return None

    def _on_export(self) -> None:
        """Обработчик кнопки 'Экспортировать'."""
        # Validate inputs
        error = self._validate_inputs()
        if error:
            messagebox.showerror("Validation Error", error, parent=self)
            return

        try:
            # Create template
            template = self._create_template_object()

            # Get export path
            export_path = Path(self._path_var.get())

            # Sign if requested
            signed = self._sign_var.get()
            if signed:
                template.is_special_blank = True
                # Signing will be done by TemplateManager.save_template

            # Save template
            saved_path = self._template_manager.save_template(
                template=template,
                is_special_blank=signed,
                validate=True,
            )

            # If user selected different path, copy there
            if saved_path != export_path:
                import shutil

                shutil.copy(saved_path, export_path)
                saved_path = export_path

            # Create result
            self._result = ExportResult(
                path=saved_path,
                signed=signed,
                template_name=template.name,
                version=template.version,
            )

            logger.info(f"Template exported: {saved_path}, signed={signed}")
            self.destroy()

        except Exception as e:
            logger.error(f"Template export failed: {e}")
            messagebox.showerror("Export Error", f"Failed to export template:\n{e}", parent=self)

    def _on_cancel(self) -> None:
        """Обработчик кнопки 'Отмена'."""
        self._result = None
        self.destroy()

    def show(self) -> Optional[ExportResult]:
        """Показывает диалог и возвращает результат.

        Returns:
            ExportResult или None если отменено.
        """
        self.wait_window()
        return self._result

    def get_estimated_size(self) -> tuple[int, int]:
        """Возвращает оценочные размеры шаблона.

        Returns:
            Кортеж (original_size, optimized_size).
        """
        return (self._original_size, self._optimized_size)

    def set_export_path(self, path: Path) -> None:
        """Устанавливает путь экспорта programmatically.

        Args:
            path: Путь для сохранения.
        """
        self._path_var.set(str(path))

    def enable_signature(self, enabled: bool = True) -> None:
        """Включает/выключает опцию подписи.

        Args:
            enabled: True для включения подписи.
        """
        self._sign_var.set(enabled)
        self._on_sign_toggle()


__all__ = [
    "ExportResult",
    "TemplateExportDialog",
]
