"""Диалоги для работы с QR-кодами.

Компоненты:
- QRCodeSettingsDialog: Диалог настроек QR-кода
- QRDataInputDialog: Расширенный ввод данных с поддержкой валидации

Поддерживаемые возможности:
    - Уровень коррекции ошибок (L, M, Q, H)
    - Версия QR-кода (1-40, auto)
    - Размер модуля (box_size)
    - Граница (border)
    - Предпросмотр с реальным рендерингом
    - Экспорт в PNG

Example:
    >>> from src.gui.dialogs.qr_code_dialog import QRCodeSettingsDialog
    >>> from src.gui.dialogs.barcode_dialog import BarcodeMode
    >>> dialog = QRCodeSettingsDialog(parent)
    >>> result = dialog.show()
    >>> if result:
    ...     print(f"Data: {result.data}")
    ...     print(f"Error correction: {result.error_correction}")

Module: src/gui/dialogs/qr_code_dialog.py
Version: 1.0
"""

from __future__ import annotations

import logging
import tkinter as tk
from dataclasses import dataclass
from tkinter import messagebox, ttk
from typing import Any, Final, Optional

from src.gui.dialogs.barcode_dialog import BarcodeMode
from src.gui.dialogs.base_dialog import BaseDialog
from src.gui.themes import get_theme_manager

logger: Final = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

DIALOG_WIDTH: Final[int] = 600
DIALOG_HEIGHT: Final[int] = 650
MIN_DIALOG_WIDTH: Final[int] = 550
MIN_DIALOG_HEIGHT: Final[int] = 500

# QR code specific limits
QR_MAX_DATA_LENGTH: Final[int] = 4296  # Alphanumeric mode, version 40
QR_RECOMMENDED_MAX: Final[int] = 1000  # UX recommendation

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

# Error correction levels with descriptions
ERROR_CORRECTION_LEVELS: Final[list[tuple[str, str, str]]] = [
    ("L", "Low", "~7% data recovery"),
    ("M", "Medium", "~15% data recovery"),
    ("Q", "Quartile", "~25% data recovery"),
    ("H", "High", "~30% data recovery"),
]

# QR versions with capacity hints
QR_VERSIONS: Final[list[tuple[str, str]]] = [
    ("auto", "Automatic selection"),
    ("1", "Version 1 (21×21, ~25 alphanumeric chars)"),
    ("2", "Version 2 (25×25, ~47 alphanumeric chars)"),
    ("5", "Version 5 (37×37, ~154 alphanumeric chars)"),
    ("10", "Version 10 (57×57, ~426 alphanumeric chars)"),
    ("20", "Version 20 (97×97, ~1390 alphanumeric chars)"),
    ("30", "Version 30 (137×137, ~2700 alphanumeric chars)"),
    ("40", "Version 40 (177×177, ~4296 alphanumeric chars)"),
]

# Default box sizes (pixels per module)
BOX_SIZES: Final[list[int]] = [2, 3, 4, 5, 6, 8, 10]

# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass(frozen=True)
class QRCodeSettings:
    """Настройки QR-кода.

    Attributes:
        data: Данные для кодирования.
        error_correction: Уровень коррекции (L, M, Q, H).
        version: Версия QR (1-40, auto).
        box_size: Размер модуля в пикселях.
        border: Ширина границы в модулях.
        mode: Режим генерации (Software - единственный для QR).

    Example:
        >>> settings = QRCodeSettings(
        ...     data="https://example.com",
        ...     error_correction="M",
        ...     version="auto",
        ...     box_size=4,
        ...     border=4,
        ... )
    """

    data: str = ""
    error_correction: str = "M"
    version: str = "auto"
    box_size: int = 4
    border: int = 4
    mode: BarcodeMode = BarcodeMode.SOFTWARE


@dataclass(frozen=True)
class QRCodeResult:
    """Результат настройки QR-кода.

    Attributes:
        settings: Полные настройки QR-кода.
        export_path: Путь для экспорта (опционально).

    Example:
        >>> result = QRCodeResult(
        ...     settings=QRCodeSettings(data="test"),
        ...     export_path="/tmp/qr.png",
        ... )
    """

    settings: QRCodeSettings
    export_path: Optional[str] = None


# =============================================================================
# DIALOG CLASSES
# =============================================================================


class QRCodeSettingsDialog(BaseDialog):
    """Диалог настроек и генерации QR-кода.

    Предоставляет интерфейс для настройки всех параметров QR-кода,
    предпросмотра с реальным рендерингом, и экспорта в PNG.

    Attributes:
        _settings: Текущие настройки.
        _result: Результат диалога.
        _preview_photo: Ссылка на PhotoImage (для GC).

    Example:
        >>> dialog = QRCodeSettingsDialog(parent)
        >>> result = dialog.show()
        >>> if result:
        ...     print(f"QR Data: {result.settings.data}")
    """

    def __init__(
        self,
        parent: tk.Widget,
        default_data: str = "",
        default_settings: Optional[QRCodeSettings] = None,
    ) -> None:
        """Инициализация диалога настроек QR.

        Args:
            parent: Родительский виджет.
            default_data: Данные по умолчанию.
            default_settings: Настройки по умолчанию.
        """
        super().__init__(parent)

        self._parent: tk.Widget = parent
        self._settings = default_settings or QRCodeSettings(data=default_data)
        self._result: Optional[QRCodeResult] = None
        self._preview_photo: Optional[tk.PhotoImage] = None

        self._theme_manager = get_theme_manager()

        self._create_ui()
        self._setup_window()

    def _setup_window(self) -> None:
        """Настраивает параметры окна диалога."""
        self.title("QR Code Settings")
        self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}")
        self.minsize(MIN_DIALOG_WIDTH, MIN_DIALOG_HEIGHT)

        # Center window
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - (DIALOG_WIDTH // 2)
        y = (self.winfo_screenheight() // 2) - (DIALOG_HEIGHT // 2)
        self.geometry(f"+{x}+{y}")

        # Apply theme
        self._theme_manager.apply_to_widget(self)

        # Protocol for closing

    def _create_ui(self) -> None:
        """Создаёт UI компоненты диалога."""
        self.config(bg=COLOR_BG)

        # Main container with padding
        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        header = ttk.Label(
            main_frame,
            text="QR Code Settings",
            font=("Helvetica", 14, "bold"),
        )
        header.pack(anchor="w", pady=(0, 5))

        desc = ttk.Label(
            main_frame,
            text="Configure QR code parameters and preview result",
            foreground=COLOR_TEXT_SECONDARY,
        )
        desc.pack(anchor="w", pady=(0, 15))

        # Create two columns layout
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        content_frame.columnconfigure(0, weight=1)  # Settings
        content_frame.columnconfigure(1, weight=1)  # Preview

        # Left column: Settings
        settings_frame = self._create_settings_column(content_frame)
        settings_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 15))

        # Right column: Preview
        preview_frame = self._create_preview_column(content_frame)
        preview_frame.grid(row=0, column=1, sticky="nsew")

        # Data length indicator
        self._data_length_var = tk.StringVar(master=self, value="0 characters")
        ttk.Label(
            main_frame,
            textvariable=self._data_length_var,
            foreground=COLOR_TEXT_SECONDARY,
            font=("Helvetica", 9),
        ).pack(anchor="w")

        # Status bar
        self._status_var = tk.StringVar(master=self, value="Ready")
        status_label = ttk.Label(
            main_frame,
            textvariable=self._status_var,
            foreground=COLOR_INFO,
            font=("Helvetica", 9, "italic"),
        )
        status_label.pack(anchor="w", pady=(5, 0))

        # Buttons
        self._create_button_section(main_frame)

    def _create_settings_column(self, parent: ttk.Frame) -> ttk.LabelFrame:
        """Создаёт колонку настроек.

        Args:
            parent: Родительский фрейм.

        Returns:
            Фрейм с настройками.
        """
        frame = ttk.LabelFrame(parent, text="Settings", padding="15")

        # Data input
        ttk.Label(
            frame,
            text="Data:",
            font=("Helvetica", 10, "bold"),
        ).pack(anchor="w", pady=(0, 5))

        self._data_text = tk.Text(
            frame,
            height=4,
            width=30,
            wrap=tk.WORD,
            font=("Helvetica", 10),
            relief=tk.SOLID,
            borderwidth=1,
        )
        self._data_text.pack(fill=tk.X, pady=(0, 10))
        self._data_text.insert("1.0", self._settings.data)
        self._data_text.bind("<KeyRelease>", self._on_data_changed)

        # Error correction
        ttk.Label(
            frame,
            text="Error correction:",
            font=("Helvetica", 10, "bold"),
        ).pack(anchor="w", pady=(10, 5))

        self._ec_var = tk.StringVar(master=self, value=self._settings.error_correction)
        ec_frame = ttk.Frame(frame)
        ec_frame.pack(fill=tk.X, pady=(0, 5))

        for value, label, desc in ERROR_CORRECTION_LEVELS:
            ttk.Radiobutton(
                ec_frame,
                text=f"{label} ({value}) - {desc}",
                variable=self._ec_var,
                value=value,
                command=self._update_preview,
            ).pack(anchor="w", pady=2)

        # Version selection
        ttk.Label(
            frame,
            text="Version:",
            font=("Helvetica", 10, "bold"),
        ).pack(anchor="w", pady=(15, 5))

        self._version_var = tk.StringVar(master=self, value=self._settings.version)
        version_combo = ttk.Combobox(
            frame,
            textvariable=self._version_var,
            values=[v[0] for v in QR_VERSIONS],
            state="readonly",
            width=35,
        )
        version_combo.pack(fill=tk.X, pady=(0, 5))

        # Version description
        self._version_desc = ttk.Label(
            frame,
            text="Automatic optimal size selection",
            foreground=COLOR_TEXT_SECONDARY,
            font=("Helvetica", 8),
        )
        self._version_desc.pack(anchor="w", pady=(0, 10))
        version_combo.bind("<<ComboboxSelected>>", self._on_version_changed)

        # Box size and border row
        size_frame = ttk.Frame(frame)
        size_frame.pack(fill=tk.X, pady=(10, 0))

        # Box size
        ttk.Label(size_frame, text="Size:").pack(side=tk.LEFT)
        self._box_size_var = tk.IntVar(master=self, value=self._settings.box_size)
        box_size_spin = ttk.Spinbox(
            size_frame,
            from_=2,
            to=10,
            textvariable=self._box_size_var,
            width=5,
            command=self._update_preview,
        )
        box_size_spin.pack(side=tk.LEFT, padx=(10, 0))
        ttk.Label(size_frame, text="px").pack(side=tk.LEFT)

        # Border
        border_frame = ttk.Frame(frame)
        border_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Label(border_frame, text="Border:").pack(side=tk.LEFT)
        self._border_var = tk.IntVar(master=self, value=self._settings.border)
        border_spin = ttk.Spinbox(
            border_frame,
            from_=1,
            to=8,
            textvariable=self._border_var,
            width=5,
            command=self._update_preview,
        )
        border_spin.pack(side=tk.LEFT, padx=(10, 0))
        ttk.Label(border_frame, text="modules").pack(side=tk.LEFT)

        return frame

    def _create_preview_column(self, parent: ttk.Frame) -> ttk.LabelFrame:
        """Создаёт колонку предпросмотра.

        Args:
            parent: Родительский фрейм.

        Returns:
            Фрейм с предпросмотром.
        """
        frame = ttk.LabelFrame(parent, text="Preview", padding="15")

        # Canvas for preview
        self._preview_canvas = tk.Canvas(
            frame,
            width=250,
            height=250,
            bg=COLOR_CARD_BG,
            relief=tk.SOLID,
            borderwidth=1,
            highlightthickness=0,
        )
        self._preview_canvas.pack(pady=(0, 15))

        # Preview placeholder text
        self._preview_canvas.create_text(
            125,
            125,
            text="Enter data\nfor preview",
            fill=COLOR_TEXT_SECONDARY,
            font=("Helvetica", 10),
            justify=tk.CENTER,
        )

        # QR info frame
        info_frame = ttk.LabelFrame(frame, text="Info", padding="10")
        info_frame.pack(fill=tk.X, pady=(0, 10))

        self._qr_info_var = tk.StringVar(master=self, value="Waiting for data...")
        ttk.Label(
            info_frame,
            textvariable=self._qr_info_var,
            font=("Helvetica", 9),
        ).pack(anchor="w")

        # Warning label for large data
        self._size_warning_var = tk.StringVar(master=self, value="")
        self._size_warning = ttk.Label(
            frame,
            textvariable=self._size_warning_var,
            foreground=COLOR_WARNING,
            font=("Helvetica", 8, "bold"),
            wraplength=250,
        )
        self._size_warning.pack(anchor="w")

        return frame

    def _create_button_section(self, parent: ttk.Frame) -> None:
        """Создаёт секцию кнопок.

        Args:
            parent: Родительский фрейм.
        """
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X)

        # Export button (left)
        self._export_btn = ttk.Button(
            btn_frame,
            text="Export PNG",
            command=self._on_export,
            state=tk.DISABLED,
        )
        self._export_btn.pack(side=tk.LEFT)

        # Update preview button
        self._update_btn = ttk.Button(
            btn_frame,
            text="Update",
            command=self._update_preview,
        )
        self._update_btn.pack(side=tk.LEFT, padx=(10, 0))

        # Cancel button (right)
        ttk.Button(
            btn_frame,
            text="Cancel",
            command=self._on_cancel,
        ).pack(side=tk.RIGHT)

        # Insert button (right)
        self._insert_btn = ttk.Button(
            btn_frame,
            text="Insert",
            command=self._on_insert,
            state=tk.DISABLED,
        )
        self._insert_btn.pack(side=tk.RIGHT, padx=(0, 10))

    def _on_data_changed(self, event: Optional[tk.Event] = None) -> None:
        """Обработчик изменения данных.

        Args:
            event: Событие изменения.
        """
        data = self._data_text.get("1.0", tk.END).strip()
        length = len(data)

        # Update length indicator
        self._data_length_var.set(f"{length} characters")

        # Check size limits
        if length > QR_MAX_DATA_LENGTH:
            self._size_warning_var.set(f"⚠️ Exceeded maximum ({QR_MAX_DATA_LENGTH} characters)!")
        elif length > QR_RECOMMENDED_MAX:
            self._size_warning_var.set("💡 Large data volume. High QR version needed.")
        else:
            self._size_warning_var.set("")

        # Auto-update preview if data is not empty
        if data:
            self._after_ids.append(self.after(500, self._update_preview_delayed))

    def _update_preview_delayed(self) -> None:
        """Отложенное обновление предпросмотра (debounce)."""
        self._update_preview()

    def _on_version_changed(self, event: Optional[tk.Event] = None) -> None:
        """Обработчик изменения версии.

        Args:
            event: Событие изменения.
        """
        version = self._version_var.get()
        desc = next(
            (d for v, d in QR_VERSIONS if v == version),
            "Unknown version",
        )
        self._version_desc.config(text=desc)
        self._update_preview()

    def _update_preview(self) -> None:
        """Обновляет предпросмотр QR-кода."""
        data = self._data_text.get("1.0", tk.END).strip()

        if not data:
            self._show_placeholder("Enter data\nfor preview")
            self._export_btn.config(state=tk.DISABLED)
            self._insert_btn.config(state=tk.DISABLED)
            return

        try:
            # Try to generate preview
            preview_image = self._generate_preview(
                data,
                self._ec_var.get(),
                self._version_var.get(),
                self._box_size_var.get(),
                self._border_var.get(),
            )

            if preview_image:
                self._show_image(preview_image)
                self._qr_info_var.set(
                    f"✓ QR code generated\nSize: {preview_image.width}×{preview_image.height} px"
                )
                self._export_btn.config(state=tk.NORMAL)
                self._insert_btn.config(state=tk.NORMAL)
                self._status_var.set("Ready to insert")
            else:
                self._show_placeholder("⚠️ Generation error\nCheck data")
                self._status_var.set("Generation error")

        except Exception as e:
            logger.error(f"QR preview generation error: {e}")
            self._show_placeholder(f"⚠️ Error:\n{str(e)[:50]}")
            self._status_var.set(f"Error: {e}")

    def _generate_preview(
        self,
        data: str,
        error_correction: str,
        version: str,
        box_size: int,
        border: int,
    ) -> Optional[Any]:
        """Генерирует изображение QR-кода для предпросмотра.

        Args:
            data: Данные для кодирования.
            error_correction: Уровень коррекции ошибок.
            version: Версия QR.
            box_size: Размер модуля.
            border: Ширина границы.

        Returns:
            PIL Image или None в случае ошибки.
        """
        try:
            # Lazy import to avoid dependency at module level
            from qrcode import QRCode
            from qrcode.constants import (
                ERROR_CORRECT_H,
                ERROR_CORRECT_L,
                ERROR_CORRECT_M,
                ERROR_CORRECT_Q,
            )

            # Map error correction string to constant
            ec_map = {
                "L": ERROR_CORRECT_L,
                "M": ERROR_CORRECT_M,
                "Q": ERROR_CORRECT_Q,
                "H": ERROR_CORRECT_H,
            }

            # Parse version
            if version == "auto":
                version_num = None
            else:
                version_num = int(version)

            # Create QR code
            qr = QRCode(
                version=version_num,
                error_correction=ec_map.get(error_correction, ERROR_CORRECT_M),
                box_size=box_size,
                border=border,
            )
            qr.add_data(data)
            qr.make(fit=True)

            # Generate image
            img = qr.make_image(fill_color="black", back_color="white")

            # Resize for preview (max 250x250)
            from PIL import Image

            max_size = 250
            if img.width > max_size or img.height > max_size:
                ratio = min(max_size / img.width, max_size / img.height)
                new_size = (int(img.width * ratio), int(img.height * ratio))
                img = img.resize(new_size, Image.LANCZOS)  # type: ignore[attr-defined]

            return img

        except ImportError:
            # qrcode library not available - show placeholder
            logger.warning("qrcode library not available for preview")
            return None
        except Exception as e:
            logger.error(f"QR generation error: {e}")
            return None

    def _show_image(self, image: Any) -> None:
        """Отображает изображение на canvas.

        Args:
            image: PIL Image для отображения.
        """
        # Clear canvas
        self._preview_canvas.delete("all")

        # Convert PIL to PhotoImage
        try:
            from PIL import ImageTk

            self._preview_photo = ImageTk.PhotoImage(image)
        except ImportError:
            logger.warning("ImageTk not available, QR preview disabled")
            self._preview_photo = None
            self._show_placeholder("Preview unavailable\n(requires python3-pillow-tk)")
            return

        # Center image
        cx = self._preview_canvas.winfo_width() // 2 or 125
        cy = self._preview_canvas.winfo_height() // 2 or 125

        self._preview_canvas.create_image(cx, cy, image=self._preview_photo, anchor=tk.CENTER)

    def _show_placeholder(self, text: str) -> None:
        """Показывает placeholder текст.

        Args:
            text: Текст для отображения.
        """
        self._preview_canvas.delete("all")
        self._preview_canvas.create_text(
            125,
            125,
            text=text,
            fill=COLOR_TEXT_SECONDARY,
            font=("Helvetica", 10),
            justify=tk.CENTER,
        )
        self._preview_photo = None

    def _on_export(self) -> None:
        """Обработчик кнопки экспорта."""
        data = self._data_text.get("1.0", tk.END).strip()
        if not data:
            messagebox.showwarning(
                "Warning",
                "Enter data to encode",
                parent=self,
            )
            return

        # File save dialog
        from tkinter import filedialog

        file_path = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=".png",
            filetypes=[
                ("PNG files", "*.png"),
                ("All files", "*.*"),
            ],
            title="Save QR Code",
        )

        if not file_path:
            return

        try:
            # Generate full-size image
            img = self._generate_preview(
                data,
                self._ec_var.get(),
                self._version_var.get(),
                self._box_size_var.get(),
                self._border_var.get(),
            )

            if img:
                # Save original size (without resize for preview)
                from qrcode import QRCode
                from qrcode.constants import (
                    ERROR_CORRECT_H,
                    ERROR_CORRECT_L,
                    ERROR_CORRECT_M,
                    ERROR_CORRECT_Q,
                )

                ec_map = {
                    "L": ERROR_CORRECT_L,
                    "M": ERROR_CORRECT_M,
                    "Q": ERROR_CORRECT_Q,
                    "H": ERROR_CORRECT_H,
                }

                version = self._version_var.get()
                version_num = None if version == "auto" else int(version)

                qr = QRCode(
                    version=version_num,
                    error_correction=ec_map.get(self._ec_var.get(), ERROR_CORRECT_M),
                    box_size=self._box_size_var.get(),
                    border=self._border_var.get(),
                )
                qr.add_data(data)
                qr.make(fit=True)

                full_img = qr.make_image(fill_color="black", back_color="white")
                full_img.save(file_path)

                self._status_var.set(f"Saved: {file_path}")
                messagebox.showinfo(
                    "Success",
                    f"QR code saved:\n{file_path}",
                    parent=self,
                )

        except Exception as e:
            logger.error(f"QR export error: {e}")
            messagebox.showerror(
                "Error",
                f"Failed to save QR code:\n{e}",
                parent=self,
            )

    def _on_insert(self) -> None:
        """Обработчик кнопки вставки."""
        data = self._data_text.get("1.0", tk.END).strip()

        if not data:
            messagebox.showwarning(
                "Warning",
                "Enter data to encode",
                parent=self,
            )
            return

        self._result = QRCodeResult(
            settings=QRCodeSettings(
                data=data,
                error_correction=self._ec_var.get(),
                version=self._version_var.get(),
                box_size=self._box_size_var.get(),
                border=self._border_var.get(),
                mode=BarcodeMode.SOFTWARE,  # QR всегда software mode
            ),
            export_path=None,
        )
        self.destroy()

    def _on_cancel(self) -> None:
        """Обработчик кнопки отмены."""
        self._result = None
        self.destroy()

    def show(self) -> Optional[QRCodeResult]:
        """Показывает диалог и возвращает результат.

        Returns:
            QRCodeResult с настройками или None.
        """
        self.wait_window()
        return self._result
