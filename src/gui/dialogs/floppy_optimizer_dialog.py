"""Диалог оптимизации шаблонов для дискеты 3.5" (1.44 MB).

Модуль реализует FloppyOptimizerDialog — UI для анализа и оптимизации
размера шаблонов форм для сохранения на дискету.

Key Features:
    - Интерактивный расчёт экономии при изменении опций
    - Визуальное отображение статуса (✅/❌)
    - Progress bar для длительных операций
    - Интеграция с FloppyOptimizerProtocol

Example:
    >>> from src.gui.dialogs.floppy_optimizer_dialog import FloppyOptimizerDialog
    >>> dialog = FloppyOptimizerDialog(parent, template_bytes)
    >>> success, optimized_data = dialog.show()

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, cast

from src.gui.dialogs.base_dialog import BaseDialog

logger = logging.getLogger(__name__)

# Forward imports for type checking
if TYPE_CHECKING:
    pass


# =============================================================================
# CONSTANTS
# =============================================================================

COLOR_BG: str = "#f5f5f5"
COLOR_SUCCESS: str = "#2ecc71"
COLOR_ERROR: str = "#e74c3c"
COLOR_WARNING: str = "#f39c12"
COLOR_TEXT: str = "#2c3e50"

FONTS: dict[str, tuple[str, int, str]] = {
    "header": ("Helvetica", 14, "bold"),
    "normal": ("Helvetica", 10, "normal"),
    "small": ("Helvetica", 9, "normal"),
    "mono": ("Courier", 10, "normal"),
}


# =============================================================================
# DATACLASSES
# =============================================================================


@dataclass
class OptimizationOptions:
    """Опции оптимизации для расчёта размера.

    Attributes:
        remove_thumbnails: Удалить миниатюры превью.
        compact_json: Использовать компактный JSON без пробелов.
        use_ed25519: Использовать Ed25519 вместо ML-DSA-65.
        remove_descriptions: Удалить описания полей.

    Example:
        >>> opts = OptimizationOptions(remove_thumbnails=True, compact_json=True)
        >>> opts.to_method_set()
        {'remove_thumbnails', 'compact_json'}
    """

    remove_thumbnails: bool = True
    compact_json: bool = True
    use_ed25519: bool = True
    remove_descriptions: bool = False

    def to_method_set(self) -> set[str]:
        """Конвертирует опции в множество строковых идентификаторов.

        Returns:
            Множество активных методов оптимизации.
        """
        methods: set[str] = set()
        if self.compact_json:
            methods.add("compact_json")
        if self.use_ed25519:
            methods.add("ed25519")
        if self.remove_descriptions:
            methods.add("remove_descriptions")
        if self.remove_thumbnails:
            methods.add("remove_thumbnails")
        return methods


@dataclass
class EstimatedSavings:
    """Результат расчёта экономии.

    Attributes:
        original_size: Исходный размер в байтах.
        optimized_size: Оптимизированный размер в байтах.
        active_methods: Активные методы оптимизации.
        target_bytes: Целевой размер (по умолчанию MAX_FLOPPY_BYTES).

    Example:
        >>> savings = EstimatedSavings(
        ...     original_size=2_000_000,
        ...     optimized_size=1_200_000,
        ...     active_methods=["compact_json"],
        ... )
        >>> savings.savings_percent
        40.0
    """

    original_size: int
    optimized_size: int
    active_methods: list[str] = field(default_factory=list)
    target_bytes: int = 1_340_000

    @property
    def savings_bytes(self) -> int:
        """Экономия в байтах.

        Returns:
            original_size - optimized_size.
        """
        return self.original_size - self.optimized_size

    @property
    def savings_percent(self) -> float:
        """Экономия в процентах.

        Returns:
            Процент экономии (0.0-100.0).
        """
        if self.original_size == 0:
            return 0.0
        return ((self.original_size - self.optimized_size) / self.original_size) * 100

    @property
    def fits_on_floppy(self) -> bool:
        """Проверяет, помещается ли результат на дискету.

        Returns:
            True если optimized_size <= target_bytes.
        """
        return self.optimized_size <= self.target_bytes


# =============================================================================
# MAIN DIALOG CLASS
# =============================================================================


class FloppyOptimizerDialog(BaseDialog):
    """Диалог оптимизации шаблона для дискеты (1.44MB).

    Проверяет размер шаблона и предлагает оптимизации:
    - Удаление миниатюр
    - Компактный JSON
    - Ed25519 подпись вместо ML-DSA-65
    - Удаление описаний полей

    Attributes:
        MAX_FLOPPY_BYTES: Максимальный размер (~1.28MB полезной нагрузки).

    Example:
        >>> dialog = FloppyOptimizerDialog(parent, template_data)
        >>> success, optimized_data = dialog.show()
        >>> if success:
        ...     print(f"Оптимизировано: {len(optimized_data)} bytes")

    Note:
        Интегрируется с FloppyOptimizerProtocol для реальной оптимизации.
    """

    MAX_FLOPPY_BYTES: int = 1_340_000
    """Максимальный размер данных для дискеты 3.5" (~1.28 MB)."""

    def __init__(
        self,
        parent: tk.Widget,
        template_data: bytes,
        optimizer: Optional[Any] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """Инициализация диалога оптимизации.

        Args:
            parent: Родительский виджет.
            template_data: Данные шаблона для оптимизации.
            optimizer: Опциональный экземпляр FloppyOptimizer.
            *args: Дополнительные аргументы для Toplevel.
            **kwargs: Дополнительные kwargs для Toplevel.
        """
        super().__init__(parent, *args, modal=True, **kwargs)

        self._parent: tk.Widget = parent
        self._original_data: bytes = template_data
        self._optimizer: Optional[Any] = optimizer
        self._optimized_data: Optional[bytes] = None
        self._result: bool = False

        # Current options state
        self._options = OptimizationOptions()

        # Create UI components
        self._create_ui()
        self._setup_window()
        self._analyze()

    def _setup_window(self) -> None:
        """Настраивает параметры окна."""
        self.title("Floppy Optimizer")
        self.geometry("500x480")
        self.minsize(450, 400)

    def _create_ui(self) -> None:
        """Создаёт UI диалога."""
        # Main container with padding
        main_frame = tk.Frame(self, bg=COLOR_BG)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Header
        self._create_header(main_frame)

        # Size info panel
        self._create_size_panel(main_frame)

        # Optimizations panel
        self._create_optimizations_panel(main_frame)

        # Status panel
        self._create_status_panel(main_frame)

        # Progress bar
        self._create_progress_bar(main_frame)

        # Buttons
        self._create_buttons(main_frame)

    def _create_header(self, parent: tk.Widget) -> None:
        """Создаёт заголовок диалога.

        Args:
            parent: Родительский виджет.
        """
        header_frame = tk.Frame(parent, bg=COLOR_BG)
        header_frame.pack(fill=tk.X, pady=(0, 15))

        header = tk.Label(
            header_frame,
            text="💾 Floppy Optimizer",
            font=FONTS["header"],
            bg=COLOR_BG,
            fg=COLOR_TEXT,
        )
        header.pack(anchor="w")

        desc = tk.Label(
            header_frame,
            text='Оптимизация шаблона для сохранения на дискету 3.5"',
            font=FONTS["small"],
            bg=COLOR_BG,
            fg="#666666",
        )
        desc.pack(anchor="w")

    def _create_size_panel(self, parent: tk.Widget) -> None:
        """Создаёт панель информации о размере.

        Args:
            parent: Родительский виджет.
        """
        size_frame = tk.LabelFrame(
            parent,
            text=" Информация о размере ",
            font=FONTS["normal"],
            bg=COLOR_BG,
            fg=COLOR_TEXT,
        )
        size_frame.pack(fill=tk.X, pady=(0, 10), ipady=5)

        # Current size
        self._current_var = tk.StringVar(master=self, value="Current size: calculating...")
        current_label = tk.Label(
            size_frame,
            textvariable=self._current_var,
            font=FONTS["normal"],
            bg=COLOR_BG,
            fg=COLOR_TEXT,
            anchor="w",
        )
        current_label.pack(fill=tk.X, padx=10, pady=(5, 2))

        # Optimized size
        self._optimized_var = tk.StringVar(master=self, value="After optimization: -")
        optimized_label = tk.Label(
            size_frame,
            textvariable=self._optimized_var,
            font=FONTS["normal"],
            bg=COLOR_BG,
            fg=COLOR_SUCCESS,
            anchor="w",
        )
        optimized_label.pack(fill=tk.X, padx=10, pady=2)

        # Savings
        self._savings_var = tk.StringVar(master=self, value="Savings: -")
        savings_label = tk.Label(
            size_frame,
            textvariable=self._savings_var,
            font=FONTS["normal"],
            bg=COLOR_BG,
            fg=COLOR_SUCCESS,
            anchor="w",
        )
        savings_label.pack(fill=tk.X, padx=10, pady=(2, 5))

    def _create_optimizations_panel(self, parent: tk.Widget) -> None:
        """Создаёт панель опций оптимизации.

        Args:
            parent: Родительский виджет.
        """
        opt_frame = tk.LabelFrame(
            parent,
            text=" Оптимизации ",
            font=FONTS["normal"],
            bg=COLOR_BG,
            fg=COLOR_TEXT,
        )
        opt_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10), ipady=5)

        # Remove thumbnails
        self._thumbnails_var = tk.BooleanVar(master=self, value=self._options.remove_thumbnails)
        thumbnails_cb = tk.Checkbutton(
            opt_frame,
            text="[✓] Remove thumbnails",
            variable=self._thumbnails_var,
            command=self._on_thumbnails_toggle,
            font=FONTS["normal"],
            bg=COLOR_BG,
            fg=COLOR_TEXT,
            selectcolor=COLOR_BG,
            activebackground=COLOR_BG,
            anchor="w",
        )
        thumbnails_cb.pack(fill=tk.X, padx=10, pady=3)

        # Compact JSON
        self._json_var = tk.BooleanVar(master=self, value=self._options.compact_json)
        json_cb = tk.Checkbutton(
            opt_frame,
            text="[✓] Compact JSON",
            variable=self._json_var,
            command=self._on_json_toggle,
            font=FONTS["normal"],
            bg=COLOR_BG,
            fg=COLOR_TEXT,
            selectcolor=COLOR_BG,
            activebackground=COLOR_BG,
            anchor="w",
        )
        json_cb.pack(fill=tk.X, padx=10, pady=3)

        # Use Ed25519 signature
        self._signature_var = tk.BooleanVar(master=self, value=self._options.use_ed25519)
        signature_cb = tk.Checkbutton(
            opt_frame,
            text="[✓] Use Ed25519 signature (64 B vs 3,309 B)",
            variable=self._signature_var,
            command=self._on_signature_toggle,
            font=FONTS["normal"],
            bg=COLOR_BG,
            fg=COLOR_TEXT,
            selectcolor=COLOR_BG,
            activebackground=COLOR_BG,
            anchor="w",
        )
        signature_cb.pack(fill=tk.X, padx=10, pady=3)

        # Remove field descriptions
        self._descriptions_var = tk.BooleanVar(master=self, value=self._options.remove_descriptions)
        descriptions_cb = tk.Checkbutton(
            opt_frame,
            text="[ ] Remove field descriptions",
            variable=self._descriptions_var,
            command=self._on_descriptions_toggle,
            font=FONTS["normal"],
            bg=COLOR_BG,
            fg=COLOR_TEXT,
            selectcolor=COLOR_BG,
            activebackground=COLOR_BG,
            anchor="w",
        )
        descriptions_cb.pack(fill=tk.X, padx=10, pady=3)

    def _create_status_panel(self, parent: tk.Widget) -> None:
        """Создаёт панель статуса.

        Args:
            parent: Родительский виджет.
        """
        self._status_var = tk.StringVar(master=self, value="Status: analyzing...")
        status_label = tk.Label(
            parent,
            textvariable=self._status_var,
            font=FONTS["normal"],
            bg=COLOR_BG,
            fg=COLOR_TEXT,
            anchor="w",
        )
        status_label.pack(fill=tk.X, pady=(0, 10))

    def _create_progress_bar(self, parent: tk.Widget) -> None:
        """Создаёт прогресс-бар.

        Args:
            parent: Родительский виджет.
        """
        self._progress_var = tk.DoubleVar(master=self, value=0.0)
        self._progress = tk.Scale(
            parent,
            from_=0,
            to=100,
            orient=tk.HORIZONTAL,
            variable=self._progress_var,
            bg=COLOR_BG,
            highlightthickness=0,
            state=tk.DISABLED,
            showvalue=False,
            troughcolor="#e0e0e0",
        )
        self._progress.pack(fill=tk.X, pady=(0, 15))
        self._progress.pack_forget()  # Hidden by default

    def _create_buttons(self, parent: tk.Widget) -> None:
        """Создаёт панель кнопок.

        Args:
            parent: Родительский виджет.
        """
        btn_frame = tk.Frame(parent, bg=COLOR_BG)
        btn_frame.pack(fill=tk.X)

        # Cancel button (left)
        cancel_btn = tk.Button(
            btn_frame,
            text="❌ Cancel",
            command=self._on_cancel,
            font=FONTS["normal"],
            bg="#e0e0e0",
            fg=COLOR_TEXT,
            relief=tk.RAISED,
            bd=1,
            padx=15,
            pady=5,
        )
        cancel_btn.pack(side=tk.RIGHT, padx=(5, 0))

        # Export button (center-right)
        self._export_btn = tk.Button(
            btn_frame,
            text="📥 Export",
            command=self._on_export,
            font=FONTS["normal"],
            bg="#3498db",
            fg="white",
            relief=tk.RAISED,
            bd=1,
            padx=15,
            pady=5,
            state=tk.DISABLED,
        )
        self._export_btn.pack(side=tk.RIGHT, padx=5)

        # Optimize button (center)
        self._optimize_btn = tk.Button(
            btn_frame,
            text="💾 Optimize",
            command=self._on_optimize,
            font=FONTS["normal"],
            bg="#2ecc71",
            fg="white",
            relief=tk.RAISED,
            bd=1,
            padx=15,
            pady=5,
        )
        self._optimize_btn.pack(side=tk.RIGHT, padx=5)

    # =============================================================================
    # EVENT HANDLERS
    # =============================================================================

    def _on_thumbnails_toggle(self) -> None:
        """Обработчик переключения удаления миниатюр."""
        self._options.remove_thumbnails = self._thumbnails_var.get()
        self._recalculate()

    def _on_json_toggle(self) -> None:
        """Обработчик переключения компактного JSON."""
        self._options.compact_json = self._json_var.get()
        self._recalculate()

    def _on_signature_toggle(self) -> None:
        """Обработчик переключения Ed25519 подписи."""
        self._options.use_ed25519 = self._signature_var.get()
        self._recalculate()

    def _on_descriptions_toggle(self) -> None:
        """Обработчик переключения удаления описаний полей."""
        self._options.remove_descriptions = self._descriptions_var.get()
        self._recalculate()

    def _on_optimize(self) -> None:
        """Обработчик кнопки Optimize — применяет оптимизации."""
        self._set_busy(True)
        self._show_progress()
        self._update_progress(0)

        try:
            # Try to use real optimizer if available
            if self._optimizer is not None:
                optimized, result = self._apply_real_optimization()
            else:
                # Fallback to estimation-based optimization
                optimized = self._apply_estimated_optimization()

            self._optimized_data = optimized
            self._result = True
            self._update_progress(100)
            self.destroy()

        except Exception as e:
            logger.error(f"Optimization failed: {e}")
            self._status_var.set(f"❌ Error: {e}")
            self._set_busy(False)
            self._hide_progress()

    def _on_export(self) -> None:
        """Обработчик кнопки Export — открывает диалог сохранения."""
        from tkinter import filedialog

        if self._optimized_data is None:
            # Optimize first
            self._on_optimize()
            if not self._result:
                return

        filename = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=".fxstpl",
            filetypes=[("FX Template", "*.fxstpl"), ("All files", "*.*")],
            title="Export optimized template",
        )

        if filename and self._optimized_data is not None:
            try:
                Path(filename).write_bytes(self._optimized_data)
                self._status_var.set(f"✅ Saved to {Path(filename).name}")
            except Exception as e:
                self._status_var.set(f"❌ Save failed: {e}")

    def _on_cancel(self) -> None:
        """Обработчик кнопки Cancel — закрывает диалог."""
        self._result = False
        self._optimized_data = None
        self.destroy()

    # =============================================================================
    # CORE LOGIC
    # =============================================================================

    def _analyze(self) -> None:
        """Анализирует текущий размер и обновляет UI."""
        original_size = len(self._original_data)
        current_mb = original_size / (1024 * 1024)
        self._current_var.set(f"Current size: {original_size:,} bytes ({current_mb:.2f} MB)")

        self._recalculate()

    def _recalculate(self) -> None:
        """Пересчитывает оптимизированный размер на основе опций."""
        estimation = self._estimate_savings()

        # Update optimized size label
        optimized_mb = estimation.optimized_size / (1024 * 1024)
        self._optimized_var.set(
            f"After optimization: {estimation.optimized_size:,} bytes ({optimized_mb:.2f} MB)"
        )

        # Update savings label
        savings_mb = estimation.savings_bytes / (1024 * 1024)
        self._savings_var.set(
            f"Savings: {estimation.savings_bytes:,} bytes "
            f"({savings_mb:.2f} MB, {estimation.savings_percent:.1f}%)"
        )

        # Update status
        if estimation.fits_on_floppy:
            free_space = self.MAX_FLOPPY_BYTES - estimation.optimized_size
            self._status_var.set(f"✅ Fits on floppy ({free_space:,} bytes free)")
            self._optimize_btn.config(state=tk.NORMAL)
            self._export_btn.config(state=tk.NORMAL)
        else:
            overflow = estimation.optimized_size - self.MAX_FLOPPY_BYTES
            self._status_var.set(f"❌ Exceeds floppy by {overflow:,} bytes")
            self._optimize_btn.config(state=tk.DISABLED)
            self._export_btn.config(state=tk.DISABLED)

    def _estimate_savings(self) -> EstimatedSavings:
        """Оценивает экономию на основе выбранных опций.

        Returns:
            EstimatedSavings с результатами расчёта.
        """
        original_size = len(self._original_data)
        savings = 0
        active_methods: list[str] = []

        # Remove thumbnails (~20% of template size if present)
        if self._options.remove_thumbnails:
            thumb_savings = int(original_size * 0.15)
            savings += thumb_savings
            active_methods.append("remove_thumbnails")

        # Compact JSON (~15-30% savings on JSON data)
        if self._options.compact_json:
            json_savings = int(original_size * 0.20)
            savings += json_savings
            active_methods.append("compact_json")

        # Ed25519 vs ML-DSA-65 (3,309 - 64 = 3,245 bytes saved)
        if self._options.use_ed25519:
            sig_savings = 3245
            savings += sig_savings
            active_methods.append("ed25519")

        # Remove descriptions (~10% of field data)
        if self._options.remove_descriptions:
            desc_savings = int(original_size * 0.10)
            savings += desc_savings
            active_methods.append("remove_descriptions")

        # Cap savings at original size
        savings = min(savings, original_size - 100)  # Keep at least 100 bytes
        optimized_size = original_size - savings

        return EstimatedSavings(
            original_size=original_size,
            optimized_size=optimized_size,
            active_methods=active_methods,
            target_bytes=self.MAX_FLOPPY_BYTES,
        )

    def _apply_real_optimization(self) -> tuple[bytes, Any]:
        """Применяет реальную оптимизацию через FloppyOptimizer.

        Returns:
            Кортеж (optimized_data, result).

        Raises:
            RuntimeError: Если оптимизация невозможна.
        """
        if self._optimizer is None:
            raise RuntimeError("Optimizer not available")

        # Import here to avoid circular imports
        from src.services.protocols.template_security import (
            OptimizationType,
        )

        # Map options to allowed methods
        allowed_methods: set[OptimizationType] = set()
        if self._options.compact_json:
            allowed_methods.add(OptimizationType.USE_COMPACT_FORMAT)
        if self._options.remove_descriptions:
            allowed_methods.add(OptimizationType.TRUNCATE_METADATA)

        # Always allow compression
        allowed_methods.add(OptimizationType.COMPRESSION)

        result = self._optimizer.optimize(
            self._original_data,
            target_size=self.MAX_FLOPPY_BYTES,
            allowed_methods=allowed_methods,
        )
        return cast(tuple[bytes, Any], result)

    def _apply_estimated_optimization(self) -> bytes:
        """Применяет базовую оптимизацию на основе оценки.

        Returns:
            Оптимизированные данные.
        """
        import gzip
        import json

        estimation = self._estimate_savings()

        # Try to parse as JSON for field modifications
        try:
            data = json.loads(self._original_data)

            # Remove field descriptions if requested
            if self._options.remove_descriptions:
                for page in data.get("pages", []):
                    for field in page.get("fields", []):
                        field.pop("help_text", None)
                        field.pop("description", None)

            # Compact JSON format
            if self._options.compact_json:
                json_str = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
            else:
                json_str = json.dumps(data, ensure_ascii=False)

            result = json_str.encode("utf-8")
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Not JSON data, try compression
            result = self._original_data

        # Apply compression
        result = gzip.compress(result, compresslevel=6)

        # Verify size matches estimation
        if len(result) > estimation.optimized_size * 1.2:
            # Fallback to simple compression
            result = gzip.compress(self._original_data, compresslevel=9)

        return result

    # =============================================================================
    # UI HELPERS
    # =============================================================================

    def _set_busy(self, busy: bool) -> None:
        """Устанавливает состояние "занят" для UI.

        Args:
            busy: True для блокировки кнопок, False для разблокировки.
        """
        state: str = tk.DISABLED if busy else tk.NORMAL
        self._optimize_btn.config(state=cast(Any, state))
        self._export_btn.config(state=cast(Any, state))

    def _show_progress(self) -> None:
        """Показывает прогресс-бар."""
        self._progress.pack(fill=tk.X, pady=(0, 15), before=self._optimize_btn.master)

    def _hide_progress(self) -> None:
        """Скрывает прогресс-бар."""
        self._progress.pack_forget()

    def _update_progress(self, value: float) -> None:
        """Обновляет значение прогресс-бара.

        Args:
            value: Значение от 0 до 100.
        """
        self._progress_var.set(value)
        self.update_idletasks()

    # =============================================================================
    # PUBLIC API
    # =============================================================================

    def show(self) -> tuple[bool, Optional[bytes]]:
        """Показывает диалог и возвращает результат.

        Returns:
            Кортеж (success, optimized_data).
            success: True если оптимизация выполнена успешно.
            optimized_data: Оптимизированные данные или None.

        Example:
            >>> dialog = FloppyOptimizerDialog(parent, data)
            >>> success, optimized = dialog.show()
            >>> if success:
            ...     print(f"Optimized: {len(optimized)} bytes")
        """
        self.wait_window()
        return (self._result, self._optimized_data if self._result else None)

    def get_estimated_savings(self) -> EstimatedSavings:
        """Возвращает текущую оценку экономии.

        Returns:
            EstimatedSavings с текущими опциями.
        """
        return self._estimate_savings()

    def set_options(self, options: OptimizationOptions) -> None:
        """Устанавливает опции оптимизации programmatically.

        Args:
            options: Новые опции оптимизации.
        """
        self._options = options
        self._thumbnails_var.set(options.remove_thumbnails)
        self._json_var.set(options.compact_json)
        self._signature_var.set(options.use_ed25519)
        self._descriptions_var.set(options.remove_descriptions)
        self._recalculate()


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "FloppyOptimizerDialog",
    "OptimizationOptions",
    "EstimatedSavings",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-04-11"
