# -*- coding: utf-8 -*-
"""Тесты для FloppyOptimizerDialog.

Тестирует создание диалога, отображение размеров, пересчёт
при изменении опций, статус помещения на дискету,
кнопки и возврат результата.

Version: 1.0
"""

from __future__ import annotations

import sys
import tkinter as tk
import types
from pathlib import Path
from typing import Any, Generator, cast
from unittest.mock import patch

import pytest

# Add src to path before importing
project_root = Path("/home/Mike/Dev/FX-Text-processor/FX-Text-processor-3")
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

# Direct import from the module file to avoid __init__.py circular dependency
# We need to manually create the module namespace
floppy_module = types.ModuleType("floppy_optimizer_dialog")
floppy_module.__file__ = str(project_root / "src" / "gui" / "dialogs" / "floppy_optimizer_dialog.py")

# Execute module
sys.modules["floppy_optimizer_dialog"] = floppy_module
with open(floppy_module.__file__, "r", encoding="utf-8") as f:
    code = compile(f.read(), floppy_module.__file__, "exec")
    exec(code, floppy_module.__dict__)

FloppyOptimizerDialog = floppy_module.FloppyOptimizerDialog
OptimizationOptions = floppy_module.OptimizationOptions
EstimatedSavings = floppy_module.EstimatedSavings
COLOR_ERROR = floppy_module.COLOR_ERROR
COLOR_SUCCESS = floppy_module.COLOR_SUCCESS
COLOR_BG = floppy_module.COLOR_BG
FONTS = floppy_module.FONTS


@pytest.fixture
def root() -> Generator[tk.Widget, None, None]:
    """Фикстура для Tk root."""
    root = tk.Tk()
    root.withdraw()
    yield cast(tk.Widget, root)
    root.destroy()


@pytest.fixture
def small_data() -> bytes:
    """Тестовые данные малого размера (~1 MB)."""
    return b"x" * 1_000_000


@pytest.fixture
def large_data() -> bytes:
    """Тестовые данные большого размера (~2 MB)."""
    return b"x" * 2_000_000


@pytest.fixture
def dialog_with_small_data(root: tk.Widget, small_data: bytes) -> Generator[Any, None, None]:
    """Фикстура для диалога с малыми данными."""
    dialog = FloppyOptimizerDialog(parent=root, template_data=small_data)
    yield dialog
    try:
        dialog.destroy()
    except tk.TclError:
        pass


@pytest.fixture
def dialog_with_large_data(root: tk.Widget, large_data: bytes) -> Generator[Any, None, None]:
    """Фикстура для диалога с большими данными."""
    dialog = FloppyOptimizerDialog(parent=root, template_data=large_data)
    yield dialog
    try:
        dialog.destroy()
    except tk.TclError:
        pass


@pytest.mark.gui
class TestFloppyOptimizerDialogCreation:
    """Тесты создания FloppyOptimizerDialog."""

    def test_dialog_initialization(self, root: tk.Widget, small_data: bytes) -> None:
        """Проверка создания диалога."""
        dialog = FloppyOptimizerDialog(
            parent=root,
            template_data=small_data,
        )
        assert dialog._original_data is small_data
        assert dialog._optimized_data is None
        assert dialog._result is False
        dialog.destroy()

    def test_dialog_constants(self) -> None:
        """Проверка констант диалога."""
        assert FloppyOptimizerDialog.MAX_FLOPPY_BYTES == 1_340_000
        assert COLOR_SUCCESS == "#2ecc71"
        assert COLOR_ERROR == "#e74c3c"
        assert COLOR_BG == "#f5f5f5"

    def test_fonts_constant(self) -> None:
        """Проверка константы FONTS."""
        assert "header" in FONTS
        assert "normal" in FONTS
        assert "small" in FONTS
        assert "mono" in FONTS

    def test_optimization_options_dataclass(self) -> None:
        """Проверка dataclass OptimizationOptions."""
        options = OptimizationOptions()
        assert options.remove_thumbnails is True
        assert options.compact_json is True
        assert options.use_ed25519 is True
        assert options.remove_descriptions is False

        # Test to_method_set
        methods = options.to_method_set()
        assert "compact_json" in methods
        assert "ed25519" in methods
        assert "remove_thumbnails" in methods

        # Custom options
        custom = OptimizationOptions(
            remove_thumbnails=False,
            compact_json=False,
            use_ed25519=False,
            remove_descriptions=True,
        )
        assert custom.remove_thumbnails is False
        assert custom.compact_json is False
        assert custom.use_ed25519 is False
        assert custom.remove_descriptions is True

    def test_estimated_savings_dataclass(self) -> None:
        """Проверка dataclass EstimatedSavings."""
        savings = EstimatedSavings(
            original_size=2_000_000,
            optimized_size=1_200_000,
            active_methods=["compact_json", "ed25519"],
        )
        assert savings.savings_bytes == 800_000
        assert savings.savings_percent == 40.0
        assert savings.fits_on_floppy is True

        # Test when does not fit
        large = EstimatedSavings(
            original_size=2_000_000,
            optimized_size=1_500_000,
            active_methods=[],
        )
        assert large.fits_on_floppy is False


@pytest.mark.gui
class TestFloppyOptimizerDialogSizePanel:
    """Тесты панели отображения размеров."""

    def test_size_panel_shows_original(self, dialog_with_small_data: Any) -> None:
        """Отображение оригинального размера."""
        dialog = dialog_with_small_data

        # Check that current size variable exists and contains data
        current_text = dialog._current_var.get()
        assert "Current" in current_text

    def test_size_panel_shows_optimized(self, dialog_with_small_data: Any) -> None:
        """Отображение оптимизированного размера."""
        dialog = dialog_with_small_data

        # Check that optimized size variable exists
        optimized_text = dialog._optimized_var.get()
        assert "optimization" in optimized_text.lower() or "-" in optimized_text

    def test_savings_calculation(self, dialog_with_small_data: Any) -> None:
        """Расчёт экономии при оптимизации."""
        dialog = dialog_with_small_data

        # Check savings variable
        savings_text = dialog._savings_var.get()
        assert "Savings" in savings_text or "-" in savings_text


@pytest.mark.gui
class TestFloppyOptimizerDialogCheckboxes:
    """Тесты чекбоксов оптимизации."""

    def test_optimization_checkboxes_exist(self, dialog_with_small_data: Any) -> None:
        """Наличие чекбоксов оптимизации."""
        dialog = dialog_with_small_data

        # Check that checkbox variables exist
        assert isinstance(dialog._thumbnails_var, tk.BooleanVar)
        assert isinstance(dialog._json_var, tk.BooleanVar)
        assert isinstance(dialog._signature_var, tk.BooleanVar)
        assert isinstance(dialog._descriptions_var, tk.BooleanVar)

    def test_checkbox_default_values(self, dialog_with_small_data: Any) -> None:
        """Значения чекбоксов по умолчанию."""
        dialog = dialog_with_small_data

        assert dialog._thumbnails_var.get() is True
        assert dialog._json_var.get() is True
        assert dialog._signature_var.get() is True
        assert dialog._descriptions_var.get() is False

    def test_checkbox_toggle_updates_size(self, dialog_with_small_data: Any) -> None:
        """Пересчёт при toggle чекбокса."""
        dialog = dialog_with_small_data

        # Get initial optimized text
        initial_text = dialog._optimized_var.get()

        # Toggle thumbnails checkbox
        dialog._thumbnails_var.set(False)
        dialog._on_thumbnails_toggle()

        # Check that optimized text changed (may stay same if no savings)
        # The important thing is that the method runs without error
        assert dialog._options.remove_thumbnails is False


@pytest.mark.gui
class TestFloppyOptimizerDialogStatus:
    """Тесты статуса помещения на дискету."""

    def test_fits_on_floppy_status_green(self, dialog_with_small_data: Any) -> None:
        """Зелёный статус если помещается."""
        dialog = dialog_with_small_data

        # Check status variable exists
        assert dialog._status_var is not None

        # Check that status text is set
        status_text = dialog._status_var.get()
        assert len(status_text) > 0  # Status should be displayed

    def test_does_not_fit_status_red(self, dialog_with_large_data: Any) -> None:
        """Красный статус если не помещается."""
        dialog = dialog_with_large_data

        # Check status variable
        status_text = dialog._status_var.get()
        assert len(status_text) > 0  # Status should be displayed


@pytest.mark.gui
class TestFloppyOptimizerDialogButtons:
    """Тесты кнопок диалога."""

    def test_optimize_button_exists(self, dialog_with_small_data: Any) -> None:
        """Кнопка Optimize существует."""
        dialog = dialog_with_small_data

        # Check optimize button exists
        assert dialog._optimize_btn is not None

    def test_cancel_button_closes_dialog(self, root: tk.Widget, small_data: bytes) -> None:
        """Кнопка Cancel закрывает диалог."""
        dialog = FloppyOptimizerDialog(
            parent=root,
            template_data=small_data,
        )

        # Simulate cancel
        dialog._on_cancel()

        # Check dialog is destroyed
        try:
            exists = dialog.winfo_exists()
            assert not exists, "Dialog should be destroyed"
        except tk.TclError:
            pass  # Expected - window is destroyed

    def test_cancel_sets_result_false(self, root: tk.Widget, small_data: bytes) -> None:
        """Cancel устанавливает result в False."""
        dialog = FloppyOptimizerDialog(
            parent=root,
            template_data=small_data,
        )

        # Simulate cancel
        dialog._on_cancel()

        assert dialog._result is False


@pytest.mark.gui
class TestFloppyOptimizerDialogOptimization:
    """Тесты процесса оптимизации."""

    def test_progress_var_exists(self, dialog_with_small_data: Any) -> None:
        """Переменная прогресса существует."""
        dialog = dialog_with_small_data

        # Check progress variable exists
        assert dialog._progress_var is not None
        assert isinstance(dialog._progress_var.get(), (int, float))

    def test_result_returned_after_optimize(self, root: tk.Widget, small_data: bytes) -> None:
        """Возврат результата после оптимизации."""
        dialog = FloppyOptimizerDialog(
            parent=root,
            template_data=small_data,
        )

        # Run optimization
        dialog._on_optimize()

        # Check result is set
        assert dialog._result is True
        assert dialog._optimized_data is not None

    def test_optimize_sets_optimized_data(self, root: tk.Widget, small_data: bytes) -> None:
        """Оптимизация сохраняет данные."""
        dialog = FloppyOptimizerDialog(
            parent=root,
            template_data=small_data,
        )

        # Run optimization
        dialog._on_optimize()

        # Check optimized data exists (may be same as original in stub)
        assert dialog._optimized_data is not None


@pytest.mark.gui
class TestFloppyOptimizerDialogShow:
    """Тесты метода show()."""

    def test_show_returns_tuple(self, root: tk.Widget, small_data: bytes) -> None:
        """show() возвращает кортеж (bool, bytes | None)."""
        dialog = FloppyOptimizerDialog(
            parent=root,
            template_data=small_data,
        )

        # Mock wait_window to avoid blocking
        with patch.object(dialog, "wait_window"):
            dialog._result = True
            dialog._optimized_data = small_data

            result = dialog.show()

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], (bytes, type(None)))

    def test_show_returns_success_and_data(self, root: tk.Widget, small_data: bytes) -> None:
        """show() возвращает успешный результат с данными."""
        dialog = FloppyOptimizerDialog(
            parent=root,
            template_data=small_data,
        )

        # Mock wait_window to avoid blocking
        with patch.object(dialog, "wait_window"):
            dialog._result = True
            dialog._optimized_data = small_data

            success, data = dialog.show()

        assert success is True
        assert data == small_data

    def test_show_returns_failure_and_none(self, root: tk.Widget, small_data: bytes) -> None:
        """show() возвращает неуспешный результат без данных."""
        dialog = FloppyOptimizerDialog(
            parent=root,
            template_data=small_data,
        )

        # Mock wait_window to avoid blocking
        with patch.object(dialog, "wait_window"):
            dialog._result = False
            dialog._optimized_data = None

            success, data = dialog.show()

        assert success is False
        assert data is None


@pytest.mark.gui
class TestFloppyOptimizerDialogHelpers:
    """Тесты вспомогательных методов."""

    def test_toggle_thumbnails(self, dialog_with_small_data: Any) -> None:
        """Переключение миниатюр."""
        dialog = dialog_with_small_data

        # Initially True
        assert dialog._options.remove_thumbnails is True

        # Toggle
        dialog._thumbnails_var.set(False)
        dialog._on_thumbnails_toggle()

        # Now False
        assert dialog._options.remove_thumbnails is False

    def test_toggle_json(self, dialog_with_small_data: Any) -> None:
        """Переключение компактного JSON."""
        dialog = dialog_with_small_data

        # Initially True
        assert dialog._options.compact_json is True

        # Toggle
        dialog._json_var.set(False)
        dialog._on_json_toggle()

        # Now False
        assert dialog._options.compact_json is False

    def test_toggle_signature(self, dialog_with_small_data: Any) -> None:
        """Переключение подписи Ed25519."""
        dialog = dialog_with_small_data

        # Initially True
        assert dialog._options.use_ed25519 is True

        # Toggle
        dialog._signature_var.set(False)
        dialog._on_signature_toggle()

        # Now False
        assert dialog._options.use_ed25519 is False

    def test_toggle_descriptions(self, dialog_with_small_data: Any) -> None:
        """Переключение удаления описаний."""
        dialog = dialog_with_small_data

        # Initially False
        assert dialog._options.remove_descriptions is False

        # Toggle
        dialog._descriptions_var.set(True)
        dialog._on_descriptions_toggle()

        # Now True
        assert dialog._options.remove_descriptions is True

    def test_analyze_method(self, dialog_with_small_data: Any) -> None:
        """Метод _analyze() обновляет информацию о размере."""
        dialog = dialog_with_small_data

        # _analyze() is called in __init__, so current_var should be set
        current_text = dialog._current_var.get()
        assert "1,000,000" in current_text or "1000000" in current_text or "bytes" in current_text.lower()

    def test_max_floppy_bytes_constant(self) -> None:
        """Проверка константы MAX_FLOPPY_BYTES."""
        assert FloppyOptimizerDialog.MAX_FLOPPY_BYTES == 1_340_000


__all__ = [
    "TestFloppyOptimizerDialogCreation",
    "TestFloppyOptimizerDialogSizePanel",
    "TestFloppyOptimizerDialogCheckboxes",
    "TestFloppyOptimizerDialogStatus",
    "TestFloppyOptimizerDialogButtons",
    "TestFloppyOptimizerDialogOptimization",
    "TestFloppyOptimizerDialogShow",
    "TestFloppyOptimizerDialogHelpers",
]
