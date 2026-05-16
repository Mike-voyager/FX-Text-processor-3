"""Unit-тесты для FormatToolbar.

Проверяет:
- Создание FormatToolbar
- Управление CPI
- Toggle-кнопки форматирования
- Callback-функции

Coverage target: ≥90%
"""

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock

import pytest
from src.gui.components.format_toolbar import FormatToolbar

# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Fixture для Tk root окна."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def format_toolbar(tk_root: tk.Tk) -> Generator[FormatToolbar, None, None]:
    """Fixture для FormatToolbar."""
    toolbar = FormatToolbar(widget_id="test_toolbar")
    toolbar.mount(tk_root)
    yield toolbar


# =============================================================================
# TEST: FormatToolbar Creation
# =============================================================================


class TestFormatToolbarCreation:
    """Тесты создания FormatToolbar."""

    def test_creation(self, tk_root: tk.Tk) -> None:
        """Создание FormatToolbar."""
        toolbar = FormatToolbar(widget_id="test_toolbar")
        toolbar.mount(tk_root)

        assert toolbar.widget_id == "test_toolbar"
        assert toolbar.is_mounted()

    def test_creation_default_id(self, tk_root: tk.Tk) -> None:
        """Создание с дефолтным id."""
        toolbar = FormatToolbar()
        toolbar.mount(tk_root)

        assert toolbar.widget_id == "format_toolbar"

    def test_creation_with_callbacks(self, tk_root: tk.Tk) -> None:
        """Создание с callback-функциями."""
        on_cpi = MagicMock()
        on_format = MagicMock()

        toolbar = FormatToolbar(
            widget_id="test_toolbar",
            on_cpi_change=on_cpi,
            on_format_toggle=on_format,
        )
        toolbar.mount(tk_root)

        assert toolbar._on_cpi_change == on_cpi
        assert toolbar._on_format_toggle == on_format


# =============================================================================
# TEST: CPI Management
# =============================================================================


class TestCPIManagement:
    """Тесты управления CPI."""

    def test_get_current_cpi_default(self, format_toolbar: FormatToolbar) -> None:
        """get_current_cpi() возвращает дефолтное значение."""
        cpi = format_toolbar.get_current_cpi()

        assert cpi == "10"

    def test_set_cpi(self, format_toolbar: FormatToolbar) -> None:
        """set_cpi() устанавливает CPI."""
        format_toolbar.set_cpi(12)

        assert format_toolbar.get_current_cpi() == "12"

    def test_set_cpi_invalid_raises(self, format_toolbar: FormatToolbar) -> None:
        """set_cpi() с невалидным CPI вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid CPI value"):
            format_toolbar.set_cpi(99)

    def test_valid_cpi_values(self, format_toolbar: FormatToolbar) -> None:
        """Все валидные CPI значения принимаются."""
        valid_values = (10, 12, 15, 17, 20)

        for cpi in valid_values:
            format_toolbar.set_cpi(cpi)
            assert format_toolbar.get_current_cpi() == str(cpi)


# =============================================================================
# TEST: Format Management
# =============================================================================


class TestFormatManagement:
    """Тесты управления форматированием."""

    def test_set_format_active(self, format_toolbar: FormatToolbar) -> None:
        """set_format_active() устанавливает состояние формата."""
        format_toolbar.set_format_active("bold", True)

        assert format_toolbar.is_format_active("bold") is True

    def test_set_format_inactive(self, format_toolbar: FormatToolbar) -> None:
        """set_format_active() с False деактивирует формат."""
        format_toolbar.set_format_active("bold", True)
        format_toolbar.set_format_active("bold", False)

        assert format_toolbar.is_format_active("bold") is False

    def test_is_format_active_default(self, format_toolbar: FormatToolbar) -> None:
        """is_format_active() возвращает False по умолчанию."""
        assert format_toolbar.is_format_active("bold") is False
        assert format_toolbar.is_format_active("italic") is False

    def test_set_format_invalid_raises(self, format_toolbar: FormatToolbar) -> None:
        """set_format_active() с невалидным форматом вызывает ValueError."""
        with pytest.raises(ValueError, match="Unknown format type"):
            format_toolbar.set_format_active("invalid_format", True)

    def test_is_format_invalid_raises(self, format_toolbar: FormatToolbar) -> None:
        """is_format_active() с невалидным форматом вызывает ValueError."""
        with pytest.raises(ValueError, match="Unknown format type"):
            format_toolbar.is_format_active("invalid_format")

    def test_reset_formats(self, format_toolbar: FormatToolbar) -> None:
        """reset_formats() сбрасывает все форматы."""
        format_toolbar.set_format_active("bold", True)
        format_toolbar.set_format_active("italic", True)
        format_toolbar.reset_formats()

        assert format_toolbar.is_format_active("bold") is False
        assert format_toolbar.is_format_active("italic") is False


# =============================================================================
# TEST: Format Types
# =============================================================================


class TestFormatTypes:
    """Тесты типов форматирования."""

    def test_all_format_types(self, format_toolbar: FormatToolbar) -> None:
        """Все типы форматирования поддерживаются."""
        format_types = ["bold", "italic", "underline", "strikethrough", "subscript", "superscript"]

        for fmt_type in format_types:
            format_toolbar.set_format_active(fmt_type, True)
            assert format_toolbar.is_format_active(fmt_type) is True

            format_toolbar.set_format_active(fmt_type, False)
            assert format_toolbar.is_format_active(fmt_type) is False


# =============================================================================
# TEST: Lifecycle
# =============================================================================


class TestLifecycle:
    """Тесты жизненного цикла."""

    def test_mount_creates_widget(self, tk_root: tk.Tk) -> None:
        """mount() создаёт виджет."""
        toolbar = FormatToolbar(widget_id="test")
        toolbar.mount(tk_root)

        assert toolbar.is_mounted()


# =============================================================================
# TEST: Constants
# =============================================================================


class TestConstants:
    """Тесты констант."""

    def test_cpi_values(self) -> None:
        """CPI_VALUES содержит ожидаемые значения."""
        assert FormatToolbar.CPI_VALUES == ("10", "12", "15", "17", "20")

    def test_format_labels(self) -> None:
        """FORMAT_LABELS содержит ожидаемые метки."""
        assert FormatToolbar.FORMAT_LABELS == {
            "bold": "B",
            "italic": "I",
            "underline": "U",
            "strikethrough": "S",
            "subscript": "x₂",
            "superscript": "x²",
        }


# =============================================================================
# TEST: Callbacks
# =============================================================================


class TestCallbacks:
    """Тесты callback-функций."""

    def test_cpi_change_callback(self, tk_root: tk.Tk) -> None:
        """on_cpi_change callback вызывается."""
        callback_called = False
        callback_value = None

        def on_cpi_change(cpi: int) -> None:
            nonlocal callback_called, callback_value
            callback_called = True
            callback_value = cpi

        toolbar = FormatToolbar(
            widget_id="test",
            on_cpi_change=on_cpi_change,
        )
        toolbar.mount(tk_root)

        # Simulate CPI change
        toolbar._cpi_var.set("12")
        toolbar._on_cpi_selected()

        assert callback_called is True
        assert callback_value == 12

    def test_format_toggle_callback(self, tk_root: tk.Tk) -> None:
        """on_format_toggle callback вызывается."""
        callback_called = False
        callback_format = None
        callback_active = None

        def on_format_toggle(fmt: str, active: bool) -> None:
            nonlocal callback_called, callback_format, callback_active
            callback_called = True
            callback_format = fmt
            callback_active = active

        toolbar = FormatToolbar(
            widget_id="test",
            on_format_toggle=on_format_toggle,
        )
        toolbar.mount(tk_root)

        # Simulate format toggle
        toolbar._toggle_format("bold")

        assert callback_called is True
        assert callback_format == "bold"
        assert callback_active is True


# =============================================================================
# TEST: Subscript/Superscript
# =============================================================================


class TestScriptManagement:
    """Тесты управления subscript/superscript."""

    def test_set_subscript(self, format_toolbar: FormatToolbar) -> None:
        """set_subscript() включает/отключает subscript."""
        format_toolbar.set_subscript(True)
        assert format_toolbar.is_script_active("subscript") is True
        assert format_toolbar.is_format_active("subscript") is True

        format_toolbar.set_subscript(False)
        assert format_toolbar.is_script_active("subscript") is False

    def test_set_superscript(self, format_toolbar: FormatToolbar) -> None:
        """set_superscript() включает/отключает superscript."""
        format_toolbar.set_superscript(True)
        assert format_toolbar.is_script_active("superscript") is True
        assert format_toolbar.is_format_active("superscript") is True

        format_toolbar.set_superscript(False)
        assert format_toolbar.is_script_active("superscript") is False

    def test_script_mutual_exclusion(self, format_toolbar: FormatToolbar) -> None:
        """Subscript и superscript взаимоисключающие."""
        # Включаем subscript через API - он должен включиться
        format_toolbar.set_subscript(True)
        assert format_toolbar.is_script_active("subscript") is True
        assert format_toolbar.is_script_active("superscript") is False

        # Включаем superscript - subscript должен отключиться через API
        format_toolbar.set_superscript(True)
        assert format_toolbar.is_script_active("superscript") is True
        assert format_toolbar.is_script_active("subscript") is False

        # В обратном порядке через _toggle_format
        format_toolbar._toggle_format("subscript")
        assert format_toolbar.is_script_active("subscript") is True
        assert format_toolbar.is_script_active("superscript") is False

    def test_reset_scripts(self, format_toolbar: FormatToolbar) -> None:
        """reset_scripts() сбрасывает только script-форматы."""
        # Устанавливаем разные форматы
        format_toolbar.set_format_active("bold", True)
        format_toolbar.set_subscript(True)
        format_toolbar.set_superscript(True)

        # Сбрасываем только scripts
        format_toolbar.reset_scripts()

        assert format_toolbar.is_script_active("subscript") is False
        assert format_toolbar.is_script_active("superscript") is False
        assert format_toolbar.is_format_active("bold") is True  # Не тронут

    def test_is_script_active_invalid(self, format_toolbar: FormatToolbar) -> None:
        """is_script_active() с невалидным типом вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid script formatting type"):
            format_toolbar.is_script_active("bold")  # Не script тип

        with pytest.raises(ValueError, match="Invalid script formatting type"):
            format_toolbar.is_script_active("invalid")

    def test_script_toggle_callback(self, tk_root: tk.Tk) -> None:
        """on_script_toggle callback вызывается."""
        callback_calls: list[tuple[str, bool]] = []

        def on_script_toggle(script_type: str, active: bool) -> None:
            callback_calls.append((script_type, active))

        toolbar = FormatToolbar(
            widget_id="test",
            on_script_toggle=on_script_toggle,
        )
        toolbar.mount(tk_root)

        # Toggle subscript
        toolbar._toggle_format("subscript")
        assert ("subscript", True) in callback_calls

        # Toggle superscript - subscript выключается
        toolbar._toggle_format("superscript")
        assert ("superscript", True) in callback_calls

    def test_script_toggle_no_callback(self, tk_root: tk.Tk) -> None:
        """Вызов _toggle_format без callback не вызывает ошибку."""
        toolbar = FormatToolbar(widget_id="test")
        toolbar.mount(tk_root)

        # Не должно вызвать ошибку
        toolbar._toggle_format("subscript")
        toolbar._toggle_format("superscript")

    def test_apply_script_method(self, tk_root: tk.Tk) -> None:
        """_apply_script() вызывает on_script_toggle."""
        callback_calls: list[tuple[str, bool]] = []

        def on_script_toggle(script_type: str, active: bool) -> None:
            callback_calls.append((script_type, active))

        toolbar = FormatToolbar(
            widget_id="test",
            on_script_toggle=on_script_toggle,
        )
        toolbar.mount(tk_root)

        toolbar._apply_script("superscript", True)
        assert ("superscript", True) in callback_calls

        toolbar._apply_script("superscript", False)
        assert ("superscript", False) in callback_calls

    def test_apply_script_invalid(self, tk_root: tk.Tk) -> None:
        """_apply_script() с невалидным типом вызывает ValueError."""
        toolbar = FormatToolbar(widget_id="test")
        toolbar.mount(tk_root)

        with pytest.raises(ValueError, match="Invalid script formatting type"):
            toolbar._apply_script("bold", True)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.components.format_toolbar"])
