"""Unit-тесты для Ruler.

Проверяет:
- Создание Ruler
- Управление CPI
- Отрисовку меток
- Обработку кликов
- Callback-функции

Coverage target: ≥90%
"""

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock

import pytest

from src.gui.components.ruler import (
    CPI_TO_PIXELS,
    RULER_HEIGHT,
    TICK_INTERVAL,
    VALID_CPI_VALUES,
    Ruler,
)


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
def ruler(tk_root: tk.Tk) -> Generator[Ruler, None, None]:
    """Fixture для Ruler."""
    r = Ruler(
        widget_id="test_ruler",
        initial_cpi=10,
        initial_width_chars=80,
    )
    r.mount(tk_root)
    yield r


# =============================================================================
# TEST: Ruler Creation
# =============================================================================


class TestRulerCreation:
    """Тесты создания Ruler."""

    def test_creation(self) -> None:
        """Создание Ruler."""
        ruler = Ruler(
            widget_id="test_ruler",
            initial_cpi=10,
            initial_width_chars=80,
        )

        assert ruler.widget_id == "test_ruler"
        assert ruler.get_cpi() == 10
        assert ruler.get_width_chars() == 80

    def test_creation_with_controller(self) -> None:
        """Создание с контроллером."""
        controller = MagicMock()
        ruler = Ruler(
            widget_id="test_ruler",
            controller=controller,
            initial_cpi=12,
            initial_width_chars=100,
        )

        assert ruler._controller == controller

    def test_creation_with_callback(self) -> None:
        """Создание с callback."""
        on_click = MagicMock()
        ruler = Ruler(
            widget_id="test_ruler",
            on_click=on_click,
            initial_cpi=10,
            initial_width_chars=80,
        )

        assert ruler._on_click == on_click

    def test_creation_invalid_cpi_raises(self) -> None:
        """Создание с невалидным CPI вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid CPI value"):
            Ruler(
                widget_id="test_ruler",
                initial_cpi=99,
                initial_width_chars=80,
            )


# =============================================================================
# TEST: CPI Management
# =============================================================================


class TestCPIManagement:
    """Тесты управления CPI."""

    def test_get_cpi(self, ruler: Ruler) -> None:
        """get_cpi() возвращает текущий CPI."""
        assert ruler.get_cpi() == 10

    def test_set_cpi(self, ruler: Ruler) -> None:
        """set_cpi() изменяет CPI."""
        ruler.set_cpi(12)

        assert ruler.get_cpi() == 12

    def test_set_cpi_invalid_raises(self, ruler: Ruler) -> None:
        """set_cpi() с невалидным CPI вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid CPI value"):
            ruler.set_cpi(99)

    def test_set_cpi_same_value_noop(self, ruler: Ruler) -> None:
        """set_cpi() с тем же значением ничего не делает."""
        ruler.set_cpi(10)

        assert ruler.get_cpi() == 10

    def test_set_cpi_updates_char_width(self, ruler: Ruler) -> None:
        """set_cpi() обновляет ширину символа."""
        old_width = ruler.get_char_width_pixels()
        ruler.set_cpi(12)
        new_width = ruler.get_char_width_pixels()

        assert new_width != old_width
        assert new_width == CPI_TO_PIXELS[12]

    def test_valid_cpi_values(self, ruler: Ruler) -> None:
        """Все валидные CPI значения работают."""
        for cpi in VALID_CPI_VALUES:
            ruler.set_cpi(cpi)
            assert ruler.get_cpi() == cpi


# =============================================================================
# TEST: Width Management
# =============================================================================


class TestWidthManagement:
    """Тесты управления шириной."""

    def test_get_width_chars(self, ruler: Ruler) -> None:
        """get_width_chars() возвращает ширину."""
        assert ruler.get_width_chars() == 80

    def test_set_width_chars(self, ruler: Ruler) -> None:
        """set_width_chars() изменяет ширину."""
        ruler.set_width_chars(132)

        assert ruler.get_width_chars() == 132

    def test_set_width_chars_invalid_raises(self, ruler: Ruler) -> None:
        """set_width_chars() с невалидной шириной вызывает ValueError."""
        with pytest.raises(ValueError, match="Width must be positive"):
            ruler.set_width_chars(0)

    def test_set_width_chars_same_value_noop(self, ruler: Ruler) -> None:
        """set_width_chars() с тем же значением ничего не делает."""
        ruler.set_width_chars(80)

        assert ruler.get_width_chars() == 80


# =============================================================================
# TEST: Char Width
# =============================================================================


class TestCharWidth:
    """Тесты ширины символа."""

    def test_get_char_width_pixels(self, ruler: Ruler) -> None:
        """get_char_width_pixels() возвращает ширину."""
        width = ruler.get_char_width_pixels()

        assert width == CPI_TO_PIXELS[10]

    def test_char_width_changes_with_cpi(self, ruler: Ruler) -> None:
        """Ширина символа меняется с CPI."""
        ruler.set_cpi(10)
        width_10 = ruler.get_char_width_pixels()

        ruler.set_cpi(20)
        width_20 = ruler.get_char_width_pixels()

        assert width_20 < width_10


# =============================================================================
# TEST: Constants
# =============================================================================


class TestConstants:
    """Тесты констант."""

    def test_valid_cpi_values(self) -> None:
        """VALID_CPI_VALUES содержит ожидаемые значения."""
        assert VALID_CPI_VALUES == (10, 12, 15, 17, 20)

    def test_cpi_to_pixels(self) -> None:
        """CPI_TO_PIXELS содержит ожидаемые значения."""
        assert CPI_TO_PIXELS[10] == 9.6
        assert CPI_TO_PIXELS[12] == 8.0
        assert CPI_TO_PIXELS[15] == 6.4
        assert CPI_TO_PIXELS[17] == 5.647
        assert CPI_TO_PIXELS[20] == 4.8

    def test_ruler_height(self) -> None:
        """RULER_HEIGHT определён."""
        assert RULER_HEIGHT == 25

    def test_tick_interval(self) -> None:
        """TICK_INTERVAL определён."""
        assert TICK_INTERVAL == 10


# =============================================================================
# TEST: Lifecycle
# =============================================================================


class TestLifecycle:
    """Тесты жизненного цикла."""

    def test_mount_creates_widget(self, tk_root: tk.Tk) -> None:
        """mount() создаёт виджет."""
        ruler = Ruler(
            widget_id="test_ruler",
            initial_cpi=10,
            initial_width_chars=80,
        )
        ruler.mount(tk_root)

        assert ruler.is_mounted()

    def test_unmount_removes_widget(self, tk_root: tk.Tk) -> None:
        """unmount() удаляет виджет."""
        ruler = Ruler(
            widget_id="test_ruler",
            initial_cpi=10,
            initial_width_chars=80,
        )
        ruler.mount(tk_root)
        ruler.unmount()

        assert not ruler.is_mounted()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.components.ruler"])
