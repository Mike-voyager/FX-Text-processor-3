"""Unit-тесты для PaperToolbar и PaperConfig.

Проверяет:
- Создание PaperConfig со значениями по умолчанию
- Создание PaperConfig с пользовательскими значениями
- Frozen-иммутабельность PaperConfig
- Создание PaperToolbar
- Монтирование PaperToolbar

Coverage target: ≥90%
"""

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock

import pytest

from src.gui.components.paper_toolbar import PaperConfig, PaperToolbar
from src.services.paper_format_service import Orientation, PaperSize


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
def paper_toolbar(tk_root: tk.Tk) -> Generator[PaperToolbar, None, None]:
    """Fixture для PaperToolbar."""
    tb = PaperToolbar(widget_id="test_paper_toolbar")
    tb.mount(tk_root)
    yield tb


# =============================================================================
# TEST: PaperConfig
# =============================================================================


class TestPaperConfig:
    """Тесты PaperConfig."""

    def test_default_values(self) -> None:
        """PaperConfig создаётся со значениями по умолчанию."""
        config = PaperConfig()
        assert config.paper_size == PaperSize.A4
        assert config.cpi == 10
        assert config.line_spacing == "1/6"
        assert config.paper_source == "auto"
        assert config.width_mm == 210.0
        assert config.height_mm == 297.0
        assert config.top_margin_mm == 10.0
        assert config.bottom_margin_mm == 10.0
        assert config.left_margin_mm == 10.0
        assert config.right_margin_mm == 10.0
        assert config.orientation == Orientation.PORTRAIT
        assert config.skip_perforation is False
        assert config.perforation_enabled is False
        assert config.perforation_margin_mm == 0.0
        assert config.paper_form_type == "custom"

    def test_custom_values(self) -> None:
        """PaperConfig создаётся с пользовательскими значениями."""
        config = PaperConfig(
            paper_size=PaperSize.LETTER,
            cpi=12,
            line_spacing="1/8",
            width_mm=215.9,
            height_mm=279.4,
            orientation=Orientation.LANDSCAPE,
            skip_perforation=True,
        )
        assert config.paper_size == PaperSize.LETTER
        assert config.cpi == 12
        assert config.line_spacing == "1/8"
        assert config.width_mm == 215.9
        assert config.height_mm == 279.4
        assert config.orientation == Orientation.LANDSCAPE
        assert config.skip_perforation is True

    def test_frozen_immutability(self) -> None:
        """PaperConfig неизменяем (frozen=True)."""
        config = PaperConfig()
        with pytest.raises(AttributeError):
            config.cpi = 15  # type: ignore[misc]

    def test_frozen_with_custom_values(self) -> None:
        """Frozen PaperConfig с пользовательскими значениями неизменяем."""
        config = PaperConfig(cpi=15)
        with pytest.raises(AttributeError):
            config.cpi = 10  # type: ignore[misc]

    def test_equality(self) -> None:
        """Два PaperConfig с одинаковыми значениями равны."""
        config1 = PaperConfig()
        config2 = PaperConfig()
        assert config1 == config2

    def test_inequality(self) -> None:
        """Два PaperConfig с разными значениями не равны."""
        config1 = PaperConfig(cpi=10)
        config2 = PaperConfig(cpi=12)
        assert config1 != config2

    def test_hash(self) -> None:
        """Frozen PaperConfig можно использовать как ключ словаря."""
        config = PaperConfig()
        d = {config: "value"}
        assert d[config] == "value"


# =============================================================================
# TEST: PaperToolbar Creation
# =============================================================================


class TestPaperToolbarCreation:
    """Тесты создания PaperToolbar."""

    def test_creation(self) -> None:
        """PaperToolbar создаётся с widget_id по умолчанию."""
        tb = PaperToolbar()
        assert tb.widget_id == "paper_toolbar"

    def test_creation_custom_id(self) -> None:
        """PaperToolbar создаётся с пользовательским widget_id."""
        tb = PaperToolbar(widget_id="custom_toolbar")
        assert tb.widget_id == "custom_toolbar"

    def test_creation_with_controller(self) -> None:
        """PaperToolbar создаётся с контроллером."""
        controller = MagicMock()
        tb = PaperToolbar(widget_id="tb_ctrl", controller=controller)
        assert tb.widget_id == "tb_ctrl"

    def test_mount(self, tk_root: tk.Tk) -> None:
        """PaperToolbar монтируется в родительский виджет."""
        tb = PaperToolbar(widget_id="mount_tb")
        widget = tb.mount(tk_root)
        assert widget is not None
        assert isinstance(widget, tk.Frame)
        assert tb.is_mounted()


# =============================================================================
# TEST: PaperToolbar Lifecycle
# =============================================================================


class TestPaperToolbarLifecycle:
    """Тесты жизненного цикла PaperToolbar."""

    def test_unmount(self, tk_root: tk.Tk) -> None:
        """PaperToolbar корректно демонтируется."""
        tb = PaperToolbar(widget_id="unmount_tb")
        tb.mount(tk_root)
        assert tb.is_mounted()
        tb.unmount()
        assert not tb.is_mounted()

    def test_double_mount_raises(self, tk_root: tk.Tk) -> None:
        """Повторное монтирование вызывает LifecycleError."""
        from src.gui.core.exceptions import LifecycleError

        tb = PaperToolbar(widget_id="dbl_mount_tb")
        tb.mount(tk_root)
        with pytest.raises(LifecycleError):
            tb.mount(tk_root)

    def test_unmount_not_mounted_raises(self) -> None:
        """Демонтация несмонтированного виджета вызывает LifecycleError."""
        from src.gui.core.exceptions import LifecycleError

        tb = PaperToolbar(widget_id="not_mounted_tb")
        with pytest.raises(LifecycleError):
            tb.unmount()