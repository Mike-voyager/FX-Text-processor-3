"""Unit-тесты для PanedLayout.

Проверяет:
- Создание и инициализацию PanedLayout
- Добавление левой и правой панелей
- Управление позицией sash (set/get)
- Свертывание/развертывание панели (collapse/expand)
- Сохранение и восстановление состояния
- Callback при изменении позиции

Coverage target: ≥90%
"""

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock

import pytest
from src.gui.core.exceptions import GUIError, LifecycleError
from src.gui.layout.layout_constants import (
    PANEL_RATIO_DEFAULT,
    PANEL_RATIO_MAX,
    PANEL_RATIO_MIN,
    SIDEBAR_COLLAPSED_WIDTH,
)
from src.gui.layout.paned_layout import (
    CollapseStateCallback,
    PanedLayout,
    PanedLayoutState,
    SashChangeCallback,
)


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Fixture для Tk root окна."""
    root = tk.Tk()
    root.withdraw()  # Hide window during tests
    yield root
    root.destroy()


@pytest.fixture
def paned_layout(tk_root: tk.Tk) -> PanedLayout:
    """Fixture для PanedLayout."""
    layout = PanedLayout(widget_id="test_paned")
    return layout


@pytest.fixture
def mounted_paned_layout(tk_root: tk.Tk) -> PanedLayout:
    """Fixture для смонтированного PanedLayout."""
    layout = PanedLayout(widget_id="test_paned_mounted")
    layout.mount(tk_root)
    return layout


@pytest.fixture
def mock_sash_callback() -> MagicMock:
    """Fixture для mock sash callback."""
    return MagicMock(spec=SashChangeCallback)


@pytest.fixture
def mock_collapse_callback() -> MagicMock:
    """Fixture для mock collapse callback."""
    return MagicMock(spec=CollapseStateCallback)


# =============================================================================
# TEST: PanedLayout Creation
# =============================================================================


@pytest.mark.gui
class TestPanedLayoutCreation:
    """Тесты создания PanedLayout."""

    def test_paned_layout_creation(self) -> None:
        """Создание PanedLayout с валидными параметрами."""
        layout = PanedLayout(widget_id="test_create")

        assert layout.widget_id == "test_create"
        assert layout.orientation == "horizontal"
        assert not layout.is_collapsed
        assert not layout.is_mounted()

    def test_paned_layout_creation_vertical(self) -> None:
        """Создание PanedLayout с вертикальной ориентацией."""
        layout = PanedLayout(widget_id="test_vertical", orientation="vertical")

        assert layout.orientation == "vertical"

    def test_paned_layout_creation_invalid_orientation(self) -> None:
        """Невалидная ориентация вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid orientation"):
            PanedLayout(widget_id="test_invalid", orientation="invalid")

    def test_paned_layout_creation_with_callbacks(
        self, mock_sash_callback: MagicMock, mock_collapse_callback: MagicMock
    ) -> None:
        """Создание PanedLayout с callback."""
        layout = PanedLayout(
            widget_id="test_callbacks",
            sash_callback=mock_sash_callback,
            collapse_callback=mock_collapse_callback,
        )

        assert layout._sash_callback is mock_sash_callback
        assert layout._collapse_callback is mock_collapse_callback


# =============================================================================
# TEST: PanedLayout Mount/Unmount
# =============================================================================


@pytest.mark.gui
class TestPanedLayoutMountUnmount:
    """Тесты монтирования/демонтирования PanedLayout."""

    def test_mount_creates_paned_window(
        self, paned_layout: PanedLayout, tk_root: tk.Tk
    ) -> None:
        """mount() создаёт PanedWindow."""
        widget = paned_layout.mount(tk_root)

        assert widget is not None
        assert isinstance(widget, tk.PanedWindow)
        assert paned_layout.is_mounted()

    def test_double_mount_raises_error(
        self, mounted_paned_layout: PanedLayout, tk_root: tk.Tk
    ) -> None:
        """Повторный mount() вызывает LifecycleError."""
        with pytest.raises(LifecycleError, match="already mounted"):
            mounted_paned_layout.mount(tk_root)

    def test_unmount_cleans_resources(
        self, paned_layout: PanedLayout, tk_root: tk.Tk
    ) -> None:
        """unmount() очищает ресурсы."""
        paned_layout.mount(tk_root)
        paned_layout.unmount()

        assert not paned_layout.is_mounted()

    def test_unmount_not_mounted_raises_error(self, paned_layout: PanedLayout) -> None:
        """unmount() для not mountedного вызывает LifecycleError."""
        with pytest.raises(LifecycleError, match="not mounted"):
            paned_layout.unmount()


# =============================================================================
# TEST: Add Panels
# =============================================================================


@pytest.mark.gui
class TestAddPanels:
    """Тесты добавления панелей."""

    def test_add_left_panel(self, mounted_paned_layout: PanedLayout, tk_root: tk.Tk) -> None:
        """add_left_panel() добавляет левую панель."""
        left_frame = tk.Frame(tk_root)
        mounted_paned_layout.add_left_panel(left_frame)

        assert mounted_paned_layout._left_widget is left_frame

    def test_add_right_panel(self, mounted_paned_layout: PanedLayout, tk_root: tk.Tk) -> None:
        """add_right_panel() добавляет правую панель."""
        right_frame = tk.Frame(tk_root)
        mounted_paned_layout.add_right_panel(right_frame)

        assert mounted_paned_layout._right_widget is right_frame

    def test_add_left_panel_not_mounted_raises_error(
        self, paned_layout: PanedLayout, tk_root: tk.Tk
    ) -> None:
        """add_left_panel() без mount вызывает LifecycleError."""
        left_frame = tk.Frame(tk_root)
        with pytest.raises(LifecycleError, match="not mounted"):
            paned_layout.add_left_panel(left_frame)

    def test_add_right_panel_not_mounted_raises_error(
        self, paned_layout: PanedLayout, tk_root: tk.Tk
    ) -> None:
        """add_right_panel() без mount вызывает LifecycleError."""
        right_frame = tk.Frame(tk_root)
        with pytest.raises(LifecycleError, match="not mounted"):
            paned_layout.add_right_panel(right_frame)

    def test_add_left_panel_twice_raises_error(
        self, mounted_paned_layout: PanedLayout, tk_root: tk.Tk
    ) -> None:
        """Повторное add_left_panel() вызывает GUIError."""
        left_frame = tk.Frame(tk_root)
        mounted_paned_layout.add_left_panel(left_frame)

        with pytest.raises(GUIError, match="Left panel already added"):
            mounted_paned_layout.add_left_panel(tk.Frame(tk_root))

    def test_add_right_panel_twice_raises_error(
        self, mounted_paned_layout: PanedLayout, tk_root: tk.Tk
    ) -> None:
        """Повторное add_right_panel() вызывает GUIError."""
        right_frame = tk.Frame(tk_root)
        mounted_paned_layout.add_right_panel(right_frame)

        with pytest.raises(GUIError, match="Right panel already added"):
            mounted_paned_layout.add_right_panel(tk.Frame(tk_root))


# =============================================================================
# TEST: Sash Position
# =============================================================================


@pytest.mark.gui
class TestSashPosition:
    """Тесты управления позицией sash."""

    def test_set_sash_position(self, mounted_paned_layout: PanedLayout) -> None:
        """set_sash_position() устанавливает ratio."""
        mounted_paned_layout.set_sash_position(0.3)

        assert mounted_paned_layout.get_sash_position() == pytest.approx(0.3, abs=0.01)

    def test_set_sash_position_clamps_min(
        self, mounted_paned_layout: PanedLayout
    ) -> None:
        """set_sash_position() ограничивает минимумом."""
        mounted_paned_layout.set_sash_position(0.05)

        assert mounted_paned_layout.get_sash_position() >= PANEL_RATIO_MIN

    def test_set_sash_position_clamps_max(
        self, mounted_paned_layout: PanedLayout
    ) -> None:
        """set_sash_position() ограничивает максимумом."""
        mounted_paned_layout.set_sash_position(0.5)

        assert mounted_paned_layout.get_sash_position() <= PANEL_RATIO_MAX

    def test_set_sash_position_clears_collapsed(
        self, mounted_paned_layout: PanedLayout
    ) -> None:
        """set_sash_position() сбрасывает collapsed."""
        mounted_paned_layout._is_collapsed = True
        mounted_paned_layout.set_sash_position(0.25)

        assert not mounted_paned_layout.is_collapsed

    def test_set_sash_position_triggers_callback(
        self, tk_root: tk.Tk, mock_sash_callback: MagicMock
    ) -> None:
        """set_sash_position() вызывает sash callback."""
        layout = PanedLayout(
            widget_id="test_sash_cb",
            sash_callback=mock_sash_callback,
        )
        layout.mount(tk_root)

        layout.set_sash_position(0.3)

        mock_sash_callback.assert_called_once()
        args = mock_sash_callback.call_args
        assert 0.25 <= args[0][0] <= 0.35  # ratio in valid range

    def test_set_sash_position_not_mounted_raises_error(
        self, paned_layout: PanedLayout
    ) -> None:
        """set_sash_position() без mount вызывает LifecycleError."""
        with pytest.raises(LifecycleError, match="not mounted"):
            paned_layout.set_sash_position(0.25)

    def test_get_sash_position_not_mounted_raises_error(
        self, paned_layout: PanedLayout
    ) -> None:
        """get_sash_position() без mount вызывает LifecycleError."""
        with pytest.raises(LifecycleError, match="not mounted"):
            paned_layout.get_sash_position()

    def test_get_sash_pixels_not_mounted_raises_error(
        self, paned_layout: PanedLayout
    ) -> None:
        """get_sash_pixels() без mount вызывает LifecycleError."""
        with pytest.raises(LifecycleError, match="not mounted"):
            paned_layout.get_sash_pixels()

    def test_get_sash_pixels_returns_int(
        self, mounted_paned_layout: PanedLayout
    ) -> None:
        """get_sash_pixels() возвращает int."""
        mounted_paned_layout._container_width = 1000
        mounted_paned_layout._current_ratio = 0.25

        pixels = mounted_paned_layout.get_sash_pixels()

        assert isinstance(pixels, int)


# =============================================================================
# TEST: Collapse/Expand
# =============================================================================


@pytest.mark.gui
class TestCollapseExpand:
    """Тесты сворачивания/разворачивания."""

    def test_collapse_left_sets_collapsed(
        self, mounted_paned_layout: PanedLayout
    ) -> None:
        """collapse_left() устанавливает collapsed=True."""
        mounted_paned_layout.set_sash_position(0.25)
        mounted_paned_layout.collapse_left()

        assert mounted_paned_layout.is_collapsed

    def test_collapse_left_saves_ratio(
        self, mounted_paned_layout: PanedLayout
    ) -> None:
        """collapse_left() сохраняет ratio перед collapse."""
        mounted_paned_layout.set_sash_position(0.3)
        mounted_paned_layout.collapse_left()

        assert mounted_paned_layout._saved_ratio_before_collapse == pytest.approx(
            0.3, abs=0.01
        )

    def test_collapse_left_already_collapsed_noop(
        self, mounted_paned_layout: PanedLayout
    ) -> None:
        """collapse_left() когда уже collapsed - noop."""
        mounted_paned_layout.set_sash_position(0.25)
        mounted_paned_layout.collapse_left()
        mounted_paned_layout.collapse_left()  # Second call

        assert mounted_paned_layout.is_collapsed

    def test_collapse_left_triggers_callback(
        self, tk_root: tk.Tk, mock_collapse_callback: MagicMock
    ) -> None:
        """collapse_left() вызывает collapse callback."""
        layout = PanedLayout(
            widget_id="test_collapse_cb",
            collapse_callback=mock_collapse_callback,
        )
        layout.mount(tk_root)
        layout.set_sash_position(0.25)

        layout.collapse_left()

        mock_collapse_callback.assert_called_once_with(True)

    def test_expand_left_restores_ratio(
        self, mounted_paned_layout: PanedLayout
    ) -> None:
        """expand_left() восстанавливает ratio."""
        mounted_paned_layout.set_sash_position(0.3)
        mounted_paned_layout.collapse_left()
        mounted_paned_layout.expand_left()

        assert not mounted_paned_layout.is_collapsed
        assert mounted_paned_layout.get_sash_position() == pytest.approx(0.3, abs=0.01)

    def test_expand_left_not_collapsed_noop(
        self, mounted_paned_layout: PanedLayout
    ) -> None:
        """expand_left() когда не collapsed - noop."""
        mounted_paned_layout.set_sash_position(0.25)
        mounted_paned_layout.expand_left()  # Should do nothing

        assert not mounted_paned_layout.is_collapsed

    def test_expand_left_triggers_callback(
        self, tk_root: tk.Tk, mock_collapse_callback: MagicMock
    ) -> None:
        """expand_left() вызывает collapse callback."""
        layout = PanedLayout(
            widget_id="test_expand_cb",
            collapse_callback=mock_collapse_callback,
        )
        layout.mount(tk_root)
        layout.set_sash_position(0.25)
        layout.collapse_left()
        mock_collapse_callback.reset_mock()

        layout.expand_left()

        mock_collapse_callback.assert_called_once_with(False)

    def test_collapse_left_not_mounted_raises_error(
        self, paned_layout: PanedLayout
    ) -> None:
        """collapse_left() без mount вызывает LifecycleError."""
        with pytest.raises(LifecycleError, match="not mounted"):
            paned_layout.collapse_left()

    def test_expand_left_not_mounted_raises_error(
        self, paned_layout: PanedLayout
    ) -> None:
        """expand_left() без mount вызывает LifecycleError."""
        with pytest.raises(LifecycleError, match="not mounted"):
            paned_layout.expand_left()


# =============================================================================
# TEST: Toggle Left
# =============================================================================


@pytest.mark.gui
class TestToggleLeft:
    """Тесты переключения состояния панели."""

    def test_toggle_left_collapses_when_expanded(
        self, mounted_paned_layout: PanedLayout
    ) -> None:
        """toggle_left() сворачивает когда развернуто."""
        mounted_paned_layout.set_sash_position(0.25)

        mounted_paned_layout.toggle_left()

        assert mounted_paned_layout.is_collapsed

    def test_toggle_left_expands_when_collapsed(
        self, mounted_paned_layout: PanedLayout
    ) -> None:
        """toggle_left() разворачивает когда свернуто."""
        mounted_paned_layout.set_sash_position(0.3)
        mounted_paned_layout.collapse_left()

        mounted_paned_layout.toggle_left()

        assert not mounted_paned_layout.is_collapsed


# =============================================================================
# TEST: Save/Restore State
# =============================================================================


@pytest.mark.gui
class TestSaveRestoreState:
    """Тесты сохранения/восстановления состояния."""

    def test_save_restore_state(self, mounted_paned_layout: PanedLayout) -> None:
        """save_state и restore_state работают."""
        mounted_paned_layout.set_sash_position(0.3)
        mounted_paned_layout._container_width = 800
        mounted_paned_layout._container_height = 600

        state = mounted_paned_layout.save_state()

        assert isinstance(state, PanedLayoutState)
        assert state.ratio == pytest.approx(0.3, abs=0.01)
        assert state.collapsed is False
        assert state.width == 800
        assert state.height == 600

    def test_restore_state_collapsed(self, mounted_paned_layout: PanedLayout) -> None:
        """restore_state восстанавливает collapsed."""
        state = PanedLayoutState(
            ratio=0.25,
            collapsed=True,
            width=800,
            height=600,
        )

        mounted_paned_layout.restore_state(state)

        assert mounted_paned_layout.is_collapsed

    def test_restore_state_expanded(self, mounted_paned_layout: PanedLayout) -> None:
        """restore_state восстанавливает expanded."""
        mounted_paned_layout.collapse_left()

        state = PanedLayoutState(
            ratio=0.25,
            collapsed=False,
            width=800,
            height=600,
        )

        mounted_paned_layout.restore_state(state)

        assert not mounted_paned_layout.is_collapsed

    def test_save_state_not_mounted_raises_error(
        self, paned_layout: PanedLayout
    ) -> None:
        """save_state() без mount вызывает LifecycleError."""
        with pytest.raises(LifecycleError, match="not mounted"):
            paned_layout.save_state()

    def test_restore_state_not_mounted_raises_error(
        self, paned_layout: PanedLayout
    ) -> None:
        """restore_state() без mount вызывает LifecycleError."""
        state = PanedLayoutState(
            ratio=0.25,
            collapsed=False,
            width=800,
            height=600,
        )
        with pytest.raises(LifecycleError, match="not mounted"):
            paned_layout.restore_state(state)


# =============================================================================
# TEST: Properties
# =============================================================================


@pytest.mark.gui
class TestPanedLayoutProperties:
    """Тесты свойств PanedLayout."""

    def test_orientation_property(self, paned_layout: PanedLayout) -> None:
        """orientation property возвращает ориентацию."""
        assert paned_layout.orientation == "horizontal"

    def test_is_collapsed_property_initial(self, paned_layout: PanedLayout) -> None:
        """is_collapsed property изначально False."""
        assert not paned_layout.is_collapsed


# =============================================================================
# TEST: Module Exports
# =============================================================================


class TestModuleExports:
    """Тесты exports модуля."""

    def test_all_exports_defined(self) -> None:
        """Все exports определены в __all__."""
        from src.gui.layout import paned_layout

        assert hasattr(paned_layout, "__all__")
        assert "PanedLayout" in paned_layout.__all__
        assert "PanedLayoutState" in paned_layout.__all__
        assert "SashChangeCallback" in paned_layout.__all__
        assert "CollapseStateCallback" in paned_layout.__all__

    def test_module_metadata(self) -> None:
        """Модуль имеет метаданные версии."""
        from src.gui.layout import paned_layout

        assert hasattr(paned_layout, "__version__")
        assert hasattr(paned_layout, "__author__")
        assert hasattr(paned_layout, "__date__")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.layout.paned_layout"])
