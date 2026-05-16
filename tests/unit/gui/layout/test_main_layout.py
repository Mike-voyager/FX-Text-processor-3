"""Unit-тесты для MainLayout.

Проверяет:
- Создание и инициализацию MainLayout
- Установку sidebar, content, statusbar
- Сворачивание/разворачивание sidebar
- Получение/установку ширины sidebar
- Callback при переключении sidebar
- Сохранение/восстановление состояния sidebar

Coverage target: ≥90%
"""

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock

import pytest
from src.gui.core.exceptions import GUIError, LifecycleError
from src.gui.layout.layout_constants import SIDEBAR_COLLAPSED_WIDTH
from src.gui.layout.main_layout import MainLayout, SidebarToggleCallback


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
def main_layout(tk_root: tk.Tk) -> MainLayout:
    """Fixture для MainLayout."""
    layout = MainLayout(widget_id="test_main_layout", root=tk_root)
    return layout


@pytest.fixture
def mounted_main_layout(tk_root: tk.Tk) -> MainLayout:
    """Fixture для смонтированного MainLayout."""
    layout = MainLayout(widget_id="test_main_mounted", root=tk_root)
    layout.mount(tk_root)
    return layout


@pytest.fixture
def mock_sidebar_callback() -> MagicMock:
    """Fixture для mock sidebar toggle callback."""
    return MagicMock(spec=SidebarToggleCallback)


# =============================================================================
# TEST: MainLayout Creation
# =============================================================================


@pytest.mark.gui
class TestMainLayoutCreation:
    """Тесты создания MainLayout."""

    def test_main_layout_creation(self, tk_root: tk.Tk) -> None:
        """Создание MainLayout с валидными параметрами."""
        layout = MainLayout(widget_id="test_create", root=tk_root)

        assert layout.widget_id == "test_create"
        assert layout._root is tk_root
        assert not layout._is_mounted

    def test_main_layout_creation_without_root(self) -> None:
        """Создание MainLayout без root."""
        layout = MainLayout(widget_id="test_no_root")

        assert layout._root is None

    def test_main_layout_creation_with_callback(
        self, tk_root: tk.Tk, mock_sidebar_callback: MagicMock
    ) -> None:
        """Создание MainLayout с callback."""
        layout = MainLayout(
            widget_id="test_callback",
            root=tk_root,
            sidebar_toggle_callback=mock_sidebar_callback,
        )

        assert layout._sidebar_toggle_callback is mock_sidebar_callback


# =============================================================================
# TEST: MainLayout Mount/Unmount
# =============================================================================


@pytest.mark.gui
class TestMainLayoutMountUnmount:
    """Тесты монтирования/демонтирования MainLayout."""

    def test_main_layout_creation_mount_creates_widget(
        self, main_layout: MainLayout, tk_root: tk.Tk
    ) -> None:
        """mount() создаёт widget."""
        widget = main_layout.mount(tk_root)

        assert widget is not None
        assert isinstance(widget, tk.Frame)
        assert main_layout._is_mounted

    def test_mount_creates_internal_paned_layout(
        self, main_layout: MainLayout, tk_root: tk.Tk
    ) -> None:
        """mount() создаёт внутренний PanedLayout."""
        main_layout.mount(tk_root)

        assert main_layout._paned_layout is not None

    def test_unmount_cleans_resources(
        self, mounted_main_layout: MainLayout
    ) -> None:
        """unmount() очищает ресурсы."""
        mounted_main_layout.unmount()

        assert not mounted_main_layout._is_mounted
        assert mounted_main_layout._paned_layout is None

    def test_unmount_not_mounted_raises_error(self, main_layout: MainLayout) -> None:
        """unmount() для not mountedного вызывает LifecycleError."""
        with pytest.raises(LifecycleError, match="not mounted"):
            main_layout.unmount()


# =============================================================================
# TEST: Set Sidebar
# =============================================================================


@pytest.mark.gui
class TestSetSidebar:
    """Тесты установки sidebar."""

    def test_set_sidebar(self, mounted_main_layout: MainLayout, tk_root: tk.Tk) -> None:
        """set_sidebar() устанавливает sidebar."""
        sidebar_widget = tk.Frame(tk_root)
        mounted_main_layout.set_sidebar(sidebar_widget)

        assert mounted_main_layout._sidebar_widget is sidebar_widget

    def test_set_sidebar_not_mounted_raises_error(
        self, main_layout: MainLayout, tk_root: tk.Tk
    ) -> None:
        """set_sidebar() без mount вызывает LifecycleError."""
        with pytest.raises(LifecycleError, match="not mounted"):
            main_layout.set_sidebar(tk.Frame(tk_root))

    def test_set_sidebar_twice_raises_error(
        self, mounted_main_layout: MainLayout, tk_root: tk.Tk
    ) -> None:
        """Повторное set_sidebar() вызывает GUIError."""
        mounted_main_layout.set_sidebar(tk.Frame(tk_root))

        with pytest.raises(GUIError, match="Sidebar already set"):
            mounted_main_layout.set_sidebar(tk.Frame(tk_root))


# =============================================================================
# TEST: Set Content
# =============================================================================


@pytest.mark.gui
class TestSetContent:
    """Тесты установки content."""

    def test_set_content(self, mounted_main_layout: MainLayout, tk_root: tk.Tk) -> None:
        """set_content() устанавливает content."""
        content_widget = tk.Frame(tk_root)
        mounted_main_layout.set_content(content_widget)

        assert mounted_main_layout._content_widget is content_widget

    def test_set_content_not_mounted_raises_error(
        self, main_layout: MainLayout, tk_root: tk.Tk
    ) -> None:
        """set_content() без mount вызывает LifecycleError."""
        with pytest.raises(LifecycleError, match="not mounted"):
            main_layout.set_content(tk.Frame(tk_root))

    def test_set_content_twice_raises_error(
        self, mounted_main_layout: MainLayout, tk_root: tk.Tk
    ) -> None:
        """Повторное set_content() вызывает GUIError."""
        mounted_main_layout.set_content(tk.Frame(tk_root))

        with pytest.raises(GUIError, match="Content already set"):
            mounted_main_layout.set_content(tk.Frame(tk_root))


# =============================================================================
# TEST: Set Statusbar
# =============================================================================


@pytest.mark.gui
class TestSetStatusbar:
    """Тесты установки statusbar."""

    def test_set_statusbar(self, mounted_main_layout: MainLayout, tk_root: tk.Tk) -> None:
        """set_statusbar() устанавливает statusbar."""
        statusbar_widget = tk.Frame(tk_root)
        mounted_main_layout.set_statusbar(statusbar_widget)

        assert mounted_main_layout._statusbar_widget is statusbar_widget

    def test_set_statusbar_not_mounted_raises_error(
        self, main_layout: MainLayout, tk_root: tk.Tk
    ) -> None:
        """set_statusbar() без mount вызывает LifecycleError."""
        with pytest.raises(LifecycleError, match="not mounted"):
            main_layout.set_statusbar(tk.Frame(tk_root))

    def test_set_statusbar_twice_raises_error(
        self, mounted_main_layout: MainLayout, tk_root: tk.Tk
    ) -> None:
        """Повторное set_statusbar() вызывает GUIError."""
        mounted_main_layout.set_statusbar(tk.Frame(tk_root))

        with pytest.raises(GUIError, match="StatusBar already set"):
            mounted_main_layout.set_statusbar(tk.Frame(tk_root))


# =============================================================================
# TEST: Collapse/Expand Sidebar
# =============================================================================


@pytest.mark.gui
class TestCollapseExpandSidebar:
    """Тесты сворачивания/разворачивания sidebar."""

    def test_collapse_sidebar_sets_collapsed(
        self, mounted_main_layout: MainLayout
    ) -> None:
        """collapse_sidebar() устанавливает sidebar_collapsed=True."""
        mounted_main_layout.collapse_sidebar()

        assert mounted_main_layout.sidebar_collapsed

    def test_expand_sidebar_clears_collapsed(
        self, mounted_main_layout: MainLayout
    ) -> None:
        """expand_sidebar() устанавливает sidebar_collapsed=False."""
        mounted_main_layout.collapse_sidebar()
        mounted_main_layout.expand_sidebar()

        assert not mounted_main_layout.sidebar_collapsed

    def test_toggle_sidebar(self, mounted_main_layout: MainLayout) -> None:
        """toggle_sidebar() переключает состояние."""
        initial = mounted_main_layout.sidebar_collapsed

        mounted_main_layout.toggle_sidebar()

        assert mounted_main_layout.sidebar_collapsed != initial

        mounted_main_layout.toggle_sidebar()

        assert mounted_main_layout.sidebar_collapsed == initial

    def test_collapse_sidebar_not_mounted_raises_error(
        self, main_layout: MainLayout
    ) -> None:
        """collapse_sidebar() без mount вызывает LifecycleError."""
        with pytest.raises(LifecycleError, match="not mounted"):
            main_layout.collapse_sidebar()

    def test_expand_sidebar_not_mounted_raises_error(
        self, main_layout: MainLayout
    ) -> None:
        """expand_sidebar() без mount вызывает LifecycleError."""
        with pytest.raises(LifecycleError, match="not mounted"):
            main_layout.expand_sidebar()


# =============================================================================
# TEST: Sidebar Width Get/Set
# =============================================================================


@pytest.mark.gui
class TestSidebarWidthGetSet:
    """Тесты получения/установки ширины sidebar."""

    def test_get_sidebar_width_collapsed(
        self, mounted_main_layout: MainLayout
    ) -> None:
        """get_sidebar_width() возвращает SIDEBAR_COLLAPSED_WIDTH когда collapsed."""
        mounted_main_layout.collapse_sidebar()

        width = mounted_main_layout.get_sidebar_width()

        assert width == SIDEBAR_COLLAPSED_WIDTH

    def test_set_sidebar_width_negative_raises_error(
        self, mounted_main_layout: MainLayout
    ) -> None:
        """set_sidebar_width() с отрицательным значением вызывает ValueError."""
        with pytest.raises(ValueError, match="Width must be non-negative"):
            mounted_main_layout.set_sidebar_width(-10)

    def test_set_sidebar_width_updates_ratio(
        self, mounted_main_layout: MainLayout, tk_root: tk.Tk
    ) -> None:
        """set_sidebar_width() обновляет sidebar_ratio."""
        # Set up a content frame with known width
        content_frame = tk.Frame(tk_root, width=1000, height=600)
        content_frame.pack()
        tk_root.update_idletasks()

        mounted_main_layout.set_content(content_frame)
        mounted_main_layout.set_sidebar_width(200)

        # Ratio should be approximately 200/1000 = 0.2
        assert mounted_main_layout.sidebar_ratio > 0


# =============================================================================
# TEST: Properties
# =============================================================================


@pytest.mark.gui
class TestMainLayoutProperties:
    """Тесты свойств MainLayout."""

    def test_sidebar_ratio_property(self, mounted_main_layout: MainLayout) -> None:
        """sidebar_ratio property возвращает ratio."""
        assert isinstance(mounted_main_layout.sidebar_ratio, float)

    def test_sidebar_collapsed_property(self, mounted_main_layout: MainLayout) -> None:
        """sidebar_collapsed property возвращает состояние."""
        assert isinstance(mounted_main_layout.sidebar_collapsed, bool)

    def test_is_sidebar_visible(self, mounted_main_layout: MainLayout) -> None:
        """is_sidebar_visible() возвращает видимость."""
        visible = mounted_main_layout.is_sidebar_visible()
        assert isinstance(visible, bool)

        mounted_main_layout.collapse_sidebar()
        assert not mounted_main_layout.is_sidebar_visible()


# =============================================================================
# TEST: Save/Restore Sidebar State
# =============================================================================


@pytest.mark.gui
class TestSaveRestoreSidebarState:
    """Тесты сохранения/восстановления состояния sidebar."""

    def test_save_sidebar_state(self, mounted_main_layout: MainLayout) -> None:
        """save_sidebar_state() возвращает словарь с состоянием."""
        state = mounted_main_layout.save_sidebar_state()

        assert isinstance(state, dict)
        assert "ratio" in state
        assert "collapsed" in state
        assert "width" in state

    def test_restore_sidebar_state(self, mounted_main_layout: MainLayout) -> None:
        """restore_sidebar_state() восстанавливает состояние."""
        state = {
            "ratio": 0.3,
            "collapsed": True,
            "width": 200,
        }

        mounted_main_layout.restore_sidebar_state(state)

        assert mounted_main_layout.sidebar_collapsed


# =============================================================================
# TEST: Content Area
# =============================================================================


@pytest.mark.gui
class TestContentArea:
    """Тесты области контента."""

    def test_get_content_area(self, mounted_main_layout: MainLayout) -> None:
        """get_content_area() возвращает размеры."""
        width, height = mounted_main_layout.get_content_area()

        assert isinstance(width, int)
        assert isinstance(height, int)


# =============================================================================
# TEST: Sidebar Toggle Callback
# =============================================================================


@pytest.mark.gui
class TestSidebarToggleCallback:
    """Тесты callback при переключении sidebar."""

    def test_sidebar_toggle_callback_collapsed(
        self, tk_root: tk.Tk, mock_sidebar_callback: MagicMock
    ) -> None:
        """Callback вызывается при сворачивании."""
        layout = MainLayout(
            widget_id="test_cb_collapsed",
            root=tk_root,
            sidebar_toggle_callback=mock_sidebar_callback,
        )
        layout.mount(tk_root)

        layout.collapse_sidebar()

        mock_sidebar_callback.assert_called()

    def test_sidebar_toggle_callback_expanded(
        self, tk_root: tk.Tk, mock_sidebar_callback: MagicMock
    ) -> None:
        """Callback вызывается при разворачивании."""
        layout = MainLayout(
            widget_id="test_cb_expanded",
            root=tk_root,
            sidebar_toggle_callback=mock_sidebar_callback,
        )
        layout.mount(tk_root)
        layout.collapse_sidebar()
        mock_sidebar_callback.reset_mock()

        layout.expand_sidebar()

        mock_sidebar_callback.assert_called()


# =============================================================================
# TEST: Module Exports
# =============================================================================


class TestModuleExports:
    """Тесты exports модуля."""

    def test_all_exports_defined(self) -> None:
        """Все exports определены в __all__."""
        from src.gui.layout import main_layout

        assert hasattr(main_layout, "__all__")
        assert "MainLayout" in main_layout.__all__
        assert "SidebarToggleCallback" in main_layout.__all__

    def test_module_metadata(self) -> None:
        """Модуль имеет метаданные версии."""
        from src.gui.layout import main_layout

        assert hasattr(main_layout, "__version__")
        assert hasattr(main_layout, "__author__")
        assert hasattr(main_layout, "__date__")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.layout.main_layout"])
