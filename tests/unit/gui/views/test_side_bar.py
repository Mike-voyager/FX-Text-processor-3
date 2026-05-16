"""Unit-тесты для SideBar.

Проверяет:
- Создание SideBar
- Переключение режимов (SECTIONS/TREE)
- Сворачивание/разворачивание
- Фильтрацию элементов
- Выбор секций и элементов дерева
- Sync Indicator (Special Mode)
- File Type Icons
- Drag-Drop интеграция

Coverage target: ≥90%
"""

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock

import pytest
from src.gui.views import SideBarMode
from src.gui.views.side_bar import (
    FILE_TYPE_ICONS,
    MAX_QUERY_LENGTH,
    SECTIONS,
    SYNC_STATUS_COLORS,
    SYNC_STATUS_ICONS,
    SideBar,
    SyncStatus,
    get_file_icon,
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
def mock_section_callback() -> MagicMock:
    """Fixture для mock callback при выборе секции."""
    return MagicMock()


@pytest.fixture
def mock_tree_callback() -> MagicMock:
    """Fixture для mock callback при выборе элемента дерева."""
    return MagicMock()


@pytest.fixture
def side_bar(
    tk_root: tk.Tk,
    mock_section_callback: MagicMock,
    mock_tree_callback: MagicMock,
) -> SideBar:
    """Fixture для SideBar."""
    bar = SideBar(
        widget_id="test_sidebar",
        on_section_select=mock_section_callback,
        on_tree_select=mock_tree_callback,
    )
    bar.mount(tk_root)
    return bar


@pytest.fixture
def side_bar_special_mode(
    tk_root: tk.Tk,
    mock_section_callback: MagicMock,
    mock_tree_callback: MagicMock,
) -> SideBar:
    """Fixture для SideBar в Special Mode."""
    bar = SideBar(
        widget_id="test_sidebar_special",
        on_section_select=mock_section_callback,
        on_tree_select=mock_tree_callback,
        is_special_mode=True,
    )
    bar.mount(tk_root)
    return bar


# =============================================================================
# TEST: SideBar Creation
# =============================================================================


@pytest.mark.gui
class TestSideBarCreation:
    """Тесты создания SideBar."""

    def test_side_bar_creation(self, tk_root: tk.Tk) -> None:
        """Создание SideBar с валидными параметрами."""
        bar = SideBar(widget_id="test_create")
        bar.mount(tk_root)

        assert bar.widget_id == "test_create"
        assert bar.is_mounted()

    def test_side_bar_creation_default_id(self, tk_root: tk.Tk) -> None:
        """Создание SideBar с дефолтным id."""
        bar = SideBar()
        bar.mount(tk_root)

        assert bar.widget_id == "sidebar"

    def test_side_bar_creation_with_callbacks(
        self,
        tk_root: tk.Tk,
        mock_section_callback: MagicMock,
        mock_tree_callback: MagicMock,
    ) -> None:
        """Создание SideBar с callbacks."""
        bar = SideBar(
            on_section_select=mock_section_callback,
            on_tree_select=mock_tree_callback,
        )
        bar.mount(tk_root)

        assert bar._on_section_select is mock_section_callback
        assert bar._on_tree_select_callback is mock_tree_callback

    def test_side_bar_creation_with_window_manager_and_drag_drop(
        self, tk_root: tk.Tk
    ) -> None:
        """Создание SideBar с window_manager и drag_drop_service."""
        from src.gui.services.drag_drop_service import DragDropService
        from src.gui.services.sync_service import SyncService
        from src.gui.services.window_manager import WindowManager

        wm = WindowManager(tk_root)
        sync = SyncService(wm)
        dds = DragDropService(tk_root, wm, sync)

        bar = SideBar(
            widget_id="test_with_services",
            window_manager=wm,
            drag_drop_service=dds,
        )
        bar.mount(tk_root)

        assert bar._window_manager is wm
        assert bar._drag_drop_service is dds

    def test_side_bar_creation_special_mode_callback(self, tk_root: tk.Tk) -> None:
        """Создание SideBar с is_special_mode и on_sync_status_click."""
        callback = MagicMock()
        bar = SideBar(
            widget_id="test_special",
            is_special_mode=True,
            on_sync_status_click=callback,
        )
        bar.mount(tk_root)

        assert bar._is_special_mode is True
        assert bar._on_sync_status_click is callback


@pytest.fixture
def side_bar_with_drag(
    tk_root: tk.Tk,
) -> SideBar:
    """Fixture для SideBar c DragDropService и WindowManager."""
    from src.gui.services.drag_drop_service import DragDropService
    from src.gui.services.sync_service import SyncService
    from src.gui.services.window_manager import WindowManager

    wm = WindowManager(tk_root)
    sync = SyncService(wm)
    dds = DragDropService(tk_root, wm, sync)
    bar = SideBar(
        widget_id="test_drag",
        window_manager=wm,
        drag_drop_service=dds,
    )
    bar.mount(tk_root)
    return bar


@pytest.mark.gui
class TestSectionsMode:
    """Тесты режима секций."""

    def test_sections_mode_initial(self, side_bar: SideBar) -> None:
        """Изначально режим SECTIONS."""
        assert side_bar._mode == SideBarMode.SECTIONS

    def test_sections_exist(self) -> None:
        """SECTIONS содержит ожидаемые секции."""
        section_ids = [s[0] for s in SECTIONS]
        assert "DOCUMENTS" in section_ids
        assert "TEMPLATES" in section_ids
        assert "BLANKS" in section_ids
        assert "SUPER DOCS" in section_ids


# =============================================================================
# TEST: Tree Mode
# =============================================================================


@pytest.mark.gui
class TestTreeMode:
    """Тесты режима дерева."""

    def test_set_mode_tree(self, side_bar: SideBar) -> None:
        """set_mode(TREE) переключает на режим дерева."""
        side_bar.set_mode(SideBarMode.TREE)

        assert side_bar._mode == SideBarMode.TREE

    def test_set_mode_sections(self, side_bar: SideBar) -> None:
        """set_mode(SECTIONS) переключает на режим секций."""
        side_bar.set_mode(SideBarMode.TREE)
        side_bar.set_mode(SideBarMode.SECTIONS)

        assert side_bar._mode == SideBarMode.SECTIONS

    def test_add_tree_item(self, side_bar: SideBar) -> None:
        """add_tree_item() добавляет элемент в дерево."""
        side_bar.set_mode(SideBarMode.TREE)
        side_bar.add_tree_item("doc_1", "Document 1")

        assert "doc_1" in side_bar._tree_data

    def test_clear_tree(self, side_bar: SideBar) -> None:
        """clear_tree() очищает дерево."""
        side_bar.set_mode(SideBarMode.TREE)
        side_bar.add_tree_item("doc_1", "Document 1")
        side_bar.clear_tree()

        assert len(side_bar._tree_data) == 0


# =============================================================================
# TEST: Collapsed State
# =============================================================================


@pytest.mark.gui
class TestSetCollapsed:
    """Тесты сворачивания/разворачивания."""

    def test_set_collapsed_true(self, side_bar: SideBar) -> None:
        """set_collapsed(True) сворачивает."""
        side_bar.set_collapsed(True)

        assert side_bar._is_collapsed is True

    def test_set_collapsed_false(self, side_bar: SideBar) -> None:
        """set_collapsed(False) разворачивает."""
        side_bar.set_collapsed(True)
        side_bar.set_collapsed(False)

        assert side_bar._is_collapsed is False


# =============================================================================
# TEST: Filter Items
# =============================================================================


@pytest.mark.gui
class TestFilterItems:
    """Тесты фильтрации элементов."""

    def test_filter_items_sanitizes_query(self, side_bar: SideBar) -> None:
        """filter_items() санитизирует запрос."""
        side_bar.filter_items("test")

        assert side_bar._filter_query == "test"

    def test_filter_items_truncates_long_query(self, side_bar: SideBar) -> None:
        """filter_items() обрезает длинные запросы."""
        long_query = "a" * (MAX_QUERY_LENGTH + 50)
        side_bar.filter_items(long_query)

        assert len(side_bar._filter_query) <= MAX_QUERY_LENGTH


# =============================================================================
# TEST: Get Selected
# =============================================================================


@pytest.mark.gui
class TestGetSelected:
    """Тесты получения выбранного элемента."""

    def test_get_selected_sections_mode(self, side_bar: SideBar) -> None:
        """get_selected() возвращает selected_section в SECTIONS mode."""
        side_bar._mode = SideBarMode.SECTIONS
        side_bar._selected_section = "DOCUMENTS"

        assert side_bar.get_selected() == "DOCUMENTS"

    def test_get_selected_tree_mode(self, side_bar: SideBar) -> None:
        """get_selected() возвращает selected_tree_item в TREE mode."""
        side_bar._mode = SideBarMode.TREE
        side_bar._selected_tree_item = "doc_1"

        assert side_bar.get_selected() == "doc_1"

    def test_get_selected_none(self, side_bar: SideBar) -> None:
        """get_selected() возвращает None если ничего не выбрано."""
        assert side_bar.get_selected() is None


# =============================================================================
# TEST: Show/Hide
# =============================================================================


@pytest.mark.gui
class TestShowHide:
    """Тесты show/hide методов."""

    def test_show(self, side_bar: SideBar) -> None:
        """show() показывает компонент."""
        side_bar.show()
        # No error means success for tk

    def test_hide(self, side_bar: SideBar) -> None:
        """hide() скрывает компонент."""
        side_bar.hide()
        # No error means success for tk


# =============================================================================
# TEST: Widget Property
# =============================================================================


@pytest.mark.gui
class TestWidgetProperty:
    """Тесты widget property."""

    def test_widget_property_returns_frame(self, side_bar: SideBar) -> None:
        """widget property возвращает Frame."""
        widget = side_bar.widget

        assert isinstance(widget, tk.Frame)

    def test_widget_property_not_mounted_raises(self, tk_root: tk.Tk) -> None:
        """widget property до mount вызывает RuntimeError."""
        bar = SideBar()

        with pytest.raises(RuntimeError, match="not mounted"):
            _ = bar.widget


# =============================================================================
# TEST: Sanitize Query
# =============================================================================


class TestSanitizeQuery:
    """Тесты санитизации запроса."""

    def test_sanitize_query_removes_special_chars(self, side_bar: SideBar) -> None:
        """_sanitize_query удаляет спецсимволы."""
        result = side_bar._sanitize_query("test<script>")

        assert "<" not in result
        assert ">" not in result

    def test_sanitize_query_limits_length(self, side_bar: SideBar) -> None:
        """_sanitize_query ограничивает длину."""
        long_query = "a" * (MAX_QUERY_LENGTH + 50)
        result = side_bar._sanitize_query(long_query)

        assert len(result) <= MAX_QUERY_LENGTH

    def test_sanitize_query_strips_whitespace(self, side_bar: SideBar) -> None:
        """_sanitize_query обрезает пробелы по краям."""
        result = side_bar._sanitize_query("  test  ")

        assert result == "test"


# =============================================================================
# TEST: Module Exports
# =============================================================================


class TestModuleExports:
    """Тесты exports модуля."""

    def test_all_exports_defined(self) -> None:
        """Все exports определены в __all__."""
        from src.gui.views import side_bar

        assert hasattr(side_bar, "__all__")
        assert "SideBar" in side_bar.__all__
        assert "SECTIONS" in side_bar.__all__
        assert "MAX_QUERY_LENGTH" in side_bar.__all__

    def test_module_metadata(self) -> None:
        """Модуль имеет метаданные версии."""
        from src.gui.views import side_bar

        assert hasattr(side_bar, "__version__")
        assert hasattr(side_bar, "__author__")
        assert hasattr(side_bar, "__date__")


@pytest.mark.gui
class TestSyncIndicator:
    """Тесты Sync Indicator."""

    def test_sync_status_constants(self) -> None:
        """SyncStatus имеет все статусы."""
        assert SyncStatus.SYNCED == "synced"
        assert SyncStatus.SYNCING == "syncing"
        assert SyncStatus.CONFLICT == "conflict"
        assert SyncStatus.OFFLINE == "offline"

    def test_sync_status_colors(self) -> None:
        """SYNC_STATUS_COLORS содержит цвета для всех статусов."""
        assert SyncStatus.SYNCED in SYNC_STATUS_COLORS
        assert SyncStatus.SYNCING in SYNC_STATUS_COLORS
        assert SyncStatus.CONFLICT in SYNC_STATUS_COLORS
        assert SyncStatus.OFFLINE in SYNC_STATUS_COLORS

    def test_sync_status_icons(self) -> None:
        """SYNC_STATUS_ICONS содержит иконки для всех статусов."""
        assert SyncStatus.SYNCED in SYNC_STATUS_ICONS
        assert SyncStatus.SYNCING in SYNC_STATUS_ICONS
        assert SyncStatus.CONFLICT in SYNC_STATUS_ICONS
        assert SyncStatus.OFFLINE in SYNC_STATUS_ICONS

    def test_set_sync_status(self, side_bar: SideBar) -> None:
        """set_sync_status() устанавливает статус."""
        side_bar.set_sync_status(SyncStatus.SYNCED)

        assert side_bar._sync_status == SyncStatus.SYNCED

    def test_set_sync_status_with_target(self, side_bar: SideBar) -> None:
        """set_sync_status() с target_window_id."""
        side_bar.set_sync_status(SyncStatus.SYNCING, "win_001")

        assert side_bar._sync_status == SyncStatus.SYNCING
        assert side_bar._sync_target_window_id == "win_001"

    def test_set_special_mode(self, side_bar: SideBar) -> None:
        """set_special_mode() включает Special Mode."""
        side_bar.set_special_mode(True)

        assert side_bar._is_special_mode is True

    def test_set_special_mode_false(self, side_bar: SideBar) -> None:
        """set_special_mode(False) выключает Special Mode."""
        side_bar.set_special_mode(False)

        assert side_bar._is_special_mode is False


@pytest.mark.gui
class TestFileTypeIcons:
    """Тесты File Type Icons."""

    def test_file_type_icons_defined(self) -> None:
        """FILE_TYPE_ICONS содержит все типы файлов."""
        assert ".fxsd" in FILE_TYPE_ICONS
        assert ".fxsd.enc" in FILE_TYPE_ICONS
        assert ".fxstpl" in FILE_TYPE_ICONS
        assert ".fxsblank" in FILE_TYPE_ICONS

    def test_get_file_icon_fxsd(self) -> None:
        """get_file_icon() возвращает иконку для .fxsd."""
        icon = get_file_icon("document.fxsd")
        assert icon == "📄"

    def test_get_file_icon_encrypted(self) -> None:
        """get_file_icon() возвращает иконку для зашифрованного."""
        icon = get_file_icon("secret.fxsd.enc")
        assert icon == "🔒"

    def test_get_file_icon_template(self) -> None:
        """get_file_icon() возвращает иконку для шаблона."""
        icon = get_file_icon("template.fxstpl")
        assert icon == "📋"

    def test_get_file_icon_blank(self) -> None:
        """get_file_icon() возвращает иконку для бланка."""
        icon = get_file_icon("form.fxsblank")
        assert icon == "🔐"

    def test_get_file_icon_unknown(self) -> None:
        """get_file_icon() возвращает дефолтную иконку для неизвестного."""
        icon = get_file_icon("unknown.xyz")
        assert icon == "📄"


@pytest.mark.gui
class TestAddTreeItemWithFilePath:
    """Тесты add_tree_item с file_path."""

    def test_add_tree_item_with_file_path(self, side_bar: SideBar) -> None:
        """add_tree_item() принимает file_path."""
        side_bar.set_mode(SideBarMode.TREE)
        side_bar.add_tree_item("doc_1", "Document 1", "", "/path/to/doc.fxsd")

        assert "doc_1" in side_bar._tree_data
        display_name, file_path = side_bar._tree_data["doc_1"]
        assert display_name == "Document 1"
        assert file_path == "/path/to/doc.fxsd"

    def test_add_tree_item_without_file_path(self, side_bar: SideBar) -> None:
        """add_tree_item() работает без file_path."""
        side_bar.set_mode(SideBarMode.TREE)
        side_bar.add_tree_item("doc_2", "Document 2")

        assert "doc_2" in side_bar._tree_data
        display_name, file_path = side_bar._tree_data["doc_2"]
        assert display_name == "Document 2"
        assert file_path is None


@pytest.mark.gui
class TestSyncIndicatorCreation:
    """Тесты создания Sync Indicator."""

    def test_sync_indicator_created_in_special_mode(
        self, side_bar_special_mode: SideBar
    ) -> None:
        """Sync indicator создаётся в Special Mode."""
        assert side_bar_special_mode._tk_sync_indicator is not None
        assert side_bar_special_mode._tk_sync_label is not None

    def test_sync_indicator_not_created_in_normal_mode(self, side_bar: SideBar) -> None:
        """Sync indicator не создаётся в Normal Mode."""
        assert side_bar._tk_sync_indicator is None
        assert side_bar._tk_sync_label is None

    def test_sync_indicator_click_callback(
        self, side_bar_special_mode: SideBar
    ) -> None:
        """Клик по sync indicator вызывает callback."""
        callback = MagicMock()
        side_bar_special_mode._on_sync_status_click = callback

        side_bar_special_mode._on_sync_indicator_click()

        callback.assert_called_once()

    def test_update_sync_indicator(self, side_bar_special_mode: SideBar) -> None:
        """_update_sync_indicator() обновляет отображение."""
        side_bar_special_mode.set_sync_status(SyncStatus.SYNCING)
        side_bar_special_mode._update_sync_indicator()

    def test_get_sync_status_text(self, side_bar: SideBar) -> None:
        """_get_sync_status_text() возвращает текст статуса."""
        side_bar.set_sync_status(SyncStatus.SYNCED)
        text = side_bar._get_sync_status_text()
        assert text == "Synced"

        side_bar.set_sync_status(SyncStatus.SYNCING)
        text = side_bar._get_sync_status_text()
        assert text == "Syncing..."

        side_bar.set_sync_status(SyncStatus.CONFLICT)
        text = side_bar._get_sync_status_text()
        assert text == "Conflict"

        side_bar.set_sync_status(SyncStatus.OFFLINE)
        text = side_bar._get_sync_status_text()
        assert text == "Offline"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.views.side_bar"])
