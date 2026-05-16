"""Unit-тесты для CardFileTabBar.

Проверяет:
- Добавление вкладки (add_tab)
- Закрытие вкладки (close_tab)
- Установку активной вкладки (set_active_tab)
- Установку индикатора изменений (set_tab_modified)
- Лимит на количество вкладок

Coverage target: ≥90%
"""

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock

import pytest
from src.documents.types.document_type import DocumentMode
from src.gui.views.card_file_tab_bar import (
    ICON_FREEFORM,
    ICON_MODIFIED,
    ICON_STRUCTURED,
    MAX_TABS,
    MAX_TITLE_LENGTH,
    CardFileTabBar,
    TabInfo,
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
def mock_new_tab_callback() -> MagicMock:
    """Fixture для mock callback создания вкладки."""
    return MagicMock()


@pytest.fixture
def mock_close_callback() -> MagicMock:
    """Fixture для mock callback закрытия вкладки (returns True)."""
    return MagicMock(return_value=True)


@pytest.fixture
def mock_activate_callback() -> MagicMock:
    """Fixture для mock callback активации вкладки."""
    return MagicMock()


@pytest.fixture
def tab_bar(
    tk_root: tk.Tk,
    mock_new_tab_callback: MagicMock,
    mock_close_callback: MagicMock,
    mock_activate_callback: MagicMock,
) -> CardFileTabBar:
    """Fixture для CardFileTabBar."""
    bar = CardFileTabBar(
        widget_id="test_tabbar",
        on_new_tab=mock_new_tab_callback,
        on_tab_close=mock_close_callback,
        on_tab_activate=mock_activate_callback,
    )
    bar.mount(tk_root)
    return bar


# =============================================================================
# TEST: Add Tab
# =============================================================================


@pytest.mark.gui
class TestAddTab:
    """Тесты добавления вкладок."""

    def test_add_tab(self, tab_bar: CardFileTabBar) -> None:
        """add_tab() добавляет вкладку."""
        tab_bar.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM)

        assert "doc_1" in tab_bar._tabs
        assert len(tab_bar._tabs) == 1

    def test_add_tab_creates_tab_info(self, tab_bar: CardFileTabBar) -> None:
        """add_tab() создаёт TabInfo."""
        tab_bar.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM)

        tab_info = tab_bar._tabs["doc_1"]
        assert isinstance(tab_info, TabInfo)
        assert tab_info.document_id == "doc_1"
        assert tab_info.title == "Document 1"
        assert tab_info.mode == DocumentMode.FREE_FORM

    def test_add_tab_with_modified(self, tab_bar: CardFileTabBar) -> None:
        """add_tab() с modified=True создаёт modified вкладку."""
        tab_bar.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM, modified=True)

        assert tab_bar._tabs["doc_1"].modified is True

    def test_add_tab_activates_first(self, tab_bar: CardFileTabBar) -> None:
        """add_tab() активирует первую вкладку."""
        tab_bar.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM)

        assert tab_bar._active_tab_id == "doc_1"

    def test_add_tab_duplicate_activates_existing(
        self, tab_bar: CardFileTabBar
    ) -> None:
        """add_tab() с существующим id активирует существующую вкладку."""
        tab_bar.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM)
        tab_bar.add_tab("doc_2", "Document 2", DocumentMode.FREE_FORM)

        tab_bar.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM)  # Duplicate

        assert tab_bar._active_tab_id == "doc_1"

    def test_add_tab_exceeds_limit_raises(self, tab_bar: CardFileTabBar) -> None:
        """add_tab() превышающий лимит вызывает ValueError."""
        # Fill up to limit
        for i in range(MAX_TABS):
            tab_bar.add_tab(f"doc_{i}", f"Document {i}", DocumentMode.FREE_FORM)

        with pytest.raises(ValueError, match="Tab limit reached"):
            tab_bar.add_tab("extra", "Extra", DocumentMode.FREE_FORM)

    def test_add_tab_invalid_document_id_raises(self, tab_bar: CardFileTabBar) -> None:
        """add_tab() с невалидным document_id вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid document_id"):
            tab_bar.add_tab("invalid id!", "Title", DocumentMode.FREE_FORM)

    def test_add_tab_truncates_long_title(self, tab_bar: CardFileTabBar) -> None:
        """add_tab() обрезает длинные заголовки."""
        long_title = "A" * (MAX_TITLE_LENGTH + 50)
        tab_bar.add_tab("doc_1", long_title, DocumentMode.FREE_FORM)

        assert len(tab_bar._tabs["doc_1"].title) <= MAX_TITLE_LENGTH


# =============================================================================
# TEST: Close Tab
# =============================================================================


@pytest.mark.gui
class TestCloseTab:
    """Тесты закрытия вкладок."""

    def test_close_tab(self, tab_bar: CardFileTabBar) -> None:
        """close_tab() закрывает вкладку."""
        tab_bar.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM)

        result = tab_bar.close_tab("doc_1")

        assert result is True
        assert "doc_1" not in tab_bar._tabs

    def test_close_tab_calls_callback(
        self, tab_bar: CardFileTabBar, mock_close_callback: MagicMock
    ) -> None:
        """close_tab() вызывает on_tab_close callback."""
        tab_bar.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM)

        tab_bar.close_tab("doc_1")

        mock_close_callback.assert_called_once_with("doc_1")

    def test_close_tab_callback_returns_false(self, tab_bar: CardFileTabBar) -> None:
        """close_tab() возвращает False если callback возвращает False."""
        tab_bar._on_tab_close = MagicMock(return_value=False)
        tab_bar.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM)

        result = tab_bar.close_tab("doc_1")

        assert result is False
        # Tab should still exist
        assert "doc_1" in tab_bar._tabs

    def test_close_tab_not_found_returns_false(self, tab_bar: CardFileTabBar) -> None:
        """close_tab() для несуществующей вкладки возвращает False."""
        result = tab_bar.close_tab("nonexistent")

        assert result is False

    def test_close_tab_invalid_id_returns_false(self, tab_bar: CardFileTabBar) -> None:
        """close_tab() с невалидным id возвращает False."""
        result = tab_bar.close_tab("invalid id!")

        assert result is False

    def test_close_tab_activates_previous(self, tab_bar: CardFileTabBar) -> None:
        """close_tab() активирует предыдущую вкладку."""
        tab_bar.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM)
        tab_bar.add_tab("doc_2", "Document 2", DocumentMode.FREE_FORM)

        tab_bar.close_tab("doc_2")

        assert tab_bar._active_tab_id == "doc_1"


# =============================================================================
# TEST: Set Active Tab
# =============================================================================


@pytest.mark.gui
class TestSetActiveTab:
    """Тесты установки активной вкладки."""

    def test_set_active_tab(self, tab_bar: CardFileTabBar) -> None:
        """set_active_tab() устанавливает активную вкладку."""
        tab_bar.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM)
        tab_bar.add_tab("doc_2", "Document 2", DocumentMode.FREE_FORM)

        tab_bar.set_active_tab("doc_1")

        assert tab_bar._active_tab_id == "doc_1"

    def test_set_active_tab_calls_callback(
        self, tab_bar: CardFileTabBar, mock_activate_callback: MagicMock
    ) -> None:
        """set_active_tab() вызывает on_tab_activate callback."""
        tab_bar.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM)
        tab_bar.add_tab("doc_2", "Document 2", DocumentMode.FREE_FORM)

        tab_bar.set_active_tab("doc_2")

        mock_activate_callback.assert_called_with("doc_2")

    def test_set_active_tab_invalid_id_raises(self, tab_bar: CardFileTabBar) -> None:
        """set_active_tab() с невалидным id вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid document_id"):
            tab_bar.set_active_tab("invalid id!")

    def test_set_active_tab_not_found_noop(self, tab_bar: CardFileTabBar) -> None:
        """set_active_tab() для несуществующей вкладки ничего не делает."""
        tab_bar.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM)

        tab_bar.set_active_tab("nonexistent")  # Should not raise


# =============================================================================
# TEST: Set Tab Modified
# =============================================================================


@pytest.mark.gui
class TestSetTabModified:
    """Тесты установки индикатора изменений."""

    def test_set_tab_modified_true(self, tab_bar: CardFileTabBar) -> None:
        """set_tab_modified(True) устанавливает modified=True."""
        tab_bar.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM)

        tab_bar.set_tab_modified("doc_1", True)

        assert tab_bar._tabs["doc_1"].modified is True

    def test_set_tab_modified_false(self, tab_bar: CardFileTabBar) -> None:
        """set_tab_modified(False) устанавливает modified=False."""
        tab_bar.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM, modified=True)

        tab_bar.set_tab_modified("doc_1", False)

        assert tab_bar._tabs["doc_1"].modified is False

    def test_set_tab_modified_invalid_id_raises(self, tab_bar: CardFileTabBar) -> None:
        """set_tab_modified() с невалидным id вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid document_id"):
            tab_bar.set_tab_modified("invalid id!", True)

    def test_set_tab_modified_not_found_noop(self, tab_bar: CardFileTabBar) -> None:
        """set_tab_modified() для несуществующей вкладки ничего не делает."""
        tab_bar.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM)

        tab_bar.set_tab_modified("nonexistent", True)  # Should not raise


# =============================================================================
# TEST: Get Active Tab
# =============================================================================


@pytest.mark.gui
class TestGetActiveTab:
    """Тесты получения активной вкладки."""

    def test_get_active_tab(self, tab_bar: CardFileTabBar) -> None:
        """get_active_tab() возвращает активную вкладку."""
        tab_bar.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM)

        assert tab_bar.get_active_tab() == "doc_1"

    def test_get_active_tab_none(self, tab_bar: CardFileTabBar) -> None:
        """get_active_tab() возвращает None если нет вкладок."""
        assert tab_bar.get_active_tab() is None


# =============================================================================
# TEST: Show/Hide
# =============================================================================


@pytest.mark.gui
class TestShowHide:
    """Тесты show/hide методов."""

    def test_show(self, tab_bar: CardFileTabBar) -> None:
        """show() показывает компонент."""
        tab_bar.show()
        # No error means success for tk

    def test_hide(self, tab_bar: CardFileTabBar) -> None:
        """hide() скрывает компонент."""
        tab_bar.hide()
        # No error means success for tk


# =============================================================================
# TEST: Widget Property
# =============================================================================


@pytest.mark.gui
class TestWidgetProperty:
    """Тесты widget property."""

    def test_widget_property_returns_frame(self, tab_bar: CardFileTabBar) -> None:
        """widget property возвращает Frame."""
        widget = tab_bar.widget

        assert isinstance(widget, tk.Frame)

    def test_widget_property_not_mounted_raises(self, tk_root: tk.Tk) -> None:
        """widget property до mount вызывает RuntimeError."""
        bar = CardFileTabBar()

        with pytest.raises(RuntimeError, match="is not mounted"):
            _ = bar.widget


# =============================================================================
# TEST: Tab Icons
# =============================================================================


class TestTabIcons:
    """Тесты иконок вкладок."""

    def test_icon_free_form(self, tab_bar: CardFileTabBar) -> None:
        """FREE_FORM использует ICON_FREEFORM."""
        icon = tab_bar._get_icon_for_mode(DocumentMode.FREE_FORM)

        assert icon == ICON_FREEFORM

    def test_icon_structured_form(self, tab_bar: CardFileTabBar) -> None:
        """STRUCTURED_FORM использует ICON_STRUCTURED."""
        icon = tab_bar._get_icon_for_mode(DocumentMode.STRUCTURED_FORM)

        assert icon == ICON_STRUCTURED


# =============================================================================
# TEST: Max Tabs Limit
# =============================================================================


class TestMaxTabsLimit:
    """Тесты лимита на количество вкладок."""

    def test_max_tabs_constant(self) -> None:
        """MAX_TABS имеет разумное значение."""
        assert MAX_TABS > 0
        assert MAX_TABS < 100  # Should be reasonable


# =============================================================================
# TEST: Module Exports
# =============================================================================


class TestModuleExports:
    """Тесты exports модуля."""

    def test_all_exports_defined(self) -> None:
        """Все exports определены в __all__."""
        from src.gui.views import card_file_tab_bar

        assert hasattr(card_file_tab_bar, "__all__")
        assert "CardFileTabBar" in card_file_tab_bar.__all__
        assert "TabInfo" in card_file_tab_bar.__all__
        assert "MAX_TABS" in card_file_tab_bar.__all__
        assert "MAX_TITLE_LENGTH" in card_file_tab_bar.__all__

    def test_module_metadata(self) -> None:
        """Модуль имеет метаданные версии."""
        from src.gui.views import card_file_tab_bar

        assert hasattr(card_file_tab_bar, "__version__")
        assert hasattr(card_file_tab_bar, "__author__")
        assert hasattr(card_file_tab_bar, "__date__")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.views.card_file_tab_bar"])
