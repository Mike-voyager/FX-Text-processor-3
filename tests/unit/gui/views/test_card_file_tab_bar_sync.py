"""Unit-тесты для wiring SyncService в CardFileTabBar.

Проверяет:
- Передача sync_service от MainWindow в CardFileTabBar
- Регистрация handler при создании вкладки
- Корректный unmount sync_indicator при закрытии вкладки

Coverage target: ≥90%
"""

from __future__ import annotations

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock

import pytest
from src.documents.types.document_type import DocumentMode
from src.gui.views.card_file_tab_bar import CardFileTabBar

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
def mock_sync_service() -> MagicMock:
    """Mock SyncService с поддержкой register_handler/unregister_handler."""
    service = MagicMock()
    service.register_handler.return_value = "handler_123"
    return service


@pytest.fixture
def tab_bar_with_sync(
    tk_root: tk.Tk,
    mock_sync_service: MagicMock,
) -> CardFileTabBar:
    """Fixture для CardFileTabBar с переданным sync_service."""
    bar = CardFileTabBar(
        widget_id="test_tabbar_sync",
        sync_service=mock_sync_service,
    )
    bar.mount(tk_root)
    return bar


# =============================================================================
# TEST: Sync Service Wiring
# =============================================================================


@pytest.mark.gui
class TestSyncServiceWiring:
    """Тесты проводки SyncService от MainWindow к TabSyncIndicator."""

    def test_sync_service_passed_to_indicator(
        self,
        tab_bar_with_sync: CardFileTabBar,
        mock_sync_service: MagicMock,
    ) -> None:
        """add_tab передаёт sync_service в TabSyncIndicator при создании вкладки."""
        tab_bar_with_sync.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM)

        tab_info = tab_bar_with_sync._tabs["doc_1"]
        assert tab_info.sync_indicator is not None
        assert tab_info.sync_indicator._sync_service is mock_sync_service
        mock_sync_service.register_handler.assert_called_once()

    def test_sync_indicator_unmount_on_close(
        self,
        tab_bar_with_sync: CardFileTabBar,
        mock_sync_service: MagicMock,
    ) -> None:
        """close_tab вызывает unmount на sync_indicator перед удалением."""
        tab_bar_with_sync.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM)

        tab_info = tab_bar_with_sync._tabs["doc_1"]
        assert tab_info.sync_indicator is not None
        tab_bar_with_sync.close_tab("doc_1")

        mock_sync_service.unregister_handler.assert_called_once_with("handler_123")
        assert "doc_1" not in tab_bar_with_sync._tabs

    def test_sync_indicator_unmount_on_close_all(
        self,
        tab_bar_with_sync: CardFileTabBar,
        mock_sync_service: MagicMock,
    ) -> None:
        """_close_all_tabs вызывает unmount для всех sync_indicator."""
        tab_bar_with_sync.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM)
        tab_bar_with_sync.add_tab("doc_2", "Document 2", DocumentMode.STRUCTURED_FORM)

        tab_bar_with_sync._close_all_tabs()

        assert mock_sync_service.unregister_handler.call_count == 2
        assert len(tab_bar_with_sync._tabs) == 0

    def test_sync_indicator_unmount_on_close_others(
        self,
        tab_bar_with_sync: CardFileTabBar,
        mock_sync_service: MagicMock,
    ) -> None:
        """_close_other_tabs вызывает unmount для остальных sync_indicator."""
        tab_bar_with_sync.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM)
        tab_bar_with_sync.add_tab("doc_2", "Document 2", DocumentMode.STRUCTURED_FORM)
        tab_bar_with_sync.add_tab("doc_3", "Document 3", DocumentMode.FREE_FORM)

        tab_bar_with_sync._close_other_tabs("doc_2")

        assert mock_sync_service.unregister_handler.call_count == 2
        assert "doc_2" in tab_bar_with_sync._tabs
        assert "doc_1" not in tab_bar_with_sync._tabs
        assert "doc_3" not in tab_bar_with_sync._tabs

    def test_sync_service_optional_none(
        self,
        tk_root: tk.Tk,
    ) -> None:
        """CardFileTabBar корректно работает без sync_service."""
        bar = CardFileTabBar(
            widget_id="test_no_sync",
        )
        bar.mount(tk_root)
        bar.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM)

        tab_info = bar._tabs["doc_1"]
        assert tab_info.sync_indicator is not None
        assert tab_info.sync_indicator._sync_service is None
        bar.close_tab("doc_1")
        assert "doc_1" not in bar._tabs


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.views.card_file_tab_bar"])
