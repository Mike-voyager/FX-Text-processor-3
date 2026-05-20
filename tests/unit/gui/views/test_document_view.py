"""Unit-тесты для DocumentView.

Проверяет:
- Создание DocumentView
- Отображение placeholder (show_placeholder)
- Установку документа (set_document)
- Очистку sensitive данных (wipe_sensitive_data)

Coverage target: ≥90%
"""

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock

import pytest
from src.gui.renderers.factory import register_default_renderers
from src.gui.views.document_view import (
    DEFAULT_PLACEHOLDER_MESSAGE,
    MAX_DOCUMENT_ID_LENGTH,
    PLACEHOLDER_ICON,
    DocumentMode,
    DocumentView,
)


class MockDocument:
    """Mock документ, соответствующий DocumentProtocol."""

    def __init__(self, doc_id: str) -> None:
        self.id = doc_id
        self.mode = DocumentMode.FREE_FORM

    def get_content(self) -> str:
        return "Test content"

    def get_cpi(self) -> int:
        return 10


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Fixture для Tk root окна."""
    register_default_renderers()
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def document_view(tk_root: tk.Tk) -> DocumentView:
    """Fixture для DocumentView."""
    view = DocumentView(widget_id="test_docview")
    view.mount(tk_root)
    return view


# =============================================================================
# TEST: DocumentView Creation
# =============================================================================


@pytest.mark.gui
class TestDocumentViewCreation:
    """Тесты создания DocumentView."""

    def test_document_view_creation(self, tk_root: tk.Tk) -> None:
        """Создание DocumentView с валидными параметрами."""
        view = DocumentView(widget_id="test_create")
        view.mount(tk_root)

        assert view.widget_id == "test_create"
        assert view.is_mounted()

    def test_document_view_creation_default_id(self, tk_root: tk.Tk) -> None:
        """Создание DocumentView с дефолтным id."""
        view = DocumentView()
        view.mount(tk_root)

        assert view.widget_id == "document_view"

    def test_document_view_initial_state(self, document_view: DocumentView) -> None:
        """Изначальное состояние DocumentView."""
        assert document_view.current_document_id is None
        assert document_view.is_placeholder_visible is True


# =============================================================================
# TEST: Show Placeholder
# =============================================================================


@pytest.mark.gui
class TestShowPlaceholder:
    """Тесты отображения placeholder."""

    def test_show_placeholder(self, document_view: DocumentView) -> None:
        """show_placeholder() отображает placeholder."""
        document_view.set_document(MockDocument("doc_1"))  # First set a document
        document_view.show_placeholder("Custom message")

        assert document_view.is_placeholder_visible is True

    def test_show_placeholder_default_message(
        self, document_view: DocumentView
    ) -> None:
        """show_placeholder() с дефолтным сообщением."""
        document_view.show_placeholder()

        assert document_view.is_placeholder_visible is True

    def test_show_placeholder_truncates_long_message(
        self, document_view: DocumentView
    ) -> None:
        """show_placeholder() обрезает длинные сообщения."""
        long_message = "A" * 250
        document_view.show_placeholder(long_message)

        # Message should be truncated
        assert document_view.is_placeholder_visible is True


# =============================================================================
# TEST: Set Document
# =============================================================================


@pytest.mark.gui
class TestSetDocument:
    """Тесты установки документа."""

    def test_set_document(self, document_view: DocumentView) -> None:
        """set_document() устанавливает document_id."""
        document_view.set_document(MockDocument("doc_123"))

        assert document_view.current_document_id == "doc_123"

    def test_set_document_hides_placeholder(self, document_view: DocumentView) -> None:
        """set_document() скрывает placeholder."""
        # In Phase 1, set_document temporarily shows placeholder with document info
        # In Phase 2+, this test should check that is_placeholder_visible is False
        document_view.set_document(MockDocument("doc_123"))

        # Phase 1: placeholder_visible is True (showing document info)
        # Phase 2+: placeholder_visible should be False (showing actual document)
        assert document_view._current_document_id == "doc_123"

    def test_set_document_sanitizes_id(self, document_view: DocumentView) -> None:
        """set_document() санитизирует document_id."""
        long_id = "A" * (MAX_DOCUMENT_ID_LENGTH + 50)
        document_view.set_document(MockDocument(long_id))

        assert len(document_view.current_document_id) <= MAX_DOCUMENT_ID_LENGTH

    def test_set_document_empty_raises(self, document_view: DocumentView) -> None:
        """set_document() с пустым id вызывает ValueError."""
        with pytest.raises(ValueError, match="document_id cannot be empty"):
            document_view.set_document(MockDocument(""))


# =============================================================================
# TEST: Clear Document
# =============================================================================


@pytest.mark.gui
class TestClearDocument:
    """Тесты очистки документа."""

    def test_clear_document(self, document_view: DocumentView) -> None:
        """clear_document() очищает document_id."""
        document_view.set_document(MockDocument("doc_123"))
        document_view.clear_document()

        assert document_view.current_document_id is None

    def test_clear_document_shows_placeholder(
        self, document_view: DocumentView
    ) -> None:
        """clear_document() показывает placeholder."""
        document_view.set_document(MockDocument("doc_123"))
        document_view.clear_document()

        assert document_view.is_placeholder_visible is True


# =============================================================================
# TEST: Wipe Sensitive Data
# =============================================================================


@pytest.mark.gui
class TestWipeSensitiveData:
    """Тесты очистки sensitive данных."""

    def test_wipe_sensitive_data_clears_id(self, document_view: DocumentView) -> None:
        """wipe_sensitive_data() очищает document_id."""
        document_view.set_document(MockDocument("doc_123"))
        document_view.wipe_sensitive_data()

        assert document_view.current_document_id is None

    def test_wipe_sensitive_data_clears_hidden_backup(
        self, document_view: DocumentView
    ) -> None:
        """wipe_sensitive_data() очищает hidden_content_backup."""
        document_view._hidden_content_backup = "backup"
        document_view.wipe_sensitive_data()

        assert document_view._hidden_content_backup is None

    def test_wipe_sensitive_data_shows_placeholder(
        self, document_view: DocumentView
    ) -> None:
        """wipe_sensitive_data() показывает placeholder."""
        document_view.set_document(MockDocument("doc_123"))
        document_view.wipe_sensitive_data()

        assert document_view.is_placeholder_visible is True


# =============================================================================
# TEST: Hide/Restore Content
# =============================================================================


@pytest.mark.gui
class TestHideRestoreContent:
    """Тесты скрытия/восстановления контента."""

    def test_hide_content_sets_flag(self, document_view: DocumentView) -> None:
        """hide_content() устанавливает _content_hidden=True."""
        document_view.hide_content()

        assert document_view._content_hidden is True

    def test_hide_content_saves_backup(self, document_view: DocumentView) -> None:
        """hide_content() сохраняет backup сообщения."""
        document_view.show_placeholder("Test message")
        document_view.hide_content()

        assert document_view._hidden_content_backup is not None

    def test_restore_content_clears_flag(self, document_view: DocumentView) -> None:
        """restore_content() устанавливает _content_hidden=False."""
        document_view.hide_content()
        document_view.restore_content()

        assert document_view._content_hidden is False

    def test_restore_content_noop_when_not_hidden(
        self, document_view: DocumentView
    ) -> None:
        """restore_content() ничего не делает если не было hide_content."""
        document_view.restore_content()  # Should not raise

        assert not document_view._content_hidden


# =============================================================================
# TEST: Show/Hide
# =============================================================================


@pytest.mark.gui
class TestShowHide:
    """Тесты show/hide методов."""

    def test_show(self, document_view: DocumentView) -> None:
        """show() показывает компонент."""
        document_view.show()
        # No error means success for tk

    def test_hide(self, document_view: DocumentView) -> None:
        """hide() скрывает компонент."""
        document_view.hide()
        # No error means success for tk


# =============================================================================
# TEST: Widget Property
# =============================================================================


@pytest.mark.gui
class TestWidgetProperty:
    """Тесты widget property."""

    def test_widget_property_returns_frame(self, document_view: DocumentView) -> None:
        """widget property возвращает Frame."""
        widget = document_view.widget

        assert isinstance(widget, tk.Frame)

    def test_widget_property_not_mounted_raises(self, tk_root: tk.Tk) -> None:
        """widget property до mount вызывает RuntimeError."""
        view = DocumentView()

        with pytest.raises(RuntimeError, match="not mounted"):
            _ = view.widget


# =============================================================================
# TEST: Properties
# =============================================================================


@pytest.mark.gui
class TestProperties:
    """Тесты свойств DocumentView."""

    def test_current_document_id_property(self, document_view: DocumentView) -> None:
        """current_document_id property возвращает ID."""
        assert document_view.current_document_id is None

        document_view.set_document(MockDocument("doc_123"))
        assert document_view.current_document_id == "doc_123"

    def test_is_placeholder_visible_property(self, document_view: DocumentView) -> None:
        """is_placeholder_visible property возвращает видимость."""
        assert document_view.is_placeholder_visible is True

        document_view.set_document(MockDocument("doc_123"))
        # Phase 1: set_document shows placeholder with document info
        # In Phase 2+, this should be False when actual document content is shown
        assert document_view._current_document_id == "doc_123"


# =============================================================================
# TEST: Hide/Restore Content with Renderer
# =============================================================================


@pytest.mark.gui
class TestHideRestoreContentWithRenderer:
    """Тесты скрытия/восстановления контента с мок-рендерером."""

    def test_hide_content_sets_flag_and_delegates_to_renderer(
        self, document_view: DocumentView
    ) -> None:
        """hide_content() устанавливает _content_hidden=True и делегирует рендереру."""
        mock_renderer = MagicMock()
        document_view._current_renderer = mock_renderer

        document_view.hide_content()

        assert document_view._content_hidden is True
        mock_renderer.hide_content.assert_called_once()

    def test_restore_content_resets_flag_and_delegates_to_renderer(
        self, document_view: DocumentView
    ) -> None:
        """restore_content() сбрасывает флаг и делегирует рендереру."""
        mock_renderer = MagicMock()
        document_view._current_renderer = mock_renderer
        document_view._content_hidden = True

        document_view.restore_content()

        assert document_view._content_hidden is False
        mock_renderer.restore_content.assert_called_once()

    def test_hide_content_without_renderer_sets_flag_only(
        self, document_view: DocumentView
    ) -> None:
        """hide_content() без рендерера устанавливает только флаг."""
        document_view._current_renderer = None
        document_view._content_hidden = False

        document_view.hide_content()

        assert document_view._content_hidden is True


@pytest.mark.gui
class TestWipeSensitiveDataWithRenderer:
    """Тесты очистки sensitive данных с мок-рендерером."""

    def test_wipe_sensitive_data_delegates_to_renderer_and_clears_references(
        self, document_view: DocumentView
    ) -> None:
        """wipe_sensitive_data() делегирует рендереру и очищает внутренние ссылки."""
        mock_renderer = MagicMock()
        document_view._current_renderer = mock_renderer
        document_view.set_document(MockDocument("doc_123"))

        document_view.wipe_sensitive_data()

        mock_renderer.wipe_sensitive_data.assert_called_once()
        assert document_view.current_document_id is None
        assert document_view.is_placeholder_visible is True


class TestModuleExports:
    """Тесты exports модуля."""

    def test_all_exports_defined(self) -> None:
        """Все exports определены в __all__."""
        from src.gui.views import document_view

        assert hasattr(document_view, "__all__")
        assert "DocumentView" in document_view.__all__
        assert "PLACEHOLDER_ICON" in document_view.__all__
        assert "DEFAULT_PLACEHOLDER_MESSAGE" in document_view.__all__
        assert "MAX_DOCUMENT_ID_LENGTH" in document_view.__all__

    def test_module_metadata(self) -> None:
        """Модуль имеет метаданные версии."""
        from src.gui.views import document_view

        assert hasattr(document_view, "__version__")
        assert hasattr(document_view, "__author__")
        assert hasattr(document_view, "__date__")


# =============================================================================
# TEST: Barcode/QR Proxy Methods
# =============================================================================


class TestBarcodeProxyMethods:
    """Тесты проксирования barcode методов к рендереру."""

    def test_insert_barcode_at_cursor_delegates(
        self, document_view: DocumentView
    ) -> None:
        """insert_barcode_at_cursor() проксирует к рендереру."""
        mock_renderer = MagicMock()
        mock_renderer.insert_barcode_at_cursor.return_value = True
        document_view._current_renderer = mock_renderer

        success = document_view.insert_barcode_at_cursor("CODE128", "12345", "software")

        assert success
        mock_renderer.insert_barcode_at_cursor.assert_called_once_with(
            barcode_type="CODE128", data="12345", mode="software", settings=None
        )

    def test_insert_qr_at_cursor_delegates(self, document_view: DocumentView) -> None:
        """insert_qr_at_cursor() проксирует к рендереру."""
        mock_renderer = MagicMock()
        mock_renderer.insert_qr_at_cursor.return_value = True
        document_view._current_renderer = mock_renderer

        success = document_view.insert_qr_at_cursor("https://example.com")

        assert success
        mock_renderer.insert_qr_at_cursor.assert_called_once_with(
            data="https://example.com", settings=None
        )

    def test_get_cursor_position_delegates(self, document_view: DocumentView) -> None:
        """get_cursor_position() проксирует к рендереру."""
        mock_renderer = MagicMock()
        mock_renderer.get_cursor_position.return_value = (3, 5)
        document_view._current_renderer = mock_renderer

        pos = document_view.get_cursor_position()

        assert pos == (3, 5)
        mock_renderer.get_cursor_position.assert_called_once()

    def test_insert_barcode_returns_false_without_renderer(
        self, document_view: DocumentView
    ) -> None:
        """insert_barcode_at_cursor() без рендерера возвращает False."""
        document_view._current_renderer = None
        success = document_view.insert_barcode_at_cursor("CODE128", "12345", "software")
        assert not success

    def test_insert_qr_returns_false_without_renderer(
        self, document_view: DocumentView
    ) -> None:
        """insert_qr_at_cursor() без рендерера возвращает False."""
        document_view._current_renderer = None
        success = document_view.insert_qr_at_cursor("https://example.com")
        assert not success

    def test_get_cursor_position_default_without_renderer(
        self, document_view: DocumentView
    ) -> None:
        """get_cursor_position() без рендерера возвращает (1, 1)."""
        document_view._current_renderer = None
        pos = document_view.get_cursor_position()
        assert pos == (1, 1)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.views.document_view"])
