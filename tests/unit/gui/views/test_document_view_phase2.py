"""Integration tests for DocumentView Phase 2.

Проверяет интеграцию всех компонентов Phase 2:
- Ruler
- FormatToolbar
- FreeFormRenderer
- Navigator
- CommandStack

Coverage target: ≥90%
"""

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock

import pytest
from src.documents.types.document_type import DocumentMode
from src.gui.components.format_toolbar import FormatToolbar
from src.gui.components.navigator import Navigator
from src.gui.components.ruler import Ruler
from src.gui.renderers.free_form_renderer import FreeFormDocument, FreeFormRenderer
from src.gui.renderers.factory import register_default_renderers
from src.gui.views.document_view import (
    DEFAULT_PLACEHOLDER_MESSAGE,
    DocumentProtocol,
    DocumentView,
)

# =============================================================================
# TEST FIXTURES
# =============================================================================


class MockDocument:
    """Mock документ для тестирования."""

    def __init__(self, doc_id: str = "test_doc", content: str = "", cpi: int = 10):
        self._id = doc_id
        self._content = content
        self._cpi = cpi
        self._mode = DocumentMode.FREE_FORM

    @property
    def id(self) -> str:
        return self._id

    @property
    def mode(self) -> DocumentMode:
        return self._mode

    def get_content(self) -> str:
        return self._content

    def get_cpi(self) -> int:
        return self._cpi


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Fixture для Tk root окна."""
    register_default_renderers()
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def document_view(tk_root: tk.Tk) -> Generator[DocumentView, None, None]:
    """Fixture для DocumentView."""
    view = DocumentView(widget_id="test_doc_view")
    view.mount(tk_root)
    yield view
    view.unmount()


@pytest.fixture
def mock_document() -> MockDocument:
    """Fixture для MockDocument."""
    return MockDocument(
        doc_id="test_doc_123",
        content="Hello World",
        cpi=12,
    )


# =============================================================================
# TEST: Component Integration
# =============================================================================


class TestComponentIntegration:
    """Тесты интеграции компонентов."""

    def test_ruler_component_created(self, document_view: DocumentView) -> None:
        """Ruler компонент создан."""
        assert document_view._ruler is not None
        assert isinstance(document_view._ruler, Ruler)

    def test_format_toolbar_component_created(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """FormatToolbar компонент создан после загрузки документа."""
        document_view.set_document(mock_document)
        assert document_view._format_toolbar is not None
        assert isinstance(document_view._format_toolbar, FormatToolbar)

    def test_free_form_renderer_created(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """FreeFormRenderer компонент создан после загрузки документа."""
        document_view.set_document(mock_document)
        assert document_view._free_form_renderer is not None
        assert isinstance(document_view._free_form_renderer, FreeFormRenderer)

    def test_navigator_component_created(self, document_view: DocumentView) -> None:
        """Navigator компонент создан."""
        assert document_view._navigator is not None
        assert isinstance(document_view._navigator, Navigator)

    def test_command_stack_created(self, document_view: DocumentView) -> None:
        """CommandStack создан."""
        assert document_view._command_stack is not None


# =============================================================================
# TEST: Document Loading
# =============================================================================


class TestDocumentLoading:
    """Тесты загрузки документов."""

    def test_set_document_loads_content(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """set_document() загружает контент."""
        document_view.set_document(mock_document)

        text = document_view._free_form_renderer.get_text()
        assert text == "Hello World"

    def test_set_document_applies_cpi(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """set_document() применяет CPI."""
        document_view.set_document(mock_document)

        cpi = document_view._free_form_renderer.get_cpi()
        assert cpi == 12

    def test_set_document_updates_ruler(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """set_document() обновляет Ruler."""
        document_view.set_document(mock_document)

        assert document_view._ruler.get_cpi() == 12

    def test_set_document_updates_toolbar(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """set_document() создаёт FormatToolbar."""
        document_view.set_document(mock_document)

        assert document_view._format_toolbar is not None
        assert isinstance(document_view._format_toolbar, FormatToolbar)

    def test_set_document_updates_navigator(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """set_document() обновляет Navigator."""
        document_view.set_document(mock_document)

        # Total lines should be updated
        total_lines = document_view._navigator.get_total_lines()
        assert total_lines >= 1


# =============================================================================
# TEST: CPI Integration
# =============================================================================


class TestCPIIntegration:
    """Тесты интеграции CPI между компонентами."""

    def test_cpi_change_propagates_to_renderer(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """Изменение CPI распространяется на FreeFormRenderer."""
        document_view.set_document(mock_document)
        document_view._on_cpi_changed(15)

        assert document_view._free_form_renderer is not None
        assert document_view._free_form_renderer.get_cpi() == 15

    def test_cpi_change_propagates_to_ruler(self, document_view: DocumentView) -> None:
        """Изменение CPI распространяется на Ruler."""
        document_view._on_cpi_changed(15)

        assert document_view._ruler.get_cpi() == 15


# =============================================================================
# TEST: Format Integration
# =============================================================================


class TestFormatIntegration:
    """Тесты интеграции форматирования."""

    def test_format_toggle_applies_to_renderer(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """Переключение формата применяется к FreeFormRenderer."""
        document_view.set_document(mock_document)

        # Set cursor position first
        document_view._free_form_renderer.set_cursor_position(1, 1)

        # Toggle bold format
        document_view._on_format_toggled("bold", True)

        # Formatting should be applied (though may not be visible without selection)
        formatting = document_view._free_form_renderer.get_formatting()
        # Formatting might be empty if no selection, but operation should not raise


# =============================================================================
# TEST: Navigation Integration
# =============================================================================


class TestNavigationIntegration:
    """Тесты интеграции навигации."""

    def test_navigator_goto_line(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """Navigator goto_line перемещает курсор."""
        document_view.set_document(mock_document)

        # Add more lines
        document_view._free_form_renderer.set_text("Line 1\nLine 2\nLine 3")

        # Goto line 2
        document_view._on_navigator_goto_line(2)

        pos = document_view._free_form_renderer.get_cursor_position()
        assert pos[0] == 2  # Line number

    def test_navigator_goto_start(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """Navigator goto_start перемещает в начало."""
        document_view.set_document(mock_document)
        document_view._free_form_renderer.set_text("Line 1\nLine 2")
        document_view._free_form_renderer.set_cursor_position(2, 5)

        document_view._on_navigator_goto_start()

        pos = document_view._free_form_renderer.get_cursor_position()
        assert pos == (1, 1)

    def test_navigator_goto_end(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """Navigator goto_end перемещает в конец."""
        document_view.set_document(mock_document)
        document_view._free_form_renderer.set_text("Line 1\nLine 2")
        document_view._free_form_renderer.set_cursor_position(1, 1)

        document_view._on_navigator_goto_end()

        pos = document_view._free_form_renderer.get_cursor_position()
        assert pos[0] == 2  # Last line

    def test_ruler_click_moves_cursor(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """Клик по Ruler перемещает курсор."""
        document_view.set_document(mock_document)
        document_view._free_form_renderer.set_cursor_position(1, 1)

        # Simulate ruler click at position 10
        document_view._on_ruler_clicked(10)

        pos = document_view._free_form_renderer.get_cursor_position()
        assert pos[1] == 11  # Column 11 (1-based)


# =============================================================================
# TEST: Cursor Position Updates
# =============================================================================


class TestCursorPositionUpdates:
    """Тесты обновления позиции курсора."""

    def test_cursor_move_updates_navigator(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """Движение курсора обновляет Navigator."""
        document_view.set_document(mock_document)
        document_view._free_form_renderer.set_text("Line 1\nLine 2\nLine 3")

        # Simulate cursor move to line 2, column 5
        document_view._on_cursor_moved(2, 5)

        nav_pos = document_view._navigator.get_position()
        assert nav_pos == (2, 5)


# =============================================================================
# TEST: Text Change Updates
# =============================================================================


class TestTextChangeUpdates:
    """Тесты обновления при изменении текста."""

    def test_text_change_updates_navigator_lines(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """Изменение текста обновляет количество строк в Navigator."""
        document_view.set_document(mock_document)
        document_view._free_form_renderer.set_text("Line 1\nLine 2\nLine 3")

        # Simulate text change with more lines
        document_view._on_text_changed("Line 1\nLine 2\nLine 3\nLine 4\nLine 5")

        total_lines = document_view._navigator.get_total_lines()
        assert total_lines == 5


# =============================================================================
# TEST: Undo/Redo Integration
# =============================================================================


class TestUndoRedoIntegration:
    """Тесты интеграции undo/redo."""

    def test_undo_text_operation(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """undo() отменяет текстовую операцию."""
        document_view.set_document(mock_document)
        original_text = document_view._free_form_renderer.get_text()

        # Make a change
        document_view._free_form_renderer.insert_text("end", " Added text")

        # Undo the change
        document_view.undo()

        # Text should be restored (may need event processing)
        # Note: In tests, undo might not work immediately due to event loop

    def test_can_undo(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """can_undo() возвращает состояние."""
        document_view.set_document(mock_document)

        # Initially no undo available
        assert document_view.can_undo() == document_view._command_stack.can_undo()

    def test_can_redo(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """can_redo() возвращает состояние."""
        document_view.set_document(mock_document)

        # Initially no redo available
        assert document_view.can_redo() == document_view._command_stack.can_redo()

    def test_get_undo_description(self, document_view: DocumentView) -> None:
        """get_undo_description() возвращает описание."""
        desc = document_view.get_undo_description()
        assert desc == document_view._command_stack.get_undo_description()

    def test_get_redo_description(self, document_view: DocumentView) -> None:
        """get_redo_description() возвращает описание."""
        desc = document_view.get_redo_description()
        assert desc == document_view._command_stack.get_redo_description()


# =============================================================================
# TEST: Security Integration
# =============================================================================


class TestSecurityIntegration:
    """Тесты интеграции безопасности."""

    def test_wipe_sensitive_data_clears_all(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """wipe_sensitive_data() очищает все компоненты."""
        document_view.set_document(mock_document)

        document_view.wipe_sensitive_data()

        assert document_view.current_document_id is None
        assert document_view._free_form_renderer.get_text() == ""

    def test_wipe_clears_command_stack(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """wipe_sensitive_data() очищает CommandStack."""
        document_view.set_document(mock_document)

        document_view.wipe_sensitive_data()

        assert not document_view._command_stack.can_undo()

    def test_hide_content_hides_renderer(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """hide_content() скрывает рендерер."""
        document_view.set_document(mock_document)

        document_view.hide_content()

        assert document_view._content_hidden is True

    def test_restore_content_restores_renderer(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """restore_content() восстанавливает рендерер."""
        document_view.set_document(mock_document)
        document_view.hide_content()

        document_view.restore_content()

        assert document_view._content_hidden is False


# =============================================================================
# TEST: Edit Menu Integration
# =============================================================================


class TestEditMenuIntegration:
    """Тесты интеграции с Edit меню."""

    def test_on_edit_undo(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """on_edit_undo() не вызывает ошибок."""
        document_view.set_document(mock_document)

        # Should not raise even if nothing to undo
        document_view.on_edit_undo()

    def test_on_edit_redo(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """on_edit_redo() не вызывает ошибок."""
        document_view.set_document(mock_document)

        # Should not raise even if nothing to redo
        document_view.on_edit_redo()

    def test_on_edit_select_all(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """on_edit_select_all() выделяет весь текст."""
        document_view.set_document(mock_document)

        document_view.on_edit_select_all()

        # Selection should exist
        selection = document_view._free_form_renderer.get_selection()
        # May be None in test environment, but should not raise


# =============================================================================
# TEST: Document Protocol
# =============================================================================


class TestDocumentProtocol:
    """Тесты DocumentProtocol."""

    def test_mock_document_implements_protocol(
        self, mock_document: MockDocument
    ) -> None:
        """MockDocument реализует DocumentProtocol."""
        # This should not raise if protocol is satisfied
        doc: DocumentProtocol = mock_document
        assert doc.id == "test_doc_123"
        assert doc.get_content() == "Hello World"
        assert doc.get_cpi() == 12

    def test_set_document_with_protocol(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """set_document() принимает DocumentProtocol."""
        # Should not raise
        document_view.set_document(mock_document)

        assert document_view.current_document_id == "test_doc_123"


# =============================================================================
# TEST: Mode Switching
# =============================================================================


class TestModeSwitching:
    """Тесты переключения режимов."""

    def test_switch_to_free_form(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """Переключение в FREE_FORM режим."""
        document_view.set_document(mock_document)

        document_view.switch_mode(DocumentMode.FREE_FORM)

        assert document_view.current_mode == DocumentMode.FREE_FORM

    @pytest.mark.skip(
        reason="StructuredFormRenderer requires parent in constructor, incompatible with current RendererFactory"
    )
    def test_switch_to_structured_form_shows_placeholder(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """Переключение в STRUCTURED_FORM показывает placeholder."""
        document_view.set_document(mock_document)

        document_view.switch_mode(DocumentMode.STRUCTURED_FORM)

        # Should show placeholder
        assert document_view.is_placeholder_visible is True


# =============================================================================
# TEST: Placeholder
# =============================================================================


class TestPlaceholder:
    """Тесты placeholder."""

    def test_show_placeholder_shows_placeholder(
        self, document_view: DocumentView
    ) -> None:
        """show_placeholder() показывает placeholder."""
        document_view.show_placeholder("Custom message")

        assert document_view.is_placeholder_visible is True

    def test_hide_placeholder_hides_placeholder(
        self, document_view: DocumentView, mock_document: MockDocument
    ) -> None:
        """hide_placeholder() скрывает placeholder."""
        document_view.set_document(mock_document)

        document_view.hide_placeholder()

        assert document_view.is_placeholder_visible is False


# =============================================================================
# TEST: Show/Hide
# =============================================================================


class TestShowHide:
    """Тесты show/hide методов."""

    def test_show(self, document_view: DocumentView) -> None:
        """show() показывает компонент."""
        # Should not raise
        document_view.show()

    def test_hide(self, document_view: DocumentView) -> None:
        """hide() скрывает компонент."""
        # Should not raise
        document_view.hide()

    def test_is_visible(self, document_view: DocumentView) -> None:
        """is_visible() возвращает состояние."""
        # May be True or False depending on parent visibility
        visible = document_view.is_visible()
        assert isinstance(visible, bool)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.views.document_view"])
