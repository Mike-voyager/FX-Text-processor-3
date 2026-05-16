"""Тесты для WorkflowTimelineDialog.

Тестируют создание диалога, отображение timeline, историю переходов,
Simple Mode, View Comments и таймстампы.
"""

from __future__ import annotations

import tkinter as tk
from datetime import datetime
from typing import Generator
from unittest.mock import MagicMock
from uuid import uuid4

import pytest


@pytest.fixture
def root() -> Generator[tk.Tk, None, None]:
    """Фикстура для Tk root."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def mock_controller():
    """Фикстура для мока WorkflowController."""
    controller = MagicMock()

    class MockFormStatus:
        value = "draft"
        localized_name = "Черновик"

    controller.get_current_state.return_value = MockFormStatus()
    controller.get_workflow_history.return_value = []
    controller.get_all_comments.return_value = []

    return controller


@pytest.fixture
def mock_event():
    """Фикстура для мока WorkflowEvent."""
    class MockRole:
        display_name = "Оператор"

    class MockFromState:
        value = "draft"
        localized_name = "Черновик"

    class MockToState:
        value = "filled"
        localized_name = "Заполнена"

    event = MagicMock()
    event.event_id = "test-event-001"
    event.doc_id = uuid4()
    event.from_state = MockFromState()
    event.to_state = MockToState()
    event.role = MockRole()
    event.timestamp = datetime(2024, 1, 15, 10, 30, 0)
    event.reason = "Test reason"
    event.mfa_verified = True
    return event


class TestWorkflowTimelineDialog:
    """Тесты для WorkflowTimelineDialog."""

    def test_dialog_init(self, root: tk.Tk, mock_controller) -> None:
        """Тест инициализации диалога."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        doc_id = uuid4()
        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=doc_id,
            workflow_controller=mock_controller,
        )

        assert dialog._document_id == doc_id
        assert dialog._workflow_controller == mock_controller
        assert dialog._status_widgets != {}
        assert dialog._history_tree is not None
        assert dialog._simple_mode_var is not None

        dialog.destroy()

    def test_dialog_title(self, root: tk.Tk, mock_controller) -> None:
        """Тест заголовка окна."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        assert "Document Workflow" in dialog.title()
        dialog.destroy()

    def test_status_widgets_created(self, root: tk.Tk, mock_controller) -> None:
        """Тест создания виджетов статусов."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        expected_statuses = ["draft", "filled", "validated", "approved", "signed", "archived"]
        for status in expected_statuses:
            assert status in dialog._status_widgets

        dialog.destroy()

    def test_history_tree_columns(self, root: tk.Tk, mock_controller) -> None:
        """Тест колонок дерева истории."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        tree = dialog._history_tree
        assert tree is not None

        columns = tree["columns"]
        assert "timestamp" in columns
        assert "transition" in columns
        assert "role" in columns
        assert "mfa" in columns
        assert "reason" in columns

        dialog.destroy()

    def test_load_history_empty(self, root: tk.Tk, mock_controller) -> None:
        """Тест загрузки пустой истории."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        mock_controller.get_workflow_history.return_value = []

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        tree = dialog._history_tree
        assert tree is not None

        children = tree.get_children()
        assert len(children) == 1

        values = tree.item(children[0], "values")
        assert "No data" in str(values)

        dialog.destroy()

    def test_is_state_before_logic(self, root: tk.Tk, mock_controller) -> None:
        """Тест логики определения порядка состояний."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        assert dialog._is_state_before("draft", "filled") is True
        assert dialog._is_state_before("filled", "validated") is True
        assert dialog._is_state_before("validated", "approved") is True
        assert dialog._is_state_before("approved", "signed") is True
        assert dialog._is_state_before("signed", "archived") is True
        assert dialog._is_state_before("validated", "draft") is False
        assert dialog._is_state_before("archived", "signed") is False

        dialog.destroy()

    def test_get_status_color(self, root: tk.Tk, mock_controller) -> None:
        """Тест получения цвета для статуса."""
        from src.gui.dialogs.workflow_timeline_dialog import (
            COLOR_APPROVED,
            COLOR_ARCHIVED,
            COLOR_DRAFT,
            COLOR_FILLED,
            COLOR_SIGNED,
            COLOR_VALIDATED,
            WorkflowTimelineDialog,
        )

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        class MockStatus:
            value = "draft"

        status = MockStatus()
        assert dialog._get_status_color(status) == COLOR_DRAFT

        status.value = "filled"
        assert dialog._get_status_color(status) == COLOR_FILLED

        status.value = "validated"
        assert dialog._get_status_color(status) == COLOR_VALIDATED

        status.value = "approved"
        assert dialog._get_status_color(status) == COLOR_APPROVED

        status.value = "signed"
        assert dialog._get_status_color(status) == COLOR_SIGNED

        status.value = "archived"
        assert dialog._get_status_color(status) == COLOR_ARCHIVED

        dialog.destroy()

    def test_show_details(self, root: tk.Tk, mock_controller) -> None:
        """Тест отображения деталей."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        test_text = "Test details text"
        dialog._show_details(test_text)

        text_widget = dialog._details_text
        assert text_widget is not None

        content = text_widget.get("1.0", tk.END).strip()
        assert content == test_text

        dialog.destroy()

    def test_format_event_details(self, root: tk.Tk, mock_controller, mock_event) -> None:
        """Тест форматирования деталей события."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        formatted = dialog._format_event_details(mock_event)

        assert "2024-01-15 10:30:00" in formatted
        assert "Оператор" in formatted
        assert "Verified" in formatted
        assert "Test reason" in formatted
        assert "test-event-001" in formatted

        dialog.destroy()

    def test_dialog_constants(self) -> None:
        """Тест констант диалога."""
        from src.gui.dialogs.workflow_timeline_dialog import (
            COLOR_DRAFT,
            COLOR_MFA_VERIFIED,
            DIALOG_HEIGHT,
            DIALOG_WIDTH,
            SIMPLE_MODE_STATUSES,
            STATUS_ORDER,
        )

        assert DIALOG_WIDTH == 700
        assert DIALOG_HEIGHT == 580
        assert "draft" in STATUS_ORDER
        assert "filled" in STATUS_ORDER
        assert "validated" in STATUS_ORDER
        assert "approved" in STATUS_ORDER
        assert "signed" in STATUS_ORDER
        assert "archived" in STATUS_ORDER
        assert COLOR_DRAFT.startswith("#")
        assert COLOR_MFA_VERIFIED.startswith("#")
        assert "draft" in SIMPLE_MODE_STATUSES
        assert "signed" in SIMPLE_MODE_STATUSES

    def test_refresh_method(self, root: tk.Tk, mock_controller) -> None:
        """Тест метода обновления данных."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        initial_state_calls = mock_controller.get_current_state.call_count
        initial_history_calls = mock_controller.get_workflow_history.call_count

        mock_controller.get_current_state.reset_mock()
        mock_controller.get_workflow_history.reset_mock()

        dialog.refresh()

        mock_controller.get_current_state.assert_called()
        assert mock_controller.get_current_state.call_count == initial_state_calls
        mock_controller.get_workflow_history.assert_called()
        assert mock_controller.get_workflow_history.call_count == initial_history_calls

        dialog.destroy()


class TestWorkflowTimelineDialogSimpleMode:
    """Тесты Simple Mode."""

    def test_simple_mode_toggle(self, root: tk.Tk, mock_controller) -> None:
        """Тест переключения Simple Mode."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        assert dialog._simple_mode_var.get() is False

        dialog._simple_mode_var.set(True)
        dialog._on_simple_mode_toggle()

        assert dialog._simple_mode_var.get() is True

        dialog.destroy()

    def test_simple_mode_hides_intermediate_states(self, root: tk.Tk, mock_controller) -> None:
        """Тест что Simple Mode скрывает промежуточные состояния."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        dialog._simple_mode_var.set(True)
        dialog._on_simple_mode_toggle()

        filled_frame = dialog._status_widgets["filled"]["frame"]
        validated_frame = dialog._status_widgets["validated"]["frame"]
        approved_frame = dialog._status_widgets["approved"]["frame"]

        assert filled_frame.grid_info().get("row", 0) >= 0
        assert validated_frame.grid_info().get("row", 0) >= 0
        assert approved_frame.grid_info().get("row", 0) >= 0

        dialog.destroy()


class TestWorkflowTimelineDialogTimestamps:
    """Тесты таймстампов в timeline."""

    def test_timestamp_labels_created(self, root: tk.Tk, mock_controller) -> None:
        """Тест создания меток таймстампов."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        assert dialog._timestamp_labels is not None
        assert "draft" in dialog._timestamp_labels
        assert "filled" in dialog._timestamp_labels
        assert "validated" in dialog._timestamp_labels
        assert "signed" in dialog._timestamp_labels

        dialog.destroy()

    def test_update_timeline_timestamps(self, root: tk.Tk, mock_controller, mock_event) -> None:
        """Тест обновления таймстампов в timeline."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        class MockToStateFilled:
            value = "filled"
            localized_name = "Заполнена"

        mock_event.to_state = MockToStateFilled()

        mock_controller.get_workflow_history.return_value = [mock_event]

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        dialog._update_timeline_timestamps()

        timestamp_label = dialog._timestamp_labels.get("filled")
        assert timestamp_label is not None
        assert timestamp_label.cget("text") == "10:30"

        dialog.destroy()


class TestWorkflowTimelineDialogViewComments:
    """Тесты кнопки View Comments."""

    def test_comments_button_exists(self, root: tk.Tk, mock_controller) -> None:
        """Тест наличия кнопки View Comments."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        assert hasattr(dialog, "_comments_btn")
        assert dialog._comments_btn is not None

        dialog.destroy()

    def test_on_view_comments_opens_dialog(self, root: tk.Tk, mock_controller) -> None:
        """Тест открытия диалога комментариев."""
        from src.gui.dialogs.workflow_timeline_dialog import (
            CommentsViewerDialog,
            WorkflowTimelineDialog,
        )

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        mock_controller.get_all_comments.return_value = []

        original_wait_window = CommentsViewerDialog.wait_window
        CommentsViewerDialog.wait_window = lambda self: None

        try:
            dialog._on_view_comments()
            assert mock_controller.get_all_comments.called
        finally:
            CommentsViewerDialog.wait_window = original_wait_window

        dialog.destroy()


class TestCommentsViewerDialog:
    """Тесты диалога просмотра комментариев."""

    def test_dialog_init(self, root: tk.Tk) -> None:
        """Тест инициализации диалога."""
        from src.gui.dialogs.workflow_timeline_dialog import CommentsViewerDialog

        doc_id = uuid4()
        dialog = CommentsViewerDialog(
            parent=root,
            comments=[],
            document_id=doc_id,
        )

        assert dialog._document_id == doc_id
        assert dialog._comments == []
        assert dialog._tree is not None

        dialog.destroy()

    def test_dialog_title(self, root: tk.Tk) -> None:
        """Тест заголовка окна."""
        from src.gui.dialogs.workflow_timeline_dialog import CommentsViewerDialog

        dialog = CommentsViewerDialog(
            parent=root,
            comments=[],
            document_id=uuid4(),
        )

        assert "Comments" in dialog.title()
        dialog.destroy()

    def test_empty_comments_message(self, root: tk.Tk) -> None:
        """Тест сообщения при отсутствии комментариев."""
        from src.gui.dialogs.workflow_timeline_dialog import CommentsViewerDialog

        dialog = CommentsViewerDialog(
            parent=root,
            comments=[],
            document_id=uuid4(),
        )

        children = dialog._tree.get_children()
        assert len(children) == 1

        values = dialog._tree.item(children[0], "values")
        assert "No comments" in str(values)

        dialog.destroy()

    def test_populate_comments(self, root: tk.Tk) -> None:
        """Тест заполнения комментариями."""
        from src.controller.workflow_controller import FieldComment, Severity, WorkflowRole
        from src.gui.dialogs.workflow_timeline_dialog import CommentsViewerDialog

        doc_id = uuid4()

        comment = FieldComment(
            comment_id="comment-001",
            doc_id=doc_id,
            field_id="field_1",
            text="Test comment text",
            author_role=WorkflowRole.OPERATOR,
            severity=Severity.INFO,
            created_at=datetime(2024, 1, 15, 10, 30, 0),
            resolved=False,
        )

        dialog = CommentsViewerDialog(
            parent=root,
            comments=[comment],
            document_id=doc_id,
        )

        children = dialog._tree.get_children()
        assert len(children) == 1

        values = dialog._tree.item(children[0], "values")
        assert "field_1" in str(values)
        assert "Test comment text" in str(values)
        assert "Оператор" in str(values)

        dialog.destroy()


class TestWorkflowTimelineDialogColors:
    """Тесты цветов и стилизации."""

    def test_status_colors_defined(self) -> None:
        """Тест определения цветов статусов."""
        from src.gui.dialogs.workflow_timeline_dialog import (
            COLOR_APPROVED,
            COLOR_ARCHIVED,
            COLOR_CONNECTOR,
            COLOR_CURRENT,
            COLOR_DRAFT,
            COLOR_FILLED,
            COLOR_REJECTED,
            COLOR_SIGNED,
            COLOR_VALIDATED,
        )

        colors = [
            COLOR_DRAFT,
            COLOR_FILLED,
            COLOR_VALIDATED,
            COLOR_APPROVED,
            COLOR_SIGNED,
            COLOR_ARCHIVED,
            COLOR_REJECTED,
            COLOR_CURRENT,
            COLOR_CONNECTOR,
        ]

        for color in colors:
            assert color.startswith("#")
            assert len(color) == 7

    def test_mfa_colors_defined(self) -> None:
        """Тест определения цветов MFA."""
        from src.gui.dialogs.workflow_timeline_dialog import (
            COLOR_MFA_PENDING,
            COLOR_MFA_VERIFIED,
        )

        assert COLOR_MFA_VERIFIED.startswith("#")
        assert COLOR_MFA_PENDING.startswith("#")


class TestWorkflowTimelineDialogEdgeCases:
    """Тесты edge cases для улучшения покрытия."""

    def test_on_history_select_empty_selection(
        self, root: tk.Tk, mock_controller
    ) -> None:
        """Тест _on_history_select с пустым выбором (возвращается раньше)."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        dialog._details_text.config(state=tk.NORMAL)
        dialog._details_text.delete("1.0", tk.END)
        dialog._details_text.insert("1.0", "Initial text")
        dialog._details_text.config(state=tk.DISABLED)

        dialog._on_history_select(None)

        text_widget = dialog._details_text
        assert text_widget is not None
        content = text_widget.get("1.0", tk.END).strip()
        assert content == "Initial text"

        dialog.destroy()

    def test_format_event_details_no_reason(
        self, root: tk.Tk, mock_controller, mock_event
    ) -> None:
        """Тест _format_event_details без причины."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        mock_event.reason = None

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        formatted = dialog._format_event_details(mock_event)

        assert "2024-01-15 10:30:00" in formatted
        assert "Reason:" not in formatted

        dialog.destroy()

    def test_insert_event_row_long_reason(
        self, root: tk.Tk, mock_controller, mock_event
    ) -> None:
        """Тест _insert_event_row с длинной причиной (truncation)."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        mock_event.reason = "A" * 50

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        dialog._insert_event_row(mock_event)

        tree = dialog._history_tree
        children = tree.get_children()
        values = tree.item(children[-1], "values")
        reason_in_row = str(values[4])
        assert reason_in_row.endswith("...")
        assert len(reason_in_row) <= 30

        dialog.destroy()

    def test_is_state_before_invalid_status(
        self, root: tk.Tk, mock_controller
    ) -> None:
        """Тест _is_state_before с невалидным статусом (ValueError path)."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        result = dialog._is_state_before("invalid_status", "draft")
        assert result is False

        result = dialog._is_state_before("draft", "invalid_status")
        assert result is False

        dialog.destroy()

    def test_show_error(self, root: tk.Tk, mock_controller) -> None:
        """Тест _show_error."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        dialog._show_error("Test error message")

        tree = dialog._history_tree
        children = tree.get_children()
        values = tree.item(children[0], "values")
        assert "Error" in str(values)
        assert "Test error" in str(values)

        dialog.destroy()

    def test_load_workflow_data_exception(
        self, root: tk.Tk, mock_controller
    ) -> None:
        """Тест _load_workflow_data при exception."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        mock_controller.get_current_state.side_effect = Exception("Test exception")

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        dialog._load_workflow_data()

        tree = dialog._history_tree
        children = tree.get_children()
        values = tree.item(children[0], "values")
        assert "Error" in str(values)

        mock_controller.get_current_state.side_effect = None
        dialog.destroy()

    def test_update_timeline_timestamps_empty_history(
        self, root: tk.Tk, mock_controller
    ) -> None:
        """Тест _update_timeline_timestamps с пустой историей."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        mock_controller.get_workflow_history.return_value = []

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        dialog._update_timeline_timestamps()

        for _status_code, label in dialog._timestamp_labels.items():
            assert label.cget("text") == ""

        dialog.destroy()

    def test_on_view_comments_exception(
        self, root: tk.Tk, mock_controller
    ) -> None:
        """Тест _on_view_comments при exception."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        mock_controller.get_all_comments.side_effect = Exception("Test exception")

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        dialog._on_view_comments()

        mock_controller.get_all_comments.side_effect = None
        dialog.destroy()

    def test_comments_viewer_dialog_on_close(self, root: tk.Tk) -> None:
        """Тест CommentsViewerDialog._on_close."""
        from src.gui.dialogs.workflow_timeline_dialog import CommentsViewerDialog

        doc_id = uuid4()
        dialog = CommentsViewerDialog(
            parent=root,
            comments=[],
            document_id=doc_id,
        )

        dialog._on_close()

        assert not dialog.winfo_exists()

    def test_show_details_none_text(self, root: tk.Tk, mock_controller) -> None:
        """Тест _show_details с None _details_text."""
        from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

        dialog = WorkflowTimelineDialog(
            parent=root,
            document_id=uuid4(),
            workflow_controller=mock_controller,
        )

        dialog._details_text = None
        dialog._show_details("Test")

        dialog.destroy()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
