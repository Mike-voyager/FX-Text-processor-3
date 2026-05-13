"""Интеграционный тест: Workflow Timeline в StatusBar через DocumentView.

Запускать только через xvfb-run -a python -m pytest tests/integration/gui/test_workflow_timeline_integration.py
"""
from __future__ import annotations

import tkinter as tk
from typing import Any

import pytest

from src.documents.constructor.form_status import FormStatus
from src.documents.types.document_type import DocumentMode
from src.gui.views.document_view import DocumentView
from src.gui.views.status_bar import StatusBar
from src.gui.workflow.role_badge import WorkflowRole


class DummyDocument:
    """Dummy document для тестирования интеграции."""

    def __init__(self, mode: DocumentMode, status: FormStatus | None = None) -> None:
        self.id = "test-doc-1"
        self.mode = mode
        self._status = status
        self._content = "Test content\nLine 2"
        self._cpi = 10

    @property
    def status(self) -> FormStatus | None:
        return self._status

    def get_content(self) -> str:
        return self._content

    def get_cpi(self) -> int:
        return self._cpi


@pytest.fixture
def tk_root() -> tk.Tk:
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


class TestWorkflowTimelineIntegration:
    """Тесты интеграции Workflow Timeline в StatusBar через DocumentView."""

    def test_document_view_receives_statusbar(self, tk_root: tk.Tk) -> None:
        """DocumentView принимает statusbar параметр."""
        statusbar = StatusBar(widget_id="sb")
        statusbar.mount(tk_root)

        doc_view = DocumentView(
            widget_id="dv",
            statusbar=statusbar,
        )
        doc_view.mount(tk_root)

        assert doc_view._statusbar is statusbar

    def test_switch_mode_structured_shows_timeline(self, tk_root: tk.Tk) -> None:
        """switch_mode(STRUCTURED_FORM) вызывает set_document_mode(STRUCTURED_FORM)."""
        statusbar = StatusBar(widget_id="sb")
        statusbar.mount(tk_root)

        doc_view = DocumentView(widget_id="dv", statusbar=statusbar)
        doc_view.mount(tk_root)

        # Initially FREE_FORM
        assert statusbar.get_document_mode() is None

        doc_view.switch_mode(DocumentMode.STRUCTURED_FORM)

        assert statusbar.get_document_mode() == DocumentMode.STRUCTURED_FORM

    def test_switch_mode_free_form_hides_timeline(self, tk_root: tk.Tk) -> None:
        """switch_mode(FREE_FORM) скрывает timeline через set_document_mode."""
        statusbar = StatusBar(widget_id="sb")
        statusbar.mount(tk_root)

        doc_view = DocumentView(widget_id="dv", statusbar=statusbar)
        doc_view.mount(tk_root)

        doc_view.switch_mode(DocumentMode.STRUCTURED_FORM)
        assert statusbar.get_document_mode() == DocumentMode.STRUCTURED_FORM

        doc_view.switch_mode(DocumentMode.FREE_FORM)
        assert statusbar.get_document_mode() == DocumentMode.FREE_FORM

    def test_set_document_structured_syncs_workflow(self, tk_root: tk.Tk) -> None:
        """set_document() с STRUCTURED_FORM синхронизирует workflow статус."""
        statusbar = StatusBar(widget_id="sb")
        statusbar.mount(tk_root)

        doc_view = DocumentView(widget_id="dv", statusbar=statusbar)
        doc_view.mount(tk_root)

        doc = DummyDocument(mode=DocumentMode.STRUCTURED_FORM, status=FormStatus.FILLED)
        doc_view.set_document(doc)  # type: ignore[arg-type]

        assert statusbar.get_document_mode() == DocumentMode.STRUCTURED_FORM
        assert statusbar.get_workflow_status() == "filled"

    def test_workflow_action_updates_timeline(self, tk_root: tk.Tk) -> None:
        """_on_workflow_action обновляет timeline и role badge."""
        statusbar = StatusBar(widget_id="sb")
        statusbar.mount(tk_root)

        doc_view = DocumentView(widget_id="dv", statusbar=statusbar)
        doc_view.mount(tk_root)

        # Simulate structured form mode
        doc_view.switch_mode(DocumentMode.STRUCTURED_FORM)

        # Workflow action "validate" should update status to VALIDATED
        doc_view._update_statusbar_for_action("validate")

        assert statusbar.get_workflow_status() == "validated"

    def test_role_switch_updates_badge(self, tk_root: tk.Tk) -> None:
        """_update_statusbar_for_action обновляет role badge."""
        statusbar = StatusBar(widget_id="sb")
        statusbar.mount(tk_root)

        doc_view = DocumentView(widget_id="dv", statusbar=statusbar)
        doc_view.mount(tk_root)

        doc_view._update_statusbar_for_action("switch_to_supervisor")

        assert statusbar._current_role == WorkflowRole.SUPERVISOR

    def test_document_without_status_no_crash(self, tk_root: tk.Tk) -> None:
        """set_document() без status не падает."""
        statusbar = StatusBar(widget_id="sb")
        statusbar.mount(tk_root)

        doc_view = DocumentView(widget_id="dv", statusbar=statusbar)
        doc_view.mount(tk_root)

        doc = DummyDocument(mode=DocumentMode.STRUCTURED_FORM, status=None)
        doc_view.set_document(doc)  # type: ignore[arg-type]

        # Should not crash; mode should still be set
        assert statusbar.get_document_mode() == DocumentMode.STRUCTURED_FORM

    def test_document_view_without_statusbar_no_crash(self, tk_root: tk.Tk) -> None:
        """DocumentView без StatusBar работает без ошибок."""
        doc_view = DocumentView(widget_id="dv")
        doc_view.mount(tk_root)

        doc = DummyDocument(mode=DocumentMode.STRUCTURED_FORM, status=FormStatus.DRAFT)
        doc_view.set_document(doc)  # type: ignore[arg-type]

        assert doc_view.current_mode == DocumentMode.STRUCTURED_FORM
