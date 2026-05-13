"""Тесты для WorkflowTimeline."""

from __future__ import annotations

import pytest
import tkinter as tk
from datetime import datetime

from src.view.workflow import WorkflowState, CommentSeverity
from src.view.workflow.timeline import WorkflowTimeline, WorkflowEntry


@pytest.fixture
def root():
    """Фикстура для Tk root."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def sample_entries():
    """Фикстура с тестовыми записями."""
    return [
        WorkflowEntry(
            from_state=WorkflowState.DRAFT,
            to_state=WorkflowState.FILLED,
            timestamp=datetime(2024, 1, 1, 10, 0),
            user="operator1",
            comment="Document filled",
            severity=CommentSeverity.INFO,
        ),
        WorkflowEntry(
            from_state=WorkflowState.FILLED,
            to_state=WorkflowState.VALIDATED,
            timestamp=datetime(2024, 1, 1, 11, 0),
            user="editor1",
            comment="Validation passed",
            severity=CommentSeverity.INFO,
        ),
    ]


class TestWorkflowTimeline:
    """Тесты для timeline workflow."""

    def test_init_empty(self, root):
        """Тест инициализации без записей."""
        timeline = WorkflowTimeline(root)
        assert timeline.get_entries() == []

    def test_init_with_entries(self, root, sample_entries):
        """Тест инициализации с записями."""
        timeline = WorkflowTimeline(root, entries=sample_entries)
        assert len(timeline.get_entries()) == 2

    def test_add_entry(self, root):
        """Тест добавления записи."""
        timeline = WorkflowTimeline(root)

        entry = WorkflowEntry(
            from_state=WorkflowState.DRAFT,
            to_state=WorkflowState.FILLED,
            timestamp=datetime.now(),
            user="test_user",
        )

        timeline.add_entry(entry)
        entries = timeline.get_entries()
        assert len(entries) == 1
        assert entries[0].user == "test_user"

    def test_set_entries(self, root, sample_entries):
        """Тест установки записей."""
        timeline = WorkflowTimeline(root)
        timeline.set_entries(sample_entries)
        assert len(timeline.get_entries()) == 2

    def test_clear(self, root, sample_entries):
        """Тест очистки записей."""
        timeline = WorkflowTimeline(root, entries=sample_entries)
        timeline.clear()
        assert timeline.get_entries() == []

    def test_entry_order(self, root):
        """Тест порядка записей."""
        entries = [
            WorkflowEntry(
                from_state=WorkflowState.DRAFT,
                to_state=WorkflowState.FILLED,
                timestamp=datetime(2024, 1, 1, 10, 0),
                user="user1",
            ),
            WorkflowEntry(
                from_state=WorkflowState.FILLED,
                to_state=WorkflowState.VALIDATED,
                timestamp=datetime(2024, 1, 1, 11, 0),
                user="user2",
            ),
        ]

        timeline = WorkflowTimeline(root, entries=entries)
        result_entries = timeline.get_entries()

        assert result_entries[0].user == "user1"
        assert result_entries[1].user == "user2"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
