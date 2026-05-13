"""Тесты для WorkflowIndicator."""

from __future__ import annotations

import pytest
import tkinter as tk
from tkinter import ttk

from src.view.workflow import WorkflowState
from src.view.workflow.indicator import WorkflowIndicator


@pytest.fixture
def root():
    """Фикстура для Tk root."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


class TestWorkflowIndicator:
    """Тесты для индикатора workflow."""

    def test_init_default_state(self, root):
        """Тест инициализации с дефолтным состоянием."""
        indicator = WorkflowIndicator(root)
        assert indicator.get_state() == WorkflowState.DRAFT

    def test_init_custom_state(self, root):
        """Тест инициализации с кастомным состоянием."""
        indicator = WorkflowIndicator(root, current_state=WorkflowState.VALIDATED)
        assert indicator.get_state() == WorkflowState.VALIDATED

    def test_set_state(self, root):
        """Тест установки состояния."""
        indicator = WorkflowIndicator(root)
        indicator.set_state(WorkflowState.APPROVED)
        assert indicator.get_state() == WorkflowState.APPROVED

    def test_all_states(self, root):
        """Тест всех состояний workflow."""
        for state in WorkflowState:
            indicator = WorkflowIndicator(root, current_state=state)
            assert indicator.get_state() == state

    def test_callback_on_state_click(self, root):
        """Тест callback при клике на состояние."""
        clicked_state = []

        def on_click(state):
            clicked_state.append(state)

        indicator = WorkflowIndicator(root, on_state_click=on_click)
        # Имитируем клик через прямой вызов
        on_click(WorkflowState.FILLED)

        assert len(clicked_state) == 1
        assert clicked_state[0] == WorkflowState.FILLED


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
