"""Workflow components for FX Text Processor 3 structured forms.

Phase 4 workflow components:
- FormWorkflowBar: панель workflow со статусами и переходами

Example:
    >>> from src.gui.modes.structured_form.workflow import FormWorkflowBar
    >>> bar = FormWorkflowBar(
    ...     parent=frame,
    ...     current_status=FormStatus.DRAFT,
    ...     on_transition=on_status_change,
    ... )
"""

from __future__ import annotations

from src.gui.modes.structured_form.workflow.form_workflow_bar import FormWorkflowBar

__all__: list[str] = [
    "FormWorkflowBar",
]
