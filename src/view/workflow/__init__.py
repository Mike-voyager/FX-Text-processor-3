"""Прокси-модуль workflow для обратной совместимости.

Реэкспортирует WorkflowState и WorkflowIndicator из src.view.
"""

from __future__ import annotations

from src.view import WorkflowIndicator, WorkflowState

__all__ = ["WorkflowIndicator", "WorkflowState"]
