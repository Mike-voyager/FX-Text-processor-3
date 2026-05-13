"""Прокси-модуль для обратной совместимости.

Модуль src.view реэкспортирует компоненты из src.gui
для обратной совместимости с существующим кодом.

Note: Новый код должен использовать src.gui напрямую.
"""

from __future__ import annotations

from enum import Enum, auto

# Re-export from src.gui.workflow
from src.gui.workflow.workflow_indicator import WorkflowIndicator


class WorkflowState(Enum):
    """Состояния workflow документа.

    Соответствует статусам FormStatus для интеграции
    с GUI компонентами.
    """

    DRAFT = auto()
    FILLED = auto()
    VALIDATED = auto()
    APPROVED = auto()
    SIGNED = auto()
    PRINTED = auto()
    ARCHIVED = auto()
    REJECTED = auto()


__all__ = ["WorkflowIndicator", "WorkflowState"]
