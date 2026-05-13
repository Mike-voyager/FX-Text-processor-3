# -*- coding: utf-8 -*-
"""Тесты для Workflow Simple Mode.

Покрывает: переключение режимов, доступные статусы,
переходы между статусами, интеграцию с индикатором.

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import TYPE_CHECKING, Generator
from unittest.mock import MagicMock, patch

import pytest

from src.documents.constructor.form_status import FormStatus
from src.gui.workflow.workflow_indicator import (
    DOT_SIZE,
    FULL_MODE_STATUSES,
    SIMPLE_MODE_STATUSES,
    STATUS_COLORS,
    STATUS_NAMES,
    WorkflowIndicator,
)

if TYPE_CHECKING:
    from collections.abc import Generator

try:
    from src.gui.views.main_window import MainWindow
    MAIN_WINDOW_AVAILABLE = True
except ImportError:
    MAIN_WINDOW_AVAILABLE = False


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def root() -> Generator[tk.Tk, None, None]:
    """Фикстура для Tk root."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def mock_click() -> MagicMock:
    """Фикстура для mock callback клика."""
    return MagicMock()


# =============================================================================
# TestWorkflowSimpleMode - тесты Simple Mode
# =============================================================================


class TestWorkflowSimpleMode:
    """Тесты для Simple Mode workflow."""

    def test_simple_mode_statuses_defined(self) -> None:
        """Simple Mode статусы определены корректно."""
        assert len(SIMPLE_MODE_STATUSES) == 2
        assert "draft" in SIMPLE_MODE_STATUSES
        assert "signed" in SIMPLE_MODE_STATUSES

    def test_full_mode_statuses_defined(self) -> None:
        """В Full Mode 8 статусов (включая approved)."""
        assert len(FULL_MODE_STATUSES) == 8
        assert "draft" in FULL_MODE_STATUSES
        assert "filled" in FULL_MODE_STATUSES
        assert "validated" in FULL_MODE_STATUSES
        assert "approved" in FULL_MODE_STATUSES
        assert "signed" in FULL_MODE_STATUSES
        assert "printed" in FULL_MODE_STATUSES
        assert "archived" in FULL_MODE_STATUSES
        assert "rejected" in FULL_MODE_STATUSES

    def test_init_with_simple_mode(self, root: tk.Tk) -> None:
        """Инициализация с включенным Simple Mode."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_click=None,
            simple_mode=True,
        )
        assert indicator.is_simple_mode() is True

    def test_init_with_full_mode(self, root: tk.Tk) -> None:
        """Инициализация с отключенным Simple Mode (Full Mode)."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_click=None,
            simple_mode=False,
        )
        assert indicator.is_simple_mode() is False

    def test_set_simple_mode_true(self, root: tk.Tk) -> None:
        """Включение Simple Mode."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_click=None,
            simple_mode=False,
        )
        indicator.set_simple_mode(True)
        assert indicator.is_simple_mode() is True

    def test_set_simple_mode_false(self, root: tk.Tk) -> None:
        """Отключение Simple Mode (Full Mode)."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_click=None,
            simple_mode=True,
        )
        indicator.set_simple_mode(False)
        assert indicator.is_simple_mode() is False

    def test_set_same_mode_no_change(self, root: tk.Tk) -> None:
        """Установка того же режима не вызывает изменений."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_click=None,
            simple_mode=True,
        )
        # Setting same mode should not change anything
        indicator.set_simple_mode(True)
        assert indicator.is_simple_mode() is True

    def test_get_available_statuses_simple_mode(self, root: tk.Tk) -> None:
        """Получение доступных статусов в Simple Mode."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_click=None,
            simple_mode=True,
        )
        statuses = indicator.get_available_statuses()
        assert statuses == ["draft", "signed"]

    def test_get_available_statuses_full_mode(self, root: tk.Tk) -> None:
        """Получение доступных статусов в Full Mode."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_click=None,
            simple_mode=False,
        )
        statuses = indicator.get_available_statuses()
        assert statuses == FULL_MODE_STATUSES

    def test_is_status_allowed_in_simple_mode(self, root: tk.Tk) -> None:
        """Проверка допустимости статусов в Simple Mode."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_click=None,
            simple_mode=True,
        )
        assert indicator._is_status_allowed("draft") is True
        assert indicator._is_status_allowed("signed") is True
        assert indicator._is_status_allowed("filled") is False
        assert indicator._is_status_allowed("validated") is False

    def test_is_status_allowed_in_full_mode(self, root: tk.Tk) -> None:
        """Проверка допустимости статусов в Full Mode."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_click=None,
            simple_mode=False,
        )
        # All statuses should be allowed in full mode
        for status in FULL_MODE_STATUSES:
            assert indicator._is_status_allowed(status) is True


class TestWorkflowSimpleModeTransitions:
    """Тесты переходов между статусами в Simple Mode."""

    def test_draft_to_signed_allowed_in_simple_mode(self, root: tk.Tk) -> None:
        """Переход DRAFT -> SIGNED разрешён в Simple Mode."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_click=None,
            simple_mode=True,
        )
        assert indicator.can_transition_to(FormStatus.SIGNED) is True

    def test_signed_to_draft_allowed_in_simple_mode(self, root: tk.Tk) -> None:
        """Переход SIGNED -> DRAFT разрешён в Simple Mode."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.SIGNED,
            on_click=None,
            simple_mode=True,
        )
        assert indicator.can_transition_to(FormStatus.DRAFT) is True

    def test_draft_to_filled_blocked_in_simple_mode(self, root: tk.Tk) -> None:
        """Переход DRAFT -> FILLED заблокирован в Simple Mode."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_click=None,
            simple_mode=True,
        )
        assert indicator.can_transition_to(FormStatus.FILLED) is False

    def test_draft_to_validated_blocked_in_simple_mode(self, root: tk.Tk) -> None:
        """Переход DRAFT -> VALIDATED заблокирован в Simple Mode."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_click=None,
            simple_mode=True,
        )
        assert indicator.can_transition_to(FormStatus.VALIDATED) is False

    def test_all_transitions_allowed_in_full_mode(self, root: tk.Tk) -> None:
        """Все переходы разрешены в Full Mode."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_click=None,
            simple_mode=False,
        )
        # In full mode, can_transition_to returns True for all statuses in FULL_MODE_STATUSES
        for status in FormStatus:
            assert indicator.can_transition_to(status) is True


class TestWorkflowSimpleModeStatusMapping:
    """Тесты маппинга статусов при переключении режимов."""

    def test_filled_maps_to_draft_when_switching_to_simple(self, root: tk.Tk) -> None:
        """FILLED маппится в DRAFT при переключении в Simple Mode."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.FILLED,
            on_click=None,
            simple_mode=False,
        )
        indicator.set_simple_mode(True)
        # FILLED should map to DRAFT
        assert indicator.get_status() == "draft"

    def test_validated_maps_to_draft_when_switching_to_simple(self, root: tk.Tk) -> None:
        """VALIDATED маппится в DRAFT при переключении в Simple Mode."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.VALIDATED,
            on_click=None,
            simple_mode=False,
        )
        indicator.set_simple_mode(True)
        # VALIDATED should map to DRAFT
        assert indicator.get_status() == "draft"

    def test_printed_maps_to_signed_when_switching_to_simple(self, root: tk.Tk) -> None:
        """PRINTED маппится в SIGNED при переключении в Simple Mode."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.PRINTED,
            on_click=None,
            simple_mode=False,
        )
        indicator.set_simple_mode(True)
        # PRINTED should map to SIGNED
        assert indicator.get_status() == "signed"

    def test_archived_maps_to_signed_when_switching_to_simple(self, root: tk.Tk) -> None:
        """ARCHIVED маппится в SIGNED при переключении в Simple Mode."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.ARCHIVED,
            on_click=None,
            simple_mode=False,
        )
        indicator.set_simple_mode(True)
        # ARCHIVED should map to SIGNED
        assert indicator.get_status() == "signed"

    def test_rejected_maps_to_draft_when_switching_to_simple(self, root: tk.Tk) -> None:
        """REJECTED маппится в DRAFT при переключении в Simple Mode."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.REJECTED,
            on_click=None,
            simple_mode=False,
        )
        indicator.set_simple_mode(True)
        # REJECTED should map to DRAFT
        assert indicator.get_status() == "draft"

    def test_draft_remains_draft_when_switching_to_simple(self, root: tk.Tk) -> None:
        """DRAFT остаётся DRAFT при переключении в Simple Mode."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_click=None,
            simple_mode=False,
        )
        indicator.set_simple_mode(True)
        assert indicator.get_status() == "draft"

    def test_signed_remains_signed_when_switching_to_simple(self, root: tk.Tk) -> None:
        """SIGNED остаётся SIGNED при переключении в Simple Mode."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.SIGNED,
            on_click=None,
            simple_mode=False,
        )
        indicator.set_simple_mode(True)
        assert indicator.get_status() == "signed"


@pytest.mark.skipif(not MAIN_WINDOW_AVAILABLE, reason="MainWindow not available (circular import)")
class TestWorkflowSimpleModeMenuIntegration:
    """Тесты интеграции с меню."""

    def test_menu_callback_toggles_simple_mode(self, root: tk.Tk) -> None:
        """Callback меню переключает Simple Mode."""
        from src.gui.views.main_window import MainWindow

        window = MainWindow()
        window._root = root
        window._toast_service = MagicMock()

        # Initial state
        assert window.is_workflow_simple_mode() is False

        # Create the BooleanVar and set it
        window._workflow_simple_var = tk.BooleanVar(value=False)
        window._workflow_simple_var.set(True)

        # Call the callback
        window._on_view_workflow_simple_mode()

        # Verify mode changed
        assert window.is_workflow_simple_mode() is True

    def test_menu_callback_dispatches_event(self, root: tk.Tk) -> None:
        """Callback меню отправляет событие контроллеру."""
        from src.gui.views.main_window import MainWindow

        window = MainWindow()
        window._root = root
        window._toast_service = MagicMock()
        window._controller = MagicMock()

        # Set up the menu var
        window._workflow_simple_var = tk.BooleanVar(value=True)

        # Call the callback
        window._on_view_workflow_simple_mode()

        # Verify event was dispatched
        window._controller.dispatch.assert_called_once()
        call_args = window._controller.dispatch.call_args
        assert call_args[0][0] == "workflow_mode_changed"
        assert call_args[1]["simple_mode"] is True

    def test_menu_callback_shows_toast(self, root: tk.Tk) -> None:
        """Callback меню показывает уведомление."""
        from src.gui.views.main_window import MainWindow

        window = MainWindow()
        window._root = root
        window._toast_service = MagicMock()

        # Set up the menu var
        window._workflow_simple_var = tk.BooleanVar(value=True)

        # Call the callback
        window._on_view_workflow_simple_mode()

        # Verify toast was shown
        window._toast_service.show.assert_called_once()
        call_args = window._toast_service.show.call_args
        assert "упрощённый" in call_args[0][0]


class TestWorkflowSimpleModeConstants:
    """Тесты констант Simple Mode."""

    def test_simple_mode_in_all_exports(self) -> None:
        """Константы Simple Mode в __all__."""
        from src.gui.workflow.workflow_indicator import __all__

        assert "SIMPLE_MODE_STATUSES" in __all__
        assert "FULL_MODE_STATUSES" in __all__

    def test_simple_mode_statuses_subset_of_full(self) -> None:
        """Simple Mode статусы - подмножество Full Mode."""
        for status in SIMPLE_MODE_STATUSES:
            assert status in FULL_MODE_STATUSES


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "TestWorkflowSimpleMode",
    "TestWorkflowSimpleModeTransitions",
    "TestWorkflowSimpleModeStatusMapping",
    "TestWorkflowSimpleModeMenuIntegration",
    "TestWorkflowSimpleModeConstants",
]
