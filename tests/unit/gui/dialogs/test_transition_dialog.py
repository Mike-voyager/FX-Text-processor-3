# -*- coding: utf-8 -*-
"""Тесты для TransitionDialog.

Тестирует создание диалога перехода состояния, подтверждение
для ARCHIVED, валидацию текста и формирование результата.

Version: 1.0
"""

from __future__ import annotations

from typing import Any, Generator
from unittest.mock import MagicMock, patch

import pytest

TKINTER_AVAILABLE = False
TransitionDialog: Any = None
try:
    import tkinter as tk

    from src.gui.workflow.transition_dialog import (
        COLOR_BG,
        COLOR_DANGER_BG,
        COLOR_DANGER_BORDER,
        COLOR_WARNING_BG,
        DIALOG_HEIGHT,
        DIALOG_WIDTH,
        MIN_DIALOG_HEIGHT,
        MIN_DIALOG_WIDTH,
        TransitionDialog,
    )

    TKINTER_AVAILABLE = True
except (ImportError, AttributeError, OSError, RuntimeError):
    pass


pytestmark = pytest.mark.skipif(
    not TKINTER_AVAILABLE,
    reason="Tkinter недоступен",
)


@pytest.fixture
def root() -> Generator[tk.Tk, None, None]:
    """Создаёт Tk root для тестов."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


def _make_mock_status(value: str) -> MagicMock:
    """Создаёт mock объекта FormStatus."""
    mock = MagicMock()
    mock.value = value
    mock.name = value.upper()
    return mock


class TestTransitionDialog:
    """Тесты для TransitionDialog."""

    def test_constants(self) -> None:
        """Тест констант диалога."""
        assert DIALOG_WIDTH == 500
        assert DIALOG_HEIGHT == 450
        assert MIN_DIALOG_WIDTH == 400
        assert MIN_DIALOG_HEIGHT == 350

    @patch("src.gui.workflow.transition_dialog.TransitionDialog._create_status_visualization")
    def test_init_basic(
        self,
        mock_viz: MagicMock,
        root: tk.Tk,
    ) -> None:
        """Тест базовой инициализации диалога."""
        from_status = _make_mock_status("draft")
        to_status = _make_mock_status("filled")
        dialog = TransitionDialog(
            parent=root,
            from_state=from_status,
            to_state=to_status,
        )
        assert dialog._requires_mfa is False
        assert dialog._is_archived is False
        assert dialog._result is None
        dialog.destroy()

    @patch("src.gui.workflow.transition_dialog.TransitionDialog._create_status_visualization")
    @patch("src.gui.workflow.transition_dialog.TransitionDialog._create_archived_warning")
    def test_init_archived_transition(
        self,
        mock_archived: MagicMock,
        mock_viz: MagicMock,
        root: tk.Tk,
    ) -> None:
        """Тест инициализации для перехода в ARCHIVED."""
        from_status = _make_mock_status("signed")
        to_status = _make_mock_status("archived")
        dialog = TransitionDialog(
            parent=root,
            from_state=from_status,
            to_state=to_status,
        )
        assert dialog._is_archived is True
        dialog.destroy()

    @patch("src.gui.workflow.transition_dialog.TransitionDialog._create_status_visualization")
    def test_validate_confirmation_non_archived(
        self,
        mock_viz: MagicMock,
        root: tk.Tk,
    ) -> None:
        """Тест валидации подтверждения для не-ARCHIVED перехода."""
        from_status = _make_mock_status("draft")
        to_status = _make_mock_status("filled")
        dialog = TransitionDialog(
            parent=root,
            from_state=from_status,
            to_state=to_status,
        )
        assert dialog._validate_confirmation() is True
        dialog.destroy()

    @patch("src.gui.workflow.transition_dialog.TransitionDialog._create_status_visualization")
    @patch("src.gui.workflow.transition_dialog.TransitionDialog._create_archived_warning")
    def test_validate_confirmation_archived_correct(
        self,
        mock_archived: MagicMock,
        mock_viz: MagicMock,
        root: tk.Tk,
    ) -> None:
        """Тест валидации подтверждения ARCHIVED с правильным текстом."""
        from_status = _make_mock_status("signed")
        to_status = _make_mock_status("archived")
        dialog = TransitionDialog(
            parent=root,
            from_state=from_status,
            to_state=to_status,
        )
        dialog._confirm_var.set("ARCHIVE")
        assert dialog._validate_confirmation() is True
        dialog.destroy()

    @patch("src.gui.workflow.transition_dialog.TransitionDialog._create_status_visualization")
    @patch("src.gui.workflow.transition_dialog.TransitionDialog._create_archived_warning")
    def test_validate_confirmation_archived_incorrect(
        self,
        mock_archived: MagicMock,
        mock_viz: MagicMock,
        root: tk.Tk,
    ) -> None:
        """Тест валидации подтверждения ARCHIVED с неверным текстом."""
        from_status = _make_mock_status("signed")
        to_status = _make_mock_status("archived")
        dialog = TransitionDialog(
            parent=root,
            from_state=from_status,
            to_state=to_status,
        )
        dialog._confirm_var.set("WRONG")
        assert dialog._validate_confirmation() is False
        dialog.destroy()

    @patch("src.gui.workflow.transition_dialog.TransitionDialog._create_status_visualization")
    def test_on_cancel(
        self,
        mock_viz: MagicMock,
        root: tk.Tk,
    ) -> None:
        """Тест отмены диалога."""
        from_status = _make_mock_status("draft")
        to_status = _make_mock_status("filled")
        dialog = TransitionDialog(
            parent=root,
            from_state=from_status,
            to_state=to_status,
        )
        dialog._on_cancel()
        assert dialog._result is None
        dialog.destroy()

    @patch("src.gui.workflow.transition_dialog.TransitionDialog._create_status_visualization")
    def test_confirm_var_initialized(
        self,
        mock_viz: MagicMock,
        root: tk.Tk,
    ) -> None:
        """Тест что _confirm_var всегда инициализирована."""
        from_status = _make_mock_status("draft")
        to_status = _make_mock_status("filled")
        dialog = TransitionDialog(
            parent=root,
            from_state=from_status,
            to_state=to_status,
        )
        assert hasattr(dialog, "_confirm_var")
        assert dialog._confirm_var is not None
        dialog.destroy()