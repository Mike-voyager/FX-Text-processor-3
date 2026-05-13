"""Тесты для RejectDialog.

Тестирует создание диалога, валидацию ввода и MFA интеграцию.
"""

from __future__ import annotations

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest

from src.documents.constructor.form_status import FormStatus
from src.gui.dialogs.reject_dialog import (
    COLOR_BG,
    COLOR_DANGER,
    COLOR_INFO,
    DIALOG_HEIGHT,
    DIALOG_WIDTH,
    MAX_REASON_LENGTH,
    MIN_REASON_LENGTH,
    RejectDialog,
)


@pytest.fixture
def root() -> Generator[tk.Tk, None, None]:
    """Фикстура для Tk root."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def mock_reject_callback() -> MagicMock:
    """Фикстура для mock callback отклонения."""
    return MagicMock()


class TestRejectDialog:
    """Тесты для RejectDialog."""

    def test_init_draft_status(self, root: tk.Tk) -> None:
        """Тест инициализации со статусом DRAFT."""
        dialog = RejectDialog(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_reject=None,
        )
        assert dialog._current_status == FormStatus.DRAFT
        dialog.destroy()

    def test_init_validated_status(self, root: tk.Tk) -> None:
        """Тест инициализации со статусом VALIDATED."""
        dialog = RejectDialog(
            parent=root,
            current_status=FormStatus.VALIDATED,
            on_reject=None,
        )
        assert dialog._current_status == FormStatus.VALIDATED
        dialog.destroy()

    def test_dialog_title(self, root: tk.Tk) -> None:
        """Тест заголовка окна."""
        dialog = RejectDialog(
            parent=root,
            current_status=FormStatus.VALIDATED,
            on_reject=None,
        )
        assert "Reject" in dialog.title()
        dialog.destroy()

    def test_reject_options_defined(self, root: tk.Tk) -> None:
        """Тест что опции отклонения определены."""
        dialog = RejectDialog(
            parent=root,
            current_status=FormStatus.VALIDATED,
            on_reject=None,
        )
        options = dialog.REJECT_OPTIONS
        assert len(options) == 2
        assert options[0][0] == "to_draft"
        assert options[1][0] == "to_rejected"
        dialog.destroy()

    def test_selected_option_default(self, root: tk.Tk) -> None:
        """Тест значения по умолчанию для выбранной опции."""
        dialog = RejectDialog(
            parent=root,
            current_status=FormStatus.VALIDATED,
            on_reject=None,
        )
        assert dialog._selected_option.get() == "to_draft"
        dialog.destroy()

    def test_validate_input_empty_reason(self, root: tk.Tk) -> None:
        """Тест валидации пустой причины."""
        dialog = RejectDialog(
            parent=root,
            current_status=FormStatus.VALIDATED,
            on_reject=None,
        )
        dialog._reason_text = tk.Text(dialog)
        # Пустой текст

        valid, error = dialog._validate_input()

        assert valid is False
        assert "reason" in error.lower() or "причина" in error.lower()
        dialog.destroy()

    def test_validate_input_short_reason(self, root: tk.Tk) -> None:
        """Тест валидации слишком короткой причины."""
        dialog = RejectDialog(
            parent=root,
            current_status=FormStatus.VALIDATED,
            on_reject=None,
        )
        dialog._reason_text = tk.Text(dialog)
        dialog._reason_text.insert("1.0", "short")  # Меньше MIN_REASON_LENGTH

        valid, error = dialog._validate_input()

        assert valid is False
        assert "10" in error or str(MIN_REASON_LENGTH) in error
        dialog.destroy()

    def test_mfa_required_for_rejected(self, root: tk.Tk) -> None:
        """Тест что MFA требуется для REJECTED."""
        dialog = RejectDialog(
            parent=root,
            current_status=FormStatus.VALIDATED,
            on_reject=None,
        )
        # Выбираем to_rejected
        dialog._selected_option.set("to_rejected")

        assert dialog._is_mfa_required() is True
        dialog.destroy()

    def test_mfa_not_required_for_draft_from_draft(self, root: tk.Tk) -> None:
        """Тест что MFA не требуется для возврата в DRAFT из DRAFT."""
        dialog = RejectDialog(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_reject=None,
        )
        dialog._selected_option.set("to_draft")

        # Из DRAFT в DRAFT не требует MFA
        assert dialog._is_mfa_required() is False
        dialog.destroy()

    def test_mfa_required_transitions_set(self, root: tk.Tk) -> None:
        """Тест множества переходов, требующих MFA."""
        from src.gui.dialogs.reject_dialog import _MFA_REQUIRED_FROM

        expected = {
            FormStatus.VALIDATED,
            FormStatus.SIGNED,
            FormStatus.PRINTED,
        }
        assert _MFA_REQUIRED_FROM == expected

    def test_dialog_constants(self) -> None:
        """Тест констант диалога."""
        assert DIALOG_WIDTH == 500
        assert DIALOG_HEIGHT == 450
        assert MIN_REASON_LENGTH == 10
        assert MAX_REASON_LENGTH == 1000
        assert COLOR_BG.startswith("#")
        assert COLOR_DANGER.startswith("#")
        assert COLOR_INFO.startswith("#")

    def test_get_selected_status_to_draft(self, root: tk.Tk) -> None:
        """Тест получения выбранного статуса (to_draft)."""
        dialog = RejectDialog(
            parent=root,
            current_status=FormStatus.VALIDATED,
            on_reject=None,
        )
        # Симулируем результат
        dialog._result = {
            "option": "to_draft",
            "target_status": FormStatus.DRAFT,
            "reason": "Test reason",
        }

        status = dialog.get_selected_status()
        assert status == FormStatus.DRAFT
        dialog.destroy()

    def test_get_selected_status_to_rejected(self, root: tk.Tk) -> None:
        """Тест получения выбранного статуса (to_rejected)."""
        dialog = RejectDialog(
            parent=root,
            current_status=FormStatus.VALIDATED,
            on_reject=None,
        )
        # Симулируем результат
        dialog._result = {
            "option": "to_rejected",
            "target_status": FormStatus.REJECTED,
            "reason": "Test reason",
        }

        status = dialog.get_selected_status()
        assert status == FormStatus.REJECTED
        dialog.destroy()

    def test_get_reason(self, root: tk.Tk) -> None:
        """Тест получения причины."""
        dialog = RejectDialog(
            parent=root,
            current_status=FormStatus.VALIDATED,
            on_reject=None,
        )
        # Симулируем результат
        dialog._result = {
            "option": "to_draft",
            "target_status": FormStatus.DRAFT,
            "reason": "Test rejection reason",
        }

        reason = dialog.get_reason()
        assert reason == "Test rejection reason"
        dialog.destroy()

    def test_get_reason_cancelled(self, root: tk.Tk) -> None:
        """Тест получения причины при отмене."""
        dialog = RejectDialog(
            parent=root,
            current_status=FormStatus.VALIDATED,
            on_reject=None,
        )
        # Результат None при отмене
        dialog._result = None

        reason = dialog.get_reason()
        assert reason is None
        dialog.destroy()

    def test_update_warning_to_draft(self, root: tk.Tk) -> None:
        """Тест обновления предупреждения для to_draft."""
        dialog = RejectDialog(
            parent=root,
            current_status=FormStatus.VALIDATED,
            on_reject=None,
        )
        dialog._selected_option.set("to_draft")
        dialog._update_warning()

        # Проверяем что текст содержит информацию о возврате
        assert dialog._warning_label is not None
        dialog.destroy()

    def test_update_warning_to_rejected(self, root: tk.Tk) -> None:
        """Тест обновления предупреждения для to_rejected."""
        dialog = RejectDialog(
            parent=root,
            current_status=FormStatus.VALIDATED,
            on_reject=None,
        )
        dialog._selected_option.set("to_rejected")
        dialog._update_warning()

        # Проверяем что текст содержит WARNING
        assert dialog._warning_label is not None
        dialog.destroy()

    def test_update_button_appearance_to_rejected(self, root: tk.Tk) -> None:
        """Тест обновления кнопки для to_rejected."""
        dialog = RejectDialog(
            parent=root,
            current_status=FormStatus.VALIDATED,
            on_reject=None,
        )
        dialog._selected_option.set("to_rejected")
        dialog._update_button_appearance()

        assert dialog._confirm_btn is not None
        dialog.destroy()

    def test_update_button_appearance_to_draft(self, root: tk.Tk) -> None:
        """Тест обновления кнопки для to_draft."""
        dialog = RejectDialog(
            parent=root,
            current_status=FormStatus.VALIDATED,
            on_reject=None,
        )
        dialog._selected_option.set("to_draft")
        dialog._update_button_appearance()

        assert dialog._confirm_btn is not None
        dialog.destroy()


class TestRejectDialogValidation:
    """Тесты валидации RejectDialog."""

    def test_reason_length_limits(self, root: tk.Tk) -> None:
        """Тест лимитов длины причины."""
        dialog = RejectDialog(
            parent=root,
            current_status=FormStatus.VALIDATED,
            on_reject=None,
        )
        dialog._reason_text = tk.Text(dialog)

        # Слишком короткая причина
        dialog._reason_text.insert("1.0", "a" * 5)
        valid, _ = dialog._validate_input()
        assert valid is False

        # Минимальная допустимая длина
        dialog._reason_text.delete("1.0", tk.END)
        dialog._reason_text.insert("1.0", "a" * MIN_REASON_LENGTH)
        valid, _ = dialog._validate_input()
        assert valid is True

        dialog.destroy()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
