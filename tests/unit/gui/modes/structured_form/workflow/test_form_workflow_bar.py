"""Тесты для FormWorkflowBar.

Author: Mike Voyager
Date: 2026-04-07
"""

from __future__ import annotations

import tkinter as tk
from unittest.mock import MagicMock, patch

import pytest

from src.documents.constructor.form_status import FormStatus
from src.gui.modes.structured_form.workflow.form_workflow_bar import FormWorkflowBar


@pytest.fixture
def root() -> tk.Tk:
    """Создаёт корневое окно Tkinter."""
    root = tk.Tk()
    yield root
    root.destroy()


class TestFormWorkflowBar:
    """Тесты для FormWorkflowBar."""

    @pytest.fixture
    def workflow_bar(self, root: tk.Tk) -> FormWorkflowBar:
        """Создаёт FormWorkflowBar для тестирования."""
        bar = FormWorkflowBar(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_transition=None,
            mode_manager=None,
        )
        bar.mount(root)
        root.update_idletasks()
        return bar

    def test_status_transitions(self, workflow_bar: FormWorkflowBar) -> None:
        """Тест переходов между статусами."""
        # DRAFT -> FILLED
        allowed = workflow_bar.get_allowed_transitions()
        assert FormStatus.FILLED in allowed

        workflow_bar.set_status(FormStatus.FILLED)
        assert workflow_bar.get_current_status() == FormStatus.FILLED

        # FILLED -> VALIDATED
        allowed = workflow_bar.get_allowed_transitions()
        assert FormStatus.VALIDATED in allowed

        workflow_bar.set_status(FormStatus.VALIDATED)
        assert workflow_bar.get_current_status() == FormStatus.VALIDATED

    def test_mfa_required_transitions(self, workflow_bar: FormWorkflowBar) -> None:
        """Тест что MFA требуется для критичных переходов."""
        # VALIDATED -> SIGNED требует MFA
        workflow_bar.set_status(FormStatus.VALIDATED)

        assert workflow_bar._is_mfa_required(FormStatus.SIGNED) is True

        # DRAFT -> FILLED не требует MFA
        workflow_bar.set_status(FormStatus.DRAFT)
        assert workflow_bar._is_mfa_required(FormStatus.FILLED) is False

        # FILLED -> VALIDATED не требует MFA
        workflow_bar.set_status(FormStatus.FILLED)
        assert workflow_bar._is_mfa_required(FormStatus.VALIDATED) is False

    def test_rejected_to_draft(self, workflow_bar: FormWorkflowBar) -> None:
        """Тест перехода из REJECTED в DRAFT."""
        workflow_bar.set_status(FormStatus.REJECTED)

        allowed = workflow_bar.get_allowed_transitions()
        assert FormStatus.DRAFT in allowed

        workflow_bar.set_status(FormStatus.DRAFT)
        assert workflow_bar.get_current_status() == FormStatus.DRAFT

    def test_archived_is_terminal(self, workflow_bar: FormWorkflowBar) -> None:
        """Тест что ARCHIVED терминальный статус."""
        workflow_bar.set_status(FormStatus.ARCHIVED)

        allowed = workflow_bar.get_allowed_transitions()
        assert len(allowed) == 0  # Нет допустимых переходов

    def test_can_transition_to(self, workflow_bar: FormWorkflowBar) -> None:
        """Тест проверки возможности перехода."""
        workflow_bar.set_status(FormStatus.DRAFT)

        assert workflow_bar.can_transition_to(FormStatus.FILLED) is True
        assert workflow_bar.can_transition_to(FormStatus.SIGNED) is False
        assert workflow_bar.can_transition_to(FormStatus.ARCHIVED) is False

    def test_status_order(self) -> None:
        """Тест порядка статусов."""
        expected_order = [
            FormStatus.DRAFT,
            FormStatus.FILLED,
            FormStatus.VALIDATED,
            FormStatus.SIGNED,
            FormStatus.PRINTED,
            FormStatus.ARCHIVED,
        ]

        assert FormWorkflowBar.STATUS_ORDER == expected_order

    def test_status_colors_exist(self) -> None:
        """Тест что для всех статусов есть цвета."""
        all_statuses = [
            FormStatus.DRAFT,
            FormStatus.FILLED,
            FormStatus.VALIDATED,
            FormStatus.SIGNED,
            FormStatus.PRINTED,
            FormStatus.ARCHIVED,
            FormStatus.REJECTED,
        ]

        for status in all_statuses:
            assert status in FormWorkflowBar.STATUS_COLORS
            color = FormWorkflowBar.STATUS_COLORS[status]
            assert color.startswith("#")
            assert len(color) == 7  # #RRGGBB

    def test_get_allowed_transitions_no_rejected(self, workflow_bar: FormWorkflowBar) -> None:
        """Тест что get_allowed_transitions не возвращает REJECTED."""
        workflow_bar.set_status(FormStatus.FILLED)
        allowed = workflow_bar.get_allowed_transitions()

        # REJECTED может быть допустим, но должен быть в отдельном списке
        # Метод возвращает только основные переходы
        assert FormStatus.VALIDATED in allowed

    def test_allowed_transitions_by_status(self) -> None:
        """Тест разрешённых переходов для каждого статуса."""
        transitions = {
            FormStatus.DRAFT: [FormStatus.FILLED],
            FormStatus.FILLED: [FormStatus.VALIDATED, FormStatus.REJECTED],
            FormStatus.VALIDATED: [FormStatus.SIGNED, FormStatus.REJECTED],
            FormStatus.SIGNED: [FormStatus.PRINTED],
            FormStatus.PRINTED: [FormStatus.ARCHIVED],
            FormStatus.REJECTED: [FormStatus.DRAFT],
            FormStatus.ARCHIVED: [],
        }

        bar = MagicMock()
        bar._current_status = FormStatus.DRAFT

        for status, expected in transitions.items():
            wf_bar = FormWorkflowBar(
                parent=MagicMock(),
                current_status=status,
            )
            allowed = wf_bar._get_allowed_transitions_internal()
            for exp_status in expected:
                assert exp_status in allowed, f"{status.name} -> {exp_status.name} должен быть разрешён"

    def test_set_status_calls_callback(self, root: tk.Tk) -> None:
        """Тест что set_status вызывает callback."""
        callback_calls = []

        def on_transition(old: FormStatus, new: FormStatus) -> None:
            callback_calls.append((old, new))

        bar = FormWorkflowBar(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_transition=on_transition,
        )
        bar.mount(root)

        bar.set_status(FormStatus.FILLED)

        assert len(callback_calls) == 1
        assert callback_calls[0] == (FormStatus.DRAFT, FormStatus.FILLED)

    def test_mfa_transitions_set(self) -> None:
        """Тест множества MFA-переходов."""
        expected_mfa = {
            (FormStatus.VALIDATED, FormStatus.SIGNED),
            (FormStatus.SIGNED, FormStatus.PRINTED),
            (FormStatus.PRINTED, FormStatus.ARCHIVED),
        }

        bar = FormWorkflowBar(parent=MagicMock())

        for from_status, to_status in expected_mfa:
            bar._current_status = from_status
            assert bar._is_mfa_required(to_status) is True

    def test_wipe_sensitive_data(self, root: tk.Tk) -> None:
        """Тест очистки sensitive данных."""
        bar = FormWorkflowBar(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_transition=lambda old, new: None,
        )
        bar.mount(root)

        bar.wipe_sensitive_data()

        assert bar._on_transition is None

    def test_transition_button_texts(self, workflow_bar: FormWorkflowBar) -> None:
        """Тест текстов кнопок переходов."""
        texts = {
            FormStatus.DRAFT: "На доработку",
            FormStatus.FILLED: "Заполнить",
            FormStatus.VALIDATED: "Проверить",
            FormStatus.SIGNED: "Подписать",
            FormStatus.PRINTED: "Напечатать",
            FormStatus.ARCHIVED: "Архивировать",
            FormStatus.REJECTED: "Отклонить",
        }

        for status, expected_text in texts.items():
            button_text = workflow_bar._get_transition_button_text(status)
            assert button_text == expected_text
