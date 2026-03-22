"""Тесты для модуля управления статусом формы.

Tests cover:
- FormStatus enum properties and methods
- FormStatusManager state transitions
- MFA requirements for critical transitions
- Error handling for invalid transitions
- Audit callback functionality
"""

from __future__ import annotations

import logging
from dataclasses import FrozenInstanceError
from typing import Any
from unittest.mock import Mock

import pytest
from src.documents.constructor.form_status import (
    _MFA_REQUIRED_TRANSITIONS,
    FormStatus,
    FormStatusManager,
    StatusTransitionError,
)

# =============================================================================
# FormStatus Enum Tests
# =============================================================================


class TestFormStatus:
    """Тесты для enum FormStatus."""

    def test_form_status_values(self) -> None:
        """Проверка значений состояний."""
        assert FormStatus.DRAFT.value == "draft"
        assert FormStatus.FILLED.value == "filled"
        assert FormStatus.VALIDATED.value == "validated"
        assert FormStatus.SIGNED.value == "signed"
        assert FormStatus.PRINTED.value == "printed"
        assert FormStatus.ARCHIVED.value == "archived"
        assert FormStatus.REJECTED.value == "rejected"

    def test_localized_names(self) -> None:
        """Проверка локализованных названий состояний."""
        assert FormStatus.DRAFT.localized_name == "Черновик"
        assert FormStatus.FILLED.localized_name == "Заполнена"
        assert FormStatus.VALIDATED.localized_name == "Проверена"
        assert FormStatus.SIGNED.localized_name == "Подписана"
        assert FormStatus.PRINTED.localized_name == "Напечатана"
        assert FormStatus.ARCHIVED.localized_name == "Архивирована"
        assert FormStatus.REJECTED.localized_name == "Отклонена"

    def test_is_editable(self) -> None:
        """Проверка свойства is_editable."""
        assert FormStatus.DRAFT.is_editable is True
        assert FormStatus.FILLED.is_editable is False
        assert FormStatus.VALIDATED.is_editable is False
        assert FormStatus.SIGNED.is_editable is False
        assert FormStatus.PRINTED.is_editable is False
        assert FormStatus.ARCHIVED.is_editable is False
        assert FormStatus.REJECTED.is_editable is False

    def test_is_terminal(self) -> None:
        """Проверка свойства is_terminal."""
        assert FormStatus.DRAFT.is_terminal is False
        assert FormStatus.FILLED.is_terminal is False
        assert FormStatus.VALIDATED.is_terminal is False
        assert FormStatus.SIGNED.is_terminal is False
        assert FormStatus.PRINTED.is_terminal is False
        assert FormStatus.ARCHIVED.is_terminal is True
        assert FormStatus.REJECTED.is_terminal is True

    def test_str_comparison(self) -> None:
        """Проверка сравнения со строками."""
        assert FormStatus.DRAFT.value == "draft"
        assert FormStatus.FILLED.value == "filled"


# =============================================================================
# FormStatusManager Creation Tests
# =============================================================================


class TestFormStatusManagerCreation:
    """Тесты создания FormStatusManager."""

    def test_create_with_defaults(self) -> None:
        """Создание с параметрами по умолчанию."""
        manager = FormStatusManager()
        assert manager.require_mfa is True
        assert manager.audit_callback is None

    def test_create_without_mfa(self) -> None:
        """Создание без требования MFA."""
        manager = FormStatusManager(require_mfa=False)
        assert manager.require_mfa is False

    def test_create_with_audit_callback(self) -> None:
        """Создание с audit callback."""
        callback = Mock()
        manager = FormStatusManager(audit_callback=callback)
        assert manager.audit_callback is callback

    def test_invalid_require_mfa_type(self) -> None:
        """Ошибка при некорректном типе require_mfa."""
        with pytest.raises(TypeError, match="require_mfa должен быть bool"):
            FormStatusManager(require_mfa="yes")  # type: ignore

    def test_frozen_instance(self) -> None:
        """Проверка неизменяемости объекта."""
        manager = FormStatusManager()
        with pytest.raises(FrozenInstanceError):
            manager.require_mfa = False  # type: ignore


# =============================================================================
# Allowed Transitions Tests
# =============================================================================


class TestAllowedTransitions:
    """Тесты допустимых переходов между состояниями."""

    def test_draft_transitions(self) -> None:
        """Переходы из DRAFT."""
        manager = FormStatusManager()
        allowed = manager.get_allowed_transitions(FormStatus.DRAFT)
        assert FormStatus.FILLED in allowed
        assert FormStatus.REJECTED in allowed
        assert FormStatus.VALIDATED not in allowed
        assert FormStatus.SIGNED not in allowed

    def test_filled_transitions(self) -> None:
        """Переходы из FILLED."""
        manager = FormStatusManager()
        allowed = manager.get_allowed_transitions(FormStatus.FILLED)
        assert FormStatus.VALIDATED in allowed
        assert FormStatus.DRAFT in allowed
        assert FormStatus.REJECTED in allowed
        assert FormStatus.SIGNED not in allowed

    def test_validated_transitions(self) -> None:
        """Переходы из VALIDATED."""
        manager = FormStatusManager()
        allowed = manager.get_allowed_transitions(FormStatus.VALIDATED)
        assert FormStatus.SIGNED in allowed
        assert FormStatus.FILLED in allowed
        assert FormStatus.REJECTED in allowed

    def test_signed_transitions(self) -> None:
        """Переходы из SIGNED."""
        manager = FormStatusManager()
        allowed = manager.get_allowed_transitions(FormStatus.SIGNED)
        assert FormStatus.PRINTED in allowed
        assert FormStatus.VALIDATED in allowed
        assert FormStatus.ARCHIVED not in allowed

    def test_printed_transitions(self) -> None:
        """Переходы из PRINTED."""
        manager = FormStatusManager()
        allowed = manager.get_allowed_transitions(FormStatus.PRINTED)
        assert FormStatus.ARCHIVED in allowed
        assert FormStatus.SIGNED in allowed
        assert FormStatus.DRAFT not in allowed

    def test_archived_transitions(self) -> None:
        """Переходы из ARCHIVED (терминальное состояние)."""
        manager = FormStatusManager()
        allowed = manager.get_allowed_transitions(FormStatus.ARCHIVED)
        assert allowed == []

    def test_rejected_transitions(self) -> None:
        """Переходы из REJECTED (возврат на доработку)."""
        manager = FormStatusManager()
        allowed = manager.get_allowed_transitions(FormStatus.REJECTED)
        assert FormStatus.DRAFT in allowed
        assert len(allowed) == 1


# =============================================================================
# MFA Requirements Tests
# =============================================================================


class TestMFARequirements:
    """Тесты требований MFA для переходов."""

    def test_mfa_required_transitions(self) -> None:
        """Переходы, требующие MFA."""
        required = _MFA_REQUIRED_TRANSITIONS
        assert (FormStatus.FILLED, FormStatus.VALIDATED) in required
        assert (FormStatus.VALIDATED, FormStatus.SIGNED) in required
        assert (FormStatus.SIGNED, FormStatus.PRINTED) in required
        assert (FormStatus.PRINTED, FormStatus.ARCHIVED) in required
        assert (FormStatus.VALIDATED, FormStatus.FILLED) in required
        assert (FormStatus.SIGNED, FormStatus.VALIDATED) in required

    def test_mfa_not_required_transitions(self) -> None:
        """Переходы, не требующие MFA."""
        required = _MFA_REQUIRED_TRANSITIONS
        assert (FormStatus.DRAFT, FormStatus.FILLED) not in required
        assert (FormStatus.FILLED, FormStatus.DRAFT) not in required
        assert (FormStatus.FILLED, FormStatus.REJECTED) not in required


# =============================================================================
# Can Transition Tests
# =============================================================================


class TestCanTransition:
    """Тесты проверки возможности перехода."""

    def test_can_transition_valid(self) -> None:
        """Допустимый переход."""
        manager = FormStatusManager()
        doc = Mock()
        doc.status = FormStatus.DRAFT

        assert manager.can_transition(doc, FormStatus.FILLED) is True

    def test_can_transition_invalid(self) -> None:
        """Недопустимый переход."""
        manager = FormStatusManager()
        doc = Mock()
        doc.status = FormStatus.DRAFT

        assert manager.can_transition(doc, FormStatus.SIGNED) is False

    def test_can_transition_from_string_status(self) -> None:
        """Переход когда статус хранится как строка."""
        manager = FormStatusManager()
        doc = Mock()
        doc.status = "draft"

        assert manager.can_transition(doc, FormStatus.FILLED) is True

    def test_can_transition_no_status(self) -> None:
        """Переход когда статус не установлен (считается DRAFT)."""
        manager = FormStatusManager()
        doc = Mock(spec=[])

        assert manager.can_transition(doc, FormStatus.FILLED) is True


# =============================================================================
# Transition Execution Tests
# =============================================================================


class TestTransitionExecution:
    """Тесты выполнения переходов."""

    def test_successful_transition(self) -> None:
        """Успешный переход без MFA."""
        manager = FormStatusManager(require_mfa=False)
        doc = Mock()
        doc.status = FormStatus.DRAFT

        manager.transition(doc, FormStatus.FILLED, mfa=False)
        assert doc.status == FormStatus.FILLED

    def test_transition_with_mfa(self) -> None:
        """Переход с подтверждением MFA."""
        manager = FormStatusManager(require_mfa=True)
        doc = Mock()
        doc.status = FormStatus.FILLED

        manager.transition(doc, FormStatus.VALIDATED, mfa=True)
        assert doc.status == FormStatus.VALIDATED

    def test_transition_mfa_required_but_not_provided(self) -> None:
        """Ошибка при отсутствии MFA для критичного перехода."""
        manager = FormStatusManager(require_mfa=True)
        doc = Mock()
        doc.status = FormStatus.FILLED

        with pytest.raises(ValueError, match="требует подтверждения MFA"):
            manager.transition(doc, FormStatus.VALIDATED, mfa=False)

    def test_transition_mfa_not_required(self) -> None:
        """Переход без MFA когда он не требуется."""
        manager = FormStatusManager(require_mfa=True)
        doc = Mock()
        doc.status = FormStatus.DRAFT

        # DRAFT -> FILLED не требует MFA
        manager.transition(doc, FormStatus.FILLED, mfa=False)
        assert doc.status == FormStatus.FILLED

    def test_invalid_transition_raises_error(self) -> None:
        """Ошибка при недопустимом переходе."""
        manager = FormStatusManager()
        doc = Mock()
        doc.status = FormStatus.DRAFT
        doc.id = "test-doc"

        with pytest.raises(StatusTransitionError) as exc_info:
            manager.transition(doc, FormStatus.SIGNED)

        error = exc_info.value
        assert error.from_state == FormStatus.DRAFT
        assert error.to_state == FormStatus.SIGNED
        assert "draft" in str(error)
        assert "signed" in str(error)

    def test_full_workflow_transition(self) -> None:
        """Полный workflow от DRAFT до ARCHIVED."""
        manager = FormStatusManager(require_mfa=False)
        doc = Mock()
        doc.status = FormStatus.DRAFT
        doc.id = "workflow-test"

        # DRAFT -> FILLED
        manager.transition(doc, FormStatus.FILLED)
        assert doc.status == FormStatus.FILLED

        # FILLED -> VALIDATED
        manager.transition(doc, FormStatus.VALIDATED)
        assert doc.status == FormStatus.VALIDATED

        # VALIDATED -> SIGNED
        manager.transition(doc, FormStatus.SIGNED)
        assert doc.status == FormStatus.SIGNED

        # SIGNED -> PRINTED
        manager.transition(doc, FormStatus.PRINTED)
        assert doc.status == FormStatus.PRINTED

        # PRINTED -> ARCHIVED
        manager.transition(doc, FormStatus.ARCHIVED)
        assert doc.status == FormStatus.ARCHIVED


# =============================================================================
# Audit Callback Tests
# =============================================================================


class TestAuditCallback:
    """Тесты audit callback функциональности."""

    def test_audit_callback_called(self) -> None:
        """Callback вызывается при переходе."""
        callback = Mock()
        manager = FormStatusManager(require_mfa=False, audit_callback=callback)
        doc = Mock()
        doc.status = FormStatus.DRAFT
        doc.id = "audit-test"

        manager.transition(doc, FormStatus.FILLED)

        callback.assert_called_once()
        call_args = callback.call_args[1]
        assert call_args["event_type"] == "workflow.transition"
        assert call_args["from_state"] == "draft"
        assert call_args["to_state"] == "filled"
        assert call_args["document_id"] == "audit-test"

    def test_audit_callback_exception_logged(self, caplog: Any) -> None:
        """Исключение в callback логируется но не прерывает выполнение."""
        callback = Mock(side_effect=Exception("Audit failed"))
        manager = FormStatusManager(require_mfa=False, audit_callback=callback)
        doc = Mock()
        doc.status = FormStatus.DRAFT
        doc.id = "audit-error-test"

        with caplog.at_level(logging.WARNING):
            manager.transition(doc, FormStatus.FILLED)

        assert "Ошибка аудит-колбэка" in caplog.text
        # Переход всё равно выполнен
        assert doc.status == FormStatus.FILLED


# =============================================================================
# Status Info Tests
# =============================================================================


class TestGetStatusInfo:
    """Тесты получения информации о состоянии."""

    def test_get_status_info_draft(self) -> None:
        """Информация о состоянии DRAFT."""
        manager = FormStatusManager()
        info = manager.get_status_info(FormStatus.DRAFT)

        assert info["value"] == "draft"
        assert info["localized_name"] == "Черновик"
        assert info["is_editable"] is True
        assert info["is_terminal"] is False
        assert "filled" in info["allowed_transitions"]
        assert "rejected" in info["allowed_transitions"]

    def test_get_status_info_archived(self) -> None:
        """Информация о терминальном состоянии ARCHIVED."""
        manager = FormStatusManager()
        info = manager.get_status_info(FormStatus.ARCHIVED)

        assert info["value"] == "archived"
        assert info["is_terminal"] is True
        assert info["allowed_transitions"] == []


# =============================================================================
# Error Class Tests
# =============================================================================


class TestStatusTransitionError:
    """Тесты класса StatusTransitionError."""

    def test_error_message_format(self) -> None:
        """Форматирование сообщения об ошибке."""
        error = StatusTransitionError(
            from_state=FormStatus.DRAFT,
            to_state=FormStatus.ARCHIVED,
            message="Нельзя пропустить промежуточные состояния",
        )

        msg = str(error)
        assert "draft" in msg
        assert "archived" in msg
        assert "Нельзя пропустить" in msg

    def test_error_attributes(self) -> None:
        """Атрибуты ошибки."""
        error = StatusTransitionError(
            from_state=FormStatus.FILLED, to_state=FormStatus.PRINTED, message="Test message"
        )

        assert error.from_state == FormStatus.FILLED
        assert error.to_state == FormStatus.PRINTED
        assert error.message == "Test message"


# =============================================================================
# Edge Cases and Boundary Tests
# =============================================================================


class TestEdgeCases:
    """Тесты граничных случаев."""

    def test_reject_from_any_state(self) -> None:
        """Отклонение возможно из большинства состояний."""
        manager = FormStatusManager(require_mfa=False)

        for from_status in [FormStatus.DRAFT, FormStatus.FILLED, FormStatus.VALIDATED]:
            doc = Mock()
            doc.status = from_status
            manager.transition(doc, FormStatus.REJECTED)
            assert doc.status == FormStatus.REJECTED

    def test_return_to_draft_after_reject(self) -> None:
        """Возврат в DRAFT после REJECTED."""
        manager = FormStatusManager(require_mfa=False)
        doc = Mock()
        doc.status = FormStatus.REJECTED

        manager.transition(doc, FormStatus.DRAFT)
        assert doc.status == FormStatus.DRAFT

    def test_no_mfa_when_require_mfa_false(self) -> None:
        """MFA не проверяется когда require_mfa=False."""
        manager = FormStatusManager(require_mfa=False)
        doc = Mock()
        doc.status = FormStatus.FILLED

        # Даже для критичного перехода MFA не требуется
        manager.transition(doc, FormStatus.VALIDATED, mfa=False)
        assert doc.status == FormStatus.VALIDATED

    def test_allowed_transitions_returns_copy(self) -> None:
        """Метод возвращает копию списка."""
        manager = FormStatusManager()
        allowed1 = manager.get_allowed_transitions(FormStatus.DRAFT)
        allowed2 = manager.get_allowed_transitions(FormStatus.DRAFT)

        assert allowed1 is not allowed2
        assert allowed1 == allowed2


# =============================================================================
# Parametrized Transition Tests
# =============================================================================


@pytest.mark.parametrize(
    "from_state,to_state,should_succeed",
    [
        # Valid transitions
        (FormStatus.DRAFT, FormStatus.FILLED, True),
        (FormStatus.DRAFT, FormStatus.REJECTED, True),
        (FormStatus.FILLED, FormStatus.VALIDATED, True),
        (FormStatus.FILLED, FormStatus.DRAFT, True),
        (FormStatus.FILLED, FormStatus.REJECTED, True),
        (FormStatus.VALIDATED, FormStatus.SIGNED, True),
        (FormStatus.VALIDATED, FormStatus.FILLED, True),
        (FormStatus.VALIDATED, FormStatus.REJECTED, True),
        (FormStatus.SIGNED, FormStatus.PRINTED, True),
        (FormStatus.SIGNED, FormStatus.VALIDATED, True),
        (FormStatus.PRINTED, FormStatus.ARCHIVED, True),
        (FormStatus.PRINTED, FormStatus.SIGNED, True),
        (FormStatus.REJECTED, FormStatus.DRAFT, True),
        # Invalid transitions
        (FormStatus.DRAFT, FormStatus.VALIDATED, False),
        (FormStatus.DRAFT, FormStatus.SIGNED, False),
        (FormStatus.DRAFT, FormStatus.ARCHIVED, False),
        (FormStatus.ARCHIVED, FormStatus.DRAFT, False),
        (FormStatus.ARCHIVED, FormStatus.FILLED, False),
    ],
)
def test_parametrized_transitions(
    from_state: FormStatus, to_state: FormStatus, should_succeed: bool
) -> None:
    """Параметризованные тесты переходов."""
    manager = FormStatusManager(require_mfa=False)
    doc = Mock()
    doc.status = from_state

    if should_succeed:
        manager.transition(doc, to_state)
        assert doc.status == to_state
    else:
        with pytest.raises(StatusTransitionError):
            manager.transition(doc, to_state)
