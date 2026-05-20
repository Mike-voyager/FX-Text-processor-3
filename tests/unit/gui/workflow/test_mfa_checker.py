"""Тесты для MFA requirement checker.

Проверяет корректность определения необходимости MFA
для переходов состояний и смены ролей.
"""

from __future__ import annotations

from enum import Enum

import pytest

from src.gui.workflow.mfa_checker import MFAOperationDescriber, MFARequirementChecker


class _FakeFormStatus(Enum):
    """Поддельный FormStatus для тестов."""
    DRAFT = "draft"
    FILLED = "filled"
    VALIDATED = "validated"
    APPROVED = "approved"
    SIGNED = "signed"
    ARCHIVED = "archived"


class _FakeWorkflowRole(Enum):
    """Поддельный WorkflowRole для тестов."""
    OPERATOR = "operator"
    EDITOR = "editor"
    SUPERVISOR = "supervisor"
    SIGNATORY = "signatory"


class TestMFARequirementChecker:
    """Тесты MFARequirementChecker."""

    def test_transition_filled_to_validated_requires_mfa(self) -> None:
        """Переход FILLED→VALIDATED требует MFA."""
        checker = MFARequirementChecker()
        assert checker.is_transition_mfa_required(
            _FakeFormStatus.FILLED, _FakeFormStatus.VALIDATED,
        ) is True

    def test_transition_validated_to_approved_requires_mfa(self) -> None:
        """Переход VALIDATED→APPROVED требует MFA."""
        checker = MFARequirementChecker()
        assert checker.is_transition_mfa_required(
            _FakeFormStatus.VALIDATED, _FakeFormStatus.APPROVED,
        ) is True

    def test_transition_approved_to_signed_requires_mfa(self) -> None:
        """Переход APPROVED→SIGNED требует MFA."""
        checker = MFARequirementChecker()
        assert checker.is_transition_mfa_required(
            _FakeFormStatus.APPROVED, _FakeFormStatus.SIGNED,
        ) is True

    def test_transition_draft_to_filled_no_mfa(self) -> None:
        """Переход DRAFT→FILLED не требует MFA."""
        checker = MFARequirementChecker()
        assert checker.is_transition_mfa_required(
            _FakeFormStatus.DRAFT, _FakeFormStatus.FILLED,
        ) is False

    def test_exempt_transition_no_mfa(self) -> None:
        """Освобождённые переходы не требуют MFA даже в free mode."""
        checker = MFARequirementChecker(free_mode_enabled=True)
        # draft→filled освобождён
        assert checker.is_transition_mfa_required(
            _FakeFormStatus.DRAFT, _FakeFormStatus.FILLED,
        ) is False

    def test_free_mode_all_require_mfa(self) -> None:
        """В free mode все переходы (кроме освобождённых) требуют MFA."""
        checker = MFARequirementChecker(free_mode_enabled=True)
        assert checker.is_transition_mfa_required(
            _FakeFormStatus.DRAFT, _FakeFormStatus.VALIDATED,
        ) is True

    def test_free_mode_property(self) -> None:
        """Свойство free_mode_enabled корректно читается и устанавливается."""
        checker = MFARequirementChecker()
        assert checker.free_mode_enabled is False
        checker.free_mode_enabled = True
        assert checker.free_mode_enabled is True

    def test_role_switch_to_supervisor_requires_mfa(self) -> None:
        """Переключение на SUPERVISOR требует MFA."""
        checker = MFARequirementChecker()
        assert checker.is_role_switch_mfa_required(
            _FakeWorkflowRole.OPERATOR, _FakeWorkflowRole.SUPERVISOR,
        ) is True

    def test_role_switch_to_signatory_requires_mfa(self) -> None:
        """Переключение на SIGNATORY требует MFA."""
        checker = MFARequirementChecker()
        assert checker.is_role_switch_mfa_required(
            _FakeWorkflowRole.OPERATOR, _FakeWorkflowRole.SIGNATORY,
        ) is True

    def test_role_switch_operator_to_editor_no_mfa(self) -> None:
        """Переключение OPERATOR→EDITOR не требует MFA."""
        checker = MFARequirementChecker()
        assert checker.is_role_switch_mfa_required(
            _FakeWorkflowRole.OPERATOR, _FakeWorkflowRole.EDITOR,
        ) is False

    def test_role_switch_same_role_no_mfa(self) -> None:
        """Переключение на ту же роль не требует MFA."""
        checker = MFARequirementChecker()
        assert checker.is_role_switch_mfa_required(
            _FakeWorkflowRole.OPERATOR, _FakeWorkflowRole.OPERATOR,
        ) is False

    def test_role_switch_free_mode_all_require_mfa(self) -> None:
        """В free mode все переключения ролей требуют MFA."""
        checker = MFARequirementChecker(free_mode_enabled=True)
        assert checker.is_role_switch_mfa_required(
            _FakeWorkflowRole.OPERATOR, _FakeWorkflowRole.EDITOR,
        ) is True

    def test_role_switch_free_mode_override(self) -> None:
        """Переопределение free_mode в is_role_switch_mfa_required."""
        checker = MFARequirementChecker()
        # default off, but override on
        assert checker.is_role_switch_mfa_required(
            _FakeWorkflowRole.OPERATOR, _FakeWorkflowRole.EDITOR,
            free_mode=True,
        ) is True

    def test_is_archived_transition(self) -> None:
        """Определение перехода в ARCHIVED."""
        checker = MFARequirementChecker()
        assert checker.is_archived_transition(_FakeFormStatus.ARCHIVED) is True
        assert checker.is_archived_transition(_FakeFormStatus.SIGNED) is False

    def test_requires_extra_confirmation_archived(self) -> None:
        """ARCHIVED требует дополнительного подтверждения."""
        checker = MFARequirementChecker()
        assert checker.requires_extra_confirmation(_FakeFormStatus.ARCHIVED) is True
        assert checker.requires_extra_confirmation(_FakeFormStatus.FILLED) is False

    def test_add_remove_required_transition(self) -> None:
        """Добавление и удаление MFA-переходов."""
        checker = MFARequirementChecker()
        checker.add_required_transition("draft", "signed")
        assert ("draft", "signed") in checker._required_transitions

        checker.remove_required_transition("draft", "signed")
        assert ("draft", "signed") not in checker._required_transitions


class TestMFAOperationDescriber:
    """Тесты MFAOperationDescriber."""

    def test_describe_transition(self) -> None:
        """Описание перехода состояния."""
        describer = MFAOperationDescriber()
        description = describer.describe_transition(
            _FakeFormStatus.FILLED, _FakeFormStatus.VALIDATED,
        )
        assert isinstance(description, str)
        assert len(description) > 0

    def test_describe_archived_transition(self) -> None:
        """Описание архивации содержит предупреждение."""
        describer = MFAOperationDescriber()
        description = describer.describe_transition(
            _FakeFormStatus.SIGNED, _FakeFormStatus.ARCHIVED,
        )
        assert "Архивация" in description or "необратимое" in description.lower()

    def test_describe_role_switch(self) -> None:
        """Описание смены роли."""
        describer = MFAOperationDescriber()
        description = describer.describe_role_switch(
            _FakeWorkflowRole.OPERATOR, _FakeWorkflowRole.SUPERVISOR,
        )
        assert isinstance(description, str)
        assert len(description) > 0

    def test_describe_role_switch_free_mode(self) -> None:
        """Описание смены роли в free mode."""
        checker = MFARequirementChecker(free_mode_enabled=True)
        describer = MFAOperationDescriber(checker=checker)
        description = describer.describe_role_switch(
            _FakeWorkflowRole.OPERATOR, _FakeWorkflowRole.EDITOR,
        )
        assert "свободный режим" in description or "свобод" in description

    def test_describer_with_custom_checker(self) -> None:
        """Describer использует переданный checker."""
        checker = MFARequirementChecker()
        describer = MFAOperationDescriber(checker=checker)
        # Должен использовать тот же checker
        assert describer._checker is checker