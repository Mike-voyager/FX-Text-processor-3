"""Тесты для RoleBadge.

Тестирует создание, смену роли и отображение MFA предупреждений.
"""

from __future__ import annotations

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock

import pytest

from src.gui.workflow.role_badge import RoleBadge, WorkflowRole


@pytest.fixture
def root() -> Generator[tk.Tk, None, None]:
    """Фикстура для Tk root."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def mock_role_change() -> MagicMock:
    """Фикстура для mock callback смены роли."""
    return MagicMock()


class TestRoleBadge:
    """Тесты для RoleBadge."""

    def test_init_operator(self, root: tk.Tk) -> None:
        """Тест инициализации с ролью OPERATOR."""
        badge = RoleBadge(
            parent=root,
            current_role=WorkflowRole.OPERATOR,
            on_role_change=None,
        )
        assert badge.get_role() == WorkflowRole.OPERATOR
        assert badge.get_role_color() == "#3498db"  # Синий

    def test_init_editor(self, root: tk.Tk) -> None:
        """Тест инициализации с ролью EDITOR."""
        badge = RoleBadge(
            parent=root,
            current_role=WorkflowRole.EDITOR,
            on_role_change=None,
        )
        assert badge.get_role() == WorkflowRole.EDITOR
        assert badge.get_role_color() == "#2ecc71"  # Зелёный

    def test_init_supervisor(self, root: tk.Tk) -> None:
        """Тест инициализации с ролью SUPERVISOR."""
        badge = RoleBadge(
            parent=root,
            current_role=WorkflowRole.SUPERVISOR,
            on_role_change=None,
        )
        assert badge.get_role() == WorkflowRole.SUPERVISOR
        assert badge.get_role_color() == "#f39c12"  # Оранжевый

    def test_init_signatory(self, root: tk.Tk) -> None:
        """Тест инициализации с ролью SIGNATORY."""
        badge = RoleBadge(
            parent=root,
            current_role=WorkflowRole.SIGNATORY,
            on_role_change=None,
        )
        assert badge.get_role() == WorkflowRole.SIGNATORY
        assert badge.get_role_color() == "#e74c3c"  # Красный

    def test_set_role_updates_display(self, root: tk.Tk) -> None:
        """Тест что set_role обновляет отображение."""
        badge = RoleBadge(
            parent=root,
            current_role=WorkflowRole.OPERATOR,
            on_role_change=None,
        )
        badge.mount(root)

        badge.set_role(WorkflowRole.SIGNATORY)

        assert badge.get_role() == WorkflowRole.SIGNATORY
        assert badge.get_role_color() == "#e74c3c"

        badge.widget.destroy()

    def test_role_change_triggers_callback(
        self, root: tk.Tk, mock_role_change: MagicMock
    ) -> None:
        """Тест что смена роли вызывает callback."""
        badge = RoleBadge(
            parent=root,
            current_role=WorkflowRole.OPERATOR,
            on_role_change=mock_role_change,
        )
        badge.mount(root)

        # Вызываем смену роли напрямую
        badge._on_role_selected(WorkflowRole.EDITOR)

        mock_role_change.assert_called_once_with(WorkflowRole.EDITOR)
        badge.widget.destroy()

    def test_mfa_required_for_privileged_roles(self, root: tk.Tk) -> None:
        """Тест что MFA требуется для привилегированных ролей."""
        badge = RoleBadge(
            parent=root,
            current_role=WorkflowRole.OPERATOR,
            on_role_change=None,
        )

        # OPERATOR и EDITOR не требуют MFA
        assert badge._requires_mfa(WorkflowRole.OPERATOR) is False
        assert badge._requires_mfa(WorkflowRole.EDITOR) is False

        # SUPERVISOR и SIGNATORY требуют MFA
        assert badge._requires_mfa(WorkflowRole.SUPERVISOR) is True
        assert badge._requires_mfa(WorkflowRole.SIGNATORY) is True

    def test_privileged_roles_set(self, root: tk.Tk) -> None:
        """Тест множества привилегированных ролей."""
        expected = {WorkflowRole.SUPERVISOR, WorkflowRole.SIGNATORY}
        assert RoleBadge.PRIVILEGED_ROLES == expected

    def test_role_icons_defined(self) -> None:
        """Тест что все роли имеют иконки."""
        for role in WorkflowRole:
            assert role in RoleBadge.ROLE_ICONS
            assert len(RoleBadge.ROLE_ICONS[role]) > 0

    def test_role_names_defined(self) -> None:
        """Тест что все роли имеют локализованные названия."""
        for role in WorkflowRole:
            assert role in RoleBadge.ROLE_NAMES
            assert len(RoleBadge.ROLE_NAMES[role]) > 0

    def test_role_colors_defined(self) -> None:
        """Тест что все роли имеют цвета."""
        for role in WorkflowRole:
            assert role in RoleBadge.ROLE_COLORS
            color = RoleBadge.ROLE_COLORS[role]
            assert color.startswith("#")
            assert len(color) == 7  # #RRGGBB

    def test_cleanup_clears_references(
        self, root: tk.Tk, mock_role_change: MagicMock
    ) -> None:
        """Тест что cleanup очищает ссылки."""
        badge = RoleBadge(
            parent=root,
            current_role=WorkflowRole.OPERATOR,
            on_role_change=mock_role_change,
        )
        badge.mount(root)

        badge._cleanup()

        assert badge._on_role_change is None

    def test_all_roles_in_enum(self) -> None:
        """Тест что все роли определены в enum."""
        expected_roles = [
            WorkflowRole.OPERATOR,
            WorkflowRole.EDITOR,
            WorkflowRole.SUPERVISOR,
            WorkflowRole.SIGNATORY,
        ]
        assert list(WorkflowRole) == expected_roles


class TestWorkflowRoleEnum:
    """Тесты для WorkflowRole enum."""

    def test_operator_value(self) -> None:
        """Тест значения OPERATOR."""
        assert WorkflowRole.OPERATOR.value == "operator"

    def test_editor_value(self) -> None:
        """Тест значения EDITOR."""
        assert WorkflowRole.EDITOR.value == "editor"

    def test_supervisor_value(self) -> None:
        """Тест значения SUPERVISOR."""
        assert WorkflowRole.SUPERVISOR.value == "supervisor"

    def test_signatory_value(self) -> None:
        """Тест значения SIGNATORY."""
        assert WorkflowRole.SIGNATORY.value == "signatory"


class TestBug23MfaGate:
    """Тесты для бага BUG-23: MFA gate при смене на привилегированную роль."""

    def test_privileged_role_without_mfa_callback_changes_immediately(
        self, root: tk.Tk, mock_role_change: MagicMock
    ) -> None:
        """Без mfa_required_callback смена на SUPERVISOR выполняется немедленно."""
        badge = RoleBadge(
            parent=root,
            current_role=WorkflowRole.OPERATOR,
            on_role_change=mock_role_change,
        )
        badge.mount(root)

        badge._on_role_selected(WorkflowRole.SUPERVISOR)

        # Роль должна смениться немедленно (обратная совместимость)
        assert badge.get_role() == WorkflowRole.SUPERVISOR
        mock_role_change.assert_called_once_with(WorkflowRole.SUPERVISOR)
        badge.widget.destroy()

    def test_privileged_role_with_mfa_callback_defers_change(
        self, root: tk.Tk, mock_role_change: MagicMock
    ) -> None:
        """С mfa_required_callback смена на SUPERVISOR откладывается до MFA."""
        mfa_callback = MagicMock()
        badge = RoleBadge(
            parent=root,
            current_role=WorkflowRole.OPERATOR,
            on_role_change=mock_role_change,
            mfa_required_callback=mfa_callback,
        )
        badge.mount(root)

        badge._on_role_selected(WorkflowRole.SUPERVISOR)

        # Роль НЕ должна смениться немедленно
        assert badge.get_role() == WorkflowRole.OPERATOR
        mock_role_change.assert_not_called()

        # mfa_required_callback должен быть вызван
        mfa_callback.assert_called_once()
        call_args = mfa_callback.call_args
        assert call_args[0][0] == WorkflowRole.SUPERVISOR
        # Второй аргумент — continuation callback
        assert callable(call_args[0][1])

        badge.widget.destroy()

    def test_mfa_callback_continuation_applies_role(
        self, root: tk.Tk, mock_role_change: MagicMock
    ) -> None:
        """Continuation callback из mfa_required_callback применяет смену роли."""
        continuation: list[Callable[[], None]] = []

        def capture_mfa(role: WorkflowRole, on_success: Callable[[], None]) -> None:
            continuation.append(on_success)

        badge = RoleBadge(
            parent=root,
            current_role=WorkflowRole.OPERATOR,
            on_role_change=mock_role_change,
            mfa_required_callback=capture_mfa,
        )
        badge.mount(root)

        badge._on_role_selected(WorkflowRole.SIGNATORY)

        # Роль ещё не сменена
        assert badge.get_role() == WorkflowRole.OPERATOR
        mock_role_change.assert_not_called()

        # Вызываем continuation (имитируем успешную MFA-проверку)
        assert len(continuation) == 1
        continuation[0]()

        # Теперь роль сменена
        assert badge.get_role() == WorkflowRole.SIGNATORY
        mock_role_change.assert_called_once_with(WorkflowRole.SIGNATORY)
        badge.widget.destroy()

    def test_non_privileged_role_bypasses_mfa_callback(
        self, root: tk.Tk, mock_role_change: MagicMock
    ) -> None:
        """Смена на EDITOR (не привилегированная) обходит mfa_required_callback."""
        mfa_callback = MagicMock()
        badge = RoleBadge(
            parent=root,
            current_role=WorkflowRole.OPERATOR,
            on_role_change=mock_role_change,
            mfa_required_callback=mfa_callback,
        )
        badge.mount(root)

        badge._on_role_selected(WorkflowRole.EDITOR)

        # Роль должна смениться немедленно
        assert badge.get_role() == WorkflowRole.EDITOR
        mock_role_change.assert_called_once_with(WorkflowRole.EDITOR)
        mfa_callback.assert_not_called()
        badge.widget.destroy()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
