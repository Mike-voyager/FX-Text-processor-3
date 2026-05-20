"""MFA requirement checker для workflow.

Тонкая обёртка над константами из constants.py для проверки
необходимости MFA при переходах состояний и смене ролей.

Бизнес-правила (MFA_REQUIRED_TRANSITIONS, MFA_REQUIRED_ROLES,
MFA_EXEMPT_TRANSITIONS) определены в constants.py — единый источник.

Version: 1.1
Date: May 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, Set, Tuple

from src.gui.workflow.constants import (
    MFA_EXEMPT_TRANSITIONS,
    MFA_REQUIRED_ROLES,
    MFA_REQUIRED_TRANSITIONS,
)

if TYPE_CHECKING:
    from src.controller.workflow_controller import FormStatus, WorkflowRole


class MFARequirementChecker:
    """Проверщик необходимости MFA для workflow операций.

    Тонкая обёртка над константами из constants.py.
    Бизнес-правила (переходы и роли, требующие MFA) определены
    в constants.py — единый источник истины.

    Attributes:
        _required_transitions: Набор переходов, требующих MFA (копия, можно мутировать).
        _privileged_roles: Роли, всегда требующие MFA (копия).
        _free_mode_enabled: Режим свободного переключения (все операции требуют MFA).

    Example:
        >>> checker = MFARequirementChecker()
        >>> checker.is_transition_mfa_required(FormStatus.FILLED, FormStatus.VALIDATED)
        True
        >>> checker.is_role_switch_mfa_required(WorkflowRole.OPERATOR, WorkflowRole.SUPERVISOR)
        True
    """

    # Дефолтные значения из constants.py (для восстановления при reset)
    DEFAULT_REQUIRED_TRANSITIONS: Set[Tuple[str, str]] = set(MFA_REQUIRED_TRANSITIONS)
    DEFAULT_PRIVILEGED_ROLES: Set[str] = set(MFA_REQUIRED_ROLES)

    # Переходы, освобождённые от MFA даже в free mode — из constants.py
    MFA_EXEMPT_TRANSITIONS: Set[Tuple[str, str]] = set(MFA_EXEMPT_TRANSITIONS)

    def __init__(self, free_mode_enabled: bool = False) -> None:
        """Инициализация проверщика.

        Args:
            free_mode_enabled: Если True, все операции требуют MFA
                (кроме явно освобождённых).
        """
        self._required_transitions = set(MFA_REQUIRED_TRANSITIONS)
        self._privileged_roles = set(MFA_REQUIRED_ROLES)
        self._free_mode_enabled = free_mode_enabled

    @property
    def free_mode_enabled(self) -> bool:
        """True если включён режим свободного переключения."""
        return self._free_mode_enabled

    @free_mode_enabled.setter
    def free_mode_enabled(self, value: bool) -> None:
        """Устанавливает режим свободного переключения."""
        self._free_mode_enabled = value

    def is_transition_mfa_required(
        self,
        from_state: "FormStatus",
        to_state: "FormStatus",
    ) -> bool:
        """Проверяет, требуется ли MFA для перехода состояния.

        Args:
            from_state: Исходное состояние.
            to_state: Целевое состояние.

        Returns:
            True если MFA требуется.
        """
        from_str = from_state.value
        to_str = to_state.value

        transition = (from_str, to_str)

        # Проверяем освобождённые переходы
        if transition in self.MFA_EXEMPT_TRANSITIONS:
            return False

        # В режиме свободного переключения все переходы требуют MFA
        if self._free_mode_enabled:
            return True

        # Проверяем список обязательных переходов
        return transition in self._required_transitions

    def is_role_switch_mfa_required(
        self,
        from_role: "WorkflowRole",
        to_role: "WorkflowRole",
        free_mode: Optional[bool] = None,
    ) -> bool:
        """Проверяет, требуется ли MFA для смены роли.

        Args:
            from_role: Текущая роль.
            to_role: Целевая роль.
            free_mode: Переопределение режима (None = использовать настройку).

        Returns:
            True если MFA требуется.
        """
        from_str = from_role.value
        to_str = to_role.value

        # Если роли одинаковые - MFA не требуется
        if from_str == to_str:
            return False

        # Режим свободного переключения
        use_free_mode = free_mode if free_mode is not None else self._free_mode_enabled
        if use_free_mode:
            return True

        # Проверяем привилегированные роли
        if to_str in self._privileged_roles:
            return True

        # Проверяем переходы между привилегированными ролями
        if from_str in self._privileged_roles and to_str in self._privileged_roles:
            # SUPERVISOR <-> SIGNATORY не требует MFA
            if {from_str, to_str} == {"supervisor", "signatory"}:
                return False
            return True

        return False

    def is_archived_transition(self, to_state: "FormStatus") -> bool:
        """Проверяет, является ли переход в ARCHIVED.

        Args:
            to_state: Целевое состояние.

        Returns:
            True если переход в ARCHIVED.
        """
        to_str = to_state.value
        return to_str == "archived"

    def requires_extra_confirmation(self, to_state: "FormStatus") -> bool:
        """Проверяет, требуется ли дополнительное подтверждение.

        Args:
            to_state: Целевое состояние.

        Returns:
            True если требуется доп. подтверждение (например, для ARCHIVED).
        """
        return self.is_archived_transition(to_state)

    def get_transition_description(
        self,
        from_state: "FormStatus",
        to_state: "FormStatus",
    ) -> str:
        """Возвращает описание перехода для MFA диалога.

        Args:
            from_state: Исходное состояние.
            to_state: Целевое состояние.

        Returns:
            Строка описания операции.
        """
        from_str = from_state.value
        to_str = to_state.value

        # Определяем тип операции
        if self.is_archived_transition(to_state):
            return "Архивация документа"

        # Определяем направление

        from_order = self._get_state_order(from_str)
        to_order = self._get_state_order(to_str)

        if to_order < from_order:
            return f"Откат состояния: {from_str} → {to_str}"
        else:
            return f"Переход состояния: {from_str} → {to_str}"

    def get_role_switch_description(
        self,
        from_role: "WorkflowRole",
        to_role: "WorkflowRole",
    ) -> str:
        """Возвращает описание смены роли для MFA диалога.

        Args:
            from_role: Текущая роль.
            to_role: Новая роль.

        Returns:
            Строка описания операции.
        """
        from_str = from_role.value
        to_str = to_role.value

        if self._free_mode_enabled:
            return f"Смена роли (свободный режим): {from_str} → {to_str}"

        to_name = to_str.capitalize()
        return f"Переход на роль: {to_name}"

    def _get_state_order(self, state: str) -> int:
        """Возвращает порядковый номер состояния.

        Args:
            state: Название состояния.

        Returns:
            Порядковый номер (меньше = раньше в workflow).
        """
        from src.gui.workflow.constants import STATUS_ORDER

        try:
            return STATUS_ORDER.index(state)
        except ValueError:
            return -1

    def add_required_transition(
        self,
        from_state: str,
        to_state: str,
    ) -> None:
        """Добавляет переход в список требующих MFA.

        Args:
            from_state: Исходное состояние.
            to_state: Целевое состояние.
        """
        self._required_transitions.add((from_state, to_state))

    def remove_required_transition(
        self,
        from_state: str,
        to_state: str,
    ) -> None:
        """Удаляет переход из списка требующих MFA.

        Args:
            from_state: Исходное состояние.
            to_state: Целевое состояние.
        """
        self._required_transitions.discard((from_state, to_state))


class MFAOperationDescriber:
    """Генератор описаний операций для MFA диалогов.

    Создаёт пользовательские описания операций,
    требующих MFA подтверждения.
    """

    def __init__(self, checker: Optional[MFARequirementChecker] = None) -> None:
        """Инициализация.

        Args:
            checker: Экземпляр проверщика или None для создания нового.
        """
        self._checker = checker or MFARequirementChecker()

    def describe_transition(
        self,
        from_state: "FormStatus",
        to_state: "FormStatus",
    ) -> str:
        """Описывает переход для отображения в MFA диалоге.

        Args:
            from_state: Исходное состояние.
            to_state: Целевое состояние.

        Returns:
            Описание операции.
        """
        if self._checker.is_archived_transition(to_state):
            return (
                "Архивация документа\n\n"
                "⚠️ Внимание: После архивации документ будет доступен "
                "только для чтения. Это необратимое действие."
            )

        description = self._checker.get_transition_description(from_state, to_state)
        return f"Подтверждение операции:\n{description}"

    def describe_role_switch(
        self,
        from_role: "WorkflowRole",
        to_role: "WorkflowRole",
    ) -> str:
        """Описывает смену роли для отображения в MFA диалоге.

        Args:
            from_role: Текущая роль.
            to_role: Новая роль.

        Returns:
            Описание операции.
        """
        description = self._checker.get_role_switch_description(from_role, to_role)
        return f"Подтверждение смены роли:\n{description}"


__all__ = [
    "MFARequirementChecker",
    "MFAOperationDescriber",
]
