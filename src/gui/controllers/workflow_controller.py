"""Контроллер для управления workflow документов.

Связывает GUI компоненты с сервисным слоем WorkflowService.
Обрабатывает переходы между состояниями и смену ролей с MFA защитой.

Module: src/gui/controllers/workflow_controller.py
Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
import uuid
from typing import Any, Optional

from src.controller.workflow_controller import FormStatus, WorkflowRole
from src.gui.core.protocols import WorkflowControllerProtocol
from src.gui.security.mfa_gate import MFAGate
from src.services.workflow_service import WorkflowService

logger = logging.getLogger(__name__)


class WorkflowController(WorkflowControllerProtocol):
    """Контроллер для управления workflow документов.

    Выполняет переходы между состояниями документа (DRAFT -> FILLED -> VALIDATED -> ...)
    и смену ролей (OPERATOR -> EDITOR -> SUPERVISOR -> SIGNATORY).
    Интегрирует MFAGate для защищённых операций.

    Принимает WorkflowService и MFAGate через DI в конструктор.

    Attributes:
        controller_id: Уникальный идентификатор контроллера.
        _service: Сервис управления workflow.
        _mfa_gate: Менеджер MFA верификации.

    Example:
        >>> from src.gui.controllers.workflow_controller import WorkflowController
        >>> controller = WorkflowController(
        ...     service=workflow_service,
        ...     mfa_gate=mfa_gate
        ... )
        >>> controller.dispatch("workflow_transition", new_state=FormStatus.FILLED)
    """

    def __init__(
        self,
        service: WorkflowService,
        mfa_gate: Optional[MFAGate] = None,
    ) -> None:
        """Инициализирует контроллер workflow.

        Args:
            service: Сервис управления workflow.
            mfa_gate: Менеджер MFA верификации (опционально).
        """
        self.controller_id = "workflow_controller"
        self._service: WorkflowService = service
        self._mfa_gate: Optional[MFAGate] = mfa_gate
        self._views: dict[str, Any] = {}
        self._doc_id: Any = None  # UUID или идентификатор активного документа

    def set_doc_id(self, doc_id: Any) -> None:
        """Устанавливает ID активного документа.

        Args:
            doc_id: Идентификатор документа.
        """
        self._doc_id = doc_id

    # --- Диспетчеризация ---

    def dispatch(self, action: str, **kwargs: Any) -> Optional[Any]:
        """Диспетчирует действие в подметоды контроллера.

        Реализует только маршрутизацию — NO бизнес-логики.

        Args:
            action: Идентификатор действия ("workflow_transition", "role_switch").
            **kwargs: Параметры действия.

        Returns:
            Результат выполнения или None.

        Example:
            >>> controller.dispatch("on_workflow_transition", new_state=FormStatus.FILLED)
        """
        if action == "on_workflow_transition":
            return self.on_workflow_transition(**kwargs)
        elif action == "on_role_switch":
            return self.on_role_switch(**kwargs)
        return None

    # --- WorkflowControllerProtocol реализация ---

    def on_workflow_transition(self, new_state: FormStatus) -> bool:
        """Выполняет переход workflow в новое состояние.

        Args:
            new_state: Целевое состояние документа.

        Returns:
            True если переход выполнен успешно, False при отмене или ошибке.

        Security:
            Некоторые переходы (например, DRAFT -> SIGNED) требуют MFA.
            Проверяется через MFAGate.

        Example:
            >>> if controller.on_workflow_transition(FormStatus.SIGNED):
            ...     print("Состояние изменено")
        """
        if self._doc_id is None:
            logger.warning("No document ID set for workflow transition")
            return False

        doc_id = self._doc_id

        # Check if MFA is required
        requires_mfa = self._service.is_mfa_required(doc_id, new_state)

        if requires_mfa and self._mfa_gate is not None:
            # Wrap transition in MFA gate
            result = self._mfa_gate.execute(
                parent=self._get_parent_for_mfa(),
                operation=lambda: self._execute_transition(doc_id, new_state),
                operation_name=f"Переход в состояние '{new_state.localized_name}'",
                requires_mfa=True,
            )
            return result is not None

        # No MFA required
        if requires_mfa and self._mfa_gate is None:
            logger.error("MFA required but not configured")
            return False

        return self._execute_transition(doc_id, new_state)

    def on_role_switch(self, new_role: WorkflowRole) -> bool:
        """Выполняет смену роли пользователя.

        Args:
            new_role: Новая роль пользователя.

        Returns:
            True если смена роли успешна, False при отмене.

        Security:
            Смена роли требует MFA верификации.

        Example:
            >>> if controller.on_role_switch(WorkflowRole.CREATOR):
            ...     print("Роль изменена")
        """
        if self._doc_id is None:
            logger.warning("No document ID set for role switch")
            return False

        doc_id = self._doc_id

        # Role switch always requires MFA
        if self._mfa_gate is not None:
            result = self._mfa_gate.execute(
                parent=self._get_parent_for_mfa(),
                operation=lambda: self._execute_role_switch(doc_id, new_role),
                operation_name=f"Смена роли на '{new_role.display_name}'",
                requires_mfa=True,
            )
            return result is not None

        logger.error("MFA required for role switch but not configured")
        return False

    # --- Internal helpers ---

    def _execute_transition(self, doc_id: Any, new_state: FormStatus) -> bool:
        """Выполняет переход в новое состояние без MFA проверки.

        Вызывается из on_workflow_transition() после MFA verification.

        Args:
            doc_id: ID документа.
            new_state: Целевое состояние.

        Returns:
            True если переход успешен.
        """
        try:
            doc_id = self._normalize_doc_id(doc_id)
            role = self._service.get_current_role(doc_id) or WorkflowRole.OPERATOR
            reason = "Пользовательский переход"
            return self._service.transition(doc_id, new_state, reason, role)
        except Exception as e:
            logger.error("Failed to execute workflow transition: %s", e, exc_info=True)
            return False

    def _execute_role_switch(self, doc_id: Any, new_role: WorkflowRole) -> bool:
        """Выполняет смену роли без MFA проверки.

        Вызывается из on_role_switch() после MFA verification.

        Args:
            doc_id: ID документа.
            new_role: Новая роль.

        Returns:
            True если смена успешна.
        """
        try:
            doc_id = self._normalize_doc_id(doc_id)
            self._service.set_role(doc_id, new_role)
            return True
        except Exception as e:
            logger.error("Failed to execute role switch: %s", e, exc_info=True)
            return False

    def _normalize_doc_id(self, doc_id: Any) -> Any:
        """Нормализует ID документа для совместимости.

        Args:
            doc_id: ID документа (может быть UUID или строкой).

        Returns:
            Нормализованный ID.
        """
        if isinstance(doc_id, uuid.UUID):
            return str(doc_id)
        return doc_id

    def _get_parent_for_mfa(self) -> Any:
        """Возвращает родительский виджет для MFA диалога.

        Returns:
            Родительский виджет или None.
        """
        main_window = self._views.get("main_window")
        if isinstance(main_window, tk.Widget):
            return main_window
        for view in self._views.values():
            if isinstance(view, tk.Widget):
                return view
        return None

    # --- ControllerProtocol реализация ---

    def notify_view_update(self, widget_id: str, data: Any) -> None:
        """Уведомляет View об изменениях в Model.

        Реализует ControllerProtocol.notify_view_update().

        Args:
            widget_id: Идентификатор виджета для обновления.
            data: Данные для обновления.
        """
        callback = self._views.get(widget_id)
        if callback is not None:
            callback(widget_id, data)

    def register_view(self, widget_id: str, callback: Any) -> None:
        """Регистрирует callback для обновления View.

        Реализует ControllerProtocol.register_view().

        Args:
            widget_id: Идентификатор виджета.
            callback: Функция обратного вызова.
        """
        self._views[widget_id] = callback

    def unregister_view(self, widget_id: str) -> None:
        """Отменяет регистрацию View callback.

        Реализует ControllerProtocol.unregister_view().

        Args:
            widget_id: Идентификатор виджета.
        """
        if widget_id in self._views:
            del self._views[widget_id]
