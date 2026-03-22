"""Модуль управления статусом формы и переходами между состояниями.

Предоставляет:
- FormStatus: Enum для состояний формы
  (DRAFT, FILLED, VALIDATED, SIGNED, PRINTED, ARCHIVED, REJECTED)
- FormStatusManager: Менеджер для управления переходами между состояниями

Модуль реализует конечный автомат состояний формы с проверкой допустимых переходов
и поддержкой MFA (Multi-Factor Authentication) для критичных операций.

Example:
    >>> from src.documents.constructor.form_status import FormStatus, FormStatusManager
    >>> from src.model.document import Document
    >>> doc = Document()
    >>> manager = FormStatusManager()
    >>> manager.transition(doc, FormStatus.FILLED)
    >>> manager.can_transition(doc, FormStatus.VALIDATED)
    True
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Final, Protocol

if TYPE_CHECKING:

    class StatusableDocument(Protocol):
        """Protocol для документа со статусом."""

        @property
        def id(self) -> Any:
            """Идентификатор документа."""
            ...

        @property
        def status(self) -> str:
            """Статус документа."""
            ...

        @status.setter
        def status(self, value: "FormStatus") -> None: ...


logger: Final = logging.getLogger(__name__)


class FormStatus(str, Enum):
    """Состояния жизненного цикла формы.

    Форма проходит через фиксированные состояния от создания до архивации.
    Переходы между состояниями контролируются через FormStatusManager.

    Attributes:
        DRAFT: Черновик — редактирование разрешено.
        FILLED: Заполнена — ожидает валидации.
        VALIDATED: Проверена — ожидает подписи.
        SIGNED: Подписана — поля заблокированы.
        PRINTED: Напечатана — физическая копия создана.
        ARCHIVED: Архивирована — хранение в архиве.
        REJECTED: Отклонена — возврат для исправления.
    """

    DRAFT = "draft"
    FILLED = "filled"
    VALIDATED = "validated"
    SIGNED = "signed"
    PRINTED = "printed"
    ARCHIVED = "archived"
    REJECTED = "rejected"

    @property
    def localized_name(self) -> str:
        """Возвращает локализованное название состояния."""
        names = {
            FormStatus.DRAFT: "Черновик",
            FormStatus.FILLED: "Заполнена",
            FormStatus.VALIDATED: "Проверена",
            FormStatus.SIGNED: "Подписана",
            FormStatus.PRINTED: "Напечатана",
            FormStatus.ARCHIVED: "Архивирована",
            FormStatus.REJECTED: "Отклонена",
        }
        return names.get(self, self.value)

    @property
    def is_editable(self) -> bool:
        """Проверяет, разрешено ли редактирование в этом состоянии.

        Редактирование разрешено только в состоянии DRAFT.

        Returns:
            True если редактирование разрешено.
        """
        return self == FormStatus.DRAFT

    @property
    def is_terminal(self) -> bool:
        """Проверяет, является ли состояние терминальным.

        Терминальные состояния: ARCHIVED, REJECTED.

        Returns:
            True если состояние терминальное.
        """
        return self in (FormStatus.ARCHIVED, FormStatus.REJECTED)


# Определение допустимых переходов между состояниями
# Ключ: текущее состояние, Значение: список допустимых следующих состояний
_ALLOWED_TRANSITIONS: Final[dict[FormStatus, list[FormStatus]]] = {
    FormStatus.DRAFT: [FormStatus.FILLED, FormStatus.REJECTED],
    FormStatus.FILLED: [FormStatus.VALIDATED, FormStatus.DRAFT, FormStatus.REJECTED],
    FormStatus.VALIDATED: [FormStatus.SIGNED, FormStatus.FILLED, FormStatus.REJECTED],
    FormStatus.SIGNED: [FormStatus.PRINTED, FormStatus.VALIDATED],
    FormStatus.PRINTED: [FormStatus.ARCHIVED, FormStatus.SIGNED],
    FormStatus.ARCHIVED: [],  # Терминальное состояние
    FormStatus.REJECTED: [FormStatus.DRAFT],  # Возврат на доработку
}

# Состояния, требующие MFA для перехода
_MFA_REQUIRED_TRANSITIONS: Final[set[tuple[FormStatus, FormStatus]]] = {
    (FormStatus.FILLED, FormStatus.VALIDATED),
    (FormStatus.VALIDATED, FormStatus.SIGNED),
    (FormStatus.SIGNED, FormStatus.PRINTED),
    (FormStatus.PRINTED, FormStatus.ARCHIVED),
    (FormStatus.VALIDATED, FormStatus.FILLED),  # Откат валидации
    (FormStatus.SIGNED, FormStatus.VALIDATED),  # Откат подписи
}


@dataclass(frozen=True)
class StatusTransitionError(Exception):
    """Исключение при недопустимом переходе между состояниями.

    Attributes:
        from_state: Исходное состояние.
        to_state: Целевое состояние.
        message: Сообщение об ошибке.
    """

    from_state: FormStatus
    to_state: FormStatus
    message: str

    def __str__(self) -> str:
        """Возвращает строковое представление ошибки."""
        return (
            f"Недопустимый переход из '{self.from_state.value}' "
            f"в '{self.to_state.value}': {self.message}"
        )


@dataclass(frozen=True)
class FormStatusManager:
    """Менеджер для управления состояниями формы.

    Реализует конечный автомат состояний с проверкой допустимых переходов,
    поддержкой MFA и валидацией бизнес-правил.

    Attributes:
        require_mfa: Требовать ли MFA для критичных переходов.
        audit_callback: Опциональная функция для логирования переходов.

    Example:
        >>> manager = FormStatusManager(require_mfa=True)
        >>> class DocWithStatus:
        ...     def __init__(self):
        ...         self.id = "test-id"
        ...         self.status = FormStatus.DRAFT
        >>> doc = DocWithStatus()
        >>> manager.transition(doc, FormStatus.FILLED, mfa=False)
        >>> manager.can_transition(doc, FormStatus.VALIDATED)
        True
    """

    require_mfa: bool = True
    audit_callback: Any = field(default=None, compare=False)

    def __post_init__(self) -> None:
        """Валидация параметров после инициализации."""
        if not isinstance(self.require_mfa, bool):
            raise TypeError(
                f"require_mfa должен быть bool, получен {type(self.require_mfa).__name__}"
            )

    def get_allowed_transitions(self, from_state: FormStatus) -> list[FormStatus]:
        """Возвращает список допустимых переходов из указанного состояния.

        Args:
            from_state: Текущее состояние формы.

        Returns:
            Список допустимых целевых состояний.

        Example:
            >>> manager = FormStatusManager()
            >>> manager.get_allowed_transitions(FormStatus.DRAFT)
            [FormStatus.FILLED, FormStatus.REJECTED]
        """
        return _ALLOWED_TRANSITIONS.get(from_state, []).copy()

    def can_transition(
        self,
        document: StatusableDocument,
        to_state: FormStatus,
    ) -> bool:
        """Проверяет, возможен ли переход в указанное состояние.

        Args:
            document: Документ для проверки перехода.
            to_state: Целевое состояние.

        Returns:
            True если переход допустим, False в противном случае.

        Example:
            >>> class DocWithStatus:
            ...     def __init__(self):
            ...         self.id = "test-id"
            ...         self.status = FormStatus.DRAFT
            >>> doc = DocWithStatus()
            >>> manager = FormStatusManager()
            >>> manager.can_transition(doc, FormStatus.FILLED)
            True
            >>> manager.can_transition(doc, FormStatus.SIGNED)
            False  # Нельзя пропустить FILLED и VALIDATED
        """
        current_status = self._get_document_status(document)
        return to_state in self.get_allowed_transitions(current_status)

    def transition(
        self,
        document: StatusableDocument,
        to_state: FormStatus,
        mfa: bool = True,
    ) -> None:
        """Выполняет переход формы в указанное состояние.

        Args:
            document: Документ для изменения состояния.
            to_state: Целевое состояние.
            mfa: Флаг подтверждения MFA (для критичных переходов).

        Raises:
            StatusTransitionError: Если переход недопустим.
            ValueError: Если требуется MFA, но не подтверждён.

        Example:
            >>> class DocWithStatus:
            ...     def __init__(self):
            ...         self.id = "test-id"
            ...         self.status = FormStatus.DRAFT
            >>> doc = DocWithStatus()
            >>> manager = FormStatusManager()
            >>> manager.transition(doc, FormStatus.FILLED, mfa=False)
            >>> doc.status == FormStatus.FILLED
            True
        """
        from_state = self._get_document_status(document)

        # Проверяем, что переход допустим
        if to_state not in self.get_allowed_transitions(from_state):
            allowed = [s.value for s in self.get_allowed_transitions(from_state)]
            raise StatusTransitionError(
                from_state=from_state,
                to_state=to_state,
                message=f"Допустимые переходы: {allowed}",
            )

        # Проверяем MFA для критичных переходов
        if self.require_mfa and self._is_mfa_required(from_state, to_state) and not mfa:
            raise ValueError(
                f"Переход из '{from_state.value}' в '{to_state.value}' требует подтверждения MFA"
            )

        # Устанавливаем новое состояние
        self._set_document_status(document, to_state)

        # Логируем переход
        logger.info(f"Форма переведена из '{from_state.value}' в '{to_state.value}'")

        # Callback для аудита (если настроен)
        if self.audit_callback is not None:
            try:
                self.audit_callback(
                    event_type="workflow.transition",
                    from_state=from_state.value,
                    to_state=to_state.value,
                    document_id=str(document.id),
                )
            except Exception as e:
                logger.warning(f"Ошибка аудит-колбэка: {e}")

    def _is_mfa_required(self, from_state: FormStatus, to_state: FormStatus) -> bool:
        """Проверяет, требуется ли MFA для перехода.

        Args:
            from_state: Исходное состояние.
            to_state: Целевое состояние.

        Returns:
            True если требуется MFA.
        """
        return (from_state, to_state) in _MFA_REQUIRED_TRANSITIONS

    def _get_document_status(self, document: StatusableDocument) -> FormStatus:
        """Получает текущий статус документа.

        Args:
            document: Документ для получения статуса.

        Returns:
            Текущее состояние формы.

        Raises:
            AttributeError: Если у документа нет атрибута status.
        """
        # Проверяем наличие атрибута status (для объектов без Protocol)
        if not hasattr(document, "status"):
            # Если статус не установлен, считаем что это DRAFT
            return FormStatus.DRAFT

        status = document.status
        if isinstance(status, str):
            return FormStatus(status)
        if isinstance(status, FormStatus):
            return status
        raise ValueError(f"Invalid status type: {type(status).__name__}")

    def _set_document_status(self, document: StatusableDocument, status: FormStatus) -> None:
        """Устанавливает статус документа.

        Args:
            document: Документ для установки статуса.
            status: Новое состояние.
        """
        document.status = status

    def get_status_info(self, status: FormStatus) -> dict[str, Any]:
        """Возвращает информацию о состоянии.

        Args:
            status: Состояние для получения информации.

        Returns:
            Словарь с информацией о состоянии.
        """
        return {
            "value": status.value,
            "localized_name": status.localized_name,
            "is_editable": status.is_editable,
            "is_terminal": status.is_terminal,
            "allowed_transitions": [s.value for s in self.get_allowed_transitions(status)],
        }
