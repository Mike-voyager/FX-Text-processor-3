"""Протоколы для режимов отображения документов FX Text Processor 3.

Модуль определяет Protocol-классы и dataclasses для реализации режимов
документов: FREE_FORM (свободный текст) и STRUCTURED_FORM (структурированная форма).

Протоколы наследуются от DocumentRendererProtocol, расширяя его методами
специфичными для режимов: получение контекста, создание тулбара, управление
состоянием режима.

Example:
    >>> from src.gui.modes.protocols import DocumentModeRendererProtocol
    >>> from src.documents.types.document_type import DocumentMode
    >>> renderer: DocumentModeRendererProtocol = FreeFormRenderer()
    >>> renderer.get_mode()
    <DocumentMode.FREE_FORM: 'free_form'>

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol, Tuple, runtime_checkable

from src.documents.types.document_type import DocumentMode
from src.gui.renderers.protocols import DocumentRendererProtocol

# =============================================================================
# MODE CONTEXT
# =============================================================================


@dataclass(frozen=True)
class ModeContext:
    """Контекст режима отображения документа.

    Неизменяемый dataclass с информацией о текущем состоянии режима.
    Используется для передачи контекста между компонентами GUI.

    Attributes:
        mode: Режим документа (FREE_FORM или STRUCTURED_FORM).
        document: Ссылка на документ (опционально).
        is_dirty: Флаг несохранённых изменений.
        viewport: Параметры области просмотра (x, y, width, height).
        metadata: Дополнительные метаданные режима.

    Example:
        >>> ctx = ModeContext(
        ...     mode=DocumentMode.FREE_FORM,
        ...     is_dirty=True,
        ...     viewport=(0, 0, 80, 66),
        ... )
        >>> ctx.mode
        <DocumentMode.FREE_FORM: 'free_form'>
    """

    mode: DocumentMode
    document: Optional[Any] = None
    is_dirty: bool = False
    viewport: Tuple[int, int, int, int] = (0, 0, 80, 66)
    metadata: Tuple[Tuple[str, Any], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        """Валидация параметров viewport после инициализации."""
        if len(self.viewport) != 4:
            raise ValueError("viewport должен содержать ровно 4 значения (x, y, width, height)")
        x, y, width, height = self.viewport
        if width < 0 or height < 0:
            raise ValueError("width и height viewport не могут быть отрицательными")

    def with_dirty(self, is_dirty: bool) -> ModeContext:
        """Создаёт новый контекст с изменённым флагом is_dirty.

        Args:
            is_dirty: Новое значение флага несохранённых изменений.

        Returns:
            Новый экземпляр ModeContext с обновлённым флагом.

        Example:
            >>> ctx = ModeContext(mode=DocumentMode.FREE_FORM, is_dirty=True)
            >>> new_ctx = ctx.with_dirty(False)
            >>> new_ctx.is_dirty
            False
        """
        return ModeContext(
            mode=self.mode,
            document=self.document,
            is_dirty=is_dirty,
            viewport=self.viewport,
            metadata=self.metadata,
        )

    def with_viewport(self, x: int, y: int, width: int, height: int) -> ModeContext:
        """Создаёт новый контекст с изменённой областью просмотра.

        Args:
            x: Координата X области просмотра.
            y: Координата Y области просмотра.
            width: Ширина области просмотра.
            height: Высота области просмотра.

        Returns:
            Новый экземпляр ModeContext с обновлённой областью.

        Example:
            >>> ctx = ModeContext(mode=DocumentMode.FREE_FORM)
            >>> new_ctx = ctx.with_viewport(0, 0, 80, 66)
            >>> new_ctx.viewport
            (0, 0, 80, 66)
        """
        return ModeContext(
            mode=self.mode,
            document=self.document,
            is_dirty=self.is_dirty,
            viewport=(x, y, width, height),
            metadata=self.metadata,
        )


# =============================================================================
# MODE SWITCH EVENT
# =============================================================================


@dataclass(frozen=True)
class ModeSwitchEvent:
    """Событие переключения режима отображения документа.

    Реализует EventProtocol для интеграции с системой событий GUI.
    Создаётся при смене режима редактирования документа.

    Attributes:
        timestamp: Временная метка создания события (Unix timestamp).
        source_widget_id: Идентификатор виджета-источника события.
        event_type: Тип события (всегда "mode_switched").
        old_mode: Предыдущий режим документа.
        new_mode: Новый режим документа.
        old_renderer_id: Идентификатор предыдущего рендерера.
        new_renderer_id: Идентификатор нового рендерера.
        document: Ссылка на документ (опционально).

    Example:
        >>> event = ModeSwitchEvent(
        ...     source_widget_id="doc_view_01",
        ...     old_mode=DocumentMode.FREE_FORM,
        ...     new_mode=DocumentMode.STRUCTURED_FORM,
        ...     old_renderer_id="free_form_01",
        ...     new_renderer_id="structured_01",
        ... )
        >>> event.event_type
        'mode_switched'
    """

    source_widget_id: str
    old_mode: DocumentMode
    new_mode: DocumentMode
    timestamp: float = field(default_factory=lambda: __import__("time").time())
    event_type: str = "mode_switched"
    old_renderer_id: Optional[str] = None
    new_renderer_id: Optional[str] = None
    document: Optional[Any] = None

    def get_data(self) -> dict[str, Any]:
        """Возвращает данные события в виде словаря.

        Returns:
            Словарь с данными события переключения режима.

        Example:
            >>> event = ModeSwitchEvent(
            ...     source_widget_id="view_01",
            ...     old_mode=DocumentMode.FREE_FORM,
            ...     new_mode=DocumentMode.STRUCTURED_FORM,
            ... )
            >>> data = event.get_data()
            >>> "old_mode" in data
            True
        """
        return {
            "old_mode": self.old_mode,
            "new_mode": self.new_mode,
            "old_renderer_id": self.old_renderer_id,
            "new_renderer_id": self.new_renderer_id,
            "document": self.document,
        }

    def is_propagation_stopped(self) -> bool:
        """Проверяет, остановлено ли распространение события.

        Всегда возвращает False, так как ModeSwitchEvent не поддерживает
        остановку распространения (event propagation).

        Returns:
            False (событие всегда распространяется).
        """
        return False

    def stop_propagation(self) -> None:
        """Заглушка для остановки распространения события.

        Note:
            ModeSwitchEvent не поддерживает остановку распространения,
            поэтому метод ничего не делает.
        """
        pass


# =============================================================================
# MODE TOOLBAR PROTOCOL
# =============================================================================


@runtime_checkable
class ModeToolbarProtocol(Protocol):
    """Protocol для тулбаров режимов отображения.

    Определяет единый интерфейс для тулбаров, специфичных для каждого режима.
    Тулбар создаётся рендерером режима и содержит инструменты,
    актуальные для данного режима редактирования.

    Attributes:
        toolbar_id: Уникальный идентификатор тулбара.

    Example:
        >>> toolbar: ModeToolbarProtocol = FreeFormToolbar()
        >>> widget = toolbar.mount(parent_frame)
        >>> toolbar.set_enabled(True)
    """

    toolbar_id: str

    def mount(self, parent: tk.Widget) -> tk.Widget:
        """Монтирует тулбар в родительский контейнер.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Корневой виджет тулбара.

        Raises:
            ValueError: Если parent is None.
            LifecycleError: Если тулбар уже смонтирован.
        """
        ...

    def unmount(self) -> None:
        """Размонтирует тулбар и освобождает ресурсы.

        Удаляет все виджеты тулбара и очищает ссылки на данные.
        """
        ...

    def is_mounted(self) -> bool:
        """Проверяет, смонтирован ли тулбар.

        Returns:
            True если тулбар смонтирован и готов к работе.
        """
        ...

    def set_enabled(self, enabled: bool) -> None:
        """Устанавливает доступность всех элементов тулбара.

        Args:
            enabled: True для активации, False для деактивации.

        Example:
            >>> toolbar.set_enabled(False)
            >>> # Все кнопки тулбара неактивны
        """
        ...

    def on_command(self, callback: Callable[[str], None]) -> None:
        """Устанавливает callback для обработки команд тулбара.

        Args:
            callback: Функция обратного вызова, принимающая
                     идентификатор команды (str).

        Example:
            >>> def handle_command(cmd: str) -> None:
            ...     print(f"Command: {cmd}")
            >>> toolbar.on_command(handle_command)
        """
        ...

    def update_button_state(self, command_id: str, enabled: bool) -> None:
        """Обновляет состояние отдельной кнопки тулбара.

        Args:
            command_id: Идентификатор команды (кнопки).
            enabled: True для активации, False для деактивации.

        Example:
            >>> toolbar.update_button_state("bold", can_apply_bold)
        """
        ...


# =============================================================================
# DOCUMENT MODE RENDERER PROTOCOL
# =============================================================================


class DocumentModeRendererProtocol(DocumentRendererProtocol[Any, Any], Protocol):
    """Protocol для рендереров режимов документов.

    Расширяет DocumentRendererProtocol, добавляя методы специфичные
    для режимов отображения: получение режима, создание тулбара,
    управление контекстом режима.

    Каждый рендерер режима работает с определённым DocumentMode:
    - FreeFormRenderer: DocumentMode.FREE_FORM
    - StructuredFormRenderer: DocumentMode.STRUCTURED_FORM

    Example:
        >>> renderer: DocumentModeRendererProtocol = FreeFormRenderer()
        >>> renderer.get_mode()
        <DocumentMode.FREE_FORM: 'free_form'>
        >>> toolbar = renderer.create_toolbar()
    """

    def get_mode(self) -> DocumentMode:
        """Возвращает режим документа, поддерживаемый рендерером.

        Returns:
            Режим документа (FREE_FORM или STRUCTURED_FORM).

        Example:
            >>> renderer.get_mode()
            <DocumentMode.FREE_FORM: 'free_form'>
        """
        ...

    def create_toolbar(self) -> ModeToolbarProtocol:  # type: ignore[override]
        """Создаёт тулбар специфичный для данного режима.

        Returns:
            Экземпляр ModeToolbarProtocol для данного режима.

        Note:
            Тулбар должен быть смонтирован отдельно через toolbar.mount().

        Example:
            >>> toolbar = renderer.create_toolbar()
            >>> toolbar.mount(toolbar_frame)
        """
        ...

    def get_context(self) -> ModeContext:
        """Возвращает текущий контекст режима.

        Returns:
            ModeContext с текущим состоянием режима.

        Raises:
            LifecycleError: Если рендерер не смонтирован.

        Example:
            >>> ctx = renderer.get_context()
            >>> ctx.mode
            <DocumentMode.FREE_FORM: 'free_form'>
            >>> ctx.is_dirty
            False
        """
        ...

    def update_context(self, context: ModeContext) -> None:
        """Обновляет контекст режима.

        Args:
            context: Новый контекст режима.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
            ValueError: Если context.mode не соответствует get_mode().

        Example:
            >>> new_ctx = ctx.with_dirty(True)
            >>> renderer.update_context(new_ctx)
        """
        ...

    def on_mode_enter(self) -> None:
        """Вызывается при входе в режим.

        Выполняет инициализацию специфичную для данного режима.
        Вызывается после mount(), перед началом работы с документом.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        ...

    def on_mode_exit(self) -> None:
        """Вызывается при выходе из режима.

        Выполняет очистку специфичную для данного режима.
        Вызывается перед unmount(), при смене режима.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        ...

    def supports_workflow(self) -> bool:
        """Проверяет, поддерживает ли рендерер workflow-переходы.

        Returns:
            True если рендерер поддерживает MFA workflow transitions.
        """
        ...

    def get_undo_manager(self) -> Any:
        """Возвращает менеджер undo/redo операций.

        Returns:
            Экземпляр CommandStack или аналогичного менеджера.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        ...

    def display_document(self, document: Any) -> None:
        """Отображает документ с учётом SmartEdit режима.

        Если редактор находится в режиме редактирования,
        вызов может игнорироваться для защиты пользовательского ввода.

        Args:
            document: Документ для отображения.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        ...

    def get_editor_state(self) -> dict[str, Any]:
        """Возвращает текущее состояние редактора.

        Returns:
            Словарь с состоянием редактора (специфичен для режима).

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        ...


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__: list[str] = [
    "DocumentModeRendererProtocol",
    "ModeContext",
    "ModeSwitchEvent",
    "ModeToolbarProtocol",
]
