"""Базовый класс для рендереров режимов документов.

Предоставляет абстрактный базовый класс BaseModeRenderer, реализующий
DocumentModeRendererProtocol. Содержит общую логику lifecycle management,
интеграции с CommandStack и работы с контекстом режима.

Наследники должны реализовать абстрактные методы для конкретного режима:
- _do_render(): отрисовка содержимого
- _do_get_content(): получение содержимого
- get_mode(): возврат поддерживаемого режима

Example:
    >>> from src.gui.modes.base import BaseModeRenderer
    >>> from src.documents.types.document_type import DocumentMode
    >>> class FreeFormRenderer(BaseModeRenderer):
    ...     def get_mode(self) -> DocumentMode:
    ...         return DocumentMode.FREE_FORM
    ...     def _do_render(self, document: Any) -> None:
    ...         pass
    ...     def _do_get_content(self) -> str:
    ...         return ""

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from abc import ABC, abstractmethod
from typing import Generic, Optional, TypeVar

from src.documents.types.document_type import DocumentMode
from src.gui.core.commands.command import Command
from src.gui.core.commands.command_stack import CommandStack
from src.gui.layout.layout_constants import ESCP_COLS, ESCP_ROWS
from src.gui.modes.protocols import (
    ModeContext,
    ModeToolbarProtocol,
)

DocumentT = TypeVar("DocumentT")
ContentT = TypeVar("ContentT")


class LifecycleError(Exception):
    """Ошибка жизненного цикла рендерера.

    Вызывается при вызове методов, требующих смонтированного рендерера.

    Example:
        >>> raise LifecycleError("Рендерер не смонтирован")
    """

    pass


class BaseModeRenderer(ABC, Generic[DocumentT, ContentT]):
    """Абстрактный базовый класс для рендереров режимов.

    Реализует DocumentModeRendererProtocol, предоставляя общую логику
    lifecycle management (mount/unmount), работы с CommandStack и
    управления контекстом режима.

    Наследники должны реализовать абстрактные методы для работы
    с конкретным типом содержимого.

    Type Parameters:
        DocumentT: Тип документа (FreeFormDocument, StructuredFormDocument)
        ContentT: Тип возвращаемого содержимого (str, FormData и т.д.)

    Attributes:
        renderer_id: Уникальный идентификатор рендерера.
        _mounted: Флаг смонтированного состояния.
        _parent: Родительский виджет (None если не смонтирован).
        _command_stack: Стек команд для undo/redo.
        _context: Текущий контекст режима.
        _root_widget: Корневой виджет рендерера.

    Example:
        >>> class MyRenderer(BaseModeRenderer[str, str]):
        ...     def get_mode(self) -> DocumentMode:
        ...         return DocumentMode.FREE_FORM
        ...     def _do_render(self, document: str) -> None:
        ...         pass
        ...     def _do_get_content(self) -> str:
        ...         return ""
        >>> renderer = MyRenderer("my_renderer_01")
        >>> widget = renderer.mount(parent_frame)
    """

    def __init__(self, renderer_id: str) -> None:
        """Инициализирует базовый рендерер.

        Args:
            renderer_id: Уникальный идентификатор рендерера.

        Example:
            >>> renderer = BaseModeRenderer("free_form_01")
            >>> renderer.renderer_id
            'free_form_01'
        """
        self.renderer_id: str = renderer_id
        self._mounted: bool = False
        self._parent: Optional[tk.Widget] = None
        self._command_stack: Optional[CommandStack] = None
        self._context: ModeContext = ModeContext(
            mode=self.get_mode(),
            is_dirty=False,
            viewport=(0, 0, ESCP_COLS, ESCP_ROWS),
        )
        self._root_widget: Optional[tk.Widget] = None

    # ======================================================================
    # ABSTRACT METHODS - Должны быть реализованы наследниками
    # ======================================================================

    @abstractmethod
    def get_mode(self) -> DocumentMode:
        """Возвращает режим документа, поддерживаемый рендерером.

        Returns:
            Режим документа (FREE_FORM или STRUCTURED_FORM).

        Example:
            >>> renderer.get_mode()
            <DocumentMode.FREE_FORM: 'free_form'>
        """
        ...

    @abstractmethod
    def _do_render(self, document: DocumentT) -> None:
        """Выполняет отрисовку содержимого документа.

        Args:
            document: Документ для отрисовки.

        Note:
            Вызывается только если рендерер смонтирован.
            Реализация зависит от конкретного режима.
        """
        ...

    @abstractmethod
    def _do_get_content(self) -> ContentT:
        """Возвращает текущее содержимое редактора.

        Returns:
            Текущее содержимое документа.

        Note:
            Вызывается только если рендерер смонтирован.
            Реализация зависит от конкретного режима.
        """
        ...

    @abstractmethod
    def _do_wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные из редактора.

        Note:
            Вызывается только если рендерер смонтирован.
            Реализация зависит от конкретного режима.
        """
        ...

    @abstractmethod
    def _do_hide_content(self) -> None:
        """Скрывает содержимое редактора.

        Note:
            Вызывается только если рендерер смонтирован.
            Реализация зависит от конкретного режима.
        """
        ...

    @abstractmethod
    def _do_restore_content(self) -> None:
        """Восстанавливает содержимое редактора.

        Note:
            Вызывается только если рендерер смонтирован.
            Реализация зависит от конкретного режима.
        """
        ...

    @abstractmethod
    def _do_apply_command(self, command: Command) -> None:
        """Применяет команду к документу.

        Args:
            command: Команда для выполнения.

        Note:
            Вызывается только если рендерер смонтирован.
            Реализация зависит от конкретного режима.
        """
        ...

    @abstractmethod
    def _do_create_root_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт корневой виджет рендерера.

        Args:
            parent: Родительский виджет.

        Returns:
            Корневой виджет рендерера.

        Note:
            Реализация зависит от конкретного режима.
        """
        ...

    @abstractmethod
    def _do_unmount(self) -> None:
        """Выполняет размонтирование виджетов.

        Note:
            Вызывается только если рендерер смонтирован.
            Реализация зависит от конкретного режима.
        """
        ...

    @abstractmethod
    def create_toolbar(self) -> ModeToolbarProtocol:
        """Создаёт тулбар специфичный для данного режима.

        Returns:
            Экземпляр ModeToolbarProtocol для данного режима.
        """
        ...

    # ======================================================================
    # LIFECYCLE MANAGEMENT
    # ======================================================================

    def mount(self, parent: tk.Widget) -> tk.Widget:
        """Монтирует рендерер в родительский виджет.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Корневой виджет рендерера.

        Raises:
            ValueError: Если parent is None.
            LifecycleError: Если рендерер уже смонтирован.

        Example:
            >>> widget = renderer.mount(parent_frame)
            >>> renderer.is_mounted()
            True
        """
        if parent is None:
            raise ValueError("parent не может быть None")
        if self._mounted:
            raise LifecycleError("Рендерер уже смонтирован")

        self._parent = parent
        self._root_widget = self._do_create_root_widget(parent)
        self._mounted = True

        return self._root_widget

    def unmount(self) -> None:
        """Размонтирует рендерер и освобождает ресурсы.

        Очищает все виджеты и освобождает ссылки на данные.

        Example:
            >>> renderer.unmount()
            >>> renderer.is_mounted()
            False
        """
        if not self._mounted:
            return

        self._do_unmount()

        self._parent = None
        self._root_widget = None
        self._mounted = False
        self._command_stack = None

    def is_mounted(self) -> bool:
        """Проверяет, смонтирован ли рендерер.

        Returns:
            True если рендерер смонтирован и готов к работе.

        Example:
            >>> renderer.is_mounted()
            False
            >>> renderer.mount(parent)
            >>> renderer.is_mounted()
            True
        """
        return self._mounted

    def _ensure_mounted(self) -> None:
        """Проверяет, что рендерер смонтирован.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        if not self._mounted:
            raise LifecycleError("Рендерер не смонтирован")

    # ======================================================================
    # RENDERING
    # ======================================================================

    def render(self, document: DocumentT) -> None:
        """Загружает и отображает содержимое документа.

        Args:
            document: Документ для отображения.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
            ValueError: Если документ неверного типа.

        Example:
            >>> renderer.render(my_document)
        """
        self._ensure_mounted()
        self._context = self._context.with_dirty(False)
        self._do_render(document)

    def get_content(self) -> ContentT:
        """Возвращает текущее содержимое редактора.

        Returns:
            Текущее содержимое документа.

        Raises:
            LifecycleError: Если рендерер не смонтирован.

        Example:
            >>> content = renderer.get_content()
        """
        self._ensure_mounted()
        return self._do_get_content()

    def can_handle(self, mode: DocumentMode) -> bool:
        """Проверяет, может ли рендерер обрабатывать данный режим.

        Args:
            mode: Режим документа для проверки.

        Returns:
            True если рендерер поддерживает данный режим.

        Example:
            >>> renderer.can_handle(DocumentMode.FREE_FORM)
            True
            >>> renderer.can_handle(DocumentMode.STRUCTURED_FORM)
            False
        """
        return self.get_mode() == mode

    # ======================================================================
    # COMMAND HANDLING
    # ======================================================================

    def apply_command(self, command: Command) -> None:
        """Применяет команду к документу.

        Args:
            command: Команда для выполнения.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
            ValueError: Если команда неприменима к данному типу документа.

        Example:
            >>> renderer.apply_command(my_command)
        """
        self._ensure_mounted()
        self._do_apply_command(command)
        if self._command_stack is not None:
            self._command_stack.execute(command)

    def set_command_stack(self, stack: CommandStack) -> None:
        """Устанавливает CommandStack для undo/redo операций.

        Args:
            stack: Стек команд для данного рендерера.

        Note:
            Рендерер должен использовать переданный stack вместо
            создания собственного.
        """
        self._command_stack = stack

    # ======================================================================
    # SECURITY & DATA PROTECTION
    # ======================================================================

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные из редактора.

        Очищает содержимое, undo историю и все ссылки на данные.
        Используется при выходе из режима редактирования
        или при блокировке сессии.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        self._ensure_mounted()
        if self._command_stack is not None:
            self._command_stack.clear()
        self._do_wipe_sensitive_data()

    def hide_content(self) -> None:
        """Скрывает содержимое редактора (session lock).

        Показывает placeholder или маску вместо реального содержимого.
        Содержимое остаётся в памяти, но не видно пользователю.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        self._ensure_mounted()
        self._do_hide_content()

    def restore_content(self) -> None:
        """Восстанавливает содержимое редактора (session unlock).

        Возвращает отображение содержимого после разблокировки сессии.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        self._ensure_mounted()
        self._do_restore_content()

    # ======================================================================
    # FORMATTING
    # ======================================================================

    def supports_formatting(self) -> bool:
        """Проверяет, поддерживает ли рендерер форматирование текста.

        Returns:
            True для FREE_FORM режима (CPI, bold, italic, underline).
            False для STRUCTURED_FORM режима.

        Example:
            >>> renderer.supports_formatting()
            True
        """
        return self.get_mode() == DocumentMode.FREE_FORM

    # ======================================================================
    # MODE CONTEXT
    # ======================================================================

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
        """
        self._ensure_mounted()
        return self._context

    def update_context(self, context: ModeContext) -> None:
        """Обновляет контекст режима.

        Args:
            context: Новый контекст режима.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
            ValueError: Если context.mode не соответствует get_mode().

        Example:
            >>> new_ctx = ModeContext(
            ...     mode=DocumentMode.FREE_FORM,
            ...     is_dirty=True,
            ... )
            >>> renderer.update_context(new_ctx)
        """
        self._ensure_mounted()
        if context.mode != self.get_mode():
            raise ValueError(
                f"Контекст режима {context.mode} не соответствует "
                f"режиму рендерера {self.get_mode()}"
            )
        self._context = context

    # ======================================================================
    # MODE LIFECYCLE CALLBACKS
    # ======================================================================

    def on_mode_enter(self) -> None:
        """Вызывается при входе в режим.

        Выполняет инициализацию специфичную для данного режима.
        Вызывается после mount(), перед началом работы с документом.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        self._ensure_mounted()
        # Переопределяется в наследниках при необходимости

    def on_mode_exit(self) -> None:
        """Вызывается при выходе из режима.

        Выполняет очистку специфичную для данного режима.
        Вызывается перед unmount(), при смене режима.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        self._ensure_mounted()
        # Переопределяется в наследниках при необходимости


__all__: list[str] = [
    "BaseModeRenderer",
    "LifecycleError",
]
