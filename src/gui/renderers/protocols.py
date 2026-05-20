"""Протоколы для рендереров документов FX Text Processor 3.

Модуль определяет Protocol-классы для реализации Strategy Pattern
в DocumentView. Позволяет унифицировать работу с различными
типами рендереров (FreeForm, StructuredForm, Preview).

Example:
    >>> from src.gui.renderers.protocols import DocumentRendererProtocol
    >>> class MyRenderer:
    ...     def render(self, document): pass
    ...     def can_handle(self, mode): return True
    >>> renderer: DocumentRendererProtocol = MyRenderer()

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Any, Callable, Protocol, TypeVar, Union, runtime_checkable

from src.documents.types.document_type import DocumentMode
from src.gui.core.commands.command import Command
from src.gui.core.commands.command_stack import CommandStack

# Type variable for document types (contravariant for protocol methods)
DocumentT = TypeVar("DocumentT", contravariant=True)
ContentT = TypeVar("ContentT", covariant=True)


class DocumentRendererProtocol(Protocol[DocumentT, ContentT]):
    """Protocol для рендереров документов.

    Определяет единый интерфейс для всех типов рендереров,
    позволяя DocumentView использовать Strategy Pattern
    для переключения между режимами отображения.

    Type Parameters:
        DocumentT: Тип документа (FreeFormDocument, StructuredFormDocument и т.д.)
        ContentT: Тип возвращаемого содержимого (str, FormData и т.д.)

    Example:
        >>> renderer: DocumentRendererProtocol = FreeFormRenderer()
        >>> renderer.render(document)
        >>> content = renderer.get_content()
    """

    def render(self, document: DocumentT) -> None:
        """Загружает и отображает содержимое документа.

        Args:
            document: Документ для отображения.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
            ValueError: Если документ неверного типа.
        """
        ...

    def display_document(self, document: DocumentT) -> None:
        """Отображает документ в редакторе с проверкой режима редактирования.

        SmartEdit-aware метод: если редактор находится в режиме
        редактирования (_is_editing=True), вызов игнорируется
        для предотвращения потери пользовательского ввода.

        Args:
            document: Документ для отображения.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
            ValueError: Если документ неверного типа.
        """
        ...

    def create_toolbar(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт панель инструментов для режима редактирования.

        Strategy Pattern метод: каждый рендерер создаёт toolbar,
        специфичный для своего режима (FormatToolbar для FREE_FORM,
        поле-палитра для STRUCTURED_FORM и т.д.).

        Args:
            parent: Родительский виджет для размещения toolbar.

        Returns:
            Корневой виджет созданного toolbar или dummy-виджет.

        Raises:
            ValueError: Если parent is None.
        """
        ...

    def create_editor(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт редактор для режима документа.

        Strategy Pattern метод: монтирует рендерер в parent и
        возвращает корневой виджет редактора.

        Args:
            parent: Родительский виджет для размещения редактора.

        Returns:
            Корневой виджет редактора.

        Raises:
            ValueError: Если parent is None.
        """
        ...

    def get_editor_state(self) -> dict[str, Any]:
        """Возвращает текущее состояние редактора.

        Returns:
            Словарь с состоянием (cursor_line, cursor_column,
            selection_start, selection_end, text_length, cpi,
            is_editing и т.д.).

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        ...

    def get_content(self) -> ContentT:
        """Возвращает текущее содержимое редактора.

        Returns:
            Текущее содержимое документа.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        ...

    def apply_command(self, command: Command) -> None:
        """Применяет команду к документу.

        Args:
            command: Команда для выполнения.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
            ValueError: Если команда неприменима к данному типу документа.
        """
        ...

    def can_handle(self, mode: DocumentMode) -> bool:
        """Проверяет, может ли рендерер обрабатывать данный режим.

        Args:
            mode: Режим документа для проверки.

        Returns:
            True если рендерер поддерживает данный режим.
        """
        ...

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные из редактора.

        Очищает содержимое, undo историю и все ссылки на данные.
        Используется при выходе из режима редактирования
        или при блокировке сессии.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        ...

    def hide_content(self) -> None:
        """Скрывает содержимое редактора (session lock).

        Показывает placeholder или маску вместо реального содержимого.
        Содержимое остается в памяти, но не видно пользователю.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        ...

    def restore_content(self) -> None:
        """Восстанавливает содержимое редактора (session unlock).

        Возвращает отображение содержимого после разблокировки сессии.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        ...

    def set_command_stack(self, stack: CommandStack) -> None:
        """Устанавливает CommandStack для undo/redo операций.

        Args:
            stack: Стек команд для данного рендерера.

        Note:
            Рендерер должен использовать переданный stack вместо
            создания собственного.
        """
        ...

    def supports_formatting(self) -> bool:
        """Проверяет, поддерживает ли рендерер форматирование текста.

        Returns:
            True для FreeFormRenderer (CPI, bold, italic, underline).
            False для StructuredFormRenderer.
        """
        ...

    def mount(self, parent: tk.Widget) -> tk.Widget:
        """Монтирует рендерер в родительский виджет.

        Args:
            parent: Родительский tkinter виджет.

        Returns:
            Корневой виджет рендерера.

        Raises:
            ValueError: Если parent is None.
        """
        ...

    def unmount(self) -> None:
        """Размонтирует рендерер и освобождает ресурсы.

        Очищает все виджеты и освобождает ссылки на данные.
        """
        ...

    def is_mounted(self) -> bool:
        """Проверяет, смонтирован ли рендерер.

        Returns:
            True если рендерер смонтирован и готов к работе.
        """
        ...

    def show(self) -> None:
        """Показывает виджет рендерера."""
        ...

    def hide(self) -> None:
        """Скрывает виджет рендерера."""
        ...


@runtime_checkable
class RendererCleanupProtocol(Protocol):
    """Дополнительный protocol для cleanup операций.

    Используется RendererFactory для управления lifecycle
    рендереров при переключении режимов.
    """

    def cleanup(self) -> None:
        """Выполняет полную очистку рендерера.

        Вызывается перед переключением на другой рендерер.
        Должен выполнить wipe_sensitive_data и unmount.
        """
        ...

    def save_state(self) -> dict[str, Any]:
        """Сохраняет состояние рендерера для последующего восстановления.

        Returns:
            Словарь с сериализованным состоянием.
        """
        ...

    def restore_state(self, state: dict[str, Any]) -> None:
        """Восстанавливает состояние рендерера.

        Args:
            state: Состояние, полученное от save_state().

        Raises:
            ValueError: Если состояние невалидно.
        """
        ...


# Union type для всех рендереров
AnyDocumentRenderer = Union[
    "DocumentRendererProtocol[Any, Any]",
    "RendererCleanupProtocol",
]


# =============================================================================
# DECORATOR
# =============================================================================


def implements(protocol: type) -> Callable[[type], type]:
    """Декоратор для явного указания реализации Protocol.

    Используется для документирования intent и проверки типов.
    Runtime проверка не выполняется, декоратор только для читаемости.

    Args:
        protocol: Protocol класс, который реализуется.

    Example:
        >>> @implements(DocumentRendererProtocol)
        ... class FreeFormRenderer:
        ...     pass
    """

    def decorator(cls: type) -> type:
        """Внутренний декоратор."""
        cls.__implements__ = protocol  # type: ignore[attr-defined]
        return cls

    return decorator


# Module exports
__all__: list[str] = [
    "AnyDocumentRenderer",
    "DocumentRendererProtocol",
    "RendererCleanupProtocol",
    "implements",
]
