"""Фабрика рендереров документов для FX Text Processor 3.

Реализует паттерн Factory для создания и управления lifecycle
рендереров документов. Поддерживает lazy loading, регистрацию
новых типов рендереров и cleanup при переключении режимов.

Example:
    >>> from src.gui.renderers.factory import RendererFactory
    >>> from src.gui.renderers.free_form_renderer import FreeFormRenderer
    >>> RendererFactory.register(DocumentMode.FREE_FORM, FreeFormRenderer)
    >>> renderer = RendererFactory.create(DocumentMode.FREE_FORM, parent=frame)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import inspect
import logging
import tkinter as tk
from typing import Any, Optional

from src.documents.types.document_type import DocumentMode
from src.gui.core.commands.command_stack import CommandStack
from src.gui.core.exceptions import WidgetCreationError
from src.gui.renderers.protocols import RendererCleanupProtocol

logger = logging.getLogger(__name__)


class RendererFactory:
    """Фабрика для создания и управления рендерерами документов.

    Реализует паттерн Registry + Factory для поддержки Strategy Pattern
    в DocumentView. Позволяет регистрировать новые типы рендереров
    без изменения кода DocumentView.

    Attributes:
        _renderers: Реестр зарегистрированных типов рендереров.
        _current_mode: Текущий активный режим документа.
        _current_renderer: Текущий созданный экземпляр рендерера.

    Example:
        >>> RendererFactory.register(DocumentMode.FREE_FORM, FreeFormRenderer)
        >>> RendererFactory.register(
        ...     DocumentMode.STRUCTURED_FORM, StructuredFormRenderer
        ... )
        >>> renderer = RendererFactory.create(
        ...     DocumentMode.FREE_FORM,
        ...     parent=frame,
        ...     controller=my_controller,
        ...     command_stack=stack,
        ... )
    """

    # Registry of renderer classes by DocumentMode
    _renderers: dict[DocumentMode, type[Any]] = {}

    # Current state for lifecycle management
    _current_mode: Optional[DocumentMode] = None
    _current_renderer: Optional[Any] = None

    @classmethod
    def register(
        cls,
        mode: DocumentMode,
        renderer_class: type[Any],
    ) -> None:
        """Регистрирует класс рендерера для указанного режима.

        Args:
            mode: Режим документа (FREE_FORM или STRUCTURED_FORM).
            renderer_class: Класс рендерера, реализующий DocumentRendererProtocol.

        Raises:
            ValueError: Если renderer_class не реализует нужный интерфейс.
            TypeError: Если renderer_class не является классом.

        Example:
            >>> RendererFactory.register(DocumentMode.FREE_FORM, FreeFormRenderer)
        """
        if not isinstance(renderer_class, type):
            raise TypeError(f"Expected class, got {type(renderer_class)}")

        # Basic validation - check for required methods
        required_methods = [
            "render",
            "get_content",
            "wipe_sensitive_data",
            "hide_content",
            "restore_content",
            "can_handle",
            "create_toolbar",
            "create_editor",
            "get_editor_state",
            "display_document",
        ]
        missing = [m for m in required_methods if not hasattr(renderer_class, m)]
        if missing:
            raise ValueError(f"Renderer class {renderer_class.__name__} missing methods: {missing}")

        cls._renderers[mode] = renderer_class

    @classmethod
    def create(
        cls,
        mode: DocumentMode,
        parent: tk.Widget,
        controller: Optional[Any] = None,
        command_stack: Optional[CommandStack] = None,
        mode_manager: Optional[Any] = None,
        **kwargs: Any,
    ) -> Any:
        """Создаёт экземпляр рендерера для указанного режима.

        Выполняет cleanup текущего рендерера перед созданием нового.
        Передаёт общие параметры (parent, controller, command_stack) в конструктор.

        Args:
            mode: Режим документа для которого создаётся рендерер.
            parent: Родительский tkinter виджет.
            controller: Опциональный контроллер для callbacks.
            command_stack: Опциональный CommandStack для undo/redo.
            mode_manager: Опциональный ModeManager для workflow transitions.
            **kwargs: Дополнительные параметры для конкретного рендерера.

        Returns:
            Экземпляр рендерера для указанного режима.

        Raises:
            WidgetCreationError: Если режим не зарегистрирован.
            ValueError: Если parent is None.

        Example:
            >>> renderer = RendererFactory.create(
            ...     DocumentMode.FREE_FORM,
            ...     parent=frame,
            ...     command_stack=CommandStack(),
            ... )
        """
        if parent is None:
            raise ValueError("parent cannot be None")

        # Cleanup current renderer before creating new one
        cls.cleanup_current()

        # Get registered renderer class
        renderer_class = cls._renderers.get(mode)
        if renderer_class is None:
            available = [m.value for m in cls._renderers.keys()]
            raise WidgetCreationError(
                widget_type=f"DocumentRenderer_{mode.value}",
                factory_name="RendererFactory.create",
                message=f"No renderer registered for mode {mode.value}. Available: {available}",
            )

        # Build constructor arguments based on renderer type
        # Note: parent is NOT passed to constructor, it's passed to mount()
        constructor_args: dict[str, Any] = {}

        # Add optional dependencies if constructor accepts them
        sig = inspect.signature(renderer_class.__init__)
        params = sig.parameters

        if "widget_id" in params:
            constructor_args["widget_id"] = kwargs.get("widget_id", f"renderer_{mode.value}")
        if "controller" in params and controller is not None:
            constructor_args["controller"] = controller
        if "command_stack" in params and command_stack is not None:
            constructor_args["command_stack"] = command_stack
        if "mode_manager" in params and mode_manager is not None:
            constructor_args["mode_manager"] = mode_manager
        if "workflow_manager" in params and kwargs.get("workflow_manager") is not None:
            constructor_args["workflow_manager"] = kwargs["workflow_manager"]
        if "mfa_gate" in params and kwargs.get("mfa_gate") is not None:
            constructor_args["mfa_gate"] = kwargs["mfa_gate"]

        # Add any additional kwargs that constructor accepts
        for key, value in kwargs.items():
            if key in params and key not in constructor_args:
                constructor_args[key] = value

        # Create and mount the renderer
        try:
            renderer = renderer_class(**constructor_args)
            renderer.mount(parent)
        except Exception as e:
            raise WidgetCreationError(
                widget_type=renderer_class.__name__,
                factory_name="RendererFactory.create",
                message=str(e),
                cause=e,
            ) from e

        # Update current state
        cls._current_mode = mode
        cls._current_renderer = renderer

        return renderer

    @classmethod
    def cleanup_current(cls) -> None:
        """Выполняет cleanup текущего рендерера.

        Вызывает wipe_sensitive_data и unmount для текущего рендерера,
        если он реализует RendererCleanupProtocol.
        """
        if cls._current_renderer is not None:
            try:
                # Wipe sensitive data first
                cls._current_renderer.wipe_sensitive_data()

                # Try cleanup if available
                if isinstance(cls._current_renderer, RendererCleanupProtocol):
                    cls._current_renderer.cleanup()

                # Unmount to release resources
                cls._current_renderer.unmount()
            except Exception as e:
                logger.warning("Renderer factory cleanup error: %s", e)
            finally:
                cls._current_renderer = None
                cls._current_mode = None

    @classmethod
    def get_current(cls) -> Optional[Any]:
        """Возвращает текущий рендерер.

        Returns:
            Текущий активный рендерер или None.
        """
        return cls._current_renderer

    @classmethod
    def get_current_mode(cls) -> Optional[DocumentMode]:
        """Возвращает текущий режим документа.

        Returns:
            Текущий режим или None.
        """
        return cls._current_mode

    @classmethod
    def is_registered(cls, mode: DocumentMode) -> bool:
        """Проверяет, зарегистрирован ли рендерер для режима.

        Args:
            mode: Режим документа для проверки.

        Returns:
            True если рендерер зарегистрирован.
        """
        return mode in cls._renderers

    @classmethod
    def get_registered_modes(cls) -> list[DocumentMode]:
        """Возвращает список зарегистрированных режимов.

        Returns:
            Список режимов с зарегистрированными рендерерами.
        """
        return list(cls._renderers.keys())

    @classmethod
    def unregister(cls, mode: DocumentMode) -> None:
        """Удаляет регистрацию рендерера для режима.

        Используется для переопределения рендерера или очистки.

        Args:
            mode: Режим для удаления.
        """
        if mode in cls._renderers:
            del cls._renderers[mode]

    @classmethod
    def reset(cls) -> None:
        """Полный сброс фабрики.

        Очищает все регистрации и текущий рендерер.
        Используется только для тестирования.
        """
        cls.cleanup_current()
        cls._renderers.clear()


# =============================================================================
# DEFAULT REGISTRATIONS
# =============================================================================


def register_default_renderers() -> None:
    """Регистрирует стандартные рендереры.

    Вызывается автоматически при импорте модуля.
    Регистрирует FreeFormRenderer и StructuredFormRenderer.
    """
    # Delay imports to avoid circular dependencies
    try:
        from src.gui.renderers.free_form_renderer import FreeFormRenderer
        from src.gui.renderers.structured_form_renderer import StructuredFormRenderer

        RendererFactory.register(DocumentMode.FREE_FORM, FreeFormRenderer)
        RendererFactory.register(DocumentMode.STRUCTURED_FORM, StructuredFormRenderer)
    except ImportError:
        # Module not available yet, will be registered when imported
        pass


# Auto-register on module import
register_default_renderers()

# Module exports
__all__: list[str] = [
    "RendererFactory",
    "register_default_renderers",
]
