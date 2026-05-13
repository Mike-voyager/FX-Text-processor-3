"""Интеграция режимов (Mode Integration) для FX Text Processor 3."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Dict, Optional

from src.gui.modes.base import BaseModeRenderer
from src.gui.modes.free_form.renderer import FreeFormRenderer
from src.gui.modes.protocols import (
    ModeState,
)
from src.gui.modes.structured_form.renderer import StructuredFormRenderer

if TYPE_CHECKING:
    from src.model.enums import DocumentMode

logger = logging.getLogger(__name__)


class ModeIntegration:
    """Интеграция различных режимов работы документа.

    Управляет переключением между режимами документа:
    - Свободный (free-form)
    - Структурированный (structured form)

    Сохраняет состояние viewport при переключении.
    """

    def __init__(self) -> None:
        """Инициализирует интегратор режимов."""
        self._current_mode: Optional[DocumentMode] = None
        self._current_renderer: Optional[BaseModeRenderer] = None
        self._state_cache: Dict[DocumentMode, ModeState] = {}
        self._viewport_cache: Dict[DocumentMode, Any] = {}

    def switch_mode(
        self,
        mode: DocumentMode,
        parent: Any,
        controller: Any,
    ) -> BaseModeRenderer:
        """Переключает режим документа.

        Args:
            mode: Целевой режим.
            parent: Родительский виджет.
            controller: Контроллер документа.

        Returns:
            Созданный или восстановленный рендерер.
        """
        # Save current viewport if any
        if self._current_renderer is not None:
            self._save_viewport()

        self._current_mode = mode

        # Check cache
        if mode in self._state_cache:
            state = self._state_cache[mode]
            renderer_cls: type[BaseModeRenderer]
            if mode == getattr(DocumentMode, "FREE_FORM", None) or str(mode) == "free_form":
                renderer_cls = FreeFormRenderer
            else:
                renderer_cls = StructuredFormRenderer

            renderer = renderer_cls(parent, controller)
            renderer.restore_state(state)
            self._current_renderer = renderer
            return renderer

        # Create new
        if mode == getattr(DocumentMode, "FREE_FORM", None) or str(mode) == "free_form":
            renderer = FreeFormRenderer(parent, controller)
        else:
            renderer = StructuredFormRenderer(parent, controller)

        self._current_renderer = renderer
        return renderer

    def _save_viewport(self) -> None:
        """Сохраняет текущий viewport в кэш."""
        if self._current_mode is None or self._current_renderer is None:
            return
        try:
            self._viewport_cache[self._current_mode] = self._current_renderer.get_viewport()
        except (AttributeError, RuntimeError) as e:
            logger.debug("Viewport save failed: %s", e)

    def save_state(self) -> None:
        """Сохраняет состояние текущего режима."""
        if self._current_mode is None or self._current_renderer is None:
            return

        try:
            content: Any = None
            if hasattr(self._current_renderer, "get_content"):
                try:
                    content = self._current_renderer.get_content()
                except (AttributeError, RuntimeError) as e:
                    # Игнорируем ошибки получения контента
                    logger.debug("get_content failed: %s", e)

            state = ModeState(
                mode=self._current_mode,
                content=content,
                viewport=getattr(self._current_renderer, "viewport", None),
                is_dirty=getattr(self._current_renderer, "is_dirty", False),
            )
            self._state_cache[self._current_mode] = state
        except (AttributeError, RuntimeError) as e:
            # Игнорируем ошибки сохранения состояния
            logger.debug("State save failed: %s", e)
            logger.exception("State save failed")

    def get_saved_state(self, mode: DocumentMode) -> Optional[ModeState]:
        """Возвращает сохранённое состояние режима.

        Args:
            mode: Режим документа.

        Returns:
            Ранее сохранённое состояние или None.
        """
        return self._state_cache.get(mode)

    @property
    def current_renderer(self) -> Optional[BaseModeRenderer]:
        """Текущий активный рендерер."""
        return self._current_renderer

    @property
    def current_mode(self) -> Optional[DocumentMode]:
        """Текущий активный режим."""
        return self._current_mode

    def clear_cache(self) -> None:
        """Очищает весь кэш состояний."""
        self._state_cache.clear()
        self._viewport_cache.clear()

__all__ = ["ModeIntegration"]
