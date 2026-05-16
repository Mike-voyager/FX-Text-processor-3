"""Интеграция режимов (Mode Integration) для FX Text Processor 3."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from src.documents.types.document_type import DocumentMode
from src.gui.modes.free_form.renderer import FreeFormModeRenderer
from src.gui.modes.protocols import ModeState
from src.gui.modes.structured_form.renderer import StructuredFormModeRenderer

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
        self._current_renderer: Optional[Any] = None
        self._state_cache: Dict[DocumentMode, ModeState] = {}
        self._viewport_cache: Dict[DocumentMode, Any] = {}

    def switch_mode(
        self,
        mode: DocumentMode,
        parent: Any,
        controller: Any,
    ) -> Any:
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
            renderer: Any
            if str(mode) == DocumentMode.FREE_FORM.value:
                renderer = FreeFormModeRenderer(parent, controller)
            else:
                renderer = StructuredFormModeRenderer(parent, controller)

            try:
                renderer.restore_state(state)
            except AttributeError:
                pass
            self._current_renderer = renderer
            return renderer

        # Create new
        if str(mode) == DocumentMode.FREE_FORM.value:
            renderer = FreeFormModeRenderer(parent, controller)
        else:
            renderer = StructuredFormModeRenderer(parent, controller)

        self._current_renderer = renderer
        return renderer

    def _save_viewport(self) -> None:
        """Сохраняет текущий viewport в кэш."""
        if self._current_mode is None or self._current_renderer is None:
            return
        try:
            self._viewport_cache[self._current_mode] = self._current_renderer.get_viewport()
        except (AttributeError, RuntimeError) as exc:
            logger.debug("Viewport save failed: %s", exc)

    def save_state(self) -> None:
        """Сохраняет состояние текущего режима."""
        if self._current_mode is None or self._current_renderer is None:
            return

        try:
            content: Any = None
            if hasattr(self._current_renderer, "get_content"):
                try:
                    content = self._current_renderer.get_content()
                except (AttributeError, RuntimeError) as exc:
                    # Игнорируем ошибки получения контента
                    logger.debug("get_content failed: %s", exc)

            state = ModeState(
                mode=self._current_mode,
                content=content,
                viewport=getattr(self._current_renderer, "viewport", None),
                is_dirty=getattr(self._current_renderer, "is_dirty", False),
            )
            self._state_cache[self._current_mode] = state
        except (AttributeError, RuntimeError) as exc:
            # Игнорируем ошибки сохранения состояния
            logger.debug("State save failed: %s", exc)
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
    def current_renderer(self) -> Optional[Any]:
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
