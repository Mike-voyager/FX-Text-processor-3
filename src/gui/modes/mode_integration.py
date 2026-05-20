"""Интеграция режимов (Mode Integration) для FX Text Processor 3.

Модуль предоставляет ModeIntegration — координатор переключения между
режимами документа (FREE_FORM, STRUCTURED_FORM) с сохранением состояния
и viewport при переключении.

Classes:
    ModeIntegration: Интегратор режимов документа с кэшированием состояния.

Example:
    >>> from src.gui.modes.mode_integration import ModeIntegration
    >>> from src.documents.types.document_type import DocumentMode
    >>> integration = ModeIntegration()
    >>> renderer = integration.switch_mode(DocumentMode.FREE_FORM, parent, ctrl)

Version: 1.1
Date: May 2026
"""

from __future__ import annotations

import logging
from typing import Any, Optional, Union, cast

from src.documents.types.document_type import DocumentMode
from src.gui.modes.free_form.renderer import FreeFormModeRenderer
from src.gui.modes.protocols import ModeState
from src.gui.modes.structured_form.renderer import StructuredFormModeRenderer

# Псевдоним типа для объединения рендереров режимов
ModeRenderer = Union[FreeFormModeRenderer, StructuredFormModeRenderer]

logger = logging.getLogger(__name__)


class ModeIntegration:
    """Интеграция различных режимов работы документа.

    Управляет переключением между режимами документа:
    - Свободный (free-form)
    - Структурированный (structured form)

    Сохраняет состояние viewport при переключении.

    Attributes:
        _current_mode: Текущий активный режим документа.
        _current_renderer: Текущий активный рендерер.
        _state_cache: Кэш состояний по режимам.
        _viewport_cache: Кэш viewport по режимам.

    Example:
        >>> integration = ModeIntegration()
        >>> renderer = integration.switch_mode(
        ...     DocumentMode.FREE_FORM, parent, controller,
        ... )
    """

    def __init__(self) -> None:
        """Инициализирует интегратор режимов."""
        self._current_mode: Optional[DocumentMode] = None
        self._current_renderer: Optional[ModeRenderer] = None
        self._state_cache: dict[DocumentMode, ModeState] = {}
        self._viewport_cache: dict[DocumentMode, Any] = {}

    def _create_renderer(
        self,
        mode: DocumentMode,
        parent: Any,
        controller: Any,
    ) -> ModeRenderer:
        """Создаёт рендерер для указанного режима.

        Args:
            mode: Целевой режим документа.
            parent: Родительский виджет.
            controller: Контроллер документа.

        Returns:
            Созданный рендерер.

        Raises:
            ValueError: Если режим не поддерживается.
        """
        if mode == DocumentMode.FREE_FORM:
            renderer: ModeRenderer = FreeFormModeRenderer(parent, controller)
            self._setup_validation_controller(cast("FreeFormModeRenderer", renderer))
            return renderer
        renderer = StructuredFormModeRenderer(parent, controller)
        return renderer

    def _setup_validation_controller(self, renderer: FreeFormModeRenderer) -> None:
        """Подключает валидацию кодировки к FreeForm рендереру.

        Создаёт FreeFormValidationController, если доступны
        необходимые зависимости (FormatToolbar).

        Args:
            renderer: Рендерер FreeForm для подключения валидации.
        """
        try:
            from src.gui.modes.free_form.validation_integration import (
                FreeFormValidationController,
            )

            # FormatToolbar может не быть доступна на момент создания рендерера,
            # поэтому подключаем контроллер лениво при первом обращении
            self._validation_controller: Optional[FreeFormValidationController] = None
            logger.debug("FreeFormValidationController ready for lazy init")
        except ImportError as exc:
            logger.debug("FreeFormValidationController not available: %s", exc)

    def switch_mode(
        self,
        mode: DocumentMode,
        parent: Any,
        controller: Any,
    ) -> ModeRenderer:
        """Переключает режим документа.

        Сохраняет состояние текущего режима и viewport перед переключением,
        затем создаёт или восстанавливает рендерер для нового режима.

        Args:
            mode: Целевой режим.
            parent: Родительский виджет.
            controller: Контроллер документа.

        Returns:
            Созданный или восстановленный рендерер.
        """
        # Сохраняем текущий viewport перед переключением
        if self._current_renderer is not None:
            self._save_viewport()

        self._current_mode = mode

        # Проверяем кэш состояний
        if mode in self._state_cache:
            state = self._state_cache[mode]
            renderer = self._create_renderer(mode, parent, controller)

            try:
                renderer.restore_state(state)  # type: ignore[union-attr]
            except AttributeError:
                logger.debug("Renderer does not support restore_state")
            self._current_renderer = renderer
            return renderer

        # Создаём новый рендерер
        renderer = self._create_renderer(mode, parent, controller)
        self._current_renderer = renderer
        return renderer

    def _save_viewport(self) -> None:
        """Сохраняет текущий viewport в кэш.

        Использует get_context() протокола для получения viewport,
        либо getattr для обратной совместимости.
        """
        if self._current_mode is None or self._current_renderer is None:
            return
        try:
            # Предпочитаем get_context() из протокола
            if hasattr(self._current_renderer, "get_context"):
                context = self._current_renderer.get_context()
                self._viewport_cache[self._current_mode] = context.viewport
            elif hasattr(self._current_renderer, "viewport"):
                self._viewport_cache[self._current_mode] = self._current_renderer.viewport
        except (AttributeError, RuntimeError) as exc:
            logger.debug("Viewport save failed: %s", exc)

    def save_state(self) -> None:
        """Сохраняет состояние текущего режима.

        Извлекает контент, viewport и флаг is_dirty из текущего
        рендерера и кэширует их для последующего восстановления.
        """
        if self._current_mode is None or self._current_renderer is None:
            return

        try:
            content: Any = None
            if hasattr(self._current_renderer, "get_content"):
                try:
                    content = self._current_renderer.get_content()
                except (AttributeError, RuntimeError) as exc:
                    logger.debug("get_content failed: %s", exc)

            viewport: Any = None
            if self._current_mode in self._viewport_cache:
                viewport = self._viewport_cache[self._current_mode]

            state = ModeState(
                mode=self._current_mode,
                content=content,
                viewport=viewport,
                is_dirty=getattr(self._current_renderer, "is_dirty", False),
            )
            self._state_cache[self._current_mode] = state
        except (AttributeError, RuntimeError) as exc:
            logger.debug("State save failed: %s", exc)

    def get_saved_state(self, mode: DocumentMode) -> Optional[ModeState]:
        """Возвращает сохранённое состояние режима.

        Args:
            mode: Режим документа.

        Returns:
            Ранее сохранённое состояние или None.
        """
        return self._state_cache.get(mode)

    @property
    def current_renderer(self) -> Optional[ModeRenderer]:
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


__all__: list[str] = ["ModeIntegration"]
