"""Пакет modes для FX Text Processor 3.

Модуль определяет протоколы и базовые классы для реализации режимов
отображения документов (FREE_FORM и STRUCTURED_FORM).

Пакет следует строгому разделению:
- Protocols: определяют интерфейсы
- Base: абстрактные базовые классы
- Реализации: в отдельных модулях (free_form, structured_form)

Example:
    >>> from src.gui.modes import DocumentModeRendererProtocol
    >>> from src.gui.modes import BaseModeRenderer
    >>> from src.documents.types.document_type import DocumentMode

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from src.gui.modes.base import BaseModeRenderer
from src.gui.modes.protocols import (
    DocumentModeRendererProtocol,
    ModeContext,
    ModeState,
    ModeSwitchEvent,
    ModeToolbarProtocol,
)

__all__: list[str] = [
    "BaseModeRenderer",
    "DocumentModeRendererProtocol",
    "ModeContext",
    "ModeState",
    "ModeSwitchEvent",
    "ModeToolbarProtocol",
]
