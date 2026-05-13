"""Подпакет base для modes.

Содержит абстрактные базовые классы для реализации рендереров режимов.

Example:
    >>> from src.gui.modes.base import BaseModeRenderer
    >>> class MyRenderer(BaseModeRenderer):
    ...     pass

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from src.gui.modes.base.base_mode_renderer import BaseModeRenderer

__all__: list[str] = [
    "BaseModeRenderer",
]
