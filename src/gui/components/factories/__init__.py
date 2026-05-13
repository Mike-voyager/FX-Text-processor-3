"""Фабричные функции для GUI-компонентов.

Модуль предоставляет factory functions для создания компонентов
с lazy imports для предотвращения circular imports.

Example:
    >>> from src.gui.components.factories import create_form_field
    >>> field = create_form_field(parent, field_def, document_index)

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

from src.gui.components.factories.form_field_factory import create_form_field

__all__ = ["create_form_field"]
