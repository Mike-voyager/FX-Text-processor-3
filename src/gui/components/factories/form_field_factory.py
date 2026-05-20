"""Фабрика для создания FormField без circular import.

Импортирует FormField лениво (внутри метода) для разрыва цикла
components → dialogs → renderers → components.

Example:
    >>> from src.gui.components.factories.form_field_factory import create_form_field
    >>> field = create_form_field(parent, field_def, document_index)

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable, Optional

from src.documents.types.type_schema import FieldDefinition
from src.services.autocomplete_service import AutocompleteService

if TYPE_CHECKING:
    from src.gui.components.form_field import FormField


def create_form_field(
    parent: Any,
    field_def: FieldDefinition,
    document_index: str,
    autocomplete_service: Optional[AutocompleteService] = None,
    on_change: Optional[Callable[[str, Any], None]] = None,
    on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = None,
) -> FormField:
    """Создаёт FormField через ленивый импорт.

    Lazy import разрывает circular import между renderers и components.

    Args:
        parent: Родительский виджет.
        field_def: Определение поля.
        document_index: Индекс документа.
        autocomplete_service: Сервис автокомплита.
        on_change: Callback при изменении.
        on_validate: Callback при валидации.

    Returns:
        FormField instance (ttk.Frame).
    """
    from src.gui.components.form_field import FormField

    return FormField(
        parent=parent,
        field_def=field_def,
        document_index=document_index,
        autocomplete_service=autocomplete_service,
        on_change=on_change,
        on_validate=on_validate,
    )
