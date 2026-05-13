"""Конвертер DesignerPage -> FormTemplate.

Module: src/gui/form_designer/converters/designer_to_template.py
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Final, Optional

from src.documents.constructor.form_constructor import FormTemplate
from src.gui.form_designer.types import DesignerPage
from src.gui.renderers.form_canvas import FormFieldWidget

logger: Final = logging.getLogger(__name__)


class DesignerToTemplateConverter:
    """Конвертирует DesignerPage в FormTemplate.

    Собирает все поля со всех страниц дизайнера и создаёт
    полноценный FormTemplate для сохранения в .fxstpl.

    Example:
        >>> converter = DesignerToTemplateConverter()
        >>> template = converter.convert(
        ...     pages=designer_pages,
        ...     metadata={"type_code": "CUSTOM", "name": "MyTemplate"}
        ... )
        >>> print(template.type_code)
        "CUSTOM"
    """

    def convert(
        self,
        pages: list[DesignerPage],
        metadata: Optional[dict[str, Any]] = None,
    ) -> FormTemplate:
        """Конвертирует страницы дизайнера в FormTemplate.

        Args:
            pages: Список страниц дизайнера.
            metadata: Метаданные для шаблона (type_code, subtype, series, etc.).

        Returns:
            FormTemplate с полной структурой полей.
        """
        metadata = metadata or {}

        # Собираем field_defaults из всех полей
        field_defaults: dict[str, Any] = {}

        for page in pages:
            for field_widget in page.fields:
                field_def = self._convert_field_widget(field_widget, page.index)
                field_defaults[field_widget.field_id] = field_def

        # Создаём шаблон
        template = FormTemplate(
            type_code=metadata.get("type_code", "CUSTOM"),
            subtype=metadata.get("subtype", "01"),
            series=metadata.get("series", "GEN"),
            field_defaults=field_defaults,
            metadata={
                "page_count": len(pages),
                "created_at": datetime.now().isoformat(),
                "pages": [
                    {
                        "index": page.index,
                        "profile_name": page.profile.name if page.profile else None,
                    }
                    for page in pages
                ],
                **(metadata or {}),
            },
        )

        logger.debug(f"Converted {len(pages)} pages to template with {len(field_defaults)} fields")
        return template

    def _convert_field_widget(self, widget: FormFieldWidget, page_index: int) -> dict[str, Any]:
        """Конвертирует виджет поля в FieldDefinition dict.

        Args:
            widget: Виджет поля формы.
            page_index: Индекс страницы.

        Returns:
            Словарь с полным определением поля.
        """
        position = widget.position
        field_def = widget.field_def

        return {
            "field_id": widget.field_id,
            "field_type": field_def.field_type.value,
            "label": field_def.label,
            "label_i18n": field_def.label_i18n,
            "required": field_def.required,
            "readonly": field_def.readonly,
            "default_value": field_def.default_value,
            "validation_pattern": field_def.validation_pattern,
            "max_length": field_def.max_length,
            "options": field_def.options,
            "min_value": field_def.min_value,
            "max_value": field_def.max_value,
            "min_date": field_def.min_date.isoformat() if field_def.min_date else None,
            "max_date": field_def.max_date.isoformat() if field_def.max_date else None,
            "required_if": field_def.required_if,
            "help_text": field_def.help_text,
            "placeholder": field_def.placeholder,
            "tab_index": field_def.tab_index,
            "position": {
                "page": page_index,
                "row": position.row,
                "col": position.col,
                "width": position.width,
                "height": position.height,
            },
            "constraints": [
                {"type": c.type.value, "params": c.params} for c in field_def.constraints
            ]
            if hasattr(field_def, "constraints") and field_def.constraints
            else [],
        }


__all__ = ["DesignerToTemplateConverter"]
