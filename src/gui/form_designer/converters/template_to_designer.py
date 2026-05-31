"""Конвертер FormTemplate -> DesignerPage.

Module: src/gui/form_designer/converters/template_to_designer.py
"""

from __future__ import annotations

import logging
from datetime import date
from typing import Any, Callable, Final, Optional

from src.documents.constructor.form_constructor import FormTemplate
from src.documents.types.type_schema import FieldDefinition, FieldType
from src.gui.form_designer.types import DesignerPage
from src.gui.renderers.form_canvas import FieldPosition, FormCanvas, FormFieldWidget
from src.services.paper_format_service import PaperFormatService, PaperProfile

logger: Final = logging.getLogger(__name__)


class TemplateToDesignerConverter:
    """Конвертирует FormTemplate в DesignerPage.

    Восстанавливает структуру страниц и полей из сохранённого шаблона.

    Example:
        >>> converter = TemplateToDesignerConverter(canvas_factory)
        >>> pages = converter.convert(template)
        >>> for page in pages:
        ...     print(f"Page {page.index}: {len(page.fields)} fields")
    """

    def __init__(
        self,
        canvas_factory: Callable[[], FormCanvas],
        profile_service: Optional[PaperFormatService] = None,
    ) -> None:
        """Инициализирует конвертер.

        Args:
            canvas_factory: Фабрика для создания FormCanvas.
            profile_service: Сервис профилей бумаги (optional).
        """
        self._canvas_factory = canvas_factory
        self._profile_service = profile_service or PaperFormatService()

    def convert(self, template: FormTemplate) -> list[DesignerPage]:
        """Конвертирует шаблон в страницы дизайнера.

        Args:
            template: Загруженный шаблон формы.

        Returns:
            Список страниц дизайнера.
        """
        pages_by_index: dict[int, DesignerPage] = {}

        for field_id, field_data in template.field_defaults.items():
            page_num = field_data.get("position", {}).get("page", 0)

            if page_num not in pages_by_index:
                pages_by_index[page_num] = self._create_page(page_num, template)

            self._create_field_on_page(pages_by_index[page_num], field_id, field_data)

        # Сортируем страницы по индексу
        return [pages_by_index[i] for i in sorted(pages_by_index.keys())]

    def _create_page(self, index: int, template: FormTemplate) -> DesignerPage:
        """Создаёт страницу дизайнера.

        Args:
            index: Индекс страницы.
            template: Шаблон для получения метаданных страницы.

        Returns:
            Созданная страница дизайнера.
        """
        # Получаем профиль из метаданных или используем дефолтный
        profile = self._get_page_profile(index, template)

        # Создаём canvas
        canvas = self._canvas_factory()

        # Создаём фрейм для страницы (будет заменён при монтировании)
        import tkinter as tk

        frame = tk.Frame()

        return DesignerPage(
            index=index,
            profile=profile,
            canvas=canvas,
            frame=frame,
            fields=[],
        )

    def _get_page_profile(self, index: int, template: FormTemplate) -> PaperProfile:
        """Получает профиль бумаги для страницы.

        Args:
            index: Индекс страницы.
            template: Шаблон с метаданными.

        Returns:
            Профиль бумаги.
        """
        # Пробуем получить из метаданных
        pages_metadata = template.metadata.get("pages", [])
        if index < len(pages_metadata):
            profile_name = pages_metadata[index].get("profile_name")
            if profile_name:
                try:
                    profile = self._profile_service.get_profile(profile_name)
                    if profile is not None:
                        return profile
                except (ValueError, TypeError, AttributeError, KeyError) as e:
                    logging.getLogger(__name__).exception(
                        "Exception ignored during profile retrieval: %s",
                        e,
                    )

        # Возвращаем дефолтный профиль
        default_profile = self._profile_service.get_default_profile()
        if default_profile is None:
            raise RuntimeError("No default paper profile available")
        return default_profile

    def _create_field_on_page(
        self,
        page: DesignerPage,
        field_id: str,
        field_data: dict[str, Any],
    ) -> None:
        """Создаёт поле на странице из данных шаблона.

        Args:
            page: Страница для добавления поля.
            field_id: ID поля.
            field_data: Данные поля из шаблона.
        """
        # Восстанавливаем FieldDefinition
        pos_data = field_data.get("position", {})
        position = FieldPosition(
            col=pos_data.get("col", 0),
            row=pos_data.get("row", 0),
            width=pos_data.get("width", 10),
            height=pos_data.get("height", 1),
        )

        # Создаём FieldDefinition
        field_def = self._create_field_definition(field_id, field_data)

        # Создаём FormFieldWidget
        field_widget = FormFieldWidget(
            field_id=field_id,
            field_def=field_def,
            position=position,
        )

        # Добавляем на canvas
        if page.canvas is not None:
            page.canvas.create_field(
                field_def, position.col, position.row, position.width, position.height
            )

        # Добавляем в список полей страницы
        page.fields.append(field_widget)

        logger.debug("Created field %s on page %d", field_id, page.index)

    def _create_field_definition(
        self, field_id: str, field_data: dict[str, Any]
    ) -> FieldDefinition:
        """Создаёт FieldDefinition из данных шаблона.

        Args:
            field_id: ID поля.
            field_data: Данные поля.

        Returns:
            FieldDefinition для поля.
        """
        # Преобразуем min_date/max_date из строки
        min_date = None
        max_date = None
        if field_data.get("min_date"):
            try:
                min_date = date.fromisoformat(field_data["min_date"])
            except ValueError:
                pass
        if field_data.get("max_date"):
            try:
                max_date = date.fromisoformat(field_data["max_date"])
            except ValueError:
                pass

        return FieldDefinition(
            field_id=field_id,
            field_type=FieldType(field_data.get("field_type", "TEXT_INPUT")),
            label=field_data.get("label", ""),
            label_i18n=field_data.get("label_i18n", {}),
            required=field_data.get("required", False),
            readonly=field_data.get("readonly", False),
            default_value=field_data.get("default_value"),
            validation_pattern=field_data.get("validation_pattern"),
            max_length=field_data.get("max_length"),
            options=tuple(field_data["options"]) if field_data.get("options") else None,
            min_value=field_data.get("min_value"),
            max_value=field_data.get("max_value"),
            min_date=min_date,
            max_date=max_date,
            required_if=field_data.get("required_if"),
            help_text=field_data.get("help_text"),
            placeholder=field_data.get("placeholder"),
            tab_index=field_data.get("tab_index"),
        )


__all__ = ["TemplateToDesignerConverter"]
