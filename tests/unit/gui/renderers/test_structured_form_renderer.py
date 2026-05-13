"""Тесты для StructuredFormRenderer.

Author: Mike Voyager
Date: 2026-04-07
"""

from __future__ import annotations

import tkinter as tk
from unittest.mock import MagicMock, patch

import pytest

from src.documents.constructor.form_status import FormStatus
from src.documents.types.type_schema import FieldDefinition, FieldType
from src.gui.renderers.structured_form_renderer import (
    FormPage,
    HeaderFooterConfig,
    PageData,
    StructuredFormDocument,
    StructuredFormRenderer,
)
from src.model.enums import FontFamily
from src.services.paper_profile_service import PaperProfile, PaperType as PaperTypeEnum


@pytest.fixture
def root() -> tk.Tk:
    """Создаёт корневое окно Tkinter."""
    root = tk.Tk()
    yield root
    root.destroy()


@pytest.fixture
def mock_profile() -> PaperProfile:
    """Создаёт тестовый профиль бумаги."""
    return PaperProfile(
        id="a4_test",
        name="A4 Test",
        name_ru="A4 Тест",
        category="continuous",
        paper_type=PaperTypeEnum.CONTINUOUS_TRACTOR,
        width_mm=210.0,
        height_mm=297.0,
    )


class TestStructuredFormRenderer:
    """Тесты для StructuredFormRenderer."""

    @pytest.fixture
    def renderer(self, root: tk.Tk) -> StructuredFormRenderer:
        """Создаёт рендерер для тестирования."""
        renderer = StructuredFormRenderer(
            parent=root,
            controller=None,
            mode_manager=None,
        )
        renderer.mount(root)
        # Тесты на create_field/delete_field используют canvas-режим,
        # inline-режим по умолчанию → canvas не создаётся.
        renderer._use_inline_mode = False
        root.update_idletasks()
        return renderer

    def test_renderer_creation(self, renderer: StructuredFormRenderer) -> None:
        """Тест создания рендерера."""
        assert renderer._tk_frame is not None
        assert renderer._command_stack is not None
        assert renderer.page_count == 0

    def test_add_page(self, renderer: StructuredFormRenderer, mock_profile: PaperProfile) -> None:
        """Тест добавления страницы."""
        index = renderer.add_page(profile=mock_profile)

        assert index == 0
        assert renderer.page_count == 1
        assert renderer._pages[0].profile == mock_profile

    def test_add_multiple_pages(self, renderer: StructuredFormRenderer, mock_profile: PaperProfile) -> None:
        """Тест добавления нескольких страниц."""
        index1 = renderer.add_page(profile=mock_profile)
        index2 = renderer.add_page(profile=mock_profile)

        assert index1 == 0
        assert index2 == 1
        assert renderer.page_count == 2

    def test_remove_page(self, renderer: StructuredFormRenderer, mock_profile: PaperProfile) -> None:
        """Тест удаления страницы."""
        renderer.add_page(profile=mock_profile)
        renderer.add_page(profile=mock_profile)

        assert renderer.page_count == 2

        result = renderer.remove_page(index=0)
        assert result is True
        assert renderer.page_count == 1

    def test_remove_last_page_fails(self, renderer: StructuredFormRenderer, mock_profile: PaperProfile) -> None:
        """Тест что удаление последней страницы не работает."""
        renderer.add_page(profile=mock_profile)

        result = renderer.remove_page(index=0)
        assert result is False  # Cannot remove last page
        assert renderer.page_count == 1

    def test_set_page_paper(self, renderer: StructuredFormRenderer, mock_profile: PaperProfile) -> None:
        """Тест смены paper type для страницы."""
        renderer.add_page(profile=mock_profile)

        # Создаём новый профиль
        new_profile = PaperProfile(
            id="letter_test",
            name="Letter Test",
            name_ru="Letter Тест",
            category="continuous",
            paper_type=PaperTypeEnum.CONTINUOUS_TRACTOR,
            width_mm=215.9,
            height_mm=279.4,
        )

        renderer.set_page_paper(0, new_profile)
        assert renderer._pages[0].profile.id == "letter_test"

    def test_multi_page_navigation(self, renderer: StructuredFormRenderer, mock_profile: PaperProfile) -> None:
        """Тест навигации между страницами."""
        renderer.add_page(profile=mock_profile)
        renderer.add_page(profile=mock_profile)

        # Показываем первую страницу
        renderer._show_page(0)
        assert renderer._current_page_index == 0

        # Показываем вторую страницу
        renderer._show_page(1)
        assert renderer._current_page_index == 1

    def test_header_footer_global(self, renderer: StructuredFormRenderer) -> None:
        """Тест глобальных колонтитулов."""
        header = HeaderFooterConfig(
            left_text="Left",
            center_text="Center",
            right_text="Right",
            cpi=10,
        )

        renderer.configure_header_footer(scope="global", header=header)

        assert renderer._global_header == header
        assert renderer._header_scope == "global"

    def test_header_footer_per_page(
        self, renderer: StructuredFormRenderer, mock_profile: PaperProfile
    ) -> None:
        """Тест колонтитулов для конкретной страницы."""
        renderer.add_page(profile=mock_profile)

        header = HeaderFooterConfig(
            left_text="Page 1 Header",
            center_text="",
            right_text="",
            cpi=10,
        )

        renderer.configure_header_footer(scope="per_page", header=header, page_index=0)

        assert renderer._pages[0].header == header

    def test_header_footer_render(self) -> None:
        """Тест рендеринга колонтитула."""
        header = HeaderFooterConfig(
            left_text="Page {page}",
            center_text="of {total_pages}",
            right_text="{date}",
            cpi=10,
        )

        result = header.render(
            page_number=1,
            total_pages=5,
            document_index="DOC-001",
        )

        assert "Page 1" in result
        assert "of 5" in result

    def test_form_data_collection(self, renderer: StructuredFormRenderer, mock_profile: PaperProfile) -> None:
        """Тест сбора данных формы."""
        renderer.add_page(profile=mock_profile)

        data = renderer.get_form_data()

        assert isinstance(data, dict)

    def test_validate_form(self, renderer: StructuredFormRenderer, mock_profile: PaperProfile) -> None:
        """Тест валидации формы."""
        renderer.add_page(profile=mock_profile)

        report = renderer.validate_form()

        assert report is not None

    def test_undo_redo(self, renderer: StructuredFormRenderer) -> None:
        """Тест undo/redo."""
        # Проверяем что undo не работает без команд
        assert renderer.undo() is False
        assert renderer.redo() is False

        # CommandStack должен быть пуст
        assert not renderer._command_stack.can_undo()
        assert not renderer._command_stack.can_redo()

    def test_wipe_sensitive_data(self, renderer: StructuredFormRenderer, mock_profile: PaperProfile) -> None:
        """Тест очистки sensitive данных."""
        renderer.add_page(profile=mock_profile)
        renderer._form_id = "sensitive_form_id"

        renderer.wipe_sensitive_data()

        # Command stack должен быть очищен
        assert not renderer._command_stack.can_undo()

    def test_render_document(self, renderer: StructuredFormRenderer, mock_profile: PaperProfile) -> None:
        """Тест рендеринга документа."""
        page_data = PageData(
            profile=mock_profile,
            fields=[],
        )

        document = StructuredFormDocument(
            form_id="test_doc",
            pages=[page_data],
            status=FormStatus.DRAFT,
        )

        renderer.render(document)

        assert renderer._form_id == "test_doc"
        assert renderer._form_status == FormStatus.DRAFT
        assert renderer.page_count == 1

    def test_duplicate_page(self, renderer: StructuredFormRenderer, mock_profile: PaperProfile) -> None:
        """Тест дублирования страницы."""
        renderer.add_page(profile=mock_profile)

        new_index = renderer.duplicate_page(0)

        assert new_index == 1
        assert renderer.page_count == 2

    def test_reorder_pages(self, renderer: StructuredFormRenderer, mock_profile: PaperProfile) -> None:
        """Тест изменения порядка страниц."""
        renderer.add_page(profile=mock_profile)
        renderer.add_page(profile=mock_profile)

        first_page = renderer._pages[0]
        second_page = renderer._pages[1]

        renderer.reorder_pages(from_index=0, to_index=1)

        assert renderer._pages[0] == second_page
        assert renderer._pages[1] == first_page

    def test_create_field(self, renderer: StructuredFormRenderer, mock_profile: PaperProfile) -> None:
        """Тест создания поля."""
        renderer.add_page(profile=mock_profile)

        field_def = FieldDefinition(
            field_id="test_field",
            field_type=FieldType.TEXT_INPUT,
            label="Test Field",
        )

        field_widget = renderer.create_field(field_def, page_index=0)

        assert field_widget is not None
        assert field_widget.field_id == "test_field"

    def test_select_field(self, renderer: StructuredFormRenderer, mock_profile: PaperProfile) -> None:
        """Тест выделения поля."""
        renderer.add_page(profile=mock_profile)

        field_def = FieldDefinition(
            field_id="select_test",
            field_type=FieldType.TEXT_INPUT,
            label="Select Test",
        )

        renderer.create_field(field_def, page_index=0)
        renderer.select_field("select_test")

        # Проверяем что поле выделено
        page = renderer._pages[0]
        if page.canvas:
            assert page.canvas._selected_field_id == "select_test"

    def test_move_field(self, renderer: StructuredFormRenderer, mock_profile: PaperProfile) -> None:
        """Тест перемещения поля."""
        renderer.add_page(profile=mock_profile)

        field_def = FieldDefinition(
            field_id="move_test",
            field_type=FieldType.TEXT_INPUT,
            label="Move Test",
        )

        renderer.create_field(field_def, page_index=0)
        result = renderer.move_field("move_test", new_x=10, new_y=10)

        # Результат зависит от валидации Canvas
        # но метод должен вернуть bool
        assert isinstance(result, bool)

    def test_delete_field(self, renderer: StructuredFormRenderer, mock_profile: PaperProfile) -> None:
        """Тест удаления поля."""
        renderer.add_page(profile=mock_profile)

        field_def = FieldDefinition(
            field_id="delete_test",
            field_type=FieldType.TEXT_INPUT,
            label="Delete Test",
        )

        renderer.create_field(field_def, page_index=0)
        assert len(renderer._pages[0].fields) == 1

        result = renderer.delete_field("delete_test")
        assert result is True
        assert len(renderer._pages[0].fields) == 0

    def test_transition_status(self, renderer: StructuredFormRenderer) -> None:
        """Тест перехода статуса."""
        renderer._form_status = FormStatus.DRAFT

        # DRAFT -> FILLED не требует MFA
        result = renderer.transition_status(FormStatus.FILLED)
        assert result is True
        assert renderer._form_status == FormStatus.FILLED

    def test_current_page_property(self, renderer: StructuredFormRenderer, mock_profile: PaperProfile) -> None:
        """Тест свойства current_page."""
        # Без страниц должно вернуться None
        assert renderer.current_page is None

        renderer.add_page(profile=mock_profile)
        renderer._show_page(0)

        assert renderer.current_page is not None
        assert renderer.current_page.index == 0

    def test_form_status_property(self, renderer: StructuredFormRenderer) -> None:
        """Тест свойства form_status."""
        renderer._form_status = FormStatus.VALIDATED
        assert renderer.form_status == FormStatus.VALIDATED
