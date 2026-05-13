"""Тесты для режима StructuredForm.

Модуль содержит тесты для режима структурированных форм,
предназначенного для работы с шаблонами документов.
"""

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest

from src.documents.constructor.form_status import FormStatus
from src.documents.types.type_schema import FieldDefinition, FieldType
from src.gui.core.exceptions import LifecycleError
from src.gui.modes.structured_form.renderer import StructuredFormModeRenderer
from src.gui.modes.structured_form.widgets.checkbox_widget import CheckboxWidget
from src.gui.modes.structured_form.widgets.multi_line_widget import MultiLineWidget
from src.gui.modes.structured_form.widgets.text_input_widget import TextInputWidget


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Fixture для Tk root окна."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def mounted_renderer(
    tk_root: tk.Tk,
) -> Generator[tuple[StructuredFormModeRenderer, MagicMock], None, None]:
    """Fixture для смонтированного StructuredFormModeRenderer с замоканными sub-widgets."""
    with (
        patch("src.gui.modes.structured_form.renderer.FormWorkflowBar"),
        patch("src.gui.renderers.structured_form_renderer.StructuredFormRenderer"),
    ):
        renderer = StructuredFormModeRenderer(parent=tk_root)
        renderer.mount(tk_root)
        inner_mock: MagicMock = renderer._inner_renderer  # type: ignore[assignment]
        try:
            yield renderer, inner_mock
        finally:
            if renderer.is_mounted():
                renderer.unmount()


class TestStructuredFormModeRenderer:
    """Тесты для рендерера режима StructuredForm."""

    def test_renderer_initialization(self, tk_root: tk.Tk) -> None:
        """Тест инициализации рендерера.

        Проверяет создание экземпляра StructuredFormModeRenderer
        с загрузкой шаблона формы и базовыми атрибутами.
        """
        renderer = StructuredFormModeRenderer(parent=tk_root)
        assert renderer.widget_id == "structured_form_mode_renderer"
        assert renderer.get_current_status() == FormStatus.DRAFT
        assert renderer.get_snap_to_grid() is True
        assert not renderer.is_mounted()

        # Операции до mount должны вызывать LifecycleError
        with pytest.raises(LifecycleError, match="не смонтирован"):
            renderer.render(MagicMock())
        with pytest.raises(LifecycleError, match="не смонтирован"):
            renderer.get_content()
        with pytest.raises(LifecycleError, match="не смонтирован"):
            renderer.validate()
        with pytest.raises(LifecycleError, match="не смонтирован"):
            renderer.apply_command(MagicMock())

    def test_field_rendering(
        self,
        mounted_renderer: tuple[StructuredFormModeRenderer, MagicMock],
    ) -> None:
        """Тест отрисовки полей формы.

        Проверяет отображение полей ввода согласно шаблону формы
        и делегирование вызовов внутреннему рендереру.
        """
        renderer, inner_mock = mounted_renderer
        doc = MagicMock()
        doc.status = FormStatus.FILLED

        renderer.render(doc)
        inner_mock.render.assert_called_once_with(doc)
        assert renderer.get_current_status() == FormStatus.FILLED

        # get_content делегируется внутреннему рендереру
        expected_doc = MagicMock()
        inner_mock.get_content.return_value = expected_doc
        assert renderer.get_content() is expected_doc

        # validate делегируется внутреннему рендереру
        report = MagicMock()
        inner_mock.validate_form.return_value = report
        assert renderer.validate() is report

    def test_template_binding(self, tk_root: tk.Tk) -> None:
        """Тест привязки шаблона.

        Проверяет загрузку и привязку шаблона формы к рендереру,
        установку callbacks и обработчик workflow-переходов.
        """
        with (
            patch("src.gui.modes.structured_form.renderer.FormWorkflowBar"),
            patch("src.gui.renderers.structured_form_renderer.StructuredFormRenderer"),
        ):
            renderer = StructuredFormModeRenderer(parent=tk_root)
            renderer.mount(tk_root)
            try:
                inner_mock: MagicMock = renderer._inner_renderer  # type: ignore[assignment]

                cb_field = MagicMock()
                cb_page = MagicMock()
                cb_status = MagicMock()

                renderer.set_on_field_select_callback(cb_field)
                renderer.set_on_page_change_callback(cb_page)
                renderer.set_on_status_change_callback(cb_status)

                assert renderer._on_field_select_callback is cb_field
                assert renderer._on_page_change_callback is cb_page
                assert renderer._on_status_change_callback is cb_status

                # Callbacks прокинуты во внутренний рендерер
                inner_mock.set_on_field_select_callback.assert_called_with(cb_field)
                inner_mock.set_on_page_change_callback.assert_called_with(cb_page)

                # Workflow-переход уведомляет внешний callback
                renderer._on_workflow_transition(FormStatus.DRAFT, FormStatus.FILLED)
                cb_status.assert_called_once_with(FormStatus.DRAFT, FormStatus.FILLED)
                assert renderer.get_current_status() == FormStatus.FILLED
            finally:
                if renderer.is_mounted():
                    renderer.unmount()


class TestStructuredFormFields:
    """Тесты полей структурированной формы."""

    def test_text_field_widget(self, tk_root: tk.Tk) -> None:
        """Тест виджета текстового поля.

        Проверяет создание и отображение однострочного текстового поля,
        работу с value, focus и wipe_sensitive_data.
        """
        field_def = FieldDefinition(
            field_id="name",
            field_type=FieldType.TEXT_INPUT,
            label="Имя",
            required=False,
            max_length=20,
        )
        parent = tk.Frame(tk_root)
        widget = TextInputWidget(parent=parent, field_def=field_def)
        widget.mount(parent)
        try:
            assert widget.field_id == "name"
            assert widget.field_type == FieldType.TEXT_INPUT

            widget.set_value("Alice")
            assert widget.get_value() == "Alice"

            widget.focus()
            assert widget._entry is not None

            widget.wipe_sensitive_data()
            assert widget.get_value() == ""
        finally:
            widget.unmount()

    def test_multiline_field_widget(self, tk_root: tk.Tk) -> None:
        """Тест виджета многострочного поля.

        Проверяет создание и отображение многострочного текстового поля,
        операции set/get, очистку и подсчёт строк.
        """
        field_def = FieldDefinition(
            field_id="descr",
            field_type=FieldType.MULTI_LINE_TEXT,
            label="Описание",
            required=False,
        )
        parent = tk.Frame(tk_root)
        widget = MultiLineWidget(parent=parent, field_def=field_def, height=3)
        widget.mount(parent)
        try:
            assert widget.field_id == "descr"
            assert widget.field_type == FieldType.MULTI_LINE_TEXT

            widget.set_value("Line1\nLine2")
            assert widget.get_value() == "Line1\nLine2"
            assert widget.get_line_count() == 2

            widget.clear()
            assert widget.get_value() == ""
            # Пустой Text виджет содержит одну строку
            assert widget.get_line_count() == 1

            widget.wipe_sensitive_data()
            assert widget.get_value() == ""
        finally:
            widget.unmount()

    def test_checkbox_field_widget(self, tk_root: tk.Tk) -> None:
        """Тест виджета чекбокса.

        Проверяет создание и отображение поля-флажка,
        toggle, set/get value и wipe_sensitive_data.
        """
        field_def = FieldDefinition(
            field_id="agree",
            field_type=FieldType.CHECKBOX,
            label="Согласие",
            required=False,
        )
        parent = tk.Frame(tk_root)
        widget = CheckboxWidget(parent=parent, field_def=field_def)
        widget.mount(parent)
        try:
            assert widget.field_id == "agree"
            assert widget.field_type == FieldType.CHECKBOX
            assert not widget.get_value()

            widget.set_value(True)
            assert widget.get_value() is True

            widget.toggle()
            assert widget.get_value() is False

            widget.wipe_sensitive_data()
            assert widget.get_value() is False
        finally:
            widget.unmount()


class TestStructuredFormValidation:
    """Тесты валидации формы."""

    def test_required_field_validation(self, tk_root: tk.Tk) -> None:
        """Тест валидации обязательных полей.

        Проверяет проверку заполнения обязательных полей формы
        и корректную работу с необязательными полями.
        """
        required_def = FieldDefinition(
            field_id="req",
            field_type=FieldType.TEXT_INPUT,
            label="Обязательное",
            required=True,
        )
        parent_req = tk.Frame(tk_root)
        widget_req = TextInputWidget(parent=parent_req, field_def=required_def)
        widget_req.mount(parent_req)
        try:
            widget_req.set_value("")
            assert not widget_req.validate()
            assert not widget_req._is_valid

            widget_req.set_value("filled")
            assert widget_req.validate()
            assert widget_req._is_valid
        finally:
            widget_req.unmount()

        optional_def = FieldDefinition(
            field_id="opt",
            field_type=FieldType.TEXT_INPUT,
            label="Необязательное",
            required=False,
        )
        parent_opt = tk.Frame(tk_root)
        widget_opt = TextInputWidget(parent=parent_opt, field_def=optional_def)
        widget_opt.mount(parent_opt)
        try:
            widget_opt.set_value("")
            assert widget_opt.validate()
            assert widget_opt._is_valid
        finally:
            widget_opt.unmount()

        # Checkbox required
        cb_def = FieldDefinition(
            field_id="cb_req",
            field_type=FieldType.CHECKBOX,
            label="Флажок обязательный",
            required=True,
        )
        parent_cb = tk.Frame(tk_root)
        widget_cb = CheckboxWidget(parent=parent_cb, field_def=cb_def)
        widget_cb.mount(parent_cb)
        try:
            assert not widget_cb.validate()
            widget_cb.set_value(True)
            assert widget_cb.validate()
        finally:
            widget_cb.unmount()

    def test_field_format_validation(self, tk_root: tk.Tk) -> None:
        """Тест валидации формата поля.

        Проверяет проверку соответствия введённых данных формату поля
        и корректное поведение при некорректном regex.
        """
        field_def = FieldDefinition(
            field_id="digits",
            field_type=FieldType.TEXT_INPUT,
            label="Только цифры",
            required=False,
            validation_pattern=r"^\d+$",
        )
        parent = tk.Frame(tk_root)
        widget = TextInputWidget(parent=parent, field_def=field_def)
        widget.mount(parent)
        try:
            widget.set_value("12345")
            assert widget.validate()

            widget.set_value("abc")
            assert not widget.validate()
        finally:
            widget.unmount()

        # Некорректный regex не должен приводить к падению
        bad_def = FieldDefinition(
            field_id="bad_regex",
            field_type=FieldType.TEXT_INPUT,
            label="Плохой regex",
            required=False,
            validation_pattern="[",
        )
        parent_bad = tk.Frame(tk_root)
        widget_bad = TextInputWidget(parent=parent_bad, field_def=bad_def)
        widget_bad.mount(parent_bad)
        try:
            widget_bad.set_value("x")
            assert widget_bad.validate()
        finally:
            widget_bad.unmount()

    def test_field_length_validation(self, tk_root: tk.Tk) -> None:
        """Тест валидации длины поля.

        Проверяет ограничение максимальной длины вводимых данных.
        """
        field_def = FieldDefinition(
            field_id="short",
            field_type=FieldType.TEXT_INPUT,
            label="Короткое",
            required=False,
            max_length=5,
        )
        parent = tk.Frame(tk_root)
        widget = TextInputWidget(parent=parent, field_def=field_def)
        widget.mount(parent)
        try:
            widget.set_value("hello")
            assert widget.validate()

            widget.set_value("hello!")
            assert not widget.validate()
            assert widget._error_message is not None
        finally:
            widget.unmount()


class TestStructuredFormNavigation:
    """Тесты навигации по форме."""

    def test_tab_navigation(
        self,
        mounted_renderer: tuple[StructuredFormModeRenderer, MagicMock],
    ) -> None:
        """Тест навигации по Tab.

        Проверяет переход между полями и управление страницами
        через делегирование внутреннему рендереру.
        """
        renderer, inner_mock = mounted_renderer

        # Делегирование управления страницами
        inner_mock.add_page.return_value = 2
        assert renderer.add_page() == 2
        inner_mock.add_page.assert_called_once()

        inner_mock.remove_page.return_value = True
        assert renderer.remove_page(1) is True
        inner_mock.remove_page.assert_called_once_with(1)

        inner_mock.duplicate_page.return_value = 3
        assert renderer.duplicate_page(1) == 3
        inner_mock.duplicate_page.assert_called_once_with(1)

        inner_mock._current_page_index = 5
        assert renderer.get_current_page() == 5

        renderer.set_current_page(3)
        inner_mock._show_page.assert_called_once_with(3)

        # undo/redo делегируются
        inner_mock.undo.return_value = True
        assert renderer.undo() is True
        inner_mock.undo.assert_called_once()

        inner_mock.redo.return_value = True
        assert renderer.redo() is True
        inner_mock.redo.assert_called_once()

    def test_field_focus_indication(
        self,
        mounted_renderer: tuple[StructuredFormModeRenderer, MagicMock],
    ) -> None:
        """Тест индикации фокуса поля.

        Проверяет визуальное выделение активного поля ввода
        через делегирование выбора поля внутреннему рендереру.
        """
        renderer, inner_mock = mounted_renderer

        renderer.select_field("field_1")
        inner_mock.select_field.assert_called_once_with("field_1")

        inner_mock.delete_field.return_value = True
        assert renderer.delete_field("field_1") is True
        inner_mock.delete_field.assert_called_once_with("field_1")

        # create_field делегируется с правильными аргументами
        field_def = FieldDefinition(
            field_id="new",
            field_type=FieldType.TEXT_INPUT,
            label="Новое",
        )
        inner_mock.create_field.return_value = MagicMock()
        renderer.create_field(field_def)
        inner_mock.create_field.assert_called_once_with(field_def, None)
