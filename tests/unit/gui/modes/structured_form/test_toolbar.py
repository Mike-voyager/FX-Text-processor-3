"""Тесты для StructuredFormToolbar и StructuredFormModeRenderer.

Покрывает критические пути:
- StructuredFormToolbar: set_role, set_status, toggle buttons, field palette
- FieldType enum (локальный): иконки, названия

Author: Mike Voyager
Date: 2026-05
"""

from __future__ import annotations

import tkinter as tk
from unittest.mock import MagicMock

import pytest

from src.documents.constructor.form_status import FormStatus
from src.gui.modes.structured_form.toolbar import FieldType, StructuredFormToolbar
from src.gui.workflow.role_badge import WorkflowRole


@pytest.fixture
def root() -> tk.Tk:
    """Создаёт корневое окно Tkinter."""
    root = tk.Tk()
    yield root
    root.destroy()


# =========================================================================
# FieldType (локальный enum)
# =========================================================================


class TestFieldTypeEnum:
    """Тесты для локального FieldType enum в toolbar."""

    def test_all_have_icons(self) -> None:
        """Все типы полей имеют иконки."""
        for ft in FieldType:
            assert ft.icon != "?", f"FieldType.{ft.name} не имеет иконки"

    def test_all_have_localized_names(self) -> None:
        """Все типы полей имеют локализованные названия."""
        for ft in FieldType:
            assert ft.localized_name != ft.value, f"FieldType.{ft.name} не имеет русского названия"

    def test_icon_not_empty(self) -> None:
        """Иконки не пустые."""
        for ft in FieldType:
            assert len(ft.icon) > 0


# =========================================================================
# StructuredFormToolbar
# =========================================================================


class TestStructuredFormToolbar:
    """Тесты для StructuredFormToolbar."""

    @pytest.fixture
    def toolbar(self, root: tk.Tk) -> StructuredFormToolbar:
        """Создаёт панель инструментов для тестирования."""
        toolbar = StructuredFormToolbar(
            parent=root,
            controller=None,
            mode_manager=None,
        )
        toolbar.mount(root)
        root.update_idletasks()
        return toolbar

    def test_default_role_is_operator(self, toolbar: StructuredFormToolbar) -> None:
        """По умолчанию роль OPERATOR."""
        assert toolbar.get_role() == WorkflowRole.OPERATOR

    def test_set_role(self, toolbar: StructuredFormToolbar) -> None:
        """Установка роли обновляет UI."""
        toolbar.set_role(WorkflowRole.SIGNATORY)
        assert toolbar.get_role() == WorkflowRole.SIGNATORY

    def test_set_role_callback(self, root: tk.Tk) -> None:
        """Callback вызывается при смене роли."""
        role_changes: list[WorkflowRole] = []
        toolbar = StructuredFormToolbar(
            parent=root,
            on_role_change=lambda role: role_changes.append(role),
        )
        toolbar.mount(root)
        root.update_idletasks()

        toolbar.set_role(WorkflowRole.EDITOR)
        assert len(role_changes) == 1
        assert role_changes[0] == WorkflowRole.EDITOR

    def test_default_status_is_draft(self, toolbar: StructuredFormToolbar) -> None:
        """По умолчанию статус DRAFT."""
        assert toolbar.get_status() == FormStatus.DRAFT

    def test_set_status(self, toolbar: StructuredFormToolbar) -> None:
        """Установка статуса обновляет UI."""
        toolbar.set_status(FormStatus.SIGNED)
        assert toolbar.get_status() == FormStatus.SIGNED

    def test_snap_to_grid_default_true(self, toolbar: StructuredFormToolbar) -> None:
        """Snap-to-grid включён по умолчанию."""
        assert toolbar.get_snap_to_grid() is True

    def test_set_snap_to_grid(self, toolbar: StructuredFormToolbar) -> None:
        """Переключение snap-to-grid."""
        toolbar.set_snap_to_grid(False)
        assert toolbar.get_snap_to_grid() is False
        toolbar.set_snap_to_grid(True)
        assert toolbar.get_snap_to_grid() is True

    def test_validation_enabled_default_true(self, toolbar: StructuredFormToolbar) -> None:
        """Валидация включена по умолчанию."""
        assert toolbar.get_validation_enabled() is True

    def test_set_validation_enabled(self, toolbar: StructuredFormToolbar) -> None:
        """Переключение валидации."""
        toolbar.set_validation_enabled(False)
        assert toolbar.get_validation_enabled() is False

    def test_field_type_callback(self, root: tk.Tk) -> None:
        """Callback вызывается при выборе типа поля."""
        selected_types: list[FieldType] = []
        toolbar = StructuredFormToolbar(
            parent=root,
            on_field_add=lambda ft: selected_types.append(ft),
        )
        toolbar.mount(root)
        root.update_idletasks()

        toolbar.set_on_field_add_callback(lambda ft: selected_types.append(ft))
        toolbar._on_field_type_click(FieldType.TEXT)
        assert len(selected_types) == 1
        assert selected_types[0] == FieldType.TEXT

    def test_enable_field_type(self, toolbar: StructuredFormToolbar) -> None:
        """Включение/отключение кнопки типа поля."""
        toolbar.enable_field_type(FieldType.BARCODE, False)
        btn = toolbar._field_buttons.get(FieldType.BARCODE)
        assert btn is not None
        assert str(btn.cget("state")) == "disabled"

        toolbar.enable_field_type(FieldType.BARCODE, True)
        assert str(btn.cget("state")) == "normal"

    def test_wipe_cleanup(self, toolbar: StructuredFormToolbar) -> None:
        """Очистка при демонтировании."""
        toolbar._cleanup()
        assert len(toolbar._field_buttons) == 0
        assert len(toolbar._status_labels) == 0

    def test_role_colors_exist(self) -> None:
        """Для каждой роли определён цвет."""
        for role in WorkflowRole:
            assert role in StructuredFormToolbar.ROLE_COLORS
            color = StructuredFormToolbar.ROLE_COLORS[role]
            assert color.startswith("#")