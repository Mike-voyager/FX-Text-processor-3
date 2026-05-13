"""Тесты для FormCanvas.

Tests:
    - TestFormCanvas: тесты для Canvas с динамической сеткой

Author: Mike Voyager
Date: 2026-04-07
"""

from __future__ import annotations

import tkinter as tk
from unittest.mock import MagicMock

import pytest

from src.documents.types.type_schema import FieldDefinition, FieldType
from src.gui.renderers.form_canvas import FieldPosition, FormCanvas, FormFieldWidget
from src.services.paper_profile_service import PaperProfile, PaperType as PaperTypeEnum


class MockPaperProfile:
    """Мок профиля бумаги для тестирования."""

    def __init__(self) -> None:
        self.width_mm = 210.0
        self.height_mm = 297.0
        self.name = "A4 Test"
        self.left_margin_mm = 13.0
        self.right_margin_mm = 13.0
        self.top_margin_mm = 4.2
        self.bottom_margin_mm = 4.2

    def get_printable_area(self):
        """Возвращает мок printable area."""
        class PrintableArea:
            x = 13.0
            y = 4.2
            width = 184.0
            height = 288.6
        return PrintableArea()


@pytest.fixture
def root() -> tk.Tk:
    """Создаёт корневое окно Tkinter."""
    root = tk.Tk()
    yield root
    root.destroy()


class TestFormCanvas:
    """Тесты для FormCanvas."""

    @pytest.fixture
    def mock_profile(self) -> MockPaperProfile:
        """Создаёт мок профиля бумаги."""
        return MockPaperProfile()

    @pytest.fixture
    def canvas(self, root: tk.Tk, mock_profile: MockPaperProfile) -> FormCanvas:
        """Создаёт FormCanvas для тестирования."""
        canvas = FormCanvas(
            widget_id="test_canvas",
            profile=mock_profile,  # type: ignore[arg-type]
            zoom=1.0,
            show_grid=True,
            show_margins=True,
        )
        canvas.mount(root)
        root.update_idletasks()
        return canvas

    def test_canvas_creation(self, canvas: FormCanvas) -> None:
        """Тест создания Canvas."""
        assert canvas._tk_widget is not None
        assert isinstance(canvas._tk_widget, tk.Canvas)

    def test_canvas_dimensions(self, canvas: FormCanvas) -> None:
        """Тест размеров Canvas."""
        assert canvas._cols > 0
        assert canvas._rows > 0
        assert canvas._canvas_width > 0
        assert canvas._canvas_height > 0

    def test_zoom_levels(self, canvas: FormCanvas) -> None:
        """Тест уровней масштабирования."""
        # Test zoom in
        initial_zoom = canvas._zoom
        canvas.zoom_in()
        assert canvas._zoom > initial_zoom

        # Test zoom out
        canvas.zoom_out()
        assert canvas._zoom <= initial_zoom

        # Test zoom limits
        canvas.set_zoom(0.1)  # Should clamp to MIN_ZOOM
        assert canvas._zoom >= canvas.MIN_ZOOM

        canvas.set_zoom(5.0)  # Should clamp to MAX_ZOOM
        assert canvas._zoom <= canvas.MAX_ZOOM

    def test_dynamic_grid_resize(self, canvas: FormCanvas) -> None:
        """Тест динамического изменения размера сетки."""
        initial_cols = canvas._cols
        initial_rows = canvas._rows

        # Change zoom should affect grid
        canvas.set_zoom(1.5)

        # Grid dimensions should be recalculated
        assert canvas._cols == initial_cols
        assert canvas._rows == initial_rows

    def test_margin_visualization(self, canvas: FormCanvas) -> None:
        """Тест визуализации полей."""
        # Margins should be calculated
        assert canvas._left_margin_px >= 0
        assert canvas._right_margin_px >= 0
        assert canvas._top_margin_px >= 0
        assert canvas._bottom_margin_px >= 0

        # Toggle margins
        canvas.show_margins(False)
        assert canvas._show_margins is False

        canvas.show_margins(True)
        assert canvas._show_margins is True

    def test_grid_visibility(self, canvas: FormCanvas) -> None:
        """Тест видимости сетки."""
        # Grid should be visible by default
        assert canvas._show_grid is True

        # Hide grid
        canvas.show_grid(False)
        assert canvas._show_grid is False

        # Show grid
        canvas.show_grid(True)
        assert canvas._show_grid is True

    def test_snap_to_grid(self, canvas: FormCanvas) -> None:
        """Тест привязки к сетке."""
        # Snap should be enabled by default
        assert canvas._snap_to_grid is True

        # Toggle snap
        canvas.set_snap_to_grid(False)
        assert canvas._snap_to_grid is False

        canvas.set_snap_to_grid(True)
        assert canvas._snap_to_grid is True

    def test_field_creation(self, canvas: FormCanvas) -> None:
        """Тест создания поля."""
        field_def = FieldDefinition(
            field_id="test_field",
            field_type=FieldType.TEXT_INPUT,
            label="Test Field",
        )

        field_widget = canvas.create_field(field_def, x=5, y=5, width=3, height=1)

        assert field_widget is not None
        assert field_widget.field_id == "test_field"
        assert field_widget.position.col == 5
        assert field_widget.position.row == 5
        assert field_widget.position.width == 3
        assert field_widget.position.height == 1
        assert "test_field" in canvas._fields

    def test_field_bounds_calculation(self, canvas: FormCanvas) -> None:
        """Тест расчёта границ поля."""
        field_def = FieldDefinition(
            field_id="test_field",
            field_type=FieldType.TEXT_INPUT,
            label="Test",
        )

        field_widget = FormFieldWidget(
            field_id="test_field",
            field_def=field_def,
            position=FieldPosition(col=2, row=3, width=4, height=2),
        )

        x1, y1, x2, y2 = field_widget.get_bounds(
            cell_width=canvas._cell_width,
            cell_height=canvas._cell_height,
        )

        assert x1 == 2 * canvas._cell_width
        assert y1 == 3 * canvas._cell_height
        assert x2 == (2 + 4) * canvas._cell_width
        assert y2 == (3 + 2) * canvas._cell_height

    def test_field_validation_out_of_bounds(self, canvas: FormCanvas) -> None:
        """Тест валидации позиции - за границами."""
        is_valid, error = canvas.validate_field_position(
            field_id="test",
            x=-1,  # Negative
            y=0,
            width=1,
            height=1,
        )
        assert is_valid is False
        assert error == "out_of_bounds"

        # Too far right
        is_valid, error = canvas.validate_field_position(
            field_id="test",
            x=canvas._cols - 1,
            y=0,
            width=5,  # Would exceed bounds
            height=1,
        )
        assert is_valid is False
        assert error == "out_of_bounds"

    def test_field_validation_in_margin(self, canvas: FormCanvas) -> None:
        """Тест валидации позиции - внутри margin."""
        # Try to place field in left margin
        is_valid, error = canvas.validate_field_position(
            field_id="test",
            x=0,
            y=0,
            width=1,
            height=1,
        )

        # Should fail if in margin
        if canvas._left_margin_px > 0:
            margin_cols = canvas._left_margin_px // canvas._cell_width
            if margin_cols > 0:
                is_valid, error = canvas.validate_field_position(
                    field_id="test",
                    x=0,
                    y=0,
                    width=1,
                    height=1,
                )
                assert error == "in_margin"

    def test_field_validation_overlap(self, canvas: FormCanvas) -> None:
        """Тест валидации позиции - перекрытие полей."""
        field_def1 = FieldDefinition(
            field_id="field1",
            field_type=FieldType.TEXT_INPUT,
            label="Field 1",
        )
        field_def2 = FieldDefinition(
            field_id="field2",
            field_type=FieldType.TEXT_INPUT,
            label="Field 2",
        )

        # Create first field
        canvas.create_field(field_def1, x=10, y=10, width=5, height=2)

        # Try to create second field overlapping
        is_valid, error = canvas.validate_field_position(
            field_id="field2",
            x=12,  # Overlaps with field1 (10-14)
            y=11,  # Overlaps with field1 (10-11)
            width=3,
            height=2,
        )

        assert is_valid is False
        assert error == "overlap"

    def test_profile_change_recalculates_grid(self, canvas: FormCanvas, mock_profile: MockPaperProfile) -> None:
        """Тест что смена профиля пересчитывает сетку."""
        initial_cols = canvas._cols
        initial_rows = canvas._rows

        # Create new profile with different dimensions
        new_profile = MockPaperProfile()
        new_profile.width_mm = 297.0  # A3 width
        new_profile.height_mm = 420.0  # A3 height

        canvas.set_profile(new_profile)  # type: ignore[arg-type]

        # Grid should be recalculated
        assert canvas._profile is new_profile

    def test_move_field(self, canvas: FormCanvas) -> None:
        """Тест перемещения поля."""
        field_def = FieldDefinition(
            field_id="move_test",
            field_type=FieldType.TEXT_INPUT,
            label="Move Test",
        )

        field_widget = canvas.create_field(field_def, x=5, y=5, width=2, height=1)

        # Move field
        result = canvas.move_field("move_test", new_x=10, new_y=15)

        assert result is True
        assert field_widget.position.col == 10
        assert field_widget.position.row == 15

    def test_move_field_invalid(self, canvas: FormCanvas) -> None:
        """Тест перемещения поля на невалидную позицию."""
        field_def = FieldDefinition(
            field_id="move_test",
            field_type=FieldType.TEXT_INPUT,
            label="Move Test",
        )

        canvas.create_field(field_def, x=5, y=5, width=2, height=1)

        # Try to move out of bounds
        result = canvas.move_field("move_test", new_x=-1, new_y=-1)
        assert result is False

    def test_remove_field(self, canvas: FormCanvas) -> None:
        """Тест удаления поля."""
        field_def = FieldDefinition(
            field_id="remove_test",
            field_type=FieldType.TEXT_INPUT,
            label="Remove Test",
        )

        canvas.create_field(field_def, x=5, y=5, width=2, height=1)

        # Remove field
        result = canvas.remove_field("remove_test")

        assert result is True
        assert "remove_test" not in canvas._fields

    def test_select_field(self, canvas: FormCanvas) -> None:
        """Тест выделения поля."""
        field_def = FieldDefinition(
            field_id="select_test",
            field_type=FieldType.TEXT_INPUT,
            label="Select Test",
        )

        field_widget = canvas.create_field(field_def, x=5, y=5, width=2, height=1)

        # Select field
        canvas.select_field("select_test")

        assert field_widget.selected is True
        assert canvas._selected_field_id == "select_test"

    def test_get_field_at(self, canvas: FormCanvas) -> None:
        """Тест получения поля по координатам."""
        field_def = FieldDefinition(
            field_id="at_test",
            field_type=FieldType.TEXT_INPUT,
            label="At Test",
        )

        canvas.create_field(field_def, x=10, y=10, width=5, height=3)

        # Get field at position inside
        field = canvas.get_field_at(12, 11)
        assert field is not None
        assert field.field_id == "at_test"

        # Get field at position outside
        field = canvas.get_field_at(20, 20)
        assert field is None

    def test_get_printable_bounds(self, canvas: FormCanvas) -> None:
        """Тест получения границ печатной области."""
        left, top, right, bottom = canvas.get_printable_bounds()

        assert left >= 0
        assert top >= 0
        assert right > left
        assert bottom > top
        assert right <= canvas._cols
        assert bottom <= canvas._rows

    def test_grid_to_pixel_conversion(self, canvas: FormCanvas) -> None:
        """Тест конвертации grid -> pixel."""
        x, y = canvas._grid_to_pixel(5, 10)

        assert x == 5 * canvas._cell_width
        assert y == 10 * canvas._cell_height

    def test_pixel_to_grid_conversion(self, canvas: FormCanvas) -> None:
        """Тест конвертации pixel -> grid."""
        col, row = canvas._pixel_to_grid(
            5 * canvas._cell_width,
            10 * canvas._cell_height,
        )

        assert col == 5
        assert row == 10

    def test_clear_fields(self, canvas: FormCanvas) -> None:
        """Тест очистки всех полей."""
        # Create multiple fields
        for i in range(3):
            field_def = FieldDefinition(
                field_id=f"field_{i}",
                field_type=FieldType.TEXT_INPUT,
                label=f"Field {i}",
            )
            canvas.create_field(field_def, x=i * 10, y=i * 5, width=2, height=1)

        assert len(canvas._fields) == 3

        canvas.clear_fields()

        assert len(canvas._fields) == 0

    def test_fields_dict_isolation(self, canvas: FormCanvas) -> None:
        """Тест изоляции словаря полей."""
        field_def = FieldDefinition(
            field_id="iso_test",
            field_type=FieldType.TEXT_INPUT,
            label="Isolation Test",
        )

        canvas.create_field(field_def, x=5, y=5, width=2, height=1)

        # Get fields dict
        fields = canvas.get_fields()
        assert len(fields) == 1

        # Modifying returned dict should not affect canvas
        fields.clear()
        assert len(canvas._fields) == 1


class TestOverlapDetection:
    """Тесты для обнаружения перекрытий полей."""

    @pytest.fixture
    def mock_profile(self) -> MockPaperProfile:
        """Создаёт мок профиля бумаги."""
        return MockPaperProfile()

    @pytest.fixture
    def canvas(self, root: tk.Tk, mock_profile: MockPaperProfile) -> FormCanvas:
        """Создаёт FormCanvas для тестирования."""
        canvas = FormCanvas(
            widget_id="test_overlap_canvas",
            profile=mock_profile,  # type: ignore[arg-type]
            zoom=1.0,
            show_grid=True,
            show_margins=False,
        )
        canvas.mount(root)
        root.update_idletasks()
        return canvas

    def test_check_overlap_no_overlap(self, canvas: FormCanvas) -> None:
        """Тест check_overlap когда перекрытия нет."""
        field_def = FieldDefinition(
            field_id="field1",
            field_type=FieldType.TEXT_INPUT,
            label="Field 1",
        )
        canvas.create_field(field_def, x=10, y=10, width=3, height=2)

        # No overlap - adjacent field
        has_overlap = canvas.check_overlap("field2", x=14, y=10, width=3, height=2)
        assert has_overlap is False

    def test_check_overlap_with_overlap(self, canvas: FormCanvas) -> None:
        """Тест check_overlap когда есть перекрытие."""
        field_def1 = FieldDefinition(
            field_id="field1",
            field_type=FieldType.TEXT_INPUT,
            label="Field 1",
        )
        canvas.create_field(field_def1, x=10, y=10, width=3, height=2)

        field_def2 = FieldDefinition(
            field_id="field2",
            field_type=FieldType.TEXT_INPUT,
            label="Field 2",
        )
        canvas.create_field(field_def2, x=12, y=11, width=3, height=2)

        # Check overlap with field1
        has_overlap = canvas.check_overlap("field2", x=11, y=10, width=3, height=2)
        assert has_overlap is True

    def test_check_overlap_excludes_self(self, canvas: FormCanvas) -> None:
        """Тест что check_overlap исключает self."""
        field_def = FieldDefinition(
            field_id="self_field",
            field_type=FieldType.TEXT_INPUT,
            label="Self Field",
        )
        canvas.create_field(field_def, x=10, y=10, width=3, height=2)

        # Should not report overlap with self
        has_overlap = canvas.check_overlap("self_field", x=10, y=10, width=3, height=2)
        assert has_overlap is False

    def test_check_overlap_corner_touch(self, canvas: FormCanvas) -> None:
        """Тест check_overlap при касании углов (не перекрытие)."""
        field_def1 = FieldDefinition(
            field_id="field1",
            field_type=FieldType.TEXT_INPUT,
            label="Field 1",
        )
        canvas.create_field(field_def1, x=10, y=10, width=3, height=2)

        # Field at corner - just touching
        has_overlap = canvas.check_overlap("field2", x=13, y=12, width=2, height=2)
        assert has_overlap is False

    def test_set_overlap_preview(self, canvas: FormCanvas) -> None:
        """Тест set_overlap_preview."""
        # Create field
        field_def = FieldDefinition(
            field_id="field1",
            field_type=FieldType.TEXT_INPUT,
            label="Field 1",
        )
        canvas.create_field(field_def, x=10, y=10, width=3, height=2)

        # Show overlap preview
        canvas.set_overlap_preview("field1", x=12, y=11, width=3, height=2, show=True)

        # Preview should be created
        assert canvas._drag_overlap_item is not None

        # Hide preview
        canvas.set_overlap_preview("field1", x=12, y=11, width=3, height=2, show=False)
        assert canvas._drag_overlap_item is None

    def test_clear_overlap_preview(self, canvas: FormCanvas) -> None:
        """Тест clear_overlap_preview."""
        # Create field and show preview
        field_def = FieldDefinition(
            field_id="field1",
            field_type=FieldType.TEXT_INPUT,
            label="Field 1",
        )
        canvas.create_field(field_def, x=10, y=10, width=3, height=2)
        canvas.set_overlap_preview("field1", x=12, y=11, width=3, height=2, show=True)

        assert canvas._drag_overlap_item is not None

        # Clear preview
        canvas.clear_overlap_preview()
        assert canvas._drag_overlap_item is None

    def test_drag_prevents_overlap_drop(self, canvas: FormCanvas) -> None:
        """Тест что drag предотвращает drop при перекрытии."""
        field_def1 = FieldDefinition(
            field_id="field1",
            field_type=FieldType.TEXT_INPUT,
            label="Field 1",
        )
        canvas.create_field(field_def1, x=10, y=10, width=3, height=2)

        field_def2 = FieldDefinition(
            field_id="field2",
            field_type=FieldType.TEXT_INPUT,
            label="Field 2",
        )
        canvas.create_field(field_def2, x=15, y=10, width=3, height=2)

        # Try to move field2 to overlapping position
        result = canvas.move_field("field2", new_x=11, new_y=10)
        assert result is False

        # Field should stay at original position
        field2 = canvas._fields["field2"]
        assert field2.position.col == 15
