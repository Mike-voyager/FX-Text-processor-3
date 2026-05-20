"""Tests for DesignerTab.

Tests three-panel layout, page management, grid toggle, zoom levels,
and undo/redo integration for the Form Designer.

Coverage target: ≥90%
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from src.gui.form_designer.designer_tab import DesignerTab, DesignerPage, FieldPaletteItem
from src.gui.form_designer.property_panel import PropertyPanel
from src.documents.types.type_schema import FieldType
from src.services.paper_format_service import PaperProfile


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def root():
    """Create a Tk root window for tests."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def designer_tab(root):
    """Create a mounted DesignerTab instance."""
    tab = DesignerTab(
        parent=root,
        document=None,
        controller=None,
    )
    tab.mount(root)
    yield tab
    tab.unmount()


@pytest.fixture
def sample_profile():
    """Create a sample paper profile."""
    from src.services.paper_format_service import PaperSize, Orientation, PaperType, TrayType
    
    return PaperProfile(
        id="a4_10cpi",
        name="A4 10 CPI",
        paper_size=PaperSize.A4,
        orientation=Orientation.PORTRAIT,
        paper_type=PaperType.PLAIN,
        weight=80,
        tray=TrayType.AUTO,
    )


# =============================================================================
# TEST: Three-Panel Layout
# =============================================================================


class TestThreePanelLayout:
    """Test suite for three-panel layout."""

    def test_three_panel_layout_created(self, root):
        """Test that three-panel layout is created."""
        tab = DesignerTab(parent=root, document=None)
        tab.mount(root)

        # Check that frames are created
        assert tab._left_frame is not None
        assert tab._center_frame is not None
        assert tab._right_frame is not None
        assert tab._bottom_frame is not None

        tab.unmount()

    def test_left_panel_width(self, designer_tab):
        """Test left panel has minimum width."""
        assert designer_tab._left_frame is not None
        # Grid info should exist for the left frame
        info = designer_tab._left_frame.grid_info()
        assert "column" in info
        assert info.get("column") == 0

    def test_center_panel_expands(self, designer_tab):
        """Test center panel expands to fill space."""
        assert designer_tab._center_frame is not None
        info = designer_tab._center_frame.grid_info()
        assert info.get("column") == 1

    def test_right_panel_width(self, designer_tab):
        """Test right panel has minimum width."""
        assert designer_tab._right_frame is not None
        info = designer_tab._right_frame.grid_info()
        assert info.get("column") == 2

    def test_field_palette_created(self, designer_tab):
        """Test field palette is created in left panel."""
        assert designer_tab._field_palette is not None
        assert designer_tab._left_frame is not None

    def test_property_panel_created(self, designer_tab):
        """Test property panel instance is created in right panel."""
        assert designer_tab._property_panel_instance is not None
        assert designer_tab._property_panel is not None

    def test_scrollable_canvas_created(self, designer_tab):
        """Test scrollable canvas is created in center panel."""
        assert designer_tab._outer_canvas is not None
        assert designer_tab._scrollbar is not None
        assert designer_tab._scrollable_frame is not None


# =============================================================================
# TEST: Add Page
# =============================================================================


class TestAddPage:
    """Test suite for page management."""

    def test_add_page_increases_count(self, designer_tab, sample_profile):
        """Test add_page increases page count."""
        initial_count = len(designer_tab.get_pages())

        designer_tab.add_page(sample_profile)

        assert len(designer_tab.get_pages()) == initial_count + 1

    def test_add_page_returns_index(self, designer_tab, sample_profile):
        """Test add_page returns page index."""
        index = designer_tab.add_page(sample_profile)

        assert index == 0

        # Add another page
        index2 = designer_tab.add_page(sample_profile)
        assert index2 == 1

    def test_add_page_creates_designer_page(self, designer_tab, sample_profile):
        """Test add_page creates DesignerPage instance."""
        index = designer_tab.add_page(sample_profile)

        pages = designer_tab.get_pages()
        assert len(pages) == 1
        assert isinstance(pages[0], DesignerPage)
        assert pages[0].index == index
        assert pages[0].profile == sample_profile

    def test_add_page_creates_canvas(self, designer_tab, sample_profile):
        """Test add_page creates FormCanvas."""
        designer_tab.add_page(sample_profile)

        pages = designer_tab.get_pages()
        assert pages[0].canvas is not None

    def test_add_page_updates_page_count_label(self, designer_tab, sample_profile):
        """Test add_page updates page count label."""
        designer_tab.add_page(sample_profile)

        assert designer_tab._page_count_label is not None
        assert "1" in designer_tab._page_count_label.cget("text")

    def test_add_multiple_pages(self, designer_tab, sample_profile):
        """Test adding multiple pages."""
        for i in range(5):
            index = designer_tab.add_page(sample_profile)
            assert index == i

        assert len(designer_tab.get_pages()) == 5


# =============================================================================
# TEST: Continuous Scroll
# =============================================================================


class TestContinuousScroll:
    """Test suite for continuous scroll layout."""

    def test_scrollable_frame_exists(self, designer_tab):
        """Test scrollable frame exists."""
        assert designer_tab._scrollable_frame is not None

    def test_scrollbar_configured(self, designer_tab):
        """Test scrollbar is configured."""
        assert designer_tab._scrollbar is not None
        assert designer_tab._outer_canvas is not None

        # Scrollbar should be linked to canvas
        yscrollcommand = designer_tab._outer_canvas.cget("yscrollcommand")
        assert yscrollcommand is not None

    def test_pages_stacked_vertically(self, designer_tab, sample_profile):
        """Test pages are stacked vertically in scrollable frame."""
        designer_tab.add_page(sample_profile)
        designer_tab.add_page(sample_profile)

        pages = designer_tab.get_pages()
        assert len(pages) == 2

        # Each page should have a frame
        for page in pages:
            assert page.frame is not None


# =============================================================================
# TEST: Grid Toggle
# =============================================================================


class TestGridToggle:
    """Test suite for grid toggle functionality."""

    def test_grid_visible_by_default(self, designer_tab):
        """Test grid is visible by default."""
        assert designer_tab._show_grid is True

    def test_toggle_grid_changes_state(self, designer_tab):
        """Test toggle_grid changes grid visibility state."""
        designer_tab.toggle_grid(False)
        assert designer_tab._show_grid is False

        designer_tab.toggle_grid(True)
        assert designer_tab._show_grid is True

    def test_toggle_grid_no_argument_toggles(self, designer_tab):
        """Test toggle_grid without argument toggles state."""
        initial_state = designer_tab._show_grid

        designer_tab.toggle_grid()
        assert designer_tab._show_grid is not initial_state

    def test_toggle_grid_updates_canvas(self, designer_tab, sample_profile):
        """Test toggle_grid updates all page canvases."""
        designer_tab.add_page(sample_profile)
        designer_tab.add_page(sample_profile)

        with patch.object(designer_tab._pages[0].canvas, 'show_grid') as mock1, \
             patch.object(designer_tab._pages[1].canvas, 'show_grid') as mock2:
            designer_tab.toggle_grid(False)

            mock1.assert_called_once_with(False)
            mock2.assert_called_once_with(False)


# =============================================================================
# TEST: Zoom Levels
# =============================================================================


class TestZoomLevels:
    """Test suite for zoom functionality."""

    def test_default_zoom_is_1(self, designer_tab):
        """Test default zoom is 1.0."""
        assert designer_tab._zoom == 1.0

    def test_set_zoom_changes_zoom(self, designer_tab):
        """Test set_zoom changes zoom level."""
        designer_tab.set_zoom(1.5)
        assert designer_tab._zoom == 1.5

    def test_set_zoom_updates_label(self, designer_tab):
        """Test set_zoom updates zoom label."""
        designer_tab.set_zoom(1.5)

        assert designer_tab._zoom_label is not None
        assert designer_tab._zoom_label.cget("text") == "150%"

    def test_set_zoom_clamps_minimum(self, designer_tab):
        """Test set_zoom clamps to minimum 0.5."""
        designer_tab.set_zoom(0.1)
        assert designer_tab._zoom == 0.5

    def test_set_zoom_clamps_maximum(self, designer_tab):
        """Test set_zoom clamps to maximum 2.0."""
        designer_tab.set_zoom(5.0)
        assert designer_tab._zoom == 2.0

    def test_set_zoom_updates_all_pages(self, designer_tab, sample_profile):
        """Test set_zoom updates zoom on all pages."""
        designer_tab.add_page(sample_profile)
        designer_tab.add_page(sample_profile)

        with patch.object(designer_tab._pages[0].canvas, 'set_zoom') as mock1, \
             patch.object(designer_tab._pages[1].canvas, 'set_zoom') as mock2:
            designer_tab.set_zoom(1.5)

            mock1.assert_called_once_with(1.5)
            mock2.assert_called_once_with(1.5)


# =============================================================================
# TEST: Undo/Redo Integration
# =============================================================================


class TestUndoRedoIntegration:
    """Test suite for undo/redo integration."""

    def test_undo_returns_false_when_empty(self, designer_tab):
        """Test undo returns False when stack is empty."""
        result = designer_tab.undo()
        assert result is False

    def test_redo_returns_false_when_empty(self, designer_tab):
        """Test redo returns False when stack is empty."""
        result = designer_tab.redo()
        assert result is False

    def test_undo_executes_command(self, designer_tab):
        """Test undo executes undo on command stack."""
        from src.gui.core.commands.command import Command

        class TestCommand(Command):
            def __init__(self):
                super().__init__("Test command")
                self.undone = False

            def execute(self) -> None:
                super().execute()

            def undo(self) -> None:
                super().undo()
                self.undone = True

            def redo(self) -> None:
                super().redo()

        cmd = TestCommand()
        cmd.execute()
        designer_tab._command_stack.execute(cmd)

        # Undo should call command.undo()
        designer_tab.undo()
        assert cmd.undone is True

    def test_clear_empties_command_stack(self, designer_tab):
        """Test clear_all empties command stack."""
        from src.gui.core.commands.command import Command

        class TestCommand(Command):
            def __init__(self):
                super().__init__("Test command")
                self.undone = False

            def execute(self) -> None:
                super().execute()

            def undo(self) -> None:
                super().undo()
                self.undone = True

            def redo(self) -> None:
                super().redo()

        cmd = TestCommand()
        cmd.execute()
        designer_tab._command_stack.execute(cmd)

        assert designer_tab._command_stack.can_undo() is True

        designer_tab.clear_all()

        assert designer_tab._command_stack.can_undo() is False


# =============================================================================
# TEST: Palette Items
# =============================================================================


class TestPaletteItems:
    """Test suite for palette items."""

    def test_palette_items_defined(self, designer_tab):
        """Test PALETTE_ITEMS are defined."""
        assert len(designer_tab.PALETTE_ITEMS) > 0

    def test_palette_items_have_required_fields(self, designer_tab):
        """Test palette items have required fields."""
        for item in designer_tab.PALETTE_ITEMS:
            assert hasattr(item, 'field_type')
            assert hasattr(item, 'icon')
            assert hasattr(item, 'label')
            assert hasattr(item, 'description')

    def test_palette_items_cover_basic_types(self, designer_tab):
        """Test palette covers basic field types."""
        field_types = {item.field_type for item in designer_tab.PALETTE_ITEMS}

        assert FieldType.TEXT_INPUT in field_types
        assert FieldType.NUMBER_INPUT in field_types
        assert FieldType.CHECKBOX in field_types


# =============================================================================
# TEST: Field Selection
# =============================================================================


class TestFieldSelection:
    """Test suite for field selection."""

    def test_current_field_initially_none(self, designer_tab):
        """Test current field is initially None."""
        assert designer_tab.get_current_field() is None

    def test_on_field_select_updates_current(self, designer_tab, sample_profile):
        """Test on_field_select updates current field."""
        # Create a mock field widget
        mock_field = MagicMock()
        mock_field.field_id = "test_field"
        mock_field.selected = False

        designer_tab.on_field_select(mock_field)

        assert designer_tab.get_current_field() == mock_field

    def test_on_field_select_deselects_previous(self, designer_tab):
        """Test on_field_select deselects previous field."""
        mock_field1 = MagicMock()
        mock_field1.field_id = "field1"
        mock_field1.selected = False

        mock_field2 = MagicMock()
        mock_field2.field_id = "field2"
        mock_field2.selected = False

        designer_tab.on_field_select(mock_field1)
        designer_tab.on_field_select(mock_field2)

        assert mock_field1.selected is False
        assert mock_field2.selected is True


# =============================================================================
# TEST: Page Removal
# =============================================================================


class TestPageRemoval:
    """Test suite for page removal."""

    def test_remove_page_decreases_count(self, designer_tab, sample_profile):
        """Test remove_page decreases page count."""
        designer_tab.add_page(sample_profile)
        designer_tab.add_page(sample_profile)

        assert len(designer_tab.get_pages()) == 2

        designer_tab.remove_page(0)

        assert len(designer_tab.get_pages()) == 1

    def test_remove_page_raises_on_invalid_index(self, designer_tab):
        """Test remove_page raises IndexError on invalid index."""
        with pytest.raises(IndexError):
            designer_tab.remove_page(0)


# =============================================================================
# TEST: Form Validation
# =============================================================================


class TestFormValidation:
    """Test suite for form validation."""

    def test_validate_form_returns_report(self, designer_tab):
        """Test validate_form returns ValidationReport."""
        from src.documents.constructor.form_constructor import ValidationReport

        report = designer_tab.validate_form()

        assert isinstance(report, ValidationReport)

    def test_validate_form_empty_is_valid(self, designer_tab):
        """Test empty form is valid."""
        report = designer_tab.validate_form()

        assert report.is_valid is True


# =============================================================================
# TEST: PropertyPanel Integration
# =============================================================================


class TestPropertyPanelIntegration:
    """Test suite for PropertyPanel integration into DesignerTab."""

    def test_property_panel_instance_created(self, designer_tab):
        """Test PropertyPanel instance is created."""
        assert designer_tab._property_panel_instance is not None
        assert isinstance(designer_tab._property_panel_instance, PropertyPanel)

    def test_update_property_panel_binds_field(self, designer_tab, sample_profile):
        """Test _update_property_panel binds current field."""
        designer_tab.add_page(sample_profile)
        mock_field = MagicMock()
        mock_field.field_id = "test_field"
        mock_field.field_def = MagicMock()
        mock_field.field_def.label = "Test"
        mock_field.field_def.label_i18n = {"ru": "Тест"}
        mock_field.field_def.required = True
        mock_field.field_def.validation_pattern = None
        mock_field.field_def.min_value = None
        mock_field.field_def.max_value = None
        mock_field.field_def.default_value = None
        mock_field.field_def.autocomplete_source = None
        mock_field.position = MagicMock()
        mock_field.position.col = 5
        mock_field.position.row = 3
        mock_field.position.width = 10
        mock_field.position.height = 1

        designer_tab._current_field = mock_field
        designer_tab._update_property_panel(mock_field)

        panel = designer_tab._property_panel_instance
        assert panel is not None
        assert panel.get_bound_field() == mock_field

    def test_on_panel_property_change_no_field(self, designer_tab):
        """Test property change callback does nothing when no field selected."""
        designer_tab._current_field = None
        result = designer_tab._on_panel_property_change("label", "New")
        assert result is None

    def test_on_panel_property_change_label(self, designer_tab, sample_profile):
        """Test label property change uses on_property_change."""
        from src.gui.form_designer.types import DesignerPage

        designer_tab.add_page(sample_profile)
        mock_field = MagicMock()
        mock_field.field_id = "test_field"
        mock_field.field_def = MagicMock()
        mock_field.field_def.label = "Old"
        mock_field.position = MagicMock()

        designer_tab._current_field = mock_field
        p = designer_tab._pages[0]
        designer_tab._pages[0] = DesignerPage(
            index=p.index, profile=p.profile, canvas=p.canvas,
            frame=p.frame, fields=[mock_field], page_break_id=p.page_break_id,
        )
        designer_tab._panel_state_cache = {"label": "Old"}

        with patch.object(designer_tab, "on_property_change") as mock_change:
            designer_tab._on_panel_property_change("label", "New")
            mock_change.assert_called_once_with("test_field", "label", "New")

    def test_on_panel_property_change_position(self, designer_tab, sample_profile):
        """Test position property change creates FieldMoveCommand."""
        from dataclasses import dataclass
        from src.gui.form_designer.types import DesignerPage
        from src.gui.renderers.form_canvas import FieldPosition
        from src.gui.core.commands.design_commands import FieldMoveCommand

        @dataclass
        class MockFieldDef:
            field_id: str = "test_field"
            label: str = "Test"
            label_i18n: dict = field(default_factory=dict)
            required: bool = True
            readonly: bool = False
            validation_pattern: str | None = None
            min_value: float | None = None
            max_value: float | None = None
            default_value: Any = None
            autocomplete_source: str | None = None

        designer_tab.add_page(sample_profile)
        mock_field = MagicMock()
        mock_field.field_id = "test_field"
        mock_field.position = FieldPosition(col=5, row=3, width=10, height=1)
        mock_field.field_def = MockFieldDef()

        designer_tab._current_field = mock_field
        p = designer_tab._pages[0]
        designer_tab._pages[0] = DesignerPage(
            index=p.index, profile=p.profile, canvas=p.canvas,
            frame=p.frame, fields=[mock_field], page_break_id=p.page_break_id,
        )
        designer_tab._panel_state_cache = {"position": mock_field.position}

        with patch(
            "src.gui.core.commands.design_commands.FieldMoveCommand",
        ) as MockCmd:
            with patch.object(designer_tab._command_stack, "execute"):
                designer_tab._on_panel_property_change("x", "10")
                MockCmd.assert_called_once()
                MockCmd.return_value.execute.assert_called_once()

    def test_on_panel_field_duplicate(self, designer_tab, sample_profile):
        """Test duplicate calls on_field_create."""
        from dataclasses import dataclass
        from src.documents.types.type_schema import FieldType as FT
        from src.gui.form_designer.types import DesignerPage

        @dataclass
        class MockFieldDef:
            field_id: str = "test_field"
            field_type: FT = FT.TEXT_INPUT
            label: str = "Test"
            label_i18n: dict = field(default_factory=dict)
            required: bool = True
            readonly: bool = False

        designer_tab.add_page(sample_profile)
        mock_field = MagicMock()
        mock_field.field_id = "test_field"
        mock_field.field_def = MockFieldDef()
        mock_field.position = MagicMock()
        mock_field.position.col = 5
        mock_field.position.row = 3

        designer_tab._current_field = mock_field
        p = designer_tab._pages[0]
        designer_tab._pages[0] = DesignerPage(
            index=p.index, profile=p.profile, canvas=p.canvas,
            frame=p.frame, fields=[mock_field], page_break_id=p.page_break_id,
        )

        with patch.object(designer_tab, "on_field_create") as mock_create:
            designer_tab._on_panel_field_duplicate()
            mock_create.assert_called_once()
            args, kwargs = mock_create.call_args
            # args = (field_type, x, y, page_index)
            assert args[1] == 6
            assert args[2] == 4
            assert args[3] == 0

    def _create_test_command(self):
        """Create a valid Command object for undo/redo tests."""
        from src.gui.core.commands.command import Command

        class TestCommand(Command):
            def execute(self):
                pass

            def undo(self):
                pass

            def redo(self):
                pass

        return TestCommand("test")

    def test_undo_refreshes_panel(self, designer_tab):
        """Test undo refreshes property panel."""
        with patch.object(designer_tab, "_refresh_panel_after_command") as mock_refresh:
            cmd = self._create_test_command()
            designer_tab._command_stack.execute(cmd)
            designer_tab.undo()
            mock_refresh.assert_called_once()

    def test_redo_refreshes_panel(self, designer_tab):
        """Test redo refreshes property panel."""
        with patch.object(designer_tab, "_refresh_panel_after_command") as mock_refresh:
            cmd = self._create_test_command()
            designer_tab._command_stack.execute(cmd)
            designer_tab.undo()
            designer_tab.redo()
            assert mock_refresh.call_count == 2


# =============================================================================
# TEST: DesignerTab Cleanup
# =============================================================================


class TestDesignerTabCleanup:
    """Test suite for cleanup."""

    def test_cleanup_clears_panel_state(self, designer_tab):
        """Test cleanup clears panel state cache."""
        designer_tab._panel_state_cache["key"] = "value"
        designer_tab._cleanup()
        assert len(designer_tab._panel_state_cache) == 0

    def test_cleanup_unmounts_property_panel(self, designer_tab):
        """Test cleanup unmounts property panel instance."""
        designer_tab._cleanup()
        assert designer_tab._property_panel_instance is None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.form_designer.designer_tab"])
