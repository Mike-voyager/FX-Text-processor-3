"""Tests for PropertyPanel.

Tests field binding, property change callbacks, two-way binding,
and validation error display.

Coverage target: ≥90%
"""

from __future__ import annotations

import tkinter as tk
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from src.gui.form_designer.property_panel import PropertyPanel, SectionFrame
from src.gui.renderers.form_canvas import FormFieldWidget
from src.documents.types.type_schema import FieldDefinition, FieldType


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
def mock_callbacks():
    """Create mock callbacks for panel."""
    return {
        "on_property_change": MagicMock(),
        "on_field_delete": MagicMock(),
        "on_field_duplicate": MagicMock(),
    }


@pytest.fixture
def property_panel(root, mock_callbacks):
    """Create a mounted PropertyPanel instance."""
    panel = PropertyPanel(
        parent=root,
        on_property_change=mock_callbacks["on_property_change"],
        on_field_delete=mock_callbacks["on_field_delete"],
        on_field_duplicate=mock_callbacks["on_field_duplicate"],
    )
    panel.mount(root)
    yield panel
    panel.unmount()


@pytest.fixture
def mock_field_widget():
    """Create a mock FormFieldWidget."""
    field_def = FieldDefinition(
        field_id="test_field",
        field_type=FieldType.TEXT_INPUT,
        label="Test Label",
        required=True,
    )

    # Create mock position
    from dataclasses import dataclass

    @dataclass
    class MockPosition:
        col: int = 5
        row: int = 3
        width: int = 10
        height: int = 1

    widget = MagicMock(spec=FormFieldWidget)
    widget.field_id = "test_field"
    widget.field_def = field_def
    widget.position = MockPosition()

    return widget


# =============================================================================
# TEST: SectionFrame
# =============================================================================


class TestSectionFrame:
    """Test suite for collapsible section frame."""

    def test_section_frame_creation(self, root):
        """Test SectionFrame creation."""
        section = SectionFrame(root, "Test Section")
        assert section is not None
        assert section._title == "Test Section"

    def test_section_frame_collapsed_initially(self, root):
        """Test SectionFrame can be created collapsed."""
        section = SectionFrame(root, "Test Section", is_collapsed=True)
        assert section._is_collapsed is True

    def test_section_frame_expand(self, root):
        """Test SectionFrame expand."""
        section = SectionFrame(root, "Test Section", is_collapsed=True)
        section.expand()
        assert section._is_collapsed is False

    def test_section_frame_collapse(self, root):
        """Test SectionFrame collapse."""
        section = SectionFrame(root, "Test Section", is_collapsed=False)
        section.collapse()
        assert section._is_collapsed is True

    def test_section_frame_toggle(self, root):
        """Test SectionFrame toggle."""
        section = SectionFrame(root, "Test Section", is_collapsed=False)
        section._on_toggle(None)
        assert section._is_collapsed is True


# =============================================================================
# TEST: Bind to Field
# =============================================================================


class TestBindToField:
    """Test suite for field binding."""

    def test_bind_to_field_sets_bound_field(self, property_panel, mock_field_widget):
        """Test bind_to_field sets bound field."""
        property_panel.bind_to_field(mock_field_widget)

        assert property_panel.get_bound_field() == mock_field_widget

    def test_bind_to_field_populates_values(self, property_panel, mock_field_widget):
        """Test bind_to_field populates field values."""
        property_panel.bind_to_field(mock_field_widget)

        # Check that values are populated
        assert property_panel._prop_vars.get("field_id") is not None
        assert property_panel._prop_vars.get("label") is not None

    def test_bind_to_field_none_clears_values(self, property_panel, mock_field_widget):
        """Test bind_to_field with None clears values."""
        property_panel.bind_to_field(mock_field_widget)
        property_panel.bind_to_field(None)

        assert property_panel.get_bound_field() is None


# =============================================================================
# TEST: Property Change Callback
# =============================================================================


class TestPropertyChangeCallback:
    """Test suite for property change callback."""

    def test_property_change_callback_invoked(self, property_panel, mock_callbacks, mock_field_widget):
        """Test on_property_change callback is invoked."""
        property_panel.bind_to_field(mock_field_widget)

        # Simulate a property change
        property_panel._on_prop_change("label", "New Label")

        mock_callbacks["on_property_change"].assert_called_once_with("label", "New Label")

    def test_property_change_updates_field(self, property_panel, mock_field_widget):
        """Test property change updates field property."""
        property_panel.bind_to_field(mock_field_widget)

        # Change x position
        property_panel._prop_vars["x"].set("10")
        property_panel._on_x_change(None)

        # Field position should be updated
        assert mock_field_widget.position.col == 10

    def test_property_change_validates_value(self, property_panel, mock_field_widget):
        """Test property change validates value."""
        property_panel.bind_to_field(mock_field_widget)

        # Try to set invalid field_id
        with patch.object(property_panel, "_populate_values") as mock_populate:
            result = property_panel._validate_prop("field_id", "")
            assert result is False


# =============================================================================
# TEST: Two-Way Binding
# =============================================================================


class TestTwoWayBinding:
    """Test suite for two-way binding."""

    def test_ui_to_field_binding(self, property_panel, mock_field_widget):
        """Test UI change propagates to field."""
        property_panel.bind_to_field(mock_field_widget)

        # Change in UI
        property_panel._prop_vars["x"].set("15")
        property_panel._on_x_change(None)

        # Field should be updated
        assert mock_field_widget.position.col == 15

    def test_refresh_updates_ui(self, property_panel, mock_field_widget):
        """Test refresh updates UI from field."""
        property_panel.bind_to_field(mock_field_widget)

        # Change field position
        from dataclasses import dataclass

        @dataclass
        class NewPosition:
            col: int = 20
            row: int = 5
            width: int = 15
            height: int = 1

        mock_field_widget.position = NewPosition()

        # Refresh should update UI
        property_panel.refresh()

        # Check that UI is updated
        x_var = property_panel._prop_vars.get("x")
        if x_var:
            assert x_var.get() == "20"


# =============================================================================
# TEST: Validation Error Display
# =============================================================================


class TestValidationErrorDisplay:
    """Test suite for validation error display."""

    def test_field_id_validation_rejects_empty(self, property_panel):
        """Test field_id validation rejects empty string."""
        result = property_panel._validate_prop("field_id", "")
        assert result is False

    def test_field_id_validation_rejects_invalid_chars(self, property_panel):
        """Test field_id validation rejects invalid characters."""
        result = property_panel._validate_prop("field_id", "field@123")
        assert result is False

    def test_field_id_validation_accepts_valid(self, property_panel):
        """Test field_id validation accepts valid ID."""
        result = property_panel._validate_prop("field_id", "valid_field_123")
        assert result is True

    def test_x_validation_rejects_negative(self, property_panel):
        """Test x validation rejects negative values."""
        result = property_panel._validate_prop("x", "-5")
        assert result is False

    def test_x_validation_accepts_zero(self, property_panel):
        """Test x validation accepts zero."""
        result = property_panel._validate_prop("x", "0")
        assert result is True

    def test_width_validation_rejects_zero(self, property_panel):
        """Test width validation rejects zero."""
        result = property_panel._validate_prop("width", "0")
        assert result is False

    def test_width_validation_accepts_positive(self, property_panel):
        """Test width validation accepts positive value."""
        result = property_panel._validate_prop("width", "5")
        assert result is True

    def test_pattern_validation_accepts_empty(self, property_panel):
        """Test pattern validation accepts empty string."""
        result = property_panel._validate_prop("validation_pattern", "")
        assert result is True

    def test_pattern_validation_rejects_invalid_regex(self, property_panel):
        """Test pattern validation rejects invalid regex."""
        result = property_panel._validate_prop("validation_pattern", "[invalid")
        assert result is False

    def test_pattern_validation_accepts_valid_regex(self, property_panel):
        """Test pattern validation accepts valid regex."""
        result = property_panel._validate_prop("validation_pattern", r"^\d{4}$")
        assert result is True


# =============================================================================
# TEST: Section Management
# =============================================================================


class TestSectionManagement:
    """Test suite for section management."""

    def test_expand_section(self, property_panel):
        """Test expand_section expands a section."""
        # First bind to a field to create sections
        mock_field = MagicMock()
        mock_field.field_def = FieldDefinition(
            field_id="test",
            field_type=FieldType.TEXT_INPUT,
            label="Test",
        )
        mock_field.position = MagicMock()
        mock_field.position.col = 0
        mock_field.position.row = 0
        mock_field.position.width = 1
        mock_field.position.height = 1

        property_panel.bind_to_field(mock_field)

        if "Basic" in property_panel._sections:
            property_panel.expand_section("Basic")
            assert property_panel._sections["Basic"]._is_collapsed is False

    def test_collapse_section(self, property_panel):
        """Test collapse_section collapses a section."""
        mock_field = MagicMock()
        mock_field.field_def = FieldDefinition(
            field_id="test",
            field_type=FieldType.TEXT_INPUT,
            label="Test",
        )
        mock_field.position = MagicMock()
        mock_field.position.col = 0
        mock_field.position.row = 0
        mock_field.position.width = 1
        mock_field.position.height = 1

        property_panel.bind_to_field(mock_field)

        if "Basic" in property_panel._sections:
            property_panel.collapse_section("Basic")
            assert property_panel._sections["Basic"]._is_collapsed is True

    def test_expand_section_raises_on_invalid(self, property_panel):
        """Test expand_section raises on invalid section."""
        with pytest.raises(ValueError, match="Section not found"):
            property_panel.expand_section("InvalidSection")


# =============================================================================
# TEST: Property Enable/Disable
# =============================================================================


class TestPropertyEnableDisable:
    """Test suite for property enable/disable."""

    def test_set_prop_enabled_disables_widget(self, property_panel, mock_field_widget):
        """Test set_prop_enabled disables widget."""
        property_panel.bind_to_field(mock_field_widget)

        # Disable field_id
        property_panel.set_prop_enabled("field_id", False)

        # Widget should be disabled
        widget = property_panel._prop_widgets.get("field_id")
        if widget:
            assert str(widget.cget("state")) == "disabled"

    def test_set_prop_enabled_enables_widget(self, property_panel, mock_field_widget):
        """Test set_prop_enabled enables widget."""
        property_panel.bind_to_field(mock_field_widget)

        # Disable then enable
        property_panel.set_prop_enabled("field_id", False)
        property_panel.set_prop_enabled("field_id", True)

        widget = property_panel._prop_widgets.get("field_id")
        if widget:
            assert str(widget.cget("state")) == "normal"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.form_designer.property_panel"])
