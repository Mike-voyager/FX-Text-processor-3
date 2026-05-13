"""Tests for Design Commands.

Tests field creation, move, resize, delete, and property change commands
with undo/redo functionality.

Coverage target: ≥90%
"""

from __future__ import annotations

import tkinter as tk
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from src.gui.core.commands.design_commands import (
    FieldCreateCommand,
    FieldMoveCommand,
    FieldResizeCommand,
    FieldDeleteCommand,
    PropertyChangeCommand,
    SelectFieldCommand,
    BatchCommand,
)
from src.gui.core.commands.command import Command
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
def mock_canvas():
    """Create a mock FormCanvas."""
    canvas = MagicMock()
    canvas._cell_width = 12
    canvas._cell_height = 12
    return canvas


@pytest.fixture
def sample_field_def():
    """Create a sample FieldDefinition."""
    return FieldDefinition(
        field_id="test_field",
        field_type=FieldType.TEXT_INPUT,
        label="Test Field",
    )


@pytest.fixture
def mock_field_widget():
    """Create a mock FormFieldWidget."""
    from src.documents.types.type_schema import FieldDefinition, FieldType
    
    widget = MagicMock()
    widget.field_id = "test_field"
    widget.field_def = FieldDefinition(
        field_id="test_field",
        field_type=FieldType.TEXT_INPUT,
        label="Test Label",
    )
    
    # Create a mock position
    position = MagicMock()
    position.col = 5
    position.row = 3
    position.width = 10
    position.height = 1
    widget.position = position
    
    return widget


# =============================================================================
# TEST: Field Create Command
# =============================================================================


class TestFieldCreateCommand:
    """Test suite for FieldCreateCommand."""

    def test_create_command_initialization(self, mock_canvas, sample_field_def):
        """Test FieldCreateCommand initialization."""
        cmd = FieldCreateCommand(mock_canvas, sample_field_def, x=5, y=3)
        
        assert cmd._canvas == mock_canvas
        assert cmd._field_def == sample_field_def
        assert cmd._x == 5
        assert cmd._y == 3

    def test_execute_creates_field(self, mock_canvas, sample_field_def):
        """Test execute creates field on canvas."""
        mock_field = MagicMock()
        mock_field.field_id = "created_field"
        mock_canvas.create_field.return_value = mock_field
        
        cmd = FieldCreateCommand(mock_canvas, sample_field_def, x=5, y=3)
        cmd.execute()
        
        mock_canvas.create_field.assert_called_once_with(sample_field_def, 5, 3)
        assert cmd._created_field_id == "created_field"
        assert cmd._is_executed is True

    def test_undo_deletes_field(self, mock_canvas, sample_field_def):
        """Test undo removes created field."""
        mock_field = MagicMock()
        mock_field.field_id = "created_field"
        mock_canvas.create_field.return_value = mock_field
        
        cmd = FieldCreateCommand(mock_canvas, sample_field_def, x=5, y=3)
        cmd.execute()
        cmd.undo()
        
        mock_canvas.remove_field.assert_called_once_with("created_field")
        assert cmd._is_executed is False

    def test_redo_reexecutes(self, mock_canvas, sample_field_def):
        """Test redo re-executes the command."""
        mock_field = MagicMock()
        mock_field.field_id = "created_field"
        mock_canvas.create_field.return_value = mock_field
        
        cmd = FieldCreateCommand(mock_canvas, sample_field_def, x=5, y=3)
        cmd.execute()
        cmd.undo()
        cmd.redo()
        
        # Should call create_field again
        assert mock_canvas.create_field.call_count == 2

    def test_get_description(self, mock_canvas, sample_field_def):
        """Test get_description returns correct string."""
        cmd = FieldCreateCommand(mock_canvas, sample_field_def, x=5, y=3)
        assert cmd.get_description() == "Create field test_field"


# =============================================================================
# TEST: Field Move Command
# =============================================================================


class TestFieldMoveCommand:
    """Test suite for FieldMoveCommand."""

    def test_move_command_initialization(self, mock_canvas):
        """Test FieldMoveCommand initialization."""
        cmd = FieldMoveCommand(mock_canvas, "field_1", (5, 3), (10, 5))
        
        assert cmd._canvas == mock_canvas
        assert cmd._field_id == "field_1"
        assert cmd._old_position == (5, 3)
        assert cmd._new_position == (10, 5)

    def test_execute_moves_field(self, mock_canvas, mock_field_widget):
        """Test execute moves field to new position."""
        mock_canvas.get_fields.return_value = {"field_1": mock_field_widget}
        
        cmd = FieldMoveCommand(mock_canvas, "field_1", (5, 3), (10, 5))
        cmd.execute()
        
        # Check that position was updated
        assert mock_field_widget.position.col == 10
        assert mock_field_widget.position.row == 5
        assert cmd._is_executed is True

    def test_undo_restores_old_position(self, mock_canvas, mock_field_widget):
        """Test undo restores field to old position."""
        mock_canvas.get_fields.return_value = {"field_1": mock_field_widget}
        
        cmd = FieldMoveCommand(mock_canvas, "field_1", (5, 3), (10, 5))
        cmd.execute()
        cmd.undo()
        
        # Check that position was restored
        assert mock_field_widget.position.col == 5
        assert mock_field_widget.position.row == 3
        assert cmd._is_executed is False

    def test_execute_raises_on_missing_field(self, mock_canvas):
        """Test execute raises when field not found."""
        mock_canvas.get_fields.return_value = {}
        
        cmd = FieldMoveCommand(mock_canvas, "missing_field", (5, 3), (10, 5))
        
        with pytest.raises(RuntimeError, match="Field missing_field not found"):
            cmd.execute()

    def test_get_description(self, mock_canvas):
        """Test get_description returns correct string."""
        cmd = FieldMoveCommand(mock_canvas, "field_1", (5, 3), (10, 5))
        assert cmd.get_description() == "Move field field_1"


# =============================================================================
# TEST: Field Resize Command
# =============================================================================


class TestFieldResizeCommand:
    """Test suite for FieldResizeCommand."""

    def test_resize_command_initialization(self, mock_canvas):
        """Test FieldResizeCommand initialization."""
        cmd = FieldResizeCommand(mock_canvas, "field_1", (1, 1), (2, 3))
        
        assert cmd._canvas == mock_canvas
        assert cmd._field_id == "field_1"
        assert cmd._old_size == (1, 1)
        assert cmd._new_size == (2, 3)

    def test_execute_resizes_field(self, mock_canvas, mock_field_widget):
        """Test execute resizes field."""
        mock_canvas.get_fields.return_value = {"field_1": mock_field_widget}
        
        cmd = FieldResizeCommand(mock_canvas, "field_1", (1, 1), (2, 3))
        cmd.execute()
        
        # Check that size was updated
        assert mock_field_widget.position.width == 2
        assert mock_field_widget.position.height == 3
        assert cmd._is_executed is True

    def test_undo_restores_old_size(self, mock_canvas, mock_field_widget):
        """Test undo restores old size."""
        mock_canvas.get_fields.return_value = {"field_1": mock_field_widget}
        
        cmd = FieldResizeCommand(mock_canvas, "field_1", (1, 1), (2, 3))
        cmd.execute()
        cmd.undo()
        
        # Check that size was restored
        assert mock_field_widget.position.width == 1
        assert mock_field_widget.position.height == 1

    def test_get_description(self, mock_canvas):
        """Test get_description returns correct string."""
        cmd = FieldResizeCommand(mock_canvas, "field_1", (1, 1), (2, 3))
        assert cmd.get_description() == "Resize field field_1"


# =============================================================================
# TEST: Field Delete Command
# =============================================================================


class TestFieldDeleteCommand:
    """Test suite for FieldDeleteCommand."""

    def test_delete_command_initialization(self, mock_canvas, mock_field_widget):
        """Test FieldDeleteCommand initialization."""
        cmd = FieldDeleteCommand(mock_canvas, mock_field_widget)
        
        assert cmd._canvas == mock_canvas
        assert cmd._field_def == mock_field_widget.field_def
        assert cmd._deleted_field_id == "test_field"

    def test_execute_deletes_field(self, mock_canvas, mock_field_widget):
        """Test execute deletes field from canvas."""
        cmd = FieldDeleteCommand(mock_canvas, mock_field_widget)
        cmd.execute()
        
        mock_canvas.remove_field.assert_called_once_with("test_field")
        assert cmd._is_executed is True

    def test_undo_restores_field(self, mock_canvas, mock_field_widget):
        """Test undo recreates field."""
        cmd = FieldDeleteCommand(mock_canvas, mock_field_widget)
        cmd.execute()
        cmd.undo()
        
        mock_canvas.create_field.assert_called_once()
        assert cmd._is_executed is False

    def test_get_description(self, mock_canvas, mock_field_widget):
        """Test get_description returns correct string."""
        cmd = FieldDeleteCommand(mock_canvas, mock_field_widget)
        assert cmd.get_description() == "Delete field test_field"


# =============================================================================
# TEST: Property Change Command
# =============================================================================


class TestPropertyChangeCommand:
    """Test suite for PropertyChangeCommand."""

    def test_property_change_initialization(self, mock_canvas):
        """Test PropertyChangeCommand initialization."""
        cmd = PropertyChangeCommand(mock_canvas, "field_1", "label", "Old", "New")
        
        assert cmd._canvas == mock_canvas
        assert cmd._field_id == "field_1"
        assert cmd._property_name == "label"
        assert cmd._old_value == "Old"
        assert cmd._new_value == "New"

    def test_execute_sets_new_value(self, mock_canvas, mock_field_widget):
        """Test execute sets new property value."""
        mock_canvas.get_fields.return_value = {"field_1": mock_field_widget}
        mock_canvas._redraw_field = MagicMock()
        # field_def is already a FieldDefinition dataclass
        
        cmd = PropertyChangeCommand(mock_canvas, "field_1", "label", "Old Label", "New Label")
        cmd.execute()
        
        assert cmd._is_executed is True
        assert mock_field_widget.field_def.label == "New Label"

    def test_undo_restores_old_value(self, mock_canvas, mock_field_widget):
        """Test undo restores old property value."""
        mock_canvas.get_fields.return_value = {"field_1": mock_field_widget}
        mock_canvas._redraw_field = MagicMock()
        # field_def is already a FieldDefinition dataclass
        
        cmd = PropertyChangeCommand(mock_canvas, "field_1", "label", "Old Label", "New Label")
        cmd.execute()
        cmd.undo()
        
        assert cmd._is_executed is False
        assert mock_field_widget.field_def.label == "Old Label"

    def test_get_description(self, mock_canvas):
        """Test get_description returns correct string."""
        cmd = PropertyChangeCommand(mock_canvas, "field_1", "label", "Old", "New")
        assert cmd.get_description() == "Change label to New"


# =============================================================================
# TEST: Select Field Command
# =============================================================================


class TestSelectFieldCommand:
    """Test suite for SelectFieldCommand."""

    def test_select_command_initialization(self, mock_canvas):
        """Test SelectFieldCommand initialization."""
        cmd = SelectFieldCommand(mock_canvas, "old_field", "new_field")
        
        assert cmd._canvas == mock_canvas
        assert cmd._old_field_id == "old_field"
        assert cmd._new_field_id == "new_field"

    def test_execute_selects_new_field(self, mock_canvas):
        """Test execute selects new field."""
        cmd = SelectFieldCommand(mock_canvas, "old_field", "new_field")
        cmd.execute()
        
        mock_canvas.select_field.assert_called_once_with("new_field")
        assert cmd._is_executed is True

    def test_undo_restores_old_selection(self, mock_canvas):
        """Test undo restores old selection."""
        cmd = SelectFieldCommand(mock_canvas, "old_field", "new_field")
        cmd.execute()
        cmd.undo()
        
        mock_canvas.select_field.assert_called_with("old_field")
        assert cmd._is_executed is False

    def test_get_description(self, mock_canvas):
        """Test get_description returns correct string."""
        cmd = SelectFieldCommand(mock_canvas, "field_1", "field_2")
        assert cmd.get_description() == "Select field field_1 → field_2"


# =============================================================================
# TEST: Batch Command
# =============================================================================


class TestBatchCommand:
    """Test suite for BatchCommand."""

    def test_batch_command_initialization(self):
        """Test BatchCommand initialization."""
        cmd1 = MagicMock(spec=Command)
        cmd2 = MagicMock(spec=Command)
        
        batch = BatchCommand([cmd1, cmd2], "Batch operation")
        
        assert len(batch._commands) == 2
        assert batch._description == "Batch operation"

    def test_batch_execute_executes_all(self):
        """Test execute runs all commands."""
        cmd1 = MagicMock(spec=Command)
        cmd1.execute = MagicMock()
        cmd2 = MagicMock(spec=Command)
        cmd2.execute = MagicMock()
        
        batch = BatchCommand([cmd1, cmd2])
        batch.execute()
        
        cmd1.execute.assert_called_once()
        cmd2.execute.assert_called_once()
        assert batch._is_executed is True

    def test_batch_undo_undoes_all(self):
        """Test undo undoes all commands in reverse."""
        cmd1 = MagicMock(spec=Command)
        cmd1.is_executed = True
        cmd1.undo = MagicMock()
        cmd2 = MagicMock(spec=Command)
        cmd2.is_executed = True
        cmd2.undo = MagicMock()
        
        batch = BatchCommand([cmd1, cmd2])
        batch._executed = True
        batch.undo()
        
        cmd2.undo.assert_called_once()
        cmd1.undo.assert_called_once()
        assert batch._is_executed is False

    def test_batch_get_description(self):
        """Test get_description includes command count."""
        cmd1 = MagicMock(spec=Command)
        cmd2 = MagicMock(spec=Command)
        
        batch = BatchCommand([cmd1, cmd2], "Create fields")
        
        assert batch.get_description() == "Create fields (2 operations)"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.commands.design_commands"])
