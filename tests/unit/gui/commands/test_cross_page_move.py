"""Tests for Cross-Page Field Move functionality.

Tests FieldCrossPageMoveCommand and DesignerTab integration for moving
fields between pages with undo/redo support.

Coverage target: ≥90%

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from typing import Any, Generator
from unittest.mock import MagicMock, Mock, patch

import pytest

from src.gui.core.commands.design_commands import FieldCrossPageMoveCommand
from src.gui.core.commands.command import Command
from src.documents.types.type_schema import FieldDefinition, FieldType


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def mock_designer_tab() -> MagicMock:
    """Создаёт мок DesignerTab для тестирования."""
    tab = MagicMock()
    tab.move_field = MagicMock(return_value=True)
    return tab


@pytest.fixture
def mock_designer_tab_with_pages() -> MagicMock:
    """Создаёт мок DesignerTab с двумя страницами."""
    tab = MagicMock()

    # Create mock pages
    page0 = MagicMock()
    page0.canvas = MagicMock()
    page0.fields = []
    page0.index = 0

    page1 = MagicMock()
    page1.canvas = MagicMock()
    page1.fields = []
    page1.index = 1

    tab._pages = [page0, page1]
    tab.move_field = MagicMock(return_value=True)

    return tab


@pytest.fixture
def sample_field_definition() -> FieldDefinition:
    """Создаёт пример FieldDefinition."""
    return FieldDefinition(
        field_id="test_field",
        field_type=FieldType.TEXT_INPUT,
        label="Test Field",
    )


@pytest.fixture
def mock_field_widget() -> MagicMock:
    """Создаёт мок FormFieldWidget."""
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
# TEST: FieldCrossPageMoveCommand
# =============================================================================


class TestFieldCrossPageMoveCommand:
    """Test suite for FieldCrossPageMoveCommand."""

    def test_init_with_all_parameters(self, mock_designer_tab: MagicMock) -> None:
        """Тест инициализации команды со всеми параметрами."""
        cmd = FieldCrossPageMoveCommand(
            designer_tab=mock_designer_tab,
            field_id="field1",
            from_page=0,
            to_page=1,
            from_pos=(5, 3),
            to_pos=(10, 7),
        )

        assert cmd._designer_tab == mock_designer_tab
        assert cmd._field_id == "field1"
        assert cmd._from_page == 0
        assert cmd._to_page == 1
        assert cmd._from_pos == (5, 3)
        assert cmd._to_pos == (10, 7)
        assert cmd._is_executed is False

    def test_init_same_page(self, mock_designer_tab: MagicMock) -> None:
        """Тест инициализации при перемещении внутри одной страницы."""
        cmd = FieldCrossPageMoveCommand(
            designer_tab=mock_designer_tab,
            field_id="field1",
            from_page=0,
            to_page=0,
            from_pos=(5, 3),
            to_pos=(10, 7),
        )

        assert cmd._from_page == 0
        assert cmd._to_page == 0

    def test_execute_moves_field_to_target_page(self, mock_designer_tab: MagicMock) -> None:
        """Тест выполнения перемещения на целевую страницу."""
        cmd = FieldCrossPageMoveCommand(
            designer_tab=mock_designer_tab,
            field_id="field1",
            from_page=0,
            to_page=1,
            from_pos=(5, 3),
            to_pos=(10, 7),
        )

        cmd.execute()

        mock_designer_tab.move_field.assert_called_once_with(
            "field1", 10, 7, 1
        )
        assert cmd._is_executed is True

    def test_execute_raises_on_failure(self, mock_designer_tab: MagicMock) -> None:
        """Тест выброса исключения при неудаче move_field."""
        mock_designer_tab.move_field.return_value = False

        cmd = FieldCrossPageMoveCommand(
            designer_tab=mock_designer_tab,
            field_id="field1",
            from_page=0,
            to_page=1,
            from_pos=(5, 3),
            to_pos=(10, 7),
        )

        with pytest.raises(RuntimeError, match="Failed to move field field1"):
            cmd.execute()

        assert cmd._is_executed is False

    def test_undo_returns_field_to_original_page(self, mock_designer_tab: MagicMock) -> None:
        """Тест возврата поля на исходную страницу при undo."""
        cmd = FieldCrossPageMoveCommand(
            designer_tab=mock_designer_tab,
            field_id="field1",
            from_page=0,
            to_page=1,
            from_pos=(5, 3),
            to_pos=(10, 7),
        )

        cmd.execute()
        mock_designer_tab.move_field.reset_mock()

        cmd.undo()

        mock_designer_tab.move_field.assert_called_once_with(
            "field1", 5, 3, 0
        )
        assert cmd._is_executed is False

    def test_undo_raises_on_failure(self, mock_designer_tab: MagicMock) -> None:
        """Тест выброса исключения при неудаче undo."""
        # First call succeeds (execute), second fails (undo)
        mock_designer_tab.move_field.side_effect = [True, False]

        cmd = FieldCrossPageMoveCommand(
            designer_tab=mock_designer_tab,
            field_id="field1",
            from_page=0,
            to_page=1,
            from_pos=(5, 3),
            to_pos=(10, 7),
        )

        cmd.execute()

        with pytest.raises(RuntimeError, match="Failed to undo move for field field1"):
            cmd.undo()

    def test_redo_re_executes_move(self, mock_designer_tab: MagicMock) -> None:
        """Тест повторного выполнения перемещения при redo."""
        cmd = FieldCrossPageMoveCommand(
            designer_tab=mock_designer_tab,
            field_id="field1",
            from_page=0,
            to_page=1,
            from_pos=(5, 3),
            to_pos=(10, 7),
        )

        cmd.execute()
        cmd.undo()
        mock_designer_tab.move_field.reset_mock()

        cmd.redo()

        mock_designer_tab.move_field.assert_called_once_with(
            "field1", 10, 7, 1
        )
        assert cmd._is_executed is True

    def test_description_cross_page(self, mock_designer_tab: MagicMock) -> None:
        """Тест описания при перемещении между страницами."""
        cmd = FieldCrossPageMoveCommand(
            designer_tab=mock_designer_tab,
            field_id="field1",
            from_page=0,
            to_page=1,
            from_pos=(5, 3),
            to_pos=(10, 7),
        )

        assert cmd.get_description() == "Move field field1 to page 2"

    def test_description_same_page(self, mock_designer_tab: MagicMock) -> None:
        """Тест описания при перемещении внутри одной страницы."""
        cmd = FieldCrossPageMoveCommand(
            designer_tab=mock_designer_tab,
            field_id="field1",
            from_page=0,
            to_page=0,
            from_pos=(5, 3),
            to_pos=(10, 7),
        )

        assert cmd.get_description() == "Move field field1"

    def test_description_via_base_class_method(self, mock_designer_tab: MagicMock) -> None:
        """Тест получения описания через базовый метод get_description."""
        cmd = FieldCrossPageMoveCommand(
            designer_tab=mock_designer_tab,
            field_id="field1",
            from_page=0,
            to_page=1,
            from_pos=(5, 3),
            to_pos=(10, 7),
        )

        # get_description is inherited from base Command class
        assert cmd.get_description() == "Move field field1 to page 2"


# =============================================================================
# TEST: Move Scenarios
# =============================================================================


class TestMoveScenarios:
    """Test suite for various move scenarios."""

    def test_move_from_page_0_to_page_1(self, mock_designer_tab: MagicMock) -> None:
        """Тест перемещения с страницы 0 на страницу 1."""
        cmd = FieldCrossPageMoveCommand(
            designer_tab=mock_designer_tab,
            field_id="field1",
            from_page=0,
            to_page=1,
            from_pos=(5, 3),
            to_pos=(10, 7),
        )

        cmd.execute()

        # Field moved to page 1
        mock_designer_tab.move_field.assert_called_with(
            "field1", 10, 7, 1
        )

    def test_move_same_page(self, mock_designer_tab: MagicMock) -> None:
        """Тест перемещения внутри одной страницы."""
        cmd = FieldCrossPageMoveCommand(
            designer_tab=mock_designer_tab,
            field_id="field1",
            from_page=0,
            to_page=0,
            from_pos=(5, 3),
            to_pos=(10, 7),
        )

        cmd.execute()

        # Move within same page
        mock_designer_tab.move_field.assert_called_with(
            "field1", 10, 7, 0
        )

    def test_complete_undo_redo_cycle(self, mock_designer_tab: MagicMock) -> None:
        """Тест полного цикла execute -> undo -> redo."""
        cmd = FieldCrossPageMoveCommand(
            designer_tab=mock_designer_tab,
            field_id="field1",
            from_page=0,
            to_page=1,
            from_pos=(5, 3),
            to_pos=(10, 7),
        )

        # Execute
        cmd.execute()
        assert cmd._is_executed is True
        mock_designer_tab.move_field.assert_called_with("field1", 10, 7, 1)

        # Undo
        mock_designer_tab.move_field.reset_mock()
        cmd.undo()
        assert cmd._is_executed is False
        mock_designer_tab.move_field.assert_called_with("field1", 5, 3, 0)

        # Redo
        mock_designer_tab.move_field.reset_mock()
        cmd.redo()
        assert cmd._is_executed is True
        mock_designer_tab.move_field.assert_called_with("field1", 10, 7, 1)

    def test_undo_without_execute_raises(self, mock_designer_tab: MagicMock) -> None:
        """Тест что undo без execute вызывает RuntimeError."""
        cmd = FieldCrossPageMoveCommand(
            designer_tab=mock_designer_tab,
            field_id="field1",
            from_page=0,
            to_page=1,
            from_pos=(5, 3),
            to_pos=(10, 7),
        )

        # Mock move_field to fail
        mock_designer_tab.move_field.return_value = False

        # Without executing first, undo should fail
        # because move_field will return False
        with pytest.raises(RuntimeError):
            cmd.undo()


# =============================================================================
# TEST: DesignerTab Integration
# =============================================================================


class TestDesignerTabIntegration:
    """Test suite for DesignerTab integration methods."""

    def test_move_field_validates_position(self) -> None:
        """Тест что move_field вызывает validate_field_position."""
        from src.gui.form_designer.designer_tab import DesignerTab
        from src.gui.form_designer.types import DesignerPage

        tab = MagicMock(spec=DesignerTab)
        tab._pages = []

        # Create mock pages with proper structure
        page0 = MagicMock(spec=DesignerPage)
        page0.index = 0
        page0.canvas = MagicMock()
        page0.canvas.validate_field_position.return_value = (True, "")
        page0.fields = []

        tab._pages.append(page0)

        # Create mock field
        mock_field = MagicMock()
        mock_field.field_id = "field1"
        mock_field.position.col = 5
        mock_field.position.row = 3
        mock_field.position.width = 10
        mock_field.position.height = 1

        page0.fields.append(mock_field)

        # Call move_field with same page
        result = DesignerTab.move_field(tab, "field1", 10, 5)

        # Verify validation was called on target page (same as source)
        page0.canvas.validate_field_position.assert_called_once()

    def test_move_field_removes_from_source_page(self) -> None:
        """Тест что move_field удаляет поле из исходной страницы."""
        from src.gui.form_designer.designer_tab import DesignerTab
        from src.gui.form_designer.types import DesignerPage

        # Create a testable scenario
        tab = MagicMock(spec=DesignerTab)
        tab._pages = []

        # Create page0
        page0 = MagicMock(spec=DesignerPage)
        page0.index = 0
        page0.canvas = MagicMock()
        page0.canvas.validate_field_position.return_value = (True, "")
        page0.fields = []

        # Create page1
        page1 = MagicMock(spec=DesignerPage)
        page1.index = 1
        page1.canvas = MagicMock()
        page1.canvas.validate_field_position.return_value = (True, "")
        page1.fields = []

        tab._pages = [page0, page1]

        # Create and add mock field to page0
        mock_field = MagicMock()
        mock_field.field_id = "field1"
        mock_field.position.col = 5
        mock_field.position.row = 3
        mock_field.position.width = 10
        mock_field.position.height = 1
        mock_field.field_def = MagicMock()

        page0.fields.append(mock_field)

        # Patch FieldPosition
        with patch('src.gui.renderers.form_canvas.FieldPosition') as mock_pos_class:
            mock_pos = MagicMock()
            mock_pos_class.return_value = mock_pos

            # Call move_field
            result = DesignerTab.move_field(tab, "field1", 10, 5, 1)

        assert result is True
        page0.canvas.remove_field.assert_called_once_with("field1")

    def test_move_field_adds_to_target_page(self) -> None:
        """Тест что move_field добавляет поле на целевую страницу."""
        from src.gui.form_designer.designer_tab import DesignerTab
        from src.gui.form_designer.types import DesignerPage

        tab = MagicMock(spec=DesignerTab)
        tab._pages = []

        # Create page0
        page0 = MagicMock(spec=DesignerPage)
        page0.index = 0
        page0.canvas = MagicMock()
        page0.canvas.validate_field_position.return_value = (True, "")
        page0.fields = []

        # Create page1
        page1 = MagicMock(spec=DesignerPage)
        page1.index = 1
        page1.canvas = MagicMock()
        page1.canvas.validate_field_position.return_value = (True, "")
        page1.fields = []

        tab._pages = [page0, page1]

        # Create and add mock field to page0
        mock_field = MagicMock()
        mock_field.field_id = "field1"
        mock_field.position.col = 5
        mock_field.position.row = 3
        mock_field.position.width = 10
        mock_field.position.height = 1
        mock_field.field_def = MagicMock()

        page0.fields.append(mock_field)

        # Patch FieldPosition
        with patch('src.gui.renderers.form_canvas.FieldPosition'):
            result = DesignerTab.move_field(tab, "field1", 10, 5, 1)

        assert result is True
        assert mock_field in page1.fields
        page1.canvas.create_field.assert_called_once()

    def test_move_field_same_page_uses_canvas_move(self) -> None:
        """Тест что для перемещения внутри страницы используется canvas.move_field."""
        from src.gui.form_designer.designer_tab import DesignerTab
        from src.gui.form_designer.types import DesignerPage

        tab = MagicMock(spec=DesignerTab)
        tab._pages = []

        # Create mock page
        page0 = MagicMock(spec=DesignerPage)
        page0.index = 0
        page0.canvas = MagicMock()
        page0.canvas.move_field.return_value = True
        page0.canvas.validate_field_position.return_value = (True, "")
        page0.fields = []

        tab._pages = [page0]

        # Create and add mock field
        mock_field = MagicMock()
        mock_field.field_id = "field1"
        mock_field.position.col = 5
        mock_field.position.row = 3
        mock_field.position.width = 10
        mock_field.position.height = 1

        page0.fields.append(mock_field)

        # Call move_field without page change (same page)
        result = DesignerTab.move_field(tab, "field1", 10, 5)

        assert result is True
        page0.canvas.move_field.assert_called_once_with("field1", 10, 5)

    def test_move_field_invalid_position_returns_false(self) -> None:
        """Тест что при невалидной позиции возвращается False."""
        from src.gui.form_designer.designer_tab import DesignerTab
        from src.gui.form_designer.types import DesignerPage

        tab = MagicMock(spec=DesignerTab)
        tab._pages = []

        # Create page0
        page0 = MagicMock(spec=DesignerPage)
        page0.index = 0
        page0.canvas = MagicMock()
        page0.fields = []

        # Create page1 with validation that fails
        page1 = MagicMock(spec=DesignerPage)
        page1.index = 1
        page1.canvas = MagicMock()
        page1.canvas.validate_field_position.return_value = (False, "Out of bounds")
        page1.fields = []

        tab._pages = [page0, page1]

        # Create and add mock field to page0
        mock_field = MagicMock()
        mock_field.field_id = "field1"
        mock_field.position.col = 5
        mock_field.position.row = 3
        mock_field.position.width = 10
        mock_field.position.height = 1

        page0.fields.append(mock_field)

        # Call move_field to page 1 with invalid position
        result = DesignerTab.move_field(tab, "field1", 100, 100, 1)

        assert result is False

    def test_move_field_nonexistent_field_returns_false(self) -> None:
        """Тест что при несуществующем поле возвращается False."""
        from src.gui.form_designer.designer_tab import DesignerTab

        tab = MagicMock(spec=DesignerTab)

        page0 = MagicMock()
        page0.index = 0
        page0.fields = []

        tab._pages = [page0]

        result = DesignerTab.move_field(tab, "nonexistent_field", 10, 5, 1)

        assert result is False

    def test_move_field_to_invalid_page_returns_false(self) -> None:
        """Тест что при несуществующей странице возвращается False."""
        from src.gui.form_designer.designer_tab import DesignerTab

        tab = MagicMock(spec=DesignerTab)

        page0 = MagicMock()
        page0.index = 0
        page0.fields = []

        mock_field = MagicMock()
        mock_field.field_id = "field1"
        page0.fields.append(mock_field)

        tab._pages = [page0]

        # Try to move to page 100
        result = DesignerTab.move_field(tab, "field1", 10, 5, 100)

        assert result is False


# =============================================================================
# TEST: _move_field_to_page Integration
# =============================================================================


class TestMoveFieldToPage:
    """Test suite for _move_field_to_page method."""

    def test_move_field_to_page_finds_current_location(self) -> None:
        """Тест поиска текущего расположения поля."""
        from src.gui.form_designer.designer_tab import DesignerTab

        tab = MagicMock(spec=DesignerTab)
        tab._command_stack = MagicMock()

        page0 = MagicMock()
        page0.index = 0
        page0.fields = []

        page1 = MagicMock()
        page1.index = 1
        page1.fields = []

        tab._pages = [page0, page1]

        mock_field = MagicMock()
        mock_field.field_id = "field1"
        mock_field.position.col = 5
        mock_field.position.row = 3
        page0.fields.append(mock_field)

        with patch('src.gui.commands.design_commands.FieldCrossPageMoveCommand') as mock_cmd_class:
            mock_cmd = MagicMock()
            mock_cmd_class.return_value = mock_cmd

            DesignerTab._move_field_to_page(tab, "field1", 1)

            # Verify command was created with correct params
            mock_cmd_class.assert_called_once()
            call_kwargs = mock_cmd_class.call_args.kwargs
            assert call_kwargs['field_id'] == "field1"
            assert call_kwargs['from_page'] == 0
            assert call_kwargs['to_page'] == 1
            assert call_kwargs['from_pos'] == (5, 3)

    def test_move_field_to_page_same_page_returns_true(self) -> None:
        """Тест что перемещение на ту же страницу возвращает True."""
        from src.gui.form_designer.designer_tab import DesignerTab

        tab = MagicMock(spec=DesignerTab)

        page0 = MagicMock()
        page0.index = 0
        page0.fields = []

        tab._pages = [page0]

        mock_field = MagicMock()
        mock_field.field_id = "field1"
        mock_field.position.col = 5
        mock_field.position.row = 3
        page0.fields.append(mock_field)

        result = DesignerTab._move_field_to_page(tab, "field1", 0)

        assert result is True

    def test_move_field_to_page_nonexistent_field_returns_false(self) -> None:
        """Тест что при несуществующем поле возвращается False."""
        from src.gui.form_designer.designer_tab import DesignerTab

        tab = MagicMock(spec=DesignerTab)

        page0 = MagicMock()
        page0.index = 0
        page0.fields = []

        tab._pages = [page0]

        result = DesignerTab._move_field_to_page(tab, "nonexistent", 1)

        assert result is False

    def test_move_field_to_page_invalid_page_returns_false(self) -> None:
        """Тест что при несуществующей странице возвращается False."""
        from src.gui.form_designer.designer_tab import DesignerTab

        tab = MagicMock(spec=DesignerTab)

        page0 = MagicMock()
        page0.index = 0
        page0.fields = []

        mock_field = MagicMock()
        mock_field.field_id = "field1"
        page0.fields.append(mock_field)

        tab._pages = [page0]

        result = DesignerTab._move_field_to_page(tab, "field1", 100)

        assert result is False

    def test_move_field_to_page_pushes_command_to_stack(self) -> None:
        """Тест что команда добавляется в command stack."""
        from src.gui.form_designer.designer_tab import DesignerTab

        tab = MagicMock(spec=DesignerTab)
        tab._command_stack = MagicMock()

        page0 = MagicMock()
        page0.index = 0
        page0.fields = []

        page1 = MagicMock()
        page1.index = 1
        page1.fields = []

        tab._pages = [page0, page1]

        mock_field = MagicMock()
        mock_field.field_id = "field1"
        mock_field.position.col = 5
        mock_field.position.row = 3
        page0.fields.append(mock_field)

        with patch('src.gui.commands.design_commands.FieldCrossPageMoveCommand') as mock_cmd_class:
            mock_cmd = MagicMock()
            mock_cmd_class.return_value = mock_cmd

            DesignerTab._move_field_to_page(tab, "field1", 1)

            tab._command_stack.execute.assert_called_once_with(mock_cmd)


# =============================================================================
# TEST: Edge Cases
# =============================================================================


class TestEdgeCases:
    """Test suite for edge cases."""

    def test_execute_after_already_executed(self, mock_designer_tab: MagicMock) -> None:
        """Тест повторного execute после уже выполненной команды."""
        cmd = FieldCrossPageMoveCommand(
            designer_tab=mock_designer_tab,
            field_id="field1",
            from_page=0,
            to_page=1,
            from_pos=(5, 3),
            to_pos=(10, 7),
        )

        cmd.execute()
        cmd.execute()  # Second execute

        # Should call move_field twice
        assert mock_designer_tab.move_field.call_count == 2

    def test_undo_when_already_undone(self, mock_designer_tab: MagicMock) -> None:
        """Тест undo когда команда уже отменена."""
        cmd = FieldCrossPageMoveCommand(
            designer_tab=mock_designer_tab,
            field_id="field1",
            from_page=0,
            to_page=1,
            from_pos=(5, 3),
            to_pos=(10, 7),
        )

        cmd.execute()
        cmd.undo()

        # Second undo should fail
        mock_designer_tab.move_field.return_value = False
        with pytest.raises(RuntimeError):
            cmd.undo()

    def test_redo_without_execute(self, mock_designer_tab: MagicMock) -> None:
        """Тест redo без предварительного execute."""
        cmd = FieldCrossPageMoveCommand(
            designer_tab=mock_designer_tab,
            field_id="field1",
            from_page=0,
            to_page=1,
            from_pos=(5, 3),
            to_pos=(10, 7),
        )

        # Redo without executing first
        cmd.redo()

        # Should execute the command
        mock_designer_tab.move_field.assert_called_once()

    def test_move_to_page_with_position_at_origin(self, mock_designer_tab: MagicMock) -> None:
        """Тест перемещения в позицию (0, 0)."""
        cmd = FieldCrossPageMoveCommand(
            designer_tab=mock_designer_tab,
            field_id="field1",
            from_page=0,
            to_page=1,
            from_pos=(5, 3),
            to_pos=(0, 0),
        )

        cmd.execute()

        mock_designer_tab.move_field.assert_called_with(
            "field1", 0, 0, 1
        )

    def test_move_with_large_coordinates(self, mock_designer_tab: MagicMock) -> None:
        """Тест перемещения с большими координатами."""
        cmd = FieldCrossPageMoveCommand(
            designer_tab=mock_designer_tab,
            field_id="field1",
            from_page=0,
            to_page=1,
            from_pos=(999, 999),
            to_pos=(1000, 1000),
        )

        cmd.execute()

        mock_designer_tab.move_field.assert_called_with(
            "field1", 1000, 1000, 1
        )

    def test_move_with_negative_coordinates(self, mock_designer_tab: MagicMock) -> None:
        """Тест перемещения с отрицательными координатами."""
        cmd = FieldCrossPageMoveCommand(
            designer_tab=mock_designer_tab,
            field_id="field1",
            from_page=0,
            to_page=1,
            from_pos=(-5, -3),
            to_pos=(10, 7),
        )

        cmd.execute()

        mock_designer_tab.move_field.assert_called_with(
            "field1", 10, 7, 1
        )


# =============================================================================
# TEST: Command Stack Integration
# =============================================================================


class TestCommandStackIntegration:
    """Test suite for Command Stack integration."""

    def test_command_is_executable(self, mock_designer_tab: MagicMock) -> None:
        """Тест что команда соответствует интерфейсу Command."""
        cmd = FieldCrossPageMoveCommand(
            designer_tab=mock_designer_tab,
            field_id="field1",
            from_page=0,
            to_page=1,
            from_pos=(5, 3),
            to_pos=(10, 7),
        )

        # Verify it inherits from Command
        assert isinstance(cmd, Command)

    def test_command_executed_flag_tracking(self, mock_designer_tab: MagicMock) -> None:
        """Тест отслеживания флага is_executed."""
        cmd = FieldCrossPageMoveCommand(
            designer_tab=mock_designer_tab,
            field_id="field1",
            from_page=0,
            to_page=1,
            from_pos=(5, 3),
            to_pos=(10, 7),
        )

        assert cmd.is_executed is False

        cmd.execute()
        assert cmd.is_executed is True

        cmd.undo()
        assert cmd.is_executed is False

        cmd.redo()
        assert cmd.is_executed is True

    def test_multiple_commands_in_sequence(self, mock_designer_tab: MagicMock) -> None:
        """Тест нескольких команд в последовательности."""
        commands: list[FieldCrossPageMoveCommand] = []

        for i in range(3):
            cmd = FieldCrossPageMoveCommand(
                designer_tab=mock_designer_tab,
                field_id=f"field{i}",
                from_page=i,
                to_page=i + 1,
                from_pos=(5, 3),
                to_pos=(10, 7),
            )
            commands.append(cmd)

        # Execute all
        for cmd in commands:
            cmd.execute()

        assert all(cmd.is_executed for cmd in commands)

        # Undo all in reverse
        for cmd in reversed(commands):
            cmd.undo()

        assert not any(cmd.is_executed for cmd in commands)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.commands.design_commands"])
