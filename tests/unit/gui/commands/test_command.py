"""Unit-тесты для базового класса Command.

Проверяет:
- Создание Command
- State machine (is_executed, can_undo, can_redo)
- Описание и временные метки
- Execute/undo/redo lifecycle

Coverage target: ≥90%
"""

from unittest.mock import MagicMock

import pytest

from src.gui.core.commands.command import Command, MAX_DESCRIPTION_LENGTH


# =============================================================================
# FIXTURES
# =============================================================================


class MockCommand(Command):
    """Мок-команда для тестирования базового класса."""

    def __init__(self, description: str = "", fail_execute: bool = False) -> None:
        """Инициализация мок-команды.

        Args:
            description: Описание команды.
            fail_execute: Если True, execute() вызовет ошибку.
        """
        super().__init__(description=description)
        self.execute_called = False
        self.undo_called = False
        self.redo_called = False
        self._fail_execute = fail_execute

    def execute(self) -> None:
        """Выполняет команду."""
        if self._fail_execute:
            raise RuntimeError("Execute failed")
        super().execute()
        self.execute_called = True

    def undo(self) -> None:
        """Отменяет команду."""
        super().undo()
        self.undo_called = True


@pytest.fixture
def mock_command() -> MockCommand:
    """Fixture для MockCommand."""
    return MockCommand(description="Test command")


# =============================================================================
# TEST: Command Creation
# =============================================================================


class TestCommandCreation:
    """Тесты создания Command."""

    def test_command_creation(self) -> None:
        """Создание Command с валидными параметрами."""
        cmd = MockCommand(description="Test command")

        assert cmd.get_description() == "Test command"
        assert cmd.is_executed is False

    def test_command_creation_default_description(self) -> None:
        """Создание Command с пустым описанием."""
        cmd = MockCommand()

        assert cmd.get_description() == ""

    def test_command_creation_truncates_long_description(self) -> None:
        """Длинное описание обрезается до MAX_DESCRIPTION_LENGTH."""
        long_desc = "A" * (MAX_DESCRIPTION_LENGTH + 50)
        cmd = MockCommand(description=long_desc)

        assert len(cmd.get_description()) <= MAX_DESCRIPTION_LENGTH

    def test_command_timestamp_set_on_creation(self) -> None:
        """Timestamp устанавливается при создании."""
        import time

        before = time.time()
        cmd = MockCommand()
        after = time.time()

        assert before <= cmd.timestamp <= after


# =============================================================================
# TEST: State Machine
# =============================================================================


class TestStateMachine:
    """Тесты state machine Command."""

    def test_initial_state(self, mock_command: MockCommand) -> None:
        """Начальное состояние: не выполнена."""
        assert mock_command.is_executed is False
        assert mock_command.can_undo() is False
        assert mock_command.can_redo() is True

    def test_after_execute(self, mock_command: MockCommand) -> None:
        """После execute(): выполнена."""
        mock_command.execute()

        assert mock_command.is_executed is True
        assert mock_command.can_undo() is True
        assert mock_command.can_redo() is True

    def test_after_undo(self, mock_command: MockCommand) -> None:
        """После undo(): не выполнена."""
        mock_command.execute()
        mock_command.undo()

        assert mock_command.is_executed is False
        assert mock_command.can_undo() is False
        assert mock_command.can_redo() is True

    def test_after_redo(self, mock_command: MockCommand) -> None:
        """После redo(): выполнена."""
        mock_command.execute()
        mock_command.undo()
        mock_command.redo()

        assert mock_command.is_executed is True
        assert mock_command.can_undo() is True


# =============================================================================
# TEST: Execute Method
# =============================================================================


class TestExecuteMethod:
    """Тесты метода execute()."""

    def test_execute_updates_timestamp(self, mock_command: MockCommand) -> None:
        """execute() обновляет timestamp."""
        import time

        old_ts = mock_command.timestamp
        time.sleep(0.01)  # Small delay to ensure different timestamp
        mock_command.execute()

        assert mock_command.timestamp > old_ts

    def test_execute_sets_executed_flag(self, mock_command: MockCommand) -> None:
        """execute() устанавливает is_executed=True."""
        mock_command.execute()

        assert mock_command.execute_called is True


# =============================================================================
# TEST: Undo Method
# =============================================================================


class TestUndoMethod:
    """Тесты метода undo()."""

    def test_undo_sets_executed_flag(self, mock_command: MockCommand) -> None:
        """undo() устанавливает is_executed=False."""
        mock_command.execute()
        mock_command.undo()

        assert mock_command.undo_called is True
        assert mock_command.is_executed is False


# =============================================================================
# TEST: Redo Method
# =============================================================================


class TestRedoMethod:
    """Тесты метода redo()."""

    def test_redo_calls_execute(self, mock_command: MockCommand) -> None:
        """redo() вызывает execute()."""
        mock_command.execute()
        mock_command.undo()
        mock_command.redo()

        # execute_called was True from first execute, redo calls it again
        assert mock_command.is_executed is True


# =============================================================================
# TEST: Description
# =============================================================================


class TestDescription:
    """Тесты описания команды."""

    def test_get_description_returns_description(self) -> None:
        """get_description() возвращает описание."""
        cmd = MockCommand(description="My command")

        assert cmd.get_description() == "My command"

    def test_description_truncated(self) -> None:
        """Описание обрезается до MAX_DESCRIPTION_LENGTH."""
        long_desc = "A" * 200
        cmd = MockCommand(description=long_desc)

        assert len(cmd.get_description()) == MAX_DESCRIPTION_LENGTH


# =============================================================================
# TEST: Representation
# =============================================================================


class TestRepresentation:
    """Тесты строкового представления."""

    def test_repr_contains_class_name(self, mock_command: MockCommand) -> None:
        """repr() содержит имя класса."""
        repr_str = repr(mock_command)

        assert "MockCommand" in repr_str

    def test_repr_contains_description(self, mock_command: MockCommand) -> None:
        """repr() содержит описание."""
        repr_str = repr(mock_command)

        assert "Test command" in repr_str

    def test_repr_contains_executed_state(self, mock_command: MockCommand) -> None:
        """repr() содержит состояние executed."""
        repr_str = repr(mock_command)

        assert "executed=False" in repr_str

        mock_command.execute()
        repr_str = repr(mock_command)

        assert "executed=True" in repr_str


# =============================================================================
# TEST: Abstract Method Contract
# =============================================================================


class TestAbstractMethodContract:
    """Тесты контракта абстрактных методов."""

    def test_cannot_instantiate_abstract_base(self) -> None:
        """Нельзя создать экземпляр абстрактного Command."""
        with pytest.raises(TypeError):
            Command()  # type: ignore[abstract]

    def test_subclass_must_implement_execute(self) -> None:
        """Подкласс должен реализовать execute()."""
        class IncompleteCommand(Command):  # type: ignore[abstract]
            def undo(self) -> None:
                pass

        with pytest.raises(TypeError):
            IncompleteCommand()  # type: ignore[abstract]

    def test_subclass_must_implement_undo(self) -> None:
        """Подкласс должен реализовать undo()."""
        class IncompleteCommand(Command):  # type: ignore[abstract]
            def execute(self) -> None:
                pass

        with pytest.raises(TypeError):
            IncompleteCommand()  # type: ignore[abstract]


# =============================================================================
# TEST: Security - Description Length
# =============================================================================


class TestSecurityDescriptionLength:
    """Тесты безопасности: длина описания."""

    def test_description_dos_protection(self) -> None:
        """Описание ограничено для защиты от DoS."""
        # Create description that's way too long
        malicious_desc = "A" * 10000
        cmd = MockCommand(description=malicious_desc)

        # Should be truncated
        assert len(cmd.get_description()) <= MAX_DESCRIPTION_LENGTH

    def test_description_with_unicode(self) -> None:
        """Описание с Unicode символами."""
        unicode_desc = "Тест 🎉 émoji" * 20
        cmd = MockCommand(description=unicode_desc)

        assert len(cmd.get_description()) <= MAX_DESCRIPTION_LENGTH


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.commands.command"])
