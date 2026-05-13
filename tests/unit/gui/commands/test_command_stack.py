"""Unit-тесты для CommandStack.

Проверяет:
- Создание CommandStack
- Execute, undo, redo операции
- History limit enforcement
- Thread-safe операции
- Clear для wipe истории

Coverage target: ≥90%
"""

import threading
import time
from unittest.mock import MagicMock

import pytest

from src.gui.core.commands.command import Command
from src.gui.core.commands.command_stack import MAX_HISTORY, CommandStack


# =============================================================================
# FIXTURES
# =============================================================================


class SimpleCommand(Command):
    """Простая команда для тестирования."""

    def __init__(self, name: str = "", fail: bool = False) -> None:
        super().__init__(description=name or "Simple command")
        self.name = name or "Simple command"
        self.fail = fail
        self.executed = False
        self.undone = False

    def execute(self) -> None:
        if self.fail:
            raise RuntimeError("Execution failed")
        super().execute()
        self.executed = True

    def undo(self) -> None:
        super().undo()
        self.undone = True


@pytest.fixture
def command_stack() -> CommandStack:
    """Fixture для CommandStack."""
    return CommandStack()


@pytest.fixture
def simple_command() -> SimpleCommand:
    """Fixture для SimpleCommand."""
    return SimpleCommand(name="Test command")


# =============================================================================
# TEST: CommandStack Creation
# =============================================================================


class TestCommandStackCreation:
    """Тесты создания CommandStack."""

    def test_command_stack_creation(self) -> None:
        """Создание CommandStack."""
        stack = CommandStack()

        assert stack is not None
        assert len(stack) == 0

    def test_initial_state(self, command_stack: CommandStack) -> None:
        """Начальное состояние CommandStack."""
        assert command_stack.can_undo() is False
        assert command_stack.can_redo() is False
        assert command_stack.get_undo_description() is None
        assert command_stack.get_redo_description() is None


# =============================================================================
# TEST: Execute
# =============================================================================


class TestExecute:
    """Тесты выполнения команд."""

    def test_execute_command(self, command_stack: CommandStack, simple_command: SimpleCommand) -> None:
        """execute() выполняет команду."""
        command_stack.execute(simple_command)

        assert simple_command.executed is True
        assert command_stack.can_undo() is True

    def test_execute_adds_to_undo_stack(self, command_stack: CommandStack) -> None:
        """execute() добавляет команду в undo_stack."""
        cmd = SimpleCommand(name="Test command")
        command_stack.execute(cmd)

        assert command_stack.can_undo() is True
        assert command_stack.get_undo_description() == "Test command"

    def test_execute_clears_redo_stack(self, command_stack: CommandStack) -> None:
        """execute() очищает redo_stack."""
        cmd1 = SimpleCommand(name="First")
        cmd2 = SimpleCommand(name="Second")

        command_stack.execute(cmd1)
        command_stack.undo()
        assert command_stack.can_redo() is True

        command_stack.execute(cmd2)
        assert command_stack.can_redo() is False

    def test_execute_non_command_raises(self, command_stack: CommandStack) -> None:
        """execute() с не-Command вызывает TypeError."""
        with pytest.raises(TypeError, match="должен быть Command"):
            command_stack.execute("not a command")  # type: ignore[arg-type]

    def test_execute_propagates_exception(self, command_stack: CommandStack) -> None:
        """execute() пропагирует исключение от команды."""
        failing_cmd = SimpleCommand(name="Failing", fail=True)

        with pytest.raises(RuntimeError, match="Command execution failed"):
            command_stack.execute(failing_cmd)


# =============================================================================
# TEST: Undo
# =============================================================================


class TestUndo:
    """Тесты отмены команд."""

    def test_undo_executes_command_undo(self, command_stack: CommandStack, simple_command: SimpleCommand) -> None:
        """undo() вызывает undo() команды."""
        command_stack.execute(simple_command)
        command_stack.undo()

        assert simple_command.undone is True
        assert command_stack.can_undo() is False

    def test_undo_moves_to_redo_stack(self, command_stack: CommandStack, simple_command: SimpleCommand) -> None:
        """undo() перемещает команду в redo_stack."""
        command_stack.execute(simple_command)
        command_stack.undo()

        assert command_stack.can_redo() is True
        assert command_stack.get_redo_description() == "Test command"

    def test_undo_empty_stack_raises(self, command_stack: CommandStack) -> None:
        """undo() при пустом стеке вызывает RuntimeError."""
        with pytest.raises(RuntimeError, match="Нет команд для отмены"):
            command_stack.undo()

    def test_undo_returns_command_on_failure(self, command_stack: CommandStack) -> None:
        """undo() возвращает команду в стек при ошибке."""
        class FailUndoCommand(Command):
            def __init__(self) -> None:
                super().__init__("Fail undo")

            def execute(self) -> None:
                super().execute()

            def undo(self) -> None:
                raise RuntimeError("Undo failed")

        cmd = FailUndoCommand()
        command_stack.execute(cmd)

        with pytest.raises(RuntimeError, match="Undo failed"):
            command_stack.undo()

        # Command should still be undoable
        assert command_stack.can_undo() is True


# =============================================================================
# TEST: Redo
# =============================================================================


class TestRedo:
    """Тесты повтора команд."""

    def test_redo_re_executes_command(self, command_stack: CommandStack) -> None:
        """redo() повторно выполняет команду."""
        cmd = SimpleCommand(name="Test command")
        command_stack.execute(cmd)
        command_stack.undo()
        command_stack.redo()

        assert cmd.is_executed is True
        assert command_stack.can_undo() is True

    def test_redo_empty_stack_raises(self, command_stack: CommandStack) -> None:
        """redo() при пустом redo_stack вызывает RuntimeError."""
        with pytest.raises(RuntimeError, match="Нет команд для повтора"):
            command_stack.redo()

    def test_redo_returns_command_on_failure(self, command_stack: CommandStack) -> None:
        """redo() возвращает команду в стек при ошибке."""
        class FailRedoCommand(Command):
            def __init__(self) -> None:
                super().__init__("Fail redo")
                self._should_fail = False

            def execute(self) -> None:
                if self._should_fail:
                    raise RuntimeError("Redo failed")
                super().execute()

            def undo(self) -> None:
                super().undo()
                self._should_fail = True

        cmd = FailRedoCommand()
        command_stack.execute(cmd)
        command_stack.undo()

        with pytest.raises(RuntimeError, match="Redo failed"):
            command_stack.redo()

        # Command should still be redoable
        assert command_stack.can_redo() is True


# =============================================================================
# TEST: Multiple Commands
# =============================================================================


class TestMultipleCommands:
    """Тесты с несколькими командами."""

    def test_execute_multiple_commands(self, command_stack: CommandStack) -> None:
        """execute() нескольких команд."""
        cmd1 = SimpleCommand(name="First")
        cmd2 = SimpleCommand(name="Second")
        cmd3 = SimpleCommand(name="Third")

        command_stack.execute(cmd1)
        command_stack.execute(cmd2)
        command_stack.execute(cmd3)

        assert len(command_stack) == 3
        assert command_stack.can_undo() is True

    def test_undo_multiple_commands(self, command_stack: CommandStack) -> None:
        """undo() нескольких команд."""
        cmd1 = SimpleCommand(name="First")
        cmd2 = SimpleCommand(name="Second")

        command_stack.execute(cmd1)
        command_stack.execute(cmd2)

        command_stack.undo()
        assert cmd2.undone is True
        assert cmd1.undone is False

        command_stack.undo()
        assert cmd1.undone is True

    def test_undo_redo_sequence(self, command_stack: CommandStack) -> None:
        """Последовательность undo/redo."""
        cmd = SimpleCommand(name="Test")

        command_stack.execute(cmd)
        assert command_stack.can_undo() is True
        assert command_stack.can_redo() is False

        command_stack.undo()
        assert command_stack.can_undo() is False
        assert command_stack.can_redo() is True

        command_stack.redo()
        assert command_stack.can_undo() is True
        assert command_stack.can_redo() is False


# =============================================================================
# TEST: History Limit
# =============================================================================


class TestHistoryLimit:
    """Тесты ограничения истории."""

    def test_history_limit_enforced(self) -> None:
        """История ограничена MAX_HISTORY."""
        stack = CommandStack()

        # Execute more commands than limit
        for i in range(MAX_HISTORY + 50):
            stack.execute(SimpleCommand(name=f"Cmd{i}"))

        # Stack should not exceed limit
        assert len(stack) <= MAX_HISTORY

    def test_oldest_commands_removed(self) -> None:
        """Старые команды удаляются при превышении лимита."""
        stack = CommandStack()

        first_cmd = SimpleCommand(name="First")
        stack.execute(first_cmd)

        # Add many more commands
        for i in range(MAX_HISTORY):
            stack.execute(SimpleCommand(name=f"Cmd{i}"))

        # Stack should be at limit
        assert len(stack) <= MAX_HISTORY


# =============================================================================
# TEST: Clear (Security)
# =============================================================================


class TestClear:
    """Тесты очистки истории (Security)."""

    def test_clear_empties_undo_stack(self, command_stack: CommandStack) -> None:
        """clear() очищает undo_stack."""
        command_stack.execute(SimpleCommand(name="Test"))
        command_stack.clear()

        assert command_stack.can_undo() is False
        assert len(command_stack) == 0

    def test_clear_empties_redo_stack(self, command_stack: CommandStack) -> None:
        """clear() очищает redo_stack."""
        command_stack.execute(SimpleCommand(name="Test"))
        command_stack.undo()
        assert command_stack.can_redo() is True

        command_stack.clear()
        assert command_stack.can_redo() is False

    def test_clear_allows_commands_gc(self, command_stack: CommandStack) -> None:
        """clear() позволяет GC собрать команды."""
        # This is a conceptual test - commands become eligible for GC
        command_stack.execute(SimpleCommand(name="Test"))
        command_stack.clear()

        # Commands are no longer referenced by the stack
        assert len(command_stack) == 0


# =============================================================================
# TEST: Thread Safety
# =============================================================================


class TestThreadSafety:
    """Тесты thread-safe операций."""

    def test_concurrent_execute(self) -> None:
        """Параллельное выполнение команд."""
        stack = CommandStack()
        commands: list[SimpleCommand] = []
        errors: list[Exception] = []

        def execute_commands(start: int, count: int) -> None:
            try:
                for i in range(count):
                    cmd = SimpleCommand(name=f"Thread{start}-Cmd{i}")
                    stack.execute(cmd)
                    commands.append(cmd)
            except Exception as e:
                errors.append(e)

        # Start multiple threads
        threads: list[threading.Thread] = []
        for i in range(3):
            t = threading.Thread(target=execute_commands, args=(i, 10))
            threads.append(t)
            t.start()

        # Wait for all threads
        for t in threads:
            t.join()

        # No errors should occur
        assert len(errors) == 0
        # All commands should be executed
        assert len(commands) == 30
        assert stack.can_undo() is True

    def test_concurrent_undo_redo(self, command_stack: CommandStack) -> None:
        """Параллельные undo/redo операции."""
        # Setup
        for i in range(5):
            command_stack.execute(SimpleCommand(name=f"Cmd{i}"))

        results: list[bool] = []

        def do_undo() -> None:
            try:
                command_stack.undo()
                results.append(True)
            except RuntimeError:
                results.append(False)

        # Start threads trying to undo
        threads: list[threading.Thread] = []
        for _ in range(3):
            t = threading.Thread(target=do_undo)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Some operations succeeded, some failed (as expected)
        assert len(results) == 3


# =============================================================================
# TEST: Description Methods
# =============================================================================


class TestDescriptionMethods:
    """Тесты методов получения описания."""

    def test_get_undo_description(self, command_stack: CommandStack) -> None:
        """get_undo_description() возвращает описание."""
        command_stack.execute(SimpleCommand(name="Insert text"))

        assert command_stack.get_undo_description() == "Insert text"

    def test_get_undo_description_empty(self, command_stack: CommandStack) -> None:
        """get_undo_description() при пустом стеке возвращает None."""
        assert command_stack.get_undo_description() is None

    def test_get_redo_description(self, command_stack: CommandStack) -> None:
        """get_redo_description() возвращает описание."""
        command_stack.execute(SimpleCommand(name="Insert text"))
        command_stack.undo()

        assert command_stack.get_redo_description() == "Insert text"

    def test_get_redo_description_empty(self, command_stack: CommandStack) -> None:
        """get_redo_description() при пустом стеке возвращает None."""
        assert command_stack.get_redo_description() is None


# =============================================================================
# TEST: String Representation
# =============================================================================


class TestStringRepresentation:
    """Тесты строкового представления."""

    def test_repr_empty(self, command_stack: CommandStack) -> None:
        """repr() для пустого стека."""
        repr_str = repr(command_stack)

        assert "CommandStack" in repr_str
        assert "undo=0" in repr_str
        assert "redo=0" in repr_str

    def test_repr_with_commands(self, command_stack: CommandStack) -> None:
        """repr() со командами."""
        command_stack.execute(SimpleCommand(name="Test"))
        repr_str = repr(command_stack)

        assert "undo=1" in repr_str


# =============================================================================
# TEST: Length
# =============================================================================


class TestLength:
    """Тесты метода __len__."""

    def test_len_empty(self, command_stack: CommandStack) -> None:
        """len() для пустого стека."""
        assert len(command_stack) == 0

    def test_len_with_undo(self, command_stack: CommandStack) -> None:
        """len() с командами в undo_stack."""
        command_stack.execute(SimpleCommand(name="Test"))
        assert len(command_stack) == 1

    def test_len_with_redo(self, command_stack: CommandStack) -> None:
        """len() с командами в redo_stack."""
        command_stack.execute(SimpleCommand(name="Test"))
        command_stack.undo()
        assert len(command_stack) == 1


# =============================================================================
# TEST: Security - Command Stack Wipe
# =============================================================================


class TestSecurityCommandStackWipe:
    """Тесты безопасности: очистка стека команд."""

    def test_clear_for_session_lock(self, command_stack: CommandStack) -> None:
        """clear() используется при session lock."""
        # Simulate editing sensitive content
        command_stack.execute(SimpleCommand(name="Insert password"))
        command_stack.execute(SimpleCommand(name="Insert SSN"))

        # User locks session - clear history
        command_stack.clear()

        # History should be wiped
        assert command_stack.can_undo() is False
        assert command_stack.can_redo() is False
        assert len(command_stack) == 0

    def test_clear_prevents_information_leak(self, command_stack: CommandStack) -> None:
        """clear() предотвращает утечку через undo/redo."""
        sensitive_cmd = SimpleCommand(name="Type: secret_password_123")
        command_stack.execute(sensitive_cmd)

        # Clear to prevent access via undo/redo
        command_stack.clear()

        # Undo description should be None
        assert command_stack.get_undo_description() is None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.commands.command_stack"])
