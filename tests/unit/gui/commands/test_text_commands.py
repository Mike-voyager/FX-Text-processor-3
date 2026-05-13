"""Unit-тесты для текстовых команд.

Проверяет:
- InsertTextCommand
- DeleteTextCommand
- ApplyFormatCommand
- SetCPICommand

Coverage target: ≥90%
"""

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock

import pytest

from src.gui.core.commands.text_commands import (
    DEFAULT_CPI,
    MAX_TEXT_LENGTH,
    VALID_CPI_VALUES,
    ApplyFormatCommand,
    DeleteTextCommand,
    InsertTextCommand,
    SetCPICommand,
)


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Fixture для Tk root окна."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def text_widget(tk_root: tk.Tk) -> tk.Text:
    """Fixture для tk.Text виджета."""
    return tk.Text(tk_root)


# =============================================================================
# TEST: InsertTextCommand
# =============================================================================


class TestInsertTextCommand:
    """Тесты InsertTextCommand."""

    def test_creation(self, text_widget: tk.Text) -> None:
        """Создание InsertTextCommand."""
        cmd = InsertTextCommand(text_widget, "Hello", "1.0")

        assert cmd.get_description() == 'Insert "Hello" at 1.0'

    def test_creation_with_tags(self, text_widget: tk.Text) -> None:
        """Создание с тегами форматирования."""
        cmd = InsertTextCommand(text_widget, "Hello", "1.0", tags=("bold",))

        assert cmd._tags == ("bold",)

    def test_creation_invalid_widget(self) -> None:
        """Создание с невалидным виджетом вызывает ValueError."""
        with pytest.raises(ValueError, match="должен быть tk.Text"):
            InsertTextCommand(None, "Hello", "1.0")  # type: ignore[arg-type]

    def test_creation_long_text_truncated(self, text_widget: tk.Text) -> None:
        """Длинный текст обрезается до MAX_TEXT_LENGTH."""
        long_text = "A" * (MAX_TEXT_LENGTH + 100)
        cmd = InsertTextCommand(text_widget, long_text, "1.0")

        assert len(cmd._text) <= MAX_TEXT_LENGTH

    def test_execute_inserts_text(self, text_widget: tk.Text) -> None:
        """execute() вставляет текст."""
        cmd = InsertTextCommand(text_widget, "Hello", "1.0")
        cmd.execute()

        content = text_widget.get("1.0", "end-1c")
        assert content == "Hello"

    def test_execute_with_tags(self, text_widget: tk.Text) -> None:
        """execute() вставляет текст с тегами."""
        text_widget.tag_configure("bold", font=("Courier", 12, "bold"))

        cmd = InsertTextCommand(text_widget, "Hello", "1.0", tags=("bold",))
        cmd.execute()

        content = text_widget.get("1.0", "end-1c")
        assert content == "Hello"

    def test_execute_sets_end_index(self, text_widget: tk.Text) -> None:
        """execute() устанавливает _end_index."""
        cmd = InsertTextCommand(text_widget, "Hello", "1.0")
        cmd.execute()

        assert cmd._end_index is not None
        assert cmd._end_index == "1.5"

    def test_execute_multiline(self, text_widget: tk.Text) -> None:
        """execute() с многострочным текстом."""
        cmd = InsertTextCommand(text_widget, "Line1\nLine2", "1.0")
        cmd.execute()

        content = text_widget.get("1.0", "end-1c")
        assert content == "Line1\nLine2"

    def test_undo_deletes_text(self, text_widget: tk.Text) -> None:
        """undo() удаляет вставленный текст."""
        cmd = InsertTextCommand(text_widget, "Hello", "1.0")
        cmd.execute()
        cmd.undo()

        content = text_widget.get("1.0", "end-1c")
        assert content == ""

    def test_undo_before_execute_raises(self, text_widget: tk.Text) -> None:
        """undo() до execute() вызывает RuntimeError."""
        cmd = InsertTextCommand(text_widget, "Hello", "1.0")

        with pytest.raises(RuntimeError, match="execute.*должен быть вызван"):
            cmd.undo()


# =============================================================================
# TEST: DeleteTextCommand
# =============================================================================


class TestDeleteTextCommand:
    """Тесты DeleteTextCommand."""

    def test_creation(self, text_widget: tk.Text) -> None:
        """Создание DeleteTextCommand."""
        cmd = DeleteTextCommand(text_widget, "1.0", "1.5")

        assert "Delete text from 1.0 to 1.5" in cmd.get_description()

    def test_creation_invalid_widget(self) -> None:
        """Создание с невалидным виджетом вызывает ValueError."""
        with pytest.raises(ValueError, match="должен быть tk.Text"):
            DeleteTextCommand(None, "1.0", "1.5")  # type: ignore[arg-type]

    def test_execute_deletes_text(self, text_widget: tk.Text) -> None:
        """execute() удаляет текст."""
        text_widget.insert("1.0", "Hello World")

        cmd = DeleteTextCommand(text_widget, "1.0", "1.5")
        cmd.execute()

        content = text_widget.get("1.0", "end-1c")
        assert content == " World"

    def test_execute_saves_deleted_text(self, text_widget: tk.Text) -> None:
        """execute() сохраняет удалённый текст."""
        text_widget.insert("1.0", "Hello World")

        cmd = DeleteTextCommand(text_widget, "1.0", "1.5")
        cmd.execute()

        assert cmd._deleted_text == "Hello"

    def test_undo_restores_text(self, text_widget: tk.Text) -> None:
        """undo() восстанавливает удалённый текст."""
        text_widget.insert("1.0", "Hello World")

        cmd = DeleteTextCommand(text_widget, "1.0", "1.5")
        cmd.execute()
        cmd.undo()

        content = text_widget.get("1.0", "end-1c")
        assert content == "Hello World"

    def test_undo_before_execute_raises(self, text_widget: tk.Text) -> None:
        """undo() до execute() вызывает RuntimeError."""
        cmd = DeleteTextCommand(text_widget, "1.0", "1.5")

        with pytest.raises(RuntimeError, match="execute.*должен быть вызван"):
            cmd.undo()


# =============================================================================
# TEST: ApplyFormatCommand
# =============================================================================


class TestApplyFormatCommand:
    """Тесты ApplyFormatCommand."""

    def test_creation(self, text_widget: tk.Text) -> None:
        """Создание ApplyFormatCommand."""
        cmd = ApplyFormatCommand(text_widget, "1.0", "1.5", ("bold",))

        assert "bold" in cmd.get_description()

    def test_creation_multiple_formats(self, text_widget: tk.Text) -> None:
        """Создание с несколькими форматами."""
        cmd = ApplyFormatCommand(text_widget, "1.0", "1.5", ("bold", "italic"))

        assert "bold" in cmd.get_description()
        assert "italic" in cmd.get_description()

    def test_creation_invalid_widget(self) -> None:
        """Создание с невалидным виджетом вызывает ValueError."""
        with pytest.raises(ValueError, match="должен быть tk.Text"):
            ApplyFormatCommand(None, "1.0", "1.5", ("bold",))  # type: ignore[arg-type]

    def test_creation_invalid_format(self, text_widget: tk.Text) -> None:
        """Создание с невалидным форматом вызывает ValueError."""
        with pytest.raises(ValueError, match="Неподдерживаемые форматы"):
            ApplyFormatCommand(text_widget, "1.0", "1.5", ("invalid_format",))

    def test_execute_applies_format(self, text_widget: tk.Text) -> None:
        """execute() применяет форматирование."""
        text_widget.insert("1.0", "Hello World")
        text_widget.tag_configure("bold", font=("Courier", 12, "bold"))

        cmd = ApplyFormatCommand(text_widget, "1.0", "1.5", ("bold",))
        cmd.execute()

        # Check that tag is applied
        tags = text_widget.tag_names("1.0")
        assert "bold" in tags

    def test_undo_removes_format(self, text_widget: tk.Text) -> None:
        """undo() удаляет форматирование."""
        text_widget.insert("1.0", "Hello World")
        text_widget.tag_configure("bold", font=("Courier", 12, "bold"))

        cmd = ApplyFormatCommand(text_widget, "1.0", "1.5", ("bold",))
        cmd.execute()
        cmd.undo()

        # Check that tag is removed
        tags = text_widget.tag_names("1.0")
        assert "bold" not in tags

    def test_undo_before_execute_raises(self, text_widget: tk.Text) -> None:
        """undo() до execute() вызывает RuntimeError."""
        cmd = ApplyFormatCommand(text_widget, "1.0", "1.5", ("bold",))

        with pytest.raises(RuntimeError, match="execute.*должен быть вызван"):
            cmd.undo()


# =============================================================================
# TEST: SetCPICommand
# =============================================================================


class TestSetCPICommand:
    """Тесты SetCPICommand."""

    def test_creation(self, text_widget: tk.Text) -> None:
        """Создание SetCPICommand."""
        cmd = SetCPICommand(text_widget, 12.0)

        assert cmd.get_description() == "Set CPI to 12.0"

    def test_creation_invalid_widget(self) -> None:
        """Создание с невалидным виджетом вызывает ValueError."""
        with pytest.raises(ValueError, match="должен быть tk.Text"):
            SetCPICommand(None, 12.0)  # type: ignore[arg-type]

    def test_creation_invalid_cpi(self, text_widget: tk.Text) -> None:
        """Создание с невалидным CPI вызывает ValueError."""
        with pytest.raises(ValueError, match="Недопустимое значение CPI"):
            SetCPICommand(text_widget, 13.0)

    def test_valid_cpi_values(self, text_widget: tk.Text) -> None:
        """Все валидные значения CPI принимаются."""
        for cpi in VALID_CPI_VALUES:
            cmd = SetCPICommand(text_widget, cpi)
            assert cmd._new_cpi == cpi

    def test_execute_applies_cpi_tag(self, text_widget: tk.Text) -> None:
        """execute() применяет CPI тег."""
        text_widget.insert("1.0", "Hello World")

        cmd = SetCPICommand(text_widget, 12.0)
        cmd.execute()

        # Check that tag is applied
        tags = text_widget.tag_names("1.0")
        assert "cpi_12" in tags

    def test_execute_range(self, text_widget: tk.Text) -> None:
        """execute() применяет CPI к диапазону."""
        text_widget.insert("1.0", "Hello World")

        cmd = SetCPICommand(text_widget, 15.0, "1.0", "1.5")
        cmd.execute()

        # Check that tag is applied to range
        tags = text_widget.tag_names("1.0")
        assert "cpi_15" in tags

    def test_undo_removes_cpi_tag(self, text_widget: tk.Text) -> None:
        """undo() удаляет CPI тег."""
        text_widget.insert("1.0", "Hello World")

        cmd = SetCPICommand(text_widget, 12.0)
        cmd.execute()
        cmd.undo()

        # Check that tag is removed
        tags = text_widget.tag_names("1.0")
        assert "cpi_12" not in tags

    def test_undo_before_execute_raises(self, text_widget: tk.Text) -> None:
        """undo() до execute() вызывает RuntimeError."""
        cmd = SetCPICommand(text_widget, 12.0)

        with pytest.raises(RuntimeError, match="execute.*должен быть вызван"):
            cmd.undo()


# =============================================================================
# TEST: Constants
# =============================================================================


class TestConstants:
    """Тесты констант."""

    def test_max_text_length(self) -> None:
        """MAX_TEXT_LENGTH определён."""
        assert MAX_TEXT_LENGTH == 100_000

    def test_valid_cpi_values(self) -> None:
        """VALID_CPI_VALUES содержит ожидаемые значения."""
        assert VALID_CPI_VALUES == frozenset({10.0, 12.0, 15.0, 17.0, 20.0})

    def test_default_cpi(self) -> None:
        """DEFAULT_CPI определён."""
        assert DEFAULT_CPI == 10.0


# =============================================================================
# TEST: Security - Text Length
# =============================================================================


class TestSecurityTextLength:
    """Тесты безопасности: длина текста."""

    def test_insert_text_dos_protection(self, text_widget: tk.Text) -> None:
        """InsertTextCommand ограничивает длину для DoS защиты."""
        malicious_text = "A" * 1000000  # Very large text

        cmd = InsertTextCommand(text_widget, malicious_text, "1.0")
        cmd.execute()

        content = text_widget.get("1.0", "end-1c")
        assert len(content) <= MAX_TEXT_LENGTH


# =============================================================================
# TEST: Module Exports
# =============================================================================


class TestModuleExports:
    """Тесты экспорта модуля."""

    def test_all_exports_defined(self) -> None:
        """Все exports определены."""
        from src.gui.core.commands import text_commands

        assert hasattr(text_commands, "__all__")
        assert "InsertTextCommand" in text_commands.__all__
        assert "DeleteTextCommand" in text_commands.__all__
        assert "ApplyFormatCommand" in text_commands.__all__
        assert "SetCPICommand" in text_commands.__all__


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.commands.text_commands"])
