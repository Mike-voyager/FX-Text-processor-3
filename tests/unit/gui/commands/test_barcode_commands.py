"""Тесты для barcode_commands модуля.

Проверяет:
- InsertBarcodeCommand
- InsertQRCommand
- InsertPlaceholderCommand

Coverage target: ≥90%
"""

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock

import pytest

from src.gui.core.commands.barcode_commands import (
    InsertBarcodeCommand,
    InsertPlaceholderCommand,
    InsertQRCommand,
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
def text_widget(tk_root: tk.Tk) -> Generator[tk.Text, None, None]:
    """Fixture для tk.Text виджета."""
    widget = tk.Text(tk_root)
    widget.pack()
    yield widget
    widget.destroy()


@pytest.fixture
def mock_photo_image(tk_root: tk.Tk) -> Generator[tk.PhotoImage, None, None]:
    """Fixture для мок PhotoImage."""
    # Создаём реальный PhotoImage с минимальным размером
    img = tk.PhotoImage(width=1, height=1)
    yield img


# =============================================================================
# TEST: InsertBarcodeCommand
# =============================================================================


class TestInsertBarcodeCommand:
    """Тесты InsertBarcodeCommand."""

    def test_creation_with_valid_widget(self, text_widget: tk.Text, mock_photo_image: tk.PhotoImage) -> None:
        """Создание с валидным tk.Text."""
        cmd = InsertBarcodeCommand(text_widget, mock_photo_image, "1.0")
        assert cmd._text_widget == text_widget
        assert cmd._image == mock_photo_image

    def test_creation_with_invalid_widget(self, mock_photo_image: tk.PhotoImage) -> None:
        """Создание с невалидным виджетом вызывает ValueError."""
        with pytest.raises(ValueError, match="должен быть tk.Text"):
            InsertBarcodeCommand(MagicMock(), mock_photo_image, "1.0")

    def test_execute_inserts_image(self, text_widget: tk.Text, mock_photo_image: tk.PhotoImage) -> None:
        """execute() вставляет изображение."""
        cmd = InsertBarcodeCommand(text_widget, mock_photo_image, "1.0")
        cmd.execute()

        # После вставки изображения текстовое содержимое должно быть пустым,
        # но виджет содержит embedded image (1 embedded object)
        assert cmd._start_index is not None
        assert cmd._end_index is not None

    def test_undo_removes_image(self, text_widget: tk.Text, mock_photo_image: tk.PhotoImage) -> None:
        """undo() удаляет вставленное изображение."""
        cmd = InsertBarcodeCommand(text_widget, mock_photo_image, "1.0")
        cmd.execute()
        assert cmd._image is not None

        cmd.undo()

        # Ссылка на изображение очищена
        assert cmd._image is None

    def test_undo_without_execute_raises(self, text_widget: tk.Text, mock_photo_image: tk.PhotoImage) -> None:
        """undo() без execute() вызывает RuntimeError."""
        cmd = InsertBarcodeCommand(text_widget, mock_photo_image, "1.0")
        with pytest.raises(RuntimeError, match="execute.*должен быть вызван"):
            cmd.undo()


# =============================================================================
# TEST: InsertQRCommand
# =============================================================================


class TestInsertQRCommand:
    """Тесты InsertQRCommand."""

    def test_creation_with_valid_widget(self, text_widget: tk.Text, mock_photo_image: tk.PhotoImage) -> None:
        """Создание с валидным tk.Text."""
        cmd = InsertQRCommand(text_widget, mock_photo_image, "1.0")
        assert cmd._text_widget == text_widget

    def test_creation_with_invalid_widget(self, mock_photo_image: tk.PhotoImage) -> None:
        """Создание с невалидным виджетом вызывает ValueError."""
        with pytest.raises(ValueError, match="должен быть tk.Text"):
            InsertQRCommand(MagicMock(), mock_photo_image, "1.0")

    def test_execute_inserts_image(self, text_widget: tk.Text, mock_photo_image: tk.PhotoImage) -> None:
        """execute() вставляет QR изображение."""
        cmd = InsertQRCommand(text_widget, mock_photo_image, "1.0")
        cmd.execute()

        assert cmd._start_index is not None
        assert cmd._end_index is not None

    def test_undo_removes_image(self, text_widget: tk.Text, mock_photo_image: tk.PhotoImage) -> None:
        """undo() удаляет QR изображение."""
        cmd = InsertQRCommand(text_widget, mock_photo_image, "1.0")
        cmd.execute()
        assert cmd._image is not None

        cmd.undo()
        assert cmd._image is None

    def test_undo_without_execute_raises(self, text_widget: tk.Text, mock_photo_image: tk.PhotoImage) -> None:
        """undo() без execute() вызывает RuntimeError."""
        cmd = InsertQRCommand(text_widget, mock_photo_image, "1.0")
        with pytest.raises(RuntimeError, match="execute.*должен быть вызван"):
            cmd.undo()


# =============================================================================
# TEST: InsertPlaceholderCommand
# =============================================================================


class TestInsertPlaceholderCommand:
    """Тесты InsertPlaceholderCommand."""

    def test_creation_with_valid_widget(self, text_widget: tk.Text) -> None:
        """Создание с валидным tk.Text."""
        cmd = InsertPlaceholderCommand(text_widget, "BARCODE:CODE128", "12345", "1.0")
        assert cmd._text_widget == text_widget

    def test_creation_with_invalid_widget(self) -> None:
        """Создание с невалидным виджетом вызывает ValueError."""
        with pytest.raises(ValueError, match="должен быть tk.Text"):
            InsertPlaceholderCommand(MagicMock(), "BARCODE:CODE128", "12345", "1.0")

    def test_execute_inserts_placeholder(self, text_widget: tk.Text) -> None:
        """execute() вставляет placeholder текст."""
        cmd = InsertPlaceholderCommand(text_widget, "BARCODE:CODE128", "12345", "1.0")
        cmd.execute()

        text = text_widget.get("1.0", "end-1c")
        assert "┇BARCODE:CODE128:12345┇" in text

    def test_execute_inserts_qr_placeholder(self, text_widget: tk.Text) -> None:
        """execute() вставляет QR placeholder."""
        cmd = InsertPlaceholderCommand(text_widget, "QR", "https://example.com", "1.0")
        cmd.execute()

        text = text_widget.get("1.0", "end-1c")
        assert "┇QR:https://example.com┇" in text

    def test_undo_removes_placeholder(self, text_widget: tk.Text) -> None:
        """undo() удаляет placeholder текст."""
        cmd = InsertPlaceholderCommand(text_widget, "BARCODE:CODE128", "12345", "1.0")
        cmd.execute()

        assert text_widget.get("1.0", "end-1c") != ""

        cmd.undo()
        assert text_widget.get("1.0", "end-1c") == ""

    def test_undo_without_execute_raises(self, text_widget: tk.Text) -> None:
        """undo() без execute() вызывает RuntimeError."""
        cmd = InsertPlaceholderCommand(text_widget, "BARCODE:CODE128", "12345", "1.0")
        with pytest.raises(RuntimeError, match="execute.*должен быть вызван"):
            cmd.undo()

    def test_truncate_long_marker(self, text_widget: tk.Text) -> None:
        """Длинный marker_type обрезается."""
        long_marker = "X" * 50
        cmd = InsertPlaceholderCommand(text_widget, long_marker, "D", "1.0")
        assert len(cmd._marker_type) == 20

    def test_truncate_long_data(self, text_widget: tk.Text) -> None:
        """Длинные данные обрезаются до 50 символов."""
        long_data = "X" * 100
        cmd = InsertPlaceholderCommand(text_widget, "BARCODE:CODE128", long_data, "1.0")
        assert len(cmd._data) == 50


# =============================================================================
# TEST: Command Base Class Compliance
# =============================================================================


class TestCommandCompliance:
    """Тесты compliance с Command базовым классом."""

    def test_barcode_is_executed_after_execute(self, text_widget: tk.Text, mock_photo_image: tk.PhotoImage) -> None:
        """InsertBarcodeCommand.is_executed == True после execute()."""
        cmd = InsertBarcodeCommand(text_widget, mock_photo_image, "1.0")
        assert not cmd.is_executed
        cmd.execute()
        assert cmd.is_executed

    def test_barcode_is_executed_false_after_undo(self, text_widget: tk.Text, mock_photo_image: tk.PhotoImage) -> None:
        """InsertBarcodeCommand.is_executed == False после undo()."""
        cmd = InsertBarcodeCommand(text_widget, mock_photo_image, "1.0")
        cmd.execute()
        cmd.undo()
        assert not cmd.is_executed

    def test_qr_is_executed_after_execute(self, text_widget: tk.Text, mock_photo_image: tk.PhotoImage) -> None:
        """InsertQRCommand.is_executed == True после execute()."""
        cmd = InsertQRCommand(text_widget, mock_photo_image, "1.0")
        assert not cmd.is_executed
        cmd.execute()
        assert cmd.is_executed

    def test_placeholder_is_executed_after_execute(self, text_widget: tk.Text) -> None:
        """InsertPlaceholderCommand.is_executed == True после execute()."""
        cmd = InsertPlaceholderCommand(text_widget, "QR", "test", "1.0")
        assert not cmd.is_executed
        cmd.execute()
        assert cmd.is_executed


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.commands.barcode_commands"])
