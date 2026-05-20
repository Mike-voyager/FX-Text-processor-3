"""Unit-тесты для confirm_dialog.

Проверяет:
- SaveChangesDialog создание и show()
- ConfirmResult frozen dataclass
- Кнопки Сохранить/Не сохранять/Отмена
- show_static() обратная совместимость
- __all__ экспорты

Coverage target: >=90%
"""

from __future__ import annotations

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest
from src.gui.dialogs.confirm_dialog import ConfirmResult, SaveChangesDialog


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Fixture для Tk root окна."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


# =============================================================================
# TEST: ConfirmResult
# =============================================================================


class TestConfirmResult:
    """Тесты frozen dataclass ConfirmResult."""

    def test_confirm_result_yes(self) -> None:
        """Создание результата 'yes'."""
        result = ConfirmResult(choice="yes")
        assert result.choice == "yes"

    def test_confirm_result_no(self) -> None:
        """Создание результата 'no'."""
        result = ConfirmResult(choice="no")
        assert result.choice == "no"

    def test_confirm_result_cancel(self) -> None:
        """Создание результата 'cancel'."""
        result = ConfirmResult(choice="cancel")
        assert result.choice == "cancel"

    def test_confirm_result_frozen(self) -> None:
        """ConfirmResult — frozen dataclass, неизменяемый."""
        result = ConfirmResult(choice="yes")
        with pytest.raises(AttributeError):
            result.choice = "no"  # type: ignore[misc]

    def test_confirm_result_equality(self) -> None:
        """Два ConfirmResult с одинаковым choice равны."""
        r1 = ConfirmResult(choice="yes")
        r2 = ConfirmResult(choice="yes")
        assert r1 == r2

    def test_confirm_result_inequality(self) -> None:
        """Два ConfirmResult с разным choice не равны."""
        r1 = ConfirmResult(choice="yes")
        r2 = ConfirmResult(choice="no")
        assert r1 != r2


# =============================================================================
# TEST: SaveChangesDialog Creation
# =============================================================================


class TestSaveChangesDialogCreation:
    """Тесты создания SaveChangesDialog."""

    def test_dialog_creation(self, tk_root: tk.Tk) -> None:
        """Создание диалога без имени документа."""
        dialog = SaveChangesDialog(parent=tk_root)
        assert dialog._document_name == ""
        assert dialog._result_data is None
        dialog.destroy()

    def test_dialog_creation_with_name(self, tk_root: tk.Tk) -> None:
        """Создание диалога с именем документа."""
        dialog = SaveChangesDialog(parent=tk_root, document_name="test.fxsd")
        assert dialog._document_name == "test.fxsd"
        dialog.destroy()

    def test_dialog_title(self, tk_root: tk.Tk) -> None:
        """Заголовок окна — «Сохранить изменения?»."""
        dialog = SaveChangesDialog(parent=tk_root)
        assert "Сохранить изменения" in dialog.title()
        dialog.destroy()


# =============================================================================
# TEST: SaveChangesDialog Interaction
# =============================================================================


class TestSaveChangesDialogInteraction:
    """Тесты взаимодействия с SaveChangesDialog."""

    @patch.object(SaveChangesDialog, "wait_window")
    @patch.object(SaveChangesDialog, "wait_visibility")
    @patch.object(SaveChangesDialog, "deiconify")
    def test_show_returns_none_initially(
        self,
        mock_deiconify: MagicMock,
        mock_wait_vis: MagicMock,
        mock_wait: MagicMock,
        tk_root: tk.Tk,
    ) -> None:
        """show() возвращает None если результат не установлен."""
        dialog = SaveChangesDialog(parent=tk_root)
        result = dialog.show()
        assert result is None
        dialog.destroy()

    @patch.object(SaveChangesDialog, "wait_window")
    @patch.object(SaveChangesDialog, "wait_visibility")
    @patch.object(SaveChangesDialog, "deiconify")
    def test_show_returns_result_data(
        self,
        mock_deiconify: MagicMock,
        mock_wait_vis: MagicMock,
        mock_wait: MagicMock,
        tk_root: tk.Tk,
    ) -> None:
        """show() возвращает _result_data если установлен."""
        dialog = SaveChangesDialog(parent=tk_root)
        dialog._result_data = ConfirmResult(choice="yes")
        result = dialog.show()
        assert result is not None
        assert result.choice == "yes"
        dialog.destroy()

    @patch.object(SaveChangesDialog, "close")
    def test_on_yes_calls_close(self, mock_close: MagicMock, tk_root: tk.Tk) -> None:
        """_on_yes устанавливает результат 'yes' и вызывает close."""
        dialog = SaveChangesDialog(parent=tk_root)
        dialog._on_yes()
        assert dialog._result_data is not None
        assert dialog._result_data.choice == "yes"
        mock_close.assert_called_once()

    @patch.object(SaveChangesDialog, "close")
    def test_on_no_calls_close(self, mock_close: MagicMock, tk_root: tk.Tk) -> None:
        """_on_no устанавливает результат 'no' и вызывает close."""
        dialog = SaveChangesDialog(parent=tk_root)
        dialog._on_no()
        assert dialog._result_data is not None
        assert dialog._result_data.choice == "no"
        mock_close.assert_called_once()

    @patch.object(SaveChangesDialog, "close")
    def test_on_cancel_calls_close(self, mock_close: MagicMock, tk_root: tk.Tk) -> None:
        """_on_cancel устанавливает результат 'cancel' и вызывает close."""
        dialog = SaveChangesDialog(parent=tk_root)
        dialog._on_cancel()
        assert dialog._result_data is not None
        assert dialog._result_data.choice == "cancel"
        mock_close.assert_called_once()


# =============================================================================
# TEST: SaveChangesDialog show_static()
# =============================================================================


class TestSaveChangesDialogStatic:
    """Тесты статического метода show_static()."""

    @patch("src.gui.dialogs.confirm_dialog.messagebox.askyesnocancel")
    def test_show_static_yes(self, mock_messagebox: MagicMock) -> None:
        """show_static() возвращает 'yes' при True."""
        mock_messagebox.return_value = True
        result = SaveChangesDialog.show_static()
        assert result == "yes"

    @patch("src.gui.dialogs.confirm_dialog.messagebox.askyesnocancel")
    def test_show_static_no(self, mock_messagebox: MagicMock) -> None:
        """show_static() возвращает 'no' при False."""
        mock_messagebox.return_value = False
        result = SaveChangesDialog.show_static()
        assert result == "no"

    @patch("src.gui.dialogs.confirm_dialog.messagebox.askyesnocancel")
    def test_show_static_cancel(self, mock_messagebox: MagicMock) -> None:
        """show_static() возвращает 'cancel' при None."""
        mock_messagebox.return_value = None
        result = SaveChangesDialog.show_static()
        assert result == "cancel"


# =============================================================================
# TEST: Module Exports
# =============================================================================


class TestConfirmDialogExports:
    """Тесты экспортов модуля."""

    def test_all_contains_classes(self) -> None:
        """__all__ содержит SaveChangesDialog и ConfirmResult."""
        from src.gui.dialogs.confirm_dialog import __all__

        assert "SaveChangesDialog" in __all__
        assert "ConfirmResult" in __all__


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.dialogs.confirm_dialog"])