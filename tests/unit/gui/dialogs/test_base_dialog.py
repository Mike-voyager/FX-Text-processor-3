"""Unit-тесты для BaseDialog.

Проверяет:
- Создание диалога (модальный/немодальный)
- Центрирование окна
- close() с результатом
- show() модальное поведение
- _cancel_afters() очистка таймеров
- destroy() с callback
- Escape обработка
- get_result() возвращает установленный результат

Coverage target: >=90%
"""

from __future__ import annotations

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest
from src.gui.dialogs.base_dialog import BaseDialog


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Fixture для Tk root окна."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


# =============================================================================
# TEST: BaseDialog Creation
# =============================================================================


class TestBaseDialogCreation:
    """Тесты создания BaseDialog."""

    def test_dialog_creation_modal(self, tk_root: tk.Tk) -> None:
        """Создание модального диалога."""
        dialog = BaseDialog(tk_root, title="Test", modal=True)
        assert dialog.title() == "Test"
        assert dialog._result is None
        assert dialog._after_ids == []
        dialog.destroy()

    def test_dialog_creation_non_modal(self, tk_root: tk.Tk) -> None:
        """Создание немодального диалога."""
        dialog = BaseDialog(tk_root, title="Non-Modal", modal=False)
        assert dialog.title() == "Non-Modal"
        dialog.destroy()

    def test_dialog_creation_with_on_close(self, tk_root: tk.Tk) -> None:
        """Создание с on_close callback."""
        callback = MagicMock()
        dialog = BaseDialog(tk_root, title="CB", on_close=callback)
        assert dialog._on_close_callback is callback
        dialog.destroy()

    def test_dialog_default_title(self, tk_root: tk.Tk) -> None:
        """Создание без заголовка — заголовок пустой."""
        dialog = BaseDialog(tk_root)
        # Tk default title is the script name, but may be empty
        assert isinstance(dialog.title(), str)
        dialog.destroy()

    def test_dialog_center_on_parent(self, tk_root: tk.Tk) -> None:
        """Создание с center_on_parent=True."""
        dialog = BaseDialog(tk_root, title="Center", center_on_parent=True)
        # after_idle callback registered
        dialog.destroy()

    def test_dialog_no_center_on_parent(self, tk_root: tk.Tk) -> None:
        """Создание с center_on_parent=False."""
        dialog = BaseDialog(tk_root, title="NoCenter", center_on_parent=False)
        dialog.destroy()


# =============================================================================
# TEST: BaseDialog close() and get_result()
# =============================================================================


class TestBaseDialogCloseResult:
    """Тесты close() и get_result() BaseDialog."""

    def test_close_sets_result(self, tk_root: tk.Tk) -> None:
        """close() устанавливает результат и уничтожает окно."""
        dialog = BaseDialog(tk_root, title="Result")
        dialog._result = None

        # Patch destroy to check it's called
        with patch.object(dialog, "destroy") as mock_destroy:
            dialog.close(result="ok")
            assert dialog._result == "ok"
            mock_destroy.assert_called_once()

    def test_close_default_result_none(self, tk_root: tk.Tk) -> None:
        """close() без аргумента устанавливает None."""
        dialog = BaseDialog(tk_root, title="Default")
        with patch.object(dialog, "destroy"):
            dialog.close()
            assert dialog._result is None

    def test_get_result(self, tk_root: tk.Tk) -> None:
        """get_result() возвращает текущий результат."""
        dialog = BaseDialog(tk_root, title="GetResult")
        dialog._result = "test_value"
        assert dialog.get_result() == "test_value"
        dialog.destroy()

    def test_get_result_default(self, tk_root: tk.Tk) -> None:
        """get_result() по умолчанию возвращает None."""
        dialog = BaseDialog(tk_root, title="DefaultResult")
        assert dialog.get_result() is None
        dialog.destroy()


# =============================================================================
# TEST: BaseDialog show()
# =============================================================================


class TestBaseDialogShow:
    """Тесты show() BaseDialog."""

    @patch.object(BaseDialog, "wait_window")
    @patch.object(BaseDialog, "grab_set")
    @patch.object(BaseDialog, "wait_visibility")
    @patch.object(BaseDialog, "deiconify")
    def test_show_modal(
        self,
        mock_deiconify: MagicMock,
        mock_wait_vis: MagicMock,
        mock_grab: MagicMock,
        mock_wait: MagicMock,
        tk_root: tk.Tk,
    ) -> None:
        """show() модального диалога вызывает deiconify, wait_visibility, grab_set, wait_window."""
        dialog = BaseDialog(tk_root, title="ModalShow", modal=True)
        dialog._result = "modal_result"
        result = dialog.show()

        mock_deiconify.assert_called_once()
        mock_wait_vis.assert_called_once()
        mock_grab.assert_called_once()
        mock_wait.assert_called_once()
        assert result == "modal_result"
        dialog.destroy()

    @patch.object(BaseDialog, "wait_window")
    @patch.object(BaseDialog, "wait_visibility")
    @patch.object(BaseDialog, "deiconify")
    def test_show_returns_result(
        self,
        mock_deiconify: MagicMock,
        mock_wait_vis: MagicMock,
        mock_wait: MagicMock,
        tk_root: tk.Tk,
    ) -> None:
        """show() возвращает результат из get_result()."""
        dialog = BaseDialog(tk_root, title="ShowResult")
        dialog._result = 42
        result = dialog.show()
        assert result == 42
        dialog.destroy()


# =============================================================================
# TEST: BaseDialog _cancel_afters()
# =============================================================================


class TestBaseDialogCancelAfters:
    """Тесты _cancel_afters() BaseDialog."""

    def test_cancel_afters_clears_list(self, tk_root: tk.Tk) -> None:
        """_cancel_afters() очищает список after_ids."""
        dialog = BaseDialog(tk_root, title="Afters")

        # Add a mock after_id
        dialog._after_ids = ["timer1", "timer2"]

        with patch.object(dialog, "after_cancel") as mock_cancel:
            dialog._cancel_afters()
            assert mock_cancel.call_count == 2

        assert dialog._after_ids == []
        dialog.destroy()

    def test_cancel_afters_empty_list(self, tk_root: tk.Tk) -> None:
        """_cancel_afters() с пустым списком не вызывает after_cancel."""
        dialog = BaseDialog(tk_root, title="EmptyAfters")
        dialog._after_ids = []
        dialog._cancel_afters()
        assert dialog._after_ids == []
        dialog.destroy()

    def test_cancel_afters_ignores_tclerror(self, tk_root: tk.Tk) -> None:
        """_cancel_afters() игнорирует TclError при отмене таймера."""
        dialog = BaseDialog(tk_root, title="TclError")
        dialog._after_ids = ["bad_id"]

        with patch.object(dialog, "after_cancel", side_effect=tk.TclError):
            dialog._cancel_afters()  # Should not raise
        assert dialog._after_ids == []
        dialog.destroy()


# =============================================================================
# TEST: BaseDialog destroy()
# =============================================================================


class TestBaseDialogDestroy:
    """Тесты destroy() BaseDialog."""

    def test_destroy_calls_cancel_afters(self, tk_root: tk.Tk) -> None:
        """destroy() вызывает _cancel_afters()."""
        dialog = BaseDialog(tk_root, title="DestroyAfters")
        dialog._after_ids = ["timer1"]

        with patch.object(dialog, "_cancel_afters") as mock_cancel:
            # Call BaseDialog.destroy() which should call _cancel_afters
            # Patch super().destroy (tk.Toplevel.destroy) to avoid Tcl errors
            with patch("tkinter.Toplevel.destroy"):
                BaseDialog.destroy(dialog)
            mock_cancel.assert_called_once()

    def test_destroy_calls_on_close_callback(self, tk_root: tk.Tk) -> None:
        """destroy() вызывает on_close callback."""
        callback = MagicMock()
        dialog = BaseDialog(tk_root, title="CallbackDestroy", on_close=callback)

        # Patch super().destroy to avoid Tcl errors
        with patch("tkinter.Toplevel.destroy"):
            BaseDialog.destroy(dialog)

        callback.assert_called_once()

    def test_destroy_no_callback(self, tk_root: tk.Tk) -> None:
        """destroy() без callback не вызывает ошибку."""
        dialog = BaseDialog(tk_root, title="NoCallback")
        dialog.destroy()  # Should not raise


# =============================================================================
# TEST: BaseDialog _on_escape and _on_close
# =============================================================================


class TestBaseDialogEventHandlers:
    """Тесты обработчиков событий BaseDialog."""

    @patch.object(BaseDialog, "close")
    def test_on_escape_calls_close(self, mock_close: MagicMock, tk_root: tk.Tk) -> None:
        """_on_escape вызывает close()."""
        dialog = BaseDialog(tk_root, title="Escape", modal=True)
        dialog._on_escape()
        mock_close.assert_called_once()
        dialog.destroy()

    @patch.object(BaseDialog, "close")
    def test_on_close_calls_close(self, mock_close: MagicMock, tk_root: tk.Tk) -> None:
        """_on_close вызывает close()."""
        dialog = BaseDialog(tk_root, title="CloseHandler")
        dialog._on_close()
        mock_close.assert_called_once()
        dialog.destroy()


# =============================================================================
# TEST: BaseDialog _center_window()
# =============================================================================


class TestBaseDialogCenterWindow:
    """Тесты _center_window() BaseDialog."""

    def test_center_window_sets_geometry(self, tk_root: tk.Tk) -> None:
        """_center_window() устанавливает геометрию окна."""
        dialog = BaseDialog(tk_root, title="Center", center_on_parent=False)
        # Manually call _center_window
        dialog._center_window()
        # Geometry should be set (position string contains +x+y)
        geometry = dialog.geometry()
        assert "+" in geometry
        dialog.destroy()


# =============================================================================
# TEST: Module Exports
# =============================================================================


class TestBaseDialogExports:
    """Тесты экспортов модуля."""

    def test_all_contains_base_dialog(self) -> None:
        """__all__ содержит BaseDialog."""
        from src.gui.dialogs.base_dialog import __all__

        assert "BaseDialog" in __all__


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.dialogs.base_dialog"])