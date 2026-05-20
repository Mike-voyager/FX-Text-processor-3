"""Тесты для undo/redo menu items.

Проверяет UndoRedoMenuItems и UndoRedoToolbarButtons.
GUI-тесты запускаются через xvfb-run.
"""

from __future__ import annotations

import tkinter as tk
from typing import Optional, Tuple

import pytest

from src.gui.workflow.undo_redo_menu import UndoRedoMenuItems, UndoRedoToolbarButtons


@pytest.fixture
def tk_root() -> tk.Tk:
    """Создаёт Tkinter root для тестов."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


class TestUndoRedoMenuItems:
    """Тесты UndoRedoMenuItems."""

    def test_add_to_menu(self, tk_root: tk.Tk) -> None:
        """add_to_menu добавляет пункты меню."""
        menu = tk.Menu(tk_root)
        items = UndoRedoMenuItems(
            undo_callback=lambda: None,
            redo_callback=lambda: None,
            get_undo_text=lambda: "Отменить переход",
            get_redo_text=lambda: "Повторить переход",
        )
        result = items.add_to_menu(menu)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_add_to_menu_with_index(self, tk_root: tk.Tk) -> None:
        """add_to_menu с указанным индексом добавляет пункты."""
        menu = tk.Menu(tk_root)
        items = UndoRedoMenuItems(
            undo_callback=lambda: None,
            redo_callback=lambda: None,
            get_undo_text=lambda: "Отменить",
            get_redo_text=lambda: "Повторить",
        )
        result = items.add_to_menu(menu, index=0)
        assert result == (0, 1)

    def test_update_labels(self, tk_root: tk.Tk) -> None:
        """update_labels обновляет подписи пунктов."""
        menu = tk.Menu(tk_root)
        counter = {"undo": 0, "redo": 0}

        def get_undo() -> Optional[str]:
            counter["undo"] += 1
            return f"Отмена {counter['undo']}"

        def get_redo() -> Optional[str]:
            counter["redo"] += 1
            return f"Повтор {counter['redo']}"

        items = UndoRedoMenuItems(
            undo_callback=lambda: None,
            redo_callback=lambda: None,
            get_undo_text=get_undo,
            get_redo_text=get_redo,
        )
        items.add_to_menu(menu)
        items.update_labels(menu)
        # Должно быть вызвано для обновления
        assert counter["undo"] > 0

    def test_enable_undo(self, tk_root: tk.Tk) -> None:
        """enable_undo переключает состояние пункта."""
        menu = tk.Menu(tk_root)
        items = UndoRedoMenuItems(
            undo_callback=lambda: None,
            redo_callback=lambda: None,
            get_undo_text=lambda: "Отменить",
            get_redo_text=lambda: "Повторить",
        )
        items.add_to_menu(menu)
        # Не должно вызывать ошибок
        items.enable_undo(menu, enabled=False)
        items.enable_undo(menu, enabled=True)

    def test_enable_redo(self, tk_root: tk.Tk) -> None:
        """enable_redo переключает состояние пункта."""
        menu = tk.Menu(tk_root)
        items = UndoRedoMenuItems(
            undo_callback=lambda: None,
            redo_callback=lambda: None,
            get_undo_text=lambda: "Отменить",
            get_redo_text=lambda: "Повторить",
        )
        items.add_to_menu(menu)
        items.enable_redo(menu, enabled=True)
        items.enable_redo(menu, enabled=False)

    def test_none_text_fallback(self, tk_root: tk.Tk) -> None:
        """None из get_text заменяется на стандартный текст."""
        menu = tk.Menu(tk_root)
        items = UndoRedoMenuItems(
            undo_callback=lambda: None,
            redo_callback=lambda: None,
            get_undo_text=lambda: None,
            get_redo_text=lambda: None,
        )
        result = items.add_to_menu(menu)
        assert result is not None


class TestUndoRedoToolbarButtons:
    """Тесты UndoRedoToolbarButtons."""

    def test_create_buttons(self, tk_root: tk.Tk) -> None:
        """create создаёт кнопки undo/redo."""
        frame = tk.Frame(tk_root)
        buttons = UndoRedoToolbarButtons(frame)
        undo_btn, redo_btn = buttons.create(
            undo_callback=lambda: None,
            redo_callback=lambda: None,
        )
        assert isinstance(undo_btn, tk.Button)
        assert isinstance(redo_btn, tk.Button)

    def test_set_undo_enabled(self, tk_root: tk.Tk) -> None:
        """set_undo_enabled переключает состояние кнопки."""
        frame = tk.Frame(tk_root)
        buttons = UndoRedoToolbarButtons(frame)
        buttons.create(
            undo_callback=lambda: None,
            redo_callback=lambda: None,
        )
        buttons.set_undo_enabled(True)
        buttons.set_undo_enabled(False)

    def test_set_redo_enabled(self, tk_root: tk.Tk) -> None:
        """set_redo_enabled переключает состояние кнопки."""
        frame = tk.Frame(tk_root)
        buttons = UndoRedoToolbarButtons(frame)
        buttons.create(
            undo_callback=lambda: None,
            redo_callback=lambda: None,
        )
        buttons.set_redo_enabled(True)
        buttons.set_redo_enabled(False)

    def test_set_undo_tooltip_no_error(self, tk_root: tk.Tk) -> None:
        """set_undo_tooltip не вызывает ошибок (заглушка)."""
        frame = tk.Frame(tk_root)
        buttons = UndoRedoToolbarButtons(frame)
        buttons.create(
            undo_callback=lambda: None,
            redo_callback=lambda: None,
        )
        buttons.set_undo_tooltip("Отменить переход")

    def test_set_redo_tooltip_no_error(self, tk_root: tk.Tk) -> None:
        """set_redo_tooltip не вызывает ошибок (заглушка)."""
        frame = tk.Frame(tk_root)
        buttons = UndoRedoToolbarButtons(frame)
        buttons.create(
            undo_callback=lambda: None,
            redo_callback=lambda: None,
        )
        buttons.set_redo_tooltip("Повторить переход")

    def test_buttons_initially_disabled(self, tk_root: tk.Tk) -> None:
        """Кнопки создаются в отключённом состоянии."""
        frame = tk.Frame(tk_root)
        buttons = UndoRedoToolbarButtons(frame)
        undo_btn, redo_btn = buttons.create(
            undo_callback=lambda: None,
            redo_callback=lambda: None,
        )
        assert str(undo_btn.cget("state")) == "disabled"
        assert str(redo_btn.cget("state")) == "disabled"