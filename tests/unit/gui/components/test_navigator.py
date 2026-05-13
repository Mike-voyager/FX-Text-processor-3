"""Unit-тесты для Navigator.

Проверяет:
- Создание Navigator
- Управление позицией
- Переход к строкам
- Валидация ввода
- Callback-функции

Coverage target: ≥90%
"""

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock

import pytest

from src.gui.components.navigator import (
    MAX_LINE_NUMBER,
    NAVIGATOR_HEIGHT,
    Navigator,
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
def navigator(tk_root: tk.Tk) -> Generator[Navigator, None, None]:
    """Fixture для Navigator."""
    nav = Navigator(
        widget_id="test_navigator",
        initial_line=1,
        initial_column=1,
        initial_total_lines=100,
    )
    nav.mount(tk_root)
    yield nav


# =============================================================================
# TEST: Navigator Creation
# =============================================================================


class TestNavigatorCreation:
    """Тесты создания Navigator."""

    def test_creation(self) -> None:
        """Создание Navigator."""
        nav = Navigator(
            widget_id="test_navigator",
            initial_line=1,
            initial_column=1,
            initial_total_lines=100,
        )

        assert nav.widget_id == "test_navigator"
        assert nav.get_position() == (1, 1)
        assert nav.get_total_lines() == 100

    def test_creation_with_controller(self) -> None:
        """Создание с контроллером."""
        controller = MagicMock()
        nav = Navigator(
            widget_id="test_navigator",
            controller=controller,
            initial_line=1,
            initial_column=1,
            initial_total_lines=100,
        )

        assert nav._controller == controller

    def test_creation_with_callbacks(self) -> None:
        """Создание с callback-функциями."""
        on_goto_line = MagicMock()
        on_goto_start = MagicMock()
        on_goto_end = MagicMock()

        nav = Navigator(
            widget_id="test_navigator",
            on_goto_line=on_goto_line,
            on_goto_start=on_goto_start,
            on_goto_end=on_goto_end,
            initial_line=1,
            initial_column=1,
            initial_total_lines=100,
        )

        assert nav._on_goto_line == on_goto_line
        assert nav._on_goto_start == on_goto_start
        assert nav._on_goto_end == on_goto_end

    def test_creation_invalid_line_raises(self) -> None:
        """Создание с невалидной строкой вызывает ValueError."""
        with pytest.raises(ValueError, match="Номер строки должен быть >= 1"):
            Navigator(
                widget_id="test_navigator",
                initial_line=0,
                initial_column=1,
                initial_total_lines=100,
            )

    def test_creation_invalid_column_raises(self) -> None:
        """Создание с невалидной колонкой вызывает ValueError."""
        with pytest.raises(ValueError, match="Номер колонки должен быть >= 1"):
            Navigator(
                widget_id="test_navigator",
                initial_line=1,
                initial_column=0,
                initial_total_lines=100,
            )

    def test_creation_negative_total_lines_raises(self) -> None:
        """Создание с отрицательным количеством строк вызывает ValueError."""
        with pytest.raises(ValueError, match="Количество строк не может быть отрицательным"):
            Navigator(
                widget_id="test_navigator",
                initial_line=1,
                initial_column=1,
                initial_total_lines=-1,
            )


# =============================================================================
# TEST: Position Management
# =============================================================================


class TestPositionManagement:
    """Тесты управления позицией."""

    def test_get_position(self, navigator: Navigator) -> None:
        """get_position() возвращает текущую позицию."""
        assert navigator.get_position() == (1, 1)

    def test_set_position(self, navigator: Navigator) -> None:
        """set_position() устанавливает позицию."""
        navigator.set_position(line=10, column=25)

        assert navigator.get_position() == (10, 25)

    def test_set_position_invalid_line_raises(self, navigator: Navigator) -> None:
        """set_position() с невалидной строкой вызывает ValueError."""
        with pytest.raises(ValueError, match="Номер строки должен быть >= 1"):
            navigator.set_position(line=0, column=1)

    def test_set_position_invalid_column_raises(self, navigator: Navigator) -> None:
        """set_position() с невалидной колонкой вызывает ValueError."""
        with pytest.raises(ValueError, match="Номер колонки должен быть >= 1"):
            navigator.set_position(line=1, column=0)


# =============================================================================
# TEST: Total Lines Management
# =============================================================================


class TestTotalLinesManagement:
    """Тесты управления общим количеством строк."""

    def test_get_total_lines(self, navigator: Navigator) -> None:
        """get_total_lines() возвращает общее количество строк."""
        assert navigator.get_total_lines() == 100

    def test_set_total_lines(self, navigator: Navigator) -> None:
        """set_total_lines() устанавливает количество строк."""
        navigator.set_total_lines(150)

        assert navigator.get_total_lines() == 150

    def test_set_total_lines_negative_sets_one(self, navigator: Navigator) -> None:
        """set_total_lines() с отрицательным значением вызывает ошибку."""
        with pytest.raises(ValueError, match="Количество строк не может быть отрицательным"):
            navigator.set_total_lines(-5)


# =============================================================================
# TEST: Sanitization
# =============================================================================


class TestSanitization:
    """Тесты санитизации ввода."""

    def test_sanitize_line_input_valid(self, navigator: Navigator) -> None:
        """_sanitize_line_input() принимает валидный ввод."""
        result = navigator._sanitize_line_input("50")

        assert result == 50

    def test_sanitize_line_input_non_numeric(self, navigator: Navigator) -> None:
        """_sanitize_line_input() отклоняет нечисловой ввод."""
        result = navigator._sanitize_line_input("abc")

        assert result is None

    def test_sanitize_line_input_zero(self, navigator: Navigator) -> None:
        """_sanitize_line_input() отклоняет 0."""
        result = navigator._sanitize_line_input("0")

        assert result is None

    def test_sanitize_line_input_too_large(self, navigator: Navigator) -> None:
        """_sanitize_line_input() отклоняет слишком большое число."""
        result = navigator._sanitize_line_input(str(MAX_LINE_NUMBER + 1))

        assert result is None


# =============================================================================
# TEST: Format Position
# =============================================================================


class TestFormatPosition:
    """Тесты форматирования позиции."""

    def test_format_position(self, navigator: Navigator) -> None:
        """_format_position() форматирует позицию."""
        navigator.set_position(10, 25)
        result = navigator._format_position()

        assert result == "Ln 10, Col 25"


# =============================================================================
# TEST: Constants
# =============================================================================


class TestConstants:
    """Тесты констант."""

    def test_max_line_number(self) -> None:
        """MAX_LINE_NUMBER определён."""
        assert MAX_LINE_NUMBER == 999999

    def test_navigator_height(self) -> None:
        """NAVIGATOR_HEIGHT определён."""
        assert NAVIGATOR_HEIGHT == 28


# =============================================================================
# TEST: Lifecycle
# =============================================================================


class TestLifecycle:
    """Тесты жизненного цикла."""

    def test_mount_creates_widget(self, tk_root: tk.Tk) -> None:
        """mount() создаёт виджет."""
        nav = Navigator(
            widget_id="test_navigator",
            initial_line=1,
            initial_column=1,
            initial_total_lines=100,
        )
        nav.mount(tk_root)

        assert nav.is_mounted()


# =============================================================================
# TEST: Callbacks
# =============================================================================


class TestCallbacks:
    """Тесты callback-функций."""

    def test_on_goto_line_callback(self, tk_root: tk.Tk) -> None:
        """on_goto_line callback вызывается."""
        callback_called = False
        callback_line = None

        def on_goto_line(line: int) -> None:
            nonlocal callback_called, callback_line
            callback_called = True
            callback_line = line

        nav = Navigator(
            widget_id="test_navigator",
            on_goto_line=on_goto_line,
            initial_line=1,
            initial_column=1,
            initial_total_lines=100,
        )
        nav.mount(tk_root)

        # Simulate goto line
        if nav._goto_entry is not None:
            nav._goto_entry.insert(0, "50")
            nav._on_go_clicked()

        assert callback_called is True
        assert callback_line == 50

    def test_on_goto_start_callback(self, tk_root: tk.Tk) -> None:
        """on_goto_start callback вызывается."""
        callback_called = False

        def on_goto_start() -> None:
            nonlocal callback_called
            callback_called = True

        nav = Navigator(
            widget_id="test_navigator",
            on_goto_start=on_goto_start,
            initial_line=1,
            initial_column=1,
            initial_total_lines=100,
        )
        nav.mount(tk_root)

        # Simulate goto start
        nav._on_start_clicked()

        assert callback_called is True

    def test_on_goto_end_callback(self, tk_root: tk.Tk) -> None:
        """on_goto_end callback вызывается."""
        callback_called = False

        def on_goto_end() -> None:
            nonlocal callback_called
            callback_called = True

        nav = Navigator(
            widget_id="test_navigator",
            on_goto_end=on_goto_end,
            initial_line=1,
            initial_column=1,
            initial_total_lines=100,
        )
        nav.mount(tk_root)

        # Simulate goto end
        nav._on_end_clicked()

        assert callback_called is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.components.navigator"])
