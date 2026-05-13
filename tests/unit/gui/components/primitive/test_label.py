"""Тесты для виджета ThemedLabel.

Проверяет базовую функциональность примитивного виджета Label.

Example:
    $ pytest tests/unit/gui/components/primitive/test_label.py -v

Note:
    Требуется запуск с виртуальным дисплеем для GUI тестов:
    $ xvfb-run -a python -m pytest tests/unit/gui/components/primitive/test_label.py -v
"""

from __future__ import annotations

import tkinter as tk
from typing import Any

import pytest

from src.gui.components.primitive.label import ThemedLabel
from src.gui.core.exceptions import LifecycleError


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def tk_app() -> tk.Tk:
    """Fixture: создаёт корневое окно Tk."""
    root = tk.Tk()
    root.withdraw()  # Скрываем окно
    yield root
    root.destroy()


@pytest.fixture
def parent_frame(tk_app: tk.Tk) -> tk.Frame:
    """Fixture: создаёт родительский фрейм."""
    frame = tk.Frame(tk_app)
    frame.pack()
    return frame


# =============================================================================
# CONSTRUCTOR TESTS
# =============================================================================


class TestThemedLabelConstructor:
    """Тесты для конструктора ThemedLabel."""

    def test_init_with_default_text(self) -> None:
        """Тест: создание с текстом по умолчанию (пустая строка)."""
        label = ThemedLabel(widget_id="test_label")
        assert label.get_text() == ""

    def test_init_with_custom_text(self) -> None:
        """Тест: создание с пользовательским текстом."""
        label = ThemedLabel(widget_id="test_label", text="Custom Text")
        assert label.get_text() == "Custom Text"

    def test_init_stores_widget_id(self) -> None:
        """Тест: widget_id сохраняется корректно."""
        label = ThemedLabel(widget_id="my_label", text="Test")
        assert label.widget_id == "my_label"

    def test_init_rejects_empty_widget_id(self) -> None:
        """Тест: пустой widget_id вызывает ValueError."""
        with pytest.raises(ValueError, match="widget_id"):
            ThemedLabel(widget_id="")

    def test_init_rejects_whitespace_only_id(self) -> None:
        """Тест: widget_id только из пробелов вызывает ValueError."""
        with pytest.raises(ValueError, match="widget_id"):
            ThemedLabel(widget_id="   ")


# =============================================================================
# TEXT METHODS TESTS
# =============================================================================


class TestThemedLabelText:
    """Тесты для методов работы с текстом."""

    def test_set_text_updates_stored_value(self) -> None:
        """Тест: set_text() обновляет хранимое значение."""
        label = ThemedLabel(widget_id="test", text="Old")
        label.set_text("New")
        assert label.get_text() == "New"

    def test_set_text_updates_tk_widget(self, parent_frame: tk.Frame) -> None:
        """Тест: set_text() обновляет Tkinter виджет."""
        label = ThemedLabel(widget_id="test", text="Initial")
        tk_widget = label.mount(parent_frame)

        label.set_text("Updated")

        assert str(tk_widget.cget("text")) == "Updated"

    def test_set_text_before_mount(self) -> None:
        """Тест: set_text() до mount() обновляет только внутреннее значение."""
        label = ThemedLabel(widget_id="test", text="Initial")
        label.set_text("Changed")
        assert label.get_text() == "Changed"

    def test_get_text_returns_current_value(self) -> None:
        """Тест: get_text() возвращает текущее значение."""
        label = ThemedLabel(widget_id="test", text="Hello")
        assert label.get_text() == "Hello"


# =============================================================================
# LIFECYCLE TESTS
# =============================================================================


class TestThemedLabelLifecycle:
    """Тесты для жизненного цикла ThemedLabel."""

    def test_is_mounted_returns_false_before_mount(self) -> None:
        """Тест: is_mounted() возвращает False до mount()."""
        label = ThemedLabel(widget_id="test")
        assert label.is_mounted() is False

    def test_is_mounted_returns_true_after_mount(self, parent_frame: tk.Frame) -> None:
        """Тест: is_mounted() возвращает True после mount()."""
        label = ThemedLabel(widget_id="test")
        label.mount(parent_frame)
        assert label.is_mounted() is True

    def test_is_mounted_returns_false_after_unmount(self, parent_frame: tk.Frame) -> None:
        """Тест: is_mounted() возвращает False после unmount()."""
        label = ThemedLabel(widget_id="test")
        label.mount(parent_frame)
        label.unmount()
        assert label.is_mounted() is False

    def test_mount_returns_tk_widget(self, parent_frame: tk.Frame) -> None:
        """Тест: mount() возвращает Tkinter виджет."""
        label = ThemedLabel(widget_id="test")
        result = label.mount(parent_frame)
        assert isinstance(result, tk.Label)

    def test_mount_rejects_invalid_parent(self) -> None:
        """Тест: mount() с невалидным parent вызывает TypeError."""
        label = ThemedLabel(widget_id="test")
        with pytest.raises(TypeError, match="parent"):
            label.mount("invalid_parent")

    def test_double_mount_raises_lifecycle_error(self, parent_frame: tk.Frame) -> None:
        """Тест: повторный mount() вызывает LifecycleError."""
        label = ThemedLabel(widget_id="test")
        label.mount(parent_frame)

        with pytest.raises(LifecycleError):
            label.mount(parent_frame)

    def test_unmount_without_mount_raises_lifecycle_error(self) -> None:
        """Тест: unmount() без mount() вызывает LifecycleError."""
        label = ThemedLabel(widget_id="test")

        with pytest.raises(LifecycleError):
            label.unmount()


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "TestThemedLabelConstructor",
    "TestThemedLabelText",
    "TestThemedLabelLifecycle",
]
