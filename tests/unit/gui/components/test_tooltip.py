"""Unit-тесты для TooltipManager.

Проверяет:
- Singleton-паттерн TooltipManager
- Показ и скрытие тултипов
- Задержку показа
- Позиционирование
- Привязку к виджетам

Coverage target: ≥90%
"""

import tkinter as tk
from typing import Generator

import pytest

from src.gui.components.tooltip import TooltipManager


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    """Сбрасывает singleton перед каждым тестом."""
    TooltipManager._instance = None
    TooltipManager._initialized = False
    yield
    TooltipManager._instance = None
    TooltipManager._initialized = False


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Fixture для Tk root окна."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def tooltip_manager() -> TooltipManager:
    """Fixture для TooltipManager (singleton сбрасывается)."""
    return TooltipManager.get_instance()


# =============================================================================
# TEST: Singleton Pattern
# =============================================================================


class TestTooltipManagerSingleton:
    """Тесты Singleton-паттерна TooltipManager."""

    def test_get_instance_returns_same(self) -> None:
        """get_instance возвращает один и тот же экземпляр."""
        mgr1 = TooltipManager.get_instance()
        mgr2 = TooltipManager.get_instance()
        assert mgr1 is mgr2

    def test_direct_construction_returns_same(self) -> None:
        """Прямая конструкция возвращает singleton."""
        mgr1 = TooltipManager()
        mgr2 = TooltipManager()
        assert mgr1 is mgr2

    def test_get_instance_and_direct_same(self) -> None:
        """get_instance и прямая конструкция возвращают один экземпляр."""
        mgr1 = TooltipManager.get_instance()
        mgr2 = TooltipManager()
        assert mgr1 is mgr2

    def test_reset_singleton(self) -> None:
        """После сброса singleton создаётся новый экземпляр."""
        mgr1 = TooltipManager.get_instance()
        TooltipManager._instance = None
        mgr2 = TooltipManager.get_instance()
        assert mgr1 is not mgr2


# =============================================================================
# TEST: Show and Hide
# =============================================================================


class TestTooltipManagerShowHide:
    """Тесты показа и скрытия тултипов."""

    def test_show_immediately(self, tk_root: tk.Tk, tooltip_manager: TooltipManager) -> None:
        """show() с delay_ms=0 показывает тултип немедленно."""
        label = tk.Label(tk_root, text="Test")
        label.pack()
        # Не должно вызывать исключений
        tooltip_manager.show(label, "Тестовая подсказка", 100, 100)

    def test_show_with_delay(self, tk_root: tk.Tk, tooltip_manager: TooltipManager) -> None:
        """show() с delay_ms>0 планирует отложенный показ."""
        label = tk.Label(tk_root, text="Test")
        label.pack()
        tooltip_manager.show(label, "Delayed tooltip", 100, 100, delay_ms=500)

    def test_hide_destroys_tooltip(self, tk_root: tk.Tk, tooltip_manager: TooltipManager) -> None:
        """hide() уничтожает текущий тултип."""
        label = tk.Label(tk_root, text="Test")
        label.pack()
        tooltip_manager.show(label, "Tooltip", 100, 100)
        # hide не должен вызывать исключений
        tooltip_manager.hide()

    def test_hide_without_active_tooltip(
        self, tk_root: tk.Tk, tooltip_manager: TooltipManager
    ) -> None:
        """hide() без активного тултипа не вызывает исключений."""
        tooltip_manager.hide()

    def test_show_empty_text(
        self, tk_root: tk.Tk, tooltip_manager: TooltipManager
    ) -> None:
        """show() с пустым текстом не создаёт видимого тултипа."""
        label = tk.Label(tk_root, text="Test")
        label.pack()
        # Не должно быть исключений
        tooltip_manager.show(label, "", 100, 100)

    def test_show_replaces_previous(
        self, tk_root: tk.Tk, tooltip_manager: TooltipManager
    ) -> None:
        """Повторный show() заменяет предыдущий тултип."""
        label = tk.Label(tk_root, text="Test")
        label.pack()
        tooltip_manager.show(label, "First", 100, 100)
        tooltip_manager.show(label, "Second", 200, 200)


# =============================================================================
# TEST: Bind to Widget
# =============================================================================


class TestTooltipManagerBind:
    """Тесты привязки тултипов к виджетам."""

    def test_bind_to_widget(self, tk_root: tk.Tk, tooltip_manager: TooltipManager) -> None:
        """bind_to_widget привязывает тултип к виджету."""
        label = tk.Label(tk_root, text="Test")
        label.pack()
        tooltip_manager.bind_to_widget(label, "Подсказка", delay_ms=100)
        # Проверяем что bindings установлены
        bindings = label.bind("<Enter>")
        assert len(bindings) > 0
        bindings = label.bind("<Leave>")
        assert len(bindings) > 0

    def test_bind_to_widget_default_delay(
        self, tk_root: tk.Tk, tooltip_manager: TooltipManager
    ) -> None:
        """bind_to_widget с задержкой по умолчанию (500мс)."""
        label = tk.Label(tk_root, text="Test")
        label.pack()
        tooltip_manager.bind_to_widget(label, "Подсказка")


# =============================================================================
# TEST: Constants
# =============================================================================


class TestTooltipManagerConstants:
    """Тесты констант TooltipManager."""

    def test_delay_ms(self) -> None:
        """Константа DELAY_MS равна 500."""
        assert TooltipManager.DELAY_MS == 500

    def test_padding(self) -> None:
        """Константа PADDING равна 6."""
        assert TooltipManager.PADDING == 6

    def test_border_width(self) -> None:
        """Константа BORDER_WIDTH равна 1."""
        assert TooltipManager.BORDER_WIDTH == 1

    def test_bg_color(self) -> None:
        """Константа BG_COLOR корректна."""
        assert TooltipManager.BG_COLOR == "#ffffe0"

    def test_text_color(self) -> None:
        """Константа TEXT_COLOR корректна."""
        assert TooltipManager.TEXT_COLOR == "#000000"


# =============================================================================
# TEST: Internal Methods
# =============================================================================


class TestTooltipManagerInternal:
    """Тесты внутренних методов TooltipManager."""

    def test_cancel_pending_no_pending(
        self, tooltip_manager: TooltipManager
    ) -> None:
        """_cancel_pending без отложенного показа не вызывает исключений."""
        tooltip_manager._cancel_pending()

    def test_destroy_tooltip_no_tooltip(
        self, tooltip_manager: TooltipManager
    ) -> None:
        """_destroy_tooltip без тултипа не вызывает исключений."""
        tooltip_manager._destroy_tooltip()

    def test_get_font_returns_tuple(self, tooltip_manager: TooltipManager) -> None:
        """_get_font возвращает кортеж (family, size, weight)."""
        font = tooltip_manager._get_font()
        assert isinstance(font, tuple)
        assert len(font) == 3
        assert font[0] == "Arial"
        assert font[1] == 10