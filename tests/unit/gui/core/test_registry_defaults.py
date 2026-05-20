"""Unit-тесты для модуля registry_defaults.

Проверяет:
- Регистрацию стандартных виджетов
- Метаданные виджетов (категории, описания)
- Фабричные функции
- Идемпотентность регистрации

Coverage target: >=90%
"""

import pytest

from src.gui.core.registry import (
    WidgetCategory,
    WidgetComplexity,
    WidgetRegistry,
)
from src.gui.core.registry_defaults import register_default_widgets


# ==============================================================================
# FIXTURES
# ==============================================================================


@pytest.fixture(autouse=True)
def _reset_registry() -> None:
    """Сброс singleton реестра перед каждым тестом."""
    WidgetRegistry.reset_instance()
    yield
    WidgetRegistry.reset_instance()


# ==============================================================================
# TEST: register_default_widgets
# ==============================================================================


class TestRegisterDefaultWidgets:
    """Тесты регистрации стандартных виджетов."""

    def test_registers_all_default_widgets(self) -> None:
        """Регистрирует все стандартные виджеты."""
        registry = WidgetRegistry.get_instance()
        register_default_widgets(registry)

        expected_widgets = [
            "themed_button",
            "themed_label",
            "themed_entry",
            "themed_checkbox",
            "status_bar",
        ]
        for widget_type in expected_widgets:
            assert registry.is_registered(widget_type), (
                f"Widget '{widget_type}' not registered"
            )

    def test_idempotent_registration(self) -> None:
        """Повторная регистрация не выбрасывает исключение."""
        registry = WidgetRegistry.get_instance()
        register_default_widgets(registry)
        # Второй вызов не должен выбрасывать исключение
        register_default_widgets(registry)

    def test_uses_default_registry(self) -> None:
        """Без аргументов использует singleton реестр."""
        register_default_widgets()
        registry = WidgetRegistry.get_instance()
        assert registry.is_registered("themed_button")

    def test_button_metadata(self) -> None:
        """Метаданные ThemedButton корректны."""
        registry = WidgetRegistry.get_instance()
        register_default_widgets(registry)
        meta = registry.get_metadata("themed_button")
        assert meta.category == WidgetCategory.INPUT
        assert meta.complexity == WidgetComplexity.PRIMITIVE
        assert meta.requires_mfa is False
        assert "click" in meta.supported_events

    def test_label_metadata(self) -> None:
        """Метаданные ThemedLabel корректны."""
        registry = WidgetRegistry.get_instance()
        register_default_widgets(registry)
        meta = registry.get_metadata("themed_label")
        assert meta.category == WidgetCategory.DISPLAY
        assert meta.complexity == WidgetComplexity.PRIMITIVE

    def test_entry_metadata(self) -> None:
        """Метаданные ThemedEntry корректны."""
        registry = WidgetRegistry.get_instance()
        register_default_widgets(registry)
        meta = registry.get_metadata("themed_entry")
        assert meta.category == WidgetCategory.INPUT
        assert "focus" in meta.supported_events
        assert "change" in meta.supported_events

    def test_checkbox_metadata(self) -> None:
        """Метаданные ThemedCheckbox корректны."""
        registry = WidgetRegistry.get_instance()
        register_default_widgets(registry)
        meta = registry.get_metadata("themed_checkbox")
        assert meta.category == WidgetCategory.INPUT
        assert "change" in meta.supported_events

    def test_status_bar_metadata(self) -> None:
        """Метаданные StatusBar корректны."""
        registry = WidgetRegistry.get_instance()
        register_default_widgets(registry)
        meta = registry.get_metadata("status_bar")
        assert meta.category == WidgetCategory.DISPLAY
        assert meta.complexity == WidgetComplexity.COMPOSITE

    def test_widget_count(self) -> None:
        """Регистрируется 5 виджетов."""
        registry = WidgetRegistry.get_instance()
        register_default_widgets(registry)
        stats = registry.get_statistics()
        assert stats.total == 5

    def test_validate_false(self) -> None:
        """Регистрация без валидации Protocol."""
        registry = WidgetRegistry.get_instance()
        register_default_widgets(registry, validate=False)
        assert registry.is_registered("themed_button")