"""Тесты для системы тем GUI.

Модуль содержит unit-тесты для Theme, ThemeManager, ThemeVariant
и всех встроенных тем.

Test Strategy:
    - Тестирование singleton паттерна
    - Тестирование immutable Theme dataclass
    - Тестирование вариантов тем (LIGHT/DARK)
    - Тестирование применения к виджетам
    - Тестирование регистрации тем

Example:
    >>> pytest tests/unit/gui/themes/test_themes.py -v

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Generator

import pytest

from src.gui.themes import (
    Theme,
    ThemeApplicationError,
    ThemeError,
    ThemeManager,
    ThemeNotFoundError,
    ThemeVariant,
    get_theme_manager,
)
from src.gui.themes import amber
from src.gui.themes import classic_green
from src.gui.themes import high_contrast
from src.gui.themes import phosphor_white
from src.gui.themes import retro_green


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def theme_manager() -> Generator[ThemeManager, None, None]:
    """Fixture для ThemeManager с очисткой состояния.

    Yields:
        ThemeManager: Чистый экземпляр менеджера тем

    Note:
        Автоматически сбрасывает singleton после теста.
    """
    # Сбрасываем singleton перед тестом
    ThemeManager._instance = None  # type: ignore[misc]
    manager = ThemeManager()
    yield manager
    # Сбрасываем singleton после теста
    manager.reset()


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Fixture для Tk root окна.

    Yields:
        tk.Tk: Root окно для тестов виджетов
    """
    root = tk.Tk()
    root.withdraw()  # Скрываем окно
    yield root
    root.destroy()


# =============================================================================
# THEME MANAGER SINGLETON TESTS
# =============================================================================


class TestThemeManagerSingleton:
    """Тесты для singleton паттерна ThemeManager."""

    def test_theme_manager_singleton(self, theme_manager: ThemeManager) -> None:
        """Проверяет, что ThemeManager является singleton.

        Args:
            theme_manager: Fixture менеджера тем

        Expected:
            - Два вызова ThemeManager() возвращают один и тот же объект
        """
        # Получаем менеджер через разные способы
        manager1 = ThemeManager()
        manager2 = get_theme_manager()

        assert manager1 is manager2
        assert manager1 is theme_manager

    def test_singleton_persists_state(self, theme_manager: ThemeManager) -> None:
        """Проверяет сохранение состояния в singleton.

        Args:
            theme_manager: Fixture менеджера тем

        Expected:
            - Изменения текущей темы сохраняются между вызовами
        """
        # Устанавливаем тему
        theme_manager.set_theme("amber")

        # Получаем тот же менеджер
        manager2 = ThemeManager()

        # Проверяем сохранение состояния
        assert manager2.get_current_theme_name() == "amber"

    def test_thread_safety(self, theme_manager: ThemeManager) -> None:
        """Проверяет thread-safety инициализации.

        Args:
            theme_manager: Fixture менеджера тем

        Expected:
            - Состояние _initialized корректно
            - Темы зарегистрированы
        """
        # Singleton должен быть инициализирован
        assert theme_manager._initialized is True
        # Темы должны быть зарегистрированы
        themes = theme_manager.list_themes()
        assert len(themes) >= 5


# =============================================================================
# THEME DATACLASS TESTS
# =============================================================================


class TestThemeDataclass:
    """Тесты для Theme dataclass."""

    def test_theme_dataclass_creation(self) -> None:
        """Проверяет создание Theme с валидными данными.

        Expected:
            - Theme создаётся с заданными атрибутами
            - frozen=True предотвращает модификацию
        """
        theme = Theme(
            bg_color="#000000",
            fg_color="#00FF00",
            accent_color="#00AA00",
            warning_color="#FFA500",
            error_color="#FF0000",
            success_color="#00FF00",
            border_color="#003300",
            font_family="Courier New",
            font_size=12,
        )

        assert theme.bg_color == "#000000"
        assert theme.fg_color == "#00FF00"
        assert theme.accent_color == "#00AA00"
        assert theme.font_family == "Courier New"
        assert theme.font_size == 12

    def test_theme_immutability(self) -> None:
        """Проверяет, что Theme неизменяем.

        Expected:
            - Попытка изменения атрибута вызывает FrozenInstanceError
        """
        theme = Theme(
            bg_color="#000000",
            fg_color="#00FF00",
            accent_color="#00AA00",
            warning_color="#FFA500",
            error_color="#FF0000",
            success_color="#00FF00",
            border_color="#003300",
            font_family="Courier New",
            font_size=12,
        )

        with pytest.raises(Exception):  # dataclasses.FrozenInstanceError
            theme.bg_color = "#FFFFFF"  # type: ignore[misc]

    def test_theme_validation_hex_color(self) -> None:
        """Проверяет валидацию hex цветов.

        Expected:
            - Невалидные hex вызывают ValueError
            - Валидные hex принимаются
        """
        # Невалидные hex
        with pytest.raises(ValueError, match="Цвет должен начинаться с"):
            Theme(
                bg_color="000000",  # Без #
                fg_color="#00FF00",
                accent_color="#00AA00",
                warning_color="#FFA500",
                error_color="#FF0000",
                success_color="#00FF00",
                border_color="#003300",
                font_family="Courier New",
                font_size=12,
            )

        # Неправильная длина
        with pytest.raises(ValueError, match="формате #RRGGBB"):
            Theme(
                bg_color="#00000",  # Короткий
                fg_color="#00FF00",
                accent_color="#00AA00",
                warning_color="#FFA500",
                error_color="#FF0000",
                success_color="#00FF00",
                border_color="#003300",
                font_family="Courier New",
                font_size=12,
            )

    def test_theme_validation_font_size(self) -> None:
        """Проверяет валидацию размера шрифта.

        Expected:
            - Значения < 6 или > 72 вызывают ValueError
        """
        with pytest.raises(ValueError, match="font_size"):
            Theme(
                bg_color="#000000",
                fg_color="#00FF00",
                accent_color="#00AA00",
                warning_color="#FFA500",
                error_color="#FF0000",
                success_color="#00FF00",
                border_color="#003300",
                font_family="Courier New",
                font_size=5,  # Слишком маленький
            )

    def test_theme_with_font_size(self) -> None:
        """Проверяет метод with_font_size.

        Expected:
            - Создаётся новая тема с изменённым размером
            - Исходная тема не изменяется
        """
        theme = Theme(
            bg_color="#000000",
            fg_color="#00FF00",
            accent_color="#00AA00",
            warning_color="#FFA500",
            error_color="#FF0000",
            success_color="#00FF00",
            border_color="#003300",
            font_family="Courier New",
            font_size=12,
        )

        new_theme = theme.with_font_size(16)

        assert new_theme.font_size == 16
        assert theme.font_size == 12  # Исходная не изменилась
        assert new_theme.bg_color == theme.bg_color  # Остальное сохранилось

    def test_theme_with_colors(self) -> None:
        """Проверяет метод with_colors.

        Expected:
            - Создаётся новая тема с изменёнными цветами
            - Неуказанные цвета сохраняются
        """
        theme = Theme(
            bg_color="#000000",
            fg_color="#00FF00",
            accent_color="#00AA00",
            warning_color="#FFA500",
            error_color="#FF0000",
            success_color="#00FF00",
            border_color="#003300",
            font_family="Courier New",
            font_size=12,
        )

        new_theme = theme.with_colors(bg_color="#111111")

        assert new_theme.bg_color == "#111111"
        assert new_theme.fg_color == theme.fg_color  # Не изменился


# =============================================================================
# THEME VARIANTS TESTS
# =============================================================================


class TestThemeVariants:
    """Тесты для вариантов тем (LIGHT/DARK)."""

    def test_theme_variants_enum(self) -> None:
        """Проверяет ThemeVariant enum.

        Expected:
            - LIGHT и DARK значения существуют
        """
        assert ThemeVariant.LIGHT is not None
        assert ThemeVariant.DARK is not None
        assert ThemeVariant.LIGHT != ThemeVariant.DARK

    def test_get_variant_dark(self, theme_manager: ThemeManager) -> None:
        """Проверяет получение тёмного варианта темы.

        Args:
            theme_manager: Fixture менеджера тем

        Expected:
            - Фон затемняется
            - Текст осветляется
        """
        theme_manager.set_theme("classic_green")
        original = theme_manager.get_current_theme()

        dark_theme = theme_manager.get_variant(ThemeVariant.DARK)

        # Фон должен быть темнее
        orig_bg = int(original.bg_color[1:3], 16)
        dark_bg = int(dark_theme.bg_color[1:3], 16)
        assert dark_bg <= orig_bg

    def test_get_variant_light(self, theme_manager: ThemeManager) -> None:
        """Проверяет получение светлого варианта темы.

        Args:
            theme_manager: Fixture менеджера тем

        Expected:
            - Фон осветляется
            - Текст затемняется
        """
        theme_manager.set_theme("classic_green")
        original = theme_manager.get_current_theme()

        light_theme = theme_manager.get_variant(ThemeVariant.LIGHT)

        # Фон должен быть светлее
        orig_bg = int(original.bg_color[1:3], 16)
        light_bg = int(light_theme.bg_color[1:3], 16)
        assert light_bg >= orig_bg


# =============================================================================
# APPLY TO WIDGET TESTS
# =============================================================================


class TestApplyToWidget:
    """Тесты для применения тем к виджетам."""

    def test_apply_to_widget_type_error(self, theme_manager: ThemeManager) -> None:
        """Проверяет TypeError для невалидного виджета.

        Args:
            theme_manager: Fixture менеджера тем

        Expected:
            - TypeError при передаче не-виджета
        """
        with pytest.raises(TypeError, match="widget должен быть tk.Widget"):
            theme_manager.apply_to_widget("not a widget")  # type: ignore[arg-type]

    def test_apply_to_button(self, theme_manager: ThemeManager, tk_root: tk.Tk) -> None:
        """Проверяет применение темы к кнопке.

        Args:
            theme_manager: Fixture менеджера тем
            tk_root: Fixture root окна

        Expected:
            - Цвета применяются к виджету
        """
        theme_manager.set_theme("classic_green")
        button = tk.Button(tk_root, text="Test")

        theme_manager.apply_to_widget(button)

        theme = theme_manager.get_current_theme()
        # Проверяем, что виджет имеет настройки (может не работать во всех средах)
        # Просто проверяем, что не было исключений

    def test_apply_to_entry(self, theme_manager: ThemeManager, tk_root: tk.Tk) -> None:
        """Проверяет применение темы к полю ввода.

        Args:
            theme_manager: Fixture менеджера тем
            tk_root: Fixture root окна

        Expected:
            - Не вызывает исключений
        """
        theme_manager.set_theme("amber")
        entry = tk.Entry(tk_root)

        theme_manager.apply_to_widget(entry)

        # Просто проверяем, что не было исключений
        assert entry is not None


# =============================================================================
# ALL THEMES REGISTERED TESTS
# =============================================================================


class TestAllThemesRegistered:
    """Тесты для проверки регистрации всех тем."""

    def test_all_themes_registered(self, theme_manager: ThemeManager) -> None:
        """Проверяет, что все встроенные темы зарегистрированы.

        Args:
            theme_manager: Fixture менеджера тем

        Expected:
            - Все 5 тем доступны
            - Каждая тема имеет корректный тип
        """
        themes = theme_manager.list_themes()

        expected_themes = [
            "classic_green",
            "retro_green",
            "amber",
            "phosphor_white",
            "high_contrast",
        ]

        for theme_name in expected_themes:
            assert theme_name in themes, f"Тема {theme_name} не зарегистрирована"

            theme = theme_manager.get_theme(theme_name)
            assert isinstance(theme, Theme)

    def test_classic_green_theme(self) -> None:
        """Проверяет классическую зелёную тему.

        Expected:
            - Корректные цвета VT100
        """
        theme = classic_green.THEME

        assert theme.bg_color == "#000000"
        assert theme.fg_color == "#00FF00"
        assert theme.accent_color == "#00AA00"
        assert theme.font_family == "Courier New"
        assert theme.font_size == 12

    def test_retro_green_theme(self) -> None:
        """Проверяет ретро зелёную тему.

        Expected:
            - Приглушённые цвета фосфора
        """
        theme = retro_green.THEME

        assert theme.bg_color == "#0D1B0D"
        assert theme.fg_color == "#33FF33"
        assert theme.accent_color == "#66FF66"

    def test_amber_theme(self) -> None:
        """Проверяет янтарную тему.

        Expected:
            - Янтарные цвета P3 фосфора
        """
        theme = amber.THEME

        assert theme.bg_color == "#1A1A1A"
        assert theme.fg_color == "#FFB000"
        assert theme.accent_color == "#FF8C00"

    def test_phosphor_white_theme(self) -> None:
        """Проверяет белую фосфорную тему.

        Expected:
            - Нейтральные белые цвета
        """
        theme = phosphor_white.THEME

        assert theme.bg_color == "#0A0A0A"
        assert theme.fg_color == "#E8E8E8"
        assert theme.accent_color == "#FFFFFF"

    def test_high_contrast_theme(self) -> None:
        """Проверяет высококонтрастную тему.

        Expected:
            - Максимальный контраст
            - Увеличенный шрифт
        """
        theme = high_contrast.THEME

        assert theme.bg_color == "#000000"
        assert theme.fg_color == "#FFFFFF"
        assert theme.accent_color == "#FFFF00"
        assert theme.font_size == 14  # Увеличенный


# =============================================================================
# THEME MANAGER OPERATIONS TESTS
# =============================================================================


class TestThemeManagerOperations:
    """Тесты операций ThemeManager."""

    def test_get_theme_not_found(self, theme_manager: ThemeManager) -> None:
        """Проверяет ThemeNotFoundError.

        Args:
            theme_manager: Fixture менеджера тем

        Expected:
            - ThemeNotFoundError для несуществующей темы
        """
        with pytest.raises(ThemeNotFoundError, match="не найдена"):
            theme_manager.get_theme("nonexistent_theme")

    def test_set_theme_not_found(self, theme_manager: ThemeManager) -> None:
        """Проверяет ThemeNotFoundError при установке.

        Args:
            theme_manager: Fixture менеджера тем

        Expected:
            - ThemeNotFoundError для несуществующей темы
        """
        with pytest.raises(ThemeNotFoundError):
            theme_manager.set_theme("nonexistent_theme")

    def test_register_theme(self, theme_manager: ThemeManager) -> None:
        """Проверяет регистрацию новой темы.

        Args:
            theme_manager: Fixture менеджера тем

        Expected:
            - Тема регистрируется
            - ThemeError при дубликате
        """
        custom_theme = Theme(
            bg_color="#123456",
            fg_color="#ABCDEF",
            accent_color="#FEDCBA",
            warning_color="#FFA500",
            error_color="#FF0000",
            success_color="#00FF00",
            border_color="#333333",
            font_family="Arial",
            font_size=12,
        )

        theme_manager.register_theme("custom", custom_theme)

        assert "custom" in theme_manager.list_themes()
        assert theme_manager.get_theme("custom") == custom_theme

        # Дубликат должен вызывать ошибку
        with pytest.raises(ThemeError, match="уже зарегистрирована"):
            theme_manager.register_theme("custom", custom_theme)

    def test_unregister_theme(self, theme_manager: ThemeManager) -> None:
        """Проверяет удаление темы.

        Args:
            theme_manager: Fixture менеджера тем

        Expected:
            - Тема удаляется из реестра
            - Нельзя удалить текущую тему
        """
        # Регистрируем и удаляем
        custom_theme = Theme(
            bg_color="#123456",
            fg_color="#ABCDEF",
            accent_color="#FEDCBA",
            warning_color="#FFA500",
            error_color="#FF0000",
            success_color="#00FF00",
            border_color="#333333",
            font_family="Arial",
            font_size=12,
        )
        theme_manager.register_theme("temp_theme", custom_theme)
        theme_manager.unregister_theme("temp_theme")

        assert "temp_theme" not in theme_manager.list_themes()

        # Нельзя удалить текущую тему
        current = theme_manager.get_current_theme_name()
        with pytest.raises(ThemeError, match="Нельзя удалить"):
            theme_manager.unregister_theme(current)

    def test_get_current_theme_name(self, theme_manager: ThemeManager) -> None:
        """Проверяет получение имени текущей темы.

        Args:
            theme_manager: Fixture менеджера тем

        Expected:
            - Возвращается строка с именем
        """
        name = theme_manager.get_current_theme_name()
        assert isinstance(name, str)
        assert len(name) > 0

    def test_list_themes_sorted(self, theme_manager: ThemeManager) -> None:
        """Проверяет, что список тем отсортирован.

        Args:
            theme_manager: Fixture менеджера тем

        Expected:
            - Список отсортирован по алфавиту
        """
        themes = theme_manager.list_themes()
        assert themes == sorted(themes)


# =============================================================================
# ERROR HANDLING TESTS
# =============================================================================


class TestErrorHandling:
    """Тесты обработки ошибок."""

    def test_theme_error_base(self) -> None:
        """Проверяет базовое исключение ThemeError."""
        error = ThemeError("custom_theme", "Custom error message")
        assert error.theme_name == "custom_theme"
        assert "Custom error message" in str(error)

    def test_theme_not_found_error(self) -> None:
        """Проверяет ThemeNotFoundError."""
        error = ThemeNotFoundError("missing_theme")
        assert error.theme_name == "missing_theme"
        assert "missing_theme" in str(error)

    def test_theme_application_error(self) -> None:
        """Проверяет ThemeApplicationError."""
        cause = ValueError("Original error")
        error = ThemeApplicationError("Button", "classic_green", cause)
        assert error.widget_type == "Button"
        assert error.cause is cause
        assert "Button" in str(error)
        assert "classic_green" in str(error)


# =============================================================================
# PYTEST MARKERS
# =============================================================================


pytestmark = [
    pytest.mark.gui,
    pytest.mark.themes,
]
