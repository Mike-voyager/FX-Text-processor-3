"""Тесты для модуля тем.

Module: tests/unit/view/test_themes.py
"""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from src.view.themes import ThemeConfig, ThemeManager, get_theme_manager


class TestThemeConfig:
    """Тесты для ThemeConfig."""

    def test_create_default(self) -> None:
        """Создание конфигурации с умолчаниями."""
        config = ThemeConfig(name="Test")

        assert config.name == "Test"
        assert config.ui_font_size == 10
        assert config.editor_font == "Courier New"
        assert config.editor_font_size == 12
        assert config.cursor_blink_interval == 500

    def test_create_custom(self) -> None:
        """Создание конфигурации с пользовательскими значениями."""
        config = ThemeConfig(
            name="Custom",
            colors={"bg": "#000000", "fg": "#FFFFFF"},
            ui_font_size=14,
            editor_font_size=16,
            cursor_blink_interval=1000,
        )

        assert config.name == "Custom"
        assert config.colors["bg"] == "#000000"
        assert config.ui_font_size == 14
        assert config.cursor_blink_interval == 1000

    def test_to_dict(self) -> None:
        """Конвертация в словарь."""
        config = ThemeConfig(name="Test", colors={"bg": "#000000"})
        data = config.to_dict()

        assert data["name"] == "Test"
        assert data["colors"]["bg"] == "#000000"
        assert "ui_font_size" in data

    def test_from_dict(self) -> None:
        """Создание из словаря."""
        data = {
            "name": "FromDict",
            "colors": {"bg": "#FFFFFF"},
            "ui_font_size": 12,
            "editor_font": "Courier",
            "editor_font_size": 14,
            "cursor_blink_interval": 750,
        }

        config = ThemeConfig.from_dict(data)

        assert config.name == "FromDict"
        assert config.colors["bg"] == "#FFFFFF"
        assert config.ui_font_size == 12


class TestThemeManager:
    """Тесты для ThemeManager."""

    def test_create_manager(self) -> None:
        """Создание менеджера тем."""
        with TemporaryDirectory() as tmpdir:
            manager = ThemeManager(Path(tmpdir))

            # Должен содержать встроенные темы
            themes = manager.list_themes()
            assert "classic_green" in themes
            assert "amber" in themes
            assert "matrix" in themes

    def test_get_theme(self) -> None:
        """Получение темы."""
        with TemporaryDirectory() as tmpdir:
            manager = ThemeManager(Path(tmpdir))

            theme = manager.get_theme("classic_green")

            assert theme.name == "Classic Green"
            assert theme.colors["bg"] == "#000000"
            assert theme.colors["fg"] == "#00FF00"

    def test_get_default_theme(self) -> None:
        """Получение темы по умолчанию для неизвестной темы."""
        with TemporaryDirectory() as tmpdir:
            manager = ThemeManager(Path(tmpdir))

            # Неизвестная тема возвращает classic_green
            theme = manager.get_theme("unknown_theme")

            assert theme.name == "Classic Green"

    def test_create_user_theme(self) -> None:
        """Создание пользовательской темы."""
        with TemporaryDirectory() as tmpdir:
            manager = ThemeManager(Path(tmpdir))

            customizations = {
                "colors": {"bg": "#123456"},
                "ui_font_size": 12,
            }
            theme = manager.create_user_theme("My Theme", "classic_green", customizations)

            assert theme.name == "My Theme"
            assert theme.colors["bg"] == "#123456"
            # Другие цвета должны быть унаследованы
            assert "fg" in theme.colors

    def test_user_theme_is_persisted(self) -> None:
        """Пользовательская тема сохраняется."""
        with TemporaryDirectory() as tmpdir:
            # Создаём менеджер и тему
            manager1 = ThemeManager(Path(tmpdir))
            customizations = {"colors": {"bg": "#123456"}}
            manager1.create_user_theme("Persisted", "classic_green", customizations)

            # Создаём новый менеджер - должен загрузить тему
            manager2 = ThemeManager(Path(tmpdir))
            themes = manager2.list_themes()

            assert "persisted" in themes
            assert "(пользовательская)" in themes["persisted"]

    def test_is_user_theme(self) -> None:
        """Проверка пользовательской темы."""
        with TemporaryDirectory() as tmpdir:
            manager = ThemeManager(Path(tmpdir))

            assert manager.is_user_theme("classic_green") is False

            manager.create_user_theme("User Theme", "classic_green", {})
            assert manager.is_user_theme("user_theme") is True

    def test_delete_user_theme(self) -> None:
        """Удаление пользовательской темы."""
        with TemporaryDirectory() as tmpdir:
            manager = ThemeManager(Path(tmpdir))
            manager.create_user_theme("ToDelete", "classic_green", {})

            # Ключ темы: "todelete" (ToDelete -> lower, нет пробелов для замены)
            result = manager.delete_user_theme("todelete")

            assert result is True
            assert "todelete" not in manager.list_themes()

    def test_delete_nonexistent_theme(self) -> None:
        """Удаление несуществующей темы."""
        with TemporaryDirectory() as tmpdir:
            manager = ThemeManager(Path(tmpdir))

            result = manager.delete_user_theme("nonexistent")

            assert result is False


class TestGetThemeManager:
    """Тесты для глобального менеджера тем."""

    def test_singleton(self) -> None:
        """Менеджер тем - синглтон."""
        manager1 = get_theme_manager()
        manager2 = get_theme_manager()

        assert manager1 is manager2

    def test_manager_has_themes(self) -> None:
        """Глобальный менеджер содержит темы."""
        manager = get_theme_manager()
        themes = manager.list_themes()

        assert len(themes) >= 5  # Минимум встроенные темы
