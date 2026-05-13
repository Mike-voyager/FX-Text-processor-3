"""Тесты для AutocompleteEntry."""

from __future__ import annotations

import pytest
import tkinter as tk

from src.view.widgets.autocomplete_entry import AutocompleteEntry


@pytest.fixture
def root():
    """Фикстура для Tk root."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def mock_suggestions():
    """Фикстура с тестовыми подсказками."""
    def get_suggestions(query: str, limit: int):
        suggestions = [
            ("apple", 10),
            ("application", 8),
            ("apply", 5),
            ("apricot", 3),
        ]
        filtered = [(v, f) for v, f in suggestions if query.lower() in v.lower()]
        return filtered[:limit]

    return get_suggestions


class TestAutocompleteEntry:
    """Тесты для поля ввода с автодополнением."""

    def test_init_default(self, root):
        """Тест инициализации."""
        entry = AutocompleteEntry(root)
        assert entry.get() == ""

    def test_get_set(self, root):
        """Тест get и set методов."""
        entry = AutocompleteEntry(root)
        entry.set("test_value")
        assert entry.get() == "test_value"

    def test_clear(self, root):
        """Тест очистки."""
        entry = AutocompleteEntry(root)
        entry.set("test_value")
        entry.clear()
        assert entry.get() == ""

    def test_min_chars_config(self, root):
        """Тест конфигурации min_chars."""
        entry = AutocompleteEntry(root, min_chars=3)
        assert entry._min_chars == 3

    def test_max_suggestions_config(self, root):
        """Тест конфигурации max_suggestions."""
        entry = AutocompleteEntry(root, max_suggestions=10)
        assert entry._max_suggestions == 10

    def test_custom_suggestions(self, root):
        """Тест кастомных подсказок."""
        suggestions = [("suggestion1", 5), ("suggestion2", 3)]

        def get_suggestions(query, limit):
            return suggestions

        entry = AutocompleteEntry(root, get_suggestions=get_suggestions)
        entry._fetch_suggestions("test")

        assert entry._suggestions == suggestions


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
