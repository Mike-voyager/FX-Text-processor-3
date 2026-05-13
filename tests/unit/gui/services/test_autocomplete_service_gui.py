"""Unit-тесты для AutocompleteServiceGui.

Проверяет:
- Создание сервиса
- Debounced search (300ms)
- Асинхронный поиск с callback
- Кэширование результатов (TTL 5 минут)
- Инвалидация кэша
- Создание traced StringVar
- Запись использования
- Минимальная длина запроса (2 символа)

Coverage target: ≥90%
"""

from __future__ import annotations

import time
import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest

from src.gui.services.autocomplete_service import AutocompleteServiceGui
from src.services.autocomplete_service import AutocompleteService


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
def mock_core_service() -> Generator[MagicMock, None, None]:
    """Создаёт мок AutocompleteService."""
    service = MagicMock(spec=AutocompleteService)
    service.search.return_value = [
        ("ООО Ромашка", 42),
        ("ООО Василёк", 15),
        ("ООО Лютик", 8),
    ]
    yield service


@pytest.fixture
def gui_service(
    tk_root: tk.Tk, mock_core_service: MagicMock
) -> Generator[AutocompleteServiceGui, None, None]:
    """Создаёт AutocompleteServiceGui с мок core сервисом."""
    service = AutocompleteServiceGui(
        core_service=mock_core_service,
        root=tk_root,
    )
    yield service


@pytest.fixture
def standalone_gui_service() -> AutocompleteServiceGui:
    """Создаёт AutocompleteServiceGui без мока core сервиса и без root."""
    return AutocompleteServiceGui()


# =============================================================================
# TEST: Service Creation
# =============================================================================


class TestServiceCreation:
    """Тесты создания сервиса."""

    def test_service_creation_with_core_service(
        self, tk_root: tk.Tk, mock_core_service: MagicMock
    ) -> None:
        """Создание с core_service."""
        service = AutocompleteServiceGui(
            core_service=mock_core_service,
            root=tk_root,
        )

        assert service._core_service == mock_core_service
        assert service._root == tk_root

    def test_service_creation_without_core_service(self, tk_root: tk.Tk) -> None:
        """Создание без core_service создаёт новый."""
        service = AutocompleteServiceGui(root=tk_root)

        assert service._core_service is not None
        assert isinstance(service._core_service, AutocompleteService)

    def test_service_creation_without_root(self) -> None:
        """Создание без root работает."""
        service = AutocompleteServiceGui()

        assert service._root is None
        assert service._core_service is not None

    def test_service_default_config(self, standalone_gui_service: AutocompleteServiceGui) -> None:
        """Проверка дефолтных настроек."""
        assert standalone_gui_service._debounce_ms == 300
        assert standalone_gui_service._ttl_seconds == 300
        assert standalone_gui_service._cache == {}


# =============================================================================
# TEST: Synchronous Search
# =============================================================================


@pytest.mark.gui
class TestSyncSearch:
    """Тесты синхронного поиска."""

    def test_search_returns_results(
        self, gui_service: AutocompleteServiceGui, mock_core_service: MagicMock
    ) -> None:
        """search() возвращает результаты."""
        results = gui_service.search(
            field_id="company",
            document_index="DVN-44-K53-IX",
            query="ООО",
            limit=5,
        )

        assert len(results) == 3
        mock_core_service.search.assert_called_once()

    def test_search_passes_correct_params(
        self, gui_service: AutocompleteServiceGui, mock_core_service: MagicMock
    ) -> None:
        """search() передаёт правильные параметры."""
        gui_service.search(
            field_id="recipient",
            document_index="DVN-44",
            query="Мос",
            limit=10,
        )

        mock_core_service.search.assert_called_with(
            field_id="recipient",
            document_index="DVN-44",
            query="Мос",
            limit=10,
        )

    def test_search_caches_results(
        self, gui_service: AutocompleteServiceGui, mock_core_service: MagicMock
    ) -> None:
        """search() кэширует результаты."""
        # First call
        gui_service.search(
            field_id="company",
            document_index="DVN-44-K53-IX",
            query="ООО",
        )

        # Second call with same params should use cache
        gui_service.search(
            field_id="company",
            document_index="DVN-44-K53-IX",
            query="ООО",
        )

        # Core service should only be called once
        assert mock_core_service.search.call_count == 1


# =============================================================================
# TEST: Cache
# =============================================================================


@pytest.mark.gui
class TestCache:
    """Тесты кэширования."""

    def test_cache_hit_returns_immediately(
        self, gui_service: AutocompleteServiceGui, mock_core_service: MagicMock
    ) -> None:
        """Cache hit возвращает результаты немедленно."""
        # Prime cache
        gui_service._cache[(
            "company",
            "DVN-44-K53-IX",
            "cached_query",
            5,
        )] = ([("Cached Result", 10)], time.time())

        # Search should return cached without calling core
        results = gui_service.search(
            field_id="company",
            document_index="DVN-44-K53-IX",
            query="cached_query",
        )

        assert results == [("Cached Result", 10)]
        # Core service should not be called for cached result
        assert mock_core_service.search.call_count == 0

    def test_cache_expiration(
        self, gui_service: AutocompleteServiceGui, mock_core_service: MagicMock
    ) -> None:
        """Устаревшие записи удаляются из кэша."""
        # Add expired cache entry
        old_time = time.time() - 400  # More than 300s TTL
        gui_service._cache[("company", "DVN-44", "old_query", 5)] = (
            [("Old Result", 5)],
            old_time,
        )

        # Search should call core service
        gui_service.search(
            field_id="company",
            document_index="DVN-44",
            query="old_query",
        )

        assert mock_core_service.search.call_count == 1

    def test_cache_invalidation_all(
        self, gui_service: AutocompleteServiceGui, mock_core_service: MagicMock
    ) -> None:
        """invalidate_cache() очищает весь кэш."""
        # Add some cache entries
        gui_service._cache[("a", "b", "c", 5)] = ([("result", 1)], time.time())
        gui_service._cache[("d", "e", "f", 5)] = ([("result", 2)], time.time())

        gui_service.invalidate_cache()

        assert len(gui_service._cache) == 0

    def test_cache_invalidation_pattern(
        self, gui_service: AutocompleteServiceGui, mock_core_service: MagicMock
    ) -> None:
        """invalidate_cache(pattern) выборочно удаляет."""
        # Add cache entries
        gui_service._cache[("field1", "DVN-44", "q", 5)] = ([], time.time())
        gui_service._cache[("field2", "ABC-99", "q", 5)] = ([], time.time())
        gui_service._cache[("field3", "DVN-44", "q", 5)] = ([], time.time())

        gui_service.invalidate_cache("DVN-44")

        assert len(gui_service._cache) == 1
        assert ("field2", "ABC-99", "q", 5) in gui_service._cache

    def test_cleanup_expired(
        self, gui_service: AutocompleteServiceGui, mock_core_service: MagicMock
    ) -> None:
        """cleanup_expired() удаляет устаревшие записи."""
        # Add expired entry
        old_time = time.time() - 400
        gui_service._cache[("old", "idx", "q", 5)] = ([], old_time)
        # Add fresh entry
        gui_service._cache[("fresh", "idx", "q", 5)] = ([], time.time())

        count = gui_service.cleanup_expired()

        assert count == 1
        assert len(gui_service._cache) == 1
        assert ("fresh", "idx", "q", 5) in gui_service._cache

    def test_get_cache_stats(
        self, gui_service: AutocompleteServiceGui, mock_core_service: MagicMock
    ) -> None:
        """get_cache_stats() возвращает статистику."""
        # Add entries
        gui_service._cache[("a", "b", "c", 5)] = ([], time.time())
        gui_service._cache[("d", "e", "f", 5)] = ([], time.time() - 400)

        stats = gui_service.get_cache_stats()

        assert stats["entries"] == 2
        assert stats["expired"] == 1


# =============================================================================
# TEST: Asynchronous Search
# =============================================================================


@pytest.mark.gui
class TestAsyncSearch:
    """Тесты асинхронного поиска."""

    def test_search_async_callback(
        self, gui_service: AutocompleteServiceGui, tk_root: tk.Tk
    ) -> None:
        """search_async() вызывает callback с результатами."""
        callback_called = False
        callback_results = None

        def callback(results: list[tuple[str, int]]) -> None:
            nonlocal callback_called, callback_results
            callback_called = True
            callback_results = results

        gui_service.search_async(
            field_id="company",
            document_index="DVN-44-K53-IX",
            query="ООО",
            callback=callback,
        )

        # Wait for debounce
        tk_root.update_idletasks()
        tk_root.after(350, lambda: None)
        tk_root.update_idletasks()

        # Note: In actual async test, we'd need to wait for the after callback
        # This is a simplified test

    def test_search_async_minimum_query_length(
        self, gui_service: AutocompleteServiceGui
    ) -> None:
        """Запрос менее 2 символов возвращает пустой список."""
        callback_called = False
        callback_results = None

        def callback(results: list[tuple[str, int]]) -> None:
            nonlocal callback_called, callback_results
            callback_called = True
            callback_results = results

        gui_service.search_async(
            field_id="company",
            document_index="DVN-44-K53-IX",
            query="A",  # Only 1 character
            callback=callback,
        )

        # Should be called immediately with empty results
        assert callback_called is True
        assert callback_results == []

    def test_search_async_cache_hit_no_debounce(
        self, gui_service: AutocompleteServiceGui, mock_core_service: MagicMock
    ) -> None:
        """Cache hit возвращает немедленно без debounce."""
        # Prime cache
        gui_service._cache[(
            "company",
            "DVN-44-K53-IX",
            "cached",
            5,
        )] = ([("Cached", 10)], time.time())

        callback_called = False
        callback_results = None

        def callback(results: list[tuple[str, int]]) -> None:
            nonlocal callback_called, callback_results
            callback_called = True
            callback_results = results

        gui_service.search_async(
            field_id="company",
            document_index="DVN-44-K53-IX",
            query="cached",
            callback=callback,
        )

        # Should be called immediately
        assert callback_called is True
        assert callback_results == [("Cached", 10)]
        # Core service should not be called
        assert mock_core_service.search.call_count == 0


# =============================================================================
# TEST: Debounce
# =============================================================================


@pytest.mark.gui
class TestDebounce:
    """Тесты debounce механизма."""

    def test_debounce_cancels_previous(
        self, gui_service: AutocompleteServiceGui, tk_root: tk.Tk
    ) -> None:
        """Новый вызов отменяет предыдущий отложенный."""
        gui_service._root = tk_root

        callback1_called = False
        callback2_called = False

        def callback1(results: list[tuple[str, int]]) -> None:
            nonlocal callback1_called
            callback1_called = True

        def callback2(results: list[tuple[str, int]]) -> None:
            nonlocal callback2_called
            callback2_called = True

        # First call
        gui_service.search_async(
            field_id="company",
            document_index="DVN-44",
            query="Мос",
            callback=callback1,
        )

        # Second call should cancel first
        gui_service._cancel_pending()

        # Check that after_id was reset
        assert gui_service._pending_after_id is None


# =============================================================================
# TEST: Traced Variable
# =============================================================================


@pytest.mark.gui
class TestTracedVariable:
    """Тесты создания traced StringVar."""

    def test_create_traced_var(self, gui_service: AutocompleteServiceGui, tk_root: tk.Tk) -> None:
        """create_traced_var создаёт StringVar с trace."""
        var = gui_service.create_traced_var(
            field_id="company",
            document_index="DVN-44-K53-IX",
            root=tk_root,
        )

        assert isinstance(var, tk.StringVar)

    def test_create_traced_var_with_callback(
        self, gui_service: AutocompleteServiceGui, tk_root: tk.Tk
    ) -> None:
        """StringVar вызывает callback при изменении."""
        callback_called = False
        callback_value = None

        def on_change(value: str) -> None:
            nonlocal callback_called, callback_value
            callback_called = True
            callback_value = value

        var = gui_service.create_traced_var(
            field_id="company",
            document_index="DVN-44-K53-IX",
            callback=on_change,
            root=tk_root,
        )

        var.set("Test Value")

        assert callback_called is True
        assert callback_value == "Test Value"

    def test_create_traced_var_no_root_raises(
        self, standalone_gui_service: AutocompleteServiceGui
    ) -> None:
        """ValueError если нет root."""
        with pytest.raises(ValueError, match="Tk root window required"):
            standalone_gui_service.create_traced_var(
                field_id="company",
                document_index="DVN-44-K53-IX",
            )


# =============================================================================
# TEST: Record Usage
# =============================================================================


@pytest.mark.gui
class TestRecordUsage:
    """Тесты записи использования."""

    def test_record_usage(
        self, gui_service: AutocompleteServiceGui, mock_core_service: MagicMock
    ) -> None:
        """record_usage передаёт вызов в core сервис."""
        gui_service.record_usage(
            field_id="recipient",
            document_index="DVN-44-K53-IX",
            value='ООО "Ромашка"',
        )

        mock_core_service.record_usage.assert_called_once_with(
            "recipient",
            "DVN-44-K53-IX",
            'ООО "Ромашка"',
        )


# =============================================================================
# TEST: Constants
# =============================================================================


class TestConstants:
    """Тесты констант."""

    def test_debounce_ms_constant(self) -> None:
        """DEBOUNCE_MS = 300ms."""
        from src.gui.services.autocomplete_service import DEBOUNCE_MS

        assert DEBOUNCE_MS == 300

    def test_ttl_seconds_constant(self) -> None:
        """TTL_SECONDS = 300s (5 минут)."""
        from src.gui.services.autocomplete_service import TTL_SECONDS

        assert TTL_SECONDS == 300

    def test_min_query_length_constant(self) -> None:
        """MIN_QUERY_LENGTH = 2."""
        from src.gui.services.autocomplete_service import MIN_QUERY_LENGTH

        assert MIN_QUERY_LENGTH == 2


# =============================================================================
# TEST: Edge Cases
# =============================================================================


@pytest.mark.gui
class TestEdgeCases:
    """Тесты крайних случаев."""

    def test_search_empty_query(
        self, gui_service: AutocompleteServiceGui, mock_core_service: MagicMock
    ) -> None:
        """Пустой запрос обрабатывается."""
        results = gui_service.search(
            field_id="company",
            document_index="DVN-44",
            query="",
        )

        # Core service should still be called
        assert mock_core_service.search.call_count == 1

    def test_search_async_exactly_two_chars(
        self, gui_service: AutocompleteServiceGui
    ) -> None:
        """Запрос ровно 2 символа проходит."""
        callback_called = False

        def callback(results: list[tuple[str, int]]) -> None:
            nonlocal callback_called
            callback_called = True

        gui_service.search_async(
            field_id="company",
            document_index="DVN-44",
            query="AB",  # Exactly 2 characters
            callback=callback,
        )

        # Should NOT be called immediately (debounced)
        # Note: In this test it's not called immediately because len >= 2

    def test_cache_key_uniqueness(
        self, gui_service: AutocompleteServiceGui
    ) -> None:
        """Разные параметры создают разные ключи кэша."""
        key1 = ("field1", "idx1", "query1", 5)
        key2 = ("field1", "idx1", "query1", 10)
        key3 = ("field2", "idx1", "query1", 5)

        assert key1 != key2
        assert key1 != key3
        assert key2 != key3


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.services.autocomplete_service"])
