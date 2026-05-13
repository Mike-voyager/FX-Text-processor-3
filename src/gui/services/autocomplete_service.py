# -*- coding: utf-8 -*-
"""Tkinter-friendly wrapper для AutocompleteService.

Предоставляет GUI-обёртку вокруг core AutocompleteService с поддержкой:
- Debounced search (300ms задержка)
- Асинхронный поиск с callback
- Кэширование результатов (TTL 5 минут)
- Фабрика traced StringVar для автоматической привязки

Example:
    >>> from tkinter import Tk
    >>> from src.gui.services.autocomplete_service import AutocompleteServiceGui
    >>> root = Tk()
    >>> gui_service = AutocompleteServiceGui()
    >>> var = gui_service.create_traced_var(
    ...     field_id="recipient",
    ...     document_index="DVN-44-K53-IX",
    ...     callback=lambda results: print(results)
    ... )
    >>> var.set("ООО")  # Триггерит debounced search

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import time
import tkinter as tk
from typing import Callable, Final, Optional, TypeAlias

from src.services.autocomplete_service import AutocompleteService

# Типы
CacheKey: TypeAlias = tuple[str, str, str, int]  # (field_id, document_index, query, limit)
SearchResult: TypeAlias = list[tuple[str, int]]
CacheEntry: TypeAlias = tuple[SearchResult, float]  # (results, timestamp)

# Константы
DEBOUNCE_MS: Final[int] = 300  # 300ms задержка для debounce
TTL_SECONDS: Final[int] = 300  # 5 минут TTL для кэша
MIN_QUERY_LENGTH: Final[int] = 2  # Минимальная длина запроса для поиска


class AutocompleteServiceGui:
    """Tkinter-friendly wrapper для AutocompleteService.

    Обеспечивает debounced поиск с кэшированием результатов.
    Все операции выполняются в главном потоке Tkinter через after(),
    что делает реализацию потокобезопасной для GUI.

    Attributes:
        _core_service: Core AutocompleteService для выполнения поиска.
        _cache: Кэш результатов поиска с TTL.
        _pending_after_id: ID текущего отложенного вызова (для отмены).
        _debounce_ms: Задержка debounce в миллисекундах.
        _ttl_seconds: Время жизни записи кэша в секундах.
        _root: Опциональная ссылка на корневое окно Tkinter.

    Example:
        >>> service = AutocompleteServiceGui()
        >>> service.search_async(
        ...     field_id="company",
        ...     document_index="DVN-44-K53-IX",
        ...     query="ООО",
        ...     callback=lambda r: print(f"Found {len(r)} results"),
        ... )
    """

    def __init__(
        self,
        core_service: Optional[AutocompleteService] = None,
        root: Optional[tk.Tk] = None,
    ) -> None:
        """Инициализация GUI wrapper.

        Args:
            core_service: Core сервис для автокомплита. Если None, создаётся
                новый экземпляр AutocompleteService.
            root: Корневое окно Tkinter для использования after().
                Если None, должен быть передан при вызове методов.
        """
        self._core_service: AutocompleteService = core_service or AutocompleteService()
        self._cache: dict[CacheKey, CacheEntry] = {}
        self._pending_after_id: Optional[str] = None
        self._debounce_ms: int = DEBOUNCE_MS
        self._ttl_seconds: int = TTL_SECONDS
        self._root: Optional[tk.Tk] = root

    def search(
        self,
        field_id: str,
        document_index: str,
        query: str,
        limit: int = 5,
    ) -> list[tuple[str, int]]:
        """Синхронный поиск с кэшированием.

        Выполняет поиск в кэше или делегирует core сервису.
        Результаты сохраняются в кэш при отсутствии hit.

        Args:
            field_id: Идентификатор поля для поиска.
            document_index: Индекс документа (или его часть для иерархии).
            query: Строка поиска (префикс).
            limit: Максимальное количество результатов.

        Returns:
            Список кортежей (value, use_count), отсортированный
            по убыванию частоты использования.

        Example:
            >>> service = AutocompleteServiceGui()
            >>> results = service.search(
            ...     field_id="recipient",
            ...     document_index="DVN-44-K53-IX",
            ...     query="ООО",
            ...     limit=5,
            ... )
            >>> len(results) <= 5
            True
        """
        cache_key = (field_id, document_index, query, limit)

        # Проверяем кэш
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        # Кэш miss - вызываем core сервис
        results = self._core_service.search(
            field_id=field_id,
            document_index=document_index,
            query=query,
            limit=limit,
        )

        # Сохраняем в кэш
        self._set_cached(cache_key, results)

        return results

    def search_async(
        self,
        field_id: str,
        document_index: str,
        query: str,
        callback: Callable[[list[tuple[str, int]]], None],
        limit: int = 5,
    ) -> None:
        """Асинхронный поиск с debounce и callback.

        Отменяет предыдущий отложенный поиск и запускает новый
        после задержки debounce_ms. При кэш hit вызывает callback
        немедленно без задержки.

        Args:
            field_id: Идентификатор поля для поиска.
            document_index: Индекс документа.
            query: Строка поиска (префикс).
            callback: Функция вызываемая с результатами поиска.
            limit: Максимальное количество результатов.

        Example:
            >>> def on_results(results: list[tuple[str, int]]) -> None:
            ...     for value, freq in results:
            ...         print(f"  {value} ({freq})")
            >>> service = AutocompleteServiceGui()
            >>> service.search_async(
            ...     field_id="company",
            ...     document_index="DVN-44",
            ...     query="Мос",
            ...     callback=on_results,
            ... )
        """
        # Проверяем минимальную длину запроса
        if len(query) < MIN_QUERY_LENGTH:
            callback([])
            return

        cache_key = (field_id, document_index, query, limit)

        # Проверяем кэш
        cached = self._get_cached(cache_key)
        if cached is not None:
            callback(cached)
            return

        # Отменяем предыдущий отложенный вызов
        self._cancel_pending()

        # Сохраняем параметры для отложенного вызова
        self._pending_search_params = (field_id, document_index, query, callback, limit)

        # Запускаем debounced поиск через after()
        if self._root is not None:
            self._pending_after_id = self._root.after(
                self._debounce_ms,
                self._execute_search,
            )
        else:
            # Fallback: синхронный вызов если нет root
            self._execute_search()

    def _execute_search(self) -> None:
        """Выполняет отложенный поиск и вызывает callback."""
        self._pending_after_id = None

        if not hasattr(self, "_pending_search_params"):
            return

        field_id, document_index, query, callback, limit = self._pending_search_params
        delattr(self, "_pending_search_params")

        results = self.search(field_id, document_index, query, limit)
        callback(results)

    def _cancel_pending(self) -> None:
        """Отменяет текущий отложенный вызов."""
        if self._pending_after_id is not None and self._root is not None:
            self._root.after_cancel(self._pending_after_id)
            self._pending_after_id = None

    def create_traced_var(
        self,
        field_id: str,
        document_index: str,
        callback: Optional[Callable[[str], None]] = None,
        root: Optional[tk.Tk] = None,
    ) -> tk.StringVar:
        """Создаёт traced StringVar с автоматическим поиском.

        Создаёт StringVar, которая автоматически триггерит
        debounced поиск при изменении значения. Результаты
        передаются через callback.

        Args:
            field_id: Идентификатор поля для поиска.
            document_index: Индекс документа.
            callback: Функция вызываемая с текстом при изменении.
                Если None, только сохраняет root для after().
            root: Корневое окно Tkinter. Если не передано, использует
                root из __init__. Один из них должен быть указан.

        Returns:
            tk.StringVar с установленным trace.

        Raises:
            ValueError: Если не указан root ни здесь, ни в __init__.

        Example:
            >>> root = tk.Tk()
            >>> service = AutocompleteServiceGui(root=root)
            >>> def on_change(text: str) -> None:
            ...     print(f"Search for: {text}")
            >>> var = service.create_traced_var(
            ...     field_id="recipient",
            ...     document_index="DVN-44-K53-IX",
            ...     callback=on_change,
            ... )
            >>> var.set("ООО")  # Триггерит on_change
        """
        effective_root = root or self._root
        if effective_root is None:
            raise ValueError("Tk root window required. Pass it to __init__ or create_traced_var()")

        # Сохраняем root для использования в callback
        if root is not None and self._root is None:
            self._root = root

        var = tk.StringVar()

        def on_var_change(*args: object) -> None:
            """Обработчик изменения переменной."""
            value = var.get()
            if callback is not None:
                callback(value)

        var.trace_add("write", on_var_change)

        return var

    def invalidate_cache(self, pattern: Optional[str] = None) -> None:
        """Инвалидация кэша результатов.

        Args:
            pattern: Опциональный паттерн для выборочной инвалидации.
                Если указан, удаляются записи, где field_id или
                document_index содержат pattern. Если None,
                кэш полностью очищается.

        Example:
            >>> service = AutocompleteServiceGui()
            >>> service.invalidate_cache()  # Полная очистка
            >>> service.invalidate_cache("DVN-44")  # Частичная
        """
        if pattern is None:
            self._cache.clear()
            return

        # Выборочная инвалидация по паттерну
        keys_to_remove: list[CacheKey] = []
        for key in self._cache:
            field_id, document_index, query, _ = key
            if pattern in field_id or pattern in document_index:
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del self._cache[key]

    def record_usage(
        self,
        field_id: str,
        document_index: str,
        value: str,
    ) -> None:
        """Записывает использование значения в историю.

        Пробрасывает вызов напрямую в core сервис.

        Args:
            field_id: Идентификатор поля.
            document_index: Полный индекс документа.
            value: Использованное значение.

        Example:
            >>> service = AutocompleteServiceGui()
            >>> service.record_usage(
            ...     field_id="recipient",
            ...     document_index="DVN-44-K53-IX",
            ...     value='ООО "Ромашка"',
            ... )
        """
        self._core_service.record_usage(field_id, document_index, value)

    def _get_cached(self, key: CacheKey) -> Optional[list[tuple[str, int]]]:
        """Получает результаты из кэша если они не устарели.

        Args:
            key: Ключ кэша (field_id, document_index, query, limit).

        Returns:
            Результаты если найдены и не устарели, иначе None.
        """
        if key not in self._cache:
            return None

        results, timestamp = self._cache[key]

        # Проверяем TTL
        if time.time() - timestamp > self._ttl_seconds:
            del self._cache[key]
            return None

        return results

    def _set_cached(self, key: CacheKey, results: list[tuple[str, int]]) -> None:
        """Сохраняет результаты в кэш.

        Args:
            key: Ключ кэша.
            results: Результаты для сохранения.
        """
        self._cache[key] = (results, time.time())

    def cleanup_expired(self) -> int:
        """Очищает устаревшие записи кэша.

        Returns:
            Количество удалённых записей.
        """
        now = time.time()
        expired_keys: list[CacheKey] = []

        for key, (_, timestamp) in self._cache.items():
            if now - timestamp > self._ttl_seconds:
                expired_keys.append(key)

        for key in expired_keys:
            del self._cache[key]

        return len(expired_keys)

    def get_cache_stats(self) -> dict[str, int]:
        """Возвращает статистику кэша.

        Returns:
            Словарь с количеством записей и размером кэша.

        Example:
            >>> service = AutocompleteServiceGui()
            >>> stats = service.get_cache_stats()
            >>> print(f"Cache size: {stats['entries']}")
        """
        return {
            "entries": len(self._cache),
            "expired": self._count_expired(),
        }

    def _count_expired(self) -> int:
        """Считает количество устаревших записей.

        Returns:
            Количество записей с истёкшим TTL.
        """
        now = time.time()
        return sum(
            1 for _, timestamp in self._cache.values() if now - timestamp > self._ttl_seconds
        )


__all__: list[str] = [
    "AutocompleteServiceGui",
]
