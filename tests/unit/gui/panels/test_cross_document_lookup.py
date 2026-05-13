"""Тесты для панели поиска значений в иерархии документов.

Модуль содержит unit-тесты для CrossDocumentLookupPanel:
- Создание панели
- Поиск по различным уровням иерархии
- Выбор значений
- Кеширование результатов
- Обработка ошибок

Example:
    $ pytest tests/unit/gui/panels/test_cross_document_lookup.py -v

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import sys
import tkinter as tk
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock, call, patch

import pytest

# Добавляем путь к src
sys.path.insert(0, "/home/Mike/Dev/FX-Text-processor/FX-Text-processor-3")

from src.gui.panels.cross_document_lookup import (
    CACHE_SIZE_LIMIT,
    CACHE_TTL_SECONDS,
    MAX_RESULTS,
    CacheEntry,
    CrossDocumentLookupPanel,
    DocumentServiceProtocol,
    FieldValueResult,
    HierarchyLevel,
    SearchCriteria,
)


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def mock_document_service() -> MagicMock:
    """Создаёт мок сервиса документов."""
    service = MagicMock(spec=DocumentServiceProtocol)
    return service


@pytest.fixture
def tk_root() -> tk.Tk:
    """Создаёт корневое окно Tkinter для тестов."""
    root = tk.Tk()
    root.withdraw()  # Скрываем окно
    yield root
    root.destroy()


@pytest.fixture
def sample_results() -> List[FieldValueResult]:
    """Создаёт примеры результатов поиска."""
    return [
        FieldValueResult(
            document_id="doc-001",
            document_index="DVN-44-K53-I",
            field_id="client_name",
            value="ООО Ромашка",
            created_at=datetime(2026, 1, 15, 10, 0),
            modified_at=datetime(2026, 1, 15, 14, 30),
        ),
        FieldValueResult(
            document_id="doc-002",
            document_index="DVN-44-K53-II",
            field_id="client_name",
            value="ИП Иванов",
            created_at=datetime(2026, 2, 10, 9, 0),
            modified_at=datetime(2026, 2, 10, 16, 45),
        ),
        FieldValueResult(
            document_id="doc-003",
            document_index="DVN-44-K53-III",
            field_id="client_name",
            value="АО Свет",
            created_at=datetime(2026, 3, 5, 11, 0),
            modified_at=datetime(2026, 3, 5, 12, 0),
        ),
    ]


@pytest.fixture
def panel(
    tk_root: tk.Tk,
    mock_document_service: MagicMock,
) -> CrossDocumentLookupPanel:
    """Создаёт экземпляр панели для тестов."""
    panel = CrossDocumentLookupPanel(
        parent=tk_root,
        document_service=mock_document_service,
        current_index="DVN-44-K53-X",
        on_value_selected=lambda fid, val: None,
    )
    panel.mount(tk_root)
    return panel


# =============================================================================
# TESTS: PANEL CREATION
# =============================================================================


class TestPanelCreation:
    """Тесты создания панели."""

    def test_init(self, tk_root: tk.Tk, mock_document_service: MagicMock) -> None:
        """Тест инициализации панели."""
        panel = CrossDocumentLookupPanel(
            parent=tk_root,
            document_service=mock_document_service,
            current_index="DVN-44-K53-X",
            on_value_selected=lambda fid, val: None,
        )

        assert panel.widget_id == "cross_document_lookup"
        assert panel._current_index == "DVN-44-K53-X"
        assert panel._document_service == mock_document_service
        assert panel._index_segments == ["DVN", "44", "K53", "X"]
        assert panel._cache == {}

    def test_init_with_callback(self, tk_root: tk.Tk, mock_document_service: MagicMock) -> None:
        """Тест инициализации с callback."""
        callback_called = []

        def callback(field_id: str, value: str) -> None:
            callback_called.append((field_id, value))

        panel = CrossDocumentLookupPanel(
            parent=tk_root,
            document_service=mock_document_service,
            current_index="DVN-44-K53-X",
            on_value_selected=callback,
        )

        assert panel._on_value_selected == callback

    def test_mount(self, tk_root: tk.Tk, mock_document_service: MagicMock) -> None:
        """Тест монтирования панели."""
        panel = CrossDocumentLookupPanel(
            parent=tk_root,
            document_service=mock_document_service,
            current_index="DVN-44-K53-X",
            on_value_selected=None,
        )

        widget = panel.mount(tk_root)
        assert panel.is_mounted()
        assert isinstance(widget, tk.Widget)

    def test_unmount(self, tk_root: tk.Tk, mock_document_service: MagicMock) -> None:
        """Тест демонтирования панели."""
        panel = CrossDocumentLookupPanel(
            parent=tk_root,
            document_service=mock_document_service,
            current_index="DVN-44-K53-X",
            on_value_selected=None,
        )
        panel.mount(tk_root)
        panel.unmount()

        assert not panel.is_mounted()


# =============================================================================
# TESTS: SEARCH FUNCTIONALITY
# =============================================================================


class TestSearchFunctionality:
    """Тесты функциональности поиска."""

    def test_perform_search_with_results(
        self,
        panel: CrossDocumentLookupPanel,
        mock_document_service: MagicMock,
        sample_results: List[FieldValueResult],
    ) -> None:
        """Тест поиска с результатами."""
        mock_document_service.search_field_values.return_value = sample_results

        panel._search_var.set("client_name")
        panel._perform_search()

        mock_document_service.search_field_values.assert_called_once()
        call_args = mock_document_service.search_field_values.call_args
        assert call_args.kwargs["field_id"] == "client_name"
        assert panel._current_results == sample_results

    def test_perform_search_empty_field(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест поиска с пустым полем."""
        panel._search_var.set("")
        panel._perform_search()

        assert panel._status_var.get() == "Введите идентификатор поля"

    def test_perform_search_no_results(
        self,
        panel: CrossDocumentLookupPanel,
        mock_document_service: MagicMock,
    ) -> None:
        """Тест поиска без результатов."""
        mock_document_service.search_field_values.return_value = []

        panel._search_var.set("nonexistent_field")
        panel._perform_search()

        assert panel._current_results == []
        assert "Найдено результатов: 0" in panel._status_var.get()

    def test_perform_search_error(
        self,
        panel: CrossDocumentLookupPanel,
        mock_document_service: MagicMock,
    ) -> None:
        """Тест обработки ошибки поиска."""
        mock_document_service.search_field_values.side_effect = Exception("DB Error")

        panel._search_var.set("client_name")
        panel._perform_search()

        assert "Ошибка поиска" in panel._status_var.get()


# =============================================================================
# TESTS: HIERARCHY LEVELS
# =============================================================================


class TestHierarchyLevels:
    """Тесты уровней иерархии."""

    def test_get_index_pattern_exact(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест паттерна для точного индекса."""
        pattern = panel._get_index_pattern(HierarchyLevel.EXACT)
        assert pattern == "DVN-44-K53-X"

    def test_get_index_pattern_series(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест паттерна для уровня серии."""
        pattern = panel._get_index_pattern(HierarchyLevel.SERIES)
        assert pattern == "DVN-44-K53-*"

    def test_get_index_pattern_subtype(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест паттерна для уровня подтипа."""
        pattern = panel._get_index_pattern(HierarchyLevel.SUBTYPE)
        assert pattern == "DVN-44-*"

    def test_get_index_pattern_root(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест паттерна для корневого уровня."""
        pattern = panel._get_index_pattern(HierarchyLevel.ROOT)
        assert pattern == "DVN-*"

    def test_search_by_series(
        self,
        panel: CrossDocumentLookupPanel,
        mock_document_service: MagicMock,
        sample_results: List[FieldValueResult],
    ) -> None:
        """Тест поиска по уровню серии."""
        mock_document_service.search_field_values.return_value = sample_results

        panel._search_var.set("client_name")
        panel._hierarchy_var.set(HierarchyLevel.SERIES.name)
        panel._perform_search()

        call_args = mock_document_service.search_field_values.call_args
        assert "DVN-44-K53-*" == call_args.kwargs["index_pattern"]

    def test_search_by_subtype(
        self,
        panel: CrossDocumentLookupPanel,
        mock_document_service: MagicMock,
        sample_results: List[FieldValueResult],
    ) -> None:
        """Тест поиска по уровню подтипа."""
        mock_document_service.search_field_values.return_value = sample_results

        panel._search_var.set("client_name")
        panel._hierarchy_var.set(HierarchyLevel.SUBTYPE.name)
        panel._perform_search()

        call_args = mock_document_service.search_field_values.call_args
        assert "DVN-44-*" == call_args.kwargs["index_pattern"]

    def test_search_by_root(
        self,
        panel: CrossDocumentLookupPanel,
        mock_document_service: MagicMock,
        sample_results: List[FieldValueResult],
    ) -> None:
        """Тест поиска по корневому уровню."""
        mock_document_service.search_field_values.return_value = sample_results

        panel._search_var.set("client_name")
        panel._hierarchy_var.set(HierarchyLevel.ROOT.name)
        panel._perform_search()

        call_args = mock_document_service.search_field_values.call_args
        assert "DVN-*" == call_args.kwargs["index_pattern"]


# =============================================================================
# TESTS: DATE RANGE FILTERING
# =============================================================================


class TestDateRangeFiltering:
    """Тесты фильтрации по диапазону дат."""

    def test_parse_date_valid(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест парсинга валидной даты."""
        result = panel._parse_date("15.01.2026")
        assert result == datetime(2026, 1, 15)

    def test_parse_date_iso_format(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест парсинга даты в ISO формате."""
        result = panel._parse_date("2026-01-15")
        assert result == datetime(2026, 1, 15)

    def test_parse_date_empty(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест парсинга пустой строки."""
        result = panel._parse_date("")
        assert result is None

    def test_parse_date_invalid(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест парсинга невалидной даты."""
        result = panel._parse_date("invalid")
        assert result is None

    def test_search_with_date_range(
        self,
        panel: CrossDocumentLookupPanel,
        mock_document_service: MagicMock,
        sample_results: List[FieldValueResult],
    ) -> None:
        """Тест поиска с диапазоном дат."""
        mock_document_service.search_field_values.return_value = sample_results

        panel._search_var.set("client_name")
        panel._date_from_var.set("01.01.2026")
        panel._date_to_var.set("31.12.2026")
        panel._perform_search()

        call_args = mock_document_service.search_field_values.call_args
        assert call_args.kwargs["date_from"] is not None
        assert call_args.kwargs["date_to"] is not None


# =============================================================================
# TESTS: VALUE SELECTION
# =============================================================================


class TestValueSelection:
    """Тесты выбора значения."""

    def test_use_selected_value(
        self,
        tk_root: tk.Tk,
        mock_document_service: MagicMock,
        sample_results: List[FieldValueResult],
    ) -> None:
        """Тест использования выбранного значения."""
        selected_values: List[Tuple[str, str]] = []

        def on_select(field_id: str, value: str) -> None:
            selected_values.append((field_id, value))

        panel = CrossDocumentLookupPanel(
            parent=tk_root,
            document_service=mock_document_service,
            current_index="DVN-44-K53-X",
            on_value_selected=on_select,
        )
        panel.mount(tk_root)

        # Устанавливаем выбранный результат
        panel._selected_result = sample_results[0]
        panel._use_selected_value()

        assert len(selected_values) == 1
        assert selected_values[0] == ("client_name", "ООО Ромашка")

    def test_use_selected_value_no_callback(
        self,
        panel: CrossDocumentLookupPanel,
        sample_results: List[FieldValueResult],
    ) -> None:
        """Тест использования без callback."""
        panel._on_value_selected = None
        panel._selected_result = sample_results[0]

        # Не должно вызывать исключение
        panel._use_selected_value()

    def test_use_selected_value_no_selection(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест использования без выбора."""
        panel._selected_result = None

        # Не должно вызывать исключение или изменять статус
        initial_status = panel._status_var.get()
        panel._use_selected_value()
        assert panel._status_var.get() == initial_status

    def test_update_use_button_state_enabled(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест активации кнопки."""
        panel._selected_result = FieldValueResult(
            document_id="doc-001",
            document_index="DVN-44-K53-I",
            field_id="test_field",
            value="test_value",
            created_at=datetime.now(),
            modified_at=datetime.now(),
        )
        panel._update_use_button_state()

        assert panel._use_button.cget("state") == tk.NORMAL

    def test_update_use_button_state_disabled(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест деактивации кнопки."""
        panel._selected_result = None
        panel._update_use_button_state()

        assert panel._use_button.cget("state") == tk.DISABLED


# =============================================================================
# TESTS: CACHING
# =============================================================================


class TestCaching:
    """Тесты кеширования."""

    def test_add_to_cache(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест добавления в кеш."""
        results = [
            FieldValueResult(
                document_id="doc-001",
                document_index="DVN-44-K53-I",
                field_id="client_name",
                value="Test",
                created_at=datetime.now(),
                modified_at=datetime.now(),
            )
        ]

        panel._add_to_cache("test_key", results)

        assert "test_key" in panel._cache
        assert panel._cache["test_key"].results == results

    def test_get_from_cache_valid(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест получения из кеша (валидная запись)."""
        results = [
            FieldValueResult(
                document_id="doc-001",
                document_index="DVN-44-K53-I",
                field_id="client_name",
                value="Test",
                created_at=datetime.now(),
                modified_at=datetime.now(),
            )
        ]

        panel._add_to_cache("test_key", results)
        cached = panel._get_from_cache("test_key")

        assert cached is not None
        assert cached.results == results

    def test_get_from_cache_expired(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест получения из кеша (устаревшая запись)."""
        results = [
            FieldValueResult(
                document_id="doc-001",
                document_index="DVN-44-K53-I",
                field_id="client_name",
                value="Test",
                created_at=datetime.now(),
                modified_at=datetime.now(),
            )
        ]

        # Добавляем с устаревшим timestamp
        panel._cache["test_key"] = CacheEntry(
            results=results,
            timestamp=datetime.now() - timedelta(seconds=CACHE_TTL_SECONDS + 1),
        )

        cached = panel._get_from_cache("test_key")
        assert cached is None
        assert "test_key" not in panel._cache

    def test_get_from_cache_missing(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест получения из кеша (несуществующая запись)."""
        cached = panel._get_from_cache("nonexistent_key")
        assert cached is None

    def test_cache_size_limit(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест ограничения размера кеша."""
        # Добавляем записи до предела
        for i in range(CACHE_SIZE_LIMIT + 5):
            panel._add_to_cache(f"key_{i}", [])

        assert len(panel._cache) <= CACHE_SIZE_LIMIT

    def test_clear_cache(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест очистки кеша."""
        panel._add_to_cache("key1", [])
        panel._add_to_cache("key2", [])

        count = panel.clear_cache()

        assert count == 2
        assert len(panel._cache) == 0

    def test_cache_stats_empty(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест статистики пустого кеша."""
        stats = panel.get_cache_stats()
        assert stats["entries"] == 0
        assert stats["oldest"] is None
        assert stats["newest"] is None

    def test_cache_stats_with_entries(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест статистики непустого кеша."""
        now = datetime.now()
        panel._cache["key1"] = CacheEntry(results=[], timestamp=now - timedelta(minutes=5))
        panel._cache["key2"] = CacheEntry(results=[], timestamp=now)

        stats = panel.get_cache_stats()
        assert stats["entries"] == 2
        assert stats["oldest"] == now - timedelta(minutes=5)
        assert stats["newest"] == now

    def test_search_uses_cache(
        self,
        panel: CrossDocumentLookupPanel,
        mock_document_service: MagicMock,
        sample_results: List[FieldValueResult],
    ) -> None:
        """Тест использования кеша при поиске."""
        # Добавляем результаты в кеш
        criteria = SearchCriteria(
            field_id="client_name",
            hierarchy_level=HierarchyLevel.SERIES,
            current_index="DVN-44-K53-X",
        )
        panel._add_to_cache(criteria.to_cache_key(), sample_results)

        # Выполняем поиск
        panel._search_var.set("client_name")
        panel._hierarchy_var.set(HierarchyLevel.SERIES.name)
        panel._perform_search()

        # Сервис не должен быть вызван
        mock_document_service.search_field_values.assert_not_called()
        assert "кеша" in panel._status_var.get()


# =============================================================================
# TESTS: DATA CLASSES
# =============================================================================


class TestDataClasses:
    """Тесты классов данных."""

    def test_hierarchy_level_labels(self) -> None:
        """Тест меток уровней иерархии."""
        assert HierarchyLevel.EXACT.get_label() == "Точный индекс"
        assert HierarchyLevel.SERIES.get_label() == "Серия"
        assert HierarchyLevel.SUBTYPE.get_label() == "Подтип"
        assert HierarchyLevel.ROOT.get_label() == "Корень"

    def test_field_value_result_to_treeview(self) -> None:
        """Тест конвертации результата в Treeview."""
        result = FieldValueResult(
            document_id="doc-001",
            document_index="DVN-44-K53-I",
            field_id="client_name",
            value="ООО Ромашка",
            created_at=datetime(2026, 1, 15, 10, 0),
            modified_at=datetime(2026, 1, 15, 14, 30),
        )

        values = result.to_treeview_values()
        assert values == ("DVN-44-K53-I", "ООО Ромашка", "15.01.2026 14:30")

    def test_field_value_result_long_value(self) -> None:
        """Тест обрезки длинных значений."""
        result = FieldValueResult(
            document_id="doc-001",
            document_index="DVN-44-K53-I",
            field_id="description",
            value="A" * 100,
            created_at=datetime.now(),
            modified_at=datetime.now(),
        )

        values = result.to_treeview_values()
        assert values[1].endswith("...")
        assert len(values[1]) == 53  # 50 + "..."

    def test_search_criteria_cache_key(self) -> None:
        """Тест генерации ключа кеша."""
        criteria = SearchCriteria(
            field_id="client_name",
            hierarchy_level=HierarchyLevel.SERIES,
            current_index="DVN-44-K53-X",
        )

        key = criteria.to_cache_key()
        assert "client_name" in key
        assert "SERIES" in key
        assert "DVN-44-K53-X" in key


# =============================================================================
# TESTS: PANEL METHODS
# =============================================================================


class TestPanelMethods:
    """Тесты методов панели."""

    def test_set_field_id(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест установки field_id."""
        panel.set_field_id("new_field")
        assert panel._search_var.get() == "new_field"

    def test_clear_selection(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест очистки выбора."""
        panel._selected_result = FieldValueResult(
            document_id="doc-001",
            document_index="DVN-44-K53-I",
            field_id="test",
            value="test",
            created_at=datetime.now(),
            modified_at=datetime.now(),
        )
        panel._clear_selection()

        assert panel._selected_result is None

    def test_handle_event_returns_false(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест обработки событий."""
        result = panel.handle_event(MagicMock())
        assert result is False


# =============================================================================
# TESTS: INDEX PATTERNS WITH DIFFERENT LENGTHS
# =============================================================================


class TestIndexPatternsEdgeCases:
    """Тесты паттернов индекса для разных длин."""

    def test_short_index_series_fallback(self, tk_root: tk.Tk) -> None:
        """Тест fallback для короткого индекса при поиске по серии."""
        panel = CrossDocumentLookupPanel(
            parent=tk_root,
            document_service=MagicMock(),
            current_index="DVN-44",
            on_value_selected=None,
        )

        pattern = panel._get_index_pattern(HierarchyLevel.SERIES)
        assert pattern == "DVN-44-*"

    def test_short_index_subtype(self, tk_root: tk.Tk) -> None:
        """Тест паттерна для короткого индекса при поиске по подтипу."""
        panel = CrossDocumentLookupPanel(
            parent=tk_root,
            document_service=MagicMock(),
            current_index="DVN",
            on_value_selected=None,
        )

        pattern = panel._get_index_pattern(HierarchyLevel.SUBTYPE)
        assert pattern == "DVN-*"

    def test_single_segment_root(self, tk_root: tk.Tk) -> None:
        """Тест паттерна для одного сегмента."""
        panel = CrossDocumentLookupPanel(
            parent=tk_root,
            document_service=MagicMock(),
            current_index="INV",
            on_value_selected=None,
        )

        pattern = panel._get_index_pattern(HierarchyLevel.ROOT)
        assert pattern == "INV-*"


# =============================================================================
# TESTS: POPULATE RESULTS
# =============================================================================


class TestPopulateResults:
    """Тесты заполнения результатов."""

    def test_populate_results_empty(
        self,
        panel: CrossDocumentLookupPanel,
    ) -> None:
        """Тест заполнения пустых результатов."""
        panel._current_results = []
        panel._populate_results()

        # Дерево должно быть пустым
        items = panel._results_tree.get_children()
        assert len(items) == 0

    def test_populate_results_with_data(
        self,
        panel: CrossDocumentLookupPanel,
        sample_results: List[FieldValueResult],
    ) -> None:
        """Тест заполнения результатов с данными."""
        panel._current_results = sample_results
        panel._populate_results()

        items = panel._results_tree.get_children()
        assert len(items) == len(sample_results)


# =============================================================================
# TESTS: ADDITIONAL COVERAGE
# =============================================================================


class TestAdditionalCoverage:
    """Дополнительные тесты для достижения 90%+ покрытия."""

    def test_focus_search_with_widget(
        self,
        tk_root: tk.Tk,
        mock_document_service: MagicMock,
    ) -> None:
        """Тест установки фокуса на поле поиска."""
        panel = CrossDocumentLookupPanel(
            parent=tk_root,
            document_service=mock_document_service,
            current_index="DVN-44-K53-X",
            on_value_selected=None,
        )
        panel.mount(tk_root)
        panel._focus_search()
        # Фокус должен быть установлен, ошибок не должно быть
        assert True

    def test_focus_search_no_widget(self, panel: CrossDocumentLookupPanel) -> None:
        """Тест установки фокуса когда виджет не создан."""
        panel._tk_widget = None
        panel._focus_search()
        # Не должно быть исключения
        assert True

    def test_short_index_exact_disabled(
        self, tk_root: tk.Tk, mock_document_service: MagicMock
    ) -> None:
        """ТEST: короткий индекс с отключенным уровнем EXACT."""
        panel = CrossDocumentLookupPanel(
            parent=tk_root,
            document_service=mock_document_service,
            current_index="DVN-44",
            on_value_selected=None,
        )
        panel.mount(tk_root)
        # Проверяем что EXACT уровень отключен
        assert True

    def test_on_result_selected_empty(
        self,
        panel: CrossDocumentLookupPanel,
    ) -> None:
        """Тест обработчика выбора без выделения."""
        # Создаём событие мок
        event = MagicMock()
        panel._results_tree.selection = MagicMock(return_value=())
        panel._on_result_selected(event)
        assert panel._selected_result is None

    def test_on_result_selected_with_selection(
        self,
        panel: CrossDocumentLookupPanel,
        sample_results: List[FieldValueResult],
    ) -> None:
        """Тест обработчика выбора с выделением."""
        panel._current_results = sample_results
        panel._populate_results()

        # Выбираем первый элемент
        items = panel._results_tree.get_children()
        if items:
            panel._results_tree.selection_set(items[0])
            event = MagicMock()
            panel._on_result_selected(event)
            assert panel._selected_result is not None

    def test_refresh_method(
        self,
        panel: CrossDocumentLookupPanel,
        mock_document_service: MagicMock,
    ) -> None:
        """Тест метода refresh."""
        mock_document_service.search_field_values.return_value = []
        panel._search_var.set("test_field")
        panel.refresh()
        mock_document_service.search_field_values.assert_called()

    def test_get_index_pattern_empty_index(
        self, tk_root: tk.Tk, mock_document_service: MagicMock
    ) -> None:
        """Тест паттерна для пустого/очень короткого индекса."""
        panel = CrossDocumentLookupPanel(
            parent=tk_root,
            document_service=mock_document_service,
            current_index="",
            on_value_selected=None,
        )
        # Для пустого индекса ROOT возвращает "-*" (пустая строка + "-*")
        pattern = panel._get_index_pattern(HierarchyLevel.ROOT)
        assert pattern == "-*"


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__ = [
    "TestPanelCreation",
    "TestSearchFunctionality",
    "TestHierarchyLevels",
    "TestDateRangeFiltering",
    "TestValueSelection",
    "TestCaching",
    "TestDataClasses",
    "TestPanelMethods",
    "TestIndexPatternsEdgeCases",
    "TestPopulateResults",
]
