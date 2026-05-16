"""Панель поиска значений полей по документам в иерархии индекса.

Предоставляет интерфейс для поиска значений полей из предыдущих документов
в той же иерархии индекса. Поддерживает фильтрацию по уровням иерархии:
- Точный индекс
- Одна серия
- Один подтип
- Один корень

Example:
    >>> from src.gui.panels.cross_document_lookup import CrossDocumentLookupPanel
    >>> panel = CrossDocumentLookupPanel(
    ...     parent=parent_frame,
    ...     document_service=doc_service,
    ...     current_index="DVN-44-K53-X",
    ...     on_value_selected=lambda fid, val: print(f"Selected {fid}={val}")
    ... )
    >>> panel.mount(parent_frame)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from tkinter import ttk
from typing import Any, Callable, Dict, Final, List, Optional, Protocol, Tuple

from src.documents.types.index_formatter import parse_index
from src.gui.components.base.widget import BaseWidget
from src.gui.core.protocols import ControllerProtocol

logger: Final = logging.getLogger(__name__)


# =============================================================================
# CONSTANTS
# =============================================================================

CACHE_SIZE_LIMIT: Final[int] = 100
"""Максимальное количество записей в кеше результатов."""

CACHE_TTL_SECONDS: Final[int] = 300
"""Время жизни записи в кеше (5 минут)."""

MAX_RESULTS: Final[int] = 1000
"""Максимальное количество результатов поиска."""


# =============================================================================
# ENUMS AND DATA CLASSES
# =============================================================================


class HierarchyLevel(Enum):
    """Уровни иерархии индекса для поиска.

    - EXACT: Точное совпадение полного индекса
    - SERIES: Документы той же серии (DVN-44-K53-*)
    - SUBTYPE: Документы того же подтипа (DVN-44-*)
    - ROOT: Документы того же корневого типа (DVN-*)
    """

    EXACT = auto()
    SERIES = auto()
    SUBTYPE = auto()
    ROOT = auto()

    def get_label(self) -> str:
        """Возвращает локализованную метку для уровня иерархии."""
        labels = {
            HierarchyLevel.EXACT: "Точный индекс",
            HierarchyLevel.SERIES: "Серия",
            HierarchyLevel.SUBTYPE: "Подтип",
            HierarchyLevel.ROOT: "Корень",
        }
        return labels.get(self, str(self))


@dataclass(frozen=True)
class FieldValueResult:
    """Результат поиска значения поля.

    Attrs:
        document_id: Уникальный идентификатор документа.
        document_index: Полный индекс документа.
        field_id: Идентификатор поля.
        value: Значение поля.
        created_at: Дата создания документа.
        modified_at: Дата последнего изменения.
    """

    document_id: str
    document_index: str
    field_id: str
    value: str
    created_at: datetime
    modified_at: datetime

    def to_treeview_values(self) -> Tuple[str, str, str]:
        """Возвращает значения для отображения в Treeview.

        Returns:
            Кортеж (индекс, значение, дата) для отображения.
        """
        date_str = self.modified_at.strftime("%d.%m.%Y %H:%M")
        # Ограничиваем длину значения для отображения
        display_value = self.value[:50] + "..." if len(self.value) > 50 else self.value
        return (self.document_index, display_value, date_str)


@dataclass
class CacheEntry:
    """Запись в кеше результатов.

    Attrs:
        results: Список результатов.
        timestamp: Время создания записи.
        query_hash: Хеш запроса для инвалидации.
    """

    results: List[FieldValueResult]
    timestamp: datetime = field(default_factory=datetime.now)
    query_hash: str = ""


@dataclass(frozen=True)
class SearchCriteria:
    """Критерии поиска для кеширования.

    Attrs:
        field_id: Идентификатор поля.
        hierarchy_level: Уровень иерархии.
        current_index: Текущий индекс документа.
        date_from: Начальная дата диапазона (опционально).
        date_to: Конечная дата диапазона (опционально).
    """

    field_id: str
    hierarchy_level: HierarchyLevel
    current_index: str
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None

    def to_cache_key(self) -> str:
        """Генерирует ключ кеша из критериев.

        Returns:
            Строка-ключ для использования в кеше.
        """
        date_from_str = self.date_from.isoformat() if self.date_from else ""
        date_to_str = self.date_to.isoformat() if self.date_to else ""
        return (
            f"{self.field_id}:{self.hierarchy_level.name}:"
            f"{self.current_index}:{date_from_str}:{date_to_str}"
        )


# =============================================================================
# PROTOCOLS
# =============================================================================


class DocumentServiceProtocol(Protocol):
    """Протокол сервиса документов для поиска.

    Определяет интерфейс для получения данных из истории документов.
    """

    def search_field_values(
        self,
        field_id: str,
        index_pattern: str,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[FieldValueResult]:
        """Ищет значения полей по шаблону индекса.

        Args:
            field_id: Идентификатор поля для поиска.
            index_pattern: Шаблон индекса (с поддержкой wildcard *).
            date_from: Начальная дата диапазона (опционально).
            date_to: Конечная дата диапазона (опционально).
            limit: Максимальное количество результатов.

        Returns:
            Список результатов поиска.
        """
        ...

    def get_document_history(
        self,
        index_prefix: str,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Возвращает историю документов по префиксу индекса.

        Args:
            index_prefix: Префикс индекса для фильтрации.
            limit: Максимальное количество документов.

        Returns:
            Список документов с метаданными.
        """
        ...


class ValueSelectedCallback(Protocol):
    """Протокол callback функции при выборе значения."""

    def __call__(self, field_id: str, value: str) -> None:
        """Вызывается при выборе значения из результатов.

        Args:
            field_id: Идентификатор поля.
            value: Выбранное значение.
        """
        ...


# =============================================================================
# CROSS DOCUMENT LOOKUP PANEL
# =============================================================================


class CrossDocumentLookupPanel(BaseWidget):
    """Панель поиска значений полей в иерархии документов.

    Предоставляет UI для поиска значений полей из предыдущих документов
    с фильтрацией по уровням иерархии индекса и кешированием результатов.

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        _current_index: Текущий индекс документа.
        _document_service: Сервис для доступа к документам.
        _on_value_selected: Callback при выборе значения.
        _cache: Кеш результатов поиска.

    Example:
        >>> panel = CrossDocumentLookupPanel(
        ...     parent=root,
        ...     document_service=doc_service,
        ...     current_index="DVN-44-K53-X",
        ...     on_value_selected=on_select
        ... )
        >>> panel.mount(parent_frame)
    """

    def __init__(
        self,
        parent: tk.Widget,
        document_service: DocumentServiceProtocol,
        current_index: str,
        on_value_selected: Optional[ValueSelectedCallback] = None,
        controller: Optional[ControllerProtocol] = None,
    ) -> None:
        """Инициализация панели поиска.

        Args:
            parent: Родительский виджет.
            document_service: Сервис для доступа к документам.
            current_index: Текущий индекс документа (например "DVN-44-K53-X").
            on_value_selected: Callback при выборе значения.
            controller: Опциональный контроллер для dispatch.
        """
        super().__init__(widget_id="cross_document_lookup", controller=controller)

        self._parent = parent
        self._document_service = document_service
        self._current_index = current_index
        self._on_value_selected = on_value_selected

        # Парсим текущий индекс для извлечения компонентов
        self._index_segments = parse_index(current_index)

        # Кеш результатов
        self._cache: Dict[str, CacheEntry] = {}

        # Текущее состояние
        self._current_results: List[FieldValueResult] = []
        self._selected_result: Optional[FieldValueResult] = None

        # UI компоненты (инициализируются в _create_tk_widget)
        self._search_var: tk.StringVar = tk.StringVar(master=self._tk_widget)
        self._hierarchy_var: tk.StringVar = tk.StringVar(value=HierarchyLevel.SERIES.name)
        self._date_from_var: tk.StringVar = tk.StringVar(master=self._tk_widget)
        self._date_to_var: tk.StringVar = tk.StringVar(master=self._tk_widget)
        self._status_var: tk.StringVar = tk.StringVar(value="Готов к поиску")

        self._tk_widget: Optional[tk.Widget] = None
        self._results_tree: Optional[ttk.Treeview] = None
        self._use_button: Optional[tk.Button] = None
        self._search_button: Optional[tk.Button] = None

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Tkinter виджет панели.

        Args:
            parent: Родительский виджет.

        Returns:
            Корневой Frame панели.
        """
        main_frame = tk.Frame(parent, bg="#f5f5f5")
        main_frame.rowconfigure(1, weight=1)  # Results area expands
        main_frame.columnconfigure(0, weight=1)

        # Создаём секции UI
        self._create_search_section(main_frame)
        self._create_results_section(main_frame)
        self._create_status_section(main_frame)

        return main_frame

    def _create_search_section(self, parent: tk.Frame) -> None:
        """Создаёт секцию поиска.

        Args:
            parent: Родительский Frame.
        """
        search_frame = tk.LabelFrame(
            parent,
            text="Cross-document search",
            bg="#f5f5f5",
            font=("Segoe UI", 10, "bold"),
        )
        search_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        search_frame.columnconfigure(1, weight=1)

        # Поле ввода field_id
        tk.Label(
            search_frame,
            text="Field:",
            bg="#f5f5f5",
            font=("Segoe UI", 9),
        ).grid(row=0, column=0, sticky="w", padx=5, pady=5)

        field_entry = tk.Entry(
            search_frame,
            textvariable=self._search_var,
            font=("Segoe UI", 9),
            width=30,
        )
        field_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        field_entry.bind("<Return>", lambda e: self._perform_search())

        # Селектор уровня иерархии
        tk.Label(
            search_frame,
            text="Level:",
            bg="#f5f5f5",
            font=("Segoe UI", 9),
        ).grid(row=1, column=0, sticky="nw", padx=5, pady=5)

        hierarchy_frame = tk.Frame(search_frame, bg="#f5f5f5")
        hierarchy_frame.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

        levels = [
            (HierarchyLevel.EXACT, "Exact index"),
            (HierarchyLevel.SERIES, "Series (K53)"),
            (HierarchyLevel.SUBTYPE, "Subtype (44)"),
            (HierarchyLevel.ROOT, "Root (DVN)"),
        ]

        for _i, (level, label) in enumerate(levels):
            rb = tk.Radiobutton(
                hierarchy_frame,
                text=label,
                variable=self._hierarchy_var,
                value=level.name,
                bg="#f5f5f5",
                font=("Segoe UI", 9),
            )
            rb.pack(side=tk.LEFT, padx=5)

            # Устанавливаем подсказку в зависимости от доступности
            if level == HierarchyLevel.EXACT and len(self._index_segments) < 4:
                rb.config(state=tk.DISABLED)

        # Диапазон дат (опционально)
        date_frame = tk.Frame(search_frame, bg="#f5f5f5")
        date_frame.grid(row=2, column=0, columnspan=2, sticky="ew", padx=5, pady=5)

        tk.Label(
            date_frame,
            text="From:",
            bg="#f5f5f5",
            font=("Segoe UI", 9),
        ).pack(side=tk.LEFT, padx=5)

        date_from_entry = tk.Entry(
            date_frame,
            textvariable=self._date_from_var,
            font=("Segoe UI", 9),
            width=12,
        )
        date_from_entry.pack(side=tk.LEFT, padx=5)
        date_from_entry.insert(0, "")

        tk.Label(
            date_frame,
            text="To:",
            bg="#f5f5f5",
            font=("Segoe UI", 9),
        ).pack(side=tk.LEFT, padx=5)

        date_to_entry = tk.Entry(
            date_frame,
            textvariable=self._date_to_var,
            font=("Segoe UI", 9),
            width=12,
        )
        date_to_entry.pack(side=tk.LEFT, padx=5)
        date_to_entry.insert(0, "")

        # Кнопка поиска
        self._search_button = tk.Button(
            search_frame,
            text="🔍 Search",
            command=self._perform_search,
            bg="#4a90d9",
            fg="white",
            font=("Segoe UI", 9, "bold"),
            cursor="hand2",
        )
        self._search_button.grid(row=3, column=0, columnspan=2, pady=10)

    def _create_results_section(self, parent: tk.Frame) -> None:
        """Создаёт секцию результатов.

        Args:
            parent: Родительский Frame.
        """
        results_frame = tk.LabelFrame(
            parent,
            text="Results",
            bg="#f5f5f5",
            font=("Segoe UI", 10, "bold"),
        )
        results_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        results_frame.rowconfigure(0, weight=1)
        results_frame.columnconfigure(0, weight=1)

        # Treeview для результатов
        columns = ("index", "value", "date")
        self._results_tree = ttk.Treeview(
            results_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        # Настройка колонок
        self._results_tree.heading("index", text="Document index")
        self._results_tree.heading("value", text="Value")
        self._results_tree.heading("date", text="Date")

        self._results_tree.column("index", width=150, minwidth=100)
        self._results_tree.column("value", width=300, minwidth=150)
        self._results_tree.column("date", width=120, minwidth=80)

        # Скроллбары
        vsb = ttk.Scrollbar(results_frame, orient="vertical", command=self._results_tree.yview)
        hsb = ttk.Scrollbar(results_frame, orient="horizontal", command=self._results_tree.xview)
        self._results_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # Размещение
        self._results_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        # Обработчик выбора
        self._results_tree.bind("<<TreeviewSelect>>", self._on_result_selected)
        self._results_tree.bind("<Double-1>", lambda e: self._use_selected_value())

    def _create_status_section(self, parent: tk.Frame) -> None:
        """Создаёт секцию статуса и кнопок действий.

        Args:
            parent: Родительский Frame.
        """
        status_frame = tk.Frame(parent, bg="#f5f5f5", height=40)
        status_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=10)
        status_frame.grid_propagate(False)

        # Статусная строка
        status_label = tk.Label(
            status_frame,
            textvariable=self._status_var,
            bg="#f5f5f5",
            font=("Segoe UI", 9),
            fg="#666666",
        )
        status_label.pack(side=tk.LEFT, padx=5)

        # Кнопка "Использовать"
        self._use_button = tk.Button(
            status_frame,
            text="📋 Use",
            command=self._use_selected_value,
            state=tk.DISABLED,
            bg="#4caf50",
            fg="white",
            font=("Segoe UI", 9, "bold"),
            cursor="hand2",
        )
        self._use_button.pack(side=tk.RIGHT, padx=5)

    def _setup_bindings(self) -> None:
        """Настраивает keyboard bindings."""
        if self._tk_widget is not None:
            self._tk_widget.bind("<Control-f>", lambda _e: self._focus_search())
            self._tk_widget.bind("<Escape>", lambda _e: self._clear_selection())

    def _focus_search(self) -> None:
        """Устанавливает фокус на поле поиска."""
        if self._tk_widget is None:
            return
        for widget in self._tk_widget.winfo_children():
            if isinstance(widget, tk.LabelFrame):
                for child in widget.winfo_children():
                    if isinstance(child, tk.Entry):
                        tv = child.cget("textvariable")
                        if tv == str(self._search_var):
                            child.focus_set()
                            child.select_range(0, tk.END)
                            return

    def _clear_selection(self) -> None:
        """Очищает выбор в таблице результатов."""
        if self._results_tree is not None:
            for item in self._results_tree.selection():
                self._results_tree.selection_remove(item)
        self._selected_result = None
        self._update_use_button_state()

    def _get_index_pattern(self, hierarchy_level: HierarchyLevel) -> str:
        """Генерирует шаблон индекса для поиска.

        Args:
            hierarchy_level: Уровень иерархии.

        Returns:
            Шаблон индекса с wildcard.
        """
        segments: list[str] = self._index_segments

        if hierarchy_level == HierarchyLevel.EXACT:
            return self._current_index
        elif hierarchy_level == HierarchyLevel.SERIES:
            # DVN-44-K53-*
            if len(segments) >= 3:
                return "-".join(segments[:3]) + "-*"
            return self._current_index + "-*"
        elif hierarchy_level == HierarchyLevel.SUBTYPE:
            # DVN-44-*
            if len(segments) >= 2:
                return "-".join(segments[:2]) + "-*"
            return self._current_index + "-*"
        elif hierarchy_level == HierarchyLevel.ROOT:
            # DVN-*
            if len(segments) >= 1:
                return segments[0] + "-*"
            return "*"

        return "*"

    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Парсит строку даты.

        Args:
            date_str: Строка даты в формате DD.MM.YYYY.

        Returns:
            datetime объект или None если не удалось распарсить.
        """
        if not date_str.strip():
            return None

        formats = ["%d.%m.%Y", "%Y-%m-%d", "%d.%m.%Y %H:%M"]
        for fmt in formats:
            try:
                return datetime.strptime(date_str.strip(), fmt)
            except ValueError:
                continue
        return None

    def _perform_search(self) -> None:
        """Выполняет поиск с учётом кеширования."""
        field_id = self._search_var.get().strip()
        if not field_id:
            self._status_var.set("Введите идентификатор поля")
            return

        hierarchy_level = HierarchyLevel[self._hierarchy_var.get()]
        index_pattern = self._get_index_pattern(hierarchy_level)

        date_from = self._parse_date(self._date_from_var.get())
        date_to = self._parse_date(self._date_to_var.get())

        # Проверяем кеш
        criteria = SearchCriteria(
            field_id=field_id,
            hierarchy_level=hierarchy_level,
            current_index=self._current_index,
            date_from=date_from,
            date_to=date_to,
        )
        cache_key = criteria.to_cache_key()

        cached_entry = self._get_from_cache(cache_key)
        if cached_entry is not None:
            self._current_results = cached_entry.results
            self._populate_results()
            self._status_var.set(f"Результатов из кеша: {len(self._current_results)}")
            logger.debug("Использован кеш для запроса: %s", cache_key)
            return

        # Выполняем поиск через сервис
        try:
            self._status_var.set("Поиск...")
            self._tk_widget.update_idletasks()  # type: ignore[union-attr]

            results = self._document_service.search_field_values(
                field_id=field_id,
                index_pattern=index_pattern,
                date_from=date_from,
                date_to=date_to,
                limit=MAX_RESULTS,
            )

            self._current_results = results
            self._populate_results()

            # Сохраняем в кеш
            self._add_to_cache(cache_key, results)

            self._status_var.set(f"Найдено результатов: {len(results)}")
            logger.debug(
                "Поиск выполнен: field=%s, pattern=%s, results=%d",
                field_id,
                index_pattern,
                len(results),
            )

        except Exception as exc:
            logger.error("Ошибка поиска: %s", exc)
            self._status_var.set(f"Ошибка поиска: {exc}")

    def _populate_results(self) -> None:
        """Заполняет таблицу результатов."""
        if self._results_tree is None:
            return

        # Очищаем текущие результаты
        for item in self._results_tree.get_children():
            self._results_tree.delete(item)

        # Добавляем новые результаты
        for result in self._current_results:
            self._results_tree.insert(
                "",
                tk.END,
                values=result.to_treeview_values(),
                tags=(result.document_id,),
            )

    def _on_result_selected(self, event: tk.Event) -> None:
        """Обработчик выбора результата.

        Args:
            event: Событие выбора.
        """
        if self._results_tree is None:
            return

        selection = self._results_tree.selection()
        if not selection:
            self._selected_result = None
            self._update_use_button_state()
            return

        # Получаем индекс выбранного элемента
        item = selection[0]
        idx = self._results_tree.index(item)

        if 0 <= idx < len(self._current_results):
            self._selected_result = self._current_results[idx]
            self._update_use_button_state()

    def _update_use_button_state(self) -> None:
        """Обновляет состояние кнопки "Использовать"."""
        if self._use_button is not None:
            if self._selected_result is not None:
                self._use_button.config(state=tk.NORMAL)
            else:
                self._use_button.config(state=tk.DISABLED)

    def _use_selected_value(self) -> None:
        """Использует выбранное значение."""
        if self._selected_result is None:
            return

        if self._on_value_selected is not None:
            try:
                self._on_value_selected(
                    self._selected_result.field_id,
                    self._selected_result.value,
                )
                self._status_var.set(f"Выбрано: {self._selected_result.value[:30]}...")
                logger.debug(
                    "Выбрано значение: field=%s, doc=%s",
                    self._selected_result.field_id,
                    self._selected_result.document_index,
                )
            except Exception as exc:
                logger.error("Ошибка при использовании значения: %s", exc)
                self._status_var.set(f"Ошибка: {exc}")

    def _get_from_cache(self, cache_key: str) -> Optional[CacheEntry]:
        """Получает запись из кеша с проверкой TTL.

        Args:
            cache_key: Ключ кеша.

        Returns:
            Запись кеша или None если не найдена или устарела.
        """
        entry = self._cache.get(cache_key)
        if entry is None:
            return None

        # Проверяем TTL
        age = (datetime.now() - entry.timestamp).total_seconds()
        if age > CACHE_TTL_SECONDS:
            del self._cache[cache_key]
            return None

        return entry

    def _add_to_cache(self, cache_key: str, results: List[FieldValueResult]) -> None:
        """Добавляет запись в кеш с ограничением размера.

        Args:
            cache_key: Ключ кеша.
            results: Результаты для кеширования.
        """
        # Ограничиваем размер кеша
        if len(self._cache) >= CACHE_SIZE_LIMIT:
            # Удаляем самую старую запись
            oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k].timestamp)
            del self._cache[oldest_key]

        self._cache[cache_key] = CacheEntry(
            results=results,
            timestamp=datetime.now(),
            query_hash=cache_key,
        )

    def clear_cache(self) -> int:
        """Очищает кеш результатов.

        Returns:
            Количество удалённых записей.
        """
        count = len(self._cache)
        self._cache.clear()
        logger.debug("Кеш очищен: %d записей", count)
        return count

    def get_cache_stats(self) -> Dict[str, Any]:
        """Возвращает статистику кеша.

        Returns:
            Словарь с информацией о кеше.
        """
        if not self._cache:
            return {"entries": 0, "oldest": None, "newest": None}

        timestamps = [entry.timestamp for entry in self._cache.values()]
        return {
            "entries": len(self._cache),
            "oldest": min(timestamps),
            "newest": max(timestamps),
        }

    def set_field_id(self, field_id: str) -> None:
        """Устанавливает идентификатор поля для поиска.

        Args:
            field_id: Идентификатор поля.
        """
        self._search_var.set(field_id)

    def refresh(self) -> None:
        """Обновляет результаты поиска."""
        self._perform_search()

    def _cleanup(self) -> None:
        """Очищает ресурсы при демонтировании."""
        self._cache.clear()
        self._current_results.clear()
        self._selected_result = None
        logger.debug("CrossDocumentLookupPanel cleanup completed")

    def search(
        self,
        field_id: str,
        document_index_pattern: str,
    ) -> list[tuple[str, str]]:
        """Публичный API для поиска значений поля по шаблону индекса.

        Args:
            field_id: Идентификатор поля для поиска.
            document_index_pattern: Шаблон индекса (с поддержкой wildcard *).

        Returns:
            Список кортежей (document_index, value).
        """
        try:
            results = self._document_service.search_field_values(
                field_id=field_id,
                index_pattern=document_index_pattern,
                limit=MAX_RESULTS,
            )
            return [(r.document_index, r.value) for r in results]
        except Exception as exc:
            logger.error("Ошибка поиска: %s", exc)
            return []

    def handle_event(self, event: Any) -> bool:
        """Обрабатывает события.

        Args:
            event: Событие для обработки.

        Returns:
            True если событие обработано.
        """
        # Панель не обрабатывает специфичные события
        return False


# =============================================================================
# CROSS DOCUMENT LOOKUP DIALOG (modal popup)
# =============================================================================


class CrossDocumentLookupDialog(tk.Toplevel):
    """Модальный диалог cross-document lookup.

    Предоставляет компактный popup для поиска значений поля по документам
    с фильтрацией по шаблону индекса. Подходит для вызова из полей
    ввода (например AutocompleteEntry по Ctrl+Space).

    Attributes:
        _document_service: Сервис документов для поиска.
        _field_id: Идентификатор поля.
        _document_index: Текущий индекс документа.
        _on_select: Callback при выборе значения.
        _pattern_var: Шаблон индекса для поиска.
        _tree: Treeview с результатами.

    Example:
        >>> dialog = CrossDocumentLookupDialog(
        ...     parent=entry,
        ...     document_service=doc_service,
        ...     field_id="recipient_name",
        ...     document_index="DVN-44-K53-IX",
        ...     on_select=lambda val: entry.set_value(val),
        ... )
    """

    def __init__(
        self,
        parent: tk.Widget,
        document_service: DocumentServiceProtocol,
        field_id: str,
        document_index: str,
        on_select: Callable[[str], None],
    ) -> None:
        """Инициализация модального диалога lookup.

        Args:
            parent: Родительский виджет (обычно поле ввода).
            document_service: Сервис документов для поиска.
            field_id: Идентификатор поля.
            document_index: Полный индекс документа.
            on_select: Callback при выборе значения (принимает value).
        """
        super().__init__(parent)
        self.title(f"Cross-Document Lookup: {field_id}")
        self.transient(parent.winfo_toplevel())
        try:
            self.grab_set()
        except tk.TclError:
            pass

        self._document_service: DocumentServiceProtocol = document_service
        self._field_id: str = field_id
        self._document_index: str = document_index
        self._on_select: Callable[[str], None] = on_select

        self._pattern_var: tk.StringVar = tk.StringVar(value=self._default_pattern(document_index))
        self._status_var: tk.StringVar = tk.StringVar(value="")

        self._tree: Optional[ttk.Treeview] = None
        self._results: List[FieldValueResult] = []
        self._after_ids: list[str] = []

        self._create_ui()
        self._setup_bindings()

        # Автопоиск при открытии
        self._after_ids.append(self.after(50, self._perform_search))
        self.bind("<Destroy>", lambda _e: self._cancel_afters(), add=True)

    def _cancel_afters(self) -> None:
        """Отменяет все зарегистрированные after() таймеры."""
        for after_id in self._after_ids:
            try:
                self.after_cancel(after_id)
            except tk.TclError:
                pass
        self._after_ids.clear()

    def destroy(self) -> None:
        """Уничтожает окно с отменой таймеров."""
        self._cancel_afters()
        try:
            super().destroy()
        except tk.TclError:
            pass

    def _default_pattern(self, document_index: str) -> str:
        """Генерирует шаблон по умолчанию по уровню серии.

        Args:
            document_index: Полный индекс документа.

        Returns:
            Шаблон индекса с wildcard.

        Example:
            >>> self._default_pattern("DVN-44-K53-IX")
            'DVN-44-K53-*'
        """
        parts = document_index.split("-")
        if len(parts) >= 2:
            return "-".join(parts[:-1]) + "-*"
        return document_index + "-*"

    def _create_ui(self) -> None:
        """Создаёт UI диалога."""
        self.geometry("600x400")
        self.rowconfigure(1, weight=1)
        self.columnconfigure(0, weight=1)

        # Верхняя панель: pattern + refresh
        top_frame = tk.Frame(self, padx=10, pady=10)
        top_frame.grid(row=0, column=0, sticky="ew")
        top_frame.columnconfigure(1, weight=1)

        tk.Label(
            top_frame,
            text="Pattern:",
            font=("Segoe UI", 9),
        ).grid(row=0, column=0, sticky="w", padx=(0, 5))

        pattern_entry = tk.Entry(
            top_frame,
            textvariable=self._pattern_var,
            font=("Segoe UI", 9),
        )
        pattern_entry.grid(row=0, column=1, sticky="ew", padx=(0, 5))
        pattern_entry.bind("<Return>", lambda _e: self._perform_search())

        refresh_btn = tk.Button(
            top_frame,
            text="🔄 Refresh",
            command=self._perform_search,
            font=("Segoe UI", 9),
            cursor="hand2",
        )
        refresh_btn.grid(row=0, column=2, sticky="e")

        # Результаты: Treeview Document | Value
        results_frame = tk.LabelFrame(
            self,
            text="Results",
            font=("Segoe UI", 10, "bold"),
            padx=5,
            pady=5,
        )
        results_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        results_frame.rowconfigure(0, weight=1)
        results_frame.columnconfigure(0, weight=1)

        columns = ("document", "value")
        self._tree = ttk.Treeview(
            results_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )
        self._tree.heading("document", text="Document")
        self._tree.heading("value", text="Value")
        self._tree.column("document", width=180, minwidth=100)
        self._tree.column("value", width=380, minwidth=150)

        vsb = ttk.Scrollbar(results_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        self._tree.bind("<Double-1>", lambda _e: self._use_selected())

        # Статусная строка
        status_label = tk.Label(
            self,
            textvariable=self._status_var,
            font=("Segoe UI", 9),
            fg="#666666",
            anchor=tk.W,
        )
        status_label.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 5))

        # Нижняя панель кнопок
        btn_frame = tk.Frame(self, padx=10, pady=10)
        btn_frame.grid(row=3, column=0, sticky="ew")

        use_btn = tk.Button(
            btn_frame,
            text="📋 Use Selected",
            command=self._use_selected,
            font=("Segoe UI", 9, "bold"),
            bg="#4caf50",
            fg="white",
            cursor="hand2",
        )
        use_btn.pack(side=tk.LEFT, padx=(0, 5))

        cancel_btn = tk.Button(
            btn_frame,
            text="❌ Cancel",
            command=self.destroy,
            font=("Segoe UI", 9),
            cursor="hand2",
        )
        cancel_btn.pack(side=tk.RIGHT)

    def _setup_bindings(self) -> None:
        """Настраивает keyboard bindings для диалога."""
        self.bind("<Escape>", lambda _e: self.destroy())

    def _perform_search(self) -> None:
        """Выполняет поиск и заполняет Treeview."""
        pattern = self._pattern_var.get().strip()
        if not pattern:
            self._status_var.set("Введите шаблон индекса")
            return

        try:
            self._status_var.set("Поиск...")
            self.update_idletasks()

            results = self._document_service.search_field_values(
                field_id=self._field_id,
                index_pattern=pattern,
                limit=MAX_RESULTS,
            )
            self._results = results
            self._populate_tree()
            self._status_var.set(f"Найдено: {len(results)}")
            logger.debug(
                "Lookup dialog search: field=%s pattern=%s results=%d",
                self._field_id,
                pattern,
                len(results),
            )
        except Exception as exc:
            logger.error("Ошибка lookup: %s", exc)
            self._status_var.set(f"Ошибка: {exc}")

    def _populate_tree(self) -> None:
        """Заполняет Treeview результатами поиска."""
        if self._tree is None:
            return
        for item in self._tree.get_children():
            self._tree.delete(item)
        for result in self._results:
            display_value = result.value[:50] + "..." if len(result.value) > 50 else result.value
            self._tree.insert(
                "",
                tk.END,
                values=(result.document_index, display_value),
                tags=(result.document_id,),
            )

    def _use_selected(self) -> None:
        """Использует выбранное значение и закрывает диалог."""
        if self._tree is None:
            return
        selection = self._tree.selection()
        if not selection:
            self._status_var.set("Выберите значение")
            return

        item = self._tree.item(selection[0])
        values = item.get("values", [])
        if len(values) >= 2:
            selected_value = str(values[1])
            self._on_select(selected_value)
            self.destroy()
        else:
            self._status_var.set("Ошибка выбора")


def show_lookup_dialog(
    parent: tk.Widget,
    document_service: DocumentServiceProtocol,
    field_id: str,
    document_index: str,
    on_select: Callable[[str], None],
) -> CrossDocumentLookupDialog:
    """Показывает модальный диалог Cross-Document Lookup.

    Args:
        parent: Родительский виджет.
        document_service: Сервис документов для поиска.
        field_id: Идентификатор поля.
        document_index: Полный индекс документа.
        on_select: Callback при выборе значения.

    Returns:
        Созданный диалог (уже отображён и модален).
    """
    dialog = CrossDocumentLookupDialog(
        parent=parent,
        document_service=document_service,
        field_id=field_id,
        document_index=document_index,
        on_select=on_select,
    )
    return dialog


__all__ = [
    "CrossDocumentLookupPanel",
    "CrossDocumentLookupDialog",
    "DocumentServiceProtocol",
    "FieldValueResult",
    "HierarchyLevel",
    "SearchCriteria",
    "CacheEntry",
    "ValueSelectedCallback",
    "show_lookup_dialog",
]
