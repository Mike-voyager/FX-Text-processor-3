"""Табличное поле с редактируемыми ячейками для STRUCTURED_FORM режима.

Предоставляет:
- TableField: tk.Frame с заголовками, editable rows (Entry) и кнопками +/-.

Features:
- Заголовки колонок (tk.Label)
- Редактируемые ячейки (tk.Entry)
- Кнопки "+" (добавить строку), "-" (удалить выделенную строку)
- on_change(field_id, table_data) при изменении любой ячейки
- Скроллинг через Canvas+Scrollbar для больших таблиц

Example:
    >>> table = TableField(
    ...     parent=frame,
    ...     field_id="items",
    ...     columns=["Наименование", "Кол-во", "Цена"],
    ...     rows=2,
    ...     on_change=on_changed,
    ... )
    >>> table.pack(fill=tk.BOTH, expand=True)

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Any, Callable, Optional

from src.gui.modes.structured_form.widgets.base_field import BaseField


class TableField(BaseField):
    """Табличное поле с редактируемыми ячейками.

    Attributes:
        columns: Список названий колонок.
        min_rows: Минимальное количество строк (default: 1).
        max_rows: Максимальное количество строк (default: 100).

    Example:
        >>> table = TableField(parent, field_id="t1", columns=["A", "B"])
        >>> table.pack(fill=tk.BOTH, expand=True)
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_id: str,
        columns: list[str],
        rows: int = 1,
        on_change: Optional[Callable[[str, Any], None]] = None,
        **kwargs: Any,
    ) -> None:
        """Инициализация табличного поля.

        Args:
            parent: Родительский Tkinter виджет.
            field_id: Идентификатор поля.
            columns: Список названий колонок.
            rows: Начальное количество строк.
            on_change: Callback при изменении значения.
            **kwargs: Дополнительные аргументы для tk.Frame.
        """
        label = kwargs.pop("label", "") if "label" in kwargs else ""
        super().__init__(
            parent=parent,
            field_id=field_id,
            label=label,
            on_change=on_change,
            **kwargs,
        )

        self.columns: list[str] = list(columns)
        self._num_cols: int = len(columns)
        self._min_rows: int = 1
        self._max_rows: int = 100
        self._entries: list[list[tk.Entry]] = []
        self._row_frames: list[tk.Frame] = []
        self._selected_row_index: int = -1
        self._canvas: Optional[tk.Canvas] = None
        self._scroll_frame: Optional[tk.Frame] = None

        self._create_content()
        for _ in range(max(rows, self._min_rows)):
            self._add_row()

    def _create_content(self) -> None:
        """Создаёт структуру таблицы: заголовки, скролл-область, кнопки."""
        # Тулбар с кнопками
        toolbar = tk.Frame(self)
        toolbar.pack(fill=tk.X, pady=(2, 2))

        self._btn_add = tk.Button(toolbar, text="+", width=3, command=self._on_add_row)
        self._btn_add.pack(side=tk.LEFT, padx=(0, 4))

        self._btn_remove = tk.Button(toolbar, text="-", width=3, command=self._on_remove_row)
        self._btn_remove.pack(side=tk.LEFT)

        self._row_label = tk.Label(toolbar, text="Rows: 0")
        self._row_label.pack(side=tk.LEFT, padx=(10, 0))

        # Скроллируемый контейнер
        scroll_container = tk.Frame(self, relief=tk.SUNKEN, bd=1)
        scroll_container.pack(fill=tk.BOTH, expand=True)

        self._canvas = tk.Canvas(scroll_container, highlightthickness=0)
        scrollbar = tk.Scrollbar(scroll_container, orient=tk.VERTICAL, command=self._canvas.yview)
        self._canvas.config(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self._canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._scroll_frame = tk.Frame(self._canvas)
        self._canvas_window = self._canvas.create_window(
            (0, 0), window=self._scroll_frame, anchor=tk.NW
        )

        # Обновление scrollregion
        self._scroll_frame.bind("<Configure>", self._on_frame_configure)
        self._canvas.bind("<Configure>", self._on_canvas_configure)

        # Заголовки колонок
        header_frame = tk.Frame(self._scroll_frame)
        header_frame.pack(fill=tk.X)

        self._header_labels: list[tk.Label] = []
        for col_text in self.columns:
            lbl = tk.Label(
                header_frame,
                text=col_text,
                font=("TkDefaultFont", 9, "bold"),
                relief=tk.RIDGE,
                bd=1,
                bg="#e0e0e0",
            )
            lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)
            self._header_labels.append(lbl)

        # Контейнер строк
        self._rows_container = tk.Frame(self._scroll_frame)
        self._rows_container.pack(fill=tk.BOTH, expand=True)

    def _on_frame_configure(self, event: tk.Event[Any]) -> None:
        """Обновляет scrollregion при изменении размеров фрейма.

        Args:
            event: Событие Tkinter.
        """
        _ = event
        if self._canvas is not None:
            self._canvas.config(scrollregion=self._canvas.bbox("all"))

    def _on_canvas_configure(self, event: tk.Event[Any]) -> None:
        """Обновляет ширину окна Canvas.

        Args:
            event: Событие Tkinter.
        """
        if self._canvas is not None:
            self._canvas.itemconfig(self._canvas_window, width=event.width)

    def _make_select_row_handler(self, row_index: int) -> Callable[[tk.Event[Any]], None]:
        """Создаёт обработчик для выбора строки.

        Args:
            row_index: Индекс строки.

        Returns:
            Функция-обработчик FocusIn.
        """

        def handler(event: tk.Event[Any]) -> None:
            _ = event
            self._select_row(row_index)

        return handler

    def _add_row(self, values: Optional[list[str]] = None) -> None:
        """Добавляет новую строку в таблицу.

        Args:
            values: Начальные значения ячеек (или None для пустых).
        """
        if len(self._row_frames) >= self._max_rows:
            return

        row_frame = tk.Frame(self._rows_container)
        row_frame.pack(fill=tk.X)

        row_entries: list[tk.Entry] = []
        row_idx = len(self._row_frames)
        for col_idx in range(self._num_cols):
            entry = tk.Entry(
                row_frame,
                font=("Courier", 10),
                relief=tk.SUNKEN,
                borderwidth=1,
            )
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
            if values is not None and col_idx < len(values):
                entry.insert(0, str(values[col_idx]))
            entry.bind("<KeyRelease>", self._on_cell_change)
            entry.bind("<FocusIn>", self._make_select_row_handler(row_idx))
            row_entries.append(entry)

        self._row_frames.append(row_frame)
        self._entries.append(row_entries)
        self._update_row_count()

    def _remove_row_by_index(self, index: int) -> None:
        """Удаляет строку по индексу.

        Args:
            index: Индекс строки.
        """
        if not (0 <= index < len(self._row_frames)):
            return
        if len(self._row_frames) <= self._min_rows:
            return

        frame = self._row_frames.pop(index)
        frame.destroy()
        self._entries.pop(index)

        # Обновляем привязки FocusIn
        for new_idx, entries in enumerate(self._entries):
            for entry in entries:
                entry.bind("<FocusIn>", self._make_select_row_handler(new_idx))

        self._selected_row_index = -1
        self._update_row_count()
        self._trigger_on_change()

    def _on_add_row(self) -> None:
        """Обработчик кнопки '+': добавляет строку."""
        if len(self._row_frames) >= self._max_rows:
            return
        self._add_row()
        self._trigger_on_change()

    def _on_remove_row(self) -> None:
        """Обработчик кнопки '-': удаляет выделенную или последнюю строку."""
        if len(self._row_frames) <= self._min_rows:
            return

        if 0 <= self._selected_row_index < len(self._row_frames):
            self._remove_row_by_index(self._selected_row_index)
        else:
            self._remove_row_by_index(len(self._row_frames) - 1)

    def _select_row(self, index: int) -> None:
        """Устанавливает выделенную строку.

        Args:
            index: Индекс строки.
        """
        self._selected_row_index = index

    def _on_cell_change(self, event: tk.Event[Any]) -> None:
        """Обработчик изменения ячейки.

        Args:
            event: Событие Tkinter.
        """
        _ = event
        self._trigger_on_change()

    def _trigger_on_change(self) -> None:
        """Вызывает on_change с текущими данными таблицы."""
        data = self.get_value()
        if self._on_change is not None:
            self._on_change(self.field_id, data)

    def _update_row_count(self) -> None:
        """Обновляет индикатор количества строк."""
        self._row_label.config(text=f"Rows: {len(self._row_frames)}")

    def get_value(self) -> list[list[str]]:
        """Возвращает данные таблицы как список строк.

        Returns:
            Список строк; каждая строка — список строковых значений ячеек.
        """
        data: list[list[str]] = []
        for row in self._entries:
            row_data = [entry.get() for entry in row]
            data.append(row_data)
        return data

    def set_value(self, value: Any) -> None:
        """Устанавливает данные таблицы.

        Args:
            value: Список строк (list[list[str]]) или None.
        """
        if value is None:
            value = []

        if not isinstance(value, list):
            value = []

        # Сохраняем то, что может быть вне диапазона
        data: list[list[str]] = []
        for row in value:
            if isinstance(row, list):
                data.append([str(cell) for cell in row])
            elif isinstance(row, dict):
                # Поддержка dict: берём значения в порядке колонок
                row_list: list[str] = []
                for col in self.columns:
                    row_list.append(str(row.get(col, "")))
                data.append(row_list)
            else:
                data.append([str(row)])

        # Очищаем текущие строки
        for frame in self._row_frames:
            frame.destroy()
        self._row_frames.clear()
        self._entries.clear()

        # Добавляем новые строки
        for row_data in data:
            self._add_row(row_data)

        # Гарантируем минимум строк
        while len(self._row_frames) < self._min_rows:
            self._add_row()

        self._update_row_count()

        if self._on_change is not None:
            self._on_change(self.field_id, self.get_value())

    def validate(self) -> bool:
        """Валидирует таблицу.

        Returns:
            True если количество строк в пределах min/max.
        """
        row_count = len(self._row_frames)
        if row_count < self._min_rows:
            self.set_error(f"Минимум {self._min_rows} строк")
            return False
        if row_count > self._max_rows:
            self.set_error(f"Максимум {self._max_rows} строк")
            return False

        self.set_error(None)
        return True

    def focus(self) -> None:
        """Устанавливает фокус на первую ячейку таблицы."""
        if self._entries and self._entries[0]:
            self._entries[0][0].focus_set()

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные таблицы."""
        for row in self._entries:
            for entry in row:
                entry.delete(0, tk.END)
        self._value = []


__all__: list[str] = ["TableField"]
