"""Виджет табличного поля (mini Excel).

Предоставляет:
- TableWidget: табличное поле с редактируемыми ячейками
- TableEditorDialog: модальный редактор таблицы
- TableData: данные таблицы

Example:
    >>> widget = TableWidget(
    ...     parent=frame,
    ...     field_def=field_def,
    ...     on_change=on_field_change
    ... )
    >>> widget.set_value([{"col1": "value1", "col2": 123}])
"""

from __future__ import annotations

import tkinter as tk
from copy import deepcopy
from dataclasses import dataclass, field
from decimal import Decimal
from tkinter import messagebox, simpledialog, ttk
from typing import Any, Callable, Optional, Union

from src.documents.constructor.table_schema import (
    SummaryFunction,
    TableSchema,
)
from src.documents.types.type_schema import FieldDefinition
from src.gui.modes.structured_form.widgets.base_field_widget import BaseFieldWidget


@dataclass
class TableData:
    """Данные таблицы.

    Attributes:
        rows: Список строк (каждая строка - словарь {column_id: value}).
        summary_row: Итоговая строка (для отображения).
    """

    rows: list[dict[str, Any]] = field(default_factory=list)
    summary_row: Optional[dict[str, Any]] = None

    def to_list(self) -> list[dict[str, Any]]:
        """Возвращает данные как список словарей."""
        return deepcopy(self.rows)

    def add_row(self, row_data: dict[str, Any]) -> None:
        """Добавляет строку в таблицу."""
        self.rows.append(deepcopy(row_data))

    def remove_row(self, index: int) -> None:
        """Удаляет строку по индексу."""
        if 0 <= index < len(self.rows):
            del self.rows[index]

    def update_cell(self, row_index: int, column_id: str, value: Any) -> None:
        """Обновляет значение ячейки."""
        if 0 <= row_index < len(self.rows):
            self.rows[row_index][column_id] = value

    def get_cell(self, row_index: int, column_id: str) -> Any:
        """Возвращает значение ячейки."""
        if 0 <= row_index < len(self.rows):
            return self.rows[row_index].get(column_id)
        return None


class TableWidget(BaseFieldWidget):
    """Табличное поле (mini Excel).

    Attributes:
        _treeview: Tkinter Treeview widget для отображения таблицы.
        _data: Данные таблицы.
        _table_schema: Схема таблицы из field_def.
        _edit_button: Кнопка открытия редактора.

    Example:
        >>> widget = TableWidget(parent, field_def)
        >>> widget.set_value([{"item": "Product", "qty": 5, "price": 100.50}])
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_def: FieldDefinition,
        on_change: Optional[Callable[[str, Any], None]] = None,
        on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = None,
    ) -> None:
        """Инициализация табличного поля.

        Args:
            parent: Родительский Tkinter виджет.
            field_def: Определение поля из схемы.
            on_change: Callback при изменении значения.
            on_validate: Callback при валидации.
        """
        super().__init__(parent, field_def, on_change, on_validate)
        self._table_schema: Optional[TableSchema] = field_def.table_schema
        self._data: TableData = TableData()
        self._treeview: Optional[ttk.Treeview] = None
        self._scrollbar: Optional[tk.Scrollbar] = None
        self._edit_button: Optional[tk.Button] = None
        self._cached_rows: Optional[list[dict[str, Any]]] = None

    def _create_widget(self) -> tk.Widget:
        """Создаёт виджет табличного поля.

        Returns:
            Frame с Treeview и кнопкой редактирования.
        """
        frame = tk.Frame(self._main_frame)

        if self._table_schema is None:
            # No schema - show placeholder
            tk.Label(
                frame,
                text="(No table schema)",
                fg="gray",
            ).pack(pady=20)
            return frame

        # Create frame for treeview + scrollbar
        tree_frame = tk.Frame(frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        # Prepare columns
        columns = [col.column_id for col in self._table_schema.columns]
        headers = [col.header for col in self._table_schema.columns]

        # Create treeview
        self._treeview = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            height=min(5, max(3, self._table_schema.min_rows + 2)),
        )

        # Configure columns
        for col, header in zip(self._table_schema.columns, headers, strict=True):
            width = col.width_chars or 15
            self._treeview.heading(col.column_id, text=header)
            self._treeview.column(col.column_id, width=width * 8, anchor=tk.W)

        # Add scrollbar
        self._scrollbar = tk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self._treeview.yview)
        self._treeview.config(yscrollcommand=self._scrollbar.set)

        self._treeview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Edit button
        self._edit_button = tk.Button(
            frame,
            text="Edit Table...",
            command=self.show_table_editor,
            padx=10,
            pady=2,
        )
        self._edit_button.pack(pady=(5, 0), anchor=tk.W)

        # Apply readonly state
        if self._field_def.readonly:
            self._edit_button.config(state="disabled")

        # Initialize with min_rows empty rows if needed
        if not self._data.rows and self._table_schema.min_rows > 0:
            for _ in range(self._table_schema.min_rows):
                empty_row: dict[str, Any] = {}
                for col in self._table_schema.columns:
                    empty_row[col.column_id] = col.default_value or ""
                self._data.add_row(empty_row)

        self._refresh_treeview()

        return frame

    def _refresh_treeview(self) -> None:
        """Обновляет Treeview через diff (только изменённые строки)."""
        if self._treeview is None:
            return

        # Check if data has changed (optimization)
        if not self._has_data_changed():
            return

        # Get current state
        current_ids = set(self._treeview.get_children())
        new_rows = self._data.rows
        new_ids = {str(i) for i in range(len(new_rows))}

        # 1. Remove deleted rows
        for item_id in current_ids - new_ids:
            self._treeview.delete(item_id)

        # 2. Update changed rows, insert new rows
        for i, row in enumerate(new_rows):
            item_id = str(i)
            values = self._format_row_values(row)

            if item_id in current_ids:
                # UPDATE existing (fast!)
                current_values = self._treeview.item(item_id, "values")
                if current_values != tuple(values):
                    self._treeview.item(item_id, values=values)
            else:
                # INSERT new (only for new rows)
                self._treeview.insert("", tk.END, iid=item_id, values=values)

        # 3. Update cache
        self._update_cache()

    def _has_data_changed(self) -> bool:
        """Проверяет, изменились ли данные с прошлого обновления."""
        if self._cached_rows is None:
            return True
        return self._cached_rows != self._data.rows

    def _update_cache(self) -> None:
        """Обновляет кэш данных."""
        if self._data:
            self._cached_rows = deepcopy(self._data.rows)
        else:
            self._cached_rows = None

    def _format_row_values(self, row: dict[str, Any]) -> list[str]:
        """Форматирует значения строки для Treeview."""
        if not self._table_schema:
            return []

        values: list[str] = []
        for col in self._table_schema.columns:
            value = row.get(col.column_id, "")
            # Format values based on column type
            if col.column_type.value in ("currency", "number_input") and value:
                try:
                    formatted = f"{float(str(value)):,.2f}".replace(",", " ")
                    values.append(formatted)
                except (ValueError, TypeError):
                    values.append(str(value))
            else:
                values.append(str(value) if value is not None else "")

        return values

    def _calculate_summary(self) -> Optional[dict[str, Any]]:
        """Вычисляет итоговую строку."""
        if self._table_schema is None or not self._table_schema.show_summary_row:
            return None

        summary: dict[str, Any] = {}

        for col in self._table_schema.columns:
            if col.summary_function is None:
                summary[col.column_id] = ""
                continue

            values: list[Union[int, float, Decimal]] = []
            for row in self._data.rows:
                val = row.get(col.column_id)
                if val is not None and val != "":
                    try:
                        values.append(Decimal(str(val)))
                    except (ValueError, TypeError):
                        pass

            if not values:
                summary[col.column_id] = ""
                continue

            if col.summary_function == SummaryFunction.SUM:
                summary[col.column_id] = sum(values, Decimal(0))
            elif col.summary_function == SummaryFunction.COUNT:
                summary[col.column_id] = len(values)
            elif col.summary_function == SummaryFunction.AVG:
                summary[col.column_id] = sum(values, Decimal(0)) / len(values)
            elif col.summary_function == SummaryFunction.MIN:
                summary[col.column_id] = min(values)
            elif col.summary_function == SummaryFunction.MAX:
                summary[col.column_id] = max(values)

        return summary

    def show_table_editor(self) -> None:
        """Показывает модальный редактор таблицы."""
        if self._table_schema is None:
            return
        if self._main_frame is None:
            return

        dialog = TableEditorDialog(
            self._main_frame,
            self._table_schema,
            self._data,
            self._field_def.readonly,
        )

        new_data = dialog.show()
        if new_data is not None:
            self.set_value(new_data.to_list())

    def get_value(self) -> list[dict[str, Any]]:
        """Возвращает текущее значение.

        Returns:
            Список словарей с данными таблицы.
        """
        return self._data.to_list()

    def set_value(self, value: Any) -> None:
        """Устанавливает значение таблицы.

        Args:
            value: Список словарей с данными.
        """
        if value is None:
            value = []

        if not isinstance(value, list):
            value = []

        # Validate and convert
        new_rows: list[dict[str, Any]] = []
        for row in value:
            if isinstance(row, dict):
                new_rows.append(deepcopy(row))

        self._data.rows = new_rows
        self._refresh_treeview()

        # Update summary
        self._data.summary_row = self._calculate_summary()

        super().set_value(self._data.to_list())

    def validate(self) -> bool:
        """Валидирует значение поля.

        Returns:
            True если значение валидно.
        """
        errors: list[str] = []

        if self._table_schema is None:
            if self._field_def.required:
                errors.append(f"Поле '{self._field_def.label}' обязательно")
            self._update_validation_state(len(errors) == 0, errors)
            return len(errors) == 0

        # Check min_rows
        if len(self._data.rows) < self._table_schema.min_rows:
            errors.append(f"Таблица должна содержать минимум {self._table_schema.min_rows} строк")

        # Check max_rows
        if self._table_schema.max_rows is not None:
            if len(self._data.rows) > self._table_schema.max_rows:
                errors.append(
                    f"Таблица может содержать максимум {self._table_schema.max_rows} строк"
                )

        # Validate required columns
        for row_idx, row in enumerate(self._data.rows):
            for col in self._table_schema.required_columns:
                val = row.get(col.column_id)
                if val is None or val == "":
                    errors.append(f"Строка {row_idx + 1}, колонка '{col.header}': обязательно")

        self._update_validation_state(len(errors) == 0, errors)
        return len(errors) == 0

    def _update_font(self) -> None:
        """Обновляет шрифт виджета."""
        # Treeview font is theme-dependent, but we can update column widths
        if self._treeview and self._table_schema:
            for col in self._table_schema.columns:
                width = col.width_chars or 15
                self._treeview.column(col.column_id, width=width * 8)

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные."""
        self._data.rows.clear()
        self._data.summary_row = None
        self._refresh_treeview()
        super().wipe_sensitive_data()

    def focus(self) -> None:
        """Устанавливает фокус на таблицу."""
        if self._treeview is not None:
            self._treeview.focus_set()


class TableEditorDialog:
    """Модальный редактор таблицы.

    Attributes:
        _parent: Родительский виджет.
        _schema: Схема таблицы.
        _data: Данные таблицы.
        _readonly: Режим только чтения.
        _dialog: Toplevel окно диалога.
        _entries: Словарь {row_idx: {col_id: Entry}}.
    """

    def __init__(
        self,
        parent: tk.Widget,
        schema: TableSchema,
        data: TableData,
        readonly: bool = False,
    ) -> None:
        """Инициализация диалога редактирования.

        Args:
            parent: Родительский виджет.
            schema: Схема таблицы.
            data: Текущие данные таблицы.
            readonly: Режим только чтения.
        """
        self._parent: tk.Widget = parent
        self._schema: TableSchema = schema
        self._data: TableData = deepcopy(data)
        self._readonly: bool = readonly
        self._dialog: Optional[tk.Toplevel] = None
        self._entries: dict[int, dict[str, tk.Entry]] = {}
        self._canvas: Optional[tk.Canvas] = None
        self._result: Optional[TableData] = None

    def show(self) -> Optional[TableData]:
        """Показывает диалог и возвращает результат.

        Returns:
            Новые данные таблицы или None если отменено.
        """
        self._dialog = tk.Toplevel(self._parent)
        self._dialog.title("Редактирование таблицы")
        self._dialog.geometry("800x600")
        self._dialog.transient(self._parent.winfo_toplevel())
        try:
            self._dialog.grab_set()
        except tk.TclError:
            pass

        self._create_widgets()
        self._populate_data()

        # Center dialog
        self._dialog.update_idletasks()
        x = (self._dialog.winfo_screenwidth() // 2) - (800 // 2)
        y = (self._dialog.winfo_screenheight() // 2) - (600 // 2)
        self._dialog.geometry(f"+{x}+{y}")

        # Wait for dialog to close
        self._parent.wait_window(self._dialog)

        return self._result

    def _create_widgets(self) -> None:
        """Создаёт виджеты диалога."""
        if self._dialog is None:
            return

        # Main container with scrollbar
        main_frame = tk.Frame(self._dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Toolbar
        toolbar = tk.Frame(main_frame)
        toolbar.pack(fill=tk.X, pady=(0, 10))

        if not self._readonly:
            tk.Button(toolbar, text="Add Row", command=self._add_row).pack(
                side=tk.LEFT, padx=(0, 5)
            )
            tk.Button(toolbar, text="Delete Row", command=self._delete_row).pack(
                side=tk.LEFT, padx=(0, 5)
            )
            tk.Button(toolbar, text="Paste from Excel", command=self._paste_from_clipboard).pack(
                side=tk.LEFT, padx=(0, 5)
            )

        tk.Button(toolbar, text="Cancel", command=self._cancel).pack(side=tk.RIGHT)
        if not self._readonly:
            tk.Button(toolbar, text="Save", command=self._save).pack(side=tk.RIGHT, padx=(0, 5))

        # Scrollable frame for table
        canvas_frame = tk.Frame(main_frame)
        canvas_frame.pack(fill=tk.BOTH, expand=True)

        self._canvas = tk.Canvas(canvas_frame)
        scrollbar = tk.Scrollbar(canvas_frame, orient=tk.VERTICAL, command=self._canvas.yview)
        self._canvas.config(yscrollcommand=scrollbar.set)

        self._table_frame = tk.Frame(self._canvas)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self._canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._canvas.create_window((0, 0), window=self._table_frame, anchor=tk.NW)

        def on_configure(event: tk.Event[Any]) -> None:
            if self._canvas is not None:
                self._canvas.config(scrollregion=self._canvas.bbox("all"))

        self._table_frame.bind("<Configure>", on_configure)

        # Create headers
        tk.Label(
            self._table_frame,
            text="#",
            font=("TkDefaultFont", 10, "bold"),
            width=4,
        ).grid(row=0, column=0, padx=2, pady=2)

        for col_idx, col in enumerate(self._schema.columns):
            tk.Label(
                self._table_frame,
                text=col.header,
                font=("TkDefaultFont", 10, "bold"),
                width=col.width_chars or 15,
            ).grid(row=0, column=col_idx + 1, padx=2, pady=2)

    def _populate_data(self) -> None:
        """Заполняет таблицу данными."""
        self._entries.clear()

        # Clear existing widgets (except headers)
        for widget in self._table_frame.winfo_children():
            if int(widget.grid_info().get("row", 0)) > 0:
                widget.destroy()

        for row_idx, row in enumerate(self._data.rows):
            self._create_row_widgets(row_idx, row)

        if self._canvas:
            self._canvas.config(scrollregion=self._canvas.bbox("all"))

    def _create_row_widgets(self, row_idx: int, row: dict[str, Any]) -> None:
        """Создаёт виджеты для строки."""
        tk.Label(self._table_frame, text=str(row_idx + 1), width=4).grid(
            row=row_idx + 1, column=0, padx=2, pady=1
        )

        self._entries[row_idx] = {}

        for col_idx, col in enumerate(self._schema.columns):
            value = row.get(col.column_id, "")

            entry = tk.Entry(
                self._table_frame,
                width=col.width_chars or 15,
                state="readonly" if self._readonly else "normal",
            )
            entry.insert(0, str(value) if value is not None else "")
            entry.grid(row=row_idx + 1, column=col_idx + 1, padx=2, pady=1)

            self._entries[row_idx][col.column_id] = entry

    def _add_row(self) -> None:
        """Добавляет новую строку."""
        if self._schema.max_rows is not None:
            if len(self._entries) >= self._schema.max_rows:
                messagebox.showwarning("Limit", f"Maximum {self._schema.max_rows} rows")
                return

        # Collect current data
        self._collect_data()

        # Add empty row
        new_row: dict[str, Any] = {}
        for col in self._schema.columns:
            new_row[col.column_id] = col.default_value or ""
        self._data.add_row(new_row)

        # Refresh
        self._populate_data()

    def _delete_row(self) -> None:
        """Удаляет выбранную строку."""
        if len(self._entries) <= self._schema.min_rows:
            messagebox.showwarning("Limit", f"Minimum {self._schema.min_rows} rows")
            return

        # Show simple dialog for row number
        row_num = simpledialog.askinteger(
            "Удаление",
            f"Введите номер строки для удаления (1-{len(self._entries)}):",
            minvalue=1,
            maxvalue=len(self._entries),
        )

        if row_num is not None:
            # Collect current data
            self._collect_data()

            # Remove row
            self._data.remove_row(row_num - 1)

            # Refresh
            self._populate_data()

    def _collect_data(self) -> None:
        """Собирает данные из виджетов в _data."""
        self._data.rows.clear()

        for row_idx in sorted(self._entries.keys()):
            row_data: dict[str, Any] = {}
            for col_id, entry in self._entries[row_idx].items():
                value_str: str = entry.get()
                value: Any = value_str
                # Try to preserve numeric types
                try:
                    value = float(value_str)
                except ValueError:
                    pass
                row_data[col_id] = value
            self._data.add_row(row_data)

    def _paste_from_clipboard(self) -> None:
        """Вставляет данные из буфера обмена."""
        if self._dialog is None:
            return
        try:
            clipboard = self._dialog.clipboard_get()
        except tk.TclError:
            messagebox.showinfo("Clipboard", "Clipboard is empty")
            return

        # Parse tab-separated data
        lines = clipboard.strip().split("\n")
        if not lines:
            return

        # Collect current data first
        self._collect_data()

        # Parse and add rows
        for line in lines:
            values = line.split("\t")
            new_row: dict[str, Any] = {}
            for idx, col in enumerate(self._schema.columns):
                if idx < len(values):
                    val_str = values[idx].strip()
                    parsed_val: Any = val_str
                    # Try to preserve numeric types
                    try:
                        parsed_val = float(val_str)
                    except ValueError:
                        pass
                    new_row[col.column_id] = parsed_val
                else:
                    new_row[col.column_id] = ""
            self._data.add_row(new_row)

        # Refresh
        self._populate_data()

    def _save(self) -> None:
        """Сохраняет данные и закрывает диалог."""
        self._collect_data()

        # Validate
        errors: list[str] = []
        if len(self._data.rows) < self._schema.min_rows:
            errors.append(f"Minimum {self._schema.min_rows} rows")

        if errors:
            messagebox.showerror("Error", "\n".join(errors))
            return

        self._result = self._data
        if self._dialog:
            self._dialog.destroy()

    def _cancel(self) -> None:
        """Отменяет изменения и закрывает диалог."""
        self._result = None
        if self._dialog:
            self._dialog.destroy()


__all__: list[str] = [
    "TableWidget",
    "TableEditorDialog",
    "TableData",
]
