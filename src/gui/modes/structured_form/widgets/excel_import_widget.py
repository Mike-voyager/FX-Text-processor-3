"""Виджет импорта данных из Excel/CSV.

Предоставляет:
- ExcelImportWidget: кнопка импорта с диалогом сопоставления колонок.

Example:
    >>> widget = ExcelImportWidget(
    ...     parent=frame,
    ...     field_def=field_def,
    ...     import_fields=["name", "amount"],
    ...     on_import=on_import_callback,
    ... )
"""

from __future__ import annotations

import csv
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable, Optional

from src.documents.types.type_schema import FieldDefinition
from src.gui.modes.structured_form.widgets.base_field_widget import BaseFieldWidget


class ExcelImportWidget(BaseFieldWidget):
    """Виджет импорта данных из Excel/CSV.

    Attributes:
        _import_button: Кнопка для вызова диалога импорта.
        _status_label: Метка со статусом.
        _file_label: Read-only поле с именем файла.
        _import_fields: Список идентификаторов полей для сопоставления.
        _on_import: Callback при подтверждении импорта.

    Example:
        >>> widget = ExcelImportWidget(
        ...     parent,
        ...     field_def,
        ...     import_fields=["field_a", "field_b"],
        ...     on_import=lambda fid, mapping: print(mapping),
        ... )
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_def: FieldDefinition,
        on_change: Optional[Callable[[str, Any], None]] = None,
        on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = None,
        on_import: Optional[Callable[[str, dict[str, str]], None]] = None,
        import_fields: Optional[list[str]] = None,
    ) -> None:
        """Инициализация виджета импорта.

        Args:
            parent: Родительский Tkinter виджет.
            field_def: Определение поля из схемы.
            on_change: Callback при изменении значения.
            on_validate: Callback при валидации.
            on_import: Callback при подтверждении импорта.
            import_fields: Список идентификаторов полей для сопоставления.
        """
        super().__init__(parent, field_def, on_change, on_validate)
        self._on_import: Optional[Callable[[str, dict[str, str]], None]] = on_import
        self._import_fields: list[str] = (
            import_fields if import_fields is not None else [field_def.field_id]
        )
        self._import_button: Optional[tk.Button] = None
        self._status_label: Optional[tk.Label] = None
        self._file_label: Optional[tk.Entry] = None
        self._current_file: Optional[Path] = None

    def _create_widget(self) -> tk.Widget:
        """Создаёт виджет импорта.

        Returns:
            Tkinter Frame с кнопкой и статусом.
        """
        frame = tk.Frame(self._main_frame)

        self._import_button = tk.Button(
            frame,
            text="📥 Import from Excel",
            command=self._on_import_click,
            font=("TkDefaultFont", 10),
        )
        self._import_button.pack(fill=tk.X, pady=(0, 4))

        self._file_label = tk.Entry(
            frame,
            font=("TkDefaultFont", 9),
            state="readonly",
            relief=tk.SUNKEN,
            borderwidth=1,
        )
        self._file_label.pack(fill=tk.X, pady=(0, 2))

        self._status_label = tk.Label(
            frame,
            text="",
            font=("TkDefaultFont", 8),
            fg="gray",
            anchor=tk.W,
        )
        self._status_label.pack(fill=tk.X)

        if self._field_def.readonly:
            self._import_button.config(state="disabled")

        return frame

    def _on_import_click(self) -> None:
        """Обработчик нажатия кнопки импорта."""
        file_path_str = filedialog.askopenfilename(
            title="Выберите файл для импорта",
            filetypes=[
                ("Excel files", "*.xlsx *.xls"),
                ("CSV files", "*.csv"),
                ("All files", "*.*"),
            ],
        )
        if not file_path_str:
            return

        self._current_file = Path(file_path_str)
        if self._file_label is not None:
            self._file_label.config(state="normal")
            self._file_label.delete(0, tk.END)
            self._file_label.insert(0, str(self._current_file.name))
            self._file_label.config(state="readonly")

        columns = self._read_columns(self._current_file)
        if columns is not None:
            self._show_mapping_dialog(columns)

    def _read_columns(self, file_path: Path) -> Optional[list[str]]:
        """Читает заголовки колонок из файла.

        Args:
            file_path: Путь к файлу.

        Returns:
            Список имён колонок или None при ошибке.
        """
        suffix = file_path.suffix.lower()
        try:
            if suffix == ".csv":
                return self._read_csv_columns(file_path)
            if suffix in (".xlsx", ".xls"):
                return self._read_excel_columns(file_path)
            messagebox.showerror("Ошибка", f"Неподдерживаемый формат файла: {suffix}")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Ошибка", f"Не удалось прочитать файл: {exc}")

        return None

    def _read_csv_columns(self, file_path: Path) -> list[str]:
        """Читает заголовки колонок из CSV.

        Args:
            file_path: Путь к CSV файлу.

        Returns:
            Список имён колонок.
        """
        with open(file_path, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            try:
                return next(reader)
            except StopIteration:
                return []

    def _read_excel_columns(self, file_path: Path) -> list[str]:
        """Читает заголовки колонок из Excel.

        Args:
            file_path: Путь к Excel файлу.

        Returns:
            Список имён колонок.

        Raises:
            ImportError: Если openpyxl не установлен.
        """
        try:
            import openpyxl
        except ImportError:
            messagebox.showerror(
                "Ошибка",
                "Для работы с Excel требуется установить openpyxl.",
            )
            raise

        wb = openpyxl.load_workbook(file_path, read_only=True, data_only=True)
        try:
            ws = wb.active
            if ws is None:
                return []
            return [
                str(cell) if cell is not None else ""
                for cell in next(ws.iter_rows(values_only=True))
            ]
        finally:
            wb.close()

    def _show_mapping_dialog(self, columns: list[str]) -> None:
        """Отображает диалог сопоставления полей и колонок.

        Args:
            columns: Список имён колонок из файла.
        """
        if not columns:
            messagebox.showwarning("Предупреждение", "Файл не содержит колонок.")
            return

        dialog = tk.Toplevel(self._parent)
        dialog.title("Сопоставление колонок")
        top = self._parent.winfo_toplevel()
        dialog.transient(top)
        dialog.grab_set()

        tk.Label(
            dialog,
            text="Доступные колонки:",
            font=("TkDefaultFont", 10, "bold"),
        ).pack(anchor=tk.W, padx=8, pady=(8, 2))

        tk.Label(
            dialog,
            text=", ".join(columns),
            font=("TkDefaultFont", 9),
            wraplength=400,
        ).pack(anchor=tk.W, padx=8, pady=(0, 8))

        tk.Label(
            dialog,
            text="Сопоставление:",
            font=("TkDefaultFont", 10, "bold"),
        ).pack(anchor=tk.W, padx=8, pady=(0, 4))

        combo_vars: dict[str, tk.StringVar] = {}
        for field_id in self._import_fields:
            row = tk.Frame(dialog)
            row.pack(fill=tk.X, padx=8, pady=2)

            tk.Label(row, text=f"{field_id} →", font=("TkDefaultFont", 9)).pack(side=tk.LEFT)

            var = tk.StringVar()
            combo = ttk.Combobox(
                row,
                textvariable=var,
                values=columns,
                state="readonly",
                width=30,
            )
            combo.pack(side=tk.LEFT, padx=(4, 0))
            combo_vars[field_id] = var

        def _on_apply() -> None:
            mapping: dict[str, str] = {}
            for field_id, var in combo_vars.items():
                col = var.get()
                if col:
                    mapping[field_id] = col

            if self._status_label is not None:
                self._status_label.config(
                    text=f"Импорт: {len(mapping)} полей сопоставлено",
                    fg="green",
                )

            self._value = str(self._current_file) if self._current_file else ""
            if self._on_change is not None:
                self._on_change(self.field_id, self._value)

            if self._on_import is not None:
                self._on_import(self.field_id, mapping)

            dialog.destroy()

        tk.Button(
            dialog,
            text="Apply",
            command=_on_apply,
            font=("TkDefaultFont", 10),
        ).pack(pady=8)

    def get_value(self) -> str:
        """Возвращает текущее значение.

        Returns:
            Путь к выбранному файлу или пустая строка.
        """
        return str(self._value) if self._value is not None else ""

    def set_value(self, value: Any) -> None:
        """Устанавливает значение поля.

        Args:
            value: Путь к файлу.
        """
        str_value = str(value) if value is not None else ""
        self._value = str_value

        if self._file_label is not None:
            self._file_label.config(state="normal")
            self._file_label.delete(0, tk.END)
            if str_value:
                self._file_label.insert(0, Path(str_value).name)
            self._file_label.config(state="readonly")

        if self._on_change is not None:
            self._on_change(self.field_id, str_value)

    def validate(self) -> bool:
        """Валидирует значение поля.

        Returns:
            True если значение валидно.
        """
        return super().validate()

    def _update_font(self) -> None:
        """Обновляет шрифт виджета."""
        font_size = max(8, min(14, 14 - (self._cpi - 10) // 2))
        if self._import_button is not None:
            self._import_button.config(font=("TkDefaultFont", font_size))

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные."""
        self._current_file = None
        if self._file_label is not None:
            self._file_label.config(state="normal")
            self._file_label.delete(0, tk.END)
            self._file_label.config(state="readonly")
        if self._status_label is not None:
            self._status_label.config(text="", fg="gray")
        super().wipe_sensitive_data()

    def focus(self) -> None:
        """Устанавливает фокус на кнопку импорта."""
        if self._import_button is not None:
            self._import_button.focus_set()


__all__: list[str] = ["ExcelImportWidget"]
