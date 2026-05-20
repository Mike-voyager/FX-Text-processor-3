"""Диалог редактирования опций поля для Form Designer.

Предоставляет интерфейс для редактирования списка опций
для полей типа DROPDOWN и RADIO_GROUP.

Features:
    - Таблица с опциями (value, label_ru, label_en)
    - Добавление/удаление/перемещение опций
    - Валидация уникальности value
    - Импорт из CSV (placeholder)
    - Drag-and-drop reorder (future)

Example:
    >>> dialog = OptionsEditorDialog(
    ...     parent=root,
    ...     current_options=[
    ...         FieldOption("yes", "Да", "Yes"),
    ...         FieldOption("no", "Нет", "No"),
    ...     ],
    ... )
    >>> result = dialog.show()
    >>> if result:
    ...     print(f"Options: {len(result)} items")

Version: 1.0
"""

from __future__ import annotations

import logging
import tkinter as tk
from dataclasses import dataclass
from tkinter import messagebox, ttk
from typing import Any, Final, Optional, cast

logger: Final = logging.getLogger(__name__)

# Dialog constants
DIALOG_WIDTH: Final[int] = 550
DIALOG_HEIGHT: Final[int] = 500
MIN_DIALOG_WIDTH: Final[int] = 400
MIN_DIALOG_HEIGHT: Final[int] = 300

# Colors
COLOR_BG: Final[str] = "#f8f9fa"
COLOR_HEADER: Final[str] = "#e9ecef"
COLOR_SELECTED: Final[str] = "#cce5ff"
COLOR_ERROR: Final[str] = "#f8d7da"


@dataclass(frozen=True)
class FieldOption:
    """Опция для DROPDOWN/RADIO_GROUP поля.

    Attributes:
        value: Значение опции (сохраняется в данных).
        label_ru: Отображаемая метка на русском.
        label_en: Отображаемая метка на английском.
    """

    value: str
    label_ru: str
    label_en: str = ""


class OptionsEditorDialog(tk.Toplevel):
    """Диалог редактирования опций поля.

    Attributes:
        _options: Текущий список опций.
        _tree: Treeview для отображения опций.
        _selected_index: Индекс выбранной опции.

    Example:
        >>> dialog = OptionsEditorDialog(
        ...     parent=root,
        ...     current_options=[FieldOption("a", "Option A")],
        ... )
        >>> result = dialog.show()
        >>> if result:
        ...     for opt in result:
        ...         print(f"{opt.value}: {opt.label_ru}")
    """

    def __init__(
        self,
        parent: tk.Widget,
        current_options: Optional[list[FieldOption]] = None,
        field_id: str = "",
    ) -> None:
        """Инициализация диалога редактирования опций.

        Args:
            parent: Родительский виджет.
            current_options: Текущий список опций.
            field_id: ID поля для отображения в заголовке.
        """
        super().__init__(cast(Any, parent))

        self._parent: tk.Widget = parent
        self._options: list[FieldOption] = list(current_options) if current_options else []
        self._field_id: str = field_id
        self._result: Optional[list[FieldOption]] = None

        # UI references
        self._tree: Optional[ttk.Treeview] = None
        self._value_entry: Optional[tk.Entry] = None
        self._label_ru_entry: Optional[tk.Entry] = None
        self._label_en_entry: Optional[tk.Entry] = None
        self._status_label: Optional[tk.Label] = None

        # Configure window
        title = f"Field Options: {field_id}" if field_id else "Options Editor"
        self.title(title)
        self.transient(cast(tk.Wm, parent))
        try:
            self.grab_set()
        except tk.TclError:
            pass

        # Set size and position
        self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}")
        self.minsize(MIN_DIALOG_WIDTH, MIN_DIALOG_HEIGHT)
        self._center_window()

        # Build UI
        self._create_ui()
        self._refresh_list()

        # Protocol handlers
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

        # Focus
        self.focus_set()

    def _center_window(self) -> None:
        """Центрирует окно относительно родителя."""
        self.update_idletasks()
        parent = self._parent.winfo_toplevel()
        x = parent.winfo_x() + (parent.winfo_width() - DIALOG_WIDTH) // 2
        y = parent.winfo_y() + (parent.winfo_height() - DIALOG_HEIGHT) // 2
        self.geometry(f"+{x}+{y}")

    def _create_ui(self) -> None:
        """Создает пользовательский интерфейс диалога."""
        # Main container
        main_frame = tk.Frame(self, bg=COLOR_BG)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Configure grid
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=0)  # Header
        main_frame.rowconfigure(1, weight=1)  # Treeview
        main_frame.rowconfigure(2, weight=0)  # Editor
        main_frame.rowconfigure(3, weight=0)  # Buttons

        # Header
        self._create_header(main_frame)

        # List section
        self._create_list_section(main_frame)

        # Editor section
        self._create_editor_section(main_frame)

        # Buttons
        self._create_buttons(main_frame)

    def _create_header(self, parent: tk.Frame) -> None:
        """Создает заголовок диалога.

        Args:
            parent: Родительский фрейм.
        """
        header = tk.Frame(parent, bg=COLOR_HEADER, relief=tk.GROOVE, bd=1)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        # Title
        title_text = f"Editing options for: {self._field_id}"
        label = tk.Label(
            header,
            text=title_text,
            bg=COLOR_HEADER,
            font=("Arial", 10, "bold"),
            anchor=tk.W,
        )
        label.pack(fill=tk.X, padx=5, pady=5)

        # Description
        desc = tk.Label(
            header,
            text="Add options for dropdown or radio group",
            bg=COLOR_HEADER,
            font=("Arial", 9),
            fg="#555555",
            anchor=tk.W,
        )
        desc.pack(fill=tk.X, padx=5, pady=(0, 5))

    def _create_list_section(self, parent: tk.Frame) -> None:
        """Создает секцию со списком опций.

        Args:
            parent: Родительский фрейм.
        """
        # Frame for treeview
        list_frame = tk.LabelFrame(
            parent,
            text="Option List",
            bg=COLOR_BG,
            font=("Arial", 9, "bold"),
        )
        list_frame.grid(row=1, column=0, sticky="nsew", pady=5)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        # Treeview
        columns = ("value", "label_ru", "label_en")
        self._tree = ttk.Treeview(
            list_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
            height=8,
        )

        # Configure columns
        self._tree.heading("value", text="Value")
        self._tree.heading("label_ru", text="Label (RU)")
        self._tree.heading("label_en", text="Label (EN)")

        self._tree.column("value", width=150, anchor=tk.W)
        self._tree.column("label_ru", width=150, anchor=tk.W)
        self._tree.column("label_en", width=150, anchor=tk.W)

        # Scrollbar
        scrollbar = ttk.Scrollbar(
            list_frame,
            orient=tk.VERTICAL,
            command=self._tree.yview,
        )
        self._tree.configure(yscrollcommand=scrollbar.set)

        # Pack
        self._tree.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        scrollbar.grid(row=0, column=1, sticky="ns", pady=5)

        # Bind selection
        self._tree.bind("<<TreeviewSelect>>", self._on_selection_change)

    def _create_editor_section(self, parent: tk.Frame) -> None:
        """Создает секцию редактирования отдельной опции.

        Args:
            parent: Родительский фрейм.
        """
        editor_frame = tk.LabelFrame(
            parent,
            text="Edit Option",
            bg=COLOR_BG,
            font=("Arial", 9, "bold"),
        )
        editor_frame.grid(row=2, column=0, sticky="ew", pady=10)
        editor_frame.columnconfigure(1, weight=1)

        # Value
        tk.Label(
            editor_frame,
            text="Value:*",
            bg=COLOR_BG,
            anchor=tk.W,
        ).grid(row=0, column=0, sticky="w", padx=5, pady=5)

        self._value_entry = tk.Entry(editor_frame)
        self._value_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)

        # Label RU
        tk.Label(
            editor_frame,
            text="Label (RU):*",
            bg=COLOR_BG,
            anchor=tk.W,
        ).grid(row=1, column=0, sticky="w", padx=5, pady=5)

        self._label_ru_entry = tk.Entry(editor_frame)
        self._label_ru_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

        # Label EN
        tk.Label(
            editor_frame,
            text="Label (EN):",
            bg=COLOR_BG,
            anchor=tk.W,
        ).grid(row=2, column=0, sticky="w", padx=5, pady=5)

        self._label_en_entry = tk.Entry(editor_frame)
        self._label_en_entry.grid(row=2, column=1, sticky="ew", padx=5, pady=5)

        # Action buttons for editor
        btn_frame = tk.Frame(editor_frame, bg=COLOR_BG)
        btn_frame.grid(row=3, column=0, columnspan=2, sticky="e", padx=5, pady=5)

        # Add button
        add_btn = tk.Button(
            btn_frame,
            text="➕ Add",
            command=self._on_add,
            bg="#28a745",
            fg="white",
        )
        add_btn.pack(side=tk.LEFT, padx=2)

        # Update button
        update_btn = tk.Button(
            btn_frame,
            text="💾 Update",
            command=self._on_update,
            bg="#007bff",
            fg="white",
        )
        update_btn.pack(side=tk.LEFT, padx=2)

        # Delete button
        delete_btn = tk.Button(
            btn_frame,
            text="🗑️ Delete",
            command=self._on_delete,
            bg="#dc3545",
            fg="white",
        )
        delete_btn.pack(side=tk.LEFT, padx=2)

    def _create_buttons(self, parent: tk.Frame) -> None:
        """Создает кнопки диалога.

        Args:
            parent: Родительский фрейм.
        """
        button_frame = tk.Frame(parent, bg=COLOR_BG)
        button_frame.grid(row=3, column=0, sticky="ew", pady=(10, 0))

        # Status label
        self._status_label = tk.Label(
            button_frame,
            text="",
            fg="#dc3545",
            bg=COLOR_BG,
            font=("Arial", 9),
        )
        self._status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Move buttons
        move_frame = tk.Frame(button_frame, bg=COLOR_BG)
        move_frame.pack(side=tk.LEFT, padx=10)

        up_btn = tk.Button(
            move_frame,
            text="⬆️ Up",
            command=self._on_move_up,
            width=10,
        )
        up_btn.pack(side=tk.LEFT, padx=2)

        down_btn = tk.Button(
            move_frame,
            text="⬇️ Down",
            command=self._on_move_down,
            width=10,
        )
        down_btn.pack(side=tk.LEFT, padx=2)

        # Cancel button
        cancel_btn = tk.Button(
            button_frame,
            text="Cancel",
            command=self._on_cancel,
            width=10,
        )
        cancel_btn.pack(side=tk.RIGHT, padx=5)

        # OK button
        ok_btn = tk.Button(
            button_frame,
            text="OK",
            command=self._on_ok,
            bg="#28a745",
            fg="white",
            width=10,
        )
        ok_btn.pack(side=tk.RIGHT, padx=5)

    def _refresh_list(self) -> None:
        """Обновляет отображение списка опций."""
        if self._tree is None:
            return

        # Clear tree
        for item in self._tree.get_children():
            self._tree.delete(item)

        # Add options
        for i, option in enumerate(self._options):
            self._tree.insert(
                "",
                tk.END,
                iid=str(i),
                values=(option.value, option.label_ru, option.label_en),
            )

    def _clear_editor(self) -> None:
        """Очищает поля редактора."""
        if self._value_entry:
            self._value_entry.delete(0, tk.END)
        if self._label_ru_entry:
            self._label_ru_entry.delete(0, tk.END)
        if self._label_en_entry:
            self._label_en_entry.delete(0, tk.END)

    def _get_editor_values(self) -> tuple[str, str, str]:
        """Получает значения из полей редактора.

        Returns:
            Кортеж (value, label_ru, label_en).
        """
        value = self._value_entry.get().strip() if self._value_entry else ""
        label_ru = self._label_ru_entry.get().strip() if self._label_ru_entry else ""
        label_en = self._label_en_entry.get().strip() if self._label_en_entry else ""
        return value, label_ru, label_en

    def _set_editor_values(self, option: FieldOption) -> None:
        """Устанавливает значения в поля редактора.

        Args:
            option: Опция для отображения.
        """
        if self._value_entry:
            self._value_entry.delete(0, tk.END)
            self._value_entry.insert(0, option.value)
        if self._label_ru_entry:
            self._label_ru_entry.delete(0, tk.END)
            self._label_ru_entry.insert(0, option.label_ru)
        if self._label_en_entry:
            self._label_en_entry.delete(0, tk.END)
            self._label_en_entry.insert(0, option.label_en)

    def _on_selection_change(self, event: tk.Event) -> None:
        """Обработчик изменения выбора в списке.

        Args:
            event: Событие выбора.
        """
        _ = event
        if self._tree is None:
            return

        selection = self._tree.selection()
        if not selection:
            return

        index = int(selection[0])
        if 0 <= index < len(self._options):
            self._set_editor_values(self._options[index])

    def _validate_option(
        self,
        value: str,
        label_ru: str,
        exclude_index: Optional[int] = None,
    ) -> tuple[bool, str]:
        """Валидирует опцию.

        Args:
            value: Значение опции.
            label_ru: Метка на русском.
            exclude_index: Индекс для исключения из проверки дубликатов.

        Returns:
            Кортеж (is_valid, error_message).
        """
        if not value:
            return False, "Value is required"

        if not label_ru:
            return False, "Label (RU) is required"

        # Check for duplicates
        for i, opt in enumerate(self._options):
            if i == exclude_index:
                continue
            if opt.value == value:
                return False, f"Value '{value}' already exists"

        return True, ""

    def _on_add(self) -> None:
        """Обработчик нажатия кнопки Добавить."""
        value, label_ru, label_en = self._get_editor_values()

        is_valid, error = self._validate_option(value, label_ru)
        if not is_valid:
            if self._status_label:
                self._status_label.config(text=error)
            return

        # Add option
        self._options.append(FieldOption(value, label_ru, label_en))
        self._refresh_list()
        self._clear_editor()

        if self._status_label:
            self._status_label.config(text="Option added", fg="#28a745")

    def _on_update(self) -> None:
        """Обработчик нажатия кнопки Обновить."""
        if self._tree is None:
            return

        selection = self._tree.selection()
        if not selection:
            if self._status_label:
                self._status_label.config(text="Select an option to update")
            return

        index = int(selection[0])
        if not (0 <= index < len(self._options)):
            return

        value, label_ru, label_en = self._get_editor_values()

        is_valid, error = self._validate_option(value, label_ru, exclude_index=index)
        if not is_valid:
            if self._status_label:
                self._status_label.config(text=error)
            return

        # Update option
        self._options[index] = FieldOption(value, label_ru, label_en)
        self._refresh_list()

        if self._status_label:
            self._status_label.config(text="Option updated", fg="#28a745")

    def _on_delete(self) -> None:
        """Обработчик нажатия кнопки Удалить."""
        if self._tree is None:
            return

        selection = self._tree.selection()
        if not selection:
            if self._status_label:
                self._status_label.config(text="Select an option to delete")
            return

        index = int(selection[0])
        if not (0 <= index < len(self._options)):
            return

        # Confirm deletion
        option = self._options[index]
        if not messagebox.askyesno(
            "Confirm",
            f'Delete option "{option.label_ru}" ({option.value})?',
            parent=self,
        ):
            return

        # Delete option
        del self._options[index]
        self._refresh_list()
        self._clear_editor()

        if self._status_label:
            self._status_label.config(text="Option deleted", fg="#28a745")

    def _on_move_up(self) -> None:
        """Обработчик нажатия кнопки Вверх."""
        if self._tree is None:
            return

        selection = self._tree.selection()
        if not selection:
            return

        index = int(selection[0])
        if index <= 0 or index >= len(self._options):
            return

        # Swap with previous
        self._options[index], self._options[index - 1] = (
            self._options[index - 1],
            self._options[index],
        )
        self._refresh_list()

        # Reselect
        self._tree.selection_set(str(index - 1))

    def _on_move_down(self) -> None:
        """Обработчик нажатия кнопки Вниз."""
        if self._tree is None:
            return

        selection = self._tree.selection()
        if not selection:
            return

        index = int(selection[0])
        if index < 0 or index >= len(self._options) - 1:
            return

        # Swap with next
        self._options[index], self._options[index + 1] = (
            self._options[index + 1],
            self._options[index],
        )
        self._refresh_list()

        # Reselect
        self._tree.selection_set(str(index + 1))

    def _on_ok(self) -> None:
        """Обработчик нажатия кнопки OK."""
        # Validate all options have required fields
        for i, opt in enumerate(self._options):
            if not opt.value or not opt.label_ru:
                messagebox.showerror(
                    "Error",
                    f"Option {i + 1} is incomplete",
                    parent=self,
                )
                return

        # Set result
        self._result = list(self._options)
        self.destroy()

    def _on_cancel(self) -> None:
        """Обработчик нажатия кнопки Отмена или закрытия окна."""
        self._result = None
        self.destroy()

    def show(self) -> Optional[list[FieldOption]]:
        """Показывает диалог и ожидает закрытия.

        Returns:
            Список опций или None если отменено.
        """
        self.wait_window()
        return self._result


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__ = ["OptionsEditorDialog", "FieldOption"]
