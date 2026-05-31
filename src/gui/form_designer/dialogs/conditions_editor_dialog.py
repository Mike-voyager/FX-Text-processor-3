"""Диалог редактирования условий поля для Form Designer.

Предоставляет интерфейс для редактирования условных выражений:
- visibility_condition: условие видимости поля
- enabled_condition: условие активности поля
- read_only_condition: условие только для чтения

Features:
    - Редактирование трех типов условий в одном диалоге
    - Подсветка синтаксиса (базовая)
    - Валидация выражений
    - Примеры условий в подсказках

Example:
    >>> from src.documents.types.type_schema import FieldDefinition
    >>> dialog = ConditionsEditorDialog(
    ...     parent=root,
    ...     field_def=field_definition,
    ... )
    >>> result = dialog.show()
    >>> if result:
    ...     print(f"Visibility: {result['visibility_condition']}")

Version: 1.0
"""

from __future__ import annotations

import logging
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from typing import Any, Final, Optional, cast

from src.documents.types.type_schema import FieldDefinition

logger: Final = logging.getLogger(__name__)

# Module metadata
__version__: Final[str] = "1.0.0"
__author__: Final[str] = "Mike Voyager"
__date__: Final[str] = "April 2026"

# Dialog constants
DIALOG_WIDTH: Final[int] = 600
DIALOG_HEIGHT: Final[int] = 500
MIN_DIALOG_WIDTH: Final[int] = 400
MIN_DIALOG_HEIGHT: Final[int] = 350

# Colors
COLOR_BG: Final[str] = "#f8f9fa"
COLOR_HEADER: Final[str] = "#e9ecef"
COLOR_BORDER: Final[str] = "#dee2e6"
COLOR_TEXT_BG: Final[str] = "#ffffff"
COLOR_EXAMPLE: Final[str] = "#6c757d"

# Example conditions for help
EXAMPLES: Final[list[str]] = [
    "agreement_type == 'service'",
    "amount > 1000 and currency == 'RUB'",
    "is_urgent == True",
    "recipient is not None",
    "status in ('approved', 'pending')",
]


class ConditionsEditorDialog(tk.Toplevel):
    """Диалог редактирования условий поля.

    Attributes:
        _field_def: Определение поля для редактирования.
        _result: Результат редактирования или None.
        _visibility_text: Text widget для visibility_condition.
        _enabled_text: Text widget для enabled_condition.
        _readonly_text: Text widget для read_only_condition.

    Example:
        >>> dialog = ConditionsEditorDialog(parent=root, field_def=field)
        >>> result = dialog.show()
        >>> if result:
        ...     print("Conditions updated")
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_def: FieldDefinition,
        available_fields: Optional[list[str]] = None,
    ) -> None:
        """Инициализация диалога редактирования условий.

        Args:
            parent: Родительский виджет.
            field_def: Определение поля для редактирования.
            available_fields: Список доступных field_id для autocomplete.
        """
        super().__init__(cast(Any, parent))

        self._parent: tk.Widget = parent
        self._field_def: FieldDefinition = field_def
        self._available_fields: list[str] = available_fields or []
        self._result: Optional[dict[str, Optional[str]]] = None

        # UI references
        self._visibility_text: Optional[scrolledtext.ScrolledText] = None
        self._enabled_text: Optional[scrolledtext.ScrolledText] = None
        self._readonly_text: Optional[scrolledtext.ScrolledText] = None
        self._status_label: Optional[tk.Label] = None

        # Configure window
        self.title(f"Field Conditions: {field_def.field_id}")
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
        self._load_values()

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

        # Configure grid weights
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=0)  # Header
        main_frame.rowconfigure(1, weight=1)  # Notebook
        main_frame.rowconfigure(2, weight=0)  # Examples
        main_frame.rowconfigure(3, weight=0)  # Buttons

        # Header
        self._create_header(main_frame)

        # Notebook with condition tabs
        self._create_notebook(main_frame)

        # Examples section
        self._create_examples_section(main_frame)

        # Buttons
        self._create_buttons(main_frame)

    def _create_header(self, parent: tk.Frame) -> None:
        """Создает заголовок диалога.

        Args:
            parent: Родительский фрейм.
        """
        header = tk.Frame(parent, bg=COLOR_HEADER, relief=tk.GROOVE, bd=1)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        header.columnconfigure(0, weight=1)

        # Field info
        info_text = f"Field: {self._field_def.field_id} ({self._field_def.field_type.value})"
        label = tk.Label(
            header,
            text=info_text,
            bg=COLOR_HEADER,
            font=("Arial", 10, "bold"),
            anchor=tk.W,
        )
        label.pack(fill=tk.X, padx=5, pady=5)

        # Description
        desc = tk.Label(
            header,
            text="Conditions define field behavior based on values of other fields",
            bg=COLOR_HEADER,
            font=("Arial", 9),
            fg="#555555",
            anchor=tk.W,
            wraplength=550,
        )
        desc.pack(fill=tk.X, padx=5, pady=(0, 5))

    def _create_notebook(self, parent: tk.Frame) -> None:
        """Создает вкладки для разных типов условий.

        Args:
            parent: Родительский фрейм.
        """
        # Notebook
        notebook = ttk.Notebook(parent)
        notebook.grid(row=1, column=0, sticky="nsew", pady=5)

        # Visibility tab
        visibility_frame = tk.Frame(notebook, bg=COLOR_BG)
        notebook.add(visibility_frame, text=" Visibility ", padding=5)
        self._visibility_text = self._create_condition_editor(visibility_frame)

        # Enabled tab
        enabled_frame = tk.Frame(notebook, bg=COLOR_BG)
        notebook.add(enabled_frame, text=" Enabled ", padding=5)
        self._enabled_text = self._create_condition_editor(enabled_frame)

        # Read-only tab
        readonly_frame = tk.Frame(notebook, bg=COLOR_BG)
        notebook.add(readonly_frame, text=" Read-Only ", padding=5)
        self._readonly_text = self._create_condition_editor(readonly_frame)

    def _create_condition_editor(
        self,
        parent: tk.Frame,
    ) -> scrolledtext.ScrolledText:
        """Создает редактор условия.

        Args:
            parent: Родительский фрейм.

        Returns:
            ScrolledText widget для редактирования.
        """
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)

        # Text widget
        text = scrolledtext.ScrolledText(
            parent,
            wrap=tk.WORD,
            bg=COLOR_TEXT_BG,
            fg="#212529",
            font=("Consolas", 10),
            padx=5,
            pady=5,
            height=10,
        )
        text.grid(row=0, column=0, sticky="nsew")

        # Placeholder/label
        placeholder = tk.Label(
            parent,
            text="Enter a Python expression or leave empty",
            fg=COLOR_EXAMPLE,
            bg=COLOR_BG,
            font=("Arial", 8, "italic"),
            anchor=tk.W,
        )
        placeholder.grid(row=1, column=0, sticky="ew", pady=(5, 0))

        return text

    def _create_examples_section(self, parent: tk.Frame) -> None:
        """Создает секцию с примерами условий.

        Args:
            parent: Родительский фрейм.
        """
        examples_frame = tk.LabelFrame(
            parent,
            text="Condition Examples",
            bg=COLOR_BG,
            font=("Arial", 9, "bold"),
        )
        examples_frame.grid(row=2, column=0, sticky="ew", pady=10)
        examples_frame.columnconfigure(0, weight=1)

        # Examples text
        examples_str = "  •  " + "\n  •  ".join(EXAMPLES)
        label = tk.Label(
            examples_frame,
            text=examples_str,
            bg=COLOR_BG,
            fg=COLOR_EXAMPLE,
            font=("Consolas", 9),
            anchor=tk.W,
            justify=tk.LEFT,
        )
        label.pack(fill=tk.X, padx=5, pady=5)

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
            fg="#e74c3c",
            bg=COLOR_BG,
            font=("Arial", 9),
        )
        self._status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Validate button
        validate_btn = tk.Button(
            button_frame,
            text="Validate",
            command=self._on_validate,
            bg="#3498db",
            fg="white",
            activebackground="#2980b9",
            width=12,
        )
        validate_btn.pack(side=tk.RIGHT, padx=5)

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
            bg="#27ae60",
            fg="white",
            activebackground="#219a52",
            width=10,
        )
        ok_btn.pack(side=tk.RIGHT, padx=5)

    def _load_values(self) -> None:
        """Загружает текущие значения условий из field_def."""
        if self._visibility_text is not None:
            condition = self._field_def.visibility_condition or ""
            self._visibility_text.delete("1.0", tk.END)
            self._visibility_text.insert("1.0", condition)

        if self._enabled_text is not None:
            condition = self._field_def.enabled_condition or ""
            self._enabled_text.delete("1.0", tk.END)
            self._enabled_text.insert("1.0", condition)

        if self._readonly_text is not None:
            condition = self._field_def.read_only_condition or ""
            self._readonly_text.delete("1.0", tk.END)
            self._readonly_text.insert("1.0", condition)

    def _get_text_value(self, text_widget: Optional[scrolledtext.ScrolledText]) -> Optional[str]:
        """Получает значение из Text widget.

        Args:
            text_widget: Виджет Text.

        Returns:
            Строка с условием или None если пусто.
        """
        if text_widget is None:
            return None

        value = text_widget.get("1.0", tk.END).strip()
        return value if value else None

    def _validate_condition(self, condition: Optional[str]) -> tuple[bool, str]:
        """Валидирует условное выражение.

        Args:
            condition: Выражение для валидации.

        Returns:
            Кортеж (is_valid, error_message).
        """
        if not condition:
            return True, ""

        # Basic syntax check - try to compile as Python expression
        try:
            compile(condition, "<string>", "eval")
        except SyntaxError as e:
            return False, f"Syntax error: {e}"
        except (ValueError, TypeError, OverflowError) as e:
            return False, f"Error: {e}"

        # Check for potentially dangerous operations
        dangerous = ["__", "import", "exec", "eval", "compile", "open", "file"]
        for keyword in dangerous:
            if keyword in condition.lower():
                return False, f"Forbidden keyword: {keyword}"

        return True, ""

    def _on_validate(self) -> None:
        """Обработчик нажатия кнопки Проверить."""
        conditions = {
            "Visibility": self._get_text_value(self._visibility_text),
            "Enabled": self._get_text_value(self._enabled_text),
            "Read-Only": self._get_text_value(self._readonly_text),
        }

        errors: list[str] = []
        for name, condition in conditions.items():
            is_valid, error = self._validate_condition(condition)
            if not is_valid:
                errors.append(f"{name}: {error}")

        if self._status_label is not None:
            if errors:
                self._status_label.config(
                    text=f"Errors: {'; '.join(errors)}",
                    fg="#e74c3c",
                )
            else:
                self._status_label.config(
                    text="All conditions valid ✓",
                    fg="#27ae60",
                )

    def _on_ok(self) -> None:
        """Обработчик нажатия кнопки OK."""
        # Get values
        visibility = self._get_text_value(self._visibility_text)
        enabled = self._get_text_value(self._enabled_text)
        readonly = self._get_text_value(self._readonly_text)

        # Validate all
        conditions = [
            ("Visibility", visibility),
            ("Enabled", enabled),
            ("Read-Only", readonly),
        ]

        errors: list[str] = []
        for name, condition in conditions:
            is_valid, error = self._validate_condition(condition)
            if not is_valid:
                errors.append(f"{name}: {error}")

        if errors:
            messagebox.showerror(
                "Validation Error",
                "Fix errors before saving:\n\n" + "\n".join(errors),
                parent=self,
            )
            return

        # Set result
        self._result = {
            "visibility_condition": visibility,
            "enabled_condition": enabled,
            "read_only_condition": readonly,
        }

        self.destroy()

    def _on_cancel(self) -> None:
        """Обработчик нажатия кнопки Отмена или закрытия окна."""
        self._result = None
        self.destroy()

    def show(self) -> Optional[dict[str, Optional[str]]]:
        """Показывает диалог и ожидает закрытия.

        Returns:
            Словарь с условиями или None если отменено.
        """
        self.wait_window()
        return self._result


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__ = ["ConditionsEditorDialog"]
