"""Диалоги для workflow и работы с документами.

Компоненты:
- AddCommentDialog: Добавление комментария к полю/документу
- PrefillDialog: Автозаполнение из предыдущих документов

Example:
    >>> comment = AddCommentDialog(parent, field_id="customer_name")
    >>> result = comment.show()
    >>> if result:
    ...     print(f"Comment added: {result['text']}")

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from dataclasses import dataclass
from tkinter import messagebox, ttk
from typing import Any, Callable, Final, Optional

from src.gui.dialogs.base_dialog import BaseDialog
from src.services.prefill_search_service import PrefillSearchService

logger: Final = logging.getLogger(__name__)

# Constants
DIALOG_WIDTH: Final[int] = 500
DIALOG_HEIGHT: Final[int] = 400
MIN_DIALOG_WIDTH: Final[int] = 400
MIN_DIALOG_HEIGHT: Final[int] = 300

# Colors
COLOR_BG: Final[str] = "#f8f9fa"
COLOR_HEADER: Final[str] = "#e9ecef"
COLOR_SUCCESS: Final[str] = "#28a745"
COLOR_ERROR: Final[str] = "#dc3545"
COLOR_WARNING: Final[str] = "#ffc107"

# Severity levels for comments
COMMENT_SEVERITY: Final[list[tuple[str, str]]] = [
    ("info", "Info"),
    ("suggestion", "Suggestion"),
    ("warning", "Warning"),
    ("error", "Error"),
    ("critical", "Critical"),
]


@dataclass
class CommentData:
    """Данные комментария.

    Attributes:
        text: Текст комментария.
        severity: Уровень важности.
        author: Автор комментария.
        field_id: ID поля (если комментарий к полю).
        timestamp: Время создания.
    """

    text: str
    severity: str = "info"
    author: str = ""
    field_id: str = ""
    timestamp: str = ""


class AddCommentDialog(BaseDialog):
    """Диалог добавления комментария.

    Позволяет добавить комментарий к полю формы или документу
    с указанием уровня важности.

    Example:
        >>> dialog = AddCommentDialog(
        ...     parent,
        ...     field_id="customer_name",
        ...     field_label="Имя клиента",
        ... )
        >>> result = dialog.show()
        >>> if result:
        ...     print(f"Added: {result['text']} ({result['severity']})")

    Attributes:
        _field_id: ID поля (если комментарий к полю).
        _field_label: Название поля.
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_id: str = "",
        field_label: str = "",
        document_id: str = "",
        author: str = "",
        on_save: Optional[Callable[[CommentData], None]] = None,
    ) -> None:
        """Инициализация диалога комментария.

        Args:
            parent: Родительский виджет.
            field_id: ID поля (если комментарий к конкретному полю).
            field_label: Название поля.
            document_id: ID документа.
            author: Автор комментария (текущий пользователь).
            on_save: Callback при сохранении.
        """
        super().__init__(parent)

        self._parent: tk.Widget = parent
        self._field_id: str = field_id
        self._field_label: str = field_label
        self._document_id: str = document_id
        self._author: str = author
        self._on_save: Optional[Callable[[CommentData], None]] = on_save
        self._result: Optional[CommentData] = None

        self._create_ui()
        self._setup_window()

    def _setup_window(self) -> None:
        """Настраивает параметры окна."""
        title = "Add Comment"
        if self._field_label:
            title += f" - {self._field_label}"

        self.title(title)
        self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}")
        self.minsize(MIN_DIALOG_WIDTH, MIN_DIALOG_HEIGHT)

    def _create_ui(self) -> None:
        """Создаёт UI диалога."""
        self.config(bg=COLOR_BG)

        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        header_text = "Comment"
        if self._field_label:
            header_text = f"Field Comment: {self._field_label}"
        elif self._document_id:
            header_text = "Document Comment"

        header = ttk.Label(
            main_frame,
            text=header_text,
            font=("Helvetica", 12, "bold"),
        )
        header.pack(anchor="w", pady=(0, 10))

        # Severity selection
        severity_frame = ttk.LabelFrame(main_frame, text="Severity", padding="10")
        severity_frame.pack(fill=tk.X, pady=(0, 10))

        self._severity_var = tk.StringVar(master=self, value="info")
        for code, label in COMMENT_SEVERITY:
            ttk.Radiobutton(
                severity_frame, text=label, value=code, variable=self._severity_var
            ).pack(anchor="w")

        # Comment text
        text_frame = ttk.LabelFrame(main_frame, text="Comment Text", padding="10")
        text_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self._text_widget = tk.Text(
            text_frame,
            wrap=tk.WORD,
            height=8,
            font=("Helvetica", 10),
        )
        self._text_widget.pack(fill=tk.BOTH, expand=True)

        # Character count
        self._char_count_var = tk.StringVar(master=self, value="0 / 1000")
        ttk.Label(text_frame, textvariable=self._char_count_var, foreground="gray").pack(anchor="e")

        # Update character count
        def update_count(*args: Any) -> None:
            count = len(self._text_widget.get("1.0", tk.END)) - 1
            self._char_count_var.set(f"{count} / 1000")

        self._text_widget.bind("<KeyRelease>", update_count)
        self._text_widget.bind("<ButtonRelease>", update_count)

        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X)

        ttk.Button(btn_frame, text="Save", command=self._on_save_click).pack(
            side=tk.RIGHT, padx=(10, 0)
        )
        ttk.Button(btn_frame, text="Cancel", command=self._on_cancel).pack(side=tk.RIGHT)

    def _on_save_click(self) -> None:
        """Обработчик кнопки 'Сохранить'."""
        text = self._text_widget.get("1.0", tk.END).strip()

        if not text:
            messagebox.showwarning("Warning", "Enter comment text")
            return

        if len(text) > 1000:
            messagebox.showerror("Error", "Comment text is too long (max 1000 characters)")
            return

        from datetime import datetime

        self._result = CommentData(
            text=text,
            severity=self._severity_var.get(),
            author=self._author,
            field_id=self._field_id,
            timestamp=datetime.now().isoformat(),
        )

        if self._on_save:
            self._on_save(self._result)

        logger.info("Comment added: field=%s, severity=%s", self._field_id, self._result.severity)

        self.destroy()

    def _on_cancel(self) -> None:
        """Обработчик кнопки 'Отмена'."""
        self._result = None
        self.destroy()

    def show(self) -> Optional[CommentData]:
        """Показывает диалог и возвращает комментарий.

        Returns:
            CommentData или None если отменено.
        """
        self.wait_window()
        return self._result


class PrefillDialog(BaseDialog):
    """Диалог автозаполнения из предыдущих документов.

    Позволяет найти и заполнить поля текущего документа
    значениями из ранее заполненных документов.

    Example:
        >>> dialog = PrefillDialog(
        ...     parent,
        ...     field_id="customer_name",
        ...     autocomplete_service=autocomplete_service,
        ... )
        >>> result = dialog.show()
        >>> if result:
        ...     print(f"Prefilled with: {result['value']}")

    Attributes:
        _field_id: ID поля для автозаполнения.
        _matches: Список найденных совпадений.
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_id: str,
        field_label: str = "",
        current_value: str = "",
        on_select: Optional[Callable[[str], None]] = None,
        search_service: Optional[PrefillSearchService] = None,
        document_index: str = "",
    ) -> None:
        """Инициализация диалога автозаполнения.

        Args:
            parent: Родительский виджет.
            field_id: ID поля для автозаполнения.
            field_label: Название поля.
            current_value: Текущее значение поля.
            on_select: Callback при выборе значения.
            search_service: Сервис поиска для автозаполнения.
            document_index: Индекс документа (DVN-индекс).
        """
        super().__init__(parent)

        self._parent: tk.Widget = parent
        self._field_id: str = field_id
        self._field_label: str = field_label or field_id
        self._current_value: str = current_value
        self._on_select: Optional[Callable[[str], None]] = on_select
        self._search_service: Optional[PrefillSearchService] = search_service
        self._document_index: str = document_index
        self._result: Optional[str] = None

        self._create_ui()
        self._setup_window()

    def _setup_window(self) -> None:
        """Настраивает параметры окна."""
        self.title(f"Prefill: {self._field_label}")
        self.geometry(f"{DIALOG_WIDTH + 100}x{DIALOG_HEIGHT + 50}")
        self.minsize(MIN_DIALOG_WIDTH + 50, MIN_DIALOG_HEIGHT + 50)

    def _create_ui(self) -> None:
        """Создаёт UI диалога."""
        self.config(bg=COLOR_BG)

        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        header = ttk.Label(
            main_frame,
            text=f"Prefill Field: {self._field_label}",
            font=("Helvetica", 12, "bold"),
        )
        header.pack(anchor="w", pady=(0, 5))

        # Current value
        ttk.Label(
            main_frame,
            text=f"Current value: {self._current_value or '(empty)'}",
            foreground="gray",
        ).pack(anchor="w", pady=(0, 10))

        # Search section
        search_frame = ttk.LabelFrame(main_frame, text="Search", padding="10")
        search_frame.pack(fill=tk.X, pady=(0, 10))

        search_input_frame = ttk.Frame(search_frame)
        search_input_frame.pack(fill=tk.X)

        self._search_var = tk.StringVar(master=self, value=self._current_value)
        ttk.Entry(search_input_frame, textvariable=self._search_var, width=40).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10)
        )
        ttk.Button(search_input_frame, text="Find", command=self._on_search).pack(side=tk.RIGHT)

        # Results section
        results_frame = ttk.LabelFrame(main_frame, text="Found Matches", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Treeview for matches
        columns = ("value", "document", "confidence")
        self._tree = ttk.Treeview(
            results_frame, columns=columns, show="headings", selectmode="browse"
        )

        self._tree.heading("value", text="Value")
        self._tree.heading("document", text="Document")
        self._tree.heading("confidence", text="Confidence")

        self._tree.column("value", width=150)
        self._tree.column("document", width=200)
        self._tree.column("confidence", width=100, anchor="center")

        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=scrollbar.set)

        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Double-click to select
        self._tree.bind("<Double-1>", lambda e: self._on_select_click())

        # Preview
        self._preview_var = tk.StringVar(master=self, value="Select a value to preview")
        ttk.Label(main_frame, textvariable=self._preview_var, wraplength=400).pack(
            fill=tk.X, pady=(0, 10)
        )

        # Bind selection
        self._tree.bind("<<TreeviewSelect>>", self._on_selection_changed)

        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X)

        ttk.Button(btn_frame, text="Select", command=self._on_select_click).pack(
            side=tk.RIGHT, padx=(10, 0)
        )
        ttk.Button(btn_frame, text="Cancel", command=self._on_cancel).pack(side=tk.RIGHT)

        # Load initial search
        if self._current_value:
            self._on_search()

    def _on_search(self) -> None:
        """Обработчик поиска совпадений."""
        query = self._search_var.get()

        # Clear existing
        for item in self._tree.get_children():
            self._tree.delete(item)

        if self._search_service is not None:
            results = self._search_service.search_field_values(
                self._field_id, query=query, limit=10
            )
            for match in results:
                confidence_label = f"{int(match.confidence * 100)}%"
                self._tree.insert(
                    "", tk.END, values=(match.field_value, match.document_name, confidence_label)
                )
        else:
            # Fallback: показываем информацию что сервис не настроен
            self._tree.insert("", tk.END, values=("Search service is not configured", "", ""))

        logger.info("Prefill search for field %s: query=%s", self._field_id, query)

    def _on_selection_changed(self, event: tk.Event) -> None:
        """Обработчик изменения выбора."""
        selection = self._tree.selection()
        if selection:
            item = self._tree.item(selection[0])
            values = item["values"]
            if values:
                self._preview_var.set(f"Value: {values[0]}\nFrom document: {values[1]}")

    def _on_select_click(self) -> None:
        """Обработчик кнопки 'Выбрать'."""
        selection = self._tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Select a value from the list")
            return

        item = self._tree.item(selection[0])
        values = item["values"]
        if values:
            self._result = str(values[0])  # The value

            if self._on_select:
                self._on_select(self._result)

            logger.info("Prefill selected for field %s: %s", self._field_id, self._result)
            self.destroy()

    def _on_cancel(self) -> None:
        """Обработчик кнопки 'Отмена'."""
        self._result = None
        self.destroy()

    def show(self) -> Optional[str]:
        """Показывает диалог и возвращает выбранное значение.

        Returns:
            Выбранное значение или None.
        """
        self.wait_window()
        return self._result


class CrossDocumentLookupPanel(ttk.Frame):
    """Панель поиска по всем документам.

    Позволяет искать значения полей во всех документах
    системы для переноса данных.

    Example:
        >>> panel = CrossDocumentLookupPanel(parent)
        >>> panel.pack(fill=tk.BOTH, expand=True)
        >>> panel.search("customer_name", "ООО Ромашка")
    """

    def __init__(
        self,
        parent: tk.Widget,
        on_result_select: Optional[Callable[[str, str], None]] = None,
        search_service: Optional[PrefillSearchService] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """Инициализация панели поиска.

        Args:
            parent: Родительский виджет.
            on_result_select: Callback при выборе результата (field_id, value).
            search_service: Сервис поиска для автозаполнения.
        """
        # modal не является валидной опцией ttk.Frame, удаляем для обратной совместимости
        kwargs.pop("modal", None)
        super().__init__(parent, *args, **kwargs)

        self._on_result_select = on_result_select
        self._search_service: Optional[PrefillSearchService] = search_service
        self._create_ui()

    def _create_ui(self) -> None:
        """Создаёт UI панели."""
        self.config(padding="10")

        # Search controls
        controls_frame = ttk.Frame(self)
        controls_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(controls_frame, text="Field:").pack(side=tk.LEFT, padx=(0, 5))
        self._field_var = tk.StringVar(master=self)
        ttk.Combobox(
            controls_frame,
            textvariable=self._field_var,
            values=["customer_name", "inn", "kpp"],
            width=20,
        ).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Label(controls_frame, text="Value:").pack(side=tk.LEFT, padx=(0, 5))
        self._value_var = tk.StringVar(master=self)
        ttk.Entry(controls_frame, textvariable=self._value_var, width=30).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10)
        )

        ttk.Button(controls_frame, text="Search", command=self._on_search).pack(side=tk.RIGHT)

        # Results
        results_frame = ttk.LabelFrame(self, text="Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("field", "value", "document", "date")
        self._tree = ttk.Treeview(results_frame, columns=columns, show="headings")

        self._tree.heading("field", text="Field")
        self._tree.heading("value", text="Value")
        self._tree.heading("document", text="Document")
        self._tree.heading("date", text="Date")

        self._tree.column("field", width=100)
        self._tree.column("value", width=150)
        self._tree.column("document", width=200)
        self._tree.column("date", width=100)

        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=scrollbar.set)

        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._tree.bind("<Double-1>", self._on_result_double_click)

    def _on_search(self) -> None:
        """Обработчик поиска."""
        field = self._field_var.get()
        value = self._value_var.get()

        # Clear existing
        for item in self._tree.get_children():
            self._tree.delete(item)

        if self._search_service is not None:
            results = self._search_service.search_field_values(
                field_id=field, query=value, limit=10
            )
            for match in results:
                confidence_label = f"{int(match.confidence * 100)}%"
                self._tree.insert(
                    "",
                    tk.END,
                    values=(
                        match.field_id,
                        match.field_value,
                        match.document_name,
                        confidence_label,
                    ),
                )
        else:
            # Обратная совместимость: показываем что сервис не настроен
            self._tree.insert("", tk.END, values=("Search service is not configured", "", "", ""))

        logger.info("Cross-document search: field=%s, value=%s", field, value)

    def _on_result_double_click(self, event: tk.Event) -> None:
        """Обработчик двойного клика по результату."""
        selection = self._tree.selection()
        if selection and self._on_result_select:
            item = self._tree.item(selection[0])
            values = item["values"]
            if len(values) >= 2:
                self._on_result_select(str(values[0]), str(values[1]))

    def search(self, field_id: str, value: str) -> None:
        """Выполняет поиск.

        Args:
            field_id: ID поля для поиска.
            value: Значение для поиска.
        """
        self._field_var.set(field_id)
        self._value_var.set(value)
        self._on_search()
