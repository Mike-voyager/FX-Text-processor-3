# -*- coding: utf-8 -*-
"""Поле ввода с автодополнением для STRUCTURED_FORM режима.

Предоставляет:
- AutocompleteEntry: Entry с выпадающим Listbox для автодополнения.

Features:
- Debounced поиск через AutocompleteServiceGui
- Навигация клавишами Up/Down/Return/Escape
- Выбор из списка вызывает on_change и скрывает Listbox

Example:
    >>> entry = AutocompleteEntry(
    ...     parent=frame,
    ...     field_id="recipient",
    ...     document_index="DVN-44-K53-IX",
    ...     label="Получатель",
    ...     on_change=on_field_changed,
    ...     autocomplete_service=AutocompleteServiceGui(),
    ... )
    >>> entry.pack(fill=tk.X)

Version: 2.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Any, Callable, Final, Optional

from src.documents.types.type_schema import FieldDefinition
from src.gui.modes.structured_form.widgets.base_field import BaseField
from src.gui.panels.cross_document_lookup import (
    CrossDocumentLookupDialog,
    DocumentServiceProtocol,
)
from src.gui.services.autocomplete_service import AutocompleteServiceGui
from src.services.autocomplete_service import AutocompleteService


class AutocompleteEntry(BaseField):
    """Entry с автодополнением из Form History.

    Использует AutocompleteServiceGui с debounce (300ms) для
    асинхронного поиска по иерархии документа.

    Attributes:
        MAX_SUGGESTIONS: Максимальное количество предложений.
        MIN_CHARS: Минимальная длина запроса для поиска.

    Example:
        >>> entry = AutocompleteEntry(
        ...     parent=frame,
        ...     field_id="company",
        ...     document_index="DVN-44-K53-IX",
        ...     label="Компания",
        ...     on_change=on_changed,
        ... )
    """

    MAX_SUGGESTIONS: Final[int] = 5
    MIN_CHARS: Final[int] = 2

    def __init__(
        self,
        parent: tk.Widget,
        field_id: str = "",
        document_index: str = "",
        label: str = "",
        on_change: Optional[Callable[[str, Any], None]] = None,
        autocomplete_service: Optional[Any] = None,
        field_def: Optional[FieldDefinition] = None,
        on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = None,
        document_service: Optional[DocumentServiceProtocol] = None,
        **kwargs: Any,
    ) -> None:
        """Инициализация поля с автодополнением.

        Args:
            parent: Родительский Tkinter виджет.
            field_id: Идентификатор поля.
            document_index: Полный индекс документа (например DVN-44-K53-IX).
            label: Текст метки поля.
            on_change: Callback при изменении значения (field_id, value).
            autocomplete_service: GUI обёртка сервиса автодополнения.
            field_def: Опциональное определение поля (legacy совместимость).
            on_validate: Callback при валидации.
            document_service: Сервис документов для cross-document lookup.
            **kwargs: Дополнительные аргументы для tk.Frame.
        """
        # Legacy совместимость: если передан field_def, берём из него
        effective_field_id = field_id if field_def is None else field_def.field_id
        effective_label = label if field_def is None else field_def.label

        super().__init__(
            parent=parent,
            field_id=effective_field_id,
            label=effective_label,
            on_change=on_change,
            **kwargs,
        )

        if on_validate is not None:
            self._on_validate = on_validate

        self._document_index: str = document_index
        self._hierarchy: list[str] = self._parse_index(document_index)
        # Определяем тип autocomplete_service: если передан AutocompleteService (legacy),
        # оборачиваем в AutocompleteServiceGui
        effective_service: AutocompleteServiceGui
        if autocomplete_service is None:
            effective_service = AutocompleteServiceGui()
        elif isinstance(autocomplete_service, AutocompleteServiceGui):
            effective_service = autocomplete_service
        elif isinstance(autocomplete_service, AutocompleteService):
            effective_service = AutocompleteServiceGui(core_service=autocomplete_service)
        else:
            effective_service = AutocompleteServiceGui()
        self._service: AutocompleteServiceGui = effective_service

        # Cross-document lookup service (provided from context / renderer)
        self._document_service: Optional[DocumentServiceProtocol] = document_service

        # Выпадающий popup
        self._popup: Optional[tk.Toplevel] = None
        self._suggestions_list: Optional[tk.Listbox] = None

        # Состояние
        self._current_query: str = ""
        self._selected_index: int = -1
        self._suggestions: list[tuple[str, int]] = []

        # Tkinter виджеты
        self._entry: Optional[tk.Entry] = None
        self._text_var: tk.StringVar = tk.StringVar()
        self._text_var.trace_add("write", self._on_text_change_trace)

        # Создаём содержимое после инициализации base_field
        self._create_content()

    def _create_content(self) -> None:
        """Создаёт виджеты поля ввода (entry + popup + lookup button)."""
        # Container for entry + button
        container = tk.Frame(self)
        container.pack(fill=tk.X, expand=True)

        self._entry = tk.Entry(
            container,
            textvariable=self._text_var,
            font=("Courier", 11),
            relief=tk.SUNKEN,
            borderwidth=1,
        )
        self._entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Lookup button (только если доступен document_service)
        self._lookup_btn: Optional[tk.Button] = None
        if self._document_service is not None:
            self._lookup_btn = tk.Button(
                container,
                text="📋 Lookup",
                command=self._show_lookup,
                font=("Courier", 9),
                relief=tk.RAISED,
                borderwidth=1,
            )
            self._lookup_btn.pack(side=tk.RIGHT, padx=(4, 0))

        # Навигация и выбор
        self._entry.bind("<KeyRelease>", self._on_key_release)
        self._entry.bind("<Down>", self._on_key_down)
        self._entry.bind("<Up>", self._on_key_up)
        self._entry.bind("<Return>", self._on_key_return)
        self._entry.bind("<Escape>", self._on_key_escape)
        self._entry.bind("<FocusOut>", self._on_focus_out)
        self._entry.bind("<Tab>", self._on_key_escape)
        self._entry.bind("<Control-space>", self._on_ctrl_space)

    def _parse_index(self, index: str) -> list[str]:
        """Парсит индекс в иерархию от общего к конкретному.

        Args:
            index: Полный индекс документа (DVN-44-K53-IX).

        Returns:
            Список уровней иерархии.

        Example:
            >>> self._parse_index("DVN-44-K53-IX")
            ['DVN', 'DVN-44', 'DVN-44-K53', 'DVN-44-K53-IX']
        """
        parts = index.split("-")
        hierarchy: list[str] = []
        for i in range(1, len(parts) + 1):
            hierarchy.append("-".join(parts[:i]))
        return hierarchy

    # ------------------------------------------------------------------
    # Debounced search
    # ------------------------------------------------------------------

    def _on_text_change_trace(self, *args: Any) -> None:
        """Обработчик trace_add write на StringVar."""
        _ = args
        self._on_text_change()

    def _on_text_change(self) -> None:
        """Запускает debounced поиск при изменении текста."""
        query = self._text_var.get()
        if len(query) >= self.MIN_CHARS:
            self._current_query = query
            self._service.search_async(
                field_id=self.field_id,
                document_index=self._document_index,
                query=query,
                limit=self.MAX_SUGGESTIONS,
                callback=self._on_search_results,
            )
        else:
            self._hide_popup()

    def _on_search_results(self, results: list[tuple[str, int]]) -> None:
        """Callback с результатами поиска.

        Args:
            results: Список (value, frequency).
        """
        if results and self._entry is not None:
            self._suggestions = results[: self.MAX_SUGGESTIONS]
            self._selected_index = -1
            self._show_popup(self._suggestions)
        else:
            self._hide_popup()

    # ------------------------------------------------------------------
    # Popup management
    # ------------------------------------------------------------------

    def _show_popup(self, suggestions: list[tuple[str, int]]) -> None:
        """Показывает popup со списком предложений.

        Args:
            suggestions: Список предложений.
        """
        if self._entry is None:
            return

        self._hide_popup()

        x = self._entry.winfo_rootx()
        y = self._entry.winfo_rooty() + self._entry.winfo_height()
        width = max(self._entry.winfo_width(), 200)

        self._popup = tk.Toplevel(self._entry)
        self._popup.wm_overrideredirect(True)
        self._popup.wm_geometry(f"{width}x150+{x}+{y}")
        self._popup.attributes("-topmost", True)

        self._suggestions_list = tk.Listbox(
            self._popup,
            font=("Courier", 10),
            selectmode=tk.SINGLE,
            activestyle="none",
        )
        self._suggestions_list.pack(fill=tk.BOTH, expand=True)

        for value, _freq in suggestions:
            self._suggestions_list.insert(tk.END, value)

        self._suggestions_list.bind("<ButtonRelease-1>", self._on_popup_select)
        self._suggestions_list.bind("<Return>", self._on_popup_select)
        self._suggestions_list.bind("<FocusOut>", self._on_popup_focus_out)

    def _hide_popup(self) -> None:
        """Скрывает popup и очищает ссылки."""
        if self._popup is not None:
            self._popup.destroy()
            self._popup = None
        self._suggestions_list = None
        self._suggestions = []
        self._selected_index = -1

    def _on_popup_focus_out(self, event: tk.Event[Any]) -> None:
        """Обработчик потери фокуса popup.

        Args:
            event: Событие Tkinter.
        """
        _ = event
        if self._entry is not None:
            self._entry.after(100, self._hide_popup)

    def _on_popup_select(self, event: tk.Event[Any]) -> None:
        """Обработчик выбора из popup мышью или Enter.

        Args:
            event: Событие Tkinter.
        """
        _ = event
        if self._suggestions_list is not None:
            selection = self._suggestions_list.curselection()  # type: ignore[no-untyped-call]
            if selection:
                index = int(selection[0])
                if 0 <= index < len(self._suggestions):
                    selected_value = self._suggestions[index][0]
                    self._text_var.set(selected_value)
                    self.set_value(selected_value)
        self._hide_popup()
        if self._entry is not None:
            self._entry.focus_set()

    # ------------------------------------------------------------------
    # Keyboard handlers
    # ------------------------------------------------------------------

    def _on_key_release(self, event: tk.Event[Any]) -> None:
        """Обработчик отпускания клавиши.

        Args:
            event: Событие клавиши.
        """
        if event.keysym in ("Up", "Down", "Return", "Escape", "Tab"):
            return
        self._on_text_change()

    def _on_key_down(self, event: tk.Event[Any]) -> Optional[str]:
        """Обработчик стрелки вниз.

        Args:
            event: Событие клавиши.

        Returns:
            "break" для остановки стандартной обработки.
        """
        _ = event
        if self._popup is not None and self._suggestions_list is not None:
            self._selected_index = min(self._selected_index + 1, len(self._suggestions) - 1)
            self._suggestions_list.selection_clear(0, tk.END)
            self._suggestions_list.selection_set(self._selected_index)
            self._suggestions_list.see(self._selected_index)
            return "break"
        return None

    def _on_key_up(self, event: tk.Event[Any]) -> Optional[str]:
        """Обработчик стрелки вверх.

        Args:
            event: Событие клавиши.

        Returns:
            "break" для остановки стандартной обработки.
        """
        _ = event
        if self._popup is not None and self._suggestions_list is not None:
            self._selected_index = max(self._selected_index - 1, 0)
            self._suggestions_list.selection_clear(0, tk.END)
            self._suggestions_list.selection_set(self._selected_index)
            self._suggestions_list.see(self._selected_index)
            return "break"
        return None

    def _on_key_return(self, event: tk.Event[Any]) -> Optional[str]:
        """Обработчик Enter.

        Args:
            event: Событие клавиши.

        Returns:
            "break" если выбор сделан из popup.
        """
        _ = event
        if self._popup is not None and self._selected_index >= 0:
            if 0 <= self._selected_index < len(self._suggestions):
                selected_value = self._suggestions[self._selected_index][0]
                self._text_var.set(selected_value)
                self.set_value(selected_value)
            self._hide_popup()
            return "break"
        return None

    def _on_ctrl_space(self, event: tk.Event[Any]) -> Optional[str]:
        """Обработчик Ctrl+Space для Cross Document Lookup.

        Args:
            event: Событие клавиши.

        Returns:
            "break" после показа lookup panel.
        """
        _ = event
        self._show_lookup()
        return "break"

    def _show_lookup(self) -> None:
        """Показывает CrossDocumentLookupDialog для поиска по документам."""
        if self._document_service is None:
            from tkinter import messagebox

            messagebox.showinfo(
                "Cross Document Lookup",
                f"Lookup для поля '{self.field_id}' недоступен: document_service не передан.",
                parent=self,
            )
            return

        self._hide_popup()

        def _on_lookup_select(selected_value: str) -> None:
            """Callback при выборе значения из lookup."""
            self.set_value(selected_value)
            if self._entry is not None:
                self._entry.focus_set()

        CrossDocumentLookupDialog(
            parent=self,
            document_service=self._document_service,
            field_id=self.field_id,
            document_index=self._document_index,
            on_select=_on_lookup_select,
        )

    def _on_key_escape(self, event: tk.Event[Any]) -> Optional[str]:
        """Обработчик Escape или Tab.

        Args:
            event: Событие клавиши.

        Returns:
            "break" если popup был скрыт.
        """
        _ = event
        if self._popup is not None:
            self._hide_popup()
            if self._entry is not None:
                self._entry.focus_set()
            return "break"
        return None

    def _on_focus_out(self, event: tk.Event[Any]) -> None:
        """Обработчик потери фокуса.

        Args:
            event: Событие Tkinter.
        """
        _ = event
        if self._entry is not None:
            self._entry.after(150, self._hide_popup)
            value = self._text_var.get()
            self.set_value(value)

    # ------------------------------------------------------------------
    # BaseField interface
    # ------------------------------------------------------------------

    def get_value(self) -> Any:
        """Возвращает текущее значение поля.

        Returns:
            Текущее строковое значение.
        """
        return self._value

    def set_value(self, value: Any) -> None:
        """Устанавливает значение поля.

        Args:
            value: Новое значение.
        """
        str_value = str(value) if value is not None else ""
        if self._entry is not None:
            current = self._text_var.get()
            if current != str_value:
                self._text_var.set(str_value)
        self._value = str_value
        if self._on_change is not None:
            self._on_change(self.field_id, str_value)

    def focus(self) -> None:
        """Устанавливает фокус на поле ввода."""
        if self._entry is not None:
            self._entry.focus_set()

    def validate(self) -> bool:
        """Валидирует значение поля.

        Returns:
            True если значение валидно.
        """
        if self._value is None or self._value == "":
            self._is_valid = True
            self.set_error(None)
            return True

        # Базовая валидация: поле не пустое если обязательное
        # (расширяется подклассами/потребителями)
        self._is_valid = True
        self.set_error(None)
        return True

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные.

        Security:
            Очищает значение, текст и закрывает popup.
        """
        if self._entry is not None:
            self._entry.delete(0, tk.END)
        self._text_var.set("")
        self._hide_popup()
        self._current_query = ""
        self._value = ""

    # ------------------------------------------------------------------
    # Legacy compatibility (FormField / BaseWidget)
    # ------------------------------------------------------------------

    def mount(self, parent: Optional[tk.Widget] = None) -> "AutocompleteEntry":
        """Legacy метод для совместимости с BaseWidget.

        Args:
            parent: Игнорируется (виджет уже смонтирован).

        Returns:
            self для цепочки вызовов.
        """
        return self


__all__: list[str] = ["AutocompleteEntry"]
