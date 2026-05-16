"""Виджет предпросмотра ESC/P вывода.

Модуль предоставляет виджет для отображения рендеренного ESC/P
документа в читаемом виде с навигацией по страницам.

Features:
    - Отображение ESC/P байтов как читаемого текста
    - Навигация по страницам (Prev/Next)
    - Подсветка ESC команд
    - Интеграция с DocumentRenderer

Example:
    >>> from src.documents.printing.document_renderer import DocumentRenderer
    >>> preview = ESCPPreviewWidget(
    ...     parent=parent_frame,
    ...     document_renderer=DocumentRenderer(),
    ... )
    >>> preview.show_document(document)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING, Final, Optional

if TYPE_CHECKING:
    from src.documents.printing.document_renderer import (
        DocumentRenderer,
        RenderSettings,
    )
    from src.model.document import Document

logger: Final = logging.getLogger(__name__)

# Colors for ESC/P preview
PREVIEW_BG_COLOR: Final[str] = "#1e1e1e"  # Dark background
PREVIEW_FG_COLOR: Final[str] = "#d4d4d4"  # Light text
PREVIEW_CMD_COLOR: Final[str] = "#569cd6"  # Blue for commands
PREVIEW_FF_COLOR: Final[str] = "#ce9178"  # Orange for form feed
PREVIEW_SELECT_BG: Final[str] = "#264f78"  # Selection background
PREVIEW_FONT: Final[tuple[str, int]] = ("Courier New", 10)
PREVIEW_CMD_FONT: Final[tuple[str, int, str]] = ("Courier New", 10, "bold")

# Constants
ESC_BYTE: Final[int] = 0x1B
FF_BYTE: Final[int] = 0x0C
CR_BYTE: Final[int] = 0x0D
LF_BYTE: Final[int] = 0x0A


class ESCPPreviewWidget(tk.Frame):
    """Виджет предпросмотра ESC/P вывода.

    Отображает документ, рендеренный в ESC/P байты, в читаемом
    виде с подсветкой команд и навигацией по страницам.

    Attributes:
        _renderer: DocumentRenderer для рендеринга документов.
        _current_document: Текущий отображаемый документ.
        _current_page: Номер текущей страницы (0-based).
        _page_count: Общее количество страниц.

    Example:
        >>> preview = ESCPPreviewWidget(parent, document_renderer)
        >>> preview.show_document(document)
        >>> preview.next_page()
    """

    def __init__(
        self,
        parent: tk.Widget,
        document_renderer: "DocumentRenderer",
    ) -> None:
        """Инициализация виджета предпросмотра.

        Args:
            parent: Родительский виджет.
            document_renderer: Рендерер документов для генерации ESC/P.
        """
        super().__init__(parent)
        self._renderer = document_renderer
        self._current_document: Optional["Document"] = None
        self._current_page: int = 0
        self._page_count: int = 1

        # Configure grid
        self.rowconfigure(0, weight=0)  # Navigation bar
        self.rowconfigure(1, weight=1)  # Text widget
        self.columnconfigure(0, weight=1)

        self._create_widgets()
        self._setup_bindings()

    def _create_widgets(self) -> None:
        """Создаёт UI компоненты."""
        # Navigation frame
        self._nav_frame = ttk.Frame(self)
        self._nav_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)

        # Previous page button
        self._prev_btn = ttk.Button(
            self._nav_frame,
            text="← Back",
            command=self._prev_page,
        )
        self._prev_btn.pack(side=tk.LEFT, padx=5)

        # Page label
        self._page_label = ttk.Label(
            self._nav_frame,
            text="Page 1/1",
            font=("Segoe UI", 10),
        )
        self._page_label.pack(side=tk.LEFT, padx=10)

        # Next page button
        self._next_btn = ttk.Button(
            self._nav_frame,
            text="Next →",
            command=self._next_page,
        )
        self._next_btn.pack(side=tk.LEFT, padx=5)

        # Spacer
        ttk.Label(self._nav_frame, text="").pack(side=tk.LEFT, expand=True)

        # Settings label
        self._settings_label = ttk.Label(
            self._nav_frame,
            text="CPI: 10 | LPI: 6 | Draft",
            font=("Segoe UI", 9),
            foreground="#666666",
        )
        self._settings_label.pack(side=tk.RIGHT, padx=5)

        # Text widget for preview
        self._text_widget = tk.Text(
            self,
            wrap=tk.NONE,
            font=PREVIEW_FONT,
            bg=PREVIEW_BG_COLOR,
            fg=PREVIEW_FG_COLOR,
            selectbackground=PREVIEW_SELECT_BG,
            insertbackground=PREVIEW_FG_COLOR,
            padx=10,
            pady=10,
        )
        self._text_widget.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

        # Scrollbars
        self._v_scroll = ttk.Scrollbar(
            self,
            orient=tk.VERTICAL,
            command=self._text_widget.yview,
        )
        self._v_scroll.grid(row=1, column=1, sticky="ns")

        self._h_scroll = ttk.Scrollbar(
            self,
            orient=tk.HORIZONTAL,
            command=self._text_widget.xview,
        )
        self._h_scroll.grid(row=2, column=0, sticky="ew")

        self._text_widget.configure(
            yscrollcommand=self._v_scroll.set,
            xscrollcommand=self._h_scroll.set,
        )

        # Configure tags
        self._text_widget.tag_configure(
            "esc_command",
            foreground=PREVIEW_CMD_COLOR,
            font=PREVIEW_CMD_FONT,
        )
        self._text_widget.tag_configure(
            "form_feed",
            foreground=PREVIEW_FF_COLOR,
            font=PREVIEW_CMD_FONT,
        )

    def _setup_bindings(self) -> None:
        """Настраивает keyboard bindings."""
        self._text_widget.bind("<Prior>", lambda e: self._prev_page())  # Page Up
        self._text_widget.bind("<Next>", lambda e: self._next_page())  # Page Down
        self._text_widget.bind("<Home>", lambda e: self._first_page())  # Home
        self._text_widget.bind("<End>", lambda e: self._last_page())  # End

    def show_document(
        self,
        document: "Document",
        settings: Optional["RenderSettings"] = None,
    ) -> None:
        """Отображает документ в режиме предпросмотра.

        Args:
            document: Документ для отображения.
            settings: Настройки рендеринга (опционально).
        """
        self._current_document = document
        self._current_page = 0
        self._page_count = self._renderer.get_page_count(document, settings)

        # Update settings label
        if settings:
            self._settings_label.configure(
                text=f"CPI: {settings.cpi.value} | "
                f"LPI: {settings.lpi.value} | "
                f"{settings.quality.value}"
            )

        self._render_current_page(settings)

    def _render_current_page(
        self,
        settings: Optional["RenderSettings"] = None,
    ) -> None:
        """Рендерит и отображает текущую страницу.

        Args:
            settings: Настройки рендеринга.
        """
        if self._current_document is None:
            return

        # Get ESC/P bytes for current page
        escp_bytes = self._renderer.render_page(
            self._current_document,
            self._current_page,
            settings,
        )

        # Convert to readable preview
        preview_content = self._escp_to_preview(escp_bytes)

        # Update UI
        self._text_widget.delete("1.0", tk.END)
        self._insert_with_tags(preview_content)

        # Update navigation
        self._page_label.configure(text=f"Page {self._current_page + 1}/{self._page_count}")
        self._prev_btn.configure(state=tk.NORMAL if self._current_page > 0 else tk.DISABLED)
        self._next_btn.configure(
            state=tk.NORMAL if self._current_page < self._page_count - 1 else tk.DISABLED
        )

        logger.debug(
            f"Rendered page {self._current_page + 1}/{self._page_count}, {len(escp_bytes)} bytes"
        )

    def _escp_to_preview(self, escp_bytes: bytes) -> list[tuple[str, str]]:
        """Конвертирует ESC/P байты в читаемое представление.

        Args:
            escp_bytes: ESC/P байты для конвертации.

        Returns:
            Список кортежей (текст, тег) для вставки.
        """
        result: list[tuple[str, str]] = []
        i = 0

        while i < len(escp_bytes):
            byte = escp_bytes[i]

            if byte == ESC_BYTE:  # ESC command
                if i + 1 < len(escp_bytes):
                    cmd = escp_bytes[i + 1]
                    # Check for parameterized commands
                    if cmd >= 0x20 and cmd <= 0x7E:
                        # Parameterized command, look for terminator
                        param_start = i + 2
                        param_end = param_start
                        while param_end < len(escp_bytes):
                            if escp_bytes[param_end] < 0x20:
                                break
                            param_end += 1
                        param = escp_bytes[param_start:param_end]
                        result.append((f"[ESC 0x{cmd:02X} {param.hex().upper()}]", "esc_command"))
                        i = param_end
                    else:
                        result.append((f"[ESC 0x{cmd:02X}]", "esc_command"))
                        i += 2
                else:
                    result.append(("[ESC]", "esc_command"))
                    i += 1

            elif byte == FF_BYTE:  # Form feed
                result.append(("[FF - Page Break]\n", "form_feed"))
                i += 1

            elif byte == CR_BYTE:  # Carriage return
                # Usually followed by LF, skip if so
                if i + 1 < len(escp_bytes) and escp_bytes[i + 1] == LF_BYTE:
                    result.append(("\n", ""))
                    i += 2
                else:
                    i += 1

            elif byte == LF_BYTE:  # Line feed
                result.append(("\n", ""))
                i += 1

            elif 32 <= byte < 127:  # Printable ASCII
                result.append((chr(byte), ""))
                i += 1

            else:  # Non-printable
                result.append((f"[0x{byte:02X}]", "esc_command"))
                i += 1

        return result

    def _insert_with_tags(self, content: list[tuple[str, str]]) -> None:
        """Вставляет текст с тегами форматирования.

        Args:
            content: Список кортежей (текст, тег).
        """
        for text, tag in content:
            if tag:
                self._text_widget.insert(tk.END, text, tag)
            else:
                self._text_widget.insert(tk.END, text)

    def _prev_page(self) -> None:
        """Переходит на предыдущую страницу."""
        if self._current_page > 0:
            self._current_page -= 1
            self._render_current_page()

    def _next_page(self) -> None:
        """Переходит на следующую страницу."""
        if self._current_page < self._page_count - 1:
            self._current_page += 1
            self._render_current_page()

    def _first_page(self) -> None:
        """Переходит на первую страницу."""
        if self._current_page != 0:
            self._current_page = 0
            self._render_current_page()

    def _last_page(self) -> None:
        """Переходит на последнюю страницу."""
        if self._current_page != self._page_count - 1:
            self._current_page = self._page_count - 1
            self._render_current_page()

    def get_current_page(self) -> int:
        """Возвращает номер текущей страницы.

        Returns:
            Номер страницы (0-based).
        """
        return self._current_page

    def get_page_count(self) -> int:
        """Возвращает общее количество страниц.

        Returns:
            Количество страниц.
        """
        return self._page_count

    def clear(self) -> None:
        """Очищает виджет."""
        self._text_widget.delete("1.0", tk.END)
        self._current_document = None
        self._current_page = 0
        self._page_count = 1
        self._page_label.configure(text="Page 1/1")


__all__ = ["ESCPPreviewWidget", "PREVIEW_BG_COLOR", "PREVIEW_FG_COLOR"]
