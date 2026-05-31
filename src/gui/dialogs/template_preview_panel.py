"""Standalone панель превью шаблона форм.

Предоставляет виджет для отображения информации о шаблоне,
его thumbnail и действий (создать документ, печать бланка).

Example:
    >>> panel = TemplatePreviewWidget(parent)
    >>> panel.load_template(template_data)
    >>> panel.on_new_document(lambda: print("New doc"))
    >>> panel.on_print_blank(lambda: print("Print"))

Version: 1.0
"""

from __future__ import annotations

import logging
import tkinter as tk
from typing import Any, Callable, Final, Optional

logger: Final = logging.getLogger(__name__)

# Colors
COLOR_BG: Final[str] = "#f8f9fa"
COLOR_HEADER: Final[str] = "#e9ecef"
COLOR_SUCCESS: Final[str] = "#28a745"
COLOR_ERROR: Final[str] = "#dc3545"

# Thumbnail size
THUMB_WIDTH: Final[int] = 240
THUMB_HEIGHT: Final[int] = 160


class TemplatePreviewWidget(tk.Frame):
    """Standalone widget предпросмотра шаблона.

    Attributes:
        _template_data: Данные текущего шаблона.
        _new_doc_callback: Callback на создание документа.
        _print_blank_callback: Callback на печать бланка.

    Example:
        >>> widget = TemplatePreviewWidget(parent)
        >>> widget.load_template({"name": "Invoice", "fields": 15})
    """

    def __init__(
        self,
        parent: tk.Widget,
        template_data: Optional[dict[str, Any]] = None,
    ) -> None:
        """Инициализация виджета.

        Args:
            parent: Родительский виджет.
            template_data: Начальные данные шаблона.
        """
        super().__init__(parent, bg=COLOR_BG, padx=10, pady=10)

        self._template_data: dict[str, Any] = template_data or {}
        self._new_doc_callback: Optional[Callable[[], None]] = None
        self._print_blank_callback: Optional[Callable[[], None]] = None

        self._create_ui()
        if self._template_data:
            self.load_template(self._template_data)

    def _create_ui(self) -> None:
        """Создаёт UI компоненты."""
        # Header — название шаблона
        self._name_var = tk.StringVar(master=self, value="No template selected")
        header = tk.Label(
            self,
            textvariable=self._name_var,
            font=("Arial", 12, "bold"),
            bg=COLOR_BG,
            fg="#2c3e50",
        )
        header.pack(anchor=tk.W, pady=(0, 10))

        # Thumbnail canvas
        self._thumb_canvas = tk.Canvas(
            self,
            width=THUMB_WIDTH,
            height=THUMB_HEIGHT,
            bg="#ffffff",
            highlightthickness=1,
            highlightbackground="#dee2e6",
        )
        self._thumb_canvas.pack(anchor=tk.W, pady=(0, 10))
        self._draw_placeholder()

        # Info frame
        info_frame = tk.Frame(self, bg=COLOR_BG)
        info_frame.pack(fill=tk.X, pady=(0, 10))

        # Fields count
        tk.Label(
            info_frame,
            text="Fields:",
            font=("Arial", 10, "bold"),
            bg=COLOR_BG,
        ).grid(row=0, column=0, sticky=tk.W, pady=2)
        self._fields_var = tk.StringVar(master=self, value="0")
        tk.Label(
            info_frame,
            textvariable=self._fields_var,
            font=("Arial", 10),
            bg=COLOR_BG,
        ).grid(row=0, column=1, sticky=tk.W, padx=(10, 0), pady=2)

        # Signature status
        tk.Label(
            info_frame,
            text="Signature:",
            font=("Arial", 10, "bold"),
            bg=COLOR_BG,
        ).grid(row=1, column=0, sticky=tk.W, pady=2)
        self._sig_var = tk.StringVar(master=self, value="—")
        self._sig_label = tk.Label(
            info_frame,
            textvariable=self._sig_var,
            font=("Arial", 10),
            bg=COLOR_BG,
        )
        self._sig_label.grid(row=1, column=1, sticky=tk.W, padx=(10, 0), pady=2)

        # Buttons
        btn_frame = tk.Frame(self, bg=COLOR_BG)
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        self._new_doc_btn = tk.Button(
            btn_frame,
            text="📄 New Document",
            command=self._trigger_new_document,
            bg="#0078d4",
            fg="#ffffff",
            activebackground="#005a9e",
        )
        self._new_doc_btn.pack(side=tk.LEFT, padx=(0, 5))

        self._print_btn = tk.Button(
            btn_frame,
            text="🖨️ Print Blank",
            command=self._trigger_print_blank,
            bg="#6c757d",
            fg="#ffffff",
            activebackground="#545b62",
        )
        self._print_btn.pack(side=tk.LEFT)

    def _draw_placeholder(self) -> None:
        """Рисует placeholder на thumbnail canvas."""
        self._thumb_canvas.delete("all")
        self._thumb_canvas.create_text(
            THUMB_WIDTH // 2,
            THUMB_HEIGHT // 2,
            text="[Preview]",
            fill="#adb5bd",
            font=("Arial", 14),
        )

    def _draw_thumbnail(self, thumbnail_data: Optional[bytes]) -> None:
        """Рисует реальный thumbnail или placeholder.

        Args:
            thumbnail_data: Бинарные данные изображения или None.
        """
        self._thumb_canvas.delete("all")
        if thumbnail_data is None:
            self._draw_placeholder()
            return
        # В будущем можно использовать PhotoImage(data=thumbnail_data)
        # Пока отображаем placeholder с подписью
        self._thumb_canvas.create_text(
            THUMB_WIDTH // 2,
            THUMB_HEIGHT // 2,
            text="[Image Preview]",
            fill="#495057",
            font=("Arial", 14),
        )

    def load_template(self, template_data: dict[str, Any]) -> None:
        """Загружает данные шаблона в виджет.

        Args:
            template_data: Словарь с полями:
                - name (str): Название шаблона.
                - fields (int): Количество полей.
                - signature_valid (bool): Статус подписи.
                - thumbnail (Optional[bytes]): Данные thumbnail.
        """
        self._template_data = template_data

        name = template_data.get("name", "Untitled")
        self._name_var.set(str(name))

        fields = template_data.get("fields", 0)
        self._fields_var.set(str(fields))

        sig_valid = template_data.get("signature_valid")
        if sig_valid is True:
            self._sig_var.set("✓ Valid")
            self._sig_label.config(fg=COLOR_SUCCESS)
        elif sig_valid is False:
            self._sig_var.set("✗ Invalid")
            self._sig_label.config(fg=COLOR_ERROR)
        else:
            self._sig_var.set("—")
            self._sig_label.config(fg="#495057")

        thumbnail = template_data.get("thumbnail")
        self._draw_thumbnail(thumbnail)

        logger.debug("TemplatePreviewWidget loaded: %s", name)

    def on_new_document(self, callback: Callable[[], None]) -> None:
        """Устанавливает callback для создания нового документа.

        Args:
            callback: Функция без аргументов.
        """
        self._new_doc_callback = callback

    def on_print_blank(self, callback: Callable[[], None]) -> None:
        """Устанавливает callback для печати бланка.

        Args:
            callback: Функция без аргументов.
        """
        self._print_blank_callback = callback

    def _trigger_new_document(self) -> None:
        """Триггерит callback создания документа."""
        if self._new_doc_callback is not None:
            try:
                self._new_doc_callback()
            except (ValueError, TypeError, AttributeError, RuntimeError) as exc:
                logger.error("Ошибка в callback new_document: %s", exc)

    def _trigger_print_blank(self) -> None:
        """Триггерит callback печати бланка."""
        if self._print_blank_callback is not None:
            try:
                self._print_blank_callback()
            except (ValueError, TypeError, AttributeError, RuntimeError) as exc:
                logger.error("Ошибка в callback print_blank: %s", exc)


__all__ = [
    "TemplatePreviewWidget",
    "THUMB_WIDTH",
    "THUMB_HEIGHT",
]
