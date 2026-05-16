"""Диалог предпросмотра печати для FX Text Processor 3.

Модуль обеспечивает визуализацию рендеренного ESC/P вывода перед отправкой
на принтер, позволяя пользователю проверить разметку и навигацию по страницам.

Version: 1.0
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Optional

from src.documents.printing.document_renderer import DocumentRenderer, RenderSettings
from src.gui.components.escp_preview_widget import ESCPPreviewWidget
from src.gui.dialogs.base_dialog import BaseDialog
from src.gui.layout.layout_constants import PADDING_NORMAL, PADDING_SMALL
from src.model.document import Document


class PrintPreviewDialog(BaseDialog):
    """Диалог полноэкранного предпросмотра документа перед печатью.

    Отображает рендеринг документа в ESC/P байты с использованием
    ESCPPreviewWidget и предоставляет быстрый доступ к диалогу печати.

    Attributes:
        _renderer: DocumentRenderer для генерации ESC/P данных.
        _document: Текущий документ для предпросмотра.
        _preview_widget: Виджет предпросмотра.
    """

    def __init__(
        self,
        parent: tk.Widget,
        document: Document,
        document_renderer: DocumentRenderer,
        theme: str = "classic_green",
        **kwargs: Any,
    ):
        """Инициализация диалога предпросмотра.

        Args:
            parent: Родительский виджет.
            document: Документ для отображения.
            document_renderer: Рендерер документов в ESC/P.
            theme: Theme оформления.
        """
        kwargs.pop("theme", None)  # theme не передаём в Toplevel
        super().__init__(parent, title="Print Preview", **kwargs)
        self._theme = theme
        self._document = document
        self._renderer = document_renderer
        self._preview_widget: Optional[ESCPPreviewWidget] = None

        self._create_ui()
        self._setup_preview()

    def _create_ui(self) -> None:
        """Создаёт интерфейс диалога."""
        # Основной контейнер
        self.main_container = ttk.Frame(self)
        self.main_container.pack(
            fill=tk.BOTH,
            expand=True,
            padx=PADDING_NORMAL,
            pady=PADDING_NORMAL,
        )

        # Верхняя панель инструментов
        self.toolbar = ttk.Frame(self.main_container)
        self.toolbar.pack(fill=tk.X, side=tk.TOP, pady=PADDING_SMALL)

        self.btn_print = ttk.Button(self.toolbar, text="Print...", command=self._on_print_clicked)
        self.btn_print.pack(side=tk.LEFT, padx=PADDING_SMALL)

        self.btn_close = ttk.Button(
            self.toolbar, text="Close", command=lambda: self.close(result=None)
        )
        self.btn_close.pack(side=tk.RIGHT, padx=PADDING_SMALL)

        # Область предпросмотра (в отдельном фрейме для скроллинга/отступов)
        self.preview_frame = ttk.Frame(self.main_container)
        self.preview_frame.pack(fill=tk.BOTH, expand=True, pady=PADDING_NORMAL)

    def _setup_preview(self) -> None:
        """Инициализирует и настраивает виджет предпросмотра."""
        self._preview_widget = ESCPPreviewWidget(
            parent=self.preview_frame, document_renderer=self._renderer
        )
        self._preview_widget.pack(fill=tk.BOTH, expand=True)

        # Рендерим документ с настройками по умолчанию
        settings = RenderSettings()
        self._preview_widget.show_document(self._document, settings)

    def _on_print_clicked(self) -> None:
        """Обработчик перехода к основному диалогу печати."""
        # В данном контексте закрываем preview и через callback родителя
        # или AppController открываем PrintDialog.
        # Поскольку диалог модальный, мы просто закрываем его с результатом 'print'.
        self.close(result="print")

    def show(self) -> Optional[str]:
        """Показывает диалог предпросмотра.

        Returns:
            'print' если нажата кнопка Печать, None иначе.
        """
        super().show()
        result = self.get_result()
        if isinstance(result, str):
            return result
        return None
