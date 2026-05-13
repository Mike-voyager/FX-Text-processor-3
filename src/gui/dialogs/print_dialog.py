"""Диалог печати для FX Text Processor 3.

Предоставляет полноценный интерфейс настроек печати, включая выбор принтера,
настройку копий, приоритетов, предпросмотр и генерацию тестовых страниц.

Version: 1.0
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Dict, List, Optional

from src.documents.printing.document_renderer import DocumentRenderer, RenderSettings
from src.gui.components.escp_preview_widget import ESCPPreviewWidget
from src.gui.dialogs.base_dialog import BaseDialog
from src.gui.dialogs.print_settings import PrintDialogResult, PrintSettings
from src.gui.layout.layout_constants import PADDING_NORMAL, PADDING_SMALL
from src.model.document import Document
from src.printer.printer_manager import PrinterInfo, PrinterManager
from src.services.print_queue_service import PrintPriority, PrintQueueService


class PrintDialog(BaseDialog):
    """Диалог настройки печати.

    Позволяет выбрать принтер из доступных адаптеров, настроить количество копий,
    приоритет задания, просмотреть рендер документа в ESC/P и запустить печать.

    Attributes:
        _printer_manager: Менеджер принтеров для выбора устройств.
        _document: Документ, отправляемый на печать.
        _renderer: Рендерер для генерации ESC/P данных.
        _print_queue: Сервис управления очередью печати.
        _settings_vars: Словарь переменных tkinter для хранения текущих настроек.
        _preview_widget: Виджет предпросмотра ESC/P.
    """

    def __init__(
        self,
        parent: tk.Widget,
        printer_manager: PrinterManager,
        document: Document,
        document_renderer: DocumentRenderer,
        print_queue: PrintQueueService,
        theme: str = "classic_green",
        **kwargs,
    ):
        """Инициализация диалога печати.

        Args:
            parent: Родительский виджет.
            printer_manager: Менеджер принтеров.
            document: Документ для печати.
            document_renderer: Рендерер документов.
            print_queue: Сервис очереди печати.
            theme: Тема оформления.
        """
        kwargs.pop("theme", None)  # theme не передаём в Toplevel
        super().__init__(parent, title="Печать", **kwargs)

        self._theme = theme
        self._printer_manager = printer_manager
        self._document = document
        self._renderer = document_renderer
        self._print_queue = print_queue

        self._settings_vars: Dict[str, Any] = {}
        self._preview_widget: Optional[ESCPPreviewWidget] = None
        self._available_printers: List[PrinterInfo] = []

        self._create_ui()
        self._initialize_defaults()

    def _create_ui(self) -> None:
        """Создаёт интерфейс диалога на основе ttk.Notebook."""
        self.main_container = ttk.Frame(self)
        self.main_container.pack(
            fill=tk.BOTH,
            expand=True,
            padx=PADDING_NORMAL,
            pady=PADDING_NORMAL,
        )

        # Вкладки настроек
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Создание вкладок
        self._tab_printer = ttk.Frame(self.notebook)
        self._tab_params = ttk.Frame(self.notebook)
        self._tab_test = ttk.Frame(self.notebook)
        self._tab_preview = ttk.Frame(self.notebook)

        self.notebook.add(self._tab_printer, text="Принтер")
        self.notebook.add(self._tab_params, text="Параметры документа")
        self.notebook.add(self._tab_test, text="Тест")
        self.notebook.add(self._tab_preview, text="Предпросмотр")

        self._build_printer_tab()
        self._build_params_tab()
        self._build_test_tab()
        self._build_preview_tab()

        # Нижняя панель с кнопками
        self.button_frame = ttk.Frame(self.main_container)
        self.button_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=PADDING_SMALL)

        self.btn_cancel = ttk.Button(
            self.button_frame, text="Отмена", command=lambda: self.close(result=None)
        )
        self.btn_cancel.pack(side=tk.RIGHT, padx=PADDING_SMALL)

        self.btn_print = ttk.Button(
            self.button_frame, text="Печать", command=self._on_print_clicked
        )
        self.btn_print.pack(side=tk.RIGHT, padx=PADDING_SMALL)

    def _build_printer_tab(self) -> None:
        """Создаёт интерфейс вкладки выбора принтера."""
        container = ttk.Frame(self._tab_printer)
        container.pack(fill=tk.BOTH, expand=True, padx=PADDING_NORMAL, pady=PADDING_NORMAL)

        # Секция выбора адаптера и принтера
        adapter_frame = ttk.LabelFrame(container, text="Выбор устройства")
        adapter_frame.pack(fill=tk.X, pady=PADDING_SMALL)

        ttk.Label(adapter_frame, text="Адаптер:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self._settings_vars["adapter"] = tk.StringVar(master=self, value="Все")
        self.adapter_combo = ttk.Combobox(
            adapter_frame,
            textvariable=self._settings_vars["adapter"],
            values=["Все", "cups", "win32", "file"],
            state="readonly",
        )
        self.adapter_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.adapter_combo.bind("<<ComboboxSelected>>", self._update_printer_list)

        ttk.Label(adapter_frame, text="Принтер:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self._settings_vars["printer_id"] = tk.StringVar()
        self.printer_combo = ttk.Combobox(
            adapter_frame, textvariable=self._settings_vars["printer_id"], state="readonly"
        )
        self.printer_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)

        # Секция дополнительных настроек
        opts_frame = ttk.LabelFrame(container, text="Опции печати")
        opts_frame.pack(fill=tk.X, pady=PADDING_SMALL)

        ttk.Label(opts_frame, text="Копии:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self._settings_vars["copies"] = tk.IntVar(master=self, value=1)
        self.copies_spin = ttk.Spinbox(
            opts_frame, from_=1, to=99, textvariable=self._settings_vars["copies"], width=5
        )
        self.copies_spin.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Label(opts_frame, text="Приоритет:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self._settings_vars["priority"] = tk.StringVar(master=self, value=PrintPriority.NORMAL.name)
        self.priority_combo = ttk.Combobox(
            opts_frame,
            textvariable=self._settings_vars["priority"],
            values=[p.name for p in PrintPriority],
            state="readonly",
        )
        self.priority_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)

        self._settings_vars["page_by_page"] = tk.BooleanVar(master=self, value=False)
        self.page_by_page_check = ttk.Checkbutton(
            opts_frame, text="Постраничная печать", variable=self._settings_vars["page_by_page"]
        )
        self.page_by_page_check.grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)

    def _build_params_tab(self) -> None:
        """Создает вкладку read-only параметров документа."""
        container = ttk.Frame(self._tab_params)
        container.pack(fill=tk.BOTH, expand=True, padx=PADDING_NORMAL, pady=PADDING_NORMAL)

        settings = RenderSettings()  # Дефолтные настройки

        info_frame = ttk.LabelFrame(container, text="Текущие настройки документа")
        info_frame.pack(fill=tk.X, pady=PADDING_SMALL)

        paper = getattr(settings, "paper_type", None)
        paper_str = paper.name if paper else "Стандарт"

        params = [
            ("CPI", f"{settings.cpi.value} CPI"),
            ("Качество", f"{settings.quality.name}"),
            ("Кодовая страница", f"{settings.codepage.name}"),
            ("Поля", f"L: {settings.margins.left}, R: {settings.margins.right}"),
            ("Тип бумаги", paper_str),
        ]

        for i, (label, value) in enumerate(params):
            ttk.Label(info_frame, text=f"{label}:").grid(
                row=i,
                column=0,
                sticky=tk.W,
                padx=5,
                pady=2,
            )
            ttk.Label(info_frame, text=value).grid(
                row=i,
                column=1,
                sticky=tk.W,
                padx=5,
                pady=2,
            )

        hint_label = ttk.Label(
            container,
            text="Для изменения настроек используйте Format Toolbar или Page Setup Dialog",
            foreground="grey",
            font=("Arial", 9, "italic"),
        )
        hint_label.pack(pady=PADDING_NORMAL)

    def _build_test_tab(self) -> None:
        """Создаёт вкладку тестовой печати."""
        container = ttk.Frame(self._tab_test)
        container.pack(fill=tk.BOTH, expand=True, padx=PADDING_NORMAL, pady=PADDING_NORMAL)

        info_text = (
            "Тестовая страница ESC/P проверяет корректность связи с принтером\n"
            "и правильность интерпретации команд. Включает:\n"
            "• ESC @ (Сброс принтера)\n"
            "• Таблицу символов выбранной кодировки\n"
            "• Тест различных CPI и стилей шрифта"
        )
        ttk.Label(container, text=info_text, justify=tk.LEFT).pack(pady=PADDING_NORMAL, anchor=tk.W)

        self._settings_vars["print_test_page"] = tk.BooleanVar(master=self, value=False)
        self.btn_test_print = ttk.Button(
            container, text="Печать тестовой страницы", command=self._on_test_print_clicked
        )
        self.btn_test_print.pack(pady=PADDING_NORMAL)

    def _build_preview_tab(self) -> None:
        """Создаёт вкладку предпросмотра."""
        self.preview_container = ttk.Frame(self._tab_preview)
        self.preview_container.pack(fill=tk.BOTH, expand=True)

        # Виджет создаётся, но show_document будет вызван при переключении вкладки
        self._preview_widget = ESCPPreviewWidget(
            parent=self.preview_container, document_renderer=self._renderer
        )
        self._preview_widget.pack(fill=tk.BOTH, expand=True)

        # Подписываемся на изменение вкладок
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

    def _initialize_defaults(self) -> None:
        """Инициализирует значения по умолчанию."""
        self._update_printer_list()

        if self._available_printers:
            default_printer = self._available_printers[0]
            self._settings_vars["printer_id"].set(default_printer.printer_id)

    def _update_printer_list(self, event: Optional[Any] = None) -> None:
        """Обновляет список доступных принтеров на основе выбранного адаптера."""
        selected_adapter = self._settings_vars["adapter"].get()

        # Получаем все доступные принтеры
        all_printers = self._printer_manager.get_available_printers()

        if selected_adapter == "Все":
            self._available_printers = all_printers
        else:
            self._available_printers = [
                p for p in all_printers if p.adapter_type == selected_adapter
            ]

        # Обновляем Combobox
        printer_names = [p.name for p in self._available_printers]
        self.printer_combo["values"] = printer_names

        if printer_names:
            # Пытаемся сохранить текущий выбор или выбрать первый
            current_id = self._settings_vars["printer_id"].get()
            if any(p.printer_id == current_id for p in self._available_printers):
                printer = next(p for p in self._available_printers if p.printer_id == current_id)
                self.printer_combo.set(printer.name)
            else:
                self.printer_combo.set(printer_names[0])
        else:
            self.printer_combo.set("")

    def _on_tab_changed(self, event: Any) -> None:
        """Обновляет содержимое вкладок при переключении."""
        tab_id = self.notebook.index(self.notebook.select())
        if tab_id == 3:  # Tab Предпросмотр
            if self._preview_widget:
                self._preview_widget.show_document(self._document)

    def _on_test_print_clicked(self) -> None:
        """Обработка кнопки печати тестовой страницы."""
        self._settings_vars["print_test_page"].set(True)
        # Сразу закрываем диалог с результатом "печать теста", чтобы AppController обработал это
        self.close(result=self._build_result())

    def _on_print_clicked(self) -> None:
        """Обработка кнопки Печать."""
        # Валидация выбора принтера
        if not self._settings_vars["printer_id"].get():
            # Здесь можно добавить toast или MessageBox
            return

        self.close(result=self._build_result())

    def _build_result(self) -> PrintDialogResult:
        """Формирует результат диалога на основе значений переменных."""
        selected_name = self.printer_combo.get()
        # Находим printer_id по имени
        printer_id = next(
            (p.printer_id for p in self._available_printers if p.name == selected_name), ""
        )

        settings = PrintSettings(
            printer_id=printer_id,
            adapter_id=self._settings_vars["adapter"].get(),
            copies=int(self.copies_spin.get()),
            priority=PrintPriority[self.priority_combo.get()],
            page_by_page=self._settings_vars["page_by_page"].get(),
            print_test_page=self._settings_vars["print_test_page"].get(),
            document_id=self._document.id if hasattr(self._document, "id") else None,
        )

        return PrintDialogResult(settings=settings)

    def show(self) -> Optional[PrintDialogResult]:
        """Показывает диалог и возвращает настройки печати.

        Returns:
            PrintDialogResult если пользователь нажал Печать, None иначе.
        """
        super().show()
        return self.get_result()
