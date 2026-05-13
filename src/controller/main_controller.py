"""Главный контроллер FX Text Processor 3.

Реализует паттерн MVC с координацией между View и Service слоями.
Управляет жизненным циклом приложения, глобальным состоянием
и обработкой меню/тулбаров.

Architecture:
    Controller → координация View ↔ Service, NO сложная логика
    Service Layer → вся бизнес-логика, DI через конструктор
    View → только callbacks к Controller

Example:
    >>> from src.controller.main_controller import MainController
    >>> controller = MainController(
    ...     auth_service=auth_service,
    ...     document_service=doc_service,
    ...     print_service=print_service,
    ...     session_manager=session_manager,
    ...     theme_manager=theme_manager,
    ... )
    >>> controller.start()

Dependencies (DI):
    - AuthService: аутентификация и авторизация
    - DocumentService: операции с документами
    - PrintService: печать и предпросмотр
    - SessionManager: управление сессиями
    - ThemeManager: управление темами
"""

from __future__ import annotations

import logging
import tkinter as tk
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from uuid import UUID

from src.gui.dialogs.paper_setup import PaperConfig, PaperSetupDialog
from src.gui.dialogs.font_dialog import FontDialog
from src.gui.dialogs.paragraph_dialog import ParagraphDialog
from src.gui.dialogs.digital_signature_dialog import DigitalSignatureDialog
from src.gui.views.main_window import MainWindow
from src.model.document import PageSettings
from src.model.enums import FontFamily, LineSpacing as ModelLineSpacing, Orientation as ModelOrientation, PageSize as ModelSize
from src.model.enums import Alignment, CharactersPerInch, PrintQuality, TextStyle
from src.services.paper_format_service import Orientation, PaperSize

if TYPE_CHECKING:
    from src.controller.auth_controller import AuthController
    from src.controller.document_controller import DocumentController
    from src.controller.form_controller import FormController
    from src.controller.print_controller import PrintController
    from src.controller.workflow_controller import WorkflowController
    from src.view.themes import ThemeManager


class ApplicationState:
    """Глобальное состояние приложения.

    Attributes:
        current_document: UUID активного документа
        open_documents: Список открытых документов
        last_directory: Последняя использованная директория
        is_modified: Флаг изменения документа
        zoom_level: Текущий уровень масштаба (проценты)
    """

    def __init__(self) -> None:
        """Инициализирует состояние приложения."""
        self.current_document: Optional[UUID] = None
        self.open_documents: List[UUID] = []
        self.last_directory: Path = Path.home()
        self.is_modified: bool = False
        self.zoom_level: int = 100
        self.sidebar_visible: bool = True
        self.status_bar_visible: bool = True

    def set_active_document(self, doc_id: Optional[UUID]) -> None:
        """Устанавливает активный документ.

        Args:
            doc_id: UUID документа или None
        """
        self.current_document = doc_id

    def add_document(self, doc_id: UUID) -> None:
        """Добавляет документ в список открытых.

        Args:
            doc_id: UUID документа
        """
        if doc_id not in self.open_documents:
            self.open_documents.append(doc_id)
        self.current_document = doc_id

    def remove_document(self, doc_id: UUID) -> None:
        """Удаляет документ из списка открытых.

        Args:
            doc_id: UUID документа
        """
        if doc_id in self.open_documents:
            self.open_documents.remove(doc_id)
        if self.current_document == doc_id:
            self.current_document = self.open_documents[-1] if self.open_documents else None


class MainController:
    """Главный контроллер приложения FX Text Processor 3.

    Отвечает за:
    - Инициализацию и управление другими контроллерами
    - Жизненный цикл приложения (startup, shutdown)
    - Координацию MainWindow с сервисами
    - Глобальное состояние приложения
    - Обработку меню и тулбаров

    Attributes:
        _auth_controller: Контроллер аутентификации
        _document_controller: Контроллер документов
        _print_controller: Контроллер печати
        _form_controller: Контроллер форм
        _workflow_controller: Контроллер workflow
        _session_manager: Менеджер сессий
        _theme_manager: Менеджер тем
        _state: Глобальное состояние приложения
        _main_window: Главное окно приложения
        _logger: Логгер контроллера
        _sub_controllers: Словарь под-контроллеров
    """

    def __init__(
        self,
        root: "tk.Tk",
        auth_controller: "AuthController",
        document_controller: "DocumentController",
        print_controller: "PrintController",
        form_controller: "FormController",
        workflow_controller: "WorkflowController",
        theme_manager: "ThemeManager",
    ) -> None:
        """Инициализирует главный контроллер.

        Args:
            root: Корневое окно Tkinter
            auth_controller: Контроллер аутентификации
            document_controller: Контроллер документов
            print_controller: Контроллер печати
            form_controller: Контроллер форм
            workflow_controller: Контроллер workflow
            theme_manager: Менеджер тем
        """
        self._root = root
        self._auth_controller = auth_controller
        self._document_controller = document_controller
        self._print_controller = print_controller
        self._form_controller = form_controller
        self._workflow_controller = workflow_controller
        self._theme_manager = theme_manager

        self._state = ApplicationState()
        self._main_window: Optional[MainWindow] = None
        self._logger = logging.getLogger(__name__)
        self._sub_controllers: Dict[str, Any] = {}
        self._settings: Dict[str, Any] = {}

        self._logger.info("MainController инициализирован")

    # === Application Lifecycle ===

    def start(self) -> None:
        """Запускает приложение.

        Инициализирует главное окно, регистрирует callbacks
        и запускает главный цикл Tkinter.
        """
        self._logger.info("Запуск приложения")

        try:
            # Проверяем аутентификацию
            if not self._auth_controller.is_authenticated():
                if not self._auth_controller.require_authentication():
                    self._logger.warning("Аутентификация отменена")
                    return

            # Устанавливаем связь с главным окном через DI
            if not self._main_window:
                self._logger.warning("MainWindow не установлено. Используйте set_main_window().")
                return

            # Регистрируем callbacks
            self._register_callbacks()

            # Устанавливаем текущую тему
            current_theme = self._theme_manager.get_current_theme()
            self._main_window.set_theme(current_theme)

            self._logger.info("Приложение запущено")

        except Exception as e:
            self._logger.error(f"Ошибка при запуске приложения: {e}")
            raise

    def shutdown(self, force: bool = False) -> bool:
        """Корректно завершает работу приложения.

        Args:
            force: Принудительное завершение без сохранения

        Returns:
            True если завершение подтверждено, False иначе
        """
        self._logger.info("Инициализация завершения работы")

        # Проверяем несохранённые изменения
        if not force and self._state.open_documents:
            for doc_id in self._state.open_documents:
                if self._document_controller.is_document_modified(doc_id):
                    # Показываем диалог подтверждения
                    if not self._show_unsaved_changes_dialog(doc_id):
                        return False

        # Закрываем все документы через контроллер
        self._document_controller.close_all_documents(confirm_if_modified=False)

        # Очищаем состояние
        self._state.open_documents.clear()
        self._state.current_document = None

        # Уничтожаем окно
        if self._main_window:
            self._main_window.destroy()
            self._main_window = None

        self._logger.info("Приложение завершено")
        return True

    def _show_unsaved_changes_dialog(self, doc_id: UUID) -> bool:
        """Показывает диалог подтверждения при несохранённых изменениях.

        Args:
            doc_id: UUID документа с изменениями

        Returns:
            True если можно продолжить завершение, False иначе
        """
        try:
            from tkinter import messagebox

            document = self._document_controller.get_document(doc_id)
            title = document.metadata.title if document else "Без названия"
            result = messagebox.askyesnocancel(
                "Несохранённые изменения",
                f'Документ "{title}" содержит несохранённые изменения.\nСохранить перед закрытием?',
            )

            if result is None:  # Cancel
                return False
            elif result:  # Yes - сохранить
                self._document_controller.save_document(doc_id)
                return True
            else:  # No - не сохранять
                return True
        except Exception as e:
            self._logger.error(f"Ошибка при показе диалога: {e}")
            return True

    def _register_callbacks(self) -> None:
        """Регистрирует все callbacks для MainWindow."""
        if not self._main_window:
            return

        # File menu
        self._main_window.register_callback("on_new", self.on_new_document)
        self._main_window.register_callback("on_open", self.on_open_document)
        self._main_window.register_callback("on_save", self.on_save_document)
        self._main_window.register_callback("on_save_as", self.on_save_as_document)
        self._main_window.register_callback("on_print", self.on_print)
        self._main_window.register_callback("on_print_preview", self.on_print_preview)
        self._main_window.register_callback("on_exit", self._on_exit_callback)

        # Edit menu
        self._main_window.register_callback("on_undo", self.on_undo)
        self._main_window.register_callback("on_redo", self.on_redo)
        self._main_window.register_callback("on_cut", self.on_cut)
        self._main_window.register_callback("on_copy", self.on_copy)
        self._main_window.register_callback("on_paste", self.on_paste)
        self._main_window.register_callback("on_find", self.on_find)
        self._main_window.register_callback("on_replace", self.on_replace)

        # View menu
        self._main_window.register_callback("on_toggle_sidebar", self.on_toggle_sidebar)
        self._main_window.register_callback("on_toggle_statusbar", self.on_toggle_statusbar)
        self._main_window.register_callback("on_theme_change", self.on_theme_change)
        self._main_window.register_callback("on_zoom_in", self.on_zoom_in)
        self._main_window.register_callback("on_zoom_out", self.on_zoom_out)
        self._main_window.register_callback("on_zoom_reset", self.on_zoom_reset)

        # Format menu
        self._main_window.register_callback("on_page_setup", self.on_page_setup)
        self._main_window.register_callback("on_font_settings", self.on_font_settings)
        self._main_window.register_callback("on_paragraph_settings", self.on_paragraph_settings)
        self._main_window.register_callback("on_cpi_change", self.on_cpi_change)
        self._main_window.register_callback("on_alignment_change", self.on_alignment_change)

        # Tools menu
        self._main_window.register_callback("on_enter_special_mode", self.on_enter_special_mode)
        self._main_window.register_callback("on_lock_session", self.on_lock_session)
        self._main_window.register_callback("on_settings", self.on_settings)
        self._main_window.register_callback("on_encryption", self.on_encryption)
        self._main_window.register_callback("on_digital_signature", self.on_digital_signature)

        # Help menu
        self._main_window.register_callback("on_help_contents", self.on_help_contents)
        self._main_window.register_callback("on_about", self.on_about)

        # Paper toolbar
        self._main_window.register_callback("on_paper_type_selected", self.on_paper_type_selected)

    # === File Menu Actions ===

    def on_new_document(self, doc_type: Optional[str] = None) -> Optional[UUID]:
        """Создаёт новый документ.

        Args:
            doc_type: Тип документа (опционально)

        Returns:
            UUID созданного документа или None при ошибке
        """
        self._logger.info(f"Создание нового документа типа: {doc_type or 'default'}")

        try:
            from src.documents.types.document_type import DocumentMode

            document = self._document_controller.create_new_document(mode=DocumentMode.FREE_FORM)
            if document is None:
                self._logger.error("Не удалось создать документ")
                return None
            self._state.add_document(document.id)

            if self._main_window:
                self._main_window.set_status("Создан новый документ")

            return document.id

        except Exception as e:
            self._logger.error(f"Ошибка при создании документа: {e}")
            self._show_error("Не удалось создать новый документ")
            return None

    def on_open_document(self, path: Optional[Path] = None) -> Optional[UUID]:
        """Открывает существующий документ.

        Args:
            path: Путь к файлу (если None, показывается диалог)

        Returns:
            UUID открытого документа или None при ошибке/отмене
        """
        self._logger.info("Открытие документа")

        try:
            if path is None:
                path = self._show_open_dialog()
                if path is None:
                    return None

            document = self._document_controller.open_document(path)
            if document is None:
                self._logger.error("Не удалось открыть документ")
                return None
            self._state.add_document(document.id)
            self._state.last_directory = path.parent

            if self._main_window:
                title = document.metadata.title or "Без названия"
                self._main_window.set_status(f'Открыт документ: "{title}"')

            return document.id

        except Exception as e:
            self._logger.error(f"Ошибка при открытии документа: {e}")
            self._show_error(f"Не удалось открыть документ: {e}")
            return None

    def on_save_document(self, doc_id: Optional[UUID] = None) -> bool:
        """Сохраняет текущий документ.

        Args:
            doc_id: UUID документа (если None, сохраняется текущий)

        Returns:
            True если сохранение успешно, False иначе
        """
        target_doc_id = doc_id or self._state.current_document
        if target_doc_id is None:
            self._logger.warning("Нет активного документа для сохранения")
            return False

        self._logger.info(f"Сохранение документа {target_doc_id}")

        try:
            success = self._document_controller.save_document(target_doc_id)

            if success and self._main_window:
                self._main_window.set_status("Документ сохранён")

            return success

        except Exception as e:
            self._logger.error(f"Ошибка при сохранении: {e}")
            self._show_error("Не удалось сохранить документ")
            return False

    def on_save_as_document(self, doc_id: Optional[UUID] = None) -> bool:
        """Сохраняет документ с новым именем.

        Args:
            doc_id: UUID документа (если None, сохраняется текущий)

        Returns:
            True если сохранение успешно, False иначе
        """
        target_doc_id = doc_id or self._state.current_document
        if target_doc_id is None:
            self._logger.warning("Нет активного документа для сохранения")
            return False

        self._logger.info(f"Сохранение документа {target_doc_id} как...")

        try:
            path = self._show_save_dialog()
            if path is None:
                return False

            success = self._document_controller.save_document_as(target_doc_id, path)
            self._state.last_directory = path.parent

            if success and self._main_window:
                self._main_window.set_status(f"Сохранено как: {path.name}")

            return success

        except Exception as e:
            self._logger.error(f"Ошибка при сохранении как: {e}")
            self._show_error("Не удалось сохранить документ")
            return False

    def on_print(self, doc_id: Optional[UUID] = None) -> bool:
        """Печатает документ.

        Args:
            doc_id: UUID документа (если None, печатается текущий)

        Returns:
            True если печать успешна, False иначе
        """
        target_doc_id = doc_id or self._state.current_document
        if target_doc_id is None:
            self._logger.warning("Нет активного документа для печати")
            return False

        self._logger.info(f"Печать документа {target_doc_id}")

        try:
            success = self._print_controller.print_document(target_doc_id)

            if success and self._main_window:
                self._main_window.set_status("Документ отправлен на печать")

            return success

        except Exception as e:
            self._logger.error(f"Ошибка при печати: {e}")
            self._show_error("Не удалось напечатать документ")
            return False

    def on_print_preview(self, doc_id: Optional[UUID] = None) -> bool:
        """Показывает предпросмотр печати.

        Args:
            doc_id: UUID документа (если None, текущий)

        Returns:
            True если предпросмотр успешен, False иначе
        """
        target_doc_id = doc_id or self._state.current_document
        if target_doc_id is None:
            self._logger.warning("Нет активного документа для предпросмотра")
            return False

        self._logger.info(f"Предпросмотр печати документа {target_doc_id}")

        try:
            success = self._print_controller.print_preview(target_doc_id)

            if success and self._main_window:
                self._main_window.set_status("Предпросмотр печати")

            return success

        except Exception as e:
            self._logger.error(f"Ошибка при предпросмотре: {e}")
            self._show_error("Не удалось создать предпросмотр")
            return False

    def _on_exit_callback(self) -> bool:
        """Callback для выхода из приложения.

        Returns:
            False для отмены выхода, True для продолжения
        """
        return self.shutdown()

    # === Edit Menu Actions ===

    def on_undo(self) -> bool:
        """Отменяет последнее действие.

        Returns:
            True если отмена успешна, False иначе
        """
        self._logger.debug("Отмена действия")
        if self._document_controller:
            view = self._document_controller.get_active_document_view()
            if view is not None and view.can_undo():
                view.command_stack.undo()
                if self._main_window:
                    self._main_window.set_status("Отмена")
                return True
        if self._main_window:
            self._main_window.set_status("Отмена недоступна")
        return False

    def on_redo(self) -> bool:
        """Повторяет отменённое действие.

        Returns:
            True если повтор успешен, False иначе
        """
        self._logger.debug("Повтор действия")
        if self._document_controller:
            view = self._document_controller.get_active_document_view()
            if view is not None and view.can_redo():
                view.command_stack.redo()
                if self._main_window:
                    self._main_window.set_status("Повтор")
                return True
        if self._main_window:
            self._main_window.set_status("Повтор недоступен")
        return False

    def on_cut(self) -> bool:
        """Вырезает выделенное.

        Returns:
            True если операция успешна, False иначе
        """
        self._logger.debug("Вырезание")
        if self._main_window:
            self._main_window.set_status("Вырезано")
        return True

    def on_copy(self) -> bool:
        """Копирует выделенное.

        Returns:
            True если операция успешна, False иначе
        """
        self._logger.debug("Копирование")
        if self._main_window:
            self._main_window.set_status("Скопировано")
        return True

    def on_paste(self) -> bool:
        """Вставляет из буфера обмена.

        Returns:
            True если операция успешна, False иначе
        """
        self._logger.debug("Вставка")
        if self._main_window:
            self._main_window.set_status("Вставлено")
        return True

    def on_find(self) -> bool:
        """Открывает диалог поиска.

        Returns:
            True если диалог открыт, False иначе
        """
        self._logger.debug("Открытие диалога поиска")
        try:
            from tkinter import messagebox
            from tkinter import simpledialog

            query = simpledialog.askstring(
                "Поиск",
                "Введите текст для поиска:",
                parent=self._root,
            )
            if not query:
                return False

            document = self._document_controller.get_active_document()
            if document is None:
                self._show_error("Нет активного документа для поиска")
                return False

            text = document.get_text_content()
            count = text.count(query)
            if count > 0:
                message = f"Найдено совпадений: {count}"
                if self._main_window:
                    self._main_window.set_status(f"Найдено {count} совпадений")
            else:
                message = "Совпадений не найдено"
                if self._main_window:
                    self._main_window.set_status("Совпадений не найдено")

            messagebox.showinfo("Результаты поиска", message)
            return True

        except Exception as e:
            self._logger.error(f"Ошибка при поиске: {e}")
            self._show_error(f"Не удалось выполнить поиск: {e}")
            return False

    def on_replace(self) -> bool:
        """Открывает диалог замены.

        Returns:
            True если замена выполнена, False иначе
        """
        self._logger.debug("Открытие диалога замены")
        try:
            from tkinter import messagebox
            from tkinter import simpledialog

            find_text = simpledialog.askstring(
                "Найти",
                "Введите текст для поиска:",
                parent=self._root,
            )
            if find_text is None:
                return False

            replace_text = simpledialog.askstring(
                "Заменить на",
                "Введите текст для замены:",
                parent=self._root,
            )
            if replace_text is None:
                return False

            count = self._document_controller.replace(find_text, replace_text)

            if count > 0:
                message = f"Заменено вхождений: {count}"
                if self._main_window:
                    self._main_window.set_status(f"Заменено {count} вхождений")
            else:
                message = "Текст для замены не найден"
                if self._main_window:
                    self._main_window.set_status("Текст не найден")

            messagebox.showinfo("Результат замены", message)
            return True

        except Exception as e:
            self._logger.error(f"Ошибка при замене: {e}")
            self._show_error(f"Не удалось выполнить замену: {e}")
            return False

    # === View Menu Actions ===

    def on_toggle_sidebar(self) -> None:
        """Переключает видимость боковой панели."""
        self._state.sidebar_visible = not self._state.sidebar_visible
        self._logger.debug(f"SideBar видимость: {self._state.sidebar_visible}")

        if self._main_window:
            status = "отображена" if self._state.sidebar_visible else "скрыта"
            self._main_window.set_status(f"Боковая панель {status}")

    def on_toggle_statusbar(self) -> None:
        """Переключает видимость статусной строки."""
        self._state.status_bar_visible = not self._state.status_bar_visible
        self._logger.debug(f"StatusBar видимость: {self._state.status_bar_visible}")

        if self._main_window:
            status = "отображена" if self._state.status_bar_visible else "скрыта"
            self._main_window.set_status(f"Статусная строка {status}")

    def on_theme_change(self, theme_name: str) -> bool:
        """Изменяет тему оформления.

        Args:
            theme_name: Название темы

        Returns:
            True если тема изменена, False иначе
        """
        self._logger.info(f"Изменение темы на: {theme_name}")

        try:
            self._theme_manager.set_theme(theme_name)

            if self._main_window:
                self._main_window.set_theme(theme_name)
                self._main_window.set_status(f"Тема изменена: {theme_name}")

            return True

        except Exception as e:
            self._logger.error(f"Ошибка при смене темы: {e}")
            self._show_error(f"Не удалось изменить тему: {e}")
            return False

    def on_zoom_in(self) -> bool:
        """Увеличивает масштаб.

        Returns:
            True если масштаб изменён, False иначе
        """
        if self._state.zoom_level < 200:
            self._state.zoom_level += 10
            self._logger.debug(f"Масштаб увеличен до {self._state.zoom_level}%")

            if self._main_window:
                self._main_window.set_zoom(self._state.zoom_level)
                self._main_window.set_status(f"Масштаб: {self._state.zoom_level}%")

        return True

    def on_zoom_out(self) -> bool:
        """Уменьшает масштаб.

        Returns:
            True если масштаб изменён, False иначе
        """
        if self._state.zoom_level > 50:
            self._state.zoom_level -= 10
            self._logger.debug(f"Масштаб уменьшен до {self._state.zoom_level}%")

            if self._main_window:
                self._main_window.set_zoom(self._state.zoom_level)
                self._main_window.set_status(f"Масштаб: {self._state.zoom_level}%")

        return True

    def on_zoom_reset(self) -> bool:
        """Сбрасывает масштаб к 100%.

        Returns:
            True если масштаб сброшен, False иначе
        """
        self._state.zoom_level = 100
        self._logger.debug("Масштаб сброшен к 100%")

        if self._main_window:
            self._main_window.set_zoom(100)
            self._main_window.set_status("Масштаб: 100%")

        return True

    # === Format Menu Actions ===

    def on_page_setup(self) -> bool:
        """Открывает диалог настройки страницы.

        Returns:
            True если диалог открыт, False иначе
        """
        self._logger.debug("Открытие настройки страницы")

        if self._main_window is None:
            self._logger.warning("MainWindow не установлено")
            return False

        try:
            parent = self._main_window.get_root()
        except Exception:
            parent = None

        if parent is None:
            self._logger.error("Не удалось получить root окно")
            return False

        # Получаем текущую конфигурацию из активного документа
        initial_config: Optional[PaperConfig] = None
        doc_id = self._state.current_document
        if doc_id is not None:
            document = self._document_controller.get_document(doc_id)
            if document is not None and hasattr(document, "page_settings"):
                ps = document.page_settings
                initial_config = self._page_settings_to_paper_config(ps)

        if initial_config is None:
            initial_config = PaperConfig()

        # Показываем диалог
        self._main_window.set_status("Настройка страницы...")

        def on_apply(config: PaperConfig) -> None:
            """Callback при нажатии Apply в диалоге."""
            self._apply_paper_config(config)

        dialog = PaperSetupDialog(
            parent=parent,
            initial_config=initial_config,
            on_apply=on_apply,
        )
        result = dialog.show()

        if result is not None:
            self._apply_paper_config(result)
            self._logger.info("Настройки страницы применены")
            self._main_window.set_status("Настройки страницы применены")
        else:
            self._logger.debug("Настройка страницы отменена")
            self._main_window.set_status("Настройка страницы отменена")

        return True

    def _page_settings_to_paper_config(self, ps: "PageSettings") -> PaperConfig:
        """Преобразует PageSettings модели в PaperConfig GUI.

        Args:
            ps: Настройки страницы из модели документа.

        Returns:
            Конфигурация для PaperSetupDialog.
        """
        # Сопоставляем PageSize из model -> PaperSize из gui/services
        size_mapping = {
            "a4": PaperSize.A4,
            "letter": PaperSize.LETTER,
            "legal": PaperSize.LEGAL,
            "fanfold_8_5": PaperSize.TRACTOR_FULL,
            "fanfold_9_5": PaperSize.TRACTOR_FULL,
            "custom": PaperSize.CUSTOM,
        }
        paper_size = size_mapping.get(ps.size.value, PaperSize.A4)

        orientation = (
            Orientation.LANDSCAPE
            if ps.orientation.value == "landscape"
            else Orientation.PORTRAIT
        )

        # CPI по умолчанию
        cpi = 10
        if hasattr(ps, "characters_per_line") and ps.characters_per_line:
            if ps.characters_per_line == 80:
                cpi = 10
            elif ps.characters_per_line == 96:
                cpi = 12
            elif ps.characters_per_line == 120:
                cpi = 15
            elif ps.characters_per_line == 137:
                cpi = 17
            elif ps.characters_per_line == 160:
                cpi = 20

        # Межстрочный интервал
        if ps.line_spacing == 27:
            line_spacing = "1/8"
        else:
            line_spacing = "1/6"

        return PaperConfig(
            paper_size=paper_size,
            cpi=cpi,
            line_spacing=line_spacing,
            width_mm=round(ps.width_inches * 25.4, 1),
            height_mm=round(ps.height_inches * 25.4, 1),
            top_margin_mm=round(ps.margin_top_inches * 25.4, 1),
            bottom_margin_mm=round(ps.margin_bottom_inches * 25.4, 1),
            left_margin_mm=round(ps.margin_left_inches * 25.4, 1),
            right_margin_mm=round(ps.margin_right_inches * 25.4, 1),
            orientation=orientation,
        )

    def _paper_config_to_page_settings(self, config: PaperConfig) -> "PageSettings":
        """Преобразует PaperConfig GUI в PageSettings модели.

        Args:
            config: Конфигурация из PaperSetupDialog.

        Returns:
            Настройки страницы для модели документа.
        """
        from src.model.enums import LineSpacing as ModelLineSpacing
        from src.model.enums import Orientation as ModelOrientation
        from src.model.enums import PageSize as ModelPageSize

        size_mapping = {
            PaperSize.A4: ModelPageSize.A4,
            PaperSize.LETTER: ModelPageSize.LETTER,
            PaperSize.LEGAL: ModelPageSize.LEGAL,
            PaperSize.TRACTOR_FULL: ModelPageSize.FANFOLD_8_5,
            PaperSize.TRACTOR_HALF: ModelPageSize.FANFOLD_8_5,
            PaperSize.TRACTOR_TRIPLET: ModelPageSize.FANFOLD_8_5,
            PaperSize.ENVELOPE_DL: ModelPageSize.CUSTOM,
            PaperSize.ENVELOPE_C5: ModelPageSize.CUSTOM,
            PaperSize.CUSTOM: ModelPageSize.CUSTOM,
        }
        page_size = size_mapping.get(config.paper_size, ModelPageSize.A4)

        orientation = (
            ModelOrientation.LANDSCAPE
            if config.orientation == Orientation.LANDSCAPE
            else ModelOrientation.PORTRAIT
        )

        line_spacing_val = 36 if config.line_spacing == "1/6" else 27
        line_spacing_mode = (
            ModelLineSpacing.ONE_SIXTH_INCH
            if config.line_spacing == "1/6"
            else ModelLineSpacing.ONE_EIGHTH_INCH
        )

        characters_per_line = 80
        if config.cpi == 12:
            characters_per_line = 96
        elif config.cpi == 15:
            characters_per_line = 120
        elif config.cpi == 17:
            characters_per_line = 137
        elif config.cpi == 20:
            characters_per_line = 160

        return PageSettings(
            size=page_size,
            orientation=orientation,
            width_inches=config.width_mm / 25.4,
            height_inches=config.height_mm / 25.4,
            margin_left_inches=config.left_margin_mm / 25.4,
            margin_right_inches=config.right_margin_mm / 25.4,
            margin_top_inches=config.top_margin_mm / 25.4,
            margin_bottom_inches=config.bottom_margin_mm / 25.4,
            line_spacing=line_spacing_val,
            line_spacing_mode=line_spacing_mode,
            characters_per_line=characters_per_line,
        )

    def _apply_paper_config(self, config: PaperConfig) -> None:
        """Применяет PaperConfig к активному документу.

        Args:
            config: Валидированная конфигурация бумаги.
        """
        doc_id = self._state.current_document
        if doc_id is None:
            self._logger.warning("Нет активного документа для применения настроек")
            return

        document = self._document_controller.get_document(doc_id)
        if document is None:
            self._logger.warning(f"Документ {doc_id} не найден")
            return

        try:
            new_settings = self._paper_config_to_page_settings(config)
            document.page_settings = new_settings
            document.is_modified = True
            self._logger.debug(f"Настройки страницы применены к документу {doc_id}")
        except Exception as e:
            self._logger.error(f"Ошибка применения настроек страницы: {e}")
            self._show_error("Не удалось применить настройки страницы")

    def on_font_settings(self) -> bool:
        """Открывает диалог настройки шрифта.

        Returns:
            True если диалог открыт, False иначе
        """
        self._logger.debug("Открытие настройки шрифта")
        if self._main_window is None or self._main_window.get_root() is None:
            return False

        root = self._main_window.get_root()
        self._main_window.set_status("Настройка шрифта...")

        document = self._document_controller.get_active_document()
        if document is not None:
            current_family = FontFamily.ROMAN
            current_cpi = CharactersPerInch.CPI_12
            current_quality = PrintQuality.NLQ
            current_bold = False
            current_italic = False
            current_underline = False
            try:
                if (
                    document.sections
                    and document.sections[0].paragraphs
                    and document.sections[0].paragraphs[0].runs
                ):
                    run = document.sections[0].paragraphs[0].runs[0]
                    current_family = run.font if isinstance(run.font, FontFamily) else FontFamily.ROMAN
                    current_cpi = run.cpi if isinstance(run.cpi, CharactersPerInch) else CharactersPerInch.CPI_12
                    current_quality = run.quality if isinstance(run.quality, PrintQuality) else PrintQuality.NLQ
                    current_bold = TextStyle.BOLD in run.style
                    current_italic = TextStyle.ITALIC in run.style
                    current_underline = TextStyle.UNDERLINE in run.style
            except Exception:
                pass

            result = FontDialog.show_dialog(
                parent=root,
                current_family=current_family,
                current_cpi=current_cpi,
                current_quality=current_quality,
                current_bold=current_bold,
                current_italic=current_italic,
                current_underline=current_underline,
            )

            if result is not None:
                try:
                    doc = self._document_controller.get_active_document()
                    if doc is not None and doc.sections and doc.sections[0].paragraphs:
                        para = doc.sections[0].paragraphs[0]
                        if para.runs:
                            run = para.runs[0]
                            run.font = result.font_family
                            run.cpi = result.cpi
                            run.quality = result.quality
                            style = TextStyle(0)
                            if result.bold:
                                style |= TextStyle.BOLD
                            if result.italic:
                                style |= TextStyle.ITALIC
                            if result.underline:
                                style |= TextStyle.UNDERLINE
                            run.style = style
                            doc.is_modified = True
                            self._main_window.set_status(
                                f"Шрифт: {result.font_family.value}, CPI: {result.cpi.value}"
                            )
                            return True
                except Exception as e:
                    self._logger.warning("Ошибка применения форматирования: %s", e)
                    self._main_window.set_status(
                        f"Шрифт: {result.font_family.value}, CPI: {result.cpi.value} (без сохранения)"
                    )
                    return True

        self._main_window.set_status("Настройка шрифта — нет активного документа")
        return True

    def on_paragraph_settings(self) -> bool:
        """Открывает диалог настройки абзаца.

        Returns:
            True если диалог открыт, False иначе
        """
        self._logger.debug("Открытие настройки абзаца")
        if self._main_window is None or self._main_window.get_root() is None:
            return False

        root = self._main_window.get_root()
        self._main_window.set_status("Настройка абзаца...")

        document = self._document_controller.get_active_document()
        if document is not None:
            current_alignment = "left"
            current_first_indent = 0
            current_left_indent = 0
            current_right_indent = 0
            current_line_spacing = "1/6"
            try:
                if document.sections and document.sections[0].paragraphs:
                    para = document.sections[0].paragraphs[0]
                    current_alignment = para.alignment.value if isinstance(para.alignment, Alignment) else "left"
                    current_first_indent = para.first_line_indent or 0
                    current_left_indent = para.left_indent or 0
                    current_right_indent = para.right_indent or 0
                    ls = para.line_spacing
                    if ls is not None:
                        current_line_spacing = ls.value if hasattr(ls, "value") else str(ls)
            except Exception:
                pass

            result = ParagraphDialog.show_dialog(
                parent=root,
                current_alignment=current_alignment,
                current_first_indent=current_first_indent,
                current_left_indent=current_left_indent,
                current_right_indent=current_right_indent,
                current_line_spacing=current_line_spacing,
            )

            if result is not None:
                try:
                    doc = self._document_controller.get_active_document()
                    if doc is not None and doc.sections and doc.sections[0].paragraphs:
                        para = doc.sections[0].paragraphs[0]
                        alignment = Alignment.from_string(result.alignment) or Alignment.LEFT
                        para.alignment = alignment
                        para.first_line_indent = float(result.first_line_indent)
                        para.left_indent = float(result.left_indent)
                        para.right_indent = float(result.right_indent)
                        # ParagraphDialogResult.line_spacing is "1/6" or "1/8"
                        ls_enum = ModelLineSpacing.from_string(result.line_spacing) or ModelLineSpacing.ONE_SIXTH_INCH
                        para.line_spacing = ls_enum.to_escp_value()
                        doc.is_modified = True
                        self._main_window.set_status(
                            f"Абзац: выравнивание={result.alignment}, отступ={result.first_line_indent}"
                        )
                        return True
                except Exception as e:
                    self._logger.warning("Ошибка применения настроек абзаца: %s", e)
                    self._main_window.set_status(
                        f"Абзац: выравнивание={result.alignment} (без сохранения)"
                    )
                    return True

        self._main_window.set_status("Настройка абзаца — нет активного документа")
        return True

    def on_cpi_change(self, cpi: int) -> bool:
        """Изменяет количество символов на дюйм.

        Args:
            cpi: Значение CPI (10, 12, 15, 17, 20)

        Returns:
            True если CPI изменён, False иначе
        """
        self._logger.info(f"Изменение CPI на: {cpi}")

        if self._main_window:
            self._main_window.set_status(f"CPI: {cpi}")

        return True

    def on_alignment_change(self, alignment: str) -> bool:
        """Изменяет выравнивание текста.

        Args:
            alignment: Тип выравнивания (left, center, right, justify)

        Returns:
            True если выравнивание изменено, False иначе
        """
        self._logger.info(f"Изменение выравнивания на: {alignment}")

        alignment_names = {
            "left": "по левому краю",
            "center": "по центру",
            "right": "по правому краю",
            "justify": "по ширине",
        }

        if self._main_window:
            self._main_window.set_status(
                f"Выравнивание: {alignment_names.get(alignment, alignment)}"
            )

        return True

    # === Tools Menu Actions ===

    def on_enter_special_mode(self) -> bool:
        """Переключает специальный режим (для работы с бланками).

        Returns:
            True если режим переключён, False иначе
        """
        from src.security.auth.session import SessionManager

        session_manager = SessionManager()
        is_special = session_manager.is_special_mode()
        new_mode = not is_special

        self._logger.info(f"{'Вход' if new_mode else 'Выход'} в специальный режим")

        try:
            session_manager.set_special_mode(new_mode)

            if self._main_window:
                status = "активирован" if new_mode else "отключён"
                self._main_window.set_status(f"Специальный режим {status}")

            return True

        except Exception as e:
            self._logger.error(f"Ошибка при переключении режима: {e}")
            self._show_error("Не удалось переключить режим")
            return False

    def on_lock_session(self) -> bool:
        """Блокирует сессию.

        Returns:
            True если сессия заблокирована, False иначе
        """
        self._logger.info("Блокировка сессии")

        try:
            # Session locking is handled by AuthController
            self._auth_controller.lock_session()

            if self._main_window:
                self._main_window.set_status("Сессия заблокирована")

            return True

        except Exception as e:
            self._logger.error(f"Ошибка при блокировке сессии: {e}")
            return False

    def on_settings(self) -> bool:
        """Открывает общие настройки.

        Returns:
            True если настройки открыты, False иначе
        """
        self._logger.debug("Открытие настроек")

        try:
            from src.gui.dialogs.settings_dialog import SettingsDialog

            if self._main_window is None:
                self._logger.warning("MainWindow не установлено")
                return False

            root = self._main_window.get_root()
            if root is None:
                self._logger.warning("Root окно недоступно")
                return False

            dialog = SettingsDialog(parent=root, current_settings=self._settings)
            result = dialog.show()

            if result is not None:
                self._settings.update(result)
                self._logger.info("Настройки обновлены: %s", self._settings)

                # Применяем тему если изменилась
                new_theme = result.get("theme")
                if new_theme and self._theme_manager:
                    try:
                        self._theme_manager.set_theme(new_theme)
                        if self._main_window:
                            current_theme = self._theme_manager.get_current_theme()
                            self._main_window.set_theme(current_theme)
                    except Exception as theme_exc:
                        self._logger.error("Ошибка применения темы: %s", theme_exc)

            if self._main_window:
                self._main_window.set_status("Настройки применены")
            return True

        except Exception as e:
            self._logger.error(f"Ошибка при открытии настроек: {e}")
            self._show_error("Не удалось открыть настройки")
            return False

    def on_encryption(self) -> bool:
        """Открывает настройки шифрования.

        Returns:
            True если диалог открыт, False иначе
        """
        self._logger.debug("Открытие настроек шифрования")

        target_doc_id = self._state.current_document
        if target_doc_id is None:
            self._logger.warning("Нет активного документа для шифрования")
            self._show_error("Нет активного документа для шифрования")
            return False

        try:
            from tkinter import messagebox
            from tkinter import simpledialog

            password = simpledialog.askstring(
                "Шифрование",
                "Введите пароль для шифрования:",
                show="*",
                parent=self._root,
            )

            if not password:
                self._logger.debug("Шифрование отменено пользователем")
                return False

            success = self._document_controller.save_document(
                target_doc_id, encrypt=True, password=password
            )

            if success:
                messagebox.showinfo("Шифрование", "Документ успешно зашифрован и сохранён")
                if self._main_window:
                    self._main_window.set_status("Документ зашифрован и сохранён")
            else:
                self._show_error("Не удалось зашифровать документ")

            return success

        except Exception as e:
            self._logger.error(f"Ошибка при шифровании: {e}")
            self._show_error(f"Не удалось зашифровать документ: {e}")
            return False

    def on_digital_signature(self) -> bool:
        """Открывает настройки цифровой подписи.

        Returns:
            True если диалог открыт, False иначе
        """
        self._logger.debug("Открытие настроек цифровой подписи")
        if self._main_window is None or self._main_window.get_root() is None:
            return False

        root = self._main_window.get_root()
        self._main_window.set_status("Цифровая подпись...")

        per_doc = getattr(self, "_current_doc_controller", None)
        doc_id: Optional[str] = None
        if per_doc is not None:
            try:
                doc = per_doc.get_document()
                doc_id = str(doc.id) if hasattr(doc, "id") else None
            except Exception:
                pass

        result = DigitalSignatureDialog.show_dialog(parent=root, document_id=doc_id)

        if result is not None:
            self._main_window.set_status(
                f"Цифровая подпись: {result.action} ({result.algorithm})"
            )
            return True

        self._main_window.set_status("Цифровая подпись — отменено")
        return True

    # === Help Menu Actions ===

    def on_help_contents(self) -> bool:
        """Открывает содержание справки.

        Returns:
            True если справка открыта, False иначе
        """
        self._logger.debug("Открытие справки")

        try:
            from tkinter import messagebox

            parent = self._main_window.get_root() if self._main_window else None

            messagebox.showinfo(
                "Справка",
                "FX Text Processor 3\n\n"
                "Горячие клавиши:\n"
                "Ctrl+N — Новый документ\n"
                "Ctrl+O — Открыть\n"
                "Ctrl+S — Сохранить\n"
                "Ctrl+P — Печать\n"
                "Ctrl+Z — Отменить\n"
                "Ctrl+F — Поиск\n\n"
                "Для подробной документации обратитесь к docs/API_REFERENCE.md",
                parent=parent,
            )

            if self._main_window:
                self._main_window.set_status("Справка")
            return True

        except Exception as e:
            self._logger.error(f"Ошибка при показе справки: {e}")
            return False

    def on_about(self) -> bool:
        """Показывает диалог "О программе".

        Returns:
            True если диалог показан, False иначе
        """
        self._logger.debug("Открытие диалога 'О программе'")

        try:
            from tkinter import messagebox

            messagebox.showinfo(
                "О программе",
                "FX Text Processor 3\n\n"
                "WYSIWYG редактор для принтера Epson FX-890\n"
                "с поддержкой криптографии Zero Trust\n\n"
                "Версия: 3.0.0\n"
                "© 2026 Air-Gap First Design",
            )

            return True

        except Exception as e:
            self._logger.error(f"Ошибка при показе диалога 'О программе': {e}")
            return False

    # === Toolbar Actions ===

    def on_paper_type_selected(self, paper_type: str) -> bool:
        """Обрабатывает выбор типа бумаги.

        Args:
            paper_type: Выбранный тип бумаги

        Returns:
            True если тип изменён, False иначе
        """
        self._logger.info(f"Выбран тип бумаги: {paper_type}")

        if self._main_window:
            self._main_window.set_status(f"Тип бумаги: {paper_type}")

        return True

    # === Dialog Helpers ===

    def _show_open_dialog(self) -> Optional[Path]:
        """Показывает диалог открытия файла.

        Returns:
            Путь к файлу или None при отмене
        """
        try:
            from tkinter import filedialog

            file_path = filedialog.askopenfilename(
                title="Открыть документ",
                initialdir=str(self._state.last_directory),
                filetypes=[
                    ("FX Text Processor документы", "*.fxsd"),
                    ("Зашифрованные документы", "*.fxsd.enc"),
                    ("Все файлы", "*.*"),
                ],
            )

            return Path(file_path) if file_path else None

        except Exception as e:
            self._logger.error(f"Ошибка при открытии диалога: {e}")
            return None

    def _show_save_dialog(self) -> Optional[Path]:
        """Показывает диалог сохранения файла.

        Returns:
            Путь к файлу или None при отмене
        """
        try:
            from tkinter import filedialog

            file_path = filedialog.asksaveasfilename(
                title="Сохранить документ",
                initialdir=str(self._state.last_directory),
                defaultextension=".fxsd",
                filetypes=[
                    ("FX Text Processor документ", "*.fxsd"),
                    ("Зашифрованный документ", "*.fxsd.enc"),
                ],
            )

            return Path(file_path) if file_path else None

        except Exception as e:
            self._logger.error(f"Ошибка при открытии диалога сохранения: {e}")
            return None

    def _show_error(self, message: str) -> None:
        """Показывает сообщение об ошибке.

        Args:
            message: Сообщение об ошибке
        """
        try:
            from tkinter import messagebox

            messagebox.showerror("Ошибка", message)
        except Exception as e:
            self._logger.error(f"Не удалось показать ошибку: {e}")

    # === State Access ===

    def get_state(self) -> ApplicationState:
        """Возвращает текущее состояние приложения.

        Returns:
            Объект состояния приложения
        """
        return self._state

    def get_active_document(self) -> Optional[UUID]:
        """Возвращает UUID активного документа.

        Returns:
            UUID активного документа или None
        """
        return self._state.current_document

    def get_main_window(self) -> Optional[MainWindow]:
        """Возвращает главное окно приложения.

        Returns:
            Объект MainWindow или None
        """
        return self._main_window

    def set_main_window(self, window: MainWindow) -> None:
        """Устанавливает главное окно приложения (DI).

        Args:
            window: Главное окно
        """
        self._main_window = window

    def get_workflow_controller(self) -> Optional[Any]:
        """Возвращает контроллер workflow.

        Returns:
            WorkflowController или None.
        """
        return getattr(self, "_workflow_controller", None)

    def get_auth_controller(self) -> Optional[Any]:
        """Возвращает контроллер аутентификации.

        Returns:
            AuthController или None.
        """
        return getattr(self, "_auth_controller", None)


__all__ = [
    "MainController",
    "ApplicationState",
]
