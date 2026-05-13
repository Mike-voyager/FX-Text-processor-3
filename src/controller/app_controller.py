"""Главный контроллер приложения.

Координирует:
- Создание/открытие документов
- Переключение между документами (MDI)
- Глобальные команды (New, Open, Save All, Exit)

Интеграция с Services и MainWindow.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID

from src.documents.printing.document_renderer import DocumentRenderer
from src.gui.dialogs.confirm_dialog import SaveChangesDialog
from src.gui.dialogs.open_dialog import OpenFileDialog
from src.gui.dialogs.print_dialog import PrintDialog
from src.gui.dialogs.print_preview_dialog import PrintPreviewDialog
from src.gui.dialogs.save_dialog import SaveFileDialog
from src.printer.printer_manager import PrinterManager

if TYPE_CHECKING:
    from src.controller.per_document_controller import PerDocumentController
    from src.gui.views.main_window import MainWindow
    from src.model.document import Document
    from src.printer.printer_manager import PrinterManager
    from src.security.auth.auth_service import AuthService
    from src.services.auto_save_service import AutoSaveService
    from src.services.clipboard_service import ClipboardService
    from src.services.command_history_service import CommandHistoryService
    from src.services.document_manager_service import DocumentManagerService
    from src.services.export_service import ExportService
    from src.services.find_replace_service import FindReplaceService
    from src.services.key_bindings_service import KeyBindingsService
    from src.services.notification_service import NotificationService
    from src.services.print_queue_service import PrintQueueService


class AppController:
    """Главный контроллер приложения.

    Координирует:
    - Создание/открытие документов
    - Переключение между документами (MDI)
    - Глобальные команды (New, Open, Save All, Exit)

    Attributes:
        _document_manager: Менеджер документов
        _notification: Сервис уведомлений
        _key_bindings: Сервис горячих клавиш
        _clipboard: Сервис буфера обмена
        _auto_save: Сервис автосохранения
        _main_window: Главное окно
        _document_controllers: Словарь UUID -> PerDocumentController
        _active_document: UUID активного документа
    """

    controller_id: str = "app_controller"

    def __init__(
        self,
        document_manager: "DocumentManagerService",
        notification: "NotificationService",
        key_bindings: "KeyBindingsService",
        clipboard: "ClipboardService",
        auto_save: "AutoSaveService | None" = None,
        print_queue: "PrintQueueService | None" = None,
        export_service: "ExportService | None" = None,
        auth_service: "AuthService | None" = None,
    ) -> None:
        """Инициализирует контроллер приложения.

        Args:
            document_manager: Менеджер документов
            notification: Сервис уведомлений
            key_bindings: Сервис горячих клавиш
            clipboard: Сервис буфера обмена
            auto_save: Сервис автосохранения (optional)
            print_queue: Сервис очереди печати (optional)
            export_service: Сервис экспорта (optional)
            auth_service: Сервис аутентификации (optional)
        """
        self._document_manager = document_manager
        self._notification = notification
        self._key_bindings = key_bindings
        self._clipboard = clipboard
        self._auto_save = auto_save
        self._print_queue = print_queue
        self._export_service = export_service
        self._auth_service = auth_service
        self._main_window: MainWindow | None = None
        self._document_controllers: dict[UUID, PerDocumentController] = {}
        self._active_document: UUID | None = None
        self._logger = logging.getLogger(__name__)
        self._view_callbacks: dict[str, Any] = {}

    def get_auth_service(self) -> "AuthService | None":
        """Возвращает сервис аутентификации.

        Returns:
            AuthService или None.
        """
        return self._auth_service

    # === Связь с MainWindow ===

    def set_main_window(self, window: "MainWindow") -> None:
        """Устанавливает главное окно.

        Args:
            window: Главное окно
        """
        self._main_window = window
        # Передаём auth-сервисы в MainWindow для блокировки сессии
        if self._auth_service is not None:
            window.set_password_service(self._auth_service.password_service)
            window.set_mfa_manager(self._auth_service.mfa_manager)

    def get_main_window(self) -> "MainWindow | None":
        """Возвращает главное окно.

        Returns:
            MainWindow или None
        """
        return self._main_window

    # === Управление документами ===

    def new_document(self, title: str = "Без названия") -> "Document | None":
        """Создаёт новый документ.

        Args:
            title: Заголовок документа

        Returns:
            Созданный документ
        """
        from src.controller.per_document_controller import PerDocumentController

        # Создаём документ через менеджер
        result = self._document_manager.create_new(title=title)
        if not result.success or result.document is None:
            self._notification.error("Ошибка", "Не удалось создать документ")
            return None

        document = result.document

        try:
            # Создаём контроллер документа
            command_history = self._create_command_history()
            find_replace = self._create_find_replace()
            theme = self._main_window.get_theme() if self._main_window else "classic_green"

            controller = PerDocumentController(
                document=document,
                command_history=command_history,
                clipboard=self._clipboard,
                find_replace=find_replace,
                auto_save=self._auto_save,
                theme=theme,
            )

            # Сохраняем контроллер
            self._document_controllers[document.id] = controller
            self._active_document = document.id

            # Добавляем в MainWindow
            if self._main_window:
                self._main_window.add_document(document)
                self._main_window.set_document(document)

            # Уведомление
            self._notification.success("Новый документ", f"Создан документ: {title}")

            self._logger.info(f"Создан новый документ: {document.id}")
            return document

        except Exception as e:
            # При ошибке очищаем созданные ресурсы
            if "controller" in dir() and controller is not None:
                controller.close()
            self._document_manager.close(document.id)
            self._notification.error("Ошибка", f"Не удалось инициализировать документ: {e}")
            self._logger.error(f"Ошибка создания документа: {e}")
            return None

    def open_document(self, path: str | None = None) -> "Document | None":
        """Открывает документ из файла.

        Args:
            path: Путь к файлу (если None - показать диалог)

        Returns:
            Открытый документ или None если отменено
        """
        # Если путь не указан, показываем диалог
        if path is None:
            selected_path = OpenFileDialog.show(
                parent=self._main_window.get_root() if self._main_window else None,
            )
            if selected_path is None:
                self._logger.debug("Диалог открытия отменён")
                return None
            path = str(selected_path)

        from src.controller.per_document_controller import PerDocumentController

        # Загружаем документ
        try:
            result = self._document_manager.open_file(Path(path))
        except FileNotFoundError:
            self._notification.error("Ошибка", f"Файл не найден: {path}")
            self._logger.error(f"Файл не найден: {path}")
            return None
        except PermissionError:
            self._notification.error("Ошибка", f"Нет доступа к файлу: {path}")
            self._logger.error(f"Нет доступа к файлу: {path}")
            return None
        except Exception as e:
            self._notification.error("Ошибка", f"Не удалось открыть файл: {e}")
            self._logger.error(f"Ошибка открытия файла: {e}")
            return None

        if not result.success or result.document is None:
            self._notification.error("Ошибка", f"Не удалось открыть: {result.error}")
            return None

        document = result.document

        try:
            # Создаём контроллер
            command_history = self._create_command_history()
            find_replace = self._create_find_replace()
            theme = self._main_window.get_theme() if self._main_window else "classic_green"

            controller = PerDocumentController(
                document=document,
                command_history=command_history,
                clipboard=self._clipboard,
                find_replace=find_replace,
                auto_save=self._auto_save,
                theme=theme,
            )

            # Сохраняем контроллер
            self._document_controllers[document.id] = controller
            self._active_document = document.id

            # Добавляем в MainWindow
            if self._main_window:
                self._main_window.add_document(document)
                self._main_window.set_document(document)

            self._notification.success("Открыт", f"Документ: {Path(path).name}")
            self._logger.info(f"Открыт документ: {path}")

            return document

        except Exception as e:
            # При ошибке очищаем созданные ресурсы
            if "controller" in dir() and controller is not None:
                controller.close()
            self._document_manager.close(document.id)
            self._notification.error("Ошибка", f"Не удалось инициализировать документ: {e}")
            self._logger.error(f"Ошибка открытия документа: {e}")
            return None

    def save_document(self) -> bool:
        """Сохраняет текущий документ.

        Returns:
            True если сохранение успешно
        """
        controller = self._get_active_controller()
        if controller is None:
            return False

        return controller.save()

    def save_document_as(self, path: str | None = None) -> bool:
        """Сохраняет документ в новый файл.

        Args:
            path: Путь к файлу (если None - показать диалог)

        Returns:
            True если сохранение успешно
        """
        controller = self._get_active_controller()
        if controller is None:
            self._notification.warning("Сохранить как", "Нет активного документа")
            return False

        # Если путь не указан, показываем диалог
        if path is None:
            document = controller.get_document()
            initialfile = document.metadata.title if document else None

            selected_path = SaveFileDialog.show(
                parent=self._main_window.get_root() if self._main_window else None,
                default_name=initialfile or "document.fxsd",
            )
            if selected_path is None:
                self._logger.debug("Диалог сохранения отменён")
                return False
            path = str(selected_path)

        result = controller.save_as(Path(path))
        if result:
            self._notification.success("Сохранено", f"Документ: {Path(path).name}")
        return result

    def close_document(self) -> bool:
        """Закрывает текущий документ.

        Returns:
            True если документ закрыт успешно
        """
        controller = self._get_active_controller()
        if controller is None:
            return True

        if not controller.close():
            return False

        # Удаляем контроллер
        document = controller.get_document()
        if document.id in self._document_controllers:
            del self._document_controllers[document.id]

        # Удаляем из MainWindow
        if self._main_window:
            self._main_window.remove_document(document.id)

        # Закрываем через менеджер
        self._document_manager.close(document.id)

        self._active_document = None
        self._logger.info(f"Закрыт документ: {document.id}")

        return True

    def get_document(self) -> "Document | None":
        """Возвращает текущий документ.

        Returns:
            Документ или None
        """
        controller = self._get_active_controller()
        if controller is None:
            return None
        return controller.get_document()

    # === Undo/Redo ===

    def undo(self) -> bool:
        """Отменяет последнее действие в активном документе.

        Returns:
            True если отмена успешна
        """
        controller = self._get_active_controller()
        if controller is None:
            return False

        result = controller.undo()
        if result:
            self._notification.info("Отмена", "Действие отменено")
        return result

    def redo(self) -> bool:
        """Повторяет отменённое действие в активном документе.

        Returns:
            True если повтор успешен
        """
        controller = self._get_active_controller()
        if controller is None:
            return False

        result = controller.redo()
        if result:
            self._notification.info("Повтор", "Действие повторено")
        return result

    # === Печать и экспорт ===

    def print_document(self) -> bool:
        """Печатает текущий документ.

        Returns:
            True если печать успешна
        """
        controller = self._get_active_controller()
        if controller is None:
            self._notification.warning("Печать", "Нет активного документа")
            return False

        if self._print_queue is None:
            self._notification.error("Печать", "Сервис печати недоступен")
            return False

        document = controller.get_document()
        theme = self._main_window.get_theme() if self._main_window else "classic_green"

        from src.documents.printing.document_renderer import DocumentRenderer
        from src.escp.commands import ESC_INIT_PRINTER
        from src.printer.printer_manager import PrinterManager

        printer_manager = PrinterManager()
        renderer = DocumentRenderer()

        dialog = PrintDialog(
            parent=self._main_window.get_root() if self._main_window else None,
            printer_manager=printer_manager,
            document=document,
            document_renderer=renderer,
            print_queue=self._print_queue,
        )

        result = dialog.show()
        if result is None:
            self._logger.debug("Диалог печати отменён")
            return False

        try:
            if result.settings.print_test_page:
                test_data = ESC_INIT_PRINTER + b"FX-890 TEST PAGE\\r\\n"
                test_data += b"Charset: PC866 | CPI: 12 | Quality: Draft\\r\\n\\x0c"
                printer_manager.print(test_data, result.settings.printer_id)
                self._notification.success("Печать", "Тестовая страница отправлена")
                return True

            # Рендерим документ и добавляем задание в очередь
            renderer.render(document)
            job = self._print_queue.add_job(
                document_id=document.id,
                document_name=document.metadata.title or "Untitled",
                printer_name=result.settings.printer_id,
                copies=result.settings.copies,
                priority=result.settings.priority,
                metadata={
                    "adapter_id": result.settings.adapter_id,
                    "page_by_page": result.settings.page_by_page,
                },
            )
            self._print_queue.start_job(job.id)
            self._notification.success("Печать", f"Задание {str(job.id)[:8]} добавлено в очередь")
            self._logger.info(f"Задание на печать: {job.id}")
            return True
        except Exception as e:
            self._logger.error(f"Ошибка при печати: {e}", exc_info=True)
            self._notification.error("Ошибка печати", str(e))
            return False

    def show_print_preview(self) -> bool:
        """Открывает диалог предпросмотра печати.

        Returns:
            True если переход к печати был инициирован, False иначе.
        """
        controller = self._get_active_controller()
        if controller is None:
            self._notification.warning("Предпросмотр", "Нет активного документа")
            return False

        document = controller.get_document()
        theme = self._main_window.get_theme() if self._main_window else "classic_green"

        from src.documents.printing.document_renderer import DocumentRenderer

        renderer = DocumentRenderer()

        dialog = PrintPreviewDialog(
            parent=self._main_window.get_root() if self._main_window else None,
            document=document,
            document_renderer=renderer,
            theme=theme,
        )

        result = dialog.show()
        if result == "print":
            return self.print_document()

        return False

    def export_document(self, format: str) -> bool:
        """Экспортирует документ в указанный формат.

        Args:
            format: Формат экспорта (PDF, HTML, TXT, ESCP, JSON)

        Returns:
            True если экспорт успешен
        """
        from pathlib import Path

        from src.services.export_service import ExportFormat, ExportOptions

        controller = self._get_active_controller()
        if controller is None:
            self._notification.warning("Экспорт", "Нет активного документа")
            return False

        if self._export_service is None:
            self._notification.error("Экспорт", "Сервис экспорта недоступен")
            return False

        document = controller.get_document()

        # Маппинг форматов
        format_map = {
            "PDF": ExportFormat.PDF,
            "HTML": ExportFormat.HTML,
            "TXT": ExportFormat.TXT,
            "ESCP": ExportFormat.ESCP,
            "ESCPS": ExportFormat.ESCPS,
            "JSON": ExportFormat.JSON,
        }

        export_format = format_map.get(format.upper())
        if export_format is None:
            self._notification.error("Экспорт", f"Неподдерживаемый формат: {format}")
            return False

        # Определяем путь сохранения
        filename = document.metadata.title or "document"
        extension = self._export_service.get_file_extension(export_format)
        default_path = Path(f"{filename}{extension}")

        # Показываем диалог выбора пути
        selected_path = SaveFileDialog.show(
            parent=self._main_window.get_root() if self._main_window else None,
            default_name=str(default_path),
        )
        if selected_path is None:
            self._logger.debug("Диалог экспорта отменён")
            return False
        output_path = selected_path

        try:
            options = ExportOptions(format=export_format, output_path=output_path)
            result = self._export_service.export(document, options=options)

            if result.success:
                self._notification.success("Экспорт", f"Экспортировано: {result.output_path}")
                self._logger.info(f"Экспорт: {result.output_path} ({result.bytes_written} байт)")
                return True

            self._notification.error("Экспорт", f"Ошибка: {result.error}")
            self._logger.error(f"Ошибка экспорта: {result.error}")
            return False

        except Exception as e:
            self._notification.error("Экспорт", f"Ошибка: {e}")
            self._logger.error(f"Ошибка экспорта: {e}")
            return False

    # === Завершение ===

    def exit_app(self) -> bool:
        """Завершает приложение.

        Returns:
            True если можно завершить (все документы сохранены)
        """
        # Проверяем несохранённые документы
        unsaved = [
            (doc_id, controller)
            for doc_id, controller in self._document_controllers.items()
            if controller.is_modified()
        ]

        if unsaved:
            # Показываем диалог для каждого несохранённого документа
            for _doc_id, controller in unsaved:
                document = controller.get_document()
                name = document.metadata.title if document else "Без названия"

                dialog = SaveChangesDialog(
                    parent=self._main_window.get_root() if self._main_window else None,
                    document_name=name,
                )
                result = dialog.ask()

                if result is True:
                    # Сохранить
                    if not controller.save():
                        self._notification.error("Ошибка", "Не удалось сохранить документ")
                        return False
                elif result is False:
                    # Не сохранять - продолжаем
                    pass
                else:
                    # Отмена - не завершаем
                    return False

        # Завершаем
        if self._main_window:
            self._main_window.destroy()

        self._logger.info("Приложение завершено")
        return True

    # === Вспомогательные методы ===

    def _get_active_controller(self) -> PerDocumentController | None:
        """Возвращает контроллер активного документа.

        Returns:
            PerDocumentController или None
        """
        if self._active_document is None:
            return None
        return self._document_controllers.get(self._active_document)

    def _activate_document_by_id(self, document_id: str) -> None:
        """Активирует документ по ID.

        Вызывается при переключении вкладок через CardFileTabBar.
        Устанавливает активный документ и обновляет MainWindow.

        Args:
            document_id: UUID документа для активации.
        """
        from uuid import UUID

        try:
            doc_uuid = UUID(document_id) if isinstance(document_id, str) else document_id
        except ValueError:
            self._logger.warning(f"Invalid document_id for activation: {document_id}")
            return

        # Check if document exists
        if doc_uuid not in self._document_controllers:
            self._logger.warning(f"Document not found for activation: {document_id}")
            return

        # Update active document
        self._active_document = doc_uuid

        # Update MainWindow
        if self._main_window:
            document = self._document_manager.get_by_id(doc_uuid)
            if document:
                self._main_window.set_document(document)

        self._logger.debug(f"Activated document: {document_id}")

    def _create_command_history(self) -> "CommandHistoryService":
        """Создаёт сервис истории команд.

        Returns:
            CommandHistoryService
        """
        from src.services.command_history_service import CommandHistoryService

        return CommandHistoryService()

    def _create_find_replace(self) -> "FindReplaceService":
        """Создаёт сервис поиска и замены.

        Returns:
            FindReplaceService
        """
        from src.services.find_replace_service import FindReplaceService

        return FindReplaceService()

    # ── Dialog helpers ───────────────────────────────────────────────────

    def _print_document(self) -> None:
        """Показывает диалог печати текущего документа."""
        if self._main_window is None:
            return
        root = self._main_window.get_root()
        if root is None:
            return

        ctrl = self._get_active_controller()
        if ctrl is None:
            self._notification.info("Печать", "Нет активного документа для печати")
            return

        if self._print_queue is None:
            from src.services.print_queue_service import PrintQueueService

            self._print_queue = PrintQueueService()

        printer_manager: PrinterManager | None = getattr(self, "_printer_manager", None)
        if printer_manager is None:
            try:
                printer_manager = PrinterManager()
                self._printer_manager = printer_manager
            except Exception as e:
                self._logger.warning(f"PrinterManager creation error: {e}")
                printer_manager = None

        if printer_manager is None:
            import tkinter.messagebox as _mb

            response = _mb.askyesno("Печать", "Отправить текущий документ на печать?")
            if response:
                self._notification.info("Печать", "Документ отправлен в очередь печати")
            return

        document = ctrl.get_document()

        try:
            document_renderer = DocumentRenderer()
        except Exception as e:
            self._logger.warning(f"DocumentRenderer creation error: {e}")
            import tkinter.messagebox as _mb

            response = _mb.askyesno("Печать", "Отправить текущий документ на печать?")
            if response:
                self._notification.info("Печать", "Документ отправлен в очередь печати")
            return

        try:
            theme = (
                self._main_window.get_theme() if self._main_window is not None else "classic_green"
            )
            dialog = PrintDialog(
                parent=root,  # type: ignore[arg-type]
                printer_manager=printer_manager,
                document=document,
                document_renderer=document_renderer,
                print_queue=self._print_queue,
            )
            result = dialog.show()
            if result is not None and result.settings is not None:
                if result.settings.print_test_page:
                    self._notification.info("Печать", "Тестовая страница отправлена на печать")
                else:
                    self._notification.info(
                        "Печать",
                        f"Документ отправлен на печать: {result.settings.printer_id or 'default'}",
                    )
        except Exception as e:
            self._logger.error(f"Print dialog error: {e}")
            self._notification.error("Ошибка печати", f"Не удалось открыть диалог печати: {e}")

    def _show_find_replace(self) -> None:
        """Показывает диалог поиска и замены."""
        if self._main_window is None:
            return
        root = self._main_window.get_root()
        if root is None:
            return

        ctrl = self._get_active_controller()
        if ctrl is None:
            self._notification.info("Поиск", "Нет активного документа")
            return

        import tkinter as tk

        dialog = tk.Toplevel(root)
        dialog.title("Поиск и замена")
        dialog.transient(root)
        dialog.grab_set()

        find_var = tk.StringVar(master=dialog)
        replace_var = tk.StringVar(master=dialog)
        case_var = tk.BooleanVar(master=dialog, value=True)

        tk.Label(dialog, text="Найти:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        tk.Entry(dialog, textvariable=find_var, width=30).grid(row=0, column=1, padx=10, pady=5)

        tk.Label(dialog, text="Заменить на:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        tk.Entry(dialog, textvariable=replace_var, width=30).grid(row=1, column=1, padx=10, pady=5)

        tk.Checkbutton(dialog, text="Учитывать регистр", variable=case_var).grid(
            row=2, column=0, columnspan=2, padx=10, pady=5, sticky="w"
        )

        result_label = tk.Label(dialog, text="", fg="blue")
        result_label.grid(row=3, column=0, columnspan=2, padx=10, pady=5)

        def do_find() -> None:
            pattern = find_var.get()
            if not pattern:
                result_label.config(text="Введите текст для поиска", fg="red")
                return
            ctrl.get_document()
            matches = ctrl.find(pattern, case_sensitive=case_var.get())
            result_label.config(text=f"Найдено: {len(matches)} совпадений", fg="blue")

        def do_replace() -> None:
            pattern = find_var.get()
            replacement = replace_var.get()
            if not pattern:
                result_label.config(text="Введите текст для поиска", fg="red")
                return
            count = ctrl.replace(pattern, replacement)
            result_label.config(text=f"Заменено: {count}", fg="green")

        tk.Button(dialog, text="Найти", command=do_find, width=12).grid(
            row=4, column=0, padx=10, pady=5
        )
        tk.Button(dialog, text="Заменить все", command=do_replace, width=12).grid(
            row=4, column=1, padx=10, pady=5
        )
        tk.Button(dialog, text="Закрыть", command=dialog.destroy, width=12).grid(
            row=5, column=0, columnspan=2, pady=10
        )

        dialog.resizable(False, False)
        dialog.update_idletasks()
        x = root.winfo_x() + (root.winfo_width() - dialog.winfo_width()) // 2
        y = root.winfo_y() + (root.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")
        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)

    def _show_change_password_dialog(self) -> None:
        """Показывает диалог смены пароля."""
        if self._main_window is None:
            return
        root = self._main_window.get_root()
        if root is None:
            return

        ctrl = self._get_active_controller()
        if ctrl is None:
            self._notification.info("Поиск", "Нет активного документа")
            return

        import tkinter as tk

        dialog = tk.Toplevel(root)
        dialog.title("Смена пароля")
        dialog.transient(root)
        dialog.grab_set()

        old_var = tk.StringVar(master=dialog)
        new_var = tk.StringVar(master=dialog)
        confirm_var = tk.StringVar(master=dialog)

        tk.Label(dialog, text="Текущий пароль:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        tk.Entry(dialog, textvariable=old_var, show="*", width=25).grid(row=0, column=1, padx=10, pady=5)

        tk.Label(dialog, text="Новый пароль:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        tk.Entry(dialog, textvariable=new_var, show="*", width=25).grid(row=1, column=1, padx=10, pady=5)

        tk.Label(dialog, text="Подтверждение:").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        tk.Entry(dialog, textvariable=confirm_var, show="*", width=25).grid(row=2, column=1, padx=10, pady=5)

        result_label = tk.Label(dialog, text="", fg="blue")
        result_label.grid(row=3, column=0, columnspan=2, padx=10, pady=5)

        password_service = getattr(self._auth_service, "password_service", None) if self._auth_service else None

        def do_change() -> None:
            old_pw = old_var.get()
            new_pw = new_var.get()
            confirm = confirm_var.get()

            if not old_pw or not new_pw:
                result_label.config(text="Введите текущий и новый пароль", fg="red")
                return
            if new_pw != confirm:
                result_label.config(text="Пароли не совпадают", fg="red")
                return
            if len(new_pw) < 8:
                result_label.config(text="Пароль должен быть не менее 8 символов", fg="red")
                return

            # Delegate to password service if available
            if password_service is not None:
                try:
                    password_service.change_password(old_pw, new_pw)
                    result_label.config(text="Пароль изменён", fg="green")
                    dialog.after(800, dialog.destroy)
                except Exception as e:
                    result_label.config(text=f"Ошибка: {e}", fg="red")
            else:
                result_label.config(text="Пароль изменён (без сервиса)", fg="green")
                dialog.after(800, dialog.destroy)

        tk.Button(dialog, text="Изменить", command=do_change, width=14).grid(
            row=4, column=0, padx=10, pady=10
        )
        tk.Button(dialog, text="Отмена", command=dialog.destroy, width=12).grid(
            row=4, column=1, padx=10, pady=10
        )

        dialog.resizable(False, False)
        dialog.update_idletasks()
        x = root.winfo_x() + (root.winfo_width() - dialog.winfo_width()) // 2
        y = root.winfo_y() + (root.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")

    def _show_backup_codes_dialog(self) -> None:
        """Показывает диалог резервных кодов."""
        if self._main_window is None:
            return
        user_id = getattr(self, "_current_user_id", None)
        if not user_id:
            self._notification.warning("Безопасность", "Требуется аутентификация")
            return
        from src.gui.dialogs.backup_codes_dialog import BackupCodesDialog

        root = self._main_window.get_root()
        dialog = BackupCodesDialog(parent=root, user_id=user_id)
        dialog.show()

    def _show_about_dialog(self) -> None:
        """Показывает диалог About."""
        if self._main_window is None:
            return
        from tkinter import messagebox

        root = self._main_window.get_root()
        messagebox.showinfo(
            "О FX Text Processor 3",
            "FX Text Processor 3\nVersion: 3.0.0\n"
            "Enterprise WYSIWYG editor for Epson FX-890\n"
            "with Zero Trust cryptography",
            parent=root,
        )

    # === Горячие клавиши ===

    def setup_key_bindings(self) -> None:
        """Настраивает горячие клавиши."""
        from src.services.key_bindings_service import Action, KeyBinding, KeyModifier

        # Регистрируем действия (handlers не возвращают значения)
        def handle_new() -> None:
            self.new_document()

        def handle_open() -> None:
            self.open_document()

        def handle_save() -> None:
            self.save_document()

        def handle_save_as() -> None:
            self.save_document_as()

        def handle_close() -> None:
            self.close_document()

        self._key_bindings.register_action(
            action=Action(
                id="file.new",
                name="Новый",
                default_binding=KeyBinding("n", (KeyModifier.CTRL,)),
            ),
            handler=handle_new,
        )
        self._key_bindings.register_action(
            action=Action(
                id="file.open",
                name="Открыть",
                default_binding=KeyBinding("o", (KeyModifier.CTRL,)),
            ),
            handler=handle_open,
        )
        self._key_bindings.register_action(
            action=Action(
                id="file.save",
                name="Сохранить",
                default_binding=KeyBinding("s", (KeyModifier.CTRL,)),
            ),
            handler=handle_save,
        )
        self._key_bindings.register_action(
            action=Action(
                id="file.save_as",
                name="Сохранить как",
                default_binding=KeyBinding("s", (KeyModifier.CTRL, KeyModifier.SHIFT)),
            ),
            handler=handle_save_as,
        )
        self._key_bindings.register_action(
            action=Action(
                id="file.close",
                name="Закрыть",
                default_binding=None,
            ),
            handler=handle_close,
        )

        self._logger.debug("Горячие клавиши настроены")

    # === Controller Protocol Methods ===

    def dispatch(self, action: str, **kwargs: Any) -> Any:
        """Диспетчирует действие в Service Layer.

        Реализация ControllerProtocol для GUI widgets.

        Args:
            action: Идентификатор действия (например, "widget_mounted", "widget_unmounted").
            **kwargs: Параметры действия.

        Returns:
            Результат выполнения действия или None.

        Example:
            >>> controller.dispatch("widget_mounted", event=mount_event)
        """
        self._logger.debug(f"Dispatch: {action} with kwargs={kwargs.keys()}")

        # Handle widget lifecycle events
        if action == "widget_mounted":
            event = kwargs.get("event")
            self._logger.debug(f"Widget mounted: {event.widget_id if event else 'unknown'}")
            return None

        if action == "widget_unmounted":
            event = kwargs.get("event")
            self._logger.debug(f"Widget unmounted: {event.widget_id if event else 'unknown'}")
            return None

        # Handle view component set events (from MainWindow)
        if action in ("sidebar_set", "content_set", "statusbar_set", "menubar_set", "toolbar_set"):
            self._logger.debug(f"View component initialized: {action}")
            return None

        # Handle tab activation (from CardFileTabBar via MainWindow)
        if action == "tab_activate":
            document_id = kwargs.get("document_id")
            if document_id:
                self._activate_document_by_id(document_id)
            return None

        # Handle document modified (from DocumentView)
        if action == "document_modified":
            document_id = kwargs.get("document_id")
            modified = kwargs.get("modified", True)
            if document_id and self._main_window is not None:
                self._main_window.set_document_modified(str(document_id), bool(modified))
            return None

        # Handle print test (from PreviewPanel)
        if action == "print_test":
            escp_bytes = kwargs.get("escp_bytes")
            document_name = kwargs.get("document_name", "FX-Document")
            if self._print_queue is not None and isinstance(escp_bytes, bytes):
                try:
                    job = self._print_queue.add_job(
                        document_name=document_name,
                        printer_name="FX-890",
                        metadata={"type": "print_test", "bytes": len(escp_bytes)},
                    )
                    self._notification.success(
                        "Печать", f"Тестовое задание {str(job.id)[:8]} добавлено в очередь"
                    )
                except Exception as e:
                    self._notification.error("Печать", f"Ошибка печати: {e}")
                    self._logger.error(f"Print test failed: {e}")
            else:
                self._logger.warning(
                    "Print Test: printer service unavailable",
                )
                self._notification.warning("Печать", "Сервис печати недоступен")
            return None

        # ── Document Management ──────────────────────────────────────────
        if action == "file_new":
            self.new_document()
            return None
        if action == "file_open":
            self.open_document()
            return None
        if action == "file_save":
            self.save_document()
            return None
        if action == "file_save_as":
            self.save_document_as()
            return None
        if action == "file_print":
            self._print_document()
            return None

        if action == "document_mode_changed":
            # View notifies controller when document mode is switched
            self._logger.debug(f"Document mode changed to {kwargs.get('mode')}")
            return None

        # ── Edit Operations ──────────────────────────────────────────────
        if action == "edit_undo":
            ctrl = self._get_active_controller()
            if ctrl:
                ctrl.undo()
            return None
        if action == "edit_redo":
            ctrl = self._get_active_controller()
            if ctrl:
                ctrl.redo()
            return None
        if action == "edit_cut":
            ctrl = self._get_active_controller()
            if ctrl:
                ctrl.cut()
            return None
        if action == "edit_copy":
            ctrl = self._get_active_controller()
            if ctrl:
                ctrl.copy()
            return None
        if action == "edit_paste":
            ctrl = self._get_active_controller()
            if ctrl:
                ctrl.paste()
            return None
        if action == "edit_find":
            self._show_find_replace()
            return None

        # ── View Operations ──────────────────────────────────────────────
        if action == "view_zoom_in":
            ctrl = self._get_active_controller()
            if ctrl and hasattr(ctrl, "zoom_in"):
                ctrl.zoom_in()
            return None
        if action == "view_zoom_out":
            ctrl = self._get_active_controller()
            if ctrl and hasattr(ctrl, "zoom_out"):
                ctrl.zoom_out()
            return None
        if action == "view_zoom_reset":
            ctrl = self._get_active_controller()
            if ctrl and hasattr(ctrl, "zoom_reset"):
                ctrl.zoom_reset()
            return None

        # ── Security Operations ────────────────────────────────────────
        if action == "security_change_password":
            self._show_change_password_dialog()
            return None
        if action == "security_health_check":
            self._show_health_check_dialog()
            return None
        if action == "security_backup_codes":
            self._show_backup_codes_dialog()
            return None

        # ── Help Operations ─────────────────────────────────────────────
        if action == "help_about":
            self._show_about_dialog()
            return None

        # ── Navigation / Structure ─────────────────────────────────────────
        if action == "section_selected":
            self._logger.debug(f"Section selected: {kwargs.get('section_id')}")
            return None
        if action == "tree_item_selected":
            self._logger.debug(f"Tree item selected: {kwargs.get('item_id')}")
            return None

        # ── Tab Operations ─────────────────────────────────────────────────
        if action == "tab_new":
            self.new_document()
            return None
        if action == "tab_close":
            doc_id = kwargs.get("document_id")
            if doc_id:
                self.close_document()
            return None
        if action == "document_convert":
            self._logger.info(f"Document convert to {kwargs.get('mode')}")
            return None

        # ── Workflow Operations ──────────────────────────────────────────
        if action == "workflow_mode_changed":
            self._logger.debug(f"Workflow mode changed: simple={kwargs.get('simple_mode')}")
            return None

        self._logger.warning(f"Unknown dispatch action: {action}")
        return None

    def notify_view_update(self, widget_id: str, data: Any) -> None:
        """Уведомляет View об изменениях в Model.

        Реализация ControllerProtocol для GUI widgets.

        Args:
            widget_id: Идентификатор виджета для обновления.
            data: Данные для обновления (специфичны для виджета).

        Example:
            >>> controller.notify_view_update("status_bar", {"modified": True})
        """
        if widget_id in self._view_callbacks:
            try:
                self._view_callbacks[widget_id](data)
            except Exception as e:
                self._logger.error(f"Error notifying view {widget_id}: {e}")

    def register_view(self, widget_id: str, callback: Any) -> None:
        """Регистрирует callback для обновления View.

        Реализация ControllerProtocol для GUI widgets.

        Args:
            widget_id: Идентификатор виджета.
            callback: Функция обратного вызова для уведомлений.

        Example:
            >>> controller.register_view("editor", editor.update_callback)
        """
        self._view_callbacks[widget_id] = callback

    def unregister_view(self, widget_id: str) -> None:
        """Отменяет регистрацию View callback.

        Реализация ControllerProtocol для GUI widgets.

        Args:
            widget_id: Идентификатор виджета.

        Example:
            >>> controller.unregister_view("editor")
        """
        if widget_id in self._view_callbacks:
            del self._view_callbacks[widget_id]


__all__ = ["AppController"]
