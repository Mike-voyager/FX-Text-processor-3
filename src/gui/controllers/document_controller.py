"""Контроллер для работы с документами.

Связывает GUI компоненты с сервисным слоем DocumentManagerService.
Обрабатывает FREE_FORM (текст) и STRUCTURED_FORM (формы) режимы.

Module: src/gui/controllers/document_controller.py
Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from src.documents.printing.document_renderer import DocumentRenderer, RenderSettings
from src.gui.core.commands.command import Command
from src.gui.core.commands.command_stack import CommandStack
from src.gui.core.protocols import DocumentControllerProtocol
from src.gui.dialogs.print_settings import PrintSettings
from src.gui.security.mfa_gate import MFAGate
from src.printer.printer_manager import PrinterManager
from src.security.crypto.core.exceptions import AuthError, CryptoError
from src.services.document_manager_service import DocumentManagerService

logger = logging.getLogger(__name__)


class DocumentController(DocumentControllerProtocol):
    """Контроллер для управления документами.

    Обрабатывает операции с документами: открытие, сохранение,
    печать, отмена действий. Интегрируется с DocumentManagerService
    и использует MFAGate для защищённых операций.

    Принимает DocumentManagerService через DI в конструктор.

    Attributes:
        controller_id: Уникальный идентификатор контроллера.
        _service: Сервис управления документами.
        _mfa_gate: Менеджер MFA верификации (опционально).
        _parent: Родительский виджет для MFA диалогов.

    Example:
        >>> from src.gui.controllers.document_controller import DocumentController
        >>> controller = DocumentController(
        ...     service=doc_manager_service,
        ...     mfa_gate=mfa_gate
        ... )
        >>> controller.dispatch("save", path="/tmp/doc.fxsd")
    """

    def __init__(
        self,
        service: DocumentManagerService,
        mfa_gate: Optional[MFAGate] = None,
        parent: Any = None,
        printer_manager: Optional[PrinterManager] = None,
        command_stack: Optional[CommandStack] = None,
    ) -> None:
        """Инициализирует контроллер документа.

        Args:
            service: Сервис управления документами.
            mfa_gate: Менеджер MFA верификации (опционально).
            parent: Родительский виджет для MFA диалогов.
            printer_manager: Менеджер принтеров (опционально).
            command_stack: Стек команд для undo/redo (опционально).
        """
        self.controller_id: str = "document_controller"
        self._service: DocumentManagerService = service
        self._mfa_gate: Optional[MFAGate] = mfa_gate
        self._parent: Any = parent
        self._printer_manager: PrinterManager = printer_manager or PrinterManager()
        self._command_stack: CommandStack = (
            command_stack if command_stack is not None else CommandStack()
        )
        self._views: dict[str, Any] = {}

    # --- Диспетчеризация ---

    def dispatch(self, action: str, **kwargs: Any) -> Any:
        """Диспетчирует действие в подметоды контроллера.

        Реализует только маршрутизацию — NO бизнес-логики.

        Args:
            action: Идентификатор действия ("text_changed", "field_changed",
                   "save", "print", "undo", "redo").
            **kwargs: Параметры действия.

        Returns:
            Результат выполнения или None.

        Example:
            >>> controller.dispatch("on_save")
            >>> controller.dispatch("on_text_changed", text="Hello")
        """
        if action == "on_text_changed":
            return self.on_text_changed(**kwargs)
        elif action == "on_field_changed":
            return self.on_field_changed(**kwargs)
        elif action == "on_save":
            return self.on_save()
        elif action == "on_print":
            return self.on_print()
        elif action == "on_undo":
            return self.on_undo()
        elif action == "on_redo":
            return self.on_redo()
        elif action == "edit_undo":
            return self.on_undo()
        elif action == "edit_redo":
            return self.on_redo()
        return None

    # --- DocumentControllerProtocol реализация ---

    def on_text_changed(self, text: str) -> None:
        """Обрабатывает изменение текста в FREE_FORM режиме.

        Вызывается SmartWidget при выходе из режима редактирования
        или по таймеру автосохранения.

        Args:
            text: Новый текст документа.

        Note:
            Контроллер передаёт изменение в DocumentService,
            который обновляет Model и логирует в AuditService.

        Example:
            >>> controller.on_text_changed("Hello, World!")
        """
        active_doc = self._service.active_document
        if active_doc is not None:
            active_doc.set_text_content(text)
            active_doc.is_modified = True
            logger.info("Document text changed, modified=True")
            self._notify_views("editor", {"text": text, "modified": True})

    def on_field_changed(self, field_id: str, value: str) -> None:
        """Обрабатывает изменение поля в STRUCTURED_FORM режиме.

        Устанавливает флаг модификации документа и уведомляет все связанные View.
        """
        active_doc = self._service.active_document
        if active_doc is not None:
            active_doc.is_modified = True
            logger.info("Field %s changed to %s", field_id, value)
            self._notify_views("form", {"field_id": field_id, "value": value, "modified": True})

    def on_save(self) -> bool:
        """Сохраняет текущий документ.

        Для зашифрованных документов может потребоваться MFA.

        Returns:
            True если сохранение успешно, False при ошибке или отмене.
            Ошибки записи возвращают False вместо исключений.

        Security:
            Документы с SecurityPreset.PARANOID/PQC требуют MFA.
            Используется MFAGate для проверки.

        Example:
            >>> if controller.on_save():
            ...     print("Документ сохранён")
        """
        active_doc = self._service.active_document
        if active_doc is None:
            logger.warning("No active document to save")
            return False

        try:
            parent = self._parent
            if self._mfa_gate is not None:
                result = self._mfa_gate.execute(
                    parent=parent,
                    operation=lambda: self._save_document(),
                    operation_name="Сохранение документа",
                    requires_mfa=True,
                )
                return result is not None
            else:
                return self._save_document()
        except (AuthError, CryptoError) as e:
            logger.critical("Security error during document save: %s", e, exc_info=True)
            return False
        except (OSError, ValueError) as e:
            logger.error("Unexpected error during document save: %s", e, exc_info=True)
            return False

    def on_print(self) -> bool:
        """Печатает текущий документ.

        Открывает PrintDialog, формирует ESC/P команды,
        отправляет на принтер через PrinterService.

        Returns:
            True если печать успешно запущена, False при отмене.

        Security:
            Для подписанных документов печать может требовать MFA
            для генерации QR-кода подтверждения.

        Example:
            >>> if controller.on_print():
            ...     print("Задание отправлено на печать")
        """
        active_doc = self._service.active_document
        if active_doc is None:
            logger.warning("No active document to print")
            return False

        try:
            parent = self._parent
            if self._mfa_gate is not None:
                result = self._mfa_gate.execute(
                    parent=parent,
                    operation=lambda: self._print_document(),
                    operation_name="Печать документа",
                    requires_mfa=True,
                )
                return result is not None
            else:
                return self._print_document()
        except (AuthError, CryptoError) as e:
            logger.critical("Security error during document print: %s", e, exc_info=True)
            return False
        except (OSError, ValueError) as e:
            logger.error("Unexpected error during document print: %s", e, exc_info=True)
            return False

    def execute_command(self, cmd: Command) -> None:
        """Выполняет команду через CommandStack (Вариант B слоения).

        Проксирует вызов из View в CommandStack.execute().
        Обеспечивает единую точку входа для всех undo/redo операций.

        Args:
            cmd: Команда для выполнения.

        Example:
            >>> controller.execute_command(InsertTextCommand(widget, "Hello", "1.0"))
        """
        self._command_stack.execute(cmd)

    def on_undo(self) -> bool:
        """Отменяет последнее действие.

        Returns:
            True если отмена выполнена, False если история пуста.

        Example:
            >>> while controller.on_undo():
            ...     print("Отменено одно действие")
        """
        if not self._command_stack.can_undo():
            return False
        self._command_stack.undo()
        self._sync_view_state()
        return True

    def on_redo(self) -> bool:
        """Повторяет отменённое действие.

        Returns:
            True если повтор выполнен, False если redo-история пуста.

        Example:
            >>> controller.on_redo()
            True
        """
        if not self._command_stack.can_redo():
            return False
        self._command_stack.redo()
        self._sync_view_state()
        return True

    def _sync_view_state(self) -> None:
        """Синхронизирует View после undo/redo.

        Уведомляет зарегистрированные View о необходимости обновления.
        """
        self._notify_views("editor", {"action": "sync"})

    # --- Internal helpers ---

    def _save_document(self) -> bool:
        """Выполняет сохранение документа.

        Вызывается из on_save() после MFA проверки.

        Returns:
            True если сохранение успешно.
        """
        active_doc = self._service.active_document
        if active_doc is None:
            return False
        save_result = self._service.save(active_doc.id)
        if save_result.success:
            logger.info("Document saved successfully")
            self._notify_views("status_bar", {"message": "Документ сохранён"})
            return True
        else:
            logger.error("Failed to save document: %s", save_result.error)
            return False

    def _print_document(self, settings: Optional[PrintSettings] = None) -> bool:
        """Выполняет печать документа.

        Вызывается из on_print() после MFA проверки.

        Args:
            settings: Настройки печати из PrintDialog (optional)

        Returns:
            True если печать запущена успешно.
        """
        active_doc = self._service.active_document
        if active_doc is None:
            return False

        try:
            # Render document to ESC/P bytes
            renderer = DocumentRenderer()

            # Используем настройки из диалога или дефолтные
            render_settings = RenderSettings()
            escp_data = renderer.render(active_doc, render_settings)

            # Определяем принтер: из настроек или best_printer
            printer_id = (
                settings.printer_id if settings else self._printer_manager.get_best_printer()
            )

            if printer_id:
                # Выполняем печать (в реальном приложении здесь будет add_job в очередь)
                result = self._printer_manager.print(escp_data, printer_id)
                if result.success:
                    logger.info("Print job submitted successfully")
                    self._notify_views("status_bar", {"message": "Печать запущена"})
                    return True
                else:
                    logger.error("Print failed: %s", result.message)
                    self._notify_views("status_bar", {"message": "Ошибка печати"})
                    return False
            else:
                # Fallback to file output
                from pathlib import Path

                output_path = Path("./output") / f"document_{active_doc.id}.escp"
                output_path.parent.mkdir(exist_ok=True)
                renderer.render_to_file(active_doc, output_path, render_settings)
                logger.info("Print job saved to file: %s", output_path)
                message = f"Документ сохранен как ESC/P: {output_path.name}"
                self._notify_views("status_bar", {"message": message})
                return True

        except (OSError, ValueError) as e:
            logger.error("Failed to print document: %s", e, exc_info=True)
            self._notify_views("status_bar", {"message": "Ошибка печати"})
            return False

    def _notify_views(self, widget_id: str, data: Any) -> None:
        """Уведомляет зарегистрированные View об изменениях.

        Args:
            widget_id: Идентификатор виджета.
            data: Данные для обновления.
        """
        callback = self._views.get(widget_id)
        if callback is not None:
            callback(widget_id, data)

    def notify_view_update(self, widget_id: str, data: Any) -> None:
        """Уведомляет View об изменениях в Model.

        Реализует ControllerProtocol.notify_view_update().

        Args:
            widget_id: Идентификатор виджета для обновления.
            data: Данные для обновления.
        """
        self._notify_views(widget_id, data)

    def register_view(self, widget_id: str, callback: Any) -> None:
        """Регистрирует callback для обновления View.

        Реализует ControllerProtocol.register_view().

        Args:
            widget_id: Идентификатор виджета.
            callback: Функция обратного вызова.
        """
        self._views[widget_id] = callback

    def unregister_view(self, widget_id: str) -> None:
        """Отменяет регистрацию View callback.

        Реализует ControllerProtocol.unregister_view().

        Args:
            widget_id: Идентификатор виджета.
        """
        if widget_id in self._views:
            del self._views[widget_id]
