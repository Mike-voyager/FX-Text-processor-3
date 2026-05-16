"""Per-document controller for FX Text Processor 3.

Манипулирует одним документом:
- Undo/redo операции через CommandHistoryService
- Clipboard операции (cut/copy/paste)
- Find/replace операции
- Сохранение/загрузка документа
- Отслеживание состояния modified

Каждый открытый документ имеет свой PerDocumentController.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from src.model.document import Document
    from src.services.clipboard_service import ClipboardService
    from src.services.command_history_service import CommandHistoryService
    from src.services.find_replace_service import FindReplaceService


class PerDocumentController:
    """Контроллер для работы с одним документом.

    Управляет операциями над конкретным документом:
    - История команд (undo/redo)
    - Буфер обмена (cut/copy/paste)
    - Поиск и замена
    - Сохранение/загрузка

    Attributes:
        _document: Документ, которым управляет контроллер
        _command_history: История команд для undo/redo
        _clipboard: Сервис буфера обмена
        _find_replace: Сервис поиска и замены
        _document_view: Представление документа (опционально)
        _is_modified: Флаг изменения документа
        _file_path: Путь к файлу документа
        _logger: Логгер
    """

    def __init__(
        self,
        document: "Document",
        command_history: "CommandHistoryService",
        clipboard: "ClipboardService",
        find_replace: "FindReplaceService",
        auto_save: Optional[Any] = None,
        theme: str = "classic_green",
    ) -> None:
        """Инициализирует контроллер документа.

        Args:
            document: Документ для управления
            command_history: Сервис истории команд
            clipboard: Сервис буфера обмена
            find_replace: Сервис поиска и замены
            auto_save: Сервис автосохранения (опционально)
            theme: Тема оформления
        """
        self._document = document
        self._command_history = command_history
        self._clipboard = clipboard
        self._find_replace = find_replace
        self._auto_save = auto_save
        self._theme = theme

        self._document_view: Optional[Any] = None
        self._is_modified = False
        self._file_path: Optional[Path] = None
        self._logger = logging.getLogger(__name__)

    # === Document Access ===

    def get_document(self) -> "Document":
        """Возвращает управляемый документ.

        Returns:
            Документ
        """
        return self._document

    def set_view(self, view: Any) -> None:
        """Устанавливает представление документа.

        Args:
            view: Представление документа (DocumentView)
        """
        self._document_view = view

    def get_view(self) -> Optional[Any]:
        """Возвращает представление документа.

        Returns:
            Представление документа или None
        """
        return self._document_view

    # === Modification State ===

    def is_modified(self) -> bool:
        """Проверяет, был ли документ изменён.

        Returns:
            True если документ изменён
        """
        return self._is_modified

    def set_modified(self, modified: bool) -> None:
        """Устанавливает флаг изменения документа.

        Args:
            modified: Новое значение флага
        """
        self._is_modified = modified

    # === Undo/Redo ===

    def can_undo(self) -> bool:
        """Проверяет возможность отмены.

        Returns:
            True если можно отменить последнее действие
        """
        return self._command_history.can_undo(self._document.id)

    def can_redo(self) -> bool:
        """Проверяет возможность повтора.

        Returns:
            True если можно повторить отменённое действие
        """
        return self._command_history.can_redo(self._document.id)

    def undo(self) -> bool:
        """Отменяет последнее действие.

        Returns:
            True если отмена выполнена
        """
        if not self.can_undo():
            return False

        result = self._command_history.undo()
        if result.success:
            self._is_modified = True
            if self._document_view is not None:
                try:
                    self._document_view.undo()
                except Exception as e:
                    self._logger.debug(f"View undo update error (non-critical): {e}")
        return result.success

    def redo(self) -> bool:
        """Повторяет отменённое действие.

        Returns:
            True если повтор выполнен
        """
        if not self.can_redo():
            return False

        result = self._command_history.redo()
        if result.success:
            self._is_modified = True
            if self._document_view is not None:
                try:
                    self._document_view.redo()
                except Exception as e:
                    self._logger.debug(f"View redo update error (non-critical): {e}")
        return result.success

    # === Save/Load ===

    def save(self) -> bool:
        """Сохраняет документ.

        Если путь не указан, возвращает False (нужно использовать save_as).

        Returns:
            True если сохранение успешно
        """
        if self._file_path is None:
            return False

        return self.save_as(self._file_path)

    def save_as(self, path: Path) -> bool:
        """Сохраняет документ в указанный файл.

        Args:
            path: Путь для сохранения

        Returns:
            True если сохранение успешно
        """
        try:
            from src.documents.format.document_format import DocumentFormat

            document_format = DocumentFormat()
            document_format.save(self._document, path)
            self._file_path = path
            self._is_modified = False
            self._logger.info(f"Документ сохранён: {path}")
            return True
        except Exception as e:
            self._logger.error(f"Ошибка сохранения: {e}")
            return False

    def close(self) -> bool:
        """Закрывает документ.

        Returns:
            True если документ можно закрыть
        """
        if self._is_modified:
            try:
                from tkinter import messagebox

                parent = (
                    self._document_view.get_root()
                    if self._document_view is not None
                    else None
                )
                title = getattr(
                    getattr(self._document, "metadata", None),
                    "title",
                    None,
                ) or "Без названия"
                result = messagebox.askyesnocancel(
                    title="Несохранённые изменения",
                    message=(
                        f'Документ "{title}" содержит несохранённые изменения.\n'
                        f"Сохранить перед закрытием?"
                    ),
                    parent=parent,
                )
            except Exception as e:
                self._logger.error(f"Ошибка при показе диалога: {e}")
                return True

            if result is None:  # Cancel
                return False
            elif result:  # Yes — сохранить
                save_result = self.save()
                if not save_result:
                    # Нет file_path — невозможно сохранить без диалога
                    # в PerDocumentController, отменяем закрытие
                    return False
                return save_result
            else:  # No — не сохранять
                return True

        self._document_view = None
        return True

    # === Clipboard Operations ===

    def copy(self) -> bool:
        """Копирует выделенный текст в буфер обмена.

        Returns:
            True если копирование выполнено
        """
        if self._document_view is None:
            return False

        try:
            selection = self._document_view.get_selection()
            if selection and selection[0] != selection[1]:
                text = self._document_view.get_text_widget().get("sel.first", "sel.last")
                self._clipboard.copy_text(text)
                return True
        except Exception as e:
            self._logger.error(f"Ошибка копирования: {e}")

        return False

    def cut(self) -> bool:
        """Вырезает выделенный текст в буфер обмена.

        Returns:
            True если вырезание выполнено
        """
        if self._document_view is None:
            return False

        try:
            selection = self._document_view.get_selection()
            if selection and selection[0] != selection[1]:
                text = self._document_view.get_text_widget().get("sel.first", "sel.last")
                self._clipboard.cut_text(text)
                self._document_view.delete_text(selection[0], selection[1])
                self._is_modified = True
                return True
        except Exception as e:
            self._logger.error(f"Ошибка вырезания: {e}")

        return False

    def paste(self) -> bool:
        """Вставляет текст из буфера обмена.

        Returns:
            True если вставка выполнена
        """
        if self._document_view is None:
            return False

        try:
            text = self._clipboard.paste_text()
            if text:
                position = self._document_view.get_cursor_position()
                self._document_view.insert_text(position, text)
                self._is_modified = True
                return True
        except Exception as e:
            self._logger.error(f"Ошибка вставки: {e}")

        return False

    # === Find/Replace Operations ===

    def find(self, text: str, **options: Any) -> list[int]:
        """Ищет текст в документе.

        Args:
            text: Текст для поиска
            **options: Опции поиска

        Returns:
            Список позиций найденных совпадений
        """
        from src.services.find_replace_service import SearchOptions

        search_options = SearchOptions(**options)
        result = self._find_replace.find(self._document, text, search_options)
        if result.success:
            return [m.start_offset for m in result.matches]
        return []

    def find_next(self) -> Optional[int]:
        """Находит следующее совпадение.

        Returns:
            Позиция следующего совпадения или None
        """
        result = self._find_replace.find_next(self._document, "")
        if result.success and result.matches:
            return result.matches[0].start_offset
        return None

    def replace(self, old_text: str, new_text: str, **options: Any) -> int:
        """Заменяет текст в документе.

        Args:
            old_text: Текст для замены
            new_text: Новый текст
            **options: Опции замены

        Returns:
            Количество замен
        """
        from src.services.find_replace_service import SearchOptions

        search_options = SearchOptions(**options)
        result = self._find_replace.replace_all(
            self._document, old_text, new_text, search_options
        )
        if result.replaced_count > 0:
            self._is_modified = True
        return result.replaced_count


# Alias for backward compatibility with tests
DocumentController = PerDocumentController

__all__ = ["PerDocumentController", "DocumentController"]
