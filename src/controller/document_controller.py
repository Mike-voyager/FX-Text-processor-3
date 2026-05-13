"""Контроллер документа для FX Text Processor 3.

Управляет жизненным циклом документов и операциями:
- Создание новых документов (text и form modes)
- Открытие существующих документов из файлов
- Сохранение документов (с шифрованием при необходимости)
- Управление вкладками документов в CardFileTabBar
- Обработка флага модификации документа
- Координация между DocumentView и DocumentService

Интеграция с View через callbacks, с Service через DI.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID

if TYPE_CHECKING:
    from src.documents.format.document_format import DocumentFormat
    from src.documents.types.document_type import DocumentMode
    from src.model.document import Document
    from src.security.crypto.service.crypto_service import CryptoService
    from src.services.document_manager_service import (
        CloseResult,
        CreateResult,
        DocumentManagerService,
        OpenResult,
        SaveResult,
    )
    from src.view.document_view import DocumentView
    from src.view.main_window import MainWindow
    from src.view.tabs import CardFileTabBar


class DocumentControllerError(Exception):
    """Базовое исключение для ошибок DocumentController."""

    pass


class DocumentNotFoundError(DocumentControllerError):
    """Документ не найден."""

    pass


class OpenError(DocumentControllerError):
    """Ошибка открытия документа."""

    pass


class SaveError(DocumentControllerError):
    """Ошибка сохранения документа."""

    pass


class DocumentTabInfo:
    """Информация о вкладке документа."""

    def __init__(self, doc_id: UUID, title: str, modified: bool = False) -> None:
        self.doc_id = doc_id
        self.title = title
        self.modified = modified


class DocumentMode:
    """Режим документа."""

    FREE_FORM = "free_form"
    STRUCTURED_FORM = "structured_form"


class DocumentController:
    """Контроллер документа.

    Управляет жизненным циклом документов и координирует операции
    между View, Service Layer и криптографическими сервисами.

    Attributes:
        _document_manager: Сервис управления документами (MDI)
        _crypto_service: Сервис шифрования/дешифрования
        _main_window: Главное окно приложения
        _tab_bar: Панель вкладок документов
        _document_views: Словарь UUID -> DocumentView
        _document_controllers: Словарь UUID -> DocumentController (per-doc)
        _active_document: ID активного документа
        _document_format: Сервис форматирования документов
        _logger: Логгер

    Example:
        >>> controller = DocumentController(
        ...     document_manager=document_manager_service,
        ...     crypto_service=crypto_service,
        ...     main_window=main_window,
        ...     tab_bar=tab_bar,
        ... )
        >>> doc = controller.create_new_document(DocumentMode.FREE_FORM)
        >>> controller.open_document(Path("document.fxsd"))
        >>> controller.save_document(doc.id)
    """

    def __init__(
        self,
        document_manager: "DocumentManagerService",
        crypto_service: "CryptoService | None" = None,
        main_window: "MainWindow | None" = None,
        tab_bar: "CardFileTabBar | None" = None,
    ) -> None:
        """Инициализирует контроллер документа.

        Args:
            document_manager: Сервис управления документами
            crypto_service: Сервис шифрования (опционально)
            main_window: Главное окно приложения (опционально)
            tab_bar: Панель вкладок (опционально)
        """
        self._document_manager = document_manager
        self._crypto_service = crypto_service
        self._main_window = main_window
        self._tab_bar = tab_bar

        # Хранилище связей документов с их представлениями
        self._document_views: dict[UUID, DocumentView] = {}
        self._document_controllers: dict[UUID, DocumentController] = {}
        self._active_document: UUID | None = None

        # Сервисы (DI)
        self._document_format = DocumentFormat()
        self._logger = logging.getLogger(__name__)

    # ========== Создание документов ==========

    def create_new_document(
        self,
        mode: "DocumentMode | None" = None,
        title: str = "Без названия",
    ) -> "Document | None":
        """Создаёт новый документ указанного режима.

        Args:
            mode: Режим документа (FREE_FORM или STRUCTURED_FORM)
            title: Заголовок документа

        Returns:
            Созданный документ или None при ошибке
        """
        # Импортируем здесь для избежания циклических зависимостей

        result: CreateResult = self._document_manager.create_new(title=title)

        if not result.success or result.document is None:
            self._logger.error(f"Не удалось создать документ: {result.error}")
            return None

        document = result.document
        self._active_document = document.id

        # Добавляем вкладку если есть tab_bar
        if self._tab_bar is not None:
            self._tab_bar.add_tab(document.id, title)
            self._tab_bar.set_active_tab(document.id)

        # Обновляем UI
        if self._main_window is not None:
            self._main_window.add_document(document)

        self._logger.info(
            f"Создан новый документ {mode.value if mode else 'FREE_FORM'}: {document.id}"
        )
        return document

    def create_form_document(
        self,
        form_type: str,
        title: str = "Новая форма",
    ) -> Document | None:
        """Создаёт новый документ формы (STRUCTURED_FORM).

        Args:
            form_type: Тип формы (например, "INV", "DVN")
            title: Заголовок формы

        Returns:
            Созданный документ формы или None при ошибке
        """
        result: CreateResult = self._document_manager.create_new(title=title)

        if not result.success or result.document is None:
            self._logger.error(f"Не удалось создать форму: {result.error}")
            return None

        document = result.document
        self._active_document = document.id

        # Добавляем вкладку
        if self._tab_bar is not None:
            self._tab_bar.add_tab(document.id, title)
            self._tab_bar.set_active_tab(document.id)

        # Обновляем UI
        if self._main_window is not None:
            self._main_window.add_document(document)

        self._logger.info(f"Создана новая форма {form_type}: {document.id}")
        return document

    # ========== Открытие документов ==========

    def open_document(
        self,
        path: Path,
        *,
        decrypt: bool = False,
        password: str | None = None,
    ) -> Document | None:
        """Открывает документ из файла.

        Args:
            path: Путь к файлу (.fxsd, .fxsd.enc, .fxsblank)
            decrypt: Флаг дешифрования для зашифрованных файлов
            password: Пароль для дешифрования (если decrypt=True)

        Returns:
            Открытый документ или None при ошибке

        Raises:
            FileNotFoundError: Если файл не существует
            PermissionError: Если нет доступа к файлу
        """
        if not path.exists():
            self._logger.error(f"Файл не найден: {path}")
            raise FileNotFoundError(f"Файл не найден: {path}")

        # Определяем нужно ли дешифрование по расширению
        if path.suffix == ".enc" or str(path).endswith(".fxsd.enc"):
            decrypt = True

        try:
            result: OpenResult = self._document_manager.open_file(
                path,
                decrypt=decrypt,
                password=password,
            )
        except Exception as e:
            self._logger.error(f"Ошибка открытия файла {path}: {e}")
            return None

        if not result.success or result.document is None:
            self._logger.error(f"Не удалось открыть документ: {result.error}")
            return None

        document = result.document
        self._active_document = document.id

        # Добавляем вкладку
        display_name = document.metadata.title or path.stem
        if self._tab_bar is not None:
            self._tab_bar.add_tab(document.id, display_name)
            self._tab_bar.set_active_tab(document.id)

        # Обновляем UI
        if self._main_window is not None:
            self._main_window.add_document(document)

        self._logger.info(f"Открыт документ: {path}")
        return document

    def open_encrypted_document(
        self,
        path: Path,
        password: str,
    ) -> Document | None:
        """Открывает зашифрованный документ с паролем.

        Args:
            path: Путь к зашифрованному файлу
            password: Пароль для дешифрования

        Returns:
            Расшифрованный документ или None при ошибке
        """
        return self.open_document(path, decrypt=True, password=password)

    # ========== Сохранение документов ==========

    def save_document(
        self,
        doc_id: UUID,
        path: Path | None = None,
        *,
        encrypt: bool = False,
        password: str | None = None,
    ) -> bool:
        """Сохраняет документ.

        Args:
            doc_id: ID документа
            path: Путь сохранения (если None - используется текущий)
            encrypt: Флаг шифрования
            password: Пароль для шифрования (если encrypt=True)

        Returns:
            True если сохранение успешно
        """
        # Определяем путь сохранения
        save_path = path or self._document_manager.get_document_path(doc_id)
        if save_path is None:
            self._logger.error("Путь сохранения не указан")
            return False

        # Если нужно шифрование, используем DocumentFormat с crypto
        if encrypt and self._crypto_service is not None and password:
            try:
                from src.documents.format.document_format import DocumentFormat

                document_format = DocumentFormat()
                doc = self._document_manager.get_by_id(doc_id)
                if doc is not None:
                    document_format.save(doc, save_path, encrypt=True, crypto=self._crypto_service)
                    self._logger.info(f"Зашифрованный документ сохранён: {save_path}")
                    return True
            except Exception as e:
                self._logger.error(f"Ошибка шифрования: {e}")
                return False

        # Сохраняем через DocumentManager
        result: SaveResult = self._document_manager.save(doc_id, save_path)

        if not result.success:
            self._logger.error(f"Ошибка сохранения: {result.error}")
            return False

        # Обновляем UI
        if self._main_window is not None:
            self._main_window.get_status_bar().set_modified(False)

        self._logger.info(f"Документ сохранён: {save_path}")
        return True

    def save_document_as(
        self,
        doc_id: UUID,
        path: Path,
        *,
        encrypt: bool = False,
    ) -> bool:
        """Сохраняет документ в новый файл.

        Args:
            doc_id: ID документа
            path: Новый путь сохранения
            encrypt: Флаг шифрования

        Returns:
            True если сохранение успешно
        """
        return self.save_document(doc_id, path, encrypt=encrypt)

    def save_all_documents(self) -> dict[UUID, bool]:
        """Сохраняет все изменённые документы.

        Returns:
            Словарь {doc_id: success} с результатами сохранения
        """
        results: dict[UUID, bool] = {}
        save_results = self._document_manager.save_all()

        for doc_id, result in save_results.items():
            results[doc_id] = result.success
            if result.success:
                self._logger.info(f"Документ сохранён: {doc_id}")
            else:
                self._logger.error(f"Ошибка сохранения {doc_id}: {result.error}")

        return results

    # ========== Закрытие документов ==========

    def close_document(
        self,
        doc_id: UUID,
        confirm_if_modified: bool = True,
    ) -> bool:
        """Закрывает документ.

        Args:
            doc_id: ID документа
            confirm_if_modified: Показывать подтверждение если есть изменения

        Returns:
            True если документ закрыт успешно
        """
        document = self._document_manager.get_by_id(doc_id)
        if document is None:
            self._logger.warning(f"Документ не найден: {doc_id}")
            return False

        # Проверяем изменения
        needs_save = document.is_modified

        if needs_save and confirm_if_modified:
            self._logger.info(f"Документ {doc_id} имеет несохранённые изменения")
            import tkinter.messagebox as _mb
            parent: object | None = (
                self._main_window.get_root()
                if self._main_window is not None
                else None
            )
            result = _mb.askyesnocancel(
                title="Несохранённые изменения",
                message="Документ содержит несохранённые изменения.\n"
                        "Сохранить перед закрытием?",
                parent=parent,
            )
            if result is None:  # Отмена
                self._logger.info(f"Закрытие документа {doc_id} отменено")
                return False
            elif result is True:  # Сохранить
                try:
                    save_success = self.save_document(doc_id)
                    if not save_success:
                        self._logger.error(
                            f"Не удалось сохранить документ {doc_id}"
                        )
                        return False
                except Exception as e:
                    self._logger.error(
                        f"Ошибка при сохранении документа {doc_id}: {e}"
                    )
                    return False
            # Иначе result is False — не сохранять и продолжить закрытие

        # Закрываем через DocumentManager
        result: CloseResult = self._document_manager.close(
            doc_id,
            save_if_modified=False,  # Уже сохранили выше или пользователь отказался
            force=needs_save if confirm_if_modified else not confirm_if_modified,
        )

        if not result.success:
            self._logger.error(f"Ошибка закрытия документа: {result.error}")
            return False

        # Удаляем вкладку
        if self._tab_bar is not None:
            self._tab_bar.remove_tab(doc_id)

        # Удаляем из UI
        if self._main_window is not None:
            self._main_window.remove_document(doc_id)

        # Очищаем локальные ссылки
        if doc_id in self._document_views:
            del self._document_views[doc_id]
        if doc_id in self._document_controllers:
            del self._document_controllers[doc_id]

        # Обновляем активный документ
        if self._active_document == doc_id:
            # Находим другой открытый документ
            remaining = list(self._document_manager.documents)
            self._active_document = remaining[0].id if remaining else None
            if self._active_document and self._tab_bar is not None:
                self._tab_bar.set_active_tab(self._active_document)

        self._logger.info(f"Документ закрыт: {doc_id}")
        return True

    def close_all_documents(
        self,
        confirm_if_modified: bool = True,
    ) -> bool:
        """Закрывает все открытые документы.

        Args:
            confirm_if_modified: Показывать подтверждение для изменённых

        Returns:
            True если все документы закрыты успешно
        """
        results = self._document_manager.close_all(
            save_if_modified=not confirm_if_modified,
            force=not confirm_if_modified,
        )

        all_success = all(r.success for r in results.values())

        # Очищаем вкладки
        if self._tab_bar is not None:
            for doc_id in list(results.keys()):
                self._tab_bar.remove_tab(doc_id)

        # Очищаем UI
        if self._main_window is not None:
            for doc_id in list(results.keys()):
                self._main_window.remove_document(doc_id)

        self._document_views.clear()
        self._document_controllers.clear()
        self._active_document = None

        self._logger.info(f"Закрыто документов: {len(results)}")
        return all_success

    # ========== Управление активным документом ==========

    def replace(self, old_text: str, new_text: str) -> int:
        """Заменяет текст в активном документе.

        Args:
            old_text: Текст для поиска.
            new_text: Текст для замены.

        Returns:
            Количество выполненных замен.
        """
        if self._active_document is None:
            return 0

        document = self._document_manager.get_by_id(self._active_document)
        if document is None:
            return 0

        text = document.get_text_content()
        count = text.count(old_text)
        if count == 0:
            return 0

        updated_text = text.replace(old_text, new_text)
        document.set_text_content(updated_text)

        # Обновляем UI
        if self._main_window is not None:
            view = self._document_views.get(self._active_document)
            if view is not None:
                try:
                    view.set_text_content(updated_text)
                except Exception:
                    pass
            self._main_window.get_status_bar().set_modified(True)

        self._logger.info(f"Заменено {count} вхождений '{old_text}' → '{new_text}'")
        return count

    def get_active_document(self) -> Document | None:
        """Возвращает текущий активный документ.

        Returns:
            Активный документ или None
        """
        if self._active_document is None:
            return None
        return self._document_manager.get_by_id(self._active_document)

    def set_active_document(self, doc_id: UUID) -> bool:
        """Устанавливает активный документ.

        Args:
            doc_id: ID документа для активации

        Returns:
            True если документ активирован
        """
        document = self._document_manager.get_by_id(doc_id)
        if document is None:
            self._logger.warning(f"Документ не найден: {doc_id}")
            return False

        self._active_document = doc_id

        # Обновляем вкладку
        if self._tab_bar is not None:
            self._tab_bar.set_active_tab(doc_id)

        # Обновляем UI
        if self._main_window is not None:
            self._main_window._set_active_document(doc_id)

        self._logger.debug(f"Активирован документ: {doc_id}")
        return True

    def get_document(self, doc_id: UUID) -> Document | None:
        """Возвращает документ по ID.

        Args:
            doc_id: ID документа

        Returns:
            Документ или None
        """
        return self._document_manager.get_by_id(doc_id)

    def get_document_by_path(self, path: Path) -> Document | None:
        """Возвращает документ по пути файла.

        Args:
            path: Путь к файлу

        Returns:
            Документ или None
        """
        return self._document_manager.get_by_path(path)

    # ========== Управление флагом модификации ==========

    def set_document_modified(self, doc_id: UUID, modified: bool) -> None:
        """Устанавливает флаг модификации документа.

        Args:
            doc_id: ID документа
            modified: True если документ изменён
        """
        document = self._document_manager.get_by_id(doc_id)
        if document is not None:
            document.is_modified = modified

            # Обновляем UI
            if self._active_document == doc_id and self._main_window is not None:
                self._main_window.get_status_bar().set_modified(modified)

    def is_document_modified(self, doc_id: UUID) -> bool:
        """Проверяет, изменён ли документ.

        Args:
            doc_id: ID документа

        Returns:
            True если документ имеет несохранённые изменения
        """
        document = self._document_manager.get_by_id(doc_id)
        if document is None:
            return False
        return document.is_modified

    def has_unsaved_changes(self) -> bool:
        """Проверяет наличие несохранённых изменений во всех документах.

        Returns:
            True если есть изменённые документы
        """
        return self._document_manager.has_unsaved_changes()

    def get_modified_documents(self) -> list[Document]:
        """Возвращает список изменённых документов.

        Returns:
            Список документов с несохранёнными изменениями
        """
        return self._document_manager.modified_documents

    # ========== Проверка перед закрытием приложения ==========

    def can_close_application(self) -> bool:
        """Проверяет, можно ли закрыть приложение.

        Проверяет наличие несохранённых изменений во всех документах.

        Returns:
            True если все документы сохранены
        """
        modified = self.get_modified_documents()
        if not modified:
            return True

        self._logger.info(f"Несохранённые документы: {len(modified)}")
        return False

    def get_unsaved_documents_info(self) -> list[tuple[UUID, str, Path | None]]:
        """Возвращает информацию о несохранённых документах.

        Returns:
            Список кортежей (doc_id, title, path) для несохранённых документов
        """
        result: list[tuple[UUID, str, Path | None]] = []
        for doc in self.get_modified_documents():
            path = self._document_manager.get_document_path(doc.id)
            result.append((doc.id, doc.metadata.title or "Без названия", path))
        return result

    # ========== Управление представлениями ==========

    def register_document_view(self, doc_id: UUID, view: "DocumentView") -> None:
        """Регистрирует представление для документа.

        Args:
            doc_id: ID документа
            view: Представление документа
        """
        self._document_views[doc_id] = view

    def unregister_document_view(self, doc_id: UUID) -> None:
        """Удаляет регистрацию представления.

        Args:
            doc_id: ID документа
        """
        if doc_id in self._document_views:
            del self._document_views[doc_id]

    def get_document_view(self, doc_id: UUID) -> "DocumentView | None":
        """Возвращает представление документа.

        Args:
            doc_id: ID документа

        Returns:
            Представление документа или None
        """
        return self._document_views.get(doc_id)

    def get_active_document_view(self) -> "DocumentView | None":
        """Возвращает представление активного документа.

        Returns:
            DocumentView или None
        """
        if self._active_document is None:
            return None
        return self._document_views.get(self._active_document)

    # ========== Свойства ==========

    @property
    def active_document_id(self) -> UUID | None:
        """Возвращает ID активного документа."""
        return self._active_document

    @property
    def document_count(self) -> int:
        """Возвращает количество открытых документов."""
        return self._document_manager.document_count

    @property
    def open_documents(self) -> "list[Document]":
        """Возвращает список всех открытых документов."""
        return list(self._document_manager.documents)


__all__ = ["DocumentController"]
