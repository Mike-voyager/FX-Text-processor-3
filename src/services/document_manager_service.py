"""Сервис управления документами (MDI).

Отвечает за:
- Создание, открытие, закрытие документов
- Управление списком открытых документов
- Активный документ (current)
- Блокировка повторного открытия (через document_lock_service)
- Интеграция с DocumentFormat для I/O

Module: src/services/document_manager_service.py
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Protocol
from uuid import UUID

if TYPE_CHECKING:
    from src.documents.format.document_format import DocumentFormat
    from src.model.document import Document

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Протоколы
# ---------------------------------------------------------------------------


class DocumentLockProtocol(Protocol):
    """Протокол сервиса блокировки документов."""

    def try_lock(self, path: Path, owner_id: str) -> bool:
        """Попытка захватить блокировку файла.

        Args:
            path: Путь к файлу
            owner_id: Идентификатор владельца (session_id)

        Returns:
            True если блокировка успешна
        """
        ...

    def release_lock(self, path: Path, owner_id: str) -> None:
        """Освободить блокировку файла."""
        ...

    def is_locked(self, path: Path) -> bool:
        """Проверить, заблокирован ли файл."""
        ...

    def get_lock_info(self, path: Path) -> Optional[Dict[str, Any]]:
        """Получить информацию о блокировке."""
        ...


class AuditCallbackProtocol(Protocol):
    """Протокол callback для аудита."""

    def __call__(self, event: str, details: Dict[str, Any]) -> None:
        """Записать событие аудита."""
        ...


# ---------------------------------------------------------------------------
# Результаты операций
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CreateResult:
    """Результат создания документа.

    Attrs:
        success: True при успехе
        document: Созданный документ или None
        error: Сообщение об ошибке или None
    """

    success: bool
    document: Optional["Document"] = None
    error: Optional[str] = None


@dataclass(frozen=True)
class OpenResult:
    """Результат открытия документа.

    Attrs:
        success: True при успехе
        document: Открытый документ или None
        error: Сообщение об ошибке или None
        already_open: True если документ уже открыт в MDI
        already_locked: True если документ заблокирован другим процессом
    """

    success: bool
    document: Optional["Document"] = None
    error: Optional[str] = None
    already_open: bool = False
    already_locked: bool = False


@dataclass(frozen=True)
class CloseResult:
    """Результат закрытия документа.

    Attrs:
        success: True при успехе
        needs_save: True если документ изменён и требует сохранения
        saved: True если документ был сохранён перед закрытием
        error: Сообщение об ошибке или None
    """

    success: bool
    needs_save: bool = False
    saved: bool = False
    error: Optional[str] = None


@dataclass(frozen=True)
class SaveResult:
    """Результат сохранения документа.

    Attrs:
        success: True при успехе
        path: Путь сохранения
        error: Сообщение об ошибке или None
    """

    success: bool
    path: Optional[Path] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# DocumentManagerService
# ---------------------------------------------------------------------------


class DocumentManagerService:
    """MDI менеджер документов.

    Управляет жизненным циклом открытых документов:
    - Создание новых документов (blank, from template)
    - Открытие файлов (.fxsd, .fxsd.enc)
    - Закрытие с проверкой изменений
    - Переключение между документами
    - Сохранение (save/save_as/save_all)

    Интеграции:
    - DocumentFormat: сериализация/десериализация
    - DocumentLockService: защита от двойного открытия
    - AuditCallback: логирование операций

    Пример:
        >>> manager = DocumentManagerService(format=DocumentFormat())
        >>> result = manager.create_new("Новый документ")
        >>> if result.success:
        ...     print(f"Создан: {result.document.id}")
    """

    def __init__(
        self,
        format: "DocumentFormat",
        lock_service: Optional[DocumentLockProtocol] = None,
        audit_callback: Optional[AuditCallbackProtocol] = None,
        max_documents: int = 100,
    ) -> None:
        """Инициализирует менеджер документов.

        Args:
            format: Сервис сериализации документов
            lock_service: Сервис блокировки файлов (optional)
            audit_callback: Callback для аудита (optional)
            max_documents: Максимальное количество открытых документов
        """
        self._format = format
        self._lock_service = lock_service
        self._audit_callback = audit_callback
        self._max_documents = max_documents

        # Внутреннее состояние
        self._documents: Dict[UUID, "Document"] = {}
        self._paths: Dict[UUID, Path] = {}  # document_id -> file_path
        self._active_id: Optional[UUID] = None
        self._owner_id: str = "default"  # Идентификатор сессии для блокировок

    # ---------- Свойства ----------

    @property
    def active_document(self) -> Optional["Document"]:
        """Возвращает активный документ или None."""
        if self._active_id is None:
            return None
        return self._documents.get(self._active_id)

    @property
    def active_path(self) -> Optional[Path]:
        """Возвращает путь активного документа или None."""
        if self._active_id is None:
            return None
        return self._paths.get(self._active_id)

    @property
    def document_count(self) -> int:
        """Возвращает количество открытых документов."""
        return len(self._documents)

    @property
    def documents(self) -> Iterator["Document"]:
        """Итератор по всем открытым документам."""
        return iter(self._documents.values())

    @property
    def modified_documents(self) -> List["Document"]:
        """Список изменённых документов."""
        return [doc for doc in self._documents.values() if doc.is_modified]

    # ---------- Создание документов ----------

    def create_new(
        self,
        title: str = "Без названия",
        template: Optional["Document"] = None,
    ) -> CreateResult:
        """Создаёт новый документ.

        Args:
            title: Заголовок документа
            template: Шаблон для копирования (optional)

        Returns:
            CreateResult с созданным документом или ошибкой
        """
        # Проверка лимита
        if len(self._documents) >= self._max_documents:
            error = f"Достигнут лимит открытых документов: {self._max_documents}"
            logger.warning(error)
            return CreateResult(success=False, error=error)

        # Импорт здесь для избежания циклических зависимостей
        from src.model.document import Document, DocumentMetadata

        # Создание документа
        if template is not None:
            # Копируем из шаблона (без sections, т.к. они не serializable)
            metadata = DocumentMetadata(
                title=title,
                author=template.metadata.author,
                subject=template.metadata.subject,
                keywords=template.metadata.keywords.copy(),
            )
            doc = Document(
                metadata=metadata,
                page_settings=template.page_settings,
                printer_settings=template.printer_settings,
            )
        else:
            metadata = DocumentMetadata(title=title)
            doc = Document(metadata=metadata)
            # Add initial section with empty paragraph
            section = doc.add_section()
            from src.model.paragraph import Paragraph

            section.add_paragraph(Paragraph())  # Empty paragraph for editing

        # Добавляем в менеджер
        self._documents[doc.id] = doc
        self._active_id = doc.id

        logger.info("Создан новый документ: %s (%s)", doc.id, title)
        self._audit("document.created", {"doc_id": str(doc.id), "title": title})

        return CreateResult(success=True, document=doc)

    # ---------- Открытие документов ----------

    def open_file(
        self,
        path: Path,
        *,
        decrypt: bool = False,
        password: Optional[str] = None,
    ) -> OpenResult:
        """Открывает документ из файла.

        Args:
            path: Путь к файлу (.fxsd или .fxsd.enc)
            decrypt: Флаг дешифрования для .fxsd.enc
            password: Пароль для дешифрования

        Returns:
            OpenResult с документом или ошибкой
        """
        # Проверка существования файла
        if not path.exists():
            error = f"Файл не найден: {path}"
            logger.warning(error)
            return OpenResult(success=False, error=error)

        # Проверка на уже открытый документ
        for doc_id, doc_path in self._paths.items():
            if doc_path.resolve() == path.resolve():
                # Документ уже открыт в этом менеджере
                doc = self._documents.get(doc_id)
                if doc is not None:
                    self._active_id = doc_id
                    logger.info("Документ уже открыт: %s", path)
                    return OpenResult(success=True, document=doc, already_open=True)

        # Проверка блокировки (если сервис доступен)
        if self._lock_service:
            if self._lock_service.is_locked(path):
                lock_info = self._lock_service.get_lock_info(path)
                if lock_info and lock_info.get("owner_id") != self._owner_id:
                    logger.warning("Файл заблокирован: %s", path)
                    return OpenResult(
                        success=False,
                        already_locked=True,
                        error="Файл заблокирован другим процессом",
                    )

        # Проверка лимита
        if len(self._documents) >= self._max_documents:
            error = f"Достигнут лимит открытых документов: {self._max_documents}"
            logger.warning(error)
            return OpenResult(success=False, error=error)

        try:
            # Загрузка через DocumentFormat
            if decrypt and password:
                # Требуется криптосервис
                doc = self._load_encrypted(path, password)
            else:
                doc = self._format.load(path)

            # Блокировка файла
            if self._lock_service:
                self._lock_service.try_lock(path, self._owner_id)

            # Добавляем в менеджер
            self._documents[doc.id] = doc
            self._paths[doc.id] = path.resolve()
            doc.file_path = path.resolve()
            self._active_id = doc.id

            logger.info("Открыт документ: %s (%s)", doc.id, path)
            self._audit("document.opened", {"doc_id": str(doc.id), "path": str(path)})

            return OpenResult(success=True, document=doc)

        except Exception as exc:
            error = f"Ошибка открытия файла {path}: {exc}"
            logger.error(error, exc_info=True)
            return OpenResult(success=False, error=error)

    def _load_encrypted(self, path: Path, password: str) -> "Document":
        """Загружает зашифрованный документ.

        В текущей версии выбрасывает NotImplementedError.
        Полная реализация требует CryptoService.

        Args:
            path: Путь к зашифрованному файлу
            password: Пароль дешифрования

        Returns:
            Расшифрованный документ

        Raises:
            NotImplementedError: Метод требует интеграции с CryptoService
        """
        raise NotImplementedError(
            "Дешифрование требует интеграции с CryptoService. "
            "Используйте open_file с параметром decrypt=False или "
            "передайте расшифрованные данные."
        )

    # ---------- Закрытие документов ----------

    def close(
        self,
        document_id: UUID,
        *,
        save_if_modified: bool = True,
        force: bool = False,
    ) -> CloseResult:
        """Закрывает документ.

        Args:
            document_id: Идентификатор документа
            save_if_modified: Сохранять изменённый документ
            force: Закрыть без сохранения даже если изменён

        Returns:
            CloseResult с результатом операции
        """
        doc = self._documents.get(document_id)
        if doc is None:
            return CloseResult(success=False, error=f"Документ не найден: {document_id}")

        # Проверка изменений
        needs_save = doc.is_modified and not force

        if needs_save and save_if_modified:
            # Автосохранение
            path = self._paths.get(document_id)
            if path:
                save_result = self.save(document_id, path)
                if not save_result.success:
                    return CloseResult(
                        success=False,
                        needs_save=True,
                        error=save_result.error,
                    )
                return CloseResult(success=True, needs_save=True, saved=True)

        # Удаляем из менеджера
        del self._documents[document_id]
        path = self._paths.pop(document_id, None)

        # Освобождаем блокировку
        if path and self._lock_service:
            self._lock_service.release_lock(path, self._owner_id)

        # Переключаем активный документ
        if self._active_id == document_id:
            self._active_id = next(iter(self._documents.keys()), None)

        logger.info("Закрыт документ: %s", document_id)
        self._audit("document.closed", {"doc_id": str(document_id), "saved": needs_save})

        return CloseResult(success=True, needs_save=needs_save, saved=False)

    def close_all(
        self,
        *,
        save_if_modified: bool = True,
        force: bool = False,
    ) -> Dict[UUID, CloseResult]:
        """Закрывает все открытые документы.

        Args:
            save_if_modified: Сохранять изменённые документы
            force: Закрыть без сохранения

        Returns:
            Словарь {document_id: CloseResult}
        """
        results: Dict[UUID, CloseResult] = {}
        for doc_id in list(self._documents.keys()):
            results[doc_id] = self.close(doc_id, save_if_modified=save_if_modified, force=force)
        return results

    # ---------- Сохранение документов ----------

    def save(
        self,
        document_id: UUID,
        path: Optional[Path] = None,
    ) -> SaveResult:
        """Сохраняет документ.

        Args:
            document_id: Идентификатор документа
            path: Путь сохранения (если None, использует текущий путь)

        Returns:
            SaveResult с результатом операции
        """
        doc = self._documents.get(document_id)
        if doc is None:
            return SaveResult(success=False, error=f"Документ не найден: {document_id}")

        # Определяем путь
        save_path = path or self._paths.get(document_id)
        if save_path is None:
            return SaveResult(success=False, error="Путь сохранения не указан")

        try:
            # Обновляем метаданные
            # Note: Document.metadata is frozen=True, нужно создать новый metadata
            # В текущей версии просто сохраняем

            # Сохранение через DocumentFormat
            self._format.save(doc, save_path)

            # Обновляем состояние
            self._paths[document_id] = save_path.resolve()
            doc.file_path = save_path.resolve()
            doc.is_modified = False

            logger.info("Сохранён документ: %s -> %s", document_id, save_path)
            self._audit("document.saved", {"doc_id": str(document_id), "path": str(save_path)})

            return SaveResult(success=True, path=save_path)

        except Exception as exc:
            error = f"Ошибка сохранения: {exc}"
            logger.error(error, exc_info=True)
            return SaveResult(success=False, error=error)

    def save_all(self) -> Dict[UUID, SaveResult]:
        """Сохраняет все изменённые документы.

        Returns:
            Словарь {document_id: SaveResult}
        """
        results: Dict[UUID, SaveResult] = {}
        for doc in self.modified_documents:
            if doc.id:
                results[doc.id] = self.save(doc.id)
        return results

    # ---------- Активация документов ----------

    def set_active(self, document_id: UUID) -> bool:
        """Устанавливает активный документ.

        Args:
            document_id: Идентификатор документа

        Returns:
            True если документ найден и активирован
        """
        if document_id in self._documents:
            self._active_id = document_id
            logger.debug("Активирован документ: %s", document_id)
            return True
        return False

    def get_by_id(self, document_id: UUID) -> Optional["Document"]:
        """Возвращает документ по ID.

        Args:
            document_id: Идентификатор документа

        Returns:
            Document или None если не найден
        """
        return self._documents.get(document_id)

    def get_by_path(self, path: Path) -> Optional["Document"]:
        """Возвращает документ по пути файла.

        Args:
            path: Путь к файлу

        Returns:
            Document или None если не найден
        """
        resolved = path.resolve()
        for doc_id, doc_path in self._paths.items():
            if doc_path == resolved:
                return self._documents.get(doc_id)
        return None

    # ---------- Утилиты ----------

    def has_unsaved_changes(self) -> bool:
        """Проверяет, есть ли несохранённые изменения."""
        return len(self.modified_documents) > 0

    def get_document_path(self, document_id: UUID) -> Optional[Path]:
        """Возвращает путь документа по ID."""
        return self._paths.get(document_id)

    def set_owner_id(self, owner_id: str) -> None:
        """Устанавливает идентификатор владельца для блокировок."""
        self._owner_id = owner_id

    def _audit(self, event: str, details: Dict[str, Any]) -> None:
        """Записывает событие аудита."""
        if self._audit_callback:
            try:
                self._audit_callback(event, details)
            except Exception as exc:
                logger.error("Ошибка аудита: %s", exc)


__all__ = [
    "DocumentManagerService",
    "DocumentLockProtocol",
    "AuditCallbackProtocol",
    "CreateResult",
    "OpenResult",
    "CloseResult",
    "SaveResult",
]
