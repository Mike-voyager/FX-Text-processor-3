"""Тесты DocumentManagerService.

Module: tests/unit/services/test_document_manager_service.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch
from uuid import UUID

import pytest

from src.services.document_manager_service import (
    AuditCallbackProtocol,
    CloseResult,
    CreateResult,
    DocumentLockProtocol,
    DocumentManagerService,
    OpenResult,
    SaveResult,
)


# ---------------------------------------------------------------------------
# Моки
# ---------------------------------------------------------------------------


class MockDocumentFormat:
    """Мок DocumentFormat."""

    def __init__(self) -> None:
        self.saved_documents: Dict[Path, Any] = {}
        self.load_side_effect: Optional[Exception] = None

    def save(self, document: Any, path: Path) -> None:
        """Сохраняет документ в файл."""
        # Создаём директорию и файл
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}")
        self.saved_documents[path] = document

    def load(self, path: Path) -> Any:
        """Загружает документ из файла."""
        if self.load_side_effect:
            raise self.load_side_effect
        if path not in self.saved_documents:
            raise FileNotFoundError(f"File not found: {path}")
        return self.saved_documents[path]


class MockDocument:
    """Мок Document."""

    def __init__(self, title: str = "Test", doc_id: Optional[UUID] = None) -> None:
        from uuid import uuid4

        self.id = doc_id or uuid4()
        self.metadata = MagicMock()
        self.metadata.title = title
        self.file_path: Optional[Path] = None
        self._is_modified = False

    @property
    def is_modified(self) -> bool:
        return self._is_modified

    @is_modified.setter
    def is_modified(self, value: bool) -> None:
        self._is_modified = value


class MockLockService:
    """Мок DocumentLockProtocol."""

    def __init__(self) -> None:
        self.locks: Dict[Path, str] = {}

    def try_lock(self, path: Path, owner_id: str) -> bool:
        """Попытка захватить блокировку."""
        if path in self.locks and self.locks[path] != owner_id:
            return False
        self.locks[path] = owner_id
        return True

    def release_lock(self, path: Path, owner_id: str) -> None:
        """Освободить блокировку."""
        if path in self.locks:
            del self.locks[path]

    def is_locked(self, path: Path) -> bool:
        """Проверить блокировку."""
        return path in self.locks

    def get_lock_info(self, path: Path) -> Optional[Dict[str, Any]]:
        """Получить информацию о блокировке."""
        if path in self.locks:
            return {"owner_id": self.locks[path]}
        return None


# ---------------------------------------------------------------------------
# Фикстуры
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_format() -> MockDocumentFormat:
    """Мок DocumentFormat."""
    return MockDocumentFormat()


@pytest.fixture
def lock_service() -> MockLockService:
    """Мок LockService."""
    return MockLockService()


@pytest.fixture
def audit_events() -> list[tuple[str, Dict[str, Any]]]:
    """Список событий аудита."""
    return []


@pytest.fixture
def audit_callback(
    audit_events: list[tuple[str, Dict[str, Any]]],
) -> AuditCallbackProtocol:
    """Callback для аудита."""

    def callback(event: str, details: Dict[str, Any]) -> None:
        audit_events.append((event, details))

    return callback


@pytest.fixture
def manager(
    mock_format: MockDocumentFormat,
    lock_service: MockLockService,
    audit_callback: AuditCallbackProtocol,
) -> DocumentManagerService:
    """Менеджер документов с моками."""
    return DocumentManagerService(
        format=mock_format,  # type: ignore
        lock_service=lock_service,
        audit_callback=audit_callback,
        max_documents=10,
    )


# ---------------------------------------------------------------------------
# Тесты создания документов
# ---------------------------------------------------------------------------


class TestCreateDocument:
    """Тесты создания документов."""

    def test_create_new_success(self, manager: DocumentManagerService) -> None:
        """Тест успешного создания документа."""
        result = manager.create_new("Тестовый документ")

        assert result.success
        assert result.document is not None
        assert result.error is None
        assert manager.document_count == 1
        assert manager.active_document == result.document

    def test_create_new_default_title(self, manager: DocumentManagerService) -> None:
        """Тест создания с заголовком по умолчанию."""
        result = manager.create_new()

        assert result.success
        assert result.document is not None
        # Проверяем, что документ создан

    def test_create_new_max_limit(self, mock_format: MockDocumentFormat) -> None:
        """Тест лимита документов."""
        manager = DocumentManagerService(
            format=mock_format,  # type: ignore
            max_documents=2,
        )

        # Создаём 2 документа
        manager.create_new("Doc 1")
        manager.create_new("Doc 2")

        # Третий должен быть отклонён
        result = manager.create_new("Doc 3")
        assert not result.success
        assert "лимит" in (result.error or "").lower()

    def test_create_new_activates_document(self, manager: DocumentManagerService) -> None:
        """Тест, что созданный документ становится активным."""
        manager.create_new("Doc 1")
        result2 = manager.create_new("Doc 2")

        assert manager.active_document == result2.document


# ---------------------------------------------------------------------------
# Тесты открытия документов
# ---------------------------------------------------------------------------


class TestOpenFile:
    """Тесты открытия файлов."""

    def test_open_file_not_found(self, manager: DocumentManagerService) -> None:
        """Тест открытия несуществующего файла."""
        result = manager.open_file(Path("/nonexistent.fxsd"))

        assert not result.success
        assert "не найден" in (result.error or "").lower()

    def test_open_file_success(
        self,
        manager: DocumentManagerService,
        mock_format: MockDocumentFormat,
        tmp_path: Path,
    ) -> None:
        """Тест успешного открытия файла."""
        # Создаём тестовый файл
        from src.model.document import Document, DocumentMetadata

        doc = Document(metadata=DocumentMetadata(title="Test"))
        test_file = tmp_path / "test.fxsd"
        mock_format.saved_documents[test_file] = doc
        # Создаём файл (DocumentManager проверяет существование)
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("{}")

        result = manager.open_file(test_file)

        assert result.success
        assert result.document is not None
        assert not result.already_open
        assert manager.document_count == 1

    def test_open_file_already_open(
        self,
        manager: DocumentManagerService,
        mock_format: MockDocumentFormat,
        tmp_path: Path,
    ) -> None:
        """Тест повторного открытия того же файла."""
        from src.model.document import Document, DocumentMetadata

        doc = Document(metadata=DocumentMetadata(title="Test"))
        test_file = tmp_path / "test.fxsd"
        mock_format.saved_documents[test_file] = doc
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("{}")

        # Первое открытие
        result1 = manager.open_file(test_file)
        assert result1.success

        # Повторное открытие
        result2 = manager.open_file(test_file)
        assert result2.success
        assert result2.already_open
        assert result2.document == result1.document

    def test_open_file_locked(
        self,
        mock_format: MockDocumentFormat,
        lock_service: MockLockService,
        audit_callback: AuditCallbackProtocol,
        tmp_path: Path,
    ) -> None:
        """Тест открытия заблокированного файла."""
        from src.model.document import Document, DocumentMetadata

        manager = DocumentManagerService(
            format=mock_format,  # type: ignore
            lock_service=lock_service,
            audit_callback=audit_callback,
        )
        manager.set_owner_id("owner1")

        # Создаём тестовый файл
        doc = Document(metadata=DocumentMetadata(title="Test"))
        test_file = tmp_path / "test.fxsd"
        mock_format.saved_documents[test_file] = doc
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("{}")

        # Блокируем файл другим процессом
        lock_service.try_lock(test_file, "other_owner")

        result = manager.open_file(test_file)
        assert not result.success
        assert result.already_locked


# ---------------------------------------------------------------------------
# Тесты закрытия документов
# ---------------------------------------------------------------------------


class TestCloseDocument:
    """Тесты закрытия документов."""

    def test_close_success(self, manager: DocumentManagerService) -> None:
        """Тест успешного закрытия."""
        create_result = manager.create_new("Test")
        doc_id = create_result.document.id  # type: ignore

        close_result = manager.close(doc_id)

        assert close_result.success
        assert not close_result.needs_save
        assert manager.document_count == 0

    def test_close_nonexistent(self, manager: DocumentManagerService) -> None:
        """Тест закрытия несуществующего документа."""
        from uuid import uuid4

        result = manager.close(uuid4())

        assert not result.success
        assert "не найден" in (result.error or "").lower()

    def test_close_modified_document(
        self,
        manager: DocumentManagerService,
        mock_format: MockDocumentFormat,
        tmp_path: Path,
    ) -> None:
        """Тест закрытия изменённого документа."""
        from src.model.document import Document, DocumentMetadata

        # Создаём документ с сохранением
        doc = Document(metadata=DocumentMetadata(title="Test"))
        test_file = tmp_path / "test.fxsd"
        mock_format.saved_documents[test_file] = doc
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("{}")

        open_result = manager.open_file(test_file)
        doc_id = open_result.document.id  # type: ignore

        # Помечаем как изменённый
        open_result.document._is_modified = True  # type: ignore

        # Закрываем с автосохранением
        close_result = manager.close(doc_id, save_if_modified=True)

        assert close_result.success
        assert close_result.needs_save
        assert close_result.saved

    def test_close_all(self, manager: DocumentManagerService) -> None:
        """Тест закрытия всех документов."""
        manager.create_new("Doc 1")
        manager.create_new("Doc 2")
        manager.create_new("Doc 3")

        assert manager.document_count == 3

        results = manager.close_all()

        assert all(r.success for r in results.values())
        assert manager.document_count == 0


# ---------------------------------------------------------------------------
# Тесты сохранения документов
# ---------------------------------------------------------------------------


class TestSaveDocument:
    """Тесты сохранения документов."""

    def test_save_success(
        self,
        manager: DocumentManagerService,
        mock_format: MockDocumentFormat,
        tmp_path: Path,
    ) -> None:
        """Тест успешного сохранения."""
        from src.model.document import Document, DocumentMetadata

        doc = Document(metadata=DocumentMetadata(title="Test"))
        test_file = tmp_path / "test.fxsd"
        mock_format.saved_documents[test_file] = doc
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("{}")

        open_result = manager.open_file(test_file)
        doc_id = open_result.document.id  # type: ignore

        save_result = manager.save(doc_id)

        assert save_result.success
        assert save_result.path == test_file

    def test_save_nonexistent(self, manager: DocumentManagerService) -> None:
        """Тест сохранения несуществующего документа."""
        from uuid import uuid4

        result = manager.save(uuid4())

        assert not result.success
        assert "не найден" in (result.error or "").lower()

    def test_save_no_path(
        self,
        manager: DocumentManagerService,
    ) -> None:
        """Тест сохранения без указания пути."""
        create_result = manager.create_new("Test")
        doc_id = create_result.document.id  # type: ignore

        save_result = manager.save(doc_id)

        assert not save_result.success
        assert "путь" in (save_result.error or "").lower()


# ---------------------------------------------------------------------------
# Тесты активации документов
# ---------------------------------------------------------------------------


class TestDocumentActivation:
    """Тесты активации документов."""

    def test_set_active(self, manager: DocumentManagerService) -> None:
        """Тест установки активного документа."""
        result1 = manager.create_new("Doc 1")
        result2 = manager.create_new("Doc 2")

        assert manager.active_document == result2.document

        # Переключаем на первый
        success = manager.set_active(result1.document.id)  # type: ignore

        assert success
        assert manager.active_document == result1.document

    def test_set_active_nonexistent(self, manager: DocumentManagerService) -> None:
        """Тест установки несуществующего активного документа."""
        from uuid import uuid4

        success = manager.set_active(uuid4())
        assert not success

    def test_get_by_id(self, manager: DocumentManagerService) -> None:
        """Тест получения документа по ID."""
        result = manager.create_new("Test")
        doc_id = result.document.id  # type: ignore

        found = manager.get_by_id(doc_id)

        assert found == result.document

    def test_get_by_path(
        self,
        manager: DocumentManagerService,
        mock_format: MockDocumentFormat,
        tmp_path: Path,
    ) -> None:
        """Тест получения документа по пути."""
        from src.model.document import Document, DocumentMetadata

        doc = Document(metadata=DocumentMetadata(title="Test"))
        test_file = tmp_path / "test.fxsd"
        mock_format.saved_documents[test_file] = doc
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("{}")

        manager.open_file(test_file)

        found = manager.get_by_path(test_file)
        assert found is not None


# ---------------------------------------------------------------------------
# Тесты утилит
# ---------------------------------------------------------------------------


class TestUtilities:
    """Тесты утилитарных методов."""

    def test_has_unsaved_changes(self, manager: DocumentManagerService) -> None:
        """Тест проверки несохранённых изменений."""
        assert not manager.has_unsaved_changes()

        result = manager.create_new("Test")
        assert not manager.has_unsaved_changes()

        # Помечаем как изменённый
        result.document._is_modified = True  # type: ignore
        assert manager.has_unsaved_changes()

    def test_modified_documents(self, manager: DocumentManagerService) -> None:
        """Тест списка изменённых документов."""
        manager.create_new("Doc 1")
        result2 = manager.create_new("Doc 2")
        manager.create_new("Doc 3")

        assert len(manager.modified_documents) == 0

        # Изменяем один документ
        result2.document._is_modified = True  # type: ignore
        assert len(manager.modified_documents) == 1

    def test_set_owner_id(self, manager: DocumentManagerService) -> None:
        """Тест установки ID владельца."""
        manager.set_owner_id("new_owner")
        # Просто проверяем, что метод не падает
        assert manager._owner_id == "new_owner"

    def test_audit_callback(
        self,
        manager: DocumentManagerService,
        audit_events: list[tuple[str, Dict[str, Any]]],
    ) -> None:
        """Тест вызова audit callback."""
        result = manager.create_new("Test")

        # Проверяем, что событие записано
        assert len(audit_events) == 1
        event, details = audit_events[0]
        assert event == "document.created"
        assert "doc_id" in details
        assert details["title"] == "Test"


# ---------------------------------------------------------------------------
# Тесты интеграции
# ---------------------------------------------------------------------------


class TestIntegration:
    """Интеграционные тесты."""

    def test_full_lifecycle(
        self,
        mock_format: MockDocumentFormat,
        tmp_path: Path,
    ) -> None:
        """Тест полного жизненного цикла документа."""
        from src.model.document import Document, DocumentMetadata

        # Создаём менеджер
        manager = DocumentManagerService(format=mock_format)  # type: ignore

        # Создаём документ
        create_result = manager.create_new("Новый документ")
        assert create_result.success

        # Создаём тестовый файл для сохранения
        doc = Document(metadata=DocumentMetadata(title="Test"))
        test_file = tmp_path / "test.fxsd"
        mock_format.saved_documents[test_file] = doc
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("{}")

        # Открываем файл
        open_result = manager.open_file(test_file)
        assert open_result.success

        # Переключаемся между документами
        manager.set_active(create_result.document.id)  # type: ignore
        assert manager.active_document == create_result.document

        manager.set_active(open_result.document.id)  # type: ignore
        assert manager.active_document == open_result.document

        # Закрываем все
        results = manager.close_all()
        assert all(r.success for r in results.values())
        assert manager.document_count == 0