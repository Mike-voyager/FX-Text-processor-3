"""Сервис истории версий.

Управление версиями документов с возможностью отката.
Автоматическое сохранение снимков при изменениях.

Module: src/services/version_history_service.py
"""

from __future__ import annotations

import difflib
import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Protocol
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from src.model.document import Document

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Типы и константы
# ---------------------------------------------------------------------------


class VersionType(Enum):
    """Тип версии."""

    AUTO = "auto"  # Автоматическое сохранение
    MANUAL = "manual"  # Ручное сохранение
    CHECKPOINT = "checkpoint"  # Контрольная точка
    MILESTONE = "milestone"  # Важная веха


class DiffType(Enum):
    """Тип изменения."""

    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    MOVED = "moved"


# Import Enum at runtime for VersionType


@dataclass(frozen=True)
class VersionInfo:
    """Информация о версии.

    Attrs:
        id: Уникальный идентификатор
        document_id: ID документа
        version_number: Номер версии
        version_type: Тип версии
        created_at: Время создания
        created_by: Автор (optional)
        description: Описание изменений
        parent_version: ID родительской версии (optional)
        size_bytes: Размер в байтах
        checksum: Контрольная сумма
        metadata: Дополнительные метаданные
    """

    id: UUID = field(default_factory=uuid4)
    document_id: Optional[UUID] = None
    version_number: int = 1
    version_type: VersionType = VersionType.AUTO
    created_at: datetime = field(default_factory=datetime.now)
    created_by: str = ""
    description: str = ""
    parent_version: Optional[UUID] = None
    size_bytes: int = 0
    checksum: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class VersionDiff:
    """Различия между версиями.

    Attrs:
        from_version: ID исходной версии
        to_version: ID целевой версии
        changes: Список изменений
        added_lines: Добавлено строк
        removed_lines: Удалено строк
        modified_lines: Изменено строк
    """

    from_version: UUID
    to_version: UUID
    changes: List[Dict[str, Any]] = field(default_factory=list)
    added_lines: int = 0
    removed_lines: int = 0
    modified_lines: int = 0


@dataclass(frozen=True)
class VersionSnapshot:
    """Снимок версии.

    Attrs:
        version_info: Информация о версии
        data: Сериализованные данные
        path: Путь к файлу снимка
    """

    version_info: VersionInfo
    data: bytes = b""
    path: Optional[Path] = None


# ---------------------------------------------------------------------------
# Протоколы
# ---------------------------------------------------------------------------


class StorageBackend(Protocol):
    """Протокол бэкенда хранения."""

    def save_snapshot(self, snapshot: VersionSnapshot) -> bool:
        """Сохраняет снимок.

        Args:
            snapshot: Снимок версии

        Returns:
            True если успешно
        """
        ...

    def load_snapshot(self, version_id: UUID) -> Optional[VersionSnapshot]:
        """Загружает снимок.

        Args:
            version_id: ID версии

        Returns:
            Снимок или None
        """
        ...

    def delete_snapshot(self, version_id: UUID) -> bool:
        """Удаляет снимок.

        Args:
            version_id: ID версии

        Returns:
            True если успешно
        """
        ...

    def list_versions(self, document_id: UUID) -> List[VersionInfo]:
        """Возвращает список версий документа.

        Args:
            document_id: ID документа

        Returns:
            Список информации о версиях
        """
        ...


# ---------------------------------------------------------------------------
# VersionHistoryService
# ---------------------------------------------------------------------------


class VersionHistoryService:
    """Сервис истории версий.

    Предоставляет:
    - Создание снимков версий
    - Откат к предыдущим версиям
    - Сравнение версий
    - Автоматическое управление версиями
    - Ограничение количества версий

    Пример:
        >>> service = VersionHistoryService()
        >>> version = service.create_version(document, VersionType.MANUAL, "Initial version")
        >>> versions = service.get_versions(document.id)
        >>> service.rollback(document, version.id)
    """

    DEFAULT_MAX_VERSIONS = 50
    DEFAULT_AUTO_SAVE_INTERVAL = 300  # секунд

    def __init__(
        self,
        storage_dir: Optional[Path] = None,
        max_versions: int = DEFAULT_MAX_VERSIONS,
        auto_save_interval: int = DEFAULT_AUTO_SAVE_INTERVAL,
    ) -> None:
        """Инициализирует сервис.

        Args:
            storage_dir: Директория для хранения (optional)
            max_versions: Максимум версий на документ
            auto_save_interval: Интервал автосохранения (секунды)
        """
        self._storage_dir = storage_dir or Path(".versions")
        self._max_versions = max_versions
        self._auto_save_interval = auto_save_interval

        # Кэш версий: document_id -> list of VersionInfo
        self._versions: Dict[UUID, List[VersionInfo]] = {}

        # Текущая версия документа: document_id -> version_id
        self._current: Dict[UUID, UUID] = {}

        # Создаём директорию если нужно
        self._storage_dir.mkdir(parents=True, exist_ok=True)

    # ---------- Создание версий ----------

    def create_version(
        self,
        document: "Document",
        version_type: VersionType = VersionType.AUTO,
        description: str = "",
        created_by: str = "",
    ) -> Optional[VersionInfo]:
        """Создаёт новую версию документа.

        Args:
            document: Документ
            version_type: Тип версии
            description: Описание изменений
            created_by: Автор

        Returns:
            Информация о версии или None при ошибке
        """
        try:
            # Сериализуем документ
            data = self._serialize_document(document)

            # Вычисляем контрольную сумму
            checksum = hashlib.sha256(data).hexdigest()

            # Определяем номер версии
            existing = self._versions.get(document.id, [])
            version_number = len(existing) + 1

            # Определяем родительскую версию
            parent_id = self._current.get(document.id)

            # Создаём информацию о версии
            version_info = VersionInfo(
                document_id=document.id,
                version_number=version_number,
                version_type=version_type,
                created_by=created_by,
                description=description,
                parent_version=parent_id,
                size_bytes=len(data),
                checksum=checksum,
            )

            # Создаём снимок
            snapshot_path = self._get_snapshot_path(version_info.id)
            snapshot = VersionSnapshot(
                version_info=version_info,
                data=data,
                path=snapshot_path,
            )

            # Сохраняем снимок
            if not self._save_snapshot(snapshot):
                logger.error("Не удалось сохранить снимок версии")
                return None

            # Добавляем в кэш
            if document.id not in self._versions:
                self._versions[document.id] = []
            self._versions[document.id].append(version_info)
            self._current[document.id] = version_info.id

            # Ограничиваем количество версий
            self._prune_versions(document.id)

            logger.info(
                "Создана версия %d документа %s",
                version_number,
                document.id,
            )
            return version_info

        except Exception as exc:
            logger.error("Ошибка создания версии: %s", exc)
            return None

    def create_checkpoint(
        self,
        document: "Document",
        description: str = "",
    ) -> Optional[VersionInfo]:
        """Создаёт контрольную точку.

        Args:
            document: Документ
            description: Описание

        Returns:
            Информация о версии или None
        """
        return self.create_version(
            document=document,
            version_type=VersionType.CHECKPOINT,
            description=description or "Checkpoint",
        )

    def create_milestone(
        self,
        document: "Document",
        description: str = "",
    ) -> Optional[VersionInfo]:
        """Создаёт важную веху.

        Args:
            document: Документ
            description: Описание

        Returns:
            Информация о версии или None
        """
        return self.create_version(
            document=document,
            version_type=VersionType.MILESTONE,
            description=description or "Milestone",
        )

    # ---------- Откат версий ----------

    def rollback(
        self,
        document: "Document",
        version_id: UUID,
    ) -> bool:
        """Откатывает документ к указанной версии.

        Args:
            document: Документ
            version_id: ID версии для отката

        Returns:
            True если успешно
        """
        snapshot = self._load_snapshot(version_id)
        if snapshot is None:
            logger.warning("Версия не найдена: %s", version_id)
            return False

        try:
            # Десериализуем данные
            self._deserialize_document(document, snapshot.data)

            # Обновляем текущую версию
            self._current[document.id] = version_id

            logger.info("Документ откачен к версии %s", version_id)
            return True

        except Exception as exc:
            logger.error("Ошибка отката: %s", exc)
            return False

    def rollback_to_last_checkpoint(self, document: "Document") -> bool:
        """Откатывает к последней контрольной точке.

        Args:
            document: Документ

        Returns:
            True если успешно
        """
        versions = self._versions.get(document.id, [])

        # Ищем последнюю контрольную точку или веху
        for version_info in reversed(versions):
            if version_info.version_type in (VersionType.CHECKPOINT, VersionType.MILESTONE):
                return self.rollback(document, version_info.id)

        logger.warning("Контрольная точка не найдена")
        return False

    # ---------- Запросы ----------

    def get_versions(self, document_id: UUID) -> List[VersionInfo]:
        """Возвращает все версии документа.

        Args:
            document_id: ID документа

        Returns:
            Список версий (последние сначала)
        """
        versions = self._versions.get(document_id, [])
        return list(reversed(versions))

    def get_version(self, version_id: UUID) -> Optional[VersionInfo]:
        """Возвращает информацию о версии.

        Args:
            version_id: ID версии

        Returns:
            Информация о версии или None
        """
        for versions in self._versions.values():
            for version_info in versions:
                if version_info.id == version_id:
                    return version_info
        return None

    def get_current_version(self, document_id: UUID) -> Optional[VersionInfo]:
        """Возвращает текущую версию документа.

        Args:
            document_id: ID документа

        Returns:
            Информация о текущей версии или None
        """
        version_id = self._current.get(document_id)
        if version_id is None:
            return None
        return self.get_version(version_id)

    def get_version_count(self, document_id: UUID) -> int:
        """Возвращает количество версий.

        Args:
            document_id: ID документа

        Returns:
            Количество версий
        """
        return len(self._versions.get(document_id, []))

    def has_unsaved_changes(self, document: "Document") -> bool:
        """Проверяет наличие несохранённых изменений.

        Сравнивает контрольную сумму текущего документа с checksum
        последней сохранённой версии.

        Args:
            document: Документ для проверки

        Returns:
            True если есть несохранённые изменения
        """
        versions = self._versions.get(document.id, [])
        if not versions:
            return True

        try:
            data = self._serialize_document(document)
            current_checksum = hashlib.sha256(data).hexdigest()
        except Exception as exc:
            logger.error("Ошибка сериализации документа: %s", exc)
            return True

        last_version = versions[-1]
        return current_checksum != last_version.checksum

    # ---------- Сравнение версий ----------

    @staticmethod
    def _count_modified_lines(old_text: str, new_text: str) -> int:
        """Считает количество изменённых строк между двумя текстами.

        Использует difflib.Differ для построчного сравнения.
        Изменёнными считаются строки, помеченные '? ' (внутренние
        изменения в строке), а также пара удалённая + добавленная,
        если они отличаются.

        Args:
            old_text: Исходный текст
            new_text: Новый текст

        Returns:
            Количество изменённых строк
        """
        old_lines = old_text.splitlines()
        new_lines = new_text.splitlines()
        differ = difflib.Differ()
        diff = list(differ.compare(old_lines, new_lines))

        modified = 0
        i = 0
        while i < len(diff):
            line = diff[i]
            if line.startswith("? "):
                modified += 1
            i += 1

        return modified

    def compare_versions(
        self,
        version_id1: UUID,
        version_id2: UUID,
    ) -> Optional[VersionDiff]:
        """Сравнивает две версии.

        Args:
            version_id1: ID первой версии
            version_id2: ID второй версии

        Returns:
            Различия или None
        """
        snapshot1 = self._load_snapshot(version_id1)
        snapshot2 = self._load_snapshot(version_id2)

        if snapshot1 is None or snapshot2 is None:
            return None

        # Простой diff по строкам
        text1 = snapshot1.data.decode("utf-8", errors="replace")
        text2 = snapshot2.data.decode("utf-8", errors="replace")
        lines1 = text1.splitlines()
        lines2 = text2.splitlines()

        # Вычисляем различия через Differ
        differ = difflib.Differ()
        diff = list(differ.compare(lines1, lines2))

        added = sum(1 for line in diff if line.startswith("+ "))
        removed = sum(1 for line in diff if line.startswith("- "))
        modified = self._count_modified_lines(text1, text2)

        return VersionDiff(
            from_version=version_id1,
            to_version=version_id2,
            added_lines=added,
            removed_lines=removed,
            modified_lines=modified,
        )

    # ---------- Управление версиями ----------

    def delete_version(self, version_id: UUID) -> bool:
        """Удаляет версию.

        Args:
            version_id: ID версии

        Returns:
            True если успешно
        """
        version_info = self.get_version(version_id)
        if version_info is None:
            return False

        # Удаляем файл снимка
        snapshot_path = self._get_snapshot_path(version_id)
        if snapshot_path.exists():
            snapshot_path.unlink()

        # Удаляем из кэша
        for document_id, versions in self._versions.items():
            for i, v in enumerate(versions):
                if v.id == version_id:
                    versions.pop(i)
                    logger.info("Версия %s удалена", version_id)
                    return True

        return False

    def delete_all_versions(self, document_id: UUID) -> int:
        """Удаляет все версии документа.

        Args:
            document_id: ID документа

        Returns:
            Количество удалённых версий
        """
        versions = self._versions.get(document_id, [])
        count = 0

        for version_info in versions:
            snapshot_path = self._get_snapshot_path(version_info.id)
            if snapshot_path.exists():
                snapshot_path.unlink()
            count += 1

        if document_id in self._versions:
            del self._versions[document_id]
        if document_id in self._current:
            del self._current[document_id]

        logger.info("Удалено %d версий документа %s", count, document_id)
        return count

    def set_version_description(self, version_id: UUID, description: str) -> bool:
        """Устанавливает описание версии.

        Args:
            version_id: ID версии
            description: Описание

        Returns:
            True если успешно
        """
        version_info = self.get_version(version_id)
        if version_info is None:
            return False

        # Создаём новую версию с обновлённым описанием
        updated = VersionInfo(
            id=version_info.id,
            document_id=version_info.document_id,
            version_number=version_info.version_number,
            version_type=version_info.version_type,
            created_at=version_info.created_at,
            created_by=version_info.created_by,
            description=description,
            parent_version=version_info.parent_version,
            size_bytes=version_info.size_bytes,
            checksum=version_info.checksum,
            metadata=version_info.metadata,
        )

        # Обновляем в кэше
        for document_id, versions in self._versions.items():
            for i, v in enumerate(versions):
                if v.id == version_id:
                    versions[i] = updated
                    return True

        return False

    # ---------- Внутренние методы ----------

    def _serialize_document(self, document: "Document") -> bytes:
        """Сериализует документ в байты.

        Args:
            document: Документ

        Returns:
            Сериализованные данные
        """
        if not hasattr(document, "to_dict"):
            raise TypeError("Объект должен иметь метод to_dict")

        data = document.to_dict()
        return json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")

    def _deserialize_document(self, document: "Document", data: bytes) -> None:
        """Десериализует данные в документ.

        Args:
            document: Документ
            data: Данные
        """
        from src.model.document import Document

        parsed = json.loads(data.decode("utf-8"))
        loaded = Document.from_dict(parsed)

        # Обновляем содержимое документа из загруженной версии
        document.metadata = loaded.metadata
        document.page_settings = loaded.page_settings
        document.printer_settings = loaded.printer_settings
        document.sections = loaded.sections
        if loaded.file_path is not None:
            document.file_path = loaded.file_path
        document.is_modified = False

    def _get_snapshot_path(self, version_id: UUID) -> Path:
        """Возвращает путь к файлу снимка.

        Args:
            version_id: ID версии

        Returns:
            Путь к файлу
        """
        return self._storage_dir / f"{version_id}.snapshot"

    def _save_snapshot(self, snapshot: VersionSnapshot) -> bool:
        """Сохраняет снимок в файл.

        Args:
            snapshot: Снимок

        Returns:
            True если успешно
        """
        try:
            path = snapshot.path or self._get_snapshot_path(snapshot.version_info.id)

            # Сохраняем данные
            path.write_bytes(snapshot.data)

            # Сохраняем метаданные
            meta_path = path.with_suffix(".meta")
            meta = {
                "id": str(snapshot.version_info.id),
                "document_id": str(snapshot.version_info.document_id),
                "version_number": snapshot.version_info.version_number,
                "version_type": snapshot.version_info.version_type.value,
                "created_at": snapshot.version_info.created_at.isoformat(),
                "created_by": snapshot.version_info.created_by,
                "description": snapshot.version_info.description,
                "parent_version": str(snapshot.version_info.parent_version)
                if snapshot.version_info.parent_version
                else None,
                "size_bytes": snapshot.version_info.size_bytes,
                "checksum": snapshot.version_info.checksum,
                "metadata": snapshot.version_info.metadata,
            }
            meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

            return True

        except Exception as exc:
            logger.error("Ошибка сохранения снимка: %s", exc)
            return False

    def _load_snapshot(self, version_id: UUID) -> Optional[VersionSnapshot]:
        """Загружает снимок из файла.

        Args:
            version_id: ID версии

        Returns:
            Снимок или None
        """
        try:
            path = self._get_snapshot_path(version_id)
            if not path.exists():
                return None

            # Загружаем данные
            data = path.read_bytes()

            # Загружаем метаданные
            meta_path = path.with_suffix(".meta")
            if not meta_path.exists():
                return None

            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            version_info = VersionInfo(
                id=UUID(meta["id"]),
                document_id=UUID(meta["document_id"]),
                version_number=meta["version_number"],
                version_type=VersionType(meta["version_type"]),
                created_at=datetime.fromisoformat(meta["created_at"]),
                created_by=meta.get("created_by", ""),
                description=meta.get("description", ""),
                parent_version=UUID(meta["parent_version"]) if meta.get("parent_version") else None,
                size_bytes=meta.get("size_bytes", 0),
                checksum=meta.get("checksum", ""),
                metadata=meta.get("metadata", {}),
            )

            return VersionSnapshot(
                version_info=version_info,
                data=data,
                path=path,
            )

        except Exception as exc:
            logger.error("Ошибка загрузки снимка: %s", exc)
            return None

    def _prune_versions(self, document_id: UUID) -> None:
        """Удаляет старые версии при превышении лимита.

        Args:
            document_id: ID документа
        """
        versions = self._versions.get(document_id, [])
        if len(versions) <= self._max_versions:
            return

        # Не удаляем контрольные точки и вехи
        protected_types = (VersionType.CHECKPOINT, VersionType.MILESTONE)

        to_remove = []
        for version_info in versions:
            if version_info.version_type not in protected_types:
                to_remove.append(version_info)
                if len(versions) - len(to_remove) <= self._max_versions:
                    break

        for version_info in to_remove:
            self.delete_version(version_info.id)


__all__ = [
    "VersionHistoryService",
    "VersionInfo",
    "VersionType",
    "VersionDiff",
    "VersionSnapshot",
    "DiffType",
    "StorageBackend",
]
