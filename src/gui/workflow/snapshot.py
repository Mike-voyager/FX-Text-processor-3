"""Snapshot management для workflow undo/redo.

Предоставляет dataclasses для сохранения и восстановления
состояния документа при операциях undo/redo.

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from src.controller.workflow_controller import FormStatus, WorkflowRole


@dataclass(frozen=True)
class TransitionSnapshot:
    """Немутируемый снимок состояния документа для undo/redo.

    Хранит полное состояние документа в момент времени,
    позволяя восстановить его при операции undo.

    Attributes:
        form_status: Состояние формы (DRAFT, FILLED, и т.д.).
        field_values: Значения полей формы.
        comments: Комментарии к полям.
        timestamp: Время создания снимка.
        role: Роль пользователя при создании снимка.
        document_metadata: Дополнительные метаданные документа.

    Example:
        >>> snapshot = TransitionSnapshot(
        ...     form_status=FormStatus.DRAFT,
        ...     field_values={"name": "Иванов", "amount": "1000"},
        ...     comments=[],
        ...     timestamp=datetime.now(),
        ...     role=WorkflowRole.OPERATOR,
        ... )
        >>> # При undo восстанавливаем состояние из snapshot
        >>> restore_from_snapshot(snapshot)
    """

    form_status: "FormStatus"
    field_values: Dict[str, Any]
    comments: List[Any]
    timestamp: datetime
    role: "WorkflowRole"
    document_metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Валидация после создания."""
        # Проверяем что timestamp не в будущем
        if self.timestamp > datetime.now():
            raise ValueError("Timestamp cannot be in the future")


@dataclass(frozen=True)
class SnapshotMetadata:
    """Метаданные для управления снимками.

    Attributes:
        doc_id: ID документа.
        snapshot_id: Уникальный ID снимка.
        created_at: Время создания.
        size_bytes: Размер снимка в байтах (приблизительный).
    """

    doc_id: str
    snapshot_id: str
    created_at: datetime
    size_bytes: int = 0


class SnapshotManager:
    """Менеджер для создания и восстановления снимков.

    Управляет жизненным циклом снимков состояния документов,
    обеспечивая эффективное хранение и быстрое восстановление.

    Attributes:
        _snapshots: Словарь снимков по doc_id и snapshot_id.
        _max_snapshots_per_doc: Максимальное количество снимков на документ.

    Example:
        >>> manager = SnapshotManager(max_snapshots_per_doc=50)
        >>> snapshot = manager.create_snapshot(doc_id, form_status, fields, role)
        >>> manager.restore_snapshot(snapshot)
    """

    def __init__(self, max_snapshots_per_doc: int = 100) -> None:
        """Инициализация менеджера снимков.

        Args:
            max_snapshots_per_doc: Максимальное количество снимков на документ.
        """
        self._snapshots: Dict[str, Dict[str, TransitionSnapshot]] = {}
        self._max_snapshots_per_doc = max_snapshots_per_doc

    def create_snapshot(
        self,
        doc_id: str,
        form_status: "FormStatus",
        field_values: Dict[str, Any],
        comments: List[Any],
        role: "WorkflowRole",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TransitionSnapshot:
        """Создаёт новый снимок состояния.

        Args:
            doc_id: ID документа.
            form_status: Текущее состояние формы.
            field_values: Значения полей.
            comments: Комментарии.
            role: Текущая роль.
            metadata: Дополнительные метаданные.

        Returns:
            Созданный снимок.
        """
        snapshot = TransitionSnapshot(
            form_status=form_status,
            field_values=field_values.copy(),
            comments=comments.copy(),
            timestamp=datetime.now(),
            role=role,
            document_metadata=metadata or {},
        )

        if doc_id not in self._snapshots:
            self._snapshots[doc_id] = {}

        snapshot_id = f"{doc_id}_{snapshot.timestamp.isoformat()}"
        self._snapshots[doc_id][snapshot_id] = snapshot

        # Cleanup old snapshots if limit exceeded
        self._cleanup_old_snapshots(doc_id)

        return snapshot

    def get_snapshot(self, doc_id: str, snapshot_id: str) -> Optional[TransitionSnapshot]:
        """Получает снимок по ID.

        Args:
            doc_id: ID документа.
            snapshot_id: ID снимка.

        Returns:
            Снимок или None если не найден.
        """
        return self._snapshots.get(doc_id, {}).get(snapshot_id)

    def _cleanup_old_snapshots(self, doc_id: str) -> None:
        """Удаляет старые снимки если превышен лимит."""
        if doc_id not in self._snapshots:
            return

        snapshots = self._snapshots[doc_id]
        if len(snapshots) > self._max_snapshots_per_doc:
            # Sort by timestamp and keep newest
            sorted_ids = sorted(
                snapshots.keys(),
                key=lambda k: snapshots[k].timestamp,
                reverse=True,
            )
            to_keep = sorted_ids[: self._max_snapshots_per_doc]
            self._snapshots[doc_id] = {k: snapshots[k] for k in to_keep}

    def clear_snapshots(self, doc_id: str) -> None:
        """Удаляет все снимки для документа.

        Args:
            doc_id: ID документа.
        """
        if doc_id in self._snapshots:
            del self._snapshots[doc_id]


__all__ = [
    "TransitionSnapshot",
    "SnapshotMetadata",
    "SnapshotManager",
]
