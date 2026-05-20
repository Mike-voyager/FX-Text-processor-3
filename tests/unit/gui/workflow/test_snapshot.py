"""Тесты для snapshot management.

Проверяет корректность создания, хранения и восстановления
снимков состояния документов для undo/redo.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional

import pytest

from src.gui.workflow.snapshot import (
    SnapshotManager,
    SnapshotMetadata,
    TransitionSnapshot,
)


class _FakeFormStatus(Enum):
    """Поддельный FormStatus для тестов."""
    DRAFT = "draft"
    FILLED = "filled"
    VALIDATED = "validated"


class _FakeWorkflowRole(Enum):
    """Поддельный WorkflowRole для тестов."""
    OPERATOR = "operator"
    EDITOR = "editor"


class TestTransitionSnapshot:
    """Тесты TransitionSnapshot."""

    def test_create_snapshot(self) -> None:
        """Снимок создаётся корректно."""
        snapshot = TransitionSnapshot(
            form_status=_FakeFormStatus.DRAFT,
            field_values={"name": "Тест"},
            comments=[],
            timestamp=datetime.now(),
            role=_FakeWorkflowRole.OPERATOR,
        )
        assert snapshot.form_status == _FakeFormStatus.DRAFT
        assert snapshot.field_values["name"] == "Тест"
        assert snapshot.comments == []

    def test_frozen_snapshot(self) -> None:
        """Снимок immutable (frozen=True)."""
        snapshot = TransitionSnapshot(
            form_status=_FakeFormStatus.DRAFT,
            field_values={},
            comments=[],
            timestamp=datetime.now(),
            role=_FakeWorkflowRole.OPERATOR,
        )
        with pytest.raises(AttributeError):
            snapshot.form_status = _FakeFormStatus.FILLED  # type: ignore[misc]

    def test_future_timestamp_raises(self) -> None:
        """Timestamp в будущем вызывает ValueError."""
        with pytest.raises(ValueError, match="Timestamp"):
            TransitionSnapshot(
                form_status=_FakeFormStatus.DRAFT,
                field_values={},
                comments=[],
                timestamp=datetime.now() + timedelta(hours=1),
                role=_FakeWorkflowRole.OPERATOR,
            )

    def test_document_metadata_default(self) -> None:
        """document_metadata по умолчанию пустой словарь."""
        snapshot = TransitionSnapshot(
            form_status=_FakeFormStatus.DRAFT,
            field_values={},
            comments=[],
            timestamp=datetime.now(),
            role=_FakeWorkflowRole.OPERATOR,
        )
        assert snapshot.document_metadata == {}

    def test_document_metadata_custom(self) -> None:
        """document_metadata можно задать."""
        snapshot = TransitionSnapshot(
            form_status=_FakeFormStatus.DRAFT,
            field_values={},
            comments=[],
            timestamp=datetime.now(),
            role=_FakeWorkflowRole.OPERATOR,
            document_metadata={"index": "DVN-44-K53-I"},
        )
        assert snapshot.document_metadata["index"] == "DVN-44-K53-I"


class TestSnapshotMetadata:
    """Тесты SnapshotMetadata."""

    def test_create_metadata(self) -> None:
        """Метаданные создаются корректно."""
        meta = SnapshotMetadata(
            doc_id="doc_1",
            snapshot_id="snap_1",
            created_at=datetime.now(),
            size_bytes=1024,
        )
        assert meta.doc_id == "doc_1"
        assert meta.snapshot_id == "snap_1"
        assert meta.size_bytes == 1024

    def test_size_bytes_default_zero(self) -> None:
        """size_bytes по умолчанию 0."""
        meta = SnapshotMetadata(
            doc_id="doc_1",
            snapshot_id="snap_1",
            created_at=datetime.now(),
        )
        assert meta.size_bytes == 0


class TestSnapshotManager:
    """Тесты SnapshotManager."""

    def test_create_snapshot(self) -> None:
        """Менеджер создаёт снимок корректно."""
        manager = SnapshotManager()
        snapshot = manager.create_snapshot(
            doc_id="doc_1",
            form_status=_FakeFormStatus.DRAFT,
            field_values={"field1": "value1"},
            comments=["comment1"],
            role=_FakeWorkflowRole.OPERATOR,
        )
        assert snapshot.form_status == _FakeFormStatus.DRAFT
        assert snapshot.field_values["field1"] == "value1"

    def test_create_snapshot_copies_data(self) -> None:
        """Снимок содержит копии данных, не ссылки."""
        manager = SnapshotManager()
        original_values = {"field1": "value1"}
        snapshot = manager.create_snapshot(
            doc_id="doc_1",
            form_status=_FakeFormStatus.DRAFT,
            field_values=original_values,
            comments=[],
            role=_FakeWorkflowRole.OPERATOR,
        )
        # Изменение оригинала не влияет на снимок
        original_values["field2"] = "value2"
        assert "field2" not in snapshot.field_values

    def test_get_snapshot(self) -> None:
        """Получение снимка по ID."""
        manager = SnapshotManager()
        snapshot = manager.create_snapshot(
            doc_id="doc_1",
            form_status=_FakeFormStatus.DRAFT,
            field_values={},
            comments=[],
            role=_FakeWorkflowRole.OPERATOR,
        )
        # Получаем snapshot_id из внутреннего хранилища
        snapshots = manager._snapshots.get("doc_1", {})
        snap_id = next(iter(snapshots)) if snapshots else ""
        retrieved = manager.get_snapshot("doc_1", snap_id)
        assert retrieved is not None
        assert retrieved.form_status == _FakeFormStatus.DRAFT

    def test_get_nonexistent_snapshot(self) -> None:
        """Получение несуществующего снимка возвращает None."""
        manager = SnapshotManager()
        result = manager.get_snapshot("nonexistent", "nonexistent")
        assert result is None

    def test_max_snapshots_limit(self) -> None:
        """Превышение лимита удаляет старые снимки."""
        manager = SnapshotManager(max_snapshots_per_doc=3)
        # Создаём 5 снимков
        for i in range(5):
            manager.create_snapshot(
                doc_id="doc_1",
                form_status=_FakeFormStatus.DRAFT,
                field_values={"iter": str(i)},
                comments=[],
                role=_FakeWorkflowRole.OPERATOR,
            )
        # Должно остаться максимум 3
        assert len(manager._snapshots.get("doc_1", {})) <= 3

    def test_clear_snapshots(self) -> None:
        """clear_snapshots удаляет все снимки документа."""
        manager = SnapshotManager()
        manager.create_snapshot(
            doc_id="doc_1",
            form_status=_FakeFormStatus.DRAFT,
            field_values={},
            comments=[],
            role=_FakeWorkflowRole.OPERATOR,
        )
        manager.clear_snapshots("doc_1")
        assert "doc_1" not in manager._snapshots

    def test_clear_nonexistent_doc(self) -> None:
        """clear_snapshots для несуществующего документа не вызывает ошибок."""
        manager = SnapshotManager()
        manager.clear_snapshots("nonexistent")  # Не должно быть ошибок

    def test_multiple_documents(self) -> None:
        """Снимки разных документов хранятся раздельно."""
        manager = SnapshotManager()
        manager.create_snapshot(
            doc_id="doc_1",
            form_status=_FakeFormStatus.DRAFT,
            field_values={},
            comments=[],
            role=_FakeWorkflowRole.OPERATOR,
        )
        manager.create_snapshot(
            doc_id="doc_2",
            form_status=_FakeFormStatus.FILLED,
            field_values={},
            comments=[],
            role=_FakeWorkflowRole.EDITOR,
        )
        assert "doc_1" in manager._snapshots
        assert "doc_2" in manager._snapshots