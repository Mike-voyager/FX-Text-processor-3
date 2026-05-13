"""Тесты для PrintQueueService.

Module: tests/unit/services/test_print_queue_service.py
"""

from datetime import datetime
from unittest.mock import MagicMock
from uuid import UUID

import pytest

from src.services.print_queue_service import (
    PrintJob,
    PrintJobStatus,
    PrintPriority,
    PrintQueueCallback,
    PrintQueueService,
    PrinterAdapterProtocol,
    QueueStats,
)


class TestPrintJob:
    """Тесты PrintJob dataclass."""

    def test_create_print_job(self) -> None:
        """Создание задания печати."""
        from uuid import uuid4

        doc_id = uuid4()
        job = PrintJob(
            document_id=doc_id,
            document_name="Test Document",
            printer_name="FX-890",
            copies=2,
        )

        assert job.document_id == doc_id
        assert job.document_name == "Test Document"
        assert job.printer_name == "FX-890"
        assert job.copies == 2
        assert job.priority == PrintPriority.NORMAL
        assert job.status == PrintJobStatus.PENDING
        assert isinstance(job.id, UUID)
        assert isinstance(job.created_at, datetime)

    def test_print_job_frozen(self) -> None:
        """Проверка frozen dataclass."""
        job = PrintJob(document_name="Test")

        with pytest.raises(AttributeError):
            job.document_name = "Changed"  # type: ignore[misc]


class TestPrintQueueService:
    """Тесты PrintQueueService."""

    def test_create_service(self) -> None:
        """Создание сервиса."""
        service = PrintQueueService()
        assert service.get_queue_size() == 0
        assert service.get_active_count() == 0

    def test_create_service_with_callback(self) -> None:
        """Создание сервиса с callback."""
        callback: PrintQueueCallback = MagicMock()
        service = PrintQueueService(callback=callback)
        assert service._callback == callback

    def test_add_job(self) -> None:
        """Добавление задания."""
        service = PrintQueueService()
        job = service.add_job(
            document_name="Doc1",
            printer_name="FX-890",
            copies=1,
        )

        assert job.document_name == "Doc1"
        assert service.get_queue_size() == 1
        assert service.get_pending_jobs()[0] == job

    def test_add_job_with_priority(self) -> None:
        """Добавление задания с приоритетом."""
        service = PrintQueueService()

        low_job = service.add_job(document_name="Low", priority=PrintPriority.LOW)
        high_job = service.add_job(document_name="High", priority=PrintPriority.HIGH)
        urgent_job = service.add_job(document_name="Urgent", priority=PrintPriority.URGENT)

        # Проверяем порядок получения
        assert service.get_next_job() == urgent_job
        assert service.get_next_job() == high_job
        assert service.get_next_job() == low_job

    def test_add_job_queue_full(self) -> None:
        """Добавление задания при полной очереди."""
        service = PrintQueueService(max_jobs=2)

        service.add_job(document_name="Job1")
        service.add_job(document_name="Job2")

        with pytest.raises(ValueError, match="переполнена"):
            service.add_job(document_name="Job3")

    def test_start_job(self) -> None:
        """Запуск задания."""
        service = PrintQueueService()
        job = service.add_job(document_name="Test")

        result = service.start_job(job.id)
        assert result is True

        # Проверяем статус
        active = service.get_active_jobs()
        assert len(active) == 1
        assert active[0].status == PrintJobStatus.PRINTING
        assert active[0].started_at is not None

        # Проверяем, что удалено из очереди
        assert service.get_queue_size() == 0

    def test_start_nonexistent_job(self) -> None:
        """Запуск несуществующего задания."""
        from uuid import uuid4

        service = PrintQueueService()
        result = service.start_job(uuid4())
        assert result is False

    def test_start_wrong_status_job(self) -> None:
        """Запуск задания в неправильном статусе."""
        service = PrintQueueService()
        job = service.add_job(document_name="Test")
        service.start_job(job.id)

        # Пытаемся запустить уже запущенное
        result = service.start_job(job.id)
        assert result is False

    def test_pause_job(self) -> None:
        """Приостановка задания."""
        service = PrintQueueService()
        job = service.add_job(document_name="Test")
        service.start_job(job.id)

        result = service.pause_job(job.id)
        assert result is True

        # Проверяем, что возвращено в очередь
        pending = service.get_pending_jobs()
        assert len(pending) == 1
        assert pending[0].status == PrintJobStatus.PAUSED

    def test_pause_non_printing_job(self) -> None:
        """Приостановка не печатающегося задания."""
        service = PrintQueueService()
        job = service.add_job(document_name="Test")

        result = service.pause_job(job.id)
        assert result is False

    def test_cancel_job(self) -> None:
        """Отмена задания."""
        service = PrintQueueService()
        job = service.add_job(document_name="Test")

        result = service.cancel_job(job.id)
        assert result is True

        # Проверяем статус
        history = service.get_history()
        assert len(history) == 1
        assert history[0].status == PrintJobStatus.CANCELLED

        # Проверяем, что удалено из очереди
        assert service.get_queue_size() == 0

    def test_cancel_active_job(self) -> None:
        """Отмена активного задания."""
        service = PrintQueueService()
        job = service.add_job(document_name="Test")
        service.start_job(job.id)

        result = service.cancel_job(job.id)
        assert result is True

        assert service.get_active_count() == 0
        history = service.get_history()
        assert len(history) == 1

    def test_complete_job(self) -> None:
        """Завершение задания."""
        service = PrintQueueService()
        job = service.add_job(document_name="Test")
        service.start_job(job.id)

        result = service.complete_job(job.id)
        assert result is True

        assert service.get_active_count() == 0
        history = service.get_history()
        assert len(history) == 1
        assert history[0].status == PrintJobStatus.COMPLETED
        assert history[0].progress == 100

    def test_fail_job(self) -> None:
        """Ошибка задания."""
        service = PrintQueueService()
        job = service.add_job(document_name="Test")
        service.start_job(job.id)

        result = service.fail_job(job.id, "Paper jam")
        assert result is True

        history = service.get_history()
        assert len(history) == 1
        assert history[0].status == PrintJobStatus.FAILED
        assert history[0].error == "Paper jam"

    def test_update_progress(self) -> None:
        """Обновление прогресса."""
        service = PrintQueueService()
        job = service.add_job(document_name="Test")
        service.start_job(job.id)

        result = service.update_progress(job.id, 50)
        assert result is True

        active = service.get_active_jobs()
        assert active[0].progress == 50

    def test_update_progress_bounds(self) -> None:
        """Ограничение прогресса 0-100."""
        service = PrintQueueService()
        job = service.add_job(document_name="Test")
        service.start_job(job.id)

        service.update_progress(job.id, 150)
        active = service.get_active_jobs()
        assert active[0].progress == 100

        service.update_progress(job.id, -10)
        active = service.get_active_jobs()
        assert active[0].progress == 0

    def test_get_stats(self) -> None:
        """Получение статистики."""
        service = PrintQueueService()

        service.add_job(document_name="Job1")
        service.add_job(document_name="Job2")
        job3 = service.add_job(document_name="Job3")
        service.start_job(job3.id)

        stats = service.get_stats()
        assert stats.total_jobs == 3
        assert stats.pending == 2
        assert stats.printing == 1
        assert stats.completed == 0

    def test_get_history(self) -> None:
        """Получение истории."""
        service = PrintQueueService(max_history=10)

        for i in range(5):
            job = service.add_job(document_name=f"Job{i}")
            service.start_job(job.id)  # Нужно сначала запустить
            service.complete_job(job.id)

        history = service.get_history(limit=10)
        # 5 завершённых заданий
        assert len(history) == 5

    def test_clear_history(self) -> None:
        """Очистка истории."""
        service = PrintQueueService()
        job = service.add_job(document_name="Test")
        service.start_job(job.id)  # Нужно сначала запустить
        service.complete_job(job.id)

        count = service.clear_history()
        assert count == 1
        assert len(service.get_history()) == 0

    def test_clear_queue(self) -> None:
        """Очистка очереди."""
        service = PrintQueueService()
        service.add_job(document_name="Job1")
        service.add_job(document_name="Job2")

        count = service.clear_queue()
        assert count == 2
        assert service.get_queue_size() == 0

    def test_clear_queue_keeps_active(self) -> None:
        """Очистка очереди не трогает активные задания."""
        service = PrintQueueService()
        service.add_job(document_name="Job1")
        job2 = service.add_job(document_name="Job2")
        service.start_job(job2.id)

        service.clear_queue()
        assert service.get_queue_size() == 0
        assert service.get_active_count() == 1

    def test_callback_called(self) -> None:
        """Callback вызывается при событиях."""
        callback: PrintQueueCallback = MagicMock()
        service = PrintQueueService(callback=callback)

        job = service.add_job(document_name="Test")
        # Проверяем что callback был вызван
        assert callback.call_count >= 1

        callback.reset_mock()
        service.start_job(job.id)
        assert callback.call_count >= 1

        callback.reset_mock()
        service.complete_job(job.id)
        assert callback.call_count >= 1

    def test_get_current_job(self) -> None:
        """Получение текущего задания."""
        service = PrintQueueService()
        assert service.get_current_job() is None

        job = service.add_job(document_name="Test")
        service.start_job(job.id)

        current = service.get_current_job()
        assert current is not None
        assert current.id == job.id

    def test_get_job(self) -> None:
        """Поиск задания по ID."""
        service = PrintQueueService()
        job = service.add_job(document_name="Test")

        found = service.get_job(job.id)
        assert found is not None
        assert found.id == job.id

    def test_priority_order(self) -> None:
        """Порядок обработки по приоритету."""
        service = PrintQueueService()

        low = service.add_job(document_name="Low", priority=PrintPriority.LOW)
        normal = service.add_job(document_name="Normal", priority=PrintPriority.NORMAL)
        high = service.add_job(document_name="High", priority=PrintPriority.HIGH)

        # URGENT > HIGH > NORMAL > LOW
        assert service.get_next_job() == high
        assert service.get_next_job() == normal
        assert service.get_next_job() == low


class TestQueueStats:
    """Тесты QueueStats dataclass."""

    def test_create_stats(self) -> None:
        """Создание статистики."""
        stats = QueueStats(
            total_jobs=10,
            pending=5,
            printing=1,
            completed=3,
            failed=1,
            cancelled=0,
        )

        assert stats.total_jobs == 10
        assert stats.pending == 5
        assert stats.printing == 1
        assert stats.completed == 3
        assert stats.failed == 1
        assert stats.cancelled == 0

    def test_stats_frozen(self) -> None:
        """Проверка frozen dataclass."""
        stats = QueueStats()

        with pytest.raises(AttributeError):
            stats.total_jobs = 20  # type: ignore[misc]


class TestPrintPriority:
    """Тесты PrintPriority enum."""

    def test_priority_order(self) -> None:
        """Порядок приоритетов."""
        assert PrintPriority.LOW < PrintPriority.NORMAL
        assert PrintPriority.NORMAL < PrintPriority.HIGH
        assert PrintPriority.HIGH < PrintPriority.URGENT

    def test_priority_values(self) -> None:
        """Значения приоритетов."""
        assert PrintPriority.LOW.value == 1
        assert PrintPriority.NORMAL.value == 5
        assert PrintPriority.HIGH.value == 10
        assert PrintPriority.URGENT.value == 20


class TestPrintJobStatus:
    """Тесты PrintJobStatus enum."""

    def test_status_values(self) -> None:
        """Значения статусов."""
        assert PrintJobStatus.PENDING.value == "pending"
        assert PrintJobStatus.PRINTING.value == "printing"
        assert PrintJobStatus.COMPLETED.value == "completed"
        assert PrintJobStatus.FAILED.value == "failed"
        assert PrintJobStatus.CANCELLED.value == "cancelled"
        assert PrintJobStatus.PAUSED.value == "paused"