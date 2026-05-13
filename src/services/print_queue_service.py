"""Сервис очереди печати.

Управляет очередью заданий на печать для ESC/P принтеров.
Поддерживает приоритеты, отмену, паузу/возобновление.

Module: src/services/print_queue_service.py
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, IntEnum
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Protocol
from uuid import UUID, uuid4

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Типы и приоритеты
# ---------------------------------------------------------------------------


class PrintJobStatus(Enum):
    """Статус задания печати."""

    PENDING = "pending"  # Ожидает в очереди
    PREPARING = "preparing"  # Подготовка данных
    PRINTING = "printing"  # Печатается
    PAUSED = "paused"  # Приостановлено
    COMPLETED = "completed"  # Завершено
    CANCELLED = "cancelled"  # Отменено
    FAILED = "failed"  # Ошибка


class PrintPriority(IntEnum):
    """Приоритет печати."""

    LOW = 1
    NORMAL = 5
    HIGH = 10
    URGENT = 20


# ---------------------------------------------------------------------------
# Модели данных
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PrintJob:
    """Задание на печать.

    Attrs:
        id: Уникальный идентификатор задания
        document_id: ID документа
        document_name: Имя документа
        printer_name: Имя принтера
        copies: Количество копий
        priority: Приоритет
        status: Статус
        created_at: Время создания
        started_at: Время начала печати (optional)
        completed_at: Время завершения (optional)
        progress: Прогресс (0-100)
        error: Сообщение об ошибке (optional)
        metadata: Дополнительные метаданные
    """

    id: UUID = field(default_factory=uuid4)
    document_id: Optional[UUID] = None
    document_name: str = ""
    printer_name: str = ""
    copies: int = 1
    priority: PrintPriority = PrintPriority.NORMAL
    status: PrintJobStatus = PrintJobStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    progress: int = 0
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class QueueStats:
    """Статистика очереди печати.

    Attrs:
        total_jobs: Общее количество заданий
        pending: Ожидающие задания
        printing: Печатающиеся задания
        completed: Завершённые задания
        failed: Ошибочные задания
        cancelled: Отменённые задания
    """

    total_jobs: int = 0
    pending: int = 0
    printing: int = 0
    completed: int = 0
    failed: int = 0
    cancelled: int = 0


# ---------------------------------------------------------------------------
# Протоколы
# ---------------------------------------------------------------------------


class PrinterAdapterProtocol(Protocol):
    """Протокол адаптера принтера."""

    def get_name(self) -> str:
        """Возвращает имя принтера."""
        ...

    def is_available(self) -> bool:
        """Проверяет доступность принтера."""
        ...

    def print_data(self, data: bytes, job_name: str, copies: int) -> bool:
        """Печатает данные.

        Args:
            data: ESC/P данные для печати
            job_name: Имя задания
            copies: Количество копий

        Returns:
            True при успехе
        """
        ...

    def cancel_job(self, job_id: UUID) -> bool:
        """Отменяет задание.

        Args:
            job_id: ID задания

        Returns:
            True при успехе
        """
        ...


class PrintQueueCallback(Protocol):
    """Протокол callback для событий очереди."""

    def __call__(self, event: str, job: PrintJob) -> None:
        """Вызывается при событии очереди.

        Args:
            event: Тип события (added, started, completed, failed, cancelled)
            job: Задание печати
        """
        ...


# ---------------------------------------------------------------------------
# PrintQueueService
# ---------------------------------------------------------------------------


class PrintQueueService:
    """Сервис очереди печати.

    Управляет заданиями печати:
    - Добавление в очередь с приоритетом
    - Пауза/возобновление/отмена
    - Мониторинг прогресса
    - Обработка ошибок

    Пример:
        >>> queue = PrintQueueService()
        >>> job = queue.add_job(document_id=doc.id, printer_name="FX-890")
        >>> queue.start_job(job.id)
        >>> queue.cancel_job(job.id)
    """

    def __init__(
        self,
        max_jobs: int = 100,
        max_history: int = 50,
        callback: Optional[PrintQueueCallback] = None,
    ) -> None:
        """Инициализирует сервис очереди.

        Args:
            max_jobs: Максимум заданий в очереди
            max_history: Максимум завершённых заданий в истории
            callback: Callback для событий (optional)
        """
        self._max_jobs = max_jobs
        self._max_history = max_history
        self._callback = callback

        # Очередь: приоритет -> список заданий
        self._queue: Dict[PrintPriority, List[PrintJob]] = {
            PrintPriority.URGENT: [],
            PrintPriority.HIGH: [],
            PrintPriority.NORMAL: [],
            PrintPriority.LOW: [],
        }

        # Активные задания (печатающиеся)
        self._active: Dict[UUID, PrintJob] = {}

        # История завершённых
        self._history: List[PrintJob] = []

        # Текущее задание
        self._current_job: Optional[PrintJob] = None

    # ---------- Управление очередью ----------

    def add_job(
        self,
        document_id: Optional[UUID] = None,
        document_name: str = "",
        printer_name: str = "",
        copies: int = 1,
        priority: PrintPriority = PrintPriority.NORMAL,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PrintJob:
        """Добавляет задание в очередь.

        Args:
            document_id: ID документа (optional)
            document_name: Имя документа
            printer_name: Имя принтера
            copies: Количество копий
            priority: Приоритет
            metadata: Дополнительные метаданные

        Returns:
            Созданное задание

        Raises:
            ValueError: Если очередь переполнена
        """
        # Проверяем лимит
        if self.get_queue_size() >= self._max_jobs:
            raise ValueError(f"Очередь переполнена: {self._max_jobs} заданий")

        job = PrintJob(
            document_id=document_id,
            document_name=document_name,
            printer_name=printer_name,
            copies=copies,
            priority=priority,
            metadata=metadata or {},
        )

        self._queue[priority].append(job)
        logger.info(
            "Добавлено задание %s в очередь (приоритет: %s)",
            job.id,
            priority.name,
        )

        self._notify("added", job)
        return job

    def get_next_job(self) -> Optional[PrintJob]:
        """Возвращает следующее задание из очереди.

        Returns:
            Задание или None если очередь пуста
        """
        # Проверяем приоритеты от высокого к низкому
        for priority in [
            PrintPriority.URGENT,
            PrintPriority.HIGH,
            PrintPriority.NORMAL,
            PrintPriority.LOW,
        ]:
            if self._queue[priority]:
                return self._queue[priority].pop(0)

        return None

    def start_job(self, job_id: UUID) -> bool:
        """Запускает задание на печать.

        Args:
            job_id: ID задания

        Returns:
            True если задание запущено
        """
        job = self._find_job(job_id)
        if job is None:
            return False

        if job.status not in (PrintJobStatus.PENDING, PrintJobStatus.PAUSED):
            return False

        # Обновляем статус
        updated_job = PrintJob(
            id=job.id,
            document_id=job.document_id,
            document_name=job.document_name,
            printer_name=job.printer_name,
            copies=job.copies,
            priority=job.priority,
            status=PrintJobStatus.PRINTING,
            created_at=job.created_at,
            started_at=datetime.now(),
            metadata=job.metadata,
        )

        self._active[job_id] = updated_job
        self._current_job = updated_job

        # Удаляем из очереди если там было
        self._remove_from_queue(job_id)

        logger.info("Запущено задание %s", job_id)
        self._notify("started", updated_job)
        return True

    def pause_job(self, job_id: UUID) -> bool:
        """Приостанавливает задание.

        Args:
            job_id: ID задания

        Returns:
            True если задание приостановлено
        """
        job = self._find_job(job_id)
        if job is None or job.status != PrintJobStatus.PRINTING:
            return False

        # Обновляем статус
        updated_job = PrintJob(
            id=job.id,
            document_id=job.document_id,
            document_name=job.document_name,
            printer_name=job.printer_name,
            copies=job.copies,
            priority=job.priority,
            status=PrintJobStatus.PAUSED,
            created_at=job.created_at,
            started_at=job.started_at,
            progress=job.progress,
            metadata=job.metadata,
        )

        # Возвращаем в очередь
        self._queue[job.priority].append(updated_job)
        del self._active[job_id]

        if self._current_job and self._current_job.id == job_id:
            self._current_job = None

        logger.info("Приостановлено задание %s", job_id)
        self._notify("paused", updated_job)
        return True

    def cancel_job(self, job_id: UUID) -> bool:
        """Отменяет задание.

        Args:
            job_id: ID задания

        Returns:
            True если задание отменено
        """
        job = self._find_job(job_id)
        if job is None:
            return False

        if job.status in (PrintJobStatus.COMPLETED, PrintJobStatus.CANCELLED):
            return False

        # Обновляем статус
        updated_job = PrintJob(
            id=job.id,
            document_id=job.document_id,
            document_name=job.document_name,
            printer_name=job.printer_name,
            copies=job.copies,
            priority=job.priority,
            status=PrintJobStatus.CANCELLED,
            created_at=job.created_at,
            started_at=job.started_at,
            completed_at=datetime.now(),
            metadata=job.metadata,
        )

        # Удаляем из очереди/активных
        self._remove_from_queue(job_id)
        if job_id in self._active:
            del self._active[job_id]

        if self._current_job and self._current_job.id == job_id:
            self._current_job = None

        # Добавляем в историю
        self._add_to_history(updated_job)

        logger.info("Отменено задание %s", job_id)
        self._notify("cancelled", updated_job)
        return True

    def complete_job(self, job_id: UUID) -> bool:
        """Отмечает задание как завершённое.

        Args:
            job_id: ID задания

        Returns:
            True если задание завершено
        """
        if job_id not in self._active:
            return False

        job = self._active[job_id]
        updated_job = PrintJob(
            id=job.id,
            document_id=job.document_id,
            document_name=job.document_name,
            printer_name=job.printer_name,
            copies=job.copies,
            priority=job.priority,
            status=PrintJobStatus.COMPLETED,
            created_at=job.created_at,
            started_at=job.started_at,
            completed_at=datetime.now(),
            progress=100,
            metadata=job.metadata,
        )

        del self._active[job_id]
        self._add_to_history(updated_job)

        if self._current_job and self._current_job.id == job_id:
            self._current_job = None

        logger.info("Завершено задание %s", job_id)
        self._notify("completed", updated_job)
        return True

    def fail_job(self, job_id: UUID, error: str) -> bool:
        """Отмечает задание как ошибочное.

        Args:
            job_id: ID задания
            error: Сообщение об ошибке

        Returns:
            True если задание отмечено как ошибочное
        """
        job = self._find_job(job_id)
        if job is None:
            return False

        updated_job = PrintJob(
            id=job.id,
            document_id=job.document_id,
            document_name=job.document_name,
            printer_name=job.printer_name,
            copies=job.copies,
            priority=job.priority,
            status=PrintJobStatus.FAILED,
            created_at=job.created_at,
            started_at=job.started_at,
            completed_at=datetime.now(),
            error=error,
            metadata=job.metadata,
        )

        # Удаляем из очереди/активных
        self._remove_from_queue(job_id)
        if job_id in self._active:
            del self._active[job_id]

        if self._current_job and self._current_job.id == job_id:
            self._current_job = None

        self._add_to_history(updated_job)

        logger.error("Ошибка задания %s: %s", job_id, error)
        self._notify("failed", updated_job)
        return True

    # ---------- Запросы ----------

    def get_job(self, job_id: UUID) -> Optional[PrintJob]:
        """Возвращает задание по ID.

        Args:
            job_id: ID задания

        Returns:
            Задание или None
        """
        return self._find_job(job_id)

    def get_queue_size(self) -> int:
        """Возвращает размер очереди."""
        return sum(len(jobs) for jobs in self._queue.values())

    def get_active_count(self) -> int:
        """Возвращает количество активных заданий."""
        return len(self._active)

    def get_current_job(self) -> Optional[PrintJob]:
        """Возвращает текущее задание."""
        return self._current_job

    def get_pending_jobs(self) -> List[PrintJob]:
        """Возвращает ожидающие задания."""
        jobs: List[PrintJob] = []
        for priority in [
            PrintPriority.URGENT,
            PrintPriority.HIGH,
            PrintPriority.NORMAL,
            PrintPriority.LOW,
        ]:
            jobs.extend(self._queue[priority])
        return jobs

    def get_active_jobs(self) -> List[PrintJob]:
        """Возвращает активные задания."""
        return list(self._active.values())

    def get_history(self, limit: int = 20) -> List[PrintJob]:
        """Возвращает историю заданий.

        Args:
            limit: Максимум записей

        Returns:
            Список заданий (последние сначала)
        """
        return list(reversed(self._history[-limit:]))

    def get_stats(self) -> QueueStats:
        """Возвращает статистику очереди."""
        pending = sum(len(jobs) for jobs in self._queue.values())
        printing = len(self._active)
        completed = sum(1 for j in self._history if j.status == PrintJobStatus.COMPLETED)
        failed = sum(1 for j in self._history if j.status == PrintJobStatus.FAILED)
        cancelled = sum(1 for j in self._history if j.status == PrintJobStatus.CANCELLED)

        return QueueStats(
            total_jobs=pending + printing + completed + failed + cancelled,
            pending=pending,
            printing=printing,
            completed=completed,
            failed=failed,
            cancelled=cancelled,
        )

    def clear_history(self) -> int:
        """Очищает историю.

        Returns:
            Количество удалённых записей
        """
        count = len(self._history)
        self._history.clear()
        return count

    def clear_queue(self) -> int:
        """Очищает очередь (кроме активных).

        Returns:
            Количество удалённых заданий
        """
        count = self.get_queue_size()
        for priority in self._queue:
            self._queue[priority].clear()
        return count

    # ---------- Обновление прогресса ----------

    def update_progress(self, job_id: UUID, progress: int) -> bool:
        """Обновляет прогресс задания.

        Args:
            job_id: ID задания
            progress: Прогресс (0-100)

        Returns:
            True если обновлено успешно
        """
        if job_id not in self._active:
            return False

        job = self._active[job_id]
        progress = max(0, min(100, progress))

        updated_job = PrintJob(
            id=job.id,
            document_id=job.document_id,
            document_name=job.document_name,
            printer_name=job.printer_name,
            copies=job.copies,
            priority=job.priority,
            status=job.status,
            created_at=job.created_at,
            started_at=job.started_at,
            progress=progress,
            metadata=job.metadata,
        )

        self._active[job_id] = updated_job
        return True

    # ---------- Внутренние методы ----------

    def _find_job(self, job_id: UUID) -> Optional[PrintJob]:
        """Ищет задание по ID во всех списках.

        Args:
            job_id: ID задания

        Returns:
            Задание или None
        """
        # Проверяем активные
        if job_id in self._active:
            return self._active[job_id]

        # Проверяем очередь
        for jobs in self._queue.values():
            for job in jobs:
                if job.id == job_id:
                    return job

        # Проверяем историю
        for job in self._history:
            if job.id == job_id:
                return job

        return None

    def _remove_from_queue(self, job_id: UUID) -> bool:
        """Удаляет задание из очереди.

        Args:
            job_id: ID задания

        Returns:
            True если удалено
        """
        for _priority, jobs in self._queue.items():
            for i, job in enumerate(jobs):
                if job.id == job_id:
                    jobs.pop(i)
                    return True
        return False

    def _add_to_history(self, job: PrintJob) -> None:
        """Добавляет задание в историю.

        Args:
            job: Задание
        """
        self._history.append(job)

        # Ограничиваем размер истории
        while len(self._history) > self._max_history:
            self._history.pop(0)

    def _notify(self, event: str, job: PrintJob) -> None:
        """Вызывает callback события.

        Args:
            event: Тип события
            job: Задание
        """
        if self._callback:
            try:
                self._callback(event, job)
            except Exception as exc:
                logger.error("Ошибка callback: %s", exc)


__all__ = [
    "PrintQueueService",
    "PrintJob",
    "PrintJobStatus",
    "PrintPriority",
    "QueueStats",
    "PrinterAdapterProtocol",
    "PrintQueueCallback",
]
