"""Сервис пакетных операций.

Выполняет операции над множеством документов:
пакетная печать, экспорт, конвертация.

Module: src/services/batch_service.py
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Protocol
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from src.model.document import Document
    from src.services.print_queue_service import PrintQueueService

from src.services.export_service import ExportOptions, ExportService

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Статусы и типы операций
# ---------------------------------------------------------------------------


class BatchOperationType(Enum):
    """Тип пакетной операции."""

    EXPORT = "export"  # Экспорт в формат
    PRINT = "print"  # Печать
    CONVERT = "convert"  # Конвертация
    VALIDATE = "validate"  # Валидация
    CUSTOM = "custom"  # Пользовательская операция


class BatchStatus(Enum):
    """Статус пакетной операции."""

    PENDING = "pending"  # Ожидает
    RUNNING = "running"  # Выполняется
    PAUSED = "paused"  # Приостановлено
    COMPLETED = "completed"  # Завершено
    FAILED = "failed"  # Ошибка
    CANCELLED = "cancelled"  # Отменено


class ItemStatus(Enum):
    """Статус элемента в пакете."""

    PENDING = "pending"  # Ожидает
    PROCESSING = "processing"  # Обрабатывается
    COMPLETED = "completed"  # Завершено
    FAILED = "failed"  # Ошибка
    SKIPPED = "skipped"  # Пропущено


# ---------------------------------------------------------------------------
# Модели данных
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BatchItem:
    """Элемент пакетной операции.

    Attrs:
        id: Уникальный идентификатор
        document_id: ID документа
        document_name: Имя документа
        source_path: Путь к исходному файлу (optional)
        status: Статус элемента
        progress: Прогресс (0-100)
        error: Сообщение об ошибке (optional)
        result: Результат операции (optional)
        started_at: Время начала (optional)
        completed_at: Время завершения (optional)
    """

    id: UUID = field(default_factory=uuid4)
    document_id: Optional[UUID] = None
    document_name: str = ""
    source_path: Optional[Path] = None
    status: ItemStatus = ItemStatus.PENDING
    progress: int = 0
    error: Optional[str] = None
    result: Any = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


@dataclass(frozen=True)
class BatchOperation:
    """Пакетная операция.

    Attrs:
        id: Уникальный идентификатор
        operation_type: Тип операции
        name: Имя операции
        status: Статус операции
        items: Список элементов
        total_items: Общее количество
        completed_items: Завершённые
        failed_items: Ошибочные
        created_at: Время создания
        started_at: Время начала (optional)
        completed_at: Время завершения (optional)
        metadata: Дополнительные метаданные
    """

    id: UUID = field(default_factory=uuid4)
    operation_type: BatchOperationType = BatchOperationType.CUSTOM
    name: str = ""
    status: BatchStatus = BatchStatus.PENDING
    items: List[BatchItem] = field(default_factory=list)
    total_items: int = 0
    completed_items: int = 0
    failed_items: int = 0
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BatchResult:
    """Результат пакетной операции.

    Attrs:
        success: True если все операции успешны
        operation_id: ID операции
        total: Общее количество элементов
        completed: Успешно обработано
        failed: Количество ошибок
        skipped: Пропущено
        duration_seconds: Длительность в секундах
        errors: Список ошибок
    """

    success: bool
    operation_id: UUID
    total: int = 0
    completed: int = 0
    failed: int = 0
    skipped: int = 0
    duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Протоколы
# ---------------------------------------------------------------------------


class BatchCallback(Protocol):
    """Протокол callback для событий пакета."""

    def __call__(
        self,
        operation_id: UUID,
        event: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Вызывается при событии пакетной операции.

        Args:
            operation_id: ID операции
            event: Тип события (started, progress, completed, failed)
            data: Дополнительные данные
        """
        ...


class ItemProcessor(Protocol):
    """Протокол обработчика элемента."""

    def process(self, item: BatchItem, context: Dict[str, Any]) -> Any:
        """Обрабатывает элемент.

        Args:
            item: Элемент для обработки
            context: Контекст операции

        Returns:
            Результат обработки
        """
        ...


# ---------------------------------------------------------------------------
# BatchService
# ---------------------------------------------------------------------------


class BatchService:
    """Сервис пакетных операций.

    Предоставляет:
    - Пакетный экспорт документов
    - Пакетную печать
    - Валидацию документов
    - Прогресс и отслеживание
    - Приостановка/возобновление/отмена

    Пример:
        >>> batch = BatchService()
        >>> op = batch.create_export_batch(documents, ExportFormat.PDF)
        >>> result = batch.execute(op.id)
        >>> print(f"Завершено: {result.completed}/{result.total}")
    """

    def __init__(
        self,
        export_service: Optional["ExportService"] = None,
        print_service: Optional["PrintQueueService"] = None,
        max_concurrent: int = 3,
        callback: Optional[BatchCallback] = None,
    ) -> None:
        """Инициализирует сервис пакетных операций.

        Args:
            export_service: Сервис экспорта (optional)
            print_service: Сервис очереди печати (optional)
            max_concurrent: Максимум параллельных операций
            callback: Callback для событий (optional)
        """
        self._export = export_service
        self._print = print_service
        self._max_concurrent = max_concurrent
        self._callback = callback

        # Активные операции
        self._operations: Dict[UUID, BatchOperation] = {}
        self._processors: Dict[BatchOperationType, ItemProcessor] = {}

        # Текущая выполняемая операция
        self._current_operation: Optional[UUID] = None
        self._is_paused = False
        self._is_cancelled = False

    # ---------- Создание операций ----------

    def create_export_batch(
        self,
        documents: List["Document"],
        output_dir: Path,
        options: Optional["ExportOptions"] = None,
        name: str = "",
    ) -> BatchOperation:
        """Создаёт пакетный экспорт.

        Args:
            documents: Список документов
            output_dir: Директория для вывода
            options: Опции экспорта (optional)
            name: Имя операции (optional)

        Returns:
            Созданная операция
        """
        items = [
            BatchItem(
                document_id=doc.id,
                document_name=doc.metadata.title or f"document_{i}",
            )
            for i, doc in enumerate(documents)
        ]

        operation = BatchOperation(
            operation_type=BatchOperationType.EXPORT,
            name=name or f"Export {len(documents)} documents",
            items=items,
            total_items=len(documents),
            metadata={
                "output_dir": str(output_dir),
                "export_options": options,
                "document_map": {str(doc.id): doc for doc in documents if doc.id is not None},
            },
        )

        self._operations[operation.id] = operation
        logger.info("Создана пакетная операция экспорта: %s", operation.id)
        return operation

    def create_print_batch(
        self,
        documents: List["Document"],
        printer_name: str,
        copies: int = 1,
        name: str = "",
    ) -> BatchOperation:
        """Создаёт пакетную печать.

        Args:
            documents: Список документов
            printer_name: Имя принтера
            copies: Количество копий
            name: Имя операции (optional)

        Returns:
            Созданная операция
        """
        items = [
            BatchItem(
                document_id=doc.id,
                document_name=doc.metadata.title or f"document_{i}",
            )
            for i, doc in enumerate(documents)
        ]

        operation = BatchOperation(
            operation_type=BatchOperationType.PRINT,
            name=name or f"Print {len(documents)} documents",
            items=items,
            total_items=len(documents),
            metadata={
                "printer_name": printer_name,
                "copies": copies,
            },
        )

        self._operations[operation.id] = operation
        logger.info("Создана пакетная операция печати: %s", operation.id)
        return operation

    def create_custom_batch(
        self,
        items: List[BatchItem],
        name: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> BatchOperation:
        """Создаёт пользовательскую пакетную операцию.

        Args:
            items: Список элементов
            name: Имя операции
            metadata: Метаданные (optional)

        Returns:
            Созданная операция
        """
        operation = BatchOperation(
            operation_type=BatchOperationType.CUSTOM,
            name=name or f"Custom operation ({len(items)} items)",
            items=items,
            total_items=len(items),
            metadata=metadata or {},
        )

        self._operations[operation.id] = operation
        return operation

    # ---------- Управление операциями ----------

    def execute(self, operation_id: UUID) -> BatchResult:
        """Выполняет пакетную операцию.

        Args:
            operation_id: ID операции

        Returns:
            BatchResult с результатами
        """
        operation = self._operations.get(operation_id)
        if operation is None:
            return BatchResult(
                success=False,
                operation_id=operation_id,
                errors=["Операция не найдена"],
            )

        # Сбрасываем флаги
        self._is_paused = False
        self._is_cancelled = False
        self._current_operation = operation_id

        # Обновляем статус
        started_at = datetime.now()
        operation = self._update_operation(
            operation,
            status=BatchStatus.RUNNING,
            started_at=started_at,
        )

        self._notify(operation_id, "started", {"total": operation.total_items})

        # Обрабатываем элементы
        completed = 0
        failed = 0
        skipped = 0
        errors: List[str] = []

        for item in operation.items:
            # Проверяем отмену
            if self._is_cancelled:
                operation = self._update_operation(
                    operation,
                    status=BatchStatus.CANCELLED,
                    completed_at=datetime.now(),
                )
                break

            # Проверяем паузу
            while self._is_paused:
                import time

                time.sleep(0.1)
                if self._is_cancelled:
                    break

            if self._is_cancelled:
                operation = self._update_operation(
                    operation,
                    status=BatchStatus.CANCELLED,
                    completed_at=datetime.now(),
                )
                break

            # Обрабатываем элемент
            result = self._process_item(operation, item)

            if result.status == ItemStatus.COMPLETED:
                completed += 1
            elif result.status == ItemStatus.FAILED:
                failed += 1
                if result.error:
                    errors.append(f"{item.document_name}: {result.error}")
            elif result.status == ItemStatus.SKIPPED:
                skipped += 1

            # Обновляем операцию
            operation = self._operations[operation_id]

        # Завершаем операцию
        duration = (datetime.now() - started_at).total_seconds()

        final_status = BatchStatus.COMPLETED
        if self._is_cancelled:
            final_status = BatchStatus.CANCELLED
        elif failed > 0:
            final_status = BatchStatus.FAILED

        operation = self._update_operation(
            operation,
            status=final_status,
            completed_items=completed,
            failed_items=failed,
            completed_at=datetime.now(),
        )

        self._current_operation = None

        self._notify(
            operation_id,
            "completed" if final_status == BatchStatus.COMPLETED else "failed",
            {
                "completed": completed,
                "failed": failed,
                "skipped": skipped,
            },
        )

        return BatchResult(
            success=failed == 0 and not self._is_cancelled,
            operation_id=operation_id,
            total=operation.total_items,
            completed=completed,
            failed=failed,
            skipped=skipped,
            duration_seconds=duration,
            errors=errors,
        )

    def pause(self, operation_id: UUID) -> bool:
        """Приостанавливает операцию.

        Args:
            operation_id: ID операции

        Returns:
            True если операция приостановлена
        """
        if self._current_operation != operation_id:
            return False

        operation = self._operations.get(operation_id)
        if operation is None or operation.status != BatchStatus.RUNNING:
            return False

        self._is_paused = True
        self._update_operation(operation, status=BatchStatus.PAUSED)
        self._notify(operation_id, "paused")
        return True

    def resume(self, operation_id: UUID) -> bool:
        """Возобновляет операцию.

        Args:
            operation_id: ID операции

        Returns:
            True если операция возобновлена
        """
        operation = self._operations.get(operation_id)
        if operation is None or operation.status != BatchStatus.PAUSED:
            return False

        self._is_paused = False
        self._update_operation(operation, status=BatchStatus.RUNNING)
        self._notify(operation_id, "resumed")
        return True

    def cancel(self, operation_id: UUID) -> bool:
        """Отменяет операцию.

        Args:
            operation_id: ID операции

        Returns:
            True если операция отменена
        """
        operation = self._operations.get(operation_id)
        if operation is None:
            return False

        if operation.status in (BatchStatus.COMPLETED, BatchStatus.CANCELLED):
            return False

        self._is_cancelled = True
        self._is_paused = False
        self._update_operation(operation, status=BatchStatus.CANCELLED)
        self._notify(operation_id, "cancelled")
        return True

    # ---------- Запросы ----------

    def get_operation(self, operation_id: UUID) -> Optional[BatchOperation]:
        """Возвращает операцию по ID.

        Args:
            operation_id: ID операции

        Returns:
            Операция или None
        """
        return self._operations.get(operation_id)

    def get_all_operations(self) -> List[BatchOperation]:
        """Возвращает все операции."""
        return list(self._operations.values())

    def get_active_operations(self) -> List[BatchOperation]:
        """Возвращает активные операции."""
        return [
            op
            for op in self._operations.values()
            if op.status in (BatchStatus.RUNNING, BatchStatus.PAUSED)
        ]

    def clear_completed(self) -> int:
        """Удаляет завершённые операции.

        Returns:
            Количество удалённых операций
        """
        to_remove = [
            op_id
            for op_id, op in self._operations.items()
            if op.status in (BatchStatus.COMPLETED, BatchStatus.FAILED, BatchStatus.CANCELLED)
        ]
        for op_id in to_remove:
            del self._operations[op_id]
        return len(to_remove)

    def register_processor(
        self,
        operation_type: BatchOperationType,
        processor: ItemProcessor,
    ) -> None:
        """Регистрирует обработчик для типа операции.

        Args:
            operation_type: Тип операции
            processor: Обработчик
        """
        self._processors[operation_type] = processor
        logger.info(
            "Зарегистрирован обработчик для %s",
            operation_type.value,
        )

    # ---------- Внутренние методы ----------

    def _process_item(
        self,
        operation: BatchOperation,
        item: BatchItem,
    ) -> BatchItem:
        """Обрабатывает элемент операции.

        Args:
            operation: Операция
            item: Элемент

        Returns:
            Обновлённый элемент
        """
        started_at = datetime.now()

        # Обновляем статус
        updated_item = BatchItem(
            id=item.id,
            document_id=item.document_id,
            document_name=item.document_name,
            source_path=item.source_path,
            status=ItemStatus.PROCESSING,
            started_at=started_at,
        )

        self._update_item(operation.id, updated_item)

        try:
            # Получаем обработчик
            processor = self._processors.get(operation.operation_type)

            if processor:
                # Выполняем обработку
                result = processor.process(item, operation.metadata)
            else:
                # Обработчик по умолчанию
                result = self._default_processor(operation, item)

            # Успешное завершение
            completed_item = BatchItem(
                id=item.id,
                document_id=item.document_id,
                document_name=item.document_name,
                source_path=item.source_path,
                status=ItemStatus.COMPLETED,
                result=result,
                started_at=started_at,
                completed_at=datetime.now(),
            )
            self._update_item(operation.id, completed_item)
            return completed_item

        except Exception as exc:
            logger.error("Ошибка обработки элемента %s: %s", item.id, exc)

            failed_item = BatchItem(
                id=item.id,
                document_id=item.document_id,
                document_name=item.document_name,
                source_path=item.source_path,
                status=ItemStatus.FAILED,
                error=str(exc),
                started_at=started_at,
                completed_at=datetime.now(),
            )
            self._update_item(operation.id, failed_item)
            return failed_item

    def _default_processor(
        self,
        operation: BatchOperation,
        item: BatchItem,
    ) -> Any:
        """Обработчик по умолчанию.

        Args:
            operation: Операция
            item: Элемент

        Returns:
            Результат обработки
        """
        if operation.operation_type == BatchOperationType.EXPORT:
            return self._export_document(operation, item)

        if operation.operation_type == BatchOperationType.PRINT:
            return self._print_document(operation, item)

        return {"processed": True}

    def _export_document(
        self,
        operation: BatchOperation,
        item: BatchItem,
    ) -> Dict[str, Any]:
        """Экспортирует документ.

        Args:
            operation: Операция экспорта
            item: Элемент с документом

        Returns:
            Результат экспорта

        Raises:
            RuntimeError: Если сервис экспорта не настроен
        """
        if self._export is None:
            raise RuntimeError("Сервис экспорта не настроен")

        metadata = operation.metadata
        document_map: Dict[str, Any] = metadata.get("document_map", {})
        doc = document_map.get(str(item.document_id)) if item.document_id else None
        if doc is None:
            raise ValueError(f"Документ {item.document_id} не найден в пакете")

        options: Optional[ExportOptions] = metadata.get("export_options")
        output_dir = Path(metadata.get("output_dir", "."))

        # Определяем путь для сохранения
        filename = doc.metadata.title or f"document_{item.document_id}"
        extension = options.format.value if options else "pdf"
        output_path = output_dir / f"{filename}.{extension}"

        logger.info(
            "Экспорт документа %s (%s) в %s",
            item.document_id,
            item.document_name,
            output_path,
        )

        result = self._export.export(doc, options, output_path)
        if not result.success:
            error = result.error or "Неизвестная ошибка экспорта"
            logger.error("Ошибка экспорта %s: %s", item.document_id, error)
            raise RuntimeError(error)

        logger.info(
            "Документ %s успешно экспортирован: %s",
            item.document_id,
            result.output_path,
        )
        return {
            "exported": True,
            "path": str(result.output_path) if result.output_path else None,
            "bytes_written": result.bytes_written,
        }

    def _print_document(
        self,
        operation: BatchOperation,
        item: BatchItem,
    ) -> Dict[str, Any]:
        """Ставит документ в очередь печати и запускает.

        Args:
            operation: Операция печати
            item: Элемент с документом

        Returns:
            Результат печати

        Raises:
            RuntimeError: Если сервис печати не настроен
        """
        if self._print is None:
            raise RuntimeError("Сервис печати не настроен")

        metadata = operation.metadata
        printer_name = metadata.get("printer_name", "")
        copies = metadata.get("copies", 1)

        logger.info(
            "Печать документа %s (%s), принтер: %s, копий: %s",
            item.document_id,
            item.document_name,
            printer_name,
            copies,
        )

        job = self._print.add_job(
            document_id=item.document_id,
            document_name=item.document_name,
            printer_name=printer_name,
            copies=copies,
        )
        started = self._print.start_job(job.id)
        if not started:
            logger.error("Не удалось запустить печать для %s", item.document_id)
            raise RuntimeError("Не удалось запустить печать")

        logger.info(
            "Документ %s отправлен на печать, job_id: %s",
            item.document_id,
            job.id,
        )
        return {
            "printed": True,
            "job_id": str(job.id),
            "copies": copies,
            "printer_name": printer_name,
        }

    def _update_operation(
        self,
        operation: BatchOperation,
        **kwargs: Any,
    ) -> BatchOperation:
        """Обновляет операцию.

        Args:
            operation: Операция
            **kwargs: Поля для обновления

        Returns:
            Обновлённая операция
        """
        # Создаём новую frozen dataclass с обновлёнными полями
        updated = BatchOperation(
            id=kwargs.get("id", operation.id),
            operation_type=kwargs.get("operation_type", operation.operation_type),
            name=kwargs.get("name", operation.name),
            status=kwargs.get("status", operation.status),
            items=kwargs.get("items", operation.items),
            total_items=kwargs.get("total_items", operation.total_items),
            completed_items=kwargs.get("completed_items", operation.completed_items),
            failed_items=kwargs.get("failed_items", operation.failed_items),
            created_at=kwargs.get("created_at", operation.created_at),
            started_at=kwargs.get("started_at", operation.started_at),
            completed_at=kwargs.get("completed_at", operation.completed_at),
            metadata=kwargs.get("metadata", operation.metadata),
        )

        self._operations[updated.id] = updated
        return updated

    def _update_item(self, operation_id: UUID, item: BatchItem) -> None:
        """Обновляет элемент в операции.

        Args:
            operation_id: ID операции
            item: Обновлённый элемент
        """
        operation = self._operations.get(operation_id)
        if operation is None:
            return

        updated_items = [item if i.id == item.id else i for i in operation.items]

        self._update_operation(operation, items=updated_items)

    def _notify(
        self,
        operation_id: UUID,
        event: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Вызывает callback.

        Args:
            operation_id: ID операции
            event: Событие
            data: Данные (optional)
        """
        if self._callback:
            try:
                self._callback(operation_id, event, data)
            except Exception as exc:
                logger.error("Ошибка callback: %s", exc)


__all__ = [
    "BatchService",
    "BatchOperation",
    "BatchOperationType",
    "BatchStatus",
    "BatchItem",
    "ItemStatus",
    "BatchResult",
    "BatchCallback",
    "ItemProcessor",
]
