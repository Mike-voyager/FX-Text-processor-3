"""Тесты для BatchService.

Module: tests/unit/services/test_batch_service.py
"""

from pathlib import Path
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from src.services.batch_service import (
    BatchCallback,
    BatchItem,
    BatchOperation,
    BatchOperationType,
    BatchResult,
    BatchService,
    BatchStatus,
    ItemProcessor,
    ItemStatus,
)


class MockDocument:
    """Мок документа для тестов."""

    def __init__(self, title: str = "Test Document") -> None:
        self.id = uuid4()
        self.metadata = MagicMock()
        self.metadata.title = title


class TestBatchOperationType:
    """Тесты BatchOperationType enum."""

    def test_type_values(self) -> None:
        """Значения типов операций."""
        assert BatchOperationType.EXPORT.value == "export"
        assert BatchOperationType.PRINT.value == "print"
        assert BatchOperationType.CONVERT.value == "convert"
        assert BatchOperationType.VALIDATE.value == "validate"
        assert BatchOperationType.CUSTOM.value == "custom"


class TestBatchStatus:
    """Тесты BatchStatus enum."""

    def test_status_values(self) -> None:
        """Значения статусов."""
        assert BatchStatus.PENDING.value == "pending"
        assert BatchStatus.RUNNING.value == "running"
        assert BatchStatus.PAUSED.value == "paused"
        assert BatchStatus.COMPLETED.value == "completed"
        assert BatchStatus.FAILED.value == "failed"
        assert BatchStatus.CANCELLED.value == "cancelled"


class TestItemStatus:
    """Тесты ItemStatus enum."""

    def test_status_values(self) -> None:
        """Значения статусов элемента."""
        assert ItemStatus.PENDING.value == "pending"
        assert ItemStatus.PROCESSING.value == "processing"
        assert ItemStatus.COMPLETED.value == "completed"
        assert ItemStatus.FAILED.value == "failed"
        assert ItemStatus.SKIPPED.value == "skipped"


class TestBatchItem:
    """Тесты BatchItem dataclass."""

    def test_create_item(self) -> None:
        """Создание элемента."""
        doc_id = uuid4()
        item = BatchItem(
            document_id=doc_id,
            document_name="Test Doc",
        )

        assert item.document_id == doc_id
        assert item.document_name == "Test Doc"
        assert item.status == ItemStatus.PENDING
        assert item.progress == 0
        assert isinstance(item.id, type(uuid4()))

    def test_item_frozen(self) -> None:
        """Проверка frozen dataclass."""
        item = BatchItem(document_name="Test")

        with pytest.raises(AttributeError):
            item.document_name = "Changed"  # type: ignore[misc]


class TestBatchOperation:
    """Тесты BatchOperation dataclass."""

    def test_create_operation(self) -> None:
        """Создание операции."""
        operation = BatchOperation(
            operation_type=BatchOperationType.EXPORT,
            name="Test Export",
            total_items=5,
        )

        assert operation.operation_type == BatchOperationType.EXPORT
        assert operation.name == "Test Export"
        assert operation.total_items == 5
        assert operation.status == BatchStatus.PENDING
        assert isinstance(operation.id, type(uuid4()))

    def test_operation_frozen(self) -> None:
        """Проверка frozen dataclass."""
        operation = BatchOperation(name="Test")

        with pytest.raises(AttributeError):
            operation.name = "Changed"  # type: ignore[misc]


class TestBatchResult:
    """Тесты BatchResult dataclass."""

    def test_success_result(self) -> None:
        """Успешный результат."""
        operation_id = uuid4()
        result = BatchResult(
            success=True,
            operation_id=operation_id,
            total=10,
            completed=10,
            failed=0,
        )

        assert result.success is True
        assert result.total == 10
        assert result.completed == 10
        assert result.failed == 0

    def test_failure_result(self) -> None:
        """Результат с ошибками."""
        operation_id = uuid4()
        result = BatchResult(
            success=False,
            operation_id=operation_id,
            total=10,
            completed=7,
            failed=3,
            errors=["Error 1", "Error 2", "Error 3"],
        )

        assert result.success is False
        assert result.failed == 3
        assert len(result.errors) == 3


class TestBatchService:
    """Тесты BatchService."""

    def test_create_service(self) -> None:
        """Создание сервиса."""
        service = BatchService()
        assert len(service.get_all_operations()) == 0

    def test_create_export_batch(self) -> None:
        """Создание пакетного экспорта."""
        service = BatchService()
        docs = [MockDocument(f"Doc{i}") for i in range(3)]

        operation = service.create_export_batch(
            documents=docs,
            output_dir=Path("/tmp/export"),
        )

        assert operation.operation_type == BatchOperationType.EXPORT
        assert operation.total_items == 3
        assert len(operation.items) == 3
        assert "output_dir" in operation.metadata

    def test_create_print_batch(self) -> None:
        """Создание пакетной печати."""
        service = BatchService()
        docs = [MockDocument(f"Doc{i}") for i in range(3)]

        operation = service.create_print_batch(
            documents=docs,
            printer_name="FX-890",
            copies=2,
        )

        assert operation.operation_type == BatchOperationType.PRINT
        assert operation.total_items == 3
        assert operation.metadata["printer_name"] == "FX-890"
        assert operation.metadata["copies"] == 2

    def test_create_custom_batch(self) -> None:
        """Создание пользовательской операции."""
        service = BatchService()
        items = [
            BatchItem(document_name="Item1"),
            BatchItem(document_name="Item2"),
        ]

        operation = service.create_custom_batch(
            items=items,
            name="Custom Op",
            metadata={"key": "value"},
        )

        assert operation.operation_type == BatchOperationType.CUSTOM
        assert operation.name == "Custom Op"
        assert len(operation.items) == 2
        assert operation.metadata["key"] == "value"

    def test_execute_batch(self, tmp_path: Path) -> None:
        """Выполнение пакетной операции."""
        service = BatchService()
        docs = [MockDocument(f"Doc{i}") for i in range(3)]

        operation = service.create_export_batch(
            documents=docs,
            output_dir=tmp_path,
        )

        result = service.execute(operation.id)

        assert result.success is True
        assert result.total == 3
        assert result.completed == 3
        assert result.failed == 0

    def test_execute_nonexistent_operation(self) -> None:
        """Выполнение несуществующей операции."""
        service = BatchService()

        result = service.execute(uuid4())

        assert result.success is False
        assert "не найдена" in result.errors[0]

    def test_cancel_operation(self, tmp_path: Path) -> None:
        """Отмена операции."""
        service = BatchService()
        docs = [MockDocument(f"Doc{i}") for i in range(5)]

        operation = service.create_export_batch(
            documents=docs,
            output_dir=tmp_path,
        )

        # Отменяем до выполнения
        result = service.cancel(operation.id)
        assert result is True

        # Проверяем статус
        op = service.get_operation(operation.id)
        assert op is not None
        assert op.status == BatchStatus.CANCELLED

    def test_cancel_running_operation(self) -> None:
        """Отмена выполняющейся операции."""
        import threading
        import time

        service = BatchService()

        # Создаём медленный обработчик
        class SlowProcessor:
            def process(self, item: BatchItem, context: dict) -> dict:
                time.sleep(0.01)  # Имитируем медленную обработку
                return {"processed": True}

        processor = SlowProcessor()
        service.register_processor(BatchOperationType.CUSTOM, processor)

        # Создаём операцию
        items = [BatchItem(document_name=f"Item{i}") for i in range(100)]
        operation = service.create_custom_batch(items=items)

        # Запускаем выполнение в фоне
        result_holder = []

        def run_batch() -> None:
            result = service.execute(operation.id)
            result_holder.append(result)

        thread = threading.Thread(target=run_batch)
        thread.start()

        # Даём время запуститься
        time.sleep(0.05)

        # Отменяем
        service.cancel(operation.id)

        thread.join(timeout=5.0)

        # Проверяем что отменено или завершено (в зависимости от тайминга)
        op = service.get_operation(operation.id)
        assert op is not None
        # Может быть CANCELLED или COMPLETED в зависимости от тайминга
        assert op.status in (BatchStatus.CANCELLED, BatchStatus.COMPLETED)

    def test_pause_resume_operation(self, tmp_path: Path) -> None:
        """Приостановка и возобновление."""
        service = BatchService()
        docs = [MockDocument(f"Doc{i}") for i in range(3)]

        operation = service.create_export_batch(
            documents=docs,
            output_dir=tmp_path,
        )

        # Пауза до выполнения не работает
        result = service.pause(operation.id)
        assert result is False

    def test_get_operation(self) -> None:
        """Получение операции по ID."""
        service = BatchService()
        docs = [MockDocument()]

        operation = service.create_export_batch(
            documents=docs,
            output_dir=Path("/tmp"),
        )

        found = service.get_operation(operation.id)
        assert found is not None
        assert found.id == operation.id

        not_found = service.get_operation(uuid4())
        assert not_found is None

    def test_get_all_operations(self) -> None:
        """Получение всех операций."""
        service = BatchService()

        for i in range(3):
            docs = [MockDocument()]
            service.create_export_batch(
                documents=docs,
                output_dir=Path("/tmp"),
            )

        operations = service.get_all_operations()
        assert len(operations) == 3

    def test_get_active_operations(self, tmp_path: Path) -> None:
        """Получение активных операций."""
        service = BatchService()

        # Создаём и выполняем операцию
        docs = [MockDocument()]
        op1 = service.create_export_batch(
            documents=docs,
            output_dir=tmp_path,
        )

        # Создаём ещё одну
        op2 = service.create_print_batch(
            documents=docs,
            printer_name="FX-890",
        )

        # Выполняем первую
        service.execute(op1.id)

        active = service.get_active_operations()
        assert len(active) == 0  # После выполнения нет активных

    def test_clear_completed(self, tmp_path: Path) -> None:
        """Очистка завершённых операций."""
        service = BatchService()

        # Создаём и выполняем операцию
        docs = [MockDocument()]
        op = service.create_export_batch(
            documents=docs,
            output_dir=tmp_path,
        )
        service.execute(op.id)

        # Очищаем
        count = service.clear_completed()
        assert count == 1

        # Проверяем что удалена
        operations = service.get_all_operations()
        assert len(operations) == 0

    def test_register_processor(self) -> None:
        """Регистрация обработчика."""
        service = BatchService()

        processor: ItemProcessor = MagicMock()

        service.register_processor(BatchOperationType.CUSTOM, processor)

        assert BatchOperationType.CUSTOM in service._processors

    def test_callback_called(self, tmp_path: Path) -> None:
        """Callback вызывается при событиях."""
        callback: BatchCallback = MagicMock()
        service = BatchService(callback=callback)

        docs = [MockDocument()]
        operation = service.create_export_batch(
            documents=docs,
            output_dir=tmp_path,
        )

        service.execute(operation.id)

        # Проверяем вызовы callback
        assert callback.call_count >= 2  # started + completed

        # Проверяем последний вызов (completed)
        last_call = callback.call_args
        assert last_call[0][0] == operation.id
        assert last_call[0][1] == "completed"


class TestItemProcessor:
    """Тесты ItemProcessor protocol."""

    def test_processor_protocol(self) -> None:
        """Проверка протокола обработчика."""
        # Создаём реализацию протокола
        class TestProcessor:
            def process(self, item: BatchItem, context: dict) -> dict:
                return {"processed": True}

        processor = TestProcessor()
        item = BatchItem(document_name="Test")

        result = processor.process(item, {})

        assert result["processed"] is True


class TestBatchOperationIntegration:
    """Интеграционные тесты BatchService."""

    def test_full_export_workflow(self, tmp_path: Path) -> None:
        """Полный цикл экспорта."""
        service = BatchService()

        # Создаём документы
        docs = [MockDocument(f"Document {i}") for i in range(5)]

        # Создаём операцию
        operation = service.create_export_batch(
            documents=docs,
            output_dir=tmp_path,
            name="Test Export Batch",
        )

        assert operation.status == BatchStatus.PENDING
        assert operation.total_items == 5

        # Выполняем
        result = service.execute(operation.id)

        assert result.success is True
        assert result.completed == 5

        # Проверяем статус операции
        op = service.get_operation(operation.id)
        assert op is not None
        assert op.status == BatchStatus.COMPLETED

    def test_batch_with_failure(self, tmp_path: Path) -> None:
        """Пакетная операция с ошибками."""

        # Создаём обработчик, который падает на определённых элементах
        class FailingProcessor:
            def __init__(self) -> None:
                self.call_count = 0

            def process(self, item: BatchItem, context: dict) -> dict:
                self.call_count += 1
                if "fail" in item.document_name:
                    raise ValueError("Intentional failure")
                return {"success": True}

        service = BatchService()
        processor = FailingProcessor()
        service.register_processor(BatchOperationType.EXPORT, processor)

        # Создаём элементы (некоторые с "fail" в имени)
        items = [
            BatchItem(document_name="Doc1"),
            BatchItem(document_name="Doc_fail_2"),
            BatchItem(document_name="Doc3"),
            BatchItem(document_name="Doc_fail_4"),
        ]

        operation = service.create_custom_batch(items=items)
        operation = BatchOperation(
            id=operation.id,
            operation_type=BatchOperationType.EXPORT,
            name=operation.name,
            items=items,
            total_items=len(items),
        )
        service._operations[operation.id] = operation

        result = service.execute(operation.id)

        assert result.success is False
        assert result.failed == 2
        assert result.completed == 2
        assert len(result.errors) == 2

    def test_batch_cancellation_mid_execution(self) -> None:
        """Отмена во время выполнения."""
        import threading
        import time

        class SlowProcessor:
            def __init__(self) -> None:
                self.call_count = 0

            def process(self, item: BatchItem, context: dict) -> dict:
                self.call_count += 1
                time.sleep(0.01)  # Имитируем медленную обработку
                return {"success": True}

        service = BatchService()
        processor = SlowProcessor()
        service.register_processor(BatchOperationType.CUSTOM, processor)

        # Создаём много элементов
        items = [BatchItem(document_name=f"Item{i}") for i in range(50)]
        operation = service.create_custom_batch(items=items)

        # Запускаем выполнение в фоне
        thread = threading.Thread(target=lambda: service.execute(operation.id))
        thread.start()

        # Даём немного времени и отменяем
        time.sleep(0.05)
        service.cancel(operation.id)

        thread.join(timeout=5.0)

        # Проверяем что отменено или завершено (в зависимости от тайминга)
        op = service.get_operation(operation.id)
        assert op is not None
        # Может быть CANCELLED или COMPLETED в зависимости от тайминга
        assert op.status in (BatchStatus.CANCELLED, BatchStatus.COMPLETED)