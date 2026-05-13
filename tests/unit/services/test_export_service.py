"""Тесты для ExportService.

Module: tests/unit/services/test_export_service.py
"""

from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from src.services.export_service import (
    BatchExportResult,
    ExportCallback,
    ExportFormat,
    ExportOptions,
    ExportResult,
    ExportService,
    ExportStatus,
    RendererProtocol,
)


class MockRenderer:
    """Мок рендерера для тестов."""

    def __init__(self, extension: str = ".txt", mime_type: str = "text/plain") -> None:
        self._extension = extension
        self._mime_type = mime_type
        self.render_called = False

    def render(self, document: object, options: ExportOptions) -> bytes:
        """Рендерит документ в байты."""
        self.render_called = True
        return b"test content"

    def get_extension(self) -> str:
        """Возвращает расширение файла."""
        return self._extension

    def get_mime_type(self) -> str:
        """Возвращает MIME-тип."""
        return self._mime_type


class MockDocument:
    """Мок документа для тестов."""

    def __init__(self, title: str = "Test Document") -> None:
        self.id = uuid4()
        self.metadata = MagicMock()
        self.metadata.title = title
        self.metadata.to_dict = MagicMock(return_value={"title": title})
        self.page_settings = MagicMock()
        self.page_settings.to_dict = MagicMock(return_value={})
        self.printer_settings = MagicMock()
        self.printer_settings.to_dict = MagicMock(return_value={})
        self.sections = []
        self._text_content = "Test content\nLine 2\nLine 3"

    def get_text_content(self) -> str:
        """Возвращает текст документа."""
        return self._text_content


class TestExportFormat:
    """Тесты ExportFormat enum."""

    def test_format_values(self) -> None:
        """Значения форматов."""
        assert ExportFormat.PDF.value == "pdf"
        assert ExportFormat.HTML.value == "html"
        assert ExportFormat.TXT.value == "txt"
        assert ExportFormat.ESCP.value == "escp"
        assert ExportFormat.JSON.value == "json"


class TestExportStatus:
    """Тесты ExportStatus enum."""

    def test_status_values(self) -> None:
        """Значения статусов."""
        assert ExportStatus.PENDING.value == "pending"
        assert ExportStatus.IN_PROGRESS.value == "in_progress"
        assert ExportStatus.COMPLETED.value == "completed"
        assert ExportStatus.FAILED.value == "failed"
        assert ExportStatus.CANCELLED.value == "cancelled"


class TestExportOptions:
    """Тесты ExportOptions dataclass."""

    def test_default_options(self) -> None:
        """Опции по умолчанию."""
        options = ExportOptions()

        assert options.format == ExportFormat.PDF
        assert options.output_path is None
        assert options.encrypt is False
        assert options.include_metadata is True
        assert options.quality == "medium"
        assert options.encoding == "utf-8"

    def test_custom_options(self) -> None:
        """Пользовательские опции."""
        options = ExportOptions(
            format=ExportFormat.HTML,
            output_path=Path("/tmp/test.html"),
            encrypt=True,
            quality="high",
        )

        assert options.format == ExportFormat.HTML
        assert options.output_path == Path("/tmp/test.html")
        assert options.encrypt is True
        assert options.quality == "high"


class TestExportResult:
    """Тесты ExportResult dataclass."""

    def test_success_result(self) -> None:
        """Успешный результат."""
        result = ExportResult(
            success=True,
            output_path=Path("/tmp/test.pdf"),
            format=ExportFormat.PDF,
            bytes_written=1000,
            status=ExportStatus.COMPLETED,
        )

        assert result.success is True
        assert result.output_path == Path("/tmp/test.pdf")
        assert result.bytes_written == 1000
        assert result.error is None

    def test_failure_result(self) -> None:
        """Результат с ошибкой."""
        result = ExportResult(
            success=False,
            status=ExportStatus.FAILED,
            error="Export failed",
        )

        assert result.success is False
        assert result.error == "Export failed"


class TestExportService:
    """Тесты ExportService."""

    def test_create_service(self) -> None:
        """Создание сервиса."""
        service = ExportService()
        assert service.get_supported_formats() == list(ExportFormat)

    def test_create_service_with_renderer(self) -> None:
        """Создание сервиса с рендерером."""
        renderers = {ExportFormat.TXT: MockRenderer()}
        service = ExportService(renderers=renderers)

        assert ExportFormat.TXT in service._renderers

    def test_get_file_extension(self) -> None:
        """Получение расширения файла."""
        service = ExportService()

        assert service.get_file_extension(ExportFormat.PDF) == ".pdf"
        assert service.get_file_extension(ExportFormat.HTML) == ".html"
        assert service.get_file_extension(ExportFormat.TXT) == ".txt"

    def test_register_renderer(self) -> None:
        """Регистрация рендерера."""
        service = ExportService()
        renderer = MockRenderer()

        service.register_renderer(ExportFormat.PDF, renderer)

        assert ExportFormat.PDF in service._renderers
        assert service._renderers[ExportFormat.PDF] == renderer

    def test_export_with_renderer(self, tmp_path: Path) -> None:
        """Экспорт с рендерером."""
        service = ExportService()
        renderer = MockRenderer()
        service.register_renderer(ExportFormat.TXT, renderer)

        doc = MockDocument()
        output = tmp_path / "test.txt"

        result = service.export(doc, ExportOptions(format=ExportFormat.TXT, output_path=output))

        assert result.success is True
        assert result.output_path == output
        assert renderer.render_called is True

    def test_export_default_renderer_txt(self, tmp_path: Path) -> None:
        """Экспорт TXT без рендерера (дефолт)."""
        service = ExportService()
        doc = MockDocument()
        output = tmp_path / "test.txt"

        result = service.export(doc, ExportOptions(format=ExportFormat.TXT, output_path=output))

        assert result.success is True
        assert output.exists()
        content = output.read_text()
        assert "Test content" in content

    def test_export_default_renderer_json(self, tmp_path: Path) -> None:
        """Экспорт JSON без рендерера (дефолт)."""
        service = ExportService()
        doc = MockDocument()
        output = tmp_path / "test.json"

        result = service.export(doc, ExportOptions(format=ExportFormat.JSON, output_path=output))

        assert result.success is True
        assert output.exists()
        content = output.read_text()
        assert '"id"' in content
        assert '"metadata"' in content

    def test_export_unsupported_format(self, tmp_path: Path) -> None:
        """Экспорт в неподдерживаемый формат без рендерера."""
        service = ExportService()
        doc = MockDocument()
        output = tmp_path / "test.pdf"

        result = service.export(doc, ExportOptions(format=ExportFormat.PDF, output_path=output))

        # PDF требует рендерер, которого нет
        assert result.success is False
        assert "Неподдерживаемый формат" in (result.error or "")

    def test_export_to_pdf(self, tmp_path: Path) -> None:
        """Экспорт в PDF (требует рендерер)."""
        service = ExportService()
        doc = MockDocument()
        output = tmp_path / "test.pdf"

        # Без рендерера PDF не поддерживается
        result = service.export_to_pdf(doc, output)

        assert result.success is False

    def test_export_to_txt(self, tmp_path: Path) -> None:
        """Экспорт в TXT."""
        service = ExportService()
        doc = MockDocument()
        output = tmp_path / "test.txt"

        result = service.export_to_txt(doc, output)

        assert result.success is True
        assert output.exists()

    def test_export_to_html(self, tmp_path: Path) -> None:
        """Экспорт в HTML (требует рендерер)."""
        service = ExportService()
        html_renderer = MockRenderer(extension=".html", mime_type="text/html")
        service.register_renderer(ExportFormat.HTML, html_renderer)
        doc = MockDocument()
        output = tmp_path / "test.html"

        result = service.export_to_html(doc, output)

        assert result.success is True

    def test_export_creates_directory(self, tmp_path: Path) -> None:
        """Экспорт создаёт директорию."""
        service = ExportService()
        doc = MockDocument()
        output = tmp_path / "subdir" / "deep" / "test.txt"

        result = service.export(doc, ExportOptions(format=ExportFormat.TXT, output_path=output))

        assert result.success is True
        assert output.exists()

    def test_export_batch(self, tmp_path: Path) -> None:
        """Пакетный экспорт."""
        service = ExportService()
        # Регистрируем рендерер для TXT
        service.register_renderer(ExportFormat.TXT, MockRenderer())

        docs = [MockDocument(f"Doc{i}") for i in range(3)]

        result = service.export_batch(docs, ExportOptions(format=ExportFormat.TXT), output_dir=tmp_path)

        assert result.total == 3
        assert result.successful == 3
        assert result.failed == 0

    def test_export_batch_with_errors(self, tmp_path: Path) -> None:
        """Пакетный экспорт с ошибками."""
        service = ExportService()
        # Регистрируем рендерер для TXT
        service.register_renderer(ExportFormat.TXT, MockRenderer())

        # Документы без имени для metadata.title
        docs = [MockDocument() for _ in range(3)]
        for doc in docs:
            doc.metadata.title = ""  # Пустое имя

        result = service.export_batch(docs, ExportOptions(format=ExportFormat.TXT), output_dir=tmp_path)

        assert result.total == 3
        # Должен успешно экспортировать даже с пустым именем
        assert result.successful == 3

    def test_callback_called(self, tmp_path: Path) -> None:
        """Callback вызывается при экспорте."""
        callback: ExportCallback = MagicMock()
        service = ExportService(callback=callback)
        doc = MockDocument()
        output = tmp_path / "test.txt"

        service.export(doc, ExportOptions(format=ExportFormat.TXT, output_path=output))

        callback.assert_called_once()
        args = callback.call_args
        assert args[0][1] == ExportStatus.COMPLETED
        assert args[0][2] == 100

    def test_export_with_metadata(self, tmp_path: Path) -> None:
        """Экспорт с метаданными."""
        service = ExportService()
        doc = MockDocument()
        output = tmp_path / "test.json"

        result = service.export(
            doc,
            ExportOptions(format=ExportFormat.JSON, output_path=output, include_metadata=True),
        )

        assert result.success is True
        content = output.read_text()
        assert '"metadata"' in content

    def test_get_supported_formats(self) -> None:
        """Получение поддерживаемых форматов."""
        service = ExportService()

        formats = service.get_supported_formats()
        assert ExportFormat.PDF in formats
        assert ExportFormat.HTML in formats
        assert ExportFormat.TXT in formats
        assert ExportFormat.JSON in formats


class TestBatchExportResult:
    """Тесты BatchExportResult dataclass."""

    def test_create_result(self) -> None:
        """Создание результата."""
        result = BatchExportResult(
            total=10,
            successful=8,
            failed=2,
        )

        assert result.total == 10
        assert result.successful == 8
        assert result.failed == 2
        assert len(result.results) == 0

    def test_result_frozen(self) -> None:
        """Проверка frozen dataclass."""
        result = BatchExportResult(total=5, successful=3, failed=2)

        with pytest.raises(AttributeError):
            result.total = 10  # type: ignore[misc]


class TestRendererProtocol:
    """Тесты RendererProtocol."""

    def test_protocol_methods(self) -> None:
        """Методы протокола."""
        renderer = MockRenderer()
        options = ExportOptions()

        # Проверяем методы протокола
        assert hasattr(renderer, "render")
        assert hasattr(renderer, "get_extension")
        assert hasattr(renderer, "get_mime_type")

        # Вызываем методы
        data = renderer.render(None, options)
        assert data == b"test content"

        assert renderer.get_extension() == ".txt"
        assert renderer.get_mime_type() == "text/plain"