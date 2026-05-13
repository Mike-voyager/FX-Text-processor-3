"""Сервис экспорта документов.

Экспорт документов в различные форматы: PDF, HTML, TXT, ESC/P.
Интеграция с CryptoService для шифрования.

Module: src/services/export_service.py
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Protocol
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from src.model.document import Document
    from src.security.crypto.service.crypto_service import CryptoService

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Форматы экспорта
# ---------------------------------------------------------------------------


class ExportFormat(Enum):
    """Форматы экспорта."""

    PDF = "pdf"
    HTML = "html"
    TXT = "txt"
    ESCP = "escp"  # Raw ESC/P
    ESCPS = "escps"  # ESC/P script
    JSON = "json"


class ExportStatus(Enum):
    """Статус экспорта."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# ---------------------------------------------------------------------------
# Результаты экспорта
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExportOptions:
    """Опции экспорта.

    Attrs:
        format: Формат экспорта
        output_path: Путь для сохранения (optional)
        encrypt: Шифровать результат
        include_metadata: Включить метаданные
        page_range: Диапазон страниц (start, end)
        quality: Качество (для PDF: low/medium/high)
        encoding: Кодировка (для текстовых форматов)
        paper_size: Размер бумаги (для ESC/P)
        margins: Отступы в мм (top, right, bottom, left)
        extra: Дополнительные опции (optional)
    """

    format: ExportFormat = ExportFormat.PDF
    output_path: Optional[Path] = None
    encrypt: bool = False
    include_metadata: bool = True
    page_range: Optional[tuple[int, int]] = None
    quality: str = "medium"
    encoding: str = "utf-8"
    paper_size: str = "A4"
    margins: tuple[float, float, float, float] = (10.0, 10.0, 10.0, 10.0)
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ExportResult:
    """Результат экспорта.

    Attrs:
        success: True при успехе
        output_path: Путь к файлу результата
        format: Формат результата
        bytes_written: Количество записанных байт
        status: Статус экспорта
        error: Сообщение об ошибке или None
        encryption_key: Ключ шифрования (если encrypt=True)
        metadata: Метаданные экспорта
    """

    success: bool
    output_path: Optional[Path] = None
    format: ExportFormat = ExportFormat.PDF
    bytes_written: int = 0
    status: ExportStatus = ExportStatus.PENDING
    error: Optional[str] = None
    encryption_key: Optional[bytes] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BatchExportResult:
    """Результат пакетного экспорта.

    Attrs:
        total: Общее количество документов
        successful: Успешно экспортировано
        failed: Количество ошибок
        results: Результаты по каждому документу
    """

    total: int
    successful: int
    failed: int
    results: Dict[UUID, ExportResult] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Протоколы рендереров
# ---------------------------------------------------------------------------


class RendererProtocol(Protocol):
    """Протокол рендерера для экспорта."""

    def render(self, document: "Document", options: ExportOptions) -> bytes:
        """Рендерит документ в байты.

        Args:
            document: Документ
            options: Опции экспорта

        Returns:
            Байты результата
        """
        ...

    def get_extension(self) -> str:
        """Возвращает расширение файла."""
        ...

    def get_mime_type(self) -> str:
        """Возвращает MIME-тип."""
        ...


class ExportCallback(Protocol):
    """Протокол callback для экспорта."""

    def __call__(
        self,
        document_id: UUID,
        status: ExportStatus,
        progress: int,
        error: Optional[str],
    ) -> None:
        """Вызывается при изменении статуса экспорта.

        Args:
            document_id: ID документа
            status: Статус
            progress: Прогресс (0-100)
            error: Сообщение об ошибке
        """
        ...


# ---------------------------------------------------------------------------
# ExportService
# ---------------------------------------------------------------------------


class ExportService:
    """Сервис экспорта документов.

    Поддерживает:
    - Экспорт в PDF, HTML, TXT, ESC/P
    - Шифрование результата
    - Пакетный экспорт
    - Callback для отслеживания прогресса

    Пример:
        >>> service = ExportService()
        >>> result = service.export(document, ExportFormat.PDF)
        >>> if result.success:
        ...     print(f"Экспортировано: {result.output_path}")
    """

    def __init__(
        self,
        crypto_service: Optional["CryptoService"] = None,
        renderers: Optional[Dict[ExportFormat, RendererProtocol]] = None,
        callback: Optional[ExportCallback] = None,
    ) -> None:
        """Инициализирует сервис экспорта.

        Args:
            crypto_service: Криптосервис для шифрования (optional)
            renderers: Словарь рендереров по форматам (optional)
            callback: Callback для отслеживания прогресса (optional)
        """
        self._crypto = crypto_service
        self._renderers = renderers or {}
        self._callback = callback

        # Импортируем рендереры по умолчанию
        self._init_default_renderers()

    def _init_default_renderers(self) -> None:
        """Инициализирует рендереры по умолчанию."""
        # Рендереры будут добавлены при импорте соответствующих модулей
        # Здесь только заглушки - реальные рендереры в documents/printing/
        pass

    # ---------- Основной экспорт ----------

    def export(
        self,
        document: "Document",
        options: Optional[ExportOptions] = None,
        output_path: Optional[Path] = None,
    ) -> ExportResult:
        """Экспортирует документ в указанный формат.

        Args:
            document: Документ для экспорта
            options: Опции экспорта (optional)
            output_path: Путь для сохранения (optional)

        Returns:
            ExportResult с результатом
        """
        options = options or ExportOptions()
        if output_path:
            options = ExportOptions(
                format=options.format,
                output_path=output_path,
                encrypt=options.encrypt,
                include_metadata=options.include_metadata,
                page_range=options.page_range,
                quality=options.quality,
                encoding=options.encoding,
                paper_size=options.paper_size,
                margins=options.margins,
            )

        # Проверяем рендерер
        renderer = self._renderers.get(options.format)
        if renderer is None:
            # Используем базовый рендерер
            try:
                data = self._render_default(document, options)
            except Exception as exc:
                error = f"Ошибка рендеринга: {exc}"
                logger.error(error, exc_info=True)
                return ExportResult(
                    success=False,
                    status=ExportStatus.FAILED,
                    error=error,
                )
        else:
            try:
                data = renderer.render(document, options)
            except Exception as exc:
                error = f"Ошибка рендеринга: {exc}"
                logger.error(error, exc_info=True)
                return ExportResult(
                    success=False,
                    status=ExportStatus.FAILED,
                    error=error,
                )

        # Определяем путь
        if options.output_path is None:
            filename = document.metadata.title or "document"
            extension = renderer.get_extension() if renderer else options.format.value
            options = ExportOptions(
                format=options.format,
                output_path=Path(f"{filename}.{extension}"),
                encrypt=options.encrypt,
                include_metadata=options.include_metadata,
                page_range=options.page_range,
                quality=options.quality,
                encoding=options.encoding,
                paper_size=options.paper_size,
                margins=options.margins,
            )

        # Шифруем если нужно
        encryption_key: Optional[bytes] = None
        if options.encrypt and self._crypto:
            try:
                encryption_key = self._crypto.generate_symmetric_key()
                encrypted = self._crypto.encrypt_document(data, encryption_key)
                data = encrypted.ciphertext
            except Exception as exc:
                error = f"Ошибка шифрования: {exc}"
                logger.error(error, exc_info=True)
                return ExportResult(
                    success=False,
                    status=ExportStatus.FAILED,
                    error=error,
                )

        # Сохраняем
        try:
            output_path = options.output_path
            if output_path is None:
                raise ValueError("output_path не определён")

            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(data)

        except Exception as exc:
            error = f"Ошибка сохранения: {exc}"
            logger.error(error, exc_info=True)
            return ExportResult(
                success=False,
                status=ExportStatus.FAILED,
                error=error,
            )

        # Уведомляем callback
        self._notify(
            document.id if document.id else uuid4(),
            ExportStatus.COMPLETED,
            100,
            None,
        )

        return ExportResult(
            success=True,
            output_path=output_path,
            format=options.format,
            bytes_written=len(data),
            status=ExportStatus.COMPLETED,
            encryption_key=encryption_key,
        )

    def export_batch(
        self,
        documents: List["Document"],
        options: Optional[ExportOptions] = None,
        output_dir: Optional[Path] = None,
    ) -> BatchExportResult:
        """Экспортирует несколько документов.

        Args:
            documents: Список документов
            options: Опции экспорта (optional)
            output_dir: Директория для сохранения (optional)

        Returns:
            BatchExportResult с результатами
        """
        options = options or ExportOptions()
        results: Dict[UUID, ExportResult] = {}
        successful = 0
        failed = 0

        for i, document in enumerate(documents):
            # Определяем путь
            if output_dir:
                filename = document.metadata.title or f"document_{i}"
                extension = options.format.value
                output_path = output_dir / f"{filename}.{extension}"
            else:
                output_path = None

            # Экспортируем
            result = self.export(document, options, output_path)
            results[document.id if document.id else uuid4()] = result

            if result.success:
                successful += 1
            else:
                failed += 1

            # Уведомляем callback
            self._notify(
                document.id if document.id else uuid4(),
                result.status,
                int((i + 1) / len(documents) * 100),
                result.error,
            )

        return BatchExportResult(
            total=len(documents),
            successful=successful,
            failed=failed,
            results=results,
        )

    # ---------- Специализированные методы ----------

    def export_to_pdf(
        self,
        document: "Document",
        output_path: Optional[Path] = None,
        quality: str = "medium",
    ) -> ExportResult:
        """Экспортирует документ в PDF.

        Args:
            document: Документ
            output_path: Путь для сохранения
            quality: Качество (low/medium/high)

        Returns:
            ExportResult
        """
        options = ExportOptions(
            format=ExportFormat.PDF,
            output_path=output_path,
            quality=quality,
        )
        return self.export(document, options)

    def export_to_html(
        self,
        document: "Document",
        output_path: Optional[Path] = None,
        include_styles: bool = True,
    ) -> ExportResult:
        """Экспортирует документ в HTML.

        Args:
            document: Документ
            output_path: Путь для сохранения
            include_styles: Включить стили CSS

        Returns:
            ExportResult
        """
        options = ExportOptions(
            format=ExportFormat.HTML,
            output_path=output_path,
            extra={"include_styles": include_styles},
        )
        return self.export(document, options)

    def export_to_txt(
        self,
        document: "Document",
        output_path: Optional[Path] = None,
        encoding: str = "utf-8",
    ) -> ExportResult:
        """Экспортирует документ в текст.

        Args:
            document: Документ
            output_path: Путь для сохранения
            encoding: Кодировка

        Returns:
            ExportResult
        """
        options = ExportOptions(
            format=ExportFormat.TXT,
            output_path=output_path,
            encoding=encoding,
        )
        return self.export(document, options)

    def export_to_escp(
        self,
        document: "Document",
        output_path: Optional[Path] = None,
    ) -> ExportResult:
        """Экспортирует документ в ESC/P.

        Args:
            document: Документ
            output_path: Путь для сохранения

        Returns:
            ExportResult
        """
        options = ExportOptions(
            format=ExportFormat.ESCP,
            output_path=output_path,
        )
        return self.export(document, options)

    # ---------- Утилиты ----------

    def get_supported_formats(self) -> List[ExportFormat]:
        """Возвращает поддерживаемые форматы."""
        return list(ExportFormat)

    def get_file_extension(self, format: ExportFormat) -> str:
        """Возвращает расширение файла для формата.

        Args:
            format: Формат экспорта

        Returns:
            Расширение файла
        """
        extensions = {
            ExportFormat.PDF: ".pdf",
            ExportFormat.HTML: ".html",
            ExportFormat.TXT: ".txt",
            ExportFormat.ESCP: ".escp",
            ExportFormat.ESCPS: ".escps",
            ExportFormat.JSON: ".json",
        }
        return extensions.get(format, f".{format.value}")

    def register_renderer(
        self,
        format: ExportFormat,
        renderer: RendererProtocol,
    ) -> None:
        """Регистрирует рендерер для формата.

        Args:
            format: Формат
            renderer: Рендерер
        """
        self._renderers[format] = renderer
        logger.info("Зарегистрирован рендерер для %s", format.value)

    # ---------- Внутренние методы ----------

    def _render_default(
        self,
        document: "Document",
        options: ExportOptions,
    ) -> bytes:
        """Рендерит документ базовым методом.

        Args:
            document: Документ
            options: Опции

        Returns:
            Байты результата
        """
        if options.format == ExportFormat.TXT:
            return self._render_text(document, options)
        if options.format == ExportFormat.JSON:
            return self._render_json(document, options)

        raise ValueError(f"Неподдерживаемый формат: {options.format}")

    def _render_text(
        self,
        document: "Document",
        options: ExportOptions,
    ) -> bytes:
        """Рендерит документ в текст.

        Args:
            document: Документ
            options: Опции

        Returns:
            Текст в байтах
        """
        text = document.get_text_content()
        return text.encode(options.encoding)

    def _render_json(
        self,
        document: "Document",
        options: ExportOptions,
    ) -> bytes:
        """Рендерит документ в JSON.

        Args:
            document: Документ
            options: Опции

        Returns:
            JSON в байтах
        """
        import json

        data = {
            "id": str(document.id),
            "metadata": document.metadata.to_dict(),
            "page_settings": document.page_settings.to_dict(),
            "printer_settings": document.printer_settings.to_dict(),
            "sections": [s.to_dict() for s in getattr(document, "sections", [])]
        }
        return json.dumps(data, ensure_ascii=False, indent=2).encode(options.encoding)

    def _notify(
        self,
        document_id: UUID,
        status: ExportStatus,
        progress: int,
        error: Optional[str],
    ) -> None:
        """Вызывает callback.

        Args:
            document_id: ID документа
            status: Статус
            progress: Прогресс
            error: Ошибка
        """
        if self._callback:
            try:
                self._callback(document_id, status, progress, error)
            except Exception as exc:
                logger.error("Ошибка callback: %s", exc)


__all__ = [
    "ExportService",
    "ExportFormat",
    "ExportStatus",
    "ExportOptions",
    "ExportResult",
    "BatchExportResult",
    "RendererProtocol",
    "ExportCallback",
]
