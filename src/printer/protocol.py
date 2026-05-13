"""Протокол принтера.

Определяет интерфейс для всех адаптеров принтеров.
Использует typing.Protocol для dependency injection.

Module: src/printer/protocol.py
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Protocol
from uuid import UUID

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# Статусы и константы
# ---------------------------------------------------------------------------


class PrinterStatus(Enum):
    """Статус принтера."""

    READY = "ready"  # Готов к печати
    BUSY = "busy"  # Занят
    OFFLINE = "offline"  # Отключен
    ERROR = "error"  # Ошибка
    PAPER_JAM = "paper_jam"  # Замятие бумаги
    OUT_OF_PAPER = "out_of_paper"  # Нет бумаги
    LOW_INK = "low_ink"  # Мало чернил
    MAINTENANCE = "maintenance"  # Обслуживание
    UNKNOWN = "unknown"  # Неизвестно


class PrintJobStatus(Enum):
    """Статус задания печати."""

    PENDING = "pending"  # Ожидает
    SPOOLING = "spooling"  # Буферизация
    PRINTING = "printing"  # Печатается
    COMPLETED = "completed"  # Завершено
    FAILED = "failed"  # Ошибка
    CANCELLED = "cancelled"  # Отменено


class PaperSource(Enum):
    """Источники бумаги."""

    AUTO = "auto"  # Автоматический выбор
    MANUAL = "manual"  # Ручная подача
    TRAY_1 = "tray_1"  # Лоток 1
    TRAY_2 = "tray_2"  # Лоток 2
    CONTINUOUS = "continuous"  # Рулонная бумага


# ---------------------------------------------------------------------------
# Модели данных
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PrinterCapabilities:
    """Возможности принтера.

    Attrs:
        name: Имя принтера
        model: Модель
        manufacturer: Производитель
        supports_escp: Поддержка ESC/P
        supports_escp_script: Поддержка ESC/P скриптов
        max_width: Максимальная ширина (символы)
        max_lines: Максимум строк на страницу
        has_paper_sensor: Датчик бумаги
        has_form_sensor: Датчик формы
        continuous_feed: Рулонная подача
        supported_papers: Поддерживаемые форматы бумаги
        supported_tractors: Поддерживаемые тракторы
    """

    name: str = ""
    model: str = ""
    manufacturer: str = ""
    supports_escp: bool = True
    supports_escp_script: bool = False
    max_width: int = 136  # символов (17" для FX-890)
    max_lines: int = 66  # строк на страницу
    has_paper_sensor: bool = True
    has_form_sensor: bool = False
    continuous_feed: bool = True
    supported_papers: List[str] = field(default_factory=lambda: ["continuous", "cut_sheet"])
    supported_tractors: List[str] = field(default_factory=lambda: ["front", "rear"])


@dataclass(frozen=True)
class PrintOptions:
    """Опции печати.

    Attrs:
        copies: Количество копий
        paper_source: Источник бумаги
        paper_size: Размер бумаги
        quality: Качество печати (draft/normal/high)
        bidirectional: Двунаправленная печать
        bold_emulation: Эмуляция жирного
        italic_emulation: Эмуляция курсива
        margins: Отступы (мм)
        tear_off: Автоотрыв после печати
        micro_adjust: Микрокоррекция позиции
        output_file: Файл для сохранения (optional)
        metadata: Дополнительные метаданные
    """

    copies: int = 1
    paper_source: PaperSource = PaperSource.AUTO
    paper_size: str = "A4"
    quality: str = "normal"  # draft, normal, high
    bidirectional: bool = True
    bold_emulation: bool = True
    italic_emulation: bool = True
    margins: tuple[float, float, float, float] = (10.0, 10.0, 10.0, 10.0)
    tear_off: bool = False
    micro_adjust: int = 0  # -128 to 127
    output_file: Optional[Path] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PrintResult:
    """Результат печати.

    Attrs:
        success: Успешность операции
        job_id: ID задания (optional)
        status: Статус задания
        pages_printed: Напечатано страниц
        bytes_sent: Отправлено байт
        error_message: Сообщение об ошибке (optional)
        started_at: Время начала (optional)
        completed_at: Время завершения (optional)
        metadata: Дополнительные метаданные
    """

    success: bool
    job_id: Optional[UUID] = None
    status: PrintJobStatus = PrintJobStatus.PENDING
    pages_printed: int = 0
    bytes_sent: int = 0
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Протокол принтера
# ---------------------------------------------------------------------------


class PrinterProtocol(Protocol):
    """Протокол принтера.

    Определяет интерфейс для всех адаптеров принтеров.
    Реализации могут работать с физическими принтерами,
    виртуальными принтерами или файлами.

    Пример:
        >>> printer: PrinterProtocol = FilePrinterAdapter()
        >>> result = printer.print_data(escp_data, "Document")
        >>> if result.success:
        ...     print(f"Printed {result.bytes_sent} bytes")
    """

    def get_name(self) -> str:
        """Возвращает имя принтера.

        Returns:
            Имя принтера
        """
        ...

    def get_capabilities(self) -> PrinterCapabilities:
        """Возвращает возможности принтера.

        Returns:
            Возможности принтера
        """
        ...

    def is_available(self) -> bool:
        """Проверяет доступность принтера.

        Returns:
            True если принтер доступен
        """
        ...

    def get_status(self) -> PrinterStatus:
        """Возвращает текущий статус принтера.

        Returns:
            Статус принтера
        """
        ...

    def print_data(
        self,
        data: bytes,
        job_name: str,
        options: Optional[PrintOptions] = None,
    ) -> PrintResult:
        """Отправляет данные на печать.

        Args:
            data: ESC/P данные для печати
            job_name: Имя задания
            options: Опции печати (optional)

        Returns:
            Результат печати
        """
        ...

    def cancel_job(self, job_id: UUID) -> bool:
        """Отменяет задание печати.

        Args:
            job_id: ID задания

        Returns:
            True если успешно отменено
        """
        ...

    def get_job_status(self, job_id: UUID) -> Optional[PrintJobStatus]:
        """Возвращает статус задания.

        Args:
            job_id: ID задания

        Returns:
            Статус задания или None
        """
        ...

    def reset(self) -> bool:
        """Сбрасывает принтер в начальное состояние.

        Returns:
            True если успешно
        """
        ...

    def initialize(self) -> bool:
        """Инициализирует принтер.

        Returns:
            True если успешно
        """
        ...


__all__ = [
    "PrinterProtocol",
    "PrinterCapabilities",
    "PrinterStatus",
    "PrintJobStatus",
    "PaperSource",
    "PrintOptions",
    "PrintResult",
]
