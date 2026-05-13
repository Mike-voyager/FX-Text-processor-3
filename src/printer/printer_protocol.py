"""Протоколы и типы для модуля принтера.

Определяет интерфейсы для адаптеров печати и связанные
типы данных (frozen dataclasses).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------


class PrinterState(Enum):
    """Состояние принтера."""

    IDLE = "idle"
    PRINTING = "printing"
    PAUSED = "paused"
    ERROR = "error"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class PrintJobStatus(Enum):
    """Статус задания печати."""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# -----------------------------------------------------------------------------
# Data Classes
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class PrinterInfo:
    """Информация о принтере.

    Attributes:
        printer_id: Уникальный идентификатор (adapter:name)
        name: Отображаемое имя
        adapter_type: Тип адаптера (cups/win32/file)
        is_default: Принтер по умолчанию
        is_available: Доступен для печати
        location: Опциональное местоположение
        description: Опциональное описание
    """

    printer_id: str
    name: str
    adapter_type: str
    is_default: bool = False
    is_available: bool = True
    location: Optional[str] = None
    description: Optional[str] = None


@dataclass(frozen=True)
class PrinterStatus:
    """Статус принтера.

    Attributes:
        state: Текущее состояние
        message: Человекочитаемое сообщение
        job_count: Количество заданий в очереди
        is_accepting_jobs: Принимает ли новые задания
        last_update: Время последнего обновления
    """

    state: PrinterState
    message: str
    job_count: int = 0
    is_accepting_jobs: bool = True
    last_update: datetime = datetime.now()


@dataclass(frozen=True)
class PrintResult:
    """Результат операции печати.

    Attributes:
        success: Успешно ли выполнена операция
        job_id: ID задания печати (если доступно)
        status: Статус задания
        message: Сообщение о результате
        pages_printed: Количество напечатанных страниц
        bytes_transferred: Количество переданных байт
        timestamp: Время операции
    """

    success: bool
    job_id: Optional[str] = None
    status: PrintJobStatus = PrintJobStatus.PENDING
    message: str = ""
    pages_printed: int = 0
    bytes_transferred: int = 0
    timestamp: datetime = datetime.now()


@dataclass(frozen=True)
class PrintOptions:
    """Опции печати для адаптера.

    Attributes:
        copies: Количество копий
        raw_mode: Печать без обработки драйвером
        media: Тип носителя (A4, Letter, etc)
        orientation: Ориентация (portrait/landscape)
        duplex: Двусторонняя печать
        custom_options: Произвольные опции для адаптера
    """

    copies: int = 1
    raw_mode: bool = True
    media: Optional[str] = None
    orientation: Optional[str] = None
    duplex: bool = False
    custom_options: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Валидация опций."""
        if self.copies < 1:
            object.__setattr__(self, "copies", 1)
        if self.copies > 99:
            object.__setattr__(self, "copies", 99)


# -----------------------------------------------------------------------------
# Protocols
# -----------------------------------------------------------------------------


@runtime_checkable
class PrinterProtocol(Protocol):
    """Протокол адаптера принтера.

    Все адаптеры печати (CUPS, Windows, File) должны
    реализовывать этот интерфейс.
    """

    def print_data(
        self,
        data: bytes,
        printer_name: str,
        job_name: str = "FX-Document",
        options: Optional[PrintOptions] = None,
    ) -> PrintResult:
        """Печатает данные на принтер.

        Args:
            data: ESC/P данные для печати
            printer_name: Имя принтера
            job_name: Имя задания печати
            options: Опции печати

        Returns:
            Результат операции печати
        """
        ...

    def get_printers(self) -> List[PrinterInfo]:
        """Возвращает список доступных принтеров.

        Returns:
            Список информации о принтерах
        """
        ...

    def get_status(self, printer_name: str) -> PrinterStatus:
        """Возвращает статус принтера.

        Args:
            printer_name: Имя принтера

        Returns:
            Статус принтера
        """
        ...

    def is_available(self) -> bool:
        """Проверяет доступность адаптера.

        Returns:
            True если адаптер доступен на системе
        """
        ...

    def get_adapter_name(self) -> str:
        """Возвращает имя адаптера.

        Returns:
            Строковый идентификатор адаптера
        """
        ...


@runtime_checkable
class PrinterAdapter(Protocol):
    """Альтернативный протокол адаптера (для совместимости с print_controller).

    Используется в PrintController из controller/print_controller.py.
    """

    def get_name(self) -> str:
        """Возвращает имя принтера."""
        ...

    def is_available(self) -> bool:
        """Проверяет доступность принтера."""
        ...

    def print_data(
        self,
        data: bytes,
        job_name: str,
        copies: int = 1,
    ) -> bool:
        """Печатает данные."""
        ...

    @staticmethod
    def discover_printers() -> List[Any]:
        """Обнаруживает доступные принтеры."""
        ...
