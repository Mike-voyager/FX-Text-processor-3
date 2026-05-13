"""Базовый адаптер принтера.

Абстрактный базовый класс для всех адаптеров принтеров.
Реализует общую логику и определяет абстрактные методы.

Module: src/printer/base_adapter.py
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from src.printer.protocol import (
        PrinterCapabilities,
        PrinterStatus,
        PrintJobStatus,
        PrintOptions,
        PrintResult,
    )

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Информация о принтере
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PrinterInfo:
    """Информация о принтере.

    Attrs:
        name: Имя принтера
        model: Модель
        manufacturer: Производитель
        connection_type: Тип подключения (usb/network/file)
        port: Порт или путь к файлу
        is_default: Принтер по умолчанию
        is_online: Принтер в сети
        capabilities: Возможности принтера
    """

    name: str = ""
    model: str = ""
    manufacturer: str = ""
    connection_type: str = "unknown"
    port: str = ""
    is_default: bool = False
    is_online: bool = True
    capabilities: "PrinterCapabilities" = field(default_factory=lambda: None)  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Базовый адаптер
# ---------------------------------------------------------------------------


class BasePrinterAdapter(ABC):
    """Базовый адаптер принтера.

    Реализует общую логику для всех адаптеров:
    - Управление состоянием
    - Логирование
    - Базовые операции

    Конкретные адаптеры должны реализовать абстрактные методы.
    """

    def __init__(self, printer_info: Optional[PrinterInfo] = None) -> None:
        """Инициализирует адаптер.

        Args:
            printer_info: Информация о принтере (optional)
        """
        self._printer_info = printer_info or PrinterInfo()
        self._current_job: Optional[UUID] = None
        self._initialized = False
        self._last_error: Optional[str] = None

    # ---------- Абстрактные методы ----------

    @abstractmethod
    def get_name(self) -> str:
        """Возвращает имя принтера.

        Returns:
            Имя принтера
        """
        ...

    @abstractmethod
    def get_capabilities(self) -> "PrinterCapabilities":
        """Возвращает возможности принтера.

        Returns:
            Возможности принтера
        """
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Проверяет доступность принтера.

        Returns:
            True если принтер доступен
        """
        ...

    @abstractmethod
    def _send_data(self, data: bytes) -> bool:
        """Отправляет данные на принтер (внутренний метод).

        Args:
            data: Данные для отправки

        Returns:
            True если успешно
        """
        ...

    @abstractmethod
    def _get_printer_status(self) -> "PrinterStatus":
        """Возвращает статус принтера (внутренний метод).

        Returns:
            Статус принтера
        """
        ...

    # ---------- Реализация протокола ----------

    def get_status(self) -> "PrinterStatus":
        """Возвращает текущий статус принтера.

        Returns:
            Статус принтера
        """
        return self._get_printer_status()

    def print_data(
        self,
        data: bytes,
        job_name: str,
        options: Optional["PrintOptions"] = None,
    ) -> "PrintResult":
        """Отправляет данные на печать.

        Args:
            data: ESC/P данные для печати
            job_name: Имя задания
            options: Опции печати (optional)

        Returns:
            Результат печати
        """
        from src.printer.protocol import PrintJobStatus, PrintResult

        # Проверяем доступность
        if not self.is_available():
            return PrintResult(
                success=False,
                status=PrintJobStatus.FAILED,
                error_message="Принтер недоступен",
            )

        # Создаём задание
        job_id = uuid4()
        self._current_job = job_id
        started_at = datetime.now()

        logger.info("Начало печати: %s (job_id=%s)", job_name, job_id)

        try:
            # Инициализируем если нужно
            if not self._initialized:
                if not self.initialize():
                    return PrintResult(
                        success=False,
                        job_id=job_id,
                        status=PrintJobStatus.FAILED,
                        error_message="Не удалось инициализировать принтер",
                        started_at=started_at,
                        completed_at=datetime.now(),
                    )

            # Количество копий
            copies = 1
            if options and hasattr(options, "copies"):
                copies = max(1, options.copies)

            # Отправляем данные
            total_bytes = 0
            for copy_num in range(copies):
                if not self._send_data(data):
                    return PrintResult(
                        success=False,
                        job_id=job_id,
                        status=PrintJobStatus.FAILED,
                        error_message=self._last_error or "Ошибка отправки данных",
                        started_at=started_at,
                        completed_at=datetime.now(),
                        bytes_sent=total_bytes,
                    )
                total_bytes += len(data)

                # Сбрасываем буфер между копиями (кроме последней)
                if copy_num < copies - 1:
                    self._send_form_feed()

            # Формируем результат
            result = PrintResult(
                success=True,
                job_id=job_id,
                status=PrintJobStatus.COMPLETED,
                bytes_sent=total_bytes,
                started_at=started_at,
                completed_at=datetime.now(),
            )

            logger.info(
                "Печать завершена: %s (bytes=%d)",
                job_name,
                total_bytes,
            )

            return result

        except Exception as exc:
            logger.error("Ошибка печати: %s", exc)
            return PrintResult(
                success=False,
                job_id=job_id,
                status=PrintJobStatus.FAILED,
                error_message=str(exc),
                started_at=started_at,
                completed_at=datetime.now(),
            )

        finally:
            self._current_job = None

    def cancel_job(self, job_id: UUID) -> bool:
        """Отменяет задание печати.

        Args:
            job_id: ID задания

        Returns:
            True если успешно отменено
        """
        if job_id != self._current_job:
            return False

        # Сбрасываем текущее задание
        self._current_job = None
        logger.info("Задание отменено: %s", job_id)
        return True

    def get_job_status(self, job_id: UUID) -> Optional["PrintJobStatus"]:
        """Возвращает статус задания.

        Args:
            job_id: ID задания

        Returns:
            Статус задания или None
        """
        from src.printer.protocol import PrintJobStatus

        if job_id == self._current_job:
            return PrintJobStatus.PRINTING

        return None

    def reset(self) -> bool:
        """Сбрасывает принтер в начальное состояние.

        Returns:
            True если успешно
        """
        # ESC/P команда сброса
        reset_command = b"\x1b\x40"  # ESC @
        if self._send_data(reset_command):
            self._initialized = False
            logger.info("Принтер сброшен")
            return True
        return False

    def initialize(self) -> bool:
        """Инициализирует принтер.

        Returns:
            True если успешно
        """
        # ESC/P команда инициализации
        init_command = b"\x1b\x40"  # ESC @
        if self._send_data(init_command):
            self._initialized = True
            logger.info("Принтер инициализирован")
            return True
        return False

    # ---------- Вспомогательные методы ----------

    def _send_form_feed(self) -> bool:
        """Отправляет команду продвижения формы.

        Returns:
            True если успешно
        """
        # ESC/P команда Form Feed
        form_feed = b"\x0c"  # FF
        return self._send_data(form_feed)

    def _send_line_feed(self, lines: int = 1) -> bool:
        """Отправляет команду перевода строки.

        Args:
            lines: Количество строк

        Returns:
            True если успешно
        """
        # ESC/P команда Line Feed
        for _ in range(lines):
            if not self._send_data(b"\x0a"):  # LF
                return False
        return True

    def _send_carriage_return(self) -> bool:
        """Отправляет команду возврата каретки.

        Returns:
            True если успешно
        """
        return self._send_data(b"\x0d")  # CR

    def _set_error(self, message: str) -> None:
        """Устанавливает сообщение об ошибке.

        Args:
            message: Сообщение об ошибке
        """
        self._last_error = message
        logger.error("Ошибка принтера: %s", message)

    def get_printer_info(self) -> PrinterInfo:
        """Возвращает информацию о принтере.

        Returns:
            Информация о принтере
        """
        return self._printer_info

    @staticmethod
    def discover_printers() -> List[PrinterInfo]:
        """Обнаруживает доступные принтеры.

        Returns:
            Список обнаруженных принтеров
        """
        # Базовая реализация возвращает пустой список
        # Конкретные адаптеры должны переопределить этот метод
        return []


__all__ = [
    "BasePrinterAdapter",
    "PrinterInfo",
]
