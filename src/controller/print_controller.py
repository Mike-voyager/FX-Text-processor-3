"""Контроллер печати для FX Text Processor 3.

Управляет операциями печати на принтере Epson FX-890:
- Конвертация документов в формат ESC/P
- Управление очередью печати
- Выбор принтера (CUPS/Windows/File)
- Предпросмотр печати
- Экспорт в .escp файлы
- Печать защищённых бланков

Architecture:
    Controller (PrintController)
        ↓
    Service Layer (PrintService, PrintQueueService)
        ↓
    Model/Adapter (DocumentRenderer, PrinterAdapter)

Dependencies:
    - PrintService — операции печати
    - DocumentRenderer — конвертация в ESC/P байты
    - PrinterAdapter — транспортный слой (CUPS/Win/File)

Example:
    >>> controller = PrintController(
    ...     print_service=print_service,
    ...     document_service=document_service,
    ... )
    >>> controller.register_printer_adapter("cups", CupsAdapter())
    >>> job = controller.print_document(doc_id, settings)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Protocol,
    Tuple,
    runtime_checkable,
)
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from src.model.document import Document


# -----------------------------------------------------------------------------
# Exceptions
# -----------------------------------------------------------------------------


class PrintControllerError(Exception):
    """Базовая ошибка контроллера печати."""

    pass


class DocumentNotFoundError(PrintControllerError):
    """Документ не найден."""

    pass


class PrinterNotAvailableError(PrintControllerError):
    """Принтер недоступен."""

    pass


class BlankNotReadyError(PrintControllerError):
    """Бланк не готов для печати."""

    pass


class ExportError(PrintControllerError):
    """Ошибка экспорта."""

    pass


class RenderError(PrintControllerError):
    """Ошибка рендеринга документа."""

    pass


# -----------------------------------------------------------------------------
# Domain Models
# -----------------------------------------------------------------------------


class PaperType(str, Enum):
    """Типы бумаги для печати на Epson FX-890."""

    A4 = "a4"
    LETTER = "letter"
    TRACTOR = "tractor"
    ENVELOPE = "envelope"

    def localized_name(self) -> str:
        """Возвращает локализованное название типа бумаги."""
        names: Dict["PaperType", str] = {
            PaperType.A4: "A4 (210×297 мм)",
            PaperType.LETTER: "Letter (8.5×11 дюйм)",
            PaperType.TRACTOR: "Тракторная перфорированная",
            PaperType.ENVELOPE: "Конверт",
        }
        return names.get(self, self.value)


class PrintQuality(str, Enum):
    """Качество печати Epson FX-890."""

    DRAFT = "draft"
    NLQ = "nlq"

    def localized_name(self) -> str:
        """Возвращает локализованное название качества печати."""
        names: Dict["PrintQuality", str] = {
            PrintQuality.DRAFT: "Черновик (Draft)",
            PrintQuality.NLQ: "Высокое качество (NLQ)",
        }
        return names.get(self, self.value)


class CharactersPerInch(Enum):
    """Символов на дюйм (CPI) для Epson FX-890."""

    CPI_10 = 10
    CPI_12 = 12
    CPI_15 = 15
    CPI_17 = 17
    CPI_20 = 20

    def localized_name(self) -> str:
        """Возвращает локализованное название CPI."""
        return f"{self.value} CPI"


@dataclass(frozen=True)
class PageRange:
    """Диапазон страниц для печати.

    Attributes:
        start: Начальная страница (1-indexed, None = с начала)
        end: Конечная страница (inclusive, None = до конца)
    """

    start: Optional[int] = None
    end: Optional[int] = None

    @property
    def is_all_pages(self) -> bool:
        """True если диапазон включает все страницы."""
        return self.start is None and self.end is None

    def __str__(self) -> str:
        """Строковое представление диапазона."""
        if self.is_all_pages:
            return "Все"
        if self.start is None:
            return f"1-{self.end}"
        if self.end is None:
            return f"{self.start}-"
        if self.start == self.end:
            return str(self.start)
        return f"{self.start}-{self.end}"

    @classmethod
    def all_pages(cls) -> "PageRange":
        """Все страницы."""
        return cls(start=None, end=None)

    @classmethod
    def single_page(cls, page: int) -> "PageRange":
        """Одна страница."""
        return cls(start=page, end=page)

    @classmethod
    def from_string(cls, text: str) -> "PageRange":
        """Парсит диапазон из строки (например, "1-5", "3", "-10").

        Args:
            text: Строка с диапазоном страниц

        Returns:
            PageRange объект
        """
        text = text.strip()
        if not text or text.lower() in ("all", "все", ""):
            return cls.all_pages()

        if "-" in text:
            parts = text.split("-", 1)
            start = int(parts[0]) if parts[0].strip() else None
            end = int(parts[1]) if parts[1].strip() else None
            return cls(start=start, end=end)

        # Single page
        page = int(text)
        return cls(start=page, end=page)


@dataclass(frozen=True)
class PrintSettings:
    """Настройки печати документа.

    Attributes:
        paper_type: Тип бумаги
        cpi: Символов на дюйм
        quality: Качество печати
        copies: Количество копий (1-99)
        page_range: Диапазон страниц
        paper_source: Источник бумаги (auto/tractor/manual)
        bidirectional: Двунаправленная печать
    """

    paper_type: PaperType = PaperType.A4
    cpi: CharactersPerInch = CharactersPerInch.CPI_10
    quality: PrintQuality = PrintQuality.DRAFT
    copies: int = 1
    page_range: PageRange = field(default_factory=PageRange.all_pages)
    paper_source: str = "auto"
    bidirectional: bool = True

    def __post_init__(self) -> None:
        """Валидация настроек после создания."""
        if self.copies < 1:
            object.__setattr__(self, "copies", 1)
        if self.copies > 99:
            object.__setattr__(self, "copies", 99)


@dataclass(frozen=True)
class PrintPreviewData:
    """Данные для предпросмотра печати.

    Attributes:
        document_id: ID документа
        page_count: Количество страниц
        escp_data: ESC/P данные
        rendered_pages: Список отрендеренных страниц в текстовом виде
        warnings: Предупреждения
    """

    document_id: UUID
    page_count: int
    escp_data: bytes
    rendered_pages: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class PrinterInfo:
    """Информация о принтере.

    Attributes:
        printer_id: Уникальный идентификатор принтера
        name: Отображаемое имя
        connection_type: Тип подключения (cups/win32/file)
        is_default: Принтер по умолчанию
        is_online: Принтер доступен
    """

    printer_id: str
    name: str
    connection_type: str
    is_default: bool = False
    is_online: bool = True


# -----------------------------------------------------------------------------
# Protocols
# -----------------------------------------------------------------------------


@runtime_checkable
class PrintServiceProtocol(Protocol):
    """Протокол сервиса печати."""

    def print_document(
        self,
        document: "Document",
        printer_adapter: "PrinterAdapterProtocol",
        settings: PrintSettings,
    ) -> "PrintJob":
        """Печатает документ.

        Args:
            document: Документ для печати
            printer_adapter: Адаптер принтера
            settings: Настройки печати

        Returns:
            Задание печати
        """
        ...

    def get_document_preview(
        self,
        document: "Document",
        settings: Optional[PrintSettings] = None,
    ) -> PrintPreviewData:
        """Возвращает данные для предпросмотра.

        Args:
            document: Документ для предпросмотра
            settings: Настройки печати (опционально)

        Returns:
            Данные предпросмотра
        """
        ...


@runtime_checkable
class PrinterAdapterProtocol(Protocol):
    """Протокол адаптера принтера."""

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
        """Печатает данные.

        Args:
            data: ESC/P данные для печати
            job_name: Имя задания
            copies: Количество копий

        Returns:
            True при успехе
        """
        ...

    @staticmethod
    def discover_printers() -> List[PrinterInfo]:
        """Обнаруживает доступные принтеры.

        Returns:
            Список информации о принтерах
        """
        ...


@runtime_checkable
class DocumentRendererProtocol(Protocol):
    """Протокол рендерера документов."""

    def render(self, document: "Document") -> bytes:
        """Рендерит документ в ESC/P байты.

        Args:
            document: Документ для рендеринга

        Returns:
            ESC/P данные
        """
        ...


@runtime_checkable
class DocumentServiceProtocol(Protocol):
    """Протокол сервиса документов."""

    def get_by_id(self, doc_id: UUID) -> Optional["Document"]:
        """Возвращает документ по ID."""
        ...


@runtime_checkable
class BlankManagerProtocol(Protocol):
    """Протокол менеджера защищённых бланков."""

    def get_blank(self, blank_id: str) -> Optional[Any]:
        """Возвращает бланк по ID."""
        ...

    def sign_blank(
        self,
        blank_id: str,
        document_content: bytes,
    ) -> Tuple[Any, bytes, Any]:
        """Подписывает документ на бланке.

        Returns:
            Кортеж (signed_blank, signature, qr_data)
        """
        ...


@dataclass(frozen=True)
class PrintJob:
    """Задание на печать.

    Attributes:
        id: Уникальный идентификатор задания
        document_id: ID документа
        document_name: Имя документа
        printer_name: Имя принтера
        copies: Количество копий
        status: Статус задания
    """

    id: UUID
    document_id: UUID
    document_name: str
    printer_name: str
    copies: int
    status: str = "pending"


# -----------------------------------------------------------------------------
# PrintController
# -----------------------------------------------------------------------------


class PrintController:
    """Контроллер печати для Epson FX-890.

    Управляет полным циклом печати:
    1. Конвертация документа в ESC/P
    2. Управление очередью печати
    3. Выбор и конфигурация принтера
    4. Предпросмотр перед печатью
    5. Печать на защищённых бланках

    Attributes:
        _print_service: Сервис печати
        _document_service: Сервис документов
        _blank_manager: Менеджер защищённых бланков
        _document_renderer: Рендерер документов
        _printer_adapters: Словарь адаптеров принтеров
        _active_printer_id: ID активного принтера
        _default_settings: Настройки печати по умолчанию
        _logger: Логгер

    Example:
        >>> controller = PrintController(
        ...     print_service=print_service,
        ...     document_service=document_service,
        ... )
        >>> controller.register_printer_adapter("cups", CupsAdapter())
        >>> controller.set_active_printer("cups", "FX-890")
        >>> job = controller.print_document(doc_id, settings)
    """

    def __init__(
        self,
        print_service: Optional[PrintServiceProtocol] = None,
        document_service: Optional[DocumentServiceProtocol] = None,
        blank_manager: Optional[BlankManagerProtocol] = None,
        document_renderer: Optional[DocumentRendererProtocol] = None,
        default_settings: Optional[PrintSettings] = None,
    ) -> None:
        """Инициализирует контроллер печати.

        Args:
            print_service: Сервис печати (опционально)
            document_service: Сервис документов (опционально)
            blank_manager: Менеджер защищённых бланков (опционально)
            document_renderer: Рендерер документов (опционально)
            default_settings: Настройки по умолчанию (опционально)
        """
        self._print_service = print_service
        self._document_service = document_service
        self._blank_manager = blank_manager
        self._document_renderer = document_renderer
        self._default_settings: PrintSettings = default_settings or PrintSettings()

        # Адаптеры принтеров
        self._printer_adapters: Dict[str, PrinterAdapterProtocol] = {}
        self._active_printer_id: Optional[str] = None
        self._active_printer_name: Optional[str] = None

        # Callbacks для View
        self._status_callback: Optional[Callable[[str], None]] = None

        self._logger = logging.getLogger(__name__)
        self._logger.debug("PrintController инициализирован")

    # === Регистрация адаптеров ===

    def register_printer_adapter(
        self,
        adapter_id: str,
        adapter: PrinterAdapterProtocol,
    ) -> None:
        """Регистрирует адаптер принтера.

        Args:
            adapter_id: Уникальный ID адаптера (например, "cups", "win32", "file")
            adapter: Экземпляр адаптера

        Raises:
            TypeError: Если адаптер не соответствует протоколу
        """
        if not isinstance(adapter, PrinterAdapterProtocol):
            raise TypeError(f"Адаптер {adapter_id} должен соответствовать PrinterAdapterProtocol")

        self._printer_adapters[adapter_id] = adapter
        self._logger.info(f"Зарегистрирован адаптер принтера: {adapter_id}")

    def unregister_printer_adapter(self, adapter_id: str) -> bool:
        """Удаляет регистрацию адаптера.

        Args:
            adapter_id: ID адаптера

        Returns:
            True если адаптер удалён
        """
        if adapter_id in self._printer_adapters:
            del self._printer_adapters[adapter_id]
            if self._active_printer_id == adapter_id:
                self._active_printer_id = None
                self._active_printer_name = None
            self._logger.info(f"Удалён адаптер принтера: {adapter_id}")
            return True
        return False

    def set_active_printer(self, adapter_id: str, printer_name: str) -> bool:
        """Устанавливает активный принтер.

        Args:
            adapter_id: ID адаптера
            printer_name: Имя принтера

        Returns:
            True если принтер установлен

        Raises:
            PrinterNotAvailableError: Если адаптер не найден
        """
        if adapter_id not in self._printer_adapters:
            raise PrinterNotAvailableError(f"Адаптер не найден: {adapter_id}")

        self._active_printer_id = adapter_id
        self._active_printer_name = printer_name
        self._logger.info(f"Активный принтер: {adapter_id}/{printer_name}")
        return True

    def get_active_printer(self) -> Optional[Tuple[str, str]]:
        """Возвращает активный принтер.

        Returns:
            Кортеж (adapter_id, printer_name) или None
        """
        if self._active_printer_id and self._active_printer_name:
            return (self._active_printer_id, self._active_printer_name)
        return None

    # === Основные операции печати ===

    def print_document(
        self,
        doc_id: UUID,
        settings: Optional[PrintSettings] = None,
    ) -> PrintJob:
        """Печатает документ на принтер.

        Args:
            doc_id: ID документа
            settings: Настройки печати (optional, использует default)

        Returns:
            Созданное задание печати

        Raises:
            DocumentNotFoundError: Если документ не найден
            PrinterNotAvailableError: Если принтер недоступен
            RenderError: При ошибке рендеринга
        """
        # Получаем документ
        document = self._get_document(doc_id)
        if document is None:
            raise DocumentNotFoundError(f"Документ не найден: {doc_id}")

        # Проверяем принтер
        if self._active_printer_id is None:
            raise PrinterNotAvailableError("Принтер не выбран")

        adapter = self._printer_adapters.get(self._active_printer_id)
        if adapter is None:
            raise PrinterNotAvailableError(f"Адаптер не найден: {self._active_printer_id}")

        if not adapter.is_available():
            raise PrinterNotAvailableError(f"Принтер недоступен: {self._active_printer_name}")

        # Используем настройки или default
        print_settings = settings or self._default_settings

        # Конвертируем в ESC/P
        self._logger.info(f"Конвертация документа {doc_id} в ESC/P...")
        try:
            escp_data = self._document_to_escp(document, print_settings)
        except Exception as e:
            raise RenderError(f"Ошибка рендеринга документа: {e}") from e

        # Отправляем на печать через адаптер
        job_name = getattr(document.metadata, "title", None) or "Без названия"
        success = adapter.print_data(
            data=escp_data,
            job_name=job_name,
            copies=print_settings.copies,
        )

        if not success:
            raise PrinterNotAvailableError("Ошибка отправки данных на принтер")

        # Создаём задание печати
        job = PrintJob(
            id=uuid4(),
            document_id=doc_id,
            document_name=job_name,
            printer_name=self._active_printer_name or "Unknown",
            copies=print_settings.copies,
            status="completed",
        )

        self._logger.info(f"Документ отправлен на печать: {doc_id}")
        self._notify_status(f'Документ "{job_name}" отправлен на печать')

        return job

    def print_preview(self, doc_id: UUID) -> PrintPreviewData:
        """Подготавливает данные для предпросмотра печати.

        Args:
            doc_id: ID документа

        Returns:
            Данные для предпросмотра

        Raises:
            DocumentNotFoundError: Если документ не найден
            RenderError: При ошибке рендеринга
        """
        document = self._get_document(doc_id)
        if document is None:
            raise DocumentNotFoundError(f"Документ не найден: {doc_id}")

        # Рендерим в ESC/P
        try:
            escp_data = self._document_to_escp(document, self._default_settings)
        except Exception as e:
            raise RenderError(f"Ошибка рендеринга для предпросмотра: {e}") from e

        # Оцениваем количество страниц
        page_count = self._estimate_page_count(document)

        # Создаём текстовое представление
        rendered_pages = self._render_preview_text(document, page_count)

        # Собираем предупреждения
        warnings: List[str] = []
        if page_count > 1 and self._default_settings.paper_type == PaperType.ENVELOPE:
            warnings.append("Конверт обычно используется для одностраничных документов")

        preview = PrintPreviewData(
            document_id=doc_id,
            page_count=page_count,
            escp_data=escp_data,
            rendered_pages=rendered_pages,
            warnings=warnings,
        )

        self._logger.debug(f"Подготовлен preview для {doc_id}: {page_count} страниц")
        return preview

    def export_to_escp(self, doc_id: UUID, path: Path) -> Path:
        """Экспортирует документ в файл .escp.

        Args:
            doc_id: ID документа
            path: Путь для сохранения

        Returns:
            Путь к сохранённому файлу

        Raises:
            DocumentNotFoundError: Если документ не найден
            ExportError: При ошибке экспорта
        """
        document = self._get_document(doc_id)
        if document is None:
            raise DocumentNotFoundError(f"Документ не найден: {doc_id}")

        try:
            # Конвертируем в ESC/P
            escp_data = self._document_to_escp(document, self._default_settings)

            # Убедимся что путь имеет правильное расширение
            if not path.suffix:
                path = path.with_suffix(".escp")

            # Создаём директорию если нужно
            path.parent.mkdir(parents=True, exist_ok=True)

            # Записываем файл
            path.write_bytes(escp_data)

            self._logger.info(f"Документ экспортирован в ESC/P: {path}")
            return path

        except Exception as e:
            raise ExportError(f"Ошибка экспорта: {e}") from e

    def get_available_printers(self) -> List[PrinterInfo]:
        """Возвращает список доступных принтеров.

        Returns:
            Список информации о принтерах от всех адаптеров
        """
        printers: List[PrinterInfo] = []

        for adapter_id, adapter in self._printer_adapters.items():
            try:
                discovered = adapter.discover_printers()
                printers.extend(discovered)
            except Exception as e:
                self._logger.warning(f"Ошибка обнаружения принтеров ({adapter_id}): {e}")

        return printers

    # === Печать защищённых бланков ===

    def print_blank(
        self,
        blank_id: str,
        doc_id: Optional[UUID] = None,
        settings: Optional[PrintSettings] = None,
    ) -> Tuple[PrintJob, Optional[Any]]:
        """Печатает документ на защищённом бланке.

        Args:
            blank_id: ID защищённого бланка
            doc_id: ID документа (optional, использует текущий)
            settings: Настройки печати (optional)

        Returns:
            Кортеж (задание печати, QR данные верификации)

        Raises:
            BlankNotReadyError: Если бланк не готов для печати
            DocumentNotFoundError: Если документ не найден
        """
        if self._blank_manager is None:
            raise BlankNotReadyError("BlankManager не настроен")

        # Получаем бланк
        blank = self._blank_manager.get_blank(blank_id)
        if blank is None:
            raise BlankNotReadyError(f"Бланк не найден: {blank_id}")

        # Проверяем статус (blank должен быть готов)
        # Предполагаем, что blank имеет атрибут status или is_ready
        blank_status = getattr(blank, "status", None)
        if hasattr(blank_status, "value"):
            if blank_status.value != "ready":
                raise BlankNotReadyError(
                    f"Бланк не готов для печати. Текущий статус: {blank_status.value}"
                )

        # Получаем документ
        if doc_id is None:
            raise DocumentNotFoundError("ID документа не указан")

        doc = self._get_document(doc_id)
        if doc is None:
            raise DocumentNotFoundError(f"Документ не найден: {doc_id}")

        # Конвертируем в ESC/P
        print_settings = settings or self._default_settings
        escp_data = self._document_to_escp(doc, print_settings)

        # Подписываем документ на бланке
        try:
            signed_blank, signature, qr_data = self._blank_manager.sign_blank(
                blank_id=blank_id,
                document_content=escp_data,
            )

            # Отправляем на печать
            adapter = self._printer_adapters.get(self._active_printer_id or "")
            if adapter is None:
                raise PrinterNotAvailableError("Принтер не выбран")

            job_name = f"{getattr(doc.metadata, 'title', 'Без названия')} (Blank: {blank_id})"
            adapter.print_data(
                data=escp_data,
                job_name=job_name,
                copies=1,  # Бланки печатаются в одном экземпляре
            )

            # Создаём задание печати
            job = PrintJob(
                id=uuid4(),
                document_id=doc_id,
                document_name=job_name,
                printer_name=self._active_printer_name or "Unknown",
                copies=1,
                status="completed",
            )

            self._logger.info(f"Документ напечатан на бланке {blank_id}: {job.id}")
            return job, qr_data

        except Exception as e:
            raise BlankNotReadyError(f"Ошибка подготовки бланка: {e}") from e

    # === Настройки по умолчанию ===

    def set_default_settings(self, settings: PrintSettings) -> None:
        """Устанавливает настройки печати по умолчанию.

        Args:
            settings: Новые настройки по умолчанию
        """
        self._default_settings = settings
        self._logger.debug("Обновлены настройки печати по умолчанию")

    def get_default_settings(self) -> PrintSettings:
        """Возвращает настройки печати по умолчанию.

        Returns:
            Текущие настройки по умолчанию
        """
        return self._default_settings

    def validate_settings(self, settings: PrintSettings) -> Tuple[bool, List[str]]:
        """Валидирует настройки печати.

        Args:
            settings: Настройки для проверки

        Returns:
            Кортеж (is_valid, list_of_errors)
        """
        errors: List[str] = []

        # Проверка количества копий
        if settings.copies < 1:
            errors.append("Количество копий должно быть не менее 1")
        if settings.copies > 99:
            errors.append("Количество копий не может превышать 99")

        # Проверка диапазона страниц
        if settings.page_range.start is not None and settings.page_range.start < 1:
            errors.append("Начальная страница должна быть не менее 1")
        if settings.page_range.end is not None and settings.page_range.end < 1:
            errors.append("Конечная страница должна быть не менее 1")
        if (
            settings.page_range.start is not None
            and settings.page_range.end is not None
            and settings.page_range.start > settings.page_range.end
        ):
            errors.append("Начальная страница не может быть больше конечной")

        return len(errors) == 0, errors

    # === Callbacks для View ===

    def set_status_callback(self, callback: Callable[[str], None]) -> None:
        """Устанавливает callback для обновления статуса.

        Args:
            callback: Функция обратного вызова (message: str) -> None
        """
        self._status_callback = callback

    # === Вспомогательные методы ===

    def _get_document(self, doc_id: UUID) -> Optional["Document"]:
        """Получает документ по ID через DocumentService.

        Args:
            doc_id: ID документа

        Returns:
            Документ или None
        """
        if self._document_service is not None:
            return self._document_service.get_by_id(doc_id)
        return None

    def _document_to_escp(self, document: "Document", settings: PrintSettings) -> bytes:
        """Конвертирует документ в ESC/P байты.

        Args:
            document: Документ для конвертации
            settings: Настройки печати

        Returns:
            ESC/P данные

        Raises:
            RenderError: Если рендерер не настроен
        """
        if self._document_renderer is None:
            raise RenderError("DocumentRenderer не настроен")

        # Применяем настройки документа (CPI, quality и др.) к renderer
        printer_settings = getattr(document, "printer_settings", None)
        if printer_settings is not None:
            cpi_value = getattr(printer_settings, "characters_per_inch", None)
            quality_value = getattr(printer_settings, "print_quality", None)

            # Пробуем вызвать setter-методы renderer
            if hasattr(self._document_renderer, "set_cpi") and cpi_value is not None:
                try:
                    self._document_renderer.set_cpi(cpi_value.value)
                    self._logger.debug(
                        f"Применён CPI {cpi_value.value} к renderer"
                    )
                except Exception as e:
                    self._logger.warning(
                        f"Не удалось применить CPI к renderer: {e}"
                    )
            elif cpi_value is not None:
                self._logger.debug(
                    f"Renderer не поддерживает set_cpi; CPI {cpi_value.value} "
                    f"будет передан через RenderSettings при render()"
                )

            if hasattr(self._document_renderer, "set_quality") and quality_value is not None:
                try:
                    self._document_renderer.set_quality(quality_value)
                    self._logger.debug(
                        f"Применён quality {quality_value} к renderer"
                    )
                except Exception as e:
                    self._logger.warning(
                        f"Не удалось применить quality к renderer: {e}"
                    )
            elif quality_value is not None:
                self._logger.debug(
                    f"Renderer не поддерживает set_quality; quality {quality_value} "
                    f"будет передан через RenderSettings при render()"
                )

            if hasattr(self._document_renderer, "set_page_settings"):
                try:
                    self._document_renderer.set_page_settings(printer_settings)
                    self._logger.debug(
                        "Применены printer_settings к renderer через set_page_settings"
                    )
                except Exception as e:
                    self._logger.warning(
                        f"Не удалось применить page_settings к renderer: {e}"
                    )
            else:
                self._logger.debug(
                    "Renderer не поддерживает set_page_settings; "
                    "настройки будут переданы через RenderSettings при render()"
                )

        return self._document_renderer.render(document)

    def _estimate_page_count(self, document: "Document") -> int:
        """Оценивает количество страниц в документе.

        Args:
            document: Документ для оценки

        Returns:
            Оценочное количество страниц
        """
        # Получаем настройки страницы
        lines_per_page = 66  # Default
        if hasattr(document, "page_settings") and document.page_settings:
            if hasattr(document.page_settings, "lines_per_page"):
                lines_per_page = document.page_settings.lines_per_page

        # Получаем количество строк
        total_lines = 1
        if hasattr(document, "get_line_count"):
            total_lines = document.get_line_count()
        elif hasattr(document, "sections"):
            # Примерная оценка по секциям
            total_lines = len(getattr(document, "sections", [])) * 10

        if lines_per_page <= 0:
            lines_per_page = 66

        return max(1, (total_lines + lines_per_page - 1) // lines_per_page)

    def _render_preview_text(self, document: "Document", page_count: int) -> List[str]:
        """Создаёт текстовое представление для предпросмотра.

        Args:
            document: Документ для рендеринга
            page_count: Количество страниц

        Returns:
            Список текстовых представлений страниц
        """
        pages: List[str] = []

        # Получаем текст документа
        text_content = ""
        if hasattr(document, "get_text_content"):
            text_content = document.get_text_content()

        # Разбиваем на страницы примерно
        lines = text_content.split("\n")
        lines_per_page = 66
        if hasattr(document, "page_settings") and document.page_settings:
            if hasattr(document.page_settings, "lines_per_page"):
                lines_per_page = document.page_settings.lines_per_page

        if lines_per_page <= 0:
            lines_per_page = 66

        for page_num in range(page_count):
            start_line = page_num * lines_per_page
            end_line = min(start_line + lines_per_page, len(lines))
            page_lines = lines[start_line:end_line]
            pages.append("\n".join(page_lines))

        return pages

    def _notify_status(self, message: str) -> None:
        """Уведомляет View об изменении статуса.

        Args:
            message: Сообщение статуса
        """
        if self._status_callback is not None:
            try:
                self._status_callback(message)
            except Exception as e:
                self._logger.warning(f"Ошибка status callback: {e}")


# -----------------------------------------------------------------------------
# Factory Functions
# -----------------------------------------------------------------------------


def create_print_controller(
    print_service: Optional[PrintServiceProtocol] = None,
    document_service: Optional[DocumentServiceProtocol] = None,
    register_default_adapters: bool = True,
) -> PrintController:
    """Фабричная функция для создания PrintController.

    Args:
        print_service: Сервис печати (optional)
        document_service: Сервис документов (optional)
        register_default_adapters: Регистрировать ли стандартные адаптеры

    Returns:
        Настроенный PrintController
    """
    controller = PrintController(
        print_service=print_service,
        document_service=document_service,
    )

    if register_default_adapters:
        # Регистрируем файловый адаптер (всегда доступен для отладки)
        try:
            from src.printer.file_adapter import FileAdapter

            controller.register_printer_adapter(
                "file",
                FileAdapter(output_dir=Path("./output")),
            )
        except ImportError:
            logging.getLogger(__name__).debug("FileAdapter не доступен")

        # Регистрируем CUPS адаптер (Linux/macOS)
        try:
            from src.printer.cups_adapter import CupsAdapter

            controller.register_printer_adapter("cups", CupsAdapter())
        except ImportError:
            logging.getLogger(__name__).debug("CUPS адаптер не доступен")

        # Регистрируем Windows адаптер
        try:
            from src.printer.windows_adapter import WindowsAdapter

            controller.register_printer_adapter("win32", WindowsAdapter())
        except ImportError:
            logging.getLogger(__name__).debug("Windows адаптер не доступен")

    return controller


# -----------------------------------------------------------------------------
# Exports
# -----------------------------------------------------------------------------

__all__ = [
    # Main class
    "PrintController",
    "create_print_controller",
    # Settings
    "PrintSettings",
    "PageRange",
    # Enums
    "PaperType",
    "PrintQuality",
    "CharactersPerInch",
    # Data classes
    "PrintPreviewData",
    "PrinterInfo",
    "PrintJob",
    # Exceptions
    "PrintControllerError",
    "DocumentNotFoundError",
    "PrinterNotAvailableError",
    "BlankNotReadyError",
    "ExportError",
    "RenderError",
    # Protocols
    "PrintServiceProtocol",
    "PrinterAdapterProtocol",
    "DocumentRendererProtocol",
    "DocumentServiceProtocol",
    "BlankManagerProtocol",
]
