"""Типы настроек и результатов диалога печати.

Module: src/gui/dialogs/print_settings.py
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from uuid import UUID

from src.services.print_queue_service import PrintPriority


@dataclass(frozen=True)
class PrintSettings:
    """Настройки печати документа.

    Attrs:
        printer_id: Идентификатор принтера в формате 'adapter:name'
        adapter_id: Идентификатор адаптера (например, 'cups', 'win32', 'file')
        copies: Количество копий (по умолчанию 1)
        priority: Приоритет печати (по умолчанию NORMAL)
        page_by_page: Печать по одной странице (по умолчанию False)
        print_test_page: Печатать тестовую страницу (по умолчанию False)
        document_id: ID документа (optional)
    """

    printer_id: str
    adapter_id: str
    copies: int = 1
    priority: PrintPriority = PrintPriority.NORMAL
    page_by_page: bool = False
    print_test_page: bool = False
    document_id: Optional[UUID] = None


@dataclass(frozen=True)
class PrintDialogResult:
    """Результат работы диалога настроек печати.

    Attrs:
        settings: Выбранные настройки печати
        job_id: ID созданного задания в очереди (optional)
    """

    settings: PrintSettings
    job_id: Optional[UUID] = None
