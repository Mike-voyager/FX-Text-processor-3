"""Контроллеры GUI для FX Text Processor 3.

Слой контроллеров отвечает за маршрутизацию между View и Service Layer.
Содержит специализированные контроллеры для различных компонентов GUI.

Слои:
    - BaseController: Базовый класс для всех контроллеров
    - DocumentController: Управление документами
    - WorkflowController: Управление workflow документами
    - TemplateController: Управление шаблонами (.fxstpl)
    - BarcodeController: Управление штрих-кодами и QR-кодами

Architecture:
    View → Controller.dispatch() → Service Layer → Model
    Service Layer → Controller.notify_view_update() → View

DI Pattern:
    Контроллеры принимают сервисы через конструктор (Dependency Injection).
    Никакой сложной бизнес-логики — только маршрутизация.

Example:
    >>> from src.gui.controllers.barcode_controller import BarcodeController
    >>> controller = BarcodeController(parent_view, view=doc_view, on_insert=on_insert)
    >>> controller.show_barcode_dialog()
"""

from __future__ import annotations

from src.gui.controllers.barcode_controller import BarcodeController
from src.gui.controllers.base_controller import BaseController
from src.gui.controllers.document_controller import DocumentController
from src.gui.controllers.template_controller import TemplateController
from src.gui.controllers.workflow_controller import WorkflowController

__all__ = [
    "BarcodeController",
    "BaseController",
    "DocumentController",
    "TemplateController",
    "WorkflowController",
]
