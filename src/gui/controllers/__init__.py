"""Контроллеры GUI для FX Text Processor 3.

Слой контроллеров отвечает за маршрутизацию между View и Service Layer.

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

from src.gui.controllers.barcode_controller import (
    BarcodeController,
    BarcodeViewProtocol,
)

__all__ = [
    "BarcodeController",
    "BarcodeViewProtocol",
]
