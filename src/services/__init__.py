"""Сервисный слой приложения.

Содержит бизнес-логику, отделённую от Model (dataclasses).
Model — только данные, Service — операции над данными.
"""

from src.services.barcode_service import BarcodeService

__all__ = [
    "BarcodeService",
]