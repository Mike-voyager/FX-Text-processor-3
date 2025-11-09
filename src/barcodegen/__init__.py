"""
barcodegen

Модуль для генерации 1D и 2D штрихкодов с современным, типизированным API.

- Поддерживает все распространённые 1D-штрихкоды (EAN, UPC, Code39, …) и 2D форматы (QR, DataMatrix, PDF417).
- Полная поддержка настроек, GS1-режима, дополнительных подписей, вставки логотипа и пакетной генерации.
- Гарантированное покрытие тестами.

Public API:
    - BarcodeGenerator: универсальный генератор 1D штрихкодов (class)
    - BarcodeGenError: исключение для ошибок генерации 1D штрихкодов
    - BarcodeRenderOptions: типобезопасные опции рендеринга (TypedDict)
    - BarcodeOptions: типобезопасные опции создания (TypedDict)
    - Matrix2DCodeGenerator: генератор QR, DataMatrix, PDF417 (class)
    - Matrix2DCodeGenError: исключение для ошибок генерации 2D штрихкодов

Примеры:
    >>> from src.barcodegen import BarcodeGenerator, Matrix2DCodeGenerator
    >>> img = BarcodeGenerator(BarcodeType.EAN13, "4012345678901").render_image()
    >>> img2d = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "test123").render_image(caption="Hello")

Зависимости:
    Pillow, qrcode, pdf417gen, treepoem, python-barcode
"""

from src.barcodegen.barcode_generator import (
    BarcodeGenerator,
    BarcodeGenError,
    BarcodeOptions,
    BarcodeRenderOptions,
)
from src.barcodegen.matrix2d_generator import (
    Matrix2DCodeGenerator,
    Matrix2DCodeGenError,
)

__all__ = [
    "BarcodeGenerator",
    "BarcodeGenError",
    "BarcodeRenderOptions",
    "BarcodeOptions",
    "Matrix2DCodeGenerator",
    "Matrix2DCodeGenError",
]
