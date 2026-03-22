"""
Модель штрихкода для ESC/P и визуализации.

Domain model для штрихкода/QR/2D кодов без внешних зависимостей.
Бизнес-логика рендеринга и валидации вынесена в BarcodeService (src/services/barcode_service.py).

Ключевые принципы:
- Модель содержит только данные (dataclass frozen=True)
- NO внешних импортов генераторов (BarcodeGenerator, Matrix2DCodeGenerator)
- NO I/O операций
- NO бизнес-логики рендеринга
- Простая валидация данных без вызова внешних сервисов

Module: src/model/barcodegen.py
"""

from __future__ import annotations

import base64
import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

from .enums import BarcodeType, Matrix2DCodeType

logger = logging.getLogger(__name__)


# Версия схемы для сериализации (ClassVar, не экземпляр)
SCHEMA_VERSION: str = "1.0"


@dataclass(frozen=True)
class Barcode:
    """
    Domain-level dataclass для штрихкода/QR/2D/ESC/P кодов.

    Модель содержит ТОЛЬКО данные. Вся бизнес-логика рендеринга
    и валидации с рендерингом находится в BarcodeService.

    Attributes:
        type: Тип штрихкода (BarcodeType или Matrix2DCodeType)
        data: Данные для кодирования
        caption: Опциональная подпись под штрихкодом
        options: Опции рендеринга (проверяются в BarcodeService)
        position: Позиция (x, y) на странице
        size: Размер (width, height)
        rotation: Угол поворота в градусах
        show_label: Показывать ли текстовую подпись
        foreground: Цвет переднего плана
        background: Цвет фона
        gs1_mode: Режим GS1 для 2D кодов
        border: Настройки рамки
        padding: Отступы (left, top, right, bottom)
        opacity: Прозрачность (0.0-1.0)
        zorder: Z-order для наложения

        # Контекст документа
        parent_section: ID родительской секции
        parent_table: ID родительской таблицы
        anchor_id: ID якоря
        user_label: Пользовательская метка
        object_id: Уникальный ID объекта
        readonly: Флаг только для чтения
        hidden: Флаг скрытия

        # Динамические данные
        datasource: Источник данных для автогенерации
        auto_regenerate_on_save: Авторегенерация при сохранении

        # Метаданные
        created_at: Время создания
        updated_at: Время обновления
        created_by: Автор
        updated_by: Последний редактор

        # Криптография и подписи
        is_signature: Является ли цифровой подписью
        signature_type: Тип подписи
        signature_payload: Payload подписи (bytes)
        signer_info: Информация о подписанте
        signing_datetime: Время подписи
        certificate_thumbprint: Отпечаток сертификата
        validation_status: Статус валидации подписи
        validation_message: Сообщение валидации
        crypto_metadata: Метаданные криптографии

        metadata: Пользовательские метаданные
        custom_fields: Кастомные поля

    Example:
        >>> from src.model.barcodegen import Barcode
        >>> from src.model.enums import BarcodeType
        >>> barcode = Barcode(type=BarcodeType.EAN13, data="978014300723")
        >>> errors = barcode.validate_data()
        >>> if errors:
        ...     print("Ошибки валидации:", errors)

    Note:
        Для рендеринга и валидации с рендерингом используйте BarcodeService:
        >>> from src.services.barcode_service import BarcodeService
        >>> ok, error = BarcodeService.validate_with_render(barcode)
    """

    # Основные данные (обязательные поля без значений по умолчанию)
    type: Union[BarcodeType, Matrix2DCodeType]
    data: str
    caption: Optional[str] = None
    options: Dict[str, Any] = field(default_factory=dict)
    position: Optional[Tuple[int, int]] = None
    size: Optional[Tuple[int, int]] = None
    rotation: Optional[float] = None
    show_label: bool = True
    foreground: Optional[str] = None
    background: Optional[str] = None
    gs1_mode: Optional[bool] = None
    border: Optional[Dict[str, Any]] = None
    padding: Optional[Tuple[int, int, int, int]] = None
    opacity: Optional[float] = None
    zorder: Optional[int] = None

    # Контекст документа
    parent_section: Optional[str] = None
    parent_table: Optional[str] = None
    anchor_id: Optional[str] = None
    user_label: Optional[str] = None
    object_id: Optional[str] = None
    readonly: bool = False
    hidden: bool = False

    # Динамические данные
    datasource: Optional[str] = None
    auto_regenerate_on_save: bool = False

    # Метаданные
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    created_by: Optional[str] = None
    updated_by: Optional[str] = None

    # Криптография и подписи
    is_signature: bool = False
    signature_type: Optional[str] = None
    signature_payload: Optional[bytes] = None
    signer_info: Optional[str] = None
    signing_datetime: Optional[str] = None
    certificate_thumbprint: Optional[str] = None
    validation_status: Optional[str] = None
    validation_message: Optional[str] = None
    crypto_metadata: Dict[str, Any] = field(default_factory=dict)

    metadata: Dict[str, Any] = field(default_factory=dict)
    custom_fields: Dict[str, Any] = field(default_factory=dict)

    def validate_data(self) -> List[str]:
        """Валидирует поля данных без вызова внешних рендереров.

        Проверяет корректность типов и значений полей.
        Для валидации с рендерингом используйте BarcodeService.validate_with_render().

        Returns:
            Список сообщений об ошибках. Пустой список если валидация успешна.

        Example:
            >>> barcode = Barcode(type=BarcodeType.EAN13, data="")
            >>> errors = barcode.validate_data()
            >>> # ["Data must be a non-empty string"]
        """
        errors: List[str] = []

        # Проверка типа
        if not isinstance(self.type, (BarcodeType, Matrix2DCodeType)):
            errors.append(f"Invalid type: {self.type}, must be BarcodeType or Matrix2DCodeType")

        # Проверка данных
        if not isinstance(self.data, str) or not self.data.strip():
            errors.append("Data must be a non-empty string")

        # Проверка позиции
        if self.position is not None:
            if not isinstance(self.position, tuple) or len(self.position) != 2:
                errors.append(f"Invalid position: {self.position}, must be tuple of 2 ints")
            elif not all(isinstance(x, int) and x >= 0 for x in self.position):
                errors.append(f"Invalid position values: {self.position}, must be non-negative ints")

        # Проверка размера
        if self.size is not None:
            if not isinstance(self.size, tuple) or len(self.size) != 2:
                errors.append(f"Invalid size: {self.size}, must be tuple of 2 ints")
            elif not all(isinstance(x, int) and x > 0 for x in self.size):
                errors.append(f"Invalid size values: {self.size}, must be positive ints")

        # Проверка padding
        if self.padding is not None:
            if not isinstance(self.padding, tuple) or len(self.padding) != 4:
                errors.append(f"Invalid padding: {self.padding}, must be tuple of 4 ints")
            elif not all(isinstance(x, int) and x >= 0 for x in self.padding):
                errors.append(f"Invalid padding values: {self.padding}, must be non-negative ints")

        # Проверка opacity
        if self.opacity is not None:
            if not isinstance(self.opacity, (int, float)):
                errors.append(f"Invalid opacity type: {self.opacity}, must be number")
            elif not (0.0 <= float(self.opacity) <= 1.0):
                errors.append(f"Invalid opacity value: {self.opacity}, must be in range [0.0, 1.0]")

        # Проверка цветов
        if self.foreground is not None and not isinstance(self.foreground, str):
            errors.append(f"Invalid foreground color: {self.foreground}, must be string")
        if self.background is not None and not isinstance(self.background, str):
            errors.append(f"Invalid background color: {self.background}, must be string")

        # Проверка rotation
        if self.rotation is not None:
            if not isinstance(self.rotation, (int, float)):
                errors.append(f"Invalid rotation type: {self.rotation}, must be number")

        return errors

    def to_dict(self) -> Dict[str, Any]:
        dct: Dict[str, Any] = asdict(self)
        dct["schema_version"] = SCHEMA_VERSION
        if self.signature_payload is not None:
            dct["signature_payload"] = base64.b64encode(self.signature_payload).decode(
                "ascii"
            )
        return dct

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Barcode":
        d = dict(d)
        if "schema_version" in d and d["schema_version"] != SCHEMA_VERSION:
            logger.warning(
                "Schema version mismatch (expected %s, got %s)",
                SCHEMA_VERSION,
                d["schema_version"],
            )
        if "signature_payload" in d and d["signature_payload"]:
            d["signature_payload"] = base64.b64decode(d["signature_payload"])
        d.pop("schema_version", None)
        return cls(**d)

    def __str__(self) -> str:
        siginfo: str = "SIG" if self.is_signature else ""
        datashow: str = self.data[:16] + ("..." if len(self.data) > 16 else "")
        return f"Barcode({self.type}, data={datashow}{siginfo})"
