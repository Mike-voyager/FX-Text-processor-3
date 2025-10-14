"""
model.barcode

Структура для описания штрихкода или QR-кода в документе, с поддержкой расширенной семантики:
- 1D/2D коды, GS1-режимы, подписи, визуальное оформление, криптография, ссылки на родительские объекты и статус валидации.

Generated: 2025
"""

from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, Tuple, Union
from .enums import BarcodeType, Matrix2DCodeType

# --- Основные и визуальные параметры:


@dataclass
class Barcode:
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
    z_order: Optional[int] = None

    # --- Контейнерность и организация документа:
    parent_section: Optional[str] = None
    parent_table: Optional[str] = None
    anchor_id: Optional[str] = None

    # --- Служебные/бизнес-поля:
    user_label: Optional[str] = None
    object_id: Optional[str] = None
    readonly: bool = False
    hidden: bool = False

    # --- Автоматизация, генерация и интеграция:
    data_source: Optional[str] = None
    auto_regenerate_on_save: bool = False

    # --- Версионирование и аудит:
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    created_by: Optional[str] = None
    updated_by: Optional[str] = None

    # --- Валидация и статус:
    validation_state: Optional[str] = None  # 'ok', 'invalid', 'warning'
    validation_error_message: Optional[str] = None

    # --- Криптография / QR-подпись:
    is_signature: bool = False
    signature_type: Optional[str] = None  # "gost3410", "pkcs7", "OID", etc
    signature_payload: Optional[bytes] = (
        None  # закодированные данные (base64/base58/DER/...)
    )
    signer_info: Optional[str] = None  # user/email/oid...
    signing_datetime: Optional[str] = None
    certificate_thumbprint: Optional[str] = None
    validation_status: Optional[str] = None  # valid/invalid/expired/...
    validation_message: Optional[str] = None
    crypto_metadata: Dict[str, Any] = field(default_factory=dict)

    # --- Поля для расширений:
    metadata: Dict[str, Any] = field(default_factory=dict)
    custom_fields: Dict[str, Any] = field(default_factory=dict)

    # --- Методы:
    def validate(self) -> None:
        # Тут можно реализовать базовую проверку type, data и взаимосвязанных параметров
        pass

    def to_dict(self) -> Dict[str, Any]:
        """Экспорт объекта в JSON/dict."""
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Barcode":
        """Создание объекта Barcode из словаря."""
        return cls(**d)

    def __str__(self) -> str:
        display = self.data[:16] + ("..." if len(self.data) > 16 else "")
        sig = " [SIG]" if self.is_signature else ""
        return f"<Barcode type={self.type} data={display}{sig}>"
