"""Модуль сериализации и форматирования документов FX Text Processor 3.

Этот модуль предоставляет инструменты для:
- Сериализации/десериализации документов в форматы .fxsd и .fxsd.enc
- Сериализации шаблонов форм в формат .fxstpl с подписью
- Миграции между версиями форматов документов

Примеры:
    >>> from src.documents.format import DocumentSerializer, TemplateSerializer
    >>>
    >>> # Сериализация документа
    >>> serializer = DocumentSerializer()
    >>> data = serializer.serialize(doc)
    >>>
    >>> # Сохранение с шифрованием
    >>> serializer.encrypt_and_save(doc, Path("doc.fxsd.enc"), password="secret")
    >>>
    >>> # Работа с шаблонами
    >>> tpl = TemplateSerializer()
    >>> template_data = tpl.serialize_template(template, sign=True, private_key=key)

См. также:
    - document_format.py: DocumentSerializer, DocumentFile
    - template_format.py: TemplateSerializer
    - migration.py: MigrationManager

Version: 1.0.0
Date: April 5, 2026
"""

from src.documents.format.document_format import (
    DocumentFile,
    DocumentSerializer,
    FormatError,
    SecurityPreset,
)
from src.documents.format.migration import (
    MigrationError,
    MigrationManager,
    VersionInfo,
)
from src.documents.format.template_format import (
    TemplateError,
    TemplateSerializer,
)

__all__ = [
    # Document serialization
    "DocumentSerializer",
    "DocumentFile",
    "FormatError",
    # Template serialization
    "TemplateSerializer",
    "TemplateError",
    # Migration
    "MigrationManager",
    "VersionInfo",
    "MigrationError",
    # Security presets
    "SecurityPreset",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
