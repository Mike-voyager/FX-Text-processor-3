"""Shared fixtures for documents tests.

Предоставляет общие фикстуры для всех тестов модуля documents.
"""

from __future__ import annotations

from typing import Any, Generator
from unittest.mock import Mock

import pytest


@pytest.fixture
def sample_field_definition() -> Any:
    """Создаёт образец FieldDefinition для тестов."""
    from src.documents.types.type_schema import FieldDefinition, FieldType

    return FieldDefinition(
        field_id="test_field",
        field_type=FieldType.TEXT_INPUT,
        label="Test Field",
    )


@pytest.fixture
def sample_type_schema() -> Any:
    """Создаёт образец TypeSchema для тестов."""
    from src.documents.types.type_schema import FieldDefinition, FieldType, TypeSchema

    return TypeSchema(
        fields=(
            FieldDefinition("name", FieldType.TEXT_INPUT, "Name"),
            FieldDefinition("age", FieldType.NUMBER_INPUT, "Age"),
        )
    )


@pytest.fixture
def sample_document_type() -> Any:
    """Создаёт образец DocumentType для тестов."""
    from src.documents.types.document_type import DocumentMode, DocumentType
    from src.documents.types.type_schema import TypeSchema

    return DocumentType(
        code="TEST",
        name="Test Type",
        parent_code=None,
        document_mode=DocumentMode.FREE_FORM,
        index_template=None,
        field_schema=TypeSchema(fields=()),
    )


@pytest.fixture
def sample_index_template() -> Any:
    """Создаёт образец IndexTemplate для тестов."""
    from src.documents.types.index_template import IndexSegmentDef, IndexTemplate, SegmentType

    return IndexTemplate(
        segments=(
            IndexSegmentDef(
                name="type",
                segment_type=SegmentType.ROOT_CODE,
                label="Тип",
                label_en="Type",
                pattern=r"TEST",
            ),
            IndexSegmentDef(
                name="seq",
                segment_type=SegmentType.SEQUENCE,
                label="Номер",
                label_en="Number",
                pattern=r"[IVXLCDM]+",
            ),
        ),
        separator="-",
    )


@pytest.fixture
def mock_crypto_service() -> Any:
    """Создаёт мок CryptoService для тестов форматов."""
    crypto = Mock()
    crypto.encrypt_document.return_value = Mock(ciphertext=b"encrypted", nonce=b"nonce")
    crypto.decrypt_document.return_value = b'{"test": "data"}'
    crypto.sign_document.return_value = b"signature"
    crypto.generate_symmetric_key.return_value = b"key" * 8
    return crypto


@pytest.fixture
def mock_type_registry() -> Any:
    """Создаёт мок TypeRegistry для тестов."""
    registry = Mock()
    registry.get.return_value = Mock(
        code="TEST",
        name="Test Type",
        field_schema=Mock(fields=()),
    )
    registry.list_all.return_value = []
    return registry


@pytest.fixture
def reset_type_registry() -> Generator[None, None, None]:
    """Сбрасывает TypeRegistry singleton перед тестом."""
    from src.documents.types.registry import TypeRegistry

    TypeRegistry.reset_instance()
    yield
    TypeRegistry.reset_instance()


@pytest.fixture
def mock_document() -> Any:
    """Создаёт мок Document для тестов printing."""
    doc = Mock()
    doc.title = "Test Document"
    doc.sections = []
    doc.printer_settings = None
    doc.to_dict.return_value = {
        "metadata": {"title": "Test"},
        "sections": [],
    }
    return doc


@pytest.fixture
def mock_section() -> Any:
    """Создаёт мок Section для тестов printing."""
    section = Mock()
    section.paragraphs = []
    section.break_type = None
    return section


@pytest.fixture
def mock_paragraph() -> Any:
    """Создаёт мок Paragraph для тестов printing."""
    from src.model.enums import Alignment

    para = Mock()
    para.alignment = Alignment.LEFT
    para.runs = []
    para.tabstops = []
    return para


@pytest.fixture
def mock_run() -> Any:
    """Создаёт мок Run для тестов printing."""
    from src.model.enums import TextStyle

    run = Mock()
    run.text = "Test text"
    run.style = TextStyle(0)
    return run


@pytest.fixture
def mock_table() -> Any:
    """Создаёт мок Table для тестов printing."""
    from src.model.table import TableBorder

    table = Mock()
    table.rows = []
    table.border = TableBorder.NONE
    return table


@pytest.fixture
def mock_cell() -> Any:
    """Создаёт мок Cell для тестов printing."""
    cell = Mock()
    cell.text = "Cell text"
    return cell
