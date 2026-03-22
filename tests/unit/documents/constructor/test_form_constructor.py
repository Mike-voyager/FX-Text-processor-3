"""Тесты для модуля form_constructor.

Покрытие:
- FormConstructor инициализация
- create_from_type() создание документов
- create_from_template() загрузка из шаблонов
- _get_empty_value() пустые значения
- validate_data() валидация
- get_form_schema() получение схемы
- list_available_types() список типов
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from src.documents.constructor.form_constructor import FormConstructor
from src.documents.types.document_type import DocumentMode, DocumentType
from src.documents.types.type_schema import FieldDefinition, FieldType, TypeSchema


class TestFormConstructorInit:
    """Тесты инициализации FormConstructor."""

    def test_create_default_registry(self) -> None:
        """Создание с дефолтным реестром."""
        constructor = FormConstructor()
        assert constructor is not None
        assert constructor._registry is not None

    def test_create_with_custom_registry(self) -> None:
        """Создание с кастомным реестром."""
        mock_registry = MagicMock()
        constructor = FormConstructor(registry=mock_registry)
        assert constructor._registry is mock_registry


class TestCreateFromType:
    """Тесты метода create_from_type."""

    @pytest.fixture
    def mock_registry(self) -> MagicMock:
        """Мок реестра."""
        registry = MagicMock()
        doc_type = DocumentType(
            code="TEST",
            name="Тест",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(
                fields=(
                    FieldDefinition("name", FieldType.TEXT_INPUT, "Имя"),
                    FieldDefinition("age", FieldType.NUMBER_INPUT, "Возраст"),
                )
            ),
        )
        registry.get.return_value = doc_type
        return registry

    @pytest.fixture
    def constructor(self, mock_registry: MagicMock) -> FormConstructor:
        """Конструктор с мок реестром."""
        return FormConstructor(registry=mock_registry)

    def test_create_returns_dict(
        self, constructor: FormConstructor, mock_registry: MagicMock
    ) -> None:
        """Возвращает словарь."""
        result = constructor.create_from_type("TEST")
        assert isinstance(result, dict)

    def test_create_has_metadata(self, constructor: FormConstructor) -> None:
        """Результат содержит metadata."""
        result = constructor.create_from_type("TEST")
        assert "metadata" in result
        assert "title" in result["metadata"]
        assert "created" in result["metadata"]

    def test_create_has_fields(self, constructor: FormConstructor) -> None:
        """Результат содержит fields."""
        result = constructor.create_from_type("TEST")
        assert "fields" in result

    def test_create_empty_values(self, constructor: FormConstructor) -> None:
        """Поля инициализируются пустыми значениями."""
        result = constructor.create_from_type("TEST")
        assert result["fields"]["name"] == ""
        assert result["fields"]["age"] == 0

    def test_create_with_initial_values(self, constructor: FormConstructor) -> None:
        """Передача начальных значений."""
        result = constructor.create_from_type("TEST", name="Alice", age=30)
        assert result["fields"]["name"] == "Alice"
        assert result["fields"]["age"] == 30

    def test_create_with_title(self, constructor: FormConstructor) -> None:
        """Передача title."""
        result = constructor.create_from_type("TEST", title="My Doc")
        assert result["metadata"]["title"] == "My Doc"

    def test_create_with_author(self, constructor: FormConstructor) -> None:
        """Передача author."""
        result = constructor.create_from_type("TEST", author="admin")
        assert result["metadata"]["author"] == "admin"

    def test_calls_registry_get(
        self, constructor: FormConstructor, mock_registry: MagicMock
    ) -> None:
        """Вызывает registry.get."""
        constructor.create_from_type("TEST")
        mock_registry.get.assert_called_once_with("TEST")


class TestGetEmptyValue:
    """Тесты метода _get_empty_value."""

    @pytest.fixture
    def constructor(self) -> FormConstructor:
        """Конструктор."""
        return FormConstructor()

    def test_text_input_empty_string(self, constructor: FormConstructor) -> None:
        """TEXT_INPUT -> пустая строка."""
        assert constructor._get_empty_value(FieldType.TEXT_INPUT) == ""

    def test_number_input_zero(self, constructor: FormConstructor) -> None:
        """NUMBER_INPUT -> 0."""
        assert constructor._get_empty_value(FieldType.NUMBER_INPUT) == 0

    def test_date_input_none(self, constructor: FormConstructor) -> None:
        """DATE_INPUT -> None."""
        assert constructor._get_empty_value(FieldType.DATE_INPUT) is None

    def test_table_empty_list(self, constructor: FormConstructor) -> None:
        """TABLE -> пустой список."""
        assert constructor._get_empty_value(FieldType.TABLE) == []

    def test_checkbox_false(self, constructor: FormConstructor) -> None:
        """CHECKBOX -> False."""
        assert constructor._get_empty_value(FieldType.CHECKBOX) is False

    def test_currency_zero_float(self, constructor: FormConstructor) -> None:
        """CURRENCY -> 0.0."""
        assert constructor._get_empty_value(FieldType.CURRENCY) == 0.0

    def test_signature_none(self, constructor: FormConstructor) -> None:
        """SIGNATURE -> None."""
        assert constructor._get_empty_value(FieldType.SIGNATURE) is None


class TestCreateFromTemplate:
    """Тесты метода create_from_template."""

    @pytest.fixture
    def temp_template(self, tmp_path: Path) -> Path:
        """Временный файл шаблона."""
        template_file = tmp_path / "test.fxstpl"
        template_data = {
            "_type": "TEST",
            "fields": {
                "name": "From Template",
            },
        }
        template_file.write_text(json.dumps(template_data))
        return template_file

    def test_load_template(self, temp_template: Path) -> None:
        """Загрузка шаблона."""
        constructor = FormConstructor()
        with patch.object(constructor, "create_from_type") as mock_create:
            mock_create.return_value = {}
            constructor.create_from_template(temp_template)
            mock_create.assert_called_once()
            call_args = mock_create.call_args
            assert call_args[1]["name"] == "From Template"

    def test_missing_type_field(self, tmp_path: Path) -> None:
        """Ошибка при отсутствии _type."""
        template_file = tmp_path / "bad.fxstpl"
        template_file.write_text('{"fields": {}}')

        constructor = FormConstructor()
        with pytest.raises(ValueError, match="_type"):
            constructor.create_from_template(template_file)


class TestValidateData:
    """Тесты метода validate_data."""

    @pytest.fixture
    def mock_registry(self) -> MagicMock:
        """Мок реестра."""
        registry = MagicMock()
        doc_type = DocumentType(
            code="TEST",
            name="Тест",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(
                fields=(
                    FieldDefinition("name", FieldType.TEXT_INPUT, "Имя", required=True),
                    FieldDefinition("age", FieldType.NUMBER_INPUT, "Возраст", required=False),
                )
            ),
        )
        registry.get.return_value = doc_type
        return registry

    @pytest.fixture
    def constructor(self, mock_registry: MagicMock) -> FormConstructor:
        """Конструктор с мок реестром."""
        return FormConstructor(registry=mock_registry)

    def test_valid_data(self, constructor: FormConstructor) -> None:
        """Валидные данные."""
        data = {"fields": {"name": "Alice", "age": 30}}
        errors = constructor.validate_data("TEST", data)
        assert errors == {}

    def test_missing_required(self, constructor: FormConstructor) -> None:
        """Отсутствует обязательное поле."""
        data = {"fields": {"name": "", "age": 30}}
        errors = constructor.validate_data("TEST", data)
        assert "name" in errors

    def test_empty_fields(self, constructor: FormConstructor) -> None:
        """Пустые поля."""
        data: dict[str, Any] = {"fields": {}}
        errors = constructor.validate_data("TEST", data)
        assert "name" in errors


class TestGetFormSchema:
    """Тесты метода get_form_schema."""

    @pytest.fixture
    def mock_registry(self) -> MagicMock:
        """Мок реестра."""
        registry = MagicMock()
        doc_type = DocumentType(
            code="TEST",
            name="Тест",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        registry.get.return_value = doc_type
        return registry

    def test_returns_type_schema(self, mock_registry: MagicMock) -> None:
        """Возвращает TypeSchema."""
        constructor = FormConstructor(registry=mock_registry)
        schema = constructor.get_form_schema("TEST")
        assert isinstance(schema, TypeSchema)


class TestListAvailableTypes:
    """Тесты метода list_available_types."""

    def test_returns_list_of_tuples(self) -> None:
        """Возвращает список кортежей."""
        registry = MagicMock()
        registry.list_all.return_value = [
            DocumentType("A", "Type A", None, DocumentMode.FREE_FORM, None, TypeSchema(fields=())),
            DocumentType("B", "Type B", None, DocumentMode.FREE_FORM, None, TypeSchema(fields=())),
        ]
        constructor = FormConstructor(registry=registry)
        result = constructor.list_available_types()
        assert result == [("A", "Type A"), ("B", "Type B")]


class TestDocumentDataStructure:
    """Тесты структуры данных документа."""

    @pytest.fixture
    def mock_registry(self) -> MagicMock:
        """Мок реестра."""
        registry = MagicMock()
        doc_type = DocumentType(
            code="TEST",
            name="Тест",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        registry.get.return_value = doc_type
        return registry

    def test_document_has_type_code(self, mock_registry: MagicMock) -> None:
        """Документ содержит код типа."""
        constructor = FormConstructor(registry=mock_registry)
        result = constructor.create_from_type("TEST")
        assert result["_type"] == "TEST"
        assert result["_code"] == "TEST"

    def test_document_has_name(self, mock_registry: MagicMock) -> None:
        """Документ содержит название."""
        constructor = FormConstructor(registry=mock_registry)
        result = constructor.create_from_type("TEST")
        assert result["_name"] == "Тест"

    def test_document_version(self, mock_registry: MagicMock) -> None:
        """Документ содержит версию."""
        constructor = FormConstructor(registry=mock_registry)
        result = constructor.create_from_type("TEST")
        assert result["metadata"]["version"] == "1.0"
