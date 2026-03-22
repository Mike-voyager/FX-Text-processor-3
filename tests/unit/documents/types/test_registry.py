"""Тесты для модуля registry.

Покрытие:
- TypeRegistry singleton
- Double-checked locking
- register_type / register_subtype
- get / get_or_none
- list_children / list_subtypes
- list_all / list_roots
- unregister
- Dunder methods (__contains__, __iter__, __len__)
"""

from __future__ import annotations

from typing import Any, Generator
from unittest.mock import patch

import pytest
from src.documents.types.document_type import DocumentMode, DocumentSubtype, DocumentType
from src.documents.types.registry import TypeRegistry
from src.documents.types.type_schema import TypeSchema


@pytest.fixture(autouse=True)
def reset_registry() -> Generator[None, None, None]:
    """Сброс registry перед каждым тестом."""
    TypeRegistry.reset_instance()
    yield
    TypeRegistry.reset_instance()


# ============ Singleton Tests ============


class TestTypeRegistrySingleton:
    """Тесты singleton паттерна TypeRegistry."""

    def test_get_instance_returns_same(self) -> None:
        """get_instance возвращает один и тот же экземпляр."""
        reg1 = TypeRegistry.get_instance()
        reg2 = TypeRegistry.get_instance()
        assert reg1 is reg2

    def test_constructor_returns_same(self) -> None:
        """Constructor возвращает тот же экземпляр."""
        reg1 = TypeRegistry()
        reg2 = TypeRegistry()
        assert reg1 is reg2

    def test_reset_creates_new(self) -> None:
        """reset_instance создаёт новый экземпляр."""
        reg1 = TypeRegistry.get_instance()
        TypeRegistry.reset_instance()
        reg2 = TypeRegistry.get_instance()
        assert reg1 is not reg2

    def test_get_instance_initializes_builtin(self) -> None:
        """get_instance загружает built-in типы."""
        registry = TypeRegistry.get_instance()
        assert "DOC" in registry
        assert "INV" in registry
        assert "DVN" in registry


# ============ register_type Tests ============


class TestRegisterType:
    """Тесты для register_type."""

    def test_register_new_type(self, reset_registry: Any) -> None:
        """Регистрация нового типа."""
        registry = TypeRegistry.get_instance()
        doc_type = DocumentType(
            code="CUSTOM",
            name="Custom Type",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        result = registry.register_type(doc_type)
        assert result is doc_type
        assert "CUSTOM" in registry

    def test_register_duplicate_raises(self, reset_registry: Any) -> None:
        """Дублирующийся код вызывает ValueError."""
        registry = TypeRegistry.get_instance()
        doc_type = DocumentType(
            code="DUP",
            name="Duplicate",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        registry.register_type(doc_type)
        with pytest.raises(ValueError, match="already registered"):
            registry.register_type(doc_type)

    def test_register_with_subtypes(self, reset_registry: Any) -> None:
        """Регистрация типа с подтипами."""
        registry = TypeRegistry.get_instance()
        doc_type = DocumentType(
            code="WITH_SUB",
            name="With Subtypes",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
            subtypes=(
                DocumentSubtype(code="01", name="Subtype 1"),
                DocumentSubtype(code="02", name="Subtype 2"),
            ),
        )
        registry.register_type(doc_type)
        subtypes = registry.list_subtypes("WITH_SUB")
        assert len(subtypes) == 2


# ============ register_subtype Tests ============


class TestRegisterSubtype:
    """Тесты для register_subtype."""

    def test_register_subtype_success(self, reset_registry: Any) -> None:
        """Успешная регистрация подтипа."""
        registry = TypeRegistry.get_instance()
        doc_type = DocumentType(
            code="PARENT",
            name="Parent",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        registry.register_type(doc_type)

        subtype = DocumentSubtype(code="SUB", name="Subtype")
        result = registry.register_subtype("PARENT", subtype)

        assert result is subtype
        subtypes = registry.list_subtypes("PARENT")
        assert len(subtypes) == 1
        assert subtypes[0].code == "SUB"

    def test_register_subtype_parent_not_found(self, reset_registry: Any) -> None:
        """Родитель не найден — KeyError."""
        registry = TypeRegistry.get_instance()
        subtype = DocumentSubtype(code="SUB", name="Subtype")
        with pytest.raises(KeyError, match="not found"):
            registry.register_subtype("MISSING", subtype)

    def test_register_subtype_updates_type(self, reset_registry: Any) -> None:
        """Обновление типа с новым подтипом."""
        registry = TypeRegistry.get_instance()
        doc_type = DocumentType(
            code="PARENT",
            name="Parent",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        registry.register_type(doc_type)

        subtype = DocumentSubtype(code="NEW", name="New Subtype")
        registry.register_subtype("PARENT", subtype)

        updated_type = registry.get("PARENT")
        assert len(updated_type.subtypes) == 1


# ============ get Tests ============


class TestGet:
    """Тесты для get."""

    def test_get_existing(self, reset_registry: Any) -> None:
        """Получение существующего типа."""
        registry = TypeRegistry.get_instance()
        doc_type = DocumentType(
            code="EXISTING",
            name="Existing",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        registry.register_type(doc_type)

        result = registry.get("EXISTING")
        assert result.code == "EXISTING"
        assert result.name == "Existing"

    def test_get_not_found_raises(self, reset_registry: Any) -> None:
        """Несуществующий тип — KeyError."""
        registry = TypeRegistry.get_instance()
        with pytest.raises(KeyError, match="not found"):
            registry.get("MISSING")


class TestGetOrNone:
    """Тесты для get_or_none."""

    def test_get_or_none_existing(self, reset_registry: Any) -> None:
        """Получение существующего типа."""
        registry = TypeRegistry.get_instance()
        doc_type = DocumentType(
            code="EXISTING",
            name="Existing",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        registry.register_type(doc_type)

        result = registry.get_or_none("EXISTING")
        assert result is not None
        assert result.code == "EXISTING"

    def test_get_or_none_not_found(self, reset_registry: Any) -> None:
        """Несуществующий тип — None."""
        registry = TypeRegistry.get_instance()
        result = registry.get_or_none("MISSING")
        assert result is None


# ============ list_children Tests ============


class TestListChildren:
    """Тесты для list_children."""

    def test_list_children_found(self, reset_registry: Any) -> None:
        """Найдены дочерние типы."""
        registry = TypeRegistry.get_instance()
        parent = DocumentType(
            code="PARENT",
            name="Parent",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        child1 = DocumentType(
            code="CHILD1",
            name="Child 1",
            parent_code="PARENT",
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        child2 = DocumentType(
            code="CHILD2",
            name="Child 2",
            parent_code="PARENT",
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        other = DocumentType(
            code="OTHER",
            name="Other",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        registry.register_type(parent)
        registry.register_type(child1)
        registry.register_type(child2)
        registry.register_type(other)

        children = registry.list_children("PARENT")
        codes = {c.code for c in children}
        assert codes == {"CHILD1", "CHILD2"}

    def test_list_children_empty(self, reset_registry: Any) -> None:
        """Нет дочерних типов."""
        registry = TypeRegistry.get_instance()
        doc_type = DocumentType(
            code="NO_CHILDREN",
            name="No Children",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        registry.register_type(doc_type)

        children = registry.list_children("NO_CHILDREN")
        assert children == []


# ============ list_subtypes Tests ============


class TestListSubtypes:
    """Тесты для list_subtypes."""

    def test_list_subtypes_from_type(self, reset_registry: Any) -> None:
        """Подтипы из DocumentType."""
        registry = TypeRegistry.get_instance()
        doc_type = DocumentType(
            code="WITH_SUB",
            name="With Sub",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
            subtypes=(
                DocumentSubtype(code="01", name="First"),
                DocumentSubtype(code="02", name="Second"),
            ),
        )
        registry.register_type(doc_type)

        subtypes = registry.list_subtypes("WITH_SUB")
        codes = {s.code for s in subtypes}
        assert codes == {"01", "02"}

    def test_list_subtypes_empty(self, reset_registry: Any) -> None:
        """Нет подтипов."""
        registry = TypeRegistry.get_instance()
        doc_type = DocumentType(
            code="NO_SUB",
            name="No Sub",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        registry.register_type(doc_type)

        subtypes = registry.list_subtypes("NO_SUB")
        assert subtypes == []

    def test_list_subtypes_not_found(self, reset_registry: Any) -> None:
        """Тип не найден."""
        registry = TypeRegistry.get_instance()
        subtypes = registry.list_subtypes("MISSING")
        assert subtypes == []


# ============ list_all Tests ============


class TestListAll:
    """Тесты для list_all."""

    def test_list_all_returns_all(self, reset_registry: Any) -> None:
        """Возвращает все типы."""
        registry = TypeRegistry.get_instance()
        doc1 = DocumentType(
            code="ONE",
            name="One",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        doc2 = DocumentType(
            code="TWO",
            name="Two",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        registry.register_type(doc1)
        registry.register_type(doc2)

        all_types = registry.list_all()
        codes = {t.code for t in all_types}
        assert codes >= {"ONE", "TWO"}


# ============ list_roots Tests ============


class TestListRoots:
    """Тесты для list_roots."""

    def test_list_roots_only_roots(self, reset_registry: Any) -> None:
        """Только корневые типы."""
        registry = TypeRegistry.get_instance()
        root1 = DocumentType(
            code="ROOT1",
            name="Root 1",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        root2 = DocumentType(
            code="ROOT2",
            name="Root 2",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        registry.register_type(root1)
        registry.register_type(root2)

        roots = registry.list_roots()
        codes = {r.code for r in roots}
        assert codes >= {"ROOT1", "ROOT2"}

    def test_list_roots_excludes_children(self, reset_registry: Any) -> None:
        """Исключает дочерние типы."""
        registry = TypeRegistry.get_instance()
        root = DocumentType(
            code="ROOT",
            name="Root",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        child = DocumentType(
            code="CHILD",
            name="Child",
            parent_code="ROOT",
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        registry.register_type(root)
        registry.register_type(child)

        roots = registry.list_roots()
        codes = {r.code for r in roots}
        assert "ROOT" in codes
        assert "CHILD" not in codes


# ============ unregister Tests ============


class TestUnregister:
    """Тесты для unregister."""

    def test_unregister_success(self, reset_registry: Any) -> None:
        """Успешное удаление."""
        registry = TypeRegistry.get_instance()
        doc_type = DocumentType(
            code="REMOVE",
            name="Remove",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        registry.register_type(doc_type)
        assert "REMOVE" in registry

        result = registry.unregister("REMOVE")
        assert result is True
        assert "REMOVE" not in registry

    def test_unregister_not_found(self, reset_registry: Any) -> None:
        """Тип не найден."""
        registry = TypeRegistry.get_instance()
        result = registry.unregister("MISSING")
        assert result is False

    def test_unregister_protected_builtin(self, reset_registry: Any) -> None:
        """Защита built-in типов."""
        registry = TypeRegistry.get_instance()
        # Built-in типы защищены
        assert registry.unregister("DOC") is False
        assert registry.unregister("INV") is False
        assert registry.unregister("DVN") is False


# ============ Dunder Methods Tests ============


class TestDunderContains:
    """Тесты для __contains__."""

    def test_contains_true(self, reset_registry: Any) -> None:
        """Тип существует."""
        registry = TypeRegistry.get_instance()
        doc_type = DocumentType(
            code="TEST",
            name="Test",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        registry.register_type(doc_type)
        assert "TEST" in registry

    def test_contains_false(self, reset_registry: Any) -> None:
        """Тип не существует."""
        registry = TypeRegistry.get_instance()
        assert "MISSING" not in registry


class TestDunderIter:
    """Тесты для __iter__."""

    def test_iter_returns_types(self, reset_registry: Any) -> None:
        """Итерация возвращает типы."""
        registry = TypeRegistry.get_instance()
        doc_type = DocumentType(
            code="ITER",
            name="Iter",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        registry.register_type(doc_type)

        codes = {t.code for t in registry}
        assert "ITER" in codes


class TestDunderLen:
    """Тесты для __len__."""

    def test_len_counts_types(self, reset_registry: Any) -> None:
        """Подсчёт типов."""
        registry = TypeRegistry.get_instance()
        initial_len = len(registry)

        doc_type = DocumentType(
            code="NEW_LEN",
            name="New Len",
            parent_code=None,
            document_mode=DocumentMode.FREE_FORM,
            index_template=None,
            field_schema=TypeSchema(fields=()),
        )
        registry.register_type(doc_type)

        assert len(registry) == initial_len + 1


# ============ Thread Safety Tests ============


class TestThreadSafety:
    """Тесты thread-safety (базовые)."""

    def test_lock_used_in_register(self, reset_registry: Any) -> None:
        """Lock используется в register_type."""
        registry = TypeRegistry.get_instance()

        with patch.object(registry, "_lock") as mock_lock:
            doc_type = DocumentType(
                code="LOCK_TEST",
                name="Lock Test",
                parent_code=None,
                document_mode=DocumentMode.FREE_FORM,
                index_template=None,
                field_schema=TypeSchema(fields=()),
            )
            try:
                registry.register_type(doc_type)
            except Exception:  # noqa: S110
                pass  # We just want to check the lock was used
            # Lock должен быть использован
            assert mock_lock.__enter__.called


# ============ Initialization Tests ============


class TestInitialization:
    """Тесты инициализации."""

    def test_builtin_types_loaded(self) -> None:
        """Built-in типы загружены при инициализации."""
        TypeRegistry.reset_instance()
        registry = TypeRegistry.get_instance()

        # Проверяем что built-in типы есть
        assert "DOC" in registry
        assert "INV" in registry
        assert "DVN" in registry

        # Проверяем их свойства
        doc = registry.get("DOC")
        assert doc.name == "Базовый документ"
        assert doc.document_mode == DocumentMode.FREE_FORM

        dvn = registry.get("DVN")
        assert dvn.name == "Вербальная нота"
        assert dvn.document_mode == DocumentMode.STRUCTURED_FORM

    def test_initialized_flag_set(self) -> None:
        """Флаг _initialized установлен."""
        TypeRegistry.reset_instance()
        registry = TypeRegistry.get_instance()
        assert registry._initialized is True
