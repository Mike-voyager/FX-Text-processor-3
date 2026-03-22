"""Тесты для модуля style_manager.

Покрытие:
- StyleProperties dataclass
- StyleInheritance уровни
- StyleManager CRUD стилей
- Наследование стилей
"""

from __future__ import annotations

import pytest
from src.documents.constructor.style_manager import (
    StyleInheritance,
    StyleManager,
    StyleProperties,
)


class TestStyleProperties:
    """Тесты для StyleProperties."""

    def test_create_default(self) -> None:
        """Создание со значениями по умолчанию."""
        style = StyleProperties()
        assert style.bold is False
        assert style.italic is False
        assert style.underline is False
        assert style.custom == {}

    def test_create_with_values(self) -> None:
        """Создание с заданными значениями."""
        style = StyleProperties(
            bold=True,
            italic=True,
            font_family="Courier",
        )
        assert style.bold is True
        assert style.italic is True
        assert style.font_family == "Courier"

    def test_to_esc_commands_returns_bytes(self) -> None:
        """to_esc_commands возвращает bytes."""
        style = StyleProperties()
        result = style.to_esc_commands()
        assert isinstance(result, bytes)

    def test_to_esc_off_commands_returns_bytes(self) -> None:
        """to_esc_off_commands возвращает bytes."""
        style = StyleProperties()
        result = style.to_esc_off_commands()
        assert isinstance(result, bytes)


class TestStyleInheritance:
    """Тесты для StyleInheritance."""

    def test_document_level(self) -> None:
        """Уровень DOCUMENT."""
        assert StyleInheritance.DOCUMENT == "document"

    def test_section_level(self) -> None:
        """Уровень SECTION."""
        assert StyleInheritance.SECTION == "section"

    def test_paragraph_level(self) -> None:
        """Уровень PARAGRAPH."""
        assert StyleInheritance.PARAGRAPH == "paragraph"

    def test_run_level(self) -> None:
        """Уровень RUN."""
        assert StyleInheritance.RUN == "run"


class TestStyleManagerInit:
    """Тесты инициализации StyleManager."""

    def test_create_manager(self) -> None:
        """Создание менеджера."""
        manager = StyleManager()
        assert manager is not None

    def test_default_inheritance_chain(self) -> None:
        """Цепочка наследования по умолчанию."""
        manager = StyleManager()
        chain = [
            StyleInheritance.DOCUMENT,
            StyleInheritance.SECTION,
            StyleInheritance.PARAGRAPH,
            StyleInheritance.RUN,
        ]
        assert manager._inheritance_chain == chain


class TestSetStyle:
    """Тесты метода set_style."""

    @pytest.fixture
    def manager(self) -> StyleManager:
        """Фикстура для менеджера."""
        return StyleManager()

    def test_set_document_style(self, manager: StyleManager) -> None:
        """Установка стиля документа."""
        style = StyleProperties(bold=True)
        manager.set_style(StyleInheritance.DOCUMENT, style)
        assert StyleInheritance.DOCUMENT in manager._styles

    def test_set_paragraph_style(self, manager: StyleManager) -> None:
        """Установка стиля параграфа."""
        style = StyleProperties(italic=True)
        manager.set_style(StyleInheritance.PARAGRAPH, style)
        assert manager._styles[StyleInheritance.PARAGRAPH].italic is True

    def test_overwrite_existing(self, manager: StyleManager) -> None:
        """Перезапись существующего стиля."""
        manager.set_style(StyleInheritance.DOCUMENT, StyleProperties(bold=True))
        manager.set_style(StyleInheritance.DOCUMENT, StyleProperties(italic=True))
        assert manager._styles[StyleInheritance.DOCUMENT].italic is True
        assert manager._styles[StyleInheritance.DOCUMENT].bold is False


class TestGetStyle:
    """Тесты метода get_style."""

    @pytest.fixture
    def manager(self) -> StyleManager:
        """Фикстура для менеджера."""
        return StyleManager()

    def test_get_existing(self, manager: StyleManager) -> None:
        """Получение установленного стиля."""
        style = StyleProperties(bold=True)
        manager.set_style(StyleInheritance.DOCUMENT, style)
        result = manager.get_style(StyleInheritance.DOCUMENT)
        assert result.bold is True

    def test_get_nonexistent_returns_default(self, manager: StyleManager) -> None:
        """Несуществующий стиль — дефолт."""
        result = manager.get_style(StyleInheritance.DOCUMENT)
        assert isinstance(result, StyleProperties)
        assert result.bold is False


class TestGetEffectiveStyle:
    """Тесты метода get_effective_style."""

    @pytest.fixture
    def manager(self) -> StyleManager:
        """Фикстура для менеджера."""
        return StyleManager()

    def test_effective_run_style(self, manager: StyleManager) -> None:
        """Эффективный стиль для RUN."""
        manager.set_style(StyleInheritance.DOCUMENT, StyleProperties(bold=True))
        manager.set_style(StyleInheritance.RUN, StyleProperties(italic=True))
        result = manager.get_effective_style(StyleInheritance.RUN)
        assert result.bold is True  # Inherited
        assert result.italic is True  # Own

    def test_effective_paragraph_style(self, manager: StyleManager) -> None:
        """Эффективный стиль для PARAGRAPH."""
        manager.set_style(StyleInheritance.DOCUMENT, StyleProperties(bold=True))
        manager.set_style(StyleInheritance.PARAGRAPH, StyleProperties(underline=True))
        result = manager.get_effective_style(StyleInheritance.PARAGRAPH)
        assert result.bold is True  # Inherited
        assert result.underline is True  # Own

    def test_effective_document_style(self, manager: StyleManager) -> None:
        """Эффективный стиль для DOCUMENT."""
        manager.set_style(StyleInheritance.DOCUMENT, StyleProperties(bold=True))
        result = manager.get_effective_style(StyleInheritance.DOCUMENT)
        assert result.bold is True

    def test_effective_unknown_level(self, manager: StyleManager) -> None:
        """Неизвестный уровень."""
        result = manager.get_effective_style("unknown")
        assert isinstance(result, StyleProperties)


class TestMergeStyle:
    """Тесты метода _merge_style."""

    @pytest.fixture
    def manager(self) -> StyleManager:
        """Фикстура для менеджера."""
        return StyleManager()

    def test_merge_overrides_true(self, manager: StyleManager) -> None:
        """Source переопределяет True."""
        target = StyleProperties(bold=False)
        source = StyleProperties(bold=True)
        manager._merge_style(target, source)
        assert target.bold is True

    def test_merge_preserves_existing(self, manager: StyleManager) -> None:
        """Сохраняет существующее, если source False."""
        target = StyleProperties(bold=True)
        source = StyleProperties(bold=False)
        manager._merge_style(target, source)
        assert target.bold is True

    def test_merge_custom_dict(self, manager: StyleManager) -> None:
        """Объединение custom словаря."""
        target = StyleProperties(custom={"a": "1"})
        source = StyleProperties(custom={"b": "2"})
        manager._merge_style(target, source)
        assert target.custom == {"a": "1", "b": "2"}


class TestResetStyle:
    """Тесты метода reset_style."""

    @pytest.fixture
    def manager(self) -> StyleManager:
        """Фикстура для менеджера."""
        return StyleManager()

    def test_reset_existing(self, manager: StyleManager) -> None:
        """Сброс установленного стиля."""
        manager.set_style(StyleInheritance.DOCUMENT, StyleProperties(bold=True))
        manager.reset_style(StyleInheritance.DOCUMENT)
        assert StyleInheritance.DOCUMENT not in manager._styles

    def test_reset_nonexistent(self, manager: StyleManager) -> None:
        """Сброс несуществующего — без ошибки."""
        manager.reset_style(StyleInheritance.DOCUMENT)  # Should not raise


class TestResetAll:
    """Тесты метода reset_all."""

    def test_reset_all_clears_styles(self) -> None:
        """Очистка всех стилей."""
        manager = StyleManager()
        manager.set_style(StyleInheritance.DOCUMENT, StyleProperties(bold=True))
        manager.set_style(StyleInheritance.RUN, StyleProperties(italic=True))
        manager.reset_all()
        assert manager._styles == {}


class TestInheritFrom:
    """Тесты метода inherit_from."""

    @pytest.fixture
    def manager(self) -> StyleManager:
        """Фикстура для менеджера."""
        return StyleManager()

    def test_inherit_creates_copy(self, manager: StyleManager) -> None:
        """Создание копии стиля."""
        source = StyleProperties(bold=True, italic=True, custom={"key": "value"})
        result = manager.inherit_from(source)
        assert result.bold is True
        assert result.italic is True
        assert result.custom == {"key": "value"}
        assert result is not source

    def test_inherit_custom_dict_copied(self, manager: StyleManager) -> None:
        """Словарь custom копируется."""
        source = StyleProperties(custom={"key": "value"})
        result = manager.inherit_from(source)
        result.custom["new"] = "entry"
        assert "new" not in source.custom


class TestCreateDocumentStyle:
    """Тесты метода create_document_style."""

    @pytest.fixture
    def manager(self) -> StyleManager:
        """Фикстура для менеджера."""
        return StyleManager()

    def test_create_with_bold(self, manager: StyleManager) -> None:
        """Создание с bold."""
        result = manager.create_document_style(bold=True)
        assert result.bold is True

    def test_create_with_font_family(self, manager: StyleManager) -> None:
        """Создание с font_family."""
        result = manager.create_document_style(font_family="Courier")
        assert result.font_family == "Courier"

    def test_create_multiple_properties(self, manager: StyleManager) -> None:
        """Несколько свойств."""
        result = manager.create_document_style(
            bold=True,
            italic=True,
            underline=True,
        )
        assert result.bold is True
        assert result.italic is True
        assert result.underline is True
