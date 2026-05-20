"""Тесты для factory модуля рендереров.

Тестирует:
- RendererFactory.register: регистрацию рендереров
- RendererFactory.create: создание рендереров
- RendererFactory.cleanup_current: очистку текущего рендерера
- RendererFactory.get_current: получение текущего рендерера
- RendererFactory.is_registered: проверку регистрации
- RendererFactory.unregister: удаление регистрации
- RendererFactory.reset: полный сброс
- register_default_renderers: регистрацию по умолчанию

Example:
    $ xvfb-run -a python -m pytest tests/unit/gui/renderers/test_factory.py -v

Module: tests/unit/gui/renderers/test_factory.py
Version: 1.0
"""

from __future__ import annotations

import sys
from typing import Any, Optional
from unittest.mock import MagicMock, patch

import pytest

from src.documents.types.document_type import DocumentMode
from src.gui.core.exceptions import WidgetCreationError
from src.gui.renderers.factory import RendererFactory, register_default_renderers


@pytest.fixture(autouse=True)
def clean_factory():
    """Очищает RendererFactory перед и после каждого теста."""
    RendererFactory.reset()
    yield
    RendererFactory.reset()


class FakeRenderer:
    """Фейковый рендерер для тестирования фабрики.

    Реализует все методы DocumentRendererProtocol.
    """

    def __init__(
        self,
        widget_id: str = "fake_renderer",
        controller: Optional[Any] = None,
        command_stack: Optional[Any] = None,
    ) -> None:
        self._widget_id = widget_id
        self._controller = controller
        self._command_stack = command_stack
        self._mounted = False
        self._parent: Any = None
        self._wiped = False

    def render(self, document: Any) -> None:
        pass

    def display_document(self, document: Any) -> None:
        pass

    def create_toolbar(self, parent: Any) -> Any:
        return MagicMock()

    def create_editor(self, parent: Any) -> Any:
        return MagicMock()

    def get_editor_state(self) -> dict[str, Any]:
        return {}

    def get_content(self) -> str:
        return ""

    def apply_command(self, command: Any) -> None:
        pass

    def can_handle(self, mode: DocumentMode) -> bool:
        return True

    def wipe_sensitive_data(self) -> None:
        self._wiped = True

    def hide_content(self) -> None:
        pass

    def restore_content(self) -> None:
        pass

    def set_command_stack(self, stack: Any) -> None:
        self._command_stack = stack

    def supports_formatting(self) -> bool:
        return False

    def mount(self, parent: Any) -> Any:
        self._mounted = True
        self._parent = parent
        return MagicMock()

    def unmount(self) -> None:
        self._mounted = False
        self._parent = None

    def is_mounted(self) -> bool:
        return self._mounted


class TestRendererFactoryRegister:
    """Тесты для RendererFactory.register."""

    def test_register_valid_renderer(self) -> None:
        """Проверяет регистрацию валидного класса рендерера."""
        RendererFactory.register(DocumentMode.FREE_FORM, FakeRenderer)
        assert RendererFactory.is_registered(DocumentMode.FREE_FORM)

    def test_register_multiple_modes(self) -> None:
        """Проверяет регистрацию нескольких режимов."""
        RendererFactory.register(DocumentMode.FREE_FORM, FakeRenderer)
        RendererFactory.register(DocumentMode.STRUCTURED_FORM, FakeRenderer)
        assert len(RendererFactory.get_registered_modes()) == 2

    def test_register_non_class_raises_type_error(self) -> None:
        """Проверяет что регистрация не-класса вызывает TypeError."""
        with pytest.raises(TypeError, match="Expected class"):
            RendererFactory.register(DocumentMode.FREE_FORM, "not_a_class")  # type: ignore[arg-type]

    def test_register_class_missing_methods_raises_value_error(self) -> None:
        """Проверяет что класс без нужных методов вызывает ValueError."""

        class IncompleteRenderer:
            """Рендерер без нужных методов."""

            def render(self, document: Any) -> None:
                pass

        with pytest.raises(ValueError, match="missing methods"):
            RendererFactory.register(DocumentMode.FREE_FORM, IncompleteRenderer)

    def test_register_overwrites_existing(self) -> None:
        """Проверяет что повторная регистрация перезаписывает."""

        class AnotherFakeRenderer(FakeRenderer):
            """Другой фейковый рендерер."""

            pass

        RendererFactory.register(DocumentMode.FREE_FORM, FakeRenderer)
        RendererFactory.register(DocumentMode.FREE_FORM, AnotherFakeRenderer)
        assert RendererFactory.is_registered(DocumentMode.FREE_FORM)


class TestRendererFactoryCreate:
    """Тесты для RendererFactory.create."""

    def test_create_requires_parent(self) -> None:
        """Проверяет что parent не может быть None."""
        RendererFactory.register(DocumentMode.FREE_FORM, FakeRenderer)
        with pytest.raises(ValueError, match="parent cannot be None"):
            RendererFactory.create(DocumentMode.FREE_FORM, parent=None)  # type: ignore[arg-type]

    def test_create_unregistered_mode_raises(self) -> None:
        """Проверяет что незарегистрированный режим вызывает WidgetCreationError."""
        mock_parent = MagicMock()
        with pytest.raises(WidgetCreationError):
            RendererFactory.create(DocumentMode.FREE_FORM, parent=mock_parent)

    def test_create_returns_renderer(self) -> None:
        """Проверяет что create возвращает экземпляр рендерера."""
        RendererFactory.register(DocumentMode.FREE_FORM, FakeRenderer)
        mock_parent = MagicMock()
        renderer = RendererFactory.create(
            DocumentMode.FREE_FORM,
            parent=mock_parent,
        )
        assert isinstance(renderer, FakeRenderer)

    def test_create_mounts_renderer(self) -> None:
        """Проверяет что create монтирует рендерер."""
        RendererFactory.register(DocumentMode.FREE_FORM, FakeRenderer)
        mock_parent = MagicMock()
        renderer = RendererFactory.create(
            DocumentMode.FREE_FORM,
            parent=mock_parent,
        )
        assert renderer.is_mounted()

    def test_create_sets_current(self) -> None:
        """Проверяет что create устанавливает текущий рендерер."""
        RendererFactory.register(DocumentMode.FREE_FORM, FakeRenderer)
        mock_parent = MagicMock()
        renderer = RendererFactory.create(
            DocumentMode.FREE_FORM,
            parent=mock_parent,
        )
        assert RendererFactory.get_current() is renderer

    def test_create_passes_command_stack(self) -> None:
        """Проверяет что CommandStack передаётся в рендерер."""
        RendererFactory.register(DocumentMode.FREE_FORM, FakeRenderer)
        mock_parent = MagicMock()
        mock_stack = MagicMock()
        renderer = RendererFactory.create(
            DocumentMode.FREE_FORM,
            parent=mock_parent,
            command_stack=mock_stack,
        )
        assert renderer._command_stack is mock_stack

    def test_create_cleans_previous_renderer(self) -> None:
        """Проверяет что создание нового рендерера очищает предыдущий."""
        RendererFactory.register(DocumentMode.FREE_FORM, FakeRenderer)
        RendererFactory.register(DocumentMode.STRUCTURED_FORM, FakeRenderer)
        mock_parent = MagicMock()

        first = RendererFactory.create(
            DocumentMode.FREE_FORM,
            parent=mock_parent,
        )
        assert not first._wiped

        second = RendererFactory.create(
            DocumentMode.STRUCTURED_FORM,
            parent=mock_parent,
        )
        # Previous renderer should have been wiped
        assert first._wiped

    def test_create_sets_current_mode(self) -> None:
        """Проверяет что create устанавливает текущий режим."""
        RendererFactory.register(DocumentMode.FREE_FORM, FakeRenderer)
        mock_parent = MagicMock()
        RendererFactory.create(
            DocumentMode.FREE_FORM,
            parent=mock_parent,
        )
        assert RendererFactory.get_current_mode() == DocumentMode.FREE_FORM


class TestRendererFactoryCleanup:
    """Тесты для RendererFactory.cleanup_current."""

    def test_cleanup_wipes_sensitive_data(self) -> None:
        """Проверяет что cleanup вызывает wipe_sensitive_data."""
        RendererFactory.register(DocumentMode.FREE_FORM, FakeRenderer)
        mock_parent = MagicMock()
        renderer = RendererFactory.create(
            DocumentMode.FREE_FORM,
            parent=mock_parent,
        )
        RendererFactory.cleanup_current()
        assert renderer._wiped

    def test_cleanup_resets_current(self) -> None:
        """Проверяет что cleanup сбрасывает текущий рендерер."""
        RendererFactory.register(DocumentMode.FREE_FORM, FakeRenderer)
        mock_parent = MagicMock()
        RendererFactory.create(
            DocumentMode.FREE_FORM,
            parent=mock_parent,
        )
        RendererFactory.cleanup_current()
        assert RendererFactory.get_current() is None
        assert RendererFactory.get_current_mode() is None

    def test_cleanup_noop_when_no_renderer(self) -> None:
        """Проверяет что cleanup безопасен без текущего рендерера."""
        RendererFactory.cleanup_current()  # Не должно вызвать ошибку
        assert RendererFactory.get_current() is None


class TestRendererFactoryQueries:
    """Тесты для query методов RendererFactory."""

    def test_is_registered_false_initially(self) -> None:
        """Проверяет что режим не зарегистрирован изначально."""
        assert not RendererFactory.is_registered(DocumentMode.FREE_FORM)

    def test_is_registered_true_after_register(self) -> None:
        """Проверяет что режим зарегистрирован после регистрации."""
        RendererFactory.register(DocumentMode.FREE_FORM, FakeRenderer)
        assert RendererFactory.is_registered(DocumentMode.FREE_FORM)

    def test_get_registered_modes_empty_initially(self) -> None:
        """Проверяет что список режимов пуст изначально."""
        assert RendererFactory.get_registered_modes() == []

    def test_get_registered_modes_after_register(self) -> None:
        """Проверяет список зарегистрированных режимов."""
        RendererFactory.register(DocumentMode.FREE_FORM, FakeRenderer)
        modes = RendererFactory.get_registered_modes()
        assert DocumentMode.FREE_FORM in modes


class TestRendererFactoryUnregister:
    """Тесты для RendererFactory.unregister."""

    def test_unregister_removes_mode(self) -> None:
        """Проверяет что unregister удаляет режим."""
        RendererFactory.register(DocumentMode.FREE_FORM, FakeRenderer)
        RendererFactory.unregister(DocumentMode.FREE_FORM)
        assert not RendererFactory.is_registered(DocumentMode.FREE_FORM)

    def test_unregister_nonexistent_is_noop(self) -> None:
        """Проверяет что unregister несуществующего режима безопасен."""
        RendererFactory.unregister(DocumentMode.FREE_FORM)  # Не должно вызвать ошибку


class TestRendererFactoryReset:
    """Тесты для RendererFactory.reset."""

    def test_reset_clears_registrations(self) -> None:
        """Проверяет что reset очищает все регистрации."""
        RendererFactory.register(DocumentMode.FREE_FORM, FakeRenderer)
        RendererFactory.register(DocumentMode.STRUCTURED_FORM, FakeRenderer)
        RendererFactory.reset()
        assert RendererFactory.get_registered_modes() == []

    def test_reset_clears_current_renderer(self) -> None:
        """Проверяет что reset очищает текущий рендерер."""
        RendererFactory.register(DocumentMode.FREE_FORM, FakeRenderer)
        mock_parent = MagicMock()
        RendererFactory.create(
            DocumentMode.FREE_FORM,
            parent=mock_parent,
        )
        RendererFactory.reset()
        assert RendererFactory.get_current() is None
        assert RendererFactory.get_current_mode() is None


class TestRegisterDefaultRenderers:
    """Тесты для register_default_renderers."""

    def test_register_default_renderers(self) -> None:
        """Проверяет что register_default_renderers регистрирует стандартные рендереры."""
        # Сбросить автрегистрацию из импорта модуля
        RendererFactory.reset()
        register_default_renderers()
        # Должны быть зарегистрированы FREE_FORM и STRUCTURED_FORM
        modes = RendererFactory.get_registered_modes()
        assert DocumentMode.FREE_FORM in modes
        assert DocumentMode.STRUCTURED_FORM in modes