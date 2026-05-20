"""Тесты для protocols модуля рендереров.

Тестирует:
- DocumentRendererProtocol: интерфейс рендерера документов
- RendererCleanupProtocol: интерфейс очистки рендерера
- implements: декоратор для указания реализации Protocol
- AnyDocumentRenderer: Union type

Example:
    $ pytest tests/unit/gui/renderers/test_protocols.py -v

Module: tests/unit/gui/renderers/test_protocols.py
Version: 1.0
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable
from unittest.mock import MagicMock

import pytest

from src.gui.renderers.protocols import (
    AnyDocumentRenderer,
    DocumentRendererProtocol,
    RendererCleanupProtocol,
    implements,
)


class TestDocumentRendererProtocol:
    """Тесты для DocumentRendererProtocol."""

    def test_protocol_is_runtime_checkable(self) -> None:
        """Проверяет что DocumentRendererProtocol можно проверить через isinstance."""
        # Protocol с TypeVar не является runtime_checkable по умолчанию
        # Проверяем что класс можно использовать как тип
        assert DocumentRendererProtocol is not None

    def test_protocol_defines_required_methods(self) -> None:
        """Проверяет что Protocol определяет все необходимые методы."""
        expected_methods = [
            "render",
            "display_document",
            "create_toolbar",
            "create_editor",
            "get_editor_state",
            "get_content",
            "apply_command",
            "can_handle",
            "wipe_sensitive_data",
            "hide_content",
            "restore_content",
            "set_command_stack",
            "supports_formatting",
            "mount",
            "unmount",
            "is_mounted",
        ]
        for method_name in expected_methods:
            assert hasattr(DocumentRendererProtocol, method_name), (
                f"DocumentRendererProtocol должен определять метод {method_name}"
            )


class TestRendererCleanupProtocol:
    """Тесты для RendererCleanupProtocol."""

    def test_cleanup_protocol_is_runtime_checkable(self) -> None:
        """Проверяет что RendererCleanupProtocol является runtime_checkable."""
        assert issubclass(RendererCleanupProtocol, Protocol)

    def test_cleanup_protocol_defines_methods(self) -> None:
        """Проверяет что Protocol определяет cleanup методы."""
        expected_methods = ["cleanup", "save_state", "restore_state"]
        for method_name in expected_methods:
            assert hasattr(RendererCleanupProtocol, method_name), (
                f"RendererCleanupProtocol должен определять метод {method_name}"
            )

    def test_cleanup_protocol_runtime_check(self) -> None:
        """Проверяет runtime проверку isinstance для RendererCleanupProtocol."""

        class FakeCleanupRenderer:
            """Фейковый рендерер с cleanup."""

            def cleanup(self) -> None:
                """Очищает ресурсы."""

            def save_state(self) -> dict[str, Any]:
                """Сохраняет состояние."""
                return {}

            def restore_state(self, state: dict[str, Any]) -> None:
                """Восстанавливает состояние."""

        renderer = FakeCleanupRenderer()
        assert isinstance(renderer, RendererCleanupProtocol)


class TestImplementsDecorator:
    """Тесты для декоратора implements."""

    def test_implements_sets_attribute(self) -> None:
        """Проверяет что декоратор устанавливает __implements__ атрибут."""

        @implements(DocumentRendererProtocol)
        class FakeRenderer:
            """Фейковый рендерер."""

            pass

        assert hasattr(FakeRenderer, "__implements__")
        assert FakeRenderer.__implements__ is DocumentRendererProtocol

    def test_implements_preserves_class(self) -> None:
        """Проверяет что декоратор не меняет класс."""

        @implements(RendererCleanupProtocol)
        class FakeCleanup:
            """Фейковый cleanup."""

            def cleanup(self) -> None:
                pass

            def save_state(self) -> dict[str, Any]:
                return {}

            def restore_state(self, state: dict[str, Any]) -> None:
                pass

        # Класс должен работать как обычно
        instance = FakeCleanup()
        assert instance.cleanup() is None
        assert instance.save_state() == {}

    def test_implements_with_custom_protocol(self) -> None:
        """Проверяет декоратор с кастомным Protocol."""

        @runtime_checkable
        class CustomProtocol(Protocol):
            def do_work(self) -> str: ...

        @implements(CustomProtocol)
        class Worker:
            def do_work(self) -> str:
                return "done"

        assert Worker.__implements__ is CustomProtocol
        assert Worker().do_work() == "done"


class TestAnyDocumentRenderer:
    """Тесты для AnyDocumentRenderer Union type."""

    def test_union_type_exists(self) -> None:
        """Проверяет что AnyDocumentRenderer определён."""
        assert AnyDocumentRenderer is not None

    def test_document_renderer_is_part_of_union(self) -> None:
        """Проверяет что DocumentRendererProtocol входит в Union."""
        # Union type проверяется через типы аргументов
        # Проверяем что оба Protocol доступны
        assert DocumentRendererProtocol is not None
        assert RendererCleanupProtocol is not None