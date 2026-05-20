"""Тесты для FieldCommentWidget.

Тестирует создание, управление комментариями и взаимодействие с popup.
"""

from __future__ import annotations

from datetime import datetime
from typing import Generator

import pytest
import tkinter as tk

from src.gui.workflow.field_comment_widget import (
    FieldCommentWidget,
    Comment,
    Severity,
)
from src.gui.workflow.role_badge import WorkflowRole


@pytest.fixture
def root() -> Generator[tk.Tk, None, None]:
    """Фикстура для Tk root."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def mock_callbacks() -> tuple:
    """Фикстура с mock callback'ами."""
    add_results: list[str] = []
    resolve_results: list[str] = []

    def on_add(field_id: str, text: str, severity: Severity) -> str | None:
        add_results.append(f"{field_id}:{text}:{severity.value}")
        return f"comment_{len(add_results)}"

    def on_resolve(comment_id: str) -> bool:
        resolve_results.append(comment_id)
        return True

    return on_add, on_resolve, add_results, resolve_results


class TestFieldCommentWidget:
    """Тесты для виджета комментариев."""

    def test_init_empty(self, root: tk.Tk, mock_callbacks: tuple) -> None:
        """Тест инициализации без комментариев."""
        on_add, on_resolve, _, _ = mock_callbacks
        widget = FieldCommentWidget(
            parent=root,
            field_id="field_1",
            comments=[],
            on_add=on_add,
            on_resolve=on_resolve,
        )
        assert widget.field_id == "field_1"
        assert len(widget.comments) == 0
        assert widget.unresolved_count == 0
        assert widget.highest_severity == Severity.INFO

    def test_init_with_comments(self, root: tk.Tk, mock_callbacks: tuple) -> None:
        """Тест инициализации с комментариями."""
        on_add, on_resolve, _, _ = mock_callbacks
        comments = [
            Comment(
                comment_id="c1",
                field_id="field_1",
                text="Test comment",
                author="User1",
                author_role=WorkflowRole.OPERATOR,
                severity=Severity.WARNING,
                created_at=datetime.now(),
            ),
        ]
        widget = FieldCommentWidget(
            parent=root,
            field_id="field_1",
            comments=comments,
            on_add=on_add,
            on_resolve=on_resolve,
        )
        assert len(widget.comments) == 1
        assert widget.unresolved_count == 1
        assert widget.highest_severity == Severity.WARNING

    def test_severity_priority(
        self, root: tk.Tk, mock_callbacks: tuple
    ) -> None:
        """Тест приоритета severity (ERROR > WARNING > INFO)."""
        on_add, on_resolve, _, _ = mock_callbacks
        comments = [
            Comment(
                comment_id="c1",
                field_id="field_1",
                text="Info",
                author="User1",
                author_role=WorkflowRole.OPERATOR,
                severity=Severity.INFO,
                created_at=datetime.now(),
            ),
            Comment(
                comment_id="c2",
                field_id="field_1",
                text="Warning",
                author="User2",
                author_role=WorkflowRole.EDITOR,
                severity=Severity.WARNING,
                created_at=datetime.now(),
            ),
        ]
        widget = FieldCommentWidget(
            parent=root,
            field_id="field_1",
            comments=comments,
            on_add=on_add,
            on_resolve=on_resolve,
        )
        assert widget.highest_severity == Severity.WARNING

        # Add ERROR comment
        widget.add_local_comment("c3", "Error", Severity.ERROR)
        assert widget.highest_severity == Severity.ERROR

    def test_all_severities(self, root: tk.Tk, mock_callbacks: tuple) -> None:
        """Тест всех уровней серьёзности."""
        on_add, on_resolve, _, _ = mock_callbacks
        for severity in Severity:
            comment = Comment(
                comment_id="c1",
                field_id="field_1",
                text="Test",
                author="User",
                author_role=WorkflowRole.OPERATOR,
                severity=severity,
                created_at=datetime.now(),
            )
            widget = FieldCommentWidget(
                parent=root,
                field_id="field_1",
                comments=[comment],
                on_add=on_add,
                on_resolve=on_resolve,
            )
            assert widget.highest_severity == severity

    def test_set_comments(self, root: tk.Tk, mock_callbacks: tuple) -> None:
        """Тест установки нового списка комментариев."""
        on_add, on_resolve, _, _ = mock_callbacks
        widget = FieldCommentWidget(
            parent=root,
            field_id="field_1",
            comments=[],
            on_add=on_add,
            on_resolve=on_resolve,
        )
        new_comments = [
            Comment(
                comment_id="c1",
                field_id="field_1",
                text="New comment",
                author="User1",
                author_role=WorkflowRole.OPERATOR,
                severity=Severity.INFO,
                created_at=datetime.now(),
            ),
        ]
        widget.set_comments(new_comments)
        assert len(widget.comments) == 1

    def test_resolved_comments_not_counted(
        self, root: tk.Tk, mock_callbacks: tuple
    ) -> None:
        """Тест что разрешённые комментарии не считаются в unresolved_count."""
        on_add, on_resolve, _, _ = mock_callbacks
        comments = [
            Comment(
                comment_id="c1",
                field_id="field_1",
                text="Resolved",
                author="User1",
                author_role=WorkflowRole.OPERATOR,
                severity=Severity.ERROR,
                created_at=datetime.now(),
                resolved=True,
                resolved_at=datetime.now(),
                resolved_by="Resolver",
            ),
        ]
        widget = FieldCommentWidget(
            parent=root,
            field_id="field_1",
            comments=comments,
            on_add=on_add,
            on_resolve=on_resolve,
        )
        assert widget.unresolved_count == 0
        # Если только разрешённые, highest_severity возвращает INFO
        assert widget.highest_severity == Severity.INFO

    def test_mount_creates_widget(self, root: tk.Tk, mock_callbacks: tuple) -> None:
        """Тест что mount создаёт виджет."""
        on_add, on_resolve, _, _ = mock_callbacks
        widget = FieldCommentWidget(
            parent=root,
            field_id="field_1",
            comments=[],
            on_add=on_add,
            on_resolve=on_resolve,
        )
        result = widget.mount(root)
        assert isinstance(result, tk.Widget)
        result.destroy()

    def test_role_display_name(self) -> None:
        """Тест отображения названия роли."""
        assert WorkflowRole.OPERATOR.display_name == "Оператор"
        assert WorkflowRole.EDITOR.display_name == "Редактор"
        assert WorkflowRole.SUPERVISOR.display_name == "Супервайзер"
        assert WorkflowRole.SIGNATORY.display_name == "Подписант"

    def test_comment_immutable(self) -> None:
        """Тест что Comment immutable (frozen=True)."""
        comment = Comment(
            comment_id="c1",
            field_id="f1",
            text="Text",
            author="User",
            author_role=WorkflowRole.OPERATOR,
            severity=Severity.INFO,
            created_at=datetime.now(),
        )
        with pytest.raises(AttributeError):
            comment.text = "New text"  # type: ignore[misc]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
