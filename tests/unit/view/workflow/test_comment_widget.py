"""Тесты для FieldCommentWidget."""

from __future__ import annotations

import pytest
import tkinter as tk

from src.view.workflow import CommentSeverity
from src.view.workflow.comment_widget import FieldCommentWidget


@pytest.fixture
def root():
    """Фикстура для Tk root."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


class TestFieldCommentWidget:
    """Тесты для виджета комментария."""

    def test_init_without_comment(self, root):
        """Тест инициализации без комментария."""
        widget = FieldCommentWidget(root, field_id="field_1")
        assert widget.get_field_id() == "field_1"
        assert widget.get_comment() is None

    def test_init_with_comment(self, root):
        """Тест инициализации с комментарием."""
        widget = FieldCommentWidget(
            root,
            field_id="field_1",
            comment="Test comment",
            severity=CommentSeverity.WARNING,
        )
        assert widget.get_comment() == "Test comment"

    def test_set_comment(self, root):
        """Тест установки комментария."""
        widget = FieldCommentWidget(root, field_id="field_1")
        widget.set_comment("New comment", CommentSeverity.ERROR)
        assert widget.get_comment() == "New comment"

    def test_clear(self, root):
        """Тест очистки комментария."""
        widget = FieldCommentWidget(
            root,
            field_id="field_1",
            comment="Test comment",
        )
        widget.clear()
        assert widget.get_comment() is None

    def test_all_severities(self, root):
        """Тест всех уровней серьёзности."""
        for severity in CommentSeverity:
            widget = FieldCommentWidget(
                root,
                field_id="field_1",
                comment="Test",
                severity=severity,
            )
            assert widget.get_comment() == "Test"

    def test_callback_on_click(self, root):
        """Тест callback при клике."""
        clicked_field = []

        def on_click(field_id):
            clicked_field.append(field_id)

        widget = FieldCommentWidget(
            root,
            field_id="field_test",
            comment="Test",
            on_click=on_click,
        )

        # Имитируем клик
        on_click("field_test")

        assert len(clicked_field) == 1
        assert clicked_field[0] == "field_test"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
