"""Тесты для WorkflowIndicator.

Тестирует создание, обновление статуса и взаимодействие с индикатором.
"""

from __future__ import annotations

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock

import pytest

from src.documents.constructor.form_status import FormStatus
from src.gui.workflow.workflow_indicator import (
    DOT_SIZE,
    STATUS_COLORS,
    STATUS_NAMES,
    WorkflowIndicator,
)


@pytest.fixture
def root() -> Generator[tk.Tk, None, None]:
    """Фикстура для Tk root."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def mock_click() -> MagicMock:
    """Фикстура для mock callback клика."""
    return MagicMock()


class TestWorkflowIndicator:
    """Тесты для WorkflowIndicator."""

    def test_init_draft(self, root: tk.Tk, mock_click: MagicMock) -> None:
        """Тест инициализации со статусом DRAFT."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_click=mock_click,
        )
        assert indicator.get_status() == "draft"
        assert indicator.get_status_color() == STATUS_COLORS["draft"]

    def test_init_without_callback(self, root: tk.Tk) -> None:
        """Тест инициализации без callback."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.FILLED,
            on_click=None,
        )
        assert indicator._on_click is None
        assert indicator.get_status() == "filled"

    def test_mount_creates_widget(self, root: tk.Tk, mock_click: MagicMock) -> None:
        """Тест что mount создаёт виджет."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.VALIDATED,
            on_click=mock_click,
        )
        widget = indicator.mount(root)
        assert isinstance(widget, tk.Widget)
        widget.destroy()

    def test_set_status_updates_display(
        self, root: tk.Tk, mock_click: MagicMock
    ) -> None:
        """Тест что set_status обновляет отображение."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_click=mock_click,
        )
        indicator.mount(root)

        # Меняем статус
        indicator.set_status(FormStatus.SIGNED)

        assert indicator.get_status() == "signed"
        assert indicator.get_status_color() == STATUS_COLORS["signed"]

        indicator.widget.destroy()

    def test_set_status_all_statuses(self, root: tk.Tk) -> None:
        """Тест установки всех статусов."""
        for status in FormStatus:
            indicator = WorkflowIndicator(
                parent=root,
                current_status=status,
                on_click=None,
            )
            assert indicator.get_status() == status.value
            assert indicator.get_status_color() == STATUS_COLORS.get(
                status.value, "#95a5a6"
            )

    def test_click_triggers_callback(
        self, root: tk.Tk, mock_click: MagicMock
    ) -> None:
        """Тест что клик вызывает callback."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_click=mock_click,
        )
        indicator.mount(root)

        # Вызываем обработчик клика напрямую
        indicator._on_click_handler(tk.Event())  # type: ignore[arg-type]

        mock_click.assert_called_once()
        indicator.widget.destroy()

    def test_click_no_callback(self, root: tk.Tk) -> None:
        """Тест клика без callback не вызывает ошибок."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_click=None,
        )
        indicator.mount(root)

        # Не должно вызывать ошибок
        indicator._on_click_handler(tk.Event())  # type: ignore[arg-type]

        indicator.widget.destroy()

    def test_status_colors_defined(self) -> None:
        """Тест что все статусы имеют цвета."""
        required_statuses = [
            "draft",
            "filled",
            "validated",
            "signed",
            "printed",
            "archived",
            "rejected",
        ]

        for status in required_statuses:
            assert status in STATUS_COLORS
            color = STATUS_COLORS[status]
            assert color.startswith("#")
            assert len(color) == 7  # #RRGGBB

    def test_status_names_defined(self) -> None:
        """Тест что все статусы имеют локализованные названия."""
        required_statuses = [
            "draft",
            "filled",
            "validated",
            "signed",
            "printed",
            "archived",
            "rejected",
        ]

        for status in required_statuses:
            assert status in STATUS_NAMES
            assert len(STATUS_NAMES[status]) > 0

    def test_dot_size_constant(self) -> None:
        """Тест константы размера точки."""
        assert DOT_SIZE > 0
        assert isinstance(DOT_SIZE, int)

    def test_get_status_display_text(self, root: tk.Tk) -> None:
        """Тест получения отображаемого текста статуса."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.SIGNED,
            on_click=None,
        )

        text = indicator._get_status_display_text()
        assert text == "Подписана"

    def test_get_status_display_text_unknown(self, root: tk.Tk) -> None:
        """Тест получения текста для неизвестного статуса."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_click=None,
        )
        # Устанавливаем неизвестный статус напрямую
        indicator._current_status = "unknown"

        text = indicator._get_status_display_text()
        assert text == "unknown"

    def test_hover_cursor(self, root: tk.Tk) -> None:
        """Тест изменения курсора при наведении."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_click=None,
        )
        indicator.mount(root)

        # Тестируем enter
        indicator._on_enter(tk.Event())  # type: ignore[arg-type]
        # Курсор должен измениться на "hand2"

        # Тестируем leave
        indicator._on_leave(tk.Event())  # type: ignore[arg-type]
        # Курсор должен вернуться к стандартному

        indicator.widget.destroy()

    def test_cleanup_clears_callback(self, root: tk.Tk, mock_click: MagicMock) -> None:
        """Тест что cleanup очищает callback."""
        indicator = WorkflowIndicator(
            parent=root,
            current_status=FormStatus.DRAFT,
            on_click=mock_click,
        )
        indicator.mount(root)

        indicator._cleanup()

        assert indicator._on_click is None

    def test_status_matches_form_status_enum(self) -> None:
        """Тест что статусы в индикаторе соответствуют FormStatus."""
        for status in FormStatus:
            assert status.value in STATUS_COLORS
            assert status.value in STATUS_NAMES


class TestWorkflowIndicatorColors:
    """Тесты цветов индикатора."""

    def test_draft_color(self) -> None:
        """Тест цвета DRAFT."""
        assert STATUS_COLORS["draft"] == "#95a5a6"  # Gray

    def test_filled_color(self) -> None:
        """Тест цвета FILLED."""
        assert STATUS_COLORS["filled"] == "#3498db"  # Blue

    def test_validated_color(self) -> None:
        """Тест цвета VALIDATED."""
        assert STATUS_COLORS["validated"] == "#f39c12"  # Orange

    def test_signed_color(self) -> None:
        """Тест цвета SIGNED."""
        assert STATUS_COLORS["signed"] == "#27ae60"  # Green

    def test_archived_color(self) -> None:
        """Тест цвета ARCHIVED."""
        assert STATUS_COLORS["archived"] == "#2c3e50"  # Dark blue

    def test_rejected_color(self) -> None:
        """Тест цвета REJECTED."""
        assert STATUS_COLORS["rejected"] == "#e74c3c"  # Red


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
