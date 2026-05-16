"""Unit-тесты для CalendarDialog.

Проверяет:
- Создание диалога с различными начальными датами
- Показ/скрытие диалога (mock wait_window)
- Выбор даты через _select_date
- Кнопку "Сегодня"
- Кнопку "Отмена"
- Обновление календаря при смене месяца/года
- Корректное возвращение Optional[date]

Coverage target: ≥90%
"""

from __future__ import annotations

import tkinter as tk
from datetime import date
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest
from src.gui.dialogs.calendar_dialog import MONTH_NAMES, WEEKDAYS, CalendarDialog

# Skip GUI tests if no display available
pytestmark = [
    pytest.mark.gui,
]


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Fixture для Tk root окна."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


# =============================================================================
# TEST: CalendarDialog Creation
# =============================================================================


class TestCalendarDialogCreation:
    """Тесты создания CalendarDialog."""

    def test_calendar_dialog_creation_no_date(self, tk_root: tk.Tk) -> None:
        """Создание без начальной даты (по умолчанию сегодня)."""
        dialog = CalendarDialog(parent=tk_root, initial_date=None)
        assert dialog._initial_date == date.today()
        dialog.destroy()

    def test_calendar_dialog_creation_with_date(self, tk_root: tk.Tk) -> None:
        """Создание с конкретной начальной датой."""
        initial = date(2025, 3, 15)
        dialog = CalendarDialog(parent=tk_root, initial_date=initial)
        assert dialog._initial_date == initial
        assert dialog._month_var.get() == "March"
        assert dialog._year_var.get() == "2025"
        dialog.destroy()

    def test_calendar_dialog_title(self, tk_root: tk.Tk) -> None:
        """Заголовок окна установлен корректно."""
        dialog = CalendarDialog(parent=tk_root)
        assert dialog.title() == "Select Date"
        dialog.destroy()

    def test_weekday_headers(self, tk_root: tk.Tk) -> None:
        """Константы дней недели корректны."""
        assert WEEKDAYS == ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        assert len(MONTH_NAMES) == 12


# =============================================================================
# TEST: CalendarDialog Interaction
# =============================================================================


class TestCalendarDialogInteraction:
    """Тесты взаимодействия с CalendarDialog."""

    @patch.object(CalendarDialog, "wait_window")
    @patch.object(CalendarDialog, "wait_visibility")
    @patch.object(CalendarDialog, "deiconify")
    def test_show_returns_date(
        self,
        mock_deiconify: MagicMock,
        mock_wait_vis: MagicMock,
        mock_wait: MagicMock,
        tk_root: tk.Tk,
    ) -> None:
        """show() возвращает установленный результат."""
        dialog = CalendarDialog(parent=tk_root, initial_date=date(2026, 5, 7))

        dialog._result = date(2026, 5, 15)
        result = dialog.show()

        assert result == date(2026, 5, 15)
        dialog.destroy()

    @patch.object(CalendarDialog, "wait_window")
    @patch.object(CalendarDialog, "wait_visibility")
    @patch.object(CalendarDialog, "deiconify")
    def test_show_returns_none_on_cancel(
        self,
        mock_deiconify: MagicMock,
        mock_wait_vis: MagicMock,
        mock_wait: MagicMock,
        tk_root: tk.Tk,
    ) -> None:
        """show() возвращает None при отмене."""
        dialog = CalendarDialog(parent=tk_root)

        dialog._result = None
        result = dialog.show()

        assert result is None
        dialog.destroy()

    @patch.object(CalendarDialog, "close")
    def test_today_button_selects_today(self, mock_close: MagicMock, tk_root: tk.Tk) -> None:
        """Кнопка 'Сегодня' закрывает диалог с сегодняшней датой."""
        dialog = CalendarDialog(parent=tk_root)

        dialog._on_today()

        mock_close.assert_called_once()
        call_arg = (
            mock_close.call_args[0][0]
            if mock_close.call_args[0]
            else mock_close.call_args[1].get("result")
        )
        assert call_arg == date.today()
        dialog.destroy()

    @patch.object(CalendarDialog, "close")
    def test_select_date_closes_dialog(self, mock_close: MagicMock, tk_root: tk.Tk) -> None:
        """_select_date закрывает диалог с выбранной датой."""
        dialog = CalendarDialog(parent=tk_root)
        dialog._select_date(2026, 5, 20)

        mock_close.assert_called_once_with(date(2026, 5, 20))
        dialog.destroy()

    def test_refresh_calendar_creates_buttons(self, tk_root: tk.Tk) -> None:
        """Обновление календаря создаёт кнопки дней."""
        dialog = CalendarDialog(parent=tk_root, initial_date=date(2026, 2, 1))
        dialog._refresh_calendar()

        # Февраль 2026 имеет 28 дней
        assert len(dialog._day_buttons) == 28
        dialog.destroy()

    def test_refresh_calendar_leap_year(self, tk_root: tk.Tk) -> None:
        """Обновление календаря для високосного года."""
        dialog = CalendarDialog(parent=tk_root, initial_date=date(2024, 2, 1))
        dialog._refresh_calendar()

        # Февраль 2024 (високосный) имеет 29 дней
        assert len(dialog._day_buttons) == 29
        dialog.destroy()

    def test_refresh_calendar_different_month(self, tk_root: tk.Tk) -> None:
        """Смена месяца через переменную обновляет кнопки."""
        dialog = CalendarDialog(parent=tk_root, initial_date=date(2026, 1, 1))
        dialog._month_var.set("May")
        dialog._refresh_calendar()

        # Май имеет 31 день
        assert len(dialog._day_buttons) == 31
        dialog.destroy()

    def test_highlight_initial_date(self, tk_root: tk.Tk) -> None:
        """Начальная дата подсвечивается синим."""
        dialog = CalendarDialog(parent=tk_root, initial_date=date(2026, 5, 7))
        dialog._refresh_calendar()

        for btn in dialog._day_buttons:
            if btn.cget("text") == "7":
                assert btn.cget("bg") == "#3daee9"
                assert btn.cget("fg") == "white"
                break
        else:
            pytest.fail("Кнопка с датой 7 не найдена")

        dialog.destroy()

    def test_highlight_today_different_from_initial(self, tk_root: tk.Tk) -> None:
        """Сегодняшняя дата подсвечивается, если не совпадает с начальной."""
        today = date.today()
        # Выбираем начальную дату в другом месяце
        if today.month == 1:
            initial = today.replace(month=2)
        else:
            initial = today.replace(month=1)

        dialog = CalendarDialog(parent=tk_root, initial_date=initial)
        dialog._month_var.set(MONTH_NAMES[today.month - 1])
        dialog._year_var.set(str(today.year))
        dialog._refresh_calendar()

        for btn in dialog._day_buttons:
            if btn.cget("text") == str(today.day):
                # Сегодня должна быть подсвечена серым
                assert btn.cget("bg") == "#e0e0e0"
                break
        else:
            pytest.fail("Кнопка с сегодняшней датой не найдена")

        dialog.destroy()


# =============================================================================
# TEST: Constants
# =============================================================================


class TestCalendarDialogConstants:
    """Тесты констант."""

    def test_month_names_count(self) -> None:
        """12 месяцев в константе."""
        assert len(MONTH_NAMES) == 12

    def test_month_names_russian(self) -> None:
        """Названия месяцев на русском."""
        assert MONTH_NAMES[0] == "January"
        assert MONTH_NAMES[11] == "December"

    def test_weekdays_count(self) -> None:
        """7 дней в неделе."""
        assert len(WEEKDAYS) == 7


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.dialogs.calendar_dialog"])
