"""Диалог выбора даты на чистом tkinter.

Предоставляет:
- CalendarDialog: модальный диалог выбора даты с сеткой календаря,
  выбором месяца/года и кнопками управления.

Example:
    >>> dialog = CalendarDialog(parent, initial_date=date(2026, 5, 7))
    >>> result = dialog.show()
    >>> assert result == date(2026, 5, 7)

Version: 1.0
"""

from __future__ import annotations

import calendar
import tkinter as tk
from datetime import date
from typing import Callable, Optional, cast

from src.gui.dialogs.base_dialog import BaseDialog

MONTH_NAMES: list[str] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
]

WEEKDAYS: list[str] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


class CalendarDialog(BaseDialog):
    """Модальный диалог выбора даты.

    Attributes:
        _initial_date: Начальная дата для отображения календаря.
        _selected_date: Выбранная дата (None если пользователь отменил выбор).
        _month_var: Переменная Tkinter для выбора месяца.
        _year_var: Переменная Tkinter для выбора года.
        _day_buttons: Список кнопок дней текущего месяца.
        _days_frame: Фрейм сетки дней.

    Example:
        >>> dialog = CalendarDialog(parent=frame, initial_date=date(2026, 5, 7))
        >>> selected = dialog.show()
    """

    def __init__(
        self,
        parent: tk.Widget,
        initial_date: Optional[date] = None,
    ) -> None:
        """Инициализация диалога выбора даты.

        Args:
            parent: Родительский Tkinter виджет.
            initial_date: Начальная дата для отображения (по умолчанию сегодня).
        """
        self._initial_date: date = initial_date or date.today()
        self._selected_date: Optional[date] = None
        self._day_buttons: list[tk.Button] = []
        self._days_frame: tk.Frame

        # Родительский виджет может быть Frame; BaseDialog требует окно
        toplevel = cast(tk.Widget, parent.winfo_toplevel())
        super().__init__(
            toplevel,
            title="Select Date",
            modal=True,
            center_on_parent=True,
        )

        # Скрываем окно до вызова show(), иначе wait_visibility() в show()
        # повиснет на уже-видимом окне (в частности в тестах).
        self.withdraw()

        self._month_var = tk.StringVar(master=self, value=MONTH_NAMES[self._initial_date.month - 1])
        self._year_var = tk.StringVar(master=self, value=str(self._initial_date.year))

        self._create_ui()
        self._refresh_calendar()

    def _create_ui(self) -> None:
        """Создаёт интерфейс диалога."""
        self.geometry("300x320")

        # Заголовок с выбором месяца и года
        header_frame = tk.Frame(self)
        header_frame.pack(fill=tk.X, pady=5)

        tk.Label(header_frame, text="Month:").pack(side=tk.LEFT, padx=5)
        month_menu = tk.OptionMenu(header_frame, self._month_var, *MONTH_NAMES)
        month_menu.pack(side=tk.LEFT, padx=2)

        tk.Label(header_frame, text="Year:").pack(side=tk.LEFT, padx=(10, 5))
        year_spin = tk.Spinbox(
            header_frame,
            from_=1900,
            to=2100,
            width=6,
            textvariable=self._year_var,
        )
        year_spin.pack(side=tk.LEFT, padx=2)

        # Сетка дней недели
        days_frame = tk.Frame(self)
        days_frame.pack(pady=10)
        self._days_frame = days_frame

        for i, wd in enumerate(WEEKDAYS):
            tk.Label(
                days_frame,
                text=wd,
                font=("TkDefaultFont", 9, "bold"),
                width=4,
            ).grid(row=0, column=i, padx=1, pady=1)

        # Кнопка обновления календаря
        tk.Button(self, text="Refresh", command=self._refresh_calendar).pack(pady=2)

        # Нижние кнопки
        bottom_frame = tk.Frame(self)
        bottom_frame.pack(fill=tk.X, pady=5)

        tk.Button(bottom_frame, text="Today", command=self._on_today).pack(side=tk.LEFT, padx=5)
        tk.Button(bottom_frame, text="Cancel", command=self._on_cancel).pack(side=tk.RIGHT, padx=5)

    def _refresh_calendar(self) -> None:
        """Обновляет отображение календаря при изменении месяца/года."""
        # Удаляем старые кнопки
        for btn in self._day_buttons:
            btn.destroy()
        self._day_buttons.clear()

        try:
            month = MONTH_NAMES.index(self._month_var.get()) + 1
            year = int(self._year_var.get())
        except (ValueError, IndexError):
            return

        cal = calendar.Calendar(firstweekday=0)
        days = cal.monthdayscalendar(year, month)

        for week_num, week in enumerate(days):
            for day_num, day_val in enumerate(week):
                if day_val == 0:
                    continue

                def make_command(
                    y: int = year, m: int = month, d: int = day_val
                ) -> Callable[[], None]:
                    return lambda: self._select_date(y, m, d)

                btn = tk.Button(
                    self._days_frame,
                    text=str(day_val),
                    width=4,
                    command=make_command(),
                )
                btn.grid(row=week_num + 1, column=day_num, padx=1, pady=1)
                self._day_buttons.append(btn)

                # Подсветка начальной даты
                if (
                    year == self._initial_date.year
                    and month == self._initial_date.month
                    and day_val == self._initial_date.day
                ):
                    btn.config(bg="#3daee9", fg="white")

                # Подсветка сегодняшней даты (если не совпадает с начальной)
                today = date.today()
                if (
                    year == today.year
                    and month == today.month
                    and day_val == today.day
                    and not (
                        year == self._initial_date.year
                        and month == self._initial_date.month
                        and day_val == self._initial_date.day
                    )
                ):
                    btn.config(bg="#e0e0e0", fg="black")

    def _select_date(self, year: int, month: int, day: int) -> None:
        """Выбирает дату и закрывает диалог.

        Args:
            year: Год выбранной даты.
            month: Месяц выбранной даты.
            day: День выбранной даты.
        """
        self._selected_date = date(year, month, day)
        self.close(self._selected_date)

    def _on_today(self) -> None:
        """Устанавливает сегодняшнюю дату и закрывает диалог."""
        today = date.today()
        self._selected_date = today
        self.close(today)

    def _on_cancel(self) -> None:
        """Закрывает диалог без выбора даты."""
        self.close(None)

    def show(self) -> Optional[date]:
        """Показывает диалог модально и возвращает выбранную дату.

        Returns:
            Выбранная дата или None при отмене.
        """
        self.deiconify()
        super().show()
        return cast(Optional[date], self._result)


__all__: list[str] = [
    "CalendarDialog",
    "MONTH_NAMES",
    "WEEKDAYS",
]
