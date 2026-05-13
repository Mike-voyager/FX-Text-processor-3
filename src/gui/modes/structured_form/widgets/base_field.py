"""Базовый класс для всех полей формы STRUCTURED_FORM режима.

Предоставляет:
- BaseField: базовый виджет-контейнер tk.Frame с единым интерфейсом
  get_value(), set_value(), validate(), focus()

Example:
    >>> widget = MyField(
    ...     parent=frame,
    ...     field_id="field_1",
    ...     label="Название",
    ...     on_change=on_field_change,
    ... )
    >>> widget.pack(fill=tk.X)
    >>> widget.set_value("test")
    >>> assert widget.get_value() == "test"

Version: 2.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from abc import abstractmethod
from typing import Any, Callable, Optional


class BaseField(tk.Frame):
    """Базовый класс для всех полей формы STRUCTURED_FORM.

    Наследуется от tk.Frame и предоставляет единый интерфейс
    для получения/установки значений, валидации и управления фокусом.

    Attributes:
        field_id: Уникальный идентификатор поля.
        label: Текст метки поля.
        on_change: Callback при изменении значения (field_id, value).

    Example:
        >>> field = BaseField(parent, field_id="name", label="Имя")
        >>> field.pack(fill=tk.X)
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_id: str,
        label: str,
        on_change: Optional[Callable[[str, Any], None]] = None,
        **kwargs: Any,
    ) -> None:
        """Инициализация базового поля формы.

        Args:
            parent: Родительский Tkinter виджет.
            field_id: Уникальный идентификатор поля.
            label: Текст метки поля.
            on_change: Callback при изменении значения.
            **kwargs: Дополнительные аргументы для tk.Frame.
        """
        super().__init__(parent, **kwargs)

        self.field_id: str = field_id
        self.label: str = label
        self._on_change: Optional[Callable[[str, Any], None]] = on_change
        self._value: Any = None
        self._is_valid: bool = True

        # Внутренние виджеты
        self._label_widget: tk.Label = tk.Label(
            self,
            text=label,
            anchor=tk.W,
            font=("TkDefaultFont", 10),
        )
        self._label_widget.pack(fill=tk.X, pady=(0, 2))

        self._error_label: tk.Label = tk.Label(
            self,
            text="",
            fg="red",
            font=("TkDefaultFont", 8),
            wraplength=400,
        )
        # error_label скрыт по умолчанию
        self._error_label.pack_forget()

    @abstractmethod
    def get_value(self) -> Any:
        """Возвращает текущее значение поля.

        Returns:
            Текущее значение поля.
        """
        return self._value

    @abstractmethod
    def set_value(self, value: Any) -> None:
        """Устанавливает значение поля.

        Args:
            value: Новое значение поля.
        """
        self._value = value
        if self._on_change is not None:
            self._on_change(self.field_id, value)

    def validate(self) -> bool:
        """Валидирует значение поля.

        Returns:
            True если значение валидно, False иначе.
        """
        self._is_valid = True
        self.set_error(None)
        return True

    def focus(self) -> None:
        """Устанавливает фокус на поле ввода.

        Note:
            Подклассы могут переопределить для установки фокуса
            на конкретный виджет ввода.
        """
        self.focus_set()

    def set_error(self, message: Optional[str]) -> None:
        """Показывает или скрывает сообщение об ошибке.

        Args:
            message: Сообщение об ошибке или None для скрытия.
        """
        if message is None or message == "":
            self._error_label.config(text="")
            self._error_label.pack_forget()
            self._is_valid = True
        else:
            self._error_label.config(text=message)
            # Переупаковываем, если был скрыт
            self._error_label.pack(fill=tk.X, pady=(2, 0))
            self._is_valid = False

    def is_valid(self) -> bool:
        """Возвращает флаг валидности поля.

        Returns:
            True если поле валидно.
        """
        return self._is_valid

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные поля.

        Security:
            Сбрасывает внутреннее значение и очищает виджеты ввода.
            Подклассы должны переопределить для полной очистки.
        """
        self._value = None
        self.set_error(None)


__all__: list[str] = ["BaseField"]
