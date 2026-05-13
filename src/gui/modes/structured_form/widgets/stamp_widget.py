"""Виджет поля штампа для Structured Form.

Предоставляет:
- StampWidget: read-only поле для отображения изображения штампа (PNG/JPEG).

Example:
    >>> widget = StampWidget(
    ...     parent=frame,
    ...     field_def=field_def,
    ...     stamp_data=stamp_bytes,
    ... )
    >>> widget.mount(parent_frame)
    >>> widget.get_value() == stamp_bytes
    True
"""

from __future__ import annotations

import tkinter as tk
from io import BytesIO
from typing import Callable, Optional

try:
    from PIL import Image, ImageTk
except ImportError:
    ImageTk = None
    from PIL import Image

from src.documents.types.type_schema import FieldDefinition
from src.gui.modes.structured_form.widgets.base_field_widget import BaseFieldWidget


class StampWidget(BaseFieldWidget):
    """Read-only виджет для отображения изображения штампа.

    Attributes:
        _stamp_data: Бинарные данные изображения штампа.
        _photo_image: Tkinter-совместимое изображение (для предотвращения GC).
        _image_label: Виджет Label для отображения.
        _placeholder_text: Текст placeholder при отсутствии штампа.

    Example:
        >>> widget = StampWidget(parent, field_def, stamp_data=b"PNG...")
        >>> widget.get_value()
        b"PNG..."
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_def: FieldDefinition,
        on_change: Optional[Callable[[str, object], None]] = None,
        on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = None,
        stamp_data: Optional[bytes] = None,
    ) -> None:
        """Инициализация виджета штампа.

        Args:
            parent: Родительский Tkinter виджет.
            field_def: Определение поля из схемы.
            on_change: Callback при изменении значения.
            on_validate: Callback при валидации.
            stamp_data: Бинарные данные изображения штампа.
        """
        super().__init__(parent, field_def, on_change, on_validate)
        self._stamp_data: Optional[bytes] = stamp_data
        self._photo_image: Optional[ImageTk.PhotoImage] = None
        self._image_label: Optional[tk.Label] = None
        self._placeholder_text: str = "⬜ [Штамп не загружен]"
        if stamp_data is not None:
            self._value = stamp_data

    def _create_widget(self) -> tk.Widget:
        """Создаёт виджет для отображения штампа.

        Returns:
            Tkinter Frame с Label для изображения.
        """
        frame = tk.Frame(self._main_frame)
        self._image_label = tk.Label(frame, text=self._placeholder_text)
        self._image_label.pack(anchor=tk.W)
        self._refresh_image()
        return frame

    def _refresh_image(self) -> None:
        """Обновляет отображение изображения или placeholder."""
        if self._image_label is None:
            return

        if self._stamp_data is None or len(self._stamp_data) == 0:
            self._show_placeholder()
            return

        try:
            with Image.open(BytesIO(self._stamp_data)) as img:
                img.thumbnail((200, 100))
                self._photo_image = ImageTk.PhotoImage(img)
                self._image_label.config(image=self._photo_image, text="")
        except (OSError, ValueError, AttributeError, RuntimeError):
            # При любой ошибке декодирования — fallback на placeholder
            self._show_placeholder()

    def _show_placeholder(self) -> None:
        """Отображает placeholder вместо изображения."""
        if self._image_label is not None:
            self._image_label.config(image="", text=self._placeholder_text)
        self._photo_image = None

    def get_value(self) -> Optional[bytes]:
        """Возвращает текущие бинарные данные штампа.

        Returns:
            Бинарные данные изображения или None.
        """
        return self._stamp_data

    def set_value(self, data: Optional[bytes]) -> None:
        """Устанавливает данные штампа и обновляет отображение.

        Args:
            data: Бинарные данные изображения штампа.
        """
        self._stamp_data = data
        super().set_value(data)
        self._refresh_image()

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные штампа.

        Удаляет ссылку на PhotoImage и бинарные данные для предотвращения
        утечки в памяти.
        """
        self._stamp_data = None
        self._photo_image = None
        if self._image_label is not None:
            self._image_label.config(image="", text=self._placeholder_text)
        super().wipe_sensitive_data()

    def _update_font(self) -> None:
        """Обновляет шрифт виджета."""
        # Штамп read-only и не использует текстовый шрифт
        pass


__all__ = ["StampWidget"]
