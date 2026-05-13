"""Виджет поля подписи (Signature).

Предоставляет:
- SignatureWidget: холст для рисования подписи мышью с сохранением в bytes

Example:
    >>> widget = SignatureWidget(
    ...     parent=frame,
    ...     field_def=field_def,
    ...     on_change=on_field_change
    ... )
    >>> widget.set_value(b"\\x89PNG...")
    >>> widget.get_value()[:8] == b"\\x89PNG\\r\\n\\x1a\\n"
    True
"""

from __future__ import annotations

import io
import logging
import tkinter as tk
from typing import Any, Callable, Optional

try:
    import PIL.ImageTk as ImageTk
except ImportError:
    ImageTk = None
from PIL import Image

from src.documents.types.type_schema import FieldDefinition
from src.gui.modes.structured_form.widgets.base_field_widget import BaseFieldWidget

MAX_SIGNATURE_BYTES: int = 256_000


class SignatureWidget(BaseFieldWidget):
    """Виджет поля цифровой подписи (рисование мышью).

    Attributes:
        _canvas: Tkinter Canvas для рисования.
        _clear_button: Кнопка очистки холста.
        _last_x: Последняя координата X при рисовании.
        _last_y: Последняя координата Y при рисовании.
        _signature_data: Данные подписи в формате bytes (PNG).
        _photo: Ссылка на PhotoImage для предотвращения GC.

    Example:
        >>> widget = SignatureWidget(parent, field_def)
        >>> widget.set_value(b"\\x89PNG...")
        >>> widget.get_value()[:8] == b"\\x89PNG\\r\\n\\x1a\\n"
        True
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_def: FieldDefinition,
        on_change: Optional[Callable[[str, Any], None]] = None,
        on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = None,
    ) -> None:
        """Инициализация виджета подписи.

        Args:
            parent: Родительский Tkinter виджет.
            field_def: Определение поля из схемы.
            on_change: Callback при изменении значения.
            on_validate: Callback при валидации.
        """
        super().__init__(parent, field_def, on_change, on_validate)

        self._canvas: Optional[tk.Canvas] = None
        self._clear_button: Optional[tk.Button] = None
        self._last_x: Optional[int] = None
        self._last_y: Optional[int] = None
        self._signature_data: Optional[bytes] = None
        self._photo: Optional[ImageTk.PhotoImage] = None

    def _create_widget(self) -> tk.Widget:
        """Создаёт виджет поля подписи.

        Returns:
            Tkinter Frame с Canvas и кнопкой очистки.
        """
        frame = tk.Frame(self._main_frame)

        # Canvas для рисования подписи
        self._canvas = tk.Canvas(
            frame,
            width=200,
            height=100,
            bg="white",
            highlightthickness=1,
            highlightbackground="gray",
        )
        self._canvas.pack(side=tk.LEFT, padx=(0, 8))

        # Кнопка очистки
        self._clear_button = tk.Button(
            frame,
            text="Clear",
            command=self._clear,
        )
        self._clear_button.pack(side=tk.LEFT, anchor=tk.N)

        # Readonly / активный режим
        if self._field_def.readonly:
            self._clear_button.config(state="disabled")
            if self._signature_data:
                self._show_image(self._signature_data)
        else:
            self._canvas.bind("<Button-1>", self._on_draw_start)
            self._canvas.bind("<B1-Motion>", self._on_draw)
            self._canvas.bind("<ButtonRelease-1>", self._on_draw_end)

        return frame

    # ------------------------------------------------------------------
    # Обработчики рисования
    # ------------------------------------------------------------------

    def _on_draw_start(self, event: tk.Event[tk.Misc]) -> None:
        """Фиксирует начальную точку рисования.

        Args:
            event: Событие нажатия левой кнопки мыши.
        """
        self._last_x = event.x
        self._last_y = event.y

    def _on_draw(self, event: tk.Event[tk.Misc]) -> None:
        """Рисует линию от предыдущей точки к текущей.

        Args:
            event: Событие движения мыши с зажатой левой кнопкой.
        """
        if self._canvas is None:
            return
        if self._last_x is not None and self._last_y is not None:
            self._canvas.create_line(
                self._last_x,
                self._last_y,
                event.x,
                event.y,
                width=2,
                fill="black",
                smooth=True,
            )
        self._last_x = event.x
        self._last_y = event.y

    def _on_draw_end(self, event: tk.Event[tk.Misc]) -> None:
        """Завершает рисование и сохраняет данные.

        Args:
            event: Событие отпускания левой кнопки мыши.
        """
        self._last_x = None
        self._last_y = None
        self._update_value_from_canvas()

    # ------------------------------------------------------------------
    # Значение
    # ------------------------------------------------------------------

    def get_value(self) -> bytes:
        """Возвращает текущее значение подписи.

        Returns:
            Данные изображения подписи в формате PNG (bytes).
            Результат обрезается до MAX_SIGNATURE_BYTES.
        """
        data = self._canvas_to_bytes()
        if len(data) > MAX_SIGNATURE_BYTES:
            data = data[:MAX_SIGNATURE_BYTES]
        self._signature_data = data
        return data

    def set_value(self, value: Any) -> None:
        """Устанавливает значение подписи из bytes.

        Args:
            value: Данные изображения подписи (bytes) или None.
        """
        if not isinstance(value, bytes):
            return

        self._signature_data = value
        self._value = value
        if self._canvas is not None:
            self._show_image(value)

        if self._on_change is not None:
            self._on_change(self.field_id, value)

    # ------------------------------------------------------------------
    # Валидация
    # ------------------------------------------------------------------

    def validate(self) -> bool:
        """Проверяет, что подпись присутствует если поле обязательное.

        Returns:
            True если значение валидно, False иначе.
        """
        if self._field_def.required:
            data = self.get_value()
            if not data:
                self._update_validation_state(
                    False,
                    [f"Поле '{self._field_def.label}' обязательно для заполнения"],
                )
                return False

        self._update_validation_state(True, [])
        return True

    # ------------------------------------------------------------------
    # Очистка и безопасность
    # ------------------------------------------------------------------

    def _clear(self) -> None:
        """Очищает холст и внутренние данные подписи."""
        if self._canvas is not None:
            self._canvas.delete("all")
        self._signature_data = None
        self._value = None
        if self._on_change is not None:
            self._on_change(self.field_id, b"")

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные подписи.

        Security:
            Удаляет изображение с холста, обнуляет буферы bytes в памяти.
        """
        self._clear()
        self._last_x = None
        self._last_y = None
        self._photo = None
        super().wipe_sensitive_data()

    # ------------------------------------------------------------------
    # Внутренние методы
    # ------------------------------------------------------------------

    def _update_value_from_canvas(self) -> None:
        """Сохраняет текущее состояние холста во внутреннее значение."""
        data = self._canvas_to_bytes()
        self._signature_data = data
        self._value = data
        if self._on_change is not None:
            self._on_change(self.field_id, data)

    def _canvas_to_bytes(self) -> bytes:
        """Конвертирует содержимое Canvas в PNG bytes.

        Returns:
            Данные изображения в формате PNG.
        """
        if self._canvas is None:
            return b""

        try:
            ps_data = self._canvas.postscript(colormode="mono")  # type: ignore[no-untyped-call]
            img = Image.open(io.BytesIO(ps_data.encode("utf-8")))
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            return buf.getvalue()
        except (OSError, ValueError, AttributeError, RuntimeError):
            # При ошибке рендеринга возвращаем пустые данные
            return b""

    def _show_image(self, data: bytes) -> None:
        """Отображает изображение из bytes на холсте.

        Args:
            data: Данные изображения (PNG/JPG/etc).
        """
        if self._canvas is None or not data:
            return

        try:
            img = Image.open(io.BytesIO(data))
            img.thumbnail((200, 100))
            self._photo = ImageTk.PhotoImage(img)
            self._canvas.delete("all")
            self._canvas.create_image(0, 0, anchor=tk.NW, image=self._photo)
        except (OSError, ValueError, AttributeError, RuntimeError) as e:
            logging.getLogger(__name__).debug("Exception ignored: %s", e)

    def _update_font(self) -> None:
        """Обновляет шрифт виджета.

        Note:
            Для SignatureWidget не применимо.
        """
        pass

    def focus(self) -> None:
        """Устанавливает фокус на холст."""
        if self._canvas is not None:
            self._canvas.focus_set()


__all__: list[str] = [
    "MAX_SIGNATURE_BYTES",
    "SignatureWidget",
]
