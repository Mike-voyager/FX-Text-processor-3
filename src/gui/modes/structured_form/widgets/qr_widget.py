"""Виджет поля QR-кода для структурированных форм.

Предоставляет:
- QRWidget: виджет ввода данных и отображения QR-кода

Example:
    >>> widget = QRWidget(
    ...     parent=frame,
    ...     field_def=field_def,
    ...     on_change=on_field_change,
    ... )
    >>> widget.set_value("https://example.com")
"""

from __future__ import annotations

import logging
import tkinter as tk
from io import BytesIO
from typing import Any, Callable, Optional

from src.documents.types.type_schema import FieldDefinition
from src.gui.modes.structured_form.widgets.base_field_widget import BaseFieldWidget

logger: logging.Logger = logging.getLogger(__name__)


class QRWidget(BaseFieldWidget):
    """Виджет QR-кода для структурированной формы.

    Attributes:
        _text_widget: Многострочное поле ввода данных для QR.
        _canvas: Canvas 100×100 для отображения QR.
        _photo_image: Ссылка на PhotoImage для предотвращения GC.
        _version: Версия QR-кода (0 — авто).
        _error_correction: Уровень коррекции ошибок (L, M, Q, H).
        _qr_data: Текущие данные для QR.
        _placeholder: Текст-подсказка.

    Example:
        >>> widget = QRWidget(parent, field_def)
        >>> widget.set_value("Hello World")
    """

    def __init__(
        self,
        parent: tk.Widget,
        field_def: FieldDefinition,
        on_change: Optional[Callable[[str, Any], None]] = None,
        on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = None,
        version: int = 0,
        error_correction: str = "M",
    ) -> None:
        """Инициализация виджета QR-кода.

        Args:
            parent: Родительский Tkinter виджет.
            field_def: Определение поля из схемы.
            on_change: Callback при изменении значения.
            on_validate: Callback при валидации.
            version: Версия QR-кода (0 — автоматическая).
            error_correction: Уровень коррекции ошибок (L, M, Q, H).
        """
        super().__init__(parent, field_def, on_change, on_validate)
        self._version: int = version
        self._error_correction: str = error_correction
        self._text_widget: Optional[tk.Text] = None
        self._canvas: Optional[tk.Canvas] = None
        self._photo_image: Optional[tk.PhotoImage] = None
        self._qr_data: str = ""
        self._placeholder: str = field_def.placeholder or ""
        self._is_placeholder_active: bool = False

    def _create_widget(self) -> tk.Widget:
        """Создаёт виджет QR-кода.

        Returns:
            Frame с полем ввода, Canvas и кнопкой генерации.
        """
        frame = tk.Frame(self._main_frame)

        # Многострочное поле ввода (3 строки)
        self._text_widget = tk.Text(
            frame,
            height=3,
            wrap=tk.WORD,
            font=("Courier", 10),
            relief=tk.SUNKEN,
            borderwidth=1,
            undo=True,
            maxundo=-1,
        )
        self._text_widget.pack(side=tk.TOP, fill=tk.X, expand=False, pady=(0, 4))

        # Установить начальное значение или placeholder
        init_value: str = ""
        if self._field_def.default_value is not None:
            init_value = str(self._field_def.default_value)
            self._text_widget.insert("1.0", init_value)
            self._qr_data = init_value
        elif self._placeholder:
            self._text_widget.insert("1.0", self._placeholder)
            self._text_widget.config(fg="gray")
            self._is_placeholder_active = True

        # Canvas для QR
        self._canvas = tk.Canvas(
            frame,
            width=100,
            height=100,
            bg="white",
            relief=tk.SUNKEN,
            borderwidth=1,
        )
        self._canvas.pack(side=tk.TOP, pady=(0, 4))

        # Кнопка Generate
        generate_btn = tk.Button(
            frame,
            text="Generate",
            command=self._on_generate_click,
            font=("TkDefaultFont", 9),
        )
        generate_btn.pack(side=tk.TOP, anchor=tk.W)

        # Bind события
        self._text_widget.bind("<FocusIn>", self._on_focus_in)
        self._text_widget.bind("<FocusOut>", self._on_focus_out)
        self._text_widget.bind("<KeyRelease>", self._on_value_changed)

        # Readonly
        if self._field_def.readonly:
            self._text_widget.config(state="disabled")
            generate_btn.config(state="disabled")

        # Первичный рендеринг
        self._update_qr_canvas()

        return frame

    def _on_focus_in(self, event: tk.Event[Any]) -> None:
        """Обработчик получения фокуса.

        Args:
            event: Событие фокуса.
        """
        if self._text_widget and self._is_placeholder_active:
            self._text_widget.delete("1.0", tk.END)
            self._text_widget.config(fg="black")
            self._is_placeholder_active = False

    def _on_focus_out(self, event: tk.Event[Any]) -> None:
        """Обработчик потери фокуса.

        Args:
            event: Событие потери фокуса.
        """
        if self._text_widget and self._placeholder:
            current = self._text_widget.get("1.0", tk.END).strip()
            if not current:
                self._text_widget.insert("1.0", self._placeholder)
                self._text_widget.config(fg="gray")
                self._is_placeholder_active = True
        self._update_value_from_widget()

    def _on_value_changed(self, event: tk.Event[Any]) -> None:
        """Обработчик изменения текста.

        Args:
            event: Событие изменения.
        """
        if not self._is_placeholder_active:
            self._update_value_from_widget()

    def _update_value_from_widget(self) -> None:
        """Обновляет внутреннее значение и перерендеривает QR."""
        if self._text_widget is None or self._is_placeholder_active:
            return
        value = self._text_widget.get("1.0", tk.END).rstrip("\n")
        self._qr_data = value
        super().set_value(value)
        self._update_qr_canvas()

    def _on_generate_click(self) -> None:
        """Обработчик нажатия кнопки Generate."""
        if self._text_widget is not None and self._is_placeholder_active:
            self._text_widget.delete("1.0", tk.END)
            self._text_widget.config(fg="black")
            self._is_placeholder_active = False
        data = self._qr_data.strip() if self._qr_data else ""
        if not data:
            data = self._placeholder or ""
        self._update_qr_canvas()

    def _update_qr_canvas(self) -> None:
        """Рендерит QR-код на Canvas 100×100.

        Если доступны qrcode + PIL — генерирует реальный PNG.
        Иначе fallback placeholder с текстом [QR: {preview}].
        """
        if self._canvas is None:
            return

        data = self._qr_data.strip() if self._qr_data else ""
        if not data:
            data = self._placeholder or ""

        self._canvas.delete("all")
        self._photo_image = None

        try:
            self._render_real_qr(data)
        except Exception as e:
            self._render_placeholder(data)
            logger.debug("QR render failed, using placeholder: %s", e)

    def _render_real_qr(self, data: str) -> None:
        """Рендерит реальный QR через qrcode + PIL.

        Args:
            data: Данные для кодирования.
        """
        if self._canvas is None:
            return

        try:
            import qrcode as _qrcode
            from PIL import Image as _PilImage
            from PIL import ImageTk as _PilImageTk
        except ImportError:
            self._render_placeholder(data)
            return

        ec_map = {
            "L": _qrcode.constants.ERROR_CORRECT_L,
            "M": _qrcode.constants.ERROR_CORRECT_M,
            "Q": _qrcode.constants.ERROR_CORRECT_Q,
            "H": _qrcode.constants.ERROR_CORRECT_H,
        }
        ec = ec_map.get(self._error_correction, _qrcode.constants.ERROR_CORRECT_M)
        ver = self._version if self._version > 0 else None

        qr = _qrcode.QRCode(
            version=ver,
            error_correction=ec,
            box_size=4,
            border=1,
        )
        qr.add_data(data)
        qr.make(fit=True)

        img: Any = qr.make_image(fill_color="black", back_color="white")
        img = img.resize((100, 100), _PilImage.Resampling.LANCZOS)

        buffer = BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)

        pil_img = _PilImage.open(buffer)
        photo: tk.PhotoImage = _PilImageTk.PhotoImage(pil_img)
        self._photo_image = photo

        self._canvas.create_image(
            50,
            50,
            image=photo,
            anchor=tk.CENTER,
        )

    def _render_placeholder(self, data: str) -> None:
        """Рендерит placeholder с текстом [QR: {preview}].

        Args:
            data: Данные для отображения в placeholder.
        """
        if self._canvas is None:
            return

        self._canvas.create_rectangle(
            0,
            0,
            100,
            100,
            fill="#f8f9fa",
            outline="#adb5bd",
            width=2,
        )
        preview = data[:20] + ("..." if len(data) > 20 else "")
        self._canvas.create_text(
            50,
            50,
            text=f"[QR: {preview}]",
            fill="#495057",
            font=("Courier", 9),
            anchor=tk.CENTER,
            justify=tk.CENTER,
        )

    def get_value(self) -> str:
        """Возвращает текущее значение.

        Returns:
            Текст данных QR-кода.
        """
        return str(self._value) if self._value is not None else ""

    def set_value(self, value: Any) -> None:
        """Устанавливает значение поля.

        Args:
            value: Новое значение (строка).
        """
        str_value = str(value) if value is not None else ""
        self._qr_data = str_value

        if self._text_widget is not None:
            current = self._text_widget.get("1.0", tk.END).rstrip("\n")
            if current != str_value:
                self._text_widget.delete("1.0", tk.END)
                if str_value:
                    self._text_widget.insert("1.0", str_value)
                    self._text_widget.config(fg="black")
                    self._is_placeholder_active = False
                elif self._placeholder:
                    self._text_widget.insert("1.0", self._placeholder)
                    self._text_widget.config(fg="gray")
                    self._is_placeholder_active = True

        super().set_value(str_value)
        self._update_qr_canvas()

    def validate(self) -> bool:
        """Валидирует значение поля.

        Returns:
            True если значение валидно.
        """
        value = self.get_value()
        if not value and self._field_def.required:
            self._update_validation_state(
                False,
                [f"Поле '{self._field_def.label}' обязательно для заполнения"],
            )
            return False

        if self._field_def.max_length is not None and value:
            if len(value) > self._field_def.max_length:
                self._update_validation_state(
                    False,
                    [f"Текст должен быть не более {self._field_def.max_length} символов"],
                )
                return False

        self._update_validation_state(True, [])
        return True

    def _update_font(self) -> None:
        """Обновляет шрифт виджета."""
        if self._text_widget is not None:
            font_size = max(8, min(14, 14 - (self._cpi - 10) // 2))
            self._text_widget.config(font=("Courier", font_size))

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные."""
        if self._text_widget is not None:
            self._text_widget.delete("1.0", tk.END)
        self._qr_data = ""
        if self._canvas is not None:
            self._canvas.delete("all")
        super().wipe_sensitive_data()

    def focus(self) -> None:
        """Устанавливает фокус на текстовое поле."""
        if self._text_widget is not None:
            self._text_widget.focus_set()


__all__: list[str] = [
    "QRWidget",
]
