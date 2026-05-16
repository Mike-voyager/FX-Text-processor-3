"""Визуальная палитра полей для drag-and-drop и click-to-place.

Provides:
- FieldPaletteWidget: Палитра типов полей для форм-конструктора
- DragMode: Режимы работы палитры (drag_drop, click_place)
- FieldButton: Внутренний виджет кнопки поля

Example:
    >>> from src.documents.types.type_schema import FieldType
    >>> palette = FieldPaletteWidget(
    ...     parent=root,
    ...     on_field_drag_start=lambda ft: print(f"Drag start: {ft}"),
    ...     on_field_drag_end=lambda ft, x, y: print(f"Drop at ({x}, {y})"),
    ...     on_field_place_mode=lambda ft: print(f"Place mode: {ft}"),
    ... )
    >>> palette.mount(parent_frame)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from enum import Enum
from typing import Any, Callable, Optional, cast

from src.documents.constructor.field_palette import (
    FieldPalette,
    PaletteCategory,
    PaletteEntry,
)
from src.documents.types.type_schema import FieldType
from src.gui.components.base.widget import BaseWidget
from src.gui.services.drag_drop_service import (
    DATA_TYPE_FIELD,
    DragData,
    DragDropService,
    DropOperation,
    DropTarget,
)


class DragMode(str, Enum):
    """Режимы работы палитры полей."""

    DRAG_DROP = "drag_drop"
    CLICK_PLACE = "click_place"


class FieldPaletteWidget(BaseWidget):
    """Визуальная палитра полей для drag-and-drop и click-to-place.

    Предоставляет UI для выбора типов полей с двумя режимами:
    - drag_drop: Перетаскивание полей на Canvas
    - click_place: Клик для активации режима размещения

    Attributes:
        MODES: Доступные режимы работы.
        CATEGORIES: Группировка типов полей по категориям.
        ICONS: Emoji иконки для каждого типа поля.

    Example:
        >>> widget = FieldPaletteWidget(
        ...     parent=root,
        ...     on_field_drag_start=on_drag_start,
        ...     on_field_drag_end=on_drag_end,
        ...     on_field_place_mode=on_place_mode,
        ...     mode="drag_drop",
        ... )
        >>> widget.mount(parent_frame)
    """

    MODES: tuple[str, ...] = ("drag_drop", "click_place")
    CATEGORIES: dict[str, tuple[FieldType, ...]] = {
        "BASIC": (
            FieldType.TEXT_INPUT,
            FieldType.MULTI_LINE_TEXT,
            FieldType.DATE_INPUT,
        ),
        "TEXT": (
            FieldType.STATIC_TEXT,
            FieldType.PHONE,
            FieldType.EMAIL,
        ),
        "NUMERIC": (
            FieldType.NUMBER_INPUT,
            FieldType.CURRENCY,
        ),
        "SPECIAL": (
            FieldType.DROPDOWN,
            FieldType.CHECKBOX,
            FieldType.RADIO_GROUP,
            FieldType.TABLE,
            FieldType.CALCULATED,
        ),
        "MEDIA": (
            FieldType.BARCODE,
            FieldType.QR,
            FieldType.SIGNATURE,
            FieldType.STAMP,
        ),
    }

    # Emoji иконки для типов полей
    ICONS: dict[FieldType, str] = {
        FieldType.TEXT_INPUT: "📄",
        FieldType.MULTI_LINE_TEXT: "📃",
        FieldType.NUMBER_INPUT: "#️⃣",
        FieldType.CURRENCY: "💰",
        FieldType.DATE_INPUT: "📅",
        FieldType.CHECKBOX: "☑️",
        FieldType.DROPDOWN: "📋",
        FieldType.RADIO_GROUP: "🔘",
        FieldType.TABLE: "📊",
        FieldType.STATIC_TEXT: "📝",
        FieldType.PHONE: "📞",
        FieldType.EMAIL: "📧",
        FieldType.BARCODE: "📠",
        FieldType.QR: "🔳",
        FieldType.SIGNATURE: "✍️",
        FieldType.STAMP: "🔖",
        FieldType.CALCULATED: "🧮",
    }

    # Соответствие категорий ключам CATEGORIES
    _CATEGORY_KEYS: dict[PaletteCategory, str] = {
        PaletteCategory.BASIC: "BASIC",
        PaletteCategory.TEXT: "TEXT",
        PaletteCategory.NUMERIC: "NUMERIC",
        PaletteCategory.SPECIAL: "SPECIAL",
        PaletteCategory.MEDIA: "MEDIA",
    }

    def __init__(
        self,
        parent: tk.Widget,
        on_field_drag_start: Callable[[FieldType], None],
        on_field_drag_end: Callable[[FieldType, int, int], None],
        on_field_place_mode: Callable[[FieldType], None],
        mode: str = "drag_drop",
        drag_drop_service: Optional[DragDropService] = None,
    ) -> None:
        """Инициализация палитры.

        Args:
            parent: Родительский виджет Tkinter.
            on_field_drag_start: Callback начала drag.
            on_field_drag_end: Callback drop на Canvas (x, y).
            on_field_place_mode: Callback активации click-to-place.
            mode: Режим "drag_drop" или "click_place".
            drag_drop_service: Сервис drag-and-drop для централизованного управления.

        Raises:
            ValueError: Если mode не валиден.
        """
        super().__init__(widget_id="field_palette", controller=None)

        if mode not in self.MODES:
            raise ValueError(f"Неверный mode: {mode}. Допустимые: {self.MODES}")

        self._parent = parent
        self._mode = mode
        self._on_field_drag_start = on_field_drag_start
        self._on_field_drag_end = on_field_drag_end
        self._on_field_place_mode = on_field_place_mode
        self._drag_drop_service = drag_drop_service

        self._drag_data: Optional[DragData] = None
        self._ghost_window: Optional[tk.Toplevel] = None
        self._selected_field_type: Optional[FieldType] = None
        self._drop_target_id: Optional[str] = None

        # UI элементы
        self._mode_frame: Optional[tk.Frame] = None
        self._category_notebook: Optional[tk.Widget] = None
        self._category_frames: dict[str, tk.Frame] = {}
        self._field_buttons: dict[FieldType, tk.Frame] = {}
        self._mode_var: Optional[tk.StringVar] = None
        self._current_category: tk.StringVar = tk.StringVar(value="BASIC")
        self._status_label: Optional[tk.Label] = None

        # Стили
        self._button_width = 8
        self._button_height = 3
        self._grid_padding = 5

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт основной фрейм палитры.

        Args:
            parent: Родительский виджет.

        Returns:
            Frame с палитрой полей.
        """
        # Основной контейнер
        main_frame = tk.Frame(parent, bg="#f5f5f5", padx=5, pady=5)

        # Селектор режима
        self._mode_frame = tk.Frame(main_frame, bg="#f5f5f5")
        self._mode_frame.pack(fill=tk.X, pady=(0, 5))
        self._create_mode_selector()

        # Разделитель
        separator = tk.Frame(main_frame, height=1, bg="#cccccc")
        separator.pack(fill=tk.X, pady=5)

        # Категории с табами
        self._category_notebook = tk.Frame(main_frame, bg="#f5f5f5")
        self._category_notebook.pack(fill=tk.BOTH, expand=True)

        self._create_category_tabs()

        return main_frame

    def _create_mode_selector(self) -> None:
        """Создаёт селектор режима работы."""
        if self._mode_frame is None:
            return

        label = tk.Label(
            self._mode_frame,
            text="Mode:",
            bg="#f5f5f5",
            font=("Helvetica", 9, "bold"),
        )
        label.pack(side=tk.LEFT, padx=(0, 5))

        self._mode_var = tk.StringVar(value=self._mode)

        drag_radio = tk.Radiobutton(
            self._mode_frame,
            text="🖱️ Drag & Drop",
            variable=self._mode_var,
            value="drag_drop",
            bg="#f5f5f5",
            command=self._on_mode_change,
        )
        drag_radio.pack(side=tk.LEFT, padx=2)

        click_radio = tk.Radiobutton(
            self._mode_frame,
            text="👆 Click to Place",
            variable=self._mode_var,
            value="click_place",
            bg="#f5f5f5",
            command=self._on_mode_change,
        )
        click_radio.pack(side=tk.LEFT, padx=2)

    def _on_mode_change(self) -> None:
        """Обработчик смены режима."""
        if self._mode_var is not None:
            new_mode = self._mode_var.get()
            self.set_mode(new_mode)

    def _create_category_tabs(self) -> None:
        """Создаёт табы категорий с кнопками полей."""
        if self._category_notebook is None:
            return

        # Создаём кнопки категорий (как tab-like кнопки)
        tab_frame = tk.Frame(self._category_notebook, bg="#f5f5f5")
        tab_frame.pack(fill=tk.X, pady=(0, 5))

        category_names: dict[str, str] = {
            "BASIC": "📋 Базовые",
            "TEXT": "📝 Текст",
            "NUMERIC": "🔢 Числа",
            "SPECIAL": "⭐ Спец",
            "MEDIA": "🖼️ Медиа",
        }

        for cat_key in self.CATEGORIES:
            btn = tk.Button(
                tab_frame,
                text=category_names.get(cat_key, cat_key),
                relief=tk.FLAT,
                bg="#e0e0e0" if cat_key != "BASIC" else "#4a90d9",
                fg="white" if cat_key == "BASIC" else "black",
                font=("Helvetica", 8),
                command=self._make_category_switcher(cat_key),
            )
            btn.pack(side=tk.LEFT, padx=2)
            setattr(self, f"_tab_{cat_key}", btn)

        # Фреймы для каждой категории
        for cat_key in self.CATEGORIES:
            frame = tk.Frame(
                self._category_notebook,
                bg="#ffffff",
                relief=tk.GROOVE,
                bd=1,
            )
            self._category_frames[cat_key] = frame

            # Создаём кнопки полей
            self._create_field_buttons_for_category(frame, cat_key)

        # Показываем первую категорию
        self._switch_category("BASIC")

    def _make_category_switcher(self, cat_key: str) -> Callable[[], None]:
        """Создаёт функцию для переключения категории.

        Args:
            cat_key: Ключ категории.

        Returns:
            Функция для переключения категории.
        """

        def switch() -> None:
            self._switch_category(cat_key)

        return switch

    def _create_field_buttons_for_category(
        self,
        parent: tk.Frame,
        category: str,
    ) -> None:
        """Создаёт кнопки полей для категории.

        Args:
            parent: Родительский фрейм.
            category: Ключ категории.
        """
        field_types = self.CATEGORIES.get(category, ())

        # Grid layout: 3 columns
        for idx, field_type in enumerate(field_types):
            btn = self._create_field_button(parent, field_type)
            row = idx // 3
            col = idx % 3
            btn.grid(row=row, column=col, padx=3, pady=3, sticky="nsew")

        # Configure grid weights
        for i in range(3):
            parent.grid_columnconfigure(i, weight=1)

    def _create_field_button(
        self,
        parent: tk.Frame,
        field_type: FieldType,
    ) -> tk.Frame:
        """Создаёт кнопку для типа поля.

        Args:
            parent: Родительский фрейм.
            field_type: Тип поля.

        Returns:
            Фрейм с кнопкой поля.
        """
        # Получаем метаданные из палитры
        entry = FieldPalette.get_by_field_type(field_type)
        if entry is None:
            entry = PaletteEntry(
                field_type=field_type,
                category=PaletteCategory.BASIC,
                label=field_type.value,
                label_en=field_type.value,
                description="",
                description_en="",
                icon="default",
            )

        # Контейнер для кнопки
        container = tk.Frame(
            parent,
            bg="#ffffff",
            relief=tk.RAISED,
            bd=1,
            cursor="hand2",
        )

        # Иконка
        icon_label = tk.Label(
            container,
            text=self.ICONS.get(field_type, "📦"),
            font=("Segoe UI Emoji", 24),
            bg="#ffffff",
            cursor="hand2",
        )
        icon_label.pack(pady=(5, 0))

        # Текст
        text_label = tk.Label(
            container,
            text=entry.label,
            font=("Helvetica", 8),
            bg="#ffffff",
            wraplength=70,
            justify=tk.CENTER,
            cursor="hand2",
        )
        text_label.pack(pady=(2, 5))

        # Tooltip (description)
        if entry.description:
            self._create_tooltip(container, entry.description)
            self._create_tooltip(icon_label, entry.description)
            self._create_tooltip(text_label, entry.description)

        # Bindings
        icon_label.bind("<Button-1>", self._make_field_click_handler(field_type))
        icon_label.bind("<ButtonRelease-1>", self._make_field_release_handler(field_type))
        icon_label.bind("<B1-Motion>", self._on_drag_motion)
        icon_label.bind("<Enter>", self._make_hover_handler(container, True))
        icon_label.bind("<Leave>", self._make_hover_handler(container, False))

        text_label.bind("<Button-1>", self._make_field_click_handler(field_type))
        text_label.bind("<ButtonRelease-1>", self._make_field_release_handler(field_type))
        text_label.bind("<B1-Motion>", self._on_drag_motion)
        text_label.bind("<Enter>", self._make_hover_handler(container, True))
        text_label.bind("<Leave>", self._make_hover_handler(container, False))

        container.bind("<Button-1>", self._make_field_click_handler(field_type))
        container.bind("<ButtonRelease-1>", self._make_field_release_handler(field_type))
        container.bind("<B1-Motion>", self._on_drag_motion)
        container.bind("<Enter>", self._make_hover_handler(container, True))
        container.bind("<Leave>", self._make_hover_handler(container, False))

        self._field_buttons[field_type] = container
        return container

    def _make_field_click_handler(self, field_type: FieldType) -> Callable[[tk.Event[Any]], None]:
        """Создаёт обработчик клика для типа поля.

        Args:
            field_type: Тип поля.

        Returns:
            Обработчик события.
        """

        def handler(event: tk.Event[Any]) -> None:
            self._on_field_click(field_type, event)

        return handler

    def _make_field_release_handler(self, field_type: FieldType) -> Callable[[tk.Event[Any]], None]:
        """Создаёт обработчик отпускания кнопки для типа поля.

        Args:
            field_type: Тип поля.

        Returns:
            Обработчик события.
        """

        def handler(event: tk.Event[Any]) -> None:
            self._on_field_release(field_type, event)

        return handler

    def _make_hover_handler(
        self, container: tk.Frame, hover: bool
    ) -> Callable[[tk.Event[Any]], None]:
        """Создаёт обработчик hover для контейнера.

        Args:
            container: Контейнер кнопки.
            hover: True при наведении.

        Returns:
            Обработчик события.
        """

        def handler(event: tk.Event[Any]) -> None:
            self._on_button_hover(container, hover)

        return handler

    def _create_tooltip(self, widget: tk.Widget, text: str) -> None:
        """Создаёт tooltip для виджета.

        Args:
            widget: Виджет для tooltip.
            text: Текст подсказки.
        """
        tooltip_window: Optional[tk.Toplevel] = None

        def show_tooltip(event: tk.Event[Any]) -> None:
            nonlocal tooltip_window
            x = widget.winfo_rootx() + 20
            y = widget.winfo_rooty() + 20

            tooltip_window = tk.Toplevel(widget)
            tooltip_window.wm_overrideredirect(True)
            tooltip_window.wm_geometry(f"+{x}+{y}")

            label = tk.Label(
                tooltip_window,
                text=text,
                bg="#ffffcc",
                relief=tk.SOLID,
                bd=1,
                font=("Helvetica", 9),
                padx=5,
                pady=2,
            )
            label.pack()

        def hide_tooltip(event: tk.Event[Any]) -> None:
            nonlocal tooltip_window
            if tooltip_window is not None:
                try:
                    tooltip_window.destroy()
                except tk.TclError:
                    pass
                tooltip_window = None

        widget.bind("<Enter>", show_tooltip, add="+")
        widget.bind("<Leave>", hide_tooltip, add="+")

    def _on_button_hover(self, container: tk.Frame, hover: bool) -> None:
        """Обработчик hover эффекта на кнопку.

        Args:
            container: Контейнер кнопки.
            hover: True если курсор наведён.
        """
        if hover:
            container.config(bg="#e8f4ff")
            for child in container.winfo_children():
                if isinstance(child, (tk.Label, tk.Frame)):
                    child.config(bg="#e8f4ff")
        else:
            # Проверяем, не выбрана ли эта кнопка
            is_selected = False
            for ft, btn in self._field_buttons.items():
                if btn == container and ft == self._selected_field_type:
                    is_selected = True
                    break

            bg_color = "#d0e8ff" if is_selected else "#ffffff"
            container.config(bg=bg_color)
            for child in container.winfo_children():
                if isinstance(child, (tk.Label, tk.Frame)):
                    child.config(bg=bg_color)

    def _switch_category(self, category: str) -> None:
        """Переключает отображаемую категорию.

        Args:
            category: Ключ категории для отображения.
        """
        if category not in self._category_frames:
            return

        self._current_category.set(category)

        # Обновляем цвета табов
        for cat_key in self.CATEGORIES:
            tab_btn = getattr(self, f"_tab_{cat_key}", None)
            if isinstance(tab_btn, tk.Button):
                if cat_key == category:
                    tab_btn.config(bg="#4a90d9", fg="white", relief=tk.SUNKEN)
                else:
                    tab_btn.config(bg="#e0e0e0", fg="black", relief=tk.FLAT)

        # Прячем все фреймы
        for frame in self._category_frames.values():
            frame.pack_forget()

        # Показываем выбранный
        self._category_frames[category].pack(fill=tk.BOTH, expand=True)

    def _on_field_click(self, field_type: FieldType, event: tk.Event[Any]) -> None:
        """Обработчик нажатия на кнопку поля.

        Args:
            field_type: Тип поля.
            event: Событие мыши.
        """
        if self._mode == "click_place":
            self._on_click_place_activate(field_type)
        else:
            # Начинаем drag
            self._start_drag(field_type, event)

    def _on_field_release(self, field_type: FieldType, event: tk.Event[Any]) -> None:
        """Обработчик отпускания кнопки мыши.

        Args:
            field_type: Тип поля.
            event: Событие мыши.
        """
        if self._mode == "drag_drop" and self._drag_data is not None:
            self._on_drag_end(event)

    def _on_drag_start(self, event: tk.Event, field_type: str) -> None:
        """Обработчик начала drag операции (сервис-ориентированный).

        Args:
            event: Событие мыши.
            field_type: Тип перетаскиваемого поля как строка.
        """
        if self._drag_drop_service:
            # Use centralized service
            drag_data = DragData(
                source_window_id=self._get_window_id(),
                data_type=DATA_TYPE_FIELD,
                data={"field_type": field_type, "from_palette": True},
                preview_text=f"Field: {field_type}",
                allowed_operations=[DropOperation.COPY],
            )
            self._drag_drop_service.start_drag(self._get_window_id(), drag_data)
        else:
            # Fallback to legacy implementation
            self._legacy_drag_start(event, field_type)

    def _get_window_id(self) -> str:
        """Возвращает идентификатор окна палитры.

        Returns:
            Уникальный идентификатор окна.
        """
        return f"field_palette_{id(self)}"

    def _legacy_drag_start(self, event: tk.Event, field_type_str: str) -> None:
        """Legacy реализация начала drag.

        Args:
            event: Событие мыши.
            field_type_str: Тип поля как строка.
        """
        try:
            field_type = FieldType(field_type_str)
        except ValueError:
            field_type = FieldType.TEXT_INPUT
        self._start_drag(field_type, event)

    def _start_drag(self, field_type: FieldType, event: tk.Event[Any]) -> None:
        """Начинает операцию drag (legacy).

        Args:
            field_type: Тип перетаскиваемого поля.
            event: Событие мыши.
        """
        self._drag_data = DragData(
            field_type=field_type,
            start_x=event.x_root,
            start_y=event.y_root,
        )

        # Создаём ghost window
        self._create_ghost_window(field_type, event.x_root, event.y_root)

        # Callback
        self._on_field_drag_start(field_type)

    def _create_ghost_window(self, field_type: FieldType, x: int, y: int) -> None:
        """Создаёт окно-призрак для drag.

        Args:
            field_type: Тип поля.
            x: X координата.
            y: Y координата.
        """
        entry = FieldPalette.get_by_field_type(field_type)
        label_text = entry.label if entry else field_type.value
        icon = self.ICONS.get(field_type, "📦")

        self._ghost_window = tk.Toplevel(self._parent)
        self._ghost_window.wm_overrideredirect(True)
        self._ghost_window.attributes("-alpha", 0.7)
        self._ghost_window.attributes("-topmost", True)

        # Контент ghost window
        frame = tk.Frame(
            self._ghost_window,
            bg="#4a90d9",
            padx=10,
            pady=10,
            relief=tk.RAISED,
            bd=2,
        )
        frame.pack()

        icon_label = tk.Label(
            frame,
            text=icon,
            font=("Segoe UI Emoji", 32),
            bg="#4a90d9",
        )
        icon_label.pack()

        text_label = tk.Label(
            frame,
            text=label_text,
            font=("Helvetica", 10, "bold"),
            bg="#4a90d9",
            fg="white",
        )
        text_label.pack()

        # Позиционируем
        self._ghost_window.wm_geometry(f"+{x - 40}+{y - 40}")

    def _on_drag_motion(self, event: tk.Event[Any]) -> None:
        """Обработчик движения drag.

        Args:
            event: Событие мыши.
        """
        if self._ghost_window is not None:
            x = event.x_root - 40
            y = event.y_root - 40
            self._ghost_window.wm_geometry(f"+{x}+{y}")

    def _on_drag_end(self, event: tk.Event[Any]) -> None:
        """Обработчик окончания drag.

        Args:
            event: Событие мыши.
        """
        if self._drag_data is None:
            return

        # Получаем canvas под курсором
        canvas = self._find_canvas_at(event.x_root, event.y_root)

        if canvas is not None:
            # Вычисляем координаты относительно Canvas
            x = canvas.winfo_rootx()
            y = canvas.winfo_rooty()
            rel_x = event.x_root - x
            rel_y = event.y_root - y

            field_type = cast(FieldType, self._drag_data.field_type)
            self._on_field_drag_end(field_type, rel_x, rel_y)

        # Очищаем
        self._cleanup_drag()

    def _find_canvas_at(self, x: int, y: int) -> Optional[tk.Widget]:
        """Находит Canvas виджет под указанными координатами.

        Args:
            x: X координата экрана.
            y: Y координата экрана.

        Returns:
            Canvas виджет или None.
        """
        # Простая реализация - проверяем координаты
        widget: Any = self._parent.winfo_containing(x, y)

        # Ищем Canvas вверх по иерархии
        current: Any = widget
        while current is not None and isinstance(current, tk.Widget):
            if current.winfo_class() == "Canvas":
                result: tk.Widget = current
                return result
            try:
                parent_name = current.winfo_parent()
                if parent_name:
                    parent_widget = current.nametowidget(parent_name)
                    if isinstance(parent_widget, tk.Widget):
                        current = parent_widget
                    else:
                        break
                else:
                    break
            except (tk.TclError, AttributeError):
                break

        return None

    def _cleanup_drag(self) -> None:
        """Очищает ресурсы drag."""
        if self._ghost_window is not None:
            try:
                self._ghost_window.destroy()
            except tk.TclError:
                pass
            self._ghost_window = None

        self._drag_data = None

    def register_as_drop_target(self, form_canvas: tk.Widget) -> None:
        """Register form canvas as drop target for field drops.

        Args:
            form_canvas: Canvas виджет для регистрации как целевой.
        """
        if self._drag_drop_service:
            target = DropTarget(
                target_id=f"{self.widget_id}_canvas",
                widget=form_canvas,
                accepted_types=[DATA_TYPE_FIELD],
                accepted_operations=[DropOperation.COPY],
                on_drop=self._on_field_dropped,
            )
            self._drop_target_id = self._drag_drop_service.register_drop_target(form_canvas, target)

    def _on_field_dropped(
        self, drag_data: DragData, target_widget: tk.Widget, event: tk.Event[Any]
    ) -> None:
        """Обработчик drop поля на целевой виджет.

        Args:
            drag_data: Данные drag операции.
            target_widget: Целевой виджет.
            event: Событие мыши.
        """
        field_type_data = drag_data.data.get("field_type") if drag_data.data else None
        if field_type_data:
            try:
                field_type = FieldType(field_type_data)
                # Вычисляем координаты относительно Canvas
                x = target_widget.winfo_rootx()
                y = target_widget.winfo_rooty()
                rel_x = event.x_root - x
                rel_y = event.y_root - y
                self._on_field_drag_end(field_type, rel_x, rel_y)
            except ValueError:
                pass

    def _on_click_place_activate(self, field_type: FieldType) -> None:
        """Активирует режим click-to-place.

        Args:
            field_type: Тип поля для размещения.
        """
        self._selected_field_type = field_type

        # Подсвечиваем выбранную кнопку
        self._update_selection_highlight()

        # Callback
        self._on_field_place_mode(field_type)

    def _update_selection_highlight(self) -> None:
        """Обновляет подсветку выбранной кнопки."""
        for ft, btn in self._field_buttons.items():
            bg_color = "#d0e8ff" if ft == self._selected_field_type else "#ffffff"
            btn.config(bg=bg_color)
            for child in btn.winfo_children():
                if isinstance(child, (tk.Label, tk.Frame)):
                    child.config(bg=bg_color)

    def on_canvas_click_place(self, x: int, y: int) -> None:
        """Обработчик клика на Canvas в режиме place.

        Вызывается внешним контроллером при клике на Canvas.

        Args:
            x: X координата на Canvas.
            y: Y координата на Canvas.
        """
        if self._selected_field_type is None:
            return

        # Создаём поле
        self._on_field_drag_end(self._selected_field_type, x, y)

        # Сбрасываем режим
        self._selected_field_type = None
        self._update_selection_highlight()

        # Возвращаемся в drag_drop если нужно
        if self._mode == "click_place":
            self.set_mode("drag_drop")
            if self._mode_var is not None:
                self._mode_var.set("drag_drop")

    def set_mode(self, mode: str) -> None:
        """Устанавливает режим работы.

        Args:
            mode: "drag_drop" или "click_place".

        Raises:
            ValueError: Если mode не валиден.
        """
        if mode not in self.MODES:
            raise ValueError(f"Неверный mode: {mode}. Допустимые: {self.MODES}")

        self._mode = mode

        # Обновляем mode_var если он есть
        if hasattr(self, "_mode_var") and self._mode_var is not None:
            self._mode_var.set(mode)

        # Обновляем UI
        if mode == "click_place":
            # Показываем инструкцию
            self._show_mode_indicator("👆 Click to Place: выберите поле и кликните на Canvas")
        else:
            self._show_mode_indicator("")

    def _show_mode_indicator(self, text: str) -> None:
        """Показывает индикатор текущего режима.

        Args:
            text: Текст индикатора.
        """
        if self._status_label is not None:
            self._status_label.config(text=text)

    def get_current_category(self) -> str:
        """Возвращает текущую категорию.

        Returns:
            Ключ текущей категории.
        """
        return self._current_category.get()

    def get_selected_field_type(self) -> Optional[FieldType]:
        """Возвращает выбранный тип поля.

        Returns:
            Тип поля или None.
        """
        return self._selected_field_type

    def clear_selection(self) -> None:
        """Очищает выбор поля."""
        self._selected_field_type = None
        self._update_selection_highlight()

    def _cleanup(self) -> None:
        """Очищает ресурсы при демонтировании."""
        self._cleanup_drag()
        self._field_buttons.clear()
        self._category_frames.clear()


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "FieldPaletteWidget",
    "DragMode",
    "DragData",
]
