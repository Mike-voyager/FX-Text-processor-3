"""PropertyPanel для Form Designer (Phase 5).

Панель свойств поля формы — правая панель в DesignerTab.
Реализует редактирование всех свойств выбранного поля с real-time валидацией.

Features:
    - Collapsible sections (Basic, Position, Validation, Appearance, Advanced)
    - Two-way binding с FormFieldWidget
    - Immediate validation
    - Real-time update поля на canvas
    - Field delete/duplicate actions

Example:
    >>> from src.gui.form_designer.property_panel import PropertyPanel
    >>> panel = PropertyPanel(
    ...     parent=right_frame,
    ...     on_property_change=on_prop_change,
    ...     on_field_delete=on_delete,
    ...     on_field_duplicate=on_duplicate,
    ... )
    >>> panel.mount(right_frame)
    >>> panel.bind_to_field(selected_field)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import re
import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING, Any, Callable, Final, Literal, Optional, Union

from src.documents.types.type_schema import FieldType
from src.gui.components.base.widget import BaseWidget
from src.gui.components.tooltip import TooltipManager
from src.gui.core.protocols import ControllerProtocol
from src.gui.form_designer.dialogs import (
    ConditionsEditorDialog,
    FieldOption,
    OptionsEditorDialog,
)
from src.gui.renderers.form_canvas import FormFieldWidget
from src.model.enums import CharactersPerInch, FontFamily, LinesPerInch

# =============================================================================
# PROPERTY HELP TEXTS (Russian)
# =============================================================================

PROPERTY_HELP_TEXTS: Final[dict[str, str]] = {
    "field_id": "Уникальный идентификатор поля в форме. Используется для ссылок в условиях.",
    "label_ru": "Отображаемая метка поля на русском языке.",
    "label_en": "Отображаемая метка поля на английском языке.",
    "field_type": "Тип поля: TEXT_INPUT, DROPDOWN, CHECKBOX, etc. Определяет виджет ввода.",
    "required": "Обязательное поле. Форма не может быть сохранена без заполнения этого поля.",
    "help_text": "Подсказка, отображаемая под полем для помощи пользователю.",
    "placeholder": "Текст-заполнитель, показываемый в пустом поле.",
    "default_value": "Значение по умолчанию при создании новой формы.",
    "validation_pattern": "Регулярное выражение для валидации ввода.",
    "min_value": "Минимальное значение (для числовых полей).",
    "max_value": "Максимальное значение (для числовых полей).",
    "conditions": "Условия видимости, активности и режима только чтения.",
    "options": "Список опций для DROPDOWN и RADIO_GROUP полей.",
    "x": "Позиция поля по горизонтали (колонка).",
    "y": "Позиция поля по вертикали (строка).",
    "width": "Ширина поля в колонках.",
    "height": "Высота поля в строках.",
    "page": "Номер страницы, на которой размещено поле.",
    "font_family": "Семейство шрифта (Roman, Sans Serif, Courier).",
    "cpi": "Символов на дюйм (плотность горизонтальной печати).",
    "lpi": "Строк на дюйм (плотность вертикальной печати).",
    "label": "Отображаемая метка поля.",
    "autocomplete_source": "Источник данных для автозаполнения поля.",
}

if TYPE_CHECKING:
    from tkinter import Event

# =============================================================================
# SECTION FRAME (Collapsible)
# =============================================================================


class SectionFrame(tk.Frame):
    """Сворачиваемая секция для группировки свойств.

    Attributes:
        title: Заголовок секции.
        is_collapsed: Состояние сворачивания.
        content_frame: Фрейм с содержимым секции.
    """

    COLLAPSED_ICON: Final[str] = "▶"
    EXPANDED_ICON: Final[str] = "▼"

    def __init__(
        self,
        parent: tk.Widget,
        title: str,
        is_collapsed: bool = False,
        **kwargs: Any,
    ) -> None:
        """Инициализация секции.

        Args:
            parent: Родительский виджет.
            title: Заголовок секции.
            is_collapsed: Начальное состояние сворачивания.
            **kwargs: Дополнительные аргументы для Frame.
        """
        super().__init__(parent, bg="#e8e8e8", **kwargs)

        self._title: str = title
        self._is_collapsed: bool = is_collapsed

        # Header with toggle button
        self._header_frame: tk.Frame = tk.Frame(self, bg="#d8d8d8")
        self._header_frame.pack(fill=tk.X, pady=(2, 0))

        self._toggle_btn: tk.Label = tk.Label(
            self._header_frame,
            text=f"{self.EXPANDED_ICON} {title}",
            bg="#d8d8d8",
            font=("Arial", 9, "bold"),
            anchor=tk.W,
            cursor="hand2",
        )
        self._toggle_btn.pack(fill=tk.X, padx=2, pady=2)
        self._toggle_btn.bind("<Button-1>", self._on_toggle)

        # Content frame
        self._content_frame: tk.Frame = tk.Frame(self, bg="#e8e8e8")
        if not is_collapsed:
            self._content_frame.pack(fill=tk.X, padx=5, pady=5)

    def _on_toggle(self, event: Event[tk.Label] | None) -> None:
        """Обработчик клика на заголовок секции."""
        _ = event
        self._is_collapsed = not self._is_collapsed

        if self._is_collapsed:
            self._toggle_btn.config(text=f"{self.COLLAPSED_ICON} {self._title}")
            self._content_frame.pack_forget()
        else:
            self._toggle_btn.config(text=f"{self.EXPANDED_ICON} {self._title}")
            self._content_frame.pack(fill=tk.X, padx=5, pady=5)

    @property
    def content(self) -> tk.Frame:
        """Возвращает фрейм содержимого для добавления виджетов.

        Returns:
            Фрейм для размещения элементов секции.
        """
        return self._content_frame

    def expand(self) -> None:
        """Разворачивает секцию."""
        if self._is_collapsed:
            self._on_toggle(None)

    def collapse(self) -> None:
        """Сворачивает секцию."""
        if not self._is_collapsed:
            self._on_toggle(None)


# =============================================================================
# PROPERTY PANEL
# =============================================================================


class PropertyPanel(BaseWidget):
    """Панель свойств поля (справа в DesignerTab).

    Реализует редактирование свойств выбранного поля формы.
    Использует двустороннее связывание с FormFieldWidget.

    Attributes:
        SECTIONS: Список названий секций.
        BASIC_PROPS: Свойства в секции Basic.
        POSITION_PROPS: Свойства в секции Position.
        VALIDATION_PROPS: Свойства в секции Validation.
        APPEARANCE_PROPS: Свойства в секции Appearance.
        ADVANCED_PROPS: Свойства в секции Advanced.

    Example:
        >>> panel = PropertyPanel(
        ...     parent=right_frame,
        ...     on_property_change=lambda prop, val: print(f"{prop}={val}"),
        ...     on_field_delete=lambda: print("Delete"),
        ...     on_field_duplicate=lambda: print("Duplicate"),
        ... )
        >>> panel.mount(right_frame)
        >>> panel.bind_to_field(field_widget)
    """

    # Sections
    SECTIONS: Final[list[str]] = ["Basic", "Position", "Validation", "Appearance", "Advanced"]

    # Properties per section
    BASIC_PROPS: Final[list[str]] = ["field_id", "label", "label_ru", "field_type"]
    POSITION_PROPS: Final[list[str]] = ["x", "y", "width", "height", "page"]
    VALIDATION_PROPS: Final[list[str]] = [
        "required",
        "validation_pattern",
        "min_value",
        "max_value",
        "default_value",
    ]
    APPEARANCE_PROPS: Final[list[str]] = ["font_family", "cpi", "lpi"]
    ADVANCED_PROPS: Final[list[str]] = ["conditions", "autocomplete_source", "options"]

    # UI Constants
    LABEL_WIDTH: Final[int] = 12
    ENTRY_WIDTH: Final[int] = 20
    SPIN_WIDTH: Final[int] = 8

    def __init__(
        self,
        parent: tk.Widget,
        on_property_change: Callable[[str, Any], None],
        on_field_delete: Callable[[], None],
        on_field_duplicate: Callable[[], None],
        controller: Optional[ControllerProtocol] = None,
        tooltip_manager: Optional[TooltipManager] = None,
    ) -> None:
        """Инициализация PropertyPanel.

        Args:
            parent: Родительский Tkinter виджет.
            on_property_change: Callback изменения свойства (prop_name, new_value).
            on_field_delete: Callback удаления поля.
            on_field_duplicate: Callback дублирования поля.
            controller: Опциональная ссылка на контроллер.
            tooltip_manager: Опциональный менеджер тултипов для help текстов.
        """
        super().__init__(widget_id="property_panel", controller=controller)

        self._parent: tk.Widget = parent
        self._on_property_change: Callable[[str, Any], None] = on_property_change
        self._on_field_delete: Callable[[], None] = on_field_delete
        self._on_field_duplicate: Callable[[], None] = on_field_duplicate

        # Tooltip manager for help texts (optional, creates local instance if not provided)
        self._tooltip_manager: TooltipManager = tooltip_manager or TooltipManager.get_instance()

        self._bound_field: Optional[FormFieldWidget] = None
        self._is_updating: bool = False  # Prevent recursive updates

        # UI elements dictionary: prop_name -> widget/var
        self._prop_widgets: dict[str, Union[tk.Widget, tk.Variable]] = {}
        self._prop_vars: dict[str, tk.Variable] = {}
        self._sections: dict[str, SectionFrame] = {}

        # Tk widget references
        self._main_frame: Optional[tk.Frame] = None
        self._scroll_canvas: Optional[tk.Canvas] = None
        self._content_frame: Optional[tk.Frame] = None
        self._buttons_frame: Optional[tk.Frame] = None

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт фактический Tkinter виджет.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный корневой Frame.
        """
        # Main frame with scrollable content
        self._main_frame = tk.Frame(parent, bg="#e8e8e8")

        # Create scrollable canvas
        self._create_scrollable_content()

        # Create sections
        self._create_sections()

        # Create action buttons
        self._create_action_buttons()

        return self._main_frame

    def _create_scrollable_content(self) -> None:
        """Создаёт scrollable область для секций."""
        if self._main_frame is None:
            return

        # Scrollable canvas
        self._scroll_canvas = tk.Canvas(
            self._main_frame,
            bg="#e8e8e8",
            highlightthickness=0,
        )
        self._scroll_canvas.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # Scrollbar
        scrollbar = ttk.Scrollbar(
            self._main_frame,
            orient=tk.VERTICAL,
            command=self._scroll_canvas.yview,
        )
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._scroll_canvas.configure(yscrollcommand=scrollbar.set)

        # Content frame inside canvas
        self._content_frame = tk.Frame(self._scroll_canvas, bg="#e8e8e8")
        self._canvas_window = self._scroll_canvas.create_window(
            (0, 0),
            window=self._content_frame,
            anchor=tk.NW,
            width=180,  # Fixed width for property panel
        )

        # Update scroll region on resize
        self._content_frame.bind(
            "<Configure>",
            lambda e: self._scroll_canvas.configure(scrollregion=self._scroll_canvas.bbox("all")),  # type: ignore[union-attr]
        )

    def _create_sections(self) -> None:
        """Создаёт все секции свойств."""
        if self._content_frame is None:
            return

        # Header
        header = tk.Label(
            self._content_frame,
            text="Свойства",
            bg="#d0d0d0",
            font=("Arial", 10, "bold"),
            anchor=tk.W,
            padx=5,
        )
        header.pack(fill=tk.X, pady=(0, 5))

        # Create sections
        self._create_basic_section()
        self._create_position_section()
        self._create_validation_section()
        self._create_appearance_section()
        self._create_advanced_section()

    def _create_basic_section(self) -> None:
        """Создаёт секцию Basic (field_id, label, label_ru, field_type)."""
        if self._content_frame is None:
            return
        section = SectionFrame(self._content_frame, "Basic")
        section.pack(fill=tk.X, padx=2, pady=2)
        self._sections["Basic"] = section

        content = section.content

        # Field ID
        self._create_entry_row(content, "field_id", "Field ID:", self._on_field_id_change)

        # Label
        self._create_entry_row(content, "label", "Label:", self._on_label_change)

        # Label (RU)
        self._create_entry_row(content, "label_ru", "Label (RU):", self._on_label_ru_change)

        # Type (readonly combobox)
        self._create_combobox_row(
            content,
            "field_type",
            "Type:",
            [ft.value for ft in FieldType],
            readonly=True,
            callback=self._on_type_change,
        )

    def _create_position_section(self) -> None:
        """Создаёт секцию Position (x, y, width, height, page)."""
        if self._content_frame is None:
            return
        section = SectionFrame(self._content_frame, "Position")
        section.pack(fill=tk.X, padx=2, pady=2)
        self._sections["Position"] = section

        content = section.content

        # X and Y in one row
        pos_frame = tk.Frame(content, bg="#e8e8e8")
        pos_frame.pack(fill=tk.X, pady=2)

        self._create_spinbox_row(pos_frame, "x", "X:", 0, 999, self._on_x_change, side=tk.LEFT)
        self._create_spinbox_row(pos_frame, "y", "Y:", 0, 999, self._on_y_change, side=tk.RIGHT)

        # Width and Height in one row
        size_frame = tk.Frame(content, bg="#e8e8e8")
        size_frame.pack(fill=tk.X, pady=2)

        self._create_spinbox_row(
            size_frame, "width", "W:", 1, 999, self._on_width_change, side=tk.LEFT
        )
        self._create_spinbox_row(
            size_frame, "height", "H:", 1, 999, self._on_height_change, side=tk.RIGHT
        )

        # Page
        self._create_spinbox_row(content, "page", "Page:", 1, 99, self._on_page_change)

    def _create_validation_section(self) -> None:
        """Создаёт секцию Validation (required, pattern, min, max, default)."""
        if self._content_frame is None:
            return
        section = SectionFrame(self._content_frame, "Validation", is_collapsed=True)
        section.pack(fill=tk.X, padx=2, pady=2)
        self._sections["Validation"] = section

        content = section.content

        # Required (checkbox)
        self._create_checkbox_row(content, "required", "Required:", self._on_required_change)

        # Pattern
        self._create_entry_row(content, "validation_pattern", "Pattern:", self._on_pattern_change)

        # Min and Max in one row
        range_frame = tk.Frame(content, bg="#e8e8e8")
        range_frame.pack(fill=tk.X, pady=2)

        self._create_spinbox_row(
            range_frame, "min_value", "Min:", -999999, 999999, self._on_min_change, side=tk.LEFT
        )
        self._create_spinbox_row(
            range_frame, "max_value", "Max:", -999999, 999999, self._on_max_change, side=tk.RIGHT
        )

        # Default value
        self._create_entry_row(content, "default_value", "Default:", self._on_default_change)

    def _create_appearance_section(self) -> None:
        """Создаёт секцию Appearance (font_family, cpi, lpi)."""
        if self._content_frame is None:
            return
        section = SectionFrame(self._content_frame, "Appearance")
        section.pack(fill=tk.X, padx=2, pady=2)
        self._sections["Appearance"] = section

        content = section.content

        # Font family
        font_values = [ff.value for ff in FontFamily]
        self._create_combobox_row(
            content,
            "font_family",
            "Font:",
            font_values,
            callback=self._on_font_change,
        )

        # CPI and LPI in one row
        spacing_frame = tk.Frame(content, bg="#e8e8e8")
        spacing_frame.pack(fill=tk.X, pady=2)

        cpi_values = [cpi.value for cpi in CharactersPerInch]
        self._create_combobox_row(
            spacing_frame,
            "cpi",
            "CPI:",
            cpi_values,
            callback=self._on_cpi_change,
            width=8,
            side=tk.LEFT,
        )

        lpi_values = [lpi.value for lpi in LinesPerInch]
        self._create_combobox_row(
            spacing_frame,
            "lpi",
            "LPI:",
            lpi_values,
            callback=self._on_lpi_change,
            width=8,
            side=tk.RIGHT,
        )

    def _create_advanced_section(self) -> None:
        """Создаёт секцию Advanced (conditions, autocomplete, options)."""
        if self._content_frame is None:
            return
        section = SectionFrame(self._content_frame, "Advanced", is_collapsed=True)
        section.pack(fill=tk.X, padx=2, pady=2)
        self._sections["Advanced"] = section

        content = section.content

        # Conditions (edit button)
        self._create_button_row(
            content, "conditions", "Conditions:", "Edit...", self._on_conditions_edit
        )

        # Autocomplete source
        self._create_entry_row(
            content, "autocomplete_source", "Autocomplete:", self._on_autocomplete_change
        )

        # Options (edit button - for DROPDOWN)
        self._create_button_row(content, "options", "Options:", "Edit...", self._on_options_edit)

    def _create_action_buttons(self) -> None:
        """Создаёт кнопки Delete и Duplicate."""
        if self._main_frame is None:
            return

        self._buttons_frame = tk.Frame(self._main_frame, bg="#e8e8e8")
        self._buttons_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)

        # Delete button
        delete_btn = tk.Button(
            self._buttons_frame,
            text="🗑️ Delete",
            command=self._on_delete_click,
            bg="#ffcccc",
            activebackground="#ffaaaa",
        )
        delete_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)

        # Duplicate button
        duplicate_btn = tk.Button(
            self._buttons_frame,
            text="📋 Duplicate",
            command=self._on_duplicate_click,
            bg="#ccffcc",
            activebackground="#aaffaa",
        )
        duplicate_btn.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=2)

    # =========================================================================
    # UI Helpers
    # =========================================================================

    def _create_entry_row(
        self,
        parent: tk.Widget,
        prop_name: str,
        label_text: str,
        callback: Callable[[Event[tk.Entry] | None], None],
    ) -> None:
        """Создаёт строку с меткой и Entry.

        Args:
            parent: Родительский виджет.
            prop_name: Имя свойства.
            label_text: Текст метки.
            callback: Callback при изменении.
        """
        frame = tk.Frame(parent, bg="#e8e8e8")
        frame.pack(fill=tk.X, pady=2)

        # Label with help icon
        self._create_label_for_property(frame, label_text, prop_name, width=self.LABEL_WIDTH)

        var = tk.StringVar()
        self._prop_vars[prop_name] = var

        entry = tk.Entry(
            frame,
            textvariable=var,
            width=self.ENTRY_WIDTH,
        )
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        entry.bind("<FocusOut>", callback)
        entry.bind("<Return>", callback)

        self._prop_widgets[prop_name] = entry

    def _create_spinbox_row(
        self,
        parent: tk.Widget,
        prop_name: str,
        label_text: str,
        min_val: int,
        max_val: int,
        callback: Callable[[Event[tk.Spinbox] | None], None],
        side: Literal["left", "right", "top", "bottom"] = tk.TOP,
    ) -> None:
        """Создаёт строку с меткой и Spinbox.

        Args:
            parent: Родительский виджет.
            prop_name: Имя свойства.
            label_text: Текст метки.
            min_val: Минимальное значение.
            max_val: Максимальное значение.
            callback: Callback при изменении.
            side: Сторона для pack (LEFT/RIGHT/TOP).
        """
        frame = tk.Frame(parent, bg="#e8e8e8")
        if side == tk.TOP:
            frame.pack(fill=tk.X, pady=2)
        else:
            frame.pack(side=side, fill=tk.X, expand=True, padx=2)

        # Label with help icon (use smaller width for side-by-side)
        label_width = 4 if side != tk.TOP else self.LABEL_WIDTH
        self._create_label_for_property(frame, label_text, prop_name, width=label_width)

        var = tk.StringVar()
        self._prop_vars[prop_name] = var

        spinbox = tk.Spinbox(
            frame,
            from_=min_val,
            to=max_val,
            textvariable=var,
            width=self.SPIN_WIDTH,
            command=lambda: callback(None),
        )
        spinbox.pack(side=tk.LEFT, fill=tk.X, expand=True)
        spinbox.bind("<FocusOut>", callback)
        spinbox.bind("<Return>", callback)

        self._prop_widgets[prop_name] = spinbox

    def _create_combobox_row(
        self,
        parent: tk.Widget,
        prop_name: str,
        label_text: str,
        values: list[str],
        readonly: bool = False,
        callback: Optional[Callable[[Event[Any]], None]] = None,
        width: int = 15,
        side: Literal["left", "right", "top", "bottom"] = tk.TOP,
    ) -> None:
        """Создаёт строку с меткой и Combobox.

        Args:
            parent: Родительский виджет.
            prop_name: Имя свойства.
            label_text: Текст метки.
            values: Допустимые значения.
            readonly: Только для чтения.
            callback: Callback при изменении.
            width: Ширина combobox.
            side: Сторона для pack.
        """
        frame = tk.Frame(parent, bg="#e8e8e8")
        if side == tk.TOP:
            frame.pack(fill=tk.X, pady=2)
        else:
            frame.pack(side=side, fill=tk.X, expand=True, padx=2)

        # Label with help icon (use smaller width for side-by-side)
        label_width = 4 if side != tk.TOP else self.LABEL_WIDTH
        self._create_label_for_property(frame, label_text, prop_name, width=label_width)

        var = tk.StringVar()
        self._prop_vars[prop_name] = var

        state = "readonly" if readonly else "normal"
        combobox = ttk.Combobox(
            frame,
            textvariable=var,
            values=values,
            state=state,
            width=width,
        )
        combobox.pack(side=tk.LEFT, fill=tk.X, expand=True)

        if callback is not None:
            combobox.bind("<<ComboboxSelected>>", callback)
            if not readonly:
                combobox.bind("<FocusOut>", callback)

        self._prop_widgets[prop_name] = combobox

    def _create_checkbox_row(
        self,
        parent: tk.Widget,
        prop_name: str,
        label_text: str,
        callback: Callable[[], None],
    ) -> None:
        """Создаёт строку с меткой и Checkbox.

        Args:
            parent: Родительский виджет.
            prop_name: Имя свойства.
            label_text: Текст метки.
            callback: Callback при изменении.
        """
        frame = tk.Frame(parent, bg="#e8e8e8")
        frame.pack(fill=tk.X, pady=2)

        var = tk.BooleanVar(value=False)
        self._prop_vars[prop_name] = var

        checkbox = tk.Checkbutton(
            frame,
            text=label_text,
            variable=var,
            bg="#e8e8e8",
            command=callback,
            anchor=tk.W,
        )
        checkbox.pack(side=tk.LEFT, fill=tk.X)

        # Help icon (after checkbox)
        self._create_help_icon(frame, prop_name)

        self._prop_widgets[prop_name] = checkbox

    def _create_button_row(
        self,
        parent: tk.Widget,
        prop_name: str,
        label_text: str,
        button_text: str,
        callback: Callable[[], None],
    ) -> None:
        """Создаёт строку с меткой и кнопкой.

        Args:
            parent: Родительский виджет.
            prop_name: Имя свойства.
            label_text: Текст метки.
            button_text: Текст кнопки.
            callback: Callback при нажатии.
        """
        frame = tk.Frame(parent, bg="#e8e8e8")
        frame.pack(fill=tk.X, pady=2)

        label_frame = tk.Frame(frame, bg="#e8e8e8")
        label_frame.pack(side=tk.LEFT)

        label = tk.Label(
            label_frame,
            text=label_text,
            bg="#e8e8e8",
            width=self.LABEL_WIDTH,
            anchor=tk.W,
        )
        label.pack(side=tk.LEFT)

        # Help icon
        self._create_help_icon(label_frame, prop_name)

        btn = tk.Button(
            frame,
            text=button_text,
            command=callback,
            width=self.ENTRY_WIDTH,
        )
        btn.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self._prop_widgets[prop_name] = btn

    def _create_help_icon(self, parent: tk.Widget, prop_name: str) -> Optional[tk.Label]:
        """Создаёт иконку помощи с тултипом.

        Args:
            parent: Родительский виджет.
            prop_name: Имя свойства для поиска help текста.

        Returns:
            Созданная иконка или None если help текст не найден.
        """
        help_text = PROPERTY_HELP_TEXTS.get(prop_name, "")
        if not help_text:
            return None

        help_icon = tk.Label(
            parent,
            text="ⓘ",
            bg="#e8e8e8",
            fg="#666666",
            cursor="hand2",
            font=("Arial", 8),
        )
        help_icon.pack(side=tk.LEFT, padx=(2, 0))

        # Bind tooltip
        if self._tooltip_manager:
            self._tooltip_manager.bind_to_widget(help_icon, help_text, delay_ms=300)

        return help_icon

    def _create_label_for_property(
        self,
        parent: tk.Widget,
        label_text: str,
        prop_name: str,
        width: int = 12,
    ) -> tk.Frame:
        """Создаёт фрейм с меткой и иконкой помощи.

        Args:
            parent: Родительский виджет.
            label_text: Текст метки.
            prop_name: Имя свойства для help текста.
            width: Ширина метки.

        Returns:
            Фрейм с меткой и иконкой.
        """
        frame = tk.Frame(parent, bg="#e8e8e8")
        frame.pack(side=tk.LEFT)

        label = tk.Label(
            frame,
            text=label_text,
            bg="#e8e8e8",
            width=width,
            anchor=tk.W,
        )
        label.pack(side=tk.LEFT)

        # Help icon
        self._create_help_icon(frame, prop_name)

        return frame

    # =========================================================================
    # Binding
    # =========================================================================

    def bind_to_field(self, field_widget: Optional[FormFieldWidget]) -> None:
        """Привязывает панель к полю (или очищает если None).

        Args:
            field_widget: Поле для редактирования или None для очистки.
        """
        self._is_updating = True

        self._bound_field = field_widget

        if field_widget is None:
            self._clear_all()
        else:
            self._populate_values(field_widget)

        self._is_updating = False

    def _populate_values(self, field_widget: FormFieldWidget) -> None:
        """Заполняет значения из поля.

        Args:
            field_widget: Поле со значениями.
        """
        field_def = field_widget.field_def

        # Basic
        self._set_prop_value("field_id", field_def.field_id)
        self._set_prop_value("label", field_def.label)
        label_ru = field_def.label_i18n.get("ru", "")
        self._set_prop_value("label_ru", label_ru)
        self._set_prop_value("field_type", field_def.field_type.value)

        # Position
        self._set_prop_value("x", field_widget.position.col)
        self._set_prop_value("y", field_widget.position.row)
        self._set_prop_value("width", field_widget.position.width)
        self._set_prop_value("height", field_widget.position.height)
        # Page is not stored in FormFieldWidget, assume 0 for now
        self._set_prop_value("page", 1)

        # Validation
        self._set_prop_value("required", field_def.required)
        self._set_prop_value("validation_pattern", field_def.validation_pattern or "")
        self._set_prop_value(
            "min_value", field_def.min_value if field_def.min_value is not None else ""
        )
        self._set_prop_value(
            "max_value", field_def.max_value if field_def.max_value is not None else ""
        )
        self._set_prop_value(
            "default_value",
            str(field_def.default_value) if field_def.default_value is not None else "",
        )

        # Appearance (store in field_def for now)
        # These might not exist in current FieldDefinition, use defaults
        font_family = getattr(field_def, "font_family", FontFamily.ROMAN)
        self._set_prop_value(
            "font_family", font_family.value if isinstance(font_family, FontFamily) else "roman"
        )
        self._set_prop_value("cpi", getattr(field_def, "cpi", "10cpi"))
        self._set_prop_value("lpi", getattr(field_def, "lpi", "6"))

        # Advanced
        self._set_prop_value("autocomplete_source", field_def.autocomplete_source or "")
        # Conditions and options are complex, just show "..." for now
        self._set_prop_value("conditions", "...")
        options_str = ", ".join(field_def.options) if field_def.options else ""
        self._set_prop_value("options", options_str)

    def _clear_all(self) -> None:
        """Очищает все поля (когда нет выбранного поля)."""
        for prop_name, _widget in self._prop_widgets.items():
            if prop_name in self._prop_vars:
                var = self._prop_vars[prop_name]
                if isinstance(var, tk.StringVar):
                    var.set("")
                elif isinstance(var, tk.BooleanVar):
                    var.set(False)
                elif isinstance(var, tk.IntVar):
                    var.set(0)

    def _set_prop_value(self, prop_name: str, value: Any) -> None:
        """Устанавливает значение свойства в UI.

        Args:
            prop_name: Имя свойства.
            value: Новое значение.
        """
        if prop_name not in self._prop_vars:
            return

        var = self._prop_vars[prop_name]

        try:
            if isinstance(var, tk.BooleanVar):
                var.set(bool(value))
            elif isinstance(var, tk.StringVar):
                var.set(str(value) if value is not None else "")
            elif isinstance(var, tk.IntVar):
                var.set(int(value) if value is not None else 0)
        except tk.TclError:
            # Widget might be destroyed
            pass

    def _get_prop_value(self, prop_name: str) -> Any:
        """Возвращает текущее значение свойства из UI.

        Args:
            prop_name: Имя свойства.

        Returns:
            Текущее значение.
        """
        if prop_name not in self._prop_vars:
            return None

        var = self._prop_vars[prop_name]
        return var.get()  # type: ignore[no-untyped-call]

    # =========================================================================
    # Callback Handlers
    # =========================================================================

    def _on_prop_change(self, prop_name: str, new_value: Any) -> None:
        """Обработчик изменения свойства в UI.

        Args:
            prop_name: Имя изменённого свойства.
            new_value: Новое значение.
        """
        if self._is_updating:
            return

        # Validate value
        if not self._validate_prop(prop_name, new_value):
            # Restore previous value
            if self._bound_field is not None:
                self._populate_values(self._bound_field)
            return

        # Call external callback
        self._on_property_change(prop_name, new_value)

        # Update bound field immediately
        if self._bound_field is not None:
            self._update_field_property(prop_name, new_value)

    def _validate_prop(self, prop_name: str, value: Any) -> bool:
        """Валидирует значение свойства.

        Args:
            prop_name: Имя свойства.
            value: Значение для валидации.

        Returns:
            True если значение валидно.
        """
        # field_id: unique, alphanumeric
        if prop_name == "field_id":
            if not isinstance(value, str) or not value.strip():
                return False
            # Alphanumeric with underscore
            if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", value):
                return False
            return True

        # x, y: non-negative integers
        if prop_name in ("x", "y"):
            try:
                val = int(value)
                return val >= 0
            except (ValueError, TypeError):
                return False

        # width, height: positive integers
        if prop_name in ("width", "height"):
            try:
                val = int(value)
                return val > 0
            except (ValueError, TypeError):
                return False

        # page: positive integer
        if prop_name == "page":
            try:
                val = int(value)
                return val >= 1
            except (ValueError, TypeError):
                return False

        # pattern: valid regex or empty
        if prop_name == "validation_pattern":
            if not value:
                return True
            try:
                re.compile(str(value))
                return True
            except re.error:
                return False

        return True

    def _update_field_property(self, prop_name: str, value: Any) -> None:
        """Обновляет свойство привязанного поля.

        Args:
            prop_name: Имя свойства.
            value: Новое значение.
        """
        if not self._bound_field:
            return

        # Update position properties
        if prop_name == "x":
            try:
                new_x = int(value)
                self._bound_field.position = self._bound_field.position.__class__(
                    col=new_x,
                    row=self._bound_field.position.row,
                    width=self._bound_field.position.width,
                    height=self._bound_field.position.height,
                )
            except (ValueError, TypeError):
                pass
        elif prop_name == "y":
            try:
                new_y = int(value)
                self._bound_field.position = self._bound_field.position.__class__(
                    col=self._bound_field.position.col,
                    row=new_y,
                    width=self._bound_field.position.width,
                    height=self._bound_field.position.height,
                )
            except (ValueError, TypeError):
                pass
        elif prop_name == "width":
            try:
                new_w = int(value)
                self._bound_field.position = self._bound_field.position.__class__(
                    col=self._bound_field.position.col,
                    row=self._bound_field.position.row,
                    width=new_w,
                    height=self._bound_field.position.height,
                )
            except (ValueError, TypeError):
                pass
        elif prop_name == "height":
            try:
                new_h = int(value)
                self._bound_field.position = self._bound_field.position.__class__(
                    col=self._bound_field.position.col,
                    row=self._bound_field.position.row,
                    width=self._bound_field.position.width,
                    height=new_h,
                )
            except (ValueError, TypeError):
                pass

    def refresh(self) -> None:
        """Обновляет значения из поля (если поле изменилось извне)."""
        if self._bound_field:
            self._populate_values(self._bound_field)

    # =========================================================================
    # Specific Property Handlers
    # =========================================================================

    def _on_field_id_change(self, event: Event[tk.Entry] | None) -> None:
        """Обработчик изменения field_id."""
        _ = event
        value = self._get_prop_value("field_id")
        self._on_prop_change("field_id", value)

    def _on_label_change(self, event: Event[tk.Entry] | None) -> None:
        """Обработчик изменения label."""
        _ = event
        value = self._get_prop_value("label")
        self._on_prop_change("label", value)

    def _on_label_ru_change(self, event: Event[tk.Entry] | None) -> None:
        """Обработчик изменения label_ru."""
        _ = event
        value = self._get_prop_value("label_ru")
        self._on_prop_change("label_ru", value)

    def _on_type_change(self, event: Event[ttk.Combobox] | None) -> None:
        """Обработчик изменения field_type."""
        _ = event
        value = self._get_prop_value("field_type")
        self._on_prop_change("field_type", value)

    def _on_x_change(self, event: Event[tk.Spinbox] | None) -> None:
        """Обработчик изменения X."""
        _ = event
        value = self._get_prop_value("x")
        self._on_prop_change("x", value)

    def _on_y_change(self, event: Event[tk.Spinbox] | None) -> None:
        """Обработчик изменения Y."""
        _ = event
        value = self._get_prop_value("y")
        self._on_prop_change("y", value)

    def _on_width_change(self, event: Event[tk.Spinbox] | None) -> None:
        """Обработчик изменения width."""
        _ = event
        value = self._get_prop_value("width")
        self._on_prop_change("width", value)

    def _on_height_change(self, event: Event[tk.Spinbox] | None) -> None:
        """Обработчик изменения height."""
        _ = event
        value = self._get_prop_value("height")
        self._on_prop_change("height", value)

    def _on_page_change(self, event: Event[tk.Spinbox] | None) -> None:
        """Обработчик изменения page."""
        _ = event
        value = self._get_prop_value("page")
        self._on_prop_change("page", value)

    def _on_required_change(self) -> None:
        """Обработчик изменения required."""
        value = self._get_prop_value("required")
        self._on_prop_change("required", value)

    def _on_pattern_change(self, event: Event[tk.Entry] | None) -> None:
        """Обработчик изменения validation_pattern."""
        _ = event
        value = self._get_prop_value("validation_pattern")
        self._on_prop_change("validation_pattern", value)

    def _on_min_change(self, event: Event[tk.Spinbox] | None) -> None:
        """Обработчик изменения min_value."""
        _ = event
        value = self._get_prop_value("min_value")
        # Convert empty string to None
        if value == "":
            value = None
        else:
            try:
                value = float(value)
            except (ValueError, TypeError):
                value = None
        self._on_prop_change("min_value", value)

    def _on_max_change(self, event: Event[tk.Spinbox] | None) -> None:
        """Обработчик изменения max_value."""
        _ = event
        value = self._get_prop_value("max_value")
        # Convert empty string to None
        if value == "":
            value = None
        else:
            try:
                value = float(value)
            except (ValueError, TypeError):
                value = None
        self._on_prop_change("max_value", value)

    def _on_default_change(self, event: Event[tk.Entry] | None) -> None:
        """Обработчик изменения default_value."""
        _ = event
        value = self._get_prop_value("default_value")
        self._on_prop_change("default_value", value)

    def _on_font_change(self, event: Event[ttk.Combobox] | None) -> None:
        """Обработчик изменения font_family."""
        _ = event
        value = self._get_prop_value("font_family")
        self._on_prop_change("font_family", value)

    def _on_cpi_change(self, event: Event[ttk.Combobox] | None) -> None:
        """Обработчик изменения CPI."""
        _ = event
        value = self._get_prop_value("cpi")
        self._on_prop_change("cpi", value)

    def _on_lpi_change(self, event: Event[ttk.Combobox] | None) -> None:
        """Обработчик изменения LPI."""
        _ = event
        value = self._get_prop_value("lpi")
        self._on_prop_change("lpi", value)

    def _on_conditions_edit(self) -> None:
        """Обработчик нажатия Edit для conditions."""
        if self._bound_field is None:
            return

        # Create and show dialog
        dialog = ConditionsEditorDialog(
            parent=self._parent,
            field_def=self._bound_field.field_def,
        )
        result = dialog.show()

        if result is not None:
            # Update field definition with new conditions
            field_def = self._bound_field.field_def

            # Create new field definition with updated conditions
            from dataclasses import replace

            new_field_def = replace(
                field_def,
                visibility_condition=result.get("visibility_condition"),
                enabled_condition=result.get("enabled_condition"),
                read_only_condition=result.get("read_only_condition"),
            )

            # Update bound field
            self._bound_field.field_def = new_field_def

            # Notify about changes
            self._on_prop_change("conditions", "updated")
            self._populate_values(self._bound_field)

    def _on_autocomplete_change(self, event: Event[tk.Entry] | None) -> None:
        """Обработчик изменения autocomplete_source."""
        _ = event
        value = self._get_prop_value("autocomplete_source")
        self._on_prop_change("autocomplete_source", value)

    def _on_options_edit(self) -> None:
        """Обработчик нажатия Edit для options."""
        if self._bound_field is None:
            return

        # Convert current options to FieldOption objects
        current_options: list[FieldOption] = []
        field_def = self._bound_field.field_def

        if field_def.options:
            for opt in field_def.options:
                # Options stored as strings in FieldDefinition
                if isinstance(opt, str):
                    current_options.append(FieldOption(value=opt, label_ru=opt))
                else:
                    # Handle dict format if present
                    if isinstance(opt, dict):
                        label_ru = opt.get("label_ru", opt.get("value", ""))
                        label_en = opt.get("label_en", "")
                        value = opt.get("value", opt)
                    else:
                        label_ru = opt
                        label_en = ""
                        value = opt
                    current_options.append(
                        FieldOption(
                            value=str(value),
                            label_ru=str(label_ru),
                            label_en=str(label_en),
                        )
                    )

        # Create and show dialog
        dialog = OptionsEditorDialog(
            parent=self._parent,
            current_options=current_options,
            field_id=field_def.field_id,
        )
        result = dialog.show()

        if result is not None:
            # Convert FieldOption objects back to tuple of strings
            # Note: FieldDefinition.options expects tuple[str, ...]
            new_options = tuple(opt.value for opt in result)

            # Create new field definition with updated options
            from dataclasses import replace

            new_field_def = replace(
                field_def,
                options=new_options if new_options else None,
            )

            # Update bound field
            self._bound_field.field_def = new_field_def

            # Notify about changes
            self._on_prop_change("options", "updated")
            self._populate_values(self._bound_field)

    def _on_delete_click(self) -> None:
        """Обработчик нажатия Delete Field."""
        self._on_field_delete()

    def _on_duplicate_click(self) -> None:
        """Обработчик нажатия Duplicate Field."""
        self._on_field_duplicate()

    # =========================================================================
    # Public API
    # =========================================================================

    def get_bound_field(self) -> Optional[FormFieldWidget]:
        """Возвращает привязанное поле.

        Returns:
            Текущее поле или None.
        """
        return self._bound_field

    def expand_section(self, section_name: str) -> None:
        """Разворачивает указанную секцию.

        Args:
            section_name: Имя секции для разворачивания.

        Raises:
            ValueError: Если секция не найдена.
        """
        if section_name not in self._sections:
            raise ValueError(f"Section not found: {section_name}")
        self._sections[section_name].expand()

    def collapse_section(self, section_name: str) -> None:
        """Сворачивает указанную секцию.

        Args:
            section_name: Имя секции для сворачивания.

        Raises:
            ValueError: Если секция не найдена.
        """
        if section_name not in self._sections:
            raise ValueError(f"Section not found: {section_name}")
        self._sections[section_name].collapse()

    def set_prop_enabled(self, prop_name: str, enabled: bool) -> None:
        """Включает/выключает редактирование свойства.

        Args:
            prop_name: Имя свойства.
            enabled: True для включения, False для выключения.
        """
        if prop_name not in self._prop_widgets:
            return

        widget = self._prop_widgets[prop_name]
        state = "normal" if enabled else "disabled"

        if isinstance(widget, (tk.Entry, tk.Spinbox, tk.Checkbutton, ttk.Combobox)):
            widget.configure(state=state)  # type: ignore[call-overload]

    # =========================================================================
    # Lifecycle
    # =========================================================================

    def _cleanup(self) -> None:
        """Выполняет очистку ресурсов перед демонтированием."""
        self._bound_field = None
        self._prop_widgets.clear()
        self._prop_vars.clear()
        self._sections.clear()

        self._main_frame = None
        self._scroll_canvas = None
        self._content_frame = None
        self._buttons_frame = None

        super()._cleanup()


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__ = [
    "PropertyPanel",
    "SectionFrame",
]
