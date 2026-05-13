"""Design Commands для Form Designer (Undo/Redo support).

Реализует Command Pattern для операций дизайна форм.

Example:
    >>> from src.gui.core.commands.design_commands import FieldCreateCommand
    >>> cmd = FieldCreateCommand(canvas, field_def, x=5, y=3)
    >>> cmd.execute()
    >>> cmd.undo()  # Удаляет созданное поле

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from typing import Any, Optional

from src.documents.types.type_schema import FieldDefinition
from src.gui.core.commands.command import Command
from src.gui.renderers.form_canvas import FieldPosition, FormCanvas, FormFieldWidget


def _get_field(canvas: FormCanvas, field_id: str) -> Optional[FormFieldWidget]:
    """Получает поле по ID из Canvas.

    Args:
        canvas: Canvas с полями.
        field_id: ID поля.

    Returns:
        Поле или None если не найдено.
    """
    return canvas.get_fields().get(field_id)


class FieldCreateCommand(Command):
    """Команда создания поля.

    Attributes:
        _canvas: Canvas для создания поля.
        _field_def: Определение поля.
        _x: Колонка для создания (0-based).
        _y: Строка для создания (0-based).
        _created_field_id: ID созданного поля (для undo).

    Example:
        >>> cmd = FieldCreateCommand(canvas, field_def, x=5, y=3)
        >>> cmd.execute()
        >>> cmd.undo()  # Удаляет созданное поле
    """

    def __init__(
        self,
        canvas: FormCanvas,
        field_def: FieldDefinition,
        x: int,
        y: int,
    ) -> None:
        """Инициализация команды создания поля.

        Args:
            canvas: Canvas для создания поля.
            field_def: Определение поля.
            x: Колонка (0-based).
            y: Строка (0-based).
        """
        super().__init__(f"Create field {field_def.field_id}")
        self._canvas = canvas
        self._field_def = field_def
        self._x = x
        self._y = y
        self._created_field_id: Optional[str] = None

    def execute(self) -> None:
        """Создаёт поле на Canvas."""
        field_widget = self._canvas.create_field(self._field_def, self._x, self._y)
        self._created_field_id = field_widget.field_id
        self._is_executed = True

    def undo(self) -> None:
        """Удаляет созданное поле."""
        if self._created_field_id:
            self._canvas.remove_field(self._created_field_id)
            self._is_executed = False

    def redo(self) -> None:
        """Повторно создаёт поле."""
        # Re-execute
        self.execute()

    def get_description(self) -> str:
        """Возвращает описание команды для UI.

        Returns:
            Описание команды.
        """
        return f"Create field {self._field_def.field_id}"


class FieldMoveCommand(Command):
    """Команда перемещения поля.

    Attributes:
        _canvas: Canvas с полем.
        _field_id: ID перемещаемого поля.
        _old_position: Старая позиция (col, row).
        _new_position: Новая позиция (col, row).

    Example:
        >>> cmd = FieldMoveCommand(canvas, "field_1", (5, 3), (10, 5))
        >>> cmd.execute()  # Перемещает поле
        >>> cmd.undo()  # Возвращает на старую позицию
    """

    def __init__(
        self,
        canvas: FormCanvas,
        field_id: str,
        old_position: tuple[int, int],
        new_position: tuple[int, int],
    ) -> None:
        """Инициализация команды перемещения.

        Args:
            canvas: Canvas с полем.
            field_id: ID перемещаемого поля.
            old_position: Старая позиция (col, row).
            new_position: Новая позиция (col, row).
        """
        super().__init__(f"Move field {field_id}")
        self._canvas = canvas
        self._field_id = field_id
        self._old_position = old_position
        self._new_position = new_position

    def execute(self) -> None:
        """Перемещает поле на новую позицию."""
        field = _get_field(self._canvas, self._field_id)
        if field is None:
            raise RuntimeError(f"Field {self._field_id} not found")
        field.position = FieldPosition(
            col=self._new_position[0],
            row=self._new_position[1],
            width=field.position.width,
            height=field.position.height,
        )
        self._canvas._redraw_field(field)
        self._is_executed = True

    def undo(self) -> None:
        """Возвращает поле на старую позицию."""
        field = _get_field(self._canvas, self._field_id)
        if field is None:
            raise RuntimeError(f"Field {self._field_id} not found")
        field.position = FieldPosition(
            col=self._old_position[0],
            row=self._old_position[1],
            width=field.position.width,
            height=field.position.height,
        )
        self._canvas._redraw_field(field)
        self._is_executed = False

    def redo(self) -> None:
        """Повторно перемещает поле."""
        self.execute()

    def get_description(self) -> str:
        """Возвращает описание команды для UI.

        Returns:
            Описание команды.
        """
        return f"Move field {self._field_id}"


class FieldResizeCommand(Command):
    """Команда изменения размера поля.

    Attributes:
        _canvas: Canvas с полем.
        _field_id: ID поля для изменения размера.
        _old_size: Старый размер (width, height) в ячейках.
        _new_size: Новый размер (width, height) в ячейках.

    Example:
        >>> cmd = FieldResizeCommand(canvas, "field_1", (1, 1), (2, 3))
        >>> cmd.execute()  # Изменяет размер
        >>> cmd.undo()  # Возвращает старый размер
    """

    def __init__(
        self,
        canvas: FormCanvas,
        field_id: str,
        old_size: tuple[int, int],
        new_size: tuple[int, int],
    ) -> None:
        """Инициализация команды изменения размера.

        Args:
            canvas: Canvas с полем.
            field_id: ID поля.
            old_size: Старый размер (width, height).
            new_size: Новый размер (width, height).
        """
        super().__init__(f"Resize field {field_id}")
        self._canvas = canvas
        self._field_id = field_id
        self._old_size = old_size
        self._new_size = new_size

    def execute(self) -> None:
        """Изменяет размер поля."""
        field = _get_field(self._canvas, self._field_id)
        if field is None:
            raise RuntimeError(f"Field {self._field_id} not found")
        field.position = FieldPosition(
            col=field.position.col,
            row=field.position.row,
            width=self._new_size[0],
            height=self._new_size[1],
        )
        self._canvas._redraw_field(field)
        self._is_executed = True

    def undo(self) -> None:
        """Возвращает старый размер поля."""
        field = _get_field(self._canvas, self._field_id)
        if field is None:
            raise RuntimeError(f"Field {self._field_id} not found")
        field.position = FieldPosition(
            col=field.position.col,
            row=field.position.row,
            width=self._old_size[0],
            height=self._old_size[1],
        )
        self._canvas._redraw_field(field)
        self._is_executed = False

    def redo(self) -> None:
        """Повторно изменяет размер поля."""
        self.execute()

    def get_description(self) -> str:
        """Возвращает описание команды для UI.

        Returns:
            Описание команды.
        """
        return f"Resize field {self._field_id}"


class FieldCrossPageMoveCommand(Command):
    """Команда перемещения поля между страницами.

    Attributes:
        _designer_tab: DesignerTab с страницами.
        _field_id: ID перемещаемого поля.
        _from_page: Индекс исходной страницы.
        _to_page: Индекс целевой страницы.
        _from_pos: Исходная позиция (col, row).
        _to_pos: Целевая позиция (col, row).

    Example:
        >>> cmd = FieldCrossPageMoveCommand(tab, "field_1", 0, 1, (5, 3), (10, 5))
        >>> cmd.execute()  # Перемещает поле на страницу 1
        >>> cmd.undo()  # Возвращает на страницу 0
    """

    def __init__(
        self,
        designer_tab: Any,  # DesignerTab
        field_id: str,
        from_page: int,
        to_page: int,
        from_pos: tuple[int, int],
        to_pos: tuple[int, int],
    ) -> None:
        """Инициализация команды перемещения между страницами.

        Args:
            designer_tab: DesignerTab с страницами.
            field_id: ID перемещаемого поля.
            from_page: Индекс исходной страницы.
            to_page: Индекс целевой страницы.
            from_pos: Исходная позиция (col, row).
            to_pos: Целевая позиция (col, row).
        """
        super().__init__(f"Move field {field_id} to page {to_page + 1}")
        self._designer_tab = designer_tab
        self._field_id = field_id
        self._from_page = from_page
        self._to_page = to_page
        self._from_pos = from_pos
        self._to_pos = to_pos

    def execute(self) -> None:
        """Перемещает поле на целевую страницу."""
        success = self._designer_tab.move_field(
            self._field_id,
            self._to_pos[0],
            self._to_pos[1],
            self._to_page,
        )
        if not success:
            raise RuntimeError(f"Failed to move field {self._field_id}")

        self._is_executed = True

    def undo(self) -> None:
        """Возвращает поле на исходную страницу."""
        success = self._designer_tab.move_field(
            self._field_id,
            self._from_pos[0],
            self._from_pos[1],
            self._from_page,
        )
        if not success:
            raise RuntimeError(f"Failed to undo move for field {self._field_id}")

        self._is_executed = False

    def redo(self) -> None:
        """Повторно перемещает поле."""
        self.execute()

    def get_description(self) -> str:
        """Возвращает описание команды для UI.

        Returns:
            Описание команды.
        """
        if self._from_page == self._to_page:
            return f"Move field {self._field_id}"
        return f"Move field {self._field_id} to page {self._to_page + 1}"


class FieldDeleteCommand(Command):
    """Команда удаления поля.

    Attributes:
        _canvas: Canvas с полем.
        _field_def: Сохранённое определение поля для восстановления.
        _position: Позиция поля для восстановления.
        _deleted_field_id: ID удалённого поля.

    Example:
        >>> cmd = FieldDeleteCommand(canvas, field_widget)
        >>> cmd.execute()  # Удаляет поле
        >>> cmd.undo()  # Восстанавливает поле
    """

    def __init__(
        self,
        canvas: FormCanvas,
        field_widget: FormFieldWidget,
    ) -> None:
        """Инициализация команды удаления.

        Args:
            canvas: Canvas с полем.
            field_widget: Виджет поля для удаления.
        """
        super().__init__(f"Delete field {field_widget.field_id}")
        self._canvas = canvas
        self._field_def = field_widget.field_def
        self._position = (
            field_widget.position.col,
            field_widget.position.row,
        )
        self._deleted_field_id = field_widget.field_id

    def execute(self) -> None:
        """Удаляет поле с Canvas."""
        self._canvas.remove_field(self._deleted_field_id)
        self._is_executed = True

    def undo(self) -> None:
        """Восстанавливает удалённое поле."""
        # Recreate field
        self._canvas.create_field(
            self._field_def,
            self._position[0],
            self._position[1],
        )
        self._is_executed = False

    def redo(self) -> None:
        """Повторно удаляет поле."""
        self.execute()

    def get_description(self) -> str:
        """Возвращает описание команды для UI.

        Returns:
            Описание команды.
        """
        return f"Delete field {self._deleted_field_id}"


class PropertyChangeCommand(Command):
    """Команда изменения свойства поля.

    Attributes:
        _canvas: Canvas с полем.
        _field_id: ID поля.
        _property_name: Имя изменяемого свойства.
        _old_value: Старое значение.
        _new_value: Новое значение.

    Example:
        >>> cmd = PropertyChangeCommand(canvas, "field_1", "label", "Old", "New")
        >>> cmd.execute()  # Устанавливает новое значение
        >>> cmd.undo()  # Возвращает старое значение
    """

    def __init__(
        self,
        canvas: FormCanvas,
        field_id: str,
        property_name: str,
        old_value: Any,
        new_value: Any,
    ) -> None:
        """Инициализация команды изменения свойства.

        Args:
            canvas: Canvas с полем.
            field_id: ID поля.
            property_name: Имя свойства.
            old_value: Старое значение.
            new_value: Новое значение.
        """
        super().__init__(f"Change {property_name}")
        self._canvas = canvas
        self._field_id = field_id
        self._property_name = property_name
        self._old_value = old_value
        self._new_value = new_value

    def execute(self) -> None:
        """Устанавливает новое значение свойства."""
        self._set_property(self._new_value)
        self._is_executed = True

    def undo(self) -> None:
        """Возвращает старое значение свойства."""
        self._set_property(self._old_value)
        self._is_executed = False

    def redo(self) -> None:
        """Повторно устанавливает новое значение."""
        self.execute()

    def _set_property(self, value: Any) -> None:
        """Устанавливает значение свойства поля.

        Args:
            value: Новое значение свойства.

        Raises:
            RuntimeError: Если поле не найдено.
        """
        field = _get_field(self._canvas, self._field_id)
        if field is None:
            raise RuntimeError(f"Field {self._field_id} not found")

        # Handle specific properties
        from dataclasses import replace

        if self._property_name == "label":
            field.field_def = replace(field.field_def, label=str(value))
        elif self._property_name == "required":
            field.field_def = replace(field.field_def, required=bool(value))
        elif self._property_name == "readonly":
            field.field_def = replace(field.field_def, readonly=bool(value))
        elif self._property_name == "field_id":
            field.field_def = replace(field.field_def, field_id=str(value))
        elif self._property_name == "validation_pattern":
            field.field_def = replace(
                field.field_def,
                validation_pattern=str(value) if value else None,
            )
        elif self._property_name == "min_value":
            field.field_def = replace(
                field.field_def,
                min_value=float(value) if value is not None else None,
            )
        elif self._property_name == "max_value":
            field.field_def = replace(
                field.field_def,
                max_value=float(value) if value is not None else None,
            )
        elif self._property_name == "default_value":
            field.field_def = replace(field.field_def, default_value=value)
        elif self._property_name == "autocomplete_source":
            field.field_def = replace(
                field.field_def,
                autocomplete_source=str(value) if value else None,
            )
        elif self._property_name == "label_ru":
            new_i18n = dict(field.field_def.label_i18n)
            new_i18n["ru"] = str(value)
            field.field_def = replace(field.field_def, label_i18n=new_i18n)
        else:
            # For other properties, use reflection
            if hasattr(field, f"set_{self._property_name}"):
                setter = getattr(field, f"set_{self._property_name}")
                setter(value)
            else:
                # Fallback: try to set attribute directly
                private_attr = f"_{self._property_name}"
                if hasattr(field, private_attr):
                    setattr(field, private_attr, value)
                else:
                    setattr(field, self._property_name, value)

        # Redraw field to reflect changes
        self._canvas._redraw_field(field)

    def get_description(self) -> str:
        """Возвращает описание команды для UI.

        Returns:
            Описание команды.
        """
        return f"Change {self._property_name} to {self._new_value}"


class SelectFieldCommand(Command):
    """Команда выбора поля (для undo selection).

    Attributes:
        _canvas: Canvas с полями.
        _old_field_id: ID ранее выбранного поля.
        _new_field_id: ID нового выбранного поля.

    Example:
        >>> cmd = SelectFieldCommand(canvas, "field_1", "field_2")
        >>> cmd.execute()  # Выбирает field_2
        >>> cmd.undo()  # Возвращает выбор на field_1
    """

    def __init__(
        self,
        canvas: FormCanvas,
        old_field_id: Optional[str],
        new_field_id: Optional[str],
    ) -> None:
        """Инициализация команды выбора.

        Args:
            canvas: Canvas с полями.
            old_field_id: ID ранее выбранного поля.
            new_field_id: ID нового выбранного поля.
        """
        super().__init__("Select field")
        self._canvas = canvas
        self._old_field_id = old_field_id
        self._new_field_id = new_field_id

    def execute(self) -> None:
        """Выбирает новое поле."""
        self._canvas.select_field(self._new_field_id)
        self._is_executed = True

    def undo(self) -> None:
        """Возвращает выбор на старое поле."""
        self._canvas.select_field(self._old_field_id)
        self._is_executed = False

    def redo(self) -> None:
        """Повторно выбирает новое поле."""
        self.execute()

    def get_description(self) -> str:
        """Возвращает описание команды для UI.

        Returns:
            Описание команды.
        """
        old = self._old_field_id or "none"
        new = self._new_field_id or "none"
        return f"Select field {old} → {new}"


class BatchCommand(Command):
    """Командная группа для атомарного выполнения нескольких команд.

    Позволяет объединить несколько команд в одну для undo/redo.
    Если одна из команд не выполняется, вся группа откатывается.

    Attributes:
        _commands: Список команд для выполнения.
        _executed: Флаг выполнения группы.

    Example:
        >>> cmd1 = FieldCreateCommand(canvas, field_def1, 0, 0)
        >>> cmd2 = FieldCreateCommand(canvas, field_def2, 5, 0)
        >>> batch = BatchCommand([cmd1, cmd2], "Create two fields")
        >>> batch.execute()  # Создаёт оба поля
        >>> batch.undo()  # Удаляет оба поля
    """

    def __init__(
        self,
        commands: list[Command],
        description: str = "Batch operation",
    ) -> None:
        """Инициализация групповой команды.

        Args:
            commands: Список команд для выполнения.
            description: Описание групповой операции.
        """
        super().__init__(description)
        self._commands = commands
        self._executed = False

    def execute(self) -> None:
        """Выполняет все команды в группе.

        Raises:
            RuntimeError: Если одна из команд не выполняется.
        """
        executed: list[Command] = []
        try:
            for cmd in self._commands:
                cmd.execute()
                executed.append(cmd)
        except Exception as e:
            # Rollback already executed commands
            for cmd in reversed(executed):
                cmd.undo()
            raise RuntimeError(f"Batch command failed: {e}") from e

        self._executed = True
        self._is_executed = True

    def undo(self) -> None:
        """Отменяет все команды в группе (в обратном порядке)."""
        if not self._executed:
            return

        for cmd in reversed(self._commands):
            if cmd.is_executed:
                cmd.undo()

        self._executed = False
        self._is_executed = False

    def redo(self) -> None:
        """Повторно выполняет все команды."""
        self.execute()

    def get_description(self) -> str:
        """Возвращает описание команды для UI.

        Returns:
            Описание команды с количеством подкоманд.
        """
        return f"{self._description} ({len(self._commands)} operations)"


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__ = [
    "FieldCreateCommand",
    "FieldMoveCommand",
    "FieldCrossPageMoveCommand",
    "FieldResizeCommand",
    "FieldDeleteCommand",
    "PropertyChangeCommand",
    "SelectFieldCommand",
    "BatchCommand",
]
