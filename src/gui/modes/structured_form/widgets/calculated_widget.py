"""Виджет вычисляемого поля.

Предоставляет:
- CalculatedWidget: read-only Label с рамкой для отображения вычисленного значения.
- Безопасный движок формул через ast.parse и ограниченные операторы.

Example:
    >>> widget = CalculatedWidget(
    ...     parent=frame,
    ...     field_def=field_def,
    ... )
    >>> widget.recalculate({'price': 100, 'quantity': 2})
    >>> widget.get_value()
    200.0
"""

from __future__ import annotations

import ast
import operator
import re
import tkinter as tk
from typing import Any, Callable, Optional, Union

from src.documents.types.type_schema import FieldDefinition
from src.gui.modes.structured_form.widgets.base_field_widget import BaseFieldWidget


class FormulaSecurityError(Exception):
    """Исключение при обнаружении запрещённых конструкций в формуле."""

    pass


class FormulaSyntaxError(Exception):
    """Исключение при синтаксической ошибке в формуле."""

    pass


class FormulaEvaluationError(Exception):
    """Исключение при ошибке вычисления формулы."""

    pass


class CalculatedWidget(BaseFieldWidget):
    """Read-only Label с рамкой для вычисленного значения.

    Attributes:
        _formula: Строка формулы для вычисления.
        _value_label: Tkinter Label для отображения результата.
        _decimal_places: Количество десятичных знаков при форматировании.

    Example:
        >>> widget = CalculatedWidget(parent, field_def)
        >>> widget.recalculate({'price': 10, 'quantity': 3})
        >>> widget.get_value()
        30.0
    """

    # Разрешённые типы AST узлов (whitelist)
    _ALLOWED_NODES: frozenset[type] = frozenset(
        {
            ast.Expression,
            ast.BinOp,
            ast.UnaryOp,
            ast.Name,
            ast.Constant,
            ast.Load,
            ast.Add,
            ast.Sub,
            ast.Mult,
            ast.Div,
            ast.FloorDiv,
            ast.Mod,
            ast.Pow,
            ast.USub,
            ast.UAdd,
            ast.Compare,
            ast.Lt,
            ast.LtE,
            ast.Gt,
            ast.GtE,
            ast.Eq,
            ast.NotEq,
            ast.BoolOp,
            ast.And,
            ast.Or,
            ast.Not,
            ast.IfExp,
            ast.Tuple,
            ast.JoinedStr,
            ast.FormattedValue,
        }
    )

    # Бинарные операции
    _BIN_OPS: dict[type, Any] = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv,
        ast.Mod: operator.mod,
        ast.Pow: operator.pow,
    }

    # Унарные операции
    _UNARY_OPS: dict[type, Any] = {
        ast.UAdd: operator.pos,
        ast.USub: operator.neg,
        ast.Not: operator.not_,
    }

    # Операции сравнения
    _COMPARE_OPS: dict[type, Any] = {
        ast.Lt: operator.lt,
        ast.LtE: operator.le,
        ast.Gt: operator.gt,
        ast.GtE: operator.ge,
        ast.Eq: operator.eq,
        ast.NotEq: operator.ne,
    }

    def __init__(
        self,
        parent: tk.Widget,
        field_def: FieldDefinition,
        on_change: Optional[Callable[[str, Any], None]] = None,
        on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = None,
        decimal_places: int = 2,
    ) -> None:
        """Инициализация вычисляемого поля.

        Args:
            parent: Родительский Tkinter виджет.
            field_def: Определение поля из схемы.
            on_change: Callback игнорируется (read-only).
            on_validate: Callback игнорируется (read-only).
            decimal_places: Количество знаков после запятой.
        """
        super().__init__(parent, field_def, on_change, on_validate)
        self._formula: str = field_def.formula or ""
        self._value_label: Optional[tk.Label] = None
        self._decimal_places: int = decimal_places

    def _create_widget(self) -> tk.Widget:
        """Создаёт read-only Label с рамкой для отображения результата.

        Returns:
            Tkinter Frame с Label.
        """
        frame = tk.Frame(self._main_frame, relief=tk.SUNKEN, borderwidth=1)
        frame.config(padx=4, pady=2)

        # Отображение формулы в tooltip / help text
        display_text = ""
        if self._field_def.default_value is not None:
            display_text = str(self._field_def.default_value)
        self._value = display_text

        self._value_label = tk.Label(
            frame,
            text=display_text,
            anchor=tk.E,
            font=("Courier", 11),
            relief=tk.FLAT,
            bg="#f0f0f0",
        )
        self._value_label.pack(fill=tk.X, expand=True)

        return frame

    def _preprocess_formula(self, formula: str) -> str:
        """Заменяет ссылки на поля вида {field_id} на имя переменной field_id.

        Args:
            formula: Исходная строка формулы.

        Returns:
            Обработанная формула с корректными именами переменных.

        Raises:
            FormulaSyntaxError: При некорректном содержимом скобок.
        """
        result = formula
        if result.startswith("="):
            result = result[1:]

        # Заменяем {field_id} на корректные имена переменных
        pattern = r"\{([a-zA-Z_]\w*)\}"
        remaining = re.findall(pattern, result)
        result = re.sub(pattern, r"\1", result)

        # Проверяем некорректные оставшиеся скобки
        leftover = re.findall(r"\{([^}]*)\}", result)
        if leftover:
            raise FormulaSyntaxError(f"Invalid content in brackets: {{{leftover[0]}}}")

        # Проверяем, что имена переменных не конфликтуют с ключевыми словами
        for name in remaining:
            if name in {"__import__", "eval", "exec", "compile", "open", "dir"}:
                raise FormulaSecurityError(f"Forbidden identifier: {name}")

        return result

    def recalculate(self, context: dict[str, Union[int, float, str]]) -> None:
        """Пересчитывает значение по формуле с заданным контекстом.

        Args:
            context: Значения зависимых полей {field_id: value}.

        Note:
            Не генерирует on_change (read-only виджет).
        """
        if not self._formula:
            self._set_display_value("")
            return

        try:
            processed = self._preprocess_formula(self._formula)
            tree = ast.parse(processed, mode="eval")
            self._validate_ast(tree)
            result = self._eval_node(tree.body, context)
            self._set_display_value(result)
        except (FormulaSyntaxError, FormulaSecurityError, FormulaEvaluationError):
            self._set_display_value("")
        except ZeroDivisionError:
            self._set_display_value("")
        except (AttributeError, ValueError, TypeError, RuntimeError):
            self._set_display_value("")

    def _validate_ast(self, tree: ast.Expression) -> None:
        """Проверяет AST на наличие запрещённых конструкций.

        Args:
            tree: AST дерево выражения.

        Raises:
            FormulaSecurityError: При обнаружении запрещённых узлов.
        """
        for node in ast.walk(tree):
            node_type = type(node)
            if node_type not in self._ALLOWED_NODES:
                raise FormulaSecurityError(f"Forbidden AST node type: {node_type.__name__}")
            # Запрещаем dunder-атрибуты
            if isinstance(node, ast.Attribute):
                raise FormulaSecurityError("Object attribute access is forbidden")
            # Запрещаем импорты / getattr / eval / exec
            if isinstance(node, ast.Name):
                if node.id in {
                    "__import__",
                    "getattr",
                    "setattr",
                    "hasattr",
                    "eval",
                    "exec",
                    "compile",
                    "open",
                    "dir",
                    "type",
                    "globals",
                    "locals",
                    "vars",
                }:
                    raise FormulaSecurityError(f"Forbidden name: {node.id}")

    def _eval_node(self, node: ast.AST, context: dict[str, Union[int, float, str]]) -> Any:
        """Рекурсивно вычисляет AST узел с подстановкой контекста.

        Args:
            node: Узел AST для вычисления.
            context: Значения переменных.

        Returns:
            Результат вычисления узла.

        Raises:
            FormulaEvaluationError: При ошибке вычисления.
            FormulaSecurityError: При неизвестной переменной / имени.
        """
        if isinstance(node, ast.Constant):
            return node.value

        if isinstance(node, ast.Name):
            if node.id in context:
                value = context[node.id]
                if isinstance(value, str):
                    try:
                        return float(value)
                    except ValueError:
                        return value
                return value
            raise FormulaSecurityError(f"Unknown variable: {node.id}")

        if isinstance(node, ast.BinOp):
            left = self._eval_node(node.left, context)
            right = self._eval_node(node.right, context)
            op_type = type(node.op)
            if op_type not in self._BIN_OPS:
                raise FormulaEvaluationError(
                    f"Неподдерживаемая бинарная операция: {op_type.__name__}"
                )
            return self._BIN_OPS[op_type](left, right)

        if isinstance(node, ast.UnaryOp):
            operand = self._eval_node(node.operand, context)
            op_type = type(node.op)  # type: ignore[assignment]
            if op_type not in self._UNARY_OPS:
                raise FormulaEvaluationError(
                    f"Неподдерживаемая унарная операция: {op_type.__name__}"
                )
            return self._UNARY_OPS[op_type](operand)

        if isinstance(node, ast.BoolOp):
            values = [self._eval_node(v, context) for v in node.values]
            if isinstance(node.op, ast.And):
                return all(values)
            if isinstance(node.op, ast.Or):
                return any(values)
            raise FormulaEvaluationError(
                f"Неподдерживаемая логическая операция: {type(node.op).__name__}"
            )

        if isinstance(node, ast.Compare):
            left = self._eval_node(node.left, context)
            result = True
            for op, comparator in zip(node.ops, node.comparators, strict=True):
                right = self._eval_node(comparator, context)
                op_type = type(op)  # type: ignore[assignment]
                if op_type not in self._COMPARE_OPS:
                    raise FormulaEvaluationError(
                        f"Неподдерживаемая операция сравнения: {op_type.__name__}"
                    )
                result = result and self._COMPARE_OPS[op_type](left, right)
                left = right
            return result

        if isinstance(node, ast.IfExp):
            test = self._eval_node(node.test, context)
            if test:
                return self._eval_node(node.body, context)
            return self._eval_node(node.orelse, context)

        if isinstance(node, ast.Tuple):
            return tuple(self._eval_node(elt, context) for elt in node.elts)

        raise FormulaEvaluationError(f"Unsupported node type: {type(node).__name__}")

    def _set_display_value(self, value: Any) -> None:
        """Обновляет внутреннее значение и отображение без on_change."""
        if isinstance(value, (int, float)):
            display = f"{value:,.{self._decimal_places}f}".replace(",", " ")
        else:
            display = str(value) if value is not None else ""
        self._value = value
        if self._value_label is not None:
            self._value_label.config(text=display)

    def set_value(self, value: Any) -> None:
        """Устанавливает значение без генерации on_change.

        Args:
            value: Новое значение.
        """
        self._set_display_value(value)

    def get_value(self) -> Any:
        """Возвращает текущее вычисленное значение.

        Returns:
            Текущее значение (число, строка или None).
        """
        return self._value

    def validate(self) -> bool:
        """Вычисляемое поле всегда валидно.

        Returns:
            True.
        """
        return True

    def wipe_sensitive_data(self) -> None:
        """Очищает чувствительные данные из виджета."""
        self._value = None
        if self._value_label is not None:
            self._value_label.config(text="")

    def _update_font(self) -> None:
        """Обновляет шрифт Label при изменении CPI / Font настроек."""
        if self._value_label is not None:
            font_size = max(8, min(14, 14 - (self._cpi - 10) // 2))
            self._value_label.config(font=("Courier", font_size))


__all__: list[str] = ["CalculatedWidget"]
