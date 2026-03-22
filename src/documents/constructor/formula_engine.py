"""Безопасный движок вычисляемых полей.

Предоставляет безопасное вычисление математических и логических выражений
с поддержкой ссылок на поля документа. Использует AST whitelisting
для предотвращения выполнения произвольного кода.

Example:
    >>> engine = FormulaEngine()
    >>> result = engine.evaluate("FIELD('price') * 1.2", {'price': 100})
    >>> print(result)
    120.0
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from datetime import date
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any, Final


class FormulaError(Exception):
    """Базовое исключение для ошибок формульного движка."""

    pass


class FormulaSecurityError(FormulaError):
    """Исключение для нарушений безопасности (запрещённые операции)."""

    pass


class FormulaSyntaxError(FormulaError):
    """Исключение для синтаксических ошибок в формуле."""

    pass


class FormulaEvaluationError(FormulaError):
    """Исключение для ошибок вычисления формулы."""

    pass


@dataclass
class FormulaEngine:
    """Безопасный движок вычисления формул.

    Поддерживает математические операции, логические выражения и
    вызовы безопасных функций. Использует AST whitelisting для
    предотвращения выполнения произвольного кода.

    Attributes:
        _ALLOWED_NODES: Множество разрешённых типов AST узлов.
        _ALLOWED_FUNCTIONS: Множество разрешённых функций.
        _context: Текущий контекст вычисления (значения полей).

    Example:
        >>> engine = FormulaEngine()
        >>> result = engine.evaluate("FIELD('qty') * FIELD('price')",
        ...                          {'qty': 10, 'price': 5.5})
        >>> print(result)
        55.0
    """

    # Разрешённые типы AST узлов (whitelist)
    _ALLOWED_NODES: Final[frozenset[type]] = frozenset(
        {
            ast.Expression,
            ast.BinOp,
            ast.UnaryOp,
            ast.Call,
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
            ast.List,
            ast.Dict,
            ast.Subscript,
            ast.Attribute,
            ast.JoinedStr,
            ast.FormattedValue,
        }
    )

    # Разрешённые функции
    _ALLOWED_FUNCTIONS: Final[frozenset[str]] = frozenset(
        {"FIELD", "SUM", "COUNT", "IF", "TODAY", "ROUND", "MIN", "MAX"}
    )

    _context: dict[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        """Инициализация движка после создания."""
        self._context = {}

    def _preprocess_formula(self, formula: str) -> str:
        """Предварительная обработка формулы.

        Преобразует альтернативный синтаксис в стандартный:
        - {field_id} -> FIELD('field_id')
        - =expression -> expression (для совместимости с Excel)

        Args:
            formula: Исходная строка формулы.

        Returns:
            Обработанная строка формулы.

        Raises:
            FormulaSyntaxError: При некорректном содержимом в фигурных скобках.
        """
        result = formula

        # Преобразуем = в начале (Excel-совместимость)
        if result.startswith("="):
            result = result[1:]

        # Преобразуем {field_id} в FIELD('field_id')
        # Используем точный паттерн: простые идентификаторы без пробелов внутри
        pattern = r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}"
        result = re.sub(pattern, r"FIELD('\1')", result)

        # Проверяем оставшиеся фигурные скобки с простым содержимым
        # Пропускаем сложные выражения (dict/set comprehensions)
        remaining = re.findall(r"\{([^}]*)\}", result)
        for content in remaining:
            # Если содержит ':', 'for', 'if' - это Python синтаксис
            if ":" in content or "for" in content or "if" in content:
                continue
            # Если похоже на невалидный идентификатор (содержит пробелы или др.)
            if content and not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", content):
                raise FormulaSyntaxError(
                    "Некорректное содержимое в фигурных скобках. "
                    "Ожидается простой идентификатор поля: {field_id}"
                )

        return result

    def evaluate(self, formula: str, context: dict[str, Any] | None = None) -> Any:
        """Вычисляет формулу в заданном контексте.

        Args:
            formula: Строка формулы для вычисления.
            context: Словарь значений полей {field_id: value}.

        Returns:
            Результат вычисления формулы.

        Raises:
            FormulaSyntaxError: При синтаксической ошибке в формуле.
            FormulaSecurityError: При обнаружении запрещённой операции.
            FormulaEvaluationError: При ошибке вычисления.

        Example:
            >>> engine = FormulaEngine()
            >>> result = engine.evaluate("FIELD('a') + FIELD('b')",
            ...                          {'a': 10, 'b': 20})
            >>> print(result)
            30
        """
        self._context = context or {}

        try:
            # Предварительная обработка формулы
            processed_formula = self._preprocess_formula(formula)

            # Парсим AST
            tree = ast.parse(processed_formula, mode="eval")

            # Проверяем безопасность AST
            self._validate_ast(tree)

            # Вычисляем
            result = self._eval_node(tree.body)
            return result

        except SyntaxError as e:
            raise FormulaSyntaxError(f"Синтаксическая ошибка в формуле: {e}") from e
        except FormulaError:
            raise
        except Exception as e:
            raise FormulaEvaluationError(f"Ошибка вычисления формулы: {e}") from e

    def get_dependencies(self, formula: str) -> set[str]:
        """Возвращает множество зависимостей (field_ids) из формулы.

        Args:
            formula: Строка формулы для анализа.

        Returns:
            Множество идентификаторов полей, от которых зависит формула.

        Raises:
            FormulaSyntaxError: При синтаксической ошибке.
            FormulaSecurityError: При обнаружении запрещённой операции.

        Example:
            >>> engine = FormulaEngine()
            >>> deps = engine.get_dependencies("FIELD('a') + FIELD('b')")
            >>> print(deps)
            {'a', 'b'}
        """
        try:
            processed = self._preprocess_formula(formula)
            tree = ast.parse(processed, mode="eval")
            self._validate_ast(tree)
            return self._extract_field_dependencies(tree.body)
        except SyntaxError as e:
            raise FormulaSyntaxError(f"Синтаксическая ошибка: {e}") from e

    def _extract_field_dependencies(self, node: ast.AST) -> set[str]:
        """Рекурсивно извлекает зависимости от полей из AST.

        Args:
            node: Корневой узел AST для анализа.

        Returns:
            Множество идентификаторов полей.
        """
        deps: set[str] = set()

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name) and child.func.id == "FIELD":
                    if child.args and isinstance(child.args[0], ast.Constant):
                        deps.add(str(child.args[0].value))

        return deps

    def _validate_ast(self, tree: ast.Expression) -> None:
        """Проверяет AST на наличие запрещённых конструкций.

        Использует двухпроходную проверку:
        1. Проверка типов узлов (все узлы должны быть в whitelist)
        2. Проверка вызовов функций (только разрешённые функции)

        Args:
            tree: AST выражение для проверки.

        Raises:
            FormulaSecurityError: При обнаружении запрещённой конструкции.
        """
        # Первый проход: проверяем типы всех узлов
        for node in ast.walk(tree):
            node_type = type(node)
            if node_type not in self._ALLOWED_NODES:
                raise FormulaSecurityError(f"Запрещённый тип AST узла: {node_type.__name__}")

            # Проверка доступа к dunder-атрибутам
            if isinstance(node, ast.Attribute):
                if node.attr.startswith("__") and node.attr.endswith("__"):
                    raise FormulaSecurityError(f"Доступ к dunder-атрибутам запрещён: {node.attr}")

        # Второй проход: проверяем вызовы функций
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._validate_call(node)

    def _validate_call(self, node: ast.Call) -> None:
        """Проверяет вызов функции на безопасность.

        Рекурсивно проверяет вложенные вызовы, затем проверяет,
        что вызываемая функция разрешена.

        Args:
            node: Узел вызова функции.

        Raises:
            FormulaSecurityError: При обнаружении небезопасного вызова.
        """
        # Сначала проверяем вложенные вызовы (рекурсивно)
        for arg in node.args:
            if isinstance(arg, ast.Call):
                self._validate_call(arg)

        # Проверяем, что func является именем функции
        if isinstance(node.func, ast.Call):
            # Вызов результата другого вызова: func()()
            # Проверяем внутренний вызов на наличие getattr
            inner_func = node.func.func
            if isinstance(inner_func, ast.Name) and inner_func.id == "getattr":
                raise FormulaSecurityError("Запрещённая функция: getattr")
            raise FormulaSecurityError("Вызов непрямых функций запрещён")
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
            # Проверяем запрещённые функции
            if func_name in ("getattr", "setattr", "hasattr"):
                raise FormulaSecurityError(f"Запрещённая функция: {func_name}")
            if func_name not in self._ALLOWED_FUNCTIONS:
                raise FormulaSecurityError(f"Запрещённая функция: {func_name}")
        elif isinstance(node.func, ast.Attribute):
            # Методы объектов запрещены (кроме безопасных)
            raise FormulaSecurityError("Вызов методов объектов запрещён")
        else:
            # Любые другие callable выражения запрещены
            raise FormulaSecurityError("Вызов непрямых функций запрещён")

    def _eval_node(self, node: ast.AST) -> Any:
        """Рекурсивно вычисляет значение AST узла.

        Args:
            node: Узел AST для вычисления.

        Returns:
            Значение узла.

        Raises:
            FormulaEvaluationError: При ошибке вычисления.
        """
        if isinstance(node, ast.Constant):
            return node.value

        elif isinstance(node, ast.Name):
            # Имена переменных не поддерживаются (только FIELD)
            raise FormulaEvaluationError(f"Неизвестное имя: {node.id}")

        elif isinstance(node, ast.BinOp):
            left = self._eval_node(node.left)
            right = self._eval_node(node.right)
            return self._eval_binop(node.op, left, right)

        elif isinstance(node, ast.UnaryOp):
            operand = self._eval_node(node.operand)
            return self._eval_unaryop(node.op, operand)

        elif isinstance(node, ast.Call):
            return self._eval_call(node)

        elif isinstance(node, ast.Compare):
            left = self._eval_node(node.left)
            result = True
            for op, comparator in zip(node.ops, node.comparators, strict=True):
                right = self._eval_node(comparator)
                result = result and self._eval_compare(op, left, right)
                left = right
            return result

        elif isinstance(node, ast.BoolOp):
            values = [self._eval_node(v) for v in node.values]
            return self._eval_boolop(node.op, values)

        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not self._eval_node(node.operand)

        elif isinstance(node, ast.IfExp):
            test = self._eval_node(node.test)
            if test:
                return self._eval_node(node.body)
            else:
                return self._eval_node(node.orelse)

        elif isinstance(node, ast.Tuple):
            return tuple(self._eval_node(elt) for elt in node.elts)

        elif isinstance(node, ast.List):
            return [self._eval_node(elt) for elt in node.elts]

        elif isinstance(node, ast.Dict):
            dict_result: dict[Any, Any] = {}
            for k, v in zip(node.keys, node.values, strict=True):
                if k is None:
                    # **kwargs unpacking not supported
                    raise FormulaEvaluationError("**kwargs unpacking is not supported")
                dict_result[self._eval_node(k)] = self._eval_node(v)
            return dict_result

        else:
            raise FormulaEvaluationError(f"Неподдерживаемый тип узла: {type(node).__name__}")

    def _eval_binop(self, op: ast.operator, left: Any, right: Any) -> Any:
        """Вычисляет бинарную операцию.

        Args:
            op: Оператор AST.
            left: Левый операнд.
            right: Правый операнд.

        Returns:
            Результат операции.

        Raises:
            FormulaEvaluationError: При делении на ноль.
        """
        try:
            if isinstance(op, ast.Add):
                return left + right
            elif isinstance(op, ast.Sub):
                return left - right
            elif isinstance(op, ast.Mult):
                return left * right
            elif isinstance(op, ast.Div):
                return left / right
            elif isinstance(op, ast.FloorDiv):
                return left // right
            elif isinstance(op, ast.Mod):
                return left % right
            elif isinstance(op, ast.Pow):
                return left**right
            else:
                raise FormulaEvaluationError(
                    f"Неподдерживаемая бинарная операция: {type(op).__name__}"
                )
        except ZeroDivisionError:
            raise FormulaEvaluationError("Деление на ноль") from None

    def _eval_unaryop(self, op: ast.unaryop, operand: Any) -> Any:
        """Вычисляет унарную операцию.

        Args:
            op: Унарный оператор AST.
            operand: Операнд.

        Returns:
            Результат операции.
        """
        if isinstance(op, ast.UAdd):
            return +operand
        elif isinstance(op, ast.USub):
            return -operand
        elif isinstance(op, ast.Not):
            return not operand
        else:
            raise FormulaEvaluationError(f"Неподдерживаемая унарная операция: {type(op).__name__}")

    def _eval_call(self, node: ast.Call) -> Any:
        """Вычисляет вызов функции.

        Args:
            node: Узел вызова функции.

        Returns:
            Результат вызова функции.

        Raises:
            FormulaEvaluationError: При ошибке вызова или неизвестной функции.
            FormulaSecurityError: При попытке непрямого вызова через контекст.
        """
        if isinstance(node.func, ast.Name):
            func_name = node.func.id

            # Проверяем, не является ли имя переменной из контекста
            # Вызов переменной из контекста как функции - это непрямой вызов
            if func_name in self._context:
                raise FormulaSecurityError("Вызов непрямых функций запрещён")

            func = getattr(self, f"_func_{func_name.lower()}", None)
            if func is None:
                raise FormulaEvaluationError(f"Неизвестная функция: {func_name}")

            args = [self._eval_node(arg) for arg in node.args]
            return func(*args)
        else:
            raise FormulaEvaluationError("Неподдерживаемый тип вызова функции")

    def _eval_compare(self, op: ast.cmpop, left: Any, right: Any) -> bool:
        """Вычисляет операцию сравнения.

        Args:
            op: Оператор сравнения AST.
            left: Левый операнд.
            right: Правый операнд.

        Returns:
            Результат сравнения.
        """
        result: bool
        if isinstance(op, ast.Lt):
            result = left < right
        elif isinstance(op, ast.LtE):
            result = left <= right
        elif isinstance(op, ast.Gt):
            result = left > right
        elif isinstance(op, ast.GtE):
            result = left >= right
        elif isinstance(op, ast.Eq):
            result = left == right
        elif isinstance(op, ast.NotEq):
            result = left != right
        else:
            raise FormulaEvaluationError(
                f"Неподдерживаемая операция сравнения: {type(op).__name__}"
            )
        return result

    def _eval_boolop(self, op: ast.boolop, values: list[Any]) -> bool:
        """Вычисляет логическую операцию.

        Args:
            op: Логический оператор AST.
            values: Список значений.

        Returns:
            Результат логической операции.
        """
        if isinstance(op, ast.And):
            return all(values)
        elif isinstance(op, ast.Or):
            return any(values)
        else:
            raise FormulaEvaluationError(
                f"Неподдерживаемая логическая операция: {type(op).__name__}"
            )

    def _func_field(self, field_id: str) -> Any:
        """Возвращает значение поля из контекста.

        Args:
            field_id: Идентификатор поля.

        Returns:
            Значение поля из контекста.

        Raises:
            FormulaEvaluationError: Если поле не найдено.
        """
        if field_id not in self._context:
            raise FormulaEvaluationError(f"Поле не найдено: {field_id}")
        return self._context[field_id]

    def _func_sum(self, table_ref: Any) -> Decimal:
        """Вычисляет сумму значений в таблице.

        Args:
            table_ref: Ссылка на таблицу (список словарей или список списков)
                       или имя поля содержащего таблицу.

        Returns:
            Сумма числовых значений.
        """
        values = self._resolve_table_values(table_ref)
        total = Decimal("0")
        for v in values:
            if v is not None and v != "":
                try:
                    total += Decimal(str(v))
                except (InvalidOperation, ValueError):
                    pass  # Пропускаем нечисловые значения
        return total

    def _func_count(self, table_ref: Any) -> int:
        """Подсчитывает количество непустых значений в таблице.

        Args:
            table_ref: Ссылка на таблицу.

        Returns:
            Количество непустых значений.
        """
        try:
            values = self._resolve_table_values(table_ref, _is_count=True)
            return sum(1 for v in values if v is not None and v != "")
        except FormulaEvaluationError:
            # Для COUNT возвращаем 0 при ошибке
            return 0

    def _func_if(self, condition: bool, true_val: Any, false_val: Any) -> Any:
        """Условное выражение.

        Args:
            condition: Условие.
            true_val: Значение если условие истинно.
            false_val: Значение если условие ложно.

        Returns:
            Значение в зависимости от условия.
        """
        return true_val if condition else false_val

    def _func_today(self) -> date:
        """Возвращает текущую дату.

        Returns:
            Текущая дата.
        """
        return date.today()

    def _func_round(self, value: Any, digits: int = 0) -> float:
        """Округляет число до указанного количества знаков.

        Args:
            value: Значение для округления.
            digits: Количество знаков после запятой (по умолчанию 0).

        Returns:
            Округлённое значение как float.
        """
        try:
            d = Decimal(str(value))
            if digits < 0:
                return float(d.quantize(Decimal("1"), rounding=ROUND_HALF_UP))
            quantize_str = "0." + "0" * digits if digits > 0 else "1"
            return float(d.quantize(Decimal(quantize_str), rounding=ROUND_HALF_UP))
        except (InvalidOperation, ValueError):
            return 0.0

    def _func_min(self, *values: Any) -> Any:
        """Возвращает минимальное значение из аргументов.

        Args:
            *values: Значения для сравнения.

        Returns:
            Минимальное значение, или 0 если аргументов нет.

        Example:
            >>> engine = FormulaEngine()
            >>> engine.evaluate("MIN(5, 3, 8)", {})
            3
        """
        if not values:
            return 0
        return min(values)

    def _func_max(self, *values: Any) -> Any:
        """Возвращает максимальное значение из аргументов.

        Args:
            *values: Значения для сравнения.

        Returns:
            Максимальное значение, или 0 если аргументов нет.

        Example:
            >>> engine = FormulaEngine()
            >>> engine.evaluate("MAX(5, 3, 8)", {})
            8
        """
        if not values:
            return 0
        return max(values)

    def _resolve_table_values(self, table_ref: Any, *, _is_count: bool = False) -> list[Any]:
        """Разрешает ссылку на таблицу в список значений.

        Args:
            table_ref: Ссылка на таблицу (строка с точечной нотацией
                      или прямой список).
            _is_count: Флаг вызова из COUNT (возвращает 0 вместо ошибки).

        Returns:
            Список значений из таблицы.

        Raises:
            FormulaEvaluationError: При неверном формате ссылки.
        """
        if isinstance(table_ref, str):
            # Формат: "table_name.column_name" или просто "field_id"
            if "." in table_ref:
                parts = table_ref.split(".")
                if len(parts) != 2:
                    raise FormulaEvaluationError(f"Некорректный формат ссылки: {table_ref}")
                table_name, col_name = parts
                table_data = self._context.get(table_name)
                if table_data is None:
                    raise FormulaEvaluationError(f"Таблица не найдена: {table_name}")
                if not isinstance(table_data, (list, tuple)):
                    if _is_count:
                        return []
                    raise FormulaEvaluationError(f"Поле {table_name} не является таблицей")

                def _get_col_value(row: Any, col: str) -> Any:
                    if isinstance(row, dict):
                        return row.get(col)
                    if isinstance(row, (list, tuple)):
                        # For list/tuple, col should be an integer index
                        try:
                            idx = int(col)
                            return row[idx] if 0 <= idx < len(row) else None
                        except (ValueError, TypeError):
                            return None
                    return None

                return [_get_col_value(row, col_name) for row in table_data]
            else:
                # Простое поле без точки - проверяем формат для SUM/COUNT
                raise FormulaEvaluationError(f"Некорректный формат ссылки: {table_ref}")
        elif isinstance(table_ref, (list, tuple)):
            return list(table_ref)
        else:
            raise FormulaEvaluationError(f"Некорректный тип ссылки: {type(table_ref).__name__}")

    def detect_circular_dependencies(self, formulas: dict[str, str]) -> list[str] | None:
        """Обнаруживает циклические зависимости между формулами.

        Использует DFS для поиска циклов в графе зависимостей.

        Args:
            formulas: Словарь {field_id: formula_string}.

        Returns:
            Список field_ids образующих цикл, или None если циклов нет.

        Example:
            >>> engine = FormulaEngine()
            >>> formulas = {'a': "FIELD('b')", 'b': "FIELD('a')"}
            >>> cycle = engine.detect_circular_dependencies(formulas)
            >>> print(cycle)
            ['a', 'b', 'a']
        """
        # Строим граф зависимостей
        graph: dict[str, set[str]] = {}
        for field_id, formula in formulas.items():
            try:
                deps = self.get_dependencies(formula)
                graph[field_id] = deps
            except FormulaError:
                graph[field_id] = set()

        # DFS для поиска циклов
        visited: set[str] = set()
        rec_stack: set[str] = set()
        path: list[str] = []

        def dfs(node: str) -> list[str] | None:
            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            for neighbor in graph.get(node, set()):
                if neighbor not in visited:
                    result = dfs(neighbor)
                    if result:
                        return result
                elif neighbor in rec_stack:
                    # Нашли цикл
                    cycle_start = path.index(neighbor)
                    return path[cycle_start:] + [neighbor]

            path.pop()
            rec_stack.remove(node)
            return None

        for node in graph:
            if node not in visited:
                result = dfs(node)
                if result:
                    return result

        return None

    def has_circular_dependency(self, formulas: dict[str, str]) -> bool:
        """Проверяет наличие циклических зависимостей.

        Args:
            formulas: Словарь {field_id: formula_string}.

        Returns:
            True если есть циклические зависимости, иначе False.

        Example:
            >>> engine = FormulaEngine()
            >>> formulas = {'a': "FIELD('b')", 'b': "FIELD('a')"}
            >>> result = engine.has_circular_dependency(formulas)
            >>> print(result)
            True
        """
        return self.detect_circular_dependencies(formulas) is not None
