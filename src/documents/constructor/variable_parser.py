"""Variable parser for template substitution.

Provides:
- VariableParser: Parses and substitutes variables in templates
"""

import re
from typing import Any


class VariableParser:
    """Парсер шаблонных переменных.

    Поддерживаемые синтаксисы:
      - {{variable_name}}  (двойные фигурные скобки)
      - {variable_name}    (одинарные фигурные скобки)
      - ${variable_name}   (shell-стиль)

    Предопределённые ESC/P переменные:
      - PAGE_BREAK    -> Form Feed (0x0C)
      - RESET_PRINTER -> ESC @ (0x1B 0x40)
      - LINE_FEED     -> Line Feed (0x0A)
    """

    # Patterns for different syntaxes
    PATTERN_DOUBLE_BRACES = re.compile(r"\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}")
    PATTERN_SINGLE_BRACES = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")
    PATTERN_DOLLAR = re.compile(r"\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}")

    # ESC/P predefined variables
    ESC_VARIABLES: dict[str, bytes] = {
        "PAGE_BREAK": b"\x0c",
        "RESET_PRINTER": b"\x1b\x40",
        "LINE_FEED": b"\x0a",
    }

    def parse(self, template: str, variables: dict[str, Any]) -> str:
        """Подставляет значения переменных в шаблон.

        Args:
            template: Строка-шаблон с переменными.
            variables: Словарь {имя_переменной: значение}.

        Returns:
            Результат подстановки.
        """
        result = template

        # Заменяем двойные скобки {{var}}
        result = self.PATTERN_DOUBLE_BRACES.sub(
            lambda m: str(variables.get(m.group(1), m.group(0))), result
        )

        # Заменяем одинарные скобки {var}
        result = self.PATTERN_SINGLE_BRACES.sub(
            lambda m: str(variables.get(m.group(1), m.group(0))), result
        )

        # Заменяем доллар ${var}
        result = self.PATTERN_DOLLAR.sub(
            lambda m: str(variables.get(m.group(1), m.group(0))), result
        )

        return result

    def extract_variables(self, template: str) -> list[str]:
        """Извлекает все имена переменных из шаблона.

        Args:
            template: Строка-шаблон.

        Returns:
            Список уникальных имён переменных.
        """
        variables: set[str] = set()

        # Двойные скобки
        variables.update(self.PATTERN_DOUBLE_BRACES.findall(template))

        # Одинарные скобки
        variables.update(self.PATTERN_SINGLE_BRACES.findall(template))

        # Доллар
        variables.update(self.PATTERN_DOLLAR.findall(template))

        return sorted(variables)

    def substitute_batch(
        self, templates: list[str], variables: dict[str, Any]
    ) -> list[str]:
        """Пакетная подстановка переменных.

        Args:
            templates: Список шаблонов.
            variables: Словарь переменных.

        Returns:
            Список результатов подстановки.
        """
        return [self.parse(t, variables) for t in templates]

    def parse_esc_variables(self, template: str) -> bytes:
        """Обрабатывает ESC/P переменные.

        Заменяет имена переменных (например, PAGE_BREAK) на
        соответствующие ESC/P байты.

        Args:
            template: Строка-шаблона.

        Returns:
            Результирующие байты.
        """
        result = template

        for var_name, esc_bytes in self.ESC_VARIABLES.items():
            # Заменяем {{VAR}} на байты
            pattern = "{{" + var_name + "}}"
            result = result.replace(pattern, esc_bytes.decode("latin-1"))

        # Кодируем результат в байты
        return result.encode("latin-1")

    def has_variables(self, template: str) -> bool:
        """Проверяет, содержит ли шаблон переменные.

        Args:
            template: Строка-шаблона.

        Returns:
            True если есть переменные.
        """
        return bool(self.extract_variables(template))

    def validate_variables(
        self, template: str, variables: dict[str, Any]
    ) -> list[str]:
        """Валидирует наличие всех переменных.

        Args:
            template: Строка-шаблона.
            variables: Доступные переменные.

        Returns:
            Список отсутствующих переменных.
        """
        required = set(self.extract_variables(template))
        available = set(str(k) for k in variables.keys())

        missing = required - available
        return sorted(missing)