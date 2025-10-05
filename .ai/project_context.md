# Project Context for AI

## Quick Facts
- **Name**: ESC/P Text Editor
- **Purpose**: WYSIWYG editor for Epson FX-890 dot matrix printer
- **Language**: Python 3.11+
- **Architecture**: MVC (Model-View-Controller)
- **GUI**: Tkinter
- **Current Version**: 0.1.0
- **Status**: Active Development (10% complete)

## Key Design Decisions

1. **Src-layout**: Код в `src/`, не в корне
2. **Strict typing**: `mypy --strict` обязательно
3. **TDD**: Тесты пишутся первыми
4. **PC866**: Основная кодировка для русского языка
5. **Direct printing**: WritePrinter API, обход драйвера Windows
6. **Google-style docstrings**: На русском языке
7. **100% coverage**: Для всех модулей
8. **Black formatting**: Line length 100


## Important Files for Context
- `src/__init__.py` — Пример стиля кода
- `tests/unit/test_init.py` — Пример тестов
- `docs/ARCHITECTURE.md` — Дизайн системы
- `docs/PROMPT_TEMPLATES.md` — Как генерировать код

## Code Style Examples

### Type Hints
def process_text(text: str, bold: bool = False) -> bytes:
"""Обработать текст."""
...

text

### Docstrings (Google-style, Russian)
def get_logger(module_name: str) -> logging.Logger:
"""
Получить настроенный логгер для модуля.

text
Args:
    module_name: Имя модуля, обычно `__name__`

Returns:
    Настроенный экземпляр Logger

Example:
    >>> logger = get_logger(__name__)
    >>> logger.info("Test")
"""
text

### Error Handling
try:
result = risky_operation()
except SpecificError as e:
logger.error(f"Operation failed: {e}")
return default_value

text

### Dataclasses
from dataclasses import dataclass, field
from typing import List

@dataclass
class Document:
"""Класс документа."""

text
title: str
sections: List['Section'] = field(default_factory=list)

def add_section(self, section: 'Section') -> None:
    """Добавить секцию."""
    self.sections.append(section)
text

## Testing Pattern
import pytest

class TestModule:
"""Тесты для модуля."""

text
def test_basic_functionality(self) -> None:
    """Тест базовой функциональности."""
    # Arrange
    obj = MyClass(param=value)

    # Act
    result = obj.method()

    # Assert
    assert result == expected

def test_edge_case_empty_input(self) -> None:
    """Тест с пустым вводом."""
    obj = MyClass(param="")

    with pytest.raises(ValueError, match="param не может быть пустым"):
        obj.method()
text

## Common Imports
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path
import logging

from src import get_logger
from src.model.enums import Alignment, FontFamily

text

## Architecture Rules

### Model Layer
- **NO** imports from View or Controller
- **NO** external dependencies (только stdlib)
- **YES** dataclasses where possible
- **YES** immutable where possible

### View Layer
- **NO** business logic
- **YES** imports from Model (readonly)
- **YES** callbacks to Controller

### Controller Layer
- **YES** imports from Model
- **YES** imports from View (для обновления)
- **YES** business logic

## Naming Conventions
- Classes: `PascalCase`
- Functions/methods: `snake_case`
- Constants: `UPPER_CASE`
- Private: `_leading_underscore`
- Type variables: `T`, `K`, `V`

## File Structure Template
"""
Module short description.

Detailed description of module purpose and usage.
"""

from typing import List, Optional
import logging

from src import get_logger

logger = get_logger(name)

Constants
DEFAULT_VALUE = 42

Type aliases
ConfigDict = Dict[str, Any]

Classes
class MyClass:
"""Class description."""

text
def __init__(self, param: str) -> None:
    """Initialize."""
    self.param = param

def method(self) -> str:
    """Method description."""
    return self.param
Functions
def helper_function(arg: int) -> int:
"""Helper function description."""
return arg * 2

text

## Error Messages
- **Russian** for user-facing errors
- **English** for developer errors
- Include context in error messages
- Use f-strings for formatting

Good
raise ValueError(f"Недопустимое значение для параметра 'cpi': {cpi}. Ожидается от 10 до 20.")

Bad
raise ValueError("Invalid value")

text

## Performance Considerations
- Use `bytearray` for building ESC/P commands
- Cache frequently used commands
- Lazy load heavy resources
- Use generators for large collections

## Security Considerations
- Validate all user inputs
- Sanitize file paths
- Limit image sizes (max 10 MB)
- Timeout for printer operations (30s)

---

**Last Updated:** October 2025
**Version:** 1.0
