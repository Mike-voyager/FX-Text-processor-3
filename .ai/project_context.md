# Project Context for AI

## Quick Facts
- **Name**: ESC/P Text Editor
- **Purpose**: WYSIWYG editor for Epson FX-890 matrix printer
- **Language**: Python 3.11+
- **Architecture**: MVC (Model-View-Controller)
- **GUI**: Tkinter
- **Current Version**: 0.1.0
- **Status**: Active Development (10% complete)

## Key Design Decisions
1. **Src-layout**: Code in `src/`, not root
2. **Strict typing**: mypy --strict required
3. **TDD**: Tests first, then implementation
4. **PC866**: Primary encoding for Russian
5. **Direct printing**: WritePrinter API, bypass driver

## Current Progress
- ✅ Project structure
- ✅ Core module (`src/__init__.py`)
- ✅ Testing infrastructure
- ⏳ Model layer (10%)
- ❌ ESC/P commands (0%)
- ❌ GUI (0%)

## Next Priorities
1. Complete `src/model/enums.py`
2. Implement `src/model/run.py`
3. Implement `src/model/paragraph.py`
4. Implement `src/model/document.py`

## Important Files for Context
- `src/__init__.py` - Example of code style
- `tests/unit/test_init.py` - Example of tests
- `docs/ARCHITECTURE.md` - System design
- `docs/PROMPT_TEMPLATES.md` - How to generate code

## Code Style Examples

### Type Hints
def process_text(text: str, bold: bool = False) -> bytes:
...

text

### Docstrings
def get_logger(module_name: str) -> logging.Logger:
"""
Получить настроенный логгер для модуля.

text
Args:
    module_name: Имя модуля

Returns:
    Экземпляр Logger

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

## Common Patterns

### Model Class
from dataclasses import dataclass
from typing import List

@dataclass
class ModelClass:
"""Краткое описание."""

text
field1: str
field2: int
children: List['ChildClass'] = field(default_factory=list)

def method(self) -> None:
    """Метод описание."""
    ...
text

### Builder Pattern
class CommandBuilder:
"""Строитель команд."""

text
def __init__(self) -> None:
    self._commands: bytearray = bytearray()

def add_text(self, text: str) -> 'CommandBuilder':
    """Добавить текст."""
    self._commands.extend(text.encode('cp866'))
    return self

def build(self) -> bytes:
    """Собрать команды."""
    return bytes(self._commands)
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
text
undefined
