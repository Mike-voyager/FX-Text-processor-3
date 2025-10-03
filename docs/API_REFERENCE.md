# API Reference

> **Note:** Эта документация будет автоматически генерироваться из docstrings по мере разработки.

## Статус модулей

| Модуль | Статус | Документация |
|--------|--------|--------------|
| `src/__init__.py` | ✅ Done | Ниже |
| `src/model/enums.py` | ⏳ In Progress | TBD |
| `src/model/run.py` | ❌ TODO | TBD |
| Остальные | ❌ TODO | TBD |

---

## `src.__init__`

### Functions

#### `get_logger(module_name: str) -> logging.Logger`

Получить настроенный логгер для модуля.

**Parameters:**
- `module_name` (str): Имя модуля, обычно `__name__`

**Returns:**
- `logging.Logger`: Настроенный логгер с обработчиками

**Example:**
from src import get_logger

logger = get_logger(name)
logger.info("Модуль инициализирован")

text

---

#### `load_config() -> Dict[str, Any]`

Загрузить конфигурацию из config.json или использовать defaults.

**Returns:**
- `Dict[str, Any]`: Словарь с параметрами конфигурации

**Raises:**
- `ValueError`: Если config.json содержит невалидный JSON

**Example:**
from src import load_config

config = load_config()
printer = config['default_printer']

text

---

#### `check_dependencies() -> Dict[str, bool]`

Проверить доступность опциональных зависимостей.

**Returns:**
- `Dict[str, bool]`: Словарь {package_name: is_available}

**Example:**
from src import check_dependencies

deps = check_dependencies()
if not deps['pillow']:
print("Pillow не установлен. Обработка изображений недоступна.")

text

---

## Model Layer API

### `src/model/run.py`

#### Class: `Run`

Represents a contiguous sequence of text with uniform formatting within a paragraph.

**Attributes:**
- `text` (str): The text content
- `bold` (bool): Bold formatting flag
- `italic` (bool): Italic formatting flag
- `underline` (bool): Underline formatting flag
- `double_width` (bool): Double-width character mode
- `double_height` (bool): Double-height character mode
- `font_name` (str): Font name from SUPPORTED_FONTS
- `encoding` (str): Character encoding from SUPPORTED_ENCODINGS

**Methods:**

`validate() -> None`
Validates run content and formatting attributes. Raises `ValueError` for empty text or encoding incompatibility, `TypeError` for incorrect attribute types.

`copy() -> Run`
Creates an independent deep copy of the run.

`can_merge_with(other: Run) -> bool`
Checks if two runs have identical formatting and can be merged.

`merge_with(other: Run) -> Run`
Merges two runs with identical formatting, concatenating text. Raises `ValueError` if formatting differs.

`to_dict() -> dict[str, Any]`
Serializes run to dictionary representation.

`from_dict(data: dict[str, Any]) -> Run` *(static)*
Deserializes run from dictionary. Raises `KeyError` if 'text' missing, `TypeError` if input not dict.

**Magic Methods:**
- `__len__() -> int`: Returns text length
- `__eq__(other) -> bool`: Equality comparison
- `__repr__() -> str`: Detailed string representation

#### Functions:

`merge_consecutive_runs(runs: list[Run]) -> list[Run]`
Optimizes run list by merging consecutive runs with identical formatting.

`split_by_formatting(text: str, runs: list[Run]) -> list[Run]`
Splits text into runs based on formatting template. Raises `ValueError` if total run length doesn't match text length.

**Constants:**
- `SUPPORTED_FONTS`: frozenset of valid font names ("draft", "roman", "sans_serif", "script")
- `SUPPORTED_ENCODINGS`: frozenset of valid encodings ("cp866", "ascii", "latin1")

**Usage Example:**
from src.model.run import Run, merge_consecutive_runs

Create formatted text runs
run1 = Run(text="Hello ", bold=True)
run2 = Run(text="World", bold=True)
run3 = Run(text="!", bold=False)

Merge consecutive runs with same formatting
runs = [run1, run2, run3]
optimized = merge_consecutive_runs(runs)

Result: 2 runs instead of 3
Validate and serialize
optimized.validate()
data = optimized.to_dict()

undefined

## Coming Soon

Документация для других модулей будет добавлена по мере их реализации.

---

**Последнее обновление:** October 2025
