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

## Coming Soon

Документация для других модулей будет добавлена по мере их реализации.

---

**Последнее обновление:** October 2025
