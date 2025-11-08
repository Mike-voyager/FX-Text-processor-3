# \# Project Context for AI

## Quick Facts

- **Name**: FX Text Processor 3
- **Purpose**: Professional WYSIWYG editor for Epson FX-890 dot matrix printer with enterprise security
- **Language**: Python 3.11+ (3.13 compatible)
- **Architecture**: MVC (Model-View-Controller) + Service Layer
- **GUI**: Tkinter (in development)
- **Current Version**: 0.1.0-alpha
- **Status**: Active Development (~48% complete)
- **Last Major Update**: November 8, 2025


## Project Progress Overview

| Subsystem | Status | Coverage | Tests |
| :-- | :-- | :-- | :-- |
| Core Infrastructure | ✅ 100% | ~100% | - |
| Data Models | ✅ 86% | ~92% | 310+ |
| ESC/P Commands | ✅ 100% | >95% | 420+ |
| Barcode Generation | ✅ 100% | ~95% | 85+ |
| Security (Crypto) | ✅ 100% | ~95% | 180+ |
| Security (Auth) | ⚠️ 77% | ~90% | 150+ |
| Form Builder | ⚠️ 82% | ~75% | 95+ |
| GUI (View) | ❌ 0% | - | - |
| Controllers/Services | ❌ 0% | - | - |

**Total: 1,045+ tests, ~80% overall coverage, ~97% pass rate**

## Key Design Decisions

### Architecture

1. **Src-layout**: Код в `src/`, не в корне проекта
2. **MVC + Services**: Model-View-Controller с дополнительным Service Layer
3. **Strict typing**: `mypy --strict` обязательно для всех модулей
4. **TDD**: Тесты пишутся первыми, минимум 90% coverage
5. **Dependency Injection**: Использование DI для тестируемости (см. `app_context.py`)

### Domain-Specific

6. **PC866**: Основная кодировка для русского языка в ESC/P
7. **Direct printing**: WritePrinter API, обход драйвера Windows
8. **ESC/P Protocol**: Полная поддержка Epson FX-890 команд
9. **Zero Trust Security**: Military-grade криптография для защищённых бланков и защищенных файлов

### Deployment \& Runtime

10. **Portable Application**: Полностью портативное приложение без установки
11. **Cloud-Synced**: Вся папка приложения в облачном хранилище для синхронизации между ПК
12. **Offline-First**: Полная работоспособность без интернета
13. **Encrypted Storage**: Критичные данные зашифрованы с Argon2id (keystore.enc)
14. **Floppy Disk Support**: Опциональная оптимизация для 3.5" дискет (1.44 MB)
15. **Auto-Backup**: Автоматическое резервное копирование в `backups/`

**→ Детали**: См. [docs/DEPLOYMENT_ARCHITECTURE.md](docs/DEPLOYMENT_ARCHITECTURE.md)

### Code Quality

16. **Black formatting**: Line length 88 (стандарт), Python 3.14 target
17. **Google-style docstrings**: На русском языке
18. **Parametrized tests**: pytest.mark.parametrize для множественных сценариев
19. **Security markers**: pytest.mark.security для критичных тестов

## Important Files for Context

### Must-Read Before Starting

- `.ai/project_context.md` — Этот файл (правила и стандарты)
- `README.md` — Общее описание, статус разработки
- `docs/ARCHITECTURE.md` — Архитектура системы
- `docs/DEPLOYMENT_ARCHITECTURE.md` — Портативность, облако, шифрование
- `docs/PROMPT_TEMPLATES.md` — Шаблоны для генерации кода с AI


### Code Style References

- `src/__init__.py` — Пример инициализации модуля, логирование
- `src/app_context.py` — Dependency Injection контейнер
- `src/model/table.py` — Эталонный пример Model класса
- `tests/unit/model/test_table.py` — Эталонный пример тестов


### Architecture Documents

- `pyproject.toml` — Конфигурация проекта, зависимости
- `pytest.ini` — Настройки тестирования
- `mypy.ini` — Настройки type checking


## Security Architecture (High-Level)

### Key Management

- **Derivation**: Argon2id (master_password + salt + pepper)
- **Storage**: Единственный зашифрованный `keystore.enc` в облаке
- **Local Files**: `~/.fxtextprocessor/salt.bin` + `pepper.bin` (НЕ синхронизируются)
- **Master Password**: Единая точка доступа ко всем ключам


### File Encryption Policy

- **Обычные документы**: НЕ зашифрованы (для расшаривания с коллегами)
- **Личные документы**: Опционально зашифрованы (выбор пользователя)
- **Защищённые бланки**: ВСЕГДА зашифрованы + цифровая подпись

**→ Детали**: См. [docs/SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md)

## Cloud Synchronization (Brief)

### Portable Structure

CloudStorage/FXTextProcessor/
├── data/
│   ├── documents/
│   │   ├── invoice_2025.fxsd           \# FX Super Document
│   │   └── report.fxsd.enc             \# FX Super Document Encrypted
│   ├── templates/
│   │   └── invoice_template.fxstpl    \# FX Super Template
│   ├── private/
│   │   └── salary.fxsd.enc            \# Зашифрованный личный документ
│   └── secure/
│       ├── keystore.fxskeystore.enc   \# FX Super Keystore
│       ├── blanks/
│       │   └── blank_A001.fxsblank    \# FX Super Blank
│       └── signatures/
│           └── blank_A001.fxssig      \# FX Super Signature
├── backups/
│   └── 2025-11-08_22-00.fxsbackup     \# FX Super Backup
├── config/
│   └── settings.fxsconfig             \# FX Super Config
└── escp/
    ├── test_commands.escp             \# ESC/P Raw
    └── autoprint.escps                \# ESC/P Script

### Security

- Ключи НЕ в облаке (только `salt.bin` + `pepper.bin` локально)
- Облако видит только зашифрованные данные
- Без мастер-пароля + локальных файлов → расшифровка невозможна

**→ Детали**: См. [docs/DEPLOYMENT_ARCHITECTURE.md](docs/DEPLOYMENT_ARCHITECTURE.md)

## Code Style Examples

### Type Hints (Строгая типизация)

from typing import Optional, List, Dict, Any
from pathlib import Path

def process_text(
text: str,
*, \# force keyword-only arguments
bold: bool = False,
encoding: str = "PC866"
) -> bytes:
"""
Обработать текст для печати.

Args:
    text: Текст для обработки
    bold: Применить жирное начертание
    encoding: Кодировка (по умолчанию PC866)

Returns:
    Закодированные байты для отправки на принтер

Raises:
    ValueError: Если текст пустой или encoding неподдерживаемый

Example:
    >>> data = process_text("Привет", bold=True)
    >>> print(data.hex())
"""
...

### Docstrings (Google-style, Russian)

class SecureDocument:
"""
Документ с криптографической защитой.

Поддерживает цифровые подписи Ed25519 и шифрование AES-256-GCM.
Используется для защищённых бланков строгой отчётности.

Attributes:
    content: Содержимое документа
    signature: Цифровая подпись (если подписан)
    encrypted: Флаг шифрования

Example:
    >>> doc = SecureDocument(content="Invoice \#123")
    >>> doc.sign(private_key)
    >>> doc.encrypt(public_key)
    >>> print(doc.verify())
    True
"""

def __init__(self, content: str) -> None:
    """
    Инициализировать защищённый документ.

Args:
        content: Текстовое содержимое документа

Raises:
        ValueError: Если content пустой
    """
    ...

### Error Handling (Контекст + логирование)

from src import get_logger

logger = get_logger(name)

try:
result = risky_operation(param)
except SpecificError as e:
logger.error(
f"Operation failed for param={param}: {e}",
exc_info=True \# включить stack trace
)
raise \# re-raise для обработки выше
except Exception as e:
logger.critical(f"Unexpected error: {e}", exc_info=True)
return default_value

### Dataclasses (Immutable где возможно)

from dataclasses import dataclass, field
from typing import List, Optional

@dataclass(frozen=True) \# immutable
class Paragraph:
"""
Параграф документа.

Attributes:
    text: Текстовое содержимое
    alignment: Выравнивание (LEFT/CENTER/RIGHT)
    runs: Список форматированных фрагментов
"""
text: str
alignment: Alignment = Alignment.LEFT
runs: List['Run'] = field(default_factory=list)

def add_run(self, run: 'Run') -> 'Paragraph':
    """
    Добавить run (создаёт новый объект - immutable).

Args:
        run: Форматированный фрагмент текста

Returns:
        Новый Paragraph с добавленным run
    """
    return Paragraph(
        text=self.text,
        alignment=self.alignment,
        runs=[*self.runs, run]
    )

### Protocols (Duck Typing с типизацией)

from typing import Protocol, runtime_checkable

@runtime_checkable
class Encryptable(Protocol):
"""Протокол для объектов, поддерживающих шифрование."""

def encrypt(self, key: bytes) -> bytes:
    """Зашифровать данные."""
    ...

def decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
    """Расшифровать данные."""
    ...

## Testing Patterns

### Basic Test Structure (AAA Pattern)

import pytest
from src.model.table import Table, Cell

class TestTable:
"""Тесты для класса Table."""

def test_create_table_basic(self) -> None:
    """Создание таблицы с базовыми параметрами."""
    \# Arrange
    rows, cols = 3, 4

\# Act
    table = Table(rows=rows, cols=cols)

\# Assert
    assert table.rows == rows
    assert table.cols == cols
    assert len(table.cells) == rows * cols

### Parametrized Tests (Множественные сценарии)

@pytest.mark.parametrize("input_value,expected", [
("test", b"test"),
("привет", b"\xaf\xe0\xa8\xa2\xa5\xe2"), \# PC866
("", b""),
])
def test_encode_text(input_value: str, expected: bytes) -> None:
"""Тест кодирования текста в разных сценариях."""
result = encode_text(input_value, encoding="PC866")
assert result == expected

### Fixtures (Переиспользуемые данные)

@pytest.fixture
def sample_document() -> Document:
"""Тестовый документ с базовым содержимым."""
doc = Document(title="Test Document")
doc.add_section(Section(title="Section 1"))
return doc

def test_document_with_fixture(sample_document: Document) -> None:
"""Тест с использованием fixture."""
assert sample_document.title == "Test Document"
assert len(sample_document.sections) == 1

### Security Tests (Критичные тесты безопасности)

@pytest.mark.security
def test_password_hashing_argon2id() -> None:
"""Проверка корректности Argon2id хеширования."""
password = "SecurePassword123!"

# Хешируем

hash_result = hash_password(password)

# Проверяем формат Argon2id

assert hash_result.startswith("$argon2id$")

# Проверяем верификацию

assert verify_password(password, hash_result) is True
assert verify_password("WrongPassword", hash_result) is False

### Exception Testing

def test_invalid_input_raises_error() -> None:
"""Некорректный ввод должен вызывать ValueError."""
with pytest.raises(
ValueError,
match=r"Параметр 'cpi' должен быть в диапазоне
10
,
20
10,20"
):
set_character_pitch(cpi=5) \# invalid value

## Common Imports

### Standard Library

from typing import List, Dict, Optional, Any, Protocol, TypeVar
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum, auto
import logging

### Project Imports

from src import get_logger
from src.app_context import AppContext
from src.model.enums import Alignment, FontFamily, CharacterPitch
from src.security.crypto import AESCipher, Ed25519Signer

## Architecture Rules

### Model Layer (Data Classes)

- ❌ **NO** imports from View or Controller
- ❌ **NO** business logic (только данные и простые методы)
- ❌ **NO** external dependencies (кроме stdlib и typing)
- ✅ **YES** dataclasses with type hints
- ✅ **YES** immutable (frozen=True) где возможно
- ✅ **YES** validation в `__post_init__`


### Service Layer (Business Logic)

- ✅ **YES** все бизнес-операции здесь
- ✅ **YES** imports from Model
- ✅ **YES** dependency injection через конструктор
- ✅ **YES** чистые функции где возможно
- ❌ **NO** прямая работа с View
- ❌ **NO** глобальное состояние


### View Layer (GUI)

- ❌ **NO** business logic
- ✅ **YES** imports from Model (readonly, для отображения)
- ✅ **YES** callbacks к Controller
- ✅ **YES** валидация пользовательского ввода
- ❌ **NO** прямые вызовы Service


### Controller Layer (Orchestration)

- ✅ **YES** координация между View и Service
- ✅ **YES** обработка пользовательских действий
- ✅ **YES** трансформация данных Model ↔ View
- ❌ **NO** сложная бизнес-логика (должна быть в Service)


## Naming Conventions

### Code

- **Classes**: `PascalCase` (примеры: `Document`, `ESCPCommandBuilder`)
- **Functions/methods**: `snake_case` (примеры: `process_text`, `create_barcode`)
- **Constants**: `UPPER_CASE` (примеры: `MAX_IMAGE_SIZE`, `DEFAULT_ENCODING`)
- **Private**: `_leading_underscore` (примеры: `_internal_state`, `_validate`)
- **Type variables**: `T`, `K`, `V`, `TModel` (generic типы)
- **Protocols**: `SomethingProtocol` или `Somethingable`


### Files and Modules

- **Modules**: `snake_case.py` (примеры: `barcode_generator.py`, `second_factor.py`)
- **Test files**: `test_module_name.py` (примеры: `test_table.py`, `test_symmetric.py`)
- **Packages**: lowercase without underscore (примеры: `model`, `escp`, `security`)


### Tests

- **Test classes**: `TestClassName` (примеры: `TestTable`, `TestAESCipher`)
- **Test methods**: `test_specific_behavior` (примеры: `test_create_table_basic`, `test_encrypt_decrypt_roundtrip`)
- **Fixtures**: `snake_case` (примеры: `sample_document`, `mock_printer`)


## File Structure Template

"""
Краткое описание модуля в одной строке.

Более детальное описание назначения модуля, его основных классов
и функций. Примеры использования если необходимо.

Example:
>>> from src.module import SomeClass
>>> obj = SomeClass(param="value")
>>> result = obj.method()
"""

from future import annotations \# для forward references

from typing import List, Optional, Protocol
from dataclasses import dataclass, field
import logging

from src import get_logger
from src.model.enums import SomeEnum

Module logger
logger = get_logger(name)

Module constants
DEFAULT_VALUE = 42
MAX_ITEMS = 1000

Type aliases
ConfigDict = dict[str, Any] \# Python 3.9+ syntax

Protocols
class SomeProtocol(Protocol):
"""Протокол для объектов с определённым интерфейсом."""

def method(self) -> str:
    """Описание метода."""
    ...
Main classes
@dataclass(frozen=True)
class SomeClass:
"""
Краткое описание класса.

Детальное описание функциональности, особенностей использования,
ограничений и т.д.

Attributes:
    param: Описание параметра
    items: Описание списка элементов

Example:
    >>> obj = SomeClass(param="test")
    >>> print(obj.param)
    test
"""

param: str
items: List[str] = field(default_factory=list)

def __post_init__(self) -> None:
    """Валидация после инициализации."""
    if not self.param:
        raise ValueError("Параметр 'param' не может быть пустым")

def method(self) -> str:
    """
    Описание метода.

Returns:
        Результат работы метода

Raises:
        ValueError: Условия вызова ошибки
    """
    logger.debug(f"Calling method with param={self.param}")
    return self.param.upper()
Module-level functions
def helper_function(arg: int) -> int:
"""
Вспомогательная функция модуля.

Args:
    arg: Входной аргумент

Returns:
    Обработанное значение
"""
return arg * 2

## Error Messages Best Practices

### User-Facing Errors (Russian)

✅ Good - понятно, с контекстом, на русском
raise ValueError(
f"Недопустимое значение для параметра 'cpi': {cpi}. "
f"Ожидается значение в диапазоне ."
)

❌ Bad - непонятно, без контекста
raise ValueError("Invalid value")

### Developer Errors (English)

✅ Good - техническая ошибка с деталями
raise TypeError(
f"Expected SecureStorage instance, got {type(storage).name}. "
f"Check dependency injection configuration."
)

### Security Errors (Minimal Info Leak)

✅ Good - не раскрывает детали
raise AuthenticationError("Неверные учётные данные")

❌ Bad - раскрывает существование пользователя
raise AuthenticationError(f"Неверный пароль для пользователя {username}")

## Security Considerations

### Input Validation

def validate_user_input(text: str, max_length: int = 1000) -> str:
"""Валидация пользовательского ввода."""
if len(text) > max_length:
raise ValueError(f"Текст превышает максимальную длину {max_length}")

# Sanitize potentially dangerous characters

sanitized = text.replace('\x00', '')  \# null bytes

return sanitized

### Path Traversal Protection

def safe_file_path(user_path: str, base_dir: Path) -> Path:
"""Безопасная обработка пути к файлу."""
requested_path = (base_dir / user_path).resolve()

# Проверка, что путь внутри base_dir

if not requested_path.is_relative_to(base_dir):
    raise ValueError("Недопустимый путь к файлу")

return requested_path

### Resource Limits

Ограничения на размер данных
MAX_IMAGE_SIZE = 10 * 1024 * 1024 \# 10 MB
MAX_DOCUMENT_PAGES = 1000

Таймауты
PRINTER_TIMEOUT = 30 \# seconds
NETWORK_TIMEOUT = 10 \# seconds

### Secrets Management

✅ Good - secrets не в коде
from src.security.crypto import SecureStorage

storage = SecureStorage(path="data/secure/keystore.enc")
api_key = storage.get("printer_api_key")

❌ Bad - hardcoded secrets
API_KEY = "sk_live_abc123xyz" \# NEVER DO THIS

## Performance Considerations

### Efficient ESC/P Command Building

✅ Good - использование bytearray
def build_command() -> bytes:
"""Построение ESC/P команды эффективно."""
cmd = bytearray()
cmd.extend(b'\x1B@') \# ESC @
cmd.extend(b'\x1B!') \# ESC !
cmd.append(0x10)
return bytes(cmd)

❌ Bad - многократная конкатенация bytes
def build_command_slow() -> bytes:
cmd = b''
cmd += b'\x1B@'
cmd += b'\x1B!'
cmd += bytes([0x10])
return cmd

### Lazy Loading Resources

class ResourceManager:
"""Менеджер ресурсов с ленивой загрузкой."""

def __init__(self) -> None:
    self._font_cache: Optional[Dict[str, Any]] = None

@property
def fonts(self) -> Dict[str, Any]:
    """Шрифты (загружаются при первом обращении)."""
    if self._font_cache is None:
        self._font_cache = self._load_fonts()
    return self._font_cache

### Generator для больших коллекций

def process_large_document(doc: Document) -> Iterator[bytes]:
"""Обработка большого документа по частям."""
for section in doc.sections:
for paragraph in section.paragraphs:
yield process_paragraph(paragraph)

## Testing Requirements

### Coverage Thresholds

- **Overall Project**: минимум 80%
- **New Modules**: минимум 90%
- **Security Modules**: минимум 95%
- **Critical Paths**: 100%


### Test Markers

@pytest.mark.slow \# медленные тесты (>1s)
@pytest.mark.security \# критичные security тесты
@pytest.mark.integration \# интеграционные тесты
@pytest.mark.crypto \# криптографические тесты с NIST vectors

### Running Tests

Все тесты
pytest

Только быстрые
pytest -m "not slow"

Только security
pytest -m security

С coverage
pytest --cov=src --cov-report=html

Строгая проверка типов
mypy --strict src/

## Git Workflow

### Branch Naming

- `feature/description` - новая функциональность
- `fix/description` - исправление бага
- `refactor/description` - рефакторинг без изменения API
- `docs/description` - только документация
- `test/description` - добавление/улучшение тестов


### Commit Messages

✅ Good
feat: добавить поддержку Ed25519 подписей для защищённых бланков

Реализовано:

Ed25519Signer класс с verify/sign методами

Интеграция с SecureStorage

15 unit тестов, 97% coverage

Closes \#42

❌ Bad
update files

## AI Code Generation Guidelines

### When Using AI to Generate Code

1. **Всегда предоставляйте контекст**: этот файл + соответствующие примеры
2. **Указывайте целевой модуль**: Model/View/Controller/Service
3. **Требуйте тесты**: минимум 90% coverage
4. **Проверяйте типы**: mypy --strict должен проходить
5. **Следуйте стилю**: Black + isort автоматически

### Template Prompt for AI

Проект: FX Text Processor 3
Контекст: [ссылка на .ai/project_context.md]
Архитектура: [ссылка на docs/ARCHITECTURE.md]

Задача: Создать модуль [название]
Слой: [Model/Service/Controller/View]
Требования:

Строгая типизация (mypy --strict)

Google-style docstrings на русском

Тесты с coverage ≥90%

Следовать примерам из [конкретный файл]

Дополнительные требования:
[специфичные для задачи]

## Dependencies Management

### Core Dependencies (всегда устанавливать)

pip install -e ".[dev]" \# dev dependencies
pip install -e ".[security]" \# security features

### Optional Dependencies

- `windows` - pywin32 для Windows printer API
- `audit` - логирование и мониторинг
- `all` - все зависимости


### Version Pinning

- Используйте `>=` для библиотек (минимальная версия)
- Точные версии только для критичных security библиотек
- Регулярно обновляйте через `pip install -U`


## Common Pitfalls to Avoid

### ❌ Mutable Default Arguments

Bad
def add_item(item: str, items: List[str] = []) -> List[str]:
items.append(item)
return items

Good
def add_item(item: str, items: Optional[List[str]] = None) -> List[str]:
if items is None:
items = []
items.append(item)
return items

### ❌ Catching Too Broad Exceptions

Bad
try:
risky_operation()
except Exception:
pass \# hides all errors

Good
try:
risky_operation()
except SpecificError as e:
logger.error(f"Expected error: {e}")

# handle specific case

except Exception as e:
logger.critical(f"Unexpected error: {e}", exc_info=True)
raise \# re-raise unexpected errors

### ❌ Hardcoded Paths

Bad
config_path = "C:\Users\Admin\config.json"

Good
from pathlib import Path
config_path = Path.home() / ".fxtextprocessor" / "config.json"

## Resources

### Internal Documentation

- **Architecture**: `docs/ARCHITECTURE.md`
- **Deployment**: `docs/DEPLOYMENT_ARCHITECTURE.md`
- **Security**: `docs/SECURITY_ARCHITECTURE.md`
- **API Reference**: `docs/API_REFERENCE.md`
- **Development**: `docs/DEVELOPMENT.md`
- **Prompts**: `docs/PROMPT_TEMPLATES.md`


### External References

- **Epson ESC/P**: [Epson FX-890 Manual](https://files.support.epson.com/pdf/fx890_/fx890_ug.pdf)
- **Python Typing**: [PEP 484](https://www.python.org/dev/peps/pep-0484/)
- **Pytest**: [pytest documentation](https://docs.pytest.org/)
- **Cryptography**: [PyCA Cryptography](https://cryptography.io/)


### Code Quality Tools

- **Black**: `black src/ tests/`
- **isort**: `isort src/ tests/`
- **MyPy**: `mypy --strict src/`
- **Bandit**: `bandit -r src/` (security linting)
- **Safety**: `safety check` (dependency vulnerabilities)


## File Extensions \& Types

### FX Super Extensions

Все файлы приложения используют унифицированный префикс **`.fxs`** (FX Super):

**Documents:**

- `.fxsd` — FX Super Document (незашифрованный, JSON)
- `.fxsd.enc` — FX Super Document Encrypted (AES-256-GCM)
- `.fxstpl` — FX Super Template (шаблон формы)

**Security:**

- `.fxsblank` — FX Super Blank (защищённый бланк, всегда зашифрован)
- `.fxskeystore.enc` — FX Super Keystore (хранилище ключей)
- `.fxssig` — FX Super Signature (цифровая подпись Ed25519)

**System:**

- `.fxsconfig` — FX Super Config (конфигурация)
- `.fxsbackup` — FX Super Backup (резервная копия)
- `.fxsbundle.enc` — FX Super Bundle (экспортный пакет)

**Printer:**

- `.escp` — ESC/P Raw Commands (сырые команды принтера)
- `.escps` — ESC/P Script (скрипт автоматизации печати)

**→ Детали**: См. `src/model/enums.py` (FileExtension, FileType)

---

**Last Updated:** November 8, 2025
**Version:** 2.1
**Project Completion:** ~48%
**Maintainer:** Mike-voyager

так?

Почти идеально! Есть одна небольшая ошибка в разделе **Exception Testing** — сломано форматирование regex. Вот исправленная финальная версия:

***

# Project Context for AI

## Quick Facts

- **Name**: FX Text Processor 3
- **Purpose**: Professional WYSIWYG editor for Epson FX-890 dot matrix printer with enterprise security
- **Language**: Python 3.11+ (3.13 compatible)
- **Architecture**: MVC (Model-View-Controller) + Service Layer
- **GUI**: Tkinter (in development)
- **Current Version**: 0.1.0-alpha
- **Status**: Active Development (~48% complete)
- **Last Major Update**: November 8, 2025


## Project Progress Overview

| Subsystem | Status | Coverage | Tests |
| :-- | :-- | :-- | :-- |
| Core Infrastructure | ✅ 100% | ~100% | - |
| Data Models | ✅ 86% | ~92% | 310+ |
| ESC/P Commands | ✅ 100% | >95% | 420+ |
| Barcode Generation | ✅ 100% | ~95% | 85+ |
| Security (Crypto) | ✅ 100% | ~95% | 180+ |
| Security (Auth) | ⚠️ 77% | ~90% | 150+ |
| Form Builder | ⚠️ 82% | ~75% | 95+ |
| GUI (View) | ❌ 0% | - | - |
| Controllers/Services | ❌ 0% | - | - |

**Total: 1,045+ tests, ~80% overall coverage, ~97% pass rate**

## Key Design Decisions

### Architecture

1. **Src-layout**: Код в `src/`, не в корне проекта
2. **MVC + Services**: Model-View-Controller с дополнительным Service Layer
3. **Strict typing**: `mypy --strict` обязательно для всех модулей
4. **TDD**: Тесты пишутся первыми, минимум 90% coverage
5. **Dependency Injection**: Использование DI для тестируемости (см. `app_context.py`)

### Domain-Specific

6. **PC866**: Основная кодировка для русского языка в ESC/P
7. **Direct printing**: WritePrinter API, обход драйвера Windows
8. **ESC/P Protocol**: Полная поддержка Epson FX-890 команд
9. **Zero Trust Security**: Military-grade криптография для защищённых бланков и защищенных файлов

### Deployment \& Runtime

10. **Portable Application**: Полностью портативное приложение без установки
11. **Cloud-Synced**: Вся папка приложения в облачном хранилище для синхронизации между ПК
12. **Offline-First**: Полная работоспособность без интернета
13. **Encrypted Storage**: Критичные данные зашифрованы с Argon2id (keystore.enc)
14. **Floppy Disk Support**: Опциональная оптимизация для 3.5" дискет (1.44 MB)
15. **Auto-Backup**: Автоматическое резервное копирование в `backups/`

**→ Детали**: См. [docs/DEPLOYMENT_ARCHITECTURE.md](docs/DEPLOYMENT_ARCHITECTURE.md)

### Code Quality

16. **Black formatting**: Line length 88 (стандарт), Python 3.14 target
17. **Google-style docstrings**: На русском языке
18. **Parametrized tests**: pytest.mark.parametrize для множественных сценариев
19. **Security markers**: pytest.mark.security для критичных тестов

## Important Files for Context

### Must-Read Before Starting

- `.ai/project_context.md` — Этот файл (правила и стандарты)
- `README.md` — Общее описание, статус разработки
- `docs/ARCHITECTURE.md` — Архитектура системы
- `docs/DEPLOYMENT_ARCHITECTURE.md` — Портативность, облако, шифрование
- `docs/PROMPT_TEMPLATES.md` — Шаблоны для генерации кода с AI


### Code Style References

- `src/__init__.py` — Пример инициализации модуля, логирование
- `src/app_context.py` — Dependency Injection контейнер
- `src/model/table.py` — Эталонный пример Model класса
- `tests/unit/model/test_table.py` — Эталонный пример тестов


### Architecture Documents

- `pyproject.toml` — Конфигурация проекта, зависимости
- `pytest.ini` — Настройки тестирования
- `mypy.ini` — Настройки type checking


## Security Architecture (High-Level)

### Key Management

- **Derivation**: Argon2id (master_password + salt + pepper)
- **Storage**: Единственный зашифрованный `keystore.enc` в облаке
- **Local Files**: `~/.fxtextprocessor/salt.bin` + `pepper.bin` (НЕ синхронизируются)
- **Master Password**: Единая точка доступа ко всем ключам


### File Encryption Policy

- **Обычные документы**: НЕ зашифрованы (для расшаривания с коллегами)
- **Личные документы**: Опционально зашифрованы (выбор пользователя)
- **Защищённые бланки**: ВСЕГДА зашифрованы + цифровая подпись

**→ Детали**: См. [docs/SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md)

## Cloud Synchronization (Brief)

### Portable Structure

```
CloudStorage/FXTextProcessor/
├── data/
│   ├── documents/
│   │   ├── invoice_2025.fxsd           # FX Super Document
│   │   └── report.fxsd.enc             # FX Super Document Encrypted
│   ├── templates/
│   │   └── invoice_template.fxstpl    # FX Super Template
│   ├── private/
│   │   └── salary.fxsd.enc            # Зашифрованный личный документ
│   └── secure/
│       ├── keystore.fxskeystore.enc   # FX Super Keystore
│       ├── blanks/
│       │   └── blank_A001.fxsblank    # FX Super Blank
│       └── signatures/
│           └── blank_A001.fxssig      # FX Super Signature
├── backups/
│   └── 2025-11-08_22-00.fxsbackup     # FX Super Backup
├── config/
│   └── settings.fxsconfig             # FX Super Config
└── escp/
    ├── test_commands.escp             # ESC/P Raw
    └── autoprint.escps                # ESC/P Script
```


### Security

- Ключи НЕ в облаке (только `salt.bin` + `pepper.bin` локально)
- Облако видит только зашифрованные данные
- Без мастер-пароля + локальных файлов → расшифровка невозможна

**→ Детали**: См. [docs/DEPLOYMENT_ARCHITECTURE.md](docs/DEPLOYMENT_ARCHITECTURE.md)

## Code Style Examples

### Type Hints (Строгая типизация)

```python
from typing import Optional, List, Dict, Any
from pathlib import Path

def process_text(
    text: str,
    *,  # force keyword-only arguments
    bold: bool = False,
    encoding: str = "PC866"
) -> bytes:
    """
    Обработать текст для печати.

    Args:
        text: Текст для обработки
        bold: Применить жирное начертание
        encoding: Кодировка (по умолчанию PC866)

    Returns:
        Закодированные байты для отправки на принтер

    Raises:
        ValueError: Если текст пустой или encoding неподдерживаемый

    Example:
        >>> data = process_text("Привет", bold=True)
        >>> print(data.hex())
    """
    ...
```


### Docstrings (Google-style, Russian)

```python
class SecureDocument:
    """
    Документ с криптографической защитой.

    Поддерживает цифровые подписи Ed25519 и шифрование AES-256-GCM.
    Используется для защищённых бланков строгой отчётности.

    Attributes:
        content: Содержимое документа
        signature: Цифровая подпись (если подписан)
        encrypted: Флаг шифрования

    Example:
        >>> doc = SecureDocument(content="Invoice #123")
        >>> doc.sign(private_key)
        >>> doc.encrypt(public_key)
        >>> print(doc.verify())
        True
    """

    def __init__(self, content: str) -> None:
        """
        Инициализировать защищённый документ.

        Args:
            content: Текстовое содержимое документа

        Raises:
            ValueError: Если content пустой
        """
        ...
```


### Error Handling (Контекст + логирование)

```python
from src import get_logger

logger = get_logger(__name__)

try:
    result = risky_operation(param)
except SpecificError as e:
    logger.error(
        f"Operation failed for param={param}: {e}",
        exc_info=True  # включить stack trace
    )
    raise  # re-raise для обработки выше
except Exception as e:
    logger.critical(f"Unexpected error: {e}", exc_info=True)
    return default_value
```


### Dataclasses (Immutable где возможно)

```python
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass(frozen=True)  # immutable
class Paragraph:
    """
    Параграф документа.

    Attributes:
        text: Текстовое содержимое
        alignment: Выравнивание (LEFT/CENTER/RIGHT)
        runs: Список форматированных фрагментов
    """
    text: str
    alignment: Alignment = Alignment.LEFT
    runs: List['Run'] = field(default_factory=list)

    def add_run(self, run: 'Run') -> 'Paragraph':
        """
        Добавить run (создаёт новый объект - immutable).

        Args:
            run: Форматированный фрагмент текста

        Returns:
            Новый Paragraph с добавленным run
        """
        return Paragraph(
            text=self.text,
            alignment=self.alignment,
            runs=[*self.runs, run]
        )
```


### Protocols (Duck Typing с типизацией)

```python
from typing import Protocol, runtime_checkable

@runtime_checkable
class Encryptable(Protocol):
    """Протокол для объектов, поддерживающих шифрование."""

    def encrypt(self, key: bytes) -> bytes:
        """Зашифровать данные."""
        ...

    def decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        """Расшифровать данные."""
        ...
```


## Testing Patterns

### Basic Test Structure (AAA Pattern)

```python
import pytest
from src.model.table import Table, Cell

class TestTable:
    """Тесты для класса Table."""

    def test_create_table_basic(self) -> None:
        """Создание таблицы с базовыми параметрами."""
        # Arrange
        rows, cols = 3, 4

        # Act
        table = Table(rows=rows, cols=cols)

        # Assert
        assert table.rows == rows
        assert table.cols == cols
        assert len(table.cells) == rows * cols
```


### Parametrized Tests (Множественные сценарии)

```python
@pytest.mark.parametrize("input_value,expected", [
    ("test", b"test"),
    ("привет", b"\xaf\xe0\xa8\xa2\xa5\xe2"),  # PC866
    ("", b""),
])
def test_encode_text(input_value: str, expected: bytes) -> None:
    """Тест кодирования текста в разных сценариях."""
    result = encode_text(input_value, encoding="PC866")
    assert result == expected
```


### Fixtures (Переиспользуемые данные)

```python
@pytest.fixture
def sample_document() -> Document:
    """Тестовый документ с базовым содержимым."""
    doc = Document(title="Test Document")
    doc.add_section(Section(title="Section 1"))
    return doc

def test_document_with_fixture(sample_document: Document) -> None:
    """Тест с использованием fixture."""
    assert sample_document.title == "Test Document"
    assert len(sample_document.sections) == 1
```


### Security Tests (Критичные тесты безопасности)

```python
@pytest.mark.security
def test_password_hashing_argon2id() -> None:
    """Проверка корректности Argon2id хеширования."""
    password = "SecurePassword123!"

    # Хешируем
    hash_result = hash_password(password)

    # Проверяем формат Argon2id
    assert hash_result.startswith("$argon2id$")

    # Проверяем верификацию
    assert verify_password(password, hash_result) is True
    assert verify_password("WrongPassword", hash_result) is False
```


### Exception Testing

```python
def test_invalid_input_raises_error() -> None:
    """Некорректный ввод должен вызывать ValueError."""
    with pytest.raises(
        ValueError,
        match=r"Параметр 'cpi' должен быть в диапазоне \[10, 20\]"
    ):
        set_character_pitch(cpi=5)  # invalid value
```


## Common Imports

### Standard Library

```python
from typing import List, Dict, Optional, Any, Protocol, TypeVar
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum, auto
import logging
```


### Project Imports

```python
from src import get_logger
from src.app_context import AppContext
from src.model.enums import Alignment, FontFamily, CharacterPitch
from src.security.crypto import AESCipher, Ed25519Signer
```


## Architecture Rules

### Model Layer (Data Classes)

- ❌ **NO** imports from View or Controller
- ❌ **NO** business logic (только данные и простые методы)
- ❌ **NO** external dependencies (кроме stdlib и typing)
- ✅ **YES** dataclasses with type hints
- ✅ **YES** immutable (frozen=True) где возможно
- ✅ **YES** validation в `__post_init__`


### Service Layer (Business Logic)

- ✅ **YES** все бизнес-операции здесь
- ✅ **YES** imports from Model
- ✅ **YES** dependency injection через конструктор
- ✅ **YES** чистые функции где возможно
- ❌ **NO** прямая работа с View
- ❌ **NO** глобальное состояние


### View Layer (GUI)

- ❌ **NO** business logic
- ✅ **YES** imports from Model (readonly, для отображения)
- ✅ **YES** callbacks к Controller
- ✅ **YES** валидация пользовательского ввода
- ❌ **NO** прямые вызовы Service


### Controller Layer (Orchestration)

- ✅ **YES** координация между View и Service
- ✅ **YES** обработка пользовательских действий
- ✅ **YES** трансформация данных Model ↔ View
- ❌ **NO** сложная бизнес-логика (должна быть в Service)


## Naming Conventions

### Code

- **Classes**: `PascalCase` (примеры: `Document`, `ESCPCommandBuilder`)
- **Functions/methods**: `snake_case` (примеры: `process_text`, `create_barcode`)
- **Constants**: `UPPER_CASE` (примеры: `MAX_IMAGE_SIZE`, `DEFAULT_ENCODING`)
- **Private**: `_leading_underscore` (примеры: `_internal_state`, `_validate`)
- **Type variables**: `T`, `K`, `V`, `TModel` (generic типы)
- **Protocols**: `SomethingProtocol` или `Somethingable`


### Files and Modules

- **Modules**: `snake_case.py` (примеры: `barcode_generator.py`, `second_factor.py`)
- **Test files**: `test_module_name.py` (примеры: `test_table.py`, `test_symmetric.py`)
- **Packages**: lowercase without underscore (примеры: `model`, `escp`, `security`)


### Tests

- **Test classes**: `TestClassName` (примеры: `TestTable`, `TestAESCipher`)
- **Test methods**: `test_specific_behavior` (примеры: `test_create_table_basic`, `test_encrypt_decrypt_roundtrip`)
- **Fixtures**: `snake_case` (примеры: `sample_document`, `mock_printer`)


## File Structure Template

```python
"""
Краткое описание модуля в одной строке.

Более детальное описание назначения модуля, его основных классов
и функций. Примеры использования если необходимо.

Example:
    >>> from src.module import SomeClass
    >>> obj = SomeClass(param="value")
    >>> result = obj.method()
"""

from __future__ import annotations  # для forward references

from typing import List, Optional, Protocol
from dataclasses import dataclass, field
import logging

from src import get_logger
from src.model.enums import SomeEnum

# Module logger
logger = get_logger(__name__)

# Module constants
DEFAULT_VALUE = 42
MAX_ITEMS = 1000

# Type aliases
ConfigDict = dict[str, Any]  # Python 3.9+ syntax

# Protocols
class SomeProtocol(Protocol):
    """Протокол для объектов с определённым интерфейсом."""

    def method(self) -> str:
        """Описание метода."""
        ...

# Main classes
@dataclass(frozen=True)
class SomeClass:
    """
    Краткое описание класса.

    Детальное описание функциональности, особенностей использования,
    ограничений и т.д.

    Attributes:
        param: Описание параметра
        items: Описание списка элементов

    Example:
        >>> obj = SomeClass(param="test")
        >>> print(obj.param)
        test
    """

    param: str
    items: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Валидация после инициализации."""
        if not self.param:
            raise ValueError("Параметр 'param' не может быть пустым")

    def method(self) -> str:
        """
        Описание метода.

        Returns:
            Результат работы метода

        Raises:
            ValueError: Условия вызова ошибки
        """
        logger.debug(f"Calling method with param={self.param}")
        return self.param.upper()

# Module-level functions
def helper_function(arg: int) -> int:
    """
    Вспомогательная функция модуля.

    Args:
        arg: Входной аргумент

    Returns:
        Обработанное значение
    """
    return arg * 2
```


## Error Messages Best Practices

### User-Facing Errors (Russian)

```python
# ✅ Good - понятно, с контекстом, на русском
raise ValueError(
    f"Недопустимое значение для параметра 'cpi': {cpi}. "
    f"Ожидается значение в диапазоне [10, 20]."
)

# ❌ Bad - непонятно, без контекста
raise ValueError("Invalid value")
```


### Developer Errors (English)

```python
# ✅ Good - техническая ошибка с деталями
raise TypeError(
    f"Expected SecureStorage instance, got {type(storage).__name__}. "
    f"Check dependency injection configuration."
)
```


### Security Errors (Minimal Info Leak)

```python
# ✅ Good - не раскрывает детали
raise AuthenticationError("Неверные учётные данные")

# ❌ Bad - раскрывает существование пользователя
raise AuthenticationError(f"Неверный пароль для пользователя {username}")
```


## Security Considerations

### Input Validation

```python
def validate_user_input(text: str, max_length: int = 1000) -> str:
    """Валидация пользовательского ввода."""
    if len(text) > max_length:
        raise ValueError(f"Текст превышает максимальную длину {max_length}")

    # Sanitize potentially dangerous characters
    sanitized = text.replace('\x00', '')  # null bytes

    return sanitized
```


### Path Traversal Protection

```python
def safe_file_path(user_path: str, base_dir: Path) -> Path:
    """Безопасная обработка пути к файлу."""
    requested_path = (base_dir / user_path).resolve()

    # Проверка, что путь внутри base_dir
    if not requested_path.is_relative_to(base_dir):
        raise ValueError("Недопустимый путь к файлу")

    return requested_path
```


### Resource Limits

```python
# Ограничения на размер данных
MAX_IMAGE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_DOCUMENT_PAGES = 1000

# Таймауты
PRINTER_TIMEOUT = 30  # seconds
NETWORK_TIMEOUT = 10  # seconds
```


### Secrets Management

```python
# ✅ Good - secrets не в коде
from src.security.crypto import SecureStorage

storage = SecureStorage(path="data/secure/keystore.enc")
api_key = storage.get("printer_api_key")

# ❌ Bad - hardcoded secrets
API_KEY = "sk_live_abc123xyz"  # NEVER DO THIS
```


## Performance Considerations

### Efficient ESC/P Command Building

```python
# ✅ Good - использование bytearray
def build_command() -> bytes:
    """Построение ESC/P команды эффективно."""
    cmd = bytearray()
    cmd.extend(b'\x1B@')  # ESC @
    cmd.extend(b'\x1B!')  # ESC !
    cmd.append(0x10)
    return bytes(cmd)

# ❌ Bad - многократная конкатенация bytes
def build_command_slow() -> bytes:
    cmd = b''
    cmd += b'\x1B@'
    cmd += b'\x1B!'
    cmd += bytes([0x10])
    return cmd
```


### Lazy Loading Resources

```python
class ResourceManager:
    """Менеджер ресурсов с ленивой загрузкой."""

    def __init__(self) -> None:
        self._font_cache: Optional[Dict[str, Any]] = None

    @property
    def fonts(self) -> Dict[str, Any]:
        """Шрифты (загружаются при первом обращении)."""
        if self._font_cache is None:
            self._font_cache = self._load_fonts()
        return self._font_cache
```


### Generator для больших коллекций

```python
def process_large_document(doc: Document) -> Iterator[bytes]:
    """Обработка большого документа по частям."""
    for section in doc.sections:
        for paragraph in section.paragraphs:
            yield process_paragraph(paragraph)
```


## Testing Requirements

### Coverage Thresholds

- **Overall Project**: минимум 80%
- **New Modules**: минимум 90%
- **Security Modules**: минимум 95%
- **Critical Paths**: 100%


### Test Markers

```python
@pytest.mark.slow  # медленные тесты (>1s)
@pytest.mark.security  # критичные security тесты
@pytest.mark.integration  # интеграционные тесты
@pytest.mark.crypto  # криптографические тесты с NIST vectors
```


### Running Tests

```bash
# Все тесты
pytest

# Только быстрые
pytest -m "not slow"

# Только security
pytest -m security

# С coverage
pytest --cov=src --cov-report=html

# Строгая проверка типов
mypy --strict src/
```


## Git Workflow

### Branch Naming

- `feature/description` - новая функциональность
- `fix/description` - исправление бага
- `refactor/description` - рефакторинг без изменения API
- `docs/description` - только документация
- `test/description` - добавление/улучшение тестов


### Commit Messages

```
# ✅ Good
feat: добавить поддержку Ed25519 подписей для защищённых бланков

Реализовано:
- Ed25519Signer класс с verify/sign методами
- Интеграция с SecureStorage
- 15 unit тестов, 97% coverage

Closes #42

# ❌ Bad
update files
```


## AI Code Generation Guidelines

### When Using AI to Generate Code

1. **Всегда предоставляйте контекст**: этот файл + соответствующие примеры
2. **Указывайте целевой модуль**: Model/View/Controller/Service
3. **Требуйте тесты**: минимум 90% coverage
4. **Проверяйте типы**: mypy --strict должен проходить
5. **Следуйте стилю**: Black + isort автоматически

### Template Prompt for AI

```
Проект: FX Text Processor 3
Контекст: [ссылка на .ai/project_context.md]
Архитектура: [ссылка на docs/ARCHITECTURE.md]

Задача: Создать модуль [название]
Слой: [Model/Service/Controller/View]
Требования:
- Строгая типизация (mypy --strict)
- Google-style docstrings на русском
- Тесты с coverage ≥90%
- Следовать примерам из [конкретный файл]

Дополнительные требования:
[специфичные для задачи]
```


## Dependencies Management

### Core Dependencies (всегда устанавливать)

```bash
pip install -e ".[dev]"  # dev dependencies
pip install -e ".[security]"  # security features
```


### Optional Dependencies

- `windows` - pywin32 для Windows printer API
- `audit` - логирование и мониторинг
- `all` - все зависимости


### Version Pinning

- Используйте `>=` для библиотек (минимальная версия)
- Точные версии только для критичных security библиотек
- Регулярно обновляйте через `pip install -U`


## Common Pitfalls to Avoid

### ❌ Mutable Default Arguments

```python
# Bad
def add_item(item: str, items: List[str] = []) -> List[str]:
    items.append(item)
    return items

# Good
def add_item(item: str, items: Optional[List[str]] = None) -> List[str]:
    if items is None:
        items = []
    items.append(item)
    return items
```


### ❌ Catching Too Broad Exceptions

```python
# Bad
try:
    risky_operation()
except Exception:
    pass  # hides all errors

# Good
try:
    risky_operation()
except SpecificError as e:
    logger.error(f"Expected error: {e}")
    # handle specific case
except Exception as e:
    logger.critical(f"Unexpected error: {e}", exc_info=True)
    raise  # re-raise unexpected errors
```


### ❌ Hardcoded Paths

```python
# Bad
config_path = "C:\\Users\\Admin\\config.json"

# Good
from pathlib import Path
config_path = Path.home() / ".fxtextprocessor" / "config.json"
```


## File Extensions \& Types

### FX Super Extensions

Все файлы приложения используют унифицированный префикс **`.fxs`** (FX Super):

**Documents:**

- `.fxsd` — FX Super Document (незашифрованный, JSON)
- `.fxsd.enc` — FX Super Document Encrypted (AES-256-GCM)
- `.fxstpl` — FX Super Template (шаблон формы)

**Security:**

- `.fxsblank` — FX Super Blank (защищённый бланк, всегда зашифрован)
- `.fxskeystore.enc` — FX Super Keystore (хранилище ключей)
- `.fxssig` — FX Super Signature (цифровая подпись Ed25519)

**System:**

- `.fxsconfig` — FX Super Config (конфигурация)
- `.fxsbackup` — FX Super Backup (резервная копия)
- `.fxsbundle.enc` — FX Super Bundle (экспортный пакет)

**Printer:**

- `.escp` — ESC/P Raw Commands (сырые команды принтера)
- `.escps` — ESC/P Script (скрипт автоматизации печати)

**→ Детали**: См. `src/model/enums.py` (FileExtension, FileType)

## Resources

### Internal Documentation

- **Architecture**: `docs/ARCHITECTURE.md`
- **Deployment**: `docs/DEPLOYMENT_ARCHITECTURE.md`
- **Security**: `docs/SECURITY_ARCHITECTURE.md`
- **API Reference**: `docs/API_REFERENCE.md`
- **Development**: `docs/DEVELOPMENT.md`
- **Prompts**: `docs/PROMPT_TEMPLATES.md`


### External References

- **Epson ESC/P**: [Epson FX-890 Manual](https://files.support.epson.com/pdf/fx890_/fx890_ug.pdf)
- **Python Typing**: [PEP 484](https://www.python.org/dev/peps/pep-0484/)
- **Pytest**: [pytest documentation](https://docs.pytest.org/)
- **Cryptography**: [PyCA Cryptography](https://cryptography.io/)


### Code Quality Tools

- **Black**: `black src/ tests/`
- **isort**: `isort src/ tests/`
- **MyPy**: `mypy --strict src/`
- **Bandit**: `bandit -r src/` (security linting)
- **Safety**: `safety check` (dependency vulnerabilities)

***

**Last Updated:** November 8, 2025
**Version:** 2.1
**Project Completion:** ~48%
**Maintainer:** Mike-voyager

***
