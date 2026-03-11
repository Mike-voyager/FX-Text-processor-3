# Project Context for AI — FX Text Processor 3

> **Version:** 3.0  
> **Date:** March 2026  
> **Maintainer:** Mike-voyager  
> **Replaces:** project_context-3.md (v2.1, November 2025)

---

## 1. Quick Facts

| Parameter | Value |
|-----------|-------|
| **Name** | FX Text Processor 3 |
| **Purpose** | Professional WYSIWYG editor for Epson FX-890 dot matrix printer with enterprise security |
| **Language** | Python 3.11+ (3.13 compatible) |
| **Architecture** | MVC (Model-View-Controller) + Service Layer |
| **GUI** | Tkinter (в разработке) |
| **Current Version** | 0.2.0-alpha |
| **Status** | Active Development (~48% complete) |
| **Last Major Update** | March 2026 |
| **Security Model** | Zero Trust, Air-Gap First |
| **Target Printer** | Epson FX-890 (primary), FX-2190, LX-300+II (compatibility) |
| **Target OS** | Linux (recommended), Windows 10+, macOS 12+ |
| **Deployment** | Portable application, cloud-synced folder |

---

## 2. Project Progress Overview

| Subsystem | Status | Coverage | Tests |
|-----------|--------|----------|-------|
| Core Infrastructure | ✅ 100% | ~100% | — |
| Data Models | ✅ 86% | ~92% | 310+ |
| ESC/P Commands | ✅ 100% | >95% | 420+ |
| Barcode Generation | ✅ 100% | ~95% | 85+ |
| Security (Crypto) | ✅ 100% | ~95% | 180+ |
| Security (Auth) | 🚧 77% | ~90% | 150+ |
| Security (Audit/Blanks/Compliance) | ✅ 100% | >90% | — |
| Document Types & Indexing | 📋 TODO | — | — |
| Document Constructor | 📋 TODO (refactor from form/) | ~75% | 95+ |
| Document Rendering (ESC/P) | 📋 TODO | — | — |
| Printer Adapters | 📋 TODO | — | — |
| GUI (View) | ❌ 0% | — | — |
| Controllers/Services | ❌ 0% | — | — |

**Total: ~2,766 active tests, ~80% overall coverage**

---

## 3. Key Design Decisions

### Architecture

1. **Src-layout**: Код в `src/`, не в корне проекта
2. **MVC + Services**: Model-View-Controller с Service Layer
3. **Strict typing**: `mypy --strict` обязательно
4. **TDD**: Тесты первыми, минимум 90% coverage
5. **DI**: Dependency Injection через конструктор и Protocol
6. **Thread-safe singletons**: TypeRegistry, AlgorithmRegistry — через RLock

### Domain-Specific

7. **PC866**: Основная кодировка для русского в ESC/P
8. **Direct printing**: WritePrinter API (Windows), CUPS (Linux)
9. **ESC/P Protocol**: Полная поддержка Epson FX-890
10. **Zero Trust Security**: Military-grade crypto для Protected Blanks
11. **Hierarchical Document Indexing**: DVN-44-K53-IX формат, произвольная глубина, последний сегмент — римские цифры

### Deployment & Runtime

12. **Portable Application**: Без установки, вся папка в облаке
13. **Cloud-Synced**: Синхронизация через облачное хранилище
14. **Offline-First**: Полная работа без интернета
15. **Encrypted Storage**: Argon2id (keystore.enc), ключи НЕ в облаке
16. **Floppy Disk Support**: Опциональная оптимизация для 1.44 MB дискет
17. **Auto-Backup**: Автоматическое резервное копирование

### Code Quality

18. **Black formatting**: Line length 88, Python 3.14 target
19. **Google-style docstrings**: На русском языке
20. **Parametrized tests**: pytest.mark.parametrize
21. **Security markers**: pytest.mark.security

---

## 4. Architecture Rules

### Model Layer (Data Classes)

- ❌ **NO** imports from View or Controller
- ❌ **NO** business logic (только данные и простые методы)
- ❌ **NO** external dependencies (кроме stdlib и typing)
- ✅ dataclasses with type hints
- ✅ `frozen=True` где возможно
- ✅ validation в `__post_init__`

### ESC/P Commands Layer

- ❌ **NO** imports from `model/`
- ✅ Pure byte constants and generators
- ✅ Each file = group of ESC/P commands per FX-890 manual

### Documents Layer (Types, Constructor, Rendering)

- ✅ Imports from `model/` and `escp/commands/`
- ✅ TypeRegistry — singleton реестр типов
- ✅ Renderers: model → escp bytes

### Service Layer

- ✅ All business logic here
- ✅ Imports from Model
- ✅ DI через конструктор
- ✅ Чистые функции где возможно
- ❌ **NO** direct View access
- ❌ **NO** глобальное состояние

### View Layer (GUI)

- ❌ **NO** business logic
- ✅ Imports from Model (readonly, для отображения)
- ✅ Callbacks к Controller
- ✅ Валидация пользовательского ввода
- ❌ **NO** прямые вызовы Service

### Controller Layer

- ✅ Координация View ↔ Service
- ✅ Обработка пользовательских действий
- ✅ Трансформация данных Model ↔ View
- ❌ **NO** complex business logic (должна быть в Service)

---

## 5. File Extensions & Types

Все файлы используют унифицированный префикс `.fxs` (FX Super):

**Documents:**

| Extension | Name | Description |
|-----------|------|-------------|
| `.fxsd` | FX Super Document | JSON, незашифрованный |
| `.fxsd.enc` | FX Super Document Encrypted | AES-256-GCM |
| `.fxstpl` | FX Super Template | Шаблон формы |

**Security:**

| Extension | Name | Description |
|-----------|------|-------------|
| `.fxsblank` | FX Super Blank | Защищённый бланк, всегда зашифрован |
| `.fxskeystore.enc` | FX Super Keystore | Хранилище ключей |
| `.fxssig` | FX Super Signature | Цифровая подпись |

**System:**

| Extension | Name | Description |
|-----------|------|-------------|
| `.fxsconfig` | FX Super Config | Конфигурация (подписан master key) |
| `.fxsbackup` | FX Super Backup | Резервная копия |
| `.fxsbundle.enc` | FX Super Bundle | Экспортный пакет |
| `.fxsreg` | FX Super Registry | Device registry |

**Forms:**

| Extension | Name | Description |
|-----------|------|-------------|
| `.fxsf` | FX Super Form | Открытый формат |
| `.fxsfs` | FX Super Form Secure | Защищённый формат |

**Printer:**

| Extension | Name | Description |
|-----------|------|-------------|
| `.escp` | ESC/P Raw Commands | Сырые команды принтера |
| `.escps` | ESC/P Script | Скрипт автоматизации печати |

**Schema:**

| Extension | Name | Description |
|-----------|------|-------------|
| `.fxsschema` | FX Super Schema | JSON Schema |

---

## 6. Cloud Synchronization Structure

```
CloudStorage/FXTextProcessor/
├── data/
│   ├── documents/           # .fxsd, .fxsd.enc
│   ├── templates/           # .fxstpl
│   ├── private/             # .fxsd.enc (personal)
│   └── secure/
│       ├── keystore.fxskeystore.enc
│       ├── blanks/          # .fxsblank
│       └── signatures/      # .fxssig
├── backups/                 # .fxsbackup
├── config/                  # .fxsconfig
└── escp/                    # .escp, .escps
```

**Local only (NOT synced):**

- `~/.fxtextprocessor/salt.bin`
- `~/.fxtextprocessor/pepper.bin`

Без мастер-пароля + локальных файлов → расшифровка невозможна.

---

## 7. Security Architecture (Brief)

- **4 preset**: Standard, Paranoid, PQC, Legacy
- **MFA**: Master Password + FIDO2/TOTP/BackupCode
- **Protected Blanks**: lifecycle, crypto signing, QR verification
- **Hardware**: YubiKey 5, J3R200 (JCOP4)
- **Audit**: Immutable hash-chain log
- **Key Management**: Argon2id (master_password + salt + pepper) → `keystore.enc`
- **File Encryption**: обычные документы НЕ зашифрованы; личные — опционально; защищённые бланки — ВСЕГДА

→ **Подробности**: [SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md) v2.1

---

## 8. Document Indexing System

- **Иерархический составной индекс**: DVN-44-K53-IX
- **Типы сегментов**: `ROOT_CODE`, `SUBTYPE`, `SERIES`, `CUSTOM`, `SEQUENCE`
- **SEQUENCE** всегда последний, всегда римские цифры
- Произвольная глубина вложенности
- **TypeRegistry** для управления типами с наследованием

---

## 9. Important Files for Context

### Must-Read Before Starting

| File | Description |
|------|-------------|
| `.ai/project_context.md` | Этот файл |
| `docs/ARCHITECTURE_NEW.md` | Архитектура v3.0 |
| `docs/SECURITY_ARCHITECTURE.md` | Security Architecture v2.1 |
| `docs/API_REFERENCE.md` | API Reference v3.0 |
| `docs/SECURITY_SETUP.md` | Security Setup Guide v2.1 |

### Code Style References

| File | Description |
|------|-------------|
| `src/model/table.py` | Эталонный Model класс |
| `src/security/crypto/core/protocols.py` | Эталонные Protocol интерфейсы |
| `tests/unit/model/test_table.py` | Эталонные тесты |

### Configuration

| File | Description |
|------|-------------|
| `pyproject.toml` | Конфигурация проекта, зависимости |
| `pytest.ini` | Настройки тестирования |
| `mypy.ini` | Настройки type checking |

---

## 10. Code Style Examples

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
        Добавить run (создаёт новый объект — immutable).

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

### File Structure Template

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

### Testing Patterns

#### Basic Test Structure (AAA Pattern)

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

#### Fixtures (Переиспользуемые данные)

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

#### Parametrized Tests (Множественные сценарии)

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

#### Security Tests (Критичные тесты безопасности)

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

#### Exception Testing

```python
def test_invalid_input_raises_error() -> None:
    """Некорректный ввод должен вызывать ValueError."""
    with pytest.raises(
        ValueError,
        match=r"Параметр 'cpi' должен быть в диапазоне \[10, 20\]"
    ):
        set_character_pitch(cpi=5)  # invalid value
```

---

## 11. Naming Conventions

### Code

| Element | Convention | Examples |
|---------|-----------|----------|
| Classes | `PascalCase` | `Document`, `ESCPCommandBuilder` |
| Functions/methods | `snake_case` | `process_text`, `create_barcode` |
| Constants | `UPPER_CASE` | `MAX_IMAGE_SIZE`, `DEFAULT_ENCODING` |
| Private | `_leading_underscore` | `_internal_state`, `_validate` |
| Protocols | `SomethingProtocol` / `Somethingable` | `Encryptable`, `StorageProtocol` |
| Type variables | `T`, `K`, `V`, `TModel` | — |

### Files and Modules

| Element | Convention | Examples |
|---------|-----------|----------|
| Modules | `snake_case.py` | `barcode_generator.py`, `second_factor.py` |
| Test files | `test_module_name.py` | `test_table.py`, `test_symmetric.py` |
| Packages | lowercase without underscore | `model`, `escp`, `security` |

### Tests

| Element | Convention | Examples |
|---------|-----------|----------|
| Test classes | `TestClassName` | `TestTable`, `TestAESCipher` |
| Test methods | `test_specific_behavior` | `test_create_table_basic` |
| Fixtures | `snake_case` | `sample_document`, `mock_printer` |

---

## 12. Error Messages

### User-Facing Errors (русский, с контекстом)

```python
# ✅ Good — понятно, с контекстом, на русском
raise ValueError(
    f"Недопустимое значение для параметра 'cpi': {cpi}. "
    f"Ожидается значение в диапазоне [10, 20]."
)

# ❌ Bad — непонятно, без контекста
raise ValueError("Invalid value")
```

### Developer Errors (английский, с деталями)

```python
# ✅ Good — техническая ошибка с деталями
raise TypeError(
    f"Expected SecureStorage instance, got {type(storage).__name__}. "
    f"Check dependency injection configuration."
)
```

### Security Errors (минимум info leak)

```python
# ✅ Good — не раскрывает детали
raise AuthenticationError("Неверные учётные данные")

# ❌ Bad — раскрывает существование пользователя
raise AuthenticationError(f"Неверный пароль для пользователя {username}")
```

---

## 13. Performance Considerations

### Efficient ESC/P Command Building

```python
# ✅ Good — использование bytearray
def build_command() -> bytes:
    """Построение ESC/P команды эффективно."""
    cmd = bytearray()
    cmd.extend(b'\x1B@')  # ESC @
    cmd.extend(b'\x1B!')  # ESC !
    cmd.append(0x10)
    return bytes(cmd)

# ❌ Bad — многократная конкатенация bytes
def build_command_slow() -> bytes:
    cmd = b''
    cmd += b'\x1B@'
    cmd += b'\x1B!'
    cmd += bytes([0x10])
    return cmd
```

### Lazy Loading (ResourceManager pattern)

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

### Floppy Disk Optimization (опционально)

- `MAX_FLOPPY_BYTES` = 1,340,000 (~1.28 MB с запасом на FAT12)
- **gzip** для сжатия данных
- **Ed25519** — компактная подпись (64 B vs 3,309 B ML-DSA-65)
- **MAX_IMAGE_EMBED** = 100 KB
- `FloppyOptimizer` — автоматическая замена алгоритмов на floppy-friendly аналоги

---

## 14. Testing Requirements

### Coverage Thresholds

| Scope | Minimum Coverage |
|-------|-----------------|
| Overall Project | 80%+ |
| New Modules | 90%+ |
| Security Modules | 95%+ |
| Critical Paths | 100% |

### Test Markers

```python
@pytest.mark.slow          # медленные тесты (>1s)
@pytest.mark.security      # критичные security тесты
@pytest.mark.integration   # интеграционные тесты
@pytest.mark.crypto        # криптографические тесты с NIST vectors
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

---

## 15. Git Workflow

### Branch Naming

| Prefix | Purpose |
|--------|---------|
| `feature/` | Новая функциональность |
| `fix/` | Исправление бага |
| `refactor/` | Рефакторинг без изменения API |
| `docs/` | Только документация |
| `test/` | Добавление/улучшение тестов |

### Commit Messages (Conventional Commits, русский)

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

---

## 16. Dependencies Management

### Core Dependencies (всегда устанавливать)

```bash
pip install -e ".[dev]"       # dev dependencies
pip install -e ".[security]"  # security features
```

### Optional Dependencies

| Extra | Description |
|-------|-------------|
| `windows` | pywin32 для Windows printer API |
| `audit` | Логирование и мониторинг |
| `all` | Все зависимости |

### Critical Pinned Versions

```
liboqs>=0.15.0
pyscard>=2.0.0
yubikey-manager>=5.0.0
```

### Code Quality Tools

```bash
black src/ tests/        # Форматирование
isort src/ tests/        # Сортировка импортов
mypy --strict src/       # Проверка типов
bandit -r src/           # Security linting
safety check             # Dependency vulnerabilities
```

---

## 17. Common Pitfalls

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

### ❌ Security: Input Validation

```python
def validate_user_input(text: str, max_length: int = 1000) -> str:
    """Валидация пользовательского ввода."""
    if len(text) > max_length:
        raise ValueError(f"Текст превышает максимальную длину {max_length}")
    # Sanitize potentially dangerous characters
    sanitized = text.replace('\x00', '')  # null bytes
    return sanitized
```

### ❌ Security: Path Traversal

```python
def safe_file_path(user_path: str, base_dir: Path) -> Path:
    """Безопасная обработка пути к файлу."""
    requested_path = (base_dir / user_path).resolve()
    # Проверка, что путь внутри base_dir
    if not requested_path.is_relative_to(base_dir):
        raise ValueError("Недопустимый путь к файлу")
    return requested_path
```

### ❌ Security: Hardcoded Secrets

```python
# ✅ Good — secrets не в коде
from src.security.crypto import SecureStorage

storage = SecureStorage(path="data/secure/keystore.enc")
api_key = storage.get("printer_api_key")

# ❌ Bad — hardcoded secrets
API_KEY = "sk_live_abc123xyz"  # NEVER DO THIS
```

### ❌ Resource Limits

```python
# Ограничения на размер данных
MAX_IMAGE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_DOCUMENT_PAGES = 1000

# Таймауты
PRINTER_TIMEOUT = 30  # seconds
NETWORK_TIMEOUT = 10  # seconds
```

---

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

---

## External References

- **Epson ESC/P**: [Epson FX-890 Manual](https://files.support.epson.com/pdf/fx890_/fx890_ug.pdf)
- **Python Typing**: [PEP 484](https://www.python.org/dev/peps/pep-0484/)
- **Pytest**: [pytest documentation](https://docs.pytest.org/)
- **Cryptography**: [PyCA Cryptography](https://cryptography.io/)

---

> **Version:** 3.0 | **Date:** March 2026 | **Project Completion:** ~48%
