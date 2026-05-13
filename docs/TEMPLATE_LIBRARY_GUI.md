# Template Library GUI - Phase 5 Documentation

> **Version:** 1.0  
> **Date:** April 2026  
> **Status:** Complete  
> **Language:** Русский (технические термины на английском)

---

## Содержание

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [API Reference](#3-api-reference)
   - 3.1 [TrustChainServiceProtocol](#31-trustchainserviceprotocol)
   - 3.2 [FloppyOptimizerProtocol](#32-floppyoptimizerprotocol)
   - 3.3 [TrustChainDialog](#33-trustchaindialog)
   - 3.4 [FloppyOptimizerDialog](#34-floppyoptimizerdialog)
4. [Usage Examples](#4-usage-examples)
   - 4.1 [Проверка Trust Chain шаблона](#41-проверка-trust-chain-шаблона)
   - 4.2 [Оптимизация шаблона для дискеты](#42-оптимизация-шаблона-для-дискеты)
   - 4.3 [Интеграция в TemplateImportDialog](#43-интеграция-в-templateimportdialog)
5. [Testing](#5-testing)
   - 5.1 [Unit тесты](#51-unit-тесты)
   - 5.2 [Integration тесты](#52-integration-тесты)
   - 5.3 [Coverage отчёт](#53-coverage-отчёт)
6. [Changelog](#6-changelog)

---

## 1. Overview

Фаза 5 реализует компоненты GUI для управления **Trust Chain** (цепочкой доверия) и **Floppy Optimization** (оптимизацией для дискет) в библиотеке шаблонов FX Text Processor 3.

### Что реализовано в фазе 5

| Компонент | Описание | Статус |
|-----------|----------|--------|
| **TrustChainService** | Сервис управления цепочками доверия шаблонов | ✅ Complete |
| **TrustChainDialog** | Диалог просмотра и верификации цепочки доверия | ✅ Complete |
| **FloppyOptimizer** | Оптимизатор размера данных для дискет 3.5" | ✅ Complete |
| **FloppyOptimizerDialog** | Диалог оптимизации шаблонов для дискеты | ✅ Complete |
| **TemplateImportDialog** | Рефакторинг диалога импорта с интеграцией Trust Chain | ✅ Complete |

### Основные возможности

#### Trust Chain
- Иерархическое отображение цепочки доверия (Root → Master → Template)
- Цветовая индикация статуса (🟢 valid, 🟡 warning, 🔴 invalid)
- Детальная информация о каждом звене цепочки
- Проверка подписей шаблонов с валидацией цепочки до корневого ключа

#### Floppy Optimization
- Интерактивный расчёт экономии при изменении опций
- Визуальное отображение статуса (✅ помещается / ❌ превышение)
- Поддержка Ed25519 (64 байт) vs ML-DSA-65 (3,309 байт)
- Gzip сжатие для уменьшения объёма
- Progress bar для длительных операций

### Ограничения дискеты

```python
MAX_FLOPPY_BYTES = 1_340_000  # ~1.28 MB полезной нагрузки
```

---

## 2. Architecture

### Диаграмма компонентов

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              GUI Layer                                   │
│  ┌─────────────────────┐    ┌─────────────────────┐                     │
│  │  TemplateImportDialog │    │  TrustChainDialog   │                     │
│  │  (Refactored)         │    │                     │                     │
│  ├─────────────────────┤    ├─────────────────────┤                     │
│  │ - File selection    │    │ - Treeview          │                     │
│  │ - Preview panel     │◄──►│ - Status display    │                     │
│  │ - Trust verification│    │ - Detail panel      │                     │
│  │ - Size optimization │    │ - Verify button     │                     │
│  └──────────┬──────────┘    └──────────┬──────────┘                     │
│             │                          │                                 │
│             ▼                          ▼                                 │
│  ┌─────────────────────────────────────────────┐                         │
│  │         FloppyOptimizerDialog               │                         │
│  │  ┌─────────────────────────────────────────┐│                         │
│  │  │ - Optimization options                 ││                         │
│  │  │ - Size comparison                      ││                         │
│  │  │ - Export functionality                 ││                         │
│  │  └─────────────────────────────────────────┘│                         │
│  └─────────────────────────────────────────────┘                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                            Service Layer                               │
│  ┌─────────────────────┐    ┌─────────────────────┐                   │
│  │  TrustChainService  │    │   FloppyOptimizer   │                   │
│  │  (Implementation)   │    │   (Implementation)  │                   │
│  ├─────────────────────┤    ├─────────────────────┤                   │
│  │ - verify_template() │    │ - analyze()         │                   │
│  │ - get_trust_chain() │    │ - optimize()        │                   │
│  │ - add_trusted_key() │    │ - get_recommendations│                   │
│  │ - revoke_key()      │    │ - estimate_signature│                   │
│  └─────────────────────┘    └─────────────────────┘                   │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           Protocol Layer                               │
│  ┌─────────────────────────┐  ┌─────────────────────────┐              │
│  │ TrustChainServiceProtocol│  │ FloppyOptimizerProtocol │              │
│  │ (Abstract Interface)     │  │ (Abstract Interface)    │              │
│  └─────────────────────────┘  └─────────────────────────┘              │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           Data Layer                                   │
│  ┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────┐ │
│  │   trusted_keys.json │    │  Template Files     │    │   AuditLog  │ │
│  │   (Keystore)        │    │  (.fxstpl)          │    │             │ │
│  └─────────────────────┘    └─────────────────────┘    └─────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

### Структура модулей

```
src/
├── services/
│   ├── trust_chain_service.py      # Реализация TrustChainService
│   └── protocols/
│       └── template_security.py    # Protocol-ы: TrustChainServiceProtocol,
│                                   #              FloppyOptimizerProtocol
├── security/crypto/utilities/
│   ├── floppy_optimizer.py         # Реализация FloppyOptimizer
│   └── trust_chain_utils.py        # Утилиты Trust Chain
└── gui/dialogs/
    ├── template_import_dialog.py   # Рефакторинг: интеграция Trust Chain
    ├── trust_chain_dialog.py       # TrustChainDialog
    └── floppy_optimizer_dialog.py  # FloppyOptimizerDialog
```

---

## 3. API Reference

### 3.1 TrustChainServiceProtocol

**Путь:** [`src/services/protocols/template_security.py`](../../src/services/protocols/template_security.py)

Протокол для сервиса цепочек доверия шаблонов. Определяет контракт для управления цепочками доверия: верификация шаблонов, добавление/отзыв ключей, построение и проверка цепочек.

```python
@runtime_checkable
class TrustChainServiceProtocol(Protocol):
    """Protocol для сервиса цепочек доверия шаблонов.

    Все методы должны быть thread-safe.
    """

    def verify_template(
        self,
        template: Any,
        trusted_keys: Optional[set[str]] = None,
        verify_chain: bool = True,
    ) -> TrustVerificationResult:
        """Верифицирует шаблон по цепочке доверия."""
        ...

    def get_trust_chain(
        self,
        key_id: str,
        include_revoked: bool = False,
    ) -> list[TrustChainLink]:
        """Возвращает цепочку доверия для ключа."""
        ...

    def add_trusted_key(
        self,
        key_id: str,
        public_key: bytes,
        algorithm: str,
        parent_key_id: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> TrustChainLink:
        """Добавляет новый доверенный ключ в цепочку."""
        ...

    def revoke_key(
        self,
        key_id: str,
        reason: str,
        revoked_by: str,
    ) -> bool:
        """Отзывает ключ из цепочки доверия."""
        ...

    def is_key_trusted(
        self,
        key_id: str,
        at_time: Optional[datetime] = None,
    ) -> bool:
        """Проверяет, является ли ключ доверенным."""
        ...

    def get_root_keys(self) -> list[TrustChainLink]:
        """Возвращает все корневые (self-signed) ключи."""
        ...
```

#### Основные типы данных

**TrustChainLink** - звено цепочки доверия:

```python
@dataclass(frozen=True)
class TrustChainLink:
    key_id: str                    # Уникальный ID ключа
    public_key: bytes             # Публичный ключ
    algorithm: str                # Алгоритм подписи ("Ed25519", etc.)
    added_at: datetime           # Время добавления
    parent_key_id: Optional[str]  # ID родительского ключа
    expires_at: Optional[datetime]  # Срок действия
    signature: Optional[bytes]    # Подпись от родителя
    metadata: dict[str, Any]      # Дополнительные данные

    def is_root(self) -> bool:
        """Проверяет, является ли ключ корневым."""
        return self.parent_key_id is None

    def is_expired(self) -> bool:
        """Проверяет, истёк ли срок действия ключа."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at
```

**TrustVerificationResult** - результат верификации:

```python
@dataclass(frozen=True)
class TrustVerificationResult:
    template_id: str              # ID шаблона
    is_valid: bool               # Валидна ли подпись криптографически
    trust_status: TrustStatus    # Статус доверия
    chain_depth: int             # Глубина цепочки
    signing_key_id: str          # ID ключа подписи
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def can_trust(self) -> bool:
        """True если шаблон можно считать доверенным."""
        return self.is_valid and self.trust_status == TrustStatus.TRUSTED
```

**TrustStatus** - статусы доверия:

```python
class TrustStatus(Enum):
    TRUSTED = "trusted"      # 🟢 Доверенный
    UNTRUSTED = "untrusted"  # 🔴 Недоверенный
    REVOKED = "revoked"      # 🚫 Отозван
    EXPIRED = "expired"      # 🟡 Истёк срок
    PENDING = "pending"      # ⏳ Ожидает проверки
```

### 3.2 FloppyOptimizerProtocol

**Путь:** [`src/services/protocols/template_security.py`](../../src/services/protocols/template_security.py)

Протокол для оптимизатора размера под дискеты. Определяет контракт для анализа и оптимизации данных для сохранения на дискету 3.5".

```python
@runtime_checkable
class FloppyOptimizerProtocol(Protocol):
    """Protocol для оптимизатора размера под дискеты.

    MAX_FLOPPY_BYTES: ~1.28 MB полезной нагрузки.

    Note:
        Ed25519 предпочтительнее ML-DSA-65 для дискет
        (64 байт против 3,309 байт подписи).
    """

    def analyze(self, data: bytes) -> OptimizationResult:
        """Анализирует данные и оценивает возможность оптимизации."""
        ...

    def optimize(
        self,
        data: bytes,
        target_size: int = MAX_FLOPPY_BYTES,
        allowed_methods: Optional[set[OptimizationType]] = None,
    ) -> tuple[bytes, OptimizationResult]:
        """Оптимизирует данные до целевого размера."""
        ...

    def get_recommendations(
        self,
        data: bytes,
        target_size: int = MAX_FLOPPY_BYTES,
    ) -> list[str]:
        """Возвращает список рекомендаций по оптимизации (русский)."""
        ...

    def estimate_signature_size(
        self,
        algorithm: str,
        include_key: bool = True,
    ) -> int:
        """Оценивает размер подписи для алгоритма."""
        ...
```

#### Основные типы данных

**OptimizationResult** - результат оптимизации:

```python
@dataclass(frozen=True)
class OptimizationResult:
    original_size: int                      # Исходный размер
    optimized_size: int                   # Оптимизированный размер
    applied_methods: list[OptimizationType]  # Применённые методы
    fits_on_floppy: bool                   # Помещается ли на дискету
    target_bytes: int                      # Целевой размер
    recommendations: list[str]            # Рекомендации
    warnings: list[str]                   # Предупреждения

    @property
    def savings_bytes(self) -> int:
        """Экономия в байтах."""
        return self.original_size - self.optimized_size

    @property
    def savings_percent(self) -> float:
        """Экономия в процентах."""
        if self.original_size == 0:
            return 0.0
        return ((self.original_size - self.optimized_size)
                / self.original_size) * 100
```

**OptimizationType** - типы оптимизации:

```python
class OptimizationType(Enum):
    COMPRESSION = "compression"           # Gzip сжатие
    USE_COMPACT_FORMAT = "compact"      # Компактный JSON
    TRUNCATE_METADATA = "truncate"       # Усечение метаданных
    REMOVE_REDUNDANT = "remove"         # Удаление избыточных данных
```

**Константы размеров подписей:**

| Алгоритм | Размер подписи | Размер ключа | Итого |
|----------|---------------|--------------|-------|
| Ed25519 | 64 B | 32 B | 96 B |
| ML-DSA-65 | 3,309 B | 1,952 B | 5,261 B |
| RSA-PSS-4096 | 512 B | 512 B | 1,024 B |

### 3.3 TrustChainDialog

**Путь:** [`src/gui/dialogs/trust_chain_dialog.py`](../../src/gui/dialogs/trust_chain_dialog.py)

Диалог просмотра и верификации цепочки доверия шаблона.

```python
class TrustChainDialog(tk.Toplevel):
    """Диалог просмотра цепочки доверия шаблона.

    Attributes:
        _template: Шаблон для проверки.
        _trust_service: Сервис цепочек доверия.
        _chain_links: Загруженная цепочка доверия.
        _verification_result: Результат последней верификации.
    """

    def __init__(
        self,
        parent: tk.Widget,
        template: FormTemplate,
        trust_service: TrustChainServiceProtocol,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """Инициализация диалога цепочки доверия."""
        ...

    def show(self) -> Optional[TrustVerificationResult]:
        """Показывает диалог и возвращает результат.

        Returns:
            TrustVerificationResult или None если диалог закрыт.
        """
        ...
```

#### Основные компоненты UI

| Компонент | Описание |
|-----------|----------|
| Treeview | Иерархическое отображение цепочки Root → Master → Template |
| Status emojis | 🟢 trusted, 🔴 untrusted, 🚫 revoked, 🟡 expired, ⏳ pending |
| Detail panel | Детальная информация о выбранном звене |
| Verify button | Повторная верификация цепочки |

#### Цветовая схема

```python
COLOR_VALID: str = "#28a745"    # Green - доверенный
COLOR_WARNING: str = "#ffc107" # Yellow - предупреждение
COLOR_INVALID: str = "#dc3545" # Red - недоверенный
COLOR_INFO: str = "#17a2b8"     # Cyan - информация
```

### 3.4 FloppyOptimizerDialog

**Путь:** [`src/gui/dialogs/floppy_optimizer_dialog.py`](../../src/gui/dialogs/floppy_optimizer_dialog.py)

Диалог оптимизации шаблона для сохранения на дискету 3.5".

```python
class FloppyOptimizerDialog(tk.Toplevel):
    """Диалог оптимизации шаблона для дискеты (1.44MB).

    Attributes:
        MAX_FLOPPY_BYTES: Максимальный размер (~1.28MB полезной нагрузки).
    """

    MAX_FLOPPY_BYTES: int = 1_340_000

    def __init__(
        self,
        parent: tk.Widget,
        template_data: bytes,
        optimizer: Optional[Any] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """Инициализация диалога оптимизации."""
        ...

    def show(self) -> tuple[bool, Optional[bytes]]:
        """Показывает диалог и возвращает результат.

        Returns:
            Кортеж (success, optimized_data).
            success: True если оптимизация выполнена успешно.
            optimized_data: Оптимизированные данные или None.
        """
        ...

    def get_estimated_savings(self) -> EstimatedSavings:
        """Возвращает текущую оценку экономии."""
        ...

    def set_options(self, options: OptimizationOptions) -> None:
        """Устанавливает опции оптимизации programmatically."""
        ...
```

#### Опции оптимизации

```python
@dataclass
class OptimizationOptions:
    """Опции оптимизации для расчёта размера."""

    remove_thumbnails: bool = True    # Удалить миниатюры превью
    compact_json: bool = True         # Использовать компактный JSON
    use_ed25519: bool = True          # Использовать Ed25519 вместо ML-DSA-65
    remove_descriptions: bool = False # Удалить описания полей
```

#### UI компоненты

| Компонент | Описание |
|-----------|----------|
| Size panel | Отображение текущего, оптимизированного размера и экономии |
| Options panel | Чекбоксы для выбора методов оптимизации |
| Status panel | Статус: ✅ помещается / ❌ превышение |
| Progress bar | Прогресс оптимизации |
| Action buttons | Optimize, Export, Cancel |

---

## 4. Usage Examples

### 4.1 Проверка Trust Chain шаблона

```python
from pathlib import Path
from src.services.trust_chain_service import TrustChainService
from src.gui.dialogs.trust_chain_dialog import TrustChainDialog
from src.services.template_manager import FormTemplate
import tkinter as tk

# Создание сервиса цепочек доверия
trust_service = TrustChainService(
    keystore_path=Path.home() / ".fxtextprocessor" / "keystore",
    audit_secret_key=b"secret_key_32_bytes_long_for_hmac",
)

# Добавление корневого ключа (однократно)
root_link = trust_service.add_trusted_key(
    key_id="root-authority",
    public_key=root_public_key_bytes,
    algorithm="Ed25519",
    metadata={"name": "Organization Root CA"}
)

# Добавление подчинённого ключа
master_link = trust_service.add_trusted_key(
    key_id="master-key-001",
    public_key=master_public_key_bytes,
    algorithm="Ed25519",
    parent_key_id="root-authority",
    metadata={"name": "Template Signing Key"}
)

# Загрузка шаблона
template = FormTemplate.load(Path("template.fxstpl"))

# Программная проверка
result = trust_service.verify_template(template, verify_chain=True)
if result.can_trust:
    print(f"✅ Шаблон доверенный, глубина цепочки: {result.chain_depth}")
else:
    print(f"❌ Проверка не пройдена: {result.errors}")

# Открытие диалога Trust Chain
root = tk.Tk()
dialog = TrustChainDialog(
    parent=root,
    template=template,
    trust_service=trust_service,
)
verification_result = dialog.show()
```

### 4.2 Оптимизация шаблона для дискеты

```python
from src.security.crypto.utilities.floppy_optimizer import FloppyOptimizer
from src.gui.dialogs.floppy_optimizer_dialog import (
    FloppyOptimizerDialog,
    OptimizationOptions,
)
import tkinter as tk

# Чтение данных шаблона
template_data = Path("large_template.fxstpl").read_bytes()

# Программная оптимизация
optimizer = FloppyOptimizer()

# Анализ без изменения данных
analysis = optimizer.analyze(template_data)
print(f"Исходный размер: {analysis.original_size:,} bytes")
print(f"Помещается на дискету: {analysis.fits_on_floppy}")
print(f"Рекомендации: {analysis.recommendations}")

# Полная оптимизация
optimized_data, result = optimizer.optimize(
    template_data,
    target_size=1_340_000,  # MAX_FLOPPY_BYTES
)
print(f"Оптимизированный размер: {result.optimized_size:,} bytes")
print(f"Экономия: {result.savings_percent:.1f}%")

# Открытие диалога оптимизации
root = tk.Tk()
dialog = FloppyOptimizerDialog(
    parent=root,
    template_data=template_data,
    optimizer=optimizer,  # Опционально
)

# Установка опций programmatically
dialog.set_options(OptimizationOptions(
    remove_thumbnails=True,
    compact_json=True,
    use_ed25519=True,
    remove_descriptions=False,
))

success, optimized = dialog.show()
if success:
    Path("optimized_template.fxstpl").write_bytes(optimized)
    print(f"✅ Сохранено: {len(optimized):,} bytes")
```

### 4.3 Интеграция в TemplateImportDialog

```python
from pathlib import Path
import tkinter as tk
from src.gui.dialogs.template_import_dialog import (
    TemplateImportDialog,
    ImportResult,
)
from src.services.template_manager import TemplateManager
from src.services.trust_chain_service import TrustChainService
from src.security.crypto.utilities.floppy_optimizer import FloppyOptimizer

# Инициализация зависимостей
keystore_path = Path.home() / ".fxtextprocessor" / "keystore"
audit_key = b"32_bytes_secret_key_for_hmac_auth..."

trust_service = TrustChainService(
    keystore_path=keystore_path,
    audit_secret_key=audit_key,
)

floppy_optimizer = FloppyOptimizer()
template_manager = TemplateManager()

# Callback для обработки результата
def on_import_complete(result: ImportResult) -> None:
    if result.success:
        print(f"✅ Импортирован: {result.template_id}")
        print(f"   Страниц: {len(result.template.pages)}")
    else:
        print(f"❌ Ошибка: {result.error}")

# Создание и отображение диалога
root = tk.Tk()

dialog = TemplateImportDialog(
    parent=root,
    template_manager=template_manager,
    trust_chain_service=trust_service,
    floppy_optimizer=floppy_optimizer,
    on_import=on_import_complete,
)

result = dialog.show()
if result and result.success:
    print(f"Template imported: {result.template_id}")
```

#### Рефакторинг TemplateImportDialog

В фазе 5 `template_import_dialog.py` был рефакторирован для интеграции:

1. **Trust Chain Service** - проверка подписей шаблонов
2. **Floppy Optimizer** - оптимизация размера для дискет
3. **TrustChainDialog** - отображение цепочки доверия
4. **FloppyOptimizerDialog** - диалог оптимизации

```python
class TemplateImportDialog(tk.Toplevel):
    """Диалог импорта шаблонов с проверкой Trust Chain.

    Attributes:
        _template_manager: Менеджер шаблонов для импорта.
        _trust_chain_service: Сервис цепочек доверия.
        _floppy_optimizer: Оптимизатор размера для дискеты.
    """

    def __init__(
        self,
        parent: Optional[tk.Widget],
        template_manager: TemplateManager,
        trust_chain_service: TrustChainService,      # NEW: Trust Chain
        floppy_optimizer: FloppyOptimizer,          # NEW: Floppy Optimizer
        on_import: Optional[Callable[[ImportResult], None]] = None,
    ) -> None:
        ...

    def _on_verify(self) -> None:
        """Обработчик проверки подписи.

        Открывает TrustChainDialog для отображения
        детальной информации о цепочке доверия.
        """
        dialog = TrustChainDialog(
            parent=self,
            template=self._template,
            trust_service=self._trust_chain_service,
        )
        dialog.show()

    def _on_import(self) -> None:
        """Обработчик импорта.

        Проверяет размер файла и предлагает оптимизацию
        через FloppyOptimizerDialog если размер превышает лимит.
        """
        if file_size > MAX_FLOPPY_SIZE:
            dialog = FloppyOptimizerDialog(
                parent=self,
                template_data=self._selected_path.read_bytes(),
            )
            opt_success, optimized_data = dialog.show()
            ...
```

---

## 5. Testing

### 5.1 Unit тесты

#### Trust Chain Service

```bash
# Запуск unit тестов TrustChainService
pytest tests/unit/services/test_trust_chain_service.py -v

# С coverage отчётом
pytest tests/unit/services/test_trust_chain_service.py -v --cov=src.services.trust_chain_service --cov-report=term-missing
```

#### Trust Chain Dialog

```bash
# ⚠️ ВАЖНО: Для GUI тестов всегда используйте xvfb-run
xvfb-run -a python -m pytest tests/unit/gui/dialogs/test_trust_chain_dialog.py -v
```

#### Floppy Optimizer

```bash
# Тесты FloppyOptimizer
pytest tests/unit/security/crypto/utilities/test_floppy_optimizer.py -v

# Тесты диалога (через xvfb)
xvfb-run -a python -m pytest tests/unit/gui/dialogs/test_floppy_optimizer_dialog.py -v
```

#### Запуск всех тестов Phase 5

```bash
# Все тесты Phase 5
pytest tests/unit/services/test_trust_chain_service.py \
       tests/unit/security/crypto/utilities/test_floppy_optimizer.py \
       tests/unit/security/crypto/utilities/test_trust_chain_utils.py -v

# GUI тесты Phase 5 (через xvfb)
xvfb-run -a python -m pytest \
    tests/unit/gui/dialogs/test_trust_chain_dialog.py \
    tests/unit/gui/dialogs/test_floppy_optimizer_dialog.py -v
```

### 5.2 Integration тесты

```bash
# Интеграционные тесты TemplateImportDialog
xvfb-run -a python -m pytest tests/integration/test_template_import.py -v

# Тесты интеграции Trust Chain с TemplateManager
pytest tests/integration/test_trust_chain_integration.py -v
```

### 5.3 Coverage отчёт

```bash
# Полный coverage для модулей Phase 5
pytest tests/unit/services/test_trust_chain_service.py \
       tests/unit/security/crypto/utilities/test_floppy_optimizer.py \
       tests/unit/security/crypto/utilities/test_trust_chain_utils.py \
       --cov=src.services.trust_chain_service \
       --cov=src.security.crypto.utilities.floppy_optimizer \
       --cov=src.security.crypto.utilities.trust_chain_utils \
       --cov-report=html \
       --cov-report=term
```

**Ожидаемые показатели coverage:**

| Модуль | Ожидаемый Coverage | Минимум |
|--------|-------------------|---------|
| TrustChainService | ~95% | 90% |
| TrustChainDialog | ~85% | 80% |
| FloppyOptimizer | ~95% | 90% |
| FloppyOptimizerDialog | ~85% | 80% |

**Отчёт о покрытии:**

```bash
# Генерация HTML отчёта
pytest --cov=src --cov-report=html -m "not slow"

# Просмотр в браузере
open htmlcov/index.html
```

---

## 6. Changelog

### Что добавлено (Phase 5)

#### Новые компоненты

| Компонент | Файл | Описание |
|-----------|------|----------|
| TrustChainService | [`src/services/trust_chain_service.py`](../../src/services/trust_chain_service.py) | Сервис управления цепочками доверия |
| TrustChainDialog | [`src/gui/dialogs/trust_chain_dialog.py`](../../src/gui/dialogs/trust_chain_dialog.py) | Диалог просмотра Trust Chain |
| FloppyOptimizer | [`src/security/crypto/utilities/floppy_optimizer.py`](../../src/security/crypto/utilities/floppy_optimizer.py) | Оптимизатор для дискет |
| FloppyOptimizerDialog | [`src/gui/dialogs/floppy_optimizer_dialog.py`](../../src/gui/dialogs/floppy_optimizer_dialog.py) | Диалог оптимизации |

#### Новые Protocol-ы

| Protocol | Файл | Описание |
|----------|------|----------|
| TrustChainServiceProtocol | [`src/services/protocols/template_security.py`](../../src/services/protocols/template_security.py) | Интерфейс Trust Chain |
| FloppyOptimizerProtocol | [`src/services/protocols/template_security.py`](../../src/services/protocols/template_security.py) | Интерфейс Floppy Optimizer |

#### Новые типы данных

| Тип | Файл | Описание |
|-----|------|----------|
| TrustChainLink | [`src/services/protocols/template_security.py`](../../src/services/protocols/template_security.py) | Звено цепочки доверия |
| TrustVerificationResult | [`src/services/protocols/template_security.py`](../../src/services/protocols/template_security.py) | Результат верификации |
| TrustStatus | [`src/services/protocols/template_security.py`](../../src/services/protocols/template_security.py) | Статусы доверия |
| OptimizationResult | [`src/services/protocols/template_security.py`](../../src/services/protocols/template_security.py) | Результат оптимизации |
| OptimizationType | [`src/services/protocols/template_security.py`](../../src/services/protocols/template_security.py) | Типы оптимизации |
| KeyEntry | [`src/services/trust_chain_service.py`](../../src/services/trust_chain_service.py) | Запись о ключе в хранилище |

### Что изменено (Refactoring)

#### template_import_dialog.py

**До (Phase 4):**
```python
class TemplateImportDialog(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Widget,
        template_manager: TemplateManager,
        on_import: Optional[Callable] = None,
    ):
        ...
```

**После (Phase 5):**
```python
class TemplateImportDialog(tk.Toplevel):
    def __init__(
        self,
        parent: Optional[tk.Widget],
        template_manager: TemplateManager,
        trust_chain_service: TrustChainService,      # + NEW
        floppy_optimizer: FloppyOptimizer,          # + NEW
        on_import: Optional[Callable[[ImportResult], None]] = None,
    ):
        ...
```

**Изменения:**
- Добавлен `trust_chain_service` параметр
- Добавлен `floppy_optimizer` параметр
- Добавлен `TemplatePreviewPanel` для предпросмотра
- Добавлена секция "Проверка подписи"
- Добавлена секция "Размер файла"
- Добавлен callback `on_import: Optional[Callable[[ImportResult], None]]`
- Обновлен `ImportResult` dataclass

### Breaking Changes

#### Удалены встроенные классы

Следующие классы были **удалены** из `template_import_dialog.py`:

| Класс | Замена | Причина |
|-------|--------|---------|
| `TrustChainVerifier` (встроенный) | `TrustChainService` | Перенесено в Service Layer |
| `SizeValidator` (встроенный) | `FloppyOptimizer` | Перенесено в Service Layer |
| `SimplePreview` (встроенный) | `TemplatePreviewPanel` | Вынесено в отдельный класс |

**Миграция кода:**

```python
# Старый код (Phase 4):
dialog = TemplateImportDialog(
    parent=root,
    template_manager=template_manager,
)

# Новый код (Phase 5):
dialog = TemplateImportDialog(
    parent=root,
    template_manager=template_manager,
    trust_chain_service=trust_service,      # + REQUIRED
    floppy_optimizer=floppy_optimizer,      # + REQUIRED
)
```

#### Изменения в конструкторах

| Класс | Старый конструктор | Новый конструктор |
|-------|-------------------|-------------------|
| TemplateImportDialog | `(parent, template_manager, on_import=None)` | `(parent, template_manager, trust_chain_service, floppy_optimizer, on_import=None)` |

---

## Ссылки на исходные файлы

### Реализации

- [TrustChainService](../../src/services/trust_chain_service.py) - Сервис цепочек доверия
- [TrustChainDialog](../../src/gui/dialogs/trust_chain_dialog.py) - Диалог Trust Chain
- [FloppyOptimizer](../../src/security/crypto/utilities/floppy_optimizer.py) - Оптимизатор дискет
- [FloppyOptimizerDialog](../../src/gui/dialogs/floppy_optimizer_dialog.py) - Диалог оптимизации
- [TemplateImportDialog](../../src/gui/dialogs/template_import_dialog.py) - Диалог импорта (refactored)

### Protocol-ы

- [TrustChainServiceProtocol](../../src/services/protocols/template_security.py) - Интерфейс Trust Chain
- [FloppyOptimizerProtocol](../../src/services/protocols/template_security.py) - Интерфейс Floppy Optimizer

### Типы данных

- [template_security.py](../../src/services/protocols/template_security.py) - Все типы и константы

### Тесты

- [test_trust_chain_service.py](../../tests/unit/services/test_trust_chain_service.py)
- [test_trust_chain_dialog.py](../../tests/unit/gui/dialogs/test_trust_chain_dialog.py)
- [test_trust_chain_utils.py](../../tests/unit/security/crypto/utilities/test_trust_chain_utils.py)
- [test_floppy_optimizer.py](../../tests/unit/security/crypto/utilities/test_floppy_optimizer.py)
- [test_floppy_optimizer_dialog.py](../../tests/unit/gui/dialogs/test_floppy_optimizer_dialog.py)

---

*Document generated for FX Text Processor 3 - Phase 5*
