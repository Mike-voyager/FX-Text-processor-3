# Анализ архитектуры crypto utilities для Floppy Optimizer

**Дата анализа:** 2026-04-11  
**Агент:** 1.2  
**Статус:** Завершено

---

## 1. AlgorithmRegistry API

### 1.1 Основные компоненты

Реестр реализован как **thread-safe Singleton** в `/src/security/crypto/core/registry.py`.

#### Получение экземпляра
```python
from src.security.crypto.core.registry import AlgorithmRegistry

registry = AlgorithmRegistry.get_instance()  # Thread-safe singleton
```

#### Основные методы Registry

| Метод | Назначение | Возвращаемое значение |
|-------|------------|----------------------|
| `create(name)` | Создать экземпляр алгоритма | Algorithm instance |
| `get_metadata(name)` | Получить метаданные | AlgorithmMetadata |
| `list_algorithms()` | Список всех метаданных | List[AlgorithmMetadata] |
| `list_algorithm_names()` | Список имён алгоритмов | List[str] |
| `is_registered(name)` | Проверка регистрации | bool |

#### Query API (фильтрация)

```python
# По категории
registry.list_by_category(AlgorithmCategory.SYMMETRIC_CIPHER)
registry.list_by_category(AlgorithmCategory.SIGNATURE)

# По уровню безопасности
registry.list_by_security_level(SecurityLevel.QUANTUM_RESISTANT)

# Безопасные для production
registry.list_safe_for_production()

# Универсальный поиск
registry.search(
    category=AlgorithmCategory.SIGNATURE,
    is_post_quantum=True,
    floppy_friendly=FloppyFriendly.EXCELLENT,
)
```

#### Регистрация алгоритмов

```python
registry.register_algorithm(
    name="AES-256-GCM",
    factory=AES256GCM,  # Callable[[], Any]
    metadata=AES256GCM.metadata,  # AlgorithmMetadata
    validate=True,  # Проверка Protocol
)
```

### 1.2 RegistryStatistics

```python
stats = registry.get_statistics()
# Поля:
# - total: int (всего алгоритмов)
# - by_category: Dict[AlgorithmCategory, int]
# - by_security_level: Dict[SecurityLevel, int]
# - by_floppy_friendly: Dict[FloppyFriendly, int]  # <-- Важно для FloppyOptimizer
# - post_quantum_count: int
# - aead_count: int
# - safe_for_production_count: int
```

---

## 2. FloppyFriendly Enum

### 2.1 Определение

```python
from src.security.crypto.core.metadata import FloppyFriendly

class FloppyFriendly(int, Enum):
    EXCELLENT = 1   # 💚 < 100 bytes
    ACCEPTABLE = 2  # 💛 100-1000 bytes
    POOR = 3        # ❌ > 1000 bytes
```

### 2.2 Автоопределение по размеру

```python
# Статический метод
floppy_level = FloppyFriendly.from_size(size_bytes)

# Логика:
# - < 100 bytes  -> EXCELLENT
# - 100-1000 bytes -> ACCEPTABLE
# - > 1000 bytes -> POOR
```

### 2.3 Использование в AlgorithmMetadata

```python
from src.security.crypto.core.metadata import AlgorithmMetadata

metadata = AlgorithmMetadata(
    name="Ed25519",
    category=AlgorithmCategory.SIGNATURE,
    floppy_friendly=FloppyFriendly.EXCELLENT,  # Явное указание
    # ... другие поля
)
```

### 2.4 Поиск по FloppyFriendly в Registry

```python
# Получить только EXCELLENT алгоритмы
excellent_algos = registry.list_floppy_friendly(FloppyFriendly.EXCELLENT)

# Или через search
registry.search(floppy_friendly=FloppyFriendly.EXCELLENT)
```

---

## 3. Существующий FloppyOptimizer

### 3.1 Текущая реализация

Расположение: `/src/security/crypto/utilities/utils.py` (строки 335-471)

```python
class FloppyOptimizer:
    """
    Оптимизация криптографических операций для дискет.
    
    Валидация размеров файлов, сжатие хранилища, управление бэкапами
    и рекомендации по алгоритмам для ограниченных носителей.
    """
```

### 3.2 Константы и рекомендации

```python
_RECOMMENDED: Dict[str, List[str]] = {
    "symmetric": ["aes-256-gcm", "chacha20-poly1305", "aes-128-gcm"],
    "signing": ["ed25519"],
    "hash": ["sha-256", "blake2s"],
    "kdf": ["argon2id", "scrypt"],
    "key_exchange": ["x25519"],
}
```

### 3.3 Методы текущего FloppyOptimizer

| Метод | Назначение |
|-------|------------|
| `__init__(config)` | Инициализация с CryptoConfig |
| `validate_file_size(size)` | Проверка вмещения в лимит |
| `estimate_storage_size(dir)` | Оценка размера директории |
| `compress_keystore(data)` | Сжатие zlib |
| `decompress_keystore(data)` | Распаковка zlib |
| `cleanup_old_backups(dir)` | Очистка старых бэкапов |
| `get_recommended_algorithms(category)` | Рекомендуемые алгоритмы |

### 3.4 Инициализация

```python
from src.security.crypto.utilities.config import CryptoConfig
from src.security.crypto.utilities.utils import FloppyOptimizer

# С конфигурацией
config = CryptoConfig.floppy_aggressive()
optimizer = FloppyOptimizer(config)

# Или с дефолтной конфигурацией
optimizer = FloppyOptimizer()  # CryptoConfig.default()
```

---

## 4. Примеры utility-сервисов

### 4.1 KeyManager (`key_management.py`)

**Шаблон utility с Registry:**

```python
class KeyManager:
    def __init__(self, registry: AlgorithmRegistry) -> None:
        self._registry = registry
    
    def wrap_key(self, key_to_wrap: bytes, wrapping_key: bytes, 
                 algorithm: str) -> bytes:
        cipher = self._registry.create(algorithm)
        nonce, ciphertext = cipher.encrypt(wrapping_key, key_to_wrap)
        return nonce + ciphertext
```

### 4.2 CryptoMigrator (`migration.py`)

**Шаблон с результатом операции:**

```python
@dataclass(frozen=True)
class MigrationResult:
    old_algorithm: str
    new_algorithm: str
    success: bool
    error: Optional[str] = None

class CryptoMigrator:
    def __init__(self, registry: AlgorithmRegistry) -> None:
        self._registry = registry
```

### 4.3 PasswordHasher (`passwords.py`)

**Шаблон с fallback:**

```python
class PasswordHasher:
    def __init__(self, time_cost: int = ..., ...):
        self._argon2_hasher = _Argon2Hasher(...) if HAS_ARGON2 else None
    
    def hash_password(self, password: str) -> str:
        if self._argon2_hasher:
            return self._hash_argon2(password)
        return self._hash_scrypt(password)  # fallback
```

### 4.4 SecureStorage (`secure_storage.py`)

**Шаблон с Protocol-реализацией:**

```python
class SecureStorage:
    def save(self, name: str, data: bytes) -> None: ...  # KeyStoreProtocol
    def load(self, name: str) -> bytes: ...
    def delete(self, name: str) -> None: ...
```

---

## 5. Примеры оптимизаций (размеры алгоритмов)

### 5.1 Ed25519 vs ML-DSA-65

| Алгоритм | Тип | Размер подписи | Размер pubkey | FloppyFriendly | Overhead |
|----------|-----|----------------|---------------|----------------|----------|
| **Ed25519** | Classical | 64 bytes | 32 bytes | EXCELLENT | 96 bytes |
| **ML-DSA-65** | Post-quantum | 3,293 bytes | 1,952 bytes | POOR | 5,245 bytes |
| **ML-DSA-44** | Post-quantum | 2,420 bytes | 1,312 bytes | POOR | 3,732 bytes |
| **RSA-PSS-4096** | Classical | 512 bytes | 512 bytes | POOR | 1,024 bytes |
| **RSA-PSS-2048** | Classical | 256 bytes | 256 bytes | ACCEPTABLE | 512 bytes |

### 5.2 Симметричные шифры

| Алгоритм | Key + Nonce + Tag | FloppyFriendly |
|----------|-------------------|----------------|
| AES-128-GCM | 16 + 12 + 16 = 44 bytes | EXCELLENT |
| AES-256-GCM | 32 + 12 + 16 = 60 bytes | EXCELLENT |
| ChaCha20-Poly1305 | 32 + 24 + 16 = 72 bytes | EXCELLENT |

### 5.3 KDF алгоритмы

| Алгоритм | Состояние | FloppyFriendly |
|----------|-----------|----------------|
| Argon2id | Нет фиксированных размеров | EXCELLENT (всегда) |
| PBKDF2-SHA256 | Нет фиксированных размеров | EXCELLENT (всегда) |

---

## 6. Черновик FloppyOptimizerProtocol

### 6.1 Интерфейс (Protocol)

```python
from typing import Protocol, List, Dict, Optional
from src.security.crypto.core.metadata import AlgorithmCategory, FloppyFriendly

class FloppyOptimizerProtocol(Protocol):
    """Протокол для оптимизации под дискеты 3.5" (1.44 MB)."""
    
    MAX_FLOPPY_BYTES: int = 1_457_664  # 1.44 MB
    SAFETY_MARGIN: float = 0.95  # 5% запас на метаданные
    
    def select_best_algorithms(
        self,
        category: AlgorithmCategory,
        required_security: SecurityLevel = SecurityLevel.STANDARD,
        prefer_post_quantum: bool = False,
    ) -> List[str]:
        """
        Выбрать лучшие алгоритмы для floppy по категории.
        
        Приоритет:
        1. EXCELLENT floppy-friendly
        2. Затем ACCEPTABLE (если требуется)
        3. Учёт security_level
        4. PQ-preference (если включён)
        """
        ...
    
    def calculate_signature_overhead(
        self,
        algorithm: str,
        include_public_key: bool = True,
    ) -> int:
        """Рассчитать overhead подписи в байтах."""
        ...
    
    def estimate_document_size(
        self,
        plaintext_size: int,
        symmetric_algo: str,
        signature_algo: Optional[str] = None,
    ) -> int:
        """
        Оценить итоговый размер документа с шифрованием и подписью.
        
        Returns: plaintext + overhead + signature (опционально)
        """
        ...
    
    def can_fit_on_floppy(
        self,
        document_size: int,
        num_documents: int = 1,
    ) -> bool:
        """Проверить, поместятся ли документы на дискету."""
        ...
    
    def suggest_optimization(
        self,
        current_size: int,
        target_size: int = int(MAX_FLOPPY_BYTES * SAFETY_MARGIN),
    ) -> Dict[str, any]:
        """
        Предложить оптимизации для уменьшения размера.
        
        Returns: {
            "can_fit": bool,
            "recommended_algorithms": Dict[str, str],
            "compression_savings": int,
            "size_after": int,
        }
        """
        ...
    
    def get_size_comparison(
        self,
        algorithm: str,
    ) -> Dict[str, any]:
        """
        Получить сравнение размеров алгоритма с аналогами.
        
        Returns: {
            "algorithm": str,
            "category": AlgorithmCategory,
            "signature_size": Optional[int],
            "key_sizes": Dict[str, int],
            "floppy_friendly": FloppyFriendly,
            "comparison": List[Dict],  # Сравнение с похожими
        }
        """
        ...
```

### 6.2 Интеграция с CryptoConfig

```python
from src.security.crypto.utilities.config import CryptoConfig, FloppyMode

class EnhancedFloppyOptimizer:
    """Расширенный оптимизатор с интеграцией в CryptoConfig."""
    
    def __init__(self, registry: AlgorithmRegistry):
        self._registry = registry
        self._config = CryptoConfig.default()
    
    def apply_floppy_profile(self, mode: FloppyMode) -> None:
        """Применить floppy-профиль к конфигурации."""
        self._config.apply_floppy_mode(mode)
        # Обновить рекомендации на основе registry
```

---

## 7. Рекомендации по реализации

### 7.1 Архитектурные принципы

1. **Dependency Injection**: Принимать `AlgorithmRegistry` в конструкторе
2. **Immutable Results**: Возвращать `frozen=True` dataclasses
3. **Type Safety**: Полные type annotations, `mypy --strict`
4. **Docstrings**: Google-style на русском языке

### 7.2 Интеграция с Registry

```python
def _get_floppy_candidates(
    self,
    category: AlgorithmCategory,
) -> List[AlgorithmMetadata]:
    """Получить кандидатов из registry с сортировкой по размеру."""
    candidates = []
    for name in self._registry.list_by_category(category):
        meta = self._registry.get_metadata(name)
        if meta.is_safe_for_production():
            candidates.append(meta)
    
    # Сортировка по total_overhead_bytes()
    return sorted(candidates, key=lambda m: m.total_overhead_bytes())
```

### 7.3 Сравнительная таблица: Ed25519 vs ML-DSA

| Критерий | Ed25519 | ML-DSA-65 | ML-DSA-44 |
|----------|---------|-----------|-----------|
| Security Level | STANDARD | QUANTUM_RESISTANT | QUANTUM_RESISTANT |
| Post-Quantum | ❌ | ✅ | ✅ |
| FloppyFriendly | EXCELLENT | POOR | POOR |
| Signature Size | 64 bytes | 3,293 bytes | 2,420 bytes |
| Public Key | 32 bytes | 1,952 bytes | 1,312 bytes |
| Private Key | 32 bytes | ~4,000 bytes | ~3,000 bytes |
| **Total Overhead** | **128 bytes** | **~9,245 bytes** | **~6,732 bytes** |
| Fit on Floppy | ✅ 10,000+ | ✅ ~155 | ✅ ~215 |

**Вывод**: Ed25519 предпочтителен для floppy, ML-DSA-65 только если PQ критичен.

---

## 8. Связанные профили (CryptoProfile)

Из `/src/security/crypto/service/profiles.py`:

| Профиль | Симметричный | Подпись | Floppy-Optimized |
|-----------|--------------|---------|------------------|
| STANDARD | AES-256-GCM | Ed25519 | ❌ |
| PARANOID | AES-256-GCM-SIV | Ed448 | ❌ |
| FLOPPY_BASIC | ChaCha20-Poly1305 | Ed25519 | ✅ |
| FLOPPY_AGGRESSIVE | AES-128-GCM | Ed25519 | ✅ |
| PQC_STANDARD | AES-256-GCM | ML-DSA-65 | ❌ |
| PQC_PARANOID | AES-256-GCM-SIV | ML-DSA-87 | ❌ |

---

## 9. Тестовые паттерны

Из `/tests/unit/security/crypto/utilities/test_utils.py`:

```python
class TestFloppyOptimizer:
    def test_validate_file_size_within_limit(self):
        optimizer = FloppyOptimizer()
        assert optimizer.validate_file_size(1000) is True
    
    def test_validate_file_size_exceeds_limit(self):
        optimizer = FloppyOptimizer()
        # max_storage_size из config
        huge = optimizer._config.max_storage_size + 1
        assert optimizer.validate_file_size(huge) is False
    
    def test_get_recommended_algorithms_known_category(self):
        optimizer = FloppyOptimizer()
        algs = optimizer.get_recommended_algorithms("symmetric")
        assert "aes-256-gcm" in algs
```

---

## 10. Сводка ключевых API

### Импорты для работы

```python
# Core
from src.security.crypto.core.registry import AlgorithmRegistry
from src.security.crypto.core.metadata import (
    AlgorithmMetadata,
    AlgorithmCategory,
    SecurityLevel,
    FloppyFriendly,
)

# Utilities
from src.security.crypto.utilities.utils import FloppyOptimizer
from src.security.crypto.utilities.config import CryptoConfig, FloppyMode

# Service
from src.security.crypto.service.profiles import CryptoProfile, get_profile_config
```

### Быстрый старт

```python
# 1. Получить registry
registry = AlgorithmRegistry.get_instance()

# 2. Получить все EXCELLENT алгоритмы
excellent = registry.list_floppy_friendly(FloppyFriendly.EXCELLENT)

# 3. Поиск подходящих подписей
signatures = registry.search(
    category=AlgorithmCategory.SIGNATURE,
    floppy_friendly=FloppyFriendly.EXCELLENT,
    is_post_quantum=False,  # или True для PQ
)

# 4. Получить метаданные для сравнения
ed25519_meta = registry.get_metadata("Ed25519")
ml_dsa_meta = registry.get_metadata("ML-DSA-65")

print(f"Ed25519 overhead: {ed25519_meta.total_overhead_bytes()} bytes")
print(f"ML-DSA-65 overhead: {ml_dsa_meta.total_overhead_bytes()} bytes")
```

---

*Конец анализа*
