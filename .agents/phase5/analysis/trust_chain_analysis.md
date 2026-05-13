# Анализ архитектуры сервисов для Trust Chain

**Дата:** 2026-04-11  
**Агент:** 1.1  
**Цель:** Исследовать паттерны сервисов, audit logging и Ed25519 подписи для реализации TrustChainService

---

## 1. Паттерны построения сервисов

### 1.1 Стандартная структура сервиса

Все сервисы в проекте следуют единому паттерну:

**Импорты:**
```python
from __future__ import annotations
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Protocol
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from src.security.audit import AuditLog
```

**Протоколы для DI:**
```python
class DependencyProtocol(Protocol):
    def method(self, param: str) -> bool:
        ...

class AuditCallbackProtocol(Protocol):
    def __call__(self, event: str, details: Dict[str, Any]) -> None:
        ...
```

**Immutable результаты:**
```python
@dataclass(frozen=True)
class OperationResult:
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None
```

### 1.2 Ключевые паттерны в сервисах

| Паттерн | Назначение | Пример |
|---------|------------|--------|
| `Protocol` | DI-контейнер, mock в тестах | `DocumentLockProtocol` |
| `frozen=True` | Immutable результаты | `CreateResult`, `BatchResult` |
| `TYPE_CHECKING` | Избежание циклических зависимостей | Импорты моделей |
| `_audit()` | Единый способ логирования | `self._audit("event", {...})` |
| `__slots__` | Оптимизация памяти | `CryptoService` |

### 1.3 Пример полного сервиса

См. `document_manager_service.py`:
- Protocol для зависимостей в начале файла
- frozen dataclass для результатов
- Callback для аудита
- Внутренний метод `_audit()` для логирования

---

## 2. Интеграция Audit Logging

### 2.1 Способ 1: Callback через Protocol (рекомендуется)

```python
class AuditCallbackProtocol(Protocol):
    def __call__(self, event: str, details: Dict[str, Any]) -> None:
        ...

class SomeService:
    def __init__(self, audit_callback: Optional[AuditCallbackProtocol] = None):
        self._audit_callback = audit_callback
    
    def _audit(self, event: str, details: Dict[str, Any]) -> None:
        if self._audit_callback:
            try:
                self._audit_callback(event, details)
            except Exception as exc:
                logger.error("Ошибка аудита: %s", exc)
```

### 2.2 Способ 2: Прямое использование AuditLog

```python
from src.security.audit import AuditEventType
from src.security.audit.logger import AuditLog

class CryptoService:
    def __init__(self, audit_log: "AuditLog | None" = None):
        self._audit_log = audit_log
    
    def _log_operation(self, event_type: AuditEventType, **kwargs):
        if self._audit_log:
            self._audit_log.log_event(event_type, details=kwargs)
```

### 2.3 Релевантные AuditEventType

Из `src/security/audit/events.py`:
- `TEMPLATE_IMPORTED`, `TEMPLATE_EXPORTED`
- `TEMPLATE_SIGNATURE_INVALID`, `TEMPLATE_TRUST_CHAIN_FAILED`
- `CRYPTO_SIGNING`, `CRYPTO_VERIFICATION`
- `CRYPTO_KEY_GENERATED`

---

## 3. Работа с Ed25519 подписями

### 3.1 Характеристики Ed25519

- Размер подписи: **64 bytes**
- Размер публичного ключа: **32 bytes**
- Размер приватного ключа: **32 bytes**
- Безопасность: ~128 bits (эквивалент RSA-3072)
- Алгоритм: `Ed25519` (стандарт в проекте)

### 3.2 Использование через CryptoService

```python
from src.security.crypto.service.crypto_service import CryptoService

service = CryptoService()

# Генерация ключей
private_key, public_key = service.generate_keypair(algorithm_id="Ed25519")

# Подпись
document = b"content"
signed = service.sign_document(document, private_key)

# Верификация
is_valid = service.verify_signature(
    document, signed.signature, public_key, signed.algorithm_id
)
```

### 3.3 SignedDocument структура

```python
@dataclass(frozen=True)
class SignedDocument:
    signature: bytes       # Ed25519: 64 bytes
    algorithm_id: str      # "Ed25519"
    public_key_hint: str   # Первые 8 байт публичного ключа (hex)
```

---

## 4. Структура для TrustChainService (черновик)

### 4.1 Протоколы

```python
class CryptoServiceProtocol(Protocol):
    def sign_document(self, document: bytes, private_key: bytes, *, 
                      algorithm_id: str | None = None) -> SignedDocument: ...
    def verify_signature(self, document: bytes, signature: bytes,
                         public_key: bytes, algorithm_id: str) -> bool: ...
    def generate_keypair(self, algorithm_id: str | None = None) -> tuple[bytes, bytes]: ...

class TrustChainAuditCallback(Protocol):
    def __call__(self, event: str, details: dict[str, Any]) -> None: ...
```

### 4.2 Модели данных

```python
@dataclass(frozen=True)
class TrustAnchor:
    key_id: str                 # UUID
    public_key: bytes           # Ed25519: 32 bytes raw
    name: str                   # Описание
    created_at: datetime
    expires_at: Optional[datetime] = None
    revoked: bool = False
    
    @property
    def is_active(self) -> bool: ...

@dataclass(frozen=True)
class SignedArtifact:
    artifact_id: str            # ID артефакта
    artifact_type: str          # template, config, document
    content_hash: str           # SHA-256 hex
    signature: bytes            # Ed25519: 64 bytes
    signing_key_id: str         # ID anchor
    signed_at: datetime
    algorithm: str = "Ed25519"

@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    anchor_valid: bool = True
    chain_valid: bool = True
    expired: bool = False
    revoked: bool = False
    error: Optional[str] = None
```

### 4.3 TrustChainService класс

```python
class TrustChainService:
    def __init__(
        self,
        crypto_service: Optional[CryptoServiceProtocol] = None,
        audit_callback: Optional[TrustChainAuditCallback] = None,
        storage_path: Optional[Path] = None,
    ) -> None: ...
    
    # Anchor Management
    def create_anchor(self, name: str, expires_days: Optional[int] = None) 
                      -> tuple[TrustAnchor, bytes]: ...
    def revoke_anchor(self, key_id: str) -> bool: ...
    def get_anchor(self, key_id: str) -> Optional[TrustAnchor]: ...
    def get_active_anchors(self) -> list[TrustAnchor]: ...
    
    # Signing
    def sign_artifact(self, content: bytes, artifact_id: str, 
                      artifact_type: str, anchor_key_id: str,
                      private_key: bytes) -> SignedArtifact: ...
    
    # Verification
    def verify_signature(self, artifact: SignedArtifact, 
                         content: Optional[bytes] = None) -> VerificationResult: ...
    def verify_chain(self, artifact_id: str) -> VerificationResult: ...
```

---

## 5. Рекомендации по реализации

### 5.1 Структура файлов

```
src/security/trust/
├── __init__.py              # Экспорты
├── trust_chain_service.py   # Основной сервис
├── models.py                # TrustAnchor, SignedArtifact
├── storage.py               # Persistence
└── exceptions.py            # TrustChainError
```

### 5.2 Требования

- **Типизация:** `mypy --strict`, полные annotations
- **Immutable:** `frozen=True` для всех dataclass
- **DI:** Protocol для всех внешних зависимостей
- **Audit:** Логировать все операции
- **Безопасность:** Хранить только публичные ключи

### 5.3 События аудита для Trust Chain

Рекомендуемые новые типы:
- `TRUST_ANCHOR_ADDED`
- `TRUST_ANCHOR_REMOVED`
- `TRUST_ANCHOR_ROTATED`
- `TRUST_SIGNATURE_VERIFIED`
- `TRUST_SIGNATURE_FAILED`
- `TRUST_CHAIN_VALIDATED`
- `TRUST_CHAIN_BROKEN`

---

## 6. Ссылки на исходники

- `src/services/document_manager_service.py` - Protocol DI
- `src/services/__init__.py` - экспорты
- `src/security/crypto/service/crypto_service.py` - audit integration
- `src/security/crypto/algorithms/signing.py` - Ed25519
- `src/security/audit/events.py` - AuditEventType
- `src/security/audit/logger.py` - AuditLog

---

**Анализ завершен. Результат сохранен в:**
`/home/Mike/Dev/FX-Text-processor/FX-Text-processor-3/.agents/phase5/analysis/trust_chain_analysis.md`
