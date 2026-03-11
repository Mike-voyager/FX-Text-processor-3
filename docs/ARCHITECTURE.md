# FX Text Processor 3 — Architecture Document

> **Version:** 3.0  
> **Date:** March 2026  
> **Status:** Living Document  
> **Author:** Architecture Team  
> **Language:** Русский (технические термины на английском)

---

## Содержание

1. [Overview](#1-overview)
2. [Architecture Principles](#2-architecture-principles)
3. [Project Structure](#3-project-structure)
4. [Data Flow](#4-data-flow)
5. [Module Responsibilities](#5-module-responsibilities)
6. [Document Indexing System](#6-document-indexing-system)
7. [File Formats & Extensions](#7-file-formats--extensions)
8. [Floppy Disk Optimization](#8-floppy-disk-optimization)
9. [Cloud Synchronization](#9-cloud-synchronization)
10. [Technology Stack](#10-technology-stack)
11. [Module Status](#11-module-status)
12. [Related Documents](#12-related-documents)

---

## 1. Overview

### Назначение

**FX Text Processor 3** — профессиональный WYSIWYG-редактор документов, предназначенный для печати на матричном принтере **Epson FX-890** через протокол ESC/P. Приложение спроектировано с enterprise-grade безопасностью по модели **Zero Trust** и принципу **Air-Gap First**.

### Целевая среда

- **Один оператор** на физически изолированной (air-gapped) машине
- Полная автономная работа без подключения к сети
- Опциональная синхронизация через облачное хранилище (portable app)
- Поддержка переносных носителей (3.5" floppy, USB)

### Основные возможности

| Возможность | Описание |
|---|---|
| **WYSIWYG-редактирование** | Визуальное редактирование документов с предпросмотром результата печати |
| **Protected Blanks** | Система защищённых бланков с криптографической подписью и верификацией |
| **Криптографическая подпись** | Подпись документов (Ed25519, ML-DSA-65, ECDSA), включая PQC |
| **Печать через ESC/P** | Прямой вывод на Epson FX-890 через нативный протокол ESC/P |
| **Иерархическая типизация** | Система типов документов с наследованием, индексацией и схемами полей |
| **Импорт из Excel** | Маппинг данных из Excel-диапазонов в поля форм |
| **MFA-аутентификация** | Password + FIDO2 / TOTP / Backup Codes |
| **Audit Trail** | Неизменяемый журнал операций (hash chain + HMAC) |

---

## 2. Architecture Principles

### MVC + Service Layer

Приложение следует паттерну **Model–View–Controller** с дополнительным **Service Layer**, разделяющим бизнес-логику и координацию операций:

```
┌──────────────────────────────────────────────────┐
│                    View (Tkinter)                 │
│         GUI-виджеты, обработка событий           │
└──────────────────┬───────────────────────────────┘
                   │
┌──────────────────▼───────────────────────────────┐
│                  Controller                       │
│       Маршрутизация, валидация ввода             │
└──────────────────┬───────────────────────────────┘
                   │
┌──────────────────▼───────────────────────────────┐
│               Service Layer                       │
│    CryptoService, AuthService, PrintService,     │
│    DocumentService, BlanksService, AuditService  │
└──────────────────┬───────────────────────────────┘
                   │
┌──────────────────▼───────────────────────────────┐
│                   Model                           │
│     Dataclasses, Enums, Domain Objects           │
└──────────────────────────────────────────────────┘
```

### Zero Trust

Каждая операция аутентифицирована и авторизована. Нет доверенных зон — даже локальный пользователь проходит полный цикл аутентификации:

- Сессии с access/refresh tokens и IP binding
- Обязательный MFA (Password + второй фактор)
- Подпись конфигурации master key
- Hash-chain audit log для всех критических операций

### Air-Gap First

Система проектируется для полной работы **без сетевого подключения**:

- Все криптографические операции локальные
- Нет зависимости от внешних сервисов (CA, OCSP, CRL)
- FIDO2 через CTAP2 direct attestation (без WebAuthn сервера)
- TOTP без синхронизации времени (допуск ±30 секунд)
- Обновления через физические носители

### Preset + Fine-Tune

Четыре предустановленных профиля безопасности:

| Preset | Описание | Ключевые алгоритмы |
|---|---|---|
| **Standard** | Баланс безопасности и производительности | AES-256-GCM, Ed25519, Argon2id |
| **Paranoid** | Long-term archive, двойное шифрование | AES-256-GCM + ChaCha20, Ed25519 + ML-DSA-65, Argon2id (256MB) |
| **PQC** | Пост-квантовая криптография | ML-KEM-768, ML-DSA-65, AES-256-GCM |
| **Legacy** | Совместимость со старыми системами | AES-256-GCM, RSA-PSS-4096, PBKDF2-SHA256 |

Каждый пресет можно fine-tune: заменить отдельные алгоритмы, сохранив общую конфигурацию.

### Crypto Agility

- **Version headers** в каждом зашифрованном файле
- Алгоритмы идентифицируются по `AlgorithmId`, а не по имени
- Замена алгоритма не ломает старые документы — migration path через `documents/format/migration.py`
- Поддержка одновременно нескольких версий крипто-формата

### Defense in Depth

Многоуровневая защита:

1. **Аутентификация** — MFA с аппаратными ключами
2. **Шифрование** — AES-256-GCM (опционально двойное)
3. **Подпись** — Ed25519 / ML-DSA-65 для целостности
4. **Audit** — Неизменяемый hash-chain журнал
5. **Integrity** — Проверка хешей приложения при запуске
6. **Физическая изоляция** — Air-gap среда

### Strict Typing

```bash
mypy --strict src/
```

- Все функции с полными type annotations
- `Protocol` вместо ABC где возможно
- `TypeAlias`, `TypeVar`, `Generic` для параметризованных типов
- Никаких `Any` без явного обоснования

### TDD

- Целевое покрытие: **90%+** для всех модулей
- `pytest` + `pytest-cov`
- Тесты пишутся **до** реализации
- Property-based testing для криптографии (hypothesis)
- Fuzz-тесты для парсеров

### DI через конструктор и Protocol

```python
from typing import Protocol

class CryptoServiceProtocol(Protocol):
    def encrypt(self, data: bytes, key: bytes) -> bytes: ...
    def decrypt(self, data: bytes, key: bytes) -> bytes: ...

class DocumentService:
    def __init__(self, crypto: CryptoServiceProtocol, audit: AuditServiceProtocol) -> None:
        self._crypto = crypto
        self._audit = audit
```

- Зависимости явно передаются через конструктор
- `Protocol` для интерфейсов — structural subtyping
- `app_context.py` — единственный composition root
- Никаких глобальных синглтонов (кроме `TypeRegistry` с thread-safe доступом)

---

## 3. Project Structure

Полное дерево проекта:

```
src/
├── model/                   # Data layer — dataclasses, enums
│   ├── document.py          # Document, DocumentMetadata, PageSettings, PrinterSettings
│   ├── section.py           # Section, PageSettings (для section-level переопределений)
│   ├── paragraph.py         # Paragraph, EmbeddedObject
│   ├── run.py               # Run, EmbeddedObject, TextFormatting
│   ├── table.py             # Table, Cell, Row
│   └── enums.py             # FontFamily, CharactersPerInch, CodePage, Alignment, etc.
│
├── escp/                    # ESC/P protocol layer
│   └── commands/            # Pure byte constants — NO model imports
│       ├── text_formatting.py    # Bold, italic, underline, strikethrough, superscript, subscript
│       ├── fonts.py              # Font selection (Courier, Roman, Sans Serif, etc.)
│       ├── sizing.py             # Character width (CPI), height, proportional spacing
│       ├── positioning.py        # Absolute/relative horizontal positioning
│       ├── page_control.py       # Page length, margins, form feed
│       ├── line_spacing.py       # Line spacing modes (1/6", 1/8", n/180", n/360")
│       ├── print_quality.py      # Draft/NLQ mode selection
│       ├── hardware.py           # Printer reset, paper handling, bidirectional
│       ├── charset.py            # Code page selection (CP437, CP866, CP1251, etc.)
│       ├── barcode.py            # Barcode generation (ESC ( B)
│       ├── graphics.py           # Raster graphics modes (8-pin, 24-pin)
│       ├── shading.py            # Shading/fill commands
│       └── special_effects.py    # Outline, shadow effects
│
├── documents/               # Document processing & rendering
│   ├── types/               # Document type hierarchy
│   │   ├── registry.py           # TypeRegistry (singleton, thread-safe)
│   │   ├── document_type.py      # DocumentType, DocumentSubtype
│   │   ├── index_template.py     # IndexTemplate, IndexSegmentDef, SegmentType
│   │   ├── index_formatter.py    # format/parse индексов, int_to_roman
│   │   ├── type_schema.py        # TypeSchema, FieldDefinition, FieldType
│   │   ├── inheritance.py        # Наследование полей между типами
│   │   └── builtin/              # Встроенные типы документов
│   │       ├── base.py           # DOC — базовый документ
│   │       ├── invoice.py        # INV — счёт
│   │       └── verbal_note.py    # DVN — вербальная нота
│   │
│   ├── constructor/         # Form/document construction
│   │   ├── form_constructor.py   # Создание документа из шаблона
│   │   ├── field_builder.py      # Конструктор полей (drag-and-drop)
│   │   ├── field_palette.py      # Палитра элементов для визуального редактора
│   │   ├── variable_parser.py    # Подстановка переменных, ESC/P переменные
│   │   ├── excel_import.py       # ExcelImporter + ExcelFieldMapping
│   │   └── style_manager.py      # Стили элементов (наследование стилей)
│   │
│   ├── format/              # Serialization & migration
│   │   ├── document_format.py    # .fxsd / .fxsd.enc сериализация
│   │   ├── template_format.py    # .fxstpl сериализация
│   │   ├── migration.py          # Миграция между версиями формата
│   │   └── json_schema/          # JSON Schema для валидации
│   │       ├── document_v1.0.json
│   │       └── template_v1.0.json
│   │
│   └── printing/            # ESC/P render pipeline
│       ├── document_renderer.py  # Обход Document → ESC/P bytes
│       ├── paragraph_renderer.py # Paragraph → ESC/P bytes
│       ├── table_renderer.py     # Table → ESC/P bytes (колонки, границы)
│       ├── run_renderer.py       # Run → ESC/P bytes (форматирование текста)
│       └── barcode_renderer.py   # Barcode → ESC/P bytes (ESC ( B)
│
├── security/                # Security subsystem
│   ├── crypto/              # ✅ Cryptographic primitives (v2.3, 46 algorithms)
│   │   ├── core/            # Protocols, metadata, registry, exceptions
│   │   │   ├── protocols.py       # CipherProtocol, SignerProtocol, HasherProtocol
│   │   │   ├── metadata.py        # AlgorithmMetadata, AlgorithmId
│   │   │   ├── registry.py        # AlgorithmRegistry (thread-safe)
│   │   │   └── exceptions.py      # CryptoError, KeyError, VerificationError
│   │   │
│   │   ├── algorithms/      # Algorithm implementations
│   │   │   ├── symmetric/         # AES-256-GCM, ChaCha20-Poly1305, AES-256-CBC
│   │   │   ├── signing/           # Ed25519, ECDSA, ML-DSA-65, RSA-PSS
│   │   │   ├── asymmetric/        # X25519, RSA-OAEP, ML-KEM-768
│   │   │   ├── key_exchange/      # ECDH, X25519, ML-KEM
│   │   │   ├── hashing/           # SHA-256, SHA-512, BLAKE2b, SHA3-256
│   │   │   └── kdf/               # Argon2id, HKDF, PBKDF2
│   │   │
│   │   ├── advanced/        # Advanced cryptographic schemes
│   │   │   ├── hybrid_encryption.py   # Classical + PQC hybrid
│   │   │   ├── group_encryption.py    # Multi-recipient encryption
│   │   │   ├── key_escrow.py          # Key escrow with Shamir SSS
│   │   │   └── session_keys.py        # Ephemeral session key management
│   │   │
│   │   ├── service/         # Service layer
│   │   │   ├── crypto_service.py      # CryptoService — main entry point
│   │   │   ├── ui_helpers.py          # UI-friendly wrappers
│   │   │   └── profiles.py           # Security presets (Standard, Paranoid, PQC, Legacy)
│   │   │
│   │   ├── utilities/       # Support utilities
│   │   │   ├── utils.py              # Constant-time compare, secure random
│   │   │   ├── config.py             # CryptoConfig dataclass
│   │   │   ├── passwords.py          # Password strength validation
│   │   │   ├── secure_storage.py     # Encrypted key storage
│   │   │   ├── key_rotation.py       # Key rotation scheduler
│   │   │   ├── key_formats.py        # PEM, DER, raw key serialization
│   │   │   ├── nonce_manager.py      # Nonce/IV uniqueness guarantees
│   │   │   └── floppy_optimizer.py   # Floppy-friendly algorithm selection
│   │   │
│   │   └── hardware/        # Hardware crypto backends
│   │       └── hardware_crypto.py    # PIV (smart cards), OpenPGP, OTP
│   │
│   ├── auth/                # 🚧 Authentication (77%)
│   │   ├── password.py               # PasswordHasher (Argon2id)
│   │   ├── password_service.py       # PasswordService — change, verify, policy
│   │   ├── session.py                # SessionManager — access/refresh tokens, IP binding
│   │   ├── second_factor.py          # SecondFactorProtocol
│   │   ├── second_factor_service.py  # SecondFactorService — orchestration
│   │   ├── fido2_service.py          # CTAP2 direct (python-fido2)
│   │   ├── totp_service.py           # RFC 6238, software TOTP
│   │   ├── code_service.py           # Backup codes (one-time use)
│   │   └── second_method/            # Factor implementations
│   │       ├── totp_factor.py        # TotpFactor
│   │       ├── fido2_factor.py       # Fido2Factor
│   │       └── backup_code_factor.py # BackupCodeFactor
│   │
│   ├── audit/               # ✅ Immutable audit log
│   │   ├── audit_log.py             # AuditLog — append-only hash chain
│   │   ├── audit_entry.py           # AuditEntry dataclass
│   │   └── audit_verifier.py        # Chain integrity verification
│   │
│   ├── blanks/              # ✅ Protected Blanks security layer
│   │   ├── blank_manager.py         # BlankManager — lifecycle (create, sign, revoke)
│   │   ├── blank_signer.py          # Cryptographic signing of blanks
│   │   ├── blank_verifier.py        # Offline verification (QR-based)
│   │   └── blank_storage.py         # Secure .fxsblank storage
│   │
│   ├── compliance/          # ✅ GDPR, retention, anonymization
│   │   ├── gdpr.py                  # GDPR data processing rules
│   │   ├── retention.py             # Data retention policies
│   │   └── anonymization.py         # PII anonymization
│   │
│   ├── hardware/            # 🚧 Device registry & backends
│   │   ├── device_registry.py       # Known devices (smart cards, FIDO2 keys)
│   │   ├── piv_backend.py           # PIV smart card operations
│   │   └── openpgp_backend.py       # OpenPGP card operations
│   │
│   ├── integrity/           # 🚧 Application integrity
│   │   ├── app_hash.py             # Application binary hash check
│   │   └── config_signature.py     # Config file signature verification
│   │
│   ├── lock/                # 📋 TODO — Session lock
│   ├── erasure.py           # 📋 TODO — Secure wipe (DoD 5220.22-M)
│   └── monitoring/          # 📋 TODO — Health checks
│
├── printer/                 # Print transport layer
│   ├── base_adapter.py      # 📋 PrinterProtocol — abstract interface
│   ├── cups_adapter.py      # 📋 CUPS adapter (Linux)
│   ├── win_adapter.py       # 📋 WritePrinter API adapter (Windows)
│   └── file_adapter.py      # 📋 File output (debug/testing)
│
├── app_context.py           # DI container — composition root (singleton)
│
├── backup/                  # 📋 TODO — Key ceremony, Shamir SSS, paper key
├── network/                 # 📋 TODO — LAN verifier (opt-in, flag-enabled)
└── stealth/                 # 📋 TODO — Steganography (future)
```

---

## 4. Data Flow

### 4.1 Основной pipeline: Редактирование → Печать

```
┌─────────────┐     ┌──────────────┐     ┌───────────────┐     ┌─────────────┐
│  User Input  │────▶│  Controller  │────▶│  Service Layer │────▶│    Model    │
│  (Tkinter)   │     │  (validate)  │     │  (coordinate)  │     │ (dataclass) │
└─────────────┘     └──────────────┘     └───────────────┘     └──────┬──────┘
                                                                       │
                                                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          documents/printing/                                │
│                                                                             │
│  document_renderer.py                                                       │
│    ├── paragraph_renderer.py ──▶ run_renderer.py                           │
│    ├── table_renderer.py                                                    │
│    └── barcode_renderer.py                                                  │
│                                                                             │
│  Каждый renderer импортирует:                                               │
│    - model/* (для обхода дерева документа)                                  │
│    - escp/commands/* (для генерации ESC/P байтов)                          │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │ bytes
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            escp/commands/                                    │
│                                                                             │
│  Чистые функции:  build_bold(on=True) → b'\x1b\x45'                       │
│                   build_font(font_id) → b'\x1b\x6b\x00'                    │
│                   build_position(col) → b'\x1b\x24\x00\x01'               │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │ bytes
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                             printer/                                        │
│                                                                             │
│  PrinterProtocol.send(data: bytes) → None                                  │
│    ├── WinAdapter    → Win32 WritePrinter API                              │
│    ├── CupsAdapter   → CUPS lp/lpr                                         │
│    └── FileAdapter   → debug file output                                   │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │ raw bytes
                                   ▼
                          ┌─────────────────┐
                          │ Physical Printer │
                          │   Epson FX-890   │
                          └─────────────────┘
```

### 4.2 Protected Blanks pipeline

```
┌───────────────┐     ┌───────────────────┐     ┌────────────────────┐
│  TypeRegistry  │────▶│  form_constructor  │────▶│     Document       │
│  (тип + схема) │     │  (шаблон → doc)    │     │  (заполненный)     │
└───────────────┘     └───────────────────┘     └────────┬───────────┘
                                                          │
                                                          ▼
                                              ┌───────────────────────┐
                                              │  blanks/blank_manager  │
                                              │  (sign, assign index)  │
                                              │  blank_id + full_index │
                                              └────────┬──────────────┘
                                                       │
                                          ┌────────────┴────────────┐
                                          ▼                         ▼
                                ┌──────────────────┐    ┌──────────────────┐
                                │  .fxsblank file   │    │  printing/        │
                                │  (encrypted store) │    │  (ESC/P render)  │
                                └──────────────────┘    └────────┬─────────┘
                                                                  │
                                                                  ▼
                                                        ┌──────────────────┐
                                                        │  Physical Paper   │
                                                        │  (with QR code)  │
                                                        └────────┬─────────┘
                                                                  │
                                                                  ▼ scan QR
                                                        ┌──────────────────┐
                                                        │ blanks/verifier   │
                                                        │ (offline verify)  │
                                                        └──────────────────┘
```

### 4.3 Шифрование документа

```
Document (JSON)
    │
    ▼ gzip compress
Compressed bytes
    │
    ▼ crypto/service/crypto_service.py
    │
    ├── [Standard]  AES-256-GCM(key=derived_from_master_password)
    ├── [Paranoid]  AES-256-GCM → ChaCha20-Poly1305 (double encryption)
    ├── [PQC]       ML-KEM-768 key encapsulation → AES-256-GCM
    └── [Legacy]    AES-256-GCM + PBKDF2-SHA256 (RSA-PSS-4096)
    │
    ▼
.fxsd.enc file
    │
    ├── Version Header (algorithm_id, format_version, nonce, salt)
    ├── Encrypted Payload
    └── Authentication Tag / HMAC
```

---

## 5. Module Responsibilities

### 5.1 model/

**Назначение:** Чистый слой данных — domain objects без бизнес-логики.

**Правила:**

- Все классы — `@dataclass` с полными type hints
- `frozen=True` где возможно (immutable by default)
- Валидация в `__post_init__`
- **НЕ импортирует** из других слоёв (`escp/`, `security/`, `documents/`)
- Enum'ы для всех параметров Epson FX-890

**Ключевые классы:**

```python
# document.py
@dataclass
class Document:
    metadata: DocumentMetadata
    sections: list[Section]
    page_settings: PageSettings
    printer_settings: PrinterSettings

@dataclass(frozen=True)
class DocumentMetadata:
    title: str
    document_type: str          # код типа из TypeRegistry
    document_index: str         # e.g. "DVN-44-K53-IX"
    created_at: datetime
    modified_at: datetime
    author: str
    version: int

@dataclass(frozen=True)
class PageSettings:
    page_length_lines: int = 66          # стандарт для 11" бумаги
    left_margin_columns: int = 0
    right_margin_columns: int = 80
    top_margin_lines: int = 0
    bottom_margin_lines: int = 0

@dataclass(frozen=True)
class PrinterSettings:
    font: FontFamily = FontFamily.COURIER
    cpi: CharactersPerInch = CharactersPerInch.CPI_10
    code_page: CodePage = CodePage.CP866
    quality: PrintQuality = PrintQuality.NLQ
```

```python
# enums.py
class FontFamily(Enum):
    COURIER = 0
    ROMAN = 1
    SANS_SERIF = 2
    PRESTIGE = 3
    SCRIPT = 4

class CharactersPerInch(Enum):
    CPI_10 = 10    # стандартная ширина
    CPI_12 = 12    # condensed
    CPI_15 = 15    # ultra condensed

class CodePage(Enum):
    CP437 = 437    # US English
    CP866 = 866    # Russian
    CP1251 = 1251  # Windows Cyrillic

class Alignment(Enum):
    LEFT = "left"
    CENTER = "center"
    RIGHT = "right"
    JUSTIFY = "justify"
```

### 5.2 escp/commands/

**Назначение:** Чистые byte-константы и функции генерации ESC/P байтов.

**Правила:**

- **НЕ импортирует** из `model/`
- Каждый файл = группа ESC/P команд по Epson FX-890 Technical Reference Manual
- Enum'ы в этом модуле (`BarcodeType`, `GraphicsMode`) — **protocol-level коды**, НЕ model-level
- Все функции — pure functions: `(параметры) → bytes`

**Примеры:**

```python
# text_formatting.py
ESC = b'\x1b'

def bold_on() -> bytes:
    return ESC + b'\x45'           # ESC E

def bold_off() -> bytes:
    return ESC + b'\x46'           # ESC F

def italic_on() -> bytes:
    return ESC + b'\x34'           # ESC 4

def italic_off() -> bytes:
    return ESC + b'\x35'           # ESC 5

def underline_on() -> bytes:
    return ESC + b'\x2d\x01'      # ESC - 1

def underline_off() -> bytes:
    return ESC + b'\x2d\x00'      # ESC - 0
```

```python
# fonts.py
def select_font(font_id: int) -> bytes:
    """ESC k n — Select typeface."""
    return ESC + b'\x6b' + bytes([font_id])

# sizing.py
def set_cpi_10() -> bytes:
    """Select 10 CPI (deselect condensed)."""
    return ESC + b'\x50'           # ESC P

def set_cpi_12() -> bytes:
    """Select 12 CPI."""
    return ESC + b'\x4d'           # ESC M

def set_cpi_15() -> bytes:
    """Select 15 CPI (condensed)."""
    return ESC + b'\x67'           # ESC g
```

```python
# positioning.py
def absolute_position(dots: int) -> bytes:
    """ESC $ nL nH — Absolute horizontal position."""
    n_l = dots & 0xFF
    n_h = (dots >> 8) & 0xFF
    return ESC + b'\x24' + bytes([n_l, n_h])
```

### 5.3 documents/types/

**Назначение:** Иерархическая система типов документов с реестром, индексацией и схемами полей.

**TypeRegistry:**

```python
class TypeRegistry:
    """Singleton реестр всех зарегистрированных типов документов.
    
    Thread-safe: все мутации через Lock.
    Загружает builtin типы при инициализации.
    Пользовательские типы регистрируются через register().
    """
    _instance: ClassVar[TypeRegistry | None] = None
    _lock: ClassVar[Lock] = Lock()
    
    def get(self, code: str) -> DocumentType: ...
    def register(self, doc_type: DocumentType) -> None: ...
    def list_all(self) -> list[DocumentType]: ...
    def get_subtypes(self, parent_code: str) -> list[DocumentType]: ...
```

**DocumentType:**

```python
@dataclass(frozen=True)
class DocumentType:
    code: str                          # "DVN", "INV", "DOC"
    name: str                          # "Вербальная нота"
    parent_code: str | None            # None для корневых типов
    index_template: IndexTemplate      # Шаблон составного индекса
    field_schema: TypeSchema           # Схема полей
    subtypes: tuple[DocumentSubtype, ...] = ()
```

**IndexTemplate и IndexSegmentDef:**

```python
@dataclass(frozen=True)
class IndexTemplate:
    segments: tuple[IndexSegmentDef, ...]
    separator: str = "-"
    # Последний сегмент всегда SEQUENCE (римские цифры)

@dataclass(frozen=True)
class IndexSegmentDef:
    segment_type: SegmentType
    pattern: str                       # regex для валидации
    allowed_values: tuple[str, ...] | None = None
    description: str = ""

class SegmentType(Enum):
    ROOT_CODE = "root_code"     # Код типа документа (DVN)
    SUBTYPE = "subtype"         # Код подтипа (44)
    SERIES = "series"           # Серия (K53)
    CUSTOM = "custom"           # Произвольный сегмент
    SEQUENCE = "sequence"       # Порядковый номер (римские цифры)
```

**TypeSchema и FieldDefinition:**

```python
@dataclass(frozen=True)
class TypeSchema:
    fields: tuple[FieldDefinition, ...]
    version: str = "1.0"

@dataclass(frozen=True)
class FieldDefinition:
    field_id: str
    field_type: FieldType
    label: str                         # Отображаемое имя
    label_i18n: dict[str, str] = field(default_factory=dict)
    required: bool = False
    default_value: str | None = None
    validation_pattern: str | None = None
    max_length: int | None = None
    options: tuple[str, ...] | None = None
    escp_variable: str | None = None   # Связь с ESC/P переменной

class FieldType(Enum):
    STATIC_TEXT = "static_text"       # Неизменяемый текст шаблона
    TEXT_INPUT = "text_input"         # Текстовое поле ввода
    NUMBER_INPUT = "number_input"     # Числовое поле
    DATE_INPUT = "date_input"         # Поле даты
    TABLE = "table"                   # Табличное поле
    EXCEL_IMPORT = "excel_import"     # Импорт из Excel
    CALCULATED = "calculated"         # Вычисляемое поле
    QR = "qr"                         # QR-код
    BARCODE = "barcode"               # Штрих-код
    SIGNATURE = "signature"           # Цифровая подпись
    STAMP = "stamp"                   # Печать/штамп
```

**Наследование типов:**

```python
# inheritance.py
def resolve_schema(doc_type: DocumentType, registry: TypeRegistry) -> TypeSchema:
    """Собирает полную схему, объединяя поля родителя и потомка.
    
    Дочерний тип наследует ВСЕ поля родителя + добавляет свои.
    При конфликте field_id — поле потомка переопределяет родительское.
    """
```

### 5.4 documents/constructor/

**Назначение:** Создание документов из шаблонов, конструирование форм, импорт данных.

**form_constructor.py:**

```python
class FormConstructor:
    """Создаёт Document из шаблона (DocumentType + TypeSchema).
    
    1. Получает DocumentType из TypeRegistry
    2. Разрешает полную схему (с наследованием)
    3. Создаёт пустой Document с предзаполненными полями
    4. Применяет default_value из FieldDefinition
    """
    def create_from_type(self, type_code: str, **initial_values: str) -> Document: ...
    def create_from_template(self, template_path: Path) -> Document: ...
```

**excel_import.py:**

```python
@dataclass(frozen=True)
class ExcelFieldMapping:
    field_id: str
    source_file: Path
    sheet_name: str
    mapping_type: ExcelMappingType     # COLUMN, ROW, RANGE
    cell_range: str                     # "A1:D50", "B:B", "3:3"
    header_row: int | None = None

class ExcelMappingType(Enum):
    COLUMN = "column"
    ROW = "row"
    RANGE = "range"

class ExcelImporter:
    """Импортирует данные из Excel в поля документа."""
    def import_field(self, mapping: ExcelFieldMapping) -> list[list[str]]: ...
    def preview(self, mapping: ExcelFieldMapping, max_rows: int = 10) -> list[list[str]]: ...
```

**variable_parser.py:**

```python
class VariableParser:
    """Подстановка переменных в шаблонах.
    
    Поддерживаемые синтаксисы:
      - {{variable_name}}
      - ${variable_name}
      - {variable_name}
    
    ESC/P переменные (генерируют ESC/P байты):
      - {{PAGE_BREAK}}      → form feed
      - {{RESET_PRINTER}}   → ESC @
      - {{CURRENT_DATE}}    → текущая дата
      - {{DOCUMENT_INDEX}}  → индекс документа
    """
    def parse(self, template: str, context: dict[str, str]) -> str: ...
    def extract_variables(self, template: str) -> list[str]: ...
```

**style_manager.py:**

```python
class StyleManager:
    """Наследуемые стили для элементов формы.
    
    Иерархия стилей:
      Document Style → Section Style → Paragraph Style → Run Style
    
    Дочерний стиль наследует все свойства родителя
    и может переопределить отдельные.
    """
```

### 5.5 documents/format/

**Назначение:** Сериализация, десериализация и миграция форматов документов.

```python
# document_format.py
class DocumentFormat:
    """Сериализация Document ↔ .fxsd / .fxsd.enc"""
    
    def save(self, document: Document, path: Path, 
             encrypt: bool = False, crypto: CryptoServiceProtocol | None = None) -> None:
        """Сохраняет документ. При encrypt=True создаёт .fxsd.enc"""
    
    def load(self, path: Path, 
             crypto: CryptoServiceProtocol | None = None) -> Document:
        """Загружает документ. Автоматически определяет формат по расширению."""

# migration.py
class FormatMigration:
    """Миграция документов между версиями формата.
    
    Каждая миграция — отдельная функция: migrate_v1_0_to_v1_1(data)
    Цепочка миграций применяется автоматически.
    Версия формата хранится в заголовке документа.
    """
    def migrate(self, data: dict, from_version: str, to_version: str) -> dict: ...
```

### 5.6 documents/printing/

**Назначение:** Render pipeline — обход дерева `Document` и генерация ESC/P байтов.

**Правила:**

- Импортируют из `model/` (для обхода дерева) **И** из `escp/commands/` (для генерации байтов)
- Результат: `bytes` готовые к отправке на принтер
- Каждый renderer — stateless, получает контекст через аргументы

```python
# document_renderer.py
class DocumentRenderer:
    """Главный renderer. Обходит дерево Document → bytes.
    
    Document
      └── Section[]
            └── Paragraph[] | Table[]
                  └── Run[] | EmbeddedObject[]
    """
    def render(self, document: Document) -> bytes:
        result = bytearray()
        result.extend(self._render_init(document.printer_settings))
        for section in document.sections:
            result.extend(self._render_section(section))
        result.extend(self._render_finalize())
        return bytes(result)

# paragraph_renderer.py
class ParagraphRenderer:
    def render(self, paragraph: Paragraph, page_settings: PageSettings) -> bytes: ...

# run_renderer.py
class RunRenderer:
    def render(self, run: Run) -> bytes:
        """Run → ESC/P formatting commands + text bytes."""

# table_renderer.py
class TableRenderer:
    """Таблица → ESC/P.
    
    Использует absolute positioning для колонок.
    Границы через символы box-drawing или графический режим.
    """

# barcode_renderer.py
class BarcodeRenderer:
    """Barcode → ESC/P (ESC ( B command)."""
```

### 5.7 security/

**Назначение:** Полная подсистема безопасности. Подробное описание — в [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md) v2.1.

#### security/crypto/ (v2.3)

- **46 алгоритмов** в 6 категориях: symmetric, signing, asymmetric, key_exchange, hashing, kdf
- **4 пресета** безопасности: Standard, Paranoid, PQC, Legacy
- Полная **PQC поддержка**: ML-KEM-768, ML-DSA-65, SPHINCS+-SHA256-128f
- **Hybrid encryption**: классический + PQC для transition period
- **Hardware crypto**: PIV smart cards, OpenPGP cards
- Version headers и crypto agility

#### security/auth/

- **Password**: Argon2id hashing, configurable policy
- **Session management**: access/refresh tokens, IP binding, configurable TTL
- **MFA**: Password + обязательный второй фактор
  - **FIDO2**: CTAP2 direct attestation (air-gap compatible)
  - **TOTP**: RFC 6238 (Google Authenticator compatible)
  - **Backup Codes**: одноразовые коды восстановления

#### security/blanks/

- **BlankManager**: lifecycle управление бланками (create → sign → issue → verify → revoke)
- **BlankSigner**: криптографическая подпись (Ed25519 / ML-DSA-65)
- **BlankVerifier**: offline верификация по QR-коду на бумажном бланке
- Привязка к `blank_id` + `document_index`

#### security/audit/

- **Append-only hash chain**: каждая запись содержит hash предыдущей
- **HMAC** для защиты от подмены
- Типы событий: AUTH, DOCUMENT, BLANK, CRYPTO, CONFIG, SYSTEM
- Верификация целостности цепочки

#### security/compliance/

- **GDPR**: правила обработки персональных данных
- **Retention**: политики хранения и автоудаления
- **Anonymization**: обезличивание PII

### 5.8 printer/

**Назначение:** Transport layer — отправка ESC/P байтов на физический принтер.

```python
# base_adapter.py
class PrinterProtocol(Protocol):
    """Абстрактный интерфейс принтера."""
    def send(self, data: bytes) -> None: ...
    def is_available(self) -> bool: ...
    def get_status(self) -> PrinterStatus: ...
    def reset(self) -> None: ...

# win_adapter.py
class WinAdapter:
    """Windows: Win32 WritePrinter API.
    
    Открывает raw-доступ к принтеру через:
    OpenPrinter → StartDocPrinter → StartPagePrinter → WritePrinter
    """

# cups_adapter.py
class CupsAdapter:
    """Linux: CUPS (lp/lpr) с raw filter.
    
    Использует subprocess для отправки через:
    lp -d <printer> -o raw <file>
    """

# file_adapter.py
class FileAdapter:
    """Debug: запись ESC/P байтов в .escp файл.
    
    Для тестирования и анализа ESC/P потока.
    """
```

### 5.9 app_context.py

**Назначение:** Composition root — единственное место, где создаются и связываются все зависимости.

```python
class AppContext:
    """DI контейнер. Singleton.
    
    Создаёт все сервисы с правильными зависимостями:
    
    crypto_service = CryptoService(config=crypto_config)
    audit_service = AuditService(log_path=..., crypto=crypto_service)
    auth_service = AuthService(password=password_service, session=session_manager, ...)
    blank_manager = BlankManager(crypto=crypto_service, audit=audit_service)
    document_service = DocumentService(crypto=crypto_service, audit=audit_service)
    print_service = PrintService(renderer=document_renderer, printer=printer_adapter)
    """
    
    @classmethod
    def initialize(cls, config_path: Path) -> AppContext: ...
    
    @property
    def crypto(self) -> CryptoService: ...
    @property
    def auth(self) -> AuthService: ...
    @property
    def documents(self) -> DocumentService: ...
    @property
    def printing(self) -> PrintService: ...
    @property
    def blanks(self) -> BlankManager: ...
    @property
    def audit(self) -> AuditService: ...
```

---

## 6. Document Indexing System

### Общая концепция

Каждый документ в системе получает уникальный **составной индекс** — структурированный идентификатор, описывающий тип, подтип, серию и порядковый номер документа.

### Формат индекса

```
DVN-44-K53-IX
 │   │   │   │
 │   │   │   └── SEQUENCE:  IX (9 — римские цифры, порядковый номер)
 │   │   └────── SERIES:    K53 (серия)
 │   └────────── SUBTYPE:   44 (подтип вербальной ноты)
 └────────────── ROOT_CODE: DVN (вербальная нота)
```

### SegmentType

| SegmentType | Описание | Пример | Валидация |
|---|---|---|---|
| `ROOT_CODE` | Код типа документа | `DVN`, `INV`, `DOC` | `[A-Z]{2,5}` |
| `SUBTYPE` | Код подтипа | `44`, `01` | `\d{1,4}` |
| `SERIES` | Серия документа | `K53`, `A01` | `[A-Z]\d{1,3}` |
| `CUSTOM` | Произвольный сегмент | любой | задаётся в `IndexSegmentDef.pattern` |
| `SEQUENCE` | Порядковый номер | `I`, `IX`, `XLII` | Римские цифры |

### Правила

1. **Произвольная глубина** — количество сегментов не ограничено
2. **Последний сегмент всегда `SEQUENCE`** — порядковый номер в римских цифрах
3. Каждый сегмент валидируется по `pattern` из `IndexSegmentDef`
4. Опциональные `allowed_values` ограничивают допустимые значения
5. Разделитель по умолчанию: `-` (configurable)

### Примеры индексов разных типов

```python
# Вербальная нота
IndexTemplate(segments=(
    IndexSegmentDef(SegmentType.ROOT_CODE,  r"DVN",        description="Тип: вербальная нота"),
    IndexSegmentDef(SegmentType.SUBTYPE,    r"\d{1,2}",    description="Подтип"),
    IndexSegmentDef(SegmentType.SERIES,     r"[A-Z]\d{2}", description="Серия"),
    IndexSegmentDef(SegmentType.SEQUENCE,   r"[IVXLCDM]+", description="Порядковый номер"),
))
# Результат: DVN-44-K53-IX

# Счёт (простой)
IndexTemplate(segments=(
    IndexSegmentDef(SegmentType.ROOT_CODE,  r"INV",        description="Тип: счёт"),
    IndexSegmentDef(SegmentType.SEQUENCE,   r"[IVXLCDM]+", description="Порядковый номер"),
))
# Результат: INV-XLII

# Базовый документ (с серией)
IndexTemplate(segments=(
    IndexSegmentDef(SegmentType.ROOT_CODE,  r"DOC",        description="Тип: документ"),
    IndexSegmentDef(SegmentType.SERIES,     r"[A-Z]{2}",   description="Серия"),
    IndexSegmentDef(SegmentType.SEQUENCE,   r"[IVXLCDM]+", description="Порядковый номер"),
))
# Результат: DOC-AB-XIV
```

### Связь с Protected Blanks

Каждый Protected Blank связан с документом через:

- `blank_id` — уникальный UUID бланка (внутренний идентификатор)
- `document_index` — полный составной индекс (`DVN-44-K53-IX`)
- Подпись покрывает оба идентификатора

При верификации QR-код содержит `blank_id` + `document_index` + signature, что позволяет:
1. Проверить подлинность бланка
2. Идентифицировать документ
3. Верифицировать offline без доступа к БД

### Связь с TypeRegistry

```
TypeRegistry
    └── DocumentType("DVN", ...)
            ├── index_template: IndexTemplate(...)
            ├── field_schema: TypeSchema(...)
            └── subtypes: (DocumentSubtype("44", "Обычная"), ...)
```

`TypeRegistry.get("DVN").index_template` определяет формат индекса для всех вербальных нот.

### Утилиты: index_formatter.py

```python
def format_index(segments: list[str], separator: str = "-") -> str:
    """Собирает полный индекс из сегментов."""
    # ["DVN", "44", "K53", "IX"] → "DVN-44-K53-IX"

def parse_index(index: str, template: IndexTemplate) -> list[str]:
    """Разбирает индекс на сегменты с валидацией."""
    # "DVN-44-K53-IX" → ["DVN", "44", "K53", "IX"]

def int_to_roman(num: int) -> str:
    """Преобразует целое число в римские цифры."""
    # 9 → "IX", 42 → "XLII"

def roman_to_int(roman: str) -> int:
    """Преобразует римские цифры в целое число."""
    # "IX" → 9, "XLII" → 42
```

---

## 7. File Formats & Extensions

Все расширения файлов в FX Text Processor 3 начинаются с `.fxs` (FX Super) для единообразия.

### Documents

| Расширение | Название | Описание | Формат |
|---|---|---|---|
| `.fxsd` | FX Super Document | Незашифрованный документ | JSON |
| `.fxsd.enc` | FX Super Document Encrypted | Зашифрованный документ | Version Header + AES-256-GCM payload |
| `.fxstpl` | FX Super Template | Шаблон формы/документа | JSON |

### Security

| Расширение | Название | Описание | Формат |
|---|---|---|---|
| `.fxsblank` | FX Super Blank | Защищённый бланк (всегда зашифрован) | Encrypted binary |
| `.fxskeystore.enc` | FX Super Keystore | Хранилище ключей | Encrypted binary |
| `.fxssig` | FX Super Signature | Отделённая цифровая подпись | Binary (Ed25519/ML-DSA-65) |

### System

| Расширение | Название | Описание | Формат |
|---|---|---|---|
| `.fxsconfig` | FX Super Config | Конфигурация (подписана master key) | JSON + detached sig |
| `.fxsbackup` | FX Super Backup | Резервная копия | Encrypted archive |
| `.fxsbundle.enc` | FX Super Bundle | Экспортный пакет (документ + ключи + мета) | Encrypted archive |
| `.fxsreg` | FX Super Registry | Device registry (подписан) | JSON + detached sig |

### Printer

| Расширение | Название | Описание | Формат |
|---|---|---|---|
| `.escp` | ESC/P Raw Commands | Сырые ESC/P байты для принтера | Binary |
| `.escps` | ESC/P Script | Скрипт автоматизации печати | Text (custom DSL) |

### Forms (export/import)

| Расширение | Название | Описание | Формат |
|---|---|---|---|
| `.fxsf` | FX Super Form | Открытый формат формы | JSON |
| `.fxsfs` | FX Super Form Secure | Зашифрованная форма | Encrypted JSON |

### JSON Schema

| Расширение | Название | Описание | Формат |
|---|---|---|---|
| `.fxsschema` | FX Super Schema | JSON Schema для валидации документов | JSON Schema Draft 2020-12 |

### Структура файла .fxsd

```json
{
  "format_version": "1.0",
  "generator": "FXTextProcessor/3.0",
  "metadata": {
    "title": "Вербальная нота №IX",
    "document_type": "DVN",
    "document_index": "DVN-44-K53-IX",
    "created_at": "2026-03-12T00:00:00Z",
    "modified_at": "2026-03-12T00:00:00Z",
    "author": "operator",
    "version": 1
  },
  "page_settings": { ... },
  "printer_settings": { ... },
  "sections": [ ... ]
}
```

### Структура файла .fxsd.enc

```
┌────────────────────────────────────────┐
│ Magic bytes: "FXSD" (4 bytes)          │
│ Format version: uint16 (2 bytes)       │
│ Algorithm ID: uint16 (2 bytes)         │
│ Salt: 32 bytes                         │
│ Nonce/IV: 12-16 bytes                  │
│ Encrypted payload length: uint64       │
├────────────────────────────────────────┤
│ Encrypted payload (gzip + JSON)        │
├────────────────────────────────────────┤
│ Authentication tag: 16 bytes (GCM)     │
└────────────────────────────────────────┘
```

---

## 8. Floppy Disk Optimization

### Мотивация

Для air-gap среды обмен данными часто происходит через **3.5" дискеты** (1.44 MB). Система оптимизирована для минимизации размера файлов при сохранении полной безопасности.

### Ограничения

```python
# crypto/utilities/floppy_optimizer.py
MAX_FLOPPY_BYTES: Final[int] = 1_340_000    # ~1.28 MB (с запасом на FAT)
MAX_IMAGE_EMBED: Final[int] = 100_000        # 100 KB max для embedded base64 image
COMPRESSION_LEVEL: Final[int] = 9            # max gzip compression
```

### Стратегия оптимизации

1. **Предпочтение компактных алгоритмов:**

   | Операция | Floppy-Friendly | Размер | Full-Size | Размер |
   |---|---|---|---|---|
   | Подпись | Ed25519 | 64 B | ML-DSA-65 | ~3.3 KB |
   | Шифрование | AES-256-GCM | +28 B overhead | Hybrid (ML-KEM + AES) | ~1.5 KB overhead |
   | Хеширование | BLAKE2b | 32 B | SHA3-512 | 64 B |
   | KDF | Argon2id (reduced) | — | Argon2id (full) | — |

2. **FloppyFriendly рейтинг:**

   Каждый алгоритм в `AlgorithmMetadata` имеет поле `floppy_friendly: bool`:

   ```python
   @dataclass(frozen=True)
   class AlgorithmMetadata:
       algorithm_id: AlgorithmId
       name: str
       category: AlgorithmCategory
       key_size: int
       output_size: int
       floppy_friendly: bool        # True = подходит для дискет
       security_level: int          # bits of security
   ```

3. **Сжатие:**

   ```python
   # Порядок операций при сохранении на дискету:
   # 1. Document → JSON (serialize)
   # 2. JSON → gzip level 9 (compress)
   # 3. gzip → AES-256-GCM (encrypt)
   # 4. Encrypted → .fxsd.enc (write)
   ```

4. **Ограничение изображений:**

   ```python
   def validate_for_floppy(document: Document) -> list[str]:
       """Проверяет, помещается ли документ на дискету.
       
       Returns: список предупреждений (пустой = OK)
       """
       warnings = []
       for embedded in document.get_all_embedded():
           if len(embedded.data_base64) > MAX_IMAGE_EMBED:
               warnings.append(f"Image {embedded.name}: {len(embedded.data_base64)} > {MAX_IMAGE_EMBED}")
       return warnings
   ```

5. **floppy_optimizer.py:**

   ```python
   class FloppyOptimizer:
       """Автоматический выбор оптимальных параметров для дискеты."""
       
       def optimize_crypto_profile(self, profile: SecurityProfile) -> SecurityProfile:
           """Заменяет алгоритмы на floppy-friendly аналоги."""
       
       def estimate_size(self, document: Document) -> int:
           """Оценивает размер файла после сжатия и шифрования."""
       
       def fits_on_floppy(self, document: Document) -> bool:
           """Проверяет, помещается ли документ на дискету."""
   ```

---

## 9. Cloud Synchronization

### Архитектура: Portable Application

FX Text Processor 3 — **portable application**. Вся рабочая директория целиком синхронизируется через облачное хранилище (Dropbox, Google Drive, OneDrive) без специальной интеграции.

### Структура директории

```
CloudStorage/FXTextProcessor/
├── data/
│   ├── documents/           # .fxsd, .fxsd.enc файлы
│   ├── templates/           # .fxstpl шаблоны
│   ├── private/             # Личные документы пользователя
│   └── secure/              # .fxsblank, .fxssig файлы
│
├── backups/
│   ├── daily/               # Ежедневные автоматические бэкапы
│   └── manual/              # Ручные бэкапы (.fxsbackup)
│
├── config/
│   ├── app.fxsconfig        # Конфигурация приложения (подписана)
│   ├── types.fxsreg         # Пользовательские типы документов
│   └── devices.fxsreg       # Реестр устройств (smart cards, FIDO2)
│
└── escp/
    ├── scripts/             # .escps скрипты автоматизации
    └── output/              # .escp отладочные файлы
```

### Разделение: облако vs. локальные файлы

**В облаке (синхронизируются):**
- Все документы, шаблоны, бланки (зашифрованы)
- Конфигурация (подписана)
- Бэкапы
- ESC/P скрипты

**Только локально (НЕ синхронизируются):**

```
~/.fxtextprocessor/
├── salt.bin                 # Соль для KDF (уникальна на каждой машине)
├── pepper.bin               # Pepper для дополнительной защиты
├── session.db               # Текущая сессия (access/refresh tokens)
└── hardware.cache           # Кеш аппаратных устройств
```

### Модель безопасности

```
                    ┌─────────────────────────────┐
                    │       Encrypted Files        │
                    │    (.fxsd.enc, .fxsblank)    │
                    │                               │
                    │   Могут быть в облаке —       │
                    │   без ключей = мусор          │
                    └──────────────┬────────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         │                         │                         │
         ▼                         ▼                         ▼
┌─────────────────┐   ┌───────────────────────┐   ┌─────────────────┐
│  Master Password │   │  salt.bin (local)      │   │  pepper.bin     │
│  (в голове)      │   │  (~/.fxtextprocessor/) │   │  (local)        │
└─────────────────┘   └───────────────────────┘   └─────────────────┘
         │                         │                         │
         └─────────────────────────┼─────────────────────────┘
                                   │
                                   ▼
                         ┌──────────────────┐
                         │   Derived Key     │
                         │   (Argon2id)      │
                         └──────────────────┘
```

**Без мастер-пароля + локальных файлов (`salt.bin`, `pepper.bin`) расшифровка невозможна.**

Это означает:
- Компрометация облака не даёт доступа к данным
- Компрометация локальной машины без пароля не даёт доступа к данным
- Только комбинация всех трёх факторов позволяет расшифровку

---

## 10. Technology Stack

### Core

| Компонент | Технология | Версия |
|---|---|---|
| Язык | Python | 3.11+ (3.13 compatible) |
| GUI | Tkinter | Стандартная библиотека |
| Архитектура | MVC + Service Layer | — |
| DI | Constructor injection + Protocol | — |

### Криптография

| Компонент | Библиотека | Назначение |
|---|---|---|
| Основная крипто | `cryptography` (PyCA) | AES, Ed25519, ECDSA, RSA, X25519, HKDF |
| PQC | `liboqs-python` (≥0.15) | ML-KEM-768, ML-DSA-65, SPHINCS+ |
| KDF | `argon2-cffi` | Argon2id password hashing |

### Аппаратная безопасность

| Компонент | Библиотека | Назначение |
|---|---|---|
| FIDO2 | `python-fido2` | CTAP2 direct attestation |
| Smart Cards | `pyscard` (≥2.0) | PIV, OpenPGP card access |
| YubiKey | `yubikey-manager` (≥5.0) | YubiKey management |

### Тестирование и качество

| Инструмент | Назначение | Конфигурация |
|---|---|---|
| `pytest` | Тестовый фреймворк | — |
| `pytest-cov` | Покрытие кода | Цель: 90%+ |
| `mypy` | Статический анализ типов | `--strict` |
| `Black` | Форматирование кода | 88 символов |
| `isort` | Сортировка импортов | Compatible with Black |
| `Bandit` | Security linting | — |
| `Safety` | Проверка уязвимостей в зависимостях | — |

### Дополнительные зависимости

| Библиотека | Назначение |
|---|---|
| `openpyxl` | Чтение Excel файлов (.xlsx) |
| `qrcode` | Генерация QR-кодов |
| `Pillow` | Обработка изображений для QR и graphics |
| `hypothesis` | Property-based testing |

---

## 11. Module Status

Текущее состояние разработки по модулям (March 2026):

| Модуль | Статус | Покрытие | Тесты | Примечание |
|---|---|---|---|---|
| `model/` | ✅ 86% | ~92% | 310+ | Основные dataclasses готовы |
| `escp/commands/` | ✅ 100% | >95% | 420+ | Все ESC/P команды FX-890 |
| `security/crypto/` | ✅ 100% | ~95% | 180+ | v2.3, 46 алгоритмов |
| `security/auth/` | 🚧 77% | ~90% | 150+ | Не завершён FIDO2 flow |
| `security/audit/` | ✅ Complete | — | — | Hash chain + HMAC |
| `security/blanks/` | ✅ Complete | — | — | Lifecycle + signing + verify |
| `security/compliance/` | ✅ Complete | — | — | GDPR, retention |
| `security/hardware/` | 🚧 Extended | — | — | PIV done, OpenPGP in progress |
| `security/integrity/` | 🚧 In Progress | — | — | App hash check |
| `security/lock/` | 📋 TODO | — | — | Session lock, auto-lock |
| `security/erasure.py` | 📋 TODO | — | — | Secure wipe |
| `security/monitoring/` | 📋 TODO | — | — | Health checks |
| `documents/types/` | 📋 TODO | — | — | Рефакторинг из form/ |
| `documents/constructor/` | 📋 TODO | — | — | Рефакторинг из form/ |
| `documents/format/` | 📋 TODO | — | — | Сериализация |
| `documents/printing/` | 📋 TODO | — | — | ESC/P render pipeline |
| `printer/` | 📋 TODO | — | — | Stubs only |
| GUI (View) | ❌ 0% | — | — | Не начато |
| Controllers | ❌ 0% | — | — | Не начато |
| `backup/` | 📋 TODO | — | — | Key ceremony, Shamir SSS |
| `network/` | 📋 TODO | — | — | LAN verifier (opt-in) |
| `stealth/` | 📋 TODO | — | — | Steganography (future) |

### Условные обозначения

| Символ | Значение |
|---|---|
| ✅ | Завершён или почти завершён |
| 🚧 | В активной разработке |
| 📋 | Запланировано, не начато |
| ❌ | Не начато, нет плана |


---

## 12. Related Documents

| Документ | Описание |
|---|---|
| [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md) | Детальная архитектура безопасности (v2.1) — криптография, аутентификация, Protected Blanks |
| [SECURITY_SETUP.md](SECURITY_SETUP.md) | Инструкция по настройке безопасности — первоначальная конфигурация, key ceremony |
| [API_REFERENCE.md](API_REFERENCE.md) | Справочник API всех публичных модулей |
| [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) | Контекст проекта — цели, ограничения, решения |

---

> **FX Text Processor 3** — Architecture Document v3.0  
> Last updated: March 2026
