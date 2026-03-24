# FX Text Processor 3 — Architecture Document

> **Version:** 3.1
> **Date:** March 2026 (updated 2026-03-18)
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
   - 5.1 [model/](#51-model)
   - 5.2 [escp/commands/](#52-escp-commands)
   - 5.3 [documents/types/](#53-documentstypes)
   - 5.4 [documents/constructor/](#54-documentsconstructor)
   - 5.5 [documents/format/](#55-documentsformat)
   - 5.6 [documents/printing/](#56-documentsprinting)
   - 5.7 [services/ — Editing Services](#57-services--editing-services)
   - 5.8 [view/ — UI Layer](#58-view--ui-layer)
   - 5.9 [controller/ — Controllers](#59-controller--controllers)
   - 5.10 [security/](#510-security)
   - 5.11 [printer/](#511-printer)
   - 5.12 [app_context.py](#512-app_contextpy)
6. [Document Indexing System](#6-document-indexing-system)
7. [File Formats & Extensions](#7-file-formats--extensions)
8. [Floppy Disk Optimization](#8-floppy-disk-optimization)
9. [Cloud Synchronization](#9-cloud-synchronization)
10. [Technology Stack](#10-technology-stack)
11. [Приоритеты разработки (Q2 2026)](#11-приоритеты-разработки-q2-2026)
12. [Module Status](#12-module-status)
13. [Related Documents](#13-related-documents)

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

Приложение поддерживает **два режима работы** с документами:

#### 1. Текстовые документы (Word-like)
Свободное редактирование текста с полным форматированием, как в Microsoft Word.

| Возможность | Описание |
|---|---|
| **WYSIWYG-редактирование** | Визуальное редактирование с предпросмотром результата печати |
| **Свободный текст** | Набор и редактирование текста без ограничений формы |
| **Колонтитулы** | Верхние и нижние колонтитулы с автоматической нумерацией страниц |
| **Таблицы** | Вставка и редактирование таблиц с границами и выравниванием |
| **Форматирование** | Жирный, курсив, подчёркивание, шрифты, размеры, цвета |
| **Печать через ESC/P** | Прямой вывод на Epson FX-890 через нативный протокол |

#### 2. Формы (Protected Blanks)
Структурированные документы с полями, валидацией и криптографической защитой.

| Возможность | Описание |
|---|---|
| **Protected Blanks** | Система защищённых бланков с криптографической подписью и верификацией |
| **Схемы полей** | Определение структуры документа через TypeSchema с валидацией |
| **Иерархическая типизация** | Система типов (DVN, INV) с индексацией и наследованием |
| **Импорт из Excel** | Маппинг данных из Excel-диапазонов в поля форм |
| **Криптографическая подпись** | Подпись документов (Ed25519, ML-DSA-65, ECDSA), включая PQC |

#### Общие возможности

| Возможность | Описание |
|---|---|
| **MFA-аутентификация** | Password + FIDO2 / TOTP / Backup Codes |
| **Audit Trail** | Неизменяемый журнал операций (hash chain + HMAC) |
| **Единый формат** | Оба режима используют один класс `Document` и формат `.fxsd` |

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
├── documents/               # Document processing & rendering (⚠️ рефакторинг из form/ в процессе)
│   ├── types/               # Document type hierarchy
│   │   ├── registry.py           # TypeRegistry (singleton, thread-safe)
│   │   ├── document_type.py      # DocumentType, DocumentSubtype
│   │   ├── index_template.py     # IndexTemplate, IndexSegmentDef, SegmentType
│   │   ├── index_formatter.py    # format/parse индексов, int_to_roman
│   │   ├── type_schema.py        # TypeSchema, FieldDefinition, FieldType
│   │   ├── inheritance.py        # Наследование полей между типами
│   │   └── builtin/              # Встроенные типы документов
│   │       ├── base.py           # DOC — базовый документ (FREE_FORM, свободный текст)
│   │       ├── invoice.py        # INV — счёт (STRUCTURED_FORM, форма)
│   │       └── verbal_note.py    # DVN — вербальная нота (STRUCTURED_FORM, форма)
│   │
│   ├── constructor/         # Form/document construction
│   │   ├── form_constructor.py   # Создание документа из шаблона
│   │   ├── field_builder.py      # Конструктор полей (drag-and-drop)
│   │   ├── field_palette.py      # Палитра элементов для визуального редактора
│   │   ├── variable_parser.py    # Подстановка переменных, ESC/P переменные
│   │   ├── excel_import.py       # ExcelImporter + ExcelFieldMapping
│   │   ├── style_manager.py      # Стили элементов (наследование стилей)
│   │   ├── form_status.py        # Статусы формы (draft/pending/signed/archived)
│   │   ├── form_validator.py     # Валидация форм перед подписью
│   │   ├── formula_engine.py     # Вычисляемые поля (формулы)
│   │   ├── input_mask.py         # Маски ввода (дата, телефон, ИНН)
│   │   └── table_schema.py       # Схемы табличных полей
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
│   ├── auth/                # ✅ Authentication (98%)
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
│  User Input │────▶│  Controller  │────▶│ Service Layer │────▶│    Model    │
│  (Tkinter)  │     │  (validate)  │     │ (coordinate)  │     │ (dataclass) │
└─────────────┘     └──────────────┘     └───────────────┘     └──────┬──────┘
                                                                      │
                                                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          documents/printing/                                │
│                                                                             │
│  document_renderer.py                                                       │
│    ├── paragraph_renderer.py ──▶ run_renderer.py                            │
│    ├── table_renderer.py                                                    │
│    └── barcode_renderer.py                                                  │
│                                                                             │
│  Каждый renderer импортирует:                                               │
│    - model/* (для обхода дерева документа)                                  │
│    - escp/commands/* (для генерации ESC/P байтов)                           │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │ bytes
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            escp/commands/                                   │
│                                                                             │
│  Чистые функции:  build_bold(on=True) → b'\x1b\x45'                         │
│                   build_font(font_id) → b'\x1b\x6b\x00'                     │
│                   build_position(col) → b'\x1b\x24\x00\x01'                 │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │ bytes
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                             printer/                                        │
│                                                                             │
│  PrinterProtocol.send(data: bytes) → None                                   │
│    ├── WinAdapter    → Win32 WritePrinter API                               │
│    ├── CupsAdapter   → CUPS lp/lpr                                          │
│    └── FileAdapter   → debug file output                                    │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │ raw bytes
                                   ▼
                          ┌─────────────────┐
                          │ Physical Printer│
                          │   Epson FX-890  │
                          └─────────────────┘
```

### 4.2 Protected Blanks pipeline

```
┌───────────────┐     ┌───────────────────┐     ┌────────────────────┐
│ TypeRegistry  │────▶│  form_constructor │────▶│     Document       │
│ (тип + схема) │     │  (шаблон → doc)   │     │  (заполненный)     │
└───────────────┘     └───────────────────┘     └────────┬───────────┘
                                                          │
                                                          ▼
                                              ┌───────────────────────┐
                                              │  blanks/blank_manager │
                                              │  (sign, assign index) │
                                              │  blank_id + full_index│
                                              └────────┬──────────────┘
                                                       │
                                          ┌────────────┴────────────┐
                                          ▼                         ▼
                                ┌──────────────────┐    ┌──────────────────┐
                                │ .fxsblank file   │    │  printing/       │
                                │(encrypted store) │    │  (ESC/P render)  │
                                └──────────────────┘    └────────┬─────────┘
                                                                  │
                                                                  ▼
                                                        ┌──────────────────┐
                                                        │  Physical Paper  │
                                                        │  (with QR code)  │
                                                        └────────┬─────────┘
                                                                  │
                                                                  ▼ scan QR
                                                        ┌──────────────────┐
                                                        │ blanks/verifier  │
                                                        │ (offline verify) │
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

> **Статус:** ⚠️ В активном рефакторинге из `src/form/`. Текущая реализация в `src/form/` устарела и будет заменена.

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

**DocumentMode:**

```python
class DocumentMode(Enum):
    """Режим работы с документом.

    FREE_FORM — свободное редактирование текста (Word-like)
    STRUCTURED_FORM — структурированные документы с полями (формы)
    """
    FREE_FORM = "free_form"           # Текстовые документы
    STRUCTURED_FORM = "structured_form"  # Формы с полями и валидацией
```

**DocumentType:**

```python
@dataclass(frozen=True)
class DocumentType:
    code: str                          # "DVN", "INV", "DOC"
    name: str                          # "Вербальная нота"
    parent_code: str | None            # None для корневых типов
    document_mode: DocumentMode      # Режим: free_form или structured_form
    index_template: IndexTemplate | None  # None для текстовых документов
    field_schema: TypeSchema           # Схема полей (пустая для текстовых)
    subtypes: tuple[DocumentSubtype, ...] = ()
```

**Различие режимов:**

| Аспект | FREE_FORM (текст) | STRUCTURED_FORM (формы) |
|--------|-------------------|------------------------|
| `index_template` | `None` или опциональный | Обязательный (DVN-44-K53-IX) |
| `field_schema` | `TypeSchema(fields=())` — пустая | Полная схема с `FieldDefinition` |
| Редактор | Свободное форматирование | Поля с валидацией по схеме |
| Печать | Прямой рендеринг | Через `FormConstructor` |
| Подпись | Опциональная | Обязательная (Protected Blanks) |
| Использование | Письма, отчёты, документы | Бланки, счета, ноты |

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

**Примеры TypeSchema:**

```python
# FREE_FORM — текстовый документ (DOC)
# Пустая схема: нет предопределённых полей, документ строится свободно
free_form_schema = TypeSchema(
    fields=(),  # Пустой tuple — нет обязательных полей формы
    version="1.0"
)

# STRUCTURED_FORM — форма счёта (INV)
# Полная схема с валидацией всех полей
structured_schema = TypeSchema(
    fields=(
        FieldDefinition(
            field_id="invoice_number",
            field_type=FieldType.TEXT_INPUT,
            label="Номер счёта",
            required=True,
            validation_pattern=r"^INV-[IVXLCDM]+$"
        ),
        FieldDefinition(
            field_id="client_name",
            field_type=FieldType.TEXT_INPUT,
            label="Клиент",
            required=True,
            max_length=100
        ),
        FieldDefinition(
            field_id="amount",
            field_type=FieldType.NUMBER_INPUT,
            label="Сумма",
            required=True,
            min_value=0.01
        ),
        FieldDefinition(
            field_id="items_table",
            field_type=FieldType.TABLE,
            label="Товары/услуги",
            required=True
        ),
    ),
    version="1.0"
)
```

#### Extended Field Types

Расширенный набор типов полей для комплексных форм:

| Тип | Описание | Параметры |
|-----|----------|-----------|
| `CHECKBOX` | Булев флажок | `default_value: bool` |
| `DROPDOWN` | Выпадающий список | `options: tuple[str, ...]`, `allow_custom: bool` |
| `RADIO_GROUP` | Группа радиокнопок | `options: tuple[str, ...]`, `layout: horizontal\|vertical` |
| `CURRENCY` | Денежная сумма | `currency_code: str`, `decimal_places: int` |
| `MULTI_LINE_TEXT` | Многострочный текст | `rows: int`, `max_rows: int`, `wrap: bool` |
| `PHONE` | Телефон | `region: str`, `mask: str` |
| `EMAIL` | Email | `verify_domain: bool` |

#### Validation Rules

`FieldDefinition` поддерживает расширенные правила валидации:

```python
@dataclass(frozen=True)
class FieldDefinition:
    field_id: str
    field_type: FieldType
    label: str
    label_i18n: dict[str, str] = field(default_factory=dict)
    required: bool = False
    default_value: str | None = None
    validation_pattern: str | None = None
    max_length: int | None = None
    options: tuple[str, ...] | None = None
    escp_variable: str | None = None

    # Расширенные правила валидации
    min_value: float | None = None           # Минимальное числовое значение
    max_value: float | None = None           # Максимальное числовое значение
    min_date: date | None = None             # Минимальная дата
    max_date: date | None = None             # Максимальная дата
    required_if: str | None = None           # Условная обязательность ("fieldA == 'value'")
    cross_field_rules: tuple[str, ...] = () # Кросс-полевая валидация
```

Сервис `FormValidator` выполняет валидацию формы целиком перед подписью:

```python
class FormValidator:
    def validate(self, document: Document, schema: TypeSchema) -> ValidationResult:
        """Валидирует все поля документа по схеме."""
        ...

@dataclass(frozen=True)
class ValidationResult:
    is_valid: bool
    field_errors: dict[str, list[str]]  # field_id → список ошибок
    cross_field_errors: list[str]
```

#### Table Schema

`FieldType.TABLE` требует `TableSchema` для определения структуры таблицы:

```python
@dataclass(frozen=True)
class TableSchema:
    columns: tuple[ColumnDefinition, ...]
    min_rows: int = 0
    max_rows: int | None = None
    auto_number: bool = False              # Авто-нумерация строк
    show_summary_row: bool = False         # Итоговая строка
    summary_functions: tuple[SummaryFunction, ...] = ()  # SUM, COUNT, AVG

@dataclass(frozen=True)
class ColumnDefinition:
    column_id: str
    header: str
    column_type: FieldType                # Тип данных колонки
    width_chars: int | None = None         # Ширина в символах
    editable: bool = True
    sortable: bool = True
    summary_function: SummaryFunction | None = None  # Итоговая функция

class SummaryFunction(Enum):
    SUM = "sum"
    COUNT = "count"
    AVG = "avg"
    MIN = "min"
    MAX = "max"
```

#### Formula Engine

`FieldType.CALCULATED` использует безопасный движок формул:

```python
class FormulaEngine:
    """Безопасный движок вычисляемых полей."""

    # Поддерживаемые синтаксисы:
    # - =FIELD("amount") * 1.2
    # - {amount} * 1.2
    # - SUM(table.column_a)

    def evaluate(self, formula: str, context: dict[str, Any]) -> Any:
        """Вычисляет формулу в контексте полей документа."""
        ...

    def get_dependencies(self, formula: str) -> set[str]:
        """Возвращает зависимости формулы (field_ids)."""
        ...
```

**Функции формул:**

| Функция | Описание | Пример |
|---------|----------|--------|
| `FIELD(id)` | Ссылка на поле | `FIELD("amount")` |
| `SUM(range)` | Сумма | `SUM(table.items.price)` |
| `COUNT(range)` | Количество | `COUNT(table.items)` |
| `IF(cond, true, false)` | Условие | `IF(FIELD("type")=="A", 100, 200)` |
| `TODAY()` | Текущая дата | `TODAY()` |
| `ROUND(val, digits)` | Округление | `ROUND(FIELD("total"), 2)` |

**Безопасность:** используется `ast.literal_eval` с белым списком допустимых узлов. Запрещены: импорты, вызовы функций вне белого списка, обращения к атрибутам за пределами контекста.

#### Form Lifecycle

Жизненный цикл формы управляется через `FormStatus`:

```python
class FormStatus(Enum):
    DRAFT = "draft"           # Черновик — редактирование разрешено
    FILLED = "filled"         # Заполнена — ожидает валидации
    VALIDATED = "validated" # Проверена — ожидает подписи
    SIGNED = "signed"         # Подписана — поля заблокированы
    PRINTED = "printed"       # Напечатана — физическая копия создана
    ARCHIVED = "archived"     # Архивирована
    REJECTED = "rejected"     # Отклонена
```

**Диаграмма состояний:**

```
DRAFT → FILLED → VALIDATED → SIGNED → PRINTED → ARCHIVED
  │       │           │
  └───────┴───────────┘
            ↓
        REJECTED
```

**Блокировка полей:**

```python
@dataclass(frozen=True)
class FieldLockConfig:
    locked_fields: tuple[str, ...]          # Список заблокированных field_ids
    locked_at_status: tuple[FormStatus, ...]  # Статусы при которых блокируется
    unlock_with_mfa: bool = True            # Требовать MFA для разблокировки
```

#### Conditional Visibility

`FieldDefinition` поддерживает условную видимость и доступность:

```python
@dataclass(frozen=True)
class FieldDefinition:
    # ... базовые поля ...

    # Условия отображения
    visibility_condition: str | None = None   # Показывать если: "subtype == '44'"
    read_only_condition: str | None = None    # Только чтение если: "status == 'SIGNED'"
    enabled_condition: str | None = None      # Активно если: "fieldA == 'value'"
```

Условия записываются на подмножестве Python с операторами: `==`, `!=`, `<`, `>`, `in`, `and`, `or`, `not`. Контекст — текущие значения всех полей формы.

#### Field Positioning

Для фиксированных бланков (Protected Blanks) поддерживается позиционирование:

```python
@dataclass(frozen=True)
class FieldPosition:
    x_column: int                # Позиция X в символах ESC/P
    y_row: int                   # Позиция Y в строках ESC/P
    width_chars: int | None      # Ширина в символах
    height_rows: int = 1         # Высота в строках
    overflow_behavior: OverflowBehavior = OverflowBehavior.TRUNCATE

class OverflowBehavior(Enum):
    TRUNCATE = "truncate"        # Обрезать лишнее
    WRAP = "wrap"                # Переносить на новую строку
    SHRINK_FONT = "shrink_font"  # Уменьшать шрифт (если возможно)
```

#### Field UX

Дополнительные UX-параметры полей:

```python
@dataclass(frozen=True)
class FieldDefinition:
    # ... базовые поля ...

    # UX параметры
    tab_index: int | None = None              # Порядок Tab-навигации
    input_mask: str | None = None             # Маска ввода (дата: "##.##.####")
    placeholder: str | None = None            # Подсказка в пустом поле
    autocomplete_source: str | None = None    # Источник автодополнения
    help_text: str | None = None              # Вспомогательный текст (tooltip)
    error_message_template: str | None = None # Шаблон сообщения об ошибке
```

**Маски ввода:**

| Тип | Маска | Пример |
|-----|-------|--------|
| Дата | `##.##.####` | `25.12.2026` |
| Телефон | `+7 (###) ###-##-##` | `+7 (495) 123-45-67` |
| ИНН | `############` | `7707083893` |
| Сумма | `# ###,##` | `1 234,56` |

#### InputMask

Модуль масок ввода для полей форм:

```python
@dataclass(frozen=True)
class InputMask:
    """Маска ввода с поддержкой динамического построения из IndexTemplate."""
    pattern: str                      # Маска: "##.##.####" для даты
    placeholder: str = "_"          # Символ placeholder

    def apply(self, raw: str) -> str:
        """Применяет маску к сырому вводу."""
        ...

    def strip(self, masked: str) -> str:
        """Удаляет маску, оставляет только значимые символы."""
        ...

    def is_complete(self, masked: str) -> bool:
        """Проверяет, заполнена ли маска полностью."""
        ...

    @staticmethod
    def build_from_template(index_template: IndexTemplate) -> "InputMask":
        """Строит маску для document_index из IndexTemplate.

        Пример: DVN-44-K53-IX → "AAA-##-A##-RR"
        """
        ...
```

**Типы символов масок:**

| Символ | Значение | Пример |
|--------|----------|--------|
| `#` | Цифра | `##.##.####` → дата |
| `A` | Буква (латиница) | `AAA` → DVN |
| `R` | Римская цифра | `RR` → IX |
| `L` | Любая буква | `LLLL` → текст |
| `N` | Буква или цифра | `NNN` → код |

#### FieldAnnotation

Комментарии к полям для Approval Workflow:

```python
@dataclass(frozen=True)
class FieldAnnotation:
    """Комментарий к полю в контексте workflow."""
    annotation_id: str
    field_id: str
    comment: str
    author_role: WorkflowRole      # OPERATOR, EDITOR, SUPERVISOR
    created_at: datetime
    resolved: bool = False

class WorkflowRole(Enum):
    """Роли внутри single-operator workflow (режимы работы)."""
    OPERATOR = "operator"       # Заполнение формы
    EDITOR = "editor"           # Редактирование/проверка
    SUPERVISOR = "supervisor"   # Согласование
    SIGNATORY = "signatory"     # Подписание
```

#### Schema Versioning

Версионирование схем типов документов:

```python
@dataclass(frozen=True)
class TypeSchema:
    fields: tuple[FieldDefinition, ...]
    version: str = "1.0"                      # Версия схемы
    compatibility_version: str = "1.0"        # Минимальная совместимая версия
    deprecated_fields: tuple[str, ...] = () # Устаревшие field_ids

class SchemaMigration:
    """Миграция данных при обновлении схемы."""

    def migrate(
        self,
        data: dict[str, Any],
        from_version: str,
        to_version: str
    ) -> dict[str, Any]:
        """Применяет цепочку миграций к данным формы."""
        ...
```

**Правила миграции:**
- Поля, удалённые в новой версии, сохраняются в `_deprecated_fields`
- Новые обязательные поля получают `default_value` или `null`
- Переименования описываются в `field_renames: dict[str, str]`
- Типы данных конвертируются через `type_converters: dict[str, Callable]`

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

> **Статус:** ⚠️ В активном рефакторинге из `src/form/`.

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

#### 5.4.1 Form Template Designer

Визуальный конструктор шаблонов форм с ESC/P Grid Canvas:

```python
class FormTemplateDesigner:
    """Визуальный дизайнер шаблонов форм."""

    def __init__(self, canvas: "TemplateDesignerCanvas"):
        self.canvas = canvas  # Tkinter Canvas с сеткой 80×66
        self.grid = ESCPGrid(cols=80, rows=66)  # Символьная сетка FX-890

    def add_field(self, field_def: FieldDefinition, position: FieldPosition):
        """Добавляет поле на канву с snap-to-grid."""
        ...

    def resize_field(self, field_id: str, new_width: int, new_height: int):
        """Изменяет размер поля с snap-to-grid."""
        ...

    def export_template(self) -> Template:
        """Экспортирует шаблон в .fxstpl."""
        ...
```

**ESC/P Grid Canvas:**
- Размер: 80 столбцов × 66 строк (стандарт Letter 10 CPI)
- Snap-to-grid: поля привязываются к символьным позициям
- Live preview: рендеринг ESC/P байтов в реальном времени
- Resize handles: изменение размера перетаскиванием

**Компоненты дизайнера:**

```python
class TemplateDesignerCanvas(Canvas):
    """Canvas с символьной сеткой для размещения полей."""
    def __init__(self, parent: Widget) -> None: ...
    def snap_to_grid(self, x: int, y: int) -> tuple[int, int]: ...
    def show_field_preview(self, field: FieldDefinition): ...

class FieldPalette(Frame):
    """Палитра доступных типов полей для drag-and-drop."""
    def __init__(self, parent: Widget) -> None: ...

class PropertyPanel(Frame):
    """Панель редактирования свойств выбранного поля."""
    def edit_field(self, field: FieldDefinition) -> None: ...
```

#### 5.4.2 Test Fill Mode

Режим тестового заполнения форм без записи в Audit Log:

```python
class TestFillMode:
    """Тестовое заполнение форм синтетическими данными."""

    def generate_synthetic_data(self, schema: TypeSchema) -> dict[str, str]:
        """Генерирует тестовые данные для всех полей схемы."""
        ...

    def export_escp_dump(self, document: Document, path: Path) -> None:
        """Экспортирует ESC/P дамп через FileAdapter для проверки."""
        ...

    def run_edge_case_tests(self, schema: TypeSchema) -> list[TestResult]:
        """Тесты граничных случаев: очень длинный текст, пустые поля, кириллица."""
        ...
```

**Edge case тесты:**
- Очень длинное значение в поле с `max_length`
- Пустые обязательные поля
- Кириллица в CP866 vs Latin
- Переполнение числовых полей
- Невалидные даты

#### 5.4.3 InputMask Module

Модуль масок ввода (рядом с `variable_parser.py`):

```python
class InputMask:
    """Форматирование ввода в реальном времени."""

    def __init__(self, pattern: str, placeholder: str = "_"): ...

    def apply(self, raw: str) -> str:
        """Применяет маску: "123" + "##.##.####" → "12.3_.____" """
        ...

    def strip(self, masked: str) -> str:
        """Удаляет маску: "12.3_.____" → "123" """
        ...

    def is_complete(self, masked: str) -> bool:
        """Проверяет полноту: "12.3_.____" → False """
        ...

    @staticmethod
    def for_document_index(template: IndexTemplate) -> "InputMask":
        """Строит маску из IndexTemplate."""
        ...
```

**Примеры масок:**
- Дата: `##.##.####` → `25.12.2026`
- Телефон: `+7 (###) ###-##-##` → `+7 (495) 123-45-67`
- Индекс: `AAA-##-A##-RR` → `DVN-44-K53-IX`

#### 5.4.4 FormValidator Service

Трёхуровневая валидация форм:

```python
class FormValidator:
    """Валидация форм: поле → форма → кросс-поля."""

    def validate_field(
        self,
        field_id: str,
        value: str,
        field_def: FieldDefinition
    ) -> list[ValidationResult]:
        """Уровень 1: валидация отдельного поля."""
        ...

    def validate_form(
        self,
        document: Document,
        schema: TypeSchema
    ) -> list[ValidationResult]:
        """Уровень 2: валидация всей формы."""
        ...

    def validate_cross_fields(
        self,
        document: Document,
        schema: TypeSchema
    ) -> list[ValidationResult]:
        """Уровень 3: кросс-полевая валидация."""
        ...

@dataclass(frozen=True)
class ValidationResult:
    field_id: str | None       # None = ошибка уровня формы
    severity: Severity         # ERROR | WARNING | INFO
    code: str                  # машиночитаемый код
    message: str               # человекочитаемое сообщение

class Severity(Enum):
    ERROR = "error"       # Блокирует подпись
    WARNING = "warning"   # Предупреждение
    INFO = "info"         # Информация
```

**validation_state в Document:**

```python
@dataclass
class Document:
    # ... существующие поля ...
    validation_state: dict[str, list[ValidationResult]] = field(default_factory=dict)
    validation_timestamp: datetime | None = None
```

#### 5.4.5 Multi-step Forms

Многошаговые формы через tabbed interface:

```python
class MultiStepForm:
    """Многошаговая форма с вкладками (не wizard)."""

    def __init__(self, steps: list[FormStep]):
        self.steps = steps
        self.current_step = 0

    def validate_step(self, step_index: int) -> list[ValidationResult]:
        """Валидация конкретного шага."""
        ...

    def can_proceed(self, step_index: int) -> bool:
        """Проверяет, можно ли перейти к следующему шагу."""
        ...

@dataclass(frozen=True)
class FormStep:
    """Один шаг многошаговой формы."""
    step_id: str
    label: str
    field_ids: tuple[str, ...]  # Поля, принадлежащие этому шагу
    validation_schema: TypeSchema | None = None
```

**Навигация:**
- Все шаги видны как вкладки (tabs)
- Незаполненные шаги помечаются
- Переход без валидации разрешён, подпись — нет

#### 5.4.6 Approval Workflow (Single Operator)

Workflow согласования для одного оператора с переключением режимов:

```python
class ApprovalWorkflow:
    """State machine для single-operator workflow."""

    def transition(
        self,
        document: Document,
        from_state: FormStatus,
        to_state: FormStatus,
        mfa: bool = True
    ) -> None:
        """Переход между состояниями с MFA."""
        ...

    def switch_role(self, role: WorkflowRole) -> None:
        """Переключение роли оператора (режима работы)."""
        ...

    def add_comment(
        self,
        field_id: str,
        comment: str,
        author_role: WorkflowRole
    ) -> FieldAnnotation:
        """Добавляет комментарий к полю."""
        ...
```

**Состояния и роли:**

```
DRAFT (OPERATOR) → FILLED (EDITOR) → VALIDATED (SUPERVISOR)
                                              ↓
                                      APPROVED (SIGNATORY)
                                              ↓
                                        SIGNED → PRINTED → ARCHIVED
```

**Комментарии к полям:**
- Хранятся в `FieldAnnotation`
- Не попадают в печать
- Логируются в Audit Trail
- Разрешаются (resolved) при исправлении

#### 5.4.7 FormHistory Store

История заполнения полей для автозаполнения:

```python
class FormHistory:
    """Локальная история заполнения полей."""

    def __init__(self, history_path: Path = Path("~/.fxtextprocessor/history/")):
        self.path = history_path
        self.cache: dict[str, list[HistoryEntry]] = {}

    def add_entry(self, field_id: str, value: str, doc_type: str) -> None:
        """Добавляет запись в историю."""
        ...

    def get_suggestions(
        self,
        field_id: str,
        limit: int = 5
    ) -> list[tuple[str, int]]:  # (value, frequency)
        """Частотно-ранжированные предложения."""
        ...

    def prefill_from_previous(
        self,
        doc_type: str,
        series: str
    ) -> dict[str, str]:
        """Копирует значения из последнего документа той же серии."""
        ...
```

**Хранение:**
- Директория: `~/.fxtextprocessor/history/` или `./data/history/`
- Файл: `.fxshistory.enc` (AES-256-GCM + HMAC)
- Retention: последние 1000 записей или 90 дней

#### 5.4.8 Template Library

Библиотека шаблонов с версионированием:

```python
class TemplateLibrary:
    """Управление библиотекой шаблонов .fxstpl."""

    def __init__(self, library_path: Path = Path("~/.fxtextprocessor/templates/")):
        self.path = library_path

    def import_template(
        self,
        source_path: Path,
        verify_signature: bool = True
    ) -> TemplateInfo:
        """Импортирует шаблон с флоппи/USB."""
        ...

    def export_template(self, template_id: str, target_path: Path) -> None:
        """Экспортирует шаблон на внешний носитель."""
        ...

    def list_templates(self) -> list[TemplateInfo]:
        """Список шаблонов с превью."""
        ...

    def get_preview(self, template_id: str) -> Image:
        """Генерирует превью шаблона."""
        ...

@dataclass(frozen=True)
class TemplateInfo:
    template_id: str
    name: str
    version: str
    doc_type: str
    created_at: datetime
    signature_valid: bool
    preview_thumbnail: bytes | None
```

**Хранение:**
- Директория: `~/.fxtextprocessor/templates/`
- Формат: `.fxstpl` (зашифрованный JSON)
- Подпись: master key
- Версионирование: template_version отдельно от document_version

#### 5.4.9 SchemaDocumentationGenerator

Генератор документации из TypeSchema:

```python
class SchemaDocumentationGenerator:
    """Автоматическая генерация документации схемы."""

    def to_plaintext(self, schema: TypeSchema) -> str:
        """Текстовое описание для печати на FX-890."""
        ...

    def to_fxsd(self, schema: TypeSchema) -> Document:
        """Создаёт документ-инструкцию по заполнению."""
        ...

    def diff(self, old: TypeSchema, new: TypeSchema) -> SchemaDiff:
        """Сравнивает две версии схемы."""
        ...

@dataclass(frozen=True)
class SchemaDiff:
    added_fields: list[str]
    removed_fields: list[str]
    modified_fields: list[tuple[str, str, str]]  # field_id, old, new
    compatibility_broken: bool
```

**Применение:**
- Инструкции для операторов
- Отчёты об изменениях в бланках
- Проверка совместимости версий

#### 5.4.10 Schema Linter

Линтер для проверки схем форм:

```python
class SchemaLinter:
    """Проверка схемы на конфликты и ошибки."""

    def check_conflicts(self, schema: TypeSchema) -> list[LintResult]:
        """Проверяет конфликты позиций полей (перекрытие)."""
        ...

    def check_coverage(self, schema: TypeSchema) -> list[LintResult]:
        """Проверяет покрытие всех полей рендерером."""
        ...

    def check_references(self, schema: TypeSchema) -> list[LintResult]:
        """Проверяет валидность ссылок между полями."""
        ...
```

**Триггеры:**
- При сохранении шаблона в Designer
- При импорте шаблона с внешнего носителя
- По явной команде "Validate Template"

### 5.5 documents/format/

**Назначение:** Сериализация, десериализация и миграция форматов документов.

> **Статус:** 📋 Запланировано — реализация в процессе рефакторинга.

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

> **Статус:** ⚠️ В процессе — приоритет Q2 2026.

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

### 5.7 services/ — Editing Services

**Назначение:** Сервисы для WYSIWYG-редактирования и управления документами.

> **Статус:** 📋 Запланировано — критично для GUI.

#### Command History Service (Undo/Redo)

```python
# src/services/command_history_service.py
@dataclass(frozen=True)
class Command:
    """Базовый класс команды для undo/redo."""
    command_id: str
    timestamp: datetime
    description: str

    def execute(self) -> None: ...
    def undo(self) -> None: ...
    def redo(self) -> None: ...

class CommandHistoryService:
    """Управление историей команд — undo/redo."""
    def __init__(self, max_history: int = 100) -> None: ...
    def execute(self, command: Command) -> None: ...
    def undo(self) -> bool: ...  # True если undo доступен
    def redo(self) -> bool: ...  # True если redo доступен
    def can_undo(self) -> bool: ...
    def can_redo(self) -> bool: ...
    def clear(self) -> None: ...
```

#### Find & Replace Service

```python
# src/services/find_replace_service.py
@dataclass(frozen=True)
class SearchResult:
    paragraph_index: int
    run_index: int
    start_offset: int
    end_offset: int
    matched_text: str

class FindReplaceService:
    """Поиск и замена текста в документе."""
    def __init__(self, document: Document) -> None: ...
    def find(self, pattern: str, options: SearchOptions) -> list[SearchResult]: ...
    def find_next(self, pattern: str, from_position: CursorPosition, options: SearchOptions) -> SearchResult | None: ...
    def replace(self, result: SearchResult, replacement: str) -> Command: ...  # Возвращает команду для undo
    def replace_all(self, pattern: str, replacement: str, options: SearchOptions) -> Command: ...
```

#### Auto-save Service

```python
# src/services/auto_save_service.py
class AutoSaveService:
    """Автосохранение и восстановление после сбоя."""
    def __init__(
        self,
        document_service: DocumentServiceProtocol,
        interval_seconds: int = 60,
        temp_dir: Path | None = None
    ) -> None: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def recover_if_needed(self) -> Document | None: ...  # Возвращает восстановленный документ или None
    def clear_temp(self) -> None: ...
```

**Формат:** `.fxsd.tmp` — временный файл с метаданными для recovery.

#### Document Statistics Service

```python
# src/services/document_stats_service.py
@dataclass(frozen=True)
class DocumentStats:
    character_count: int
    word_count: int
    line_count: int
    paragraph_count: int
    page_count_estimate: int  # На основе lines_per_page

class DocumentStatsService:
    """Статистика документа — счётчики символов, слов, строк."""
    def calculate(self, document: Document) -> DocumentStats: ...
    def calculate_selection(self, document: Document, selection: Selection) -> DocumentStats: ...
```

#### Clipboard Service

```python
# src/services/clipboard_service.py
class ClipboardService:
    """Интеграция с системным буфером обмена."""
    def copy(self, content: ClipboardContent) -> None: ...
    def cut(self, content: ClipboardContent) -> Command: ...  # Возвращает команду для undo
    def paste(self) -> ClipboardContent | None: ...
    def can_paste(self) -> bool: ...
```

#### Notification Service

```python
# src/services/notification_service.py
@dataclass(frozen=True)
class Notification:
    id: str
    message: str
    level: NotificationLevel  # INFO, WARNING, ERROR, SUCCESS
    duration_ms: int
    actions: list[NotificationAction]

class NotificationService:
    """Система уведомлений и статус-бар."""
    def __init__(self) -> None: ...
    def show(self, message: str, level: NotificationLevel = NotificationLevel.INFO, duration_ms: int = 5000) -> str: ...
    def show_progress(self, message: str, total: int) -> ProgressHandle: ...
    def dismiss(self, notification_id: str) -> None: ...
    def subscribe(self, callback: Callable[[Notification], None]) -> None: ...
```

#### Document Lock Service

```python
# src/services/document_lock_service.py
class DocumentLockService:
    """Блокировка документа от двойного открытия (portable mode)."""
    def __init__(self, lock_dir: Path) -> None: ...
    def acquire(self, document_path: Path) -> LockHandle | None: ...  # None если уже заблокирован
    def release(self, handle: LockHandle) -> None: ...
    def is_locked(self, document_path: Path) -> bool: ...
    def get_lock_info(self, document_path: Path) -> LockInfo | None: ...
```

**Формат:** `.fxsd.lock` — JSON с PID, timestamp, user.

#### Version History Service

```python
# src/services/version_history_service.py
@dataclass(frozen=True)
class VersionInfo:
    version: int
    timestamp: datetime
    author: str
    change_summary: str
    snapshot_path: Path | None  # None если diff-based

class VersionHistoryService:
    """История версий документа — diff между версиями."""
    def __init__(self, history_dir: Path) -> None: ...
    def save_version(self, document: Document, change_summary: str = "") -> VersionInfo: ...
    def get_versions(self, document_id: str) -> list[VersionInfo]: ...
    def get_version(self, document_id: str, version: int) -> Document: ...
    def compare(self, document_id: str, version_a: int, version_b: int) -> DocumentDiff: ...
    def revert_to(self, document_id: str, version: int) -> Command: ...
```

#### Document Manager Service (MDI)

```python
# src/services/document_manager_service.py
class DocumentManagerService:
    """Управление несколькими открытыми документами (MDI)."""
    def __init__(self) -> None: ...
    def open_document(self, path: Path) -> DocumentHandle: ...
    def create_document(self, doc_type: str | None = None) -> DocumentHandle: ...
    def close_document(self, handle: DocumentHandle) -> bool: ...  # False если есть несохранённые изменения
    def get_active(self) -> DocumentHandle | None: ...
    def set_active(self, handle: DocumentHandle) -> None: ...
    def list_open(self) -> list[DocumentHandle]: ...
    def has_unsaved_changes(self, handle: DocumentHandle) -> bool: ...
```

#### Export Service

```python
# src/services/export_service.py
class ExportService:
    """Экспорт документа в различные форматы."""
    def __init__(self) -> None: ...
    def export_txt(self, document: Document, path: Path) -> None: ...
    def export_md(self, document: Document, path: Path) -> None: ...
    def export_html(self, document: Document, path: Path) -> None: ...
```

#### Print Queue Service

```python
# src/services/print_queue_service.py
@dataclass(frozen=True)
class PrintJob:
    id: str
    document: Document
    priority: PrintPriority
    status: PrintJobStatus
    created_at: datetime

class PrintQueueService:
    """Очередь заданий печати с приоритетами."""
    def __init__(self, printer_adapter: PrinterProtocol) -> None: ...
    def enqueue(self, document: Document, priority: PrintPriority = PrintPriority.NORMAL) -> str: ...
    def cancel(self, job_id: str) -> bool: ...
    def get_status(self, job_id: str) -> PrintJobStatus: ...
    def get_queue(self) -> list[PrintJob]: ...
    def process_queue(self) -> None: ...  # Вызывается background thread
```

#### Batch Operations Service

```python
# src/services/batch_service.py
class BatchService:
    """Пакетные операции — batch print, batch export."""
    def __init__(
        self,
        document_service: DocumentServiceProtocol,
        print_service: PrintServiceProtocol
    ) -> None: ...
    def batch_print(self, documents: list[Document], options: BatchPrintOptions) -> BatchResult: ...
    def batch_export(self, documents: list[Document], format: ExportFormat, output_dir: Path) -> BatchResult: ...
```

#### Index Search Service

```python
# src/services/index_search_service.py
class IndexSearchService:
    """Поиск и фильтрация документов по индексу DVN-44-K53-IX."""
    def __init__(self, documents_dir: Path) -> None: ...
    def search_by_index(self, pattern: str) -> list[DocumentInfo]: ...
    def search_by_type(self, doc_type: str) -> list[DocumentInfo]: ...
    def search_by_date_range(self, start: datetime, end: datetime) -> list[DocumentInfo]: ...
    def filter(self, criteria: SearchCriteria) -> list[DocumentInfo]: ...
```

#### Key Bindings Service

```python
# src/services/key_bindings_service.py
class KeyBindingsService:
    """Система горячих клавиш."""
    def __init__(self, config_path: Path | None = None) -> None: ...
    def register(self, key_combo: str, action_id: str) -> None: ...
    def unregister(self, key_combo: str) -> None: ...
    def get_action(self, key_combo: str) -> str | None: ...
    def get_bindings_for_action(self, action_id: str) -> list[str]: ...
    def load_defaults(self) -> None: ...
    def save(self) -> None: ...
```

#### Watermark Service

```python
# src/services/watermark_service.py
@dataclass(frozen=True)
class WatermarkConfig:
    text: str                    # Текст водяного знака ("КОПИЯ", "ЧЕРНОВИК")
    font_size: int = 48
    opacity: float = 0.3         # Прозрачность 0-1
    angle: int = 45              # Угол наклона в градусах
    position: WatermarkPosition = WatermarkPosition.CENTER
    repeat: bool = True          # Повторять по всей странице

class WatermarkService:
    """Водяные знаки через ESC/P graphics layer."""
    def __init__(self, renderer: DocumentRenderer) -> None: ...
    def apply_watermark(
        self,
        document: Document,
        config: WatermarkConfig
    ) -> bytes: ...  # Возвращает ESC/P с наложенным watermark
    def remove_watermark(self, document: Document) -> bytes: ...
```

**Реализация:**
- Генерация растрового изображения текста
- Наложение через ESC/P graphics commands (ESC * m nL nH)
- Поддержка режимов: DRAFT, COPY, CONFIDENTIAL

#### Paper Format Manager

```python
# src/services/paper_format_service.py
@dataclass(frozen=True)
class PaperFormat:
    """Профиль формата бумаги."""
    name: str                    # "A4", "Letter", "A5", "Custom"
    width_inches: float
    height_inches: float
    lines_per_page: int        # При 1/6 lpi (66 для Letter, 70 для A4)
    default_margins: Margins

class PaperFormatService:
    """Управление форматами бумаги и профилями."""
    def __init__(self) -> None: ...
    def get_builtin_formats(self) -> list[PaperFormat]: ...
    def get_format(self, name: str) -> PaperFormat: ...
    def create_custom_format(self, name: str, width: float, height: float, margins: Margins) -> PaperFormat: ...
    def apply_format(self, document: Document, format: PaperFormat) -> Command: ...  # Возвращает команду для undo
    def estimate_page_count(self, document: Document, format: PaperFormat) -> int: ...
```

**Встроенные форматы:**
| Формат | Размер | Строки (1/6 lpi) | Строки (1/8 lpi) |
|--------|--------|------------------|------------------|
| Letter | 8.5×11" | 66 | 88 |
| A4 | 8.27×11.69" | 70 | 93 |
| Legal | 8.5×14" | 84 | 112 |
| A5 | 5.83×8.27" | 49 | 66 |

### 5.8 view/ — UI Layer

**Назначение:** Tkinter-based GUI компоненты.

> **Статус:** ❌ Не начато — 0%.

#### Основные компоненты

```
src/view/
├── main_window.py              # Главное окно приложения
├── menu/
│   ├── main_menu.py            # Главное меню
│   ├── context_menu.py         # Контекстное меню (right-click)
│   └── recent_files.py         # Недавние файлы
├── toolbar/
│   ├── formatting_toolbar.py   # Панель форматирования
│   └── print_toolbar.py        # Панель печати
├── editor/
│   ├── document_editor.py      # Редактор документа (WYSIWYG)
│   ├── paragraph_widget.py     # Виджет параграфа
│   └── table_widget.py         # Виджет таблицы
├── dialogs/
│   ├── find_replace_dialog.py  # Диалог Find & Replace
│   ├── print_preview_dialog.py # Визуальный preview ESC/P
│   ├── export_dialog.py        # Диалог экспорта
│   ├── settings_dialog.py      # Настройки приложения
│   ├── first_run_wizard.py     # First-run wizard / Key ceremony
│   └── about_dialog.py         # О программе
├── panels/
│   ├── status_bar.py           # Статус-бар с прогрессом
│   ├── document_tabs.py        # Вкладки документов (MDI)
│   ├── template_browser.py     # Браузер шаблонов
│   └── statistics_panel.py     # Панель статистики
└── preview/
    ├── print_preview_canvas.py # Canvas для preview
    └── escp_preview_renderer.py # Рендер ESC/P в preview
```

#### Print Preview

```python
# src/view/preview/print_preview_canvas.py
class PrintPreviewCanvas(Canvas):
    """Визуальный preview вывода на матричный принтер.

    Имитирует:
    - Dot grid (точечная структура матричного принтера)
    - Шрифты Epson FX-890 (Draft, NLQ Roman, NLQ Sans Serif)
    - Форматирование (bold, italic, underline)
    - Разрывы страниц
    """
    def __init__(self, parent: Widget) -> None: ...
    def render_document(self, document: Document, zoom: float = 1.0) -> None: ...
    def go_to_page(self, page: int) -> None: ...
```

#### First-Run Wizard

```python
# src/view/dialogs/first_run_wizard.py
class FirstRunWizard(Toplevel):
    """Wizard первого запуска — key ceremony, MFA setup."""

    STEPS = [
        "welcome",           # Приветствие
        "security_preset",   # Выбор пресета безопасности
        "master_password",   # Установка master password
        "fido2_setup",       # Регистрация FIDO2
        "totp_setup",        # Настройка TOTP (опционально)
        "backup_codes",      # Генерация backup codes
        "complete",          # Завершение
    ]

    def __init__(self, parent: Widget, auth_service: AuthServiceProtocol) -> None: ...
```

#### Settings Dialog

```python
# src/view/dialogs/settings_dialog.py
class SettingsDialog(Toplevel):
    """Настройки приложения."""

    SECTIONS = [
        "general",      # Общие (auto-save, language)
        "security",     # Безопасность (presets, algorithms)
        "printer",      # Принтер (default settings)
        "key_bindings", # Горячие клавиши
        "notifications",# Уведомления
    ]

    def __init__(self, parent: Widget) -> None: ...
```

### 5.9 controller/ — Controllers

**Назначение:** Связь View ↔ Service, обработка пользовательских действий.

> **Статус:** ❌ Не начато — 0%.

```
src/controller/
├── main_controller.py          # Главный контроллер
├── document_controller.py      # Работа с документом
├── editing_controller.py       # Редактирование (undo/redo, clipboard)
├── print_controller.py         # Печать и preview
├── search_controller.py        # Find & Replace
├── settings_controller.py      # Настройки
├── wizard_controller.py        # First-run wizard
└── template_controller.py      # Работа с шаблонами
```

### 5.10 security/

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

### 5.11 printer/

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

### 5.12 app_context.py

**Назначение:** Composition root — единственное место, где создаются и связываются все зависимости.

> **Примечание:** Модули `documents/` находятся в активном рефакторинге из устаревшего `src/form/`.
> Текущая реализация в `src/form/` будет заменена на новую архитектуру `src/documents/`.
> См. раздел [Приоритеты разработки (Q2 2026)](#приоритеты-разработки-q2-2026).

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
    def command_history(self) -> CommandHistoryService: ...
    @property
    def find_replace(self) -> FindReplaceService: ...
    @property
    def auto_save(self) -> AutoSaveService: ...
    @property
    def notification(self) -> NotificationService: ...
    @property
    def document_stats(self) -> DocumentStatsService: ...
    @property
    def clipboard(self) -> ClipboardService: ...
    @property
    def document_manager(self) -> DocumentManagerService: ...
    @property
    def export(self) -> ExportService: ...
    @property
    def print_queue(self) -> PrintQueueService: ...
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

## 11. Приоритеты разработки (Q2 2026)

Актуальные приоритеты разработки в порядке важности:

| # | Модуль | Статус | Примечание |
|---|--------|--------|------------|
| 1 | `src/documents/types/` + `src/documents/constructor/` | ⚠️ В процессе | Рефакторинг из `form/` → `documents/` |
| 2 | `src/documents/printing/` | ⚠️ В процессе | ESC/P render pipeline |
| 3 | `src/printer/` | ⚠️ В процессе | Transport adapters (CUPS/Win/File) |
| 4 | `src/security/auth/` | ✅ Завершён | 98.67% coverage, MFA flow complete |
| 5 | `src/services/command_history/` | ❌ Не начато | **Критично:** Undo/Redo для GUI |
| 6 | `src/services/find_replace/` | ❌ Не начато | **Критично:** Поиск и замена |
| 7 | `src/services/auto_save/` | ❌ Не начато | **Критично:** Автосохранение |
| 8 | `src/services/notification/` | ❌ Не начато | **Критично:** Статус-бар и прогресс |
| 9 | GUI (View + Controller) | ❌ Не начато | 0% — требуется реализация Tkinter |
| 10 | Интеграционные тесты GUI ↔ Service | ❌ Не начато | Требуется завершение GUI |

### Отсутствующие модули (TODO)

#### Security модули

| Модуль | Путь | Статус | Комментарий |
|--------|------|--------|-------------|
| Session Lock | `src/security/lock/session_lock.py` | ✅ Done | SessionLockManager, AutoLockService |
| Secure Erasure | `src/security/erasure.py` | ✅ Done | Secure wipe (DoD 5220.22-M) |
| Monitoring | `src/security/monitoring/` | ✅ Done | HealthChecker, 6 health checks |
| Floppy Optimizer | `src/security/crypto/utilities/floppy_optimizer.py` | 📋 TODO | 1.44 MB optimization |

#### Infrastructure модули

| Модуль | Путь | Статус | Комментарий |
|--------|------|--------|-------------|
| File Adapter | `src/printer/file_adapter.py` | 📋 TODO | Debug file output adapter |
| Backup | `src/backup/` | 📋 TODO | Key ceremony, Shamir SSS, paper key |
| Network | `src/network/` | 📋 TODO | LAN verifier (opt-in) |
| Stealth | `src/stealth/` | 📋 TODO | Steganography (future) |

#### GUI Services (критично для WYSIWYG)

| Модуль | Путь | Статус | Комментарий |
|--------|------|--------|-------------|
| Command History | `src/services/command_history_service.py` | ❌ Не начато | Undo/Redo — паттерн Command |
| Find & Replace | `src/services/find_replace_service.py` | ❌ Не начато | Поиск с regex, replace all |
| Auto-save | `src/services/auto_save_service.py` | ❌ Не начато | .fxsd.tmp + crash recovery |
| Clipboard | `src/services/clipboard_service.py` | ❌ Не начато | Copy/paste полей, Paste Special |
| Notification | `src/services/notification_service.py` | ❌ Не начато | Status bar, progress dialogs |
| Document Stats | `src/services/document_stats_service.py` | ❌ Не начато | Счётчики символов/слов/строк |
| Document Lock | `src/services/document_lock_service.py` | ❌ Не начато | .fxsd.lock — защита от двойного открытия |
| Version History | `src/services/version_history_service.py` | ❌ Не начато | Diff между версиями |
| Document Manager | `src/services/document_manager_service.py` | ❌ Не начато | MDI — несколько документов |
| Export | `src/services/export_service.py` | ❌ Не начато | TXT, Markdown, HTML экспорт |
| Print Queue | `src/services/print_queue_service.py` | ❌ Не начато | Очередь заданий с приоритетами |
| Batch Operations | `src/services/batch_service.py` | ❌ Не начато | Batch print, batch export |
| Index Search | `src/services/index_search_service.py` | ❌ Не начато | Поиск по DVN-44-K53-IX |
| Key Bindings | `src/services/key_bindings_service.py` | ❌ Не начато | Горячие клавиши, настройка |
| Watermark | `src/services/watermark_service.py` | ❌ Не начато | "КОПИЯ", "ЧЕРНОВИК" через ESC/P graphics |
| Paper Format | `src/services/paper_format_service.py` | ❌ Не начато | Профили A4, Letter, A5, Custom |

#### UI Components (View)

| Модуль | Путь | Статус | Комментарий |
|--------|------|--------|-------------|
| Main Window | `src/view/main_window.py` | ❌ Не начато | Главное окно Tkinter |
| Document Editor | `src/view/editor/document_editor.py` | ❌ Не начато | WYSIWYG редактор |
| Print Preview | `src/view/preview/print_preview_canvas.py` | ❌ Не начато | Визуальный preview ESC/P |
| Find/Replace Dialog | `src/view/dialogs/find_replace_dialog.py` | ❌ Не начато | Диалог поиска и замены |
| Settings Dialog | `src/view/dialogs/settings_dialog.py` | ❌ Не начато | Настройки приложения |
| First-run Wizard | `src/view/dialogs/first_run_wizard.py` | ❌ Не начато | Key ceremony UI |
| Template Browser | `src/view/template_browser.py` | ❌ Не начато | Галерея шаблонов .fxstpl |
| Status Bar | `src/view/panels/status_bar.py` | ❌ Не начато | Статус-бар с прогрессом |
| Document Tabs | `src/view/panels/document_tabs.py` | ❌ Не начато | Вкладки MDI |
| Context Menu | `src/view/menu/context_menu.py` | ❌ Не начато | Right-click меню |

#### Controllers

| Модуль | Путь | Статус | Комментарий |
|--------|------|--------|-------------|
| Main Controller | `src/controller/main_controller.py` | ❌ Не начато | Главный контроллер |
| Document Controller | `src/controller/document_controller.py` | ❌ Не начато | Работа с документом |
| Editing Controller | `src/controller/editing_controller.py` | ❌ Не начато | Undo/redo, clipboard |
| Print Controller | `src/controller/print_controller.py` | ❌ Не начато | Печать и preview |
| Search Controller | `src/controller/search_controller.py` | ❌ Не начато | Find & Replace |
| Settings Controller | `src/controller/settings_controller.py` | ❌ Не начато | Настройки |
| Wizard Controller | `src/controller/wizard_controller.py` | ❌ Не начато | First-run wizard |

## 12. Module Status

Текущее состояние разработки по модулям (March 2026):

| Модуль | Статус | Покрытие | Тесты | Примечание |
|---|---|---|---|---|
| `model/` | ✅ 86% | ~92% | 310+ | Основные dataclasses готовы |
| `escp/commands/` | ✅ 100% | >95% | 420+ | Все ESC/P команды FX-890 |
| `security/crypto/` | ✅ 100% | ~95% | 180+ | v2.3, 46 алгоритмов |
| `security/auth/` | ✅ 98% | 98.67% | 616+ | MFA flow complete (Password + FIDO2/TOTP/Backup Codes) |
| `security/audit/` | ✅ Complete | — | — | Hash chain + HMAC |
| `security/blanks/` | ✅ Complete | — | — | Lifecycle + signing + verify |
| `security/compliance/` | ✅ Complete | — | — | GDPR, retention |
| `security/crypto/hardware/` | ✅ Complete | — | — | PIV, OpenPGP backends |
| `security/integrity/` | ✅ Complete | — | — | App hash check, config signature |
| `security/lock/` | ✅ Complete | — | — | SessionLockManager, AutoLockService |
| `security/erasure.py` | ✅ Complete | — | — | Secure wipe, DoD 5220.22-M |
| `security/monitoring/` | ✅ Complete | — | — | HealthChecker, 6 checks |
| `documents/types/` | 📋 TODO | — | — | Рефакторинг из form/ |
| `documents/constructor/` | 📋 TODO | — | — | Рефакторинг из form/ |
| `documents/format/` | 📋 TODO | — | — | Сериализация |
| `documents/printing/` | 📋 TODO | — | — | ESC/P render pipeline |
| `printer/` | 📋 TODO | — | — | Stubs only |
| `services/command_history/` | ❌ 0% | — | — | Undo/Redo — критично для GUI |
| `services/find_replace/` | ❌ 0% | — | — | Поиск и замена |
| `services/auto_save/` | ❌ 0% | — | — | Автосохранение и crash recovery |
| `services/clipboard/` | ❌ 0% | — | — | Буфер обмена |
| `services/notification/` | ❌ 0% | — | — | Уведомления и статус-бар |
| `services/document_stats/` | ❌ 0% | — | — | Статистика документа |
| `services/document_lock/` | ❌ 0% | — | — | Блокировка от двойного открытия |
| `services/version_history/` | ❌ 0% | — | — | История версий документа |
| `services/document_manager/` | ❌ 0% | — | — | MDI — несколько документов |
| `services/export/` | ❌ 0% | — | — | TXT, Markdown, HTML экспорт |
| `services/print_queue/` | ❌ 0% | — | — | Очередь заданий печати |
| `services/batch/` | ❌ 0% | — | — | Пакетные операции |
| `services/index_search/` | ❌ 0% | — | — | Поиск по индексу |
| `services/key_bindings/` | ❌ 0% | — | — | Горячие клавиши |
| `services/watermark/` | ❌ 0% | — | — | Водяные знаки через ESC/P graphics |
| `services/paper_format/` | ❌ 0% | — | — | Профили форматов бумаги (A4, Letter, A5) |
| `view/` (GUI) | ❌ 0% | — | — | Tkinter UI — не начато |
| `controller/` | ❌ 0% | — | — | Controllers — не начато |
| `controller/` | ❌ 0% | — | — | Controllers — не начато |
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

## 13. Related Documents

| Документ | Описание |
|---|---|
| [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md) | Детальная архитектура безопасности (v2.1) — криптография, аутентификация, Protected Blanks |
| [SECURITY_SETUP.md](SECURITY_SETUP.md) | Инструкция по настройке безопасности — первоначальная конфигурация, key ceremony |
| [API_REFERENCE.md](API_REFERENCE.md) | Справочник API всех публичных модулей |
| [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) | Контекст проекта — цели, ограничения, решения |
| [form_designer.md](form_designer.md) | Визуальный конструктор шаблонов форм — ESC/P Grid Canvas, drag-and-drop |
| [form_history.md](form_history.md) | История заполнения полей — автозаполнение, cross-document lookup |
| [template_library.md](template_library.md) | Библиотека шаблонов — версионирование, импорт/экспорт через USB/floppy |
| [approval_workflow.md](approval_workflow.md) | Workflow согласования (single-operator) — state machine, MFA-переходы |

---

> **FX Text Processor 3** — Architecture Document v3.1
> Last updated: 2026-03-18
