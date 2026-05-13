# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **⚠️ IMPORTANT: Working Directory**
> The actual project root is: `/home/Mike/Dev/FX-Text-processor/FX-Text-processor-3/`
> Always operate from this directory when creating or modifying files.
> The parent directory contains legacy files and should not be used as the working root.

## Project Overview

**FX Text Processor 3** — WYSIWYG editor for Epson FX-890 dot matrix printer with enterprise Zero Trust cryptography. Air-Gap First design, single operator, portable application.

- **Language**: Python 3.11+ (3.13 compatible)
- **Architecture**: MVC + Service Layer
- **GUI**: Tkinter (in development)
- **Current Status**: ~48% complete, Auth 98.67% complete

Full context: .ai/project_context.md | Architecture: docs/ARCHITECTURE.md | Security: docs/SECURITY_ARCHITECTURE.md

## Commands

### Testing
```bash
pytest -m "not slow"                          # Быстрые тесты (default)
pytest -m security                            # Только security тесты
pytest -m crypto                              # Крипто тесты с NIST vectors
pytest tests/unit/security/auth/test_password.py::TestPasswordHasher::test_hash  # Один тест
pytest --cov=src --cov-report=term-missing    # С coverage отчётом
```

### GUI Testing

> **⚠️ СТРОГОЕ ПРАВИЛО: НИКОГДА не запускать pytest для GUI-компонентов напрямую**

Всегда использовать виртуальный фреймбуфер:

```bash
xvfb-run -a python -m pytest tests/unit/gui/
```

### Type Checking & Linting
```bash
mypy --strict src/                            # Type checking (MUST pass)
ruff check src/ tests/                          # Быстрый линтер
ruff format src/ tests/                         # Форматирование (альтернатива Black)
black src/ tests/ && isort src/ tests/          # Традиционное форматирование
bandit -r src/ -ll                            # Security linting
```

### Full Validation
```bash
bash check.sh <file_or_dir>                   # ВСЕ проверки на цель
bash check.sh src/security/crypto/core/       # Проверка модуля
bash check.sh .                               # Проверка всего проекта
```

## Architecture (строгое слоение)

Слои (строго снизу вверх, без пропусков):

```
View (Tkinter)      → только callbacks к Controller
Controller          → координация View ↔ Service, NO сложная логика
Service Layer       → вся бизнес-логика, DI через конструктор
Model               → dataclasses (frozen=True), NO бизнес-логика
```

### Специфичные слои (не MVC)

| Модуль | Назначение | Ключевое ограничение |
|--------|------------|---------------------|
| `escp/commands/` | Byte-константы для Epson FX-890 ESC/P | NO imports из `model/` |
| `documents/types/` | TypeRegistry, DocumentType, IndexTemplate | Singleton, thread-safe |
| `documents/constructor/` | FormConstructor, ExcelImporter, FieldBuilder | Формы с валидацией |
| `documents/printing/` | Рендереры: model → escp/commands/ → bytes | Pipeline-архитектура |
| `documents/format/` | Сериализация `.fxsd`/`.fxsd.enc`, миграция | Version headers |
| `security/crypto/` | AlgorithmRegistry, 46 алгоритмов, 4 пресета | Crypto agility |
| `security/auth/` | MFA: Password + FIDO2/TOTP/BackupCode | 98.67% coverage |
| `security/audit/` | Immutable hash-chain log + HMAC | Только append |
| `security/blanks/` | Protected Blanks lifecycle + QR verification | Offline verification |
| `printer/` | PrinterProtocol → CupsAdapter/WinAdapter/FileAdapter | Transport layer |

## GUI Components

### Диалоги (`src/gui/dialogs/`)

Единый базовый класс `BaseDialog` (`base_dialog.py`) обеспечивает unified lifecycle, модальность, обработку Escape и центрирование.

| Диалог | Файл | Назначение |
|--------|------|------------|
| BaseDialog | `base_dialog.py` | Unified lifecycle, modal, escape, centering |
| SecurityHealthCheckDialog | `security_health_check_dialog.py` | 6 проверок безопасности перед Special Mode |
| TrustChainDialog | `trust_chain_dialog.py` | Просмотр/верификация цепочки доверия (verification_mode) |

### PHASE_5 Виджеты (`src/gui/modes/structured_form/widgets/`)

| Виджет | Файл | Назначение |
|--------|------|------------|
| SignatureWidget | `signature_widget.py` | Виджет подписи |
| StampWidget | `stamp_widget.py` | Виджет печати |
| BarcodeWidget | `barcode_widget.py` | Виджет штрих-кода |
| QRWidget | `qr_widget.py` | Виджет QR-кода |
| StaticTextWidget | `static_text_widget.py` | Статический текст |
| CalculatedWidget | `calculated_widget.py` | Вычисляемое поле |
| PhoneWidget | `phone_widget.py` | Поле телефона |
| EmailWidget | `email_widget.py` | Поле email |
| ExcelImportWidget | `excel_import_widget.py` | Импорт из Excel |

### GUI Сервисы (`src/gui/services/`)

| Сервис | Файл | Назначение |
|--------|------|------------|
| KeyBindingsService | `key_bindings.py` | Глобальные shortcuts, conflict detection |
| DragDropService | `drag_drop_service.py` | Drag-and-drop операции |
| SyncService | `sync_service.py` | Синхронизация данных |
| WindowManager | `window_manager.py` | Управление окнами |
| AutocompleteServiceGui | `autocomplete_service.py` | Автодополнение в GUI |

### GUI Testing

> **⚠️ СТРОГОЕ ПРАВИЛО: НИКОГДА не запускать pytest для GUI-компонентов напрямую**
>
> Всегда использовать виртуальный фреймбуфер:
>
> ```bash
> xvfb-run -a python -m pytest tests/unit/gui/
> ```

## Code Standards

### Type Safety (Strict)
- `mypy --strict` ОБЯЗАТЕЛЬНО перед коммитом
- `Protocol` вместо ABC для интерфейсов
- `frozen=True` dataclasses предпочтительно
- Полные type annotations на всех функциях

### Documentation
- Docstrings: Google-style, **на русском языке**
- Error messages: user-facing на русском с контекстом, security — минимум info leak

### Testing Requirements
- Новые модули: ≥90% coverage
- Security модули: ≥95% coverage
- Маркеры: `@pytest.mark.security`, `@pytest.mark.slow`, `@pytest.mark.crypto`

### Performance
- `bytearray` для построения ESC/P команд (не конкатенация bytes)
- PC866 для русского текста в ESC/P
- `pathlib.Path` вместо строковых путей

## File Extensions (.fxs prefix)

Все файлы приложения используют префикс `.fxs` (FX Super):

| Extension | Purpose |
|-----------|---------|
| `.fxsd` / `.fxsd.enc` | Документ / Зашифрованный документ |
| `.fxstpl` | Шаблон |
| `.fxsblank` | Защищённый бланк (всегда зашифрован) |
| `.fxskeystore.enc` | Хранилище ключей |
| `.fxssig` | Отделённая цифровая подпись |
| `.fxsconfig` | Подписанная конфигурация |
| `.fxsbackup` / `.fxsbundle.enc` | Бэкап / Экспортный пакет |
| `.fxsreg` | Реестр устройств (подписан) |
| `.escp` / `.escps` | Raw ESC/P команды / Скрипт |

## Document Indexing

Иерархический составной индекс: `DVN-44-K53-IX`
- Произвольная глубина вложенности, сегменты через `-`
- Последний сегмент — ВСЕГДА римские цифры (SEQUENCE)
- Типы сегментов: ROOT_CODE, SUBTYPE, SERIES, CUSTOM, SEQUENCE

## Security Presets

| Preset | Signing | Encryption | KDF |
|--------|---------|------------|-----|
| Standard | Ed25519 | AES-256-GCM | Argon2id (64MB) |
| Paranoid | Ed25519 + ML-DSA-65 | AES-256-GCM + ChaCha20 | Argon2id (256MB) |
| PQC | ML-DSA-65 | AES-256-GCM | Argon2id (64MB) |
| Legacy | RSA-PSS-4096 | AES-256-GCM | PBKDF2-SHA256 |

## Текущий приоритет (Q2 2026)

1. `src/documents/types/` + `src/documents/constructor/` — рефакторинг из form/ ⚠️
2. `src/documents/printing/` — ESC/P render pipeline ⚠️
3. `src/printer/` — transport adapters (CUPS/Win/File) ⚠️
4. `src/security/auth/` — ✅ 98.67%, MFA flow complete (Password + FIDO2/TOTP/Backup Codes)
5. GUI (View + Controller) — 0% ❌
6. Интеграционные тесты GUI ↔ Service ❌

## Floppy Optimization (опционально)

`MAX_FLOPPY_BYTES = 1_340_000` (~1.28 MB). Ed25519 предпочтителен (64 B vs 3,309 B ML-DSA-65). `FloppyOptimizer` в `crypto/utilities/floppy_optimizer.py`.

## Шаблон промпта для нового модуля

```
Слой: [Model/Service/Controller/View/Documents/Security]
Файл: src/[layer]/[module].py
Требования: mypy --strict, coverage ≥90%, docstrings на русском
Эталон (код): @src/security/crypto/advanced/hybrid_encryption.py
Эталон (тесты): @tests/unit/security/crypto/core/test_metadata.py
Детальные шаблоны: @old_docs/project_context.md → "File Structure Template"
```

## Interaction Rules

- If you need my input at ANY point, you MUST use the `AskUserQuestion` tool.
- Before starting any complex task, ask clarifying questions using `AskUserQuestion`.
- NEVER make assumptions about architecture, naming, or approach — ask first.

## [AI Agent Workflow & MCP Rules]

**1. Sequential Thinking (Mandatory for Architecture)**
- Before modifying core modules (`src/security/`, `src/documents/`, `src/gui/core/`), you MUST use the `Sequential Thinking` MCP tool.
- Break down the task, evaluate the impact on the MVC layers, verify your assumptions against the AST graph, and present the final plan before coding.

**2. RAG & Knowledge Base Usage**
You have access to specialized local RAG servers. Use them strictly as follows:
- **`code-graph-rag-mcp` (AST parser):** Use this ONLY for analyzing Python codebase architecture. Query it to find call chains, class inheritances, and dependencies (e.g., "Find all modules importing `AlgorithmRegistry`"). NEVER use it to search markdown documentation.
- **`docs-rag` (Semantic search):** Use this ONLY for searching `.md` and `.txt` files in the `docs/` folder (e.g., "What are the requirements for PQC signatures in `SECURITY_ARCHITECTURE.md`?"). NEVER use it to search code.

**3. Execution Limits & Fallbacks**
- **GUI Testing:** NEVER run `pytest` directly on GUI modules. Always use `xvfb-run -a python -m pytest` as defined in the Commands section. If a test times out after 30 seconds, immediately kill it and analyze the code statically.
- **Context Boundaries:** Do not ingest the `.venv`, `__pycache__`, or `tests/` directories into the RAG databases to avoid context bloat.

## [Mandatory Planning: Sequential Thinking]
- **Global Trigger:** You MUST use the `sequentialthinking` tool before writing new code, refactoring existing modules, or fixing complex bugs ANYWHERE in the project (including all GUI components, tests, and utilities).
- **Thinking Process Requirements:**
  1. **Understand & Verify:** Do not rush to edit files. First, break down the task. Use RAG tools (`code-graph-rag-mcp` and `docs-rag`) to understand current dependencies and constraints.
  2. **Type & Architecture Planning:** Think explicitly about data types, Protocol interfaces, and strict typing (`mypy --strict`). How will this code pass the `check.sh` pipeline?
  3. **Self-Correction:** Critically evaluate your plan. Does it violate Zero Trust? Does it mix Controller logic into a View? Will it cause a Tkinter headless deadlock? If yes, use the tool's revision feature to backtrack and fix your logic.
  4. **Execution:** Only proceed to file editing when `nextThoughtNeeded` is false and you have a bulletproof, type-safe implementation plan.

## Ключевые ссылки

- Стиль и паттерны: docs/project_context.md
- Архитектура v3.0: docs/ARCHITECTURE.md
- API Reference v3.0: docs/API_REFERENCE.md
- Security архитектура v2.1: docs/SECURITY_ARCHITECTURE.md
- Security setup: docs/SECURITY_SETUP.md
