# FX Text Processor 3 — UI Specification Document (Complete)

**Версия:** 2.0  
**Дата:** Апрель 2026  
**Статус:** Финальная спецификация для реализации  
**Автор:** На основе анализа всех документов проекта

---

## Содержание

1. [Архитектура Режимов](#1-архитектура-режимов)
2. [Главное Окно (MainWindow)](#2-главное-окно-mainwindow)
3. [Security & Auth UI](#3-security--auth-ui)
4. [DocumentView — Визуализация Бумаги](#4-documentview--визуализация-бумаги)
5. [Form Designer (Super Docs)](#5-form-designer-super-docs)
6. [SideBar](#6-sidebar)
7. [StatusBar — Индикаторы](#7-statusbar--индикаторы)
8. [Toast Notification System](#8-toast-notification-system)
9. [Session Lock](#9-session-lock)
10. [Paper Setup Dialog](#10-paper-setup-dialog)
11. [Template Library UI](#11-template-library-ui)
12. [Form History & Autocomplete](#12-form-history--autocomplete)
13. [Approval Workflow UI](#13-approval-workflow-ui)
14. [Barcode & QR UI](#14-barcode--qr-ui)
15. [Multi-Window Support](#15-multi-window-support)
16. [Диалоги](#16-диалоги)
17. [План Реализации](#17-план-реализации)

---

## 1. Архитектура Режимов

### 1.1 Режимы Приложения

| Режим | MFA | Доступ | Иконка в меню |
|-------|-----|--------|---------------|
| **Normal Mode** | Нет | FREE_FORM + STRUCTURED_FORM (без Audit/Workflow) | 🟢 Normal |
| **Special Mode** | Да | Полный доступ + Security features | 🔴 Special |

**Тумблер:** `Tools → Mode: [🟢 Normal ▓▓▓░░░]`

### 1.2 Health Check перед входом в Special Mode

```
┌─────────────────────────────────────────────────────────┐
│  Security Health Check                                    │
├─────────────────────────────────────────────────────────┤
│  [✓] Entropy Check — /dev/random available              │
│  [✓] Keystore — Master key loaded                       │
│  [✓] Hardware Devices — YubiKey detected                │
│  [✓] Audit Chain — Hash chain verified                 │
│  [✓] Algorithm Library — liboqs loaded                 │
│                                                          │
│  Status: All systems operational                        │
│                                                          │
│                [Enter Special Mode]  [Cancel]            │
└─────────────────────────────────────────────────────────┘
```

### 1.3 Конвертация Документов

- `Document → Convert to Special Mode` (требует MFA)
- `Document → Convert to Normal Mode` (требует подтверждение)

---

## 2. Главное Окно (MainWindow)

### 2.1 Layout

```
┌─────────────────────────────────────────────────────────────┐
│  MainToolbar                                                │
├──────────┬────────────────────────────────────────────────┤
│          │  FormatToolbar                                  │
│ SideBar  ├─────────────────────────────────────────────────┤
│ (слева)  │                                                 │
│          │  CardFileTabBar                                 │
│          ├─────────────────────────────────────────────────┤
│          │  ┌───────────────────────────────────────────┐│
│          │  │ Paper Toolbar (тип бумаги + Paper Setup)    ││
│          │  ├───────────────────────────────────────────┤│
│          │  │ Ruler (с табуляторами и маркерами полей)  ││
│          │  ├───────────────────────────────────────────┤│
│          │  │                                           ││
│          │  │   DocumentView с WYSIWYG рендерингом      ││
│          │  │   (пропорциональный шрифт, линии          ││
│          │  │    перфорации, границы листа)             ││
│          │  │                                           ││
│          │  ├───────────────────────────────────────────┤│
│          │  │ Navigator (◀◀ Стр / Стр ▶▶)              ││
│          │  └───────────────────────────────────────────┘│
├──────────┴────────────────────────────────────────────────┤
│  StatusBar: Ln/Col │ CPI │ CodePage │ Paper │ Security │ Page │ Zoom │ [n] │
│  StatusBar [2 строки при узком окне]                       │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Paper Toolbar

```
┌─────────────────────────────────────────────────────────────┐
│  [📄 A4] [📄 Letter] [🖨️ Tractor▼] [⚙️ Paper Setup...]        │
│           └─ Выпадающий список типов бумаги                 │
│              • Tractor Full (210×305)                        │
│              • Tractor Half (210×152.5)                      │
│              • Tractor Triplet (210×101.6)                 │
│              • Envelope DL                                   │
│              • Envelope C5                                   │
│              • Custom...                                     │
└─────────────────────────────────────────────────────────────┘
```

**Paper Setup** открывается:
- Через кнопку ⚙️ в Paper Toolbar
- Двойным кликом на индикаторе "Paper" в StatusBar

---

## 3. Security & Auth UI

### 3.1 AuthWindow — Главное окно аутентификации

```
┌─────────────────────────────────────────┐
│         FX Text Processor 3             │
│                                         │
│    ┌─────────────────────────────┐     │
│    │ 🔐 Authentication Required  │     │
│    ├─────────────────────────────┤     │
│    │                             │     │
│    │  Username: [______________]  │     │
│    │                             │     │
│    │  Password: [______________]  │     │
│    │                             │     │
│    │  Method:                    │     │
│    │  [● Password + FIDO2]      │     │
│    │  [○ Password + TOTP]        │     │
│    │  [○ Password + Backup Code] │     │
│    │                             │     │
│    │  [FIDO2: Touch your key]   │     │
│    │                             │     │
│    │     [Login]  [Cancel]      │     │
│    └─────────────────────────────┘     │
└─────────────────────────────────────────┘
```

**Поля:**
- Username (optional)
- Password (Argon2id verification)
- Method selector (Password + FIDO2/TOTP/Backup Code)

**Интеграция:**
- `AuthService.authenticate()`
- `SecondFactorManager.verify_mfa()`

### 3.2 FIDO2SetupDialog — Регистрация FIDO2

```
┌─────────────────────────────────────────┐
│  Setup FIDO2 Security Key                 │
├─────────────────────────────────────────┤
│  Step 1: Insert your security key       │
│  [🗝️ YubiKey 5 NFC]                      │
│                                          │
│  Step 2: Touch the key when prompted    │
│  [⠋ Waiting for touch...]               │
│                                          │
│  Step 3: Registration complete!          │
│  ✓ Credential ID: a3f2b8...             │
│                                          │
│  Backup your recovery codes:            │
│  ┌─────────────────────────────────┐   │
│  │ XXXX-XXXX-XXXX-XXXX              │   │
│  │ XXXX-XXXX-XXXX-XXXX              │   │
│  └─────────────────────────────────┘   │
│                                          │
│        [Save]  [Print Codes]  [Done]     │
└─────────────────────────────────────────┘
```

### 3.3 TOTPSetupDialog — Настройка TOTP

```
┌─────────────────────────────────────────┐
│  Setup Authenticator App                  │
├─────────────────────────────────────────┤
│  Scan this QR code with your app:       │
│  ┌─────────────────────────┐            │
│  │  ████████████████████   │            │
│  │  ██  ▄▄▄▄▄▄▄▄▄▄▄▄  ██   │            │
│  │  ██  █ ▄▄▄▄▄▄▄ █  ██   │            │
│  │  ██  █ █     █ █  ██   │            │
│  │  ██  █ █ ▄▄▄ █ █  ██   │            │
│  │  ██  █ █ ███ █ █  ██   │            │
│  │  ██  █ █ ▀▀▀ █ █  ██   │            │
│  │  ██  █ ▀▀▀▀▀▀▀ █  ██   │            │
│  │  ██  ▀▀▀▀▀▀▀▀▀▀▀▀  ██   │            │
│  │  ████████████████████   │            │
│  └─────────────────────────┘            │
│                                          │
│  Or enter manually:                     │
│  Secret: JBSW Y3DP EHPK 3PXP            │
│                                          │
│  Enter code to verify:                 │
│  [___] [___] [___] [___] [___] [___]   │
│                                          │
│              [Verify]  [Cancel]         │
└─────────────────────────────────────────┘
```

### 3.4 BackupCodesDialog — Резервные коды

```
┌─────────────────────────────────────────┐
│  Backup Recovery Codes                    │
├─────────────────────────────────────────┤
│  Save these codes in a safe place.      │
│  Each code can be used ONCE.            │
│                                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ 1234-5678│ │ 9012-3456│ │ 7890-1234│  │
│  ├──────────┤ ├──────────┤ ├──────────┤  │
│  │ 5678-9012│ │ 3456-7890│ │ 1234-5678│  │
│  ├──────────┤ ├──────────┤ ├──────────┤  │
│  │ 9012-3456│ │ 7890-1234│ │ 5678-9012│  │
│  ├──────────┤ ├──────────┤ ├──────────┤  │
│  │ 3456-7890│ │ 1234-5678│ │ 9012-3456│  │
│  └──────────┘ └──────────┘ └──────────┘  │
│                                          │
│  [🖨️ Print]  [💾 Save to File]  [Done]  │
└─────────────────────────────────────────┘
```

### 3.5 Integrity Verification UI

```
┌─────────────────────────────────────────┐
│  Application Integrity Check              │
├─────────────────────────────────────────┤
│  [⠋] Verifying application binary...     │
│  [✓] Binary hash: SHA3-256 verified     │
│                                          │
│  [⠋] Verifying configuration...         │
│  [✓] Config signature: Ed25519 valid    │
│                                          │
│  Last verified: 2026-04-05 10:30:00      │
│  Status: 🟢 All checks passed           │
│                                          │
│  [🔍 Details]  [🔄 Re-verify]  [OK]    │
└─────────────────────────────────────────┘
```

### 3.6 MFA Method Selector

```
┌─────────────────────────────────────────┐
│  MFA Verification Required              │
├─────────────────────────────────────────┤
│  Operation: Sign document               │
│  Required role: SIGNATORY              │
│                                          │
│  Select verification method:            │
│                                          │
│  [🔐 FIDO2]          [⏱️ TOTP]        │
│  Touch your key      Enter 6-digit code │
│                                          │
│  [📝 Backup Code]                       │
│  Enter one-time code                    │
│                                          │
│  Token: [______]                       │
│                                          │
│          [Cancel]  [Confirm]            │
└─────────────────────────────────────────┘
```

### 3.7 Security Preset Indicator

| Пресет | Цвет | Описание |
|--------|------|----------|
| 🔴 Legacy | Красный | RSA-PSS-4096 + AES-256-GCM + PBKDF2 |
| 🟡 Standard | Жёлтый | Ed25519 + AES-256-GCM + Argon2id |
| 🟢 Paranoid | Зелёный | Ed25519 + ML-DSA-65 + AES-256-GCM + ChaCha20 |
| 🟣 PQC | Фиолетовый | ML-DSA-65 + AES-256-GCM + Argon2id |

---

## 4. DocumentView — Визуализация Бумаги

### 4.1 Рендеринг в редакторе

| Элемент | Визуализация |
|---------|--------------|
| **Текст** | Пропорциональный шрифт (зависит от CPI) |
| **Bold** | Жирный текст + жирный на печать |
| **Italic** | Курсив + курсив на печать |
| **Subscript/Superscript** | Смещение + соответствующая команда ESC/P |
| **Линии перфорации** | Пунктирная серая линия (-10 мм) |
| **Границы листа** | Сплошная тонкая линия |
| **Конверт** | Полупрозрачное очертание под текстом |

### 4.2 Шрифты

| Режим принтера | Шрифт в UI | ESC/P команда |
|----------------|------------|---------------|
| Draft | Courier New 10cpi | ESC x 0 |
| Roman (NLQ) | Courier New Bold | ESC x 1 + ESC k 0 |
| Sans Serif (NLQ) | Arial Monospace | ESC x 1 + ESC k 1 |

### 4.3 Валидация символов кодировки

```python
class CodepageValidator:
    """Проверяет поддержку символов в выбранной кодовой странице."""
    
    def validate_text(self, text: str) -> List[CharValidationResult]:
        results = []
        for char in text:
            if char in self._supported_chars:
                results.append(CharValidationResult(char, None, True))
            else:
                replacement = self._replacements.get(char)
                results.append(CharValidationResult(char, replacement, False))
        return results
```

**Примеры замен:**
- `ё` → `е`, `Ё` → `Е`
- `—` → `-`, `–` → `-`
- `"` → `"`, `"` → `"`
- `№` → `N`

### 4.4 Double-Height Indicator

Для `CharSize.DOUBLE_HEIGHT` следующая строка в сетке помечается как shadow row (пропускается при печати).

---

## 5. Form Designer (Super Docs)

### 5.1 Открытие

- Кнопка **"📋 Super Docs"** в MainToolbar
- Открывается как вкладка в CardFileTabBar

### 5.2 Layout дизайнера

```
┌──────────┬─────────────────────────────┬──────────┐
│ Tree     │      ESC/P Grid Canvas      │ Field    │
│ Panel    │      (сетка выбранного      │ Palette  │
│ (левая)  │       типа бумаги)           │ (правая) │
├──────────┤                               ├──────────┤
│ 📁 DVN   │  ┌─────────────────────┐      │ [TEXT]   │
│  ├── I   │  │                     │      │ [NUMBER] │
│  ├── II  │  │  [Field A]         │      │ [DATE]   │
│  └── III │  │  [    Field B    ]  │      │ [DROP]   │
│ 📁 INV   │  │                     │      │ [TABLE]  │
│  └── I   │  └─────────────────────┘      │ [SIGN]   │
│          │                               │ [QR]     │
└──────────┴───────────────────────────────┴──────────┘
```

### 5.3 Tree Panel — Дерево форм по индексам

**Иерархия:** `ROOT_CODE → SUBTYPE → SERIES → CUSTOM → SEQUENCE`

```
📁 DVN (Verbal Note)
  ├── 📁 44 (Subtype)
  │     ├── 📁 K53 (Series)
  │     │     ├── 📄 I
  │     │     ├── 📄 II
  │     │     └── 📄 III
  │     └── 📁 K54
  │           └── 📄 I
  └── 📁 45
        └── 📁 K60
              └── 📄 I

📁 INV (Invoice)
  └── 📁 I
        └── 📄 I
```

**Функции:**
- Drag-and-drop для переупорядочивания
- Двойной клик — открыть форму
- Контекстное меню (создать, удалить, копировать)

### 5.4 Field Palette — Палитра полей

| Иконка | Тип | Описание |
|--------|-----|----------|
| [TEXT] | TEXT_INPUT | Текстовое поле |
| [NUMBER] | NUMBER_INPUT | Числовое поле |
| [DATE] | DATE_INPUT | Дата |
| [DROP] | DROPDOWN | Выпадающий список |
| [TABLE] | TABLE | Таблица |
| [SIGN] | SIGNATURE | Поле подписи |
| [STAMP] | STAMP | Штамп |
| [BARCODE] | BARCODE | Штрих-код |
| [QR] | QR | QR-код |

**Drag-and-drop:** Поля перетаскиваются на Canvas

### 5.5 Property Panel

```
┌─────────────────────┐
│ Field Properties    │
├─────────────────────┤
│ Field ID: [____]    │
│ Label: [________]   │
│                     │
│ Position:           │
│ X: [__]  Y: [__]   │
│ Width: [__] chars  │
│ Height: [__] rows  │
│                     │
│ [✓] Required       │
│                     │
│ Validation:         │
│ Pattern: [____]     │
│ Min: [_]  Max: [_] │
│                     │
│ [🗑️ Delete]        │
└─────────────────────┘
```

### 5.6 ESC/P Grid Canvas

**Размеры сеток:**

| Формат | Столбцы | Строки | DPI |
|--------|---------|--------|-----|
| A4 Letter | 80 | 66 | 60 |
| Wide Tractor | 132 | 66 | 60 |
| Envelope DL | 40 | 15 | 60 |
| Envelope C5 | 60 | 25 | 60 |

**Функции:**
- Snap-to-grid (привязка к символьной сетке)
- 8 Resize Handles (углы и стороны)
- Field Overlap Warning (перекрытие полей)
- ESC/P Live Preview Panel

### 5.7 Resize Handles

```
┌─────────────────────────────┐
│ nw    n    ne               │
│                             │
│ w   [Field]   e            │
│                             │
│ sw    s    se               │
└─────────────────────────────┘
```

- Угловые: меняют оба размера
- Боковые: меняют только ширину
- Верх/низ: меняют только высоту
- Минимум: 1×1 символ

### 5.8 Preview Panel

```
┌─────────────────────────────────────────┐
│ ESC/P Preview                           │
├─────────────────────────────────────────┤
│                                         │
│   1B 45 1B 78 30 1B 50 ...              │
│                                         │
│   ┌─────────────────────────┐          │
│   │  Document preview       │          │
│   │  ████████████████████   │          │
│   │  ██ Field A       ██    │          │
│   └─────────────────────────┘          │
│                                         │
│   [Refresh]  [Print Test]              │
└─────────────────────────────────────────┘
```

---

## 6. SideBar

### 6.1 Режимы отображения

#### Режим 1: Секции (Sections Mode)

```
┌──────────┐
│ [=] 🔍   │  <- Кнопка сворачивания + поиск
├──────────┤
│ DOCUMENTS│  <- Секция (раскрыта)
│ 📄 Doc1  │
│ 📄 Doc2  │
│ ➕ New...│
├──────────┤
│ TEMPLATES│  <- Секция (свернута)
│ ▸        │
├──────────┤
│ BLANKS   │  <- Секция (свернута)
│ ▸        │
├──────────┤
│ SUPER DOCS│ <- Секция для форм
│ 📋 Form1 │
│ ➕ New...│
└──────────┘
```

#### Режим 2: Единое дерево (Tree Mode)

```
┌──────────┐
│ [=] 🔍   │
├──────────┤
│ 📁 Root  │
│ ├──📄 D1 │
│ ├──📄 D2 │
│ ├──📁 F1 │
│ │  └──📋│
│ └──📋 F2 │
└──────────┘
```

### 6.2 Переключение режимов

- Пункт меню `View → SideBar Mode → Sections / Tree`
- Запоминается в настройках

### 6.3 Поиск

- Поле поиска в верхней части SideBar
- Фильтрация в реальном времени
- Поиск по имени, типу, содержимому

### 6.4 SideBar Synchronization (только Special Mode)

```
┌──────────┐
│ [=] 🔍  ⟳│  <- Индикатор синхронизации
├──────────┤
│ 📄 Doc1  │  <- Синхронизировано
│ 📄 Doc2  │  <- Синхронизировано
│ ⚡ Doc3  │  <- Ожидает синхронизации
└──────────┘
```

**Функции:**
- Синхронизация между окнами
- Drag-and-drop между окнами
- Индикатор статуса синхронизации

### 6.5 Иконки по типам файлов

| Расширение | Иконка | Описание |
|------------|--------|----------|
| `.fxsd` | 📄 | Документ |
| `.fxsd.enc` | 🔒 | Зашифрованный документ |
| `.fxstpl` | 📋 | Шаблон формы |
| `.fxsblank` | 🔐 | Защищённый бланк |
| `.escp` | 🖨️ | ESC/P команды |
| `.escps` | 📜 | ESC/P скрипт |

---

## 7. StatusBar — Индикаторы

### 7.1 Однострочный режим (ширина ≥ 1024px)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Ln 12, Col 45 │ 12 CPI │ PC866 │ Tractor │ 🔒 Standard │ Page 2/5 │ 100% │ [3] │
└─────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Двухстрочный режим (ширина < 1024px)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Ln 12, Col 45 │ Page 2/5 │ 🔒 Standard │ [3]                         │
│ 12 CPI │ PC866 │ Tractor │ 100%                                        │
└─────────────────────────────────────────────────────────────────────────┘
```

### 7.3 Индикаторы (цветные, не зависят от темы)

| Индикатор | Значение | Цвет |
|-----------|----------|------|
| ● | Modified (несохранённые изменения) | 🟠 Оранжевый |
| 🔒 | Encrypted | 🟢 Зелёный |
| 👁️ | Read-only | ⚪ Серый |
| [n] | Непрочитанные toast'ы | 🔵 Синий |

### 7.4 Разделители

Вертикальные разделители `|` между группами индикаторов:

```
Ln 12, Col 45 │ 12 CPI │ PC866 │ Tractor │ 🔒 Standard │ Page 2/5 │ 100% │ [3]
              ^        ^       ^         ^             ^          ^      ^
```

### 7.5 Workflow индикаторы (для STRUCTURED_FORM)

```
┌─────────────────────────────────────────────────────────────┐
│ [DRAFT] ──▶ [FILLED] ──▶ [VALIDATED] ──▶ [APPROVED] ──▶ [SIGNED]│
│  🔵          ⚪           ⚪            ⚪         ⚪          │
│  Role: OPERATOR                                             │
└─────────────────────────────────────────────────────────────┘
```

- Текущее состояние: ● (заполненный круг)
- Пройденные: ✓
- Будущие: ○ (пустой круг)

### 7.6 Role Badge

| Роль | Цвет |
|------|------|
| OPERATOR | 🔵 Синий |
| EDITOR | 🟢 Зелёный |
| SUPERVISOR | 🟠 Оранжевый |
| SIGNATORY | 🔴 Красный |

---

## 8. Toast Notification System

### 8.1 Позиция

- Правый нижний угол экрана
- Очередь до 6 сообщений
- Авто-закрытие через 30 секунд

### 8.2 Типы toast

| Иконка | Тип | Пример |
|--------|-----|--------|
| 💾 | Info | "Auto-saved Document1.fxsd" |
| ⚠️ | Warning | "Character 'ё' replaced with 'е'" |
| ✅ | Success | "Printed successfully" |
| ❌ | Error | "Print failed: Printer offline" |
| 🔄 | Progress | "Encrypting... 45%" |

### 8.3 Toast Panel (при hover на [n])

```
┌─────────────────────────────┐
│ Notifications [6]          │
├─────────────────────────────┤
│ 💾 Auto-saved Doc1.fxsd    │
│ ⏱️ 2 min ago              │
├─────────────────────────────┤
│ ⚠️ Character replaced      │
│ ⏱️ 5 min ago              │
├─────────────────────────────┤
│ ...                         │
├─────────────────────────────┤
│ [📌 Pin all]  [🗑️ Clear]   │
└─────────────────────────────┘
```

### 8.4 Индикатор [n]

- В самом правом краю StatusBar
- Hover — разворачивается панель с 6 последними toast'ами
- Click — все toast'ы продлеваются на 30 секунд

---

## 9. Session Lock

### 9.1 Триггеры блокировки

1. **Auto-lock** — после N минут бездействия (настраивается в Settings)
2. **Manual lock** — через Tools → Lock Session
3. **System sleep** — автоматическая блокировка

### 9.2 Экран блокировки

```
┌─────────────────────────────────────────┐
│                                         │
│         🔒 Session Locked               │
│                                         │
│    Document is protected and hidden.    │
│                                         │
│    ┌─────────────────────────────┐     │
│    │  Enter credentials:         │     │
│    │                             │     │
│    │  Password: [______________]  │     │
│    │                             │     │
│    │  Method:                    │     │
│    │  [🔐 FIDO2] [⏱️ TOTP]      │     │
│    │                             │     │
│    │  Token: [______]            │     │
│    │                             │     │
│    │     [🔓 Unlock]            │     │
│    └─────────────────────────────┘     │
│                                         │
│    Locked at: 10:30:00                 │
│    Auto-lock in: 5 min                 │
└─────────────────────────────────────────┘
```

### 9.3 Auto-Lock Settings Dialog

```
┌─────────────────────────────────────────┐
│  Auto-Lock Settings                       │
├─────────────────────────────────────────┤
│  Enable auto-lock: [✓]                  │
│                                          │
│  Lock after: [15] minutes of inactivity │
│                                          │
│  Triggers:                               │
│  [✓] System sleep                       │
│  [✓] Screen saver activation            │
│  [ ] Remote desktop disconnect          │
│                                          │
│  Require MFA to unlock: [✓]             │
│                                          │
│          [Cancel]  [Save]                 │
└─────────────────────────────────────────┘
```

---

## 10. Paper Setup Dialog

### 10.1 Диалог настройки бумаги

```
┌─────────────────────────────────────────┐
│  Paper Setup                              │
├─────────────────────────────────────────┤
│  Presets:                                 │
│  [📄 A4] [📄 Letter] [🖨️ Tractor▼]     │
│                                          │
│  Custom Dimensions:                       │
│  Width:  [210] mm   Height: [305] mm    │
│                                          │
│  Perforation:                             │
│  [☑] Enable perforation lines            │
│  Margin: [10] mm from each side          │
│                                          │
│  Preview:                                 │
│  ┌─────────────────────────────┐         │
│  │  ┌─────────────────────┐   │         │
│  │  │.....text area...... │   │         │
│  │  └─────────────────────┘   │         │
│  │  --- perforation ---       │         │
│  │  ┌─────────────────────┐   │         │
│  │  │.....text area...... │   │         │
│  │  └─────────────────────┘   │         │
│  └─────────────────────────────┘         │
├─────────────────────────────────────────┤
│  [Save as Preset]    [Cancel] [OK]      │
└─────────────────────────────────────────┘
```

### 10.2 Типы бумаги

| Тип | Размер | Примечание |
|-----|--------|------------|
| A4 | 210×297 мм | Стандартный лист |
| Letter | 216×279 мм | US стандарт |
| Legal | 216×356 мм | US legal |
| Tractor Full | 210×305 мм | Тракторная бумага |
| Tractor Half | 210×152.5 мм | Половинный лист |
| Tractor Triplet | 210×101.6 мм | Треть листа |
| Envelope DL | 220×110 мм | Конверт |
| Envelope C5 | 229×162 мм | Конверт |
| Custom | Пользовательский | Задать вручную |

---

## 11. Template Library UI

### 11.1 Template Import Dialog

```
┌─────────────────────────────────────────────────────────┐
│  Import Templates                                         │
├─────────────────────────────────────────────────────────┤
│  Source: [🖨️ Floppy Drive ▼]                             │
│           └─ Floppy Drive (/media/floppy)               │
│           └─ USB Drive (/media/usb)                     │
│           └─ External HDD (/media/external)              │
│                                                         │
│  Detected templates:                                    │
│  ┌─────────────────────────────────────────────────┐   │
│  │ [✓] invoice_v2.fxstpl     ✓ Signature valid    │   │
│  │ [✓] verbal_note_2026.fxstpl ✓ Signature valid    │   │
│  │ [✗] old_template.fxstpl     ✗ Invalid signature  │   │
│  │     [⚠️ Trust chain: Unknown key]                │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  Trust chain verification:                              │
│  [✓] Master key signature                             │
│  [✓] Timestamp within 365 days                        │
│  [?] Key not in whitelist (add?)                      │
│                                                         │
│  [📋 Preview]  [🔍 Details]  [📥 Import Selected]     │
└─────────────────────────────────────────────────────────┘
```

### 11.2 Trust Chain Verification Dialog

```
┌─────────────────────────────────────────┐
│  Trust Chain Verification                 │
├─────────────────────────────────────────┤
│  Template: invoice_v2.fxstpl            │
│                                          │
│  Certificate chain:                       │
│  ┌─────────────────────────────────┐     │
│  │ 🟢 Root CA (self-signed)        │     │
│  │    └── 🟢 Master Key (Ed25519)  │     │
│  │        └── 🟢 Template Key       │     │
│  │            └── 🟢 This Template │     │
│  └─────────────────────────────────┘     │
│                                          │
│  Public key fingerprint:                 │
│  SHA256: a3f2b8...e9d1                   │
│                                          │
│  Signed: 2026-03-15 10:30:00 UTC         │
│  Expires: 2027-03-15 10:30:00 UTC        │
│                                          │
│  [➕ Add to Whitelist]  [❌ Reject]      │
└─────────────────────────────────────────┘
```

### 11.3 Floppy Optimizer Dialog

```
┌─────────────────────────────────────────┐
│  Optimize for Floppy                    │
├─────────────────────────────────────────┤
│  Template size: 1.8 MB                  │
│  Floppy capacity: 1.44 MB                │
│  Status: 🟡 Too large                   │
│                                          │
│  Optimization options:                   │
│  [✓] Remove high-res thumbnail          │
│  [✓] Minimize JSON (compact mode)        │
│  [ ] Remove field descriptions          │
│  [ ] Compress embedded fonts            │
│                                          │
│  Estimated size after optimization:     │
│  🟢 1.28 MB (fits on floppy)            │
│                                          │
│  [Preview Changes]  [💾 Optimize]        │
└─────────────────────────────────────────┘
```

### 11.4 Template Preview Panel

```
┌─────────────────────────────────────────┐
│  Template Preview                         │
├─────────────────────────────────────────┤
│  📋 Invoice v2.0                        │
│  ┌─────────────────────────┐             │
│  │ [Thumbnail preview]     │             │
│  │                         │             │
│  │  Invoice #: [______]  │             │
│  │  Date: [________]       │             │
│  │                         │             │
│  └─────────────────────────┘             │
│                                          │
│  Fields: 15                              │
│  Signature: ✓ Valid                       │
│  Created: 2026-03-15                      │
│                                          │
│  [📄 New Document]  [🖨️ Print Blank]      │
└─────────────────────────────────────────┘
```

---

## 12. Form History & Autocomplete

### 12.1 AutocompleteEntry Widget

```
┌─────────────────────────────┐
│ Client: [ООО Ром▓]        │
│        ┌─────────────────┐│
│        │ ООО Ромашка    ↑││
│        │ ООО Ромашковый ││
│        │ ООО Романтика  ↓││
│        │ ...            ││
│        └─────────────────┘│
└─────────────────────────────┘
```

**Функции:**
- Показывает до 5 предложений
- Сортирует по частоте использования
- Фильтрует по введённому тексту
- Выбор стрелками + Enter

### 12.2 PrefillDialog

```
┌─────────────────────────────────────────┐
│  Prefill from Previous Document           │
├─────────────────────────────────────────┤
│  Series: DVN-44-K53                       │
│  Source: DVN-44-K53-VIII                  │
│                                          │
│  Select fields to copy:                   │
│  ┌─────────────────────────────────┐     │
│  │ [✓] recipient_name              │     │
│  │     "Министерство иностранных дел"     │
│  │                                 │     │
│  │ [✓] sender_name                   │     │
│  │     "Главный департамт"              │     │
│  │                                 │     │
│  │ [ ] document_number               │     │
│  │                                 │     │
│  │ [✓] priority_level                │     │
│  │     "High"                        │     │
│  └─────────────────────────────────┘     │
│                                          │
│  [Select All]  [Deselect All]             │
│                                          │
│          [Cancel]  [Apply Prefill]        │
└─────────────────────────────────────────┘
```

### 12.3 Cross-Document Lookup Panel

```
┌─────────────────────────────────────────┐
│  Cross-Document Lookup                    │
├─────────────────────────────────────────┤
│  Field: recipient_name                    │
│  Series: DVN-44-K53-*                       │
│                                          │
│  Previous values:                         │
│  ┌─────────────────────────────────┐     │
│  │ Document         │ Value          │     │
│  │ ─────────────────────────────────│     │
│  │ DVN-44-K53-IX    │ Министерство  │     │
│  │ DVN-44-K53-VIII  │ Департамент   │     │
│  │ DVN-44-K53-VII   │ Управление    │     │
│  └─────────────────────────────────┘     │
│                                          │
│  [🔄 Refresh]  [📋 Use Selected]          │
└─────────────────────────────────────────┘
```

---

## 13. Approval Workflow UI

### 13.1 Field Comment Widget

```
┌─────────────────────────────────────────┐
│  Amount: [150000.00]  💬                 │
│                                          │
│  Hover on 💬:                           │
│  ┌─────────────────────────┐             │
│  │ 💬 EDITOR, 2 hours ago │             │
│  │ "Check VAT calculation"│             │
│  │ [✓ Mark resolved]      │             │
│  └─────────────────────────┘             │
└─────────────────────────────────────────┘
```

### 13.2 Add Comment Dialog

```
┌─────────────────────────────────────────┐
│  Add Comment to Field                     │
├─────────────────────────────────────────┤
│  Field: amount                            │
│  Current value: 150000.00                 │
│                                          │
│  Your comment:                            │
│  ┌─────────────────────────────────┐     │
│  │                                 │     │
│  │                                 │     │
│  │                                 │     │
│  └─────────────────────────────────┘     │
│                                          │
│  Severity:                               │
│  [○ Info] [○ Warning] [● Error]          │
│                                          │
│  [✓] Notify next role                   │
│                                          │
│          [Cancel]  [Add Comment]          │
└─────────────────────────────────────────┘
```

### 13.3 RejectDialog

```
┌─────────────────────────────────────────┐
│  ⚠️ Reject Document                       │
├─────────────────────────────────────────┤
│  Current state: VALIDATED               │
│  Your role: SUPERVISOR                  │
│                                          │
│  Reject to:                              │
│  [● DRAFT (back to author)]             │
│  [○ FILLED (back to editor)]            │
│                                          │
│  Reason:                                  │
│  ┌─────────────────────────────────┐     │
│  │ Amount doesn't match contract   │     │
│  │ attachments.                      │     │
│  └─────────────────────────────────┘     │
│                                          │
│  MFA Required:                           │
│  Token: [______]                        │
│                                          │
│  [Cancel]  [🔴 Reject Document]           │
└─────────────────────────────────────────┘
```

### 13.4 Workflow Timeline

```
┌─────────────────────────────────────────────────────────────┐
│ Document Workflow                                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  DRAFT    FILLED    VALIDATED   APPROVED    SIGNED          │
│    ✓         ✓          ●                                    │
│   ───▶     ───▶        ───▶      ───▶       ───▶            │
│  09:00    10:30       14:00                                    │
│                                                              │
│  Role: SUPERVISOR                                            │
│                                                              │
│  History:                                                    │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ 14:00 SUPERVISOR → VALIDATED ✓ MFA verified         │    │
│  │ 10:30 EDITOR → FILLED ✓                             │    │
│  │ 09:00 OPERATOR → DRAFT                               │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  [📋 View Comments]  [🔄 Transition]                         │
└─────────────────────────────────────────────────────────────┘
```

### 13.5 Simple Mode Checkbox

```
┌─────────────────────────────────────────┐
│  View → Approval Workflow → [✓] Simple Mode
└─────────────────────────────────────────┘
```

**Simple Mode:** Только основные переходы (DRAFT ↔ SIGNED)  
**Full Mode:** Все промежуточные состояния

### 13.6 RoleBadgeWidget

```
┌────────────────────────┐
│  🔴 SIGNATORY          │
└────────────────────────┘
```

- Оператор: 🔵 Синий
- Редактор: 🟢 Зелёный
- Супервизор: 🟠 Оранжевый
- Подписант: 🔴 Красный

---

## 14. Barcode & QR UI

### 14.1 BarcodeTypeSelector

```
┌─────────────────────────────────────────┐
│  Barcode Type                             │
├─────────────────────────────────────────┤
│  Mode:                                    │
│  [● Software (preview/export)]          │
│  [○ Hardware (FX-890 ESC/P)]            │
│                                          │
│  Type: [EAN-13 ▼]                       │
│        ├─ EAN-13 (Software + Hardware)  │
│        ├─ EAN-8 (Software + Hardware)     │
│        ├─ CODE39 (Software + Hardware)    │
│        ├─ CODE128 (Software only) ⚠️      │
│        └─ PDF417 (Software only) ⚠️       │
│                                          │
│  Data: [1234567890123]                   │
│                                          │
│  [Preview]  [Insert]                      │
└─────────────────────────────────────────┘
```

### 14.2 BarcodeSettingsPanel

```
┌─────────────────────────────────────────┐
│  Barcode Settings                         │
├─────────────────────────────────────────┤
│  Width module: [3] dots (180 dpi)        │
│  Height: [100] (1/180")                 │
│  HRI (human readable): [Below ▼]          │
│  Check digit: [✓] Auto-calculate          │
│                                          │
│  Position:                               │
│  X: [10] cols  Y: [5] rows              │
│                                          │
│  Preview:                                │
│  ┌─────────────────────────┐             │
│  │ ||||||| |||| |||||||   │             │
│  │ 1234567890123          │             │
│  └─────────────────────────┘             │
└─────────────────────────────────────────┘
```

### 14.3 QRCodeSettingsDialog

```
┌─────────────────────────────────────────┐
│  QR Code Settings                         │
├─────────────────────────────────────────┤
│  Data:                                    │
│  ┌─────────────────────────────────┐     │
│  │ https://example.com/doc/123    │     │
│  └─────────────────────────────────┘     │
│                                          │
│  Error correction: [Medium ▼]           │
│  Version: [Auto] (min 2)               │
│  Size: [100] px                          │
│                                          │
│  Preview:                                │
│  ┌─────────────────┐                     │
│  │ ████████████████│                     │
│  │ ██ ▄▄▄▄▄▄▄▄▄ ██│                     │
│  │ ██ █ ▄▄▄▄ █ ██│                     │
│  │ ██ █ █   █ █ ██│                     │
│  │ ██ █ ▀▀▀▀ █ ██│                     │
│  │ ██ ▀▀▀▀▀▀▀▀▀ ██│                     │
│  │ ████████████████│                     │
│  └─────────────────┘                     │
│                                          │
│  [Export PNG]  [Insert]                   │
└─────────────────────────────────────────┘
```

### 14.4 BarcodeTypeConflictWarning

```
┌─────────────────────────────────────────┐
│  ⚠️ Barcode Type Conflict                 │
├─────────────────────────────────────────┤
│  Selected: CODE128                        │
│  Hardware mode: Not supported            │
│                                          │
│  Options:                                │
│  [● Render as image (software)]          │
│  [○ Switch to CODE39 (hardware)]         │
│  [○ Cancel]                               │
│                                          │
│  Note: CODE128 will be exported as PNG   │
│  and printed as graphics (slower).      │
└─────────────────────────────────────────┘
```

---

## 15. Multi-Window Support

### 15.1 Window Manager

```
┌─────────────────────────────────────────┐
│  Window → Manage Windows                    │
├─────────────────────────────────────────┤
│  Open windows:                            │
│  ┌─────────────────────────────────┐     │
│  │ [✓] Document1.fxsd (active)    │     │
│  │ [ ] Document2.fxsd             │     │
│  │ [ ] Template Designer          │     │
│  └─────────────────────────────────┘     │
│                                          │
│  Arrange:                               │
│  [Tile Horizontally] [Tile Vertically]   │
│  [Cascade] [Minimize All]                │
│                                          │
│  [New Window]                             │
└─────────────────────────────────────────┘
```

### 15.2 Drag-Drop Between Windows

**Drag:** Документ из SideBar  
**Drop:** Другое окно (title bar или документ area)

**Индикатор:**
```
┌─────────────────┐
│ ➕ Move here    │
│ ➕ Copy here    │
│ ➖ Cancel       │
└─────────────────┘
```

### 15.3 Document Transfer Dialog

```
┌─────────────────────────────────────────┐
│  Transfer Document                          │
├─────────────────────────────────────────┤
│  Document: Document1.fxsd                 │
│  From: Window 1                           │
│                                          │
│  To: [Window 2 ▼]                        │
│      └─ Window 2                          │
│      └─ Window 3                          │
│      └─ New Window                        │
│                                          │
│  Mode:                                    │
│  [● Move (close in source)]             │
│  [○ Copy (keep in both)]                 │
│                                          │
│  [Sync with source: ✓] (Special Mode)   │
│                                          │
│          [Cancel]  [Transfer]             │
└─────────────────────────────────────────┘
```

### 15.4 Window Sync Indicator

```
┌─────────────────────────────────────────┐
│  Document1.fxsd  [● Synced]            │
└─────────────────────────────────────────┘
```

- [●] Синхронизировано (зелёный)
- [⟳] Синхронизация... (синий)
- [⚠] Конфликт (оранжевый)
- [✗] Оффлайн (серый)

---

## 16. Диалоги

### 16.1 FindReplaceDialog

```
┌─────────────────────────────────────────┐
│  Find and Replace                         │
├─────────────────────────────────────────┤
│  Find: [____________]  [🔍 Find Next]    │
│  Replace: [__________]  [🔄 Replace]       │
│                       [🔄 Replace All]    │
│                                          │
│  Options:                                │
│  [✓] Match case                         │
│  [ ] Whole words only                    │
│  [ ] Regular expressions                 │
│  [✓] Search in current document only    │
│                                          │
│  Direction: [● Down] [○ Up]              │
│                                          │
│  [Cancel]                                 │
└─────────────────────────────────────────┘
```

### 16.2 GotoDialog

```
┌─────────────────────────────────────────┐
│  Go To...                                 │
├─────────────────────────────────────────┤
│  [Line] [Page]                           │
│                                          │
│  Line number: [    ] / 1234              │
│                                          │
│  Or select:                              │
│  ┌─────────────────────────┐             │
│  │ Bookmark 1              │             │
│  │ Bookmark 2              │             │
│  │ ───────────────────────  │             │
│  │ Start of document       │             │
│  │ End of document         │             │
│  └─────────────────────────┘             │
│                                          │
│          [Cancel]  [Go To]                │
└─────────────────────────────────────────┘
```

### 16.3 BookmarksDialog

```
┌─────────────────────────────────────────┐
│  Bookmarks                                │
├─────────────────────────────────────────┤
│  ┌─────────────────────────────────────┐ │
│  │ Name          │ Line │ Added       │ │
│  │ ─────────────────────────────────── │ │
│  │ Section 1     │ 45   │ 10:30       │ │
│  │ Important     │ 128  │ 10:45       │ │
│  │ todo fix      │ 256  │ 11:00       │ │
│  └─────────────────────────────────────┘ │
│                                          │
│  [➕ Add] [✏️ Rename] [🗑️ Delete]        │
│  [➡ Go To]  [🔍 Find]  [❌ Close]        │
└─────────────────────────────────────────┘
```

### 16.4 PageSetupDialog

```
┌─────────────────────────────────────────┐
│  Page Setup                               │
├─────────────────────────────────────────┤
│  [Margins] [Paper] [Layout]              │
│                                          │
│  Margins:                                │
│  Top:    [25.0] mm                      │
│  Bottom: [25.0] mm                      │
│  Left:   [20.0] mm                      │
│  Right:  [20.0] mm                      │
│                                          │
│  Orientation: [● Portrait] [○ Landscape]  │
│                                          │
│  Line spacing: [1/6" ▼]                  │
│  Skip perforation: [0] lines            │
│                                          │
│  [Cancel]  [Default]  [OK]              │
└─────────────────────────────────────────┘
```

---

## 17. План Реализации

### Фаза 1: Основа (Неделя 1-2)
- [ ] MainWindow с SideBar (два режима: sections/tree)
- [ ] CardFileTabBar с индикаторами Modified/Encrypted
- [ ] DocumentView с поддержкой тем
- [ ] Paper Toolbar с выбором типа бумаги
- [ ] Paper Setup Dialog
- [ ] Ruler с табуляторами
- [ ] Navigator (навигация по страницам)

### Фаза 2: Рендеринг (Неделя 3)
- [ ] Визуализация бумаги (перфорация, границы)
- [ ] Пропорциональные шрифты (Draft, Roman, Sans Serif)
- [ ] Formatting (Bold, Italic, Subscript, Superscript)
- [ ] Character validation и замены
- [ ] Double-height row indicators

### Фаза 3: Security UI (Неделя 4)
- [ ] AuthWindow (Password + MFA selection)
- [ ] FIDO2SetupDialog (QR code, touch)
- [ ] TOTPSetupDialog (QR code, verification)
- [ ] BackupCodesDialog (10 codes)
- [ ] Security HealthCheck Dialog
- [ ] AppIntegrityChecker UI
- [ ] ConfigIntegrityChecker UI

### Фаза 4: Режимы (Неделя 5)
- [ ] Тумблер Normal/Special Mode
- [ ] HealthCheck при входе в Special Mode
- [ ] MFA Authentication Dialog
- [ ] Конвертация документов между режимами
- [ ] RoleSwitchDialog

### Фаза 5: Form Designer (Недели 6-8)
- [ ] Form Designer Window
- [ ] ESC/P Grid Canvas (все типы сеток)
- [ ] Tree Panel (дерево по индексам)
- [ ] Field Palette (drag-and-drop)
- [ ] Property Panel
- [ ] Preview Panel
- [ ] Resize Handles (8 маркеров, snap-to-grid)
- [ ] Field Overlap Warning

### Фаза 6: Workflow & History (Недели 9-10)
- [ ] Workflow Timeline
- [ ] Role Badge Widget
- [ ] Field Comment Widget
- [ ] AddCommentDialog
- [ ] RejectDialog
- [ ] Workflow Annotation Panel
- [ ] AutocompleteEntry
- [ ] PrefillDialog
- [ ] Cross-Document Lookup Panel

### Фаза 7: Template & Barcode (Недели 11-12)
- [ ] TemplateImportDialog
- [ ] TemplateExportDialog
- [ ] TrustChainVerificationDialog
- [ ] FloppyOptimizerDialog
- [ ] BarcodeTypeSelector
- [ ] BarcodeSettingsPanel
- [ ] QRCodeSettingsDialog

### Фаза 8: Session & Multi-Window (Недели 13-14)
- [ ] Session Lock Screen
- [ ] AutoLockSettingsDialog
- [ ] Window Manager
- [ ] DragDropController
- [ ] DocumentTransferDialog
- [ ] WindowSyncService
- [ ] SideBar Synchronization

### Фаза 9: Полировка (Неделя 15)
- [ ] Toast Notification System
- [ ] StatusBar разделители и стабильность
- [ ] FindReplaceDialog
- [ ] GotoDialog
- [ ] BookmarksDialog
- [ ] PageSetupDialog
- [ ] FormatToolbar placeholder
- [ ] Все диалоги с валидацией

---

## Приложение A: Цветовые схемы индикаторов (не зависят от темы)

| Индикатор | Цвет | HEX |
|-----------|------|-----|
| Modified | Оранжевый | #FFA500 |
| Encrypted | Зелёный | #00FF00 |
| Read-only | Серый | #808080 |
| Toast [n] | Синий | #0080FF |
| Error | Красный | #FF0000 |
| Warning | Жёлтый | #FFFF00 |
| Success | Зелёный | #00C000 |
| Info | Синий | #0080FF |

## Приложение B: Размеры ESC/P Grid Canvas

| Формат | Столбцы | Строки | Ширина (mm) | Высота (mm) |
|--------|---------|--------|-------------|-------------|
| A4 | 80 | 66 | 203.2 | 279.4 |
| Letter | 80 | 66 | 203.2 | 279.4 |
| Wide Tractor | 132 | 66 | 335.3 | 279.4 |
| Envelope DL | 40 | 15 | 101.6 | 63.5 |
| Envelope C5 | 60 | 25 | 152.4 | 105.8 |

## Приложение C: Иерархия индексов документов

```
ROOT_CODE (например, DVN, INV)
  └── SUBTYPE (например, 44, 45)
        └── SERIES (например, K53, K54)
              └── CUSTOM (опционально)
                    └── SEQUENCE (I, II, III...)
```

**Пример:** `DVN-44-K53-IX`

---

**Конец документа**
