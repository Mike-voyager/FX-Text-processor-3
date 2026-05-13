# FX Text Processor 3 — UI Specification Document (Updated)

**Версия:** 1.1  
**Дата:** Апрель 2026  
**Статус:** Финальная спецификация для реализации  
**Автор:** На основе требований пользователя

---

## Содержание

1. [Архитектура Режимов](#1-архитектура-режимов)
2. [Главное Окно (MainWindow)](#2-главное-окно-mainwindow)
3. [DocumentView — Визуализация Бумаги](#3-documentview--визуализация-бумаги)
4. [Form Designer (Super Docs)](#4-form-designer-super-docs)
5. [StatusBar — Индикаторы](#5-statusbar--индикаторы)
6. [Toast Notification System](#6-toast-notification-system)
7. [Session Lock](#7-session-lock)
8. [Paper Setup Dialog](#8-paper-setup-dialog)
9. [План Реализации](#9-план-реализации)

---

## 1. Архитектура Режимов

### 1.1 Режимы Приложения

| Режим | MFA | Доступ | Иконка в меню |
|-------|-----|--------|---------------|
| **Normal Mode** | Нет | FREE_FORM + STRUCTURED_FORM (без Audit/Workflow) | 🟢 Normal |
| **Special Mode** | Да | Полный доступ + Security features | 🔴 Special |

**Тумблер:** `Tools → Mode: [🟢 Normal ▓▓▓░░░]`

### 1.2 Конвертация Документов

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
│          │  ┌───────────────────────────────────────────┐  │
│          │  │ Paper Toolbar (тип бумаги + Paper Setup)  │  │
│          │  ├───────────────────────────────────────────┤  │
│          │  │ Ruler (с табуляторами и маркерами полей)  │  │
│          │  ├───────────────────────────────────────────┤  │
│          │  │                                           │  │
│          │  │   DocumentView с WYSIWYG рендерингом      │  │
│          │  │   (пропорциональный шрифт, линии          │  │
│          │  │    перфорации, границы листа)             │  │
│          │  │                                           │  │
│          │  ├───────────────────────────────────────────┤  │
│          │  │ Navigator (◀◀ Стр / Стр ▶▶)              │  │
│          │  └───────────────────────────────────────────┘  │
├──────────┴────────────────────────────────────────────────┤
│  StatusBar: Ln/Col │ CPI │ CodePage │ Paper │ Security │ Page │ Zoom │ [n] │
│  StatusBar [2 строки при узком окне]                       │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Paper Toolbar (новая панель)

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

## 3. DocumentView — Визуализация Бумаги

### 3.1 Рендеринг в редакторе

| Элемент | Визуализация |
|---------|--------------|
| **Текст** | Пропорциональный шрифт (зависит от CPI) |
| **Bold** | Жирный текст + жирный на печать |
| **Italic** | Курсив + курсив на печать |
| **Subscript/Superscript** | Смещение + соответствующая команда ESC/P |
| **Линии перфорации** | Пунктирная серая линия (-10 мм) |
| **Границы листа** | Сплошная тонкая линия |
| **Конверт** | Полупрозрачное очертание под текстом |

### 3.2 Шрифты

| Режим принтера | Шрифт в UI | ESC/P команда |
|----------------|-----------|---------------|
| Draft | Courier New 10cpi | ESC x 0 |
| Roman (NLQ) | Courier New Bold | ESC x 1 + ESC k 0 |
| Sans Serif (NLQ) | Arial Monospace | ESC x 1 + ESC k 1 |

---

## 4. Form Designer (Super Docs)

### 4.1 Открытие
- Кнопка **"📋 Super Docs"** в MainToolbar
- Открывается как вкладка в CardFileTabBar

### 4.2 Layout дизайнера

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
│  └── I   │  └─────────────────────┘      │ ...      │
└──────────┴───────────────────────────────┴──────────┘
```

### 4.3 Боковые панели

**Левая (Tree Panel)** — Дерево форм по индексам:
- Иерархия: ROOT_CODE → SUBTYPE → SERIES → CUSTOM → SEQUENCE
- Drag-and-drop для переупорядочивания
- Двойной клик — открыть форму

**Правая (Field Palette)** — Палитра полей:
- Drag-and-drop на Canvas
- Типы: TEXT_INPUT, NUMBER_INPUT, DATE_INPUT, DROPDOWN, TABLE, SIGNATURE, STAMP, BARCODE, QR

---

## 5. StatusBar — Индикаторы

### 5.1 Однострочный режим (ширина ≥ 1024px)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Ln 12, Col 45 │ 12 CPI │ PC866 │ Tractor │ 🔒 Standard │ Page 2/5 │ 100% │ [3] │
└─────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Двухстрочный режим (ширина < 1024px)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Ln 12, Col 45 │ Page 2/5 │ 🔒 Standard │ [3]                         │
│ 12 CPI │ PC866 │ Tractor │ 100%                                        │
└─────────────────────────────────────────────────────────────────────────┘
```

### 5.3 Индикаторы (цветные, не зависят от темы)

| Индикатор | Значение | Цвет |
|-----------|----------|------|
| ● | Modified (несохранённые изменения) | 🟠 Оранжевый |
| 🔒 | Encrypted | 🟢 Зелёный |
| 👁️ | Read-only | ⚪ Серый |
| [n] | Непрочитанные toast'ы | 🔵 Синий |

**Toast индикатор [n]:**
- В самом правом краю StatusBar
- Hover — разворачивается панель с 6 последними toast'ами
- Click — все toast'ы продлеваются на 30 секунд

---

## 6. Toast Notification System

### 6.1 Позиция
- Правый нижний угол экрана
- Очередь до 6 сообщений
- Авто-закрытие через 30 секунд

### 6.2 Типы toast

| Иконка | Тип | Пример |
|--------|-----|--------|
| 💾 | Info | "Auto-saved Document1.fxsd" |
| ⚠️ | Warning | "Character 'ё' replaced with 'е'" |
| ✅ | Success | "Printed successfully" |
| ❌ | Error | "Print failed: Printer offline" |
| 🔄 | Progress | "Encrypting... 45%" |

---

## 7. Session Lock

### 7.1 Триггеры блокировки

1. **Auto-lock** — после N минут бездействия (настраивается в Settings)
2. **Manual lock** — через Tools → Lock Session
3. **System sleep** — автоматическая блокировка

### 7.2 Экран блокировки

```
┌─────────────────────────────────────────┐
│                                         │
│         🔒 Session Locked               │
│                                         │
│    Enter credentials to unlock:         │
│                                         │
│    Password: [________________]         │
│                                         │
│    [🔐 FIDO2] [⏱️ TOTP] [📝 Code]      │
│                                         │
│    Token: [______]                      │
│                                         │
│         [Unlock]                        │
│                                         │
└─────────────────────────────────────────┘
```

---

## 8. Paper Setup Dialog

### 8.1 Диалог настройки бумаги

```
┌─────────────────────────────────────────┐
│  Paper Setup                            │
├─────────────────────────────────────────┤
│  Presets:                               │
│  [📄 A4] [📄 Letter] [🖨️ Tractor▼]     │
│                                         │
│  Custom Dimensions:                     │
│  Width:  [210] mm   Height: [305] mm   │
│                                         │
│  Perforation:                           │
│  [☑] Enable perforation lines           │
│  Margin: [10] mm from each side         │
│                                         │
│  Preview:                               │
│  ┌─────────────────────────────┐       │
│  │  ┌─────────────────────┐   │       │
│  │  │.....text area...... │   │       │
│  │  └─────────────────────┘   │       │
│  │  --- perforation ---       │       │
│  └─────────────────────────────┘       │
├─────────────────────────────────────────┤
│  [Save as Preset]    [Cancel] [OK]    │
└─────────────────────────────────────────┘
```

---

## 9. План Реализации (Приоритеты)

### Фаза 1: Основа (Неделя 1-2)
- ✅ MainWindow с SideBar (два режима отображения: sections/tree)
- ✅ CardFileTabBar с индикаторами Modified/Encrypted
- ✅ DocumentView с поддержкой тем
- ✅ Paper Toolbar с выбором типа бумаги
- ✅ Paper Setup Dialog

### Фаза 2: Рендеринг (Неделя 3)
- ✅ Визуализация бумаги (перфорация, границы)
- ✅ Пропорциональные шрифты (Draft, Roman, Sans Serif)
- ✅ Formatting (Bold, Italic, Subscript, Superscript)
- ✅ Ruler с табуляторами

### Фаза 3: Режимы (Неделя 4)
- ✅ Тумблер Normal/Special Mode
- ✅ HealthCheck при входе в Special Mode
- ✅ MFA Authentication Dialog
- ✅ Конвертация документов между режимами

### Фаза 4: Form Designer (Недели 5-7)
- ✅ Form Designer Window
- ✅ ESC/P Grid Canvas (все типы сеток)
- ✅ Tree Panel (дерево по индексам)
- ✅ Field Palette (drag-and-drop)
- ✅ Property Panel
- ✅ Resize Handles (8 маркеров, snap-to-grid)

### Фаза 5: Workflow & Security (Недели 8-9)
- ✅ Workflow Indicator в StatusBar
- ✅ Role Indicator
- ✅ Transition Dialog (MFA)
- ✅ Approval Workflow UI

### Фаза 6: Полировка (Неделя 10)
- ✅ Toast Notification System
- ✅ Session Lock
- ✅ Multi-Window Support
- ✅ Drag-and-drop между окнами
- ✅ SideBar Synchronization

---

**Конец документа**
