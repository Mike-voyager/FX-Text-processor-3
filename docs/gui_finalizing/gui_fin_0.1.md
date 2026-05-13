# 📋 План финализации GUI FX Text Processor 3
## Версия 0.1 | Полная реализация UI_SPECIFICATION_upd_2.md

---

## 📊 Статистика проекта

| Параметр | Значение |
|----------|----------|
| **Всего файлов в GUI** | ~66+ |
| **Уже реализовано** | ~40 (60%) |
| **Нужно создать** | ~25 файлов |
| **Нужно доработать** | ~5 файлов |
| **Dead code для архивации** | ~50 файлов |
| **Общее время** | ~18 недель |

---

## 🎯 Цель
Полная реализация всех компонентов из UI_SPECIFICATION_upd_2.md согласно GUI_ARCHITECTURE_1.0

---

## 🗓️ Фаза 0: Подготовка (Неделя 1)

### Задачи:
1. **Архивация dead code**
   - Перенести `backup_code/` → `archive/backup/`
   - Перенести `src/view/` → `archive/view_legacy/`

2. **Инфраструктура тем**
   - Создать `src/gui/themes/` пакет
   - Перенести `src/gui/themes.py` → `src/gui/themes/__init__.py`

**Результат:** Чистый проект, готовый к разработке

---

## 🗓️ Фаза 1: Фундамент (Недели 2-3)

### Цель: Базовые компоненты без которых приложение не работает

| # | Файл | Статус | Сложность | Описание |
|---|------|--------|-----------|----------|
| 1 | `src/gui/themes/retro_green.py` | Создать | ⭐⭐⭐ | Ретро зеленая тема (VT100 style) |
| 2 | `src/gui/themes/amber.py` | Создать | ⭐⭐⭐ | Янтарная тема |
| 3 | `src/gui/themes/phosphor_white.py` | Создать | ⭐⭐⭐ | Фосфорно-белая тема |
| 4 | `src/gui/themes/high_contrast.py` | Создать | ⭐⭐ | Высокий контраст |
| 5 | `src/gui/themes/classic_green.py` | Создать | ⭐⭐⭐ | Классическая зеленая |
| 6 | `src/gui/themes/__init__.py` | Создать | ⭐⭐ | ThemeManager (перенос) |
| 7 | `src/gui/core/bindings.py` | Создать | ⭐⭐ | Model-View binding система |
| 8 | `src/gui/components/composite/main_toolbar.py` | Создать | ⭐⭐⭐ | Главная панель [New][Open][Save][Print] |
| 9 | `src/gui/security/auth_window.py` | Создать | ⭐⭐⭐⭐ | Окно входа Password + MFA selector |
| 10 | `src/gui/components/primitive/button.py` | Создать | ⭐⭐ | Button с поддержкой тем |
| 11 | `src/gui/components/primitive/label.py` | Создать | ⭐ | Label с поддержкой тем |
| 12 | `src/gui/components/primitive/entry.py` | Создать | ⭐⭐ | Entry с валидацией и темами |
| 13 | `src/gui/components/primitive/checkbox.py` | Создать | ⭐⭐ | Checkbox с поддержкой тем |

**Результат:** Приложение запускается с окном входа, видны основные кнопки, работают темы

---

## 🗓️ Фаза 2: Security UI (Недели 4-5)

### Цель: Полный Security flow

| # | Файл | Статус | Сложность | Описание |
|---|------|--------|-----------|----------|
| 14 | `src/gui/security/session_lock.py` | Создать | ⭐⭐⭐ | SessionLockScreen с wipe UI |
| 15 | `src/gui/dialogs/backup_codes_dialog.py` | Создать | ⭐⭐ | Отображение резервных кодов |
| 16 | `src/gui/dialogs/crypto_profile_dialog.py` | Создать | ⭐⭐⭐ | Выбор Security Preset (Legacy/Standard/Paranoid/PQC) |
| 17 | `src/gui/dialogs/auto_lock_settings_dialog.py` | Создать | ⭐⭐ | Настройки авто-блокировки |
| 18 | `src/gui/security/mode_toggle.py` | Создать | ⭐⭐ | UI тумблера Normal/Special режимов |

**Результат:** Полный Security flow: вход → MFA → режимы → блокировка

---

## 🗓️ Фаза 3: Workflow (Недели 6-7)

### Цель: Approval Workflow UI

| # | Файл | Статус | Сложность | Описание |
|---|------|--------|-----------|----------|
| 19 | `src/gui/workflow/protocols.py` | Создать | ⭐⭐ | WorkflowUIProtocol |
| 20 | `src/gui/workflow/state_manager.py` | Создать | ⭐⭐⭐⭐ | WorkflowStateManager с MFA-gated transitions |
| 21 | `src/gui/workflow/transition_dialog.py` | Создать | ⭐⭐⭐ | Диалог перехода состояния (DRAFT→FILLED→VALIDATED→APPROVED→SIGNED) |
| 22 | `src/gui/dialogs/role_switch_dialog.py` | Создать | ⭐⭐ | Смена роли с MFA (OPERATOR/EDITOR/SUPERVISOR/SIGNATORY) |
| 23 | `src/gui/dialogs/add_comment_dialog.py` | Создать | ⭐⭐ | Добавление комментария к полю с severity (INFO/WARNING/ERROR) |

**Результат:** Workflow работает: роли → состояния → MFA → комментарии

---

## 🗓️ Фаза 4: Document Features (Недели 8-9)

### Цель: Удобство работы с документами

| # | Файл | Статус | Сложность | Описание |
|---|------|--------|-----------|----------|
| 24 | `src/gui/dialogs/goto_dialog.py` | Создать | ⭐⭐ | Переход к строке/странице |
| 25 | `src/gui/dialogs/bookmarks_dialog.py` | Создать | ⭐⭐⭐ | Управление закладками |
| 26 | `src/gui/dialogs/prefill_dialog.py` | Создать | ⭐⭐⭐ | Prefill из предыдущего документа по иерархии индексов |
| 27 | `src/gui/components/form_field.py` | Создать | ⭐⭐⭐ | Composite FormField widget с валидацией |
| 28 | `src/gui/services/autocomplete_service.py` | Создать | ⭐⭐⭐ | Form History lookup (4 уровня иерархии) |

**Результат:** Полноценный editing experience

---

## 🗓️ Фаза 5: Template Library (Недели 10-11)

### Цель: Импорт и управление шаблонами

| # | Файл | Статус | Сложность | Описание |
|---|------|--------|-----------|----------|
| 29 | `src/gui/dialogs/template_import_dialog.py` | Создать | ⭐⭐⭐⭐ | Импорт шаблонов с Trust Chain verification |
| 30 | `src/gui/dialogs/trust_chain_dialog.py` | Создать | ⭐⭐⭐ | Просмотр цепочки доверия (Root CA → Master Key → Template Key) |
| 31 | `src/gui/dialogs/floppy_optimizer_dialog.py` | Создать | ⭐⭐⭐ | Оптимизация для дискет (удаление thumbnail, compact JSON) |

**Результат:** Template Library полностью работает

---

## 🗓️ Фаза 6: Barcode/QR (Неделя 12)

### Цель: Поддержка штрих-кодов и QR

| # | Файл | Статус | Сложность | Описание |
|---|------|--------|-----------|----------|
| 32 | `src/gui/dialogs/barcode_dialog.py` | Создать | ⭐⭐⭐ | Настройка штрих-кодов |
| 33 | `src/gui/dialogs/qr_code_dialog.py` | Создать | ⭐⭐⭐ | Настройка QR-кодов |

**Результат:** Barcode и QR поддержка

---

## 🗓️ Фаза 7: Services & Polish (Недели 13-14)

### Цель: Глобальные сервисы

| # | Файл | Статус | Сложность | Описание |
|---|------|--------|-----------|----------|
| 34 | `src/gui/services/window_manager.py` | Создать | ⭐⭐⭐⭐ | Multi-window support |
| 35 | `src/gui/services/notification_service.py` | Создать | ⭐⭐ | Notification service |
| 36 | `src/gui/services/drag_drop_service.py` | Создать | ⭐⭐⭐ | Drag-and-drop между окнами |
| 37 | `src/gui/services/sync_service.py` | Создать | ⭐⭐⭐ | SideBar synchronization между окнами |
| 38 | `src/gui/form_designer/preview_panel.py` | Создать | ⭐⭐⭐ | ESC/P Preview Panel с hex дампом |

**Результат:** Все сервисы работают, Multi-window support

---

## 🗓️ Фаза 8: Form Designer Polish (Недели 15-16)

### Цель: Полный Form Designer как в спецификации

| # | Файл | Статус | Сложность | Описание |
|---|------|--------|-----------|----------|
| 39 | `src/gui/form_designer/grid_canvas.py` | Создать | ⭐⭐⭐⭐⭐ | ESC/P Grid Canvas строго 80×66, snap-to-grid |
| 40 | `src/gui/modes/protocols.py` | Создать | ⭐⭐ | DocumentModeRenderer Protocol |
| 41 | `src/gui/modes/free_form/__init__.py` | Создать | ⭐ | FreeForm mode пакет |
| 42 | `src/gui/modes/free_form/renderer.py` | Создать | ⭐⭐⭐ | FreeForm mode renderer |
| 43 | `src/gui/modes/free_form/toolbar.py` | Создать | ⭐⭐ | FreeForm toolbar |
| 44 | `src/gui/modes/structured_form/__init__.py` | Создать | ⭐ | StructuredForm mode пакет |
| 45 | `src/gui/modes/structured_form/renderer.py` | Создать | ⭐⭐⭐ | StructuredForm mode renderer |
| 46 | `src/gui/modes/structured_form/toolbar.py` | Создать | ⭐⭐ | StructuredForm toolbar |
| 47 | `src/gui/components/toolbar_section.py` | Создать | ⭐⭐ | ToolbarSection compound widget |

**Результат:** Form Designer полностью соответствует спецификации

---

## 🗓️ Фаза 9: Финальные доработки (Недели 17-18)

### Цель: Финальные штрихи

| # | Файл | Действие | Сложность | Описание |
|---|------|----------|-----------|----------|
| 48 | `src/gui/dialogs/document_transfer_dialog.py` | Создать | ⭐⭐ | Перенос документа между окнами |
| 49 | `src/gui/dialogs/window_manager_dialog.py` | Создать | ⭐⭐ | Управление окнами |
| 50 | `src/gui/core/lifecycle.py` | Создать | ⭐⭐ | Mount/unmount lifecycle manager |
| 51 | `src/gui/components/format_toolbar.py` | Доработать | ⭐⭐⭐ | Расширить функционал (CPI, Bold, Italic, Subscript, Superscript) |
| 52 | `src/gui/views/main_window.py` | Доработать | ⭐⭐ | Интеграция AuthWindow, MainToolbar |
| 53 | `src/gui/views/document_view.py` | Доработать | ⭐⭐⭐ | Интеграция DocumentModeRenderer Protocol |
| 54 | `src/gui/views/status_bar.py` | Доработать | ⭐⭐ | Интеграция Toast Panel на hover [n] |

---

## 📁 Финальная структура проекта

```
src/gui/
├── core/                          # ✅ + 🆕
│   ├── protocols.py               # ✅
│   ├── registry.py                # ✅
│   ├── events.py                  # ✅
│   ├── exceptions.py              # ✅
│   ├── error_handler.py           # ✅
│   ├── lifecycle.py               # 🆕
│   └── bindings.py                # 🆕
│
├── components/                   # ⚠️ + 🆕
│   ├── base/                      # ✅
│   ├── primitive/                 # 🆕 (5 файлов)
│   │   ├── button.py
│   │   ├── label.py
│   │   ├── entry.py
│   │   └── checkbox.py
│   ├── compound/                  # 🆕 (2 файла)
│   │   ├── form_field.py
│   │   └── toolbar_section.py
│   └── composite/                 # ⚠️ Доработать
│       ├── main_toolbar.py        # 🆕
│       ├── format_toolbar.py      # ⚠️
│       ├── paper_toolbar.py       # ✅
│       ├── document_view.py       # ⚠️
│       ├── side_bar.py            # ✅
│       └── status_bar.py          # ⚠️
│
├── modes/                         # ❌ → 🆕
│   ├── protocols.py               # 🆕
│   ├── free_form/                 # 🆕
│   │   ├── __init__.py
│   │   ├── renderer.py
│   │   └── toolbar.py
│   └── structured_form/           # 🆕
│       ├── __init__.py
│       ├── renderer.py
│       ├── toolbar.py
│       └── widgets/               # ✅ (уже есть)
│
├── workflow/                      # ⚠️ + 🆕
│   ├── protocols.py               # 🆕
│   ├── state_manager.py          # 🆕
│   ├── transition_dialog.py       # 🆕
│   ├── role_badge.py             # ✅
│   ├── field_comment_widget.py   # ✅
│   └── workflow_timeline_dialog.py # ✅
│
├── security/                      # ⚠️ + 🆕
│   ├── auth_window.py            # 🆕
│   ├── session_lock.py           # 🆕
│   ├── mode_toggle.py            # 🆕
│   ├── mfa_gate.py               # ✅
│   ├── mode_manager.py            # ✅
│   └── auth_overlay.py           # ✅
│
├── dialogs/                       # ⚠️ + 🆕
│   ├── base_dialog.py            # ✅
│   ├── template_import_dialog.py # 🆕
│   ├── trust_chain_dialog.py     # 🆕
│   ├── floppy_optimizer_dialog.py # 🆕
│   ├── goto_dialog.py            # 🆕
│   ├── bookmarks_dialog.py       # 🆕
│   ├── backup_codes_dialog.py    # 🆕
│   ├── barcode_dialog.py         # 🆕
│   ├── qr_code_dialog.py         # 🆕
│   ├── crypto_profile_dialog.py  # 🆕
│   ├── prefill_dialog.py         # 🆕
│   ├── add_comment_dialog.py     # 🆕
│   ├── role_switch_dialog.py     # 🆕
│   ├── auto_lock_settings_dialog.py # 🆕
│   ├── document_transfer_dialog.py # 🆕
│   └── window_manager_dialog.py  # 🆕
│   └── ... (остальные 15 диалогов ✅)
│
├── themes/                        # ❌ → 🆕
│   ├── __init__.py                # 🆕
│   ├── retro_green.py             # 🆕
│   ├── amber.py                   # 🆕
│   ├── phosphor_white.py          # 🆕
│   ├── high_contrast.py           # 🆕
│   └── classic_green.py           # 🆕
│
├── services/                      # ⚠️ + 🆕
│   ├── toast_service.py          # ✅
│   ├── window_manager.py         # 🆕
│   ├── autocomplete_service.py  # 🆕
│   ├── notification_service.py  # 🆕
│   ├── drag_drop_service.py      # 🆕
│   └── sync_service.py           # 🆕
│
├── form_designer/                 # ⚠️ + 🆕
│   ├── designer_tab.py           # ✅
│   ├── grid_canvas.py            # 🆕
│   ├── field_palette_widget.py   # ✅
│   ├── tree_panel.py             # ✅
│   ├── property_panel.py         # ✅
│   ├── resize_handles.py          # ✅
│   ├── preview_panel.py          # 🆕
│   └── converters/               # ✅
│
├── renderers/                     # ✅
│   ├── protocols.py               # ✅
│   ├── free_form_renderer.py     # ✅
│   ├── structured_form_renderer.py # ✅
│   ├── form_canvas.py             # ✅
│   └── factory.py                 # ✅
│
├── commands/                      # ✅
│   ├── command.py                 # ✅
│   ├── command_stack.py            # ✅
│   ├── text_commands.py            # ✅
│   ├── design_commands.py          # ✅
│   └── macro_commands.py           # ✅
│
├── layout/                        # ✅
│   ├── main_layout.py              # ✅
│   ├── paned_layout.py             # ✅
│   └── layout_constants.py         # ✅
│
└── views/                         # ⚠️ Доработать
    ├── main_window.py            # ⚠️
    ├── document_view.py          # ⚠️
    ├── side_bar.py                # ✅
    ├── status_bar.py              # ⚠️
    ├── card_file_tab_bar.py       # ✅
    └── auth_overlay.py            # ✅
```

---

## ✅ Критерии готовности

Проект считается завершённым когда:

1. ✅ Все 17 разделов UI_SPECIFICATION_upd_2.md реализованы
2. ✅ Все диалоги из спецификации работают
3. ✅ Все 5 тем оформления доступны и переключаются
4. ✅ Workflow полностью функционален (DRAFT→FILLED→VALIDATED→APPROVED→SIGNED)
5. ✅ Form Designer имеет strict ESC/P Grid 80×66 с snap-to-grid
6. ✅ Multi-window support работает (Window Manager)
7. ✅ `mypy --strict src/gui/` проходит без ошибок
8. ✅ Тесты coverage ≥90% для новых модулей
9. ✅ Dead code архивирован в `archive/`
10. ✅ Все компоненты интегрированы в единый flow

---

## 📊 Таймлайн

| Фаза | Длительность | Файлов | Сложность | Ключевые результаты |
|------|--------------|--------|-----------|---------------------|
| 0 - Подготовка | 1 неделя | ~50 | ⭐ | Чистый проект |
| 1 - Фундамент | 2 недели | ~13 | ⭐⭐⭐ | Auth + Themes + MainToolbar |
| 2 - Security | 2 недели | ~5 | ⭐⭐⭐ | Полный Security flow |
| 3 - Workflow | 2 недели | ~5 | ⭐⭐⭐⭐ | Workflow State Machine |
| 4 - Documents | 2 недели | ~5 | ⭐⭐⭐ | Editing features |
| 5 - Templates | 2 недели | ~3 | ⭐⭐⭐⭐ | Template Library |
| 6 - Barcode/QR | 1 неделя | ~2 | ⭐⭐⭐ | Barcode support |
| 7 - Services | 2 недели | ~5 | ⭐⭐⭐⭐ | Multi-window |
| 8 - Designer | 2 недели | ~9 | ⭐⭐⭐⭐⭐ | Strict ESC/P Grid |
| 9 - Polish | 2 недели | ~7 | ⭐⭐ | Финальная интеграция |

**ИТОГО: ~18 недель, ~54 файла**

---

## 🚀 Приоритеты запуска

Если нужно сократить сроки:

### Обязательно (Must Have)
- Фаза 0: Подготовка
- Фаза 1: AuthWindow + MainToolbar + Themes
- Фаза 2: Session Lock + Backup Codes + Crypto Profile
- Фаза 9: Финальная интеграция

### Важно (Should Have)
- Фаза 3: Workflow State Manager
- Фаза 4: Goto + Bookmarks + Autocomplete
- Фаза 8: Strict ESC/P Grid Canvas

### Желательно (Nice to Have)
- Фаза 5: Template Library
- Фаза 6: Barcode/QR
- Фаза 7: Multi-window support

---

## 📝 Примечания

1. **Каждый файл** должен проходить `mypy --strict`
2. **Каждый модуль** должен иметь ≥90% test coverage
3. **Все диалоги** должны поддерживать ESC для закрытия
4. **Все сервисы** должны быть thread-safe
5. **Все темы** должны поддерживать светлую/тёмную вариации

---

**Создано:** 2026-04-11  
**Версия:** 0.1  
**Статус:** Ожидает начала реализации
