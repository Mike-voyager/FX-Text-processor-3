# UI Alignment - Статус реализации

## Реализованные компоненты

### 1. Диалоги (src/view/dialogs/)

#### PageSetupDialog
- Настройка размера страницы (A4, Letter, Legal, Fanfold)
- Ориентация (Портрет/Альбомная)
- Поля (левое, правое, верхнее, нижнее)
- Межстрочный интервал (1/6" или 1/8")

#### GotoDialog
- Вкладки для перехода к строке/странице
- Валидация ввода
- Поддержка горячих клавиш Enter/Escape

#### PrintPreviewDialog
- Предпросмотр документа перед печатью
- Масштабирование (50%, 75%, 100%, 150%, 200%)
- Навигация по страницам
- Кнопка печати

### 2. Компоненты вкладок (src/view/tabs.py)

#### CardFileTab
- Эффект "картотеки": закрытая вкладка как ярлык, открытая как папка
- Визуальная индикация активной вкладки
- Поддержка всех тем оформления

#### CardFileTabBar
- Панель управления вкладками
- Добавление/удаление вкладок
- Переключение между вкладками

### 3. Линейка (src/view/ruler.py)

#### Ruler
- Дюймовые деления с подписями
- Отметка полудюймов
- Маркеры табуляторов (▼)
- Границы полей (красная пунктирная линия)

### 4. Навигатор (src/view/navigator.py)

#### Navigator
- Кнопки ◀◀ Стр / Стр ▶▶
- Индикатор текущей страницы
- Поле ввода номера страницы с переходом по Enter

### 5. Темы (src/view/themes.py)

#### ThemeConfig
- Цветовая схема
- Размер шрифта UI (8-14pt)
- Размер шрифта редактора
- Интервал мигания курсора

#### ThemeManager
- Встроенные темы (classic_green, amber, dos_blue, paper_white, matrix)
- Пользовательские темы на основе существующих
- Сохранение/загрузка пользовательских тем

### 6. Закладки (src/model/bookmark.py)

#### Bookmark
- Имя, позиция (paragraph, run, offset)
- Время создания
- Сериализация в/из JSON

#### BookmarkManager
- Добавление/удаление/обновление закладок
- Получение всех закладок
- Очистка всех закладок

### 7. Расширение StatusBar (src/view/status_bar.py)

Добавлены индикаторы:
- **Insert/OVR** - режим ввода (INS/OVR) ✅ Интегрирован с DocumentView
- **Zoom** - масштаб в процентах
- **Spellcheck** - количество ошибок орфографии (✓ или ⚠ N)

### 8. Исправления PagePrinterService

Изменён порядок колляции:
- Старый: стр1(коп1) → стр1(коп2) → стр2(коп1) → стр2(коп2)
- Новый: стр1(коп1) → стр2(коп1) → стр1(коп2) → стр2(коп2)

### 9. Панель форматирования (src/view/format_toolbar.py)

#### FormatToolbar
- **CPI**: кнопки [10] [12] [15] [17] [20] [Prop]
- **Quality**: dropdown (DRAFT/HSD/UHSD/NLQ)
- **Font**: dropdown (DRAFT/ROMAN/SANS SERIF)
- **CodePage**: dropdown (PC437/PC850/PC866/etc)
- **Alignment**: кнопки [↤] [↔] [↦] [▤]
- **Styles**: кнопки [B] [I] [U] [D²]
- Интеграция с `Document.printer_settings`

### 10. Undo/Redo по слову (src/services/command_history_service.py)

#### WordCommandGrouper
- Группировка последовательных символов слова в одну команду
- Разделители (пробел, пунктуация) завершают группировку
- Пауза > 2 секунд также завершает группировку
- Удаление завершает группировку слова

#### Интеграция с CommandHistory
- `add_text_insert()` — добавление с группировкой по слову
- `add_text_delete()` — добавление удаления
- `get_pending_word()` — текущее накапливаемое слово
- `undo()` автоматически завершает группировку перед отменой

### 11. Диалог управления закладками (src/view/dialogs/bookmarks_dialog.py)

#### BookmarksDialog
- Табличное отображение закладок (имя, позиция, дата создания)
- Двойной клик для перехода к закладке
- Кнопки: Перейти, Переименовать, Удалить, Закрыть
- Подтверждение удаления
- Поддержка всех тем оформления

#### Интеграция с MainWindow
- Меню Закладки → "Управление закладками..."
- Callbacks: on_goto, on_rename, on_delete
- Автоматическое обновление меню после изменений

## Интеграция компонентов (✅ Завершено)

### MainWindow
- Заменен `ttk.Notebook` на `CardFileTabBar` (вкладки в стиле картотеки)
- Добавлена панель форматирования `FormatToolbar` между вкладками и DocumentView
- Добавлены пункты меню: "Перейти к..." (Ctrl+G), "Настройка страницы...", "Предпросмотр..." (Ctrl+Shift+P)
- **Меню Закладки** (`Ctrl+Shift+B`):
  - Добавить закладку... - диалог ввода имени
  - Управление закладками... - заглушка для диалога
  - Динамический список закладок документа
  - Автоматическое обновление при смене документа
- Lifecycle management: FormatToolbar создаётся при активации документа, удаляется при закрытии

### DocumentView
- Добавлен `Ruler` (линейка с табуляторами и полями)
- Добавлен `Navigator` (навигация ◀◀ Стр / Стр ▶▶)
- Горячая клавиша `Insert` для переключения Insert/OVR

### StatusBar интеграция
- `set_insert_mode()` связан с DocumentView.toggle_insert_mode()
- Callback `_on_insert_mode_change` обновляет индикатор при переключении

## Интеграция с Document

- Добавлен `bookmark_manager: BookmarkManager` в Document
- Методы: `add_bookmark()`, `remove_bookmark()`, `get_bookmarks()`
- Поле `is_modified` автоматически обновляется при изменении закладок

### 11. Масштабирование текста (Zoom)

#### DocumentView Zoom Methods
- `get_zoom()` — текущий масштаб в процентах
- `set_zoom(percent)` — установка масштаба (50-200%)
- `zoom_in()` — увеличение на 25%
- `zoom_out()` — уменьшение на 25%
- `zoom_reset()` — сброс к 100%
- `_get_zoomed_font()` — расчёт размера шрифта с учётом масштаба

#### MainWindow Integration
- Меню Вид: Увеличить (Ctrl++), Уменьшить (Ctrl+-), Сбросить (Ctrl+0)
- Callback `_on_zoom_change()` — обновляет StatusBar
- Автоматическая синхронизация при смене документа

#### Constants
- `ZOOM_MIN = 50%`, `ZOOM_MAX = 200%`, `ZOOM_STEP = 25%`
- `BASE_FONT_SIZE = 12pt` — базовый размер шрифта

## Тестирование

Созданы тесты:
- `tests/unit/model/test_bookmark.py` - 14 тестов
- `tests/unit/view/test_themes.py` - 14 тестов
- `tests/unit/view/test_document_view.py` - 27 тестов (включая Zoom)
- `tests/unit/view/test_status_bar.py` - 13 тестов
- `tests/unit/view/test_bookmarks_dialog.py` - 11 тестов

Все тесты проходят:
- 5660+ тестов в проекте
- mypy --strict: нет ошибок
- ruff check: все проверки пройдены

## Следующие шаги

### ✅ Завершено (2026-03-26):
1. **Paragraph LineStyle** - расширение модели для quality, font_family, char_size, line_spacing
   - `src/model/enums.py`: CharSize enum с методами occupies_grid_rows(), is_double_height()
   - `src/model/paragraph.py`: Поля quality, font_family, char_size, line_spacing
   - `src/documents/printing/paragraph_renderer.py`: Полная поддержка LineStyle в ESC/P
   - `src/view/format_toolbar.py`: Per-paragraph методы apply_*_to_selection()
   - 500+ тестов проходят, mypy --strict OK

2. **Рефакторинг** (чистка импортов, унификация API):
   - `src/view/dialogs/page_setup_dialog.py`: Удалены неиспользуемые импорты (ttk, LineSpacing, Orientation, PageSize)
   - `src/model/section.py`: Добавлены aliases `get_printable_width_inches`/`get_printable_height_inches`
   - `src/documents/printing/paragraph_renderer.py`: Убран `hasattr`, используется `getattr` для line_spacing
   - Все 77 тестов paragraph_renderer + section проходят
