# UI Integration Summary

## Выполненные изменения

### 1. MainWindow - замена ttk.Notebook на CardFileTabBar

**Файл:** `src/view/main_window.py`

- Заменен `ttk.Notebook` на `CardFileTabBar` из `src/view/tabs`
- Изменен `_create_notebook()` → `_create_tab_bar()`
- Обновлены методы:
  - `add_document()` - теперь использует `CardFileTabBar.add_tab()`
  - `remove_document()` - теперь использует `CardFileTabBar.remove_tab()`
  - `_on_tab_changed()` - принимает `UUID` вместо `tk.Event`
  - `_set_active_document()` - новый метод для управления видимостью DocumentView
- Добавлен callback `_on_insert_mode_change()` для синхронизации статуса Insert/OVR

### 2. DocumentView - добавление Ruler и Navigator

**Файл:** `src/view/document_view.py`

- Добавлены импорты `Ruler` и `Navigator`
- Добавлены атрибуты:
  - `_ruler` - линейка с табуляторами
  - `_navigator` - навигатор по страницам
- Новые методы:
  - `_create_ruler()` - создает линейку с настройками из документа
  - `_create_navigator()` - создает навигатор
  - `_on_page_change()` - callback для навигатора
  - `_on_insert_key()` - обработка клавиши Insert
  - `update_ruler()` - обновление настроек линейки
  - `update_navigator()` - обновление информации о страницах
- Обновлен `_setup_layout()` - теперь используется grid:
  - row 0: Ruler (линейка)
  - row 1: Text widget + scrollbars
  - row 2: Horizontal scrollbar
  - row 3: Navigator (навигация)
- Обновлен `set_insert_mode()` - использует `overwrite` config для Tkinter Text

### 3. StatusBar интеграция

Статус-бар уже был расширен ранее, теперь он связан с DocumentView:
- `set_insert_mode()` - вызывается при переключении Insert/OVR
- `set_zoom()` - готов к использованию
- `set_spell_status()` - готов к использованию

### 4. Новые пункты меню

Добавлены пункты в меню:
- **Редактирование** → "Перейти к..." (Ctrl+G) - GotoDialog
- **Формат** → "Настройка страницы..." - PageSetupDialog

Добавлены методы:
- `_on_goto()` - открывает GotoDialog
- `_on_page_setup()` - открывает PageSetupDialog

### 5. Type fixes

- `CardFileTabBar.__init__` - тип `parent` изменен на `Any` для совместимости с `tk.Tk`
- `DocumentView.set_insert_mode` - добавлен `# type: ignore` для `overwrite` config

## Проверка

```bash
# Type checking
mypy --strict src/view/main_window.py src/view/document_view.py src/view/tabs.py
# Success: no issues found

# Tests
pytest tests/unit/view/ -v
# 46 passed
```

## Следующие шаги

1. Реализовать полноценные тесты для `CardFileTabBar`, `Ruler`, `Navigator`
2. Интегрировать `PrintPreviewDialog` в меню Файл
3. Добавить обработку закладок (Bookmarks)
4. Связать Zoom с DocumentView (масштабирование текста)
