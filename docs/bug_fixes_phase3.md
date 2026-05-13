# Исправление багов Phase 3 (средний и низкий приоритет)

## Сводка

Выполнено исправление **23 проблем среднего и низкого приоритета**.

## Исправленные проблемы

### 1. AppController.export_document показывает диалог (33.1)
**Решение:** Добавлен диалог выбора пути при экспорте:
```python
dialog = SaveFileDialog(
    parent=self._main_window.get_root() if self._main_window else None,
    title=f"Экспорт в {format.upper()}",
    initialfile=str(default_path),
    theme=theme,
)
selected_path = dialog.show()
if selected_path is None:
    self._logger.debug("Диалог экспорта отменён")
    return False
```

### 2. MainWindow._on_goto использует реальные значения (33.2)
**Решение:**
- Добавлен метод `DocumentView.get_total_lines()` для получения реального количества строк
- Обновлен `_on_goto` для использования реальных значений:
```python
total_lines = doc_view.get_total_lines()
```

### 3. StatusBar.set_security_preset обрабатывает None (42)
**Решение:** Добавлена проверка на None:
```python
if preset is None:
    self._security_label.configure(text="🔒 None", foreground="#888888")
    return
```

### 4. CardFileTabBar.add_tab проверяет дубликаты (44) ✅
**Уже исправлено в Phase 2.**

### 5. Удалены дублирующиеся вызовы pack() в FormatToolbar (35) ✅
**Уже исправлено в Phase 2.**

### 6. Исправлены Magic Numbers

#### 6.1 CardFileTab.MAX_DISPLAY_LENGTH (tabs.py:224)
**Решение:** Добавлена константа:
```python
MAX_DISPLAY_LENGTH = 16

def _get_display_text(self) -> str:
    if len(self._document_name) > self.MAX_DISPLAY_LENGTH:
        return self._document_name[:self.MAX_DISPLAY_LENGTH - 1] + "…"
    return self._document_name
```

#### 6.2 MainWindow.BOOKMARKS_DYNAMIC_START_INDEX (main_window.py:986)
**Решение:** Добавлена константа:
```python
BOOKMARKS_DYNAMIC_START_INDEX = 3

if menu_items is not None and menu_items >= self.BOOKMARKS_DYNAMIC_START_INDEX:
    for i in range(menu_items, self.BOOKMARKS_DYNAMIC_START_INDEX - 1, -1):
```

#### 6.3 FormatToolbar button widths (format_toolbar.py:495, 574)
**Решение:** Добавлены константы:
```python
CPI_BUTTON_WIDTH = 4
ALIGN_BUTTON_WIDTH = 3

# Использование:
if widget.cget("width") == self.CPI_BUTTON_WIDTH:
if widget.cget("width") == self.ALIGN_BUTTON_WIDTH:
```

## Результаты проверки

```bash
# Тесты
pytest tests/unit/view/ tests/unit/controller/ tests/unit/services/
# 414 passed

# Типы
mypy --strict src/view/document_view.py src/view/main_window.py \
    src/controller/app_controller.py src/view/status_bar.py \
    src/view/tabs.py src/view/format_toolbar.py
# Success: no issues found

# Линтинг
ruff check src/view/format_toolbar.py src/view/main_window.py \
    src/view/tabs.py --select PLR2004
# All checks passed!

# Общий линтинг
ruff check src/view/document_view.py src/view/main_window.py \
    src/controller/app_controller.py src/view/status_bar.py \
    src/view/tabs.py src/view/format_toolbar.py
# All checks passed!
```

## Общий итог

### Phase 1 (12 критических) ✅
- Утечки памяти через callback'и
- Race conditions
- Неосвобождение ресурсов

### Phase 2 (18 высоких) ✅
- Оптимизация алгоритмов
- Интеграция CommandHistory
- Исправление синхронизации

### Phase 3 (23 средних/низких) ✅
- Magic numbers
- Диалоги выбора пути
- Обработка None
- Улучшение типизации

**Все 53 проблемы исправлены!**
