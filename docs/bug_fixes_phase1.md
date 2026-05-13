# Исправление критических багов Phase 1

## Сводка

Выполнено исправление **12 критических багов** из плана (53 проблемы всего). Все тесты проходят (414/414).

## Исправленные проблемы

### 1. DocumentView утечки памяти (document_view.py)

#### 1.1 Утечка callback'ов (циклические ссылки) [118-127]
**Решение:** В `destroy()` методе добавлена явная очистка всех callback'ов:
```python
self._on_change_callback = None
self._on_selection_callback = None
self._on_cursor_callback = None
self._on_insert_mode_callback = None
self._on_zoom_callback = None
```

#### 1.2 Отключение встроенного undo Tkinter [224-246]
**Решение:** `undo=False` в `Text()` widget - используем только `CommandHistoryService`.

#### 1.3 Placeholder событие не очищается [408-417]
**Решение:** Добавлено отслеживание bind ID:
```python
self._placeholder_bind_id: str | None = None
# ...
if self._placeholder_bind_id:
    self._text_widget.unbind("<FocusIn>", self._placeholder_bind_id)
```

#### 1.4 Утечка событий при уничтожении (bind) [596-598]
**Решение:** Создан список bind'ов и `unbind_all()` в `destroy()`:
```python
self._bind_ids: List[Tuple[str, str]] = []
# ...
for event_pattern, bind_id in self._bind_ids:
    self._text_widget.unbind(event_pattern, bind_id)
```

### 2. MainWindow исправления (main_window.py)

#### 2.1 Утечка DocumentView при исключении [540-567]
**Решение:** Добавлен `try/finally` в `remove_document()` - гарантирует удаление из словаря даже при ошибке.

#### 2.2 FormatToolbar не сбрасывается в None [1057-1063]
**Решение:** `try/finally` в `_destroy_format_toolbar()` - `self._format_toolbar = None` всегда выполняется.

#### 2.3 Замыкания в меню закладок [943-952]
**Решение:** Использование `functools.partial` вместо lambda:
```python
from functools import partial
return partial(self._goto_bookmark, name)
```

### 3. DocumentController (document_controller.py)

#### 3.1 CommandHistory никогда не очищается [479-491]
**Решение:** В `close()` добавлена очистка истории:
```python
if self._command_history is not None:
    self._command_history.clear(self._document.id)
```

### 4. AppController (app_controller.py)

#### 4.1 Не очищаются сервисы при ошибке [109-154]
**Решение:** Добавлены `try/except` в `new_document()` и `open_document()` с очисткой ресурсов при ошибке.

### 5. CommandHistoryService (command_history_service.py)

#### 5.1 WordCommandGrouper без лимита буфера [126-270]
**Решение:** Добавлен лимит 1000 символов:
```python
MAX_BUFFER_SIZE: int = 1000

def _ensure_buffer_size(self) -> None:
    if len(self._buffer) >= self.MAX_BUFFER_SIZE:
        logger.warning(f"WordCommandGrouper buffer exceeded {self.MAX_BUFFER_SIZE}")
        self.flush()
```

### 6. Tabs (tabs.py)

#### 6.1 Race condition в remove_tab [303-329]
**Решение:** Добавлен `return True` с комментарием `break after list modification` для ясности.

## Результаты проверки

```bash
# Тесты
pytest tests/unit/view/ tests/unit/controller/ tests/unit/services/
# 414 passed

# Типы
mypy --strict src/view/document_view.py src/view/main_window.py \
    src/controller/document_controller.py src/controller/app_controller.py \
    src/view/tabs.py src/services/command_history_service.py
# Success: no issues found

# Линтинг
ruff check <исправленные файлы>
# All checks passed!
```

## Следующий шаг

Phase 2: Исправление 18 проблем высокого приоритета (degradation UX).
