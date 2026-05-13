# План реализации Фазы 9: Финальные доработки GUI

**Версия:** 1.0  
**Дата:** 2026-04-15  
**Статус:** Готов к запуску агентов

---

## 🎯 Обзор

Фаза 9 завершает финализацию GUI FX Text Processor 3. Работа разбита на 2 прохода с максимум 6 агентами.

**Ключевые ограничения:**
- Макс. 6 агентов за проход
- Каждый агент запускает `check.sh` перед завершением
- Синхронизационный PR между проходами

---

## 🗓️ Проход 1: Базовые модули (Агенты A1-A3)

### Последовательность

```
A1 (lifecycle.py) ──┐
A2 (format_toolbar) ──┼──► [Синхронизационный PR] ──► Проход 2
A3 (status_bar) ────┘
```

---

### 🔧 Агент A1: Lifecycle Manager

**Цель:** Создать систему управления жизненным циклом GUI компонентов

#### Задание

Создать файл: `src/gui/core/lifecycle.py`

#### Требования

1. **Protocol LifecycleAware:**
   ```python
   class LifecycleAware(Protocol):
       def mount(self, parent: tk.Widget) -> tk.Widget: ...
       def unmount(self) -> None: ...
       def is_mounted(self) -> bool: ...
       def get_widget(self) -> Optional[tk.Widget]: ...
   ```

2. **Класс LifecycleManager:**
   - Отслеживание состояния всех компонентов
   - Регистрация/дерегистрация компонентов
   - Методы: `register()`, `unregister()`, `get_state()`
   - Thread-safe реализация

3. **Контекстный менеджер SafeMount:**
   ```python
   with SafeMount(component, parent) as widget:
       # component смонтирован
   # component размонтирован автоматически
   ```

4. **События жизненного цикла:**
   - `on_mount`, `on_unmount`, `on_destroy` callbacks
   - Сигналы через EventBus

#### Критерии приёмки

- [ ] `mypy --strict src/gui/core/lifecycle.py` проходит
- [ ] Тесты coverage ≥90%
- [ ] Docstrings на русском (Google-style)
- [ ] `check.sh src/gui/core/lifecycle.py` проходит без ошибок

#### Зависимости
Нет

#### Время: 8 часов

---

### 🔧 Агент A2: FormatToolbar Extension

**Цель:** Добавить поддержку Subscript/Superscript в панель форматирования

#### Задание

Изменить файл: `src/gui/components/format_toolbar.py`

#### Требования

1. **Добавить кнопки Subscript/Superscript:**
   - Позиция: после Strikethrough, перед разделителем Barcode
   - Метки: "x₂" (subscript), "x²" (superscript)
   - Toggle-режим (как Bold/Italic)

2. **ESC/P интеграция:**
   ```python
   # ESC/P команды
   ESCAPE = 0x1B
   SO = 0x0E   # Shift Out - superscript
   SI = 0x0F   # Shift In - subscript
   DC4 = 0x14  # Cancel shift
   ```
   - Метод `_apply_script(script_type: str, active: bool)`
   - Callback `on_script_toggle(script_type, active)`

3. **Расширить FORMAT_LABELS:**
   ```python
   FORMAT_LABELS: Final[dict[str, str]] = {
       "bold": "B",
       "italic": "I",
       "underline": "U",
       "strikethrough": "S",
       "subscript": "x₂",      # NEW
       "superscript": "x²",   # NEW
   }
   ```

4. **API методы:**
   ```python
   def set_subscript(self, active: bool) -> None
   def set_superscript(self, active: bool) -> None
   def is_script_active(self, script_type: str) -> bool
   def reset_scripts(self) -> None
   ```

5. **Взаимоисключение:**
   - Subscript и Superscript не могут быть активны одновременно
   - При включении одного - второй отключается

#### Критерии приёмки

- [ ] Кнопки отображаются корректно
- [ ] Toggle работает (SUNKEN/RAISED)
- [ ] Взаимоисключение работает
- [ ] `check.sh src/gui/components/format_toolbar.py` проходит
- [ ] Тесты на новые методы

#### Зависимости
Нет

#### Время: 6 часов

---

### 🔧 Агент A3: StatusBar Toast Integration

**Цель:** Интегрировать Toast Panel с hover-эффектом на индикаторе уведомлений

#### Задание

Изменить файл: `src/gui/views/status_bar.py`

#### Требования

1. **Добавить индикатор уведомлений [n]:**
   - Позиция: в правой части статусбара
   - Отображает количество активных уведомлений
   - Цвет: оранжевый если n > 0, серый если 0

2. **Hover-эффект:**
   - При наведении на [n] - показывать Toast Panel
   - Panel содержит список последних 5 уведомлений
   - Auto-hide через 3 секунд после mouse leave

3. **Интеграция с NotificationService:**
   ```python
   def _on_notification_count_changed(self, count: int) -> None:
       self._update_notification_indicator(count)
   ```

4. **Toast Panel UI:**
   ```
   ┌──────────────────────┐
   │ 🔔 Уведомления (3)   │
   ├──────────────────────┤
   │ ⚠️ Документ modified │
   │ ℹ️ Автосохранение    │
   │ ✓ Сохранено          │
   └──────────────────────┘
   ```

5. **API:**
   ```python
   def set_notification_count(self, count: int) -> None
   def show_toast_panel(self) -> None
   def hide_toast_panel(self) -> None
   ```

#### Критерии приёмки

- [ ] Индикатор [n] отображается корректно
- [ ] Hover показывает Toast Panel
- [ ] Auto-hide работает
- [ ] Интеграция с NotificationService
- [ ] `check.sh src/gui/views/status_bar.py` проходит

#### Зависимости
Нет

#### Время: 8 часов

---

## 🗓️ Синхронизационный PR (После A1-A3)

### Действия:
1. Создать PR: `phase9/pass1-base-modules`
2. Code review
3. Merge в develop
4. Обновить A4, A5, A6 с новым кодом

---

## 🗓️ Проход 2: Интеграция (Агенты A4-A6)

### Последовательность

```
A4 (MainWindow AuthWindow) ──► A5 (MainWindow MainToolbar) ──► A6 (DocumentView Protocol)
```

**A5 зависит от A4 (один файл - последовательное изменение)**

---

### 🔧 Агент A4: MainWindow AuthWindow Integration

**Цель:** Интегрировать окно аутентификации в поток запуска приложения

#### Задание

Изменить файл: `src/gui/views/main_window.py`

#### Требования

1. **Добавить AuthWindow в инициализацию:**
   ```python
   def _check_session_and_auth(self) -> None:
       """Проверяет сессию и показывает AuthWindow если нужно."""
       if not self._session_manager.has_active_session():
           self._show_auth_window()
   ```

2. **Метод `_show_auth_window()`:**
   ```python
   def _show_auth_window(self) -> None:
       """Показывает окно аутентификации."""
       from src.gui.security.auth_window import AuthWindow
       
       auth_window = AuthWindow(
           parent=self._root,
           auth_service=self._auth_service,
           on_auth_success=self._on_auth_success,
           on_cancel=self._on_auth_cancel,
       )
       auth_window.show()
   ```

3. **Callbacks:**
   ```python
   def _on_auth_success(self, user_id: str) -> None:
       """Обработчик успешной аутентификации."""
       self._session_manager.create_session(user_id)
       self._update_ui_for_authenticated_user(user_id)
       
   def _on_auth_cancel(self) -> None:
       """Обработчик отмены аутентификации."""
       self._prompt_exit_or_continue()
   ```

4. **Интеграция с SessionManager:**
   - Проверка сессии при старте
   - Проверка сессии при разблокировке
   - Обновление UI после аутентификации

5. **Условия показа AuthWindow:**
   - При запуске приложения (если нет сессии)
   - При разблокировке сессии
   - При смене пользователя

#### Критерии приёмки

- [ ] AuthWindow показывается при старте без сессии
- [ ] AuthWindow показывается при разблокировке
- [ ] Callbacks работают корректно
- [ ] UI обновляется после аутентификации
- [ ] `check.sh src/gui/views/main_window.py` проходит

#### Зависимости
- A1 (LifecycleManager для управления окнами)

#### Время: 8 часов

---

### 🔧 Агент A5: MainWindow MainToolbar Integration

**Цель:** Интегрировать MainToolbar в layout MainWindow

#### Задание

Изменить файл: `src/gui/views/main_window.py`

#### Требования

1. **Добавить MainToolbar в layout:**
   - Позиция: под MenuBar, над DocumentView
   - Размер: фиксированная высота (TOOLBAR_HEIGHT)

2. **Метод `_create_main_toolbar()`:**
   ```python
   def _create_main_toolbar(self) -> None:
       """Создаёт главную панель инструментов."""
       from src.gui.components.composite.main_toolbar import MainToolbar
       
       self._main_toolbar = MainToolbar(
           widget_id="main_toolbar",
           controller=self._controller,
       )
       toolbar_frame = self._main_toolbar.mount(self._root)
       toolbar_frame.pack(fill=tk.X, side=tk.TOP)
   ```

3. **Интеграция с Controller:**
   ```python
   def _setup_toolbar_commands(self) -> None:
       """Настраивает команды для кнопок тулбара."""
       if self._controller:
           self._main_toolbar.set_button_enabled("save", False)
           # Подписка на события документа
           self._controller.subscribe("document_changed", self._on_document_changed)
   ```

4. **Обновление состояния кнопок:**
   ```python
   def _update_toolbar_state(self, has_document: bool, is_modified: bool) -> None:
       """Обновляет состояние кнопок тулбара."""
       self._main_toolbar.set_button_enabled("save", has_document and is_modified)
       self._main_toolbar.set_button_enabled("print", has_document)
   ```

5. **Layout структура:**
   ```
   +-----------------------------------+
   | MenuBar                           |
   +-----------------------------------+
   | [MainToolbar]                     |  <-- NEW
   +-----------------------------------+
   | [SideBar] | [CardFileTabBar]      |
   |           |-----------------------|
   |           | [DocumentView]        |
   +-----------------------------------+
   | [StatusBar]                       |
   +-----------------------------------+
   ```

#### Критерии приёмки

- [ ] MainToolbar отображается корректно
- [ ] Кнопки New, Open, Save, Print работают
- [ ] Состояние кнопок обновляется (save только при изменениях)
- [ ] Интеграция с Controller
- [ ] `check.sh src/gui/views/main_window.py` проходит

#### Зависимости
- A4 (изменения в main_window.py)

#### Время: 6 часов

---

### 🔧 Агент A6: DocumentView Protocol Integration

**Цель:** Интегрировать DocumentModeRenderer Protocol в DocumentView

#### Задание

Изменить файл: `src/gui/views/document_view.py`

#### Требования

1. **Интеграция с DocumentModeRenderer Protocol:**
   ```python
   from src.gui.renderers.protocols import DocumentRendererProtocol
   
   class DocumentView(BaseWidget):
       """DocumentView с поддержкой DocumentModeRenderer Protocol."""
       
       def __init__(self, ...):
           self._renderer: Optional[DocumentRendererProtocol] = None
           self._mode: Optional[DocumentMode] = None
   ```

2. **Метод `_create_renderer_for_mode()`:**
   ```python
   def _create_renderer_for_mode(self, mode: DocumentMode) -> DocumentRendererProtocol:
       """Создаёт renderer для указанного режима документа."""
       from src.gui.renderers.factory import RendererFactory
       
       renderer = RendererFactory.create_renderer(mode)
       renderer.set_document(self._document)
       return renderer
   ```

3. **Адаптация интерфейса под режим:**
   ```python
   def switch_mode(self, mode: DocumentMode) -> None:
       """Переключает режим отображения документа."""
       if self._mode == mode:
           return
           
       # Сохраняем текущее состояние
       self._save_current_state()
       
       # Создаём новый renderer
       self._renderer = self._create_renderer_for_mode(mode)
       self._mode = mode
       
       # Обновляем UI
       self._setup_mode_specific_ui()
   ```

4. **Mode-specific UI:**
   ```python
   def _setup_mode_specific_ui(self) -> None:
       """Настраивает UI в зависимости от режима."""
       if self._mode == DocumentMode.FREE_FORM:
           self._show_format_toolbar(True)
           self._show_ruler(True)
       elif self._mode == DocumentMode.STRUCTURED_FORM:
           self._show_format_toolbar(False)
           self._show_ruler(True)
           self._show_field_palette(True)
   ```

5. **Проверка Protocol:**
   ```python
   def set_renderer(self, renderer: DocumentRendererProtocol) -> None:
       """Устанавливает renderer с проверкой протокола."""
       if not isinstance(renderer, DocumentRendererProtocol):
           raise TypeError("Renderer must implement DocumentRendererProtocol")
       self._renderer = renderer
   ```

#### Критерии приёмки

- [ ] DocumentModeRenderer Protocol проверяется
- [ ] Переключение режимов работает
- [ ] UI адаптируется под режим
- [ ] FreeForm/StructuredForm рендереры создаются корректно
- [ ] `check.sh src/gui/views/document_view.py` проходит

#### Зависимости
- A1 (LifecycleManager)
- `src/gui/renderers/protocols.py` (уже существует)
- `src/gui/renderers/factory.py` (уже существует)

#### Время: 10 часов

---

## 📊 Таймлайн

| Проход | Агент | Задача | Время | Зависимости |
|--------|-------|--------|-------|-------------|
| **1** | A1 | Lifecycle Manager | 8ч | - |
| **1** | A2 | FormatToolbar Extension | 6ч | - |
| **1** | A3 | StatusBar Toast | 8ч | - |
| **-** | **PR** | Синхронизация | 2ч | A1-A3 |
| **2** | A4 | MainWindow AuthWindow | 8ч | A1 |
| **2** | A5 | MainWindow MainToolbar | 6ч | A4 |
| **2** | A6 | DocumentView Protocol | 10ч | A1 |

**Итого:** ~48 часов (6 рабочих дней)

---

## 🔍 Чек-лист для каждого агента

### Перед началом
- [ ] Прочитать связанные файлы
- [ ] Проверить зависимости (должны быть выполнены)

### В процессе
- [ ] Следовать архитектуре MVC
- [ ] Использовать Protocol для интерфейсов
- [ ] Добавлять type hints
- [ ] Писать docstrings на русском

### Перед завершением
- [ ] Запустить: `mypy --strict <файл>`
- [ ] Запустить: `check.sh <файл или директория>`
- [ ] Убедиться что тесты проходят (coverage ≥90%)
- [ ] Проверить отсутствие `type: ignore`

### Сдача работы
- [ ] Коммит с понятным сообщением
- [ ] Обновить PHASE9_IMPLEMENTATION_PLAN.md (отметить выполненное)

---

## 📁 Файлы для чтения перед стартом

### Для A1:
- `src/gui/core/protocols.py` - существующие протоколы
- `src/gui/components/base/widget.py` - BaseWidget

### Для A2:
- `src/gui/components/format_toolbar.py` - текущая реализация
- `src/escp/commands/constants.py` - ESC/P команды

### Для A3:
- `src/gui/views/status_bar.py` - текущая реализация
- `src/gui/services/notification_service.py` - NotificationService
- `src/gui/services/toast_service.py` - ToastService

### Для A4:
- `src/gui/views/main_window.py` - текущая реализация
- `src/gui/security/auth_window.py` - окно аутентификации

### Для A5:
- `src/gui/views/main_window.py` - после A4
- `src/gui/components/composite/main_toolbar.py` - тулбар

### Для A6:
- `src/gui/views/document_view.py` - текущая реализация
- `src/gui/renderers/protocols.py` - DocumentRendererProtocol
- `src/gui/renderers/factory.py` - RendererFactory

---

## ⚠️ Риски и митигации

| Риск | Митигация |
|------|-----------|
| Конфликт A4+A5 в main_window.py | Последовательное выполнение, чёткое разделение зон |
| A6 может сломать DocumentView | Тщательное тестирование, fallback на текущую реализацию |
| check.sh не проходит | Исправлять до merge, не откладывать |
| Зависимости не готовы | Ждать синхронизационного PR |

---

## ✅ Критерии завершения Фазы 9

1. [ ] Все 6 агентов завершили работу
2. [ ] Все check.sh проходят
3. [ ] Финальный PR прошёл code review
4. [ ] Интеграционные тесты GUI проходят
5. [ ] Документация обновлена

---

**Создано:** 2026-04-15  
**Автор:** AI Agent  
**Статус:** Ожидает запуска агентов
