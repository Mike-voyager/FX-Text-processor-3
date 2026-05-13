# Phase 7: GUI Services Layer — Сводка

> **Версия:** 1.0  
> **Дата:** Апрель 2026  
> **Статус:** ✅ Завершён  

---

## Обзор

**Phase 7** завершает реализацию GUI Services Layer — ключевого уровня архитектуры MVC+Service, обеспечивающего взаимодействие между окнами, уведомления пользователя и поддержку drag-and-drop операций.

### Цели Phase 7

| Цель | Описание | Статус |
|------|----------|--------|
| Централизованное управление окнами | `WindowManager` — регистрация, фокусировка, закрытие окон | ✅ |
| Система уведомлений | `NotificationService` — история, приоритеты, категории | ✅ |
| Межоконная синхронизация | `SyncService` — broadcast и direct messaging | ✅ |
| Drag-and-drop | `DragDropService` — перетаскивание элементов | ✅ |
| Предпросмотр печати | `PreviewPanel` — визуальный и hex-просмотр ESC/P | ✅ |

---

## Компоненты Phase 7

### 1. WindowManager

**Файл:** `src/gui/services/window_manager.py`

Централизованный менеджер окон для многоконного режима (MDI). Управляет регистрацией, отслеживанием и жизненным циклом всех окон приложения.

**Ключевые возможности:**
- Регистрация/дерегистрация окон с UUID
- Z-order управление для активации окон
- Передача документов между окнами
- Быстрое закрытие всех окон при блокировке сессии
- Управление модальными окнами

**Security constraints:**
- `MAX_WINDOWS = 50` — защита от исчерпания ресурсов
- Отслеживание всех окон для быстрого закрытия при блокировке

**Пример использования:**

```python
from src.gui.services import WindowManager

# Инициализация
window_manager = WindowManager(root)

# Регистрация нового окна
toplevel = tk.Toplevel(root)
window_id = window_manager.register_window(
    toplevel, 
    title="Документ 1",
    document_path=Path("/docs/file.fxsd"),
    is_modal=False
)

# Вывод на передний план
window_manager.bring_to_front(window_id)

# Закрытие всех окон при блокировке
closed_count = window_manager.close_all_except_main()
```

---

### 2. NotificationService

**Файл:** `src/gui/services/notification_service.py`

Расширенная система уведомлений с историей, приоритетами и категоризацией. Интегрирован с `ToastService` и `WindowManager`.

**Ключевые возможности:**
- Четыре уровня приоритета: `LOW`, `NORMAL`, `HIGH`, `CRITICAL`
- Четыре категории: `security`, `workflow`, `system`, `sync`
- Автоматическая маршрутизация: LOW/NORMAL → ToastService, HIGH/CRITICAL → модальные диалоги
- История уведомлений с ограничением размера (`MAX_HISTORY = 100`)
- Отслеживание статуса прочтения (badge counters)

**Пример использования:**

```python
from src.gui.services.notification_service import (
    NotificationService, NotificationPriority, CATEGORY_WORKFLOW
)

# Инициализация
service = NotificationService(root, window_manager)

# Отправка уведомления
notification_id = service.notify(
    message="Документ сохранён",
    category=CATEGORY_WORKFLOW,
    priority=NotificationPriority.NORMAL,
    metadata={"document_id": "doc_123"}
)

# Получение истории
history = service.get_history(category=CATEGORY_SECURITY, unread_only=True)

# Отметка как прочитанного
service.mark_as_read(notification_id)
```

---

### 3. SyncService

**Файл:** `src/gui/services/sync_service.py`

Сервис синхронизации состояния между окнами приложения с поддержкой broadcast и direct messaging.

**Типы данных для синхронизации:**
- `DATA_SIDEBAR_STATE` — состояние боковой панели (last-write-wins)
- `DATA_BOOKMARK_CHANGE` — изменения закладок (merge стратегия)
- `DATA_DOCUMENT_UPDATE` — обновление документа (MFA-gated)
- `DATA_SELECTION_CHANGE` — изменение выделения (broadcast only)
- `DATA_MODE_CHANGE` — смена режима (MFA-gated)

**Conflict Resolution:**
- **sidebar_state**: last-write-wins (сравнение по timestamp)
- **bookmark_change**: merge стратегия (множество закладок)
- **document_update**: MFA-gated + timestamp проверка
- **selection_change**: broadcast only (без persistence)
- **mode_change**: MFA-gated операция

**Пример использования:**

```python
from src.gui.services.sync_service import (
    SyncService, DATA_SIDEBAR_STATE, DATA_DOCUMENT_UPDATE
)

# Инициализация
sync = SyncService(window_manager)

# Регистрация обработчика
def on_sidebar_update(msg: SyncMessage) -> None:
    print(f"Sidebar state: {msg.data}")

handler_id = sync.register_handler(
    DATA_SIDEBAR_STATE, "win_001", on_sidebar_update
)

# Broadcast всем окнам
sync.broadcast(
    source_window_id="win_001",
    data_type=DATA_SIDEBAR_STATE,
    data={"collapsed": True, "selected": "documents"}
)

# Direct message конкретному окну
sync.send_to_window(
    source_window_id="win_001",
    target_window_id="win_002",
    data_type=DATA_DOCUMENT_UPDATE,
    data={"doc_id": "doc_123", "modified": True}
)
```

---

### 4. DragDropService

**Протокол:** `src/gui/core/protocols.py` → `DragDropServiceProtocol`

Сервис drag-and-drop операций между виджетами и окнами. Поддерживает перетаскивание текста, файлов и документов.

**Ключевые возможности:**
- `start_drag()` — начало операции перетаскивания
- `register_drop_target()` — регистрация целевой зоны
- `cancel_drag()` — отмена операции
- `is_dragging()` — проверка состояния

**Типы данных:**
- `"text"` — Текстовые данные
- `"file"` — Пути к файлам
- `"document"` — Ссылки на документы

**Security:**
- Данные drag-and-drop не шифруются в процессе перетаскивания
- Не используйте для передачи sensitive данных без шифрования

**Пример использования:**

```python
from src.gui.services.drag_drop_service import DragDropService

# Инициализация
dds = DragDropService()

# Начало перетаскивания
dds.start_drag("win_001", {
    "type": "document",
    "doc_id": "doc_123",
    "preview": "Document preview..."
})

# Регистрация целевой зоны
target = DropTarget(on_drop=lambda d: handle_drop(d))
target_id = dds.register_drop_target(widget, target)

# Отмена операции
dds.cancel_drag()
```

---

### 5. PreviewPanel

**Файл:** `src/gui/form_designer/preview_panel.py`

Панель предпросмотра ESC/P вывода с двумя режимами отображения: визуальный и hex дамп.

**Режимы просмотра:**
- **Визуальный предпросмотр**: Canvas-рендеринг ESC/P команд
- **Hex дамп**: Подсвеченный hex-вид байтов с ASCII представлением

**Возможности:**
- Tabbed интерфейс (ttk.Notebook)
- Навигация по страницам и смещениям
- Zoom in/out для визуального предпросмотра
- Подсветка ESC команд в hex дампе
- Интеграция с DocumentRenderer

**Пример использования:**

```python
from src.gui.form_designer.preview_panel import PreviewPanel, PreviewData

# Создание панели
panel = PreviewPanel(parent=parent_frame, controller=doc_controller)
panel.mount(parent_frame)

# Установка данных
data = PreviewData(
    escp_bytes=escp_data,
    document_name="Test Document",
    page_number=1,
    total_pages=3
)
panel.set_preview_data(data)

# Переключение режимов
panel.show_hex_view()
panel.show_visual_preview()

# Навигация
panel.go_to_page(2)
panel.go_to_offset(0x100)

# Zoom
panel.zoom_in()
panel.zoom_out()
```

---

## Архитектура взаимодействия

### Диаграмма компонентов

```
┌─────────────────────────────────────────────────────────────────────┐
│                        GUI Layer (Phase 7)                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   ┌─────────────────┐         ┌─────────────────┐                  │
│   │  WindowManager  │◄───────►│  SyncService    │                  │
│   │                 │  sync   │                 │                  │
│   │ - register()    │         │ - broadcast()   │                  │
│   │ - bring_to_front│◄───────►│ - send_to_window│                  │
│   │ - close_all()   │  events │                 │                  │
│   └────────┬────────┘         └─────────────────┘                  │
│            │                                                        │
│            ▼                                                        │
│   ┌─────────────────┐         ┌─────────────────┐                  │
│   │ NotificationService        │                 │                  │
│   │                 │◄───────►│ DragDropService │                  │
│   │ - notify()    │  events │                 │                  │
│   │ - get_history()│         │ - start_drag()  │                  │
│   │ - mark_as_read()         │ - register_drop │                  │
│   └────────┬────────┘         └─────────────────┘                  │
│            │                                                        │
│            │ callbacks                                              │
│            ▼                                                        │
│   ┌─────────────────┐                                              │
│   │   ToastService  │◄─────── высокие приоритеты                    │
│   │   (низкие)      │         ───────────────────────► модальные   │
│   │                 │                                   диалоги    │
│   └─────────────────┘                                              │
│                                                                     │
│   ┌─────────────────────────────────────────────────────────────┐  │
│   │                    PreviewPanel                              │  │
│   │   ┌─────────────┐         ┌─────────────┐                 │  │
│   │   │ Визуальный  │◄───────►│   Hex дамп  │                 │  │
│   │   │  просмотр   │  switch │              │                 │  │
│   │   └─────────────┘         └─────────────┘                 │  │
│   └─────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              │ использует
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Controller Layer                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   ┌─────────────────┐         ┌─────────────────┐                  │
│   │ MainController  │◄───────►│ DocumentController                  │
│   │                 │         │                 │                  │
│   └─────────────────┘         └─────────────────┘                  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Потоки данных

#### 1. Уведомление между окнами

```
[Window A] ──notify()──► [NotificationService]
                              │
                              ├── Toast (LOW/NORMAL)
                              └── Modal Dialog (HIGH/CRITICAL)
```

#### 2. Синхронизация состояния

```
[Window A] ──broadcast()──► [SyncService] ──► [Window B]
                                    │
                                    ├── [Window C]
                                    └── [Window D]
```

#### 3. Drag-and-drop

```
[Source Widget] ──start_drag()──► [DragDropService]
                                        │
                                        ├─ register_drop_target() ── [Target A]
                                        └─ register_drop_target() ── [Target B]
                                               │
                                               ▼
                                          [Drop Event]
```

---

## Интеграция с существующей архитектурой

### Взаимодействие с Phase 1-6

| Phase | Компонент | Интеграция с Phase 7 |
|-------|-----------|----------------------|
| Phase 1 | Protocols | ✅ WindowManagerProtocol, NotificationServiceProtocol, SyncServiceProtocol |
| Phase 2 | Base Widgets | ✅ WidgetProtocol для PreviewPanel |
| Phase 3 | MainWindow | ✅ Использует все сервисы Phase 7 |
| Phase 4 | Dialogs | ✅ NotificationService для уведомлений |
| Phase 5 | Form Designer | ✅ PreviewPanel интеграция |
| Phase 6 | Security | ✅ MFA-gated операции в SyncService |

### Взаимодействие с Security Layer

```python
# MFA-защищённые операции
from src.gui.security.mfa_gate import MFAGate

# SyncService: document_update требует MFA
sync.broadcast(
    source_window_id="win_001",
    data_type=DATA_DOCUMENT_UPDATE,  # MFA-gated
    data={"doc_id": "doc_123", "content": "..."}
)

# NotificationService: security категория
service.notify(
    message="MFA верификация успешна",
    category=CATEGORY_SECURITY,
    priority=NotificationPriority.HIGH
)
```

---

## Метрики Phase 7

### Покрытие тестами

| Модуль | Файл | Coverage | Тесты |
|--------|------|----------|-------|
| WindowManager | `window_manager.py` | ~90% | 15+ тестов |
| NotificationService | `notification_service.py` | ~85% | 20+ тестов |
| SyncService | `sync_service.py` | ~88% | 25+ тестов |
| PreviewPanel | `preview_panel.py` | ~80% | 12+ тестов |

### Security Audit

| Проверка | Статус |
|----------|--------|
| Валидация входных данных | ✅ |
| Ограничение ресурсов (MAX_*) | ✅ |
| Отсутствие eval/exec | ✅ |
| Thread-safety для shared state | ✅ |
| Очистка sensitive данных | ✅ |

---

## Использование в MainWindow

```python
class MainWindow:
    def __init__(self, controller: ControllerProtocol) -> None:
        # Phase 7 Services
        self._window_manager = WindowManager(self._root)
        self._notification_service = NotificationService(
            self._root, self._window_manager
        )
        self._sync_service = SyncService(self._window_manager)
        self._drag_drop_service = DragDropService()
        
        # Register main window
        self._main_window_id = self._window_manager.register_window(
            self._root, "FX Text Processor 3"
        )
        self._window_manager.set_main_window_id(self._main_window_id)
        
        # Setup sync handlers
        self._setup_sync_handlers()
    
    def _setup_sync_handlers(self) -> None:
        self._sync_service.register_handler(
            DATA_DOCUMENT_UPDATE,
            self._main_window_id,
            self._on_document_sync
        )
    
    def _on_document_sync(self, msg: SyncMessage) -> None:
        if msg.data.get("modified"):
            self._notification_service.notify(
                message="Документ изменён в другом окне",
                category=CATEGORY_WORKFLOW,
                priority=NotificationPriority.NORMAL
            )
```

---

## Руководство разработчика

### Добавление нового сервиса

1. Создать Protocol в `src/gui/core/protocols.py`
2. Реализовать класс в `src/gui/services/`
3. Добавить экспорт в `src/gui/services/__init__.py`
4. Написать тесты в `tests/unit/gui/services/`
5. Обновить документацию

### Best Practices

1. **Всегда используйте Protocol** для интерфейсов
2. **Thread-safety** — используйте `threading.Lock` для shared state
3. **Resource limits** — устанавливайте MAX_* константы
4. **Error handling** — перехватывайте исключения в callback
5. **Cleanup** — очищайте ресурсы при демонтировании

---

## Связанная документация

- [gui_services_guide.md](gui_services_guide.md) — Подробное руководство по использованию сервисов
- [ARCHITECTURE.md](ARCHITECTURE.md) — Общая архитектура проекта
- [API_REFERENCE.md](API_REFERENCE.md) — Справочник API
- `src/gui/core/protocols.py` — Protocol-интерфейсы

---

> **FX Text Processor 3** — Phase 7 Summary Document v1.0
