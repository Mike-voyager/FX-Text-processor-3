# Руководство разработчика: GUI Services (Phase 7)

> **Версия:** 1.0  
> **Дата:** Апрель 2026  
> **Уровень:** Средний (Middle)  

---

## Содержание

1. [Обзор](#обзор)
2. [WindowManager](#windowmanager)
3. [NotificationService](#notificationservice)
4. [SyncService](#syncservice)
5. [DragDropService](#dragdropservice)
6. [PreviewPanel](#previewpanel)
7. [Интеграция сервисов](#интеграция-сервисов)
8. [Обработка ошибок](#обработка-ошибок)
9. [Security best practices](#security-best-practices)

---

## Обзор

GUI Services Layer (Phase 7) предоставляет набор сервисов для управления окнами, уведомлениями и синхронизации в многоконном приложении FX Text Processor 3.

### Список сервисов

| Сервис | Назначение | Файл |
|--------|------------|------|
| `WindowManager` | Управление окнами приложения | `src/gui/services/window_manager.py` |
| `NotificationService` | Система уведомлений с историей | `src/gui/services/notification_service.py` |
| `SyncService` | Синхронизация между окнами | `src/gui/services/sync_service.py` |
| `DragDropService` | Drag-and-drop операции | `src/gui/services/drag_drop_service.py` (через Protocol) |
| `PreviewPanel` | Предпросмотр ESC/P вывода | `src/gui/form_designer/preview_panel.py` |

### Инициализация сервисов

```python
from src.gui.services import (
    WindowManager,
    NotificationService,
    SyncService,
)

class MainWindow:
    def __init__(self, root: tk.Tk) -> None:
        # Создаём сервисы в правильном порядке
        self._window_manager = WindowManager(root)
        self._notification_service = NotificationService(
            root, self._window_manager
        )
        self._sync_service = SyncService(self._window_manager)
```

---

## WindowManager

### Назначение

Централизованное управление всеми окнами приложения: регистрация, фокусировка, закрытие, передача документов.

### Регистрация окна

```python
from src.gui.services import WindowManager

# Инициализация
wm = WindowManager(root)

# Создание и регистрация нового окна
toplevel = tk.Toplevel(root)
window_id = wm.register_window(
    window=toplevel,
    title="Документ 1 - FX Text Processor",
    document_path=Path("/docs/document.fxsd"),  # опционально
    is_modal=False,  # True для диалогов
)

print(f"Window registered: {window_id}")  # UUID
```

### Получение информации об окне

```python
# Получить ссылку на окно
window = wm.get_window(window_id)
if window:
    window.focus_force()

# Получить список всех окон
for info in wm.get_window_list():
    print(f"{info.title} ({info.window_id}): z_order={info.z_order}")
```

### Управление фокусом

```python
# Вывести окно на передний план
wm.bring_to_front(window_id)

# Проверить, является ли окно главным
if wm.is_main_window(window_id):
    print("Это главное окно")
```

### Управление состоянием окон

```python
# Свернуть все окна кроме главного
count = wm.minimize_all()
print(f"Minimized {count} windows")

# Восстановить все окна
count = wm.restore_all()

# Закрыть все окна кроме главного (при блокировке сессии)
closed = wm.close_all_except_main()
```

### Передача документов между окнами

```python
# Передать документ от одного окна к другому
success = wm.transfer_document(
    from_id="win-001",
    to_id="win-002",
    doc_id="doc-123"
)

if success:
    print("Документ передан")
else:
    print("Ошибка передачи")
```

### Обработка закрытия окна

```python
def on_window_close():
    # Сохранить документ если нужно
    if has_unsaved_changes():
        if not confirm_save():
            return  # Отменить закрытие
    
    # Удалить регистрацию
    wm.unregister_window(window_id)
    toplevel.destroy()

toplevel.protocol("WM_DELETE_WINDOW", on_window_close)
```

### Security notes

- `MAX_WINDOWS = 50` — защита от исчерпания ресурсов
- Каждое окно получает UUID для безопасной идентификации
- `close_all_except_main()` используется при блокировке сессии

---

## NotificationService

### Назначение

Система уведомлений с поддержкой приоритетов, категорий, истории и статуса прочтения.

### Базовое использование

```python
from src.gui.services.notification_service import (
    NotificationService,
    NotificationPriority,
    CATEGORY_WORKFLOW,
    CATEGORY_SECURITY,
)

# Инициализация
service = NotificationService(root, window_manager)

# Отправить уведомление
notification_id = service.notify(
    message="Документ сохранён успешно",
    category=CATEGORY_WORKFLOW,
    priority=NotificationPriority.NORMAL,
)
```

### Приоритеты уведомлений

| Приоритет | Обработка | Использование |
|-----------|-----------|---------------|
| `LOW` | Toast уведомление | Фоновые события |
| `NORMAL` | Toast + badge update | Обычные операции |
| `HIGH` | Модальный диалог | Важные события |
| `CRITICAL` | Модальный диалог с блокировкой | Критические ошибки |

```python
# Критическое уведомление (блокирует работу)
service.notify(
    message="Ошибка шифрования: ключ не найден",
    category=CATEGORY_SECURITY,
    priority=NotificationPriority.CRITICAL,
)
```

### Работа с историей

```python
# Получить всю историю
history = service.get_history()

# Фильтр по категории
security_notifications = service.get_history(category=CATEGORY_SECURITY)

# Только непрочитанные
unread = service.get_history(unread_only=True)

# Отметить как прочитанное
service.mark_as_read(notification_id)

# Отметить все как прочитанные
service.mark_all_as_read(category=CATEGORY_WORKFLOW)
```

### Badge counter

```python
# Регистрация callback для обновления badge
def update_badge(count: int) -> None:
    badge_label.config(text=str(count) if count > 0 else "")

service.register_badge_callback(update_badge)

# Получить количество непрочитанных
unread_count = service.get_unread_count(category=CATEGORY_SECURITY)
```

### Метаданные уведомлений

```python
# Уведомление с метаданными (без callable!)
notification_id = service.notify(
    message="Документ сохранён",
    category=CATEGORY_WORKFLOW,
    priority=NotificationPriority.NORMAL,
    metadata={
        "document_id": "doc_123",
        "timestamp": "2026-04-11T10:00:00",
        # Нельзя передавать функции или lambda!
    }
)

# Получить конкретное уведомление
notification = service.get_notification(notification_id)
if notification:
    print(f"Metadata: {notification.metadata}")
```

### Очистка истории

```python
# Очистить всю историю
service.clear_history()

# Очистить уведомления старше 7 дней
service.clear_history(older_than_days=7)
```

### Security notes

- `MAX_HISTORY = 100` — ограничение размера истории
- `MAX_MESSAGE_LENGTH = 500` — защита от DoS
- Метаданные проверяются на отсутствие callable
- Нельзя передавать `eval` или `exec` в метаданных

---

## SyncService

### Назначение

Синхронизация состояния между окнами приложения через broadcast или direct messaging.

### Типы данных для синхронизации

```python
from src.gui.services.sync_service import (
    SyncService,
    DATA_SIDEBAR_STATE,
    DATA_BOOKMARK_CHANGE,
    DATA_DOCUMENT_UPDATE,
    DATA_SELECTION_CHANGE,
    DATA_MODE_CHANGE,
)
```

| Константа | Стратегия конфликтов | MFA-защита |
|-----------|---------------------|------------|
| `DATA_SIDEBAR_STATE` | last-write-wins | Нет |
| `DATA_BOOKMARK_CHANGE` | merge | Нет |
| `DATA_DOCUMENT_UPDATE` | timestamp | Да |
| `DATA_SELECTION_CHANGE` | broadcast only | Нет |
| `DATA_MODE_CHANGE` | - | Да |

### Broadcast (рассылка всем)

```python
# Инициализация
sync = SyncService(window_manager)

# Отправить всем окнам кроме источника
def on_sidebar_change(msg: SyncMessage) -> None:
    print(f"Sidebar state: {msg.data}")
    # Обновить UI
    sidebar.set_collapsed(msg.data.get("collapsed", False))

# Регистрация обработчика
handler_id = sync.register_handler(
    DATA_SIDEBAR_STATE, "win-002", on_sidebar_change
)

# Broadcast всем окнам
sync.broadcast(
    source_window_id="win-001",
    data_type=DATA_SIDEBAR_STATE,
    data={"collapsed": True, "selected": "documents"},
)
```

### Direct messaging

```python
# Отправить конкретному окну
sync.send_to_window(
    source_window_id="win-001",
    target_window_id="win-002",
    data_type=DATA_DOCUMENT_UPDATE,
    data={
        "doc_id": "doc_123",
        "modified": True,
        "timestamp": time.time(),
    },
)
```

### Управление обработчиками

```python
# Удалить обработчик
sync.unregister_handler(handler_id)

# Удалить все обработчики окна (при закрытии окна)
count = sync.clear_handlers("win-001")
print(f"Removed {count} handlers")

# Удалить все обработчики
sync.clear_handlers()  # None = все
```

### Информация о синхронизации

```python
# Время последней синхронизации
last_sync = sync.get_last_sync_time(DATA_DOCUMENT_UPDATE)
print(f"Last sync: {time.time() - last_sync}s ago")

# Количество обработчиков
total_handlers = sync.get_handler_count()
sidebar_handlers = sync.get_handler_count(DATA_SIDEBAR_STATE)
```

### Thread safety

Все методы SyncService thread-safe благодаря `threading.Lock`:

```python
# Можно вызывать из любого потока
threading.Thread(
    target=lambda: sync.broadcast("win-001", DATA_SIDEBAR_STATE, data)
).start()
```

### Security notes

- Данные передаются без шифрования (shared memory)
- Для sensitive данных используйте DocumentService с шифрованием
- MFA-gated операции требуют верификации перед изменением

---

## DragDropService

### Назначение

Управление drag-and-drop операциями между виджетами и окнами.

### Начало перетаскивания

```python
from src.gui.services.drag_drop_service import DragDropService

dds = DragDropService()

# Начать перетаскивание документа
dds.start_drag("win-001", {
    "type": "document",
    "doc_id": "doc_123",
    "title": "Счёт №123",
    "preview": "ООО Ромашка...",
})

# Начать перетаскивание файла
dds.start_drag("win-001", {
    "type": "file",
    "path": "/docs/invoice.fxsd",
    "filename": "invoice.fxsd",
})
```

### Регистрация целевой зоны

```python
class DropTarget:
    def __init__(self, on_drop: Callable[[Any], None]) -> None:
        self._on_drop = on_drop
    
    def on_drop(self, data: Any) -> None:
        self._on_drop(data)

# Создать целевую зону
def handle_drop(data: dict) -> None:
    if data.get("type") == "document":
        doc_id = data.get("doc_id")
        open_document(doc_id)

target = DropTarget(on_drop=handle_drop)
target_id = dds.register_drop_target(canvas_widget, target)
```

### Управление операцией

```python
# Проверить, выполняется ли перетаскивание
if dds.is_dragging():
    print("Drag in progress...")

# Отменить текущую операцию
dds.cancel_drag()

# Удалить целевую зону
dds.unregister_drop_target(target_id)
```

### Security notes

- Данные не шифруются во время перетаскивания
- Не передавайте sensitive данные без шифрования
- Валидируйте тип данных в `on_drop`

---

## PreviewPanel

### Назначение

Панель предпросмотра ESC/P вывода с двумя режимами: визуальный и hex дамп.

### Создание панели

```python
from src.gui.form_designer.preview_panel import PreviewPanel, PreviewData

# Создать панель
panel = PreviewPanel(
    parent=parent_frame,
    controller=document_controller
)

# Смонтировать в родителя
panel.mount(parent_frame)
```

### Установка данных

```python
# Создать данные для предпросмотра
from src.documents.printing.document_renderer import DocumentRenderer

renderer = DocumentRenderer()
escp_bytes = renderer.render(document)

data = PreviewData(
    escp_bytes=escp_bytes,
    document_name="Счёт №123",
    page_number=1,
    total_pages=3,
)

panel.set_preview_data(data)
```

### Переключение режимов

```python
# Переключить на hex дамп
panel.show_hex_view()

# Переключить на визуальный просмотр
panel.show_visual_preview()
```

### Навигация

```python
# Перейти на страницу
panel.go_to_page(2)

# Перейти к смещению в hex дампе
panel.go_to_offset(0x100)

# Zoom
panel.zoom_in()
panel.zoom_out()
```

### Keyboard shortcuts

| Клавиша | Действие |
|---------|----------|
| `Page Up` / `Page Down` | Предыдущая/следующая страница |
| `Home` | Первая страница |
| `End` | Последняя страница |
| `Ctrl +` | Увеличить масштаб |
| `Ctrl -` | Уменьшить масштаб |

### Security notes

- Панель очищается при демонтировании (`_cleanup()`)
- Не храните sensitive данные в preview дольше необходимого
- Используйте `unmount()` при закрытии документа

---

## Интеграция сервисов

### Полный пример MainWindow

```python
class MainWindow:
    def __init__(self, root: tk.Tk, controller: ControllerProtocol) -> None:
        self._root = root
        self._controller = controller
        
        # Инициализация сервисов (в правильном порядке)
        self._init_services()
        
        # Регистрация главного окна
        self._register_main_window()
        
        # Настройка обработчиков
        self._setup_sync_handlers()
        self._setup_badge_callback()
    
    def _init_services(self) -> None:
        """Инициализирует все сервисы Phase 7."""
        # WindowManager первый — нужен другим сервисам
        self._window_manager = WindowManager(self._root)
        
        # NotificationService зависит от WindowManager
        self._notification_service = NotificationService(
            self._root, self._window_manager
        )
        
        # SyncService зависит от WindowManager
        self._sync_service = SyncService(self._window_manager)
        
        # DragDropService независимый
        self._drag_drop_service = DragDropService()
    
    def _register_main_window(self) -> None:
        """Регистрирует главное окно."""
        self._main_window_id = self._window_manager.register_window(
            self._root,
            title="FX Text Processor 3",
            is_modal=False
        )
        self._window_manager.set_main_window_id(self._main_window_id)
    
    def _setup_sync_handlers(self) -> None:
        """Настраивает обработчики синхронизации."""
        # Обработчик обновлений документа
        self._sync_service.register_handler(
            DATA_DOCUMENT_UPDATE,
            self._main_window_id,
            self._on_document_update
        )
        
        # Обработчик изменений боковой панели
        self._sync_service.register_handler(
            DATA_SIDEBAR_STATE,
            self._main_window_id,
            self._on_sidebar_change
        )
    
    def _on_document_update(self, msg: SyncMessage) -> None:
        """Обрабатывает обновление документа из другого окна."""
        if msg.data.get("modified"):
            self._notification_service.notify(
                message=f"Документ изменён в другом окне: {msg.source_window_id}",
                category=CATEGORY_WORKFLOW,
                priority=NotificationPriority.NORMAL,
                metadata={"doc_id": msg.data.get("doc_id")}
            )
    
    def _on_sidebar_change(self, msg: SyncMessage) -> None:
        """Синхронизирует состояние боковой панели."""
        self._sidebar.set_collapsed(
            msg.data.get("collapsed", False)
        )
    
    def _setup_badge_callback(self) -> None:
        """Настраивает обновление badge."""
        def update_badge(count: int) -> None:
            self._status_bar.set_notification_count(count)
        
        self._notification_service.register_badge_callback(update_badge)
    
    def on_session_lock(self) -> None:
        """Обрабатывает блокировку сессии."""
        # Закрыть все окна кроме главного
        closed = self._window_manager.close_all_except_main()
        
        # Закрыть все toast
        self._notification_service.close_all_toasts()
        
        # Показать overlay
        self._show_auth_overlay()
```

---

## Обработка ошибок

### WindowManager ошибки

```python
from src.gui.services.window_manager import WindowManager, MAX_WINDOWS

try:
    window_id = wm.register_window(toplevel, "Title")
except RuntimeError as e:
    if "MAX_WINDOWS" in str(e):
        messagebox.showerror(
            "Ошибка",
            f"Достигнут лимит окон ({MAX_WINDOWS}). Закройте неиспользуемые окна."
        )
```

### NotificationService ошибки

```python
from src.gui.services.notification_service import MAX_MESSAGE_LENGTH

try:
    service.notify("A" * 1000, CATEGORY_WORKFLOW, NotificationPriority.NORMAL)
except ValueError as e:
    # Сообщение слишком длинное
    service.notify(
        message[:MAX_MESSAGE_LENGTH],
        CATEGORY_WORKFLOW,
        NotificationPriority.NORMAL
    )
```

### SyncService ошибки

```python
# Обработчики вызываются вне блокировки — перехватывайте ошибки
def safe_handler(msg: SyncMessage) -> None:
    try:
        process_message(msg)
    except Exception as e:
        logger.error(f"Handler error: {e}")

sync.register_handler(DATA_TYPE, window_id, safe_handler)
```

---

## Security best practices

### 1. Валидация входных данных

```python
def notify_secure(service: NotificationService, message: str) -> str:
    # Проверка длины
    if len(message) > MAX_MESSAGE_LENGTH:
        message = message[:MAX_MESSAGE_LENGTH]
    
    # Проверка на опасные символы
    message = message.replace("\x00", "")  # null bytes
    
    return service.notify(message, CATEGORY_WORKFLOW, NotificationPriority.NORMAL)
```

### 2. Защита метаданных

```python
# Проверяйте метаданные перед передачей
def validate_metadata(metadata: dict) -> dict:
    safe = {}
    for key, value in metadata.items():
        # Нет callable
        if callable(value):
            continue
        # Нет опасных строк
        if isinstance(value, str) and ("eval(" in value or "exec(" in value):
            continue
        safe[key] = value
    return safe
```

### 3. MFA-gated операции

```python
from src.gui.security.mfa_gate import MFAGate

class SecureSyncService(SyncService):
    def broadcast(self, source_id: str, data_type: str, data: Any) -> None:
        # Проверка MFA для sensitive типов
        if data_type in (DATA_DOCUMENT_UPDATE, DATA_MODE_CHANGE):
            if not MFAGate.verify():
                raise SecurityError("MFA required")
        
        super().broadcast(source_id, data_type, data)
```

### 4. Очистка ресурсов

```python
def on_window_close(self) -> None:
    # Отписаться от обработчиков
    self._sync_service.clear_handlers(self._window_id)
    
    # Отписаться от badge callback
    self._notification_service.unregister_badge_callback(
        self._badge_callback
    )
    
    # Удалить регистрацию окна
    self._window_manager.unregister_window(self._window_id)
    
    # Закрыть окно
    self.destroy()
```

---

## FAQ

### Q: Какой порядок инициализации сервисов?

**A:** WindowManager → NotificationService → SyncService → DragDropService

NotificationService и SyncService зависят от WindowManager.

### Q: Как обработать закрытие окна?

**A:** Всегда вызывайте `unregister_window()` и `clear_handlers()`:

```python
def on_close(self):
    self._sync_service.clear_handlers(self._window_id)
    self._window_manager.unregister_window(self._window_id)
    self.destroy()
```

### Q: Как синхронизировать состояние между всеми окнами?

**A:** Используйте `broadcast()`:

```python
sync.broadcast("win-001", DATA_SIDEBAR_STATE, {"collapsed": True})
```

### Q: Как передать документ конкретному окну?

**A:** Используйте `send_to_window()`:

```python
sync.send_to_window("win-001", "win-002", DATA_DOCUMENT_UPDATE, data)
```

### Q: Как ограничить количество уведомлений?

**A:** NotificationService автоматически ограничивает историю (`MAX_HISTORY = 100`) и длину сообщения (`MAX_MESSAGE_LENGTH = 500`).

---

## Связанная документация

- [gui_phase7_summary.md](gui_phase7_summary.md) — Сводка Phase 7
- [ARCHITECTURE.md](ARCHITECTURE.md) — Общая архитектура
- `src/gui/core/protocols.py` — Protocol-интерфейсы

---

> **FX Text Processor 3** — GUI Services Guide v1.0
