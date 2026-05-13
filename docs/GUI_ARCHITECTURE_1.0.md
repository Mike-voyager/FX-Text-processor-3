# GUI Architecture v1.0 — FX Text Processor 3

**Version:** 1.0  
**Date:** April 2026  
**Status:** Approved for Implementation  
**Author:** Based on comprehensive analysis of UI_SPECIFICATION_upd_2.md, ARCHITECTURE.md, SECURITY_ARCHITECTURE.md, form_designer.md, form_history.md, approval_workflow.md, template_library.md, ui_plan.md

---

## Содержание

1. [Executive Summary](#executive-summary)
2. [Architecture Principles](#architecture-principles)
3. [Directory Structure](#directory-structure)
4. [Core Patterns](#core-patterns)
5. [Component Specifications](#component-specifications)
6. [Services](#services)
7. [Integration Points](#integration-points)
8. [Implementation Priorities](#implementation-priorities)
9. [Appendix A: Protocol Definitions](#appendix-a-protocol-definitions)
10. [Appendix B: Decision Matrix](#appendix-b-decision-matrix)

---

## Executive Summary

На основе анализа 5 ключевых документов (~5000+ строк спецификаций) выявлены критические требования, которые обязательно должны быть в архитектуре:

1. **Document Mode Strategy** — FREE_FORM vs STRUCTURED_FORM требуют принципиально разных рендереров
2. **Workflow State Machine** — UI адаптируется под текущее состояние документа (DRAFT → SIGNED)
3. **Role-Based Visibility** — разные роли видят разные кнопки/поля (OPERATOR ≠ SIGNATORY)
4. **MFA-Gated Operations** — множество действий требуют MFA-диалога
5. **Session Security** — полный wipe UI при блокировке (SecureMemory)
6. **Snap-to-Grid Canvas** — Form Designer работает на сетке 80×66 символов

### Ключевые отличия от текущей реализации

| Аспект | Текущая реализация | Новая архитектура |
|--------|-------------------|-------------------|
| **View→Controller** | Callback-hell (`register_callback("on_save")`) | Direct calls через Protocol |
| **State sync** | Ручной вызов `update()` в каждом методе | Explicit bindings |
| **Widget lifecycle** | Не определён | Explicit mount/unmount |
| **Document modes** | Нет разделения | Strategy Pattern (FREE_FORM vs STRUCTURED_FORM) |
| **Workflow** | Не реализован | State Pattern с MFA-gated transitions |
| **Undo** | Нет | Command Pattern per-document |

---

## Architecture Principles

### 1. MVC + Service Layer (строгое слоение)

```
┌─────────────────────────────────────────────────────────────┐
│                         View (Tkinter)                       │
│   GUI-виджеты, обработка событий, ТОЛЬКО callbacks          │
└──────────────────────────┬──────────────────────────────────┘
                           │ callbacks
┌──────────────────────────▼──────────────────────────────────┐
│                        Controller                            │
│   Маршрутизация View ↔ Service, NO сложная логика           │
└──────────────────────────┬──────────────────────────────────┘
                           │ calls
┌──────────────────────────▼──────────────────────────────────┐
│                     Service Layer                            │
│   Вся бизнес-логика, DI через конструктор                   │
└──────────────────────────┬──────────────────────────────────┘
                           │ uses
┌──────────────────────────▼──────────────────────────────────┐
│                         Model                                │
│   Dataclasses (frozen=True), NO бизнес-логика               │
└─────────────────────────────────────────────────────────────┘
```

**Правила:**
- View → только callbacks к Controller
- Controller → координация, NO сложная логика
- Service Layer → вся бизнес-логика
- Model → frozen dataclasses

### 2. DI через Constructor и Protocol

```python
from typing import Protocol

class DocumentServiceProtocol(Protocol):
    def open(self, path: Path) -> Document: ...
    def save(self, document: Document) -> None: ...

class DocumentController:
    def __init__(self, service: DocumentServiceProtocol) -> None:
        self._service = service
```

### 3. Hybrid View Intelligence

| Компонент | Тип | Обоснование |
|-----------|-----|-------------|
| **Plain Text Editor** | Smart | Пользователь печатает быстро, sync при FocusOut |
| **Form Fields** | Smart | Режим редактирования, валидация на лету |
| **Dropdown/Checkbox** | Глупый | Мгновенное применение, нет промежуточного состояния |
| **Theme changes** | Глупый | Сразу перерисовать всё |
| **StatusBar** | Глупый | Всегда отображает текущее состояние Model |

### 4. Explicit State Sync

```python
# Правильно: явный контроль
class SmartTextEditor:
    def _exit_edit_mode(self, event):
        self._edit_mode = False
        new_text = self._text_widget.get('1.0', tk.END)
        if new_text != self._edit_start_text:
            self._controller.on_text_changed(new_text)

# Неправильно: reactive magic
# document.text = "new"  # View сам обновляется — неявно!
```

### 5. Thread-Safe Widget Registry with Metadata

```python
class WidgetCategory(str, Enum):
    """Категории виджетов."""
    CONTAINER = "container"      # Контейнеры (Frame, Panel)
    INPUT = "input"              # Поля ввода (Entry, Text)
    DISPLAY = "display"          # Отображение (Label, Canvas)
    DIALOG = "dialog"            # Диалоги (Modal, Popup)
    MENU = "menu"                # Меню (Menu, Toolbar)
    TOOLBAR = "toolbar"          # Панели инструментов
    CUSTOM = "custom"            # Пользовательские

class WidgetComplexity(str, Enum):
    """Уровень сложности виджета."""
    PRIMITIVE = "primitive"      # Базовые (Button, Label)
    COMPOUND = "compound"        # Составные (FormField)
    COMPOSITE = "composite"      # Комплексные (DocumentView)

@dataclass(frozen=True)
class WidgetMetadata:
    """Метаданные виджета."""
    category: WidgetCategory
    complexity: WidgetComplexity
    version: str
    author: str
    description: str
    supported_events: Set[str] = field(default_factory=set)
    requires_mfa: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)

class WidgetRegistry:
    """Thread-safe Singleton реестр виджетов (как AlgorithmRegistry)."""
    
    def register(
        self, 
        widget_type: str, 
        factory: Callable[..., WidgetProtocol],
        metadata: WidgetMetadata,
        *, 
        validate: bool = True
    ) -> None: ...
    
    def create(self, widget_type: str, **kwargs) -> WidgetProtocol: ...
    
    # Query API
    def list_by_category(self, category: WidgetCategory) -> List[str]: ...
    def list_by_complexity(self, complexity: WidgetComplexity) -> List[str]: ...
    def list_requires_mfa(self) -> List[str]: ...
    def search(
        self,
        *,
        category: Optional[WidgetCategory] = None,
        complexity: Optional[WidgetComplexity] = None,
        requires_mfa: Optional[bool] = None,
    ) -> List[str]: ...
    
    def get_statistics(self) -> WidgetRegistryStatistics: ...
```

**Пример использования:**
```python
# Регистрация виджета
registry = WidgetRegistry.get_instance()
registry.register(
    widget_type="button_primary",
    factory=PrimaryButton,
    metadata=WidgetMetadata(
        category=WidgetCategory.INPUT,
        complexity=WidgetComplexity.PRIMITIVE,
        version="1.0.0",
        author="FX Team",
        description="Основная кнопка действия",
        supported_events={"click", "focus"},
        requires_mfa=False,
    ),
)

# Query API
input_widgets = registry.list_by_category(WidgetCategory.INPUT)
primitive_widgets = registry.list_by_complexity(WidgetComplexity.PRIMITIVE)
mfa_widgets = registry.list_requires_mfa()

# Поиск по фильтрам
search_results = registry.search(
    category=WidgetCategory.INPUT,
    complexity=WidgetComplexity.PRIMITIVE,
    requires_mfa=False,
)
```

---

## Directory Structure

```
src/gui/
├── core/                          # Инфраструктура (как crypto/core)
│   ├── protocols.py               # WidgetProtocol, ViewProtocol, ControllerProtocol
│   ├── registry.py               # WidgetRegistry (Singleton, thread-safe)
│   ├── exceptions.py             # GUIError hierarchy
│   ├── events.py                 # Event types (ValueChanged, FocusLost, etc)
│   ├── bindings.py               # Model↔View sync (explicit)
│   ├── lifecycle.py              # Mount/Unmount для диалогов
│   ├── commands.py               # Command pattern для undo/redo
│   └── factories.py              # Factory functions
│
├── components/                    # UI компоненты
│   ├── base/                     # Базовые виджеты
│   │   ├── widget.py            # BaseWidget (глупый)
│   │   ├── smart_widget.py      # BaseSmartWidget (с локальным состоянием)
│   │   └── container.py         # BaseContainer
│   ├── primitive/               # Примитивы
│   │   ├── button.py
│   │   ├── label.py
│   │   ├── entry.py
│   │   └── checkbox.py
│   ├── compound/                # Составные
│   │   ├── form_field.py
│   │   ├── toolbar_section.py
│   │   └── tab.py
│   └── composite/               # Комплексные
│       ├── document_view.py      # Главная область редактирования
│       ├── side_bar.py          # Боковая панель
│       ├── status_bar.py        # Статусная строка
│       ├── main_toolbar.py      # Главная панель инструментов
│       └── format_toolbar.py    # Панель форматирования
│
├── modes/                        # Режимы документа (!!! критично)
│   ├── protocols.py             # DocumentModeRenderer Protocol
│   ├── free_form/               # Свободное редактирование
│   │   ├── __init__.py
│   │   ├── renderer.py         # WYSIWYG текстовый редактор
│   │   └── toolbar.py          # FormatToolbar для текста
│   └── structured_form/         # Формы с полями
│       ├── __init__.py
│       ├── renderer.py          # Field-based редактор
│       ├── toolbar.py           # Workflow toolbar
│       └── widgets/             # Поля ввода
│           ├── __init__.py
│           ├── autocomplete_entry.py
│           ├── date_entry.py
│           ├── number_entry.py
│           └── table_field.py
│
├── workflow/                     # Workflow UI
│   ├── __init__.py
│   ├── protocols.py             # WorkflowUIProtocol
│   ├── state_indicator.py       # Timeline DRAFT→SIGNED
│   ├── role_badge.py           # Цветной индикатор роли
│   ├── transition_dialog.py    # Диалог перехода с MFA
│   └── comment_widget.py       # 💬 индикатор комментария
│
├── security/                     # Security UI
│   ├── __init__.py
│   ├── protocols.py             # SecurityUIProtocol
│   ├── auth_window.py          # AuthWindow (Password + MFA)
│   ├── mfa_dialog.py           # MFA Method Selector
│   ├── session_lock.py         # Экран блокировки
│   ├── health_check.py         # Health Check Dialog
│   ├── mode_toggle.py          # Normal/Special Mode переключение
│   └── trust_chain.py          # Trust Chain Verification UI
│
├── dialogs/                      # Все диалоги
│   ├── __init__.py
│   ├── base_dialog.py           # BaseDialog с lifecycle
│   ├── paper_setup.py          # Paper Setup Dialog
│   ├── print.py                # PrintDialog
│   ├── find_replace.py         # FindReplaceDialog
│   ├── page_setup.py           # Page Setup Dialog
│   ├── goto.py                 # Goto Dialog
│   ├── bookmarks.py            # Bookmarks Dialog
│   ├── template_import.py      # Template Import с Trust Chain
│   ├── template_preview.py     # Template Preview Panel
│   ├── floppy_optimizer.py     # Floppy Optimizer Dialog
│   ├── prefill.py              # PrefillDialog
│   ├── add_comment.py          # Add Comment Dialog
│   ├── reject.py               # Reject Dialog
│   ├── barcode.py              # Barcode Dialog
│   ├── qr_code.py              # QR Code Dialog
│   └── crypto_profile.py       # Crypto Profile Selector
│
├── themes/                       # Темы оформления
│   ├── __init__.py
│   ├── protocol.py             # ThemeProtocol
│   ├── registry.py             # ThemeRegistry
│   └── implementations/        # Конкретные темы
│       ├── retro_green.py      # Classic Green (VT100)
│       ├── amber.py            # Amber
│       ├── phosphor_white.py   # Phosphor White
│       └── high_contrast.py    # High Contrast
│
├── services/                    # UI-сервисы (глобальные)
│   ├── __init__.py
│   ├── toast_service.py        # Toast Notification System
│   ├── window_manager.py       # Multi-window support
│   ├── autocomplete_service.py # Form History lookup
│   ├── key_bindings.py         # KeyBindingsService
│   └── notification_service.py # Notification service
│
└── form_designer/              # Form Template Designer (Super Docs)
    ├── __init__.py
    ├── designer_window.py      # Form Designer Window
    ├── grid_canvas.py         # ESC/P Grid Canvas
    ├── field_palette.py        # Field Palette
    ├── tree_panel.py          # Tree Panel
    ├── property_panel.py       # Property Panel
    ├── resize_handles.py       # Resize Handles (8 handles)
    └── preview_panel.py        # ESC/P Preview Panel
```

---

## Core Patterns

### 1. Document Mode Strategy (КРИТИЧНО)

**Проблема:** FREE_FORM и STRUCTURED_FORM — принципиально разные UX:
- FREE_FORM: WYSIWYG текст, свободное форматирование
- STRUCTURED_FORM: Поля по схеме, workflow, валидация

**Решение:** Strategy Pattern

```python
# src/gui/modes/protocols.py

from typing import Protocol, runtime_checkable

@runtime_checkable
class DocumentModeRenderer(Protocol):
    """Стратегия рендеринга для разных режимов документа."""
    
    def create_toolbar(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт toolbar для этого режима."""
        ...
    
    def create_editor(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт редактор (Text или Canvas с полями)."""
        ...
    
    def supports_workflow(self) -> bool:
        """Поддерживает ли режим workflow (только STRUCTURED_FORM)."""
        ...
    
    def get_undo_manager(self) -> UndoManagerProtocol:
        """Возвращает undo manager для этого режима."""
        ...
    
    def display_document(self, document: Document) -> None:
        """Отображает документ в редакторе."""
        ...
    
    def get_editor_state(self) -> EditorState:
        """Возвращает текущее состояние редактора."""
        ...


class FreeFormRenderer:
    """Рендерер для FREE_FORM документов (WYSIWYG текст)."""
    
    def __init__(self, controller: DocumentControllerProtocol) -> None:
        self._controller = controller
        self._text_widget: tk.Text | None = None
        self._undo_manager = TextUndoManager(max_depth=50)
        self._is_editing = False
        self._edit_start_text = ""
    
    def supports_workflow(self) -> bool:
        return False  # FREE_FORM — нет workflow
    
    def create_editor(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Text widget с WYSIWYG рендерингом."""
        self._text_widget = tk.Text(parent, font=("Courier New", 10))
        
        # Smart mode: локальное редактирование
        self._text_widget.bind('<FocusIn>', self._enter_edit_mode)
        self._text_widget.bind('<FocusOut>', self._exit_edit_mode)
        self._text_widget.bind('<KeyRelease>', self._on_text_changed)
        
        return self._text_widget
    
    def _enter_edit_mode(self, event: tk.Event) -> None:
        """Вход в режим редактирования — запоминаем текст."""
        self._is_editing = True
        self._edit_start_text = self._text_widget.get('1.0', tk.END)
    
    def _exit_edit_mode(self, event: tk.Event) -> None:
        """Выход из режима — синхронизируемся с Model."""
        self._is_editing = False
        new_text = self._text_widget.get('1.0', tk.END)
        
        if new_text != self._edit_start_text:
            # Создаём Command для undo
            cmd = TextChangeCommand(
                old_text=self._edit_start_text,
                new_text=new_text,
                apply_callback=self._controller.on_text_changed
            )
            self._undo_manager.execute(cmd)
    
    def _on_text_changed(self, event: tk.Event) -> None:
        """В режиме редактирования — не синхронизируемся."""
        if self._is_editing:
            return
        # Если не в edit mode (например, paste) — синхронизируем
        new_text = self._text_widget.get('1.0', tk.END)
        self._controller.on_text_changed(new_text)
    
    def display_document(self, document: Document) -> None:
        """Отображает документ."""
        if self._is_editing:
            # Если пользователь редактирует — игнорируем внешние изменения
            return
        
        self._text_widget.delete('1.0', tk.END)
        self._text_widget.insert('1.0', document.content)
        
        # Сохраняем позицию курсора
        self._preserve_cursor_position()
    
    def _preserve_cursor_position(self) -> None:
        """Сохраняет позицию курсора при обновлении текста."""
        # Реализация сохранения cursor position
        pass


class StructuredFormRenderer:
    """Рендерер для STRUCTURED_FORM документов (поля по схеме)."""
    
    def __init__(self, 
                 controller: DocumentControllerProtocol,
                 autocomplete_service: AutocompleteServiceProtocol) -> None:
        self._controller = controller
        self._autocomplete = autocomplete_service
        self._field_widgets: dict[str, FormFieldWidget] = {}
        self._undo_manager = FormUndoManager(max_depth=50)
        self._current_document: Document | None = None
    
    def supports_workflow(self) -> bool:
        return True  # STRUCTURED_FORM — есть workflow
    
    def create_editor(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Canvas с полями по схеме."""
        self._container = tk.Frame(parent)
        self._fields_frame = tk.Frame(self._container)
        self._fields_frame.pack(fill=tk.BOTH, expand=True)
        
        return self._container
    
    def display_document(self, document: Document) -> None:
        """Отображает форму с полями по схеме."""
        self._current_document = document
        
        # Очищаем старые поля
        for widget in self._field_widgets.values():
            widget.destroy()
        self._field_widgets.clear()
        
        # Создаём поля по схеме
        for field_def in document.schema.fields:
            widget = self._create_field_widget(field_def)
            self._field_widgets[field_def.field_id] = widget
    
    def _create_field_widget(self, field_def: FieldDefinition) -> FormFieldWidget:
        """Создаёт виджет поля с Autocomplete."""
        if field_def.field_type == FieldType.TEXT_INPUT:
            return AutocompleteEntry(
                parent=self._fields_frame,
                field_id=field_def.field_id,
                label=field_def.label,
                autocomplete_service=self._autocomplete,
                document_index=self._current_document.document_index,
                on_change=self._on_field_changed,
            )
        elif field_def.field_type == FieldType.NUMBER_INPUT:
            return NumberEntry(
                parent=self._fields_frame,
                field_id=field_def.field_id,
                label=field_def.label,
                on_change=self._on_field_changed,
            )
        # ... другие типы полей
    
    def _on_field_changed(self, field_id: str, value: str) -> None:
        """Обработка изменения поля."""
        cmd = FieldChangeCommand(
            field_id=field_id,
            old_value=self._current_document.get_field(field_id),
            new_value=value,
            apply_callback=self._controller.on_field_changed
        )
        self._undo_manager.execute(cmd)
```

**Использование в DocumentView:**

```python
class DocumentView:
    """Главная область редактирования документа."""
    
    def __init__(self, parent: tk.Widget, 
                 controller: DocumentControllerProtocol) -> None:
        self._parent = parent
        self._controller = controller
        self._current_renderer: DocumentModeRenderer | None = None
        self._toolbar_frame = tk.Frame(parent)
        self._editor_frame = tk.Frame(parent)
    
    def set_document(self, document: Document) -> None:
        """Переключает рендерер при смене документа."""
        # Сохраняем undo историю предыдущего документа
        if self._current_renderer:
            undo_manager = self._current_renderer.get_undo_manager()
            undo_manager.persist()
        
        # Выбираем новый рендерер
        if document.mode == DocumentMode.FREE_FORM:
            self._current_renderer = FreeFormRenderer(self._controller)
        else:
            self._current_renderer = StructuredFormRenderer(
                self._controller,
                autocomplete_service=AutocompleteService.get_instance()
            )
        
        # Перестраиваем UI
        self._rebuild_ui(document)
    
    def _rebuild_ui(self, document: Document) -> None:
        """Перестраивает toolbar и editor."""
        # Очищаем старые виджеты
        for widget in self._toolbar_frame.winfo_children():
            widget.destroy()
        for widget in self._editor_frame.winfo_children():
            widget.destroy()
        
        # Создаём новые через рендерер
        toolbar = self._current_renderer.create_toolbar(self._toolbar_frame)
        toolbar.pack(fill=tk.X)
        
        editor = self._current_renderer.create_editor(self._editor_frame)
        editor.pack(fill=tk.BOTH, expand=True)
        
        # Отображаем документ
        self._current_renderer.display_document(document)
```

### 2. Workflow State Pattern (КРИТИЧНО)

**Проблема:** UI должен адаптироваться под текущее состояние документа и роль пользователя

**Решение:** State Pattern + Role-based Visibility

```python
# src/gui/workflow/state_manager.py

from enum import Enum, auto

class WorkflowRole(Enum):
    """Роли в workflow (один оператор, разные режимы)."""
    OPERATOR = "operator"
    EDITOR = "editor"
    SUPERVISOR = "supervisor"
    SIGNATORY = "signatory"

class FormStatus(Enum):
    """Состояния формы."""
    DRAFT = "draft"
    FILLED = "filled"
    VALIDATED = "validated"
    APPROVED = "approved"
    SIGNED = "signed"
    PRINTED = "printed"
    ARCHIVED = "archived"


class WorkflowStateManager:
    """Управление UI в зависимости от состояния workflow."""
    
    # Какие действия доступны для каждой роли
    ROLE_ACTIONS: dict[WorkflowRole, set[str]] = {
        WorkflowRole.OPERATOR: {
            "fill_fields", "save_draft", "print", "switch_to_editor"
        },
        WorkflowRole.EDITOR: {
            "fill_fields", "validate", "reject", "save_draft",
            "switch_to_operator", "switch_to_supervisor"
        },
        WorkflowRole.SUPERVISOR: {
            "validate", "approve", "reject", "view_comments",
            "switch_to_editor", "switch_to_signatory"
        },
        WorkflowRole.SIGNATORY: {
            "sign", "reject", "view_comments", "print",
            "switch_to_supervisor"
        },
    }
    
    # Какие действия доступны в каждом состоянии
    STATE_ACTIONS: dict[FormStatus, set[str]] = {
        FormStatus.DRAFT: {
            "fill_fields", "save_draft", "submit_for_validation",
            "switch_role"
        },
        FormStatus.FILLED: {
            "validate", "reject", "view_comments"
        },
        FormStatus.VALIDATED: {
            "approve", "reject", "view_comments"
        },
        FormStatus.APPROVED: {
            "sign", "reject", "view_comments"
        },
        FormStatus.SIGNED: {
            "print", "archive"
        },
    }
    
    # MFA требуется для этих переходов
    MFA_TRANSITIONS: set[tuple[FormStatus, FormStatus]] = {
        (FormStatus.FILLED, FormStatus.VALIDATED),
        (FormStatus.VALIDATED, FormStatus.APPROVED),
        (FormStatus.APPROVED, FormStatus.SIGNED),
    }
    
    def __init__(self, auth_service: AuthServiceProtocol) -> None:
        self._auth = auth_service
        self._current_role: WorkflowRole = WorkflowRole.OPERATOR
        self._current_state: FormStatus = FormStatus.DRAFT
    
    def can_perform_action(self, action: str) -> bool:
        """Проверяет, может ли текущая роль выполнить действие."""
        role_actions = self.ROLE_ACTIONS.get(self._current_role, set())
        state_actions = self.STATE_ACTIONS.get(self._current_state, set())
        return action in role_actions and action in state_actions
    
    def get_visible_actions(self) -> set[str]:
        """Возвращает доступные действия для текущего состояния и роли."""
        role_actions = self.ROLE_ACTIONS.get(self._current_role, set())
        state_actions = self.STATE_ACTIONS.get(self._current_state, set())
        return role_actions & state_actions
    
    def requires_mfa_for_transition(self, to_state: FormStatus) -> bool:
        """Требуется ли MFA для перехода."""
        return (self._current_state, to_state) in self.MFA_TRANSITIONS
    
    def switch_role(self, new_role: WorkflowRole) -> bool:
        """Переключает роль (может требовать MFA)."""
        if new_role in [WorkflowRole.SUPERVISOR, WorkflowRole.SIGNATORY]:
            if not self._auth.verify_mfa():
                return False
        
        old_role = self._current_role
        self._current_role = new_role
        
        # Логируем в audit
        AuditService.get_instance().log_event(
            AuditEventType.WORKFLOW_ROLE_SWITCHED,
            details={"from": old_role.value, "to": new_role.value}
        )
        
        return True
    
    def transition(self, new_state: FormStatus) -> bool:
        """Выполняет переход состояния."""
        # Проверяем MFA
        if self.requires_mfa_for_transition(new_state):
            if not self._auth.verify_mfa():
                return False
        
        old_state = self._current_state
        self._current_state = new_state
        
        # Логируем в audit
        AuditService.get_instance().log_event(
            AuditEventType.WORKFLOW_TRANSITION,
            details={"from": old_state.value, "to": new_state.value}
        )
        
        return True


class WorkflowToolbar(tk.Frame):
    """Toolbar с кнопками, адаптирующимися под состояние."""
    
    def __init__(self, parent: tk.Widget, 
                 state_manager: WorkflowStateManager) -> None:
        super().__init__(parent)
        self._state_manager = state_manager
        self._buttons: dict[str, tk.Button] = {}
        
        self._create_buttons()
        self._update_visibility()
    
    def _create_buttons(self) -> None:
        """Создаёт все возможные кнопки (скрытые по умолчанию)."""
        self._buttons["save_draft"] = tk.Button(
            self, text="Save Draft", command=self._on_save_draft
        )
        self._buttons["validate"] = tk.Button(
            self, text="Validate", command=self._on_validate
        )
        self._buttons["approve"] = tk.Button(
            self, text="Approve", command=self._on_approve
        )
        self._buttons["sign"] = tk.Button(
            self, text="Sign", command=self._on_sign
        )
        self._buttons["reject"] = tk.Button(
            self, text="Reject", command=self._on_reject
        )
        # ... другие кнопки
    
    def _update_visibility(self) -> None:
        """Обновляет видимость кнопок."""
        visible_actions = self._state_manager.get_visible_actions()
        
        for action, button in self._buttons.items():
            if action in visible_actions:
                button.pack(side=tk.LEFT, padx=2)
            else:
                button.pack_forget()
```

### 3. MFA-Gated Operations (КРИТИЧНО)

**Проблема:** Множество операций требуют MFA (role switching, workflow transitions, key export)

**Решение:** Decorator/Gate Pattern

```python
# src/gui/security/mfa_gate.py

from typing import Callable, Protocol
import tkinter as tk
from tkinter import messagebox

class MFAMethodSelectorDialog:
    """Диалог выбора метода MFA."""
    
    def __init__(self, parent: tk.Widget, operation_name: str) -> None:
        self._dialog = tk.Toplevel(parent)
        self._dialog.title("MFA Verification Required")
        self._dialog.transient(parent)
        self._dialog.grab_set()
        
        # UI
        tk.Label(self._dialog, text=f"Operation: {operation_name}").pack(pady=10)
        tk.Label(self._dialog, text="Select verification method:").pack()
        
        self._method = tk.StringVar(value="fido2")
        tk.Radiobutton(self._dialog, text="FIDO2 (Touch your key)", 
                      variable=self._method, value="fido2").pack(anchor=tk.W)
        tk.Radiobutton(self._dialog, text="TOTP (Enter 6-digit code)", 
                      variable=self._method, value="totp").pack(anchor=tk.W)
        tk.Radiobutton(self._dialog, text="Backup Code", 
                      variable=self._method, value="backup").pack(anchor=tk.W)
        
        self._token_entry = tk.Entry(self._dialog)
        self._token_entry.pack(pady=10)
        
        btn_frame = tk.Frame(self._dialog)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Cancel", command=self._on_cancel).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Verify", command=self._on_verify).pack(side=tk.LEFT, padx=5)
        
        self._result = False
    
    def show_modal(self) -> bool:
        """Показывает диалог модально."""
        self._dialog.wait_window()
        return self._result
    
    def _on_verify(self) -> None:
        """Проверяет MFA."""
        method = self._method.get()
        token = self._token_entry.get()
        
        auth_service = AuthService.get_instance()
        if auth_service.verify_mfa(method, token):
            self._result = True
            self._dialog.destroy()
        else:
            messagebox.showerror("Error", "MFA verification failed")
    
    def _on_cancel(self) -> None:
        """Отмена."""
        self._result = False
        self._dialog.destroy()


class MFAGate:
    """Декоратор для операций, требующих MFA."""
    
    def __init__(self, auth_service: AuthServiceProtocol) -> None:
        self._auth = auth_service
    
    def execute(self, parent: tk.Widget, 
                operation: Callable[[], T],
                operation_name: str,
                requires_mfa: bool = True) -> T | None:
        """
        Выполняет операцию с MFA-защитой.
        
        Args:
            parent: Родительское окно для диалога
            operation: Операция для выполнения
            operation_name: Название для отображения
            requires_mfa: Требуется ли MFA
        
        Returns:
            Результат операции или None если отменено
        """
        if requires_mfa:
            if not self._auth.is_mfa_verified():
                # Показываем MFA диалог
                dialog = MFAMethodSelectorDialog(parent, operation_name)
                if not dialog.show_modal():
                    return None  # Отменено пользователем
        
        return operation()


# Использование:
class DocumentController:
    def __init__(self) -> None:
        self._mfa_gate = MFAGate(AuthService.get_instance())
    
    def on_approve_document(self) -> None:
        """Согласование документа (требует MFA)."""
        def do_approve():
            self._workflow_service.transition(FormStatus.APPROVED)
            return True
        
        result = self._mfa_gate.execute(
            parent=self._main_window,
            operation=do_approve,
            operation_name="Approve document",
            requires_mfa=True
        )
        
        if result:
            self._status_bar.set_status("Document approved")
```

### 4. Session Security (КРИТИЧНО)

**Требование:** При блокировке сессии документ должен быть скрыт (не просто readonly, а полностью невидим)

```python
# src/gui/security/session_manager.py

class GUISessionManager:
    """Управление сессией UI."""
    
    def __init__(self, 
                 main_window: tk.Tk,
                 document_view: DocumentViewProtocol,
                 auth_service: AuthServiceProtocol) -> None:
        self._main_window = main_window
        self._document_view = document_view
        self._auth = auth_service
        self._is_locked = False
        self._lock_screen: SessionLockScreen | None = None
        
        # Auto-lock
        self._auto_lock_minutes = 30
        self._last_activity = time.time()
        self._schedule_auto_lock_check()
    
    def lock_session(self, trigger: str = "manual") -> None:
        """
        Блокировка сессии:
        1. Wipe sensitive widgets
        2. Скрыть DocumentView
        3. Показать SessionLockScreen
        """
        self._is_locked = True
        
        # 1. Wipe все sensitive widgets
        self._document_view.wipe_sensitive_data()
        
        # 2. Скрыть DocumentView (чёрный экран)
        self._document_view.hide_content()
        
        # 3. Показать SessionLockScreen
        self._lock_screen = SessionLockScreen(
            parent=self._main_window,
            on_unlock=self._on_unlock_attempt,
            locked_at=datetime.now(),
            trigger=trigger
        )
        
        # Логируем
        AuditService.get_instance().log_event(
            AuditEventType.SESSION_LOCKED,
            details={"trigger": trigger}
        )
    
    def _on_unlock_attempt(self, password: str, mfa_token: str) -> bool:
        """Попытка разблокировки."""
        if self._auth.verify_unlock(password, mfa_token):
            self._unlock_session()
            return True
        return False
    
    def _unlock_session(self) -> None:
        """Разблокировка: восстановление UI."""
        self._is_locked = False
        
        # Скрыть lock screen
        if self._lock_screen:
            self._lock_screen.destroy()
            self._lock_screen = None
        
        # Восстановить DocumentView
        self._document_view.restore_content()
        
        # Логируем
        AuditService.get_instance().log_event(
            AuditEventType.SESSION_UNLOCKED
        )
    
    def _schedule_auto_lock_check(self) -> None:
        """Проверка auto-lock каждую минуту."""
        if self._auto_lock_minutes > 0:
            inactive_minutes = (time.time() - self._last_activity) / 60
            if inactive_minutes >= self._auto_lock_minutes:
                self.lock_session(trigger="auto")
            else:
                self._main_window.after(60000, self._schedule_auto_lock_check)


class SessionLockScreen(tk.Toplevel):
    """Экран блокировки сессии."""
    
    def __init__(self, parent: tk.Tk,
                 on_unlock: Callable[[str, str], bool],
                 locked_at: datetime,
                 trigger: str) -> None:
        super().__init__(parent)
        self.title("Session Locked")
        self.attributes('-fullscreen', True)
        self.configure(bg='black')
        
        # Центрируем контент
        container = tk.Frame(self, bg='black')
        container.place(relx=0.5, rely=0.5, anchor='center')
        
        tk.Label(container, text="🔒 Session Locked", 
                font=('Courier New', 24), fg='white', bg='black').pack(pady=20)
        
        tk.Label(container, text="Document is protected and hidden.",
                fg='#888888', bg='black').pack(pady=10)
        
        # Форма разблокировки
        form_frame = tk.Frame(container, bg='black')
        form_frame.pack(pady=20)
        
        tk.Label(form_frame, text="Password:", fg='white', bg='black').pack()
        self._password = tk.Entry(form_frame, show='*')
        self._password.pack()
        
        tk.Label(form_frame, text="MFA Token:", fg='white', bg='black').pack()
        self._token = tk.Entry(form_frame)
        self._token.pack()
        
        tk.Button(form_frame, text="🔓 Unlock",
                 command=self._on_unlock_click).pack(pady=10)
        
        # Информация
        tk.Label(container, text=f"Locked at: {locked_at.strftime('%H:%M:%S')}",
                fg='#666666', bg='black').pack()
        tk.Label(container, text=f"Trigger: {trigger}",
                fg='#666666', bg='black').pack()
        
        self._on_unlock = on_unlock
    
    def _on_unlock_click(self) -> None:
        """Обработка разблокировки."""
        if self._on_unlock(self._password.get(), self._token.get()):
            self.destroy()
        else:
            messagebox.showerror("Error", "Invalid credentials")
```

### 5. Form Designer Snap-to-Grid (КРИТИЧНО)

**Требование:** Canvas 80×66 символов, snap-to-grid positioning, 8 resize handles

```python
# src/gui/form_designer/grid_canvas.py

class ESCPGridCanvas(tk.Canvas):
    """ESC/P Grid Canvas для Form Designer."""
    
    # Константы сетки (из документации)
    COLS = 80           # Столбцов при 10 CPI
    ROWS = 66           # Строк при 11" бумаге
    DOTS_PER_COL = 60   # 1 символ = 60 точек (1/60")
    DOTS_PER_ROW = 60   # 1 строка = 60 точек (1/60")
    
    HANDLE_SIZE = 6     # Размер маркера resize (пиксели)
    
    def __init__(self, parent: tk.Widget, 
                 on_field_moved: Callable[[str, int, int], None]) -> None:
        super().__init__(
            parent,
            width=self.COLS * self.DOTS_PER_COL,
            height=self.ROWS * self.DOTS_PER_ROW,
            bg='#f0f0f0'
        )
        
        self._on_field_moved = on_field_moved
        self._fields: dict[str, FieldWidget] = {}
        self._selected_field: FieldWidget | None = None
        self._resize_handles: ResizeHandles | None = None
        
        # Рисуем сетку
        self._draw_grid()
        
        # Drag-drop состояние
        self._drag_data = {"field": None, "x": 0, "y": 0}
    
    def _draw_grid(self) -> None:
        """Рисует сетку 80×66."""
        # Вертикальные линии
        for col in range(self.COLS + 1):
            x = col * self.DOTS_PER_COL
            self.create_line(x, 0, x, self.ROWS * self.DOTS_PER_ROW,
                           fill='#e0e0e0', tags='grid')
        
        # Горизонтальные линии
        for row in range(self.ROWS + 1):
            y = row * self.DOTS_PER_ROW
            self.create_line(0, y, self.COLS * self.DOTS_PER_COL, y,
                           fill='#e0e0e0', tags='grid')
    
    def snap_to_grid(self, x: int, y: int) -> tuple[int, int]:
        """Привязка к сетке (возвращает col, row)."""
        col = max(0, min(self.COLS - 1, round(x / self.DOTS_PER_COL)))
        row = max(0, min(self.ROWS - 1, round(y / self.DOTS_PER_ROW)))
        return (col, row)
    
    def create_field(self, field_def: FieldDefinition,
                    col: int, row: int) -> FieldWidget:
        """Создаёт поле на сетке."""
        x = col * self.DOTS_PER_COL
        y = row * self.DOTS_PER_ROW
        width = field_def.width_chars * self.DOTS_PER_COL
        height = field_def.height_rows * self.DOTS_PER_ROW
        
        # Создаём canvas item для поля
        rect_id = self.create_rectangle(
            x, y, x + width, y + height,
            fill='#3498db', outline='#2980b9', width=2,
            tags=('field', field_def.field_id)
        )
        
        text_id = self.create_text(
            x + width/2, y + height/2,
            text=field_def.label,
            fill='white', font=('Arial', 9),
            tags=('field', field_def.field_id)
        )
        
        widget = FieldWidget(
            canvas=self,
            rect_id=rect_id,
            text_id=text_id,
            field_def=field_def,
            col=col, row=row
        )
        
        self._fields[field_def.field_id] = widget
        
        # Bindings
        self.tag_bind(field_def.field_id, '<Button-1>', 
                     lambda e: self._on_field_click(e, widget))
        self.tag_bind(field_def.field_id, '<B1-Motion>', 
                     self._on_field_drag)
        self.tag_bind(field_def.field_id, '<ButtonRelease-1>', 
                     self._on_field_drop)
        
        return widget
    
    def _on_field_click(self, event: tk.Event, field: FieldWidget) -> None:
        """Выделение поля."""
        self._select_field(field)
        self._drag_data = {"field": field, "x": event.x, "y": event.y}
    
    def _on_field_drag(self, event: tk.Event) -> None:
        """Перетаскивание поля."""
        field = self._drag_data["field"]
        if not field:
            return
        
        # Смещение
        dx = event.x - self._drag_data["x"]
        dy = event.y - self._drag_data["y"]
        
        # Перемещаем canvas item
        self.move(field.field_id, dx, dy)
        
        # Обновляем drag data
        self._drag_data["x"] = event.x
        self._drag_data["y"] = event.y
        
        # Проверка перекрытия
        if self._check_overlap(field):
            self.itemconfig(field.rect_id, outline='red')
        else:
            self.itemconfig(field.rect_id, outline='#2980b9')
    
    def _on_field_drop(self, event: tk.Event) -> None:
        """Отпускание поля — snap to grid."""
        field = self._drag_data["field"]
        if not field:
            return
        
        # Получаем текущие координаты
        coords = self.coords(field.rect_id)
        x, y = coords[0], coords[1]
        
        # Snap to grid
        col, row = self.snap_to_grid(int(x), int(y))
        
        # Проверяем валидность
        if self._is_valid_position(field.field_def, col, row):
            # Перемещаем на сетку
            new_x = col * self.DOTS_PER_COL
            new_y = row * self.DOTS_PER_ROW
            self.coords(field.rect_id, 
                       new_x, new_y,
                       new_x + field.width, new_y + field.height)
            
            # Обновляем текст
            self.coords(field.text_id,
                       new_x + field.width/2, new_y + field.height/2)
            
            # Создаём Command для undo
            cmd = FieldMoveCommand(
                field_id=field.field_id,
                old_col=field.col, old_row=field.row,
                new_col=col, new_row=row,
                on_move=self._on_field_moved
            )
            self._undo_manager.execute(cmd)
            
            # Обновляем поле
            field.col = col
            field.row = row
        else:
            # Невалидная позиция — возвращаем обратно
            old_x = field.col * self.DOTS_PER_COL
            old_y = field.row * self.DOTS_PER_ROW
            self.coords(field.rect_id,
                       old_x, old_y,
                       old_x + field.width, old_y + field.height)
        
        self._drag_data = {"field": None, "x": 0, "y": 0}
    
    def _select_field(self, field: FieldWidget) -> None:
        """Выделяет поле и показывает resize handles."""
        # Убираем старое выделение
        if self._resize_handles:
            self._resize_handles.destroy()
        
        self._selected_field = field
        
        # Создаём resize handles (8 штук)
        self._resize_handles = ResizeHandles(
            canvas=self,
            field=field,
            on_resize=self._on_field_resized
        )
    
    def _check_overlap(self, field: FieldWidget) -> bool:
        """Проверяет перекрытие с другими полями."""
        for other in self._fields.values():
            if other.field_id == field.field_id:
                continue
            if self._rects_overlap(field.get_rect(), other.get_rect()):
                return True
        return False
    
    def _is_valid_position(self, field_def: FieldDefinition, 
                          col: int, row: int) -> bool:
        """Проверяет валидность позиции."""
        # Не выходит за границы
        if col + field_def.width_chars > self.COLS:
            return False
        if row + field_def.height_rows > self.ROWS:
            return False
        return True


class ResizeHandles:
    """8 маркеров изменения размера поля."""
    
    HANDLES = ['nw', 'n', 'ne', 'e', 'se', 's', 'sw', 'w']
    
    def __init__(self, canvas: tk.Canvas, field: FieldWidget,
                 on_resize: Callable[[str, int, int], None]) -> None:
        self._canvas = canvas
        self._field = field
        self._on_resize = on_resize
        self._handle_ids: dict[str, int] = {}
        
        self._create_handles()
    
    def _create_handles(self) -> None:
        """Создаёт 8 маркеров."""
        coords = self._canvas.coords(self._field.rect_id)
        x1, y1, x2, y2 = coords
        cx, cy = (x1 + x2) / 2, (y1 + y2) / 2
        
        positions = {
            'nw': (x1, y1), 'n': (cx, y1), 'ne': (x2, y1),
            'w': (x1, cy), 'e': (x2, cy),
            'sw': (x1, y2), 's': (cx, y2), 'se': (x2, y2)
        }
        
        for handle, (x, y) in positions.items():
            size = self._canvas.HANDLE_SIZE
            handle_id = self._canvas.create_rectangle(
                x - size, y - size, x + size, y + size,
                fill='white', outline='blue', width=2,
                tags=('resize_handle', handle)
            )
            self._handle_ids[handle] = handle_id
            
            # Bindings
            self._canvas.tag_bind(handle_id, '<Button-1>',
                                lambda e, h=handle: self._on_handle_click(e, h))
            self._canvas.tag_bind(handle_id, '<B1-Motion>',
                                self._on_handle_drag)
    
    def destroy(self) -> None:
        """Удаляет маркеры."""
        for handle_id in self._handle_ids.values():
            self._canvas.delete(handle_id)
```

---

## Component Specifications

### DocumentView

**Ответственность:** Главная область редактирования документа

```python
class DocumentView(BaseContainer):
    """Главная область редактирования документа."""
    
    def __init__(self, parent: tk.Widget,
                 controller: DocumentControllerProtocol) -> None:
        super().__init__(parent)
        self._controller = controller
        self._current_renderer: DocumentModeRenderer | None = None
        
        # Layout
        self._toolbar_frame = tk.Frame(self)
        self._editor_frame = tk.Frame(self)
        self._ruler = Ruler(self._editor_frame)
        self._navigator = Navigator(self._editor_frame)
        
        self._setup_layout()
    
    def set_document(self, document: Document) -> None:
        """Переключает рендерер при смене документа."""
        # Сохраняем undo историю
        if self._current_renderer:
            undo_manager = self._current_renderer.get_undo_manager()
            undo_manager.persist()
        
        # Выбираем рендерер
        if document.mode == DocumentMode.FREE_FORM:
            self._current_renderer = FreeFormRenderer(self._controller)
        else:
            self._current_renderer = StructuredFormRenderer(
                self._controller,
                AutocompleteService.get_instance()
            )
        
        # Перестраиваем UI
        self._rebuild_ui(document)
    
    def _rebuild_ui(self, document: Document) -> None:
        """Перестраивает toolbar и editor."""
        # Очищаем
        for widget in self._toolbar_frame.winfo_children():
            widget.destroy()
        for widget in self._editor_frame.winfo_children():
            widget.destroy()
        
        # Создаём новые
        toolbar = self._current_renderer.create_toolbar(self._toolbar_frame)
        toolbar.pack(fill=tk.X)
        
        editor = self._current_renderer.create_editor(self._editor_frame)
        editor.pack(fill=tk.BOTH, expand=True)
        
        # Отображаем документ
        self._current_renderer.display_document(document)
    
    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные (при блокировке)."""
        if self._current_renderer:
            self._current_renderer.wipe_data()
    
    def hide_content(self) -> None:
        """Скрывает контент (при блокировке)."""
        self._editor_frame.pack_forget()
        self._toolbar_frame.pack_forget()
    
    def restore_content(self) -> None:
        """Восстанавливает контент (при разблокировке)."""
        self._setup_layout()
```

### SideBar

**Ответственность:** Боковая панель с деревом документов

```python
class SideBar(BaseContainer):
    """Боковая панель с двумя режимами: Sections и Tree."""
    
    MODE_SECTIONS = "sections"
    MODE_TREE = "tree"
    
    def __init__(self, parent: tk.Widget,
                 controller: DocumentControllerProtocol) -> None:
        super().__init__(parent, width=250)
        self._controller = controller
        self._mode = self.MODE_SECTIONS
        
        # Header
        self._header = tk.Frame(self)
        self._header.pack(fill=tk.X, pady=5)
        
        self._toggle_btn = tk.Button(self._header, text="[=]",
                                    command=self._toggle_collapse)
        self._toggle_btn.pack(side=tk.LEFT)
        
        self._search_entry = tk.Entry(self._header)
        self._search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self._search_entry.bind('<KeyRelease>', self._on_search)
        
        # Content (Sections или Tree)
        self._content_frame = tk.Frame(self)
        self._content_frame.pack(fill=tk.BOTH, expand=True)
        
        self._sections_view: SectionsView | None = None
        self._tree_view: TreeView | None = None
        
        self._show_sections_mode()
    
    def _show_sections_mode(self) -> None:
        """Показывает режим Sections."""
        self._clear_content()
        
        self._sections_view = SectionsView(
            self._content_frame,
            sections=["DOCUMENTS", "TEMPLATES", "BLANKS", "SUPER DOCS"],
            on_select=self._on_section_select
        )
        self._sections_view.pack(fill=tk.BOTH, expand=True)
    
    def _show_tree_mode(self) -> None:
        """Показывает режим Tree."""
        self._clear_content()
        
        self._tree_view = TreeView(
            self._content_frame,
            index_service=IndexSearchService(),
            on_select=self._on_tree_select
        )
        self._tree_view.pack(fill=tk.BOTH, expand=True)
    
    def _on_search(self, event: tk.Event) -> None:
        """Фильтрация в реальном времени."""
        query = self._search_entry.get()
        if self._mode == self.MODE_SECTIONS and self._sections_view:
            self._sections_view.filter(query)
        elif self._mode == self.MODE_TREE and self._tree_view:
            self._tree_view.filter(query)
```

### StatusBar

**Ответственность:** Статусная строка с индикаторами

```python
class StatusBar(BaseContainer):
    """Статусная строка с адаптивным layout."""
    
    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent, height=25)
        
        self._indicators: dict[str, tk.Label] = {}
        self._mode = "single"  # или "double" при узком окне
        
        self._create_indicators()
        self._setup_layout()
        
        # Bind resize
        self.bind('<Configure>', self._on_resize)
    
    def _create_indicators(self) -> None:
        """Создаёт индикаторы."""
        self._indicators["cursor"] = tk.Label(self, text="Ln 1, Col 1")
        self._indicators["cpi"] = tk.Label(self, text="10 CPI")
        self._indicators["codepage"] = tk.Label(self, text="PC866")
        self._indicators["paper"] = tk.Label(self, text="A4")
        self._indicators["security"] = tk.Label(self, text="🔒 Standard")
        self._indicators["page"] = tk.Label(self, text="Page 1/1")
        self._indicators["zoom"] = tk.Label(self, text="100%")
        self._indicators["toasts"] = tk.Label(self, text="[0]")
        
        # Double-click на paper открывает Paper Setup
        self._indicators["paper"].bind('<Double-Button-1>',
                                      self._on_paper_dblclick)
        
        # Hover на toasts показывает панель
        self._indicators["toasts"].bind('<Enter>',
                                       self._show_toast_panel)
    
    def _on_resize(self, event: tk.Event) -> None:
        """Переключает между single и double row."""
        if event.width < 1024 and self._mode == "single":
            self._mode = "double"
            self._setup_double_row()
        elif event.width >= 1024 and self._mode == "double":
            self._mode = "single"
            self._setup_single_row()
    
    def set_cursor_position(self, line: int, col: int) -> None:
        """Обновляет позицию курсора."""
        self._indicators["cursor"].config(text=f"Ln {line}, Col {col}")
    
    def set_modified(self, modified: bool) -> None:
        """Устанавливает индикатор изменений."""
        if modified:
            self._indicators["cursor"].config(fg='#FFA500')  # Оранжевый
        else:
            self._indicators["cursor"].config(fg='black')
    
    def set_security_preset(self, preset: SecurityPreset) -> None:
        """Обновляет индикатор пресета безопасности."""
        colors = {
            SecurityPreset.LEGACY: '#FF0000',      # Красный
            SecurityPreset.STANDARD: '#FFFF00',    # Жёлтый
            SecurityPreset.PARANOID: '#00FF00',   # Зелёный
            SecurityPreset.PQC: '#FF00FF',        # Фиолетовый
        }
        self._indicators["security"].config(
            text=f"🔒 {preset.value}",
            fg=colors.get(preset, 'black')
        )
```

---

## Services

### Toast Notification Service

```python
class ToastService:
    """Глобальный сервис уведомлений (правый нижний угол)."""
    
    MAX_QUEUE_SIZE = 6
    AUTO_CLOSE_MS = 30000
    
    def __init__(self, parent: tk.Widget) -> None:
        self._parent = parent
        self._queue: deque[Toast] = deque(maxlen=self.MAX_QUEUE_SIZE)
        self._toasts: dict[str, ToastWindow] = {}
    
    def show(self, message: str, level: ToastLevel = ToastLevel.INFO) -> str:
        """Показывает toast."""
        toast_id = str(uuid4())
        toast = Toast(id=toast_id, message=message, level=level,
                     created_at=datetime.now())
        
        self._queue.append(toast)
        self._render_toast(toast)
        self._schedule_close(toast_id, self.AUTO_CLOSE_MS)
        
        # Обновляем индикатор в StatusBar
        self._update_statusbar_indicator()
        
        return toast_id
    
    def _render_toast(self, toast: Toast) -> None:
        """Рендерит toast окно."""
        # Позиция: правый нижний угол
        x = self._parent.winfo_screenwidth() - 310
        y = self._parent.winfo_screenheight() - 100 - (len(self._queue) * 60)
        
        toast_window = ToastWindow(
            parent=self._parent,
            toast=toast,
            x=x, y=y,
            on_close=lambda: self._remove_toast(toast.id)
        )
        self._toasts[toast.id] = toast_window
```

### Autocomplete Service (Form History)

```python
class AutocompleteService:
    """Поиск истории полей по иерархии индексов."""
    
    def __init__(self, history_storage: FormHistoryStorageProtocol) -> None:
        self._storage = history_storage
    
    def get_suggestions(self, field_id: str, query: str,
                       document_index: str,
                       limit: int = 5) -> list[tuple[str, int]]:
        """
        Ищет значения в истории с учётом иерархии:
        1. Точное совпадение индекса (DVN-44-K53-IX)
        2. Серия (DVN-44-K53-*)
        3. Подтип (DVN-44-*-*)
        4. Корневой тип (DVN-*-*-*)
        """
        segments = document_index.split('-')
        
        for depth in range(len(segments), 0, -1):
            pattern = '-'.join(segments[:depth])
            results = self._storage.search(
                field_id=field_id,
                index_pattern=pattern,
                query=query,
                limit=limit
            )
            if results:
                return results
        
        return []
```

---

## Integration Points

### Mode Switching (FREE_FORM ↔ STRUCTURED_FORM)

```python
def on_tab_changed(self, document: Document):
    """Обработка смены вкладки."""
    if document.mode == DocumentMode.FREE_FORM:
        # Показать FormatToolbar (CPI, Bold, Italic)
        self._format_toolbar.show_free_form_mode()
        # Скрыть Workflow Timeline
        self._workflow_timeline.hide()
        # Показать Ruler с tab stops
        self._ruler.show_tabs()
    else:
        # Показать Workflow Toolbar
        self._format_toolbar.show_structured_form_mode()
        # Показать Workflow Timeline
        self._workflow_timeline.show(document.workflow_state)
        # Скрыть Ruler
        self._ruler.hide()
```

### Workflow Transition

```python
def on_approve_clicked(self):
    """Согласование документа."""
    # Проверить роль
    if not self._workflow_manager.can_perform_action("approve"):
        messagebox.showerror("Error", "Insufficient permissions")
        return
    
    # Требуется MFA
    if self._workflow_manager.requires_mfa_for_transition(FormStatus.APPROVED):
        dialog = MFAMethodSelectorDialog("Approve document")
        if not dialog.show_modal():
            return  # Отменено
    
    # Выполнить переход
    self._workflow_manager.transition(FormStatus.APPROVED)
    
    # Обновить UI
    self._workflow_timeline.set_state(FormStatus.APPROVED)
    self._toolbar.update_visible_actions()
```

---

## Implementation Priorities

### Phase 1 (Недели 1-2): Core UI ✅ COMPLETED
- [x] WidgetRegistry + BaseWidget (с metadata, Query API, thread-safe Singleton) — ✅ Готово (существовало)
- [x] MainWindow + Layout — ✅ Реализовано (782 строки, check.sh пройден)
- [x] SideBar (Sections + Tree modes) — ✅ Реализовано (629 строк)
- [x] CardFileTabBar — ✅ Реализовано (819 строк, MAX_TABS=20)
- [x] DocumentView + Mode switching — ✅ Placeholder (493 строки, ready for Phase 2-4)
- [x] PaperToolbar + PaperSetupDialog — ✅ Реализовано (529 + 897 строк)
- [x] StatusBar — ✅ Реализовано (531 строка, adaptive layout)
- [x] Toast Notification System — ✅ Реализовано (383 строки)

### Phase 2 (Неделя 3): FREE_FORM ✅ COMPLETED
- [x] FreeFormRenderer — ✅ Реализовано (WYSIWYG text editor, CPI support, 1151 строк)
- [x] FormatToolbar (CPI, Bold, Italic) — ✅ Реализовано (toggle buttons)
- [x] Ruler + Navigator — ✅ Реализовано (CPI-based ruler, goto line)
- [x] Undo/Redo (Command pattern) — ✅ Реализовано (CommandStack, MAX_HISTORY=1000)

### Phase 3 (Неделя 4): Security UI ✅ COMPLETED
- [x] AuthWindow — ✅ AuthOverlay тёмный overlay (Password + MFA methods)
- [x] MFA dialogs — ✅ FIDO2/TOTP/Backup Code с FIDO2 disabled tooltip
- [x] Session Lock — ✅ Интеграция с SessionLockManager
- [x] Health Check Dialog — ✅ 6 checks с Critical/Warning/Pass индикаторами
- [x] Mode Toggle — ✅ Normal/Special режимы через Tools → Mode + StatusBar

### Phase 4 (Неделя 5): STRUCTURED_FORM basics ✅ COMPLETED
- [x] StructuredFormRenderer — ✅ Multi-page с thumbnail sidebar
- [x] FormField widgets — ✅ 9 core types (TEXT_INPUT, NUMBER_INPUT, DATE_INPUT, CHECKBOX, DROPDOWN, RADIO_GROUP, MULTI_LINE_TEXT, TABLE)
- [x] AutocompleteEntry — ✅ Hierarchical index search (4 levels)

### Phase 5 (Недели 6-8): Form Designer ✅ COMPLETED
- [x] FormDesignerCanvas — ✅ Dynamic grid, continuous scroll multi-page
- [x] Field Palette — ✅ Drag-drop + Click-to-place, 5 categories
- [x] PropertyPanel — ✅ Right panel, live editing, validation
- [x] ResizeHandles — ✅ 8 handles (nw/n/ne/e/se/s/sw/w), snap-to-grid
- [x] Drag-drop undoable — ✅ DesignCommands (create/move/resize/delete/property)
- [x] TemplateManager — ✅ .fxstpl v1.0, signature for special blanks

### Phase 6 (Недели 9-10): Workflow ✅ COMPLETED
- [x] Workflow Timeline — ✅ Диалог с визуальной шкалой и историей
- [x] Role Badge — ✅ Цветной индикатор роли (🟢OPERATOR/🟢EDITOR/🟠SUPERVISOR/🔴SIGNATORY)
- [x] Transition dialogs с MFA — ✅ Улучшенный MFA диалог с выбором метода (FIDO2/TOTP/Backup)
- [x] Field Comment Widget — ✅ Иконка + popup с комментариями (INFO/WARNING/ERROR)

---

## Appendix A: Protocol Definitions

### WidgetProtocol

```python
@runtime_checkable
class WidgetProtocol(Protocol):
    """Базовый протокол для всех виджетов."""
    
    widget_id: str
    
    def mount(self, parent: tk.Widget) -> tk.Widget: ...
    def unmount(self) -> None: ...
    def handle_event(self, event: EventProtocol) -> bool: ...
    def is_mounted(self) -> bool: ...

@runtime_checkable
class SmartWidgetProtocol(WidgetProtocol, Protocol):
    """Для виджетов с локальным состоянием."""
    
    is_editing: bool
    
    def enter_edit_mode(self) -> None: ...
    def exit_edit_mode(self) -> None: ...
    def sync_to_model(self) -> bool: ...
    def get_edit_value(self) -> str: ...
    def set_edit_value(self, value: str) -> None: ...
```

### ControllerProtocol

```python
@runtime_checkable
class ControllerProtocol(Protocol):
    """Базовый протокол для Controller."""
    
    controller_id: str
    
    def dispatch(self, action: str, **kwargs: Any) -> Optional[Any]: ...
    def notify_view_update(self, widget_id: str, data: Any) -> None: ...
    def register_view(self, widget_id: str, callback: Callable[..., None]) -> None: ...
    def unregister_view(self, widget_id: str) -> None: ...

@runtime_checkable
class DocumentControllerProtocol(ControllerProtocol, Protocol):
    """Протокол для Document Controller."""
    
    def on_text_changed(self, text: str) -> None: ...
    def on_field_changed(self, field_id: str, value: str) -> None: ...
    def on_save(self) -> bool: ...
    def on_print(self) -> bool: ...
    def on_undo(self) -> bool: ...
    def on_redo(self) -> bool: ...
```

---

## Appendix B: Decision Matrix

| Аспект | Решение | Альтернатива | Почему выбрано |
|--------|---------|--------------|----------------|
| **State sync** | Explicit (B) | Reactive (A) | Проще отлаживать, нет магии |
| **Controller→View** | Direct Calls | EventBus | Type safety, понятный stack |
| **Widget lifecycle** | Explicit mount/unmount | Implicit | Предсказуемость, ресурсы |
| **Canvas** | Direct Tkinter | Abstract | Проще, меньше слоёв |
| **View intelligence** | **Hybrid** | Глупый или Smart | Гибкость для разных компонентов |
| **Undo scope** | Per-document, limited depth | Global или Unlimited | Экономия памяти, логично для вкладок |
| **Drag-drop** | **Undoable** | Non-undoable | Требование пользователя |
| **Form selection** | View state | Model state | Model не знает про UI |
| **Toast** | Global service | Per-document | Все документы в одной очереди |
| **Mode switching** | **Strategy Pattern** | If/else | FREE_FORM ≠ STRUCTURED_FORM |
| **Workflow** | **State Pattern** | Hardcoded | UI зависит от состояния |
| **MFA** | **Decorator/Gate** | Inline checks | Много gated операций |

---

## References

- [UI_SPECIFICATION_upd_2.md](UI_SPECIFICATION_upd_2.md) — Полная спецификация UI
- [ARCHITECTURE.md](ARCHITECTURE.md) — Архитектура системы
- [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md) — Security flows
- [form_designer.md](form_designer.md) — Form Designer
- [form_history.md](form_history.md) — Form History
- [approval_workflow.md](approval_workflow.md) — Workflow
- [template_library.md](template_library.md) — Template Library
- [ui_plan.md](ui_plan.md) — UI Plan
