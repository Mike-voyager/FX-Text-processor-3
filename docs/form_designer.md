# Form Template Designer

**Version:** 1.0
**Date:** March 2026
**Status:** Living Document
**Module:** `src/documents/constructor/`

---

## Overview

Form Template Designer — визуальный конструктор шаблонов форм для FX Text Processor 3. Позволяет оператору создавать и редактировать шаблоны документов (`.fxstpl`) с точным позиционированием полей на сетке ESC/P, соответствующей физическому формату Epson FX-890.

**Ключевые особенности:**
- ESC/P Grid Canvas (80×66 символов)
- Snap-to-grid позиционирование
- Live ESC/P preview
- Field resize handles
- Drag-and-drop палитра полей

---

## Architecture

### Компоненты дизайнера

```
┌────────────────────────────────────────────────────────────┐
│                    Form Template Designer                  │
├──────────────┬─────────────────────────────┬───────────────┤
│ Field Palette│      ESC/P Grid Canvas      │ Property Panel│
│              │     (80 cols × 66 rows)     │               │
├──────────────┤                             ├───────────────┤
│ [TEXT]       │  ┌─────────────────────┐    │ Field ID: ___ │
│ [NUMBER]     │  │                     │    │ Label: ______ │
│ [DATE]       │  │  [Field A] [Field B]│    │ X: ___ Y: ___ │
│ [DROPDOWN]   │  │                     │    │ Width: ______ │
│ ...          │  │  [    Field C    ]  │    │ Required: [ ] │
│              │  │                     │    │ ...           │
│              │  └─────────────────────┘    │               │
├──────────────┴─────────────────────────────┴───────────────┤
│                     Preview Panel                          │
│  ESC/P bytes: 1B 45 ...                                    │
└────────────────────────────────────────────────────────────┘
```

### Class Hierarchy

```python
FormTemplateDesigner
├── TemplateDesignerCanvas (Tkinter.Canvas)
│   ├── ESCPGrid (80×66)
│   ├── FieldWidget (Canvas items)
│   └── ResizeHandles (Canvas items)
├── FieldPalette (tkinter.Frame)
│   └── DraggableFieldType (drag-and-drop)
├── PropertyPanel (tkinter.Frame)
│   └── FieldPropertyEditor
└── PreviewPanel (tkinter.Frame)
    └── ESCPPreviewRenderer
```

---

## ESC/P Grid Canvas

### Символьная сетка

Размер сетки соответствует стандартному формату печати Epson FX-890:

```python
class ESCPGrid:
    """Символьная сетка FX-890."""

    COLS = 80           # Столбцов при 10 CPI (стандарт)
    ROWS = 66           # Строк при 11" бумаге
    CPI = 10            # Characters per inch
    LPI = 6             # Lines per inch (1/6")

    # Размеры в точках (1/60")
    DOTS_PER_COL = 60   # 1 символ = 60 точек
    DOTS_PER_ROW = 60   # 1 строка = 60 точек
```

**Размеры в символах:**

| Формат | Ширина | Высота | Строки (1/6") | Строки (1/8") |
|--------|--------|--------|---------------|---------------|
| Letter | 80     | 66     | 66            | 88            |
| A4     | 80     | 70     | 70            | 93            |
| Legal  | 80     | 84     | 84            | 112           |

### Snap-to-Grid

Поля автоматически привязываются к символьным позициям:

```python
def snap_to_grid(x: int, y: int) -> tuple[int, int]:
    """Привязывает координаты пикселей к сетке.

    Args:
        x: X в пикселях (относительно Canvas)
        y: Y в пикселях

    Returns:
        (col, row) — позиция в символах
    """
    col = round(x / DOTS_PER_COL)
    row = round(y / DOTS_PER_ROW)
    return (col, row)
```

**Правила snap:**
- Поля позиционируются только по целым символам
- Ширина поля — целое число символов
- Высота поля — целое число строк
- Перекрытие полей запрещено (SchemaLinter)

---

## Field Positioning

### Координаты полей

```python
@dataclass(frozen=True)
class FieldPosition:
    """Позиция поля на бланке."""
    x_column: int           # X в символах (0-79)
    y_row: int              # Y в строках (0-65)
    width_chars: int        # Ширина в символах
    height_rows: int = 1    # Высота в строках
```

**Валидация позиций:**

```python
def validate_position(pos: FieldPosition) -> list[ValidationError]:
    errors = []

    if pos.x_column + pos.width_chars > 80:
        errors.append("Field exceeds right margin")

    if pos.y_row + pos.height_rows > 66:
        errors.append("Field exceeds page length")

    if pos.width_chars < 1:
        errors.append("Width must be at least 1 character")

    return errors
```

### Resize Handles

При выделении поля появляются маркеры изменения размера:

```python
class ResizeHandles:
    """Маркеры изменения размера поля."""

    HANDLE_SIZE = 6  # pixels

    def __init__(self, canvas: Canvas, field: FieldWidget):
        self.canvas = canvas
        self.field = field
        self.handles = {}  # corner -> canvas item id

    def create_handles(self):
        """Создает 8 маркеров (углы и стороны)."""
        for corner in ["nw", "n", "ne", "e", "se", "s", "sw", "w"]:
            self.handles[corner] = self._create_handle(corner)

    def on_drag(self, corner: str, dx: int, dy: int):
        """Обрабатывает перетаскивание маркера."""
        # dx, dy в пикселях → переводим в символы
        d_col = round(dx / DOTS_PER_COL)
        d_row = round(dy / DOTS_PER_ROW)

        # Обновляем размер поля с привязкой к сетке
        self.field.resize(
            width_chars=self.field.width_chars + d_col,
            height_rows=self.field.height_rows + d_row
        )
```

**Поведение resize:**
- Угловые маркеры меняют оба размера
- Боковые маркеры меняют только ширину
- Верх/низ меняют только высоту
- Минимальный размер: 1×1 символ

---

## Live ESC/P Preview

### Рендеринг preview

```python
class ESCPPreviewRenderer:
    """Рендеринг ESC/P для live preview."""

    def render_field(self, field: FieldDefinition) -> bytes:
        """Рендерит поле как ESC/P bytes."""
        result = bytearray()

        # Абсолютное позиционирование
        result.extend(build_absolute_position(
            field.position.x_column * DOTS_PER_COL
        ))

        # Если поле заполнено — рисуем границу
        if field.field_type == FieldType.TEXT_INPUT:
            result.extend(build_underline_on())
            result.extend(b" " * field.position.width_chars)
            result.extend(build_underline_off())

        return bytes(result)
```

### Отображение на Canvas

Preview отображается в отдельной панели рядом с Canvas:

```python
class PreviewPanel(Frame):
    """Панель live preview ESC/P."""

    def __init__(self, parent: Widget):
        super().__init__(parent)
        self.text = Text(self, font=("Courier", 10))
        self.text.pack(fill=BOTH, expand=True)

    def update_preview(self, escp_bytes: bytes):
        """Обновляет отображение ESC/P bytes."""
        # Преобразуем ESC/P в текстовое представление
        display = self._escp_to_display(escp_bytes)
        self.text.delete(1.0, END)
        self.text.insert(END, display)
```

---

## Field Palette

### Доступные типы полей

```python
class FieldPalette(Frame):
    """Палитра типов полей для drag-and-drop."""

    FIELD_TYPES = [
        ("TEXT_INPUT", "Текстовое поле", "#3498db"),
        ("NUMBER_INPUT", "Числовое поле", "#2ecc71"),
        ("DATE_INPUT", "Дата", "#9b59b6"),
        ("DROPDOWN", "Выпадающий список", "#e74c3c"),
        ("CHECKBOX", "Флажок", "#f39c12"),
        ("RADIO_GROUP", "Радиокнопки", "#1abc9c"),
        ("TABLE", "Таблица", "#34495e"),
        ("CALCULATED", "Вычисляемое", "#95a5a6"),
        ("QR", "QR-код", "#000000"),
    ]
```

### Drag-and-Drop

```python
class DraggableFieldType:
    """Перетаскиваемый тип поля."""

    def __init__(self, parent: Widget, field_type: FieldType):
        self.label = Label(parent, text=field_type.label)
        self.label.bind("<ButtonPress-1>", self.on_drag_start)
        self.label.bind("<B1-Motion>", self.on_drag)
        self.label.bind("<ButtonRelease-1>", self.on_drop)

    def on_drop(self, event: Event):
        """Обработка отпускания на Canvas."""
        # Преобразуем координаты в сетку
        canvas = event.widget.winfo_containing(event.x_root, event.y_root)
        if isinstance(canvas, TemplateDesignerCanvas):
            col, row = canvas.snap_to_grid(event.x, event.y)
            canvas.create_field(self.field_type, col, row)
```

---

## Property Panel

### Редактирование свойств

```python
class PropertyPanel(Frame):
    """Панель редактирования свойств поля."""

    def __init__(self, parent: Widget):
        super().__init__(parent)
        self.current_field: FieldDefinition | None = None
        self._create_widgets()

    def _create_widgets(self):
        """Создает виджеты для редактирования."""
        # Основные свойства
        Label(self, text="Field ID:").grid(row=0, column=0)
        self.field_id_var = StringVar()
        Entry(self, textvariable=self.field_id_var).grid(row=0, column=1)

        Label(self, text="Label:").grid(row=1, column=0)
        self.label_var = StringVar()
        Entry(self, textvariable=self.label_var).grid(row=1, column=1)

        Label(self, text="X (col):").grid(row=2, column=0)
        self.x_var = IntVar()
        Spinbox(self, from_=0, to=79, textvariable=self.x_var).grid(row=2, column=1)

        Label(self, text="Y (row):").grid(row=3, column=0)
        self.y_var = IntVar()
        Spinbox(self, from_=0, to=65, textvariable=self.y_var).grid(row=3, column=1)

        Label(self, text="Width:").grid(row=4, column=0)
        self.width_var = IntVar(value=20)
        Spinbox(self, from_=1, to=80, textvariable=self.width_var).grid(row=4, column=1)

        Label(self, text="Required:").grid(row=5, column=0)
        self.required_var = BooleanVar()
        Checkbutton(self, variable=self.required_var).grid(row=5, column=1)

        # Обновление при изменении
        self.field_id_var.trace("w", self._on_field_changed)
        self.label_var.trace("w", self._on_field_changed)
        # ...
```

---

## Export to .fxstpl

### Формат шаблона

```python
@dataclass
class Template:
    """Шаблон формы (.fxstpl)."""
    template_id: str
    name: str
    doc_type: str
    version: str = "1.0"
    fields: list[FieldDefinition]
    layout: TemplateLayout
    created_at: datetime
    signature: bytes  # Подпись master key

@dataclass
class TemplateLayout:
    """Параметры layout шаблона."""
    page_size: PageSize = PageSize.LETTER
    cpi: int = 10
    lpi: int = 6
    margins: Margins  # В символах/строках
```

### Экспорт

```python
class TemplateExporter:
    """Экспорт шаблона в .fxstpl."""

    def export(self, template: Template, path: Path) -> None:
        """Экспортирует шаблон с подписью."""
        # Сериализация
        data = json.dumps(template.to_dict()).encode()

        # Шифрование
        encrypted = crypto_service.encrypt(data)

        # Подпись
        signature = crypto_service.sign(encrypted)

        # Запись
        with open(path, "wb") as f:
            f.write(b"FXSTPL")  # Magic bytes
            f.write(struct.pack("<H", 1))  # Version
            f.write(signature)
            f.write(encrypted)
```

---

## Usage Example

### Создание шаблона

```python
from src.documents.constructor.template_designer import FormTemplateDesigner

# Создаем дизайнер
designer = FormTemplateDesigner()

# Добавляем поля из палитры
designer.canvas.create_field(
    field_type=FieldType.TEXT_INPUT,
    x_column=10,
    y_row=5,
    width_chars=30,
    label="Номер документа"
)

# Экспортируем шаблон
template = designer.export_template()
template.save(Path("./templates/invoice_v1.fxstpl"))
```

### Открытие существующего шаблона

```python
# Загружаем шаблон
template = Template.load(Path("./templates/invoice_v1.fxstpl"))

# Открываем в дизайнере
designer = FormTemplateDesigner()
designer.load_template(template)
```

---

## Integration

### С FormValidator

```python
# При сохранении шаблона — валидация
validator = SchemaLinter()
results = validator.check_conflicts(template.schema)

if results:
    designer.show_errors(results)
    raise TemplateValidationError("Cannot save template with conflicts")
```

### С FormHistory

```python
# При тестовом заполнении — сохранение в историю
test_mode = TestFillMode()
test_data = test_mode.generate_synthetic_data(template.schema)

# Сохраняем в историю (для автозаполнения)
for field_id, value in test_data.items():
    form_history.add_entry(field_id, value, template.doc_type)
```

---

## Security Considerations

### Подпись шаблонов

- Все шаблоны подписываются master key
- При импорте проверяется подпись
- Неподписанные/изменённые шаблоны отклоняются

### Проверка при экспорте

```python
def validate_before_export(template: Template) -> bool:
    """Проверяет шаблон перед экспортом."""
    linter = SchemaLinter()

    # Проверка конфликтов позиций
    results = linter.check_conflicts(template.schema)
    if any(r.severity == Severity.ERROR for r in results):
        return False

    # Проверка покрытия полей
    results = linter.check_coverage(template.schema, renderer)
    if any(r.severity == Severity.ERROR for r in results):
        return False

    return True
```

---

## Related Documents

- [ARCHITECTURE.md](./ARCHITECTURE.md) — Общая архитектура
- [API_REFERENCE.md](./API_REFERENCE.md) — API Reference
- [template_library.md](./template_library.md) — Управление библиотекой шаблонов
- [SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md) — Безопасность
