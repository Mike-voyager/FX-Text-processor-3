# План рефакторинга template_import_dialog.py

## Обзор файла

Файл: `/home/Mike/Dev/FX-Text-processor/FX-Text-processor-3/src/gui/dialogs/template_import_dialog.py`
Текущий размер: 745 строк

## Что удалить

### 1. Встроенный класс `TrustChainVerificationDialog` (строки 476-577)

**Причина удаления:**
- Это встроенная заглушка (placeholder) реализации
- Не использует реальные сервисы проверки подписей
- Данные в `_load_trust_chain()` захардкожены

**Код для удаления:**
```python
class TrustChainVerificationDialog(tk.Toplevel):
    # Строки 476-577 - весь класс
```

### 2. Встроенный класс `FloppyOptimizerDialog` (строки 579-745)

**Причина удаления:**
- Это встроенная заглушка реализации
- Расчеты оптимизации упрощенные/захардкоженные
- `_recalculate()` использует фиксированные проценты (30%, 10%)
- `_on_optimize()` не выполняет реальную оптимизацию

**Код для удаления:**
```python
class FloppyOptimizerDialog(tk.Toplevel):
    # Строки 579-745 - весь класс
```

## Что добавить

### Новые imports

```python
# Trust Chain диалог (новый отдельный модуль)
from src.gui.dialogs.trust_chain_dialog import TrustChainDialog

# Floppy Optimizer диалог (новый отдельный модуль)
from src.gui.dialogs.floppy_optimizer_dialog import FloppyOptimizerDialog

# Trust Chain сервисы (для интеграции)
from src.security.trust_chain import TrustChainVerifier, TrustChainResult

# Floppy Optimizer сервисы (для интеграции)
from src.security.crypto.utilities.floppy_optimizer import (
    FloppyOptimizer,
    OptimizationOptions,
    OptimizationResult,
)
```

### Константы для интеграции

```python
# Добавить после существующих констант
TRUST_CHAIN_DETAIL_TEXT: Final[str] = "Подробнее..."  # Кнопка для открытия TrustChainDialog
FLOPPY_OPT_BUTTON_TEXT: Final[str] = "Оптимизировать для дискеты"  # Новая кнопка
```

## Какие методы изменить

### 1. Метод `_create_ui()`

**Текущее состояние:**
- Создает Trust Chain секцию с кнопкой "Проверить"
- Нет кнопки для открытия детального просмотра Trust Chain
- Нет интеграции с FloppyOptimizer

**Изменения:**

#### В секцию "Проверка подписи" добавить кнопку детализации:
```python
# Trust chain section (модификация существующего)
trust_frame = ttk.LabelFrame(main_frame, text="Проверка подписи", padding="10")
trust_frame.pack(fill=tk.X, pady=(0, 10))

self._trust_var = tk.StringVar(value="Подпись не проверена")
self._trust_label = ttk.Label(trust_frame, textvariable=self._trust_var)
self._trust_label.pack(side=tk.LEFT)

# Кнопки в одном фрейме
btn_frame_trust = ttk.Frame(trust_frame)
btn_frame_trust.pack(side=tk.RIGHT)

self._verify_btn = ttk.Button(
    btn_frame_trust, text="Проверить", command=self._on_verify, state=tk.DISABLED
)
self._verify_btn.pack(side=tk.LEFT, padx=(0, 5))

# НОВАЯ: Кнопка детализации Trust Chain (изначально скрыта)
self._trust_detail_btn = ttk.Button(
    btn_frame_trust,
    text=TRUST_CHAIN_DETAIL_TEXT,
    command=self._on_show_trust_details,
    state=tk.DISABLED,
)
self._trust_detail_btn.pack(side=tk.LEFT)
```

#### Добавить секцию оптимизации для дискеты:
```python
# Floppy optimization section (НОВАЯ)
floppy_frame = ttk.LabelFrame(main_frame, text="Размер и оптимизация", padding="10")
floppy_frame.pack(fill=tk.X, pady=(0, 10))

self._size_var = tk.StringVar(value="Размер: -")
ttk.Label(floppy_frame, textvariable=self._size_var).pack(side=tk.LEFT)

# НОВАЯ: Кнопка оптимизации (изначально скрыта)
self._optimize_btn = ttk.Button(
    floppy_frame,
    text=FLOPPY_OPT_BUTTON_TEXT,
    command=self._on_optimize_floppy,
    state=tk.DISABLED,
)
self._optimize_btn.pack(side=tk.RIGHT)
```

### 2. Метод `_on_verify()`

**Текущее состояние (строки 402-431):**
- Простая проверка подписи через `template_manager.verify_template_signature()`
- Обновляет только UI статуса

**Необходимые изменения:**

```python
def _on_verify(self) -> None:
    """Обработчик кнопки 'Проверить' подпись."""
    if not self._template or not self._selected_path:
        return

    try:
        # Read signature data
        with open(self._selected_path, "rb") as f:
            data = f.read()

        # Store data for detailed view
        self._signature_data = data

        # Attempt verification
        is_valid = self._template_manager.verify_template_signature(data)
        self._signature_valid = is_valid

        # Get detailed trust chain info (NEW)
        self._trust_chain_result = self._template_manager.get_trust_chain_info(data)

        # Update UI
        if is_valid:
            self._trust_var.set("✓ Подпись валидна")
            self._trust_label.config(foreground=COLOR_SUCCESS)
            # NEW: Enable detail button
            self._trust_detail_btn.config(state=tk.NORMAL)
        else:
            self._trust_var.set("✗ Подпись невалидна или отсутствует")
            self._trust_label.config(foreground=COLOR_ERROR)
            self._trust_detail_btn.config(state=tk.DISABLED)

        # Update preview
        self._preview_panel.show_template(self._template, is_valid)

        logger.info("Template signature verified: %s", is_valid)

    except Exception as e:
        logger.error("Signature verification failed: %s", e)
        messagebox.showerror("Ошибка", f"Не удалось проверить подпись:\n{e}")
        self._trust_detail_btn.config(state=tk.DISABLED)
```

### 3. Метод `_on_import()`

**Текущее состояние (строки 433-459):**
- Простой импорт через `template_manager.import_template()`
- Нет проверки размера
- Нет оптимизации для дискеты

**Необходимые изменения:**

```python
def _on_import(self) -> None:
    """Обработчик кнопки 'Импортировать'."""
    if not self._template or not self._selected_path:
        return

    try:
        data = self._selected_path.read_bytes()
        original_size = len(data)

        # NEW: Check if floppy optimization needed
        if original_size > FloppyOptimizer.MAX_FLOPPY_BYTES:
            result = messagebox.askyesno(
                "Большой файл",
                f"Размер шаблона ({original_size:,} bytes) превышает лимит дискеты.\n\n"
                "Открыть диалог оптимизации?",
            )
            if result:
                self._on_optimize_floppy()
                # Если оптимизация отменена, прервать импорт
                if self._optimized_data is None:
                    return
                data = self._optimized_data

        # Import template
        imported = self._template_manager.import_template(data)

        self._result = ImportResult.success(
            template_id=imported.template_id,
            template=imported,
        )

        logger.info("Template imported successfully: %s", imported.template_id)

        if self._on_import:
            self._on_import(self._result)

        self.destroy()

    except Exception as e:
        logger.error("Template import failed: %s", e)
        messagebox.showerror("Ошибка импорта", f"Не удалось импортировать шаблон:\n{e}")
        self._result = ImportResult.failure(str(e))
```

### 4. Новый метод `_on_show_trust_details()`

**Добавить в класс `TemplateImportDialog`:**

```python
def _on_show_trust_details(self) -> None:
    """Открывает диалог детального просмотра Trust Chain."""
    if not hasattr(self, '_signature_data') or self._signature_data is None:
        return

    try:
        dialog = TrustChainDialog(
            parent=self,
            signature_data=self._signature_data,
            trust_result=self._trust_chain_result,
        )
        dialog.show()
    except Exception as e:
        logger.error("Failed to show trust chain details: %s", e)
        messagebox.showerror("Ошибка", f"Не удалось открыть детали подписи:\n{e}")
```

### 5. Новый метод `_on_optimize_floppy()`

**Добавить в класс `TemplateImportDialog`:**

```python
def _on_optimize_floppy(self) -> None:
    """Открывает диалог оптимизации для дискеты."""
    if not self._selected_path:
        return

    try:
        data = self._selected_path.read_bytes()

        dialog = FloppyOptimizerDialog(
            parent=self,
            template_data=data,
            template=self._template,
        )
        success, optimized_data = dialog.show()

        if success and optimized_data:
            self._optimized_data = optimized_data
            messagebox.showinfo(
                "Оптимизация завершена",
                f"Размер уменьшен с {len(data):,} до {len(optimized_data):,} bytes",
            )
        else:
            self._optimized_data = None

    except Exception as e:
        logger.error("Floppy optimization failed: %s", e)
        messagebox.showerror("Ошибка", f"Не удалось оптимизировать:\n{e}")
        self._optimized_data = None
```

### 6. Метод `_load_template()`

**Добавить обновление UI размера:**

```python
def _load_template(self) -> None:
    """Загружает шаблон из выбранного файла."""
    if not self._selected_path:
        return

    try:
        # Load template without importing
        with open(self._selected_path, "rb") as f:
            data = f.read()

        # NEW: Update size display
        self._update_size_info(len(data))

        # Parse template
        template = self._template_manager._parse_template_data(data)
        self._template = template

        # Update preview
        self._preview_panel.show_template(template, None)

        # Enable buttons
        self._verify_btn.config(state=tk.NORMAL)
        self._import_btn.config(state=tk.NORMAL)

        # NEW: Enable optimize button if size > threshold
        if len(data) > 500_000:  # Показывать для файлов > 500KB
            self._optimize_btn.config(state=tk.NORMAL)

        logger.info("Template loaded for preview: %s", template.template_id)

    except Exception as e:
        logger.error("Failed to load template: %s", e)
        messagebox.showerror("Ошибка", f"Не удалось загрузить шаблон:\n{e}")
        self._preview_panel.clear()
        self._verify_btn.config(state=tk.DISABLED)
        self._import_btn.config(state=tk.DISABLED)
        self._optimize_btn.config(state=tk.DISABLED)
        self._trust_detail_btn.config(state=tk.DISABLED)
```

### 7. Новый метод `_update_size_info()`

```python
def _update_size_info(self, size_bytes: int) -> None:
    """Обновляет отображение размера файла."""
    size_kb = size_bytes / 1024
    if size_bytes > FloppyOptimizer.MAX_FLOPPY_BYTES:
        self._size_var.set(f"Размер: {size_bytes:,} bytes ({size_kb:.1f} KB) ⚠️ Превышает лимит дискеты")
    else:
        self._size_var.set(f"Размер: {size_bytes:,} bytes ({size_kb:.1f} KB) ✓")
```

## Атрибуты для добавления в `__init__`

```python
def __init__(...):
    # ... existing code ...

    # NEW: Для Trust Chain
    self._signature_data: Optional[bytes] = None
    self._trust_chain_result: Optional[TrustChainResult] = None

    # NEW: Для Floppy Optimizer
    self._optimized_data: Optional[bytes] = None
```

## Таблица изменений

| Что | Действие | Комментарий |
|-----|----------|-------------|
| `TrustChainVerificationDialog` | Удалить класс (строки 476-577) | Перенесен в отдельный модуль |
| `FloppyOptimizerDialog` | Удалить класс (строки 579-745) | Перенесен в отдельный модуль |
| `TrustChainDialog` | Добавить import | Новый диалог из `trust_chain_dialog.py` |
| `FloppyOptimizerDialog` (внешний) | Добавить import | Новый диалог из `floppy_optimizer_dialog.py` |
| `TrustChainVerifier`, `TrustChainResult` | Добавить import | Для интеграции Trust Chain |
| `FloppyOptimizer`, `OptimizationOptions`, `OptimizationResult` | Добавить import | Для интеграции оптимизации |
| `_create_ui()` | Изменить | Добавить кнопки детализации Trust Chain и оптимизации |
| `_on_verify()` | Изменить | Сохранять signature_data, enable detail button |
| `_on_import()` | Изменить | Добавить проверку размера и оптимизацию |
| `_load_template()` | Изменить | Добавить обновление размера |
| `_on_show_trust_details()` | Добавить | Новый метод |
| `_on_optimize_floppy()` | Добавить | Новый метод |
| `_update_size_info()` | Добавить | Новый метод |

## Итоговый размер файла после рефакторинга

Приблизительно: 400-450 строк (вместо 745)
- Удалено: ~270 строк (2 встроенных класса)
- Добавлено: ~50-60 строк (новые методы и импорты)

## Пример интеграции новых диалогов

### Пример вызова TrustChainDialog:

```python
# Внутри TemplateImportDialog._on_show_trust_details()
from src.gui.dialogs.trust_chain_dialog import TrustChainDialog

def _on_show_trust_details(self) -> None:
    dialog = TrustChainDialog(
        parent=self,
        signature_data=self._signature_data,
        trust_result=self._trust_chain_result,  # Опционально
    )
    dialog.show()
```

### Пример вызова FloppyOptimizerDialog:

```python
# Внутри TemplateImportDialog._on_optimize_floppy()
from src.gui.dialogs.floppy_optimizer_dialog import FloppyOptimizerDialog

def _on_optimize_floppy(self) -> None:
    dialog = FloppyOptimizerDialog(
        parent=self,
        template_data=data,
        template=self._template,  # Опционально, для контекста
    )
    success, optimized_data = dialog.show()
    if success:
        # Использовать optimized_data для импорта
        pass
```

## Зависимости от других модулей

### Для Trust Chain:
- `src/gui/dialogs/trust_chain_dialog.py` (новый файл)
- `src/security/trust_chain.py` (существующий сервис)
- `src/services/template_manager.py` (метод `get_trust_chain_info()` - возможно нужно добавить)

### Для Floppy Optimizer:
- `src/gui/dialogs/floppy_optimizer_dialog.py` (новый файл)
- `src/security/crypto/utilities/floppy_optimizer.py` (существующий)

## Примечания

1. **Backward compatibility:** Все существующие публичные API `TemplateImportDialog` остаются неизменными
2. **New optional dependencies:** Новые импорты используются только при вызове соответствующих методов
3. **Error handling:** Каждый новый метод имеет try/except для graceful degradation
4. **UI flow:** Пользователь может пропустить оптимизацию и импортировать оригинальный файл
