# Form History

**Version:** 1.0
**Date:** March 2026
**Status:** Living Document
**Module:** `src/documents/constructor/form_history.py`

---

## Overview

Form History — локальная зашифрованная база истории заполнения полей форм. Используется для:
- Автозаполнения часто используемых значений
- Предложений на основе частоты использования
- Копирования значений из предыдущих документов той же серии
- Снижения времени заполнения повторяющихся форм

**Ключевые особенности:**
- Зашифрованное хранение (`.fxshistory.enc`)
- Частотно-ранжированные предложения
- Cross-document lookup (поиск по предыдущим документам серии)
- GDPR-compliant retention policy

---

## Storage

### Location

```python
HISTORY_DIR = Path("~/.fxtextprocessor/history/")
# или
HISTORY_DIR = Path("./data/history/")

HISTORY_FILE = HISTORY_DIR / "form_history.fxshistory.enc"
```

**Структура директории:**

```
~/.fxtextprocessor/history/
├── form_history.fxshistory.enc   # Основной файл истории
├── index.json.enc                # Индекс для быстрого поиска
└── backup/                       # Ротация бэкапов
    ├── form_history.20260301.fxshistory.enc
    └── form_history.20260315.fxshistory.enc
```

### Encryption

```python
class FormHistoryStorage:
    """Шифрованное хранилище истории."""

    def __init__(self, key: bytes):
        self.key = key
        self.cipher = AES256GCM(key)

    def save(self, entries: list[HistoryEntry]) -> None:
        """Сохраняет историю в зашифрованном виде."""
        # Сериализация
        data = json.dumps([e.to_dict() for e in entries]).encode()

        # Сжатие
        compressed = gzip.compress(data)

        # Шифрование
        nonce = os.urandom(12)
        ciphertext = self.cipher.encrypt(compressed, nonce)

        # HMAC для целостности
        hmac = HMAC(self.key).compute(ciphertext)

        # Запись
        with open(HISTORY_FILE, "wb") as f:
            f.write(nonce + ciphertext + hmac)

    def load(self) -> list[HistoryEntry]:
        """Загружает и расшифровывает историю."""
        data = HISTORY_FILE.read_bytes()

        nonce = data[:12]
        ciphertext = data[12:-32]
        hmac = data[-32:]

        # Проверка HMAC
        if not HMAC(self.key).verify(ciphertext, hmac):
            raise IntegrityError("History file corrupted")

        # Расшифровка
        compressed = self.cipher.decrypt(ciphertext, nonce)
        data = gzip.decompress(compressed)

        return [HistoryEntry.from_dict(d) for d in json.loads(data)]
```

---

## Data Model

### History Entry

```python
@dataclass(frozen=True)
class HistoryEntry:
    """Запись в истории заполнения поля."""
    entry_id: str               # UUID записи
    field_id: str               # ID поля (например, "client_name")
    value: str                  # Значение
    doc_type: str               # Тип документа (например, "INV")
    document_index: str | None # Индекс документа (например, "INV-XII")
    timestamp: datetime         # Время записи
    use_count: int = 1         # Счётчик использований (frequency)

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "field_id": self.field_id,
            "value": self.value,
            "doc_type": self.doc_type,
            "document_index": self.document_index,
            "timestamp": self.timestamp.isoformat(),
            "use_count": self.use_count
        }

    @classmethod
    def from_dict(cls, data: dict) -> "HistoryEntry":
        return cls(
            entry_id=data["entry_id"],
            field_id=data["field_id"],
            value=data["value"],
            doc_type=data["doc_type"],
            document_index=data.get("document_index"),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            use_count=data.get("use_count", 1)
        )
```

### Field Statistics

```python
@dataclass
class FieldStatistics:
    """Статистика использования поля."""
    field_id: str
    unique_values: int
    total_entries: int
    most_common: list[tuple[str, int]]  # (value, count)
    last_used: datetime
```

---

## API

### FormHistory

```python
class FormHistory:
    """История заполнения полей форм."""

    def __init__(
        self,
        history_path: Path = HISTORY_DIR,
        crypto_service: CryptoServiceProtocol,
        max_entries: int = 10000,
        retention_days: int = 90
    ):
        self.path = history_path
        self.crypto = crypto_service
        self.max_entries = max_entries
        self.retention_days = retention_days
        self._cache: dict[str, list[HistoryEntry]] = {}
        self._load()
```

#### Add Entry

```python
def add_entry(
    self,
    field_id: str,
    value: str,
    doc_type: str,
    document_index: str | None = None
) -> None:
    """Добавляет запись в историю.

    Если значение уже существует для этого поля,
    увеличиваем use_count вместо создания новой записи.
    """
    # Ищем существующую запись
    existing = self._find_entry(field_id, value)

    if existing:
        # Увеличиваем счётчик
        new_entry = HistoryEntry(
            entry_id=existing.entry_id,
            field_id=field_id,
            value=value,
            doc_type=doc_type,
            document_index=document_index,
            timestamp=datetime.now(),
            use_count=existing.use_count + 1
        )
        self._update_entry(existing, new_entry)
    else:
        # Создаём новую запись
        entry = HistoryEntry(
            entry_id=str(uuid4()),
            field_id=field_id,
            value=value,
            doc_type=doc_type,
            document_index=document_index,
            timestamp=datetime.now()
        )
        self._cache[field_id].append(entry)

    # Проверяем размер
    self._enforce_limits()

    # Сохраняем
    self._save()
```

#### Get Suggestions

```python
def get_suggestions(
    self,
    field_id: str,
    query: str = "",
    limit: int = 5,
    doc_type: str | None = None
) -> list[tuple[str, int]]:
    """Возвращает частотно-ранжированные предложения.

    Args:
        field_id: ID поля для поиска
        query: Частичный ввод для фильтрации (optional)
        limit: Максимальное количество предложений
        doc_type: Фильтр по типу документа (optional)

    Returns:
        Список (value, frequency), отсортированный по frequency DESC
    """
    entries = self._cache.get(field_id, [])

    # Фильтруем по doc_type если указан
    if doc_type:
        entries = [e for e in entries if e.doc_type == doc_type]

    # Фильтруем по query если указан
    if query:
        entries = [e for e in entries if query.lower() in e.value.lower()]

    # Сортируем по use_count DESC, затем по timestamp DESC
    entries.sort(key=lambda e: (-e.use_count, -e.timestamp.timestamp()))

    # Возвращаем топ-N
    return [(e.value, e.use_count) for e in entries[:limit]]
```

#### Prefill from Previous

```python
def prefill_from_previous(
    self,
    doc_type: str,
    series: str | None = None,
    limit: int = 1
) -> dict[str, str]:
    """Копирует значения из предыдущих документов.

    Ищет последние документы того же типа (и серии если указана)
    и возвращает их значения для автозаполнения.

    Args:
        doc_type: Тип документа (например, "INV")
        series: Серия документа (например, "K53", optional)
        limit: Сколько предыдущих документов использовать

    Returns:
        Словарь {field_id: value}
    """
    # Ищем записи по doc_type и series
    entries = []
    for field_entries in self._cache.values():
        for entry in field_entries:
            if entry.doc_type != doc_type:
                continue
            if series and entry.document_index:
                if not entry.document_index.startswith(f"{doc_type}-{series}"):
                    continue
            entries.append(entry)

    # Группируем по field_id, берём самые свежие
    result = {}
    entries_by_field: dict[str, list[HistoryEntry]] = {}

    for entry in entries:
        if entry.field_id not in entries_by_field:
            entries_by_field[entry.field_id] = []
        entries_by_field[entry.field_id].append(entry)

    # Для каждого поля берём значение из самого свежего документа
    for field_id, field_entries in entries_by_field.items():
        field_entries.sort(key=lambda e: e.timestamp, reverse=True)
        result[field_id] = field_entries[0].value

    return result
```

#### Cross-Document Lookup

```python
def lookup_in_series(
    self,
    doc_type: str,
    series: str,
    field_id: str
) -> list[tuple[str, str]]:
    """Ищет значения поля в документах серии.

    Пример: при вводе document_index = DVN-44-K53-*
    предложить известных получателей из предыдущих нот этой серии.

    Returns:
        Список (document_index, value)
    """
    results = []

    for entry in self._cache.get(field_id, []):
        if entry.doc_type != doc_type:
            continue
        if not entry.document_index:
            continue
        if f"{doc_type}-{series}" in entry.document_index:
            results.append((entry.document_index, entry.value))

    # Сортируем по индексу документа (новые первыми)
    results.sort(key=lambda x: x[0], reverse=True)

    return results
```

#### Maintenance

```python
def clear_old_entries(self, days: int | None = None) -> int:
    """Очищает старые записи.

    Args:
        days: Сколько дней хранить (None = используем retention_days)

    Returns:
        Количество удалённых записей
    """
    cutoff = datetime.now() - timedelta(days=days or self.retention_days)
    deleted = 0

    for field_id in list(self._cache.keys()):
        entries = self._cache[field_id]
        new_entries = [e for e in entries if e.timestamp > cutoff]
        deleted += len(entries) - len(new_entries)
        self._cache[field_id] = new_entries

        if not new_entries:
            del self._cache[field_id]

    self._save()
    return deleted

def enforce_max_entries(self) -> None:
    """Удаляет старые записи если превышен лимит."""
    total = sum(len(entries) for entries in self._cache.values())

    if total <= self.max_entries:
        return

    # Собираем все записи с timestamp
    all_entries = []
    for field_id, entries in self._cache.items():
        for entry in entries:
            all_entries.append((field_id, entry))

    # Сортируем по timestamp (старые в конце)
    all_entries.sort(key=lambda x: x[1].timestamp)

    # Удаляем лишние
    to_delete = total - self.max_entries
    for field_id, entry in all_entries[-to_delete:]:
        self._cache[field_id].remove(entry)

    self._save()
```

---

## UI Integration

### Autocomplete Widget

```python
class AutocompleteEntry(Entry):
    """Поле ввода с автодополнением из FormHistory."""

    def __init__(
        self,
        parent: Widget,
        field_id: str,
        form_history: FormHistory,
        doc_type: str | None = None,
        **kwargs
    ):
        super().__init__(parent, **kwargs)
        self.field_id = field_id
        self.history = form_history
        self.doc_type = doc_type

        # Список предложений
        self.suggestions: list[str] = []
        self.suggestion_window: Toplevel | None = None

        # Привязываем события
        self.bind("<KeyRelease>", self._on_key_release)
        self.bind("<Down>", self._on_down)
        self.bind("<Up>", self._on_up)
        self.bind("<Return>", self._on_return)
        self.bind("<FocusOut>", self._hide_suggestions)

    def _on_key_release(self, event):
        """Обновляет предложения при вводе."""
        query = self.get()
        if len(query) < 2:  # Не показываем для коротких запросов
            self._hide_suggestions()
            return

        # Получаем предложения
        suggestions = self.history.get_suggestions(
            self.field_id,
            query=query,
            limit=5,
            doc_type=self.doc_type
        )

        self.suggestions = [s[0] for s in suggestions]
        self._show_suggestions()

    def _show_suggestions(self):
        """Показывает окно с предложениями."""
        if not self.suggestions:
            return

        # Создаём окно
        self.suggestion_window = Toplevel(self)
        self.suggestion_window.overrideredirect(True)

        # Позиционируем под полем
        x = self.winfo_rootx()
        y = self.winfo_rooty() + self.winfo_height()
        self.suggestion_window.geometry(f"+{x}+{y}")

        # Список предложений
        listbox = Listbox(self.suggestion_window, width=self.winfo_width())
        for suggestion in self.suggestions:
            listbox.insert(END, suggestion)
        listbox.pack()

        listbox.bind("<Button-1>", self._on_suggestion_click)
```

### Prefill Dialog

```python
class PrefillDialog(Toplevel):
    """Диалог предзаполнения из предыдущих документов."""

    def __init__(
        self,
        parent: Widget,
        form_history: FormHistory,
        doc_type: str,
        series: str | None = None
    ):
        super().__init__(parent)
        self.title("Prefill from Previous")

        # Получаем данные
        prefilled = form_history.prefill_from_previous(doc_type, series)

        Label(self, text=f"Copy values from previous {doc_type}?").pack()

        # Список полей для копирования
        self.vars = {}
        for field_id, value in prefilled.items():
            var = BooleanVar(value=True)
            self.vars[field_id] = var

            frame = Frame(self)
            frame.pack(fill=X, padx=10, pady=2)

            Checkbutton(
                frame,
                text=f"{field_id}: {value[:30]}...",
                variable=var
            ).pack(side=LEFT)

        Button(self, text="Apply", command=self.apply).pack(pady=10)

    def apply(self):
        """Применяет выбранные значения."""
        selected = {
            field_id: value
            for field_id, var in self.vars.items()
            if var.get()
        }
        self.selected = selected
        self.destroy()
```

---

## Security & Privacy

### Data Minimization

```python
def sanitize_value(value: str, field_type: FieldType) -> str:
    """Очищает значение перед сохранением в историю.

    Удаляет или маскирует чувствительные данные.
    """
    # Не сохраняем пароли
    if field_type == FieldType.PASSWORD:
        return "[REDACTED]"

    # Маскируем номера карт
    if field_type == FieldType.CREDIT_CARD:
        return "****-****-****-" + value[-4:]

    # Маскируем SSN
    if field_type == FieldType.SSN:
        return "***-**-" + value[-4:]

    return value
```

### Retention Policy

```python
def enforce_retention_policy(self) -> None:
    """Применяет политику хранения (GDPR compliance)."""
    # Удаляем записи старше 90 дней
    self.clear_old_entries(days=90)

    # Ограничиваем общее количество
    self.enforce_max_entries()

    # Анонимизируем старые записи
    cutoff = datetime.now() - timedelta(days=30)

    for field_entries in self._cache.values():
        for entry in field_entries:
            if entry.timestamp < cutoff:
                # Удаляем document_index (PII)
                entry.document_index = None
```

---

## Usage Examples

### Basic Usage

```python
from src.documents.constructor.form_history import FormHistory

history = FormHistory(crypto_service=crypto)

# При заполнении формы сохраняем значения
history.add_entry(
    field_id="client_name",
    value="ООО Ромашка",
    doc_type="INV",
    document_index="INV-2026-XII"
)

# Получаем предложения
suggestions = history.get_suggestions(
    field_id="client_name",
    query="ром",
    limit=5
)
# [("ООО Ромашка", 15), ("ООО Ромашковый сад", 3), ...]
```

### Prefill from Series

```python
# Создаём новый документ в серии
new_doc = Document.create(type_code="DVN")

# Копируем значения из предыдущих документов серии K53
prefilled = history.prefill_from_previous(
    doc_type="DVN",
    series="K53",
    limit=1  # Только последний документ
)

# Применяем к новому документу
for field_id, value in prefilled.items():
    new_doc.fill_field(field_id, value)
```

### Cross-Document Lookup

```python
# Ищем получателей в серии DVN-44-K53-*
recipients = history.lookup_in_series(
    doc_type="DVN",
    series="K53",
    field_id="recipient_name"
)

# [("DVN-44-K53-IX", "Министерство"),
#  ("DVN-44-K53-VIII", "Департамент"), ...]
```

---

## Related Documents

- [ARCHITECTURE.md](./ARCHITECTURE.md) — Общая архитектура
- [form_designer.md](./form_designer.md) — Визуальный конструктор
- [approval_workflow.md](./approval_workflow.md) — Workflow согласования
- [SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md) — Безопасность
