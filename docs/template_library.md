# Template Library

**Version:** 1.0
**Date:** March 2026
**Status:** Living Document
**Module:** `src/documents/constructor/template_library.py`

---

## Overview

Template Library — зашифрованная локальная библиотека шаблонов форм (`.fxstpl`). Обеспечивает хранение, версионирование и безопасный обмен шаблонами через физические носители (floppy, USB) в соответствии с принципом Air-Gap First.

**Ключевые особенности:**
- Зашифрованное хранение шаблонов
- Цифровая подпись master key
- Версионирование шаблонов
- Импорт/экспорт через физические носители
- Превью шаблонов

---

## Storage Location

### Директория библиотеки

```python
TEMPLATES_DIR = Path("~/.fxtextprocessor/templates/")
# или
TEMPLATES_DIR = Path("./data/templates/")
```

**Структура директории:**

```
~/.fxtextprocessor/templates/
├── index.json.enc          # Зашифрованный индекс библиотеки
├── thumbnails/             # Превью шаблонов
│   ├── tpl_001.png
│   └── tpl_002.png
└── templates/              # Сами шаблоны
    ├── invoice_v1.fxstpl
    ├── invoice_v2.fxstpl
    ├── verbal_note_2026.fxstpl
    └── custom/
        └── special_form.fxstpl
```

---

## Template Format (.fxstpl)

### Файловая структура

```python
@dataclass(frozen=True)
class TemplateFile:
    """Файл шаблона .fxstpl."""

    # Header (16 bytes)
    magic: bytes = b"FXSTPL"      # 6 bytes
    version: int = 1              # 2 bytes (uint16)
    reserved: bytes = b"\x00" * 8  # 8 bytes

    # Metadata (encrypted)
    metadata: TemplateMetadata

    # Content (encrypted)
    schema: TypeSchema
    layout: TemplateLayout
    fields: list[FieldDefinition]

    # Signature (64 bytes for Ed25519)
    signature: bytes
```

### Шифрование

```python
def encrypt_template(template: Template, key: bytes) -> bytes:
    """Шифрует шаблон перед сохранением."""

    # Сериализация
    data = json.dumps({
        "metadata": template.metadata.to_dict(),
        "schema": template.schema.to_dict(),
        "layout": template.layout.to_dict(),
        "fields": [f.to_dict() for f in template.fields]
    }).encode()

    # Сжатие
    compressed = gzip.compress(data)

    # Шифрование (AES-256-GCM)
    nonce = os.urandom(12)
    ciphertext = crypto_service.encrypt(compressed, key, nonce)

    return nonce + ciphertext
```

### Подпись

Каждый шаблон подписывается master key приложения:

```python
def sign_template(encrypted_data: bytes, private_key: bytes) -> bytes:
    """Создает подпись шаблона."""
    return Ed25519Signer().sign(private_key, encrypted_data)

def verify_signature(encrypted_data: bytes, signature: bytes, public_key: bytes) -> bool:
    """Верифицирует подпись шаблона."""
    return Ed25519Signer().verify(public_key, encrypted_data, signature)
```

---

## Template Index

### Индекс библиотеки

Для быстрого доступа к шаблонам используется зашифрованный индекс:

```python
@dataclass(frozen=True)
class TemplateIndex:
    """Индекс библиотеки шаблонов."""
    version: str = "1.0"
    last_updated: datetime
    entries: dict[str, TemplateIndexEntry]  # template_id -> entry

@dataclass(frozen=True)
class TemplateIndexEntry:
    """Запись в индексе."""
    template_id: str
    name: str
    doc_type: str
    version: str
    created_at: datetime
    modified_at: datetime
    file_path: Path
    thumbnail_path: Path | None
    signature_valid: bool
    size_bytes: int
```

**Хранение индекса:**

```python
INDEX_FILE = TEMPLATES_DIR / "index.json.enc"

def save_index(index: TemplateIndex) -> None:
    """Сохраняет индекс в зашифрованном виде."""
    data = json.dumps(index.to_dict()).encode()
    encrypted = crypto_service.encrypt(data)
    INDEX_FILE.write_bytes(encrypted)
```

---

## API

### TemplateLibrary

```python
class TemplateLibrary:
    """Управление библиотекой шаблонов."""

    def __init__(
        self,
        library_path: Path = TEMPLATES_DIR,
        crypto_service: CryptoServiceProtocol
    ):
        self.path = library_path
        self.crypto = crypto_service
        self._index: TemplateIndex | None = None
        self._load_index()
```

#### Импорт шаблона

```python
def import_template(
    self,
    source_path: Path,
    verify_signature: bool = True
) -> TemplateInfo:
    """Импортирует шаблон из внешнего файла.

    Args:
        source_path: Путь к файлу .fxstpl
        verify_signature: Проверять ли подпись

    Returns:
        TemplateInfo с метаданными импортированного шаблона

    Raises:
        TemplateSignatureError: Если подпись невалидна
        TemplateVersionError: Если версия не поддерживается
        TemplateCorruptedError: Если файл повреждён
    """
    # Читаем файл
    data = source_path.read_bytes()

    # Парсим header
    header = self._parse_header(data[:16])
    if header.magic != b"FXSTPL":
        raise TemplateCorruptedError("Invalid magic bytes")

    # Извлекаем подпись и данные
    signature = data[16:80]
    encrypted = data[80:]

    # Проверяем подпись
    if verify_signature:
        if not self._verify_signature(encrypted, signature):
            raise TemplateSignatureError("Template signature invalid")

    # Дешифруем
    decrypted = self.crypto.decrypt(encrypted)
    template = Template.from_bytes(decrypted)

    # Сохраняем в библиотеку
    dest_path = self.path / "templates" / f"{template.template_id}.fxstpl"
    shutil.copy(source_path, dest_path)

    # Генерируем превью
    thumbnail = self._generate_thumbnail(template)
    thumb_path = self.path / "thumbnails" / f"{template.template_id}.png"
    thumbnail.save(thumb_path)

    # Обновляем индекс
    self._add_to_index(template, dest_path, thumb_path)

    return TemplateInfo.from_template(template)
```

#### Экспорт шаблона

```python
def export_template(
    self,
    template_id: str,
    target_path: Path
) -> None:
    """Экспортирует шаблон на внешний носитель.

    Args:
        template_id: ID шаблона в библиотеке
        target_path: Путь для сохранения

    Raises:
        TemplateNotFoundError: Если шаблон не найден
    """
    # Находим шаблон в индексе
    entry = self._index.entries.get(template_id)
    if not entry:
        raise TemplateNotFoundError(f"Template {template_id} not found")

    # Копируем с проверкой подписи
    source = entry.file_path
    shutil.copy(source, target_path)

    # Логируем экспорт
    self.audit.log_event(
        AuditEventType.TEMPLATE_EXPORTED,
        details={"template_id": template_id, "path": str(target_path)}
    )
```

#### Список шаблонов

```python
def list_templates(
    self,
    doc_type: str | None = None,
    include_corrupted: bool = False
) -> list[TemplateInfo]:
    """Возвращает список шаблонов.

    Args:
        doc_type: Фильтр по типу документа (None = все)
        include_corrupted: Включать шаблоны с невалидной подписью

    Returns:
        Список TemplateInfo
    """
    results = []

    for entry in self._index.entries.values():
        # Фильтр по типу
        if doc_type and entry.doc_type != doc_type:
            continue

        # Фильтр по целостности
        if not include_corrupted and not entry.signature_valid:
            continue

        results.append(TemplateInfo.from_index_entry(entry))

    return sorted(results, key=lambda x: x.modified_at, reverse=True)
```

#### Получение превью

```python
def get_preview(self, template_id: str) -> Image.Image:
    """Возвращает превью шаблона.

    Args:
        template_id: ID шаблона

    Returns:
        PIL Image с превью

    Raises:
        TemplateNotFoundError: Если шаблон не найден
    """
    entry = self._index.entries.get(template_id)
    if not entry:
        raise TemplateNotFoundError(f"Template {template_id} not found")

    # Проверяем кеш
    if entry.thumbnail_path and entry.thumbnail_path.exists():
        return Image.open(entry.thumbnail_path)

    # Генерируем на лету
    template = self._load_template(entry.file_path)
    preview = self._generate_thumbnail(template)

    return preview
```

---

## Versioning

### Версии шаблонов

Каждый шаблон имеет независимую версию от версии документа:

```python
@dataclass(frozen=True)
class TemplateVersion:
    """Версия шаблона."""
    major: int      # Несовместимые изменения
    minor: int      # Новые поля (обратно совместимо)
    patch: int      # Исправления

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"
```

**Правила версионирования:**

| Изменение | Версия | Пример |
|-----------|--------|--------|
| Добавление поля | minor | 1.0.0 → 1.1.0 |
| Удаление поля | major | 1.1.0 → 2.0.0 |
| Исправление позиции | patch | 1.1.0 → 1.1.1 |
| Изменение типа поля | major | 1.1.1 → 2.0.0 |

### Сравнение версий

```python
class SchemaDocumentationGenerator:
    """Генератор документации и diff."""

    def diff(self, old: TypeSchema, new: TypeSchema) -> SchemaDiff:
        """Сравнивает две версии схемы."""
        added = []
        removed = []
        modified = []

        old_fields = {f.field_id: f for f in old.fields}
        new_fields = {f.field_id: f for f in new.fields}

        # Добавленные поля
        for field_id in new_fields:
            if field_id not in old_fields:
                added.append(field_id)

        # Удалённые поля
        for field_id in old_fields:
            if field_id not in new_fields:
                removed.append(field_id)

        # Изменённые поля
        for field_id in old_fields:
            if field_id in new_fields:
                old_field = old_fields[field_id]
                new_field = new_fields[field_id]
                if old_field != new_field:
                    modified.append((field_id, str(old_field), str(new_field)))

        # Проверка совместимости
        compatibility_broken = bool(removed or modified)

        return SchemaDiff(added, removed, modified, compatibility_broken)
```

---

## Physical Media Transfer

### Air-Gap Transfer

Импорт/экспорт через физические носители:

```python
class PhysicalMediaTransfer:
    """Передача шаблонов через физические носители."""

    SUPPORTED_MEDIA = [
        "/media/floppy",      # 3.5" floppy
        "/media/usb",         # USB flash
        "/media/external",   # External HDD
    ]

    def detect_media(self) -> list[Path]:
        """Обнаруживает подключённые носители."""
        found = []
        for path in self.SUPPORTED_MEDIA:
            if Path(path).exists():
                found.append(Path(path))
        return found

    def import_from_media(self, media_path: Path) -> list[TemplateInfo]:
        """Импортирует все шаблоны с носителя."""
        imported = []

        for file in media_path.glob("*.fxstpl"):
            try:
                info = self.library.import_template(file)
                imported.append(info)
            except TemplateSignatureError:
                # Пропускаем неподписанные
                continue

        return imported

    def export_to_media(
        self,
        template_ids: list[str],
        media_path: Path
    ) -> None:
        """Экспортирует шаблоны на носитель."""
        for template_id in template_ids:
            target = media_path / f"{template_id}.fxstpl"
            self.library.export_template(template_id, target)
```

### Floppy Optimization

```python
class FloppyTemplateOptimizer:
    """Оптимизация шаблонов для дискет 1.44MB."""

    MAX_SIZE = 1_340_000  # ~1.28MB с запасом

    def optimize_for_floppy(self, template: Template) -> Template:
        """Оптимизирует шаблон для записи на дискету."""
        # Удаляем превью высокого разрешения
        template.thumbnail = None

        # Минимизируем JSON
        template.compact_json = True

        return template

    def fits_on_floppy(self, template: Template) -> bool:
        """Проверяет, поместится ли шаблон на дискету."""
        size = len(template.to_bytes())
        return size <= self.MAX_SIZE
```

---

## Security

### Verification on Import

```python
def import_with_verification(self, source_path: Path) -> TemplateInfo:
    """Импорт с полной верификацией."""

    # 1. Проверка подписи
    if not self._verify_signature(source_path):
        raise SecurityError("Template signature invalid")

    # 2. Проверка целостности
    if not self._verify_integrity(source_path):
        raise SecurityError("Template corrupted")

    # 3. Проверка на вредоносные поля
    template = self._load_template(source_path)
    if self._contains_suspicious_fields(template):
        raise SecurityError("Template contains suspicious fields")

    # 4. Проверка цепочки доверия (если импортирован с другой системы)
    if not self._verify_trust_chain(template):
        raise SecurityError("Template not in trust chain")

    # Импорт
    return self._import_template(template)
```

### Trust Chain

```python
def _verify_trust_chain(self, template: Template) -> bool:
    """Проверяет цепочку доверия для шаблона извне."""

    # Проверяем, что подпись сделана известным ключом
    public_key = template.signature_public_key

    # Проверяем против whitelist
    if public_key not in self.trusted_keys:
        return False

    # Проверяем timestamp (не старше 1 года)
    if template.created_at < datetime.now() - timedelta(days=365):
        return False

    return True
```

---

## Usage Examples

### Импорт шаблона с USB

```python
from src.documents.constructor.template_library import TemplateLibrary

library = TemplateLibrary()

# Обнаруживаем USB
media = library.detect_media()
if media:
    # Импортируем все шаблоны
    imported = library.import_from_media(media[0])
    print(f"Imported {len(imported)} templates")
```

### Экспорт на floppy

```python
# Экспортируем шаблон
library.export_template(
    template_id="invoice_v2",
    target_path=Path("/media/floppy/invoice_v2.fxstpl")
)

# Проверяем размер
if library.fits_on_floppy("invoice_v2"):
    print("Template fits on floppy")
```

### Спис шаблонов с фильтром

```python
# Все шаблоны для счетов
invoices = library.list_templates(doc_type="INV")

for template in invoices:
    print(f"{template.name} v{template.version}")
    print(f"  Valid: {template.signature_valid}")
```

---

## Related Documents

- [ARCHITECTURE.md](./ARCHITECTURE.md) — Общая архитектура
- [form_designer.md](./form_designer.md) — Визуальный конструктор
- [SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md) — Безопасность
