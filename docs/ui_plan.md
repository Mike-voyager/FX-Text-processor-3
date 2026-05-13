# UI Plan: План пользовательского интерфейса

> Документ содержит все принятые архитектурные решения по пользовательскому интерфейсу FX Text Processor 3.

---

## Содержание

1. [Общие принципы](#общие-принципы)
2. [Архитектура MVC](#архитектура-mvc)
3. [PrintDialog — Диалог печати](#printdialog--диалог-печати)
4. [FormatToolbar — Панель форматирования](#formattoolbar--панель-форматирования)
5. [MainToolbar — Главная панель инструментов](#maintoolbar--главная-панель-инструментов)
6. [Постраничная печать](#постраничная-печать)
7. [ESC/P трёхуровневая модель](#escp-трёхуровневая-модель)
8. [Модель данных Paragraph](#модель-данных-paragraph)
9. [Темы оформления](#темы-оформления)
10. [Горячие клавиши](#горячие-клавиши)
11. [Статус-бар](#статус-бар)
12. [Диалоги](#диалоги)

---

## Общие принципы

### WYSIWYP — What You See Is What You Print

**Ключевая концепция:** Форматирование текста (CPI, шрифты, выравнивание) выполняется в редакторе, настройки сохраняются вместе с документом, а на печать отправляется уже готовый отформатированный документ.

**Разделение ответственности:**

| Компонент | Назначение |
|-----------|------------|
| **FormatToolbar** | CPI, Quality, CodePage, Alignment, Styles |
| **PageSetupDialog** | Размер, поля, ориентация, межстрочный интервал |
| **PrintDialog** | Выбор принтера, копии, приоритет, постраничная печать |
| **MainToolbar** | Быстрые действия: Новый, Открыть, Сохранить, Печать |

### Retro-стиль (VT100/DOS/Matrix)

Все компоненты UI используют единый набор тем:

| Тема | Фон | Текст | Акцент |
|------|-----|-------|--------|
| classic_green | #000000 | #00FF00 | #00AA00 |
| amber | #000000 | #FFB000 | #AA7700 |
| dos_blue | #0000AA | #FFFFFF | #0000FF |
| paper_white | #FFFFFF | #000000 | #AAAAAA |
| matrix | #000000 | #00FF41 | #00AA00 |

### Принцип: Read-Only Info Panel

Настройки документа (CPI, Quality, CodePage, PageSize) в PrintDialog отображаются только для чтения. Изменение — через FormatToolbar или PageSetupDialog.

---

## Архитектура MVC

### Слои (строго снизу вверх, без пропусков)

```
┌─────────────────────────────────────────────────────────────────┐
│                        View (Tkinter)                           │
│  MainWindow, DocumentView, FormatToolbar, MainToolbar, Dialogs │
└─────────────────────────────────────────────────────────────────┘
                              ↓ callbacks
┌─────────────────────────────────────────────────────────────────┐
│                        Controller                               │
│  AppController, DocumentController                             │
└─────────────────────────────────────────────────────────────────┘
                              ↓ calls
┌─────────────────────────────────────────────────────────────────┐
│                        Service Layer                            │
│  PrintQueueService, ExportService, FindReplaceService, etc.     │
└─────────────────────────────────────────────────────────────────┘
                              ↓ uses
┌─────────────────────────────────────────────────────────────────┐
│                        Model                                    │
│  Document, Paragraph, Run, PrinterSettings, PageSettings       │
└─────────────────────────────────────────────────────────────────┘
```

### Ключевые правила

1. **View** — только отображение и callbacks к Controller
2. **Controller** — координация View ↔ Service, без сложной логики
3. **Service** — вся бизнес-логика, DI через конструктор
4. **Model** — frozen dataclasses, без бизнес-логики

---

## PrintDialog — Диалог печати

### Структура (упрощённая)

```
┌─────────────────────────────────────────────────────────────────┐
│  Параметры документа (только чтение)                            │
│  ───────────────────────────────────────────────────────────────│
│  CPI: 12 │ Качество: Draft │ PC866                              │
│  Страница: A4 Портрет │ 66 строк/страница                       │
│  Для изменения настроек используйте Format Toolbar             │
├─────────────────────────────────────────────────────────────────┤
│  [ Принтер ]  [ Тест ]                                          │
├─────────────────────────────────────────────────────────────────┤
│  Вкладка "Принтер":                                             │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Выберите принтер: [CUPS-PDF▼]                               ││
│  │ Количество копий: [1]                                       ││
│  │ [✓] Постраничная печать (с подтверждением каждой страницы) ││
│  │ Приоритет: [Обычный▼]                                       ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                 │
│  Вкладка "Тест":                                                │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Тестовая печать ESC/P                                       ││
│  │ Настройки: CPI: 12 │ Draft │ PC866                          ││
│  │ [ Печать тестовой страницы ]                                 ││
│  │ • ESC @ — сброс принтера                                    ││
│  │ • Таблица символов                                          ││
│  │ • Тест CPI, выравнивания, стилей                            ││
│  └─────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────┤
│                              [ Отмена ]  [ Печать ]            │
└─────────────────────────────────────────────────────────────────┘
```

### Убрано (перенесено)

| Было | Стало |
|------|-------|
| Вкладка "Страница" (размер, поля, ориентация) | PageSetupDialog |
| Вкладка "Качество" (CPI, Quality, CodePage) | FormatToolbar |

### Код

**Файл:** `src/view/dialogs/print_dialog.py`

**Ключевые классы:**
- `PrintDialog` — основной диалог
- `TestPageGenerator` — генератор тестовой страницы ESC/P

**Интеграция:**
```python
# MainWindow._on_print открывает PrintDialog
dialog = PrintDialog(
    parent=self._root,
    print_queue=self._print_queue,
    document=document,
    theme=self._theme,
)
job_id = dialog.show()
```

---

## FormatToolbar — Панель форматирования

### Расположение

Под меню, над редактором текста.

### Структура

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ CPI: [10][12][15][17][20][Prop] │ Quality: [Draft▼] │ Font: [---▼]         │
│ Align: [↤][↔][↦][▤]             │ Styles: [B][I][U][D²]                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Области применения

| Уровень | Параметры | Где меняется |
|---------|-----------|--------------|
| **Document** | CPI, CodePage | FormatToolbar (весь документ) |
| **Line** | Quality, Font, LineSpacing | FormatToolbar (выделенные строки) |
| **Span** | Bold, Italic, Underline | FormatToolbar (выделенный текст) |

### Логика применения

```python
class FormatToolbar:
    def apply_cpi(self, cpi: CharactersPerInch) -> None:
        """Применяет CPI ко всему документу."""
        self._document.printer_settings.characters_per_inch = cpi
        self._document.is_modified = True
        self._render_preview()

    def apply_quality(self, quality: PrintQuality) -> None:
        """Применяет Quality к текущей строке или выделенным строкам."""
        for paragraph in self._get_selected_paragraphs():
            paragraph.quality = quality
        self._document.is_modified = True
```

### Код

**Файл:** `src/view/format_toolbar.py`

---

## MainToolbar — Главная панель инструментов

### Структура

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ [📄 Новый] [📂 Открыть] [💾 Сохранить] │ [🖨️ Печать] [⚡ Быстрая печать]   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Кнопки

| Кнопка | Callback | Горячая клавиша |
|--------|----------|-----------------|
| 📄 Новый | `on_new()` | Ctrl+N |
| 📂 Открыть | `on_open()` | Ctrl+O |
| 💾 Сохранить | `on_save()` | Ctrl+S |
| 🖨️ Печать | `on_print()` | Ctrl+P |
| ⚡ Быстрая печать | `on_quick_print()` | Ctrl+Shift+P |

### Различие "Печать" и "Быстрая печать"

| Действие | Печать (🖨️) | Быстрая печать (⚡) |
|----------|--------------|---------------------|
| Диалог | Открывает PrintDialog | Нет диалога |
| Настройки | Можно изменить | Текущие из документа |
| Копии | Можно задать | Всегда 1 копия |
| Постраничная | Можно включить | Всегда выкл |

### Код

**Файл:** `src/view/main_toolbar.py`

---

## Постраничная печать

### Концепция

Многостраничные документы печатаются по одной странице с подтверждением. Порядок: **сначала все копии страницы 1, потом все копии страницы 2**.

### UI в режиме постраничной печати

```
┌─────────────────────────────────────────────────────────────────┐
│  [✓] Постраничная печать (с подтверждением каждой страницы)    │
│                                                                 │
│  Текущая страница: 1 из 5    Копия: 1 из 3                     │
│                                                                 │
│  [ Печать текущей ]  [ Следующая страница ]  [ Пропустить ]    │
└─────────────────────────────────────────────────────────────────┘
```

### После последней страницы

```
┌─────────────────────────────────────────────────────────────────┐
│  ✅ Печать завершена                                            │
│                                                                 │
│  Документ "Отчёт.fxsd" успешно напечатан.                        │
│  Страниц: 5 │ Копий: 3                                          │
│                                                                 │
│  [ Выйти ]  [ Ещё один экземпляр ]                              │
└─────────────────────────────────────────────────────────────────┘
```

### Класс PagePrinter

**Файл:** `src/services/page_printer_service.py`

```python
class PagePrinter:
    """Управляет процессом постраничной печати."""

    def __init__(self, document: Document, copies: int = 1) -> None:
        self._document = document
        self._copies = max(1, copies)
        self._current_page: int = 1
        self._current_copy: int = 1
        self._is_complete: bool = False

    def get_progress(self) -> PageProgress:
        """Возвращает текущий прогресс (страница, копия, завершено)."""

    def advance(self) -> PageProgress:
        """Переходит к следующей копии/странице."""

    def skip_page(self) -> PageProgress:
        """Пропускает текущую страницу."""

    def start_new_copy(self) -> None:
        """Начинает новый экземпляр после завершения."""
```

### Порядок печати

```
Копия 1, Страница 1 → подтверждение → Копия 2, Страница 1 → подтверждение →
Копия 3, Страница 1 → подтверждение → Копия 1, Страница 2 → подтверждение →
... → Копия 3, Страница 5 → "Печать завершена"
```

---

## ESC/P трёхуровневая модель

### Объяснение

| Уровень | Параметры | Команды ESC/P | Когда меняется |
|---------|-----------|---------------|----------------|
| **DocumentStyle** | CPI, CodePage | ESC P/M/g, ESC t n | Только между страницами |
| **LineStyle** | Quality, Font, LineSpacing | ESC x/y, ESC k n, ESC 3 n | Между строками (после CR LF) |
| **SpanStyle** | Bold, Italic, Underline | ESC E/F, ESC 4/5, ESC - | Внутри строки (в любом месте) |

### Модель данных

```
Document
├── printer_settings: PrinterSettings    # DocumentStyle ✅
│   ├── characters_per_inch (CPI)      # Уровень 1 ✅
│   └── codepage                         # Уровень 1 ✅
├── page_settings: PageSettings
│   └── line_spacing                     # Уровень 2 (переместить в Paragraph)
└── sections: List[Section]
    └── paragraphs: List[Paragraph]
        ├── alignment: Alignment         # Уровень 2 ✅
        ├── quality: PrintQuality         # Уровень 2 (НОВОЕ)
        ├── font_family: FontFamily       # Уровень 2 (НОВОЕ)
        └── runs: List[Run]
            └── styles: TextStyle         # Уровень 3 ✅
```

### Правила безопасного переключения

| Параметр | Document | Line boundary | Span |
|----------|----------|---------------|------|
| CPI | ✅ | ❌ | ❌ |
| CodePage | ✅ | ❌ | ❌ |
| Quality | ✅ | ✅ | ❌ |
| Font | ✅ | ✅ | ✅ |
| Bold/Italic/Underline | ✅ | ✅ | ✅ |

---

## Модель данных Paragraph

### Текущая структура

```python
@dataclass(slots=True)
class Paragraph:
    runs: List[Run] = field(default_factory=list)
    alignment: Alignment = Alignment.LEFT
    indent: float = 0.0
    spacing: float = 1.0
    # ... другие поля
```

### Планируемые изменения

**Файл:** `src/model/paragraph.py`

```python
@dataclass(slots=True)
class Paragraph:
    runs: List[Run] = field(default_factory=list)

    # Span-уровень (выравнивание)
    alignment: Alignment = Alignment.LEFT
    indent: float = 0.0

    # Line-уровень (ESC/P LineStyle) — НОВОЕ
    quality: PrintQuality = PrintQuality.DRAFT      # Draft/NLQ
    font_family: FontFamily = FontFamily.DRAFT      # Roman/Sans Serif
    char_size: CharSize = CharSize.NORMAL           # NORMAL/DOUBLE_WIDTH/DOUBLE_HEIGHT/CONDENSED
    line_spacing: Optional[int] = None              # n/216 дюйма

    # Для Double-height: флаг что следующая строка пустая
    _double_height_next: bool = field(default=False, repr=False)
```

### Новый Enum: CharSize

**Файл:** `src/model/enums.py`

```python
class CharSize(StringEnumMixin, str, Enum):
    NORMAL = "normal"
    DOUBLE_WIDTH = "double_width"      # ESC W 1
    DOUBLE_HEIGHT = "double_height"    # ESC w 1
    DOUBLE_WIDTH_HEIGHT = "double_wh"  # ESC W 1 + ESC w 1
    CONDENSED = "condensed"            # SI

    def occupies_lines(self) -> int:
        """Сколько строк в сетке занимает символ этого размера."""
        if self in (CharSize.DOUBLE_HEIGHT, CharSize.DOUBLE_WIDTH_HEIGHT):
            return 2
        return 1
```

---

## Темы оформления

### Структура тем

Каждая тема определяет цвета для:

| Ключ | Назначение |
|------|------------|
| `bg` | Фон |
| `fg` | Текст |
| `accent` | Акцент |
| `tab_bg` | Фон невыбранных вкладок |
| `tab_selected` | Фон выбранной вкладки |
| `menu_active` | Активный пункт меню |
| `button_bg` | Фон кнопки |
| `button_active` | Активная кнопка |
| `info_bg` | Фон информационной панели |

### Применение

```python
COLORS = {
    "classic_green": {
        "bg": "#000000",
        "fg": "#00FF00",
        "accent": "#00AA00",
        # ...
    },
    # ...
}

colors = COLORS.get(theme, COLORS["classic_green"])
```

### Файлы с темами

- `src/view/dialogs/print_dialog.py`
- `src/view/format_toolbar.py`
- `src/view/main_toolbar.py`
- `src/view/main_window.py`
- `src/view/status_bar.py`

---

## Горячие клавиши

### Стандартные

| Клавиша | Действие | Сервис |
|---------|----------|--------|
| Ctrl+N | Новый документ | DocumentManagerService |
| Ctrl+O | Открыть документ | — |
| Ctrl+S | Сохранить | — |
| Ctrl+P | Печать | PrintQueueService |
| Ctrl+Shift+P | Быстрая печать | PrintQueueService |
| Ctrl+Z | Отменить | CommandHistoryService |
| Ctrl+Y | Повторить | CommandHistoryService |
| Ctrl+X | Вырезать | ClipboardService |
| Ctrl+C | Копировать | ClipboardService |
| Ctrl+V | Вставить | ClipboardService |
| Ctrl+F | Найти | FindReplaceService |
| Ctrl+H | Заменить | FindReplaceService |
| Ctrl+A | Выделить всё | — |
| F1 | Справка | — |

### Настраиваемые

Пользователь может переназначать клавиши через `KeyBindingsService`.

```python
class KeyBindingsService:
    def register_action(self, action: Action, handler: Callable[[], None]) -> None:
        """Регистрирует действие для горячей клавиши."""
```

---

## Статус-бар

### Элементы

| Элемент | Описание | Обновление |
|---------|----------|------------|
| Ln/Col | Позиция курсора | При движении |
| CPI | Текущий CPI | При изменении |
| Modified | Статус модификации ([*]) | При редактировании |
| CodePage | Кодовая страница | При изменении |
| Security | Пресет безопасности с цветом | При входе/выходе |
| Page | Номер страницы | При прокрутке |
| Paper | Тип бумаги | При загрузке |

### Цветовая индикация Security

| Пресет | Цвет | Описание |
|--------|------|----------|
| legacy | 🔴 #FF0000 | RSA-PSS-4096 + AES-256-GCM + PBKDF2 |
| standard | 🟡 #FFFF00 | Ed25519 + AES-256-GCM + Argon2id |
| paranoid | 🟢 #00FF00 | Ed25519 + ML-DSA-65 + AES-256-GCM + ChaCha20 |
| pqc_standard | 🟣 #8B00FF | ML-DSA-65 + AES-256-GCM + Argon2id |

---

## Диалоги

### Реализованные

| Диалог | Файл | Назначение |
|--------|------|------------|
| OpenFileDialog | `src/view/dialogs/open_dialog.py` | Открытие .fxsd/.fxsd.enc |
| SaveFileDialog | `src/view/dialogs/save_dialog.py` | Сохранение |
| ConfirmDialog | `src/view/dialogs/confirm_dialog.py` | Подтверждение |
| AboutDialog | `src/view/dialogs/about_dialog.py` | О программе |
| FindReplaceDialog | `src/view/dialogs/find_replace_dialog.py` | Найти/Заменить |
| CryptoDialog | `src/view/dialogs/crypto_dialog.py` | Криптография |
| FileBrowser | `src/view/dialogs/file_browser.py` | Браузер файлов |
| PrintDialog | `src/view/dialogs/print_dialog.py` | Печать |

### Планируемые

| Диалог | Назначение |
|--------|------------|
| PageSetupDialog | Размер/поля/ориентация |
| AuthDialog | Аутентификация MFA |
| SettingsDialog | Настройки приложения |

---

## Тестовая страница ESC/P

### Содержимое

1. **ESC @** — сброс принтера
2. **ESC t n** — выбор кодовой страницы
3. **Таблица символов** 0x20-0xFF
4. **Тест CPI:** 10/12/15 cpi
5. **Тест выравнивания:** левое/центральное/правое
6. **Тест стилей:** Bold/Italic/Underline/Double-strike
7. **Тест графики:** полоса 120 dpi

### Код

**Файл:** `src/documents/printing/test_page_generator.py`

```python
class TestPageGenerator:
    def __init__(
        self,
        codepage: CodePage,
        cpi: CharactersPerInch,
        quality: PrintQuality,
    ) -> None:
        # ...

    def generate(self) -> bytes:
        """Генерирует тестовую страницу ESC/P."""
        result = bytearray()

        # ESC @ — сброс
        result.extend(ESC_AT)

        # ESC t n — кодовая страница
        result.extend(self._set_codepage())

        # ESC x n — качество
        result.extend(self._set_quality())

        # Таблица символов, тесты...
        result.extend(self._render_char_table())
        result.extend(self._render_cpi_test())
        result.extend(self._render_alignment_test())
        result.extend(self._render_style_test())
        result.extend(self._render_graphics_test())

        return bytes(result)
```

### CPI команды

| CPI | Команда | Скорость (cps) |
|-----|---------|----------------|
| 10 | ESC P | Draft: 419, HSD: 559, NLQ: 104 |
| 12 | ESC M | Draft: 503, HSD: 627, NLQ: 125 |
| 15 | ESC g | Semi-condensed |
| 17 | SI | Condensed from 10 cpi |
| 20 | SI + ESC M | Condensed from 12 cpi |
| Prop | ESC p 1 | Roman/Sans Serif only |

### Quality команды

| Режим | Команда |
|-------|---------|
| Draft | ESC x 0 |
| HSD | ESC x 0 + ESC y 1 |
| UHSD | ESC x 0 + ESC y 2 |
| NLQ | ESC x 1 |

---

## Файловые расширения

Все файлы приложения используют префикс `.fxs` (FX Super):

| Extension | Purpose |
|-----------|---------|
| .fxsd | Документ (незашифрованный) |
| .fxsd.enc | Зашифрованный документ |
| .fxstpl | Шаблон |
| .fxsblank | Защищённый бланк |
| .fxskeystore.enc | Хранилище ключей |
| .fxssig | Цифровая подпись |
| .fxsconfig | Конфигурация |
| .fxsbackup | Бэкап |
| .fxsbundle.enc | Экспортный пакет |
| .escp | Raw ESC/P команды |
| .escps | ESC/P скрипт |

---

## Приоритеты разработки

### Текущий приоритет (Q2 2026)

1. ✅ `src/documents/printing/` — ESC/P render pipeline
2. ✅ `src/printer/` — transport adapters (CUPS/Win/File)
3. ✅ `src/view/format_toolbar.py` — панель форматирования
4. ✅ `src/view/main_toolbar.py` — панель инструментов
5. 🔄 `src/view/dialogs/print_dialog.py` — постраничная печать
6. ⏳ `src/model/paragraph.py` — LineStyle поля
7. ⏳ GUI Editor (text_editor, ruler)
8. ⏳ GUI Forms (form_designer, field_palette)

---

## История изменений

| Дата | Изменение |
|------|-----------|
| 2026-03-26 | Создан документ. Описаны PrintDialog, FormatToolbar, MainToolbar, PagePrinter |
| 2026-03-26 | Добавлены секции: ESC/P трёхуровневая модель, Paragraph LineStyle, темы |

---

*Документ будет обновляться по мере развития проекта.*