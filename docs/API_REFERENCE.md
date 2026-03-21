# FX Text Processor 3 — API Reference

**Версия:** 3.1
**Дата:** March 2026 (updated 2026-03-18)
**Python:** 3.11+
**Архитектура:** MVC (Tkinter)

---

## Содержание

1. [Model Layer (`src/model/`)](#1-model-layer-srcmodel)
   - 1.1 [Document (`src/model/document.py`)](#11-document-srcmodeldocumentpy)
   - 1.2 [Enums (`src/model/enums.py`)](#12-enums-srcmodelenumspy)
   - 1.3 [Функции валидации](#13-функции-валидации)
2. [ESC/P Commands Layer (`src/escp/commands/`)](#2-escp-commands-layer-srcescpcommands)
   - 2.1 [text_formatting.py](#21-text_formattingpy)
   - 2.2 [barcode.py](#22-barcodepy)
   - 2.3 [fonts.py](#23-fontspy)
   - 2.4 [sizing.py](#24-sizingpy)
   - 2.5 [positioning.py](#25-positioningpy)
   - 2.6 [page_control.py](#26-page_controlpy)
   - 2.7 [line_spacing.py](#27-line_spacingpy)
   - 2.8 [print_quality.py](#28-print_qualitypy)
   - 2.9 [hardware.py](#29-hardwarepy)
   - 2.10 [charset.py](#210-charsetpy)
   - 2.11 [graphics.py](#211-graphicspy)
   - 2.12 [shading.py](#212-shadingpy)
   - 2.13 [special_effects.py](#213-special_effectspy)
3. [Document Types & Indexing (`src/documents/types/`)](#3-document-types--indexing-srcdocumentstypes)
   - 3.1 [TypeRegistry](#31-typeregistry)
   - 3.2 [IndexTemplate](#32-indextemplate)
   - 3.3 [FieldDefinition & TypeSchema](#33-fielddefinition--typeschema)
4. [Document Constructor (`src/documents/constructor/`)](#4-document-constructor-srcdocumentsconstructor)
   - 4.1 [ExcelImporter](#41-excelimporter)
   - 4.2 [VariableParser](#42-variableparser)
   - 4.3 [InputMask](#43-inputmask)
   - 4.4 [FormValidator](#44-formvalidator)
   - 4.5 [SchemaLinter](#45-schemalinter)
   - 4.6 [FormHistory](#46-formhistory)
   - 4.7 [TemplateLibrary](#47-templatelibrary)
   - 4.8 [ApprovalWorkflow](#48-approvalworkflow)
   - 4.9 [SchemaDocumentationGenerator](#49-schemadocumentationgenerator)
   - 4.10 [TestFillMode](#410-testfillmode)
5. [Document Rendering (`src/documents/printing/`)](#5-document-rendering-srcdocumentsprinting)
6. [Security API](#6-security-api)
   - 6.1 [CryptoService](#61-cryptoservice)
   - 6.2 [BlankManager](#62-blankmanager)
   - 6.3 [SessionManager](#63-sessionmanager)
   - 6.4 [ImmutableAuditLog](#64-immutableauditlog)
7. [Printer Adapters (`src/printer/`)](#7-printer-adapters-srcprinter)
8. [App Context (`src/app_context.py`)](#8-app-context-srcapp_contextpy)
9. [File Formats & Extensions](#9-file-formats--extensions)
10. [Editing Services API (`src/services/`)](#10-editing-services-api-srcservices)
    - 10.1 [CommandHistoryService](#101-commandhistoryservice)
    - 10.2 [FindReplaceService](#102-findreplaceservice)
    - 10.3 [AutoSaveService](#103-autosaveservice)
    - 10.4 [DocumentStatsService](#104-documentstatsservice)
    - 10.5 [ClipboardService](#105-clipboardservicen)
    - 10.6 [NotificationService](#106-notificationservice)
    - 10.7 [DocumentLockService](#107-documentlockservice)
    - 10.8 [VersionHistoryService](#108-versionhistoryservice)
    - 10.9 [DocumentManagerService](#109-documentmanagerservice)
    - 10.10 [ExportService](#1010-exportservice)
    - 10.11 [PrintQueueService](#1011-printqueueservice)
    - 10.12 [BatchService](#1012-batchservice)
    - 10.13 [IndexSearchService](#1013-indexsearchservice)
    - 10.14 [KeyBindingsService](#1014-keybindingsservice)
    - 10.15 [WatermarkService](#1015-watermarkservice)
    - 10.16 [PaperFormatService](#1016-paperformatservice)
11. [Floppy Disk Optimization API](#11-floppy-disk-optimization-api)

---

## 1. Model Layer (`src/model/`)

Основной уровень данных приложения. Содержит доменные модели документа, настройки страницы и принтера, а также все перечисления (enums), описывающие возможности матричного принтера Epson FX-890.

---

### 1.1 Document (`src/model/document.py`)

#### Класс `DocumentMetadata`

Метаданные документа. Создаётся автоматически при инициализации `Document`.

```python
@dataclass
class DocumentMetadata:
    title: str = ""
    author: str = ""
    created: datetime = field(default_factory=datetime.now)
    modified: datetime = field(default_factory=datetime.now)
    subject: str = ""
    keywords: list[str] = field(default_factory=list)
    version: str = "1.0"
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `to_dict` | `() -> dict[str, Any]` | Сериализация метаданных в словарь. Поля `created` и `modified` конвертируются в ISO 8601. |
| `from_dict` | `(data: dict[str, Any]) -> DocumentMetadata` | **classmethod.** Десериализация из словаря. Парсит ISO 8601 строки обратно в `datetime`. |

---

#### Класс `PageSettings`

Настройки страницы документа. Значения по умолчанию соответствуют стандартному формату US Letter.

```python
@dataclass
class PageSettings:
    size: PageSize = PageSize.LETTER
    orientation: Orientation = Orientation.PORTRAIT
    width_inches: float = 8.5
    height_inches: float = 11.0
    margin_left_inches: float = 1.0
    margin_right_inches: float = 1.0
    margin_top_inches: float = 1.0
    margin_bottom_inches: float = 1.0
    line_spacing: LineSpacing = LineSpacing.ONE_SIXTH_INCH
    characters_per_line: int = 80
    lines_per_page: int = 66
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `get_printable_width_inches` | `() -> float` | Возвращает `width_inches - margin_left_inches - margin_right_inches`. |
| `get_printable_height_inches` | `() -> float` | Возвращает `height_inches - margin_top_inches - margin_bottom_inches`. |
| `to_dict` | `() -> dict[str, Any]` | Сериализация. Enum-поля конвертируются через `.value`. |
| `from_dict` | `(data: dict[str, Any]) -> PageSettings` | **classmethod.** Десериализация с восстановлением enum-типов. |

---

#### Класс `PrinterSettings`

Настройки принтера Epson FX-890. Определяют кодировку, качество печати, шрифт и параметры подачи бумаги.

```python
@dataclass
class PrinterSettings:
    printer_name: str = "Epson FX-890"
    codepage: CodePage = CodePage.PC866
    print_quality: PrintQuality = PrintQuality.DRAFT
    font_family: FontFamily = FontFamily.DRAFT
    characters_per_inch: CharactersPerInch = CharactersPerInch.CPI_10
    print_direction: PrintDirection = PrintDirection.BIDIRECTIONAL
    paper_type: PaperType = PaperType.CONTINUOUS_TRACTOR
    paper_source: PaperSource = PaperSource.AUTO
    default_alignment: Alignment = Alignment.LEFT
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `to_dict` | `() -> dict[str, Any]` | Сериализация настроек принтера. |
| `from_dict` | `(data: dict[str, Any]) -> PrinterSettings` | **classmethod.** Десериализация из словаря. |

---

#### Класс `Document`

Корневой объект доменной модели. Представляет полный документ, состоящий из секций.

Поддерживает два режима работы:
- **FREE_FORM** — свободное редактирование текста (Word-like)
- **STRUCTURED_FORM** — структурированные формы с полями

Оба режима используют единый класс `Document`, различие задаётся через `document_type` &rarr; `DocumentMode`.

```python
class Document:
    id: UUID
    metadata: DocumentMetadata
    document_type: str                 # Код типа из TypeRegistry ("DOC", "INV", "DVN")
    page_settings: PageSettings
    printer_settings: PrinterSettings
    sections: list[Section]
    file_path: Path | None
    is_modified: bool
```

**Два режима документов:**

| Режим | `document_type` | Описание | Использование |
|-------|-----------------|----------|---------------|
| FREE_FORM | `"DOC"` | Свободное редактирование текста, колонтитулы, таблицы | Письма, отчёты, заметки |
| STRUCTURED_FORM | `"INV"`, `"DVN"` | Формы с полями, валидацией, подписью | Бланки, счета, ноты |

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `add_section` | `(section: Section) -> None` | Добавляет секцию в конец документа. Устанавливает `is_modified = True`. |
| `remove_section` | `(index: int) -> Section` | Удаляет и возвращает секцию по индексу. Бросает `IndexError` при невалидном индексе. |
| `get_section` | `(index: int) -> Section` | Возвращает секцию по индексу. |
| `iter_sections` | `() -> Iterator[Section]` | Итератор по всем секциям документа. |
| `get_text_content` | `() -> str` | Возвращает полный текст документа (все секции, без форматирования). |
| `get_character_count` | `() -> int` | Общее количество символов во всех секциях. |
| `get_word_count` | `() -> int` | Общее количество слов. Разделитель — пробельные символы. |
| `get_line_count` | `() -> int` | Общее количество строк. |
| `clear` | `() -> None` | Очищает все секции, сбрасывает `is_modified`. |
| `to_dict` | `() -> dict[str, Any]` | Полная сериализация документа в словарь (включая metadata, settings, sections). |
| `from_dict` | `(data: dict[str, Any]) -> Document` | **classmethod.** Восстановление документа из словаря. |
| `save_to_file` | `(path: Path) -> None` | Сохраняет документ в файл `.fxsd` (JSON). Обновляет `metadata.modified` и `file_path`. |
| `load_from_file` | `(path: Path) -> Document` | **classmethod.** Загружает документ из файла `.fxsd`. |

---

### 1.2 Enums (`src/model/enums.py`)

Все enum'ы имеют следующие общие методы:

| Метод | Тип | Описание |
|-------|-----|----------|
| `from_string(value: str)` | `@classmethod` | Создаёт экземпляр из строкового представления. Бросает `ValueError` при неизвестном значении. |
| `localized_name` | `@property` | Возвращает локализованное (русское) имя значения. |

---

#### `FontFamily`

Семейства шрифтов, поддерживаемые Epson FX-890.

```python
class FontFamily(str, Enum):
    USD = "usd"
    HSD = "hsd"
    DRAFT = "draft"
    ROMAN = "roman"
    SANS_SERIF = "sans_serif"
```

| Значение | Описание | `is_nlq` | `supports_proportional` |
|----------|----------|----------|------------------------|
| `USD` | Ultra Super Draft — максимальная скорость | `False` | `False` |
| `HSD` | High Speed Draft — повышенная скорость | `False` | `False` |
| `DRAFT` | Стандартный черновой режим | `False` | `False` |
| `ROMAN` | Шрифт Roman (NLQ — Near Letter Quality) | `True` | `True` |
| `SANS_SERIF` | Шрифт Sans Serif (NLQ) | `True` | `True` |

**Свойства:**

| Свойство | Тип | Описание |
|----------|-----|----------|
| `is_nlq` | `bool` | `True`, если шрифт поддерживает режим NLQ (высокое качество). |
| `supports_proportional` | `bool` | `True`, если шрифт поддерживает пропорциональную печать. |

---

#### `CharactersPerInch`

Плотность символов (CPI). Определяет горизонтальный размер шрифта.

```python
class CharactersPerInch(str, Enum):
    CPI_10 = "10"
    CPI_12 = "12"
    CPI_15 = "15"
    CPI_17 = "17"
    CPI_20 = "20"
    PROPORTIONAL = "proportional"
```

| Значение | Символов на дюйм | Примечание |
|----------|-------------------|------------|
| `CPI_10` | 10 | Стандартная плотность (Pica). |
| `CPI_12` | 12 | Elite. |
| `CPI_15` | 15 | Сжатый Elite. |
| `CPI_17` | 17.14 | Condensed Pica. |
| `CPI_20` | 20 | Condensed Elite. |
| `PROPORTIONAL` | Переменная | Пропорциональный режим. Доступен только для NLQ-шрифтов. |

---

#### `CodePage`

Кодовые страницы символов, поддерживаемые принтером.

```python
class CodePage(str, Enum):
    PC437 = "437"
    PC850 = "850"
    PC860 = "860"
    PC863 = "863"
    PC865 = "865"
    PC866 = "866"
```

| Значение | Название | Языки / Регион |
|----------|----------|----------------|
| `PC437` | US / Standard Europe | Английский, базовая латиница |
| `PC850` | Multilingual Latin I | Западноевропейские языки |
| `PC860` | Portuguese | Португальский |
| `PC863` | Canadian French | Канадский французский |
| `PC865` | Nordic | Скандинавские языки |
| `PC866` | Cyrillic | **Русский, кириллица** (по умолчанию) |

---

#### `PrintQuality`

Качество печати.

```python
class PrintQuality(str, Enum):
    DRAFT = "draft"
    NLQ = "nlq"
```

| Значение | Описание |
|----------|----------|
| `DRAFT` | Черновой режим — высокая скорость, низкое качество. |
| `NLQ` | Near Letter Quality — высокое качество, низкая скорость. Требует NLQ-совместимый шрифт (`FontFamily.is_nlq == True`). |

---

#### `Alignment`

Горизонтальное выравнивание текста.

```python
class Alignment(str, Enum):
    LEFT = "left"
    CENTER = "center"
    RIGHT = "right"
```

---

#### `TextStyle`

Стили форматирования текста. **Flag enum** — значения можно комбинировать побитовым OR (`|`).

```python
class TextStyle(Flag):
    NONE = 0
    BOLD = auto()
    ITALIC = auto()
    UNDERLINE = auto()
    DOUBLE_STRIKE = auto()
    SUPERSCRIPT = auto()
    SUBSCRIPT = auto()
    CONDENSED = auto()
    DOUBLE_WIDTH = auto()
    DOUBLE_HEIGHT = auto()
    OUTLINE = auto()
    SHADOW = auto()
    STRIKETHROUGH = auto()
```

**Пример комбинирования:**

```python
style = TextStyle.BOLD | TextStyle.ITALIC | TextStyle.UNDERLINE
assert TextStyle.BOLD in style  # True
```

| Значение | Описание | ESC/P поддержка |
|----------|----------|-----------------|
| `NONE` | Без форматирования | — |
| `BOLD` | Жирный | ESC E / ESC F |
| `ITALIC` | Курсив | ESC 4 / ESC 5 |
| `UNDERLINE` | Подчёркивание | ESC - 1 / ESC - 0 |
| `DOUBLE_STRIKE` | Двойной удар | ESC G / ESC H |
| `SUPERSCRIPT` | Верхний индекс | ESC S 0 |
| `SUBSCRIPT` | Нижний индекс | ESC S 1 |
| `CONDENSED` | Сжатый шрифт | SI / DC2 |
| `DOUBLE_WIDTH` | Двойная ширина | SO / DC4 |
| `DOUBLE_HEIGHT` | Двойная высота | ESC w 1 / ESC w 0 |
| `OUTLINE` | Контурный | ESC q 1 |
| `SHADOW` | Теневой | ESC q 2 |
| `STRIKETHROUGH` | Зачёркнутый | Эмуляция через overprint |

---

#### `PageSize`

Размеры страницы.

```python
class PageSize(str, Enum):
    A4 = "a4"
    LETTER = "letter"
    LEGAL = "legal"
    B5 = "b5"
    CUSTOM = "custom"
```

| Значение | Ширина (дюймы) | Высота (дюймы) |
|----------|----------------|----------------|
| `A4` | 8.27 | 11.69 |
| `LETTER` | 8.5 | 11.0 |
| `LEGAL` | 8.5 | 14.0 |
| `B5` | 6.93 | 9.84 |
| `CUSTOM` | Определяется пользователем | Определяется пользователем |

---

#### `Orientation`

Ориентация страницы.

```python
class Orientation(str, Enum):
    PORTRAIT = "portrait"
    LANDSCAPE = "landscape"
```

---

#### `LineSpacing`

Межстрочный интервал. Значения соответствуют ESC/P командам.

```python
class LineSpacing(str, Enum):
    ONE_SIXTH_INCH = "1/6"
    ONE_EIGHTH_INCH = "1/8"
    N_180TH = "n/180"
    N_360TH = "n/360"
```

| Значение | Размер | ESC/P команда | Примечание |
|----------|--------|---------------|------------|
| `ONE_SIXTH_INCH` | 1/6 дюйма | ESC 2 | Стандартный (по умолчанию). |
| `ONE_EIGHTH_INCH` | 1/8 дюйма | ESC 0 | Уплотнённый. |
| `N_180TH` | n/180 дюйма | ESC 3 n | Программируемый (n = 0–255). |
| `N_360TH` | n/360 дюйма | ESC + n | Программируемый (n = 0–255), высокое разрешение. |

---

#### `Color`

Цвет печати.

```python
class Color(str, Enum):
    BLACK = "black"
```

> **Примечание:** Epson FX-890 — монохромный принтер. Единственный поддерживаемый цвет — `BLACK`.

---

#### `BarcodeType` (model-level)

Типы штрихкодов, поддерживаемые на уровне модели документа.

```python
class BarcodeType(str, Enum):
    EAN13 = "ean13"
    EAN8 = "ean8"
    UPCA = "upca"
    UPCE = "upce"
    CODE39 = "code39"
    CODE128 = "code128"
    ITF = "itf"
    CODABAR = "codabar"
    CODE93 = "code93"
```

| Значение | Длина данных | Допустимые символы |
|----------|-------------|-------------------|
| `EAN13` | 12–13 цифр | `0-9` |
| `EAN8` | 7–8 цифр | `0-9` |
| `UPCA` | 11–12 цифр | `0-9` |
| `UPCE` | 6–8 цифр | `0-9` |
| `CODE39` | Переменная | `0-9`, `A-Z`, `-`, `.`, ` `, `$`, `/`, `+`, `%` |
| `CODE128` | Переменная | ASCII 0–127 |
| `ITF` | Чётное кол-во цифр | `0-9` |
| `CODABAR` | Переменная | `0-9`, `-`, `$`, `:`, `/`, `.`, `+`, `A-D` |
| `CODE93` | Переменная | ASCII 0–127 |

---

#### `GraphicsMode` (model-level)

Режимы графической печати с различным разрешением.

```python
class GraphicsMode(str, Enum):
    SINGLE_DENSITY = "single_density"        # 60 DPI
    DOUBLE_DENSITY = "double_density"        # 120 DPI
    HIGH_SPEED_DOUBLE = "high_speed_double"  # 120 DPI, высокая скорость
    QUAD_DENSITY = "quad_density"            # 240 DPI
    CRT_I = "crt_i"                          # 80 DPI
    CRT_II = "crt_ii"                        # 90 DPI
    TRIPLE_DENSITY = "triple_density"        # 180 DPI
    HEX_DENSITY = "hex_density"             # 360 DPI
```

| Значение | Разрешение (DPI) | Описание |
|----------|-----------------|----------|
| `SINGLE_DENSITY` | 60 | Одинарная плотность |
| `DOUBLE_DENSITY` | 120 | Двойная плотность |
| `HIGH_SPEED_DOUBLE` | 120 | Двойная плотность, высокая скорость |
| `QUAD_DENSITY` | 240 | Четверная плотность |
| `CRT_I` | 80 | CRT Graphics I |
| `CRT_II` | 90 | CRT Graphics II |
| `TRIPLE_DENSITY` | 180 | Тройная плотность |
| `HEX_DENSITY` | 360 | Максимальное разрешение |

---

#### `PaperType`

Тип бумаги.

```python
class PaperType(str, Enum):
    CONTINUOUS_TRACTOR = "continuous_tractor"
    CUT_SHEET = "cut_sheet"
    ROLL = "roll"
    ENVELOPE = "envelope"
```

| Значение | Описание |
|----------|----------|
| `CONTINUOUS_TRACTOR` | Непрерывная бумага с перфорацией (трактор). По умолчанию для FX-890. |
| `CUT_SHEET` | Отдельные листы (ручная/автоматическая подача). |
| `ROLL` | Рулонная бумага. |
| `ENVELOPE` | Конверты. |

---

#### `PaperSource`

Источник подачи бумаги.

```python
class PaperSource(str, Enum):
    AUTO = "auto"
    TRACTOR_FRONT = "tractor_front"
    TRACTOR_REAR = "tractor_rear"
    CUT_SHEET_FEEDER = "cut_sheet_feeder"
    MANUAL = "manual"
```

---

#### `PrintDirection`

Направление печати.

```python
class PrintDirection(str, Enum):
    BIDIRECTIONAL = "bidirectional"
    UNIDIRECTIONAL = "unidirectional"
```

| Значение | Описание |
|----------|----------|
| `BIDIRECTIONAL` | Двунаправленная печать (быстрее). По умолчанию. |
| `UNIDIRECTIONAL` | Однонаправленная печать (точнее вертикальное выравнивание). |

---

#### `MarginUnits`

Единицы измерения полей.

```python
class MarginUnits(str, Enum):
    INCHES = "inches"
    CENTIMETERS = "centimeters"
    CHARACTERS = "characters"
```

---

#### `ImagePosition`

Позиционирование изображений при вставке.

```python
class ImagePosition(str, Enum):
    INLINE = "inline"
    LEFT = "left"
    CENTER = "center"
    RIGHT = "right"
```

---

#### `DitheringAlgorithm`

Алгоритмы дизеринга для преобразования полутоновых изображений в монохромные точки.

```python
class DitheringAlgorithm(str, Enum):
    FLOYD_STEINBERG = "floyd_steinberg"
    ORDERED = "ordered"
    ATKINSON = "atkinson"
    THRESHOLD = "threshold"
```

---

#### `TableStyle`

Стили отрисовки таблиц.

```python
class TableStyle(str, Enum):
    NONE = "none"
    SIMPLE = "simple"
    SINGLE_LINE = "single_line"
    DOUBLE_LINE = "double_line"
    ASCII = "ascii"
```

---

### 1.3 Функции валидации

Модуль `src/model/enums.py` содержит набор функций для проверки совместимости параметров принтера.

```python
def validate_barcode(data: str, barcode_type: BarcodeType) -> bool
```
Проверяет, что строка `data` соответствует требованиям указанного типа штрихкода (длина, допустимые символы, контрольная сумма). Возвращает `True` при валидных данных, бросает `ValueError` с описанием ошибки в противном случае.

---

```python
def validate_codepage(codepage: CodePage, text: str) -> bool
```
Проверяет, что все символы строки `text` представимы в указанной кодовой странице. Возвращает `True`, если все символы поддерживаются.

---

```python
def validate_cpi_font_combination(
    cpi: CharactersPerInch,
    font: FontFamily
) -> bool
```
Проверяет совместимость плотности символов и шрифта. Например, `PROPORTIONAL` допустим только с NLQ-шрифтами (`ROMAN`, `SANS_SERIF`). Бросает `ValueError` при несовместимой комбинации.

---

```python
def validate_graphics_mode(mode: GraphicsMode, data_width: int) -> bool
```
Проверяет, что ширина графических данных не превышает максимально допустимую для выбранного режима.

---

```python
def validate_margin(
    margin_value: float,
    page_size: PageSize,
    orientation: Orientation
) -> bool
```
Проверяет, что значение поля (в дюймах) находится в допустимых пределах для данного размера и ориентации страницы.

---

```python
def validate_quality_font_combination(
    quality: PrintQuality,
    font: FontFamily
) -> bool
```
Проверяет совместимость качества печати и шрифта. NLQ-качество требует NLQ-совместимого шрифта. Draft-шрифты (`USD`, `HSD`, `DRAFT`) работают только в режиме `DRAFT`.

---

## 2. ESC/P Commands Layer (`src/escp/commands/`)

Низкоуровневый слой генерации ESC/P команд для матричного принтера Epson FX-890. Все константы имеют тип `Final[bytes]`. Функции генерируют бинарные последовательности для отправки на принтер.

---

### 2.1 `text_formatting.py`

Команды форматирования текста.

| Константа | Hex-значение | Описание |
|-----------|-------------|----------|
| `ESC_BOLD_ON` | `\x1b\x45` | Включить жирный шрифт (ESC E) |
| `ESC_BOLD_OFF` | `\x1b\x46` | Выключить жирный шрифт (ESC F) |
| `ESC_ITALIC_ON` | `\x1b\x34` | Включить курсив (ESC 4) |
| `ESC_ITALIC_OFF` | `\x1b\x35` | Выключить курсив (ESC 5) |
| `ESC_UNDERLINE_ON` | `\x1b\x2d\x01` | Включить подчёркивание (ESC - 1) |
| `ESC_UNDERLINE_DOUBLE` | `\x1b\x2d\x02` | Двойное подчёркивание (ESC - 2) |
| `ESC_UNDERLINE_OFF` | `\x1b\x2d\x00` | Выключить подчёркивание (ESC - 0) |
| `ESC_DOUBLE_STRIKE_ON` | `\x1b\x47` | Включить двойной удар (ESC G) |
| `ESC_DOUBLE_STRIKE_OFF` | `\x1b\x48` | Выключить двойной удар (ESC H) |
| `ESC_OUTLINE_ON` | `\x1b\x71\x01` | Включить контурный шрифт (ESC q 1) |
| `ESC_OUTLINE_OFF` | `\x1b\x71\x00` | Выключить контурный шрифт (ESC q 0) |
| `ESC_SHADOW_ON` | `\x1b\x71\x02` | Включить теневой шрифт (ESC q 2) |
| `ESC_SHADOW_OFF` | `\x1b\x71\x00` | Выключить теневой шрифт (ESC q 0) |

---

### 2.2 `barcode.py`

Команды печати штрихкодов через ESC ( B.

#### Enum `BarcodeType` (protocol-level)

Типы штрихкодов на уровне протокола ESC/P с hex-кодами для команды ESC ( B.

```python
class BarcodeType(IntEnum):
    EAN13 = 0x00
    EAN8 = 0x01
    INTERLEAVED_2_OF_5 = 0x02
    UPCA = 0x03
    UPCE = 0x04
    CODE39 = 0x05
    CODE128 = 0x06
    CODABAR = 0x07
    CODE93 = 0x08
```

#### Enum `BarcodeHRI`

Позиция HRI (Human Readable Interpretation) — текстового представления данных штрихкода.

```python
class BarcodeHRI(IntEnum):
    NONE = 0x00
    BELOW = 0x01
    ABOVE = 0x02
    BOTH = 0x03
```

#### Функция `print_barcode`

```python
def print_barcode(
    data: str,
    barcode_type: BarcodeType,
    module_width: int = 3,
    height: int = 162,
    hri: BarcodeHRI = BarcodeHRI.BELOW,
    hri_font: int = 0
) -> bytes
```

Генерирует ESC/P команду печати штрихкода.

**Параметры:**

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|-------------|----------|
| `data` | `str` | — | Данные штрихкода (цифры/символы в зависимости от типа). |
| `barcode_type` | `BarcodeType` | — | Тип штрихкода (protocol-level). |
| `module_width` | `int` | `3` | Ширина модуля (1–6 точек). |
| `height` | `int` | `162` | Высота штрихкода в точках (1–255). |
| `hri` | `BarcodeHRI` | `BELOW` | Позиция текста. |
| `hri_font` | `int` | `0` | Шрифт HRI: 0 = Font A, 1 = Font B. |

**Возвращает:** `bytes` — бинарная ESC/P последовательность.

---

### 2.3 `fonts.py`

Команды выбора шрифтов.

| Константа / Функция | Hex-значение / Сигнатура | Описание |
|---------------------|--------------------------|----------|
| `ESC_SELECT_ROMAN` | `\x1b\x6b\x00` | Выбрать шрифт Roman (ESC k 0) |
| `ESC_SELECT_SANS_SERIF` | `\x1b\x6b\x01` | Выбрать шрифт Sans Serif (ESC k 1) |
| `ESC_SELECT_DRAFT` | `\x1b\x78\x00` | Режим Draft (ESC x 0) |
| `ESC_SELECT_NLQ` | `\x1b\x78\x01` | Режим NLQ (ESC x 1) |
| `select_font(family: FontFamily) -> bytes` | — | Возвращает ESC/P команду для выбора указанного шрифта. |

---

### 2.4 `sizing.py`

Команды управления размером символов.

| Константа / Функция | Hex-значение / Сигнатура | Описание |
|---------------------|--------------------------|----------|
| `ESC_PICA` | `\x1b\x50` | 10 CPI — Pica (ESC P) |
| `ESC_ELITE` | `\x1b\x4d` | 12 CPI — Elite (ESC M) |
| `ESC_15_CPI` | `\x1b\x67` | 15 CPI (ESC g) |
| `ESC_CONDENSED_ON` | `\x0f` | Включить сжатый режим (SI) |
| `ESC_CONDENSED_OFF` | `\x12` | Выключить сжатый режим (DC2) |
| `ESC_DOUBLE_WIDTH_ON` | `\x0e` | Двойная ширина на строку (SO) |
| `ESC_DOUBLE_WIDTH_OFF` | `\x14` | Выключить двойную ширину (DC4) |
| `ESC_DOUBLE_WIDTH_LOCK_ON` | `\x1b\x57\x01` | Двойная ширина (постоянно) (ESC W 1) |
| `ESC_DOUBLE_WIDTH_LOCK_OFF` | `\x1b\x57\x00` | Выключить (ESC W 0) |
| `ESC_DOUBLE_HEIGHT_ON` | `\x1b\x77\x01` | Двойная высота (ESC w 1) |
| `ESC_DOUBLE_HEIGHT_OFF` | `\x1b\x77\x00` | Выключить двойную высоту (ESC w 0) |
| `ESC_PROPORTIONAL_ON` | `\x1b\x70\x01` | Включить пропорциональный режим (ESC p 1) |
| `ESC_PROPORTIONAL_OFF` | `\x1b\x70\x00` | Выключить пропорциональный режим (ESC p 0) |
| `set_cpi(cpi: CharactersPerInch) -> bytes` | — | Возвращает ESC/P команду для установки указанной плотности символов. |

---

### 2.5 `positioning.py`

Команды позиционирования печатающей головки.

| Константа / Функция | Hex-значение / Сигнатура | Описание |
|---------------------|--------------------------|----------|
| `ESC_ABSOLUTE_POS` | `\x1b\x24` | Абсолютная горизонтальная позиция (ESC $). За ней следуют 2 байта nL, nH. |
| `ESC_RELATIVE_POS` | `\x1b\x5c` | Относительная горизонтальная позиция (ESC \). |
| `set_horizontal_position(dots: int) -> bytes` | — | Устанавливает абсолютную горизонтальную позицию в точках (1/60 дюйма). |
| `move_horizontal(dots: int) -> bytes` | — | Перемещает головку на `dots` точек относительно текущей позиции. Отрицательные значения — влево. |
| `set_left_margin(columns: int) -> bytes` | — | Устанавливает левое поле в символах. |
| `set_right_margin(columns: int) -> bytes` | — | Устанавливает правое поле в символах. |
| `set_horizontal_tabs(positions: list[int]) -> bytes` | — | Задаёт позиции горизонтальных табуляторов. |
| `ESC_HORIZONTAL_TAB` | `\x09` | Горизонтальная табуляция (HT). |

---

### 2.6 `page_control.py`

Команды управления страницей.

| Константа / Функция | Hex-значение / Сигнатура | Описание |
|---------------------|--------------------------|----------|
| `ESC_FORM_FEED` | `\x0c` | Перевод страницы (FF). |
| `ESC_SET_PAGE_LENGTH_LINES` | `\x1b\x43` | Установить длину страницы в строках (ESC C n). |
| `ESC_SET_PAGE_LENGTH_INCHES` | `\x1b\x43\x00` | Установить длину страницы в дюймах (ESC C 0 n). |
| `set_page_length_lines(lines: int) -> bytes` | — | Длина страницы: 1–127 строк. |
| `set_page_length_inches(inches: int) -> bytes` | — | Длина страницы: 1–22 дюймов. |
| `set_top_margin(lines: int) -> bytes` | — | Верхнее поле в строках. |
| `set_bottom_margin(lines: int) -> bytes` | — | Нижнее поле в строках. |
| `ESC_CR` | `\x0d` | Возврат каретки (CR). |
| `ESC_LF` | `\x0a` | Перевод строки (LF). |
| `ESC_CRLF` | `\x0d\x0a` | CR + LF. |

---

### 2.7 `line_spacing.py`

Команды управления межстрочным интервалом.

| Константа / Функция | Hex-значение / Сигнатура | Описание |
|---------------------|--------------------------|----------|
| `ESC_LINE_SPACING_1_6` | `\x1b\x32` | Интервал 1/6 дюйма — стандартный (ESC 2). |
| `ESC_LINE_SPACING_1_8` | `\x1b\x30` | Интервал 1/8 дюйма (ESC 0). |
| `set_line_spacing_180(n: int) -> bytes` | — | Интервал n/180 дюйма (ESC 3 n). `n`: 0–255. |
| `set_line_spacing_360(n: int) -> bytes` | — | Интервал n/360 дюйма (ESC + n). `n`: 0–255. |
| `set_line_spacing(spacing: LineSpacing, n: int = 0) -> bytes` | — | Универсальная функция. Для `N_180TH` и `N_360TH` использует параметр `n`. |

---

### 2.8 `print_quality.py`

Команды управления качеством печати.

| Константа / Функция | Hex-значение / Сигнатура | Описание |
|---------------------|--------------------------|----------|
| `ESC_DRAFT_MODE` | `\x1b\x78\x00` | Черновой режим (ESC x 0). |
| `ESC_NLQ_MODE` | `\x1b\x78\x01` | NLQ режим (ESC x 1). |
| `set_quality(quality: PrintQuality) -> bytes` | — | Устанавливает качество печати. |

---

### 2.9 `hardware.py`

Аппаратные команды принтера.

| Константа / Функция | Hex-значение / Сигнатура | Описание |
|---------------------|--------------------------|----------|
| `ESC_RESET` | `\x1b\x40` | Сброс принтера (ESC @). Возвращает все параметры к значениям по умолчанию. |
| `ESC_UNIDIRECTIONAL_ON` | `\x1b\x55\x01` | Однонаправленная печать (ESC U 1). |
| `ESC_UNIDIRECTIONAL_OFF` | `\x1b\x55\x00` | Двунаправленная печать (ESC U 0). |
| `ESC_BELL` | `\x07` | Звуковой сигнал (BEL). |
| `ESC_CANCEL_LINE` | `\x18` | Отмена текущей строки в буфере (CAN). |
| `ESC_DELETE` | `\x7f` | Удаление последнего символа в буфере (DEL). |
| `set_print_direction(direction: PrintDirection) -> bytes` | — | Устанавливает направление печати. |

---

### 2.10 `charset.py`

Команды выбора кодовой страницы и набора символов.

| Константа / Функция | Hex-значение / Сигнатура | Описание |
|---------------------|--------------------------|----------|
| `ESC_SELECT_CHARSET` | `\x1b\x52` | Выбор международного набора символов (ESC R n). |
| `ESC_SELECT_CODEPAGE` | `\x1b\x74` | Выбор кодовой страницы (ESC t n). |
| `select_codepage(codepage: CodePage) -> bytes` | — | Генерирует команду выбора кодовой страницы. |
| `ESC_ENABLE_UPPER_CHARS` | `\x1b\x36` | Разрешить печать символов 128–255 (ESC 6). |
| `ESC_ENABLE_CONTROL_CODES` | `\x1b\x37` | Разрешить управляющие коды 0–31 (ESC 7). |
| `encode_text(text: str, codepage: CodePage) -> bytes` | — | Кодирует Unicode-текст в байты указанной кодовой страницы. |

---

### 2.11 `graphics.py`

Команды растровой графики.

| Константа / Функция | Hex-значение / Сигнатура | Описание |
|---------------------|--------------------------|----------|
| `ESC_GRAPHICS_MODE` | `\x1b\x2a` | Выбор режима графики (ESC * m nL nH). |
| `print_graphics(mode: GraphicsMode, data: bytes) -> bytes` | — | Печать растровой графики. `data` — столбцы (8 вертикальных точек = 1 байт). |
| `print_raster_line(data: bytes, mode: GraphicsMode) -> bytes` | — | Печать одной графической строки. |

**Режимы (параметр `m` команды ESC *):**

| Режим | m | Горизонтальное DPI | Вертикальное DPI |
|-------|---|-------------------|-----------------|
| Single density | 0 | 60 | 72 |
| Double density | 1 | 120 | 72 |
| High-speed double | 3 | 120 | 72 |
| Quad density | 4 | 240 | 72 |
| CRT I | 5 | 80 | 72 |
| CRT II | 6 | 90 | 72 |
| Triple density | 38 | 180 | 72 |
| Hex density | 39 | 360 | 72 |

---

### 2.12 `shading.py`

Команды заливки и затенения.

| Константа / Функция | Hex-значение / Сигнатура | Описание |
|---------------------|--------------------------|----------|
| `ESC_SHADING_ON` | `\x1b\x28\x63` | Включить затенение области (ESC ( c). |
| `set_shading(pattern: int, width: int) -> bytes` | — | Устанавливает шаблон затенения (0–100%) и ширину области. |
| `clear_shading() -> bytes` | — | Снимает затенение. |

---

### 2.13 `special_effects.py`

Специальные эффекты печати.

| Константа / Функция | Hex-значение / Сигнатура | Описание |
|---------------------|--------------------------|----------|
| `ESC_SUPERSCRIPT_ON` | `\x1b\x53\x00` | Верхний индекс (ESC S 0). |
| `ESC_SUBSCRIPT_ON` | `\x1b\x53\x01` | Нижний индекс (ESC S 1). |
| `ESC_SUPERSCRIPT_OFF` | `\x1b\x54` | Выключить верхний/нижний индекс (ESC T). |
| `ESC_MASTER_SELECT` | `\x1b\x21` | Master Select (ESC ! n) — комбинированная установка стилей одной командой. |
| `master_select(styles: TextStyle, cpi: CharactersPerInch) -> bytes` | — | Генерирует команду Master Select из комбинации стилей и CPI. |

---

## 3. Document Types & Indexing (`src/documents/types/`)

Система типизации документов и автоматической индексации. Позволяет регистрировать типы документов, определять их структуру (поля) и формат индексов.

Система поддерживает **два режима документов**:
- **FREE_FORM** — свободное редактирование текста (Word-like документы)
- **STRUCTURED_FORM** — структурированные формы с полями и валидацией

---

### Enum `DocumentMode`

```python
class DocumentMode(str, Enum):
    """Режим работы с документом."""
    FREE_FORM = "free_form"              # Текстовые документы (свободное редактирование)
    STRUCTURED_FORM = "structured_form"  # Структурированные формы с полями
```

| Значение | Описание | Примеры |
|----------|----------|---------|
| `FREE_FORM` | Свободное редактирование текста без схемы полей | DOC — базовый текстовый документ |
| `STRUCTURED_FORM` | Структурированные документы с валидацией полей | INV, DVN — формы с полями |

---

### 3.1 TypeRegistry

Singleton-реестр типов документов. Хранит все зарегистрированные типы, подтипы и пользовательские типы.

```python
class TypeRegistry:

    @classmethod
    def get_instance(cls) -> TypeRegistry
```
Возвращает единственный экземпляр реестра (Singleton pattern).

---

```python
    def register_type(
        code: str,
        name: str,
        document_mode: DocumentMode,
        index_template: IndexTemplate | None,
        field_schema: TypeSchema,
        parent_code: str | None = None,
        metadata: dict[str, Any] | None = None
    ) -> DocumentType
```
Регистрирует новый тип документа.

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `code` | `str` | Уникальный код типа (например, `"INV"` для Invoice). |
| `name` | `str` | Человеко-читаемое название типа. |
| `document_mode` | `DocumentMode` | Режим: `FREE_FORM` (текст) или `STRUCTURED_FORM` (форма). |
| `index_template` | `IndexTemplate \| None` | Шаблон индекса. `None` для текстовых документов. |
| `field_schema` | `TypeSchema` | Схема полей. Пустая для `FREE_FORM`. |
| `parent_code` | `str \| None` | Код родительского типа (для подтипов). |
| `metadata` | `dict[str, Any] \| None` | Дополнительные метаданные типа. |

**Возвращает:** `DocumentType` — зарегистрированный тип.

**Примеры:**

```python
# Регистрация текстового документа (DOC)
registry.register_type(
    code="DOC",
    name="Базовый документ",
    document_mode=DocumentMode.FREE_FORM,
    index_template=None,  # Нет индекса
    field_schema=TypeSchema(fields=()),  # Пустая схема
)

# Регистрация формы (INV)
registry.register_type(
    code="INV",
    name="Счёт",
    document_mode=DocumentMode.STRUCTURED_FORM,
    index_template=IndexTemplate(...),
    field_schema=TypeSchema(fields=[...]),
)
```

---

```python
    def register_subtype(
        parent_code: str,
        subtype_value: str,
        name: str,
        extra_fields: list[FieldDefinition] | None = None
    ) -> DocumentSubtype
```
Регистрирует подтип существующего типа документа. Подтип наследует схему полей родительского типа и может добавлять собственные.

---

```python
    def get(code: str) -> DocumentType
```
Возвращает тип по коду. Бросает `KeyError`, если тип не найден.

---

```python
    def list_children(parent_code: str) -> list[DocumentType]
```
Возвращает все подтипы указанного родительского типа.

---

```python
    def create_user_type(
        code: str,
        parent_code: str | None,
        schema: TypeSchema
    ) -> DocumentType
```
Создаёт пользовательский тип документа. В отличие от `register_type`, пользовательские типы сохраняются в файле `.fxsreg` и могут быть удалены.

---

```python
    def list_all() -> list[DocumentType]
```
Возвращает список всех зарегистрированных типов (системных и пользовательских).

---

### 3.2 IndexTemplate

Шаблон генерации и парсинга индексов документов. Индекс состоит из сегментов, разделённых сепаратором.

#### Enum `SegmentType`

```python
class SegmentType(str, Enum):
    ROOT_CODE = "root"       # Код корневого типа документа
    SUBTYPE = "subtype"      # Код подтипа
    SERIES = "series"        # Серия (например, год, отдел)
    CUSTOM = "custom"        # Пользовательский сегмент
    SEQUENCE = "sequence"    # Порядковый номер (ВСЕГДА последний, римские цифры)
```

> **Важно:** Сегмент типа `SEQUENCE` всегда является последним в индексе и отображается римскими цифрами (I, II, III, IV, ...).

---

#### Класс `IndexSegmentDef`

Определение одного сегмента индекса.

```python
@dataclass
class IndexSegmentDef:
    name: str                              # Программное имя сегмента
    segment_type: SegmentType              # Тип сегмента
    label: str                             # Метка (русский)
    label_en: str                          # Метка (английский)
    pattern: str                           # Regex-паттерн валидации
    allowed_values: list[str] | None       # Список допустимых значений (None = любое)
    auto_increment: bool                   # Автоинкремент (для SEQUENCE)
```

---

#### Класс `IndexTemplate`

```python
@dataclass
class IndexTemplate:
    segments: list[IndexSegmentDef]
    separator: str = "-"
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `format` | `(values: dict[str, str], sequence: int) -> str` | Форматирует индекс из значений сегментов и порядкового номера. Номер конвертируется в римские цифры. |
| `parse` | `(index: str) -> dict[str, str]` | Парсит строку индекса в словарь `{segment_name: value}`. Бросает `ValueError` при невалидном формате. |
| `validate` | `(index: str) -> bool` | Проверяет, что строка соответствует шаблону. Возвращает `True`/`False`. |

**Пример:**

```python
template = IndexTemplate(
    segments=[
        IndexSegmentDef("type", SegmentType.ROOT_CODE, "Тип", "Type",
                        r"[A-Z]{2,5}", None, False),
        IndexSegmentDef("series", SegmentType.SERIES, "Серия", "Series",
                        r"\d{4}", None, False),
        IndexSegmentDef("seq", SegmentType.SEQUENCE, "Номер", "Number",
                        r"[IVXLCDM]+", None, True),
    ],
    separator="-"
)

index = template.format({"type": "INV", "series": "2026"}, sequence=42)
# Результат: "INV-2026-XLII"

parsed = template.parse("INV-2026-XLII")
# Результат: {"type": "INV", "series": "2026", "seq": "XLII"}
```

---

### 3.3 FieldDefinition & TypeSchema

Определение полей документа и схемы типа.

#### Enum `FieldType`

```python
class FieldType(str, Enum):
    STATIC_TEXT = "static_text"       # Неизменяемый текст
    TEXT_INPUT = "text_input"         # Текстовое поле ввода
    NUMBER_INPUT = "number_input"     # Числовое поле
    DATE_INPUT = "date_input"         # Поле даты
    TABLE = "table"                   # Табличные данные
    EXCEL_IMPORT = "excel_import"     # Данные из Excel
    CALCULATED = "calculated"         # Вычисляемое поле
    QR = "qr"                         # QR-код
    BARCODE = "barcode"               # Штрихкод
    SIGNATURE = "signature"           # Электронная подпись
    STAMP = "stamp"                   # Печать

    # Extended Field Types
    CHECKBOX = "checkbox"             # Булев флажок
    DROPDOWN = "dropdown"               # Выпадающий список
    RADIO_GROUP = "radio_group"         # Группа радиокнопок
    CURRENCY = "currency"               # Денежная сумма
    MULTI_LINE_TEXT = "multi_line_text" # Многострочный текст
    PHONE = "phone"                     # Телефон
    EMAIL = "email"                     # Email
```

**Extended Field Types:**

| Тип | Описание | Параметры |
|-----|----------|-----------|
| `CHECKBOX` | Булев флажок | `default_value: bool` |
| `DROPDOWN` | Выпадающий список | `options: tuple[str, ...]`, `allow_custom: bool` |
| `RADIO_GROUP` | Группа радиокнопок | `options: tuple[str, ...]`, `layout: horizontal\|vertical` |
| `CURRENCY` | Денежная сумма | `currency_code: str`, `decimal_places: int` |
| `MULTI_LINE_TEXT` | Многострочный текст | `rows: int`, `max_rows: int`, `wrap: bool` |
| `PHONE` | Телефон | `region: str`, `mask: str` |
| `EMAIL` | Email | `verify_domain: bool` |

---

#### Класс `FieldDefinition`

Определение одного поля в схеме типа.

```python
@dataclass
class FieldDefinition:
    name: str                              # Программное имя поля
    field_type: FieldType                  # Тип поля
    label: str                             # Метка (русский)
    label_en: str                          # Метка (английский)
    required: bool = True                  # Обязательность
    default_value: Any = None              # Значение по умолчанию
    validation: list[str] = field(default_factory=list)  # Правила валидации (regex, min/max и т.д.)
    inherited_from: str | None = None      # Код типа, от которого поле унаследовано (None = собственное)

    # Extended Validation Rules
    min_value: float | None = None         # Минимальное числовое значение
    max_value: float | None = None         # Максимальное числовое значение
    min_date: date | None = None           # Минимальная дата
    max_date: date | None = None           # Максимальная дата
    required_if: str | None = None         # Условная обязательность ("fieldA == 'value'")
    cross_field_rules: tuple[str, ...] = () # Кросс-полевая валидация

    # Conditional Visibility
    visibility_condition: str | None = None  # Показывать если: "subtype == '44'"
    read_only_condition: str | None = None   # Только чтение если: "status == 'SIGNED'"
    enabled_condition: str | None = None     # Активно если: "fieldA == 'value'"

    # Field UX
    tab_index: int | None = None              # Порядок Tab-навигации
    input_mask: str | None = None             # Маска ввода (дата: "##.##.####")
    placeholder: str | None = None            # Подсказка в пустом поле
    autocomplete_source: str | None = None    # Источник автодополнения
    help_text: str | None = None              # Вспомогательный текст (tooltip)
```

**Правила валидации (`validation`)** — список строковых выражений:

| Формат | Пример | Описание |
|--------|--------|----------|
| `regex:PATTERN` | `regex:^\d{10}$` | Регулярное выражение |
| `min:N` | `min:0` | Минимальное числовое значение |
| `max:N` | `max:999999` | Максимальное числовое значение |
| `min_length:N` | `min_length:3` | Минимальная длина строки |
| `max_length:N` | `max_length:100` | Максимальная длина строки |
| `date_format:FMT` | `date_format:%d.%m.%Y` | Формат даты |
| `one_of:A,B,C` | `one_of:RUB,USD,EUR` | Допустимые значения |

**Расширенные правила валидации:**

- `min_value` / `max_value` — числовые диапазоны
- `min_date` / `max_date` — диапазоны дат
- `required_if` — условная обязательность ("fieldA == 'value'")
- `cross_field_rules` — кросс-полевая валидация

Сервис `FormValidator` выполняет валидацию формы целиком перед подписью:

```python
class FormValidator:
    def validate(self, document: Document, schema: TypeSchema) -> ValidationResult: ...

@dataclass
class ValidationResult:
    is_valid: bool
    field_errors: dict[str, list[str]]
    cross_field_errors: list[str]
```

---

#### Класс `TypeSchema`

Схема полей для типа документа.

```python
@dataclass
class TypeSchema:
    fields: list[FieldDefinition]
    version: str = "1.0"                      # Версия схемы
    compatibility_version: str = "1.0"        # Минимальная совместимая версия
    deprecated_fields: tuple[str, ...] = () # Устаревшие field_ids
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `get_field` | `(name: str) -> FieldDefinition` | Возвращает определение поля по имени. Бросает `KeyError`, если поле не найдено. |
| `merge_with_parent` | `(parent_schema: TypeSchema) -> TypeSchema` | Возвращает новую схему, объединяя текущую с родительской. Поля родителя помечаются `inherited_from`. Поля дочернего типа с тем же именем переопределяют родительские. |
| `validate_data` | `(data: dict[str, Any]) -> ValidationResult` | Валидирует данные по схеме. Проверяет обязательные поля, типы значений и правила `validation`. |
| `migrate` | `(data: dict[str, Any], target_version: str) -> dict[str, Any]` | Мигрирует данные формы к целевой версии схемы. |

**Версионирование схем:**

- `version` — текущая версия схемы
- `compatibility_version` — минимальная совместимая версия
- `deprecated_fields` — устаревшие поля, которые больше не используются
- `SchemaMigration` — автоматическая миграция данных при обновлении схемы

**Примеры схем:**

```python
# FREE_FORM — текстовый документ (DOC)
# Пустая схема без обязательных полей
text_document_schema = TypeSchema(
    fields=[],  # Нет предопределённых полей формы
    version="1.0"
)

# STRUCTURED_FORM — форма счёта (INV)
# Полная схема с валидацией
invoice_schema = TypeSchema(
    fields=[
        FieldDefinition(
            field_id="invoice_number",
            field_type=FieldType.TEXT_INPUT,
            label="Номер счёта",
            required=True,
            validation=[r"regex:^INV-[IVXLCDM]+"]
        ),
        FieldDefinition(
            field_id="client_name",
            field_type=FieldType.TEXT_INPUT,
            label="Клиент",
            required=True,
            max_length=100
        ),
        FieldDefinition(
            field_id="items",
            field_type=FieldType.TABLE,
            label="Товары/услуги",
            required=True
        ),
    ],
    version="1.0"
)
```

**Класс `ValidationResult`:**

```python
@dataclass
class ValidationResult:
    is_valid: bool
    errors: list[str]        # Список ошибок
    warnings: list[str]      # Список предупреждений
```

---

## 4. Document Constructor (`src/documents/constructor/`)

Модуль конструирования документов: импорт данных из Excel и подстановка переменных в шаблоны.

---

### 4.1 ExcelImporter

Импорт данных из файлов Microsoft Excel (`.xlsx`, `.xls`) в поля документа.

#### Enum `ExcelSourceType`

```python
class ExcelSourceType(str, Enum):
    COLUMN = "column"    # Столбец (вертикальный диапазон)
    ROW = "row"          # Строка (горизонтальный диапазон)
    RANGE = "range"      # Произвольный диапазон
```

---

#### Класс `ExcelFieldMapping`

Описание маппинга одного поля документа на данные в Excel.

```python
@dataclass
class ExcelFieldMapping:
    field_name: str                        # Имя поля в схеме документа
    source_type: ExcelSourceType           # Тип источника данных
    sheet_name: str | None = None          # Имя листа (None = активный лист)
    range_ref: str = ""                    # Ссылка на диапазон (например, "A1:A100", "B2", "C:C")
    skip_empty: bool = True               # Пропускать пустые ячейки
    trim: bool = True                     # Удалять пробелы по краям
    dtype: str = "auto"                   # Тип данных: "auto", "str", "int", "float", "date"
```

---

#### Класс `ExcelImporter`

```python
class ExcelImporter:
    def __init__(self, file_path: Path) -> None
```
Открывает файл Excel для чтения. Бросает `FileNotFoundError` при отсутствии файла, `ValueError` при неподдерживаемом формате.

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `get_sheets` | `() -> list[str]` | Возвращает список имён листов в файле. |
| `preview_range` | `(sheet: str, range_ref: str, limit: int = 10) -> list[Any]` | Предварительный просмотр данных из указанного диапазона. Возвращает до `limit` значений. Для `RANGE` — список списков. |
| `apply_mappings` | `(mappings: list[ExcelFieldMapping], form_data: dict[str, Any]) -> dict[str, Any]` | Применяет маппинги: извлекает данные из Excel и объединяет с существующими данными формы `form_data`. Возвращает обновлённый словарь. |

**Пример:**

```python
importer = ExcelImporter(Path("invoice_data.xlsx"))

sheets = importer.get_sheets()  # ["Sheet1", "Товары"]

preview = importer.preview_range("Товары", "A1:D5")
# [["Наименование", "Кол-во", "Цена", "Сумма"],
#  ["Товар 1", 10, 150.00, 1500.00], ...]

mappings = [
    ExcelFieldMapping("items_table", ExcelSourceType.RANGE,
                      "Товары", "A2:D100"),
    ExcelFieldMapping("total", ExcelSourceType.COLUMN,
                      "Товары", "E2"),
]

result = importer.apply_mappings(mappings, {"doc_number": "INV-001"})
```

---

### 4.2 VariableParser

Парсер шаблонных переменных. Подставляет значения в текстовые шаблоны документов.

#### Поддерживаемые синтаксисы переменных

| Синтаксис | Пример | Описание |
|-----------|--------|----------|
| `{{variable_name}}` | `{{company_name}}` | Двойные фигурные скобки (основной формат). |
| `{variable_name}` | `{date}` | Одинарные фигурные скобки. |
| `${variable_name}` | `${total_amount}` | Доллар + фигурные скобки (shell-стиль). |

#### ESC/P переменные (предопределённые)

| Переменная | Hex-значение | Описание |
|-----------|-------------|----------|
| `PAGE_BREAK` | `\x0c` | Перевод страницы (Form Feed). |
| `RESET_PRINTER` | `\x1b\x40` | Сброс принтера (ESC @). |
| `LINE_FEED` | `\x0a` | Перевод строки (LF). |

---

#### Класс `VariableParser`

```python
class VariableParser:
    def parse(
        self,
        template: str,
        variables: dict[str, str]
    ) -> str
```
Подставляет значения переменных в шаблон. Нераспознанные переменные остаются без изменений.

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `template` | `str` | Строка-шаблон с переменными. |
| `variables` | `dict[str, str]` | Словарь `{имя_переменной: значение}`. |

**Возвращает:** `str` — результат подстановки.

---

```python
    def extract_variables(
        self,
        template: str
    ) -> list[str]
```
Извлекает имена всех переменных из шаблона (все три синтаксиса). Возвращает список уникальных имён.

---

```python
    def substitute_batch(
        self,
        templates: list[str],
        variables: dict[str, str]
    ) -> list[str]
```
Пакетная подстановка переменных в список шаблонов. Эквивалентно вызову `parse()` для каждого шаблона.

**Пример:**

```python
parser = VariableParser()

template = "Счёт {{doc_number}} от {{date}} на сумму ${total} руб."
variables = {
    "doc_number": "INV-2026-I",
    "date": "12.03.2026",
    "total": "150 000.00"
}

result = parser.parse(template, variables)
# "Счёт INV-2026-I от 12.03.2026 на сумму 150 000.00 руб."

names = parser.extract_variables(template)
# ["doc_number", "date", "total"]
```

---

### 4.3 InputMask

Модуль масок ввода для полей форм.

```python
class InputMask:
    def __init__(self, pattern: str, placeholder: str = "_") -> None: ...
```

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|-------------|----------|
| `pattern` | `str` | — | Маска ввода: `#` (цифра), `A` (буква), `R` (римская цифра) |
| `placeholder` | `str` | `"_"` | Символ placeholder для незаполненных позиций |

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `apply` | `(raw: str) -> str` | Применяет маску к сырому вводу. Пример: `"123"` + `"##.##.####"` → `"12.3_.____"` |
| `strip` | `(masked: str) -> str` | Удаляет маску, оставляет только значимые символы. Пример: `"12.3_.____"` → `"123"` |
| `is_complete` | `(masked: str) -> bool` | Проверяет, заполнена ли маска полностью |
| `build_from_template` | `(index_template: IndexTemplate) -> InputMask` | **staticmethod.** Строит маску для document_index из IndexTemplate |

**Примеры масок:**

| Тип | Маска | Результат |
|-----|-------|-----------|
| Дата | `##.##.####` | `25.12.2026` |
| Телефон | `+7 (###) ###-##-##` | `+7 (495) 123-45-67` |
| Индекс | `AAA-##-A##-RR` | `DVN-44-K53-IX` |

---

### 4.4 FormValidator

Трёхуровневая валидация форм.

```python
class FormValidator:
    def __init__(self, schema: TypeSchema) -> None: ...
```

| Параметр | Тип | Описание |
|----------|-----|----------|
| `schema` | `TypeSchema` | Схема для валидации |

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `validate_field` | `(field_id: str, value: str) -> list[ValidationResult]` | Уровень 1: валидация отдельного поля |
| `validate_form` | `(document: Document) -> list[ValidationResult]` | Уровень 2: валидация всей формы |
| `validate_cross_fields` | `(document: Document) -> list[ValidationResult]` | Уровень 3: кросс-полевая валидация |

**Класс `ValidationResult`:**

```python
@dataclass(frozen=True)
class ValidationResult:
    field_id: str | None       # None = ошибка уровня формы
    severity: Severity         # ERROR | WARNING | INFO
    code: str                  # машиночитаемый код ошибки
    message: str               # человекочитаемое сообщение
```

**Класс `Severity`:**

```python
class Severity(Enum):
    ERROR = "error"       # Блокирует подпись
    WARNING = "warning"   # Предупреждение
    INFO = "info"         # Информация
```

---

### 4.5 SchemaLinter

Линтер для проверки схем форм.

```python
class SchemaLinter:
    def __init__(self) -> None: ...
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `check_conflicts` | `(schema: TypeSchema) -> list[LintResult]` | Проверяет конфликты позиций полей (перекрытие) |
| `check_coverage` | `(schema: TypeSchema, renderer: Renderer) -> list[LintResult]` | Проверяет покрытие всех полей рендерером |
| `check_references` | `(schema: TypeSchema) -> list[LintResult]` | Проверяет валидность ссылок между полями |

**Класс `LintResult`:**

```python
@dataclass(frozen=True)
class LintResult:
    severity: Severity
    code: str
    message: str
    field_id: str | None
```

---

### 4.6 FormHistory

История заполнения полей для автозаполнения.

```python
class FormHistory:
    def __init__(self, history_path: Path = Path("~/.fxtextprocessor/history/")) -> None: ...
```

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|-------------|----------|
| `history_path` | `Path` | `~/.fxtextprocessor/history/` | Путь к директории истории |

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `add_entry` | `(field_id: str, value: str, doc_type: str) -> None` | Добавляет запись в историю |
| `get_suggestions` | `(field_id: str, limit: int = 5) -> list[tuple[str, int]]` | Возвращает частотно-ранжированные предложения (value, frequency) |
| `prefill_from_previous` | `(doc_type: str, series: str) -> dict[str, str]` | Копирует значения из последнего документа той же серии |
| `clear_old_entries` | `(days: int = 90) -> int` | Очищает записи старше N дней, возвращает количество удалённых |

---

### 4.7 TemplateLibrary

Библиотека шаблонов с версионированием.

```python
class TemplateLibrary:
    def __init__(self, library_path: Path = Path("~/.fxtextprocessor/templates/")) -> None: ...
```

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|-------------|----------|
| `library_path` | `Path` | `~/.fxtextprocessor/templates/` | Путь к библиотеке шаблонов |

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `import_template` | `(source_path: Path, verify_signature: bool = True) -> TemplateInfo` | Импортирует шаблон с внешнего носителя |
| `export_template` | `(template_id: str, target_path: Path) -> None` | Экспортирует шаблон на внешний носитель |
| `list_templates` | `() -> list[TemplateInfo]` | Возвращает список шаблонов с метаданными |
| `get_preview` | `(template_id: str) -> Image` | Генерирует превью шаблона (PIL Image) |
| `delete_template` | `(template_id: str) -> bool` | Удаляет шаблон из библиотеки |

**Класс `TemplateInfo`:**

```python
@dataclass(frozen=True)
class TemplateInfo:
    template_id: str
    name: str
    version: str
    doc_type: str
    created_at: datetime
    signature_valid: bool
    preview_thumbnail: bytes | None
```

---

### 4.8 ApprovalWorkflow

Workflow согласования для single-operator.

```python
class ApprovalWorkflow:
    def __init__(self, audit_log: AuditLogProtocol) -> None: ...
```

| Параметр | Тип | Описание |
|----------|-----|----------|
| `audit_log` | `AuditLogProtocol` | Audit log для записи переходов |

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `transition` | `(document: Document, from_state: FormStatus, to_state: FormStatus, mfa: bool = True) -> None` | Переход между состояниями с MFA |
| `switch_role` | `(role: WorkflowRole) -> None` | Переключение роли оператора |
| `add_comment` | `(field_id: str, comment: str, author_role: WorkflowRole) -> FieldAnnotation` | Добавляет комментарий к полю |
| `get_comments` | `(field_id: str) -> list[FieldAnnotation]` | Возвращает комментарии к полю |
| `can_transition` | `(document: Document, to_state: FormStatus) -> bool` | Проверяет возможность перехода |

**Класс `WorkflowRole`:**

```python
class WorkflowRole(Enum):
    OPERATOR = "operator"       # Заполнение формы
    EDITOR = "editor"           # Редактирование/проверка
    SUPERVISOR = "supervisor"   # Согласование
    SIGNATORY = "signatory"     # Подписание
```

**Класс `FieldAnnotation`:**

```python
@dataclass(frozen=True)
class FieldAnnotation:
    annotation_id: str
    field_id: str
    comment: str
    author_role: WorkflowRole
    created_at: datetime
    resolved: bool = False
```

---

### 4.9 SchemaDocumentationGenerator

Генератор документации из TypeSchema.

```python
class SchemaDocumentationGenerator:
    def __init__(self) -> None: ...
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `to_plaintext` | `(schema: TypeSchema) -> str` | Текстовое описание для печати на FX-890 |
| `to_fxsd` | `(schema: TypeSchema) -> Document` | Создаёт документ-инструкцию по заполнению |
| `diff` | `(old: TypeSchema, new: TypeSchema) -> SchemaDiff` | Сравнивает две версии схемы |

**Класс `SchemaDiff`:**

```python
@dataclass(frozen=True)
class SchemaDiff:
    added_fields: list[str]
    removed_fields: list[str]
    modified_fields: list[tuple[str, str, str]]  # field_id, old, new
    compatibility_broken: bool
```

---

### 4.10 TestFillMode

Режим тестового заполнения форм.

```python
class TestFillMode:
    def __init__(self, file_adapter: FileAdapter) -> None: ...
```

| Параметр | Тип | Описание |
|----------|-----|----------|
| `file_adapter` | `FileAdapter` | Адаптер для вывода .escp дампа |

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `generate_synthetic_data` | `(schema: TypeSchema) -> dict[str, str]` | Генерирует тестовые данные для всех полей |
| `export_escp_dump` | `(document: Document, path: Path) -> None` | Экспортирует ESC/P дамп для проверки |
| `run_edge_case_tests` | `(schema: TypeSchema) -> list[TestResult]` | Тесты граничных случаев |
| `validate_output` | `(document: Document) -> list[ValidationResult]` | Проверяет валидность вывода |

**Класс `TestResult`:**

```python
@dataclass(frozen=True)
class TestResult:
    test_name: str
    passed: bool
    message: str
    severity: Severity
```

---

## 5. Document Rendering (`src/documents/printing/`)

Модуль рендеринга документов в бинарные ESC/P данные для отправки на принтер.

---

### Класс `DocumentRenderer`

Главный рендерер. Преобразует `Document` в поток ESC/P команд.

```python
class DocumentRenderer:
    def __init__(
        self,
        codepage: CodePage = CodePage.PC866
    ) -> None
```

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|-------------|----------|
| `codepage` | `CodePage` | `PC866` | Кодовая страница для кодирования текста. |

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `render` | `(document: Document) -> bytes` | Рендерит весь документ в бинарные ESC/P данные. Включает инициализацию принтера (ESC @), установку параметров страницы, рендеринг всех секций и завершающий form feed. |
| `render_to_file` | `(document: Document, path: Path) -> None` | Рендерит документ и сохраняет результат в файл `.escp`. |

---

### Класс `ParagraphRenderer`

Рендерер параграфов. Обрабатывает выравнивание, отступы и переносы строк.

```python
class ParagraphRenderer:
    def render(
        self,
        paragraph: Paragraph,
        settings: PrinterSettings
    ) -> bytes
```

Генерирует ESC/P команды для одного параграфа, включая:
- Установку выравнивания
- Рендеринг всех Run'ов внутри параграфа
- Добавление переносов строк

---

### Класс `TableRenderer`

Рендерер таблиц. Отрисовывает таблицы с помощью символов псевдографики.

```python
class TableRenderer:
    def render(
        self,
        table: Table,
        settings: PrinterSettings
    ) -> bytes
```

Генерирует ESC/P команды для таблицы, включая:
- Рамки таблицы (в зависимости от `TableStyle`)
- Выравнивание содержимого ячеек
- Автоматическое вычисление ширины столбцов

---

### Класс `RunRenderer`

Рендерер текстовых фрагментов (Run). Применяет форматирование (жирный, курсив и т.д.).

```python
class RunRenderer:
    def render(
        self,
        run: Run,
        settings: PrinterSettings
    ) -> bytes
```

Генерирует ESC/P команды для одного Run:
1. Применяет стили (`TextStyle` → ESC/P команды включения)
2. Кодирует текст в байты указанной кодовой страницы
3. Снимает стили (ESC/P команды выключения)

---

### Класс `BarcodeRenderer`

Рендерер штрихкодов.

```python
class BarcodeRenderer:
    def render(
        self,
        barcode_data: str,
        barcode_type: BarcodeType,
        module_width: int = 3,
        height: int = 162,
        hri: BarcodeHRI = BarcodeHRI.BELOW
    ) -> bytes
```

Генерирует ESC/P команды для печати штрихкода. Делегирует в `escp.commands.barcode.print_barcode()`.

**Параметры:**

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|-------------|----------|
| `barcode_data` | `str` | — | Данные штрихкода. |
| `barcode_type` | `BarcodeType` | — | Тип штрихкода. |
| `module_width` | `int` | `3` | Ширина модуля (1–6). |
| `height` | `int` | `162` | Высота в точках (1–255). |
| `hri` | `BarcodeHRI` | `BELOW` | Позиция текста. |

---

## 6. Security API

> **Детальная документация:** см. `SECURITY_ARCHITECTURE.md`

Краткая сводка ключевых интерфейсов безопасности.

---

### 6.1 CryptoService

Криптографический сервис. Обеспечивает подписание, верификацию, шифрование и дешифрование данных.

```python
class CryptoService:
    def __init__(
        self,
        profile: str = "standard"
    ) -> None
```

| Профиль | Подпись | Шифрование | KDF | Описание |
|---------|---------|-------------|-----|----------|
| `"standard"` | Ed25519 | AES-256-GCM | Argon2id (64MB) | Баланс безопасности и производительности. |
| `"paranoid"` | Ed25519 + ML-DSA-65 | AES-256-GCM + ChaCha20 | Argon2id (256MB) | Long-term archive, двойное шифрование. |
| `"pqc"` | ML-DSA-65 | AES-256-GCM | Argon2id (64MB) | Пост-квантовая криптография. |
| `"legacy"` | RSA-PSS-4096 | AES-256-GCM | PBKDF2-SHA256 | Совместимость со старыми системами. |

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `from_config` | `() -> CryptoService` | **classmethod.** Создаёт экземпляр из файла конфигурации `.fxsconfig`. |
| `sign_document` | `(document: bytes, private_key: bytes) -> bytes` | Создаёт цифровую подпись документа (Ed25519). |
| `verify_signature` | `(document: bytes, signature: bytes, public_key: bytes) -> bool` | Верифицирует подпись. Возвращает `True` при валидной подписи. |
| `encrypt` | `(plaintext: bytes) -> bytes` | Шифрует данные (AES-256-GCM). Возвращает nonce + ciphertext + tag. |
| `decrypt` | `(ciphertext: bytes) -> bytes` | Дешифрует данные. Бросает `CryptoError` при невалидных данных. |
| `describe_config` | `() -> dict` | Возвращает описание текущей конфигурации (алгоритмы, размеры ключей). |

---

### 6.2 BlankManager

Менеджер защищённых бланков. Управляет выпуском, подписанием и аннулированием бланков строгой отчётности.

```python
class BlankManager:
    def __init__(
        self,
        audit_log: ImmutableAuditLog,
        crypto_service: CryptoService,
        hw_manager: Any
    ) -> None
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `issue_blank_series` | `(series: str, count: int, blank_type: str, metadata: dict \| None = None) -> list[ProtectedBlank]` | Выпускает серию из `count` защищённых бланков. Каждый бланк получает уникальный ID и криптографическую привязку к серии. |
| `sign_blank` | `(blank_id: UUID, document_content: bytes, signer_id: str \| None = None) -> bytes` | Подписывает бланк содержимым документа. Возвращает подпись. Бланк переходит в статус `SIGNED`. |
| `void_blank` | `(blank_id: UUID, reason: str) -> None` | Аннулирует бланк с указанием причины. Бланк переходит в статус `VOIDED`. Действие необратимо. |

---

#### Функция `verify_blank`

```python
def verify_blank(
    qr_data: dict,
    printed_content: bytes
) -> VerificationResult
```

Верифицирует подлинность бланка по данным QR-кода и печатному содержимому.

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `qr_data` | `dict` | Данные из QR-кода бланка (содержит `blank_id`, `signature`, `public_key`). |
| `printed_content` | `bytes` | Содержимое, напечатанное на бланке. |

**Возвращает:** `VerificationResult` — результат верификации:

```python
@dataclass
class VerificationResult:
    is_valid: bool               # Подпись валидна
    blank_id: UUID | None        # ID бланка
    status: str                  # "valid", "invalid_signature", "voided", "expired"
    details: dict[str, Any]      # Дополнительная информация
```

---

### 6.3 SessionManager

Менеджер сессий. Управляет выпуском, валидацией и отзывом токенов доступа.

```python
class SessionManager:
    def issue(
        self,
        user_id: str,
        scopes: list[str],
        mfa_required: bool = False,
        ttl_seconds: int = 3600
    ) -> TokenBundle
```
Выпускает пару токенов (access + refresh) для пользователя.

**Класс `TokenBundle`:**

```python
@dataclass
class TokenBundle:
    access_token: str           # JWT access token
    refresh_token: str          # Opaque refresh token
    expires_at: datetime        # Время истечения access token
    scopes: list[str]           # Области действия
    session_id: UUID            # ID сессии
```

---

```python
    def validate_access(
        self,
        access_token: str,
        required_scopes: list[str] | None = None
    ) -> ValidationResult
```
Валидирует access token. Проверяет подпись, срок действия и scope'ы.

---

```python
    def refresh(
        self,
        refresh_token: str,
        rotate: bool = True
    ) -> TokenBundle
```
Обновляет токены по refresh token. При `rotate=True` (по умолчанию) старый refresh token аннулируется.

---

```python
    def mark_mfa_satisfied(
        self,
        session_id: UUID
    ) -> None
```
Помечает сессию как прошедшую MFA-верификацию.

---

```python
    def revoke_all_user_sessions(
        self,
        user_id: str
    ) -> None
```
Отзывает все активные сессии пользователя. Используется при компрометации учётных данных.

---

### 6.4 ImmutableAuditLog

Неизменяемый журнал аудита с криптографической цепочкой (hash chain).

```python
class ImmutableAuditLog:
    def __init__(
        self,
        hmac_secret: bytes,
        log_path: Path
    ) -> None
```

| Параметр | Тип | Описание |
|----------|-----|----------|
| `hmac_secret` | `bytes` | Секретный ключ для HMAC-SHA256 цепочки. |
| `log_path` | `Path` | Путь к файлу журнала. |

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `log_event` | `(event_type: AuditEventType, details: dict) -> None` | Записывает событие в журнал. Каждая запись содержит HMAC от предыдущей, образуя неразрывную цепочку. |
| `verify_chain_integrity` | `() -> ChainVerificationResult` | Проверяет целостность всей цепочки. Обнаруживает любые вставки, удаления или модификации записей. |

**Класс `ChainVerificationResult`:**

```python
@dataclass
class ChainVerificationResult:
    is_valid: bool                 # Цепочка целостна
    total_entries: int             # Общее количество записей
    first_entry_time: datetime     # Время первой записи
    last_entry_time: datetime      # Время последней записи
    broken_at_index: int | None    # Индекс, на котором цепочка нарушена (None = целостна)
```

---

## 7. Printer Adapters (`src/printer/`)

Адаптеры для отправки ESC/P данных на принтер. Реализуют единый протокол `PrinterProtocol`.

### Protocol `PrinterProtocol`

```python
class PrinterProtocol(Protocol):
    def write(self, data: bytes) -> None
        """Отправляет данные на принтер."""
        ...

    def close(self) -> None
        """Закрывает соединение с принтером."""
        ...

    def is_ready(self) -> bool
        """Проверяет готовность принтера."""
        ...
```

---

### Класс `WinPrinterAdapter`

Адаптер для Windows. Использует Win32 API (`WritePrinter`).

```python
class WinPrinterAdapter:
    def __init__(
        self,
        printer_name: str = "Epson FX-890"
    ) -> None
```

| Метод | Описание |
|-------|----------|
| `write(data: bytes) -> None` | Отправляет данные через `WritePrinter` API. Бросает `PrinterError` при ошибке. |
| `close() -> None` | Закрывает дескриптор принтера (`ClosePrinter`). |
| `is_ready() -> bool` | Проверяет статус через `GetPrinter`. Возвращает `True`, если принтер онлайн и готов. |

> **Платформа:** Только Windows. Требует `pywin32`.

---

### Класс `CupsAdapter`

Адаптер для Linux/macOS. Использует CUPS (Common UNIX Printing System).

```python
class CupsAdapter:
    def __init__(
        self,
        printer_name: str = "Epson_FX-890"
    ) -> None
```

| Метод | Описание |
|-------|----------|
| `write(data: bytes) -> None` | Отправляет задание через CUPS API. |
| `close() -> None` | Завершает задание печати. |
| `is_ready() -> bool` | Проверяет статус принтера через CUPS. |

> **Платформа:** Linux, macOS. Требует `pycups`.

---

### Класс `FileAdapter`

Адаптер для отладки. Записывает ESC/P данные в файл вместо отправки на принтер.

```python
class FileAdapter:
    def __init__(
        self,
        file_path: Path
    ) -> None
```

| Метод | Описание |
|-------|----------|
| `write(data: bytes) -> None` | Записывает данные в файл (append mode). |
| `close() -> None` | Закрывает файл. |
| `is_ready() -> bool` | Всегда возвращает `True`. |

> **Использование:** Отладка и тестирование без физического принтера. Файл можно затем отправить на принтер командой `copy /b file.escp LPT1:` (Windows) или `lp -d printer -o raw file.escp` (Linux).

---

## 8. App Context (`src/app_context.py`)

Глобальный контекст приложения. Service Locator pattern для доступа к общим сервисам.

### Класс `AppContext`

```python
class AppContext:
    storage: SecureStorage              # Защищённое хранилище (keystore)
    mfa_manager: SecondFactorManager    # Менеджер второго фактора аутентификации
    audit: Any                          # Экземпляр ImmutableAuditLog (или заглушка)
    user_id: str | None                 # ID текущего пользователя (None = не авторизован)
    services: dict[str, Any]            # Реестр сервисов
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `register_service` | `(name: str, service: Any) -> None` | Регистрирует сервис по имени. Если сервис с таким именем уже зарегистрирован, перезаписывает его. |
| `get_service` | `(name: str) -> Any` | Возвращает сервис по имени. Бросает `KeyError`, если сервис не зарегистрирован. |
| `reset_storage` | `(storage_backend: str, storage_path: Path) -> None` | Пересоздаёт защищённое хранилище с новым бэкендом. Используется при смене профиля безопасности. |

---

### Функция `get_app_context`

```python
def get_app_context(
    storage_backend: str = "file",
    storage_path: Path | None = None,
    mfa_enabled: bool = True,
    audit_enabled: bool = True,
    user_id: str | None = None
) -> AppContext
```

Возвращает глобальный Singleton экземпляр `AppContext`. При первом вызове создаёт контекст с указанными параметрами. Последующие вызовы возвращают существующий экземпляр (параметры игнорируются).

**Параметры:**

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|-------------|----------|
| `storage_backend` | `str` | `"file"` | Бэкенд хранилища: `"file"`, `"memory"`, `"system_keyring"`. |
| `storage_path` | `Path \| None` | `None` | Путь к файлу хранилища (для `"file"` бэкенда). |
| `mfa_enabled` | `bool` | `True` | Включить поддержку MFA. |
| `audit_enabled` | `bool` | `True` | Включить аудит-лог. |
| `user_id` | `str \| None` | `None` | ID пользователя для авторизации. |

---

## 9. File Formats & Extensions

Полная таблица всех файловых расширений, используемых в FX Text Processor 3.

### Documents

| Расширение | Название | Формат | Шифрование |
|-----------|----------|--------|------------|
| `.fxsd` | FX Super Document | JSON | Нет |
| `.fxsd.enc` | FX Super Document Encrypted | JSON | AES-256-GCM |
| `.fxstpl` | FX Super Template | JSON | Нет |

### Security

| Расширение | Название | Формат | Шифрование |
|-----------|----------|--------|------------|
| `.fxsblank` | FX Super Blank | JSON | Всегда зашифрован |
| `.fxskeystore.enc` | FX Super Keystore | Binary | Argon2id + AES-256-GCM |
| `.fxssig` | FX Super Signature | Binary | Нет (публично верифицируемый) |

### System

| Расширение | Название | Формат | Шифрование |
|-----------|----------|--------|------------|
| `.fxsconfig` | FX Super Config | TOML | Подписан (не зашифрован) |
| `.fxsbackup` | FX Super Backup | Archive | Зашифрован |
| `.fxsbundle.enc` | FX Super Bundle | Archive | Зашифрован |
| `.fxsreg` | FX Super Registry | JSON | Подписан |

### Forms

| Расширение | Название | Формат | Шифрование |
|-----------|----------|--------|------------|
| `.fxsf` | FX Super Form | JSON | Нет |
| `.fxsfs` | FX Super Form Secure | JSON | AES-256-GCM |

### Printer

| Расширение | Название | Формат | Шифрование |
|-----------|----------|--------|------------|
| `.escp` | ESC/P Raw Commands | Binary | Нет |
| `.escps` | ESC/P Script | Text | Нет |

### Schema

| Расширение | Название | Формат | Шифрование |
|-----------|----------|--------|------------|
| `.fxsschema` | FX Super Schema | JSON Schema | Нет |

---

## 10. Editing Services API (`src/services/`)

Сервисы для WYSIWYG-редактирования и управления документами. Критичны для GUI.

> **Статус:** ❌ Не реализовано — API спецификация.

---

### 10.1 CommandHistoryService

**Файл:** `src/services/command_history_service.py`

Управление историей команд — undo/redo.

```python
@dataclass(frozen=True)
class Command:
    """Базовый класс команды для undo/redo."""
    command_id: str
    timestamp: datetime
    description: str

    def execute(self) -> None: ...
    def undo(self) -> None: ...
    def redo(self) -> None: ...

class CommandHistoryService:
    def __init__(self, max_history: int = 100) -> None: ...
    def execute(self, command: Command) -> None: ...
    def undo(self) -> bool: ...  # True если undo доступен
    def redo(self) -> bool: ...  # True если redo доступен
    def can_undo(self) -> bool: ...
    def can_redo(self) -> bool: ...
    def clear(self) -> None: ...
    def get_history(self) -> list[Command]: ...
    def get_current_index(self) -> int: ...
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `__init__` | `(max_history: int = 100) -> None` | Создаёт сервис с ограничением истории. |
| `execute` | `(command: Command) -> None` | Выполняет команду и добавляет в историю. Очищает redo-историю. |
| `undo` | `() -> bool` | Отменяет последнюю команду. Возвращает `True` если undo было доступно. |
| `redo` | `() -> bool` | Повторяет отменённую команду. Возвращает `True` если redo было доступно. |
| `can_undo` | `() -> bool` | Проверяет, доступна ли отмена. |
| `can_redo` | `() -> bool` | Проверяет, доступен ли повтор. |
| `clear` | `() -> None` | Очищает всю историю. |
| `get_history` | `() -> list[Command]` | Возвращает список команд в истории. |
| `get_current_index` | `() -> int` | Возвращает текущий индекс в истории. |

**Пример использования:**

```python
from src.services.command_history_service import CommandHistoryService, Command

history = CommandHistoryService(max_history=50)

# Создаём и выполняем команду
insert_cmd = InsertTextCommand(position=0, text="Hello")
history.execute(insert_cmd)

# Undo
if history.can_undo():
    history.undo()

# Redo
if history.can_redo():
    history.redo()
```

---

### 10.2 FindReplaceService

**Файл:** `src/services/find_replace_service.py`

Поиск и замена текста в документе.

```python
@dataclass(frozen=True)
class SearchResult:
    paragraph_index: int
    run_index: int
    start_offset: int
    end_offset: int
    matched_text: str

@dataclass(frozen=True)
class SearchOptions:
    case_sensitive: bool = False
    whole_word: bool = False
    use_regex: bool = False
    direction: SearchDirection = SearchDirection.FORWARD

class FindReplaceService:
    def __init__(self, document: Document) -> None: ...
    def find(self, pattern: str, options: SearchOptions) -> list[SearchResult]: ...
    def find_next(
        self,
        pattern: str,
        from_position: CursorPosition,
        options: SearchOptions
    ) -> SearchResult | None: ...
    def replace(self, result: SearchResult, replacement: str) -> Command: ...
    def replace_all(
        self,
        pattern: str,
        replacement: str,
        options: SearchOptions
    ) -> Command: ...
    def count_matches(self, pattern: str, options: SearchOptions) -> int: ...
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `__init__` | `(document: Document) -> None` | Привязывает сервис к документу. |
| `find` | `(pattern: str, options: SearchOptions) -> list[SearchResult]` | Находит все вхождения паттерна. |
| `find_next` | `(pattern: str, from_position: CursorPosition, options: SearchOptions) -> SearchResult \| None` | Находит следующее вхождение от позиции. |
| `replace` | `(result: SearchResult, replacement: str) -> Command` | Заменяет найденный текст. Возвращает команду для undo. |
| `replace_all` | `(pattern: str, replacement: str, options: SearchOptions) -> Command` | Заменяет все вхождения. Возвращает составную команду. |
| `count_matches` | `(pattern: str, options: SearchOptions) -> int` | Считает количество вхождений без замены. |

---

### 10.3 AutoSaveService

**Файл:** `src/services/auto_save_service.py`

Автосохранение и восстановление после сбоя.

```python
class AutoSaveService:
    def __init__(
        self,
        document_service: DocumentServiceProtocol,
        interval_seconds: int = 60,
        temp_dir: Path | None = None
    ) -> None: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def force_save(self) -> Path: ...  # Возвращает путь к .fxsd.tmp
    def recover_if_needed(self) -> Document | None: ...
    def clear_temp(self) -> None: ...
    def has_recovery_file(self, document_path: Path) -> bool: ...
    def get_recovery_info(self, document_path: Path) -> RecoveryInfo | None: ...
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `__init__` | `(document_service, interval_seconds=60, temp_dir=None) -> None` | Создаёт сервис автосохранения. |
| `start` | `() -> None` | Запускает фоновый таймер автосохранения. |
| `stop` | `() -> None` | Останавливает таймер. |
| `force_save` | `() -> Path` | Немедленно сохраняет в .fxsd.tmp. |
| `recover_if_needed` | `() -> Document \| None` | Проверяет и восстанавливает документ из .fxsd.tmp. |
| `clear_temp` | `() -> None` | Удаляет все временные файлы. |
| `has_recovery_file` | `(document_path: Path) -> bool` | Проверяет наличие файла восстановления. |
| `get_recovery_info` | `(document_path: Path) -> RecoveryInfo \| None` | Возвращает метаданные восстановления. |

**Формат файла:** `.fxsd.tmp` — JSON с полями:
- `original_path`: путь к оригинальному файлу
- `saved_at`: timestamp автосохранения
- `document`: сериализованный документ

---

### 10.4 DocumentStatsService

**Файл:** `src/services/document_stats_service.py`

Статистика документа — счётчики символов, слов, строк.

```python
@dataclass(frozen=True)
class DocumentStats:
    character_count: int
    word_count: int
    line_count: int
    paragraph_count: int
    page_count_estimate: int  # На основе lines_per_page

@dataclass(frozen=True)
class Selection:
    start_paragraph: int
    start_offset: int
    end_paragraph: int
    end_offset: int

class DocumentStatsService:
    def calculate(self, document: Document) -> DocumentStats: ...
    def calculate_selection(self, document: Document, selection: Selection) -> DocumentStats: ...
    def get_character_count(self, document: Document) -> int: ...
    def get_word_count(self, document: Document) -> int: ...
    def get_line_count(self, document: Document) -> int: ...
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `calculate` | `(document: Document) -> DocumentStats` | Полная статистика документа. |
| `calculate_selection` | `(document: Document, selection: Selection) -> DocumentStats` | Статистика выделенного фрагмента. |
| `get_character_count` | `(document: Document) -> int` | Только количество символов. |
| `get_word_count` | `(document: Document) -> int` | Только количество слов (разделитель — пробелы). |
| `get_line_count` | `(document: Document) -> int` | Только количество строк. |

---

### 10.5 ClipboardService

**Файл:** `src/services/clipboard_service.py`

Интеграция с системным буфером обмена.

```python
@dataclass(frozen=True)
class ClipboardContent:
    text: str
    formatting: TextStyle | None  # None для plain text
    source_document: str | None  # document_id для внутреннего copy-paste

class ClipboardService:
    def __init__(self) -> None: ...
    def copy(self, content: ClipboardContent) -> None: ...
    def cut(self, content: ClipboardContent, document: Document, position: Position) -> Command: ...
    def paste(self) -> ClipboardContent | None: ...
    def can_paste(self) -> bool: ...
    def get_formats(self) -> list[ClipboardFormat]: ...
    def paste_special(self, format: ClipboardFormat) -> ClipboardContent | None: ...
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `copy` | `(content: ClipboardContent) -> None` | Копирует в системный буфер. |
| `cut` | `(content: ClipboardContent, document: Document, position: Position) -> Command` | Вырезает (копирует + удаляет). Возвращает команду для undo. |
| `paste` | `() -> ClipboardContent \| None` | Вставляет из буфера. |
| `can_paste` | `() -> bool` | Проверяет, есть ли данные в буфере. |
| `get_formats` | `() -> list[ClipboardFormat]` | Доступные форматы в буфере. |
| `paste_special` | `(format: ClipboardFormat) -> ClipboardContent \| None` | Вставка в определённом формате. |

---

### 10.6 NotificationService

**Файл:** `src/services/notification_service.py`

Система уведомлений и статус-бар.

```python
@dataclass(frozen=True)
class Notification:
    id: str
    message: str
    level: NotificationLevel  # INFO, WARNING, ERROR, SUCCESS
    duration_ms: int
    actions: list[NotificationAction]

@dataclass(frozen=True)
class NotificationAction:
    label: str
    callback: Callable[[], None]

class NotificationService:
    def __init__(self) -> None: ...
    def show(
        self,
        message: str,
        level: NotificationLevel = NotificationLevel.INFO,
        duration_ms: int = 5000
    ) -> str: ...  # Возвращает notification_id
    def show_progress(
        self,
        message: str,
        total: int
    ) -> ProgressHandle: ...
    def dismiss(self, notification_id: str) -> None: ...
    def subscribe(self, callback: Callable[[Notification], None]) -> None: ...
    def unsubscribe(self, callback: Callable[[Notification], None]) -> None: ...
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `show` | `(message: str, level=INFO, duration_ms=5000) -> str` | Показывает уведомление. Возвращает ID. |
| `show_progress` | `(message: str, total: int) -> ProgressHandle` | Показывает прогресс-бар. |
| `dismiss` | `(notification_id: str) -> None` | Скрывает уведомление. |
| `subscribe` | `(callback: Callable[[Notification], None]) -> None` | Подписка на уведомления. |
| `unsubscribe` | `(callback: Callable[[Notification], None]) -> None` | Отписка. |

---

### 10.7 DocumentLockService

**Файл:** `src/services/document_lock_service.py`

Блокировка документа от двойного открытия (portable mode).

```python
@dataclass(frozen=True)
class LockHandle:
    document_path: Path
    lock_file_path: Path
    acquired_at: datetime

@dataclass(frozen=True)
class LockInfo:
    pid: int
    username: str
    acquired_at: datetime
    machine_id: str

class DocumentLockService:
    def __init__(self, lock_dir: Path) -> None: ...
    def acquire(self, document_path: Path) -> LockHandle | None: ...
    def release(self, handle: LockHandle) -> None: ...
    def is_locked(self, document_path: Path) -> bool: ...
    def get_lock_info(self, document_path: Path) -> LockInfo | None: ...
    def force_release(self, document_path: Path) -> bool: ...  # Для recovery
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `acquire` | `(document_path: Path) -> LockHandle \| None` | Блокирует документ. None если уже заблокирован. |
| `release` | `(handle: LockHandle) -> None` | Снимает блокировку. |
| `is_locked` | `(document_path: Path) -> bool` | Проверяет блокировку. |
| `get_lock_info` | `(document_path: Path) -> LockInfo \| None` | Информация о блокировке. |
| `force_release` | `(document_path: Path) -> bool` | Принудительное снятие (для recovery). |

**Формат .fxsd.lock:**
```json
{
  "pid": 12345,
  "username": "operator",
  "machine_id": "uuid",
  "acquired_at": "2026-03-18T10:30:00Z"
}
```

---

### 10.8 VersionHistoryService

**Файл:** `src/services/version_history_service.py`

История версий документа — diff между версиями.

```python
@dataclass(frozen=True)
class VersionInfo:
    version: int
    timestamp: datetime
    author: str
    change_summary: str
    snapshot_path: Path | None

@dataclass(frozen=True)
class DocumentDiff:
    added_paragraphs: list[int]
    removed_paragraphs: list[int]
    modified_paragraphs: list[tuple[int, ParagraphDiff]]

class VersionHistoryService:
    def __init__(self, history_dir: Path) -> None: ...
    def save_version(self, document: Document, change_summary: str = "") -> VersionInfo: ...
    def get_versions(self, document_id: str) -> list[VersionInfo]: ...
    def get_version(self, document_id: str, version: int) -> Document: ...
    def compare(self, document_id: str, version_a: int, version_b: int) -> DocumentDiff: ...
    def revert_to(self, document_id: str, version: int) -> Command: ...
    def delete_version(self, document_id: str, version: int) -> bool: ...
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `save_version` | `(document: Document, change_summary="") -> VersionInfo` | Сохраняет версию. |
| `get_versions` | `(document_id: str) -> list[VersionInfo]` | Список всех версий. |
| `get_version` | `(document_id: str, version: int) -> Document` | Загружает конкретную версию. |
| `compare` | `(document_id: str, version_a: int, version_b: int) -> DocumentDiff` | Сравнивает две версии. |
| `revert_to` | `(document_id: str, version: int) -> Command` | Откатывает к версии. Возвращает команду. |
| `delete_version` | `(document_id: str, version: int) -> bool` | Удаляет версию. |

---

### 10.9 DocumentManagerService

**Файл:** `src/services/document_manager_service.py`

Управление несколькими открытыми документами (MDI).

```python
@dataclass(frozen=True)
class DocumentHandle:
    handle_id: str
    document: Document
    file_path: Path | None
    is_modified: bool
    is_active: bool

class DocumentManagerService:
    def __init__(self) -> None: ...
    def open_document(self, path: Path) -> DocumentHandle: ...
    def create_document(self, doc_type: str | None = None) -> DocumentHandle: ...
    def close_document(self, handle: DocumentHandle, force: bool = False) -> bool: ...
    def get_active(self) -> DocumentHandle | None: ...
    def set_active(self, handle: DocumentHandle) -> None: ...
    def list_open(self) -> list[DocumentHandle]: ...
    def has_unsaved_changes(self, handle: DocumentHandle) -> bool: ...
    def save_all(self) -> list[tuple[DocumentHandle, bool]]: ...  # (handle, success)
    def get_handle_by_path(self, path: Path) -> DocumentHandle | None: ...
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `open_document` | `(path: Path) -> DocumentHandle` | Открывает документ с диска. |
| `create_document` | `(doc_type: str \| None = None) -> DocumentHandle` | Создаёт новый документ. |
| `close_document` | `(handle: DocumentHandle, force: bool = False) -> bool` | Закрывает документ. False если есть несохранённые изменения. |
| `get_active` | `() -> DocumentHandle \| None` | Активный документ. |
| `set_active` | `(handle: DocumentHandle) -> None` | Делает документ активным. |
| `list_open` | `() -> list[DocumentHandle]` | Список открытых документов. |
| `has_unsaved_changes` | `(handle: DocumentHandle) -> bool` | Проверяет несохранённые изменения. |
| `save_all` | `() -> list[tuple[DocumentHandle, bool]]` | Сохраняет все документы. |
| `get_handle_by_path` | `(path: Path) -> DocumentHandle \| None` | Находит handle по пути. |

---

### 10.10 ExportService

**Файл:** `src/services/export_service.py`

Экспорт документа в различные форматы.

```python
class ExportFormat(Enum):
    TXT = "txt"
    MD = "markdown"
    HTML = "html"
    PDF = "pdf"  # Future

class ExportOptions:
    include_metadata: bool = False
    encoding: str = "utf-8"
    line_ending: str = "\n"

class ExportService:
    def __init__(self) -> None: ...
    def export_txt(self, document: Document, path: Path, options: ExportOptions | None = None) -> None: ...
    def export_md(self, document: Document, path: Path, options: ExportOptions | None = None) -> None: ...
    def export_html(self, document: Document, path: Path, options: ExportOptions | None = None) -> None: ...
    def export(self, document: Document, path: Path, format: ExportFormat, options: ExportOptions | None = None) -> None: ...
    def get_supported_formats(self) -> list[ExportFormat]: ...
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `export_txt` | `(document: Document, path: Path, options=None) -> None` | Экспорт в plain text. |
| `export_md` | `(document: Document, path: Path, options=None) -> None` | Экспорт в Markdown. |
| `export_html` | `(document: Document, path: Path, options=None) -> None` | Экспорт в HTML. |
| `export` | `(document: Document, path: Path, format: ExportFormat, options=None) -> None` | Универсальный метод экспорта. |
| `get_supported_formats` | `() -> list[ExportFormat]` | Список поддерживаемых форматов. |

---

### 10.11 PrintQueueService

**Файл:** `src/services/print_queue_service.py`

Очередь заданий печати с приоритетами.

```python
@dataclass(frozen=True)
class PrintJob:
    id: str
    document: Document
    priority: PrintPriority
    status: PrintJobStatus
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None

class PrintPriority(Enum):
    LOW = 0
    NORMAL = 1
    HIGH = 2
    URGENT = 3

class PrintJobStatus(Enum):
    PENDING = "pending"
    PRINTING = "printing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class PrintQueueService:
    def __init__(self, printer_adapter: PrinterProtocol) -> None: ...
    def enqueue(self, document: Document, priority: PrintPriority = PrintPriority.NORMAL) -> str: ...
    def cancel(self, job_id: str) -> bool: ...
    def get_status(self, job_id: str) -> PrintJobStatus: ...
    def get_queue(self) -> list[PrintJob]: ...
    def get_job(self, job_id: str) -> PrintJob | None: ...
    def process_queue(self) -> None: ...
    def pause(self) -> None: ...
    def resume(self) -> None: ...
    def clear_completed(self) -> int: ...  # Возвращает количество удалённых
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `enqueue` | `(document: Document, priority=NORMAL) -> str` | Добавляет задание в очередь. Возвращает job_id. |
| `cancel` | `(job_id: str) -> bool` | Отменяет задание. |
| `get_status` | `(job_id: str) -> PrintJobStatus` | Статус задания. |
| `get_queue` | `() -> list[PrintJob]` | Все задания в очереди. |
| `get_job` | `(job_id: str) -> PrintJob \| None` | Конкретное задание. |
| `process_queue` | `() -> None` | Обрабатывает очередь (вызывается background thread). |
| `pause` | `() -> None` | Приостанавливает обработку. |
| `resume` | `() -> None` | Возобновляет обработку. |
| `clear_completed` | `() -> int` | Удаляет завершённые задания. |

---

### 10.12 BatchService

**Файл:** `src/services/batch_service.py`

Пакетные операции — batch print, batch export.

```python
@dataclass(frozen=True)
class BatchPrintOptions:
    copies: int = 1
    collate: bool = True
    priority: PrintPriority = PrintPriority.NORMAL

@dataclass(frozen=True)
class BatchResult:
    total: int
    succeeded: int
    failed: int
    errors: list[tuple[str, str]]  # (document_id, error_message)

class BatchService:
    def __init__(
        self,
        document_service: DocumentServiceProtocol,
        print_service: PrintServiceProtocol
    ) -> None: ...
    def batch_print(
        self,
        documents: list[Document],
        options: BatchPrintOptions
    ) -> BatchResult: ...
    def batch_export(
        self,
        documents: list[Document],
        format: ExportFormat,
        output_dir: Path,
        naming_pattern: str = "{index}_{title}.{ext}"
    ) -> BatchResult: ...
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `batch_print` | `(documents: list[Document], options: BatchPrintOptions) -> BatchResult` | Пакетная печать. |
| `batch_export` | `(documents: list[Document], format: ExportFormat, output_dir: Path, naming_pattern="{index}_{title}.{ext}") -> BatchResult` | Пакетный экспорт. |

---

### 10.13 IndexSearchService

**Файл:** `src/services/index_search_service.py`

Поиск и фильтрация документов по индексу DVN-44-K53-IX.

```python
@dataclass(frozen=True)
class DocumentInfo:
    document_id: str
    file_path: Path
    document_type: str
    document_index: str
    created_at: datetime
    modified_at: datetime

@dataclass(frozen=True)
class SearchCriteria:
    document_type: str | None = None
    series: str | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None
    author: str | None = None

class IndexSearchService:
    def __init__(self, documents_dir: Path) -> None: ...
    def search_by_index(self, pattern: str) -> list[DocumentInfo]: ...
    def search_by_type(self, doc_type: str) -> list[DocumentInfo]: ...
    def search_by_series(self, series: str) -> list[DocumentInfo]: ...
    def search_by_date_range(self, start: datetime, end: datetime) -> list[DocumentInfo]: ...
    def filter(self, criteria: SearchCriteria) -> list[DocumentInfo]: ...
    def get_recent(self, count: int = 10) -> list[DocumentInfo]: ...
    def rebuild_index(self) -> None: ...
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `search_by_index` | `(pattern: str) -> list[DocumentInfo]` | Поиск по шаблону индекса (regex). |
| `search_by_type` | `(doc_type: str) -> list[DocumentInfo]` | Документы определённого типа. |
| `search_by_series` | `(series: str) -> list[DocumentInfo]` | Документы серии (например, "K53"). |
| `search_by_date_range` | `(start: datetime, end: datetime) -> list[DocumentInfo]` | По диапазону дат. |
| `filter` | `(criteria: SearchCriteria) -> list[DocumentInfo]` | Комбинированный фильтр. |
| `get_recent` | `(count: int = 10) -> list[DocumentInfo]` | Недавние документы. |
| `rebuild_index` | `() -> None` | Перестраивает индекс. |

---

### 10.14 KeyBindingsService

**Файл:** `src/services/key_bindings_service.py`

Система горячих клавиш.

```python
class KeyBindingsService:
    def __init__(self, config_path: Path | None = None) -> None: ...
    def register(self, key_combo: str, action_id: str) -> None: ...
    def unregister(self, key_combo: str) -> None: ...
    def get_action(self, key_combo: str) -> str | None: ...
    def get_bindings_for_action(self, action_id: str) -> list[str]: ...
    def is_registered(self, key_combo: str) -> bool: ...
    def load_defaults(self) -> None: ...
    def load_from_file(self, path: Path) -> None: ...
    def save(self) -> None: ...
    def reset_to_defaults(self) -> None: ...
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `register` | `(key_combo: str, action_id: str) -> None` | Регистрирует сочетание клавиш. |
| `unregister` | `(key_combo: str) -> None` | Удаляет регистрацию. |
| `get_action` | `(key_combo: str) -> str \| None` | Возвращает action_id по сочетанию. |
| `get_bindings_for_action` | `(action_id: str) -> list[str]` | Все сочетания для действия. |
| `is_registered` | `(key_combo: str) -> bool` | Проверяет регистрацию. |
| `load_defaults` | `() -> None` | Загружает дефолтные биндинги. |
| `load_from_file` | `(path: Path) -> None` | Загружает из файла. |
| `save` | `() -> None` | Сохраняет в файл. |
| `reset_to_defaults` | `() -> None` | Сброс к дефолтам. |

**Формат key_combo:** `"Ctrl+S"`, `"Ctrl+Shift+Z"`, `"F5"`, `"Alt+F4"`

---

### 10.15 WatermarkService

**Файл:** `src/services/watermark_service.py`

Водяные знаки через ESC/P graphics layer.

```python
@dataclass(frozen=True)
class WatermarkConfig:
    text: str                    # "КОПИЯ", "ЧЕРНОВИК", "КОНФИДЕНЦИАЛЬНО"
    font_size: int = 48
    opacity: float = 0.3         # 0.0 - 1.0
    angle: int = 45              # Угол наклона в градусах
    position: WatermarkPosition = WatermarkPosition.CENTER
    repeat: bool = True          # Повторять по всей странице

class WatermarkPosition(Enum):
    CENTER = "center"
    TOP_LEFT = "top_left"
    TOP_RIGHT = "top_right"
    BOTTOM_LEFT = "bottom_left"
    BOTTOM_RIGHT = "bottom_right"
    DIAGONAL = "diagonal"

class WatermarkService:
    def __init__(self, renderer: DocumentRenderer) -> None: ...
    def apply_watermark(
        self,
        document: Document,
        config: WatermarkConfig
    ) -> bytes: ...  # ESC/P с watermark
    def remove_watermark(self, escp_data: bytes) -> bytes: ...
    def preview_watermark(
        self,
        document: Document,
        config: WatermarkConfig
    ) -> Image: ...  # PIL Image для preview
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `apply_watermark` | `(document: Document, config: WatermarkConfig) -> bytes` | Накладывает водяной знак на ESC/P. |
| `remove_watermark` | `(escp_data: bytes) -> bytes` | Удаляет watermark (если возможно). |
| `preview_watermark` | `(document: Document, config: WatermarkConfig) -> Image` | Генерирует preview. |

---

### 10.16 PaperFormatService

**Файл:** `src/services/paper_format_service.py`

Управление форматами бумаги и профилями.

```python
@dataclass(frozen=True)
class PaperFormat:
    name: str                    # "A4", "Letter", "A5", "Custom"
    width_inches: float
    height_inches: float
    lines_per_page: int        # При 1/6 lpi
    default_margins: Margins

@dataclass(frozen=True)
class Margins:
    left: float
    right: float
    top: float
    bottom: float

class PaperFormatService:
    def __init__(self) -> None: ...
    def get_builtin_formats(self) -> list[PaperFormat]: ...
    def get_format(self, name: str) -> PaperFormat: ...
    def create_custom_format(
        self,
        name: str,
        width: float,
        height: float,
        margins: Margins
    ) -> PaperFormat: ...
    def apply_format(self, document: Document, format: PaperFormat) -> Command: ...
    def estimate_page_count(self, document: Document, format: PaperFormat) -> int: ...
    def delete_custom_format(self, name: str) -> bool: ...
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `get_builtin_formats` | `() -> list[PaperFormat]` | Встроенные форматы. |
| `get_format` | `(name: str) -> PaperFormat` | Формат по имени. |
| `create_custom_format` | `(name: str, width: float, height: float, margins: Margins) -> PaperFormat` | Создаёт кастомный формат. |
| `apply_format` | `(document: Document, format: PaperFormat) -> Command` | Применяет формат. Возвращает команду. |
| `estimate_page_count` | `(document: Document, format: PaperFormat) -> int` | Оценка количества страниц. |
| `delete_custom_format` | `(name: str) -> bool` | Удаляет кастомный формат. |

**Встроенные форматы:**

| Формат | Размер | Строки (1/6 lpi) | Строки (1/8 lpi) |
|--------|--------|------------------|------------------|
| Letter | 8.5×11" | 66 | 88 |
| A4 | 8.27×11.69" | 70 | 93 |
| Legal | 8.5×14" | 84 | 112 |
| A5 | 5.83×8.27" | 49 | 66 |

---

## 11. Floppy Disk Optimization API

Опциональный модуль для оптимизации документов под ограничения 3.5" дискет (1.44 MB). Включается по желанию пользователя.

### Константы

```python
# src/crypto/utilities/floppy_optimizer.py
MAX_FLOPPY_BYTES: Final[int] = 1_340_000    # ~1.28 MB (с запасом на FAT12)
```

### Класс `FloppyOptimizer`

```python
class FloppyOptimizer:
    def __init__(self, max_bytes: int = MAX_FLOPPY_BYTES) -> None: ...

    def optimize_crypto_params(self, document: Document) -> Document:
        """Заменяет алгоритмы на floppy-friendly аналоги."""
        ...

    def fits_on_floppy(self, document: Document) -> bool:
        """Проверяет, влезет ли документ на дискету."""
        ...

    def estimate_size(self, document: Document) -> int:
        """Оценивает размер документа в байтах (с учётом метаданных и крипто-overhead)."""
        ...
```

**Методы:**

| Метод | Сигнатура | Описание |
|--------|-----------|----------|
| `optimize_crypto_params` | `(document: Document) -> Document` | Заменяет алгоритмы на компактные: Ed25519 вместо ML-DSA, AES-256-GCM без hybrid. |
| `fits_on_floppy` | `(document: Document) -> bool` | `True` если размер ≤ `MAX_FLOPPY_BYTES`. |
| `estimate_size` | `(document: Document) -> int` | Оценка размера в байтах: тело + метаданные + крипто-overhead. |
| `validate_for_floppy` | `(document: Document) -> list[str]` | Список предупреждений: тяжёлые алгоритмы, размер подписи, превышение лимита. |

### Floppy-Friendly сравнение алгоритмов

| Операция | Floppy-Friendly | Размер | Full-Size | Размер |
|----------|----------------|--------|-----------|--------|
| Подпись | Ed25519 | 64 B | ML-DSA-65 | 3,309 B |
| Шифрование | AES-256-GCM | +28 B overhead | Hybrid (ML-KEM + AES) | ~1.5 KB overhead |
| KDF | Argon2id (64MB) | — | Argon2id (256MB) | — |

### Поле `floppy_friendly` в `AlgorithmMetadata`

```python
@dataclass(frozen=True)
class AlgorithmMetadata:
    name: str
    category: AlgorithmCategory
    security_level: int
    output_size: int
    floppy_friendly: bool        # True = подходит для дискет
```

> **Примечание:** Floppy-оптимизация включается опционально в настройках. Ed25519 предпочтителен для компактных подписей на дискетах.

---

*FX Text Processor 3 — API Reference v3.1 — March 2026*
