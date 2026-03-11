# FX Text Processor 3 — API Reference

**Версия:** 3.0  
**Дата:** March 2026  
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
5. [Document Rendering (`src/documents/printing/`)](#5-document-rendering-srcdocumentsprinting)
6. [Security API](#6-security-api)
   - 6.1 [CryptoService](#61-cryptoservice)
   - 6.2 [BlankManager](#62-blankmanager)
   - 6.3 [SessionManager](#63-sessionmanager)
   - 6.4 [ImmutableAuditLog](#64-immutableauditlog)
7. [Printer Adapters (`src/printer/`)](#7-printer-adapters-srcprinter)
8. [App Context (`src/app_context.py`)](#8-app-context-srcapp_contextpy)
9. [File Formats & Extensions](#9-file-formats--extensions)

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

```python
class Document:
    id: UUID
    metadata: DocumentMetadata
    page_settings: PageSettings
    printer_settings: PrinterSettings
    sections: list[Section]
    file_path: Path | None
    is_modified: bool
```

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
        index_template: IndexTemplate,
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
| `index_template` | `IndexTemplate` | Шаблон генерации индекса. |
| `field_schema` | `TypeSchema` | Схема полей документа данного типа. |
| `parent_code` | `str \| None` | Код родительского типа (для подтипов). |
| `metadata` | `dict[str, Any] \| None` | Дополнительные метаданные типа. |

**Возвращает:** `DocumentType` — зарегистрированный тип.

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
```

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

---

#### Класс `TypeSchema`

Схема полей для типа документа.

```python
@dataclass
class TypeSchema:
    fields: list[FieldDefinition]
```

**Методы:**

| Метод | Сигнатура | Описание |
|-------|-----------|----------|
| `get_field` | `(name: str) -> FieldDefinition` | Возвращает определение поля по имени. Бросает `KeyError`, если поле не найдено. |
| `merge_with_parent` | `(parent_schema: TypeSchema) -> TypeSchema` | Возвращает новую схему, объединяя текущую с родительской. Поля родителя помечаются `inherited_from`. Поля дочернего типа с тем же именем переопределяют родительские. |
| `validate_data` | `(data: dict[str, Any]) -> ValidationResult` | Валидирует данные по схеме. Проверяет обязательные поля, типы значений и правила `validation`. |

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

## 10. Floppy Disk Optimization API

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

*FX Text Processor 3 — API Reference v3.0 — March 2026*
