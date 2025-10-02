"""
Пакет ESC/P Text Editor
=======================

Профессиональный WYSIWYG текстовый редактор для матричного принтера Epson FX-890.

Этот пакет предоставляет:
    - Полную поддержку команд ESC/P для FX-890
    - WYSIWYG-рендеринг на Canvas при разрешении 240×144 DPI
    - Расширенное форматирование текста (жирный, курсив, подчеркивание и т.д.)
    - Кодировка PC866 (кириллица DOS) с динамическим переключением кодовых страниц
    - Дизеринг изображений и обработку растровой графики
    - Генерацию штрих-кодов и QR-кодов
    - Конструктор форм с пакетной печатью
    - Редактор таблиц с импортом/экспортом Excel
    - Совместимость с Markdown
    - Прямую печать через WritePrinter API (в обход драйвера Windows)

Пример базового использования:
    >>> from escp_editor import Document, EscpCommandBuilder, get_logger
    >>>
    >>> logger = get_logger(__name__)
    >>> doc = Document()
    >>> section = doc.sections[0]
    >>>
    >>> # Добавляем форматированный текст
    >>> paragraph = Paragraph()
    >>> run = Run(text="Привет, Мир!", bold=True, cpi=12)
    >>> paragraph.runs.append(run)
    >>> section.paragraphs.append(paragraph)
    >>>
    >>> # Генерируем команды ESC/P
    >>> builder = EscpCommandBuilder()
    >>> commands = builder.initialize()
    >>> commands += builder.set_cpi(12)
    >>> commands += builder.bold_on()
    >>> commands += "Привет, Мир!".encode('cp866')
    >>> commands += builder.bold_off()
    >>>
    >>> logger.info(f"Сгенерировано {len(commands)} байт ESC/P-команд")

Пример разработки плагина:
    >>> from escp_editor import Document, Paragraph, Run, Alignment, get_logger
    >>>
    >>> logger = get_logger("my_plugin")
    >>>
    >>> def create_header(doc: Document, title: str) -> None:
    ...     '''Добавить центрированный жирный заголовок в документ.'''
    ...     header = Paragraph(alignment=Alignment.CENTER)
    ...     header.runs.append(Run(text=title, bold=True, double_width=True))
    ...     doc.sections[0].paragraphs.insert(0, header)
    ...     logger.info(f"Добавлен заголовок: {title}")

Управление конфигурацией:
    >>> import os
    >>> os.environ['ESCP_LOG_LEVEL'] = 'DEBUG'
    >>>
    >>> from escp_editor import load_config, get_logger
    >>>
    >>> config = load_config()
    >>> print(f"Принтер по умолчанию: {config.get('default_printer', 'Не задан')}")
    >>>
    >>> logger = get_logger(__name__)
    >>> logger.debug("Отладочное логирование теперь включено")

Автор: ESC/P Text Editor Development Team
Версия: 0.1.0
Лицензия: MIT
Python: 3.11+
Платформа: Windows 11
"""

import json
import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

# =============================================================================
# МЕТАДАННЫЕ ВЕРСИИ
# =============================================================================

__version__ = "0.1.0"
__author__ = "ESC/P Text Editor Development Team"
__description__ = "Professional WYSIWYG text editor for Epson FX-890 dot matrix printer"
__license__ = "MIT"
__python_requires__ = ">=3.11"
__platform__ = "Windows"

# Компоненты семантической версии
VERSION_MAJOR = 0
VERSION_MINOR = 1
VERSION_PATCH = 0

# =============================================================================
# ПРОВЕРКА ВЕРСИИ PYTHON
# =============================================================================

if sys.version_info < (3, 11):
    raise RuntimeError(
        f"ESC/P Text Editor требует Python 3.11 или выше. "
        f"Текущая версия: {sys.version_info.major}."
        f"{sys.version_info.minor}.{sys.version_info.micro}"
    )

# =============================================================================
# ПРОВЕРКА ПЛАТФОРМЫ
# =============================================================================

if sys.platform != "win32":
    import warnings

    warnings.warn(
        f"ESC/P Text Editor разработан только для Windows. "
        f"Текущая платформа: {sys.platform}. "
        f"Некоторые функции могут не работать.",
        RuntimeWarning,
        stacklevel=2,
    )

# =============================================================================
# КОНФИГУРАЦИЯ ЛОГИРОВАНИЯ
# =============================================================================


def _setup_logging() -> None:
    """
    Инициализировать общепакетную конфигурацию логирования.

    Настраивает корневой логгер с:
    - Консольным обработчиком (stderr) для WARNING и выше
    - Ротирующим файловым обработчиком для всех уровней
    - Структурированным форматом с временной меткой, уровнем,
      модулем и сообщением

    Уровень логирования можно контролировать через переменную
    окружения ESCP_LOG_LEVEL. Допустимые значения:
    DEBUG, INFO, WARNING, ERROR, CRITICAL

    Эта функция вызывается автоматически при инициализации пакета.
    Она идемпотентна - повторные вызовы не имеют дополнительного эффекта.
    """
    # Получаем уровень логирования из переменной окружения
    log_level_str = os.environ.get("ESCP_LOG_LEVEL", "INFO").upper()

    # Отображаем строку в константу логирования
    log_level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    log_level = log_level_map.get(log_level_str, logging.INFO)

    # Проверяем, имеет ли корневой логгер уже обработчики
    # (избегаем дублирования конфигурации)
    root_logger = logging.getLogger("escp_editor")
    if root_logger.handlers:
        return

    root_logger.setLevel(log_level)

    # Создаём форматтер
    formatter = logging.Formatter(
        fmt=("[%(asctime)s] %(levelname)-8s " "[%(name)s.%(funcName)s:%(lineno)d] %(message)s"),
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Консольный обработчик (stderr) - WARNING и выше
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Файловый обработчик (ротирующий) - все уровни
    try:
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            filename=log_dir / "escp_editor.log",
            maxBytes=10 * 1024 * 1024,  # 10 МБ
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    except (OSError, PermissionError) as e:
        # Если файловое логирование не удалось, логируем только в консоль
        root_logger.warning(
            f"Не удалось инициализировать файловое логирование: {e}. "
            f"Используется только консоль."
        )

    # Предотвращаем распространение к корневому логгеру
    root_logger.propagate = False


def get_logger(module_name: str) -> logging.Logger:
    """
    Получить настроенный логгер для указанного модуля.

    Эта функция возвращает экземпляр логгера с централизованной
    конфигурацией логирования пакета. Логгеры именуются как
    'escp_editor.<module_name>'.

    Логгер наследует конфигурацию от корневого логгера пакета:
    - Консольный обработчик (stderr) для WARNING и выше
    - Ротирующий файловый обработчик (logs/escp_editor.log)
      для всех уровней
    - Формат: [временная_метка] УРОВЕНЬ [модуль.функция:строка]
      сообщение
    - Уровень: INFO по умолчанию, настраивается через переменную
      окружения ESCP_LOG_LEVEL

    Аргументы:
        module_name: Имя модуля, запрашивающего логгер.
                    Обычно передают `__name__` для автоматического
                    использования полного квалифицированного имени
                    модуля.

    Возвращает:
        Настроенный экземпляр logging.Logger, готовый к
        использованию.

    Пример:
        >>> logger = get_logger(__name__)
        >>> logger.info("Начинается обработка документа")
        [2025-10-02 00:14:32] INFO     [my_module.process:42]
        Начинается обработка документа

        >>> logger.debug("Значение переменной: %s", some_value)
        >>> logger.warning(
        ...     "Файл конфигурации не найден, "
        ...     "используются настройки по умолчанию"
        ... )
        >>> logger.error(
        ...     "Не удалось подключиться к принтеру: %s",
        ...     error_msg
        ... )

    Примечание:
        Уровень логирования можно контролировать через переменную
        окружения:
        - Windows: `set ESCP_LOG_LEVEL=DEBUG`
        - PowerShell: `$env:ESCP_LOG_LEVEL="DEBUG"`

        Допустимые уровни: DEBUG, INFO, WARNING, ERROR, CRITICAL
    """
    # Убеждаемся, что имя модуля находится в пространстве имён
    # escp_editor
    if not module_name.startswith("escp_editor"):
        if module_name == "__main__":
            full_name = "escp_editor.main"
        else:
            # Удаляем ведущие точки из относительных импортов
            clean_name = module_name.lstrip(".")
            full_name = f"escp_editor.{clean_name}"
    else:
        full_name = module_name

    return logging.getLogger(full_name)


# =============================================================================
# УПРАВЛЕНИЕ КОНФИГУРАЦИЕЙ
# =============================================================================

# Значения конфигурации по умолчанию
_DEFAULT_CONFIG: Dict[str, Any] = {
    "default_printer": "Epson FX-890",
    "default_codepage": "PC866",
    "auto_save_interval_seconds": 120,
    "recent_files_limit": 10,
    "ui_theme": "default",
    "log_level": "INFO",
    "page_width_inches": 8.5,
    "page_height_inches": 11.0,
    "dpi": 240,
    "default_font_family": "Draft",
    "default_cpi": 12,
    "default_lpi": 6,
}


def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Загрузить конфигурацию приложения из config.json или
    использовать настройки по умолчанию.

    Эта функция пытается загрузить конфигурацию из JSON-файла.
    Если файл не существует или содержит недопустимый JSON,
    возвращается конфигурация по умолчанию с записью
    предупреждения в лог.

    Ключи конфигурации:
        - default_printer: str - Имя принтера по умолчанию
        - default_codepage: str - Кодировка по умолчанию
        - auto_save_interval_seconds: int - Интервал автосохранения
        - recent_files_limit: int - Лимит недавних файлов
        - ui_theme: str - Название темы интерфейса
        - log_level: str - Уровень логирования
        - page_width_inches: float - Ширина страницы в дюймах
        - page_height_inches: float - Высота страницы в дюймах
        - dpi: int - DPI для рендеринга (максимум 240)
        - default_font_family: str - Семейство шрифтов
        - default_cpi: int - Символов на дюйм (10, 12, 17)
        - default_lpi: int - Строк на дюйм (6, 8)

    Аргументы:
        config_path: Опциональный путь к файлу конфигурации.
                    Если None, ищет 'config.json' в текущем каталоге.

    Возвращает:
        Словарь, содержащий параметры конфигурации. Всегда включает
        все ключи по умолчанию, с пользовательскими значениями,
        переопределяющими значения по умолчанию.

    Пример:
        >>> config = load_config()
        >>> print(config['default_printer'])
        'Epson FX-890'

        >>> # Загрузка из пользовательского пути
        >>> custom_config = load_config(Path("C:/my_config.json"))

        >>> # Доступ к значениям конфигурации
        >>> printer_name = config.get('default_printer')
        >>> dpi = config.get('dpi', 240)

    Примечание:
        Функция выполняет глубокое слияние пользовательской
        конфигурации с настройками по умолчанию.
    """
    logger = get_logger(__name__)

    # Определяем путь к файлу конфигурации
    if config_path is None:
        config_path = Path("config.json")

    # Начинаем с конфигурации по умолчанию
    config = _DEFAULT_CONFIG.copy()

    # Пытаемся загрузить пользовательскую конфигурацию
    if config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                user_config = json.load(f)

            # Проверяем, что user_config является словарём
            if not isinstance(user_config, dict):
                raise ValueError(
                    f"Файл конфигурации должен содержать JSON-объект, "
                    f"получен {type(user_config).__name__}"
                )

            # Объединяем пользовательскую конфигурацию с настройками
            # по умолчанию
            config.update(user_config)

            logger.info(f"Конфигурация загружена из {config_path}")
            logger.debug(f"Конфигурация: {config}")

        except json.JSONDecodeError as e:
            logger.warning(
                f"Не удалось разобрать {config_path}: Недопустимый JSON "
                f"в строке {e.lineno}, столбце {e.colno}. "
                f"Используется конфигурация по умолчанию."
            )
        except (OSError, PermissionError) as e:
            logger.warning(
                f"Не удалось прочитать {config_path}: {e}. "
                f"Используется конфигурация по умолчанию."
            )
        except ValueError as e:
            logger.warning(
                f"Недопустимый формат конфигурации: {e}. "
                f"Используется конфигурация по умолчанию."
            )
    else:
        logger.info(
            f"Файл конфигурации {config_path} не найден. "
            f"Используется конфигурация по умолчанию."
        )

    return config


def check_dependencies() -> Dict[str, bool]:
    """
    Проверить, установлены ли все обязательные и опциональные
    зависимости.

    Эта функция пытается импортировать каждую зависимость и сообщает
    о её доступности. Она не вызывает исключений для отсутствующих
    пакетов - вместо этого возвращает словарь состояний.

    Проверяемые зависимости:
        Обязательные:
        - tkinter: Фреймворк GUI (поставляется с Python на Windows)

        Опциональные:
        - pillow: Обработка изображений и дизеринг
        - pywin32: Прямой доступ к принтеру через Win32 API
        - qrcode: Генерация QR-кодов
        - python-barcode: Генерация одномерных штрих-кодов
        - python-markdown: Разбор Markdown
        - openpyxl: Импорт/экспорт файлов Excel

    Возвращает:
        Словарь, отображающий имена пакетов на статус доступности.

    Пример:
        >>> deps = check_dependencies()
        >>>
        >>> if not deps['pillow']:
        ...     print("Внимание: Pillow не установлен.")
        ...     print("Функции обработки изображений недоступны.")
        >>>
        >>> if not deps['pywin32']:
        ...     print("Внимание: pywin32 не установлен.")
        ...     print("Прямой доступ к принтеру недоступен.")
    """
    dependencies: Dict[str, bool] = {}

    # Проверяем tkinter (обязательная)
    try:
        import tkinter  # noqa: F401

        dependencies["tkinter"] = True
    except ImportError:
        dependencies["tkinter"] = False

    # Проверяем Pillow (опциональная)
    try:
        import PIL  # noqa: F401

        dependencies["pillow"] = True
    except ImportError:
        dependencies["pillow"] = False

    # Проверяем pywin32 (опциональная)
    try:
        import win32print  # noqa: F401

        dependencies["pywin32"] = True
    except ImportError:
        dependencies["pywin32"] = False

    # Проверяем qrcode (опциональная)
    try:
        import qrcode  # noqa: F401

        dependencies["qrcode"] = True
    except ImportError:
        dependencies["qrcode"] = False

    # Проверяем python-barcode (опциональная)
    try:
        import barcode  # noqa: F401

        dependencies["python-barcode"] = True
    except ImportError:
        dependencies["python-barcode"] = False

    # Проверяем python-markdown (опциональная)
    try:
        import markdown  # noqa: F401

        dependencies["python-markdown"] = True
    except ImportError:
        dependencies["python-markdown"] = False

    # Проверяем openpyxl (опциональная)
    try:
        import openpyxl  # noqa: F401

        dependencies["openpyxl"] = True
    except ImportError:
        dependencies["openpyxl"] = False

    return dependencies


# =============================================================================
# ИМПОРТЫ СЛОЯ МОДЕЛИ
# =============================================================================

# Примечание: Эти импорты намеренно размещены после функций утилит
# чтобы избежать циклических зависимостей и убедиться, что
# логирование настроено первым.

try:
    from .model.document import Document, DocumentMetadata

    _has_document = True
except ImportError as e:
    _logger = get_logger(__name__)
    _logger.error(f"Не удалось импортировать Document: {e}")
    _has_document = False
    Document = None  # type: ignore
    DocumentMetadata = None  # type: ignore

try:
    from .model.section import Section, PageSettings, Margins

    _has_section = True
except ImportError as e:
    _logger = get_logger(__name__)
    _logger.error(f"Не удалось импортировать Section: {e}")
    _has_section = False
    Section = None  # type: ignore
    PageSettings = None  # type: ignore
    Margins = None  # type: ignore

try:
    from .model.paragraph import Paragraph

    _has_paragraph = True
except ImportError as e:
    _logger = get_logger(__name__)
    _logger.error(f"Не удалось импортировать Paragraph: {e}")
    _has_paragraph = False
    Paragraph = None  # type: ignore

try:
    from .model.run import Run

    _has_run = True
except ImportError as e:
    _logger = get_logger(__name__)
    _logger.error(f"Не удалось импортировать Run: {e}")
    _has_run = False
    Run = None  # type: ignore

try:
    from .model.table import Table, TableRow, TableCell, TableStyle, CellBorders

    _has_table = True
except ImportError as e:
    _logger = get_logger(__name__)
    _logger.error(f"Не удалось импортировать Table: {e}")
    _has_table = False
    Table = None  # type: ignore
    TableRow = None  # type: ignore
    TableCell = None  # type: ignore
    TableStyle = None  # type: ignore
    CellBorders = None  # type: ignore

try:
    from .model.image import ImageBlock, ImagePosition

    _has_image = True
except ImportError as e:
    _logger = get_logger(__name__)
    _logger.error(f"Не удалось импортировать ImageBlock: {e}")
    _has_image = False
    ImageBlock = None  # type: ignore
    ImagePosition = None  # type: ignore

try:
    from .model.barcode import BarcodeBlock, BarcodeType

    _has_barcode = True
except ImportError as e:
    _logger = get_logger(__name__)
    _logger.error(f"Не удалось импортировать BarcodeBlock: {e}")
    _has_barcode = False
    BarcodeBlock = None  # type: ignore
    BarcodeType = None  # type: ignore

try:
    from .model.form import FormTemplate, FormElement

    _has_form = True
except ImportError as e:
    _logger = get_logger(__name__)
    _logger.error(f"Не удалось импортировать FormTemplate: {e}")
    _has_form = False
    FormTemplate = None  # type: ignore
    FormElement = None  # type: ignore

try:
    from .model.enums import (
        FontFamily,
        PrintQuality,
        PaperType,
        Orientation,
        Alignment,
        ListType,
        Color,
        DitheringAlgorithm,
    )

    _has_enums = True
except ImportError as e:
    _logger = get_logger(__name__)
    _logger.error(f"Не удалось импортировать перечисления: {e}")
    _has_enums = False
    FontFamily = None  # type: ignore
    PrintQuality = None  # type: ignore
    PaperType = None  # type: ignore
    Orientation = None  # type: ignore
    Alignment = None  # type: ignore
    ListType = None  # type: ignore
    Color = None  # type: ignore
    DitheringAlgorithm = None  # type: ignore

try:
    from .model.validation import DocumentValidator

    _has_validator = True
except ImportError as e:
    _logger = get_logger(__name__)
    _logger.error(f"Не удалось импортировать DocumentValidator: {e}")
    _has_validator = False
    DocumentValidator = None  # type: ignore

# =============================================================================
# ИМПОРТЫ СЛОЯ ESC/P
# =============================================================================

try:
    from .escp.escp_builder import EscpCommandBuilder

    _has_escp_builder = True
except ImportError as e:
    _logger = get_logger(__name__)
    _logger.error(f"Не удалось импортировать EscpCommandBuilder: {e}")
    _has_escp_builder = False
    EscpCommandBuilder = None  # type: ignore

try:
    from .charset.charset_manager import CharsetManager

    _has_charset = True
except ImportError as e:
    _logger = get_logger(__name__)
    _logger.error(f"Не удалось импортировать CharsetManager: {e}")
    _has_charset = False
    CharsetManager = None  # type: ignore

# =============================================================================
# ИНТЕРФЕЙСЫ КОНСТРУКТОРОВ
# =============================================================================

try:
    from .form.form_builder import FormBuilder

    _has_form_builder = True
except ImportError as e:
    _logger = get_logger(__name__)
    _logger.error(f"Не удалось импортировать FormBuilder: {e}")
    _has_form_builder = False
    FormBuilder = None  # type: ignore

try:
    from .table.table_editor import TableEditor

    _has_table_editor = True
except ImportError as e:
    _logger = get_logger(__name__)
    _logger.error(f"Не удалось импортировать TableEditor: {e}")
    _has_table_editor = False
    TableEditor = None  # type: ignore

# =============================================================================
# ОПРЕДЕЛЕНИЕ ПУБЛИЧНОГО API
# =============================================================================

__all__ = [
    # Метаданные версии
    "__version__",
    "__author__",
    "__description__",
    "__license__",
    "__python_requires__",
    "__platform__",
    "VERSION_MAJOR",
    "VERSION_MINOR",
    "VERSION_PATCH",
    # Утилиты
    "get_logger",
    "load_config",
    "check_dependencies",
    # Классы модели
    "Document",
    "DocumentMetadata",
    "Section",
    "PageSettings",
    "Margins",
    "Paragraph",
    "Run",
    "Table",
    "TableRow",
    "TableCell",
    "TableStyle",
    "CellBorders",
    "ImageBlock",
    "ImagePosition",
    "BarcodeBlock",
    "BarcodeType",
    "FormTemplate",
    "FormElement",
    # Перечисления
    "FontFamily",
    "PrintQuality",
    "PaperType",
    "Orientation",
    "Alignment",
    "ListType",
    "Color",
    "DitheringAlgorithm",
    # Конструкторы
    "EscpCommandBuilder",
    "CharsetManager",
    "FormBuilder",
    "TableEditor",
    # Валидация
    "DocumentValidator",
]

# =============================================================================
# ИНИЦИАЛИЗАЦИЯ ПАКЕТА
# =============================================================================

# Сначала настраиваем логирование (перед любой другой инициализацией)
_setup_logging()

# Получаем логгер для этого модуля
_logger = get_logger(__name__)
_logger.info(f"ESC/P Text Editor v{__version__} инициализируется...")
_logger.debug(f"Версия Python: {sys.version}")
_logger.debug(f"Платформа: {sys.platform}")

# Загружаем конфигурацию
try:
    _config = load_config()
    _logger.info(f"Конфигурация загружена: {len(_config)} параметров")
    _logger.debug(f"Активная конфигурация: {_config}")
except Exception as e:
    _logger.warning(
        f"Не удалось загрузить конфигурацию: {e}. " f"Используются настройки по умолчанию."
    )
    _config = _DEFAULT_CONFIG.copy()

# Проверяем зависимости
_deps = check_dependencies()
_missing = [name for name, available in _deps.items() if not available]
_available = [name for name, available in _deps.items() if available]

if _missing:
    _logger.warning(f"Отсутствуют опциональные зависимости: {', '.join(_missing)}")
    _logger.info(
        f"Некоторые функции будут недоступны. "
        f"Установите недостающие пакеты командой: "
        f"pip install {' '.join(_missing)}"
    )

_logger.info(f"Доступные зависимости: {', '.join(_available)}")

# Сообщаем об отсутствующих основных модулях
_missing_modules = []
if not _has_document:
    _missing_modules.append("Document")
if not _has_section:
    _missing_modules.append("Section")
if not _has_paragraph:
    _missing_modules.append("Paragraph")
if not _has_run:
    _missing_modules.append("Run")
if not _has_enums:
    _missing_modules.append("enums")

if _missing_modules:
    _logger.error(
        f"Критические модули не удалось импортировать: "
        f"{', '.join(_missing_modules)}. "
        f"Пакет может работать некорректно."
    )
else:
    _logger.info("Все основные модули загружены успешно")

# Логируем успешную инициализацию
_logger.info(f"ESC/P Text Editor v{__version__} успешно инициализирован")
_logger.debug(f"Расположение пакета: {Path(__file__).parent}")
