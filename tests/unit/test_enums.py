"""
Юнит-тесты для src/model/enums.py версии 2.0


Тестирует все классы перечислений, свойства, методы и функции валидации
с полным покрытием граничных случаев и аппаратных ограничений.


Версия 2.0 добавляет:
- PageSize (8 размеров страниц)
- PaperSource (6 источников бумаги)
- GraphicsMode (10 режимов графики)
- MarginUnits (4 единицы измерения)
- PrintDirection (4 направления печати)
- 3 новые функции валидации
- Расширенную валидацию констант модуля
"""

import pytest
from src.model.enums import (
    # Перечисления структуры документа
    Orientation,
    Alignment,
    PaperType,
    # Перечисления типографики
    FontFamily,
    PrintQuality,
    CharactersPerInch,
    LineSpacing,
    TextStyle,
    # Перечисления возможностей принтера
    CodePage,
    Color,
    # Перечисления типов контента
    DitheringAlgorithm,
    BarcodeType,
    TableStyle,
    ListType,
    ImagePosition,
    # ⭐ НОВЫЕ ПЕРЕЧИСЛЕНИЯ (v2.0)
    PageSize,
    PaperSource,
    GraphicsMode,
    MarginUnits,
    PrintDirection,
    # Функции валидации (включая новые)
    validate_style_combination,
    validate_cpi_font_combination,
    validate_quality_font_combination,
    validate_page_size_paper_type,
    validate_graphics_mode_resolution,
    validate_margin_values,
    # Константы
    MAX_MULTIPART_COPIES,
    MAX_PRINT_WIDTH_INCHES,
    MAX_PRINT_HEIGHT_INCHES,
    MIN_MARGIN_INCHES,
    ESC_INIT,
    FF,
    CR,
    LF,
    BEL,
    DEFAULT_FONT_FAMILY,
    DEFAULT_CPI,
    DEFAULT_CODEPAGE,
    DEFAULT_PAGE_SIZE,
    DEFAULT_PAPER_SOURCE,
    DEFAULT_GRAPHICS_MODE,
    DEFAULT_MARGIN_UNITS,
    DEFAULT_PRINT_DIRECTION,
)


# =============================================================================
# ТЕСТЫ НОВЫХ ПЕРЕЧИСЛЕНИЙ (ВЕРСИЯ 2.0)
# =============================================================================


class TestPageSize:
    """Тестирует перечисление PageSize."""

    def test_all_members_exist(self):
        """Проверяет, что все ожидаемые размеры страниц существуют."""
        assert PageSize.A4
        assert PageSize.A5
        assert PageSize.LETTER
        assert PageSize.LEGAL
        assert PageSize.EXECUTIVE
        assert PageSize.FANFOLD_8_5
        assert PageSize.FANFOLD_11
        assert PageSize.CUSTOM

    def test_values_serializable(self):
        """Проверяет, что значения перечисления — это сериализуемые строки."""
        assert PageSize.A4.value == "a4"
        assert PageSize.LETTER.value == "letter"
        assert PageSize.CUSTOM.value == "custom"

    def test_dimensions_inches(self):
        """Тестирует размеры страниц в дюймах."""
        assert PageSize.A4.dimensions_inches == (8.27, 11.69)
        assert PageSize.LETTER.dimensions_inches == (8.5, 11.0)
        assert PageSize.LEGAL.dimensions_inches == (8.5, 14.0)
        assert PageSize.FANFOLD_11.dimensions_inches == (11.0, 8.5)

    def test_is_standard(self):
        """Тестирует определение стандартного размера."""
        assert PageSize.A4.is_standard is True
        assert PageSize.LETTER.is_standard is True
        assert PageSize.CUSTOM.is_standard is False

    def test_max_characters_10cpi(self):
        """Тестирует вычисление максимального количества символов."""
        # Letter: 8.5" * 10 - 2 = 83
        assert PageSize.LETTER.max_characters_10cpi == 83
        # A4: 8.27" * 10 - 2 = 80
        assert PageSize.A4.max_characters_10cpi == 80

    def test_is_compatible_with_tractor(self):
        """Тестирует совместимость с тракторной подачей."""
        assert PageSize.FANFOLD_8_5.is_compatible_with_tractor() is True
        assert PageSize.FANFOLD_11.is_compatible_with_tractor() is True
        assert PageSize.CUSTOM.is_compatible_with_tractor() is True
        assert PageSize.A4.is_compatible_with_tractor() is False
        assert PageSize.LETTER.is_compatible_with_tractor() is False

    def test_localized_names(self):
        """Тестирует получение локализованных названий."""
        assert "210 × 297" in PageSize.A4.localized_name("en")
        assert "210 × 297" in PageSize.A4.localized_name("ru")
        assert "Letter" in PageSize.LETTER.localized_name("en")

    def test_from_string(self):
        """Тестирует поиск из строки."""
        assert PageSize.from_string("a4") == PageSize.A4
        assert PageSize.from_string("LETTER") == PageSize.LETTER
        assert PageSize.from_string("invalid") is None

    def test_str_representation(self):
        """Тестирует строковое представление."""
        assert "A4" in str(PageSize.A4)
        assert "Letter" in str(PageSize.LETTER)


class TestPaperSource:
    """Тестирует перечисление PaperSource."""

    def test_all_members_exist(self):
        """Проверяет, что все ожидаемые источники бумаги существуют."""
        assert PaperSource.AUTO
        assert PaperSource.TRACTOR
        assert PaperSource.MANUAL_FRONT
        assert PaperSource.MANUAL_REAR
        assert PaperSource.SHEET_FEEDER_BIN1
        assert PaperSource.SHEET_FEEDER_BIN2

    def test_escp_codes(self):
        """Тестирует коды ESC/P для источников бумаги."""
        assert PaperSource.AUTO.escp_code == 0
        assert PaperSource.TRACTOR.escp_code == 1
        assert PaperSource.MANUAL_FRONT.escp_code == 2
        assert PaperSource.SHEET_FEEDER_BIN1.escp_code == 4

    def test_is_continuous(self):
        """Тестирует определение непрерывного источника."""
        assert PaperSource.TRACTOR.is_continuous is True
        assert PaperSource.AUTO.is_continuous is False
        assert PaperSource.MANUAL_FRONT.is_continuous is False

    def test_requires_operator_intervention(self):
        """Тестирует определение требования вмешательства оператора."""
        assert PaperSource.MANUAL_FRONT.requires_operator_intervention is True
        assert PaperSource.MANUAL_REAR.requires_operator_intervention is True
        assert PaperSource.TRACTOR.requires_operator_intervention is False
        assert PaperSource.AUTO.requires_operator_intervention is False

    def test_to_escp(self):
        """Тестирует генерацию команды ESC/P."""
        # ESC EM 0
        assert PaperSource.AUTO.to_escp() == b"\x1b\x19\x00"
        # ESC EM 1
        assert PaperSource.TRACTOR.to_escp() == b"\x1b\x19\x01"
        # ESC EM 2
        assert PaperSource.MANUAL_FRONT.to_escp() == b"\x1b\x19\x02"

    def test_localized_names(self):
        """Тестирует локализованные названия."""
        assert "Automatic" in PaperSource.AUTO.localized_name("en")
        assert "Автоматический" in PaperSource.AUTO.localized_name("ru")
        assert "Тракторная" in PaperSource.TRACTOR.localized_name("ru")

    def test_from_string(self):
        """Тестирует поиск из строки."""
        assert PaperSource.from_string("tractor") == PaperSource.TRACTOR
        assert PaperSource.from_string("MANUAL_FRONT") == PaperSource.MANUAL_FRONT
        assert PaperSource.from_string("invalid") is None


class TestGraphicsMode:
    """Тестирует перечисление GraphicsMode."""

    def test_all_members_exist(self):
        """Проверяет, что все ожидаемые режимы графики существуют."""
        assert GraphicsMode.SINGLE_DENSITY
        assert GraphicsMode.DOUBLE_DENSITY
        assert GraphicsMode.DOUBLE_SPEED
        assert GraphicsMode.QUAD_DENSITY
        assert GraphicsMode.CRT_I
        assert GraphicsMode.CRT_II
        assert GraphicsMode.CRT_III
        assert GraphicsMode.TRIPLE_DENSITY
        assert GraphicsMode.HEXADECIMAL
        assert GraphicsMode.CRT_III_24PIN

    def test_resolution_dpi(self):
        """Тестирует разрешения режимов графики."""
        assert GraphicsMode.SINGLE_DENSITY.resolution_dpi == (60, 60)
        assert GraphicsMode.DOUBLE_DENSITY.resolution_dpi == (120, 60)
        assert GraphicsMode.HEXADECIMAL.resolution_dpi == (360, 180)
        assert GraphicsMode.TRIPLE_DENSITY.resolution_dpi == (180, 180)

    def test_pins(self):
        """Тестирует количество иголок."""
        # 8-pin режимы
        assert GraphicsMode.SINGLE_DENSITY.pins == 8
        assert GraphicsMode.DOUBLE_DENSITY.pins == 8
        assert GraphicsMode.CRT_I.pins == 8

        # 24-pin режимы
        assert GraphicsMode.HEXADECIMAL.pins == 24
        assert GraphicsMode.CRT_III_24PIN.pins == 24

    def test_escp_command_prefix(self):
        """Тестирует префиксы команд ESC/P."""
        # ESC K
        assert GraphicsMode.SINGLE_DENSITY.escp_command_prefix == b"\x1b\x4b"
        # ESC L
        assert GraphicsMode.DOUBLE_DENSITY.escp_command_prefix == b"\x1b\x4c"
        # ESC * 4
        assert GraphicsMode.HEXADECIMAL.escp_command_prefix == b"\x1b\x2a\x04"

    def test_to_escp_valid_columns(self):
        """Тестирует генерацию команды с валидными столбцами."""
        cmd = GraphicsMode.DOUBLE_DENSITY.to_escp(100)
        assert isinstance(cmd, bytes)
        # ESC L + low byte (100) + high byte (0)
        assert cmd == b"\x1b\x4c\x64\x00"

        # Тест с большим числом столбцов
        cmd = GraphicsMode.HEXADECIMAL.to_escp(1000)
        assert len(cmd) == 5  # prefix (3) + low + high

    def test_to_escp_invalid_columns(self):
        """Тестирует валидацию диапазона столбцов."""
        with pytest.raises(ValueError, match="must be 0-65535"):
            GraphicsMode.DOUBLE_DENSITY.to_escp(-1)

        with pytest.raises(ValueError, match="must be 0-65535"):
            GraphicsMode.DOUBLE_DENSITY.to_escp(65536)

    def test_localized_names(self):
        """Тестирует локализованные названия."""
        assert "60 DPI" in GraphicsMode.SINGLE_DENSITY.localized_name("en")
        assert "Одинарная плотность" in GraphicsMode.SINGLE_DENSITY.localized_name("ru")
        assert "360 DPI" in GraphicsMode.HEXADECIMAL.localized_name("en")

    def test_from_string(self):
        """Тестирует поиск из строки."""
        assert GraphicsMode.from_string("double_density") == GraphicsMode.DOUBLE_DENSITY
        assert GraphicsMode.from_string("HEXADECIMAL") == GraphicsMode.HEXADECIMAL
        assert GraphicsMode.from_string("invalid") is None


class TestMarginUnits:
    """Тестирует перечисление MarginUnits."""

    def test_all_members_exist(self):
        """Проверяет, что все ожидаемые единицы измерения существуют."""
        assert MarginUnits.INCHES
        assert MarginUnits.MILLIMETERS
        assert MarginUnits.CHARACTERS
        assert MarginUnits.DECIPOINTS

    def test_localized_names(self):
        """Тестирует локализованные названия."""
        assert MarginUnits.INCHES.localized_name("en") == "Inches"
        assert MarginUnits.INCHES.localized_name("ru") == "Дюймы"
        assert "Миллиметры" in MarginUnits.MILLIMETERS.localized_name("ru")

    def test_from_string(self):
        """Тестирует поиск из строки."""
        assert MarginUnits.from_string("inches") == MarginUnits.INCHES
        assert MarginUnits.from_string("MILLIMETERS") == MarginUnits.MILLIMETERS
        assert MarginUnits.from_string("invalid") is None


class TestPrintDirection:
    """Тестирует перечисление PrintDirection."""

    def test_all_members_exist(self):
        """Проверяет, что все ожидаемые направления печати существуют."""
        assert PrintDirection.BIDIRECTIONAL
        assert PrintDirection.UNIDIRECTIONAL
        assert PrintDirection.LEFT_TO_RIGHT
        assert PrintDirection.RIGHT_TO_LEFT

    def test_escp_codes(self):
        """Тестирует коды ESC/P."""
        assert PrintDirection.BIDIRECTIONAL.escp_code == 0
        assert PrintDirection.UNIDIRECTIONAL.escp_code == 1

    def test_to_escp(self):
        """Тестирует генерацию команды ESC/P."""
        # ESC U 0
        assert PrintDirection.BIDIRECTIONAL.to_escp() == b"\x1b\x55\x00"
        # ESC U 1
        assert PrintDirection.UNIDIRECTIONAL.to_escp() == b"\x1b\x55\x01"

    def test_localized_names(self):
        """Тестирует локализованные названия."""
        assert "Faster" in PrintDirection.BIDIRECTIONAL.localized_name("en")
        assert "быстрее" in PrintDirection.BIDIRECTIONAL.localized_name("ru")
        assert "точнее" in PrintDirection.UNIDIRECTIONAL.localized_name("ru")

    def test_from_string(self):
        """Тестирует поиск из строки."""
        assert PrintDirection.from_string("bidirectional") == PrintDirection.BIDIRECTIONAL
        assert PrintDirection.from_string("LTR") == PrintDirection.LEFT_TO_RIGHT
        assert PrintDirection.from_string("invalid") is None


# =============================================================================
# ТЕСТЫ ОБНОВЛЁННЫХ КЛАССОВ (ВЕРСИЯ 2.0)
# =============================================================================


class TestTextStyleV2:
    """Тестирует обновлённый класс TextStyle с новым методом."""

    def test_is_hardware_supported(self):
        """Тестирует определение аппаратной поддержки стилей."""
        # Аппаратно поддерживаемые стили
        assert TextStyle.BOLD.is_hardware_supported() is True
        assert TextStyle.ITALIC.is_hardware_supported() is True
        assert TextStyle.UNDERLINE.is_hardware_supported() is True
        assert TextStyle.DOUBLE_STRIKE.is_hardware_supported() is True
        assert TextStyle.SUPERSCRIPT.is_hardware_supported() is True
        assert TextStyle.SUBSCRIPT.is_hardware_supported() is True

        # Программно реализуемый стиль
        assert TextStyle.STRIKETHROUGH.is_hardware_supported() is False


# =============================================================================
# ТЕСТЫ НОВЫХ ФУНКЦИЙ ВАЛИДАЦИИ (ВЕРСИЯ 2.0)
# =============================================================================


class TestValidationFunctionsV2:
    """Тестирует новые функции валидации версии 2.0."""

    def test_validate_page_size_paper_type_valid(self):
        """Тестирует валидацию корректных комбинаций размер-тип."""
        # Тракторная подача + фальцованная бумага
        valid, error = validate_page_size_paper_type(
            PageSize.FANFOLD_8_5, PaperType.CONTINUOUS_TRACTOR
        )
        assert valid is True
        assert error is None

        # Листовая подача + стандартный размер
        valid, error = validate_page_size_paper_type(PageSize.LETTER, PaperType.SHEET_FEED)
        assert valid is True

    def test_validate_page_size_paper_type_invalid_tractor(self):
        """Тестирует отклонение несовместимого размера с тракторной подачей."""
        valid, error = validate_page_size_paper_type(
            PageSize.A4, PaperType.CONTINUOUS_TRACTOR  # Не совместим с тракторной подачей
        )
        assert valid is False
        assert "incompatible" in error.lower()

    def test_validate_page_size_paper_type_invalid_envelope(self):
        """Тестирует отклонение фальцованной бумаги с конвертами."""
        valid, error = validate_page_size_paper_type(PageSize.FANFOLD_8_5, PaperType.ENVELOPE)
        assert valid is False
        assert "incompatible" in error.lower()

    def test_validate_graphics_mode_resolution_valid(self):
        """Тестирует валидацию корректной ширины изображения."""
        # 800px @ 120 DPI = 6.67" < 8.0" max
        valid, error = validate_graphics_mode_resolution(GraphicsMode.DOUBLE_DENSITY, 800)
        assert valid is True
        assert error is None

    def test_validate_graphics_mode_resolution_invalid(self):
        """Тестирует отклонение слишком широкого изображения."""
        # 1000px @ 120 DPI = 8.33" > 8.0" max
        valid, error = validate_graphics_mode_resolution(GraphicsMode.DOUBLE_DENSITY, 1000)
        assert valid is False
        assert "exceeds maximum" in error

    def test_validate_graphics_mode_resolution_high_dpi(self):
        """Тестирует валидацию с высоким DPI."""
        # 360 DPI позволяет больше пикселей
        max_pixels_360dpi = int(8.0 * 360)  # 2880 пикселей

        valid, error = validate_graphics_mode_resolution(GraphicsMode.HEXADECIMAL, 2800)
        assert valid is True

        valid, error = validate_graphics_mode_resolution(
            GraphicsMode.HEXADECIMAL, 3000  # Превышает максимум
        )
        assert valid is False

    def test_validate_margin_values_valid_inches(self):
        """Тестирует валидацию корректных полей в дюймах."""
        valid, error = validate_margin_values(
            left=1.0,
            right=1.0,
            top=1.0,
            bottom=1.0,
            page_size=PageSize.LETTER,
            units=MarginUnits.INCHES,
        )
        assert valid is True
        assert error is None

    def test_validate_margin_values_invalid_sum(self):
        """Тестирует отклонение полей, превышающих размер страницы."""
        # Letter = 8.5" width, left+right = 5.0" + 5.0" > 8.5"
        valid, error = validate_margin_values(
            left=5.0,
            right=5.0,
            top=1.0,
            bottom=1.0,
            page_size=PageSize.LETTER,
            units=MarginUnits.INCHES,
        )
        assert valid is False
        assert "exceed" in error.lower()

    def test_validate_margin_values_negative(self):
        """Тестирует отклонение отрицательных полей."""
        valid, error = validate_margin_values(
            left=-1.0,
            right=1.0,
            top=1.0,
            bottom=1.0,
            page_size=PageSize.LETTER,
            units=MarginUnits.INCHES,
        )
        assert valid is False
        assert "negative" in error.lower()

    def test_validate_margin_values_too_small(self):
        """Тестирует отклонение слишком малых полей."""
        # MIN_MARGIN_INCHES = 0.25"
        valid, error = validate_margin_values(
            left=0.1,
            right=0.1,
            top=1.0,
            bottom=1.0,
            page_size=PageSize.LETTER,
            units=MarginUnits.INCHES,
        )
        assert valid is False
        assert "at least" in error.lower()

    def test_validate_margin_values_millimeters(self):
        """Тестирует валидацию полей в миллиметрах."""
        # 25.4mm = 1.0"
        valid, error = validate_margin_values(
            left=25.4,
            right=25.4,
            top=25.4,
            bottom=25.4,
            page_size=PageSize.LETTER,
            units=MarginUnits.MILLIMETERS,
        )
        assert valid is True

    def test_validate_margin_values_characters(self):
        """Тестирует валидацию полей в символах."""
        # 10 символов @ 10 CPI = 1.0"
        valid, error = validate_margin_values(
            left=10,
            right=10,
            top=6,
            bottom=6,
            page_size=PageSize.LETTER,
            units=MarginUnits.CHARACTERS,
        )
        assert valid is True

    def test_validate_margin_values_decipoints(self):
        """Тестирует валидацию полей в децепоинтах."""
        # 720 decipoints = 1.0"
        valid, error = validate_margin_values(
            left=720,
            right=720,
            top=720,
            bottom=720,
            page_size=PageSize.LETTER,
            units=MarginUnits.DECIPOINTS,
        )
        assert valid is True


# =============================================================================
# ТЕСТЫ НОВЫХ КОНСТАНТ (ВЕРСИЯ 2.0)
# =============================================================================


class TestConstantsV2:
    """Тестирует новые константы версии 2.0."""

    def test_new_max_constants(self):
        """Тестирует новые MAX/MIN константы."""
        assert MAX_PRINT_HEIGHT_INCHES == 22.0
        assert MIN_MARGIN_INCHES == 0.25

    def test_new_escp_bytes(self):
        """Тестирует новые байты ESC/P."""
        assert ESC_INIT == b"\x1b\x40"  # ESC @
        assert FF == b"\x0c"  # Form Feed
        assert CR == b"\x0d"  # Carriage Return
        assert LF == b"\x0a"  # Line Feed
        assert BEL == b"\x07"  # Bell

    def test_new_default_values(self):
        """Тестирует новые значения по умолчанию."""
        assert isinstance(DEFAULT_PAGE_SIZE, PageSize)
        assert DEFAULT_PAGE_SIZE == PageSize.LETTER

        assert isinstance(DEFAULT_PAPER_SOURCE, PaperSource)
        assert DEFAULT_PAPER_SOURCE == PaperSource.AUTO

        assert isinstance(DEFAULT_GRAPHICS_MODE, GraphicsMode)
        assert DEFAULT_GRAPHICS_MODE == GraphicsMode.DOUBLE_DENSITY

        assert isinstance(DEFAULT_MARGIN_UNITS, MarginUnits)
        assert DEFAULT_MARGIN_UNITS == MarginUnits.INCHES

        assert isinstance(DEFAULT_PRINT_DIRECTION, PrintDirection)
        assert DEFAULT_PRINT_DIRECTION == PrintDirection.BIDIRECTIONAL


# =============================================================================
# ИНТЕГРАЦИОННЫЕ ТЕСТЫ (ВЕРСИЯ 2.0)
# =============================================================================


class TestIntegrationV2:
    """Интеграционные тесты для новых функций версии 2.0."""

    def test_full_document_configuration_v2(self):
        """Тестирует создание полной конфигурации документа v2.0."""
        config = {
            "font": FontFamily.DRAFT,
            "cpi": CharactersPerInch.CPI_10,
            "quality": PrintQuality.DRAFT,
            "codepage": CodePage.PC866,
            "paper": PaperType.CONTINUOUS_TRACTOR,
            "orientation": Orientation.PORTRAIT,
            "alignment": Alignment.LEFT,
            # Новое в v2.0
            "page_size": PageSize.FANFOLD_8_5,
            "paper_source": PaperSource.TRACTOR,
            "graphics_mode": GraphicsMode.DOUBLE_DENSITY,
            "margin_units": MarginUnits.INCHES,
            "print_direction": PrintDirection.BIDIRECTIONAL,
        }

        # Валидируем все комбинации
        assert validate_cpi_font_combination(config["cpi"], config["font"])
        assert validate_quality_font_combination(config["quality"], config["font"])

        valid, error = validate_page_size_paper_type(config["page_size"], config["paper"])
        assert valid, f"Page size validation failed: {error}"

    def test_serialization_deserialization_v2(self):
        """Тестирует круговую JSON сериализацию с новыми классами."""
        import json

        data = {
            "page_size": PageSize.A4.value,
            "paper_source": PaperSource.TRACTOR.value,
            "graphics_mode": GraphicsMode.HEXADECIMAL.value,
            "margin_units": MarginUnits.MILLIMETERS.value,
            "print_direction": PrintDirection.UNIDIRECTIONAL.value,
        }

        json_str = json.dumps(data)
        loaded = json.loads(json_str)

        page_size = PageSize(loaded["page_size"])
        paper_source = PaperSource(loaded["paper_source"])
        graphics_mode = GraphicsMode(loaded["graphics_mode"])
        margin_units = MarginUnits(loaded["margin_units"])
        print_direction = PrintDirection(loaded["print_direction"])

        assert page_size == PageSize.A4
        assert paper_source == PaperSource.TRACTOR
        assert graphics_mode == GraphicsMode.HEXADECIMAL
        assert margin_units == MarginUnits.MILLIMETERS
        assert print_direction == PrintDirection.UNIDIRECTIONAL

    def test_escp_command_generation_sequence_v2(self):
        """Тестирует генерацию последовательности команд ESC/P v2.0."""
        commands = []

        # Инициализация принтера (новое в v2.0)
        commands.append(ESC_INIT)

        # Базовые настройки
        commands.append(FontFamily.DRAFT.to_escp())
        commands.append(CharactersPerInch.CPI_10.to_escp())
        commands.append(LineSpacing.ONE_SIXTH_INCH.to_escp())

        # Новые команды v2.0
        commands.append(PaperSource.TRACTOR.to_escp())
        commands.append(PrintDirection.BIDIRECTIONAL.to_escp())
        commands.append(GraphicsMode.DOUBLE_DENSITY.to_escp(100))

        # Проверяем, что все команды — это байты
        for cmd in commands:
            assert isinstance(cmd, bytes)
            assert len(cmd) > 0

    def test_complete_page_setup(self):
        """Тестирует полную настройку страницы."""
        page_size = PageSize.LETTER
        paper_source = PaperSource.TRACTOR
        margins = {
            "left": 1.0,
            "right": 1.0,
            "top": 1.0,
            "bottom": 1.0,
            "units": MarginUnits.INCHES,
        }

        # Проверка размеров
        width, height = page_size.dimensions_inches
        assert width == 8.5
        assert height == 11.0

        # Проверка полей
        valid, error = validate_margin_values(
            margins["left"],
            margins["right"],
            margins["top"],
            margins["bottom"],
            page_size,
            margins["units"],
        )
        assert valid, f"Margin validation failed: {error}"

        # Вычисление области печати
        print_width = width - margins["left"] - margins["right"]
        print_height = height - margins["top"] - margins["bottom"]

        assert print_width == 6.5
        assert print_height == 9.0


# =============================================================================
# ТЕСТЫ ВАЛИДАЦИИ КОНСТАНТ МОДУЛЯ
# =============================================================================


class TestModuleConstantsValidation:
    """Тестирует валидацию констант модуля."""

    def test_module_imports_without_errors(self):
        """Тестирует, что модуль импортируется без ошибок валидации."""
        # Если мы дошли до этого теста, значит импорт прошёл успешно
        # и _validate_module_constants() не выбросила AssertionError
        assert True

    def test_default_values_are_valid_enums(self):
        """Тестирует, что все DEFAULT значения — валидные члены перечислений."""
        assert isinstance(DEFAULT_FONT_FAMILY, FontFamily)
        assert isinstance(DEFAULT_CPI, CharactersPerInch)
        assert isinstance(DEFAULT_CODEPAGE, CodePage)
        assert isinstance(DEFAULT_PAGE_SIZE, PageSize)
        assert isinstance(DEFAULT_PAPER_SOURCE, PaperSource)
        assert isinstance(DEFAULT_GRAPHICS_MODE, GraphicsMode)
        assert isinstance(DEFAULT_MARGIN_UNITS, MarginUnits)
        assert isinstance(DEFAULT_PRINT_DIRECTION, PrintDirection)

    def test_default_combinations_are_compatible(self):
        """Тестирует, что DEFAULT значения совместимы друг с другом."""
        # CPI + Font
        assert validate_cpi_font_combination(DEFAULT_CPI, DEFAULT_FONT_FAMILY)

        # Quality + Font
        from src.model.enums import DEFAULT_PRINT_QUALITY

        assert validate_quality_font_combination(DEFAULT_PRINT_QUALITY, DEFAULT_FONT_FAMILY)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
