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
    validate_fx890_compatibility,
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

    def test_all_members_exist(self) -> None:
        """Проверяет, что все ожидаемые размеры страниц существуют."""
        assert PageSize.A4
        assert PageSize.A5
        assert PageSize.LETTER
        assert PageSize.LEGAL
        assert PageSize.EXECUTIVE
        assert PageSize.FANFOLD_8_5
        assert PageSize.FANFOLD_11
        assert PageSize.CUSTOM

    def test_values_serializable(self) -> None:
        """Проверяет, что значения перечисления — это сериализуемые строки."""
        assert PageSize.A4.value == "a4"
        assert PageSize.LETTER.value == "letter"
        assert PageSize.CUSTOM.value == "custom"

    def test_dimensions_inches(self) -> None:
        """Тестирует размеры страниц в дюймах."""
        assert PageSize.A4.dimensions_inches == (8.27, 11.69)
        assert PageSize.LETTER.dimensions_inches == (8.5, 11.0)
        assert PageSize.LEGAL.dimensions_inches == (8.5, 14.0)
        assert PageSize.FANFOLD_11.dimensions_inches == (11.0, 8.5)

    def test_is_standard(self) -> None:
        """Тестирует определение стандартного размера."""
        assert PageSize.A4.is_standard is True
        assert PageSize.LETTER.is_standard is True
        assert PageSize.CUSTOM.is_standard is False

    def test_max_characters_10cpi(self) -> None:
        """Тестирует вычисление максимального количества символов."""
        # Letter: 8.5" * 10 - 2 = 83
        assert PageSize.LETTER.max_characters_10cpi == 83
        # A4: 8.27" * 10 - 2 = 80
        assert PageSize.A4.max_characters_10cpi == 80

    def test_is_compatible_with_tractor(self) -> None:
        """Тестирует совместимость с тракторной подачей."""
        assert PageSize.FANFOLD_8_5.is_compatible_with_tractor() is True
        assert PageSize.FANFOLD_11.is_compatible_with_tractor() is True
        assert PageSize.CUSTOM.is_compatible_with_tractor() is True
        assert PageSize.A4.is_compatible_with_tractor() is False
        assert PageSize.LETTER.is_compatible_with_tractor() is False

    def test_localized_names(self) -> None:
        """Тестирует получение локализованных названий."""
        assert "210 × 297" in PageSize.A4.localized_name("en")
        assert "210 × 297" in PageSize.A4.localized_name("ru")
        assert "Letter" in PageSize.LETTER.localized_name("en")

    def test_from_string(self) -> None:
        """Тестирует поиск из строки."""
        assert PageSize.from_string("a4") == PageSize.A4
        assert PageSize.from_string("LETTER") == PageSize.LETTER
        assert PageSize.from_string("invalid") is None

    def test_str_representation(self) -> None:
        """Тестирует строковое представление."""
        assert "A4" in str(PageSize.A4)
        assert "Letter" in str(PageSize.LETTER)


class TestPaperSource:
    """Тестирует перечисление PaperSource."""

    def test_all_members_exist(self) -> None:
        """Проверяет, что все ожидаемые источники бумаги существуют."""
        assert PaperSource.AUTO
        assert PaperSource.TRACTOR
        assert PaperSource.MANUAL_FRONT
        assert PaperSource.MANUAL_REAR
        assert PaperSource.SHEET_FEEDER_BIN1
        assert PaperSource.SHEET_FEEDER_BIN2

    def test_escp_codes(self) -> None:
        """Тестирует коды ESC/P для источников бумаги."""
        assert PaperSource.AUTO.escp_code == 0
        assert PaperSource.TRACTOR.escp_code == 1
        assert PaperSource.MANUAL_FRONT.escp_code == 2
        assert PaperSource.SHEET_FEEDER_BIN1.escp_code == 4

    def test_is_continuous(self) -> None:
        """Тестирует определение непрерывного источника."""
        assert PaperSource.TRACTOR.is_continuous is True
        assert PaperSource.AUTO.is_continuous is False
        assert PaperSource.MANUAL_FRONT.is_continuous is False

    def test_requires_operator_intervention(self) -> None:
        """Тестирует определение требования вмешательства оператора."""
        assert PaperSource.MANUAL_FRONT.requires_operator_intervention is True
        assert PaperSource.MANUAL_REAR.requires_operator_intervention is True
        assert PaperSource.TRACTOR.requires_operator_intervention is False
        assert PaperSource.AUTO.requires_operator_intervention is False

    def test_to_escp(self) -> None:
        """Тестирует генерацию команды ESC/P."""
        # ESC EM 0
        assert PaperSource.AUTO.to_escp() == b"\x1b\x19\x00"
        # ESC EM 1
        assert PaperSource.TRACTOR.to_escp() == b"\x1b\x19\x01"
        # ESC EM 2
        assert PaperSource.MANUAL_FRONT.to_escp() == b"\x1b\x19\x02"

    def test_localized_names(self) -> None:
        """Тестирует локализованные названия."""
        assert "Automatic" in PaperSource.AUTO.localized_name("en")
        assert "Автоматический" in PaperSource.AUTO.localized_name("ru")
        assert "Тракторная" in PaperSource.TRACTOR.localized_name("ru")

    def test_from_string(self) -> None:
        """Тестирует поиск из строки."""
        assert PaperSource.from_string("tractor") == PaperSource.TRACTOR
        assert PaperSource.from_string("MANUAL_FRONT") == PaperSource.MANUAL_FRONT
        assert PaperSource.from_string("invalid") is None


class TestGraphicsMode:
    """Тестирует перечисление GraphicsMode."""

    def test_all_members_exist(self) -> None:
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

    def test_resolution_dpi(self) -> None:
        """Тестирует разрешения режимов графики."""
        assert GraphicsMode.SINGLE_DENSITY.resolution_dpi == (60, 60)
        assert GraphicsMode.DOUBLE_DENSITY.resolution_dpi == (120, 60)
        assert GraphicsMode.HEXADECIMAL.resolution_dpi == (360, 180)
        assert GraphicsMode.TRIPLE_DENSITY.resolution_dpi == (180, 180)

    def test_pins(self) -> None:
        """Тестирует количество иголок."""
        # 8-pin режимы
        assert GraphicsMode.SINGLE_DENSITY.pins == 8
        assert GraphicsMode.DOUBLE_DENSITY.pins == 8
        assert GraphicsMode.CRT_I.pins == 8

        # 24-pin режимы
        assert GraphicsMode.HEXADECIMAL.pins == 24
        assert GraphicsMode.CRT_III_24PIN.pins == 24

    def test_escp_command_prefix(self) -> None:
        """Тестирует префиксы команд ESC/P."""
        # ESC K
        assert GraphicsMode.SINGLE_DENSITY.escp_command_prefix == b"\x1b\x4b"
        # ESC L
        assert GraphicsMode.DOUBLE_DENSITY.escp_command_prefix == b"\x1b\x4c"
        # ESC * 4
        assert GraphicsMode.HEXADECIMAL.escp_command_prefix == b"\x1b\x2a\x04"

    def test_to_escp_valid_columns(self) -> None:
        """Тестирует генерацию команды с валидными столбцами."""
        cmd = GraphicsMode.DOUBLE_DENSITY.to_escp(100)
        assert isinstance(cmd, bytes)
        # ESC L + low byte (100) + high byte (0)
        assert cmd == b"\x1b\x4c\x64\x00"

        # Тест с большим числом столбцов
        cmd = GraphicsMode.HEXADECIMAL.to_escp(1000)
        assert len(cmd) == 5  # prefix (3) + low + high

    def test_to_escp_invalid_columns(self) -> None:
        """Тестирует валидацию диапазона столбцов."""
        with pytest.raises(ValueError, match="must be 0-65535"):
            GraphicsMode.DOUBLE_DENSITY.to_escp(-1)

        with pytest.raises(ValueError, match="must be 0-65535"):
            GraphicsMode.DOUBLE_DENSITY.to_escp(65536)

    def test_localized_names(self) -> None:
        """Тестирует локализованные названия."""
        assert "60 DPI" in GraphicsMode.SINGLE_DENSITY.localized_name("en")
        assert "Одинарная плотность" in GraphicsMode.SINGLE_DENSITY.localized_name("ru")
        assert "360 DPI" in GraphicsMode.HEXADECIMAL.localized_name("en")

    def test_from_string(self) -> None:
        """Тестирует поиск из строки."""
        assert GraphicsMode.from_string("double_density") == GraphicsMode.DOUBLE_DENSITY
        assert GraphicsMode.from_string("HEXADECIMAL") == GraphicsMode.HEXADECIMAL
        assert GraphicsMode.from_string("invalid") is None


class TestMarginUnits:
    """Тестирует перечисление MarginUnits."""

    def test_all_members_exist(self) -> None:
        """Проверяет, что все ожидаемые единицы измерения существуют."""
        assert MarginUnits.INCHES
        assert MarginUnits.MILLIMETERS
        assert MarginUnits.CHARACTERS
        assert MarginUnits.DECIPOINTS

    def test_localized_names(self) -> None:
        """Тестирует локализованные названия."""
        assert MarginUnits.INCHES.localized_name("en") == "Inches"
        assert MarginUnits.INCHES.localized_name("ru") == "Дюймы"
        assert "Миллиметры" in MarginUnits.MILLIMETERS.localized_name("ru")

    def test_from_string(self) -> None:
        """Тестирует поиск из строки."""
        assert MarginUnits.from_string("inches") == MarginUnits.INCHES
        assert MarginUnits.from_string("MILLIMETERS") == MarginUnits.MILLIMETERS
        assert MarginUnits.from_string("invalid") is None


class TestPrintDirection:
    """Тестирует перечисление PrintDirection."""

    def test_all_members_exist(self) -> None:
        """Проверяет, что все ожидаемые направления печати существуют."""
        assert PrintDirection.BIDIRECTIONAL
        assert PrintDirection.UNIDIRECTIONAL
        assert PrintDirection.LEFT_TO_RIGHT
        assert PrintDirection.RIGHT_TO_LEFT

    def test_escp_codes(self) -> None:
        """Тестирует коды ESC/P."""
        assert PrintDirection.BIDIRECTIONAL.escp_code == 0
        assert PrintDirection.UNIDIRECTIONAL.escp_code == 1

    def test_to_escp(self) -> None:
        """Тестирует генерацию команды ESC/P."""
        # ESC U 0
        assert PrintDirection.BIDIRECTIONAL.to_escp() == b"\x1b\x55\x00"
        # ESC U 1
        assert PrintDirection.UNIDIRECTIONAL.to_escp() == b"\x1b\x55\x01"

    def test_localized_names(self) -> None:
        """Тестирует локализованные названия."""
        assert "Faster" in PrintDirection.BIDIRECTIONAL.localized_name("en")
        assert "быстрее" in PrintDirection.BIDIRECTIONAL.localized_name("ru")
        assert "точнее" in PrintDirection.UNIDIRECTIONAL.localized_name("ru")

    def test_from_string(self) -> None:
        """Тестирует поиск из строки."""
        assert PrintDirection.from_string("bidirectional") == PrintDirection.BIDIRECTIONAL
        assert PrintDirection.from_string("LTR") == PrintDirection.LEFT_TO_RIGHT
        assert PrintDirection.from_string("invalid") is None


# =============================================================================
# ТЕСТЫ ОБНОВЛЁННЫХ КЛАССОВ (ВЕРСИЯ 2.0)
# =============================================================================


class TestTextStyleV2:
    """Тестирует обновлённый класс TextStyle с новым методом."""

    def test_is_hardware_supported(self) -> None:
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

    def test_validate_page_size_paper_type_valid(self) -> None:
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

    def test_validate_page_size_paper_type_invalid_tractor(self) -> None:
        """Тестирует отклонение несовместимого размера с тракторной подачей."""
        valid, error = validate_page_size_paper_type(
            PageSize.A4, PaperType.CONTINUOUS_TRACTOR  # Не совместим с тракторной подачей
        )
        assert valid is False
        assert error is not None and "incompatible" in error.lower()

    def test_validate_page_size_paper_type_invalid_envelope(self) -> None:
        """Тестирует отклонение фальцованной бумаги с конвертами."""
        valid, error = validate_page_size_paper_type(PageSize.FANFOLD_8_5, PaperType.ENVELOPE)
        assert valid is False
        assert error is not None and "incompatible" in error.lower()

    def test_validate_graphics_mode_resolution_valid(self) -> None:
        """Тестирует валидацию корректной ширины изображения."""
        # 800px @ 120 DPI = 6.67" < 8.0" max
        valid, error = validate_graphics_mode_resolution(GraphicsMode.DOUBLE_DENSITY, 800)
        assert valid is True
        assert error is None

    def test_validate_graphics_mode_resolution_invalid(self) -> None:
        """Проверяет validate_graphics_mode_resolution с превышением ширины."""
        valid, error = validate_graphics_mode_resolution(GraphicsMode.DOUBLE_DENSITY, 2000)
        assert not valid
        assert error is not None and "exceeds maximum" in error.lower()

    def test_validate_graphics_mode_resolution_high_dpi(self) -> None:
        """Тестирует валидацию с высоким DPI."""
        # 360 DPI позволяет больше пикселей
        max_pixels_360dpi = int(8.0 * 360)  # 2880 пикселей

        valid, error = validate_graphics_mode_resolution(GraphicsMode.HEXADECIMAL, 2800)
        assert valid is True

        valid, error = validate_graphics_mode_resolution(
            GraphicsMode.HEXADECIMAL, 3000  # Превышает максимум
        )
        assert valid is False

    def test_validate_margin_values_valid_inches(self) -> None:
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

    def test_validate_margin_values_invalid_sum(self) -> None:
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
        assert error is not None and "exceed" in error.lower()

    def test_validate_margin_values_negative(self) -> None:
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
        assert error is not None and "negative" in error.lower()

    def test_validate_margin_values_exceeds_page_height(self) -> None:
        """Проверяет validate_margin_values с перекрывающимися полями по высоте."""
        valid, error = validate_margin_values(
            0.5, 0.5, 6.0, 6.0, PageSize.LETTER, MarginUnits.INCHES
        )
        assert not valid
        assert error is not None and "exceed page height" in error.lower()

    def test_validate_margin_values_millimeters(self) -> None:
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

    def test_validate_margin_values_characters(self) -> None:
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

    def test_validate_margin_values_decipoints(self) -> None:
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

    def test_new_max_constants(self) -> None:
        """Тестирует новые MAX/MIN константы."""
        assert MAX_PRINT_HEIGHT_INCHES == 22.0
        assert MIN_MARGIN_INCHES == 0.25

    def test_new_escp_bytes(self) -> None:
        """Тестирует новые байты ESC/P."""
        assert ESC_INIT == b"\x1b\x40"  # ESC @
        assert FF == b"\x0c"  # Form Feed
        assert CR == b"\x0d"  # Carriage Return
        assert LF == b"\x0a"  # Line Feed
        assert BEL == b"\x07"  # Bell

    def test_new_default_values(self) -> None:
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

    def test_full_document_configuration_v2(self) -> None:
        """Тестирует создание полной конфигурации документа v2.0."""
        # Типизированные переменные вместо словаря
        font = FontFamily.DRAFT
        cpi = CharactersPerInch.CPI_10
        quality = PrintQuality.DRAFT
        codepage = CodePage.PC866
        paper = PaperType.CONTINUOUS_TRACTOR
        orientation = Orientation.PORTRAIT
        alignment = Alignment.LEFT
        # Новое в v2.0
        page_size = PageSize.FANFOLD_8_5
        paper_source = PaperSource.TRACTOR
        graphics_mode = GraphicsMode.DOUBLE_DENSITY
        margin_units = MarginUnits.INCHES
        print_direction = PrintDirection.BIDIRECTIONAL

        # Валидируем все комбинации
        assert validate_cpi_font_combination(cpi, font)
        assert validate_quality_font_combination(quality, font)

        valid, error = validate_page_size_paper_type(page_size, paper)
        assert valid, f"Page size validation failed: {error}"

    def test_serialization_deserialization_v2(self) -> None:
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

    def test_escp_command_generation_sequence_v2(self) -> None:
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

    def test_complete_page_setup(self) -> None:
        """Тестирует полную настройку страницы."""
        page_size = PageSize.LETTER
        paper_source = PaperSource.TRACTOR

        # Типизированные переменные вместо словаря
        margin_left = 1.0
        margin_right = 1.0
        margin_top = 1.0
        margin_bottom = 1.0
        margin_units = MarginUnits.INCHES

        # Проверка размеров
        width, height = page_size.dimensions_inches
        assert width == 8.5
        assert height == 11.0

        # Проверка полей
        valid, error = validate_margin_values(
            margin_left,
            margin_right,
            margin_top,
            margin_bottom,
            page_size,
            margin_units,
        )
        assert valid, f"Margin validation failed: {error}"

        # Вычисление области печати
        print_width = width - margin_left - margin_right
        print_height = height - margin_top - margin_bottom

        assert print_width == 6.5
        assert print_height == 9.0


# =============================================================================
# ТЕСТЫ ВАЛИДАЦИИ КОНСТАНТ МОДУЛЯ
# =============================================================================


class TestModuleConstantsValidation:
    """Тестирует валидацию констант модуля."""

    def test_module_imports_without_errors(self) -> None:
        """Тестирует, что модуль импортируется без ошибок валидации."""
        # Если мы дошли до этого теста, значит импорт прошёл успешно
        # и _validate_module_constants() не выбросила AssertionError
        assert True

    def test_default_values_are_valid_enums(self) -> None:
        """Тестирует, что все DEFAULT значения — валидные члены перечислений."""
        assert isinstance(DEFAULT_FONT_FAMILY, FontFamily)
        assert isinstance(DEFAULT_CPI, CharactersPerInch)
        assert isinstance(DEFAULT_CODEPAGE, CodePage)
        assert isinstance(DEFAULT_PAGE_SIZE, PageSize)
        assert isinstance(DEFAULT_PAPER_SOURCE, PaperSource)
        assert isinstance(DEFAULT_GRAPHICS_MODE, GraphicsMode)
        assert isinstance(DEFAULT_MARGIN_UNITS, MarginUnits)
        assert isinstance(DEFAULT_PRINT_DIRECTION, PrintDirection)

    def test_default_combinations_are_compatible(self) -> None:
        """Тестирует, что DEFAULT значения совместимы друг с другом."""
        # CPI + Font
        assert validate_cpi_font_combination(DEFAULT_CPI, DEFAULT_FONT_FAMILY)

        # Quality + Font
        from src.model.enums import DEFAULT_PRINT_QUALITY

        assert validate_quality_font_combination(DEFAULT_PRINT_QUALITY, DEFAULT_FONT_FAMILY)


# =============================================================================
# ДОПОЛНИТЕЛЬНЫЕ ТЕСТЫ ДЛЯ ПОВЫШЕНИЯ ПОКРЫТИЯ (68% → 90%+)
# =============================================================================


class TestOrientationComplete:
    """Полное покрытие Orientation."""

    def test_all_members_description_en(self) -> None:
        """Тестирует description_en для всех членов."""
        assert Orientation.PORTRAIT.description_en == "Portrait"
        assert Orientation.LANDSCAPE.description_en == "Landscape"

    def test_all_members_description_ru(self) -> None:
        """Тестирует description_ru для всех членов."""
        assert Orientation.PORTRAIT.description_ru == "Книжная"
        assert Orientation.LANDSCAPE.description_ru == "Альбомная"

    def test_invalid_language_fallback(self) -> None:
        """Тестирует fallback на английский для неподдерживаемого языка."""
        result = Orientation.PORTRAIT.localized_name("fr")
        assert result == Orientation.PORTRAIT.description_en


class TestAlignmentComplete:
    """Полное покрытие Alignment."""

    def test_all_members_description(self) -> None:
        """Тестирует описания всех членов Alignment."""
        assert Alignment.LEFT.description_en == "Left"
        assert Alignment.CENTER.description_en == "Center"
        assert Alignment.RIGHT.description_en == "Right"
        assert Alignment.JUSTIFY.description_en == "Justify"

        assert Alignment.LEFT.description_ru == "По левому краю"
        assert Alignment.CENTER.description_ru == "По центру"


class TestPaperTypeComplete:
    """Полное покрытие PaperType."""

    def test_all_members_descriptions(self) -> None:
        """Тестирует описания всех типов бумаги."""
        assert "Continuous" in PaperType.CONTINUOUS_TRACTOR.description_en
        assert "Sheet" in PaperType.SHEET_FEED.description_en
        assert "Envelope" in PaperType.ENVELOPE.description_en
        assert "Card" in PaperType.CARD.description_en
        assert "Multipart" in PaperType.MULTIPART_FORM.description_en

    def test_from_string_all_members(self) -> None:
        """Тестирует from_string для всех членов PaperType."""
        assert PaperType.from_string("continuous_tractor") == PaperType.CONTINUOUS_TRACTOR
        assert PaperType.from_string("SHEET_FEED") == PaperType.SHEET_FEED
        assert PaperType.from_string("envelope") == PaperType.ENVELOPE
        assert PaperType.from_string("card") == PaperType.CARD
        assert PaperType.from_string("multipart_form") == PaperType.MULTIPART_FORM


class TestFontFamilyComplete:
    """Полное покрытие FontFamily."""

    def test_all_members_descriptions(self) -> None:
        """Тестирует описания всех шрифтов."""
        assert "Ultra Speed" in FontFamily.USD.description_en
        assert (
            "High Speed" in FontFamily.HSD.description_en or "HSD" in FontFamily.HSD.description_en
        )
        assert "Draft" in FontFamily.DRAFT.description_en
        assert "Roman" in FontFamily.ROMAN.description_en
        assert "Sans" in FontFamily.SANS_SERIF.description_en

    def test_from_string_all_members(self) -> None:
        """Тестирует from_string для всех шрифтов."""
        assert FontFamily.from_string("usd") == FontFamily.USD
        assert FontFamily.from_string("HSD") == FontFamily.HSD
        assert FontFamily.from_string("draft") == FontFamily.DRAFT
        assert FontFamily.from_string("ROMAN") == FontFamily.ROMAN
        assert FontFamily.from_string("sans") == FontFamily.SANS_SERIF


class TestPrintQualityComplete:
    """Полное покрытие PrintQuality."""

    def test_all_members_descriptions(self) -> None:
        """Тестирует описания всех режимов качества."""
        assert "Ultra Speed" in PrintQuality.USD.description_en
        assert (
            "High Speed" in PrintQuality.HSD.description_en
            or "HSD" in PrintQuality.HSD.description_en
        )
        assert "Draft" in PrintQuality.DRAFT.description_en
        assert "Near Letter Quality" in PrintQuality.NLQ.description_en

    def test_all_members_recommended_use(self) -> None:
        """Тестирует recommended_use для всех режимов."""
        assert "internal" in PrintQuality.USD.recommended_use.lower()
        assert "draft" in PrintQuality.DRAFT.recommended_use.lower()
        assert "final" in PrintQuality.NLQ.recommended_use.lower()

    def test_from_string_all_members(self) -> None:
        """Тестирует from_string для всех режимов качества."""
        assert PrintQuality.from_string("usd") == PrintQuality.USD
        assert PrintQuality.from_string("HSD") == PrintQuality.HSD
        assert PrintQuality.from_string("draft") == PrintQuality.DRAFT
        assert PrintQuality.from_string("NLQ") == PrintQuality.NLQ


class TestCharactersPerInchComplete:
    """Полное покрытие CharactersPerInch."""

    def test_all_members_descriptions(self) -> None:
        """Тестирует описания всех CPI."""
        assert "10 CPI" in CharactersPerInch.CPI_10.description_en
        assert "12 CPI" in CharactersPerInch.CPI_12.description_en
        assert "15 CPI" in CharactersPerInch.CPI_15.description_en
        assert "17.1 CPI" in CharactersPerInch.CPI_17.description_en
        assert "20 CPI" in CharactersPerInch.CPI_20.description_en
        assert "Proportional" in CharactersPerInch.PROPORTIONAL.description_en

    def test_from_string_all_members(self) -> None:
        """Тестирует from_string для всех CPI."""
        assert CharactersPerInch.from_string("10cpi") == CharactersPerInch.CPI_10
        assert CharactersPerInch.from_string("12CPI") == CharactersPerInch.CPI_12
        assert CharactersPerInch.from_string("proportional") == CharactersPerInch.PROPORTIONAL


class TestLineSpacingComplete:
    """Полное покрытие LineSpacing."""

    def test_all_members_descriptions(self) -> None:
        """Тестирует описания всех интервалов."""
        assert "6 LPI" in LineSpacing.ONE_SIXTH_INCH.description_en
        assert "8 LPI" in LineSpacing.ONE_EIGHTH_INCH.description_en
        assert "7/72" in LineSpacing.SEVEN_SEVENTYTWOTH_INCH.description_en
        assert "Custom" in LineSpacing.CUSTOM.description_en

    def test_from_string_all_members(self) -> None:
        """Тестирует from_string для всех интервалов."""
        assert LineSpacing.from_string("1/6") == LineSpacing.ONE_SIXTH_INCH
        assert LineSpacing.from_string("1/8") == LineSpacing.ONE_EIGHTH_INCH
        assert LineSpacing.from_string("7/72") == LineSpacing.SEVEN_SEVENTYTWOTH_INCH
        assert LineSpacing.from_string("custom") == LineSpacing.CUSTOM

    def test_custom_to_escp_boundary_zero(self) -> None:
        """Тестирует CUSTOM с граничным значением 0."""
        result = LineSpacing.CUSTOM.to_escp(custom_value=0)
        assert result == b"\x1b\x33\x00"

    def test_custom_to_escp_boundary_max(self) -> None:
        """Тестирует CUSTOM с граничным значением 255."""
        result = LineSpacing.CUSTOM.to_escp(custom_value=255)
        assert result == b"\x1b\x33\xff"


class TestTextStyleComplete:
    """Полное покрытие TextStyle."""

    def test_all_members_descriptions(self) -> None:
        """Тестирует описания всех стилей."""
        assert "Bold" in TextStyle.BOLD.description_en
        assert "Italic" in TextStyle.ITALIC.description_en
        assert "Underline" in TextStyle.UNDERLINE.description_en
        assert "Double Strike" in TextStyle.DOUBLE_STRIKE.description_en
        assert "Strikethrough" in TextStyle.STRIKETHROUGH.description_en

    def test_from_string_all_members(self) -> None:
        """Тестирует from_string для всех стилей."""
        assert TextStyle.from_string("BOLD") == TextStyle.BOLD
        assert TextStyle.from_string("italic") == TextStyle.ITALIC
        assert TextStyle.from_string("underline") == TextStyle.UNDERLINE
        assert TextStyle.from_string("double_strike") == TextStyle.DOUBLE_STRIKE

    def test_bitwise_combination_three_styles(self) -> None:
        """Тестирует комбинирование трёх стилей."""
        style = TextStyle.BOLD | TextStyle.ITALIC | TextStyle.UNDERLINE
        assert TextStyle.BOLD in style
        assert TextStyle.ITALIC in style
        assert TextStyle.UNDERLINE in style
        assert TextStyle.DOUBLE_STRIKE not in style


class TestCodePageComplete:
    """Полное покрытие CodePage."""

    def test_all_members_to_escp(self) -> None:
        """Тестирует to_escp для всех кодировок."""
        assert CodePage.PC866.to_escp() == b"\x1b\x28\x74\x00\x03\x00\x11\x00"
        assert CodePage.PC437.to_escp() == b"\x1b\x28\x74\x00\x03\x00\x00\x00"
        assert CodePage.PC850.to_escp() == b"\x1b\x28\x74\x00\x03\x00\x02\x00"
        assert CodePage.PC852.to_escp() == b"\x1b\x28\x74\x00\x03\x00\x03\x00"
        assert CodePage.PC858.to_escp() == b"\x1b\x28\x74\x00\x03\x00\x0d\x00"

    def test_all_members_descriptions(self) -> None:
        """Тестирует описания всех кодировок."""
        assert "Cyrillic" in CodePage.PC866.description_en
        assert "US English" in CodePage.PC437.description_en
        assert "Western Europe" in CodePage.PC850.description_en

    def test_from_string_all_members(self) -> None:
        """Тестирует from_string для всех кодировок."""
        assert CodePage.from_string("pc866") == CodePage.PC866
        assert CodePage.from_string("PC437") == CodePage.PC437
        assert CodePage.from_string("custom") == CodePage.CUSTOM


class TestColorComplete:
    """Полное покрытие Color."""

    def test_all_members_to_escp(self) -> None:
        """Тестирует to_escp для всех цветов."""
        assert Color.BLACK.to_escp() == b"\x1b\x72\x00"
        assert Color.RED.to_escp() == b"\x1b\x72\x01"
        assert Color.YELLOW.to_escp() == b"\x1b\x72\x04"
        assert Color.BLUE.to_escp() == b"\x1b\x72\x02"
        assert Color.MAGENTA.to_escp() == b"\x1b\x72\x01"
        assert Color.CYAN.to_escp() == b"\x1b\x72\x02"

    def test_all_members_rgb_preview(self) -> None:
        """Тестирует rgb_preview для всех цветов."""
        assert Color.BLACK.rgb_preview == (0, 0, 0)
        assert Color.RED.rgb_preview == (255, 0, 0)
        assert Color.YELLOW.rgb_preview == (255, 255, 0)
        assert Color.BLUE.rgb_preview == (0, 0, 255)
        assert Color.MAGENTA.rgb_preview == (255, 0, 255)
        assert Color.CYAN.rgb_preview == (0, 255, 255)

    def test_from_string_all_members(self) -> None:
        """Тестирует from_string для всех цветов."""
        assert Color.from_string("black") == Color.BLACK
        assert Color.from_string("RED") == Color.RED
        assert Color.from_string("yellow") == Color.YELLOW


class TestDitheringAlgorithmComplete:
    """Полное покрытие DitheringAlgorithm."""

    def test_all_members_descriptions(self) -> None:
        """Тестирует описания всех алгоритмов."""
        assert "Floyd-Steinberg" in DitheringAlgorithm.FLOYD_STEINBERG.description_en
        assert "Atkinson" in DitheringAlgorithm.ATKINSON.description_en
        assert "Ordered" in DitheringAlgorithm.ORDERED_BAYER.description_en
        assert "Threshold" in DitheringAlgorithm.THRESHOLD.description_en

    def test_from_string_all_members(self) -> None:
        """Тестирует from_string для всех алгоритмов."""
        assert (
            DitheringAlgorithm.from_string("floyd_steinberg") == DitheringAlgorithm.FLOYD_STEINBERG
        )
        assert DitheringAlgorithm.from_string("ATKINSON") == DitheringAlgorithm.ATKINSON
        assert DitheringAlgorithm.from_string("threshold") == DitheringAlgorithm.THRESHOLD


class TestBarcodeTypeComplete:
    """Полное покрытие BarcodeType."""

    def test_all_members_descriptions(self) -> None:
        """Тестирует описания всех типов штрихкодов."""
        assert "Code 39" in BarcodeType.CODE39.description_en
        assert "Code 128" in BarcodeType.CODE128.description_en
        assert "EAN-8" in BarcodeType.EAN8.description_en
        assert "EAN-13" in BarcodeType.EAN13.description_en
        assert "QR" in BarcodeType.QR.description_en

    def test_from_string_all_members(self) -> None:
        """Тестирует from_string для всех типов штрихкодов."""
        assert BarcodeType.from_string("code39") == BarcodeType.CODE39
        assert BarcodeType.from_string("CODE128") == BarcodeType.CODE128
        assert BarcodeType.from_string("qr") == BarcodeType.QR

    def test_all_members_native_support(self) -> None:
        """Тестирует native_escp_support для всех типов."""
        assert BarcodeType.CODE39.native_escp_support is True
        assert BarcodeType.EAN13.native_escp_support is True
        assert BarcodeType.CODE128.native_escp_support is False
        assert BarcodeType.QR.native_escp_support is False


class TestTableStyleComplete:
    """Полное покрытие TableStyle."""

    def test_all_members_border_chars(self) -> None:
        """Тестирует border_chars для всех стилей таблиц."""
        # SIMPLE
        simple = TableStyle.SIMPLE.border_chars
        assert simple["tl"] == "+"
        assert simple["h"] == "-"
        assert simple["v"] == "|"

        # DOUBLE
        double = TableStyle.DOUBLE.border_chars
        assert double["tl"] == "╔"
        assert double["h"] == "═"

        # GRID
        grid = TableStyle.GRID.border_chars
        assert grid["tl"] == "┌"

        # MINIMAL
        minimal = TableStyle.MINIMAL.border_chars
        assert minimal["v"] == " "

    def test_from_string_all_members(self) -> None:
        """Тестирует from_string для всех стилей таблиц."""
        assert TableStyle.from_string("simple") == TableStyle.SIMPLE
        assert TableStyle.from_string("DOUBLE") == TableStyle.DOUBLE
        assert TableStyle.from_string("minimal") == TableStyle.MINIMAL


class TestListTypeComplete:
    """Полное покрытие ListType."""

    def test_all_members_descriptions(self) -> None:
        """Тестирует описания всех типов списков."""
        assert "Dash" in ListType.UNORDERED_DASH.description_en
        assert "Bullet" in ListType.UNORDERED_BULLET.description_en
        assert "Numeric" in ListType.ORDERED_NUMERIC.description_en
        assert "lowercase" in ListType.ORDERED_ALPHA_LOWER.description_en

    def test_from_string_all_members(self) -> None:
        """Тестирует from_string для всех типов списков."""
        assert ListType.from_string("ul_dash") == ListType.UNORDERED_DASH
        assert ListType.from_string("OL_NUMERIC") == ListType.ORDERED_NUMERIC


class TestImagePositionComplete:
    """Полное покрытие ImagePosition."""

    def test_all_members_descriptions(self) -> None:
        """Тестирует описания всех позиций изображений."""
        assert "Inline" in ImagePosition.INLINE.description_en
        assert "Float left" in ImagePosition.FLOAT_LEFT.description_en
        assert "Float right" in ImagePosition.FLOAT_RIGHT.description_en

    def test_from_string_all_members(self) -> None:
        """Тестирует from_string для всех позиций."""
        assert ImagePosition.from_string("inline") == ImagePosition.INLINE
        assert ImagePosition.from_string("FLOAT_LEFT") == ImagePosition.FLOAT_LEFT


class TestPageSizeAdditional:
    """Дополнительные тесты PageSize для повышения покрытия."""

    def test_all_members_dimensions(self) -> None:
        """Тестирует dimensions_inches для всех размеров."""
        assert PageSize.A5.dimensions_inches == (5.83, 8.27)
        assert PageSize.EXECUTIVE.dimensions_inches == (7.25, 10.5)
        assert PageSize.FANFOLD_8_5.dimensions_inches == (8.5, 11.0)

    def test_custom_dimensions(self) -> None:
        """Тестирует, что CUSTOM имеет размеры по умолчанию."""
        dims = PageSize.CUSTOM.dimensions_inches
        assert isinstance(dims, tuple)
        assert len(dims) == 2


class TestGraphicsModeAdditional:
    """Дополнительные тесты GraphicsMode."""

    def test_all_members_escp_command_prefix(self) -> None:
        """Тестирует escp_command_prefix для всех режимов."""
        # Стандартные 8-pin команды (прямые коды)
        assert GraphicsMode.SINGLE_DENSITY.escp_command_prefix == b"\x1b\x4b"  # ESC K
        assert GraphicsMode.DOUBLE_DENSITY.escp_command_prefix == b"\x1b\x4c"  # ESC L
        assert GraphicsMode.DOUBLE_SPEED.escp_command_prefix == b"\x1b\x59"  # ESC Y
        assert GraphicsMode.QUAD_DENSITY.escp_command_prefix == b"\x1b\x5a"  # ESC Z

        # ESC/P2 расширенные команды (ESC * m)
        assert GraphicsMode.CRT_I.escp_command_prefix == b"\x1b\x2a\x00"  # ESC * 0
        assert GraphicsMode.CRT_II.escp_command_prefix == b"\x1b\x2a\x01"  # ESC * 1
        assert GraphicsMode.CRT_III.escp_command_prefix == b"\x1b\x2a\x02"  # ESC * 2
        assert GraphicsMode.TRIPLE_DENSITY.escp_command_prefix == b"\x1b\x2a\x03"  # ESC * 3
        assert GraphicsMode.HEXADECIMAL.escp_command_prefix == b"\x1b\x2a\x04"  # ESC * 4
        assert GraphicsMode.CRT_III_24PIN.escp_command_prefix == b"\x1b\x2a\x06"  # ESC * 6

    def test_to_escp_zero_columns(self) -> None:
        """Тестирует to_escp с 0 столбцами (граничный случай)."""
        result = GraphicsMode.DOUBLE_DENSITY.to_escp(0)
        assert result == b"\x1b\x4c\x00\x00"


class TestValidationEdgeCases:
    """Дополнительные edge cases для валидационных функций."""

    def test_validate_style_combination_empty_list(self) -> None:
        """Тестирует валидацию пустого списка стилей."""
        valid, error = validate_style_combination([])
        assert valid is True
        assert error is None

    def test_validate_style_combination_single_style(self) -> None:
        """Тестирует валидацию одного стиля."""
        valid, error = validate_style_combination([TextStyle.BOLD])
        assert valid is True

    def test_validate_cpi_font_all_valid_combinations(self) -> None:
        """Тестирует все валидные комбинации CPI/Font."""
        # USD поддерживает только 10 и 12 CPI
        assert validate_cpi_font_combination(CharactersPerInch.CPI_10, FontFamily.USD)
        assert validate_cpi_font_combination(CharactersPerInch.CPI_12, FontFamily.USD)
        assert not validate_cpi_font_combination(CharactersPerInch.CPI_15, FontFamily.USD)

        # DRAFT поддерживает все фиксированные CPI
        assert validate_cpi_font_combination(CharactersPerInch.CPI_10, FontFamily.DRAFT)
        assert validate_cpi_font_combination(CharactersPerInch.CPI_15, FontFamily.DRAFT)
        assert validate_cpi_font_combination(CharactersPerInch.CPI_20, FontFamily.DRAFT)

    def test_validate_margin_values_below_minimum(self) -> None:
        """Тестирует валидацию полей ниже минимума."""
        valid, error = validate_margin_values(
            0.1, 0.5, 0.5, 0.5, PageSize.LETTER, MarginUnits.INCHES
        )
        assert valid is False
        assert error is not None and "must be at least" in error.lower()


class TestFX890Compatibility:
    """Тесты совместимости с Epson FX-890."""

    def test_graphics_mode_fx890_compatible_flag(self) -> None:
        """Тестирует is_fx890_compatible для всех графических режимов."""
        # Совместимые режимы
        assert GraphicsMode.SINGLE_DENSITY.is_fx890_compatible is True
        assert GraphicsMode.DOUBLE_DENSITY.is_fx890_compatible is True
        assert GraphicsMode.DOUBLE_SPEED.is_fx890_compatible is True
        assert GraphicsMode.QUAD_DENSITY.is_fx890_compatible is True

        # Несовместимые режимы (24-pin)
        assert GraphicsMode.CRT_I.is_fx890_compatible is False
        assert GraphicsMode.CRT_II.is_fx890_compatible is False
        assert GraphicsMode.CRT_III.is_fx890_compatible is False
        assert GraphicsMode.HEXADECIMAL.is_fx890_compatible is False
        assert GraphicsMode.CRT_III_24PIN.is_fx890_compatible is False

    def test_graphics_mode_fx890_fallback(self) -> None:
        """Тестирует fallback для несовместимых режимов."""
        # CRT_I → SINGLE_DENSITY (ESC K)
        result = GraphicsMode.CRT_I.to_escp_fx890(100)
        assert result == b"\x1b\x4b\x64\x00"

        # HEXADECIMAL → QUAD_DENSITY (ESC Z)
        result = GraphicsMode.HEXADECIMAL.to_escp_fx890(100)
        assert result == b"\x1b\x5a\x64\x00"

    def test_validate_fx890_compatibility_valid(self) -> None:
        """Тестирует валидацию совместимых настроек."""
        valid, error = validate_fx890_compatibility(
            GraphicsMode.DOUBLE_DENSITY,
            CodePage.PC437,
        )
        assert valid is True
        assert error is None

    def test_validate_fx890_compatibility_invalid_graphics(self) -> None:
        """Тестирует отклонение несовместимого графического режима."""
        valid, error = validate_fx890_compatibility(
            GraphicsMode.HEXADECIMAL,
            CodePage.PC437,
        )
        assert valid is False
        assert error is not None and "24-pin" in error.lower()

    def test_validate_fx890_compatibility_invalid_codepage(self) -> None:
        """Тестирует отклонение несовместимой кодировки."""
        valid, error = validate_fx890_compatibility(
            GraphicsMode.DOUBLE_DENSITY,
            CodePage.PC866,
        )
        assert valid is False
        assert error is not None
        # Проверяем новое сообщение: "has limited support" или "fallback"
        assert "limited support" in error.lower() or "fallback" in error.lower()


class TestCodePageFX890Compatibility:
    """Тесты совместимости CodePage с FX-890."""

    def test_is_fx890_compatible_flag(self) -> None:
        """Тестирует is_fx890_compatible для всех кодировок."""
        # Совместимые кодировки
        assert CodePage.PC437.is_fx890_compatible is True
        assert CodePage.PC850.is_fx890_compatible is True
        assert CodePage.PC858.is_fx890_compatible is True

        # Несовместимые кодировки
        assert CodePage.PC866.is_fx890_compatible is False
        assert CodePage.PC852.is_fx890_compatible is False
        assert CodePage.CUSTOM.is_fx890_compatible is False

    def test_to_escp_fx890_compatible_codepages(self) -> None:
        """Тестирует to_escp_fx890 для совместимых кодировок."""
        # PC437 → ESC t 0
        assert CodePage.PC437.to_escp_fx890() == b"\x1b\x74\x00"

        # PC850 → ESC t 2
        assert CodePage.PC850.to_escp_fx890() == b"\x1b\x74\x02"

        # PC858 → ESC t 2 (совместима с PC850)
        assert CodePage.PC858.to_escp_fx890() == b"\x1b\x74\x02"

    def test_to_escp_fx890_fallback_codepages(self) -> None:
        """Тестирует fallback для несовместимых кодировок."""
        # PC866 (Cyrillic) → fallback на PC437 (ESC t 0)
        assert CodePage.PC866.to_escp_fx890() == b"\x1b\x74\x00"

        # PC852 (Eastern Europe) → fallback на PC437 (ESC t 0)
        assert CodePage.PC852.to_escp_fx890() == b"\x1b\x74\x00"

        # CUSTOM → fallback на PC437 (ESC t 0)
        assert CodePage.CUSTOM.to_escp_fx890() == b"\x1b\x74\x00"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
