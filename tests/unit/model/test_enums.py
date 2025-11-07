from typing import Any

import pytest

from src.model.enums import (
    DEFAULT_ALIGNMENT,
    DEFAULT_CODEPAGE,
    DEFAULT_COLOR,
    DEFAULT_CPI,
    DEFAULT_DITHERING_ALGORITHM,
    DEFAULT_FONT_FAMILY,
    DEFAULT_LINE_SPACING,
    DEFAULT_MARGIN_UNITS,
    DEFAULT_ORIENTATION,
    DEFAULT_PAGE_SIZE,
    DEFAULT_PRINT_DIRECTION,
    DEFAULT_PRINT_QUALITY,
    DEFAULT_TABLE_STYLE,
    Alignment,
    BarcodeType,
    CharactersPerInch,
    CodePage,
    Color,
    DitheringAlgorithm,
    FontFamily,
    GraphicsMode,
    ImagePosition,
    LineSpacing,
    ListType,
    MarginUnits,
    Orientation,
    PageSize,
    PaperSource,
    PaperType,
    PrintDirection,
    PrintQuality,
    TableStyle,
    TextStyle,
    validate_barcode,
    validate_codepage,
    validate_cpi_font_combination,
    validate_graphics_mode,
    validate_margin,
    validate_quality_font_combination,
)


def test_fontfamily_props_and_localization() -> None:
    assert FontFamily.ROMAN.is_nlq
    assert FontFamily.SANS_SERIF.is_nlq
    assert not FontFamily.DRAFT.is_nlq
    assert FontFamily.ROMAN.supports_proportional
    assert not FontFamily.DRAFT.supports_proportional
    assert FontFamily.ROMAN.localized_name("ru").startswith("Роман")
    assert FontFamily.ROMAN.localized_name("en").startswith("Roman")


def test_charactersperinch_numeric_value_and_membership() -> None:
    for cpi in CharactersPerInch:
        if cpi == CharactersPerInch.PROPORTIONAL:
            assert cpi.numeric_value is None
        else:
            assert isinstance(cpi.numeric_value, int)
    assert CharactersPerInch.CPI_10.numeric_value == 10


def test_cpi_font_combinations_all_cases() -> None:
    # NLQ allows all, including proportional
    for cpi in CharactersPerInch:
        assert validate_cpi_font_combination(cpi, FontFamily.ROMAN)
    # USD/HSD/DRAFT: only 10/12; no proportional!
    for font in [FontFamily.USD, FontFamily.HSD, FontFamily.DRAFT]:
        assert validate_cpi_font_combination(CharactersPerInch.CPI_10, font)
        assert validate_cpi_font_combination(CharactersPerInch.CPI_12, font)
        for cpi in [
            CharactersPerInch.CPI_15,
            CharactersPerInch.CPI_17,
            CharactersPerInch.CPI_20,
            CharactersPerInch.PROPORTIONAL,
        ]:
            assert not validate_cpi_font_combination(cpi, font)


def test_barcode_types_hardware_positive_and_negative() -> None:
    supported = {
        BarcodeType.EAN8,
        BarcodeType.EAN13,
        BarcodeType.UPCA,
        BarcodeType.UPCE,
        BarcodeType.CODE39,
        BarcodeType.CODE128,
        BarcodeType.POSTNET,
        BarcodeType.ITF,
        BarcodeType.CODABAR,
    }
    for btype in BarcodeType:
        assert validate_barcode(btype) == (btype in supported)


def test_codepage_is_fx890_hardware_property_and_localized() -> None:
    for codepage in CodePage:
        assert hasattr(codepage, "is_fx890_hardware")
        assert codepage.is_fx890_hardware
        assert hasattr(codepage, "localized_name")
        assert isinstance(codepage.localized_name("ru"), str)
        assert isinstance(codepage.localized_name("en"), str)


def test_graphics_modes_positive_and_negative() -> None:
    supported = {
        GraphicsMode.SINGLE_DENSITY,
        GraphicsMode.DOUBLE_DENSITY,
        GraphicsMode.DOUBLE_SPEED,
        GraphicsMode.QUAD_DENSITY,
    }
    for gmode in GraphicsMode:
        assert validate_graphics_mode(gmode) == (gmode in supported)


def test_margin_validator_inch_and_limits() -> None:
    assert validate_margin(0.13, 0.13, 0.13, 0.13, MarginUnits.INCHES)[0]
    assert not validate_margin(0.1, 0.13, 0.13, 0.13, MarginUnits.INCHES)[0]
    assert not validate_margin(0.13, 0.1, 0.13, 0.13, MarginUnits.INCHES)[0]
    assert not validate_margin(0.13, 0.13, 0.05, 0.13, MarginUnits.INCHES)[0]


def test_defaults_types_and_values() -> None:
    assert isinstance(DEFAULT_FONT_FAMILY, FontFamily)
    assert isinstance(DEFAULT_CPI, CharactersPerInch)
    assert isinstance(DEFAULT_PRINT_QUALITY, PrintQuality)
    assert isinstance(DEFAULT_CODEPAGE, CodePage)
    assert isinstance(DEFAULT_ALIGNMENT, Alignment)
    assert isinstance(DEFAULT_LINE_SPACING, LineSpacing)
    assert isinstance(DEFAULT_COLOR, Color)
    assert isinstance(DEFAULT_PAGE_SIZE, PageSize)
    assert isinstance(DEFAULT_TABLE_STYLE, TableStyle)
    assert isinstance(DEFAULT_DITHERING_ALGORITHM, DitheringAlgorithm)
    assert isinstance(DEFAULT_PRINT_DIRECTION, PrintDirection)
    assert isinstance(DEFAULT_MARGIN_UNITS, MarginUnits)
    assert isinstance(DEFAULT_ORIENTATION, Orientation)
    assert DEFAULT_FONT_FAMILY == FontFamily.DRAFT
    assert DEFAULT_CPI == CharactersPerInch.CPI_10
    assert DEFAULT_PRINT_QUALITY == PrintQuality.DRAFT
    assert DEFAULT_CODEPAGE == CodePage.PC437


def test_localized_name_and_edge_cases() -> None:
    # Localized
    assert CodePage.PC866.localized_name("ru") == "PC866 (Кириллица)"
    assert CodePage.PC850.localized_name("ru") == "PC850 (Западная Европа)"
    assert CodePage.PC866.localized_name("en") == "PC866 (Russian Cyrillic)"
    assert CodePage.PC858.localized_name("en") == "PC858 (w/Euro)"
    assert FontFamily.USD.localized_name("en") == "Ultra Speed Draft"
    assert PaperType.CONTINUOUS_TRACTOR.localized_name("en") == "Continuous Tractor"
    assert PaperType.ENVELOPE.localized_name("ru") == "Конверт"
    assert PageSize.A4.localized_name("en") == "a4"


def test_textstyle_flags_and_membership() -> None:
    style = TextStyle.BOLD | TextStyle.ITALIC
    assert TextStyle.BOLD in style
    assert TextStyle.ITALIC in style
    assert TextStyle.UNDERLINE not in style
    # Bitwise idempotency
    for s in TextStyle:
        assert (s | s) == s


def test_paper_enums_and_properties() -> None:
    for ptype in PaperType:
        assert isinstance(ptype, PaperType)
    for psize in PageSize:
        assert isinstance(psize, PageSize)
    for align in Alignment:
        assert isinstance(align, Alignment)
    for orientation in Orientation:
        assert isinstance(orientation, Orientation)


def test_listtype_and_tablerstyle() -> None:
    for t in TableStyle:
        assert isinstance(t, TableStyle)
    for l in ListType:
        assert isinstance(l, ListType)


def test_line_spacing_variants() -> None:
    assert LineSpacing.ONE_SIXTH_INCH.value == "1/6"
    assert LineSpacing.ONE_EIGHTH_INCH.value == "1/8"
    assert LineSpacing.CUSTOM.value == "custom"


def test_validate_quality_font_combination() -> None:
    assert validate_quality_font_combination(PrintQuality.NLQ, FontFamily.ROMAN)
    assert validate_quality_font_combination(PrintQuality.DRAFT, FontFamily.DRAFT)
    assert not validate_quality_font_combination(PrintQuality.NLQ, FontFamily.DRAFT)


def test_image_position_enum_types() -> None:
    assert ImagePosition.INLINE.value == "inline"
    assert isinstance(ImagePosition.FLOAT_LEFT, ImagePosition)
    assert isinstance(ImagePosition.FLOAT_RIGHT, ImagePosition)


def test_papersource_and_printdirection() -> None:
    assert PaperSource.TRACTOR.value == "tractor"
    assert PrintDirection.BIDIRECTIONAL.value == "bidirectional"
    assert PrintDirection.UNIDIRECTIONAL.value == "unidirectional"


def test_dithering_enum_types() -> None:
    assert DitheringAlgorithm.FLOYD_STEINBERG.value == "floyd_steinberg"
    assert isinstance(DitheringAlgorithm.ORDERED_BAYER, DitheringAlgorithm)
    assert isinstance(DitheringAlgorithm.THRESHOLD, DitheringAlgorithm)


def test_repr_str_coverage_for_all_enums() -> None:
    for enum_cls in (
        FontFamily,
        CharactersPerInch,
        PrintQuality,
        LineSpacing,
        CodePage,
        BarcodeType,
        GraphicsMode,
        Alignment,
        PaperType,
        PageSize,
        Color,
        Orientation,
        TableStyle,
        ListType,
        MarginUnits,
        PrintDirection,
        PaperSource,
        DitheringAlgorithm,
        ImagePosition,
    ):
        for item in enum_cls:
            sval = str(item)
            assert isinstance(sval, str)
            # Strict string roundtrip only for simple enums
            if isinstance(enum_cls, type) and issubclass(enum_cls, str):
                # If enum uses __str__, may differ from .value
                assert isinstance(item.value, str)


def test_validate_codepage_full_coverage() -> None:
    for cp in CodePage:
        assert cp.is_fx890_hardware is True
        assert validate_codepage(cp) is True
