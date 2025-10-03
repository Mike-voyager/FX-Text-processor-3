"""
Unit tests for src/model/run.py module.

Tests cover Run class functionality, validation, serialization,
merging, and utility functions with comprehensive edge case coverage.

Version: 2.0 (updated for enums.py integration)
"""

import logging
from typing import Any

import pytest

from src.model.run import (
    Run,
    merge_consecutive_runs,
    split_by_formatting,
)

from src.model.enums import (
    FontFamily,
    CharactersPerInch,
    TextStyle,
    Color,
    CodePage,
)


class TestRunInitialization:
    """Test Run initialization and post-init validation."""

    def test_minimal_initialization(self) -> None:
        """Test creating run with only required text parameter."""
        run = Run(text="Hello")

        assert run.text == "Hello"
        assert run.font == FontFamily.DRAFT
        assert run.cpi == CharactersPerInch.CPI_10
        assert run.style == TextStyle(0)  # Empty flags
        assert run.color == Color.BLACK
        assert run.codepage == CodePage.PC866

    def test_full_initialization(self) -> None:
        """Test creating run with all parameters specified."""
        run = Run(
            text="Test",
            font=FontFamily.ROMAN,
            cpi=CharactersPerInch.CPI_12,
            style=TextStyle.BOLD | TextStyle.ITALIC | TextStyle.UNDERLINE,
            color=Color.RED,
            codepage=CodePage.PC437,
        )

        assert run.text == "Test"
        assert run.font == FontFamily.ROMAN
        assert run.cpi == CharactersPerInch.CPI_12
        assert TextStyle.BOLD in run.style
        assert TextStyle.ITALIC in run.style
        assert TextStyle.UNDERLINE in run.style
        assert run.color == Color.RED
        assert run.codepage == CodePage.PC437

    def test_invalid_cpi_font_combination_fallback(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that invalid CPI/Font combination triggers warning and fallback."""
        with caplog.at_level(logging.WARNING):
            # USD font only supports 10 and 12 CPI
            run = Run(
                text="Test",
                font=FontFamily.USD,
                cpi=CharactersPerInch.CPI_17,  # Invalid for USD
            )

        assert run.cpi == CharactersPerInch.CPI_10  # Fallback
        assert "Invalid CPI/Font combination" in caplog.text

    def test_cyrillic_text(self) -> None:
        """Test initialization with Cyrillic text."""
        run = Run(text="Привет мир", style=TextStyle.BOLD, codepage=CodePage.PC866)
        assert run.text == "Привет мир"
        assert TextStyle.BOLD in run.style

    def test_multiple_styles_with_flags(self) -> None:
        """Test initialization with multiple text styles using Flag operations."""
        run = Run(
            text="Multi-style",
            style=(
                TextStyle.BOLD | TextStyle.ITALIC | TextStyle.UNDERLINE | TextStyle.DOUBLE_STRIKE
            ),
        )

        assert TextStyle.BOLD in run.style
        assert TextStyle.ITALIC in run.style
        assert TextStyle.UNDERLINE in run.style
        assert TextStyle.DOUBLE_STRIKE in run.style
        assert TextStyle.SUPERSCRIPT not in run.style


class TestRunValidation:
    """Test Run.validate() method."""

    def test_validate_valid_run(self) -> None:
        """Test validation passes for valid run."""
        run = Run(text="Hello", style=TextStyle.BOLD)
        run.validate()  # Should not raise

    def test_validate_empty_text(self) -> None:
        """Test validation fails for empty text."""
        run = Run(text="")

        with pytest.raises(ValueError, match="cannot be empty"):
            run.validate()

    def test_validate_non_string_text(self) -> None:
        """Test validation fails for non-string text."""
        run = Run(text="test")
        object.__setattr__(run, "text", 123)

        with pytest.raises(TypeError, match="must be str"):
            run.validate()

    def test_validate_encoding_incompatible_text(self) -> None:
        """Test validation fails when text cannot be encoded."""
        # Create run with Unicode emoji (incompatible with cp866)
        run = Run(text="Hello 😀", codepage=CodePage.PC866)

        with pytest.raises(ValueError, match="incompatible with pc866"):
            run.validate()

    def test_validate_cyrillic_cp866(self) -> None:
        """Test validation passes for Cyrillic with pc866."""
        run = Run(text="Тест кириллицы", codepage=CodePage.PC866)
        run.validate()  # Should not raise

    def test_validate_enum_type_font(self) -> None:
        """Test validation fails for non-enum font."""
        run = Run(text="Test")
        object.__setattr__(run, "font", "not_an_enum")

        with pytest.raises(TypeError, match="font must be FontFamily"):
            run.validate()

    def test_validate_enum_type_cpi(self) -> None:
        """Test validation fails for non-enum cpi."""
        run = Run(text="Test")
        object.__setattr__(run, "cpi", "10")

        with pytest.raises(TypeError, match="cpi must be CharactersPerInch"):
            run.validate()

    def test_validate_enum_type_style(self) -> None:
        """Test validation fails for non-enum style."""
        run = Run(text="Test")
        object.__setattr__(run, "style", True)

        with pytest.raises(TypeError, match="style must be TextStyle"):
            run.validate()

    def test_validate_enum_type_color(self) -> None:
        """Test validation fails for non-enum color."""
        run = Run(text="Test")
        object.__setattr__(run, "color", "red")

        with pytest.raises(TypeError, match="color must be Color"):
            run.validate()

    def test_validate_enum_type_codepage(self) -> None:
        """Test validation fails for non-enum codepage."""
        run = Run(text="Test")
        object.__setattr__(run, "codepage", "cp866")

        with pytest.raises(TypeError, match="codepage must be CodePage"):
            run.validate()

    @pytest.mark.parametrize(
        "text,codepage",
        [
            ("Hello", CodePage.PC437),
            ("Привет", CodePage.PC866),
            ("Café", CodePage.PC850),
        ],
    )
    def test_validate_various_codepages(self, text: str, codepage: CodePage) -> None:
        """Test validation with various text-codepage combinations."""
        run = Run(text=text, codepage=codepage)
        run.validate()


class TestRunCopy:
    """Test Run.copy() method."""

    def test_copy_creates_independent_instance(self) -> None:
        """Test that copy creates a new independent instance."""
        original = Run(text="Original", style=TextStyle.BOLD)
        copied = original.copy()

        assert copied == original
        assert copied is not original

    def test_copy_preserves_all_attributes(self) -> None:
        """Test that copy preserves all formatting attributes."""
        original = Run(
            text="Test",
            font=FontFamily.ROMAN,
            cpi=CharactersPerInch.CPI_12,
            style=TextStyle.BOLD | TextStyle.ITALIC,
            color=Color.RED,
            codepage=CodePage.PC437,
        )
        copied = original.copy()

        assert copied.text == original.text
        assert copied.font == original.font
        assert copied.cpi == original.cpi
        assert copied.style == original.style
        assert copied.color == original.color
        assert copied.codepage == original.codepage

    def test_copy_modification_does_not_affect_original(self) -> None:
        """Test that modifying copy doesn't affect original."""
        original = Run(text="Original", style=TextStyle(0))
        copied = original.copy()

        # Modify copy
        copied.text = "Modified"
        copied.style = TextStyle.BOLD

        # Original unchanged
        assert original.text == "Original"
        assert original.style == TextStyle(0)


class TestRunMerging:
    """Test Run.can_merge_with() and merge_with() methods."""

    def test_can_merge_identical_formatting(self) -> None:
        """Test that runs with identical formatting can merge."""
        run1 = Run(text="Hello", font=FontFamily.ROMAN, style=TextStyle.BOLD)
        run2 = Run(text=" World", font=FontFamily.ROMAN, style=TextStyle.BOLD)

        assert run1.can_merge_with(run2) is True

    def test_cannot_merge_different_font(self) -> None:
        """Test that runs with different fonts cannot merge."""
        run1 = Run(text="Hello", font=FontFamily.ROMAN)
        run2 = Run(text=" World", font=FontFamily.DRAFT)

        assert run1.can_merge_with(run2) is False

    def test_cannot_merge_different_cpi(self) -> None:
        """Test that runs with different CPI cannot merge."""
        run1 = Run(text="Hello", cpi=CharactersPerInch.CPI_10)
        run2 = Run(text=" World", cpi=CharactersPerInch.CPI_12)

        assert run1.can_merge_with(run2) is False

    def test_cannot_merge_different_style(self) -> None:
        """Test that runs with different styles cannot merge."""
        run1 = Run(text="Hello", style=TextStyle.BOLD)
        run2 = Run(text=" World", style=TextStyle.ITALIC)

        assert run1.can_merge_with(run2) is False

    def test_cannot_merge_different_color(self) -> None:
        """Test that runs with different colors cannot merge."""
        run1 = Run(text="Hello", color=Color.BLACK)
        run2 = Run(text=" World", color=Color.RED)

        assert run1.can_merge_with(run2) is False

    def test_cannot_merge_different_codepage(self) -> None:
        """Test that runs with different codepages cannot merge."""
        run1 = Run(text="Hello", codepage=CodePage.PC866)
        run2 = Run(text=" World", codepage=CodePage.PC437)

        assert run1.can_merge_with(run2) is False

    def test_cannot_merge_non_run_object(self) -> None:
        """Test that can_merge_with returns False for non-Run objects."""
        run = Run(text="Hello")
        assert run.can_merge_with("not a run") is False
        assert run.can_merge_with(None) is False
        assert run.can_merge_with(123) is False

    def test_can_merge_non_strict_mode(self) -> None:
        """Test non-strict merge (only compares styles)."""
        run1 = Run(text="Hello", font=FontFamily.ROMAN, style=TextStyle.BOLD)
        run2 = Run(
            text=" World",
            font=FontFamily.DRAFT,  # Different font
            style=TextStyle.BOLD,  # Same style
        )

        # Strict mode: cannot merge
        assert run1.can_merge_with(run2, strict=True) is False

        # Non-strict mode: can merge (same style)
        assert run1.can_merge_with(run2, strict=False) is True

    def test_merge_concatenates_text(self) -> None:
        """Test that merge_with concatenates text correctly."""
        run1 = Run(text="Hello", style=TextStyle.BOLD)
        run2 = Run(text=" World", style=TextStyle.BOLD)

        merged = run1.merge_with(run2)

        assert merged.text == "Hello World"
        assert TextStyle.BOLD in merged.style

    def test_merge_preserves_formatting(self) -> None:
        """Test that merge preserves all formatting attributes."""
        run1 = Run(
            text="Part1",
            font=FontFamily.ROMAN,
            cpi=CharactersPerInch.CPI_12,
            style=TextStyle.BOLD | TextStyle.ITALIC,
        )
        run2 = Run(
            text="Part2",
            font=FontFamily.ROMAN,
            cpi=CharactersPerInch.CPI_12,
            style=TextStyle.BOLD | TextStyle.ITALIC,
        )

        merged = run1.merge_with(run2)

        assert merged.text == "Part1Part2"
        assert merged.font == FontFamily.ROMAN
        assert merged.cpi == CharactersPerInch.CPI_12
        assert TextStyle.BOLD in merged.style
        assert TextStyle.ITALIC in merged.style

    def test_merge_incompatible_raises_error(self) -> None:
        """Test that merging incompatible runs raises ValueError."""
        run1 = Run(text="Hello", style=TextStyle.BOLD)
        run2 = Run(text=" World", style=TextStyle.ITALIC)

        with pytest.raises(ValueError, match="Cannot merge runs"):
            run1.merge_with(run2)

    def test_merge_creates_new_instance(self) -> None:
        """Test that merge creates a new instance, leaving originals unchanged."""
        run1 = Run(text="Hello", style=TextStyle.BOLD)
        run2 = Run(text=" World", style=TextStyle.BOLD)

        merged = run1.merge_with(run2)

        assert merged is not run1
        assert merged is not run2
        assert run1.text == "Hello"
        assert run2.text == " World"


class TestRunSerialization:
    """Test Run.to_dict() and from_dict() methods."""

    def test_to_dict_minimal(self) -> None:
        """Test serialization with minimal/default attributes."""
        run = Run(text="Test")
        data = run.to_dict()

        assert data == {
            "text": "Test",
            "font": "draft",
            "cpi": "10cpi",
            "style": 0,  # Empty TextStyle flags
            "color": "black",
            "codepage": "pc866",
        }

    def test_to_dict_full(self) -> None:
        """Test serialization with all attributes specified."""
        run = Run(
            text="Test",
            font=FontFamily.ROMAN,
            cpi=CharactersPerInch.CPI_12,
            style=TextStyle.BOLD | TextStyle.ITALIC | TextStyle.UNDERLINE,
            color=Color.RED,
            codepage=CodePage.PC437,
        )
        data = run.to_dict()

        assert data["text"] == "Test"
        assert data["font"] == "roman"
        assert data["cpi"] == "12cpi"
        assert data["style"] > 0  # Has flags
        assert data["color"] == "red"
        assert data["codepage"] == "pc437"

    def test_from_dict_minimal(self) -> None:
        """Test deserialization with only required 'text' field."""
        data = {"text": "Hello"}
        run = Run.from_dict(data)

        assert run.text == "Hello"
        assert run.font == FontFamily.DRAFT
        assert run.cpi == CharactersPerInch.CPI_10
        assert run.style == TextStyle(0)
        assert run.color == Color.BLACK
        assert run.codepage == CodePage.PC866

    def test_from_dict_full(self) -> None:
        """Test deserialization with all fields."""
        data = {
            "text": "Test",
            "font": "roman",
            "cpi": "12cpi",
            "style": TextStyle.BOLD.value | TextStyle.ITALIC.value,
            "color": "red",
            "codepage": "pc437",
        }
        run = Run.from_dict(data)

        assert run.text == "Test"
        assert run.font == FontFamily.ROMAN
        assert run.cpi == CharactersPerInch.CPI_12
        assert TextStyle.BOLD in run.style
        assert TextStyle.ITALIC in run.style
        assert run.color == Color.RED
        assert run.codepage == CodePage.PC437

    def test_from_dict_missing_text_raises(self) -> None:
        """Test that missing 'text' key raises KeyError."""
        data: dict[str, Any] = {"font": "roman"}

        with pytest.raises(KeyError, match="Missing required key 'text'"):
            Run.from_dict(data)

    def test_from_dict_invalid_type_raises(self) -> None:
        """Test that non-dict input raises TypeError."""
        with pytest.raises(TypeError, match="Expected dict"):
            Run.from_dict("not a dict")  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="Expected dict"):
            Run.from_dict(None)  # type: ignore[arg-type]

    def test_roundtrip_serialization(self) -> None:
        """Test that to_dict/from_dict roundtrip preserves data."""
        original = Run(
            text="Roundtrip test",
            font=FontFamily.ROMAN,
            style=TextStyle.BOLD | TextStyle.UNDERLINE,
        )

        data = original.to_dict()
        restored = Run.from_dict(data)

        assert restored == original


class TestRunToESCP:
    """Test Run.to_escp() method."""

    def test_to_escp_plain_text(self) -> None:
        """Test ESC/P generation for plain text."""
        run = Run(text="Hello", codepage=CodePage.PC437)
        escp = run.to_escp()

        assert isinstance(escp, bytes)
        assert b"Hello" in escp

    def test_to_escp_with_bold(self) -> None:
        """Test ESC/P generation with bold style."""
        run = Run(text="Bold", style=TextStyle.BOLD)
        escp = run.to_escp()

        # Should contain bold on/off commands
        assert isinstance(escp, bytes)
        assert b"Bold" in escp
        assert len(escp) > len(b"Bold")  # Has ESC/P commands

    def test_to_escp_with_font(self) -> None:
        """Test ESC/P generation with font selection."""
        run = Run(text="Roman", font=FontFamily.ROMAN)
        escp = run.to_escp()

        assert isinstance(escp, bytes)
        assert b"Roman" in escp

    def test_to_escp_complex_formatting(self) -> None:
        """Test ESC/P generation with multiple formatting attributes."""
        run = Run(
            text="Complex",
            font=FontFamily.ROMAN,
            cpi=CharactersPerInch.CPI_12,
            style=TextStyle.BOLD | TextStyle.ITALIC,
            color=Color.RED,
        )
        escp = run.to_escp()

        assert isinstance(escp, bytes)
        assert b"Complex" in escp
        # Should contain multiple ESC/P commands
        assert escp.count(b"\x1b") >= 3  # At least 3 ESC commands

    def test_to_escp_cyrillic(self) -> None:
        """Test ESC/P generation with Cyrillic text."""
        run = Run(text="Тест", codepage=CodePage.PC866)
        escp = run.to_escp()

        assert isinstance(escp, bytes)
        # Cyrillic encoded in cp866
        assert run.text.encode("cp866") in escp


class TestRunMagicMethods:
    """Test Run magic methods (__len__, __eq__, __repr__)."""

    def test_len_returns_text_length(self) -> None:
        """Test that len() returns text length."""
        run = Run(text="Hello")
        assert len(run) == 5

        run_long = Run(text="This is a longer text")
        assert len(run_long) == 21

        run_empty = Run(text="")
        assert len(run_empty) == 0

    def test_equality_identical_runs(self) -> None:
        """Test that identical runs are equal."""
        run1 = Run(text="Test", font=FontFamily.ROMAN, style=TextStyle.BOLD)
        run2 = Run(text="Test", font=FontFamily.ROMAN, style=TextStyle.BOLD)

        assert run1 == run2

    def test_equality_different_text(self) -> None:
        """Test that runs with different text are not equal."""
        run1 = Run(text="Hello", style=TextStyle.BOLD)
        run2 = Run(text="World", style=TextStyle.BOLD)

        assert run1 != run2

    def test_equality_different_formatting(self) -> None:
        """Test that runs with different formatting are not equal."""
        run1 = Run(text="Test", style=TextStyle.BOLD)
        run2 = Run(text="Test", style=TextStyle.ITALIC)

        assert run1 != run2

    def test_equality_with_non_run(self) -> None:
        """Test comparison with non-Run objects."""
        run = Run(text="Test")

        assert (run == "Test") is False
        assert (run == None) is False
        assert (run == 123) is False

    def test_repr_short_text(self) -> None:
        """Test __repr__ with short text."""
        run = Run(text="Short", style=TextStyle.BOLD)
        repr_str = repr(run)

        assert "Run(" in repr_str
        assert "text='Short'" in repr_str
        assert "len=5" in repr_str

    def test_repr_long_text(self) -> None:
        """Test __repr__ truncates long text."""
        run = Run(text="This is a very long text that should be truncated")
        repr_str = repr(run)

        assert "..." in repr_str
        assert len(repr_str) < 200  # Reasonable length

    def test_repr_complex_formatting(self) -> None:
        """Test __repr__ with multiple formatting attributes."""
        run = Run(
            text="Test",
            font=FontFamily.ROMAN,
            style=TextStyle.BOLD | TextStyle.ITALIC,
        )
        repr_str = repr(run)

        assert "font=roman" in repr_str
        assert "B" in repr_str or "I" in repr_str


class TestMergeConsecutiveRuns:
    """Test merge_consecutive_runs() utility function."""

    def test_merge_empty_list(self) -> None:
        """Test merging empty list returns empty list."""
        result = merge_consecutive_runs([])
        assert result == []

    def test_merge_single_run(self) -> None:
        """Test merging single run returns copy."""
        run = Run(text="Only", style=TextStyle.BOLD)
        result = merge_consecutive_runs([run])

        assert len(result) == 1
        assert result[0] == run
        assert result[0] is not run  # Should be copy

    def test_merge_identical_consecutive_runs(self) -> None:
        """Test merging runs with identical formatting."""
        runs = [
            Run(text="Part1", style=TextStyle.BOLD),
            Run(text="Part2", style=TextStyle.BOLD),
            Run(text="Part3", style=TextStyle.BOLD),
        ]

        result = merge_consecutive_runs(runs)

        assert len(result) == 1
        assert result[0].text == "Part1Part2Part3"
        assert TextStyle.BOLD in result[0].style

    def test_merge_mixed_formatting(self) -> None:
        """Test merging with alternating formatting."""
        runs = [
            Run(text="Bold1", style=TextStyle.BOLD),
            Run(text="Bold2", style=TextStyle.BOLD),
            Run(text="Normal", style=TextStyle(0)),
            Run(text="Bold3", style=TextStyle.BOLD),
        ]

        result = merge_consecutive_runs(runs)

        assert len(result) == 3
        assert result[0].text == "Bold1Bold2"
        assert TextStyle.BOLD in result[0].style
        assert result[1].text == "Normal"
        assert result[1].style == TextStyle(0)
        assert result[2].text == "Bold3"
        assert TextStyle.BOLD in result[2].style

    def test_merge_no_mergeable_runs(self) -> None:
        """Test with no consecutive runs having same formatting."""
        runs = [
            Run(text="Bold", style=TextStyle.BOLD),
            Run(text="Italic", style=TextStyle.ITALIC),
            Run(text="Under", style=TextStyle.UNDERLINE),
        ]

        result = merge_consecutive_runs(runs)

        assert len(result) == 3
        assert result[0].text == "Bold"
        assert result[1].text == "Italic"
        assert result[2].text == "Under"

    def test_merge_preserves_original_list(self) -> None:
        """Test that original list is not modified."""
        runs = [
            Run(text="A", style=TextStyle.BOLD),
            Run(text="B", style=TextStyle.BOLD),
        ]
        original_length = len(runs)

        result = merge_consecutive_runs(runs)

        assert len(runs) == original_length  # Original unchanged
        assert result is not runs


class TestSplitByFormatting:
    """Test split_by_formatting() utility function."""

    def test_split_empty_runs(self) -> None:
        """Test splitting with no runs returns empty list."""
        result = split_by_formatting("text", [])
        assert result == []

    def test_split_single_segment(self) -> None:
        """Test splitting with single formatting segment."""
        text = "Hello"
        template = [Run(text="x" * 5, style=TextStyle.BOLD)]

        result = split_by_formatting(text, template)

        assert len(result) == 1
        assert result[0].text == "Hello"
        assert TextStyle.BOLD in result[0].style

    def test_split_multiple_segments(self) -> None:
        """Test splitting text into multiple formatted segments."""
        text = "HelloWorld"
        template = [
            Run(text="x" * 5, style=TextStyle.BOLD),
            Run(text="y" * 5, style=TextStyle(0)),
        ]

        result = split_by_formatting(text, template)

        assert len(result) == 2
        assert result[0].text == "Hello"
        assert TextStyle.BOLD in result[0].style
        assert result[1].text == "World"
        assert result[1].style == TextStyle(0)

    def test_split_complex_formatting(self) -> None:
        """Test splitting with complex formatting patterns."""
        text = "ABCDEFGH"
        template = [
            Run(text="1" * 2, font=FontFamily.ROMAN, style=TextStyle.BOLD),
            Run(text="2" * 3, font=FontFamily.DRAFT, style=TextStyle.ITALIC),
            Run(
                text="3" * 3,
                font=FontFamily.ROMAN,
                style=TextStyle.BOLD | TextStyle.ITALIC,
            ),
        ]

        result = split_by_formatting(text, template)

        assert len(result) == 3
        assert result[0].text == "AB"
        assert result[0].font == FontFamily.ROMAN
        assert TextStyle.BOLD in result[0].style
        assert result[1].text == "CDE"
        assert result[1].font == FontFamily.DRAFT
        assert TextStyle.ITALIC in result[1].style
        assert result[2].text == "FGH"
        assert TextStyle.BOLD in result[2].style
        assert TextStyle.ITALIC in result[2].style

    def test_split_length_mismatch_raises(self) -> None:
        """Test that length mismatch raises ValueError."""
        text = "HelloWorld"
        template = [Run(text="x" * 5, style=TextStyle.BOLD)]  # Only 5 chars, but text is 10

        with pytest.raises(ValueError, match="does not match"):
            split_by_formatting(text, template)

    def test_split_preserves_formatting_attributes(self) -> None:
        """Test that all formatting attributes are preserved."""
        text = "Test"
        template = [
            Run(
                text="t" * 4,
                font=FontFamily.ROMAN,
                cpi=CharactersPerInch.CPI_12,
                style=TextStyle.BOLD | TextStyle.ITALIC,
                color=Color.RED,
                codepage=CodePage.PC437,
            )
        ]

        result = split_by_formatting(text, template)

        assert result[0].font == FontFamily.ROMAN
        assert result[0].cpi == CharactersPerInch.CPI_12
        assert TextStyle.BOLD in result[0].style
        assert TextStyle.ITALIC in result[0].style
        assert result[0].color == Color.RED
        assert result[0].codepage == CodePage.PC437


class TestRunEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_run_with_whitespace_only(self) -> None:
        """Test run containing only whitespace."""
        run = Run(text="   ")
        assert len(run) == 3
        run.validate()  # Should not raise

    def test_run_with_special_characters(self) -> None:
        """Test run with special characters."""
        run = Run(text="Tab\there\nNewline", codepage=CodePage.PC437)
        run.validate()
        assert "\t" in run.text
        assert "\n" in run.text

    def test_run_with_cyrillic_and_latin(self) -> None:
        """Test run mixing Cyrillic and Latin characters."""
        run = Run(text="Привет Hello", codepage=CodePage.PC866)
        run.validate()

    def test_merge_three_runs_consecutively(self) -> None:
        """Test merging multiple runs in sequence."""
        run1 = Run(text="A", style=TextStyle.BOLD)
        run2 = Run(text="B", style=TextStyle.BOLD)
        run3 = Run(text="C", style=TextStyle.BOLD)

        merged_12 = run1.merge_with(run2)
        merged_all = merged_12.merge_with(run3)

        assert merged_all.text == "ABC"
        assert TextStyle.BOLD in merged_all.style

    @pytest.mark.parametrize("font", list(FontFamily))
    def test_all_supported_fonts(self, font: FontFamily) -> None:
        """Test that all FontFamily values work correctly."""
        run = Run(text="Test", font=font)
        assert run.font == font
        run.validate()

    @pytest.mark.parametrize("codepage", list(CodePage))
    def test_all_supported_codepages(self, codepage: CodePage) -> None:
        """Test that all CodePage values work correctly."""
        # Use text compatible with all encodings
        run = Run(text="Test", codepage=codepage)
        assert run.codepage == codepage
        run.validate()

    def test_format_summary_plain(self) -> None:
        """Test _format_summary for plain text."""
        run = Run(text="Plain")
        summary = run._format_summary()
        assert "font=draft" in summary
        assert "cpi=10cpi" in summary

    def test_format_summary_complex(self) -> None:
        """Test _format_summary with multiple attributes."""
        run = Run(
            text="Complex",
            font=FontFamily.ROMAN,
            cpi=CharactersPerInch.CPI_12,
            style=TextStyle.BOLD | TextStyle.ITALIC | TextStyle.UNDERLINE | TextStyle.DOUBLE_STRIKE,
            color=Color.RED,
            codepage=CodePage.PC437,
        )
        summary = run._format_summary()

        assert "font=roman" in summary
        assert "cpi=12cpi" in summary
        assert "B" in summary
        assert "I" in summary
        assert "U" in summary
        assert "color=red" in summary
        assert "cp=pc437" in summary


class TestRunIntegration:
    """Integration tests combining multiple operations."""

    def test_create_validate_serialize_deserialize(self) -> None:
        """Test complete workflow: create, validate, serialize, deserialize."""
        original = Run(
            text="Integration test",
            font=FontFamily.ROMAN,
            style=TextStyle.BOLD,
        )

        original.validate()
        data = original.to_dict()
        restored = Run.from_dict(data)

        assert restored == original
        restored.validate()

    def test_merge_and_split_workflow(self) -> None:
        """Test merging runs then splitting back."""
        runs = [
            Run(text="Part1", style=TextStyle.BOLD),
            Run(text="Part2", style=TextStyle.BOLD),
            Run(text="Part3", style=TextStyle(0)),
        ]

        merged = merge_consecutive_runs(runs)
        assert len(merged) == 2

        # Recreate split using the merged runs as templates
        full_text = "Part1Part2Part3"
        templates = [
            Run(text="x" * 10, style=TextStyle.BOLD),
            Run(text="y" * 5, style=TextStyle(0)),
        ]

        split_result = split_by_formatting(full_text, templates)
        assert split_result[0].text == "Part1Part2"
        assert split_result[1].text == "Part3"

    def test_copy_merge_sequence(self) -> None:
        """Test copying and merging in sequence."""
        run1 = Run(text="First", style=TextStyle.BOLD)
        run1_copy = run1.copy()

        run2 = Run(text="Second", style=TextStyle.BOLD)

        merged = run1_copy.merge_with(run2)

        assert merged.text == "FirstSecond"
        assert run1.text == "First"  # Original unchanged

    def test_to_escp_and_validate(self) -> None:
        """Test ESC/P generation with validation."""
        run = Run(
            text="Тест ESC/P",
            font=FontFamily.ROMAN,
            style=TextStyle.BOLD | TextStyle.ITALIC,
            codepage=CodePage.PC866,
        )

        run.validate()
        escp = run.to_escp()

        assert isinstance(escp, bytes)
        assert len(escp) > 0
        # Text should be encoded in cp866
        assert "Тест ESC/P".encode("cp866") in escp


class TestLogging:
    """Test logging functionality."""

    def test_merge_consecutive_runs_logging(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that merge operation logs correctly."""
        runs = [
            Run(text="Part1", style=TextStyle.BOLD),
            Run(text="Part2", style=TextStyle.BOLD),
        ]

        with caplog.at_level(logging.INFO):
            result = merge_consecutive_runs(runs)

        assert "Merged 2 runs into 1 runs" in caplog.text
        assert len(result) == 1

    def test_split_by_formatting_debug_logging(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that split_by_formatting logs debug information."""
        text = "HelloWorld"
        template = [
            Run(text="x" * 5, style=TextStyle.BOLD),
            Run(text="y" * 5, style=TextStyle(0)),
        ]

        with caplog.at_level(logging.DEBUG):
            result = split_by_formatting(text, template)

        assert "Split text into" in caplog.text
        assert "original: 2 templates" in caplog.text
        assert len(result) == 2

    def test_validation_debug_logging(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that validation logs debug information."""
        run = Run(text="Test", style=TextStyle.BOLD)

        with caplog.at_level(logging.DEBUG):
            run.validate()

        assert "Validated Run" in caplog.text
