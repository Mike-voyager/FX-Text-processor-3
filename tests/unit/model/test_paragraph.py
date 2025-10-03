"""
Unit tests for src/model/paragraph.py module.

Tests cover Paragraph class functionality, ESC/P generation, validation,
serialization, alignment, margins, and utility functions with comprehensive
edge case coverage for FX-890 compatibility.

Version: 2.0 (production-ready with ESC/P verification)
"""

import logging
from typing import Any

import pytest

from src.model.paragraph import (
    Paragraph,
    ParagraphMetrics,
    WrappedLine,
    merge_paragraphs,
    split_paragraph_at,
    MAX_INDENT,
    MIN_INDENT,
    MAX_SPACE,
    MIN_SPACE,
    MAX_MARGIN_CHARS,
)
from src.model.run import Run
from src.model.enums import (
    Alignment,
    LineSpacing,
    TextStyle,
    FontFamily,
    CodePage,
)


class TestParagraphInitialization:
    """Test Paragraph initialization and post-init validation."""

    def test_minimal_initialization(self) -> None:
        """Test creating paragraph with default values."""
        para = Paragraph()

        assert para.runs == []
        assert para.alignment == Alignment.LEFT
        assert para.first_line_indent == 0.0
        assert para.left_indent == 0.0
        assert para.right_indent == 0.0
        assert para.line_spacing == LineSpacing.ONE_SIXTH_INCH
        assert para.space_before == 0.0
        assert para.space_after == 0.0

    def test_full_initialization(self) -> None:
        """Test creating paragraph with all parameters specified."""
        runs = [Run(text="Test", style=TextStyle.BOLD)]
        para = Paragraph(
            runs=runs,
            alignment=Alignment.CENTER,
            first_line_indent=0.5,
            left_indent=1.0,
            right_indent=1.5,
            line_spacing=LineSpacing.ONE_EIGHTH_INCH,
            space_before=0.25,
            space_after=0.5,
        )

        assert len(para.runs) == 1
        assert para.alignment == Alignment.CENTER
        assert para.first_line_indent == 0.5
        assert para.left_indent == 1.0
        assert para.right_indent == 1.5
        assert para.line_spacing == LineSpacing.ONE_EIGHTH_INCH
        assert para.space_before == 0.25
        assert para.space_after == 0.5

    def test_clamping_first_line_indent(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that out-of-range first_line_indent is clamped."""
        with caplog.at_level(logging.WARNING):
            para = Paragraph(first_line_indent=10.0)  # Exceeds MAX_INDENT

        assert para.first_line_indent == MAX_INDENT
        assert "first_line_indent" in caplog.text
        assert "clamping" in caplog.text

    def test_clamping_negative_indent(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that negative indent is clamped to MIN_INDENT."""
        with caplog.at_level(logging.WARNING):
            para = Paragraph(left_indent=-1.0)

        assert para.left_indent == MIN_INDENT
        assert "left_indent" in caplog.text

    def test_clamping_space_before(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that out-of-range space_before is clamped."""
        with caplog.at_level(logging.WARNING):
            para = Paragraph(space_before=5.0)  # Exceeds MAX_SPACE

        assert para.space_before == MAX_SPACE
        assert "space_before" in caplog.text

    def test_clamping_space_after(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that out-of-range space_after is clamped."""
        with caplog.at_level(logging.WARNING):
            para = Paragraph(space_after=-0.5)

        assert para.space_after == MIN_SPACE
        assert "space_after" in caplog.text


class TestParagraphRunManagement:
    """Test run manipulation methods."""

    def test_add_run(self) -> None:
        """Test adding runs to paragraph."""
        para = Paragraph()
        run1 = Run(text="Hello")
        run2 = Run(text=" World")

        para.add_run(run1)
        assert len(para.runs) == 1

        para.add_run(run2)
        assert len(para.runs) == 2
        assert para.get_text() == "Hello World"

    def test_add_run_invalid_type(self) -> None:
        """Test that adding non-Run raises TypeError."""
        para = Paragraph()

        with pytest.raises(TypeError, match="Expected Run instance"):
            para.add_run("not a run")  # type: ignore[arg-type]

    def test_insert_run(self) -> None:
        """Test inserting run at specific index."""
        para = Paragraph()
        para.add_run(Run(text="World"))
        para.insert_run(0, Run(text="Hello "))

        assert para.get_text() == "Hello World"

    def test_insert_run_invalid_index(self) -> None:
        """Test that invalid insert index raises IndexError."""
        para = Paragraph()
        para.add_run(Run(text="Test"))

        with pytest.raises(IndexError, match="Insert index .* out of range"):
            para.insert_run(10, Run(text="Invalid"))

    def test_remove_run(self) -> None:
        """Test removing run by index."""
        para = Paragraph()
        para.add_run(Run(text="Hello"))
        para.add_run(Run(text=" World"))

        removed = para.remove_run(0)
        assert removed.text == "Hello"
        assert para.get_text() == " World"

    def test_remove_run_invalid_index(self) -> None:
        """Test that invalid remove index raises IndexError."""
        para = Paragraph()

        with pytest.raises(IndexError, match="Remove index .* out of range"):
            para.remove_run(0)

    def test_clear_runs(self) -> None:
        """Test clearing all runs."""
        para = Paragraph()
        para.add_run(Run(text="Test1"))
        para.add_run(Run(text="Test2"))

        para.clear_runs()
        assert len(para.runs) == 0
        assert para.get_text() == ""

    def test_get_run_count(self) -> None:
        """Test getting run count."""
        para = Paragraph()
        assert para.get_run_count() == 0

        para.add_run(Run(text="A"))
        para.add_run(Run(text="B"))
        assert para.get_run_count() == 2


class TestParagraphValidation:
    """Test paragraph validation logic."""

    def test_validate_valid_paragraph(self) -> None:
        """Test that valid paragraph passes validation."""
        para = Paragraph()
        para.add_run(Run(text="Valid text"))
        para.validate()  # Should not raise

    def test_validate_invalid_run(self) -> None:
        """Test that invalid run fails validation."""
        para = Paragraph()
        para.add_run(Run(text=""))  # Empty text

        with pytest.raises(ValueError, match="Run at index 0 failed validation"):
            para.validate()

    def test_validate_non_run_object(self) -> None:
        """Test that non-Run object in runs list fails validation."""
        para = Paragraph()
        para.runs.append("not a run")  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="Run at index 0 is not a Run instance"):
            para.validate()

    def test_validate_invalid_alignment_enum(self) -> None:
        """Test that invalid alignment enum fails validation."""
        para = Paragraph()
        object.__setattr__(para, "alignment", "left")  # String instead of enum

        with pytest.raises(TypeError, match="alignment must be Alignment"):
            para.validate()

    def test_validate_invalid_line_spacing_enum(self) -> None:
        """Test that invalid line_spacing enum fails validation."""
        para = Paragraph()
        object.__setattr__(para, "line_spacing", 1.0)  # Float instead of enum

        with pytest.raises(TypeError, match="line_spacing must be LineSpacing"):
            para.validate()

    def test_validate_excessive_total_indent(self) -> None:
        """Test that excessive total indent fails validation."""
        para = Paragraph(left_indent=5.0, right_indent=5.0)  # Total = 10.0 > MAX_INDENT

        with pytest.raises(ValueError, match="exceed maximum"):
            para.validate()

    def test_validate_edge_case_total_indent(self) -> None:
        """Test total indent exactly at limit."""
        para = Paragraph(left_indent=MAX_INDENT / 2, right_indent=MAX_INDENT / 2 - 0.01)
        para.validate()  # Should not raise


class TestParagraphToESCP:
    """Test ESC/P command generation."""

    def test_to_escp_minimal(self) -> None:
        """Test ESC/P generation for minimal paragraph."""
        para = Paragraph()
        para.add_run(Run(text="Test"))

        escp = para.to_escp()

        assert isinstance(escp, bytes)
        assert b"Test" in escp
        assert b"\x1b\x32" in escp  # ESC 2 (line spacing)
        assert b"\r\n" in escp  # CR+LF

    def test_to_escp_with_left_margin(self) -> None:
        """Test ESC/P generation with left margin."""
        para = Paragraph(left_indent=1.0)  # 1" = 10 chars at 10 CPI
        para.add_run(Run(text="Test"))

        escp = para.to_escp(page_width=8.5, page_cpi=10)

        assert b"\x1b\x6c\x0a" in escp  # ESC l 10 (left margin = 10 chars)

    def test_to_escp_with_right_margin(self) -> None:
        """Test ESC/P generation with right margin."""
        para = Paragraph(right_indent=1.0)  # 1" from right
        para.add_run(Run(text="Test"))

        escp = para.to_escp(page_width=8.5, page_cpi=10)

        # Page = 85 chars, right indent = 10 chars, right margin pos = 75
        assert b"\x1b\x51\x4b" in escp  # ESC Q 75 (0x4B = 75)

    def test_to_escp_with_both_margins(self) -> None:
        """Test ESC/P generation with left and right margins."""
        para = Paragraph(left_indent=1.0, right_indent=1.5)
        para.add_run(Run(text="Test"))

        escp = para.to_escp(page_width=8.5, page_cpi=10)

        assert b"\x1b\x6c\x0a" in escp  # ESC l 10
        assert b"\x1b\x51" in escp  # ESC Q (right margin)

    def test_to_escp_margin_clamping(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that margin exceeding MAX_INDENT is clamped during initialization."""
        # left_indent=30.0 exceeds MAX_INDENT (8.0), will be clamped in __post_init__
        with caplog.at_level(logging.WARNING):
            para = Paragraph(left_indent=30.0)  # Clamping happens HERE
            para.add_run(Run(text="Test"))

        # Verify clamping warning was logged
        assert "left_indent" in caplog.text
        assert "clamping" in caplog.text

        # Verify indent was clamped to MAX_INDENT
        assert para.left_indent == MAX_INDENT

        # Generate ESC/P should work without additional warnings
        escp = para.to_escp(page_cpi=10)

        # At 10 CPI: 8.0 inches = 80 chars < 255, so ESC l 80
        assert b"\x1b\x6c\x50" in escp  # 0x50 = 80 decimal

    def test_to_escp_margin_clamping_at_high_cpi(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that margin exceeding 255 chars is clamped in to_escp() at high CPI."""
        # left_indent=7.0" is valid (< MAX_INDENT 8.0)
        # But at 40 CPI: 7.0 * 40 = 280 chars > 255
        para = Paragraph(left_indent=7.0)
        para.add_run(Run(text="Test"))

        with caplog.at_level(logging.WARNING):
            escp = para.to_escp(page_cpi=40)

        # Should log warning about exceeding 255 and clamp
        assert "exceeds max 255" in caplog.text or "clamping" in caplog.text
        assert b"\x1b\x6c\xff" in escp  # ESC l 255 (max value)

    def test_to_escp_right_margin_less_than_left(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that right margin <= left margin is skipped."""
        para = Paragraph(left_indent=6.0, right_indent=3.0)  # Right < Left
        para.add_run(Run(text="Test"))

        with caplog.at_level(logging.WARNING):
            escp = para.to_escp(page_width=8.5, page_cpi=10)

        assert "Right margin position" in caplog.text
        assert "skipping right margin command" in caplog.text
        # Should have left margin but not right margin
        assert b"\x1b\x6c" in escp
        # Count ESC Q occurrences (should be 0)
        assert escp.count(b"\x1b\x51") == 0

    def test_to_escp_with_first_line_indent(self) -> None:
        """Test ESC/P generation with first line indent."""
        para = Paragraph(first_line_indent=0.5)  # 5 chars at 10 CPI
        para.add_run(Run(text="Test"))

        escp = para.to_escp(page_cpi=10)

        # Should have 5 spaces before text
        assert b"     Test" in escp or escp.count(b" ") >= 5

    def test_to_escp_with_space_before(self) -> None:
        """Test ESC/P generation with space before."""
        para = Paragraph(
            space_before=0.5, line_spacing=LineSpacing.ONE_SIXTH_INCH
        )  # 0.5" at 6 LPI = 3 lines
        para.add_run(Run(text="Test"))

        escp = para.to_escp()

        # Should have 3 line feeds before text
        assert escp.count(b"\n") >= 3

    def test_to_escp_with_space_after(self) -> None:
        """Test ESC/P generation with space after."""
        para = Paragraph(
            space_after=1.0, line_spacing=LineSpacing.ONE_SIXTH_INCH
        )  # 1" at 6 LPI = 6 lines
        para.add_run(Run(text="Test"))

        escp = para.to_escp()

        # Should have 6 line feeds after CR+LF
        assert escp.count(b"\n") >= 6

    def test_to_escp_center_alignment(self) -> None:
        """Test ESC/P generation with center alignment."""
        para = Paragraph(alignment=Alignment.CENTER)
        para.add_run(Run(text="Test"))

        escp = para.to_escp(page_width=8.5, page_cpi=10)

        # Should have padding spaces before text
        assert isinstance(escp, bytes)
        # Text should be present
        assert b"Test" in escp

    def test_to_escp_right_alignment(self) -> None:
        """Test ESC/P generation with right alignment."""
        para = Paragraph(alignment=Alignment.RIGHT)
        para.add_run(Run(text="Test"))

        escp = para.to_escp(page_width=8.5, page_cpi=10)

        # Should have padding spaces before text
        assert isinstance(escp, bytes)
        assert b"Test" in escp

    def test_to_escp_justify_alignment(self) -> None:
        """Test ESC/P generation with justify alignment (single line)."""
        para = Paragraph(alignment=Alignment.JUSTIFY)
        para.add_run(Run(text="Test"))

        escp = para.to_escp()

        # Justify behaves like LEFT for single line
        assert isinstance(escp, bytes)
        assert b"Test" in escp

    def test_to_escp_line_spacing_variants(self) -> None:
        """Test ESC/P generation with different line spacing."""
        test_cases = [
            (LineSpacing.ONE_SIXTH_INCH, b"\x1b\x32"),  # ESC 2
            (LineSpacing.ONE_EIGHTH_INCH, b"\x1b\x30"),  # ESC 0
            (LineSpacing.SEVEN_SEVENTYTWOTH_INCH, b"\x1b\x31"),  # ESC 1
        ]

        for line_spacing, expected_cmd in test_cases:
            para = Paragraph(line_spacing=line_spacing)
            para.add_run(Run(text="Test"))

            escp = para.to_escp()
            assert expected_cmd in escp

    def test_to_escp_invalid_page_width(self) -> None:
        """Test that invalid page_width raises ValueError."""
        para = Paragraph()
        para.add_run(Run(text="Test"))

        with pytest.raises(ValueError, match="page_width must be positive"):
            para.to_escp(page_width=0)

        with pytest.raises(ValueError, match="page_width must be positive"):
            para.to_escp(page_width=-1.0)

    def test_to_escp_invalid_page_cpi(self) -> None:
        """Test that invalid page_cpi raises ValueError."""
        para = Paragraph()
        para.add_run(Run(text="Test"))

        with pytest.raises(ValueError, match="page_cpi must be positive"):
            para.to_escp(page_cpi=0)

    def test_to_escp_multiple_runs(self) -> None:
        """Test ESC/P generation with multiple runs."""
        para = Paragraph()
        para.add_run(Run(text="Bold", style=TextStyle.BOLD))
        para.add_run(Run(text=" Normal"))

        escp = para.to_escp()

        assert b"Bold" in escp
        assert b"Normal" in escp


class TestParagraphCalculateWidth:
    """Test effective width calculation."""

    def test_calculate_width_no_indents(self) -> None:
        """Test width calculation with no indents."""
        para = Paragraph()
        width = para.calculate_width(8.5)

        assert width == 8.5

    def test_calculate_width_with_left_indent(self) -> None:
        """Test width calculation with left indent."""
        para = Paragraph(left_indent=1.0)
        width = para.calculate_width(8.5)

        assert width == 7.5

    def test_calculate_width_with_both_indents(self) -> None:
        """Test width calculation with both indents."""
        para = Paragraph(left_indent=1.0, right_indent=1.5)
        width = para.calculate_width(8.5)

        assert width == 6.0

    def test_calculate_width_invalid_page_width(self) -> None:
        """Test that invalid page_width raises ValueError."""
        para = Paragraph()

        with pytest.raises(ValueError, match="page_width must be positive"):
            para.calculate_width(0)

    def test_calculate_width_exceeding_indents(self) -> None:
        """Test that indents exceeding page width raise ValueError."""
        para = Paragraph(left_indent=5.0, right_indent=5.0)

        with pytest.raises(ValueError, match="exceed page width"):
            para.calculate_width(8.5)


class TestParagraphCalculateLinesForSpace:
    """Test line feed calculation for vertical spacing."""

    def test_calculate_lines_one_sixth_inch(self) -> None:
        """Test line calculation at 1/6 inch spacing (6 LPI)."""
        para = Paragraph(line_spacing=LineSpacing.ONE_SIXTH_INCH)

        assert para._calculate_lines_for_space(1.0) == 6
        assert para._calculate_lines_for_space(0.5) == 3

    def test_calculate_lines_one_eighth_inch(self) -> None:
        """Test line calculation at 1/8 inch spacing (8 LPI)."""
        para = Paragraph(line_spacing=LineSpacing.ONE_EIGHTH_INCH)

        assert para._calculate_lines_for_space(1.0) == 8
        assert para._calculate_lines_for_space(0.25) == 2

    def test_calculate_lines_seven_seventytwoth_inch(self) -> None:
        """Test line calculation at 7/72 inch spacing (~10 LPI)."""
        para = Paragraph(line_spacing=LineSpacing.SEVEN_SEVENTYTWOTH_INCH)

        # 72/7 ≈ 10.3, truncated to 10
        assert para._calculate_lines_for_space(1.0) == 10

    def test_calculate_lines_custom_spacing(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test line calculation with CUSTOM spacing (fallback to 6 LPI)."""
        para = Paragraph(line_spacing=LineSpacing.CUSTOM)

        with caplog.at_level(logging.WARNING):
            lines = para._calculate_lines_for_space(1.0)

        assert lines == 6  # Fallback
        assert "CUSTOM line spacing" in caplog.text


class TestParagraphOptimizeRuns:
    """Test run optimization."""

    def test_optimize_runs_mergeable(self) -> None:
        """Test optimizing runs with identical formatting."""
        para = Paragraph()
        para.add_run(Run(text="Hello", style=TextStyle.BOLD))
        para.add_run(Run(text=" ", style=TextStyle.BOLD))
        para.add_run(Run(text="World", style=TextStyle.BOLD))

        para.optimize_runs()

        assert len(para.runs) == 1
        assert para.runs[0].text == "Hello World"

    def test_optimize_runs_not_mergeable(self) -> None:
        """Test optimizing runs with different formatting."""
        para = Paragraph()
        para.add_run(Run(text="Bold", style=TextStyle.BOLD))
        para.add_run(Run(text="Italic", style=TextStyle.ITALIC))

        para.optimize_runs()

        assert len(para.runs) == 2

    def test_optimize_runs_single_run(self) -> None:
        """Test optimizing single run (no-op)."""
        para = Paragraph()
        para.add_run(Run(text="Single"))

        para.optimize_runs()

        assert len(para.runs) == 1

    def test_optimize_runs_empty_paragraph(self) -> None:
        """Test optimizing empty paragraph (no-op)."""
        para = Paragraph()

        para.optimize_runs()

        assert len(para.runs) == 0


class TestParagraphCopy:
    """Test paragraph copying."""

    def test_copy_creates_independent_instance(self) -> None:
        """Test that copy creates independent instance."""
        para = Paragraph(alignment=Alignment.CENTER, left_indent=1.0)
        para.add_run(Run(text="Test"))

        copied = para.copy()

        assert copied == para
        assert copied is not para
        assert copied.runs is not para.runs

    def test_copy_preserves_all_attributes(self) -> None:
        """Test that copy preserves all attributes."""
        para = Paragraph(
            alignment=Alignment.RIGHT,
            first_line_indent=0.5,
            left_indent=1.0,
            right_indent=1.5,
            line_spacing=LineSpacing.ONE_EIGHTH_INCH,
            space_before=0.25,
            space_after=0.5,
        )
        para.add_run(Run(text="Test"))

        copied = para.copy()

        assert copied.alignment == para.alignment
        assert copied.first_line_indent == para.first_line_indent
        assert copied.left_indent == para.left_indent
        assert copied.right_indent == para.right_indent
        assert copied.line_spacing == para.line_spacing
        assert copied.space_before == para.space_before
        assert copied.space_after == para.space_after

    def test_copy_modification_does_not_affect_original(self) -> None:
        """Test that modifying copy doesn't affect original."""
        para = Paragraph()
        para.add_run(Run(text="Original"))

        copied = para.copy()
        copied.runs[0].text = "Modified"

        assert para.runs[0].text == "Original"


class TestParagraphSerialization:
    """Test paragraph serialization."""

    def test_to_dict_minimal(self) -> None:
        """Test serialization with default values."""
        para = Paragraph()
        data: dict[str, Any] = para.to_dict()

        assert data == {
            "runs": [],
            "alignment": "left",
            "first_line_indent": 0.0,
            "left_indent": 0.0,
            "right_indent": 0.0,
            "line_spacing": "1/6",  # ← FULL VALUE
            "custom_line_spacing_value": None,  # ← ADD
            "space_before": 0.0,
            "space_after": 0.0,
            "tab_stops": [],  # ← ADD
        }

    def test_to_dict_full(self) -> None:
        """Test serialization with all attributes set."""
        para = Paragraph(
            alignment=Alignment.CENTER,
            first_line_indent=0.5,
            left_indent=1.0,
            right_indent=1.5,
            line_spacing=LineSpacing.ONE_EIGHTH_INCH,
            space_before=0.25,
            space_after=0.5,
        )
        para.add_run(Run(text="Test"))

        data: dict[str, Any] = para.to_dict()

        assert data["alignment"] == "center"
        assert data["line_spacing"] == "1/8"
        assert data["first_line_indent"] == 0.5
        assert len(data["runs"]) == 1

    def test_from_dict_invalid_type(self) -> None:
        """Test that non-dict input raises TypeError."""
        with pytest.raises(TypeError, match="Expected dict"):
            Paragraph.from_dict("not a dict")  # type: ignore[arg-type]

    def test_from_dict_invalid_alignment(self) -> None:
        """Test that invalid alignment value raises ValueError."""
        data = {"runs": [], "alignment": "invalid"}

        with pytest.raises(ValueError, match="Invalid alignment value"):
            Paragraph.from_dict(data)

    def test_from_dict_invalid_line_spacing(self) -> None:
        """Test that invalid line_spacing value raises ValueError."""
        data = {"runs": [], "line_spacing": "invalid"}

        with pytest.raises(ValueError, match="Invalid line_spacing value"):
            Paragraph.from_dict(data)

    def test_roundtrip_serialization(self) -> None:
        """Test that to_dict/from_dict roundtrip preserves data."""
        original = Paragraph(
            alignment=Alignment.RIGHT,
            left_indent=1.0,
            line_spacing=LineSpacing.ONE_EIGHTH_INCH,
        )
        original.add_run(Run(text="Test", style=TextStyle.BOLD))

        data = original.to_dict()
        restored = Paragraph.from_dict(data)

        assert restored == original


class TestParagraphMagicMethods:
    """Test magic methods."""

    def test_len(self) -> None:
        """Test __len__ returns total character count."""
        para = Paragraph()
        assert len(para) == 0

        para.add_run(Run(text="Hello"))
        assert len(para) == 5

        para.add_run(Run(text=" World"))
        assert len(para) == 11

    def test_eq_identical_paragraphs(self) -> None:
        """Test that identical paragraphs are equal."""
        para1 = Paragraph(alignment=Alignment.CENTER, left_indent=1.0)
        para1.add_run(Run(text="Test"))

        para2 = Paragraph(alignment=Alignment.CENTER, left_indent=1.0)
        para2.add_run(Run(text="Test"))

        assert para1 == para2

    def test_eq_different_attributes(self) -> None:
        """Test that paragraphs with different attributes are not equal."""
        para1 = Paragraph(alignment=Alignment.LEFT)
        para2 = Paragraph(alignment=Alignment.RIGHT)

        assert para1 != para2

    def test_eq_with_non_paragraph(self) -> None:
        """Test comparison with non-Paragraph objects."""
        para = Paragraph()

        assert (para == "not a paragraph") is False
        assert (para == None) is False

    def test_repr(self) -> None:
        """Test __repr__ output."""
        para = Paragraph(alignment=Alignment.CENTER)
        para.add_run(Run(text="Test"))

        repr_str = repr(para)

        assert "Paragraph(" in repr_str
        assert "runs=1" in repr_str
        assert "chars=4" in repr_str
        assert "alignment='center'" in repr_str


class TestMergeParagraphs:
    """Test merge_paragraphs utility function."""

    def test_merge_two_paragraphs(self) -> None:
        """Test merging two paragraphs."""
        para1 = Paragraph()
        para1.add_run(Run(text="First"))

        para2 = Paragraph()
        para2.add_run(Run(text="Second"))

        merged = merge_paragraphs([para1, para2], separator=" ")

        assert merged.get_text() == "First Second"
        assert len(merged.runs) == 3  # First + separator + Second

    def test_merge_preserves_first_formatting(self) -> None:
        """Test that merge uses first paragraph's formatting."""
        para1 = Paragraph(alignment=Alignment.CENTER, left_indent=1.0)
        para1.add_run(Run(text="First"))

        para2 = Paragraph(alignment=Alignment.RIGHT, left_indent=2.0)
        para2.add_run(Run(text="Second"))

        merged = merge_paragraphs([para1, para2])

        assert merged.alignment == Alignment.CENTER
        assert merged.left_indent == 1.0

    def test_merge_empty_list(self) -> None:
        """Test that merging empty list raises ValueError."""
        with pytest.raises(ValueError, match="Cannot merge empty list"):
            merge_paragraphs([])

    def test_merge_without_separator(self) -> None:
        """Test merging without separator."""
        para1 = Paragraph()
        para1.add_run(Run(text="First"))

        para2 = Paragraph()
        para2.add_run(Run(text="Second"))

        merged = merge_paragraphs([para1, para2], separator="")

        assert merged.get_text() == "FirstSecond"


class TestSplitParagraphAt:
    """Test split_paragraph_at utility function."""

    def test_split_paragraph(self) -> None:
        """Test splitting paragraph at specific index."""
        para = Paragraph()
        para.add_run(Run(text="A"))
        para.add_run(Run(text="B"))
        para.add_run(Run(text="C"))

        first, second = split_paragraph_at(para, 1)

        assert first.get_text() == "A"
        assert second.get_text() == "BC"

    def test_split_preserves_formatting(self) -> None:
        """Test that split preserves formatting in both paragraphs."""
        para = Paragraph(alignment=Alignment.CENTER, left_indent=1.0)
        para.add_run(Run(text="A"))
        para.add_run(Run(text="B"))

        first, second = split_paragraph_at(para, 1)

        assert first.alignment == Alignment.CENTER
        assert first.left_indent == 1.0
        assert second.alignment == Alignment.CENTER
        assert second.left_indent == 1.0

    def test_split_invalid_index(self) -> None:
        """Test that invalid split index raises ValueError."""
        para = Paragraph()
        para.add_run(Run(text="A"))

        with pytest.raises(ValueError, match="Split index .* must be in range"):
            split_paragraph_at(para, 0)  # Must be > 0

        with pytest.raises(ValueError, match="Split index .* must be in range"):
            split_paragraph_at(para, 5)  # Must be < len(runs)


class TestParagraphEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_paragraph_to_escp(self) -> None:
        """Test ESC/P generation for empty paragraph."""
        para = Paragraph()

        escp = para.to_escp()

        assert isinstance(escp, bytes)
        assert b"\x1b\x32" in escp  # Line spacing
        assert b"\r\n" in escp  # Line break

    def test_paragraph_with_only_whitespace(self) -> None:
        """Test paragraph containing only whitespace."""
        para = Paragraph()
        para.add_run(Run(text="   "))

        assert para.get_text() == "   "
        assert len(para) == 3

    def test_very_long_text(self) -> None:
        """Test paragraph with very long text."""
        para = Paragraph()
        long_text = "A" * 1000
        para.add_run(Run(text=long_text))

        assert len(para) == 1000
        assert para.get_text() == long_text

    @pytest.mark.parametrize("alignment", list(Alignment))
    def test_all_alignment_values(self, alignment: Alignment) -> None:
        """Test all alignment enum values."""
        para = Paragraph(alignment=alignment)
        para.add_run(Run(text="Test"))

        para.validate()
        escp = para.to_escp()
        assert isinstance(escp, bytes)

    @pytest.mark.parametrize(
        "line_spacing",
        [
            LineSpacing.ONE_SIXTH_INCH,
            LineSpacing.ONE_EIGHTH_INCH,
            LineSpacing.SEVEN_SEVENTYTWOTH_INCH,
        ],
    )
    def test_all_line_spacing_values(self, line_spacing: LineSpacing) -> None:
        """Test all line spacing enum values (except CUSTOM)."""
        para = Paragraph(line_spacing=line_spacing)
        para.add_run(Run(text="Test"))

        para.validate()
        escp = para.to_escp()
        assert isinstance(escp, bytes)


class TestParagraphIntegration:
    """Integration tests combining multiple features."""

    def test_full_workflow(self) -> None:
        """Test complete workflow: create, validate, serialize, generate ESC/P."""
        para = Paragraph(
            alignment=Alignment.CENTER,
            left_indent=1.0,
            line_spacing=LineSpacing.ONE_EIGHTH_INCH,
        )
        para.add_run(Run(text="Hello ", style=TextStyle.BOLD))
        para.add_run(Run(text="World"))

        # Validate
        para.validate()

        # Serialize
        data = para.to_dict()
        restored = Paragraph.from_dict(data)
        assert restored == para

        # Generate ESC/P
        escp = para.to_escp()
        assert isinstance(escp, bytes)
        assert b"Hello" in escp
        assert b"World" in escp

    def test_optimize_then_generate_escp(self) -> None:
        """Test optimizing runs then generating ESC/P."""
        para = Paragraph()
        para.add_run(Run(text="A", style=TextStyle.BOLD))
        para.add_run(Run(text="B", style=TextStyle.BOLD))
        para.add_run(Run(text="C", style=TextStyle.BOLD))

        para.optimize_runs()
        assert len(para.runs) == 1

        escp = para.to_escp()
        assert b"ABC" in escp


class TestParagraphMetrics:
    """Test paragraph metrics calculation."""

    def test_calculate_metrics_basic(self) -> None:
        """Test basic metrics calculation."""
        para = Paragraph()
        para.add_run(Run(text="Test"))

        metrics = para.calculate_metrics()

        assert isinstance(metrics, ParagraphMetrics)
        assert metrics.character_count == 4
        assert metrics.width_inches == 8.5  # Full page width, no indents
        assert metrics.line_count == 1

    def test_calculate_metrics_with_indents(self) -> None:
        """Test metrics with indents."""
        para = Paragraph(left_indent=1.0, right_indent=1.5)
        para.add_run(Run(text="Test"))

        metrics = para.calculate_metrics(page_width=8.5, page_cpi=10)

        assert metrics.width_inches == 6.0  # 8.5 - 1.0 - 1.5
        assert metrics.left_margin_chars == 10  # 1.0" * 10 CPI
        assert metrics.right_margin_chars == 70  # (8.5 - 1.5) * 10

    def test_calculate_metrics_with_spacing(self) -> None:
        """Test metrics with vertical spacing."""
        para = Paragraph(space_before=0.5, space_after=0.5, line_spacing=LineSpacing.ONE_SIXTH_INCH)
        para.add_run(Run(text="Test"))

        metrics = para.calculate_metrics()

        # 0.5" before at 6 LPI = 3 lines
        # 1 line for content
        # 0.5" after at 6 LPI = 3 lines
        # Total = 7 lines
        assert metrics.line_count == 7
        assert metrics.height_inches == pytest.approx(7 / 6, rel=0.01)

    def test_metrics_to_dict(self) -> None:
        """Test metrics serialization."""
        para = Paragraph()
        para.add_run(Run(text="Test"))

        metrics = para.calculate_metrics()
        data = metrics.to_dict()

        assert isinstance(data, dict)
        assert "width_inches" in data
        assert "character_count" in data
        assert data["character_count"] == 4


class TestParagraphBulkOperations:
    """Test bulk run operations."""

    def test_add_runs(self) -> None:
        """Test bulk adding runs."""
        para = Paragraph()
        runs = [
            Run(text="A"),
            Run(text="B"),
            Run(text="C"),
        ]

        para.add_runs(runs)

        assert para.get_run_count() == 3
        assert para.get_text() == "ABC"

    def test_add_runs_empty_list(self) -> None:
        """Test add_runs with empty list."""
        para = Paragraph()
        para.add_runs([])

        assert para.get_run_count() == 0

    def test_add_runs_invalid_type(self) -> None:
        """Test add_runs with invalid type."""
        para = Paragraph()

        with pytest.raises(TypeError, match="runs must be list"):
            para.add_runs("not a list")  # type: ignore

    def test_add_runs_invalid_elements(self) -> None:
        """Test add_runs with non-Run elements."""
        para = Paragraph()

        with pytest.raises(TypeError, match="All elements must be Run"):
            para.add_runs([Run(text="OK"), "not a run"])  # type: ignore

    def test_replace_runs(self) -> None:
        """Test replacing all runs."""
        para = Paragraph()
        para.add_run(Run(text="Old"))

        new_runs = [Run(text="New1"), Run(text="New2")]
        para.replace_runs(new_runs)

        assert para.get_run_count() == 2
        assert para.get_text() == "New1New2"

    def test_extend_text(self) -> None:
        """Test convenience text extension."""
        para = Paragraph()

        para.extend_text("Bold", style=TextStyle.BOLD)
        para.extend_text(" Normal")

        assert para.get_run_count() == 2
        assert para.get_text() == "Bold Normal"

    def test_extend_text_empty(self) -> None:
        """Test extend_text with empty string."""
        para = Paragraph()
        para.extend_text("")

        assert para.get_run_count() == 0


class TestParagraphMarginReset:
    """Test margin reset functionality."""

    def test_to_escp_with_margin_reset(self) -> None:
        """Test that margins are reset by default."""
        para = Paragraph(left_indent=1.0, right_indent=1.5)
        para.add_run(Run(text="Test"))

        escp = para.to_escp(reset_margins=True)

        # Should contain margin set commands
        assert b"\x1b\x6c" in escp  # ESC l (left margin)
        assert b"\x1b\x51" in escp  # ESC Q (right margin)

        # Should contain margin reset commands
        assert b"\x1b\x6c\x00" in escp  # ESC l 0
        assert b"\x1b\x51\x00" in escp  # ESC Q 0

    def test_to_escp_without_margin_reset(self) -> None:
        """Test margin reset can be disabled."""
        para = Paragraph(left_indent=1.0)
        para.add_run(Run(text="Test"))

        escp = para.to_escp(reset_margins=False)

        # Should contain margin set
        assert b"\x1b\x6c" in escp

        # Should NOT contain margin reset at end
        # (checking that ESC l 0 is not at the end)
        assert not escp.endswith(b"\x1b\x6c\x00")


# =============================================================================
# TESTS FOR NEW FEATURES (Version 2.1)
# =============================================================================


class TestParagraphCustomLineSpacing:
    """Test custom line spacing with ESC 3 n."""

    def test_custom_line_spacing_valid(self) -> None:
        """Test custom line spacing with valid value."""
        para = Paragraph(
            line_spacing=LineSpacing.CUSTOM, custom_line_spacing_value=36  # 36/216" = 1/6"
        )
        para.add_run(Run(text="Test"))

        escp = para.to_escp()

        # Should contain ESC 3 36
        assert b"\x1b\x33\x24" in escp  # 0x24 = 36 decimal

    def test_custom_line_spacing_clamping(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test custom line spacing value clamping."""
        with caplog.at_level(logging.WARNING):
            para = Paragraph(
                line_spacing=LineSpacing.CUSTOM, custom_line_spacing_value=300  # > 255
            )

        assert para.custom_line_spacing_value == 255
        assert "custom_line_spacing_value" in caplog.text
        assert "clamping" in caplog.text

    def test_custom_line_spacing_without_value(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test custom line spacing without value."""
        with caplog.at_level(logging.WARNING):
            para = Paragraph(line_spacing=LineSpacing.CUSTOM)
            para.add_run(Run(text="Test"))

        assert "CUSTOM line spacing without value" in caplog.text

    def test_custom_line_spacing_lpi_calculation(self) -> None:
        """Test LPI calculation with custom line spacing."""
        para = Paragraph(
            line_spacing=LineSpacing.CUSTOM, custom_line_spacing_value=36  # 216/36 = 6 LPI
        )

        lines = para._calculate_lines_for_space(1.0)
        assert lines == 6


class TestParagraphCaching:
    """Test ESC/P caching functionality."""

    def test_cache_hit(self) -> None:
        """Test that cache returns same result."""
        para = Paragraph()
        para.add_run(Run(text="Test"))

        escp1 = para.to_escp(use_cache=True)
        escp2 = para.to_escp(use_cache=True)

        assert escp1 == escp2
        assert escp1 is escp2  # Same object

    def test_cache_invalidation_on_add_run(self) -> None:
        """Test cache invalidation when adding run."""
        para = Paragraph()
        para.add_run(Run(text="Test1"))

        escp1 = para.to_escp(use_cache=True)

        para.add_run(Run(text="Test2"))

        escp2 = para.to_escp(use_cache=True)

        assert escp1 != escp2

    def test_cache_disabled(self) -> None:
        """Test generation with caching disabled."""
        para = Paragraph()
        para.add_run(Run(text="Test"))

        escp1 = para.to_escp(use_cache=False)
        escp2 = para.to_escp(use_cache=False)

        assert escp1 == escp2
        assert escp1 is not escp2  # Different objects

    def test_cache_different_parameters(self) -> None:
        """Test that cache stores different parameter combinations."""
        para = Paragraph(left_indent=1.0)  # ← ADD indent (зависит от CPI)
        para.add_run(Run(text="Test"))

        escp_10cpi = para.to_escp(page_cpi=10, use_cache=True)
        escp_12cpi = para.to_escp(page_cpi=12, use_cache=True)

        assert escp_10cpi != escp_12cpi  # Теперь будет разный!

    def test_get_cache_stats(self) -> None:
        """Test cache statistics."""
        para = Paragraph()
        para.add_run(Run(text="Test"))

        para.to_escp(use_cache=True)
        para.to_escp(page_cpi=12, use_cache=True)

        stats = para.get_cache_stats()

        assert stats["size"] == 2
        assert stats["max_size"] == 10
        assert stats["current_hash"] is not None

    def test_cache_eviction(self) -> None:
        """Test LRU cache eviction when limit reached."""
        para = Paragraph()
        para.add_run(Run(text="Test"))

        # Fill cache beyond limit
        for i in range(12):
            para.to_escp(page_cpi=10 + i, use_cache=True)

        stats = para.get_cache_stats()
        assert stats["size"] <= 10  # Should not exceed MAX_CACHE_SIZE


class TestParagraphTabStops:
    """Test tab stop functionality."""

    def test_set_tab_stops(self) -> None:
        """Test setting tab stops."""
        para = Paragraph()
        para.set_tab_stops([10, 20, 30, 40])

        assert len(para.tab_stops) == 4
        assert para.tab_stops[0].position == 10
        assert para.tab_stops[3].position == 40

    def test_set_tab_stops_deduplication(self) -> None:
        """Test tab stop deduplication."""
        para = Paragraph()
        para.set_tab_stops([10, 20, 10, 30, 20])  # Duplicates

        assert len(para.tab_stops) == 3
        positions = [t.position for t in para.tab_stops]
        assert positions == [10, 20, 30]

    def test_set_tab_stops_sorting(self) -> None:
        """Test tab stops are sorted."""
        para = Paragraph()
        para.set_tab_stops([30, 10, 20])

        positions = [t.position for t in para.tab_stops]
        assert positions == [10, 20, 30]

    def test_set_tab_stops_exceeds_limit(self) -> None:
        """Test that exceeding max tab stops raises error."""
        para = Paragraph()

        with pytest.raises(ValueError, match="Maximum 32 tab stops"):
            para.set_tab_stops(list(range(1, 40)))

    def test_set_tab_stops_invalid_position(self) -> None:
        """Test invalid tab position."""
        para = Paragraph()

        with pytest.raises(ValueError, match="Tab position must be 1-255"):
            para.set_tab_stops([0])

        with pytest.raises(ValueError, match="Tab position must be 1-255"):
            para.set_tab_stops([256])

    def test_tab_stops_in_escp(self) -> None:
        """Test tab stops in ESC/P output."""
        para = Paragraph()
        para.set_tab_stops([10, 20, 30])
        para.add_run(Run(text="Test"))

        escp = para.to_escp()

        # Should contain ESC D 10 20 30 NUL
        assert b"\x1b\x44" in escp  # ESC D
        assert b"\x0a\x14\x1e\x00" in escp  # 10, 20, 30, NUL

    def test_clear_tab_stops(self) -> None:
        """Test clearing tab stops."""
        para = Paragraph()
        para.set_tab_stops([10, 20, 30])

        para.clear_tab_stops()

        assert len(para.tab_stops) == 0


class TestParagraphWordWrapping:
    """Test word wrapping functionality."""

    def test_wrap_text_simple(self) -> None:
        """Test basic word wrapping."""
        para = Paragraph()
        para.add_run(Run(text="This is a long paragraph that needs wrapping"))

        lines = para.wrap_text(max_width_chars=20)

        assert len(lines) >= 2
        assert all(isinstance(line, WrappedLine) for line in lines)
        assert lines[-1].is_last

    def test_wrap_text_short_enough(self) -> None:
        """Test text that doesn't need wrapping."""
        para = Paragraph()
        para.add_run(Run(text="Short text"))

        lines = para.wrap_text(max_width_chars=50)

        assert len(lines) == 1
        assert lines[0].is_last

    def test_wrap_text_exact_width(self) -> None:
        """Test text exactly at max width."""
        para = Paragraph()
        para.add_run(Run(text="12345678901234567890"))  # 20 chars

        lines = para.wrap_text(max_width_chars=20)

        assert len(lines) == 1

    def test_wrap_text_break_long_words(self) -> None:
        """Test breaking long words."""
        para = Paragraph()
        para.add_run(Run(text="Supercalifragilisticexpialidocious"))

        lines = para.wrap_text(max_width_chars=10, break_long_words=True)

        assert len(lines) > 1

    def test_wrap_text_no_break_long_words(self) -> None:
        """Test not breaking long words (overflow)."""
        para = Paragraph()
        para.add_run(Run(text="Supercalifragilisticexpialidocious"))

        lines = para.wrap_text(max_width_chars=10, break_long_words=False)

        # Word exceeds limit but won't break
        assert len(lines) == 1
        assert lines[0].width_chars > 10

    def test_wrap_text_preserves_formatting(self) -> None:
        """Test that wrapping preserves run formatting."""
        para = Paragraph()
        para.add_run(Run(text="Bold text ", style=TextStyle.BOLD))
        para.add_run(Run(text="normal text"))

        lines = para.wrap_text(max_width_chars=15)

        # Check that formatting is preserved in wrapped runs
        assert any(run.text for run in lines[0].runs)

    def test_wrap_text_invalid_width(self) -> None:
        """Test invalid max_width_chars."""
        para = Paragraph()
        para.add_run(Run(text="Test"))

        with pytest.raises(ValueError, match="max_width_chars must be >= 1"):
            para.wrap_text(max_width_chars=0)

    def test_wrap_text_empty_paragraph(self) -> None:
        """Test wrapping empty paragraph."""
        para = Paragraph()

        lines = para.wrap_text(max_width_chars=20)

        assert lines == []


class TestParagraphJustification:
    """Test text justification functionality."""

    def test_justify_line_adds_spaces(self) -> None:
        """Test that justification adds spaces between words."""
        para = Paragraph()
        para.add_run(Run(text="Test"))
        para.add_run(Run(text=" "))
        para.add_run(Run(text="Text"))

        wrapped_line = WrappedLine(
            runs=[Run(text="Test"), Run(text=" "), Run(text="Text")],
            width_chars=9,  # "Test Text"
            is_last=False,
        )

        justified = para._justify_line(wrapped_line, target_width=20)

        # Should have more runs due to added spacing
        assert len(justified) > len(wrapped_line.runs)

    def test_justify_line_last_line_unchanged(self) -> None:
        """Test that last line is not justified."""
        para = Paragraph()

        wrapped_line = WrappedLine(runs=[Run(text="Last line")], width_chars=9, is_last=True)

        justified = para._justify_line(wrapped_line, target_width=20)

        assert justified == wrapped_line.runs

    def test_justify_line_already_full(self) -> None:
        """Test justification of already full line."""
        para = Paragraph()

        wrapped_line = WrappedLine(
            runs=[Run(text="Full line text here")], width_chars=20, is_last=False
        )

        justified = para._justify_line(wrapped_line, target_width=20)

        # Should not add spaces if already at target
        assert justified == wrapped_line.runs

    def test_to_escp_with_wrapping_basic(self) -> None:
        """Test ESC/P generation with wrapping."""
        para = Paragraph()
        para.add_run(Run(text="This is a long paragraph that needs wrapping for testing"))

        escp = para.to_escp_with_wrapping(page_width=8.5, page_cpi=10)

        assert isinstance(escp, bytes)
        assert b"This" in escp
        assert b"\r\n" in escp

    def test_to_escp_with_wrapping_and_justification(self) -> None:
        """Test wrapping with justify alignment."""
        para = Paragraph(alignment=Alignment.JUSTIFY)
        # Longer text to force wrapping (150+ chars)
        para.add_run(
            Run(
                text=(
                    "This is a very long paragraph that definitely needs wrapping "
                    "and justification to demonstrate the word wrap functionality "
                    "working correctly with multiple lines of text content"
                )
            )
        )

        escp = para.to_escp_with_wrapping(page_width=8.5, page_cpi=10)

        assert isinstance(escp, bytes)
        # Should have multiple line breaks for wrapped lines
        assert escp.count(b"\r\n") > 1

    def test_to_escp_with_wrapping_empty_paragraph(self) -> None:
        """Test wrapping empty paragraph falls back to standard generation."""
        para = Paragraph()

        escp = para.to_escp_with_wrapping()

        assert isinstance(escp, bytes)
        assert b"\x1b\x32" in escp  # Line spacing

    def test_to_escp_with_wrapping_respects_margins(self) -> None:
        """Test that wrapping respects left/right margins."""
        para = Paragraph(left_indent=1.0, right_indent=1.0)
        para.add_run(Run(text="This is a long paragraph that needs wrapping"))

        escp = para.to_escp_with_wrapping(page_width=8.5, page_cpi=10)

        # Should contain margin commands
        assert b"\x1b\x6c" in escp  # ESC l
        assert b"\x1b\x51" in escp  # ESC Q


class TestParagraphSerializationExtended:
    """Test serialization with new attributes."""

    def test_to_dict_with_custom_line_spacing(self) -> None:
        """Test serialization with custom line spacing."""
        para = Paragraph(line_spacing=LineSpacing.CUSTOM, custom_line_spacing_value=36)

        data = para.to_dict()

        assert data["line_spacing"] == "custom"
        assert data["custom_line_spacing_value"] == 36

    def test_to_dict_with_tab_stops(self) -> None:
        """Test serialization with tab stops."""
        para = Paragraph()
        para.set_tab_stops([10, 20, 30])

        data = para.to_dict()

        assert "tab_stops" in data
        assert len(data["tab_stops"]) == 3
        assert data["tab_stops"][0]["position"] == 10

    def test_from_dict_with_tab_stops(self) -> None:
        """Test deserialization with tab stops."""
        data = {
            "runs": [],
            "alignment": "left",
            "tab_stops": [
                {"position": 10, "alignment": "left"},
                {"position": 20, "alignment": "left"},
            ],
        }

        para = Paragraph.from_dict(data)

        assert len(para.tab_stops) == 2
        assert para.tab_stops[0].position == 10

    def test_roundtrip_with_all_new_features(self) -> None:
        """Test roundtrip serialization with all new features."""
        original = Paragraph(line_spacing=LineSpacing.CUSTOM, custom_line_spacing_value=36)
        original.set_tab_stops([10, 20, 30])
        original.add_run(Run(text="Test"))

        data = original.to_dict()
        restored = Paragraph.from_dict(data)

        assert restored.line_spacing == original.line_spacing
        assert restored.custom_line_spacing_value == original.custom_line_spacing_value
        assert len(restored.tab_stops) == len(original.tab_stops)


class TestParagraphIntegrationAdvanced:
    """Advanced integration tests with new features."""

    def test_full_workflow_with_new_features(self) -> None:
        """Test complete workflow with all new features."""
        para = Paragraph(
            alignment=Alignment.JUSTIFY,
            line_spacing=LineSpacing.CUSTOM,
            custom_line_spacing_value=36,
            left_indent=1.0,
        )
        para.set_tab_stops([10, 20, 30])
        para.add_run(Run(text="This is a comprehensive test of all features"))

        # Validate
        para.validate()

        # Wrap
        lines = para.wrap_text(max_width_chars=30)
        assert len(lines) >= 1

        # Generate ESC/P with wrapping
        escp = para.to_escp_with_wrapping(page_width=8.5, page_cpi=10)
        assert isinstance(escp, bytes)

        # Serialize
        data = para.to_dict()
        restored = Paragraph.from_dict(data)
        assert restored.line_spacing == para.line_spacing

    def test_caching_with_tab_stops(self) -> None:
        """Test that cache is invalidated when tab stops change."""
        para = Paragraph()
        para.add_run(Run(text="Test"))

        escp1 = para.to_escp(use_cache=True)

        para.set_tab_stops([10, 20, 30])

        escp2 = para.to_escp(use_cache=True)

        # Cache should be invalidated
        assert escp1 != escp2

    def test_metrics_with_custom_line_spacing(self) -> None:
        """Test metrics calculation with custom line spacing."""
        para = Paragraph(line_spacing=LineSpacing.CUSTOM, custom_line_spacing_value=36)  # 6 LPI
        para.add_run(Run(text="Test"))

        metrics = para.calculate_metrics()

        assert metrics.line_count == 1
        # Height should be 1 line / 6 LPI = 1/6 inch
        assert metrics.height_inches == pytest.approx(1 / 6, rel=0.01)
