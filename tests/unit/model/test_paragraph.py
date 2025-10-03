"""
Unit tests for src/model/paragraph.py module.

Tests cover Paragraph class functionality, alignment, indentation,
run manipulation, validation, serialization, and utility functions.
"""

import logging
from typing import Any

import pytest

from src.model.paragraph import (
    MAX_INDENT,
    MAX_LINE_SPACING,
    MAX_SPACE,
    MIN_INDENT,
    MIN_LINE_SPACING,
    MIN_SPACE,
    Alignment,
    Paragraph,
    merge_paragraphs,
    split_paragraph_at,
)
from src.model.run import Run


class TestAlignment:
    """Test Alignment enum."""

    def test_alignment_values(self) -> None:
        """Test that all alignment values are defined."""
        assert Alignment.LEFT.value == "left"
        assert Alignment.CENTER.value == "center"
        assert Alignment.RIGHT.value == "right"
        assert Alignment.JUSTIFY.value == "justify"

    def test_alignment_from_string(self) -> None:
        """Test creating alignment from string value."""
        assert Alignment("left") == Alignment.LEFT
        assert Alignment("center") == Alignment.CENTER
        assert Alignment("right") == Alignment.RIGHT
        assert Alignment("justify") == Alignment.JUSTIFY

    def test_alignment_invalid_string(self) -> None:
        """Test that invalid string raises ValueError."""
        with pytest.raises(ValueError):
            Alignment("invalid")


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
        assert para.line_spacing == 1.0
        assert para.space_before == 0.0
        assert para.space_after == 0.0

    def test_full_initialization(self) -> None:
        """Test creating paragraph with all parameters."""
        runs = [Run(text="Test")]
        para = Paragraph(
            runs=runs,
            alignment=Alignment.CENTER,
            first_line_indent=0.5,
            left_indent=1.0,
            right_indent=1.0,
            line_spacing=1.5,
            space_before=0.25,
            space_after=0.25,
        )

        assert len(para.runs) == 1
        assert para.alignment == Alignment.CENTER
        assert para.first_line_indent == 0.5
        assert para.left_indent == 1.0
        assert para.right_indent == 1.0
        assert para.line_spacing == 1.5
        assert para.space_before == 0.25
        assert para.space_after == 0.25

    def test_indent_clamping_too_high(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that excessive indent values are clamped."""
        with caplog.at_level(logging.WARNING):
            para = Paragraph(
                first_line_indent=100.0,
                left_indent=100.0,
                right_indent=100.0,
            )

        assert para.first_line_indent == MAX_INDENT
        assert para.left_indent == MAX_INDENT
        assert para.right_indent == MAX_INDENT
        assert "out of range" in caplog.text

    def test_indent_clamping_negative(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that negative indent values are clamped to zero."""
        with caplog.at_level(logging.WARNING):
            para = Paragraph(
                first_line_indent=-1.0,
                left_indent=-1.0,
                right_indent=-1.0,
            )

        assert para.first_line_indent == MIN_INDENT
        assert para.left_indent == MIN_INDENT
        assert para.right_indent == MIN_INDENT

    def test_line_spacing_clamping(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that line spacing is clamped to valid range."""
        with caplog.at_level(logging.WARNING):
            para1 = Paragraph(line_spacing=0.1)
            para2 = Paragraph(line_spacing=10.0)

        assert para1.line_spacing == MIN_LINE_SPACING
        assert para2.line_spacing == MAX_LINE_SPACING

    def test_space_clamping(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that space before/after is clamped."""
        with caplog.at_level(logging.WARNING):
            para = Paragraph(space_before=-1.0, space_after=10.0)

        assert para.space_before == MIN_SPACE
        assert para.space_after == MAX_SPACE

    def test_runs_not_list_conversion(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that non-list runs are converted to list."""
        with caplog.at_level(logging.WARNING):
            para = Paragraph(runs=(Run(text="A"), Run(text="B")))  # type: ignore[arg-type]

        assert isinstance(para.runs, list)
        assert len(para.runs) == 2


class TestRunManipulation:
    """Test methods for adding, inserting, and removing runs."""

    def test_add_run(self) -> None:
        """Test adding runs to paragraph."""
        para = Paragraph()
        run1 = Run(text="First")
        run2 = Run(text="Second")

        para.add_run(run1)
        assert len(para.runs) == 1
        assert para.runs[0] == run1

        para.add_run(run2)
        assert len(para.runs) == 2
        assert para.runs[1] == run2

    def test_add_run_invalid_type(self) -> None:
        """Test that adding non-Run raises TypeError."""
        para = Paragraph()

        with pytest.raises(TypeError, match="Expected Run instance"):
            para.add_run("not a run")  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="Expected Run instance"):
            para.add_run(None)  # type: ignore[arg-type]

    def test_insert_run_at_start(self) -> None:
        """Test inserting run at the beginning."""
        para = Paragraph()
        para.add_run(Run(text="Second"))
        para.insert_run(0, Run(text="First"))

        assert para.runs[0].text == "First"
        assert para.runs[1].text == "Second"

    def test_insert_run_at_middle(self) -> None:
        """Test inserting run in the middle."""
        para = Paragraph()
        para.add_run(Run(text="First"))
        para.add_run(Run(text="Third"))
        para.insert_run(1, Run(text="Second"))

        assert para.runs[0].text == "First"
        assert para.runs[1].text == "Second"
        assert para.runs[2].text == "Third"

    def test_insert_run_at_end(self) -> None:
        """Test inserting run at the end."""
        para = Paragraph()
        para.add_run(Run(text="First"))
        para.insert_run(1, Run(text="Second"))

        assert para.runs[1].text == "Second"

    def test_insert_run_invalid_index(self) -> None:
        """Test that invalid insert index raises IndexError."""
        para = Paragraph()
        para.add_run(Run(text="Test"))

        with pytest.raises(IndexError, match="out of range"):
            para.insert_run(-1, Run(text="Invalid"))

        with pytest.raises(IndexError, match="out of range"):
            para.insert_run(10, Run(text="Invalid"))

    def test_insert_run_invalid_type(self) -> None:
        """Test that inserting non-Run raises TypeError."""
        para = Paragraph()

        with pytest.raises(TypeError, match="Expected Run instance"):
            para.insert_run(0, "not a run")  # type: ignore[arg-type]

    def test_remove_run(self) -> None:
        """Test removing run by index."""
        para = Paragraph()
        run1 = Run(text="First")
        run2 = Run(text="Second")
        para.add_run(run1)
        para.add_run(run2)

        removed = para.remove_run(0)
        assert removed == run1
        assert len(para.runs) == 1
        assert para.runs[0] == run2

    def test_remove_run_invalid_index(self) -> None:
        """Test that invalid remove index raises IndexError."""
        para = Paragraph()
        para.add_run(Run(text="Test"))

        with pytest.raises(IndexError, match="out of range"):
            para.remove_run(-1)

        with pytest.raises(IndexError, match="out of range"):
            para.remove_run(10)

    def test_clear_runs(self) -> None:
        """Test clearing all runs from paragraph."""
        para = Paragraph()
        para.add_run(Run(text="A"))
        para.add_run(Run(text="B"))
        para.add_run(Run(text="C"))

        para.clear_runs()
        assert len(para.runs) == 0
        assert para.runs == []

    def test_clear_runs_empty_paragraph(self) -> None:
        """Test clearing runs from empty paragraph."""
        para = Paragraph()
        para.clear_runs()
        assert len(para.runs) == 0


class TestParagraphText:
    """Test text retrieval and counting methods."""

    def test_get_text_empty(self) -> None:
        """Test getting text from empty paragraph."""
        para = Paragraph()
        assert para.get_text() == ""

    def test_get_text_single_run(self) -> None:
        """Test getting text with single run."""
        para = Paragraph()
        para.add_run(Run(text="Hello World"))
        assert para.get_text() == "Hello World"

    def test_get_text_multiple_runs(self) -> None:
        """Test getting text with multiple runs."""
        para = Paragraph()
        para.add_run(Run(text="Hello "))
        para.add_run(Run(text="World"))
        para.add_run(Run(text="!"))
        assert para.get_text() == "Hello World!"

    def test_get_text_with_formatting(self) -> None:
        """Test that get_text ignores formatting."""
        para = Paragraph()
        para.add_run(Run(text="Bold", bold=True))
        para.add_run(Run(text=" "))
        para.add_run(Run(text="Italic", italic=True))
        assert para.get_text() == "Bold Italic"

    def test_get_run_count(self) -> None:
        """Test counting runs."""
        para = Paragraph()
        assert para.get_run_count() == 0

        para.add_run(Run(text="A"))
        assert para.get_run_count() == 1

        para.add_run(Run(text="B"))
        para.add_run(Run(text="C"))
        assert para.get_run_count() == 3

    def test_len_empty(self) -> None:
        """Test __len__ on empty paragraph."""
        para = Paragraph()
        assert len(para) == 0

    def test_len_single_run(self) -> None:
        """Test __len__ with single run."""
        para = Paragraph()
        para.add_run(Run(text="Hello"))
        assert len(para) == 5

    def test_len_multiple_runs(self) -> None:
        """Test __len__ with multiple runs."""
        para = Paragraph()
        para.add_run(Run(text="Hello"))
        para.add_run(Run(text=" "))
        para.add_run(Run(text="World"))
        assert len(para) == 11


class TestParagraphValidation:
    """Test paragraph validation logic."""

    def test_validate_empty_paragraph(self) -> None:
        """Test validating empty paragraph."""
        para = Paragraph()
        para.validate()  # Should not raise

    def test_validate_valid_paragraph(self) -> None:
        """Test validating paragraph with valid runs."""
        para = Paragraph()
        para.add_run(Run(text="Valid text"))
        para.add_run(Run(text=" more text"))
        para.validate()  # Should not raise

    def test_validate_invalid_run(self) -> None:
        """Test validation fails for invalid run."""
        para = Paragraph()
        para.add_run(Run(text="Valid"))
        para.runs.append("not a run")  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="not a Run instance"):
            para.validate()

    def test_validate_run_with_invalid_content(self) -> None:
        """Test validation fails when run validation fails."""
        para = Paragraph()
        para.add_run(Run(text=""))  # Empty text

        with pytest.raises(ValueError, match="failed validation"):
            para.validate()

    def test_validate_excessive_indent_sum(self) -> None:
        """Test validation fails when combined indents exceed limit."""
        para = Paragraph(left_indent=5.0, right_indent=5.0)

        with pytest.raises(ValueError, match="exceed maximum"):
            para.validate()

    def test_validate_valid_indent_sum(self) -> None:
        """Test validation passes for valid indent combination."""
        para = Paragraph(left_indent=1.0, right_indent=1.0)
        para.add_run(Run(text="Test"))
        para.validate()  # Should not raise


class TestParagraphCopy:
    """Test paragraph copying functionality."""

    def test_copy_empty_paragraph(self) -> None:
        """Test copying empty paragraph."""
        para = Paragraph()
        para_copy = para.copy()

        assert para_copy == para
        assert para_copy is not para
        assert para_copy.runs is not para.runs

    def test_copy_preserves_formatting(self) -> None:
        """Test that copy preserves all formatting attributes."""
        para = Paragraph(
            alignment=Alignment.CENTER,
            first_line_indent=0.5,
            left_indent=1.0,
            right_indent=1.0,
            line_spacing=1.5,
            space_before=0.25,
            space_after=0.25,
        )
        para.add_run(Run(text="Test"))

        para_copy = para.copy()

        assert para_copy.alignment == para.alignment
        assert para_copy.first_line_indent == para.first_line_indent
        assert para_copy.left_indent == para.left_indent
        assert para_copy.right_indent == para.right_indent
        assert para_copy.line_spacing == para.line_spacing
        assert para_copy.space_before == para.space_before
        assert para_copy.space_after == para.space_after

    def test_copy_creates_independent_runs(self) -> None:
        """Test that copied runs are independent."""
        para = Paragraph()
        para.add_run(Run(text="Original"))

        para_copy = para.copy()
        para_copy.runs[0].text = "Modified"

        assert para.runs[0].text == "Original"
        assert para_copy.runs[0].text == "Modified"

    def test_copy_multiple_runs(self) -> None:
        """Test copying paragraph with multiple runs."""
        para = Paragraph()
        para.add_run(Run(text="A", bold=True))
        para.add_run(Run(text="B", italic=True))
        para.add_run(Run(text="C"))

        para_copy = para.copy()

        assert len(para_copy.runs) == 3
        assert para_copy.runs[0].text == "A"
        assert para_copy.runs[0].bold is True
        assert para_copy.runs[1].text == "B"
        assert para_copy.runs[1].italic is True


class TestCalculateWidth:
    """Test calculate_width method."""

    def test_calculate_width_no_indents(self) -> None:
        """Test width calculation without indents."""
        para = Paragraph()
        assert para.calculate_width(8.5) == 8.5

    def test_calculate_width_with_left_indent(self) -> None:
        """Test width calculation with left indent."""
        para = Paragraph(left_indent=1.0)
        assert para.calculate_width(8.5) == 7.5

    def test_calculate_width_with_right_indent(self) -> None:
        """Test width calculation with right indent."""
        para = Paragraph(right_indent=1.0)
        assert para.calculate_width(8.5) == 7.5

    def test_calculate_width_with_both_indents(self) -> None:
        """Test width calculation with both indents."""
        para = Paragraph(left_indent=1.0, right_indent=1.5)
        assert para.calculate_width(8.5) == 6.0

    def test_calculate_width_invalid_page_width(self) -> None:
        """Test that invalid page width raises ValueError."""
        para = Paragraph()

        with pytest.raises(ValueError, match="must be positive"):
            para.calculate_width(0)

        with pytest.raises(ValueError, match="must be positive"):
            para.calculate_width(-5.0)

    def test_calculate_width_indents_exceed_page(self) -> None:
        """Test that excessive indents raise ValueError."""
        para = Paragraph(left_indent=5.0, right_indent=5.0)

        with pytest.raises(ValueError, match="exceed page width"):
            para.calculate_width(8.0)


class TestOptimizeRuns:
    """Test optimize_runs method."""

    def test_optimize_runs_empty(self) -> None:
        """Test optimizing empty paragraph."""
        para = Paragraph()
        para.optimize_runs()
        assert len(para.runs) == 0

    def test_optimize_runs_single_run(self) -> None:
        """Test optimizing paragraph with single run."""
        para = Paragraph()
        para.add_run(Run(text="Single"))
        para.optimize_runs()
        assert len(para.runs) == 1

    def test_optimize_runs_mergeable(self) -> None:
        """Test optimizing runs with identical formatting."""
        para = Paragraph()
        para.add_run(Run(text="Hello", bold=True))
        para.add_run(Run(text=" ", bold=True))
        para.add_run(Run(text="World", bold=True))

        para.optimize_runs()

        assert len(para.runs) == 1
        assert para.runs[0].text == "Hello World"
        assert para.runs[0].bold is True

    def test_optimize_runs_not_mergeable(self) -> None:
        """Test optimizing runs with different formatting."""
        para = Paragraph()
        para.add_run(Run(text="Bold", bold=True))
        para.add_run(Run(text="Normal", bold=False))
        para.add_run(Run(text="Italic", italic=True))

        para.optimize_runs()

        assert len(para.runs) == 3

    def test_optimize_runs_partially_mergeable(self) -> None:
        """Test optimizing with mix of mergeable and non-mergeable."""
        para = Paragraph()
        para.add_run(Run(text="A", bold=True))
        para.add_run(Run(text="B", bold=True))
        para.add_run(Run(text="C", bold=False))
        para.add_run(Run(text="D", bold=False))

        para.optimize_runs()

        assert len(para.runs) == 2
        assert para.runs[0].text == "AB"
        assert para.runs[1].text == "CD"


class TestSerialization:
    """Test to_dict and from_dict methods."""

    def test_to_dict_minimal(self) -> None:
        """Test serialization with default values."""
        para = Paragraph()
        data = para.to_dict()

        assert data["runs"] == []
        assert data["alignment"] == "left"
        assert data["first_line_indent"] == 0.0
        assert data["left_indent"] == 0.0
        assert data["right_indent"] == 0.0
        assert data["line_spacing"] == 1.0
        assert data["space_before"] == 0.0
        assert data["space_after"] == 0.0

    def test_to_dict_full(self) -> None:
        """Test serialization with all attributes set."""
        para = Paragraph(
            alignment=Alignment.CENTER,
            first_line_indent=0.5,
            left_indent=1.0,
            right_indent=1.0,
            line_spacing=1.5,
            space_before=0.25,
            space_after=0.25,
        )
        para.add_run(Run(text="Test", bold=True))

        data = para.to_dict()

        assert data["alignment"] == "center"
        assert data["first_line_indent"] == 0.5
        assert data["left_indent"] == 1.0
        assert data["right_indent"] == 1.0
        assert data["line_spacing"] == 1.5
        assert data["space_before"] == 0.25
        assert data["space_after"] == 0.25
        assert len(data["runs"]) == 1
        assert data["runs"][0]["text"] == "Test"

    def test_from_dict_minimal(self) -> None:
        """Test deserialization with minimal data."""
        data: dict[str, Any] = {}
        para = Paragraph.from_dict(data)

        assert len(para.runs) == 0
        assert para.alignment == Alignment.LEFT

    def test_from_dict_full(self) -> None:
        """Test deserialization with complete data."""
        data = {
            "runs": [{"text": "Test", "bold": True}],
            "alignment": "center",
            "first_line_indent": 0.5,
            "left_indent": 1.0,
            "right_indent": 1.0,
            "line_spacing": 1.5,
            "space_before": 0.25,
            "space_after": 0.25,
        }

        para = Paragraph.from_dict(data)

        assert len(para.runs) == 1
        assert para.runs[0].text == "Test"
        assert para.runs[0].bold is True
        assert para.alignment == Alignment.CENTER
        assert para.first_line_indent == 0.5
        assert para.left_indent == 1.0
        assert para.right_indent == 1.0
        assert para.line_spacing == 1.5
        assert para.space_before == 0.25
        assert para.space_after == 0.25

    def test_from_dict_invalid_type(self) -> None:
        """Test that non-dict input raises TypeError."""
        with pytest.raises(TypeError, match="Expected dict"):
            Paragraph.from_dict("not a dict")  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="Expected dict"):
            Paragraph.from_dict(None)  # type: ignore[arg-type]

    def test_from_dict_invalid_alignment(self) -> None:
        """Test that invalid alignment raises ValueError."""
        data = {"alignment": "invalid"}

        with pytest.raises(ValueError, match="Invalid alignment"):
            Paragraph.from_dict(data)

    def test_from_dict_runs_not_list(self) -> None:
        """Test that non-list runs raises TypeError."""
        data = {"runs": "not a list"}

        with pytest.raises(TypeError, match="'runs' must be list"):
            Paragraph.from_dict(data)

    def test_roundtrip_serialization(self) -> None:
        """Test that to_dict/from_dict roundtrip preserves data."""
        original = Paragraph(
            alignment=Alignment.JUSTIFY,
            first_line_indent=0.5,
            left_indent=1.0,
            line_spacing=1.5,
        )
        original.add_run(Run(text="Test", bold=True))
        original.add_run(Run(text=" text", italic=True))

        data = original.to_dict()
        restored = Paragraph.from_dict(data)

        assert restored == original


class TestMagicMethods:
    """Test magic methods (__eq__, __repr__)."""

    def test_equality_identical(self) -> None:
        """Test equality for identical paragraphs."""
        para1 = Paragraph()
        para1.add_run(Run(text="Test"))

        para2 = Paragraph()
        para2.add_run(Run(text="Test"))

        assert para1 == para2

    def test_equality_different_runs(self) -> None:
        """Test inequality for different runs."""
        para1 = Paragraph()
        para1.add_run(Run(text="A"))

        para2 = Paragraph()
        para2.add_run(Run(text="B"))

        assert para1 != para2

    def test_equality_different_formatting(self) -> None:
        """Test inequality for different formatting."""
        para1 = Paragraph(alignment=Alignment.LEFT)
        para2 = Paragraph(alignment=Alignment.CENTER)

        assert para1 != para2

    def test_equality_with_non_paragraph(self) -> None:
        """Test comparison with non-Paragraph objects."""
        para = Paragraph()

        assert (para == "not a paragraph") is False
        assert (para == None) is False
        assert (para == 123) is False

    def test_repr_empty(self) -> None:
        """Test __repr__ for empty paragraph."""
        para = Paragraph()
        repr_str = repr(para)

        assert "Paragraph" in repr_str
        assert "runs=0" in repr_str
        assert "chars=0" in repr_str
        assert "alignment='left'" in repr_str

    def test_repr_with_content(self) -> None:
        """Test __repr__ for paragraph with content."""
        para = Paragraph(alignment=Alignment.CENTER)
        para.add_run(Run(text="Hello"))
        repr_str = repr(para)

        assert "runs=1" in repr_str
        assert "chars=5" in repr_str
        assert "alignment='center'" in repr_str


class TestMergeParagraphs:
    """Test merge_paragraphs utility function."""

    def test_merge_empty_list(self) -> None:
        """Test that merging empty list raises ValueError."""
        with pytest.raises(ValueError, match="Cannot merge empty"):
            merge_paragraphs([])

    def test_merge_single_paragraph(self) -> None:
        """Test merging single paragraph."""
        para = Paragraph()
        para.add_run(Run(text="Test"))

        result = merge_paragraphs([para])

        assert result.get_text() == "Test"
        assert len(result.runs) == 1

    def test_merge_two_paragraphs_default_separator(self) -> None:
        """Test merging with default newline separator."""
        para1 = Paragraph()
        para1.add_run(Run(text="First"))

        para2 = Paragraph()
        para2.add_run(Run(text="Second"))

        result = merge_paragraphs([para1, para2])

        assert result.get_text() == "First\nSecond"

    def test_merge_two_paragraphs_custom_separator(self) -> None:
        """Test merging with custom separator."""
        para1 = Paragraph()
        para1.add_run(Run(text="First"))

        para2 = Paragraph()
        para2.add_run(Run(text="Second"))

        result = merge_paragraphs([para1, para2], separator=" ")

        assert result.get_text() == "First Second"

    def test_merge_multiple_paragraphs(self) -> None:
        """Test merging multiple paragraphs."""
        para1 = Paragraph()
        para1.add_run(Run(text="A"))

        para2 = Paragraph()
        para2.add_run(Run(text="B"))

        para3 = Paragraph()
        para3.add_run(Run(text="C"))

        result = merge_paragraphs([para1, para2, para3], separator="-")

        assert result.get_text() == "A-B-C"

    def test_merge_preserves_first_formatting(self) -> None:
        """Test that merge uses first paragraph's formatting."""
        para1 = Paragraph(
            alignment=Alignment.CENTER,
            first_line_indent=0.5,
        )
        para1.add_run(Run(text="First"))

        para2 = Paragraph(alignment=Alignment.RIGHT)
        para2.add_run(Run(text="Second"))

        result = merge_paragraphs([para1, para2])

        assert result.alignment == Alignment.CENTER
        assert result.first_line_indent == 0.5

    def test_merge_with_empty_separator(self) -> None:
        """Test merging with empty separator."""
        para1 = Paragraph()
        para1.add_run(Run(text="Hello"))

        para2 = Paragraph()
        para2.add_run(Run(text="World"))

        result = merge_paragraphs([para1, para2], separator="")

        assert result.get_text() == "HelloWorld"


class TestSplitParagraphAt:
    """Test split_paragraph_at utility function."""

    def test_split_at_middle(self) -> None:
        """Test splitting paragraph in the middle."""
        para = Paragraph()
        para.add_run(Run(text="A"))
        para.add_run(Run(text="B"))
        para.add_run(Run(text="C"))

        first, second = split_paragraph_at(para, 1)

        assert first.get_text() == "A"
        assert second.get_text() == "BC"

    def test_split_at_start(self) -> None:
        """Test splitting near the start."""
        para = Paragraph()
        para.add_run(Run(text="A"))
        para.add_run(Run(text="B"))
        para.add_run(Run(text="C"))

        first, second = split_paragraph_at(para, 1)

        assert len(first.runs) == 1
        assert len(second.runs) == 2

    def test_split_at_near_end(self) -> None:
        """Test splitting near the end."""
        para = Paragraph()
        para.add_run(Run(text="A"))
        para.add_run(Run(text="B"))
        para.add_run(Run(text="C"))

        first, second = split_paragraph_at(para, 2)

        assert first.get_text() == "AB"
        assert second.get_text() == "C"

    def test_split_preserves_formatting(self) -> None:
        """Test that split preserves formatting in both parts."""
        para = Paragraph(
            alignment=Alignment.CENTER,
            first_line_indent=0.5,
            line_spacing=1.5,
        )
        para.add_run(Run(text="A"))
        para.add_run(Run(text="B"))

        first, second = split_paragraph_at(para, 1)

        assert first.alignment == Alignment.CENTER
        assert first.first_line_indent == 0.5
        assert first.line_spacing == 1.5

        assert second.alignment == Alignment.CENTER
        assert second.first_line_indent == 0.5
        assert second.line_spacing == 1.5

    def test_split_invalid_index_zero(self) -> None:
        """Test that split at index 0 raises ValueError."""
        para = Paragraph()
        para.add_run(Run(text="A"))
        para.add_run(Run(text="B"))

        with pytest.raises(ValueError, match="must be in range"):
            split_paragraph_at(para, 0)

    def test_split_invalid_index_at_end(self) -> None:
        """Test that split at end index raises ValueError."""
        para = Paragraph()
        para.add_run(Run(text="A"))
        para.add_run(Run(text="B"))

        with pytest.raises(ValueError, match="must be in range"):
            split_paragraph_at(para, 2)

    def test_split_invalid_index_out_of_range(self) -> None:
        """Test that out of range index raises ValueError."""
        para = Paragraph()
        para.add_run(Run(text="A"))

        with pytest.raises(ValueError, match="must be in range"):
            split_paragraph_at(para, 10)


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_paragraph_with_only_whitespace(self) -> None:
        """Test paragraph containing only whitespace."""
        para = Paragraph()
        para.add_run(Run(text="   "))
        para.add_run(Run(text="\t"))

        assert para.get_text() == "   \t"
        assert len(para) == 4

    def test_paragraph_with_cyrillic(self) -> None:
        """Test paragraph with Cyrillic text."""
        para = Paragraph()
        para.add_run(Run(text="Привет ", encoding="cp866"))
        para.add_run(Run(text="мир", encoding="cp866"))

        assert para.get_text() == "Привет мир"
        para.validate()

    def test_all_alignment_types(self) -> None:
        """Test creating paragraphs with all alignment types."""
        for alignment in Alignment:
            para = Paragraph(alignment=alignment)
            assert para.alignment == alignment

    def test_extreme_indent_values(self) -> None:
        """Test with maximum valid indent values."""
        para = Paragraph(
            first_line_indent=MAX_INDENT - 0.1,
            left_indent=3.0,
            right_indent=3.0,
        )

        assert para.first_line_indent < MAX_INDENT
        assert para.left_indent == 3.0
        assert para.right_indent == 3.0

    def test_extreme_line_spacing(self) -> None:
        """Test with extreme line spacing values."""
        para1 = Paragraph(line_spacing=MIN_LINE_SPACING)
        para2 = Paragraph(line_spacing=MAX_LINE_SPACING)

        assert para1.line_spacing == MIN_LINE_SPACING
        assert para2.line_spacing == MAX_LINE_SPACING


class TestIntegration:
    """Integration tests combining multiple operations."""

    def test_build_format_validate_serialize(self) -> None:
        """Test complete workflow: build, format, validate, serialize."""
        para = Paragraph(
            alignment=Alignment.JUSTIFY,
            first_line_indent=0.5,
            left_indent=1.0,
            line_spacing=1.5,
        )

        para.add_run(Run(text="This is ", bold=True))
        para.add_run(Run(text="a test ", bold=False))
        para.add_run(Run(text="paragraph.", italic=True))

        para.validate()
        data = para.to_dict()
        restored = Paragraph.from_dict(data)

        assert restored == para
        assert restored.get_text() == para.get_text()

    def test_optimize_after_modification(self) -> None:
        """Test optimizing after multiple modifications."""
        para = Paragraph()

        # Add runs with same formatting
        for char in "ABCDE":
            para.add_run(Run(text=char, bold=True))

        assert len(para.runs) == 5

        para.optimize_runs()
        assert len(para.runs) == 1
        assert para.get_text() == "ABCDE"

    def test_split_and_merge_roundtrip(self) -> None:
        """Test splitting then merging paragraphs."""
        original = Paragraph(alignment=Alignment.CENTER)
        original.add_run(Run(text="First"))
        original.add_run(Run(text="Second"))
        original.add_run(Run(text="Third"))

        first, second = split_paragraph_at(original, 1)
        merged = merge_paragraphs([first, second], separator="")

        assert merged.get_text() == original.get_text()
        assert merged.alignment == original.alignment

    def test_copy_modify_validate(self) -> None:
        """Test copying, modifying, and validating independently."""
        original = Paragraph()
        original.add_run(Run(text="Original"))

        copy = original.copy()
        copy.add_run(Run(text=" Modified"))
        copy.alignment = Alignment.RIGHT

        original.validate()
        copy.validate()

        assert original.get_text() == "Original"
        assert copy.get_text() == "Original Modified"
        assert original.alignment == Alignment.LEFT
        assert copy.alignment == Alignment.RIGHT
