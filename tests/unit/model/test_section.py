"""
Unit tests for src/model/section.py module.

Tests cover Section class functionality, break types, paragraph management,
validation, serialization, and utility functions.
"""

import logging
from typing import Any

import pytest

from src.model.paragraph import Paragraph
from src.model.run import Run
from src.model.section import (MAX_PAGE_NUMBER, MIN_PAGE_NUMBER, Section,
                               SectionBreak, merge_sections, split_section_at)


class TestSectionBreak:
    """Test SectionBreak enum."""

    def test_section_break_values(self) -> None:
        """Test that all section break values are defined."""
        assert SectionBreak.CONTINUOUS.value == "continuous"
        assert SectionBreak.NEW_PAGE.value == "new_page"
        assert SectionBreak.EVEN_PAGE.value == "even_page"
        assert SectionBreak.ODD_PAGE.value == "odd_page"

    def test_section_break_from_string(self) -> None:
        """Test creating section break from string value."""
        assert SectionBreak("continuous") == SectionBreak.CONTINUOUS
        assert SectionBreak("new_page") == SectionBreak.NEW_PAGE
        assert SectionBreak("even_page") == SectionBreak.EVEN_PAGE
        assert SectionBreak("odd_page") == SectionBreak.ODD_PAGE

    def test_section_break_invalid_string(self) -> None:
        """Test that invalid string raises ValueError."""
        with pytest.raises(ValueError):
            SectionBreak("invalid")


class TestSectionInitialization:
    """Test Section initialization and post-init validation."""

    def test_minimal_initialization(self) -> None:
        """Test creating section with default values."""
        section = Section()

        assert section.paragraphs == []
        assert section.break_type == SectionBreak.NEW_PAGE
        assert section.page_number_start is None

    def test_full_initialization(self) -> None:
        """Test creating section with all parameters."""
        paragraphs = [Paragraph(), Paragraph()]
        section = Section(
            paragraphs=paragraphs,
            break_type=SectionBreak.CONTINUOUS,
            page_number_start=5,
        )

        assert len(section.paragraphs) == 2
        assert section.break_type == SectionBreak.CONTINUOUS
        assert section.page_number_start == 5

    def test_page_number_clamping_too_high(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that excessive page number is clamped."""
        with caplog.at_level(logging.WARNING):
            section = Section(page_number_start=99999)

        assert section.page_number_start == MAX_PAGE_NUMBER
        assert "out of range" in caplog.text

    def test_page_number_clamping_too_low(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that negative page number is clamped."""
        with caplog.at_level(logging.WARNING):
            section = Section(page_number_start=-5)

        assert section.page_number_start == MIN_PAGE_NUMBER

    def test_page_number_none_allowed(self) -> None:
        """Test that None page number is valid."""
        section = Section(page_number_start=None)
        assert section.page_number_start is None

    def test_page_number_invalid_type(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that non-int page number is set to None."""
        with caplog.at_level(logging.WARNING):
            section = Section(page_number_start="5")  # type: ignore[arg-type]

        assert section.page_number_start is None
        assert "must be int or None" in caplog.text

    def test_paragraphs_not_list_conversion(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that non-list paragraphs are converted to list."""
        with caplog.at_level(logging.WARNING):
            section = Section(paragraphs=(Paragraph(), Paragraph()))  # type: ignore[arg-type]

        assert isinstance(section.paragraphs, list)
        assert len(section.paragraphs) == 2


class TestParagraphManipulation:
    """Test methods for adding, inserting, and removing paragraphs."""

    def test_add_paragraph(self) -> None:
        """Test adding paragraphs to section."""
        section = Section()
        para1 = Paragraph()
        para2 = Paragraph()

        section.add_paragraph(para1)
        assert len(section.paragraphs) == 1
        assert section.paragraphs[0] == para1

        section.add_paragraph(para2)
        assert len(section.paragraphs) == 2
        assert section.paragraphs[1] == para2

    def test_add_paragraph_invalid_type(self) -> None:
        """Test that adding non-Paragraph raises TypeError."""
        section = Section()

        with pytest.raises(TypeError, match="Expected Paragraph instance"):
            section.add_paragraph("not a paragraph")  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="Expected Paragraph instance"):
            section.add_paragraph(None)  # type: ignore[arg-type]

    def test_insert_paragraph_at_start(self) -> None:
        """Test inserting paragraph at the beginning."""
        section = Section()
        para1 = Paragraph()
        para1.add_run(Run(text="Second"))
        para2 = Paragraph()
        para2.add_run(Run(text="First"))

        section.add_paragraph(para1)
        section.insert_paragraph(0, para2)

        assert section.paragraphs[0].get_text() == "First"
        assert section.paragraphs[1].get_text() == "Second"

    def test_insert_paragraph_at_middle(self) -> None:
        """Test inserting paragraph in the middle."""
        section = Section()
        para1 = Paragraph()
        para1.add_run(Run(text="First"))
        para2 = Paragraph()
        para2.add_run(Run(text="Third"))
        para3 = Paragraph()
        para3.add_run(Run(text="Second"))

        section.add_paragraph(para1)
        section.add_paragraph(para2)
        section.insert_paragraph(1, para3)

        assert section.paragraphs[0].get_text() == "First"
        assert section.paragraphs[1].get_text() == "Second"
        assert section.paragraphs[2].get_text() == "Third"

    def test_insert_paragraph_at_end(self) -> None:
        """Test inserting paragraph at the end."""
        section = Section()
        para1 = Paragraph()
        para2 = Paragraph()

        section.add_paragraph(para1)
        section.insert_paragraph(1, para2)

        assert len(section.paragraphs) == 2
        assert section.paragraphs[1] == para2

    def test_insert_paragraph_invalid_index(self) -> None:
        """Test that invalid insert index raises IndexError."""
        section = Section()
        section.add_paragraph(Paragraph())

        with pytest.raises(IndexError, match="out of range"):
            section.insert_paragraph(-1, Paragraph())

        with pytest.raises(IndexError, match="out of range"):
            section.insert_paragraph(10, Paragraph())

    def test_insert_paragraph_invalid_type(self) -> None:
        """Test that inserting non-Paragraph raises TypeError."""
        section = Section()

        with pytest.raises(TypeError, match="Expected Paragraph instance"):
            section.insert_paragraph(0, "not a paragraph")  # type: ignore[arg-type]

    def test_remove_paragraph(self) -> None:
        """Test removing paragraph by index."""
        section = Section()
        para1 = Paragraph()
        para2 = Paragraph()
        section.add_paragraph(para1)
        section.add_paragraph(para2)

        removed = section.remove_paragraph(0)
        assert removed == para1
        assert len(section.paragraphs) == 1
        assert section.paragraphs[0] == para2

    def test_remove_paragraph_invalid_index(self) -> None:
        """Test that invalid remove index raises IndexError."""
        section = Section()
        section.add_paragraph(Paragraph())

        with pytest.raises(IndexError, match="out of range"):
            section.remove_paragraph(-1)

        with pytest.raises(IndexError, match="out of range"):
            section.remove_paragraph(10)

    def test_clear_paragraphs(self) -> None:
        """Test clearing all paragraphs from section."""
        section = Section()
        section.add_paragraph(Paragraph())
        section.add_paragraph(Paragraph())
        section.add_paragraph(Paragraph())

        section.clear_paragraphs()
        assert len(section.paragraphs) == 0
        assert section.paragraphs == []

    def test_clear_paragraphs_empty_section(self) -> None:
        """Test clearing paragraphs from empty section."""
        section = Section()
        section.clear_paragraphs()
        assert len(section.paragraphs) == 0

    def test_get_paragraph_count(self) -> None:
        """Test counting paragraphs."""
        section = Section()
        assert section.get_paragraph_count() == 0

        section.add_paragraph(Paragraph())
        assert section.get_paragraph_count() == 1

        section.add_paragraph(Paragraph())
        section.add_paragraph(Paragraph())
        assert section.get_paragraph_count() == 3


class TestSectionText:
    """Test text retrieval methods."""

    def test_get_text_empty(self) -> None:
        """Test getting text from empty section."""
        section = Section()
        assert section.get_text() == ""

    def test_get_text_single_paragraph(self) -> None:
        """Test getting text with single paragraph."""
        section = Section()
        para = Paragraph()
        para.add_run(Run(text="Hello World"))
        section.add_paragraph(para)

        assert section.get_text() == "Hello World"

    def test_get_text_multiple_paragraphs(self) -> None:
        """Test getting text with multiple paragraphs."""
        section = Section()

        para1 = Paragraph()
        para1.add_run(Run(text="First paragraph"))
        section.add_paragraph(para1)

        para2 = Paragraph()
        para2.add_run(Run(text="Second paragraph"))
        section.add_paragraph(para2)

        para3 = Paragraph()
        para3.add_run(Run(text="Third paragraph"))
        section.add_paragraph(para3)

        assert section.get_text() == "First paragraph\nSecond paragraph\nThird paragraph"

    def test_get_text_empty_paragraphs(self) -> None:
        """Test getting text with empty paragraphs."""
        section = Section()
        section.add_paragraph(Paragraph())
        section.add_paragraph(Paragraph())

        assert section.get_text() == "\n"

    def test_len_empty(self) -> None:
        """Test __len__ on empty section."""
        section = Section()
        assert len(section) == 0

    def test_len_single_paragraph(self) -> None:
        """Test __len__ with single paragraph."""
        section = Section()
        para = Paragraph()
        para.add_run(Run(text="Hello"))
        section.add_paragraph(para)

        assert len(section) == 5

    def test_len_multiple_paragraphs(self) -> None:
        """Test __len__ with multiple paragraphs."""
        section = Section()

        para1 = Paragraph()
        para1.add_run(Run(text="Hello"))
        section.add_paragraph(para1)

        para2 = Paragraph()
        para2.add_run(Run(text="World"))
        section.add_paragraph(para2)

        assert len(section) == 10


class TestSectionValidation:
    """Test section validation logic."""

    def test_validate_empty_section(self) -> None:
        """Test validating empty section."""
        section = Section()
        section.validate()  # Should not raise

    def test_validate_valid_section(self) -> None:
        """Test validating section with valid paragraphs."""
        section = Section()
        para = Paragraph()
        para.add_run(Run(text="Valid text"))
        section.add_paragraph(para)

        section.validate()  # Should not raise

    def test_validate_invalid_paragraph(self) -> None:
        """Test validation fails for invalid paragraph."""
        section = Section()
        para = Paragraph()
        section.add_paragraph(para)
        section.paragraphs.append("not a paragraph")  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="not a Paragraph instance"):
            section.validate()

    def test_validate_paragraph_with_invalid_content(self) -> None:
        """Test validation fails when paragraph validation fails."""
        section = Section()
        para = Paragraph()
        para.add_run(Run(text=""))  # Empty text - invalid
        section.add_paragraph(para)

        with pytest.raises(ValueError, match="failed validation"):
            section.validate()

    def test_validate_page_number_out_of_range(self) -> None:
        """Test validation fails for out-of-range page number."""
        section = Section()
        # Bypass post_init by setting directly
        object.__setattr__(section, "page_number_start", 99999)

        with pytest.raises(ValueError, match="out of range"):
            section.validate()

    def test_validate_page_number_invalid_type(self) -> None:
        """Test validation fails for non-int page number."""
        section = Section()
        object.__setattr__(section, "page_number_start", "5")

        with pytest.raises(TypeError, match="must be int or None"):
            section.validate()

    def test_validate_page_number_none(self) -> None:
        """Test validation passes for None page number."""
        section = Section()
        section.page_number_start = None
        section.validate()  # Should not raise


class TestSectionCopy:
    """Test section copying functionality."""

    def test_copy_empty_section(self) -> None:
        """Test copying empty section."""
        section = Section()
        section_copy = section.copy()

        assert section_copy == section
        assert section_copy is not section
        assert section_copy.paragraphs is not section.paragraphs

    def test_copy_preserves_settings(self) -> None:
        """Test that copy preserves all settings."""
        section = Section(
            break_type=SectionBreak.CONTINUOUS,
            page_number_start=10,
        )
        para = Paragraph()
        para.add_run(Run(text="Test"))
        section.add_paragraph(para)

        section_copy = section.copy()

        assert section_copy.break_type == section.break_type
        assert section_copy.page_number_start == section.page_number_start
        assert len(section_copy.paragraphs) == len(section.paragraphs)

    def test_copy_creates_independent_paragraphs(self) -> None:
        """Test that copied paragraphs are independent."""
        section = Section()
        para = Paragraph()
        para.add_run(Run(text="Original"))
        section.add_paragraph(para)

        section_copy = section.copy()
        section_copy.paragraphs[0].runs[0].text = "Modified"

        assert section.paragraphs[0].runs[0].text == "Original"
        assert section_copy.paragraphs[0].runs[0].text == "Modified"

    def test_copy_multiple_paragraphs(self) -> None:
        """Test copying section with multiple paragraphs."""
        section = Section()
        for i in range(3):
            para = Paragraph()
            para.add_run(Run(text=f"Para {i}"))
            section.add_paragraph(para)

        section_copy = section.copy()

        assert len(section_copy.paragraphs) == 3
        for i in range(3):
            assert section_copy.paragraphs[i].get_text() == f"Para {i}"


class TestSerialization:
    """Test to_dict and from_dict methods."""

    def test_to_dict_minimal(self) -> None:
        """Test serialization with default values."""
        section = Section()
        data = section.to_dict()

        assert data["paragraphs"] == []
        assert data["break_type"] == "new_page"
        assert data["page_number_start"] is None

    def test_to_dict_full(self) -> None:
        """Test serialization with all attributes set."""
        section = Section(
            break_type=SectionBreak.CONTINUOUS,
            page_number_start=5,
        )
        para = Paragraph()
        para.add_run(Run(text="Test"))
        section.add_paragraph(para)

        data = section.to_dict()

        assert data["break_type"] == "continuous"
        assert data["page_number_start"] == 5
        assert len(data["paragraphs"]) == 1
        assert data["paragraphs"][0]["runs"][0]["text"] == "Test"

    def test_from_dict_minimal(self) -> None:
        """Test deserialization with minimal data."""
        data: dict[str, Any] = {}
        section = Section.from_dict(data)

        assert len(section.paragraphs) == 0
        assert section.break_type == SectionBreak.NEW_PAGE
        assert section.page_number_start is None

    def test_from_dict_full(self) -> None:
        """Test deserialization with complete data."""
        data = {
            "paragraphs": [{"runs": [{"text": "Test"}]}],
            "break_type": "continuous",
            "page_number_start": 10,
        }

        section = Section.from_dict(data)

        assert len(section.paragraphs) == 1
        assert section.paragraphs[0].runs[0].text == "Test"
        assert section.break_type == SectionBreak.CONTINUOUS
        assert section.page_number_start == 10

    def test_from_dict_invalid_type(self) -> None:
        """Test that non-dict input raises TypeError."""
        with pytest.raises(TypeError, match="Expected dict"):
            Section.from_dict("not a dict")  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="Expected dict"):
            Section.from_dict(None)  # type: ignore[arg-type]

    def test_from_dict_invalid_break_type(self) -> None:
        """Test that invalid break_type raises ValueError."""
        data = {"break_type": "invalid"}

        with pytest.raises(ValueError, match="Invalid break_type"):
            Section.from_dict(data)

    def test_from_dict_paragraphs_not_list(self) -> None:
        """Test that non-list paragraphs raises TypeError."""
        data = {"paragraphs": "not a list"}

        with pytest.raises(TypeError, match="'paragraphs' must be list"):
            Section.from_dict(data)

    def test_roundtrip_serialization(self) -> None:
        """Test that to_dict/from_dict roundtrip preserves data."""
        original = Section(
            break_type=SectionBreak.EVEN_PAGE,
            page_number_start=7,
        )
        para = Paragraph()
        para.add_run(Run(text="Roundtrip test"))
        original.add_paragraph(para)

        data = original.to_dict()
        restored = Section.from_dict(data)

        assert restored == original
        assert restored.get_text() == original.get_text()


class TestMagicMethods:
    """Test magic methods (__eq__, __repr__)."""

    def test_equality_identical(self) -> None:
        """Test equality for identical sections."""
        section1 = Section()
        para = Paragraph()
        para.add_run(Run(text="Test"))
        section1.add_paragraph(para)

        section2 = Section()
        para2 = Paragraph()
        para2.add_run(Run(text="Test"))
        section2.add_paragraph(para2)

        assert section1 == section2

    def test_equality_different_paragraphs(self) -> None:
        """Test inequality for different paragraphs."""
        section1 = Section()
        para1 = Paragraph()
        para1.add_run(Run(text="A"))
        section1.add_paragraph(para1)

        section2 = Section()
        para2 = Paragraph()
        para2.add_run(Run(text="B"))
        section2.add_paragraph(para2)

        assert section1 != section2

    def test_equality_different_break_type(self) -> None:
        """Test inequality for different break types."""
        section1 = Section(break_type=SectionBreak.NEW_PAGE)
        section2 = Section(break_type=SectionBreak.CONTINUOUS)

        assert section1 != section2

    def test_equality_different_page_start(self) -> None:
        """Test inequality for different page starts."""
        section1 = Section(page_number_start=1)
        section2 = Section(page_number_start=5)

        assert section1 != section2

    def test_equality_with_non_section(self) -> None:
        """Test comparison with non-Section objects."""
        section = Section()

        assert (section == "not a section") is False
        assert (section == None) is False
        assert (section == 123) is False

    def test_repr_empty(self) -> None:
        """Test __repr__ for empty section."""
        section = Section()
        repr_str = repr(section)

        assert "Section" in repr_str
        assert "paragraphs=0" in repr_str
        assert "chars=0" in repr_str
        assert "break='new_page'" in repr_str

    def test_repr_with_content(self) -> None:
        """Test __repr__ for section with content."""
        section = Section(break_type=SectionBreak.CONTINUOUS)
        para = Paragraph()
        para.add_run(Run(text="Hello"))
        section.add_paragraph(para)

        repr_str = repr(section)

        assert "paragraphs=1" in repr_str
        assert "chars=5" in repr_str
        assert "break='continuous'" in repr_str


class TestMergeSections:
    """Test merge_sections utility function."""

    def test_merge_empty_list(self) -> None:
        """Test that merging empty list raises ValueError."""
        with pytest.raises(ValueError, match="Cannot merge empty"):
            merge_sections([])

    def test_merge_single_section(self) -> None:
        """Test merging single section."""
        section = Section()
        para = Paragraph()
        para.add_run(Run(text="Test"))
        section.add_paragraph(para)

        result = merge_sections([section])

        assert result.get_text() == "Test"
        assert len(result.paragraphs) == 1

    def test_merge_two_sections(self) -> None:
        """Test merging two sections."""
        section1 = Section()
        para1 = Paragraph()
        para1.add_run(Run(text="First"))
        section1.add_paragraph(para1)

        section2 = Section()
        para2 = Paragraph()
        para2.add_run(Run(text="Second"))
        section2.add_paragraph(para2)

        result = merge_sections([section1, section2])

        assert len(result.paragraphs) == 2
        assert result.paragraphs[0].get_text() == "First"
        assert result.paragraphs[1].get_text() == "Second"

    def test_merge_preserves_first_settings(self) -> None:
        """Test that merge uses first section's settings."""
        section1 = Section(
            break_type=SectionBreak.CONTINUOUS,
            page_number_start=5,
        )
        para1 = Paragraph()
        para1.add_run(Run(text="First"))
        section1.add_paragraph(para1)

        section2 = Section(break_type=SectionBreak.NEW_PAGE)
        para2 = Paragraph()
        para2.add_run(Run(text="Second"))
        section2.add_paragraph(para2)

        result = merge_sections([section1, section2])

        assert result.break_type == SectionBreak.CONTINUOUS
        assert result.page_number_start == 5

    def test_merge_with_preserve_breaks(self) -> None:
        """Test merging with preserve_breaks inserts separators."""
        section1 = Section()
        para1 = Paragraph()
        para1.add_run(Run(text="First"))
        section1.add_paragraph(para1)

        section2 = Section()
        para2 = Paragraph()
        para2.add_run(Run(text="Second"))
        section2.add_paragraph(para2)

        result = merge_sections([section1, section2], preserve_breaks=True)

        assert len(result.paragraphs) == 3  # 2 content + 1 separator
        assert result.paragraphs[0].get_text() == "First"
        assert result.paragraphs[1].get_text() == ""  # Empty separator
        assert result.paragraphs[2].get_text() == "Second"

    def test_merge_multiple_sections(self) -> None:
        """Test merging multiple sections."""
        sections = []
        for i in range(3):
            section = Section()
            para = Paragraph()
            para.add_run(Run(text=f"Para {i}"))
            section.add_paragraph(para)
            sections.append(section)

        result = merge_sections(sections)

        assert len(result.paragraphs) == 3
        for i in range(3):
            assert result.paragraphs[i].get_text() == f"Para {i}"


class TestSplitSectionAt:
    """Test split_section_at utility function."""

    def test_split_at_middle(self) -> None:
        """Test splitting section in the middle."""
        section = Section()
        for i in range(3):
            para = Paragraph()
            para.add_run(Run(text=f"Para {i}"))
            section.add_paragraph(para)

        first, second = split_section_at(section, 1)

        assert first.get_paragraph_count() == 1
        assert second.get_paragraph_count() == 2
        assert first.paragraphs[0].get_text() == "Para 0"
        assert second.paragraphs[0].get_text() == "Para 1"

    def test_split_preserves_first_settings(self) -> None:
        """Test that first section preserves original settings."""
        section = Section(
            break_type=SectionBreak.CONTINUOUS,
            page_number_start=5,
        )
        section.add_paragraph(Paragraph())
        section.add_paragraph(Paragraph())

        first, second = split_section_at(section, 1)

        assert first.break_type == SectionBreak.CONTINUOUS
        assert first.page_number_start == 5

    def test_split_second_continues(self) -> None:
        """Test that second section has continuous break."""
        section = Section(break_type=SectionBreak.NEW_PAGE)
        section.add_paragraph(Paragraph())
        section.add_paragraph(Paragraph())

        first, second = split_section_at(section, 1)

        assert second.break_type == SectionBreak.CONTINUOUS
        assert second.page_number_start is None

    def test_split_invalid_index_zero(self) -> None:
        """Test that split at index 0 raises ValueError."""
        section = Section()
        section.add_paragraph(Paragraph())
        section.add_paragraph(Paragraph())

        with pytest.raises(ValueError, match="must be in range"):
            split_section_at(section, 0)

    def test_split_invalid_index_at_end(self) -> None:
        """Test that split at end index raises ValueError."""
        section = Section()
        section.add_paragraph(Paragraph())
        section.add_paragraph(Paragraph())

        with pytest.raises(ValueError, match="must be in range"):
            split_section_at(section, 2)

    def test_split_invalid_index_out_of_range(self) -> None:
        """Test that out of range index raises ValueError."""
        section = Section()
        section.add_paragraph(Paragraph())

        with pytest.raises(ValueError, match="must be in range"):
            split_section_at(section, 10)


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_section_with_empty_paragraphs(self) -> None:
        """Test section containing only empty paragraphs."""
        section = Section()
        section.add_paragraph(Paragraph())
        section.add_paragraph(Paragraph())

        assert section.get_text() == "\n"
        assert len(section) == 0

    def test_all_break_types(self) -> None:
        """Test creating sections with all break types."""
        for break_type in SectionBreak:
            section = Section(break_type=break_type)
            assert section.break_type == break_type

    def test_page_number_boundary_values(self) -> None:
        """Test page number at boundary values."""
        section1 = Section(page_number_start=MIN_PAGE_NUMBER)
        assert section1.page_number_start == MIN_PAGE_NUMBER

        section2 = Section(page_number_start=MAX_PAGE_NUMBER)
        assert section2.page_number_start == MAX_PAGE_NUMBER

    def test_large_number_of_paragraphs(self) -> None:
        """Test section with many paragraphs."""
        section = Section()
        for i in range(100):
            para = Paragraph()
            para.add_run(Run(text=f"Para {i}"))
            section.add_paragraph(para)

        assert len(section.paragraphs) == 100
        assert section.get_paragraph_count() == 100


class TestIntegration:
    """Integration tests combining multiple operations."""

    def test_build_validate_serialize(self) -> None:
        """Test complete workflow: build, validate, serialize."""
        section = Section(
            break_type=SectionBreak.NEW_PAGE,
            page_number_start=1,
        )

        para1 = Paragraph()
        para1.add_run(Run(text="First paragraph"))
        section.add_paragraph(para1)

        para2 = Paragraph()
        para2.add_run(Run(text="Second paragraph"))
        section.add_paragraph(para2)

        section.validate()
        data = section.to_dict()
        restored = Section.from_dict(data)

        assert restored == section
        assert restored.get_text() == section.get_text()

    def test_split_and_merge_roundtrip(self) -> None:
        """Test splitting then merging sections."""
        original = Section()
        for i in range(3):
            para = Paragraph()
            para.add_run(Run(text=f"Para {i}"))
            original.add_paragraph(para)

        first, second = split_section_at(original, 1)
        merged = merge_sections([first, second])

        assert merged.get_text() == original.get_text()

    def test_copy_modify_validate(self) -> None:
        """Test copying, modifying, and validating independently."""
        original = Section()
        para = Paragraph()
        para.add_run(Run(text="Original"))
        original.add_paragraph(para)

        copy = original.copy()
        para2 = Paragraph()
        para2.add_run(Run(text="Modified"))
        copy.add_paragraph(para2)
        copy.break_type = SectionBreak.CONTINUOUS

        original.validate()
        copy.validate()

        assert original.get_paragraph_count() == 1
        assert copy.get_paragraph_count() == 2
        assert original.break_type == SectionBreak.NEW_PAGE
        assert copy.break_type == SectionBreak.CONTINUOUS

    def test_complex_section_structure(self) -> None:
        """Test section with complex paragraph structure."""
        section = Section(
            break_type=SectionBreak.EVEN_PAGE,
            page_number_start=10,
        )

        # Add multiple paragraphs with various formatting
        for i in range(5):
            para = Paragraph()
            run1 = Run(text=f"Bold {i}", bold=True)
            run2 = Run(text=" ")
            run3 = Run(text=f"Italic {i}", italic=True)
            para.add_run(run1)
            para.add_run(run2)
            para.add_run(run3)
            section.add_paragraph(para)

        section.validate()
        assert len(section.paragraphs) == 5
        assert all(len(para.runs) == 3 for para in section.paragraphs)
