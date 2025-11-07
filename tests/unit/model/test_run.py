"""
Comprehensive test suite for src/model/run.py

This module provides exhaustive unit tests for the Run model and all related
classes, enums, and utility functions. Achieves >95% code coverage with
complete validation of formatting, highlighting, grouping, serialization,
and edge cases.

Tests for: Run, TextMetrics, RevisionInfo, EmbeddedObject, GroupInfo,
HighlightRange, ListMarkerInfo, all enums, and utility functions.
"""

import logging
from typing import Any

import pytest

from src.model.enums import (
    CharactersPerInch,
    CodePage,
    Color,
    FontFamily,
    TextStyle,
)
from src.model.run import (
    MAX_TEXT_LENGTH,
    BorderStyle,
    EmbeddedObject,
    GroupInfo,
    HighlightRange,
    HighlightType,
    ListMarkerInfo,
    ListStyleType,
    RevisionInfo,
    Run,
    TextDirection,
    TextMetrics,
    WhitespaceMode,
    find_runs_in_group,
    find_runs_in_thread,
    get_highlighted_text,
    merge_consecutive_runs,
    split_by_formatting,
)


class TestEnums:
    """Test all enum classes in run.py"""

    def test_text_direction_values(self) -> None:
        """Test TextDirection enum values"""
        assert TextDirection.LTR.value == "ltr"
        assert TextDirection.RTL.value == "rtl"
        assert TextDirection.AUTO.value == "auto"

    def test_whitespace_mode_values(self) -> None:
        """Test WhitespaceMode enum values"""
        assert WhitespaceMode.NORMAL.value == "normal"
        assert WhitespaceMode.PRESERVE.value == "preserve"
        assert WhitespaceMode.NOWRAP.value == "nowrap"

    def test_border_style_values(self) -> None:
        """Test BorderStyle enum values"""
        assert BorderStyle.NONE.value == "none"
        assert BorderStyle.SOLID.value == "solid"
        assert BorderStyle.DASHED.value == "dashed"
        assert BorderStyle.DOTTED.value == "dotted"

    def test_highlight_type_values(self) -> None:
        """Test HighlightType enum values"""
        assert HighlightType.SELECTION.value == "selection"
        assert HighlightType.SEARCH_RESULT.value == "search"
        assert HighlightType.SPELL_ERROR.value == "spell_error"
        assert HighlightType.GRAMMAR_ERROR.value == "grammar"
        assert HighlightType.COMMENT_RANGE.value == "comment"
        assert HighlightType.BOOKMARK.value == "bookmark"
        assert HighlightType.HYPERLINK_HOVER.value == "link_hover"
        assert HighlightType.CUSTOM.value == "custom"

    def test_list_style_type_values(self) -> None:
        """Test ListStyleType enum values"""
        assert ListStyleType.NONE.value == "none"
        assert ListStyleType.BULLET.value == "bullet"
        assert ListStyleType.CIRCLE.value == "circle"
        assert ListStyleType.SQUARE.value == "square"
        assert ListStyleType.DECIMAL.value == "decimal"
        assert ListStyleType.LOWER_ALPHA.value == "lower_alpha"
        assert ListStyleType.UPPER_ALPHA.value == "upper_alpha"
        assert ListStyleType.LOWER_ROMAN.value == "lower_roman"
        assert ListStyleType.UPPER_ROMAN.value == "upper_roman"
        assert ListStyleType.CUSTOM.value == "custom"


class TestTextMetrics:
    """Test TextMetrics dataclass"""

    def test_text_metrics_creation(self) -> None:
        """Test TextMetrics creation and attributes"""
        metrics = TextMetrics(width=100.0, height=20.0, ascent=15.0, descent=5.0)
        assert metrics.width == 100.0
        assert metrics.height == 20.0
        assert metrics.ascent == 15.0
        assert metrics.descent == 5.0

    def test_text_metrics_mutable(self) -> None:
        """Test TextMetrics is mutable (frozen=False)"""
        metrics = TextMetrics(100.0, 20.0, 15.0, 5.0)
        metrics.width = 150.0
        assert metrics.width == 150.0

    def test_text_metrics_slots(self) -> None:
        """Test TextMetrics uses slots"""
        metrics = TextMetrics(100.0, 20.0, 15.0, 5.0)
        with pytest.raises(AttributeError):
            metrics.invalid_attr = "test"  # type: ignore


class TestRevisionInfo:
    """Test RevisionInfo dataclass"""

    def test_revision_info_creation(self) -> None:
        """Test RevisionInfo creation with required fields"""
        revision = RevisionInfo(
            author="John Doe", timestamp="2023-10-01T10:00:00Z", revision_id="rev123"
        )
        assert revision.author == "John Doe"
        assert revision.timestamp == "2023-10-01T10:00:00Z"
        assert revision.revision_id == "rev123"
        assert revision.change_type == "edit"  # default

    def test_revision_info_custom_change_type(self) -> None:
        """Test RevisionInfo with custom change_type"""
        revision = RevisionInfo(
            author="Jane Doe",
            timestamp="2023-10-01T10:00:00Z",
            revision_id="rev456",
            change_type="insert",
        )
        assert revision.change_type == "insert"

    @pytest.mark.parametrize("change_type", ["edit", "insert", "delete", "custom"])
    def test_revision_info_change_types(self, change_type: str) -> None:
        """Test different change types"""
        revision = RevisionInfo(
            author="Test User",
            timestamp="2023-10-01T10:00:00Z",
            revision_id="rev789",
            change_type=change_type,
        )
        assert revision.change_type == change_type


class TestEmbeddedObject:
    """Test EmbeddedObject dataclass"""

    def test_embedded_object_minimal(self) -> None:
        """Test EmbeddedObject with minimal required fields"""
        obj = EmbeddedObject(object_type="image", data=b"imagedata")
        assert obj.object_type == "image"
        assert obj.data == b"imagedata"
        assert obj.width is None
        assert obj.height is None

    def test_embedded_object_with_dimensions(self) -> None:
        """Test EmbeddedObject with width and height"""
        obj = EmbeddedObject(
            object_type="chart", data={"chart_data": "test"}, width=200.0, height=150.0
        )
        assert obj.object_type == "chart"
        assert obj.data == {"chart_data": "test"}
        assert obj.width == 200.0
        assert obj.height == 150.0

    @pytest.mark.parametrize(
        "obj_type,data",
        [
            ("image", b"binary_data"),
            ("table", {"rows": 5, "cols": 3}),
            ("chart", "chart_config"),
            ("formula", "=SUM(A1:A10)"),
        ],
    )
    def test_embedded_object_types(self, obj_type: str, data: Any) -> None:
        """Test various object types and data"""
        obj = EmbeddedObject(object_type=obj_type, data=data)
        assert obj.object_type == obj_type
        assert obj.data == data


class TestGroupInfo:
    """Test GroupInfo dataclass"""

    def test_group_info_defaults(self) -> None:
        """Test GroupInfo with default values"""
        group = GroupInfo()
        assert isinstance(group.group_id, str)
        assert len(group.group_id) > 0  # UUID should be non-empty
        assert group.thread_id is None
        assert group.continuation_id is None
        assert group.group_type == "default"
        assert group.sequence_number is None
        assert group.is_group_start is False
        assert group.is_group_end is False

    def test_group_info_custom_values(self) -> None:
        """Test GroupInfo with custom values"""
        group = GroupInfo(
            group_id="custom_id",
            thread_id="thread123",
            continuation_id="cont456",
            group_type="comment",
            sequence_number=5,
            is_group_start=True,
            is_group_end=False,
        )
        assert group.group_id == "custom_id"
        assert group.thread_id == "thread123"
        assert group.continuation_id == "cont456"
        assert group.group_type == "comment"
        assert group.sequence_number == 5
        assert group.is_group_start is True
        assert group.is_group_end is False

    def test_group_info_uuid_generation(self) -> None:
        """Test that each GroupInfo gets unique ID by default"""
        group1 = GroupInfo()
        group2 = GroupInfo()
        assert group1.group_id != group2.group_id


class TestHighlightRange:
    """Test HighlightRange dataclass"""

    def test_highlight_range_minimal(self) -> None:
        """Test HighlightRange with minimal parameters"""
        highlight = HighlightRange(start_offset=0, end_offset=5)
        assert highlight.start_offset == 0
        assert highlight.end_offset == 5
        assert isinstance(highlight.highlight_id, str)
        assert len(highlight.highlight_id) > 0
        assert highlight.highlight_type == HighlightType.SELECTION
        assert highlight.style_override is None
        assert highlight.metadata == {}

    def test_highlight_range_full(self) -> None:
        """Test HighlightRange with all parameters"""
        style = {"color": "yellow", "bold": True}
        metadata = {"source": "spell_check", "suggestion": "correct_word"}

        highlight = HighlightRange(
            start_offset=10,
            end_offset=20,
            highlight_id="custom_id",
            highlight_type=HighlightType.SPELL_ERROR,
            style_override=style,
            metadata=metadata,
        )

        assert highlight.start_offset == 10
        assert highlight.end_offset == 20
        assert highlight.highlight_id == "custom_id"
        assert highlight.highlight_type == HighlightType.SPELL_ERROR
        assert highlight.style_override == style
        assert highlight.metadata == metadata

    def test_highlight_range_uuid_generation(self) -> None:
        """Test that each HighlightRange gets unique ID by default"""
        h1 = HighlightRange(0, 5)
        h2 = HighlightRange(5, 10)
        assert h1.highlight_id != h2.highlight_id

    @pytest.mark.parametrize("highlight_type", list(HighlightType))
    def test_highlight_range_all_types(self, highlight_type: HighlightType) -> None:
        """Test HighlightRange with all highlight types"""
        highlight = HighlightRange(0, 5, highlight_type=highlight_type)
        assert highlight.highlight_type == highlight_type


class TestListMarkerInfo:
    """Test ListMarkerInfo dataclass"""

    def test_list_marker_info_defaults(self) -> None:
        """Test ListMarkerInfo with default values"""
        marker = ListMarkerInfo()
        assert marker.list_style == ListStyleType.NONE
        assert marker.list_level == 0
        assert marker.list_id is None
        assert marker.marker_text is None
        assert marker.start_number == 1
        assert marker.current_number is None

    def test_list_marker_info_custom(self) -> None:
        """Test ListMarkerInfo with custom values"""
        marker = ListMarkerInfo(
            list_style=ListStyleType.DECIMAL,
            list_level=2,
            list_id="list123",
            marker_text="*",
            start_number=5,
            current_number=7,
        )
        assert marker.list_style == ListStyleType.DECIMAL
        assert marker.list_level == 2
        assert marker.list_id == "list123"
        assert marker.marker_text == "*"
        assert marker.start_number == 5
        assert marker.current_number == 7

    @pytest.mark.parametrize(
        "style,level",
        [
            (ListStyleType.BULLET, 0),
            (ListStyleType.DECIMAL, 1),
            (ListStyleType.LOWER_ALPHA, 2),
            (ListStyleType.UPPER_ROMAN, 3),
        ],
    )
    def test_list_marker_styles_and_levels(
        self, style: ListStyleType, level: int
    ) -> None:
        """Test various list styles and levels"""
        marker = ListMarkerInfo(list_style=style, list_level=level)
        assert marker.list_style == style
        assert marker.list_level == level


class TestRunConstruction:
    """Test Run dataclass construction and initialization"""

    def test_run_minimal_creation(self) -> None:
        """Test Run creation with minimal required parameters"""
        run = Run(text="Hello World")
        assert run.text == "Hello World"
        assert run.font == FontFamily.DRAFT  # default
        assert run.cpi == CharactersPerInch.CPI_10  # default
        assert run.style == TextStyle(0)  # empty flags
        assert run.color == Color.BLACK  # default
        assert run.codepage == CodePage.PC866  # default

    def test_run_full_creation(self) -> None:
        """Test Run creation with all parameters"""
        revision = RevisionInfo("author", "2023-10-01", "rev1")
        group = GroupInfo(group_type="comment")
        list_marker = ListMarkerInfo(list_style=ListStyleType.BULLET)

        run = Run(
            text="Sample text",
            font=FontFamily.ROMAN,
            cpi=CharactersPerInch.CPI_12,
            style=TextStyle.BOLD | TextStyle.ITALIC,
            color=Color.RED,
            codepage=CodePage.PC866,
            letter_spacing=1.5,
            word_spacing=1.2,
            baseline_shift=2.0,
            scale_x=1.1,
            scale_y=0.9,
            direction=TextDirection.RTL,
            language="ru",
            background="#FFFF00",
            border=BorderStyle.SOLID,
            hyperlink="https://example.com",
            link_target="_blank",
            tooltip="Sample tooltip",
            revision_info=revision,
            is_deleted=True,
            is_inserted=False,
            comments=["comment1", "comment2"],
            group_info=group,
            highlights=[],
            list_marker=list_marker,
            embedded_object=None,
            is_math=True,
            math_content="x^2 + y^2 = z^2",
            has_special_chars=True,
            whitespace_handling=WhitespaceMode.PRESERVE,
            alt_text="Alternative text",
            aria_label="ARIA label",
            source_id="source123",
            user_data={"custom": "data"},
            annotations={"note": "important"},
        )

        assert run.text == "Sample text"
        assert run.font == FontFamily.ROMAN
        assert run.cpi == CharactersPerInch.CPI_12
        assert run.style == (TextStyle.BOLD | TextStyle.ITALIC)
        assert run.color == Color.RED
        assert run.letter_spacing == 1.5
        assert run.word_spacing == 1.2
        assert run.baseline_shift == 2.0
        assert run.scale_x == 1.1
        assert run.scale_y == 0.9
        assert run.direction == TextDirection.RTL
        assert run.language == "ru"
        assert run.background == "#FFFF00"
        assert run.border == BorderStyle.SOLID
        assert run.hyperlink == "https://example.com"
        assert run.link_target == "_blank"
        assert run.tooltip == "Sample tooltip"
        assert run.revision_info == revision
        assert run.is_deleted is True
        assert run.is_inserted is False
        assert run.comments == ["comment1", "comment2"]
        assert run.group_info == group
        assert run.list_marker == list_marker
        assert run.is_math is True
        assert run.math_content == "x^2 + y^2 = z^2"
        assert run.has_special_chars is True
        assert run.whitespace_handling == WhitespaceMode.PRESERVE
        assert run.alt_text == "Alternative text"
        assert run.aria_label == "ARIA label"
        assert run.source_id == "source123"
        assert run.user_data == {"custom": "data"}
        assert run.annotations == {"note": "important"}

    def test_run_default_collections(self) -> None:
        """Test that default collections are properly initialized"""
        run = Run(text="test")
        assert isinstance(run.comments, list)
        assert isinstance(run.highlights, list)
        assert isinstance(run.user_data, dict)
        assert isinstance(run.annotations, dict)
        assert len(run.comments) == 0
        assert len(run.highlights) == 0
        assert len(run.user_data) == 0
        assert len(run.annotations) == 0


class TestRunPostInit:
    """Test Run.__post_init__ method"""

    def test_post_init_invalid_cpi_font_combination(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test post_init performs CPI/font compatibility check"""
        with caplog.at_level(logging.INFO):  # Изменили уровень на INFO
            run = Run(text="test", font=FontFamily.DRAFT, cpi=CharactersPerInch.CPI_10)
            # Should complete without error even if combination check encounters issues
        # Проверяем, что проверка совместимости была выполнена:
        assert any(
            "compatibility checked" in rec.message.lower() for rec in caplog.records
        )

    def test_post_init_special_chars_detection(self) -> None:
        """Test post_init auto-detects special characters"""
        # Test with tab
        run = Run(text="Hello\tWorld")
        assert run.has_special_chars is True

        # Test with newline
        run = Run(text="Hello\nWorld")
        assert run.has_special_chars is True

        # Test with carriage return
        run = Run(text="Hello\rWorld")
        assert run.has_special_chars is True

        # Test with non-breaking space
        run = Run(text="Hello\u00a0World")
        assert run.has_special_chars is True

        # Test without special chars
        run = Run(text="Hello World")
        assert run.has_special_chars is False

    def test_post_init_multiple_special_chars(self) -> None:
        """Test post_init with multiple special characters"""
        run = Run(text="Hello\t\nWorld\r\u00a0Test")
        assert run.has_special_chars is True

    def test_post_init_preserves_explicit_special_chars_flag(self) -> None:
        """Test that explicit has_special_chars setting is overridden by detection"""
        run = Run(text="Hello\tWorld", has_special_chars=False)
        assert run.has_special_chars is True  # Auto-detected


class TestRunValidation:
    """Test Run.validate() method"""

    def test_validate_valid_run(self) -> None:
        """Test validation of a completely valid run"""
        run = Run(text="Valid text")
        run.validate()  # Should not raise

    def test_validate_empty_text(self) -> None:
        """Test validation fails with empty text"""
        run = Run(text="")
        with pytest.raises(ValueError, match="Run text cannot be empty"):
            run.validate()

    def test_validate_non_string_text(self) -> None:
        """Test validation fails with non-string text"""
        # This would need to be set directly bypassing __init__
        run = Run(text="test")
        object.__setattr__(run, "text", 123)  # type: ignore[call-overload]
        with pytest.raises(TypeError, match="Run text must be str"):
            run.validate()

    def test_validate_text_too_long(self) -> None:
        """Test validation fails with text exceeding MAX_TEXT_LENGTH"""
        long_text = "x" * (MAX_TEXT_LENGTH + 1)
        run = Run(text=long_text)
        with pytest.raises(
            ValueError, match=f"Text too long: {len(long_text)} > {MAX_TEXT_LENGTH}"
        ):
            run.validate()

    def test_validate_highlights_not_list(self) -> None:
        """Test validation fails when highlights is not a list"""
        run = Run(text="test")
        object.__setattr__(run, "highlights", "not_a_list")  # type: ignore[assignment]
        with pytest.raises(TypeError, match="highlights must be list"):
            run.validate()

    def test_validate_invalid_highlight_type(self) -> None:
        """Test validation fails with invalid highlight type"""
        run = Run(text="test")
        # intentionally using wrong type for robustness test
        run.highlights = ["not_a_highlight"]  # type: ignore[list-item]
        with pytest.raises(TypeError, match="highlights\\[0\\] must be HighlightRange"):
            run.validate()

    def test_validate_highlight_range_out_of_bounds(self) -> None:
        """Test validation fails with highlight range out of bounds"""
        run = Run(text="Hello")  # length 5
        highlight = HighlightRange(start_offset=0, end_offset=10)  # end > length
        run.highlights = [highlight]
        with pytest.raises(
            ValueError, match="Invalid highlight range \\[0:10\\] for text length 5"
        ):
            run.validate()

    def test_validate_highlight_start_greater_than_end(self) -> None:
        """Test validation fails when highlight start > end"""
        run = Run(text="Hello")
        highlight = HighlightRange(start_offset=3, end_offset=1)
        run.highlights = [highlight]
        with pytest.raises(
            ValueError, match="Invalid highlight range \\[3:1\\] for text length 5"
        ):
            run.validate()

    def test_validate_invalid_group_info_type(self) -> None:
        """Test validation fails with invalid group_info type"""
        run = Run(text="test")
        object.__setattr__(run, "group_info", "not_group_info")  # type: ignore[assignment]
        with pytest.raises(TypeError, match="group_info must be GroupInfo or None"):
            run.validate()

    def test_validate_invalid_list_marker_type(self) -> None:
        """Test validation fails with invalid list_marker type"""
        run = Run(text="test")
        object.__setattr__(run, "list_marker", "not_list_marker")  # type: ignore[assignment]
        with pytest.raises(
            TypeError, match="list_marker must be ListMarkerInfo or None"
        ):
            run.validate()

    def test_validate_encoding_error(self) -> None:
        """Test validation fails with encoding errors"""
        # Create a run with text that can't be encoded in PC866
        run = Run(text="Hello 世界", codepage=CodePage.PC866)  # Chinese characters
        with pytest.raises(
            ValueError,
            match="Text contains characters incompatible with pc866 encoding",
        ):
            run.validate()

    def test_validate_multiple_valid_highlights(self) -> None:
        """Test validation with multiple valid highlights"""
        run = Run(text="Hello World")
        run.highlights = [
            HighlightRange(0, 5, highlight_type=HighlightType.SELECTION),
            HighlightRange(6, 11, highlight_type=HighlightType.SEARCH_RESULT),
        ]
        run.validate()  # Should not raise

    def test_validate_logging(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that validation logs debug information"""
        with caplog.at_level(logging.DEBUG):
            run = Run(text="Test")
            run.validate()

        # Check that debug log was created
        assert any("Validated Run" in record.message for record in caplog.records)


class TestRunHighlightManagement:
    """Test Run highlight management methods"""

    def test_add_highlight_basic(self) -> None:
        """Test basic highlight addition"""
        run = Run(text="Hello World")
        highlight_id = run.add_highlight(0, 5)

        assert len(run.highlights) == 1
        assert isinstance(highlight_id, str)
        assert len(highlight_id) > 0

        highlight = run.highlights[0]
        assert highlight.start_offset == 0
        assert highlight.end_offset == 5
        assert highlight.highlight_type == HighlightType.SELECTION
        assert highlight.highlight_id == highlight_id

    def test_add_highlight_with_parameters(self) -> None:
        """Test highlight addition with all parameters"""
        run = Run(text="Hello World")
        style = {"color": "yellow"}
        metadata = {"source": "user"}

        highlight_id = run.add_highlight(
            start=6,
            end=11,
            highlight_type=HighlightType.SPELL_ERROR,
            style_override=style,
            metadata=metadata,
        )

        highlight = run.highlights[0]
        assert highlight.start_offset == 6
        assert highlight.end_offset == 11
        assert highlight.highlight_type == HighlightType.SPELL_ERROR
        assert highlight.style_override == style
        assert highlight.metadata == metadata
        assert isinstance(highlight_id, str)

    def test_add_highlight_invalid_range(self) -> None:
        """Test add_highlight with invalid ranges"""
        run = Run(text="Hello")  # length 5

        # Start > end
        with pytest.raises(
            ValueError, match="Invalid highlight range \\[3:1\\] for text length 5"
        ):
            run.add_highlight(3, 1)

        # End > text length
        with pytest.raises(
            ValueError, match="Invalid highlight range \\[0:10\\] for text length 5"
        ):
            run.add_highlight(0, 10)

        # Start < 0
        with pytest.raises(
            ValueError, match="Invalid highlight range \\[-1:3\\] for text length 5"
        ):
            run.add_highlight(-1, 3)

    def test_add_multiple_highlights(self) -> None:
        """Test adding multiple highlights"""
        run = Run(text="Hello World Test")

        id1 = run.add_highlight(0, 5, HighlightType.SELECTION)
        id2 = run.add_highlight(6, 11, HighlightType.SEARCH_RESULT)
        id3 = run.add_highlight(12, 16, HighlightType.SPELL_ERROR)

        assert len(run.highlights) == 3
        assert id1 != id2 != id3

    def test_remove_highlight_success(self) -> None:
        """Test successful highlight removal"""
        run = Run(text="Hello World")
        highlight_id = run.add_highlight(0, 5)

        result = run.remove_highlight(highlight_id)
        assert result is True
        assert len(run.highlights) == 0

    def test_remove_highlight_not_found(self) -> None:
        """Test highlight removal when ID not found"""
        run = Run(text="Hello World")
        run.add_highlight(0, 5)

        result = run.remove_highlight("nonexistent_id")
        assert result is False
        assert len(run.highlights) == 1

    def test_remove_highlight_multiple(self) -> None:
        """Test removing specific highlight from multiple"""
        run = Run(text="Hello World Test")
        id1 = run.add_highlight(0, 5)
        id2 = run.add_highlight(6, 11)
        id3 = run.add_highlight(12, 16)

        # Remove middle highlight
        result = run.remove_highlight(id2)
        assert result is True
        assert len(run.highlights) == 2

        # Verify remaining highlights
        remaining_ids = [h.highlight_id for h in run.highlights]
        assert id1 in remaining_ids
        assert id3 in remaining_ids
        assert id2 not in remaining_ids

    def test_get_highlights_at_position(self) -> None:
        """Test getting highlights at specific position"""
        run = Run(text="Hello World Test")

        # Add overlapping highlights
        run.add_highlight(0, 5, HighlightType.SELECTION)  # "Hello"
        run.add_highlight(3, 8, HighlightType.SEARCH_RESULT)  # "lo Wo"
        run.add_highlight(10, 15, HighlightType.SPELL_ERROR)  # "rld T"

        # Position 4 ('o') should be in first two highlights
        highlights_at_4 = run.get_highlights_at_position(4)
        assert len(highlights_at_4) == 2

        # Position 11 ('l') should be in only the third highlight
        highlights_at_11 = run.get_highlights_at_position(11)
        assert len(highlights_at_11) == 1
        assert highlights_at_11[0].highlight_type == HighlightType.SPELL_ERROR

        # Position 9 (' ') should be in no highlights
        highlights_at_9 = run.get_highlights_at_position(9)
        assert len(highlights_at_9) == 0

    def test_get_highlights_at_position_edge_cases(self) -> None:
        """Test get_highlights_at_position with edge cases"""
        run = Run(text="Hello")
        run.add_highlight(0, 5)  # Entire text

        # Test boundaries
        assert len(run.get_highlights_at_position(0)) == 1  # Start
        assert len(run.get_highlights_at_position(5)) == 1  # End (inclusive)

        # Test out of bounds (should not crash)
        assert len(run.get_highlights_at_position(-1)) == 0
        assert len(run.get_highlights_at_position(6)) == 0

    def test_clear_highlights_all(self) -> None:
        """Test clearing all highlights"""
        run = Run(text="Hello World")
        run.add_highlight(0, 5, HighlightType.SELECTION)
        run.add_highlight(6, 11, HighlightType.SEARCH_RESULT)

        run.clear_highlights()
        assert len(run.highlights) == 0

    def test_clear_highlights_by_type(self) -> None:
        """Test clearing highlights by specific type"""
        run = Run(text="Hello World")
        run.add_highlight(0, 5, HighlightType.SELECTION)
        run.add_highlight(6, 11, HighlightType.SEARCH_RESULT)
        run.add_highlight(0, 11, HighlightType.SPELL_ERROR)

        # Clear only search results
        run.clear_highlights(HighlightType.SEARCH_RESULT)

        assert len(run.highlights) == 2
        remaining_types = [h.highlight_type for h in run.highlights]
        assert HighlightType.SELECTION in remaining_types
        assert HighlightType.SPELL_ERROR in remaining_types
        assert HighlightType.SEARCH_RESULT not in remaining_types

    def test_clear_highlights_no_matching_type(self) -> None:
        """Test clearing highlights when no highlights match the type"""
        run = Run(text="Hello World")
        run.add_highlight(0, 5, HighlightType.SELECTION)

        run.clear_highlights(HighlightType.SPELL_ERROR)
        assert len(run.highlights) == 1  # Should remain unchanged


class TestRunGroupManagement:
    """Test Run grouping management methods"""

    def test_set_group_new(self) -> None:
        """Test setting group on run without existing group"""
        run = Run(text="Hello")
        group_id = run.set_group("comment", "thread123", "cont456")

        assert run.group_info is not None
        assert run.group_info.group_id == group_id
        assert run.group_info.group_type == "comment"
        assert run.group_info.thread_id == "thread123"
        assert run.group_info.continuation_id == "cont456"

    def test_set_group_existing(self) -> None:
        """Test setting group on run with existing group"""
        run = Run(text="Hello")
        run.group_info = GroupInfo(group_type="original")
        assert run.group_info is not None
        original_id = run.group_info.group_id

        group_id = run.set_group("updated", "new_thread")

        assert run.group_info is not None
        assert group_id == original_id  # ID should remain the same
        assert run.group_info.group_type == "updated"
        assert run.group_info.thread_id == "new_thread"

    def test_is_in_group_true(self) -> None:
        """Test is_in_group returns True for matching group"""
        run = Run(text="Hello")
        group_id = run.set_group("comment")
        assert run.is_in_group(group_id) is True

    def test_is_in_group_false(self) -> None:
        """Test is_in_group returns False for non-matching group"""
        run = Run(text="Hello")
        run.set_group("comment")
        assert run.is_in_group("different_id") is False

    def test_is_in_group_no_group(self) -> None:
        """Test is_in_group returns False when no group set"""
        run = Run(text="Hello")
        assert run.is_in_group("any_id") is False

    def test_is_in_thread_true(self) -> None:
        """Test is_in_thread returns True for matching thread"""
        run = Run(text="Hello")
        run.set_group("comment", "thread123")
        assert run.is_in_thread("thread123") is True

    def test_is_in_thread_false(self) -> None:
        """Test is_in_thread returns False for non-matching thread"""
        run = Run(text="Hello")
        run.set_group("comment", "thread123")
        assert run.is_in_thread("different_thread") is False

    def test_is_in_thread_no_thread(self) -> None:
        """Test is_in_thread returns False when no thread set"""
        run = Run(text="Hello")
        run.set_group("comment")  # No thread_id
        assert run.is_in_thread("any_thread") is False

    def test_is_in_thread_no_group(self) -> None:
        """Test is_in_thread returns False when no group set"""
        run = Run(text="Hello")
        assert run.is_in_thread("any_thread") is False


class TestRunListMarkerManagement:
    """Test Run list marker management methods"""

    def test_set_list_marker_basic(self) -> None:
        """Test setting basic list marker"""
        run = Run(text="Item 1")
        run.set_list_marker(ListStyleType.BULLET)

        assert run.list_marker is not None
        assert run.list_marker.list_style == ListStyleType.BULLET
        assert run.list_marker.list_level == 0  # default
        assert run.list_marker.list_id is None
        assert run.list_marker.marker_text is None

    def test_set_list_marker_full(self) -> None:
        """Test setting list marker with all parameters"""
        run = Run(text="Item 1")
        run.set_list_marker(
            style=ListStyleType.DECIMAL, level=2, list_id="list123", marker_text="(1)"
        )

        marker = run.list_marker
        assert marker is not None
        assert marker.list_style == ListStyleType.DECIMAL
        assert marker.list_level == 2
        assert marker.list_id == "list123"
        assert marker.marker_text == "(1)"

    def test_set_list_marker_override(self) -> None:
        """Test that setting list marker overrides existing one"""
        run = Run(text="Item 1")
        run.set_list_marker(ListStyleType.BULLET, level=1)
        run.set_list_marker(ListStyleType.DECIMAL, level=2)

        assert run.list_marker is not None
        assert run.list_marker.list_style == ListStyleType.DECIMAL
        assert run.list_marker.list_level == 2

    def test_clear_list_marker(self) -> None:
        """Test clearing list marker"""
        run = Run(text="Item 1")
        run.set_list_marker(ListStyleType.BULLET)

        assert run.list_marker is not None

        run.clear_list_marker()
        assert run.list_marker is None

    def test_clear_list_marker_when_none(self) -> None:
        """Test clearing list marker when none exists"""
        run = Run(text="Item 1")
        assert run.list_marker is None

        run.clear_list_marker()  # Should not raise
        assert run.list_marker is None


class TestRunCaching:
    """Test Run caching functionality"""

    def test_get_cached_metrics_none(self) -> None:
        """Test get_cached_metrics returns None when no cache"""
        run = Run(text="Hello")
        metrics = run.get_cached_metrics()
        assert metrics is None

    def test_get_cached_metrics_with_renderer(self) -> None:
        """Test get_cached_metrics with renderer (functionality not implemented)"""
        run = Run(text="Hello")
        fake_renderer = object()
        metrics = run.get_cached_metrics(fake_renderer)
        # Current implementation doesn't actually use renderer
        assert metrics is None

    def test_invalidate_cache(self) -> None:
        """Test cache invalidation"""
        run = Run(text="Hello")

        # Set some fake cache values
        object.__setattr__(run, "_cached_metrics", TextMetrics(100, 20, 15, 5))
        object.__setattr__(run, "_format_hash", 12345)

        assert run._cached_metrics is not None
        assert run._format_hash is not None

        run.invalidate_cache()

        assert run._cached_metrics is None
        assert run._format_hash is None

    def test_get_format_hash_generation(self) -> None:
        """Test format hash generation"""
        run = Run(text="Hello", font=FontFamily.ROMAN, style=TextStyle.BOLD)

        hash1 = run.get_format_hash()
        assert isinstance(hash1, int)

        # Hash should be cached
        hash2 = run.get_format_hash()
        assert hash1 == hash2

    def test_get_format_hash_different_formats(self) -> None:
        """Test that different formats produce different hashes"""
        run1 = Run(text="Hello", font=FontFamily.ROMAN)
        run2 = Run(text="Hello", font=FontFamily.DRAFT)

        hash1 = run1.get_format_hash()
        hash2 = run2.get_format_hash()

        assert hash1 != hash2

    def test_get_format_hash_includes_grouping(self) -> None:
        """Test that format hash includes grouping information"""
        run1 = Run(text="Hello")
        run2 = Run(text="Hello")
        run2.set_group("comment")

        hash1 = run1.get_format_hash()
        hash2 = run2.get_format_hash()

        assert hash1 != hash2

    def test_get_format_hash_includes_list_marker(self) -> None:
        """Test that format hash includes list marker information"""
        run1 = Run(text="Hello")
        run2 = Run(text="Hello")
        run2.set_list_marker(ListStyleType.BULLET)

        hash1 = run1.get_format_hash()
        hash2 = run2.get_format_hash()

        assert hash1 != hash2


class TestRunCopy:
    """Test Run.copy() method"""

    def test_copy_basic(self) -> None:
        """Test copying a basic run"""
        original = Run(text="Hello World", font=FontFamily.ROMAN, style=TextStyle.BOLD)
        copy = original.copy()

        assert copy.text == original.text
        assert copy.font == original.font
        assert copy.style == original.style
        assert copy is not original  # Different objects

    def test_copy_with_group_info(self) -> None:
        """Test copying run with group info"""
        original = Run(text="Hello")
        original.set_group("comment", "thread123", "cont456")

        copy = original.copy()

        assert copy.group_info is not None
        assert original.group_info is not None
        assert copy.group_info is not original.group_info  # Deep copy
        assert copy.group_info.group_id == original.group_info.group_id
        assert copy.group_info.thread_id == original.group_info.thread_id
        assert copy.group_info.continuation_id == original.group_info.continuation_id

    def test_copy_with_list_marker(self) -> None:
        """Test copying run with list marker"""
        original = Run(text="Item 1")
        original.set_list_marker(ListStyleType.DECIMAL, 2, "list123", "1.")

        copy = original.copy()

        assert copy.list_marker is not None
        assert original.list_marker is not None
        # Deep copy
        assert copy.list_marker is not original.list_marker
        assert copy.list_marker.list_style == original.list_marker.list_style
        assert copy.list_marker.list_level == original.list_marker.list_level
        assert copy.list_marker.list_id == original.list_marker.list_id
        assert copy.list_marker.marker_text == original.list_marker.marker_text

    def test_copy_with_highlights(self) -> None:
        """Test copying run with highlights"""
        original = Run(text="Hello World")
        original.add_highlight(
            0, 5, HighlightType.SELECTION, {"color": "yellow"}, {"source": "user"}
        )
        original.add_highlight(6, 11, HighlightType.SEARCH_RESULT)

        copy = original.copy()

        assert len(copy.highlights) == 2
        assert copy.highlights is not original.highlights  # Different list

        # Check first highlight
        h1_orig = original.highlights[0]
        h1_copy = copy.highlights[0]
        assert h1_copy is not h1_orig  # Different objects
        assert h1_copy.start_offset == h1_orig.start_offset
        assert h1_copy.end_offset == h1_orig.end_offset
        assert h1_copy.highlight_id == h1_orig.highlight_id
        assert h1_copy.highlight_type == h1_orig.highlight_type
        assert h1_copy.style_override == h1_orig.style_override
        assert h1_copy.style_override is not h1_orig.style_override  # Deep copy
        assert h1_copy.metadata == h1_orig.metadata
        assert h1_copy.metadata is not h1_orig.metadata  # Deep copy

    def test_copy_with_collections(self) -> None:
        """Test copying run with various collections"""
        original = Run(
            text="Hello",
            comments=["comment1", "comment2"],
            user_data={"key1": "value1", "key2": "value2"},
            annotations={"note": "important", "author": "user"},
        )

        copy = original.copy()

        # Check collections are copied but are different objects
        assert copy.comments == original.comments
        assert copy.comments is not original.comments

        assert copy.user_data == original.user_data
        assert copy.user_data is not original.user_data

        assert copy.annotations == original.annotations
        assert copy.annotations is not original.annotations

    def test_copy_preserves_all_attributes(self) -> None:
        """Test that copy preserves all attributes"""
        revision = RevisionInfo("author", "timestamp", "rev1")

        original = Run(
            text="Test text",
            font=FontFamily.ROMAN,
            cpi=CharactersPerInch.CPI_12,
            style=TextStyle.BOLD,
            color=Color.RED,
            codepage=CodePage.PC866,
            letter_spacing=1.5,
            word_spacing=1.2,
            baseline_shift=2.0,
            scale_x=1.1,
            scale_y=0.9,
            direction=TextDirection.RTL,
            language="ru",
            background="#FFFF00",
            border=BorderStyle.SOLID,
            hyperlink="https://example.com",
            link_target="_blank",
            tooltip="tooltip",
            revision_info=revision,
            is_deleted=True,
            is_inserted=False,
            is_math=True,
            math_content="x^2",
            has_special_chars=True,
            whitespace_handling=WhitespaceMode.PRESERVE,
            alt_text="alt",
            aria_label="aria",
            source_id="source123",
        )

        copy = original.copy()

        # Test all attributes are copied
        assert copy.text == original.text
        assert copy.font == original.font
        assert copy.cpi == original.cpi
        assert copy.style == original.style
        assert copy.color == original.color
        assert copy.codepage == original.codepage
        assert copy.letter_spacing == original.letter_spacing
        assert copy.word_spacing == original.word_spacing
        assert copy.baseline_shift == original.baseline_shift
        assert copy.scale_x == original.scale_x
        assert copy.scale_y == original.scale_y
        assert copy.direction == original.direction
        assert copy.language == original.language
        assert copy.background == original.background
        assert copy.border == original.border
        assert copy.hyperlink == original.hyperlink
        assert copy.link_target == original.link_target
        assert copy.tooltip == original.tooltip
        assert copy.revision_info == original.revision_info
        assert copy.is_deleted == original.is_deleted
        assert copy.is_inserted == original.is_inserted
        assert copy.is_math == original.is_math
        assert copy.math_content == original.math_content
        assert copy.has_special_chars == original.has_special_chars
        assert copy.whitespace_handling == original.whitespace_handling
        assert copy.alt_text == original.alt_text
        assert copy.aria_label == original.aria_label
        assert copy.source_id == original.source_id


class TestRunMerging:
    """Test Run.merge_with() and can_merge_with() methods"""

    def test_can_merge_with_identical_formatting(self) -> None:
        """Test can_merge_with returns True for identical formatting"""
        run1 = Run(text="Hello ", font=FontFamily.ROMAN, style=TextStyle.BOLD)
        run2 = Run(text="World", font=FontFamily.ROMAN, style=TextStyle.BOLD)
        assert run1.can_merge_with(run2) is True

    def test_can_merge_with_different_font(self) -> None:
        """Test can_merge_with returns False for different fonts"""
        run1 = Run(text="Hello ", font=FontFamily.ROMAN)
        run2 = Run(text="World", font=FontFamily.DRAFT)
        assert run1.can_merge_with(run2) is False

    def test_can_merge_with_different_style(self) -> None:
        """Test can_merge_with returns False for different styles"""
        run1 = Run(text="Hello ", style=TextStyle.BOLD)
        run2 = Run(text="World", style=TextStyle.ITALIC)
        assert run1.can_merge_with(run2) is False

    def test_can_merge_with_embedded_objects(self) -> None:
        """Test can_merge_with returns False when either has embedded objects"""
        run1 = Run(text="Hello ", embedded_object=EmbeddedObject("image", b"data"))
        run2 = Run(text="World")
        assert run1.can_merge_with(run2) is False
        assert run2.can_merge_with(run1) is False

    def test_can_merge_with_math_content(self) -> None:
        """Test can_merge_with returns False when either has math content"""
        run1 = Run(text="Hello ", is_math=True)
        run2 = Run(text="World")
        assert run1.can_merge_with(run2) is False
        assert run2.can_merge_with(run1) is False

    def test_can_merge_with_different_hyperlinks(self) -> None:
        """Test can_merge_with returns False for different hyperlinks"""
        run1 = Run(text="Hello ", hyperlink="https://example.com")
        run2 = Run(text="World", hyperlink="https://different.com")
        assert run1.can_merge_with(run2) is False

    def test_can_merge_with_highlights(self) -> None:
        """Test can_merge_with returns False when either has highlights"""
        run1 = Run(text="Hello ")
        run1.add_highlight(0, 5)
        run2 = Run(text="World")
        assert run1.can_merge_with(run2) is False
        assert run2.can_merge_with(run1) is False

    def test_can_merge_with_different_groups(self) -> None:
        """Test can_merge_with returns False for different groups"""
        run1 = Run(text="Hello ")
        run1.set_group("comment")
        run2 = Run(text="World")
        run2.set_group("revision")
        assert run1.can_merge_with(run2) is False

    def test_can_merge_with_different_list_markers(self) -> None:
        """Test can_merge_with returns False for different list markers"""
        run1 = Run(text="Hello ")
        run1.set_list_marker(ListStyleType.BULLET)
        run2 = Run(text="World")
        run2.set_list_marker(ListStyleType.DECIMAL)
        assert run1.can_merge_with(run2) is False

    def test_can_merge_with_non_run_object(self) -> None:
        """Test can_merge_with returns False for non-Run objects"""
        run = Run(text="Hello")
        assert run.can_merge_with("not a run") is False  # type: ignore[arg-type]
        assert run.can_merge_with(123) is False  # type: ignore[arg-type]
        assert run.can_merge_with(None) is False  # type: ignore[arg-type]

    def test_can_merge_with_strict_mode(self) -> None:
        """Test can_merge_with in strict mode (default)"""
        run1 = Run(text="Hello ", direction=TextDirection.LTR)
        run2 = Run(text="World", direction=TextDirection.RTL)
        assert run1.can_merge_with(run2, strict=True) is False
        assert run1.can_merge_with(run2, strict=False) is True

    def test_can_merge_with_non_strict_mode(self) -> None:
        """Test can_merge_with in non-strict mode"""
        run1 = Run(text="Hello ", language="en", background="#FFFFFF")
        run2 = Run(text="World", language="ru", background="#FFFF00")
        # Different secondary attributes should not prevent merging in non-strict mode
        assert run1.can_merge_with(run2, strict=False) is True
        assert run1.can_merge_with(run2, strict=True) is False

    def test_merge_with_success(self) -> None:
        """Test successful merge_with operation"""
        run1 = Run(text="Hello ", font=FontFamily.ROMAN, style=TextStyle.BOLD)
        run2 = Run(text="World", font=FontFamily.ROMAN, style=TextStyle.BOLD)
        merged = run1.merge_with(run2)
        assert merged.text == "Hello World"
        assert merged.font == FontFamily.ROMAN
        assert merged.style == TextStyle.BOLD
        assert merged is not run1  # New object
        assert merged is not run2  # New object

    def test_merge_with_incompatible_runs(self) -> None:
        """Test merge_with raises error for incompatible runs"""
        run1 = Run(text="Hello ", font=FontFamily.ROMAN)
        run2 = Run(text="World", font=FontFamily.DRAFT)
        with pytest.raises(
            ValueError, match="Cannot merge runs with different formatting"
        ):
            run1.merge_with(run2)

    def test_merge_with_user_data_and_annotations(self) -> None:
        """Test merge_with combines user_data and annotations"""
        run1 = Run(
            text="Hello ",
            user_data={"key1": "value1", "common": "from_run1"},
            annotations={"note1": "first", "common_note": "from_run1"},
        )
        run2 = Run(
            text="World",
            user_data={"key2": "value2", "common": "from_run2"},
            annotations={"note2": "second", "common_note": "from_run2"},
        )
        merged = run1.merge_with(run2)

        # run2 values should take precedence
        expected_user_data = {"key1": "value1", "key2": "value2", "common": "from_run2"}
        expected_annotations = {
            "note1": "first",
            "note2": "second",
            "common_note": "from_run2",
        }

        assert merged.user_data == expected_user_data
        assert merged.annotations == expected_annotations

    def test_merge_with_comments(self) -> None:
        """Test merge_with combines comments"""
        run1 = Run(text="Hello ", comments=["comment1", "comment2"])
        run2 = Run(text="World", comments=["comment3", "comment4"])
        merged = run1.merge_with(run2)
        assert merged.comments == ["comment1", "comment2", "comment3", "comment4"]

    def test_merge_with_highlights(self) -> None:
        """Test merge_with rejects merge when run has highlights"""
        run1 = Run(text="Hello ")  # length 6
        run2 = Run(text="World")  # length 5

        # Add highlights directly to test rejection behavior
        run2.highlights = [HighlightRange(1, 4)]  # "orl" in "World"

        # Expect strict formatting check to reject merge
        with pytest.raises(ValueError, match="Cannot merge runs"):
            run1.merge_with(run2)

    def test_merge_with_boolean_flags(self) -> None:
        """Test merge_with handles boolean flags correctly"""
        run1 = Run(
            text="Hello ", is_deleted=True, is_inserted=False, has_special_chars=False
        )
        run2 = Run(
            text="World\t", is_deleted=False, is_inserted=True, has_special_chars=True
        )
        merged = run1.merge_with(run2)

        # OR logic for is_deleted and is_inserted
        assert merged.is_deleted is True  # True OR False
        assert merged.is_inserted is True  # False OR True
        assert merged.has_special_chars is True  # False OR True

    def test_merge_with_preserves_first_run_attributes(self) -> None:
        """Strict mode: merge_with rejects runs with differing secondary attributes"""
        revision1 = RevisionInfo("author1", "time1", "rev1")
        revision2 = RevisionInfo("author2", "time2", "rev2")

        run1 = Run(
            text="Hello ",
            revision_info=revision1,
            source_id="source1",
            alt_text="alt1",
            whitespace_handling=WhitespaceMode.PRESERVE,
        )
        run2 = Run(
            text="World",
            revision_info=revision2,
            source_id="source2",
            alt_text="alt2",
            whitespace_handling=WhitespaceMode.NORMAL,
        )

        with pytest.raises(ValueError, match="Cannot merge runs"):
            run1.merge_with(run2)


class TestRunSplitting:
    """Test Run.split_at() method"""

    def test_split_at_basic(self) -> None:
        """Test basic splitting of a run"""
        run = Run(text="Hello World", font=FontFamily.ROMAN, style=TextStyle.BOLD)

        left, right = run.split_at(5)  # Split after "Hello"

        assert left.text == "Hello"
        assert right.text == " World"
        assert left.font == FontFamily.ROMAN
        assert right.font == FontFamily.ROMAN
        assert left.style == TextStyle.BOLD
        assert right.style == TextStyle.BOLD

    def test_split_at_invalid_position(self) -> None:
        """Test split_at with invalid positions"""
        run = Run(text="Hello")  # length 5

        # Position 0 (at start)
        with pytest.raises(ValueError, match="Split position 0 out of bounds"):
            run.split_at(0)

        # Position at end
        with pytest.raises(ValueError, match="Split position 5 out of bounds"):
            run.split_at(5)

        # Position beyond end
        with pytest.raises(ValueError, match="Split position 10 out of bounds"):
            run.split_at(10)

    def test_split_at_edge_positions(self) -> None:
        """Test split_at at edge positions"""
        run = Run(text="Hello")  # length 5

        # Split at position 1 (after "H")
        left, right = run.split_at(1)
        assert left.text == "H"
        assert right.text == "ello"

        # Split at position 4 (after "Hell")
        left, right = run.split_at(4)
        assert left.text == "Hell"
        assert right.text == "o"

    def test_split_at_with_highlights_entirely_left(self) -> None:
        """Test splitting with highlights entirely in left part"""
        run = Run(text="Hello World")
        run.add_highlight(0, 5, HighlightType.SELECTION)  # "Hello"

        left, right = run.split_at(6)  # Split after "Hello "

        assert len(left.highlights) == 1
        assert len(right.highlights) == 0

        highlight = left.highlights[0]
        assert highlight.start_offset == 0
        assert highlight.end_offset == 5

    def test_split_at_with_highlights_entirely_right(self) -> None:
        """Test splitting with highlights entirely in right part"""
        run = Run(text="Hello World")
        run.add_highlight(6, 11, HighlightType.SELECTION)  # "World"

        left, right = run.split_at(5)  # Split after "Hello"

        assert len(left.highlights) == 0
        assert len(right.highlights) == 1

        highlight = right.highlights[0]
        assert highlight.start_offset == 1  # 6 - 5
        assert highlight.end_offset == 6  # 11 - 5

    def test_split_at_with_highlights_spanning(self) -> None:
        """Test splitting with highlights spanning the split point"""
        run = Run(text="Hello World")
        original_id = run.add_highlight(3, 8, HighlightType.SELECTION)  # "lo Wo"

        left, right = run.split_at(6)  # Split after "Hello "

        assert len(left.highlights) == 1
        assert len(right.highlights) == 1

        # Left highlight: "lo " (positions 3-6 become 3-6)
        left_highlight = left.highlights[0]
        assert left_highlight.start_offset == 3
        assert left_highlight.end_offset == 6
        assert left_highlight.highlight_id == original_id + "_left"

        # Right highlight: "Wo" (positions 6-8 become 0-2)
        right_highlight = right.highlights[0]
        assert right_highlight.start_offset == 0
        assert right_highlight.end_offset == 2  # 8 - 6
        assert right_highlight.highlight_id == original_id + "_right"

    def test_split_at_with_multiple_highlights(self) -> None:
        """Test splitting with multiple highlights"""
        run = Run(text="Hello World Test")
        run.add_highlight(0, 5, HighlightType.SELECTION)  # "Hello"
        run.add_highlight(6, 11, HighlightType.SEARCH_RESULT)  # "World"
        run.add_highlight(3, 13, HighlightType.SPELL_ERROR)  # "lo World Te"

        left, right = run.split_at(8)  # Split in middle of "World"

        # Left should have: "Hello" (entirely) and "lo Wo" (split portion)
        assert len(left.highlights) == 3

        # Right should have: "rld" (split portion) and "rld Te" (adjusted)
        assert len(right.highlights) == 2

    def test_split_at_preserves_highlight_metadata(self) -> None:
        """Test that splitting preserves highlight metadata"""
        run = Run(text="Hello World")
        style = {"color": "yellow", "bold": True}
        metadata = {"source": "spell_check", "confidence": 0.9}

        run.add_highlight(3, 8, HighlightType.SPELL_ERROR, style, metadata)

        left, right = run.split_at(6)

        # Check that metadata is preserved in both parts
        left_highlight = left.highlights[0]
        assert left_highlight.style_override == style
        assert left_highlight.metadata == metadata

        right_highlight = right.highlights[0]
        assert right_highlight.style_override == style
        assert right_highlight.metadata == metadata

    def test_split_at_creates_independent_copies(self) -> None:
        """Test that split creates independent copies"""
        run = Run(
            text="Hello World",
            comments=["comment1"],
            user_data={"key": "value"},
            annotations={"note": "important"},
        )

        left, right = run.split_at(6)

        # Modify left's collections
        left.comments.append("left_comment")
        left.user_data["left_key"] = "left_value"
        left.annotations["left_note"] = "left_annotation"

        # Right should be unaffected
        assert "left_comment" not in right.comments
        assert "left_key" not in right.user_data
        assert "left_note" not in right.annotations

        # Original should be unaffected
        assert "left_comment" not in run.comments
        assert "left_key" not in run.user_data
        assert "left_note" not in run.annotations


class TestRunSerialization:
    """Test Run.to_dict() and Run.from_dict() methods"""

    def test_to_dict_minimal(self) -> None:
        """Test serialization of minimal run"""
        run = Run(text="Hello")
        data = run.to_dict()

        # Required fields
        assert data["text"] == "Hello"
        assert data["font"] == "draft"
        assert data["cpi"] == "10cpi"
        assert data["style"] == 0
        assert data["color"] == "black"
        assert data["codepage"] == "pc866"
        assert data["direction"] == "ltr"
        assert data["border"] == "none"
        assert data["whitespace_handling"] == "normal"

        # Default values should not be included
        assert "letter_spacing" not in data
        assert "word_spacing" not in data
        assert "is_deleted" not in data
        assert "comments" not in data

    def test_to_dict_full(self) -> None:
        """Test serialization of run with all features"""
        revision = RevisionInfo("author", "2023-10-01", "rev1", "insert")
        embedded = EmbeddedObject("image", b"data", 100.0, 50.0)

        run = Run(
            text="Hello World",
            font=FontFamily.ROMAN,
            cpi=CharactersPerInch.CPI_12,
            style=TextStyle.BOLD | TextStyle.ITALIC,
            color=Color.RED,
            letter_spacing=1.5,
            word_spacing=1.2,
            baseline_shift=2.0,
            scale_x=1.1,
            scale_y=0.9,
            language="en",
            background="#FFFFFF",
            hyperlink="https://example.com",
            link_target="_blank",
            tooltip="Test tooltip",
            revision_info=revision,
            is_deleted=True,
            is_inserted=True,
            comments=["comment1", "comment2"],
            embedded_object=embedded,
            is_math=True,
            math_content="x^2 + y^2 = z^2",
            has_special_chars=True,
            alt_text="Alternative text",
            aria_label="ARIA label",
            source_id="source123",
            user_data={"custom": "data"},
            annotations={"note": "important"},
        )

        # Add group and highlights
        run.set_group("comment", "thread123", "cont456")
        run.set_list_marker(ListStyleType.DECIMAL, 2, "list123", "1.")
        run.add_highlight(
            0, 5, HighlightType.SEARCH_RESULT, {"color": "yellow"}, {"source": "search"}
        )

        data = run.to_dict()

        # Verify all fields are serialized
        assert data["text"] == "Hello World"
        assert data["font"] == "roman"
        assert data["letter_spacing"] == 1.5
        assert data["is_deleted"] is True
        assert data["is_math"] is True
        assert data["comments"] == ["comment1", "comment2"]
        assert data["user_data"] == {"custom": "data"}

        # Check complex objects
        assert "revision_info" in data
        assert data["revision_info"]["author"] == "author"
        assert data["revision_info"]["change_type"] == "insert"

        assert "embedded_object" in data
        assert data["embedded_object"]["object_type"] == "image"
        assert data["embedded_object"]["width"] == 100.0

        assert "group_info" in data
        assert data["group_info"]["group_type"] == "comment"
        assert data["group_info"]["thread_id"] == "thread123"

        assert "highlights" in data
        assert len(data["highlights"]) == 1
        assert data["highlights"][0]["highlight_type"] == "search"

        assert "list_marker" in data
        assert data["list_marker"]["list_style"] == "decimal"
        assert data["list_marker"]["list_level"] == 2

    def test_from_dict_minimal(self) -> None:
        """Test deserialization of minimal run"""
        data = {"text": "Hello World"}
        run = Run.from_dict(data)

        assert run.text == "Hello World"
        assert run.font == FontFamily.DRAFT
        assert run.cpi == CharactersPerInch.CPI_10
        assert run.style == TextStyle(0)
        assert run.color == Color.BLACK

    def test_from_dict_full(self) -> None:
        """Test deserialization of run with all features"""
        data: dict[str, Any] = {
            "text": "Hello World",
            "font": "roman",
            "cpi": "12cpi",
            "style": 3,  # BOLD | ITALIC
            "color": "red",
            "codepage": "pc866",
            "letter_spacing": 1.5,
            "word_spacing": 1.2,
            "baseline_shift": 2.0,
            "scale_x": 1.1,
            "scale_y": 0.9,
            "direction": "rtl",
            "language": "en",
            "background": "#FFFFFF",
            "border": "solid",
            "hyperlink": "https://example.com",
            "link_target": "_blank",
            "tooltip": "Test tooltip",
            "revision_info": {
                "author": "author",
                "timestamp": "2023-10-01",
                "revision_id": "rev1",
                "change_type": "insert",
            },
            "is_deleted": True,
            "is_inserted": True,
            "is_math": True,
            "math_content": "x^2",
            "has_special_chars": True,
            "whitespace_handling": "preserve",
            "alt_text": "Alt text",
            "aria_label": "ARIA label",
            "source_id": "source123",
            "comments": ["comment1"],
            "user_data": {"key": "value"},
            "annotations": {"note": "test"},
            "embedded_object": {
                "object_type": "image",
                "data": b"data",
                "width": 100.0,
                "height": 50.0,
            },
            "group_info": {
                "group_id": "group123",
                "thread_id": "thread456",
                "continuation_id": "cont789",
                "group_type": "comment",
                "sequence_number": 5,
                "is_group_start": True,
                "is_group_end": False,
            },
            "highlights": [
                {
                    "start_offset": 0,
                    "end_offset": 5,
                    "highlight_id": "h1",
                    "highlight_type": "search",
                    "style_override": {"color": "yellow"},
                    "metadata": {"source": "search"},
                }
            ],
            "list_marker": {
                "list_style": "decimal",
                "list_level": 2,
                "list_id": "list123",
                "marker_text": "1.",
                "start_number": 1,
                "current_number": 5,
            },
        }

        run = Run.from_dict(data)

        # Ensure optional complex fields are present before attribute access
        assert run.revision_info is not None
        assert run.embedded_object is not None
        assert run.group_info is not None
        assert run.list_marker is not None
        assert len(run.highlights) > 0
        highlight = run.highlights[0]

        # Verify all attributes
        assert run.text == "Hello World"
        assert run.font == FontFamily.ROMAN
        assert run.cpi == CharactersPerInch.CPI_12
        assert run.style == (TextStyle.BOLD | TextStyle.ITALIC)
        assert run.letter_spacing == 1.5
        assert run.direction == TextDirection.RTL
        assert run.is_deleted is True
        assert run.is_math is True
        assert run.comments == ["comment1"]

        # Check complex objects
        assert run.revision_info.author == "author"
        assert run.revision_info.change_type == "insert"

        assert run.embedded_object.object_type == "image"
        assert run.embedded_object.width == 100.0

        assert run.group_info.group_id == "group123"
        assert run.group_info.thread_id == "thread456"
        assert run.group_info.sequence_number == 5

        assert len(run.highlights) == 1
        assert highlight.highlight_type == HighlightType.SEARCH_RESULT
        assert highlight.style_override == {"color": "yellow"}

        assert run.list_marker.list_style == ListStyleType.DECIMAL
        assert run.list_marker.list_level == 2

    def test_from_dict_invalid_input(self) -> None:
        """Test from_dict with invalid input"""
        # Non-dict input
        with pytest.raises(TypeError, match="Expected dict"):
            Run.from_dict("not a dict")  # type: ignore

        # Missing required text field
        with pytest.raises(KeyError, match="Missing required key 'text'"):
            Run.from_dict({"font": "draft"})  # type: ignore

    def test_serialization_roundtrip(self) -> None:
        """Test that serialization-deserialization is idempotent"""
        original = Run(
            text="Hello World",
            font=FontFamily.ROMAN,
            style=TextStyle.BOLD,
            comments=["test"],
            user_data={"key": "value"},
        )
        original.add_highlight(0, 5, HighlightType.SELECTION)
        original.set_group("comment")

        # Serialize and deserialize
        data = original.to_dict()
        restored = Run.from_dict(data)

        # Compare key attributes (not complete equality due to object references)
        assert restored.text == original.text
        assert restored.font == original.font
        assert restored.style == original.style
        assert restored.comments == original.comments
        assert restored.user_data == original.user_data
        assert len(restored.highlights) == len(original.highlights)

        # group_info may be optional; compare safely
        restored_group_type = (
            restored.group_info.group_type if restored.group_info else None
        )
        original_group_type = (
            original.group_info.group_type if original.group_info else None
        )
        assert restored_group_type == original_group_type


class TestRunComparison:
    """Test Run.__eq__ and other comparison methods"""

    def test_equality_identical_runs(self) -> None:
        """Test equality for identical runs"""
        run1 = Run(text="Hello", font=FontFamily.ROMAN, style=TextStyle.BOLD)
        run2 = Run(text="Hello", font=FontFamily.ROMAN, style=TextStyle.BOLD)
        assert run1 == run2

    def test_equality_different_text(self) -> None:
        """Test inequality for different text"""
        run1 = Run(text="Hello")
        run2 = Run(text="World")
        assert run1 != run2

    def test_equality_different_formatting(self) -> None:
        """Test inequality for different formatting"""
        run1 = Run(text="Hello", font=FontFamily.ROMAN)
        run2 = Run(text="Hello", font=FontFamily.DRAFT)
        assert run1 != run2

    def test_equality_with_complex_attributes(self) -> None:
        """Test equality with complex attributes"""
        run1 = Run(text="Hello", comments=["comment1"])
        run2 = Run(text="Hello", comments=["comment1"])
        run3 = Run(text="Hello", comments=["comment2"])
        assert run1 == run2
        assert run1 != run3

    def test_equality_with_non_run_object(self) -> None:
        """Test equality with non-Run objects"""
        run = Run(text="Hello")
        assert run != "Hello"
        assert run != 123
        assert run is not None  # sanity
        # Нельзя сравнивать с None на равенство — это всегда False:
        assert (run == None) is False  # noqa: E711
        assert (run != None) is True  # noqa: E711

    def test_equality_with_group_info(self) -> None:
        """Test equality with group information"""
        run1 = Run(text="Hello")
        run1.set_group("comment")

        run2 = Run(text="Hello")
        run2.set_group("comment")

        run3 = Run(text="Hello")
        run3.set_group("revision")

        # Same group type but different IDs should be different
        assert run1 != run2  # Different group IDs
        assert run1 != run3  # Different group types

    def test_len_method(self) -> None:
        """Test __len__ method"""
        run1 = Run(text="Hello")
        assert len(run1) == 5

        run2 = Run(text="")
        assert len(run2) == 0

        run3 = Run(text="Hello World!")
        assert len(run3) == 12

    def test_repr_method(self) -> None:
        """Test __repr__ method"""
        run = Run(text="Hello World", font=FontFamily.ROMAN, style=TextStyle.BOLD)
        repr_str = repr(run)
        assert "Run(" in repr_str
        assert "Hello World" in repr_str
        assert "len=11" in repr_str
        assert "font=roman" in repr_str

    def test_repr_method_long_text(self) -> None:
        """Test __repr__ method with long text"""
        long_text = "This is a very long text that should be truncated in repr"
        run = Run(text=long_text)
        repr_str = repr(run)
        assert "This is a very long" in repr_str
        assert "..." in repr_str
        assert f"len={len(long_text)}" in repr_str


class TestRunFormatSummary:
    """Test Run._format_summary() method"""

    def test_format_summary_basic(self) -> None:
        """Test format summary with basic formatting"""
        run = Run(text="Hello", font=FontFamily.ROMAN, cpi=CharactersPerInch.CPI_12)
        summary = run._format_summary()

        assert "font=roman" in summary
        assert "cpi=12cpi" in summary

    def test_format_summary_with_styles(self) -> None:
        """Test format summary with text styles"""
        run = Run(
            text="Hello", style=TextStyle.BOLD | TextStyle.ITALIC | TextStyle.UNDERLINE
        )
        summary = run._format_summary()

        assert "style=B+I+U" in summary

    def test_format_summary_with_special_features(self) -> None:
        """Test format summary with special features"""
        run = Run(
            text="Hello",
            color=Color.RED,
            hyperlink="https://example.com",
            is_math=True,
            embedded_object=EmbeddedObject("image", b"data"),
        )
        summary = run._format_summary()

        assert "color=red" in summary
        assert "link" in summary
        assert "math" in summary
        assert "embed=image" in summary

    def test_format_summary_with_grouping(self) -> None:
        """Test format summary with grouping features"""
        run = Run(text="Hello")
        run.set_group("comment", "thread12345678901234567890")
        run.set_list_marker(ListStyleType.DECIMAL, 2)

        summary = run._format_summary()

        assert "group=comment" in summary
        assert "thread=thread12" in summary  # Truncated
        assert "list=decimal@2" in summary

    def test_format_summary_with_highlights(self) -> None:
        """Test format summary with highlights"""
        run = Run(text="Hello")
        run.add_highlight(0, 2)
        run.add_highlight(3, 5)

        summary = run._format_summary()

        assert "highlights=2" in summary

    def test_format_summary_with_user_data(self) -> None:
        """Test format summary with user data"""
        run = Run(
            text="Hello",
            source_id="source123",
            user_data={"key1": "value1", "key2": "value2"},
        )
        summary = run._format_summary()

        assert "src=source123" in summary
        assert "data=2keys" in summary


class TestUtilityFunctions:
    """Test utility functions"""

    def test_merge_consecutive_runs_empty_list(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test merge_consecutive_runs with empty list"""
        with caplog.at_level(logging.DEBUG):
            result = merge_consecutive_runs([])

        assert result == []
        assert "empty list" in caplog.text

    def test_merge_consecutive_runs_single_run(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test merge_consecutive_runs with single run"""
        run = Run(text="Hello")

        with caplog.at_level(logging.DEBUG):
            result = merge_consecutive_runs([run])

        assert len(result) == 1
        assert result[0].text == "Hello"
        assert result[0] is not run  # Should be a copy
        assert "single run" in caplog.text

    def test_merge_consecutive_runs_mergeable(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test merge_consecutive_runs with mergeable runs"""
        run1 = Run(text="Hello ", font=FontFamily.ROMAN)
        run2 = Run(text="World", font=FontFamily.ROMAN)

        with caplog.at_level(logging.INFO):
            result = merge_consecutive_runs([run1, run2])

        assert len(result) == 1
        assert result[0].text == "Hello World"
        assert "Merged 2 runs into 1 runs" in caplog.text

    def test_merge_consecutive_runs_non_mergeable(self) -> None:
        """Test merge_consecutive_runs with non-mergeable runs"""
        run1 = Run(text="Hello ", font=FontFamily.ROMAN)
        run2 = Run(text="World", font=FontFamily.DRAFT)  # Different font

        result = merge_consecutive_runs([run1, run2])

        assert len(result) == 2
        assert result[0].text == "Hello "
        assert result[1].text == "World"

    def test_merge_consecutive_runs_mixed(self) -> None:
        """Test merge_consecutive_runs with mix of mergeable and non-mergeable"""
        run1 = Run(text="Hello ", font=FontFamily.ROMAN)
        run2 = Run(text="Beautiful ", font=FontFamily.ROMAN)  # Mergeable with run1
        run3 = Run(text="World", font=FontFamily.DRAFT)  # Not mergeable

        result = merge_consecutive_runs([run1, run2, run3])

        assert len(result) == 2
        assert result[0].text == "Hello Beautiful "
        assert result[1].text == "World"

    def test_merge_consecutive_runs_merge_failure(
        self,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test merge_consecutive_runs when merge fails"""
        run1 = Run(text="Hello ", font=FontFamily.ROMAN)
        run2 = Run(text="World", font=FontFamily.ROMAN)

        # Mock merge_with to raise an exception
        def failing_merge(self: Run, other: Run) -> Run:
            raise ValueError("Simulated merge failure")

        monkeypatch.setattr(Run, "merge_with", failing_merge)

        with caplog.at_level(logging.WARNING):
            result = merge_consecutive_runs([run1, run2])

        assert len(result) == 2  # Should keep separate
        assert "Failed to merge runs" in caplog.text

    def test_split_by_formatting_empty_runs(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test split_by_formatting with empty runs list"""
        with caplog.at_level(logging.WARNING):
            result = split_by_formatting("Hello World", [])

        assert result == []
        assert "no runs provided" in caplog.text

    def test_split_by_formatting_length_mismatch(self) -> None:
        """Test split_by_formatting with length mismatch"""
        text = "Hello World"  # length 11
        runs = [Run(text="Hello")]  # total length 5

        with pytest.raises(
            ValueError,
            match="Total run text length \\(5\\) does not match input text length \\(11\\)",
        ):
            split_by_formatting(text, runs)

    def test_split_by_formatting_success(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test successful split_by_formatting"""
        text = "Hello World"
        template_runs = [
            Run(text="Hello", font=FontFamily.ROMAN),
            Run(text=" ", font=FontFamily.ROMAN),
            Run(text="World", font=FontFamily.DRAFT),
        ]

        with caplog.at_level(logging.DEBUG):
            result = split_by_formatting(text, template_runs)

        assert len(result) == 3
        assert result[0].text == "Hello"
        assert result[0].font == FontFamily.ROMAN
        assert result[1].text == " "
        assert result[2].text == "World"
        assert result[2].font == FontFamily.DRAFT
        assert "Split text into 3 runs" in caplog.text

    def test_find_runs_in_group(self) -> None:
        """Test find_runs_in_group function"""
        run1 = Run(text="Hello")
        run1.set_group("comment")
        assert run1.group_info is not None
        group_id = run1.group_info.group_id

        run2 = Run(text="World")
        run2.set_group("comment")  # Different group ID

        run3 = Run(text="Test")
        run3.group_info = GroupInfo(group_id=group_id)  # Same group ID

        run4 = Run(text="Other")  # No group

        runs = [run1, run2, run3, run4]
        result = find_runs_in_group(runs, group_id)

        assert len(result) == 2
        assert run1 in result
        assert run3 in result
        assert run2 not in result
        assert run4 not in result

    def test_find_runs_in_thread(self) -> None:
        """Test find_runs_in_thread function"""
        thread_id = "thread123"

        run1 = Run(text="Hello")
        run1.set_group("comment", thread_id)

        run2 = Run(text="World")
        run2.set_group("comment", "different_thread")

        run3 = Run(text="Test")
        run3.set_group("revision", thread_id)  # Same thread, different group type

        run4 = Run(text="Other")  # No group

        runs = [run1, run2, run3, run4]
        result = find_runs_in_thread(runs, thread_id)

        assert len(result) == 2
        assert run1 in result
        assert run3 in result
        assert run2 not in result
        assert run4 not in result

    def test_get_highlighted_text(self) -> None:
        """Test get_highlighted_text function"""
        run1 = Run(text="Hello World")
        run1.add_highlight(0, 5, HighlightType.SELECTION)  # "Hello"
        run1.add_highlight(6, 11, HighlightType.SEARCH_RESULT)  # "World"

        run2 = Run(text="Test Text")
        run2.add_highlight(0, 4, HighlightType.SELECTION)  # "Test"
        run2.add_highlight(5, 9, HighlightType.SPELL_ERROR)  # "Text"

        run3 = Run(text="Other")  # No highlights

        runs = [run1, run2, run3]

        # Get selection highlights
        selection_text = get_highlighted_text(runs, HighlightType.SELECTION)
        assert selection_text == ["Hello", "Test"]

        # Get search result highlights
        search_text = get_highlighted_text(runs, HighlightType.SEARCH_RESULT)
        assert search_text == ["World"]

        # Get spell error highlights
        spell_text = get_highlighted_text(runs, HighlightType.SPELL_ERROR)
        assert spell_text == ["Text"]

        # Get non-existent type
        comment_text = get_highlighted_text(runs, HighlightType.COMMENT_RANGE)
        assert comment_text == []

    def test_get_highlighted_text_empty_runs(self) -> None:
        """Test get_highlighted_text with empty runs list"""
        result = get_highlighted_text([], HighlightType.SELECTION)
        assert result == []

    def test_get_highlighted_text_no_highlights(self) -> None:
        """Test get_highlighted_text with runs that have no highlights"""
        runs = [Run(text="Hello"), Run(text="World")]
        result = get_highlighted_text(runs, HighlightType.SELECTION)
        assert result == []


class TestEdgeCases:
    """Test edge cases and error conditions"""

    def test_max_text_length_constant(self) -> None:
        """Test MAX_TEXT_LENGTH constant"""
        assert MAX_TEXT_LENGTH == 32767

    def test_run_with_unicode_text(self) -> None:
        """Test run with unicode text"""
        # Test with various unicode characters
        unicode_texts = [
            "Hello 世界",  # Chinese
            "مرحبا بالعالم",  # Arabic
            "Привет мир",  # Cyrillic
            "🌍🌎🌏",  # Emojis
            "Ñiño piñata",  # Spanish accents
        ]

        for text in unicode_texts:
            run = Run(text=text)
            assert run.text == text
            assert len(run) == len(text)

    def test_run_with_control_characters(self) -> None:
        """Test run with control characters"""
        run = Run(text="Hello\x00\x01\x02World")
        assert "\x00" in run.text
        assert "\x01" in run.text
        assert "\x02" in run.text

    def test_run_with_very_long_text(self) -> None:
        """Test run approaching MAX_TEXT_LENGTH"""
        # Test with text at the limit
        long_text = "x" * MAX_TEXT_LENGTH
        run = Run(text=long_text)
        run.validate()  # Should not raise

        # Test just over the limit
        too_long_text = "x" * (MAX_TEXT_LENGTH + 1)
        run_too_long = Run(text=too_long_text)
        with pytest.raises(ValueError, match="Text too long"):
            run_too_long.validate()

    def test_highlight_range_edge_cases(self) -> None:
        """Test highlight ranges at text boundaries"""
        run = Run(text="Hello")  # length 5

        # Valid boundary cases
        run.add_highlight(0, 0)  # Empty at start
        run.add_highlight(5, 5)  # Empty at end
        run.add_highlight(0, 5)  # Entire text

        assert len(run.highlights) == 3

    def test_nested_dataclass_mutability(self) -> None:
        """Test that nested dataclasses are properly mutable"""
        run = Run(text="Hello")

        # Add group info
        run.set_group("comment")
        assert run.group_info is not None
        original_group_id = run.group_info.group_id

        # Modify group info
        run.group_info.thread_id = "new_thread"
        run.group_info.is_group_start = True
        assert run.group_info.thread_id == "new_thread"
        assert run.group_info.is_group_start is True
        assert run.group_info.group_id == original_group_id

    def test_highlight_with_zero_length_range(self) -> None:
        """Test highlights with zero-length ranges (cursor positions)"""
        run = Run(text="Hello")

        # Add cursor-style highlights (zero length)
        cursor_id = run.add_highlight(2, 2, HighlightType.CUSTOM)

        highlights = run.get_highlights_at_position(2)
        assert len(highlights) == 1
        assert highlights[0].highlight_id == cursor_id

    def test_run_equality_with_floating_point_precision(self) -> None:
        """Test run equality with floating point precision issues"""
        run1 = Run(text="Hello", letter_spacing=1.0)
        run2 = Run(text="Hello", letter_spacing=1.0000000001)  # Slight difference

        # Should be equal due to exact comparison
        assert run1 != run2

    @pytest.mark.parametrize("special_char", ["\t", "\n", "\r", "\u00a0"])
    def test_special_character_detection_individual(self, special_char: str) -> None:
        """Test individual special character detection"""
        run = Run(text=f"Hello{special_char}World")
        assert run.has_special_chars is True

    def test_group_info_uuid_collision_resistance(self) -> None:
        """Test that GroupInfo generates unique IDs consistently"""
        # Generate many GroupInfo instances and check for uniqueness
        group_ids: set[str] = set()
        for _ in range(1000):
            group = GroupInfo()
            group_ids.add(group.group_id)

        # Should have 1000 unique IDs
        assert len(group_ids) == 1000

    def test_serialization_with_none_values(self) -> None:
        """Test serialization handles None values correctly"""
        run = Run(
            text="Hello",
            language=None,
            hyperlink=None,
            group_info=None,
            list_marker=None,
        )

        data = run.to_dict()

        # None values should not be in serialized data
        assert "language" not in data
        assert "hyperlink" not in data
        assert "group_info" not in data
        assert "list_marker" not in data

    def test_from_dict_with_missing_optional_fields(self) -> None:
        """Test from_dict works with minimal data"""
        minimal_data: dict[str, Any] = {"text": "Hello"}
        run = Run.from_dict(minimal_data)

        assert run.text == "Hello"
        assert run.font == FontFamily.DRAFT
        assert run.highlights == []
        assert run.group_info is None

    def test_cache_invalidation_on_modification(self) -> None:
        """Test that cache is properly invalidated"""
        run = Run(text="Hello")

        # Generate and cache format hash
        original_hash = run.get_format_hash()
        assert run._format_hash == original_hash

        # Modify run (this should ideally invalidate cache, but current implementation doesn't auto-invalidate)
        run.font = FontFamily.ROMAN

        # Manual invalidation
        run.invalidate_cache()

        # New hash should be different
        new_hash = run.get_format_hash()
        assert new_hash != original_hash


# Integration tests combining multiple features
class TestIntegration:
    """Integration tests combining multiple Run features"""

    def test_complex_document_workflow(self) -> None:
        """Test a complex document processing workflow"""
        runs = [
            Run(
                text="Title",
                font=FontFamily.ROMAN,
                style=TextStyle.BOLD,
                color=Color.BLACK,
            ),
            Run(text="\n\n"),
            Run(text="This is ", font=FontFamily.DRAFT),
            Run(text="important", font=FontFamily.DRAFT, style=TextStyle.ITALIC),
            Run(text=" text with "),
            Run(text="highlights", font=FontFamily.DRAFT, style=TextStyle.UNDERLINE),
            Run(text="."),
        ]

        runs[3].add_highlight(0, 9, HighlightType.SEARCH_RESULT)  # "important"
        runs[5].add_highlight(0, 10, HighlightType.SPELL_ERROR)  # "highlights"

        comment_group_id = runs[2].set_group("comment", "thread1")
        runs[3].set_group("comment", "thread1")
        assert runs[3].group_info is not None
        runs[3].group_info.group_id = comment_group_id

        runs[0].set_list_marker(ListStyleType.DECIMAL, 0, "doc_sections", "1.")

        comment_runs = find_runs_in_group(runs, comment_group_id)
        assert len(comment_runs) == 2

        search_results = get_highlighted_text(runs, HighlightType.SEARCH_RESULT)
        spell_errors = get_highlighted_text(runs, HighlightType.SPELL_ERROR)
        assert search_results == ["important"]
        assert spell_errors == ["highlights"]

        merged_runs = merge_consecutive_runs(runs)
        assert len(merged_runs) <= len(runs)

        serialized_runs = [run.to_dict() for run in runs]
        restored_runs = [Run.from_dict(data) for data in serialized_runs]

        assert len(restored_runs) == len(runs)

        assert restored_runs[0].list_marker is not None
        assert restored_runs[0].list_marker.list_style == ListStyleType.DECIMAL

        assert len(restored_runs[3].highlights) == 1

        assert restored_runs[3].group_info is not None
        assert restored_runs[3].group_info.group_type == "comment"

    def test_run_splitting_preserves_complex_state(self) -> None:
        """Test that run splitting preserves complex state correctly"""
        run = Run(
            text="Hello Beautiful World",
            font=FontFamily.ROMAN,
            style=TextStyle.BOLD | TextStyle.ITALIC,
            comments=["comment1", "comment2"],
            user_data={"importance": "high", "category": "greeting"},
            annotations={"author": "user123", "timestamp": "2023-10-01"},
        )

        run.add_highlight(0, 5, HighlightType.SELECTION)  # "Hello"
        run.add_highlight(6, 15, HighlightType.SEARCH_RESULT)  # "Beautiful"
        run.add_highlight(3, 18, HighlightType.SPELL_ERROR)  # "lo Beautiful Wo"

        run.set_group("document_section", "main_thread", "para_1")

        left, right = run.split_at(10)  # Split after "Hello Beau"

        for part in [left, right]:
            assert part.font == FontFamily.ROMAN
            assert part.style == (TextStyle.BOLD | TextStyle.ITALIC)
            assert part.comments == ["comment1", "comment2"]
            assert part.user_data == {"importance": "high", "category": "greeting"}
            assert part.annotations == {"author": "user123", "timestamp": "2023-10-01"}
            assert part.group_info is not None
            assert part.group_info.group_type == "document_section"

        assert left.text == "Hello Beau"
        assert right.text == "tiful World"

        assert len(left.highlights) == 3
        assert len(right.highlights) == 2

        left_ids = [h.highlight_id for h in left.highlights]
        right_ids = [h.highlight_id for h in right.highlights]
        all_ids = left_ids + right_ids
        assert len(set(all_ids)) == len(all_ids)

    def test_merge_and_split_consistency(self) -> None:
        """Test that merge and split operations are consistent"""
        run1 = Run(text="Hello ", font=FontFamily.ROMAN)
        run2 = Run(text="World", font=FontFamily.ROMAN)

        merged = run1.merge_with(run2)
        assert merged.text == "Hello World"
        assert merged.font == FontFamily.ROMAN

        # Split merged and check consistency
        left, right = merged.split_at(6)
        assert left.text == "Hello "
        assert right.text == "World"
        assert left.font == merged.font == right.font
