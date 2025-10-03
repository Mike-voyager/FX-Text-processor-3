"""
Unit tests for src/model/run.py module.

Tests cover Run class functionality, validation, serialization,
merging, and utility functions with comprehensive edge case coverage.
"""

import logging
from typing import Any

import pytest

from src.model.run import (
    SUPPORTED_ENCODINGS,
    SUPPORTED_FONTS,
    Run,
    merge_consecutive_runs,
    split_by_formatting,
)


class TestRunInitialization:
    """Test Run initialization and post-init validation."""

    def test_minimal_initialization(self) -> None:
        """Test creating run with only required text parameter."""
        run = Run(text="Hello")

        assert run.text == "Hello"
        assert run.bold is False
        assert run.italic is False
        assert run.underline is False
        assert run.double_width is False
        assert run.double_height is False
        assert run.font_name == "draft"
        assert run.encoding == "cp866"

    def test_full_initialization(self) -> None:
        """Test creating run with all parameters specified."""
        run = Run(
            text="Test",
            bold=True,
            italic=True,
            underline=True,
            double_width=True,
            double_height=True,
            font_name="roman",
            encoding="ascii",
        )

        assert run.text == "Test"
        assert run.bold is True
        assert run.italic is True
        assert run.underline is True
        assert run.double_width is True
        assert run.double_height is True
        assert run.font_name == "roman"
        assert run.encoding == "ascii"

    def test_unsupported_font_fallback(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that unsupported font triggers warning and fallback."""
        with caplog.at_level(logging.WARNING):
            run = Run(text="Test", font_name="invalid_font")

        assert run.font_name == "draft"
        assert "not in SUPPORTED_FONTS" in caplog.text

    def test_unsupported_encoding_fallback(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that unsupported encoding triggers warning and fallback."""
        with caplog.at_level(logging.WARNING):
            run = Run(text="Test", encoding="invalid_encoding")

        assert run.encoding == "cp866"
        assert "not in SUPPORTED_ENCODINGS" in caplog.text

    def test_cyrillic_text(self) -> None:
        """Test initialization with Cyrillic text."""
        run = Run(text="Привет мир", bold=True)
        assert run.text == "Привет мир"
        assert run.bold is True


class TestRunValidation:
    """Test Run.validate() method."""

    def test_validate_valid_run(self) -> None:
        """Test validation passes for valid run."""
        run = Run(text="Hello", bold=True)
        run.validate()  # Should not raise

    def test_validate_empty_text(self) -> None:
        """Test validation fails for empty text."""
        run = Run(text="")

        with pytest.raises(ValueError, match="cannot be empty"):
            run.validate()

    def test_validate_non_string_text(self) -> None:
        """Test validation fails for non-string text."""
        # Bypass dataclass type checking by direct assignment
        run = Run(text="test")
        object.__setattr__(run, "text", 123)

        with pytest.raises(TypeError, match="must be str"):
            run.validate()

    def test_validate_encoding_incompatible_text(self) -> None:
        """Test validation fails when text cannot be encoded."""
        # Create run with Unicode emoji (incompatible with cp866)
        run = Run(text="Hello 😀", encoding="cp866")

        with pytest.raises(ValueError, match="incompatible with cp866"):
            run.validate()

    def test_validate_cyrillic_cp866(self) -> None:
        """Test validation passes for Cyrillic with cp866."""
        run = Run(text="Тест кириллицы", encoding="cp866")
        run.validate()  # Should not raise

    def test_validate_non_boolean_attribute(self) -> None:
        """Test validation fails for non-boolean formatting attribute."""
        run = Run(text="Test")
        object.__setattr__(run, "bold", "yes")

        with pytest.raises(TypeError, match="must be bool"):
            run.validate()

    @pytest.mark.parametrize(
        "text,encoding",
        [
            ("Hello", "ascii"),
            ("Привет", "cp866"),
            ("Café", "latin1"),
        ],
    )
    def test_validate_various_encodings(self, text: str, encoding: str) -> None:
        """Test validation with various text-encoding combinations."""
        run = Run(text=text, encoding=encoding)
        run.validate()


class TestRunCopy:
    """Test Run.copy() method."""

    def test_copy_creates_independent_instance(self) -> None:
        """Test that copy creates a new independent instance."""
        original = Run(text="Original", bold=True)
        copied = original.copy()

        assert copied == original
        assert copied is not original

    def test_copy_preserves_all_attributes(self) -> None:
        """Test that copy preserves all formatting attributes."""
        original = Run(
            text="Test",
            bold=True,
            italic=True,
            underline=True,
            double_width=True,
            double_height=True,
            font_name="roman",
            encoding="ascii",
        )
        copied = original.copy()

        assert copied.text == original.text
        assert copied.bold == original.bold
        assert copied.italic == original.italic
        assert copied.underline == original.underline
        assert copied.double_width == original.double_width
        assert copied.double_height == original.double_height
        assert copied.font_name == original.font_name
        assert copied.encoding == original.encoding

    def test_copy_modification_does_not_affect_original(self) -> None:
        """Test that modifying copy doesn't affect original."""
        original = Run(text="Original", bold=False)
        copied = original.copy()

        # Modify copy
        copied.text = "Modified"
        copied.bold = True

        # Original unchanged
        assert original.text == "Original"
        assert original.bold is False


class TestRunMerging:
    """Test Run.can_merge_with() and merge_with() methods."""

    def test_can_merge_identical_formatting(self) -> None:
        """Test that runs with identical formatting can merge."""
        run1 = Run(text="Hello", bold=True, italic=False)
        run2 = Run(text=" World", bold=True, italic=False)

        assert run1.can_merge_with(run2) is True

    def test_cannot_merge_different_bold(self) -> None:
        """Test that runs with different bold cannot merge."""
        run1 = Run(text="Hello", bold=True)
        run2 = Run(text=" World", bold=False)

        assert run1.can_merge_with(run2) is False

    def test_cannot_merge_different_italic(self) -> None:
        """Test that runs with different italic cannot merge."""
        run1 = Run(text="Hello", italic=True)
        run2 = Run(text=" World", italic=False)

        assert run1.can_merge_with(run2) is False

    def test_cannot_merge_different_encoding(self) -> None:
        """Test that runs with different encodings cannot merge."""
        run1 = Run(text="Hello", encoding="cp866")
        run2 = Run(text=" World", encoding="ascii")

        assert run1.can_merge_with(run2) is False

    def test_cannot_merge_non_run_object(self) -> None:
        """Test that can_merge_with returns False for non-Run objects."""
        run = Run(text="Hello")
        assert run.can_merge_with("not a run") is False
        assert run.can_merge_with(None) is False
        assert run.can_merge_with(123) is False

    def test_merge_concatenates_text(self) -> None:
        """Test that merge_with concatenates text correctly."""
        run1 = Run(text="Hello", bold=True)
        run2 = Run(text=" World", bold=True)

        merged = run1.merge_with(run2)

        assert merged.text == "Hello World"
        assert merged.bold is True

    def test_merge_preserves_formatting(self) -> None:
        """Test that merge preserves all formatting attributes."""
        run1 = Run(
            text="Part1",
            bold=True,
            italic=True,
            underline=True,
            font_name="roman",
        )
        run2 = Run(
            text="Part2",
            bold=True,
            italic=True,
            underline=True,
            font_name="roman",
        )

        merged = run1.merge_with(run2)

        assert merged.text == "Part1Part2"
        assert merged.bold is True
        assert merged.italic is True
        assert merged.underline is True
        assert merged.font_name == "roman"

    def test_merge_incompatible_raises_error(self) -> None:
        """Test that merging incompatible runs raises ValueError."""
        run1 = Run(text="Hello", bold=True)
        run2 = Run(text=" World", bold=False)

        with pytest.raises(ValueError, match="Cannot merge runs"):
            run1.merge_with(run2)

    def test_merge_creates_new_instance(self) -> None:
        """Test that merge creates a new instance, leaving originals unchanged."""
        run1 = Run(text="Hello", bold=True)
        run2 = Run(text=" World", bold=True)

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
            "bold": False,
            "italic": False,
            "underline": False,
            "double_width": False,
            "double_height": False,
            "font_name": "draft",
            "encoding": "cp866",
        }

    def test_to_dict_full(self) -> None:
        """Test serialization with all attributes specified."""
        run = Run(
            text="Test",
            bold=True,
            italic=True,
            underline=True,
            double_width=True,
            double_height=True,
            font_name="roman",
            encoding="ascii",
        )
        data = run.to_dict()

        assert data["text"] == "Test"
        assert data["bold"] is True
        assert data["italic"] is True
        assert data["underline"] is True
        assert data["double_width"] is True
        assert data["double_height"] is True
        assert data["font_name"] == "roman"
        assert data["encoding"] == "ascii"

    def test_from_dict_minimal(self) -> None:
        """Test deserialization with only required 'text' field."""
        data = {"text": "Hello"}
        run = Run.from_dict(data)

        assert run.text == "Hello"
        assert run.bold is False
        assert run.italic is False
        assert run.font_name == "draft"
        assert run.encoding == "cp866"

    def test_from_dict_full(self) -> None:
        """Test deserialization with all fields."""
        data = {
            "text": "Test",
            "bold": True,
            "italic": True,
            "underline": True,
            "double_width": True,
            "double_height": True,
            "font_name": "roman",
            "encoding": "ascii",
        }
        run = Run.from_dict(data)

        assert run.text == "Test"
        assert run.bold is True
        assert run.italic is True
        assert run.underline is True
        assert run.double_width is True
        assert run.double_height is True
        assert run.font_name == "roman"
        assert run.encoding == "ascii"

    def test_from_dict_missing_text_raises(self) -> None:
        """Test that missing 'text' key raises KeyError."""
        data: dict[str, Any] = {"bold": True}

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
            bold=True,
            italic=False,
            underline=True,
            font_name="roman",
        )

        data = original.to_dict()
        restored = Run.from_dict(data)

        assert restored == original


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
        run1 = Run(text="Test", bold=True, italic=False)
        run2 = Run(text="Test", bold=True, italic=False)

        assert run1 == run2

    def test_equality_different_text(self) -> None:
        """Test that runs with different text are not equal."""
        run1 = Run(text="Hello", bold=True)
        run2 = Run(text="World", bold=True)

        assert run1 != run2

    def test_equality_different_formatting(self) -> None:
        """Test that runs with different formatting are not equal."""
        run1 = Run(text="Test", bold=True)
        run2 = Run(text="Test", bold=False)

        assert run1 != run2

    def test_equality_with_non_run(self) -> None:
        """Test comparison with non-Run objects."""
        run = Run(text="Test")

        assert (run == "Test") is False
        assert (run == None) is False
        assert (run == 123) is False

    def test_repr_short_text(self) -> None:
        """Test __repr__ with short text."""
        run = Run(text="Short", bold=True)
        repr_str = repr(run)

        assert "Run(" in repr_str
        assert "text='Short'" in repr_str
        assert "len=5" in repr_str
        assert "formatting='B'" in repr_str

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
            bold=True,
            italic=True,
            underline=True,
        )
        repr_str = repr(run)

        assert "B+I+U" in repr_str or all(x in repr_str for x in ["B", "I", "U"])


class TestMergeConsecutiveRuns:
    """Test merge_consecutive_runs() utility function."""

    def test_merge_empty_list(self) -> None:
        """Test merging empty list returns empty list."""
        result = merge_consecutive_runs([])
        assert result == []

    def test_merge_single_run(self) -> None:
        """Test merging single run returns copy."""
        run = Run(text="Only", bold=True)
        result = merge_consecutive_runs([run])

        assert len(result) == 1
        assert result[0] == run
        assert result[0] is not run  # Should be copy

    def test_merge_identical_consecutive_runs(self) -> None:
        """Test merging runs with identical formatting."""
        runs = [
            Run(text="Part1", bold=True),
            Run(text="Part2", bold=True),
            Run(text="Part3", bold=True),
        ]

        result = merge_consecutive_runs(runs)

        assert len(result) == 1
        assert result[0].text == "Part1Part2Part3"
        assert result[0].bold is True

    def test_merge_mixed_formatting(self) -> None:
        """Test merging with alternating formatting."""
        runs = [
            Run(text="Bold1", bold=True),
            Run(text="Bold2", bold=True),
            Run(text="Normal", bold=False),
            Run(text="Bold3", bold=True),
        ]

        result = merge_consecutive_runs(runs)

        assert len(result) == 3
        assert result[0].text == "Bold1Bold2"
        assert result[0].bold is True
        assert result[1].text == "Normal"
        assert result[1].bold is False
        assert result[2].text == "Bold3"
        assert result[2].bold is True

    def test_merge_no_mergeable_runs(self) -> None:
        """Test with no consecutive runs having same formatting."""
        runs = [
            Run(text="Bold", bold=True),
            Run(text="Italic", italic=True),
            Run(text="Under", underline=True),
        ]

        result = merge_consecutive_runs(runs)

        assert len(result) == 3
        assert result[0].text == "Bold"
        assert result[1].text == "Italic"
        assert result[2].text == "Under"

    def test_merge_preserves_original_list(self) -> None:
        """Test that original list is not modified."""
        runs = [
            Run(text="A", bold=True),
            Run(text="B", bold=True),
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
        template = [Run(text="x" * 5, bold=True)]

        result = split_by_formatting(text, template)

        assert len(result) == 1
        assert result[0].text == "Hello"
        assert result[0].bold is True

    def test_split_multiple_segments(self) -> None:
        """Test splitting text into multiple formatted segments."""
        text = "HelloWorld"
        template = [
            Run(text="x" * 5, bold=True),
            Run(text="y" * 5, bold=False),
        ]

        result = split_by_formatting(text, template)

        assert len(result) == 2
        assert result[0].text == "Hello"
        assert result[0].bold is True
        assert result[1].text == "World"
        assert result[1].bold is False

    def test_split_complex_formatting(self) -> None:
        """Test splitting with complex formatting patterns."""
        text = "ABCDEFGH"
        template = [
            Run(text="1" * 2, bold=True, italic=False),
            Run(text="2" * 3, bold=False, italic=True),
            Run(text="3" * 3, bold=True, italic=True),
        ]

        result = split_by_formatting(text, template)

        assert len(result) == 3
        assert result[0].text == "AB"
        assert result[0].bold is True
        assert result[0].italic is False
        assert result[1].text == "CDE"
        assert result[1].bold is False
        assert result[1].italic is True
        assert result[2].text == "FGH"
        assert result[2].bold is True
        assert result[2].italic is True

    def test_split_length_mismatch_raises(self) -> None:
        """Test that length mismatch raises ValueError."""
        text = "HelloWorld"
        template = [Run(text="x" * 5, bold=True)]  # Only 5 chars, but text is 10

        with pytest.raises(ValueError, match="does not match"):
            split_by_formatting(text, template)

    def test_split_preserves_formatting_attributes(self) -> None:
        """Test that all formatting attributes are preserved."""
        text = "Test"
        template = [
            Run(
                text="t" * 4,
                bold=True,
                italic=True,
                underline=True,
                double_width=True,
                double_height=True,
                font_name="roman",
                encoding="ascii",
            )
        ]

        result = split_by_formatting(text, template)

        assert result[0].bold is True
        assert result[0].italic is True
        assert result[0].underline is True
        assert result[0].double_width is True
        assert result[0].double_height is True
        assert result[0].font_name == "roman"
        assert result[0].encoding == "ascii"


class TestRunEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_run_with_whitespace_only(self) -> None:
        """Test run containing only whitespace."""
        run = Run(text="   ")
        assert len(run) == 3
        run.validate()  # Should not raise

    def test_run_with_special_characters(self) -> None:
        """Test run with special characters."""
        run = Run(text="Tab\there\nNewline", encoding="ascii")
        run.validate()
        assert "\t" in run.text
        assert "\n" in run.text

    def test_run_with_cyrillic_and_latin(self) -> None:
        """Test run mixing Cyrillic and Latin characters."""
        run = Run(text="Привет Hello", encoding="cp866")
        run.validate()

    def test_merge_three_runs_consecutively(self) -> None:
        """Test merging multiple runs in sequence."""
        run1 = Run(text="A", bold=True)
        run2 = Run(text="B", bold=True)
        run3 = Run(text="C", bold=True)

        merged_12 = run1.merge_with(run2)
        merged_all = merged_12.merge_with(run3)

        assert merged_all.text == "ABC"
        assert merged_all.bold is True

    @pytest.mark.parametrize("font", list(SUPPORTED_FONTS))
    def test_all_supported_fonts(self, font: str) -> None:
        """Test that all supported fonts work correctly."""
        run = Run(text="Test", font_name=font)
        assert run.font_name == font
        run.validate()

    @pytest.mark.parametrize("encoding", list(SUPPORTED_ENCODINGS))
    def test_all_supported_encodings(self, encoding: str) -> None:
        """Test that all supported encodings work correctly."""
        # Use text compatible with all encodings
        run = Run(text="Test", encoding=encoding)
        assert run.encoding == encoding
        run.validate()

    def test_format_summary_plain(self) -> None:
        """Test _format_summary for plain text."""
        run = Run(text="Plain")
        assert run._format_summary() == "plain"

    def test_format_summary_complex(self) -> None:
        """Test _format_summary with multiple attributes."""
        run = Run(
            text="Complex",
            bold=True,
            italic=True,
            underline=True,
            double_width=True,
            double_height=True,
        )
        summary = run._format_summary()

        assert "B" in summary
        assert "I" in summary
        assert "U" in summary
        assert "DW" in summary
        assert "DH" in summary


class TestRunIntegration:
    """Integration tests combining multiple operations."""

    def test_create_validate_serialize_deserialize(self) -> None:
        """Test complete workflow: create, validate, serialize, deserialize."""
        original = Run(
            text="Integration test",
            bold=True,
            italic=False,
            font_name="roman",
        )

        original.validate()
        data = original.to_dict()
        restored = Run.from_dict(data)

        assert restored == original
        restored.validate()

    def test_merge_and_split_workflow(self) -> None:
        """Test merging runs then splitting back."""
        runs = [
            Run(text="Part1", bold=True),
            Run(text="Part2", bold=True),
            Run(text="Part3", bold=False),
        ]

        merged = merge_consecutive_runs(runs)
        assert len(merged) == 2

        # Recreate split using the merged runs as templates
        full_text = "Part1Part2Part3"
        templates = [
            Run(text="x" * 10, bold=True),
            Run(text="y" * 5, bold=False),
        ]

        split_result = split_by_formatting(full_text, templates)
        assert split_result[0].text == "Part1Part2"
        assert split_result[1].text == "Part3"

    def test_copy_merge_sequence(self) -> None:
        """Test copying and merging in sequence."""
        run1 = Run(text="First", bold=True)
        run1_copy = run1.copy()

        run2 = Run(text="Second", bold=True)

        merged = run1_copy.merge_with(run2)

        assert merged.text == "FirstSecond"
        assert run1.text == "First"  # Original unchanged


class TestLogging:
    """Test logging functionality."""

    def test_merge_consecutive_runs_logging(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that merge operation logs correctly."""
        runs = [
            Run(text="Part1", bold=True),
            Run(text="Part2", bold=True),
        ]

        with caplog.at_level(logging.INFO):
            result = merge_consecutive_runs(runs)

        assert "Merged 2 runs into 1 runs" in caplog.text
        assert len(result) == 1

    def test_split_by_formatting_debug_logging(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that split_by_formatting logs debug information."""
        text = "HelloWorld"
        template = [
            Run(text="x" * 5, bold=True),
            Run(text="y" * 5, bold=False),
        ]

        with caplog.at_level(logging.DEBUG):
            result = split_by_formatting(text, template)

        # Проверяем, что DEBUG-сообщение записано
        assert "Split text into" in caplog.text
        assert "original: 2 templates" in caplog.text
        assert len(result) == 2
