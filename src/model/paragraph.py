"""
Модель параграфа с форматированием и коллекцией текстовых фрагментов.

Paragraph model representing a logical block of text with shared formatting
properties (alignment, indentation, spacing) and a collection of text runs.
Provides manipulation, validation, and metrics calculation for ESC/P rendering.

Module: src/model/paragraph.py
Project: ESC/P Text Editor
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Final

from src.model.run import Run, merge_consecutive_runs

logger: Final = logging.getLogger(__name__)


class Alignment(Enum):
    """Text alignment modes for paragraphs."""

    LEFT = "left"
    CENTER = "center"
    RIGHT = "right"
    JUSTIFY = "justify"


# Measurement constraints (in inches)
MIN_INDENT: Final[float] = 0.0
MAX_INDENT: Final[float] = 8.0  # FX-890 max paper width
MIN_LINE_SPACING: Final[float] = 0.5
MAX_LINE_SPACING: Final[float] = 3.0
MIN_SPACE: Final[float] = 0.0
MAX_SPACE: Final[float] = 2.0


@dataclass(slots=True)
class Paragraph:
    """
    Represents a paragraph with formatting and text runs.

    A Paragraph is a container for Run objects that share common formatting
    properties like alignment, indentation, and line spacing. It provides
    methods for manipulating runs and calculating layout metrics.

    Attributes:
        runs: List of Run objects containing the paragraph text.
        alignment: Horizontal text alignment (left, center, right, justify).
        first_line_indent: Indentation of the first line (inches).
        left_indent: Left margin indentation (inches).
        right_indent: Right margin indentation (inches).
        line_spacing: Line spacing multiplier (1.0 = single, 1.5 = 1.5x, 2.0 = double).
        space_before: Vertical space before paragraph (inches).
        space_after: Vertical space after paragraph (inches).

    Example:
        >>> para = Paragraph()
        >>> para.add_run(Run(text="Hello ", bold=True))
        >>> para.add_run(Run(text="World"))
        >>> para.get_text()
        'Hello World'
        >>> para.alignment = Alignment.CENTER
        >>> para.first_line_indent = 0.5
    """

    runs: list[Run] = field(default_factory=list)
    alignment: Alignment = Alignment.LEFT
    first_line_indent: float = 0.0
    left_indent: float = 0.0
    right_indent: float = 0.0
    line_spacing: float = 1.0
    space_before: float = 0.0
    space_after: float = 0.0

    def __post_init__(self) -> None:
        """Validate and normalize attributes after initialization."""
        # Ensure runs is a list
        if not isinstance(self.runs, list):
            logger.warning(f"runs must be list, got {type(self.runs).__name__}, converting")
            object.__setattr__(self, "runs", list(self.runs) if self.runs else [])

        # Clamp indentation values
        if not (MIN_INDENT <= self.first_line_indent <= MAX_INDENT):
            logger.warning(f"first_line_indent {self.first_line_indent} out of range, clamping")
            object.__setattr__(
                self, "first_line_indent", max(MIN_INDENT, min(self.first_line_indent, MAX_INDENT))
            )

        if not (MIN_INDENT <= self.left_indent <= MAX_INDENT):
            logger.warning(f"left_indent {self.left_indent} out of range, clamping")
            object.__setattr__(
                self, "left_indent", max(MIN_INDENT, min(self.left_indent, MAX_INDENT))
            )

        if not (MIN_INDENT <= self.right_indent <= MAX_INDENT):
            logger.warning(f"right_indent {self.right_indent} out of range, clamping")
            object.__setattr__(
                self, "right_indent", max(MIN_INDENT, min(self.right_indent, MAX_INDENT))
            )

        # Clamp line spacing
        if not (MIN_LINE_SPACING <= self.line_spacing <= MAX_LINE_SPACING):
            logger.warning(f"line_spacing {self.line_spacing} out of range, clamping")
            object.__setattr__(
                self,
                "line_spacing",
                max(MIN_LINE_SPACING, min(self.line_spacing, MAX_LINE_SPACING)),
            )

        # Clamp spacing before/after
        if not (MIN_SPACE <= self.space_before <= MAX_SPACE):
            logger.warning(f"space_before {self.space_before} out of range, clamping")
            object.__setattr__(
                self, "space_before", max(MIN_SPACE, min(self.space_before, MAX_SPACE))
            )

        if not (MIN_SPACE <= self.space_after <= MAX_SPACE):
            logger.warning(f"space_after {self.space_after} out of range, clamping")
            object.__setattr__(
                self, "space_after", max(MIN_SPACE, min(self.space_after, MAX_SPACE))
            )

    def add_run(self, run: Run) -> None:
        """
        Append a run to the end of the paragraph.

        Args:
            run: The Run object to add.

        Raises:
            TypeError: If run is not a Run instance.

        Example:
            >>> para = Paragraph()
            >>> para.add_run(Run(text="Hello"))
            >>> len(para.runs)
            1
        """
        if not isinstance(run, Run):
            raise TypeError(f"Expected Run instance, got {type(run).__name__}")

        self.runs.append(run)
        logger.debug(f"Added run to paragraph, total runs: {len(self.runs)}")

    def insert_run(self, index: int, run: Run) -> None:
        """
        Insert a run at the specified index.

        Args:
            index: Position to insert the run (0-based).
            run: The Run object to insert.

        Raises:
            TypeError: If run is not a Run instance.
            IndexError: If index is out of valid range.

        Example:
            >>> para = Paragraph()
            >>> para.add_run(Run(text="World"))
            >>> para.insert_run(0, Run(text="Hello "))
            >>> para.get_text()
            'Hello World'
        """
        if not isinstance(run, Run):
            raise TypeError(f"Expected Run instance, got {type(run).__name__}")

        if not (0 <= index <= len(self.runs)):
            raise IndexError(f"Insert index {index} out of range for {len(self.runs)} runs")

        self.runs.insert(index, run)
        logger.debug(f"Inserted run at index {index}, total runs: {len(self.runs)}")

    def remove_run(self, index: int) -> Run:
        """
        Remove and return the run at the specified index.

        Args:
            index: Position of the run to remove (0-based).

        Returns:
            The removed Run object.

        Raises:
            IndexError: If index is out of range.

        Example:
            >>> para = Paragraph()
            >>> para.add_run(Run(text="Hello"))
            >>> para.add_run(Run(text=" World"))
            >>> removed = para.remove_run(0)
            >>> removed.text
            'Hello'
            >>> para.get_text()
            ' World'
        """
        if not (0 <= index < len(self.runs)):
            raise IndexError(f"Remove index {index} out of range for {len(self.runs)} runs")

        removed = self.runs.pop(index)
        logger.debug(f"Removed run at index {index}, remaining: {len(self.runs)}")
        return removed

    def clear_runs(self) -> None:
        """
        Remove all runs from the paragraph.

        Example:
            >>> para = Paragraph()
            >>> para.add_run(Run(text="Test"))
            >>> para.clear_runs()
            >>> len(para.runs)
            0
        """
        count = len(self.runs)
        self.runs.clear()
        logger.debug(f"Cleared {count} runs from paragraph")

    def get_text(self) -> str:
        """
        Get the complete text of the paragraph.

        Concatenates text from all runs in order.

        Returns:
            The complete paragraph text.

        Example:
            >>> para = Paragraph()
            >>> para.add_run(Run(text="Hello "))
            >>> para.add_run(Run(text="World"))
            >>> para.get_text()
            'Hello World'
        """
        return "".join(run.text for run in self.runs)

    def get_run_count(self) -> int:
        """
        Get the number of runs in the paragraph.

        Returns:
            Count of Run objects.

        Example:
            >>> para = Paragraph()
            >>> para.add_run(Run(text="A"))
            >>> para.add_run(Run(text="B"))
            >>> para.get_run_count()
            2
        """
        return len(self.runs)

    def validate(self) -> None:
        """
        Validate paragraph structure and formatting.

        Checks that all runs are valid and formatting values are within
        acceptable ranges.

        Raises:
            ValueError: If formatting values are invalid or runs contain errors.
            TypeError: If runs contain non-Run objects.

        Example:
            >>> para = Paragraph()
            >>> para.add_run(Run(text="Valid"))
            >>> para.validate()  # OK
            >>> para.add_run("not a run")  # Would raise TypeError on validate
        """
        # Validate runs
        for i, run in enumerate(self.runs):
            if not isinstance(run, Run):
                raise TypeError(f"Run at index {i} is not a Run instance: {type(run).__name__}")
            try:
                run.validate()
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Run at index {i} failed validation: {exc}") from exc

        # Validate indent sum doesn't exceed reasonable limits
        total_indent = self.left_indent + self.right_indent
        if total_indent >= MAX_INDENT:
            raise ValueError(
                f"Combined left ({self.left_indent}) and right ({self.right_indent}) "
                f"indents ({total_indent}) exceed maximum ({MAX_INDENT})"
            )

        logger.debug(
            f"Validated paragraph: {len(self.runs)} runs, "
            f"alignment={self.alignment.value}, "
            f"indents=({self.first_line_indent:.2f}, {self.left_indent:.2f}, {self.right_indent:.2f})"
        )

    def copy(self) -> "Paragraph":
        """
        Create a deep copy of the paragraph.

        Creates new instances of all runs.

        Returns:
            A new Paragraph with copied runs and formatting.

        Example:
            >>> para = Paragraph()
            >>> para.add_run(Run(text="Original"))
            >>> para_copy = para.copy()
            >>> para_copy.runs[0].text = "Modified"
            >>> para.runs[0].text  # Original unchanged
            'Original'
        """
        return Paragraph(
            runs=[run.copy() for run in self.runs],
            alignment=self.alignment,
            first_line_indent=self.first_line_indent,
            left_indent=self.left_indent,
            right_indent=self.right_indent,
            line_spacing=self.line_spacing,
            space_before=self.space_before,
            space_after=self.space_after,
        )

    def calculate_width(self, page_width: float) -> float:
        """
        Calculate effective text width considering indents.

        Args:
            page_width: Total page width in inches.

        Returns:
            Available width for text after indents.

        Raises:
            ValueError: If page_width is invalid or indents exceed page width.

        Example:
            >>> para = Paragraph(left_indent=1.0, right_indent=1.0)
            >>> para.calculate_width(8.5)  # US Letter width
            6.5
        """
        if page_width <= 0:
            raise ValueError(f"page_width must be positive, got {page_width}")

        effective_width = page_width - self.left_indent - self.right_indent

        if effective_width <= 0:
            raise ValueError(
                f"Indents ({self.left_indent} + {self.right_indent}) "
                f"exceed page width ({page_width})"
            )

        return effective_width

    def optimize_runs(self) -> None:
        """
        Optimize runs by merging consecutive runs with identical formatting.

        Modifies the paragraph in-place by replacing runs with merged versions.

        Example:
            >>> para = Paragraph()
            >>> para.add_run(Run(text="Hello", bold=True))
            >>> para.add_run(Run(text=" ", bold=True))
            >>> para.add_run(Run(text="World", bold=True))
            >>> para.optimize_runs()
            >>> len(para.runs)
            1
            >>> para.runs[0].text
            'Hello World'
        """
        if len(self.runs) <= 1:
            return

        original_count = len(self.runs)
        self.runs = merge_consecutive_runs(self.runs)
        optimized_count = len(self.runs)

        if optimized_count < original_count:
            logger.info(f"Optimized paragraph: {original_count} runs → {optimized_count} runs")

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize paragraph to dictionary.

        Returns:
            Dictionary with all paragraph attributes and serialized runs.

        Example:
            >>> para = Paragraph()
            >>> para.add_run(Run(text="Test"))
            >>> data = para.to_dict()
            >>> data["alignment"]
            'left'
            >>> len(data["runs"])
            1
        """
        return {
            "runs": [run.to_dict() for run in self.runs],
            "alignment": self.alignment.value,
            "first_line_indent": self.first_line_indent,
            "left_indent": self.left_indent,
            "right_indent": self.right_indent,
            "line_spacing": self.line_spacing,
            "space_before": self.space_before,
            "space_after": self.space_after,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Paragraph":
        """
        Deserialize paragraph from dictionary.

        Args:
            data: Dictionary with paragraph attributes.

        Returns:
            Paragraph instance reconstructed from dictionary.

        Raises:
            TypeError: If data is not a dictionary.
            KeyError: If required keys are missing.
            ValueError: If alignment value is invalid.

        Example:
            >>> data = {
            ...     "runs": [{"text": "Hello"}],
            ...     "alignment": "center",
            ...     "first_line_indent": 0.5
            ... }
            >>> para = Paragraph.from_dict(data)
            >>> para.alignment
            <Alignment.CENTER: 'center'>
            >>> para.first_line_indent
            0.5
        """
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict, got {type(data).__name__}")

        # Parse runs
        runs_data = data.get("runs", [])
        if not isinstance(runs_data, list):
            raise TypeError(f"'runs' must be list, got {type(runs_data).__name__}")

        runs = [Run.from_dict(run_data) for run_data in runs_data]

        # Parse alignment
        alignment_str = data.get("alignment", "left")
        try:
            alignment = Alignment(alignment_str)
        except ValueError as exc:
            raise ValueError(f"Invalid alignment value: {alignment_str!r}") from exc

        return Paragraph(
            runs=runs,
            alignment=alignment,
            first_line_indent=data.get("first_line_indent", 0.0),
            left_indent=data.get("left_indent", 0.0),
            right_indent=data.get("right_indent", 0.0),
            line_spacing=data.get("line_spacing", 1.0),
            space_before=data.get("space_before", 0.0),
            space_after=data.get("space_after", 0.0),
        )

    def __len__(self) -> int:
        """Return the total character count of all runs."""
        return sum(len(run) for run in self.runs)

    def __eq__(self, other: object) -> bool:
        """
        Compare paragraphs for equality.

        Args:
            other: Object to compare with.

        Returns:
            True if all attributes and runs are equal.
        """
        if not isinstance(other, Paragraph):
            return NotImplemented

        return (
            self.runs == other.runs
            and self.alignment == other.alignment
            and self.first_line_indent == other.first_line_indent
            and self.left_indent == other.left_indent
            and self.right_indent == other.right_indent
            and self.line_spacing == other.line_spacing
            and self.space_before == other.space_before
            and self.space_after == other.space_after
        )

    def __repr__(self) -> str:
        """
        Return detailed string representation.

        Example:
            >>> para = Paragraph()
            >>> para.add_run(Run(text="Test"))
            >>> repr(para)
            "Paragraph(runs=1, chars=4, alignment='left')"
        """
        return (
            f"Paragraph(runs={len(self.runs)}, chars={len(self)}, "
            f"alignment='{self.alignment.value}')"
        )


def merge_paragraphs(paragraphs: list[Paragraph], separator: str = "\n") -> Paragraph:
    """
    Merge multiple paragraphs into one.

    Creates a new paragraph containing all runs from input paragraphs,
    optionally separated by a text run with the specified separator.
    Uses formatting from the first paragraph.

    Args:
        paragraphs: List of paragraphs to merge.
        separator: Text to insert between paragraph runs (default: newline).

    Returns:
        New Paragraph with merged content.

    Raises:
        ValueError: If paragraphs list is empty.

    Example:
        >>> para1 = Paragraph()
        >>> para1.add_run(Run(text="First"))
        >>> para2 = Paragraph()
        >>> para2.add_run(Run(text="Second"))
        >>> merged = merge_paragraphs([para1, para2], separator=" ")
        >>> merged.get_text()
        'First Second'
    """
    if not paragraphs:
        raise ValueError("Cannot merge empty list of paragraphs")

    # Use first paragraph's formatting
    result = paragraphs[0].copy()
    result.clear_runs()

    for i, para in enumerate(paragraphs):
        # Add runs from this paragraph
        for run in para.runs:
            result.add_run(run.copy())

        # Add separator between paragraphs (not after last)
        if separator and i < len(paragraphs) - 1:
            result.add_run(Run(text=separator))

    logger.info(f"Merged {len(paragraphs)} paragraphs into one with {len(result.runs)} runs")
    return result


def split_paragraph_at(paragraph: Paragraph, run_index: int) -> tuple[Paragraph, Paragraph]:
    """
    Split a paragraph into two at the specified run index.

    Creates two new paragraphs: the first contains runs [0:run_index),
    the second contains runs [run_index:]. Both inherit formatting from
    the original paragraph.

    Args:
        paragraph: The paragraph to split.
        run_index: Index at which to split (runs before this go to first paragraph).

    Returns:
        Tuple of (first_paragraph, second_paragraph).

    Raises:
        ValueError: If run_index is out of valid range.

    Example:
        >>> para = Paragraph()
        >>> para.add_run(Run(text="A"))
        >>> para.add_run(Run(text="B"))
        >>> para.add_run(Run(text="C"))
        >>> first, second = split_paragraph_at(para, 1)
        >>> first.get_text()
        'A'
        >>> second.get_text()
        'BC'
    """
    if not (0 < run_index < len(paragraph.runs)):
        raise ValueError(f"Split index {run_index} must be in range (0, {len(paragraph.runs)})")

    # Create first paragraph with runs before split point
    first = Paragraph(
        runs=[run.copy() for run in paragraph.runs[:run_index]],
        alignment=paragraph.alignment,
        first_line_indent=paragraph.first_line_indent,
        left_indent=paragraph.left_indent,
        right_indent=paragraph.right_indent,
        line_spacing=paragraph.line_spacing,
        space_before=paragraph.space_before,
        space_after=paragraph.space_after,
    )

    # Create second paragraph with runs from split point onward
    second = Paragraph(
        runs=[run.copy() for run in paragraph.runs[run_index:]],
        alignment=paragraph.alignment,
        first_line_indent=paragraph.first_line_indent,
        left_indent=paragraph.left_indent,
        right_indent=paragraph.right_indent,
        line_spacing=paragraph.line_spacing,
        space_before=paragraph.space_before,
        space_after=paragraph.space_after,
    )

    logger.info(
        f"Split paragraph at run {run_index}: "
        f"{len(paragraph.runs)} runs → {len(first.runs)} + {len(second.runs)}"
    )

    return first, second
