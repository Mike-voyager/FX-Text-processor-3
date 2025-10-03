"""
Модель текстового фрагмента (Run) с единообразным форматированием.

Text run model representing the minimal unit of text with uniform formatting
within a paragraph. Provides immutable operations, validation, serialization,
and merging capabilities for ESC/P document processing.

Module: src/model/run.py
Project: ESC/P Text Editor
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Final

logger: Final = logging.getLogger(__name__)


# Supported font names for Epson FX-890
SUPPORTED_FONTS: Final[frozenset[str]] = frozenset(
    [
        "draft",  # 10 CPI draft
        "roman",  # Roman font
        "sans_serif",  # Sans Serif
        "script",  # Script
    ]
)

# Supported encodings
SUPPORTED_ENCODINGS: Final[frozenset[str]] = frozenset(
    [
        "cp866",  # PC866 Cyrillic (primary)
        "ascii",  # ASCII
        "latin1",  # Latin-1
    ]
)


@dataclass(frozen=False, slots=True)
class Run:
    """
    Represents a contiguous sequence of text with uniform formatting.

    A Run is the smallest unit of text within a paragraph that shares
    identical formatting attributes. When formatting changes, a new Run begins.

    Attributes:
        text: The text content of the run.
        bold: Whether text is bold.
        italic: Whether text is italic (slanted).
        underline: Whether text is underlined.
        double_width: Whether text uses double-width characters.
        double_height: Whether text uses double-height characters.
        font_name: Font name from SUPPORTED_FONTS.
        encoding: Character encoding from SUPPORTED_ENCODINGS.

    Example:
        >>> run = Run(text="Hello", bold=True)
        >>> run.validate()
        >>> print(len(run))
        5
        >>> run2 = Run(text=" World", bold=True)
        >>> merged = run.merge_with(run2)
        >>> print(merged.text)
        Hello World
    """

    text: str
    bold: bool = False
    italic: bool = False
    underline: bool = False
    double_width: bool = False
    double_height: bool = False
    font_name: str = "draft"
    encoding: str = "cp866"

    def __post_init__(self) -> None:
        """Validate attributes after initialization."""
        if self.font_name not in SUPPORTED_FONTS:
            logger.warning(
                f"Font '{self.font_name}' not in SUPPORTED_FONTS, " f"using 'draft' fallback"
            )
            object.__setattr__(self, "font_name", "draft")

        if self.encoding not in SUPPORTED_ENCODINGS:
            logger.warning(
                f"Encoding '{self.encoding}' not in SUPPORTED_ENCODINGS, " f"using 'cp866' fallback"
            )
            object.__setattr__(self, "encoding", "cp866")

    def validate(self) -> None:
        """
        Validate run content and attributes.

        Checks that text can be encoded with the specified encoding
        and that all attributes are valid.

        Raises:
            ValueError: If text is empty or contains only whitespace.
            UnicodeEncodeError: If text cannot be encoded with the specified encoding.
            TypeError: If attributes have incorrect types.

        Example:
            >>> run = Run(text="Привет")
            >>> run.validate()  # OK for cp866
            >>> run2 = Run(text="", bold=True)
            >>> run2.validate()  # Raises ValueError
            Traceback (most recent call last):
                ...
            ValueError: Run text cannot be empty
        """
        if not isinstance(self.text, str):
            raise TypeError(f"Run text must be str, got {type(self.text).__name__}")

        if not self.text:
            raise ValueError("Run text cannot be empty")

        # Validate encoding capability
        try:
            self.text.encode(self.encoding)
        except UnicodeEncodeError as exc:
            logger.error(
                f"Cannot encode text with {self.encoding}: {exc}",
                extra={"text_preview": self.text[:50]},
            )
            raise ValueError(
                f"Text contains characters incompatible with {self.encoding} encoding"
            ) from exc

        # Validate boolean attributes
        for attr in ("bold", "italic", "underline", "double_width", "double_height"):
            value = getattr(self, attr)
            if not isinstance(value, bool):
                raise TypeError(f"Attribute '{attr}' must be bool, got {type(value).__name__}")

        logger.debug(
            f"Validated Run: len={len(self.text)}, " f"formatting={self._format_summary()}"
        )

    def copy(self) -> "Run":
        """
        Create a deep copy of the run.

        Returns:
            A new Run instance with identical attributes.

        Example:
            >>> run = Run(text="Test", bold=True)
            >>> run_copy = run.copy()
            >>> run_copy.text = "Modified"
            >>> print(run.text)  # Original unchanged
            Test
        """
        return Run(
            text=self.text,
            bold=self.bold,
            italic=self.italic,
            underline=self.underline,
            double_width=self.double_width,
            double_height=self.double_height,
            font_name=self.font_name,
            encoding=self.encoding,
        )

    def can_merge_with(self, other: object) -> bool:
        """
        Check if this run can be merged with another run.

        Two runs can be merged if they have identical formatting attributes.

        Args:
            other: The object to check for merge compatibility.

        Returns:
            True if other is a Run with identical formatting, False otherwise.

        Example:
            >>> run1 = Run(text="Hello", bold=True)
            >>> run2 = Run(text=" World", bold=True)
            >>> run1.can_merge_with(run2)
            True
            >>> run3 = Run(text="!", bold=False)
            >>> run1.can_merge_with(run3)
            False
            >>> run1.can_merge_with("not a run")
            False
        """
        if not isinstance(other, Run):
            return False

        return (
            self.bold == other.bold
            and self.italic == other.italic
            and self.underline == other.underline
            and self.double_width == other.double_width
            and self.double_height == other.double_height
            and self.font_name == other.font_name
            and self.encoding == other.encoding
        )

    def merge_with(self, other: "Run") -> "Run":
        """
        Merge this run with another run.

        Creates a new run with concatenated text, preserving formatting.

        Args:
            other: The run to merge with.

        Returns:
            A new Run with concatenated text.

        Raises:
            ValueError: If runs have incompatible formatting.

        Example:
            >>> run1 = Run(text="Hello", bold=True)
            >>> run2 = Run(text=" World", bold=True)
            >>> merged = run1.merge_with(run2)
            >>> print(merged.text)
            Hello World
        """
        if not self.can_merge_with(other):
            raise ValueError(
                f"Cannot merge runs with different formatting: "
                f"{self._format_summary()} != {other._format_summary() if isinstance(other, Run) else type(other).__name__}"
            )

        logger.debug(f"Merging runs: '{self.text[:20]}...' + '{other.text[:20]}...'")

        return Run(
            text=self.text + other.text,
            bold=self.bold,
            italic=self.italic,
            underline=self.underline,
            double_width=self.double_width,
            double_height=self.double_height,
            font_name=self.font_name,
            encoding=self.encoding,
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize run to dictionary.

        Returns:
            Dictionary representation with all attributes.

        Example:
            >>> run = Run(text="Test", bold=True, italic=False)
            >>> data = run.to_dict()
            >>> data["text"]
            'Test'
            >>> data["bold"]
            True
        """
        return {
            "text": self.text,
            "bold": self.bold,
            "italic": self.italic,
            "underline": self.underline,
            "double_width": self.double_width,
            "double_height": self.double_height,
            "font_name": self.font_name,
            "encoding": self.encoding,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Run":
        """
        Deserialize run from dictionary.

        Args:
            data: Dictionary with run attributes.

        Returns:
            Run instance constructed from dictionary data.

        Raises:
            KeyError: If required 'text' key is missing.
            TypeError: If data is not a dictionary.

        Example:
            >>> data = {"text": "Hello", "bold": True}
            >>> run = Run.from_dict(data)
            >>> run.bold
            True
            >>> run.italic  # Default value
            False
        """
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict, got {type(data).__name__}")

        if "text" not in data:
            raise KeyError("Missing required key 'text' in run data")

        return Run(
            text=data["text"],
            bold=data.get("bold", False),
            italic=data.get("italic", False),
            underline=data.get("underline", False),
            double_width=data.get("double_width", False),
            double_height=data.get("double_height", False),
            font_name=data.get("font_name", "draft"),
            encoding=data.get("encoding", "cp866"),
        )

    def _format_summary(self) -> str:
        """Generate a compact summary of formatting attributes."""
        parts: list[str] = []
        if self.bold:
            parts.append("B")
        if self.italic:
            parts.append("I")
        if self.underline:
            parts.append("U")
        if self.double_width:
            parts.append("DW")
        if self.double_height:
            parts.append("DH")
        if self.font_name != "draft":
            parts.append(f"F:{self.font_name}")
        if self.encoding != "cp866":
            parts.append(f"E:{self.encoding}")

        return "+".join(parts) if parts else "plain"

    def __len__(self) -> int:
        """Return the length of the text content."""
        return len(self.text)

    def __eq__(self, other: object) -> bool:
        """
        Compare runs for equality.

        Args:
            other: Object to compare with.

        Returns:
            True if all attributes are equal, False otherwise.
        """
        if not isinstance(other, Run):
            return NotImplemented

        return (
            self.text == other.text
            and self.bold == other.bold
            and self.italic == other.italic
            and self.underline == other.underline
            and self.double_width == other.double_width
            and self.double_height == other.double_height
            and self.font_name == other.font_name
            and self.encoding == other.encoding
        )

    def __repr__(self) -> str:
        """
        Return detailed string representation.

        Example:
            >>> run = Run(text="Hello", bold=True)
            >>> repr(run)
            "Run(text='Hello', len=5, formatting='B')"
        """
        text_preview = self.text[:20] + "..." if len(self.text) > 20 else self.text
        return (
            f"Run(text={text_preview!r}, len={len(self.text)}, "
            f"formatting='{self._format_summary()}')"
        )


def merge_consecutive_runs(runs: list[Run]) -> list[Run]:
    """
    Merge consecutive runs with identical formatting.

    Optimizes run sequences by combining adjacent runs that share
    identical formatting attributes, reducing ESC/P command overhead.

    Args:
        runs: List of runs to optimize.

    Returns:
        New list with merged runs; original list unchanged.

    Example:
        >>> run1 = Run(text="Hello", bold=True)
        >>> run2 = Run(text=" ", bold=True)
        >>> run3 = Run(text="World", bold=True)
        >>> merged = merge_consecutive_runs([run1, run2, run3])
        >>> len(merged)
        1
        >>> merged[0].text
        'Hello World'
    """
    if not runs:
        logger.debug("merge_consecutive_runs: empty list, returning empty")
        return []

    if len(runs) == 1:
        logger.debug("merge_consecutive_runs: single run, no merge needed")
        return [runs[0].copy()]

    merged: list[Run] = [runs[0].copy()]

    for current_run in runs[1:]:
        last_merged = merged[-1]

        if last_merged.can_merge_with(current_run):
            try:
                merged[-1] = last_merged.merge_with(current_run)
            except ValueError as exc:
                logger.warning(f"Failed to merge runs: {exc}")
                merged.append(current_run.copy())
        else:
            merged.append(current_run.copy())

    logger.info(f"Merged {len(runs)} runs into {len(merged)} runs")
    return merged


def split_by_formatting(
    text: str,
    runs: list[Run],
) -> list[Run]:
    """
    Split text into runs based on formatting boundaries.

    Takes raw text and a list of runs with formatting information,
    then creates a properly split sequence of runs where each run's
    text corresponds to its formatting.

    Args:
        text: The complete text to split.
        runs: List of runs defining formatting for text segments.
              Run text lengths must sum to len(text).

    Returns:
        List of runs with text properly segmented by formatting.

    Raises:
        ValueError: If total run text length doesn't match input text length.

    Example:
        >>> text = "HelloWorld"
        >>> template_runs = [
        ...     Run(text="x" * 5, bold=True),    # First 5 chars bold
        ...     Run(text="y" * 5, bold=False),   # Next 5 chars normal
        ... ]
        >>> result = split_by_formatting(text, template_runs)
        >>> result[0].text
        'Hello'
        >>> result[0].bold
        True
        >>> result[1].text
        'World'
        >>> result[1].bold
        False
    """
    if not runs:
        logger.warning("split_by_formatting: no runs provided")
        return []

    total_run_length = sum(len(run.text) for run in runs)
    if total_run_length != len(text):
        raise ValueError(
            f"Total run text length ({total_run_length}) does not match "
            f"input text length ({len(text)})"
        )

    result: list[Run] = []
    position = 0

    for template_run in runs:
        segment_length = len(template_run.text)
        text_segment = text[position : position + segment_length]

        result.append(
            Run(
                text=text_segment,
                bold=template_run.bold,
                italic=template_run.italic,
                underline=template_run.underline,
                double_width=template_run.double_width,
                double_height=template_run.double_height,
                font_name=template_run.font_name,
                encoding=template_run.encoding,
            )
        )

        position += segment_length

    logger.debug(f"Split text into {len(result)} runs (original: {len(runs)} templates)")
    return result
