"""
Модель текстового фрагмента (Run) с единообразным форматированием.

Text run model representing the minimal unit of text with uniform formatting
within a paragraph. Provides immutable operations, validation, serialization,
and merging capabilities for ESC/P document processing.

Module: src/model/run.py
Project: ESC/P Text Editor
"""

import logging
from dataclasses import dataclass
from typing import Any, Final

from src.model.enums import (
    FontFamily,
    CharactersPerInch,
    TextStyle,
    Color,
    CodePage,
    validate_cpi_font_combination,
)

logger: Final = logging.getLogger(__name__)


@dataclass(frozen=False, slots=True)
class Run:
    """
    Represents a contiguous sequence of text with uniform formatting.

    A Run is the smallest unit of text within a paragraph that shares
    identical formatting attributes. When formatting changes, a new Run begins.

    Attributes:
        text: The text content of the run.
        font: Font family from FontFamily enum.
        cpi: Characters per inch from CharactersPerInch enum.
        style: Text styling flags (TextStyle is a Flag enum).
        color: Text color from Color enum.
        codepage: Character encoding from CodePage enum.

    Example:
        >>> run = Run(
        ...     text="Hello",
        ...     font=FontFamily.ROMAN,
        ...     style=TextStyle.BOLD | TextStyle.ITALIC
        ... )
        >>> run.validate()
        >>> escp = run.to_escp()
    """

    text: str
    font: FontFamily = FontFamily.DRAFT
    cpi: CharactersPerInch = CharactersPerInch.CPI_10
    style: TextStyle = TextStyle(0)  # Empty flags
    color: Color = Color.BLACK
    codepage: CodePage = CodePage.PC866

    def __post_init__(self) -> None:
        """Validate attributes after initialization."""
        # Validate CPI/Font combination
        if not validate_cpi_font_combination(self.cpi, self.font):
            logger.warning(
                f"Invalid CPI/Font combination: {self.cpi.value}/{self.font.value}, "
                f"using fallback CPI_10"
            )
            object.__setattr__(self, "cpi", CharactersPerInch.CPI_10)

    def validate(self) -> None:
        """
        Validate run content and attributes.

        Raises:
            ValueError: If text is empty or contains only whitespace.
            UnicodeEncodeError: If text cannot be encoded with the specified encoding.
            TypeError: If attributes have incorrect types.
        """
        # 1. Validate text type
        if not isinstance(self.text, str):
            raise TypeError(f"Run text must be str, got {type(self.text).__name__}")

        if not self.text:
            raise ValueError("Run text cannot be empty")

        # 2. Validate enum types FIRST (before using their methods)
        if not isinstance(self.font, FontFamily):
            raise TypeError(f"font must be FontFamily, got {type(self.font).__name__}")
        if not isinstance(self.cpi, CharactersPerInch):
            raise TypeError(f"cpi must be CharactersPerInch, got {type(self.cpi).__name__}")
        if not isinstance(self.style, TextStyle):
            raise TypeError(f"style must be TextStyle, got {type(self.style).__name__}")
        if not isinstance(self.color, Color):
            raise TypeError(f"color must be Color, got {type(self.color).__name__}")
        if not isinstance(self.codepage, CodePage):
            raise TypeError(f"codepage must be CodePage, got {type(self.codepage).__name__}")

        # 3. Validate encoding capability (now safe to use codepage.python_encoding)
        try:
            self.text.encode(self.codepage.python_encoding)
        except UnicodeEncodeError as exc:
            logger.error(
                f"Cannot encode text with {self.codepage.python_encoding}: {exc}",
                extra={"text_preview": self.text[:50]},
            )
            raise ValueError(
                f"Text contains characters incompatible with {self.codepage.value} encoding"
            ) from exc

        logger.debug(f"Validated Run: len={len(self.text)}, formatting={self._format_summary()}")

    def to_escp(self: "Run") -> bytes:
        """
        Generate ESC/P commands for formatting and text.

        Returns:
            Byte sequence of ESC/P commands + encoded text.

        Example:
            >>> run = Run(
            ...     text="Hello",
            ...     font=FontFamily.ROMAN,
            ...     style=TextStyle.BOLD | TextStyle.ITALIC
            ... )
            >>> escp = run.to_escp()
            >>> assert b"Hello" in escp
        """
        commands: list[bytes] = []

        # 1. Set font
        commands.append(self.font.to_escp())

        # 2. Set CPI
        commands.append(self.cpi.to_escp())

        # 3. Enable styles
        active_styles: list[TextStyle] = []
        for style_flag in TextStyle:
            # Skip empty flag
            if style_flag.value == 0:
                continue
            if style_flag in self.style:
                commands.append(style_flag.to_escp_on())
                active_styles.append(style_flag)

        # 4. Set color (if not black)
        if self.color != Color.BLACK:
            commands.append(self.color.to_escp())

        # 5. Encode text
        text_bytes = self.text.encode(self.codepage.python_encoding)
        commands.append(text_bytes)

        # 6. Disable styles (in reverse order for proper nesting)
        for style_flag in reversed(active_styles):
            commands.append(style_flag.to_escp_off())

        return b"".join(commands)

    def copy(self) -> "Run":
        """Create a deep copy of the run."""
        return Run(
            text=self.text,
            font=self.font,
            cpi=self.cpi,
            style=self.style,
            color=self.color,
            codepage=self.codepage,
        )

    def can_merge_with(self, other: object, strict: bool = True) -> bool:
        """
        Check if this run can be merged with another run.

        Args:
            other: The object to check for merge compatibility.
            strict: If True, all formatting must match. If False, only styles.

        Returns:
            True if merge is possible, False otherwise.
        """
        if not isinstance(other, Run):
            return False

        if strict:
            return (
                self.font == other.font
                and self.cpi == other.cpi
                and self.style == other.style
                and self.color == other.color
                and self.codepage == other.codepage
            )
        else:
            # Only compare styles for ESC/P optimization
            return self.style == other.style

    def merge_with(self, other: "Run") -> "Run":
        """
        Merge this run with another run.

        Args:
            other: The run to merge with.

        Returns:
            A new Run with concatenated text.

        Raises:
            ValueError: If runs have incompatible formatting.
        """
        if not self.can_merge_with(other):
            raise ValueError(
                f"Cannot merge runs with different formatting: "
                f"{self._format_summary()} != {other._format_summary()}"
            )

        logger.debug(f"Merging runs: '{self.text[:20]}...' + '{other.text[:20]}...'")

        return Run(
            text=self.text + other.text,
            font=self.font,
            cpi=self.cpi,
            style=self.style,
            color=self.color,
            codepage=self.codepage,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize run to dictionary."""
        return {
            "text": self.text,
            "font": self.font.value,
            "cpi": self.cpi.value,
            "style": self.style.value,  # Int value of flags
            "color": self.color.value,
            "codepage": self.codepage.value,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Run":
        """Deserialize run from dictionary."""
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict, got {type(data).__name__}")

        if "text" not in data:
            raise KeyError("Missing required key 'text' in run data")

        return Run(
            text=data["text"],
            font=FontFamily(data.get("font", "draft")),
            cpi=CharactersPerInch(data.get("cpi", "10cpi")),
            style=TextStyle(data.get("style", 0)),
            color=Color(data.get("color", "black")),
            codepage=CodePage(data.get("codepage", "pc866")),
        )

    def _format_summary(self) -> str:
        """Generate a compact summary of formatting attributes."""
        parts: list[str] = [
            f"font={self.font.value}",
            f"cpi={self.cpi.value}",
        ]

        # Add active styles
        if self.style != TextStyle(0):
            style_flags = []
            if TextStyle.BOLD in self.style:
                style_flags.append("B")
            if TextStyle.ITALIC in self.style:
                style_flags.append("I")
            if TextStyle.UNDERLINE in self.style:
                style_flags.append("U")
            if TextStyle.DOUBLE_STRIKE in self.style:
                style_flags.append("DS")
            if TextStyle.SUPERSCRIPT in self.style:
                style_flags.append("SUP")
            if TextStyle.SUBSCRIPT in self.style:
                style_flags.append("SUB")
            if style_flags:
                parts.append(f"style={'+'.join(style_flags)}")

        if self.color != Color.BLACK:
            parts.append(f"color={self.color.value}")

        if self.codepage != CodePage.PC866:
            parts.append(f"cp={self.codepage.value}")

        return ", ".join(parts)

    def __len__(self) -> int:
        """Return the length of the text content."""
        return len(self.text)

    def __eq__(self, other: object) -> bool:
        """Compare runs for equality."""
        if not isinstance(other, Run):
            return NotImplemented

        return (
            self.text == other.text
            and self.font == other.font
            and self.cpi == other.cpi
            and self.style == other.style
            and self.color == other.color
            and self.codepage == other.codepage
        )

    def __repr__(self) -> str:
        """Return detailed string representation."""
        text_preview = self.text[:20] + "..." if len(self.text) > 20 else self.text
        return f"Run(text={text_preview!r}, len={len(self.text)}, " f"{self._format_summary()})"


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
        >>> from src.model.enums import FontFamily, TextStyle, CharactersPerInch
        >>> run1 = Run(text="Hello", font=FontFamily.ROMAN, style=TextStyle.BOLD)
        >>> run2 = Run(text=" ", font=FontFamily.ROMAN, style=TextStyle.BOLD)
        >>> run3 = Run(text="World", font=FontFamily.ROMAN, style=TextStyle.BOLD)
        >>> merged = merge_consecutive_runs([run1, run2, run3])
        >>> len(merged)
        1
        >>> merged[0].text
        'Hello World'
        >>> merged[0].style == TextStyle.BOLD
        True
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
        >>> from src.model.enums import FontFamily, TextStyle, CharactersPerInch
        >>> text = "HelloWorld"
        >>> template_runs = [
        ...     Run(
        ...         text="x" * 5,
        ...         font=FontFamily.ROMAN,
        ...         style=TextStyle.BOLD
        ...     ),  # First 5 chars bold
        ...     Run(
        ...         text="y" * 5,
        ...         font=FontFamily.ROMAN,
        ...         style=TextStyle(0)
        ...     ),  # Next 5 chars normal
        ... ]
        >>> result = split_by_formatting(text, template_runs)
        >>> result[0].text
        'Hello'
        >>> result[0].style == TextStyle.BOLD
        True
        >>> result[1].text
        'World'
        >>> result[1].style == TextStyle(0)
        True
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

        # ✅ ИСПРАВЛЕНО: Используем новые атрибуты из enums.py
        result.append(
            Run(
                text=text_segment,
                font=template_run.font,
                cpi=template_run.cpi,
                style=template_run.style,
                color=template_run.color,
                codepage=template_run.codepage,
            )
        )

        position += segment_length

    logger.debug(f"Split text into {len(result)} runs (original: {len(runs)} templates)")
    return result
