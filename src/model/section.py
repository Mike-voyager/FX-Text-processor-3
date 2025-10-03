"""
Модель секции документа с коллекцией параграфов и настройками раздела.

Section model representing a logical division of a document with its own
break type, page numbering, and collection of paragraphs. Provides content
management, validation, and serialization for document structure.

Module: src/model/section.py
Project: ESC/P Text Editor
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Final

from src.model.paragraph import Paragraph

logger: Final = logging.getLogger(__name__)


class SectionBreak(Enum):
    """Section break types determining pagination behavior."""

    CONTINUOUS = "continuous"
    NEW_PAGE = "new_page"
    EVEN_PAGE = "even_page"
    ODD_PAGE = "odd_page"


# Page numbering constraints
MIN_PAGE_NUMBER: Final[int] = 1
MAX_PAGE_NUMBER: Final[int] = 9999


@dataclass(slots=True)
class Section:
    """
    Represents a section of a document with paragraphs and break settings.

    A Section is a logical division within a document that can have its own
    page break behavior and numbering. It contains a collection of paragraphs
    and provides methods for content management.

    Attributes:
        paragraphs: List of Paragraph objects in this section.
        break_type: How this section breaks from the previous one.
        page_number_start: Starting page number for this section (None = continue).

    Example:
        >>> section = Section()
        >>> section.add_paragraph(Paragraph())
        >>> section.get_paragraph_count()
        1
        >>> section.break_type = SectionBreak.NEW_PAGE
    """

    paragraphs: list[Paragraph] = field(default_factory=list)
    break_type: SectionBreak = SectionBreak.NEW_PAGE
    page_number_start: int | None = None

    def __post_init__(self) -> None:
        """Validate and normalize attributes after initialization."""
        # Ensure paragraphs is a list
        if not isinstance(self.paragraphs, list):
            logger.warning(
                f"paragraphs must be list, got {type(self.paragraphs).__name__}, converting"
            )
            object.__setattr__(self, "paragraphs", list(self.paragraphs) if self.paragraphs else [])

        # Validate page number start
        if self.page_number_start is not None:
            if not isinstance(self.page_number_start, int):
                logger.warning(
                    f"page_number_start must be int or None, got {type(self.page_number_start).__name__}, "
                    f"setting to None"
                )
                object.__setattr__(self, "page_number_start", None)
            elif not (MIN_PAGE_NUMBER <= self.page_number_start <= MAX_PAGE_NUMBER):
                logger.warning(
                    f"page_number_start {self.page_number_start} out of range "
                    f"[{MIN_PAGE_NUMBER}, {MAX_PAGE_NUMBER}], clamping"
                )
                object.__setattr__(
                    self,
                    "page_number_start",
                    max(MIN_PAGE_NUMBER, min(self.page_number_start, MAX_PAGE_NUMBER)),
                )

    def add_paragraph(self, paragraph: Paragraph) -> None:
        """
        Append a paragraph to the end of the section.

        Args:
            paragraph: The Paragraph object to add.

        Raises:
            TypeError: If paragraph is not a Paragraph instance.

        Example:
            >>> section = Section()
            >>> section.add_paragraph(Paragraph())
            >>> len(section.paragraphs)
            1
        """
        if not isinstance(paragraph, Paragraph):
            raise TypeError(f"Expected Paragraph instance, got {type(paragraph).__name__}")

        self.paragraphs.append(paragraph)
        logger.debug(f"Added paragraph to section, total: {len(self.paragraphs)}")

    def insert_paragraph(self, index: int, paragraph: Paragraph) -> None:
        """
        Insert a paragraph at the specified index.

        Args:
            index: Position to insert the paragraph (0-based).
            paragraph: The Paragraph object to insert.

        Raises:
            TypeError: If paragraph is not a Paragraph instance.
            IndexError: If index is out of valid range.

        Example:
            >>> section = Section()
            >>> section.add_paragraph(Paragraph())
            >>> section.insert_paragraph(0, Paragraph())
            >>> len(section.paragraphs)
            2
        """
        if not isinstance(paragraph, Paragraph):
            raise TypeError(f"Expected Paragraph instance, got {type(paragraph).__name__}")

        if not (0 <= index <= len(self.paragraphs)):
            raise IndexError(
                f"Insert index {index} out of range for {len(self.paragraphs)} paragraphs"
            )

        self.paragraphs.insert(index, paragraph)
        logger.debug(f"Inserted paragraph at index {index}, total: {len(self.paragraphs)}")

    def remove_paragraph(self, index: int) -> Paragraph:
        """
        Remove and return the paragraph at the specified index.

        Args:
            index: Position of the paragraph to remove (0-based).

        Returns:
            The removed Paragraph object.

        Raises:
            IndexError: If index is out of range.

        Example:
            >>> section = Section()
            >>> section.add_paragraph(Paragraph())
            >>> removed = section.remove_paragraph(0)
            >>> len(section.paragraphs)
            0
        """
        if not (0 <= index < len(self.paragraphs)):
            raise IndexError(
                f"Remove index {index} out of range for {len(self.paragraphs)} paragraphs"
            )

        removed = self.paragraphs.pop(index)
        logger.debug(f"Removed paragraph at index {index}, remaining: {len(self.paragraphs)}")
        return removed

    def clear_paragraphs(self) -> None:
        """
        Remove all paragraphs from the section.

        Example:
            >>> section = Section()
            >>> section.add_paragraph(Paragraph())
            >>> section.clear_paragraphs()
            >>> len(section.paragraphs)
            0
        """
        count = len(self.paragraphs)
        self.paragraphs.clear()
        logger.debug(f"Cleared {count} paragraphs from section")

    def get_paragraph_count(self) -> int:
        """
        Get the number of paragraphs in the section.

        Returns:
            Count of Paragraph objects.

        Example:
            >>> section = Section()
            >>> section.add_paragraph(Paragraph())
            >>> section.get_paragraph_count()
            1
        """
        return len(self.paragraphs)

    def get_text(self) -> str:
        """
        Get the complete text of all paragraphs in the section.

        Concatenates text from all paragraphs with newlines between them.

        Returns:
            The complete section text.

        Example:
            >>> section = Section()
            >>> para1 = Paragraph()
            >>> para1.add_run(Run(text="First"))
            >>> para2 = Paragraph()
            >>> para2.add_run(Run(text="Second"))
            >>> section.add_paragraph(para1)
            >>> section.add_paragraph(para2)
            >>> section.get_text()
            'First\\nSecond'
        """
        return "\n".join(para.get_text() for para in self.paragraphs)

    def validate(self) -> None:
        """
        Validate section structure and all contained paragraphs.

        Checks that all paragraphs are valid and section settings are correct.

        Raises:
            ValueError: If section settings or paragraphs are invalid.
            TypeError: If paragraphs contain non-Paragraph objects.

        Example:
            >>> section = Section()
            >>> section.add_paragraph(Paragraph())
            >>> section.validate()  # OK
        """
        # Validate paragraphs
        for i, para in enumerate(self.paragraphs):
            if not isinstance(para, Paragraph):
                raise TypeError(
                    f"Paragraph at index {i} is not a Paragraph instance: " f"{type(para).__name__}"
                )
            try:
                para.validate()
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Paragraph at index {i} failed validation: {exc}") from exc

        # Validate page number start
        if self.page_number_start is not None:
            if not isinstance(self.page_number_start, int):
                raise TypeError(
                    f"page_number_start must be int or None, got "
                    f"{type(self.page_number_start).__name__}"
                )
            if not (MIN_PAGE_NUMBER <= self.page_number_start <= MAX_PAGE_NUMBER):
                raise ValueError(
                    f"page_number_start {self.page_number_start} out of range "
                    f"[{MIN_PAGE_NUMBER}, {MAX_PAGE_NUMBER}]"
                )

        logger.debug(
            f"Validated section: {len(self.paragraphs)} paragraphs, "
            f"break={self.break_type.value}, "
            f"page_start={self.page_number_start}"
        )

    def copy(self) -> "Section":
        """
        Create a deep copy of the section.

        Creates new instances of all paragraphs.

        Returns:
            A new Section with copied paragraphs and settings.

        Example:
            >>> section = Section()
            >>> section.add_paragraph(Paragraph())
            >>> section_copy = section.copy()
            >>> section_copy is not section
            True
            >>> len(section_copy.paragraphs)
            1
        """
        return Section(
            paragraphs=[para.copy() for para in self.paragraphs],
            break_type=self.break_type,
            page_number_start=self.page_number_start,
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize section to dictionary.

        Returns:
            Dictionary with all section attributes and serialized paragraphs.

        Example:
            >>> section = Section()
            >>> section.add_paragraph(Paragraph())
            >>> data = section.to_dict()
            >>> data["break_type"]
            'new_page'
            >>> len(data["paragraphs"])
            1
        """
        return {
            "paragraphs": [para.to_dict() for para in self.paragraphs],
            "break_type": self.break_type.value,
            "page_number_start": self.page_number_start,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Section":
        """
        Deserialize section from dictionary.

        Args:
            data: Dictionary with section attributes.

        Returns:
            Section instance reconstructed from dictionary.

        Raises:
            TypeError: If data is not a dictionary.
            ValueError: If break_type value is invalid.

        Example:
            >>> data = {
            ...     "paragraphs": [],
            ...     "break_type": "new_page",
            ...     "page_number_start": 1
            ... }
            >>> section = Section.from_dict(data)
            >>> section.break_type
            <SectionBreak.NEW_PAGE: 'new_page'>
            >>> section.page_number_start
            1
        """
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict, got {type(data).__name__}")

        # Parse paragraphs
        paragraphs_data = data.get("paragraphs", [])
        if not isinstance(paragraphs_data, list):
            raise TypeError(f"'paragraphs' must be list, got {type(paragraphs_data).__name__}")

        paragraphs = [Paragraph.from_dict(para_data) for para_data in paragraphs_data]

        # Parse break type
        break_type_str = data.get("break_type", "new_page")
        try:
            break_type = SectionBreak(break_type_str)
        except ValueError as exc:
            raise ValueError(f"Invalid break_type value: {break_type_str!r}") from exc

        return Section(
            paragraphs=paragraphs,
            break_type=break_type,
            page_number_start=data.get("page_number_start"),
        )

    def __len__(self) -> int:
        """Return the total character count of all paragraphs."""
        return sum(len(para) for para in self.paragraphs)

    def __eq__(self, other: object) -> bool:
        """
        Compare sections for equality.

        Args:
            other: Object to compare with.

        Returns:
            True if all attributes and paragraphs are equal.
        """
        if not isinstance(other, Section):
            return NotImplemented

        return (
            self.paragraphs == other.paragraphs
            and self.break_type == other.break_type
            and self.page_number_start == other.page_number_start
        )

    def __repr__(self) -> str:
        """
        Return detailed string representation.

        Example:
            >>> section = Section()
            >>> section.add_paragraph(Paragraph())
            >>> repr(section)
            "Section(paragraphs=1, chars=0, break='new_page')"
        """
        return (
            f"Section(paragraphs={len(self.paragraphs)}, chars={len(self)}, "
            f"break='{self.break_type.value}')"
        )


def merge_sections(sections: list[Section], preserve_breaks: bool = False) -> Section:
    """
    Merge multiple sections into one.

    Creates a new section containing all paragraphs from input sections.
    Uses settings from the first section unless preserve_breaks is True.

    Args:
        sections: List of sections to merge.
        preserve_breaks: If True, insert empty paragraphs at section boundaries.

    Returns:
        New Section with merged content.

    Raises:
        ValueError: If sections list is empty.

    Example:
        >>> section1 = Section()
        >>> section1.add_paragraph(Paragraph())
        >>> section2 = Section()
        >>> section2.add_paragraph(Paragraph())
        >>> merged = merge_sections([section1, section2])
        >>> merged.get_paragraph_count()
        2
    """
    if not sections:
        raise ValueError("Cannot merge empty list of sections")

    # Use first section's settings
    result = sections[0].copy()
    result.clear_paragraphs()

    for i, section in enumerate(sections):
        # Add all paragraphs from this section
        for para in section.paragraphs:
            result.add_paragraph(para.copy())

        # Add separator between sections if requested (not after last)
        if preserve_breaks and i < len(sections) - 1:
            result.add_paragraph(Paragraph())  # Empty paragraph as separator

    logger.info(
        f"Merged {len(sections)} sections into one with {len(result.paragraphs)} paragraphs"
    )
    return result


@dataclass(frozen=True, slots=True)
class Margins:
    """
    Page margins configuration.

    All margins are specified in inches. FX-890 supports margins
    from 0" to 8" (page width limit).

    Attributes:
        top: Top margin in inches (default: 0.5").
        bottom: Bottom margin in inches (default: 0.5").
        left: Left margin in inches (default: 0.5").
        right: Right margin in inches (default: 0.5").

    Example:
        >>> margins = Margins(top=1.0, bottom=1.0, left=1.5, right=1.5)
        >>> margins.top
        1.0
    """

    top: float = 0.5
    bottom: float = 0.5
    left: float = 0.5
    right: float = 0.5

    def validate(self) -> None:
        """Validate margin values."""
        for name, value in [
            ("top", self.top),
            ("bottom", self.bottom),
            ("left", self.left),
            ("right", self.right),
        ]:
            if value < 0:
                raise ValueError(f"{name} margin cannot be negative, got {value}")
            if value > 8.0:
                raise ValueError(f"{name} margin exceeds maximum 8.0 inches, got {value}")

    def to_dict(self) -> dict[str, float]:
        """Serialize margins to dictionary."""
        return {
            "top": self.top,
            "bottom": self.bottom,
            "left": self.left,
            "right": self.right,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Margins":
        """Deserialize margins from dictionary."""
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict, got {type(data).__name__}")

        return Margins(
            top=data.get("top", 0.5),
            bottom=data.get("bottom", 0.5),
            left=data.get("left", 0.5),
            right=data.get("right", 0.5),
        )


@dataclass(frozen=True, slots=True)
class PageSettings:
    """
    Page configuration for a section.

    Defines physical page properties including size and margins.
    FX-890 supports various paper sizes up to 8" width.

    Attributes:
        width: Page width in inches (default: 8.5" US Letter).
        height: Page height in inches (default: 11.0" US Letter).
        margins: Margin configuration (default: 0.5" all sides).

    Example:
        >>> settings = PageSettings(width=8.5, height=11.0)
        >>> settings.get_printable_width()
        7.5
    """

    width: float = 8.5
    height: float = 11.0
    margins: Margins = field(default_factory=Margins)

    def validate(self) -> None:
        """Validate page settings."""
        if self.width <= 0:
            raise ValueError(f"Page width must be positive, got {self.width}")
        if self.height <= 0:
            raise ValueError(f"Page height must be positive, got {self.height}")
        if self.width > 8.0:
            raise ValueError(f"FX-890 max width is 8.0 inches, got {self.width}")

        # Validate margins
        self.margins.validate()

        # Check margins don't exceed page dimensions
        if self.margins.left + self.margins.right >= self.width:
            raise ValueError(
                f"Horizontal margins ({self.margins.left} + {self.margins.right}) "
                f"exceed page width ({self.width})"
            )

    def get_printable_width(self) -> float:
        """Calculate printable width (page width minus margins)."""
        return self.width - self.margins.left - self.margins.right

    def get_printable_height(self) -> float:
        """Calculate printable height (page height minus margins)."""
        return self.height - self.margins.top - self.margins.bottom

    def to_dict(self) -> dict[str, Any]:
        """Serialize page settings to dictionary."""
        return {
            "width": self.width,
            "height": self.height,
            "margins": self.margins.to_dict(),
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "PageSettings":
        """Deserialize page settings from dictionary."""
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict, got {type(data).__name__}")

        margins_data = data.get("margins", {})
        margins = Margins.from_dict(margins_data) if margins_data else Margins()

        return PageSettings(
            width=data.get("width", 8.5),
            height=data.get("height", 11.0),
            margins=margins,
        )


def split_section_at(section: Section, paragraph_index: int) -> tuple[Section, Section]:
    """
    Split a section into two at the specified paragraph index.

    Creates two new sections: the first contains paragraphs [0:paragraph_index),
    the second contains paragraphs [paragraph_index:]. Both inherit settings
    from the original section.

    Args:
        section: The section to split.
        paragraph_index: Index at which to split (paragraphs before go to first section).

    Returns:
        Tuple of (first_section, second_section).

    Raises:
        ValueError: If paragraph_index is out of valid range.

    Example:
        >>> section = Section()
        >>> section.add_paragraph(Paragraph())
        >>> section.add_paragraph(Paragraph())
        >>> section.add_paragraph(Paragraph())
        >>> first, second = split_section_at(section, 1)
        >>> first.get_paragraph_count()
        1
        >>> second.get_paragraph_count()
        2
    """
    if not (0 < paragraph_index < len(section.paragraphs)):
        raise ValueError(
            f"Split index {paragraph_index} must be in range (0, {len(section.paragraphs)})"
        )

    # Create first section with paragraphs before split point
    first = Section(
        paragraphs=[para.copy() for para in section.paragraphs[:paragraph_index]],
        break_type=section.break_type,
        page_number_start=section.page_number_start,
    )

    # Create second section with paragraphs from split point onward
    second = Section(
        paragraphs=[para.copy() for para in section.paragraphs[paragraph_index:]],
        break_type=SectionBreak.CONTINUOUS,  # Second part continues from first
        page_number_start=None,  # Continue numbering
    )

    logger.info(
        f"Split section at paragraph {paragraph_index}: "
        f"{len(section.paragraphs)} paragraphs → {len(first.paragraphs)} + {len(second.paragraphs)}"
    )

    return first, second
