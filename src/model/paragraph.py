"""
Модель параграфа с форматированием и коллекцией текстовых фрагментов.

Paragraph model representing a logical block of text with shared formatting
properties (alignment, indentation, spacing) and a collection of text runs.
Provides manipulation, validation, metrics calculation, and advanced features
like word wrapping, justification, and ESC/P caching for FX-890 rendering.

Module: src/model/paragraph.py
Project: ESC/P Text Editor
"""

import hashlib
import json
import logging
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Final

from src.model.run import Run, merge_consecutive_runs
from src.model.enums import (
    Alignment,
    LineSpacing,
    TabAlignment,
    MAX_PRINT_WIDTH_INCHES,
    MIN_MARGIN_INCHES,
)

logger: Final = logging.getLogger(__name__)

# Measurement constraints (in inches)
MIN_INDENT: Final[float] = 0.0
MAX_INDENT: Final[float] = MAX_PRINT_WIDTH_INCHES  # FX-890 max paper width (8.0")
MIN_SPACE: Final[float] = 0.0
MAX_SPACE: Final[float] = 2.0

# ESC/P constraints for FX-890
MAX_MARGIN_CHARS: Final[int] = 255  # ESC l/Q parameter range: 0-255
MAX_TAB_STOPS: Final[int] = 32  # FX-890 supports max 32 tab stops
MAX_CACHE_SIZE: Final[int] = 10  # Maximum cached ESC/P results


# =============================================================================
# SUPPORTING DATACLASSES
# =============================================================================


@dataclass(frozen=True, slots=True)
class TabStop:
    """
    Tab stop configuration for ESC/P tab control.

    Defines a horizontal position where tab character (\\t) will advance to.
    FX-890 supports up to 32 tab stops via ESC D command.

    Attributes:
        position: Tab position in characters from left margin (1-255).
        alignment: Text alignment at tab stop (default: LEFT).

    Example:
        >>> tab = TabStop(position=10, alignment=TabAlignment.LEFT)
        >>> tab.position
        10
    """

    position: int
    alignment: TabAlignment = TabAlignment.LEFT

    def __post_init__(self) -> None:
        """Validate tab stop position."""
        if not (1 <= self.position <= 255):
            raise ValueError(f"Tab position must be 1-255, got {self.position}")

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "position": self.position,
            "alignment": self.alignment.value,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "TabStop":
        """Deserialize from dictionary."""
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict, got {type(data).__name__}")

        alignment_str = data.get("alignment", "left")
        try:
            alignment = TabAlignment(alignment_str)
        except ValueError as exc:
            raise ValueError(f"Invalid alignment value: {alignment_str!r}") from exc

        return TabStop(position=data["position"], alignment=alignment)


@dataclass(frozen=True, slots=True)
class WrappedLine:
    """
    Represents a single wrapped line of text.

    Used by word wrapping algorithm to store line information.

    Attributes:
        runs: List of Run objects for this line.
        width_chars: Width in characters.
        is_last: True if this is the last line of paragraph.

    Example:
        >>> line = WrappedLine(
        ...     runs=[Run(text="Hello")],
        ...     width_chars=5,
        ...     is_last=False
        ... )
    """

    runs: list[Run]
    width_chars: int
    is_last: bool


@dataclass(frozen=True, slots=True)
class ParagraphMetrics:
    """
    Physical metrics of a rendered paragraph.

    Provides detailed information about paragraph dimensions and resource usage
    for layout calculations, diagnostics, and optimization.

    Attributes:
        width_inches: Effective text width after indents (inches).
        height_inches: Vertical height including spacing (inches).
        line_count: Number of lines including space_before/after.
        character_count: Total characters in all runs.
        escp_byte_count: Size of generated ESC/P commands (bytes).
        left_margin_chars: Left margin in characters at specified CPI.
        right_margin_chars: Right margin in characters at specified CPI.

    Example:
        >>> metrics = ParagraphMetrics(
        ...     width_inches=7.5,
        ...     height_inches=0.5,
        ...     line_count=3,
        ...     character_count=50,
        ...     escp_byte_count=120,
        ...     left_margin_chars=10,
        ...     right_margin_chars=75
        ... )
    """

    width_inches: float
    height_inches: float
    line_count: int
    character_count: int
    escp_byte_count: int
    left_margin_chars: int
    right_margin_chars: int

    def __repr__(self) -> str:
        """Return compact string representation."""
        return (
            f'ParagraphMetrics(width={self.width_inches:.2f}", '
            f'height={self.height_inches:.2f}", '
            f"lines={self.line_count}, chars={self.character_count}, "
            f"bytes={self.escp_byte_count})"
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize metrics to dictionary."""
        return {
            "width_inches": self.width_inches,
            "height_inches": self.height_inches,
            "line_count": self.line_count,
            "character_count": self.character_count,
            "escp_byte_count": self.escp_byte_count,
            "left_margin_chars": self.left_margin_chars,
            "right_margin_chars": self.right_margin_chars,
        }


@dataclass(slots=True)
class Paragraph:
    """
    Represents a paragraph with formatting and text runs.

    A Paragraph is a container for Run objects that share common formatting
    properties like alignment, indentation, and line spacing. Provides advanced
    features including word wrapping, justification, tab stops, and ESC/P caching.

    Attributes:
        runs: List of Run objects containing the paragraph text.
        alignment: Horizontal text alignment from Alignment enum.
        first_line_indent: Indentation of the first line (inches).
        left_indent: Left margin indentation (inches).
        right_indent: Right margin indentation (inches).
        line_spacing: Line spacing from LineSpacing enum (default: 1/6").
        custom_line_spacing_value: For CUSTOM line spacing, ESC 3 n value (1-255, in 1/216").
        space_before: Vertical space before paragraph (inches).
        space_after: Vertical space after paragraph (inches).
        tab_stops: List of TabStop objects for tab positions.

    Example:
        >>> para = Paragraph()
        >>> para.add_run(Run(text="Hello ", style=TextStyle.BOLD))
        >>> para.add_run(Run(text="World"))
        >>> para.set_tab_stops([10, 20, 30])
        >>> escp = para.to_escp(page_width=8.5, page_cpi=10)
    """

    runs: list[Run] = field(default_factory=list)
    alignment: Alignment = Alignment.LEFT
    first_line_indent: float = 0.0
    left_indent: float = 0.0
    right_indent: float = 0.0
    line_spacing: LineSpacing = LineSpacing.ONE_SIXTH_INCH
    custom_line_spacing_value: int | None = None
    space_before: float = 0.0
    space_after: float = 0.0
    tab_stops: list[TabStop] = field(default_factory=list)

    # Cache management (non-init fields)
    _escp_cache: OrderedDict[tuple[float, int, bool], bytes] = field(
        default_factory=OrderedDict, init=False, repr=False
    )
    _cache_hash: str | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        """Validate and normalize attributes after initialization."""
        # Ensure runs is a list
        if not isinstance(self.runs, list):
            logger.warning(f"runs must be list, got {type(self.runs).__name__}, converting")
            object.__setattr__(self, "runs", list(self.runs) if self.runs else [])

        # Clamp indentation values
        if not (MIN_INDENT <= self.first_line_indent <= MAX_INDENT):
            logger.warning(
                f"first_line_indent {self.first_line_indent:.3f} out of range "
                f"[{MIN_INDENT}, {MAX_INDENT}], clamping"
            )
            object.__setattr__(
                self, "first_line_indent", max(MIN_INDENT, min(self.first_line_indent, MAX_INDENT))
            )

        if not (MIN_INDENT <= self.left_indent <= MAX_INDENT):
            logger.warning(
                f"left_indent {self.left_indent:.3f} out of range "
                f"[{MIN_INDENT}, {MAX_INDENT}], clamping"
            )
            object.__setattr__(
                self, "left_indent", max(MIN_INDENT, min(self.left_indent, MAX_INDENT))
            )

        if not (MIN_INDENT <= self.right_indent <= MAX_INDENT):
            logger.warning(
                f"right_indent {self.right_indent:.3f} out of range "
                f"[{MIN_INDENT}, {MAX_INDENT}], clamping"
            )
            object.__setattr__(
                self, "right_indent", max(MIN_INDENT, min(self.right_indent, MAX_INDENT))
            )

        # Clamp spacing before/after
        if not (MIN_SPACE <= self.space_before <= MAX_SPACE):
            logger.warning(
                f"space_before {self.space_before:.3f} out of range "
                f"[{MIN_SPACE}, {MAX_SPACE}], clamping"
            )
            object.__setattr__(
                self, "space_before", max(MIN_SPACE, min(self.space_before, MAX_SPACE))
            )

        if not (MIN_SPACE <= self.space_after <= MAX_SPACE):
            logger.warning(
                f"space_after {self.space_after:.3f} out of range "
                f"[{MIN_SPACE}, {MAX_SPACE}], clamping"
            )
            object.__setattr__(
                self, "space_after", max(MIN_SPACE, min(self.space_after, MAX_SPACE))
            )

        # Validate custom line spacing value
        if self.line_spacing == LineSpacing.CUSTOM:
            if self.custom_line_spacing_value is None:
                logger.warning("CUSTOM line spacing without value, will use 1/6 inch default")
            elif not (1 <= self.custom_line_spacing_value <= 255):
                logger.warning(
                    f"custom_line_spacing_value {self.custom_line_spacing_value} "
                    f"out of range [1, 255], clamping"
                )
                object.__setattr__(
                    self,
                    "custom_line_spacing_value",
                    max(1, min(self.custom_line_spacing_value, 255)),
                )

        # Ensure tab_stops is a list
        if not isinstance(self.tab_stops, list):
            logger.warning(
                f"tab_stops must be list, got {type(self.tab_stops).__name__}, converting"
            )
            object.__setattr__(self, "tab_stops", list(self.tab_stops) if self.tab_stops else [])

    # =========================================================================
    # RUN MANAGEMENT
    # =========================================================================

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
        self.invalidate_escp_cache()
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
        """
        if not isinstance(run, Run):
            raise TypeError(f"Expected Run instance, got {type(run).__name__}")

        if not (0 <= index <= len(self.runs)):
            raise IndexError(f"Insert index {index} out of range for {len(self.runs)} runs")

        self.runs.insert(index, run)
        self.invalidate_escp_cache()
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
        """
        if not (0 <= index < len(self.runs)):
            raise IndexError(f"Remove index {index} out of range for {len(self.runs)} runs")

        removed = self.runs.pop(index)
        self.invalidate_escp_cache()
        logger.debug(f"Removed run at index {index}, remaining: {len(self.runs)}")
        return removed

    def clear_runs(self) -> None:
        """Remove all runs from the paragraph."""
        count = len(self.runs)
        self.runs.clear()
        self.invalidate_escp_cache()
        logger.debug(f"Cleared {count} runs from paragraph")

    def get_text(self) -> str:
        """
        Get the complete text of the paragraph.

        Concatenates text from all runs in order.

        Returns:
            The complete paragraph text.
        """
        return "".join(run.text for run in self.runs)

    def get_run_count(self) -> int:
        """
        Get the number of runs in the paragraph.

        Returns:
            Count of Run objects.
        """
        return len(self.runs)

    def add_runs(self, runs: list[Run]) -> None:
        """
        Add multiple runs at once (more efficient than multiple add_run calls).

        Performs bulk addition of runs with single cache invalidation.

        Args:
            runs: List of Run objects to add.

        Raises:
            TypeError: If runs is not a list or contains non-Run objects.

        Example:
            >>> para = Paragraph()
            >>> para.add_runs([Run(text="A"), Run(text="B"), Run(text="C")])
            >>> para.get_run_count()
            3
        """
        if not isinstance(runs, list):
            raise TypeError(f"runs must be list, got {type(runs).__name__}")

        if not all(isinstance(run, Run) for run in runs):
            raise TypeError("All elements must be Run instances")

        if not runs:
            logger.debug("add_runs called with empty list, no-op")
            return

        self.runs.extend(runs)
        self.invalidate_escp_cache()
        logger.debug(f"Bulk added {len(runs)} runs, total: {len(self.runs)}")

    def replace_runs(self, runs: list[Run]) -> None:
        """
        Replace all runs with new ones (atomic operation).

        Args:
            runs: New list of Run objects to replace existing runs.

        Raises:
            TypeError: If runs is not a list or contains non-Run objects.

        Example:
            >>> para = Paragraph()
            >>> para.add_run(Run(text="Old"))
            >>> para.replace_runs([Run(text="New1"), Run(text="New2")])
            >>> para.get_text()
            'New1New2'
        """
        if not isinstance(runs, list):
            raise TypeError(f"runs must be list, got {type(runs).__name__}")

        if not all(isinstance(run, Run) for run in runs):
            raise TypeError("All elements must be Run instances")

        old_count = len(self.runs)
        self.runs = runs.copy()
        self.invalidate_escp_cache()
        logger.debug(f"Replaced {old_count} runs with {len(runs)} new runs")

    def extend_text(self, text: str, **run_kwargs: Any) -> None:
        """
        Convenience method to add text with optional Run formatting.

        Creates a new Run with the specified text and formatting options.

        Args:
            text: Text content to add.
            **run_kwargs: Keyword arguments passed to Run constructor.

        Example:
            >>> para = Paragraph()
            >>> para.extend_text("Bold", style=TextStyle.BOLD)
            >>> para.extend_text(" normal")
            >>> para.get_text()
            'Bold normal'
        """
        if not text:
            logger.debug("extend_text called with empty text, no-op")
            return

        run = Run(text=text, **run_kwargs)
        self.add_run(run)
        logger.debug(f"Extended paragraph with {len(text)} chars")

    # =========================================================================
    # CACHE MANAGEMENT
    # =========================================================================

    def _calculate_content_hash(self) -> str:
        """
        Calculate hash of paragraph content for cache invalidation.

        Uses SHA256 hash of key attributes that affect ESC/P output.
        Optimized for performance by hashing only essential data.

        Returns:
            SHA256 hex digest of paragraph state.
        """
        # Build state tuple (faster than JSON serialization)
        state_parts = [
            str(self.alignment.value),
            str(self.line_spacing.value),
            str(self.custom_line_spacing_value or ""),
            f"{self.first_line_indent:.6f}",
            f"{self.left_indent:.6f}",
            f"{self.right_indent:.6f}",
            f"{self.space_before:.6f}",
            f"{self.space_after:.6f}",
            "|".join(str(t.position) for t in self.tab_stops),
            "|".join(run.text for run in self.runs),
        ]

        state_str = "::".join(state_parts)
        return hashlib.sha256(state_str.encode("utf-8")).hexdigest()

    def invalidate_escp_cache(self) -> None:
        """
        Clear ESC/P cache when paragraph content is modified.

        Should be called after any modification to runs or formatting.
        Automatically called by mutating methods.
        """
        self._escp_cache.clear()
        self._cache_hash = None
        logger.debug("Invalidated ESC/P cache")

    def get_cache_stats(self) -> dict[str, Any]:
        """
        Get cache statistics for diagnostics.

        Returns:
            Dictionary with cache hit count, size, and hash.

        Example:
            >>> para = Paragraph()
            >>> para.add_run(Run(text="Test"))
            >>> para.to_escp()
            >>> stats = para.get_cache_stats()
            >>> stats["size"]
            1
        """
        return {
            "size": len(self._escp_cache),
            "max_size": MAX_CACHE_SIZE,
            "current_hash": self._cache_hash,
            "keys": list(self._escp_cache.keys()),
        }

    # =========================================================================
    # TAB STOPS
    # =========================================================================

    def set_tab_stops(self, positions: list[int]) -> None:
        """
        Set tab stops at specified positions.

        Args:
            positions: List of tab positions in characters (1-255).
                      Maximum 32 tab stops supported by FX-890.

        Raises:
            ValueError: If positions invalid or exceed limit.

        Example:
            >>> para = Paragraph()
            >>> para.set_tab_stops([10, 20, 30, 40])
            >>> len(para.tab_stops)
            4
        """
        if len(positions) > MAX_TAB_STOPS:
            raise ValueError(f"Maximum {MAX_TAB_STOPS} tab stops supported, got {len(positions)}")

        # Sort and deduplicate
        unique_positions = sorted(set(positions))

        # Validate all positions
        for pos in unique_positions:
            if not (1 <= pos <= 255):
                raise ValueError(f"Tab position must be 1-255, got {pos}")

        # Create TabStop objects
        self.tab_stops = [TabStop(position=pos) for pos in unique_positions]
        self.invalidate_escp_cache()

        logger.debug(f"Set {len(self.tab_stops)} tab stops: {unique_positions}")

    def clear_tab_stops(self) -> None:
        """Clear all tab stops."""
        count = len(self.tab_stops)
        self.tab_stops.clear()
        self.invalidate_escp_cache()
        logger.debug(f"Cleared {count} tab stops")

    # =========================================================================
    # VALIDATION
    # =========================================================================

    def validate(self) -> None:
        """
        Validate paragraph structure and formatting.

        Raises:
            ValueError: If formatting values are invalid or runs contain errors.
            TypeError: If runs contain non-Run objects or enums are invalid.
        """
        # Validate runs
        for i, run in enumerate(self.runs):
            if not isinstance(run, Run):
                raise TypeError(f"Run at index {i} is not a Run instance: {type(run).__name__}")
            try:
                run.validate()
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Run at index {i} failed validation: {exc}") from exc

        # Validate enum types
        if not isinstance(self.alignment, Alignment):
            raise TypeError(f"alignment must be Alignment, got {type(self.alignment).__name__}")
        if not isinstance(self.line_spacing, LineSpacing):
            raise TypeError(
                f"line_spacing must be LineSpacing, got {type(self.line_spacing).__name__}"
            )

        # Validate indent sum doesn't exceed reasonable limits
        total_indent = self.left_indent + self.right_indent
        if total_indent >= MAX_INDENT:
            raise ValueError(
                f"Combined left ({self.left_indent:.3f}) and right ({self.right_indent:.3f}) "
                f"indents ({total_indent:.3f}) exceed maximum ({MAX_INDENT})"
            )

        # Validate custom line spacing
        if self.line_spacing == LineSpacing.CUSTOM:
            if self.custom_line_spacing_value is not None:
                if not (1 <= self.custom_line_spacing_value <= 255):
                    raise ValueError(
                        f"custom_line_spacing_value must be 1-255, "
                        f"got {self.custom_line_spacing_value}"
                    )

        # Validate tab stops
        for i, tab in enumerate(self.tab_stops):
            if not isinstance(tab, TabStop):
                raise TypeError(
                    f"Tab stop at index {i} is not a TabStop instance: {type(tab).__name__}"
                )
            if not (1 <= tab.position <= 255):
                raise ValueError(f"Tab stop {i} position {tab.position} out of range [1, 255]")

        logger.debug(
            f"Validated paragraph: {len(self.runs)} runs, "
            f"alignment={self.alignment.value}, "
            f"line_spacing={self.line_spacing.value}, "
            f"tab_stops={len(self.tab_stops)}"
        )

    # =========================================================================
    # ESC/P GENERATION
    # =========================================================================

    def to_escp(
        self,
        page_width: float = 8.5,
        page_cpi: int = 10,
        reset_margins: bool = True,
        use_cache: bool = True,
    ) -> bytes:
        """
        Generate ESC/P commands for the paragraph with FX-890 compatibility.

        This method generates hardware-optimized ESC/P commands using:
        - ESC l n: Left margin (0-255 characters)
        - ESC Q n: Right margin (absolute position, 1-255 characters)
        - ESC 2/0/1/3: Line spacing control
        - ESC D: Tab stops configuration
        - Software alignment via spaces (FX-890 has no hardware alignment)

        Args:
            page_width: Page width in inches (default: 8.5" US Letter).
            page_cpi: Characters per inch for calculations (default: 10 CPI).
            reset_margins: If True, reset margins to 0 after paragraph (default: True).
            use_cache: If True, use cached result if available (default: True).

        Returns:
            Byte sequence of ESC/P commands.

        Raises:
            ValueError: If page_width is invalid or margins are misconfigured.

        Example:
            >>> para = Paragraph(alignment=Alignment.CENTER, left_indent=1.0)
            >>> para.add_run(Run(text="Centered", style=TextStyle.BOLD))
            >>> escp = para.to_escp(page_width=8.5, page_cpi=10)
            >>> isinstance(escp, bytes)
            True
        """
        if page_width <= 0:
            raise ValueError(f"page_width must be positive, got {page_width}")
        if page_cpi <= 0:
            raise ValueError(f"page_cpi must be positive, got {page_cpi}")

        # Check cache
        if use_cache:
            cache_key = (page_width, page_cpi, reset_margins)
            current_hash = self._calculate_content_hash()

            # Cache hit: hash matches and key exists
            if current_hash == self._cache_hash and cache_key in self._escp_cache:
                logger.debug(f"Cache HIT for key {cache_key}")
                return self._escp_cache[cache_key]

            logger.debug(f"Cache MISS for key {cache_key}")

        # Generate ESC/P commands
        commands: list[bytes] = []

        # 1. Set line spacing (ESC 2/0/1/3)
        if self.line_spacing == LineSpacing.CUSTOM and self.custom_line_spacing_value:
            # ESC 3 n - custom spacing (n/216 inches)
            commands.append(b"\x1b\x33" + bytes([self.custom_line_spacing_value]))
            logger.debug(f"Set custom line spacing: {self.custom_line_spacing_value}/216 inch")
        else:
            commands.append(self.line_spacing.to_escp())
            logger.debug(f"Set line spacing: {self.line_spacing.value}")

        # 2. Set tab stops (ESC D) if configured
        if self.tab_stops:
            positions = [min(tab.position, 255) for tab in self.tab_stops]
            tab_cmd = b"\x1b\x44" + bytes(positions) + b"\x00"
            commands.append(tab_cmd)
            logger.debug(f"Set {len(positions)} tab stops: {positions}")

        # 3. Set left margin (ESC l n) - in characters
        left_margin_set = False
        if self.left_indent > 0:
            left_margin_chars = int(self.left_indent * page_cpi)
            if left_margin_chars > MAX_MARGIN_CHARS:
                logger.warning(
                    f"Left margin {left_margin_chars} chars exceeds max {MAX_MARGIN_CHARS}, "
                    f"clamping to {MAX_MARGIN_CHARS}"
                )
                left_margin_chars = MAX_MARGIN_CHARS

            commands.append(b"\x1b\x6c" + bytes([left_margin_chars]))
            left_margin_set = True
            logger.debug(f'Set left margin: {left_margin_chars} chars ({self.left_indent:.3f}")')

        # 4. Set right margin (ESC Q n) - ABSOLUTE position from left edge
        right_margin_set = False
        if self.right_indent > 0:
            page_width_chars = int(page_width * page_cpi)
            right_indent_chars = int(self.right_indent * page_cpi)
            right_margin_pos = page_width_chars - right_indent_chars

            # Ensure right margin > left margin
            left_margin_chars = int(self.left_indent * page_cpi) if self.left_indent > 0 else 0

            if right_margin_pos <= left_margin_chars:
                logger.warning(
                    f"Right margin position {right_margin_pos} <= left margin {left_margin_chars}, "
                    f"skipping right margin command"
                )
            elif right_margin_pos > MAX_MARGIN_CHARS:
                logger.warning(
                    f"Right margin position {right_margin_pos} exceeds max {MAX_MARGIN_CHARS}, "
                    f"clamping to {MAX_MARGIN_CHARS}"
                )
                commands.append(b"\x1b\x51" + bytes([MAX_MARGIN_CHARS]))
                right_margin_set = True
            else:
                commands.append(b"\x1b\x51" + bytes([right_margin_pos]))
                right_margin_set = True
                logger.debug(
                    f"Set right margin: pos={right_margin_pos} chars "
                    f"(page={page_width_chars}, indent={right_indent_chars})"
                )

        # 5. Add space before (line feeds)
        if self.space_before > 0:
            lines_before = self._calculate_lines_for_space(self.space_before)
            if lines_before > 0:
                commands.append(b"\n" * lines_before)
                logger.debug(
                    f'Added {lines_before} line feeds for space_before={self.space_before:.3f}"'
                )

        # 6. First line indent (spaces only - no ESC/P command for this)
        if self.first_line_indent > 0:
            first_line_spaces = int(self.first_line_indent * page_cpi)
            commands.append(b" " * first_line_spaces)
            logger.debug(
                f'Added {first_line_spaces} spaces for first_line_indent={self.first_line_indent:.3f}"'
            )

        # 7. Apply software alignment (FX-890 has no hardware alignment commands)
        if self.alignment != Alignment.LEFT and self.runs:
            full_text = self.get_text()
            effective_width = self.calculate_width(page_width)
            available_chars = int(effective_width * page_cpi)
            text_length = len(full_text)

            if self.alignment == Alignment.CENTER:
                padding = max(0, (available_chars - text_length) // 2)
                if padding > 0:
                    commands.append(b" " * padding)
                    logger.debug(f"CENTER alignment: added {padding} spaces padding")

            elif self.alignment == Alignment.RIGHT:
                padding = max(0, available_chars - text_length)
                if padding > 0:
                    commands.append(b" " * padding)
                    logger.debug(f"RIGHT alignment: added {padding} spaces padding")

            elif self.alignment == Alignment.JUSTIFY:
                # JUSTIFY is handled per-line in word-wrap mode
                # For single-line paragraphs, behaves like LEFT
                logger.debug("JUSTIFY alignment: single-line mode, using LEFT alignment")

        # 8. Output runs with their formatting
        for i, run in enumerate(self.runs):
            try:
                run_escp = run.to_escp()
                commands.append(run_escp)
                logger.debug(f"Added run {i}: {len(run.text)} chars, {len(run_escp)} bytes ESC/P")
            except Exception as exc:
                logger.error(f"Failed to generate ESC/P for run {i}: {exc}")
                raise

        # 9. Line break (CR+LF)
        commands.append(b"\r\n")

        # 10. Add space after (line feeds)
        if self.space_after > 0:
            lines_after = self._calculate_lines_for_space(self.space_after)
            if lines_after > 0:
                commands.append(b"\n" * lines_after)
                logger.debug(
                    f'Added {lines_after} line feeds for space_after={self.space_after:.3f}"'
                )

        # 11. Reset margins if requested
        if reset_margins:
            if left_margin_set:
                commands.append(b"\x1b\x6c\x00")  # ESC l 0 - Reset left margin to 0
                logger.debug("Reset left margin to 0")

            if right_margin_set:
                commands.append(b"\x1b\x51\x00")  # ESC Q 0 - Reset right margin to 0
                logger.debug("Reset right margin to 0")

        result = b"".join(commands)

        # Cache result
        if use_cache:
            cache_key = (page_width, page_cpi, reset_margins)

            # Limit cache size (LRU eviction)
            if len(self._escp_cache) >= MAX_CACHE_SIZE:
                # Remove oldest entry
                self._escp_cache.popitem(last=False)
                logger.debug(f"Cache full, evicted oldest entry")

            self._escp_cache[cache_key] = result
            self._cache_hash = self._calculate_content_hash()
            logger.debug(f"Cached ESC/P for key {cache_key} ({len(result)} bytes)")

        logger.info(
            f"Generated {len(result)} bytes ESC/P for paragraph: "
            f"{len(self.runs)} runs, {len(self.get_text())} chars, "
            f"alignment={self.alignment.value}, reset_margins={reset_margins}, "
            f"cached={use_cache}"
        )
        return result

    def _calculate_lines_for_space(self, space_inches: float) -> int:
        """
        Calculate number of line feeds for vertical spacing.

        Converts inches to line count based on current line_spacing setting.

        Args:
            space_inches: Vertical space in inches.

        Returns:
            Number of line feed (LF) commands needed.

        Example:
            >>> para = Paragraph(line_spacing=LineSpacing.ONE_SIXTH_INCH)
            >>> para._calculate_lines_for_space(1.0)  # 1 inch at 6 LPI
            6
        """
        # Get LPI (lines per inch) from current line spacing
        if self.line_spacing == LineSpacing.ONE_SIXTH_INCH:
            lpi = 6  # 1/6" per line = 6 lines per inch
        elif self.line_spacing == LineSpacing.ONE_EIGHTH_INCH:
            lpi = 8  # 1/8" per line = 8 lines per inch
        elif self.line_spacing == LineSpacing.SEVEN_SEVENTYTWOTH_INCH:
            lpi = 72 // 7  # 7/72" per line ≈ 10.3 lines per inch
        elif self.line_spacing == LineSpacing.CUSTOM and self.custom_line_spacing_value:
            # Custom: n/216" per line
            # LPI = 216 / n
            lpi = 216 // self.custom_line_spacing_value
        else:  # CUSTOM without value - assume 6 LPI
            logger.warning("CUSTOM line spacing without value, assuming 6 LPI")
            lpi = 6

        lines = int(space_inches * lpi)
        logger.debug(f'Calculated {lines} lines for {space_inches:.3f}" at {lpi} LPI')
        return lines

    # =========================================================================
    # WORD WRAPPING
    # =========================================================================

    def wrap_text(
        self,
        max_width_chars: int,
        break_on_hyphens: bool = True,
        break_long_words: bool = True,
    ) -> list[WrappedLine]:
        """
        Wrap paragraph text into multiple lines.

        Performs word wrapping at word boundaries, respecting Run formatting.
        Useful for generating multi-line output for constrained widths.

        Args:
            max_width_chars: Maximum line width in characters.
            break_on_hyphens: Allow breaking at hyphens (default: True).
            break_long_words: Force break words longer than max_width (default: True).

        Returns:
            List of WrappedLine objects, one per line.

        Raises:
            ValueError: If max_width_chars < 1.

        Example:
            >>> para = Paragraph()
            >>> para.add_run(Run(text="This is a long paragraph that needs wrapping"))
            >>> lines = para.wrap_text(max_width_chars=20)
            >>> len(lines) >= 2
            True
        """
        if max_width_chars < 1:
            raise ValueError(f"max_width_chars must be >= 1, got {max_width_chars}")

        if not self.runs:
            return []

        wrapped_lines: list[WrappedLine] = []
        current_line_runs: list[Run] = []
        current_line_width = 0

        for run in self.runs:
            if not run.text:  # Skip empty runs
                continue

            words = self._split_run_into_words(run, break_on_hyphens)

            for word, space in words:
                word_len = len(word)
                space_len = len(space)
                total_len = word_len + space_len

                # Check if word fits on current line
                if current_line_width + total_len <= max_width_chars:
                    # Add to current line
                    current_line_runs.append(
                        Run(text=word + space, **self._copy_run_formatting(run))
                    )
                    current_line_width += total_len

                elif word_len <= max_width_chars:
                    # Start new line with this word
                    if current_line_runs:
                        wrapped_lines.append(
                            WrappedLine(
                                runs=current_line_runs,
                                width_chars=current_line_width,
                                is_last=False,
                            )
                        )

                    current_line_runs = [Run(text=word + space, **self._copy_run_formatting(run))]
                    current_line_width = total_len

                else:
                    # Word is too long, must break it
                    if break_long_words:
                        remaining = word
                        while remaining:
                            # Fill current line
                            available = max_width_chars - current_line_width
                            if available > 0:
                                chunk = remaining[:available]
                                current_line_runs.append(
                                    Run(text=chunk, **self._copy_run_formatting(run))
                                )
                                current_line_width += len(chunk)
                                remaining = remaining[available:]

                            # Start new line if needed
                            if remaining:
                                wrapped_lines.append(
                                    WrappedLine(
                                        runs=current_line_runs,
                                        width_chars=current_line_width,
                                        is_last=False,
                                    )
                                )
                                current_line_runs = []
                                current_line_width = 0

                        # Add trailing space if any
                        if space:
                            current_line_runs.append(
                                Run(text=space, **self._copy_run_formatting(run))
                            )
                            current_line_width += space_len

                    else:
                        # Can't break word, add anyway (overflow)
                        if current_line_runs:
                            wrapped_lines.append(
                                WrappedLine(
                                    runs=current_line_runs,
                                    width_chars=current_line_width,
                                    is_last=False,
                                )
                            )
                        current_line_runs = [
                            Run(text=word + space, **self._copy_run_formatting(run))
                        ]
                        current_line_width = word_len + space_len

        # Add last line
        if current_line_runs:
            wrapped_lines.append(
                WrappedLine(runs=current_line_runs, width_chars=current_line_width, is_last=True)
            )

        logger.info(
            f"Wrapped paragraph into {len(wrapped_lines)} lines (max_width={max_width_chars})"
        )
        return wrapped_lines

    def _split_run_into_words(self, run: Run, break_on_hyphens: bool) -> list[tuple[str, str]]:
        """
        Split run text into (word, trailing_space) tuples.

        Args:
            run: Run to split.
            break_on_hyphens: Whether to break at hyphens.

        Returns:
            List of (word, space) tuples.
        """
        if break_on_hyphens:
            # Break on spaces and hyphens
            pattern = r"(\S+?[\s-]|\S+)"
        else:
            # Break only on spaces
            pattern = r"(\S+\s?)"

        matches = re.findall(pattern, run.text)

        result = []
        for match in matches:
            # Separate word from trailing whitespace
            word = match.rstrip()
            space = match[len(word) :]
            if word:  # Only add non-empty words
                result.append((word, space))

        return result

    def _copy_run_formatting(self, run: Run) -> dict[str, Any]:
        """
        Extract non-None formatting attributes from run.

        Args:
            run: Run to extract formatting from.

        Returns:
            Dictionary with formatting attributes (excluding None values).
        """
        attrs = {}
        for attr in ["style", "font", "cpi", "color", "codepage"]:
            value = getattr(run, attr, None)
            if value is not None:
                attrs[attr] = value
        return attrs

    # =========================================================================
    # JUSTIFICATION
    # =========================================================================

    def _justify_line(self, line: WrappedLine, target_width: int) -> list[Run]:
        """
        Justify a line by distributing extra spaces between words.

        Args:
            line: WrappedLine to justify.
            target_width: Target line width in characters.

        Returns:
            List of Run objects with adjusted spacing.
        """
        if line.is_last or line.width_chars >= target_width:
            # Don't justify last line or lines that are already full
            return line.runs

        # Calculate extra spaces needed
        extra_spaces = target_width - line.width_chars
        if extra_spaces <= 0:
            return line.runs

        # Count word gaps (spaces between runs)
        word_gaps = len(line.runs) - 1
        if word_gaps <= 0:
            return line.runs

        # Distribute spaces evenly
        spaces_per_gap = extra_spaces // word_gaps
        extra_after_distribution = extra_spaces % word_gaps

        justified_runs: list[Run] = []
        for i, run in enumerate(line.runs):
            justified_runs.append(run)

            # Add extra spaces between words
            if i < len(line.runs) - 1:  # Not last run
                # Add base spacing
                extra = " " * spaces_per_gap

                # Add one more space to first N gaps (N = extra_after_distribution)
                if i < extra_after_distribution:
                    extra += " "

                if extra:
                    # Create spacing run with same formatting as current run
                    spacing_run = Run(text=extra, **self._copy_run_formatting(run))
                    justified_runs.append(spacing_run)

        logger.debug(f"Justified line: added {extra_spaces} spaces across {word_gaps} gaps")
        return justified_runs

    def to_escp_with_wrapping(
        self,
        page_width: float = 8.5,
        page_cpi: int = 10,
        reset_margins: bool = True,
    ) -> bytes:
        """
        Generate ESC/P with automatic word wrapping and justification.

        This is an enhanced version of to_escp() that handles multi-line
        paragraphs with proper word wrapping and full justification support.

        Args:
            page_width: Page width in inches.
            page_cpi: Characters per inch.
            reset_margins: Reset margins after paragraph.

        Returns:
            ESC/P command bytes for wrapped paragraph.

        Example:
            >>> para = Paragraph(alignment=Alignment.JUSTIFY, left_indent=1.0)
            >>> para.add_run(Run(text="This is a long paragraph that will be wrapped..."))
            >>> escp = para.to_escp_with_wrapping()
        """
        # Calculate effective width
        effective_width = self.calculate_width(page_width)
        max_width_chars = int(effective_width * page_cpi)

        # Wrap text
        wrapped_lines = self.wrap_text(max_width_chars)

        if not wrapped_lines:
            # Empty paragraph - use standard to_escp
            return self.to_escp(page_width, page_cpi, reset_margins, use_cache=False)

        commands: list[bytes] = []

        # === HEADER (margins, spacing, tabs) ===

        # 1. Line spacing
        if self.line_spacing == LineSpacing.CUSTOM and self.custom_line_spacing_value:
            commands.append(b"\x1b\x33" + bytes([self.custom_line_spacing_value]))
        else:
            commands.append(self.line_spacing.to_escp())

        # 2. Tab stops
        if self.tab_stops:
            positions = [min(t.position, 255) for t in self.tab_stops]
            commands.append(b"\x1b\x44" + bytes(positions) + b"\x00")

        # 3. Left margin
        left_margin_set = False
        if self.left_indent > 0:
            left_margin_chars = min(int(self.left_indent * page_cpi), MAX_MARGIN_CHARS)
            commands.append(b"\x1b\x6c" + bytes([left_margin_chars]))
            left_margin_set = True

        # 4. Right margin
        right_margin_set = False
        if self.right_indent > 0:
            page_width_chars = int(page_width * page_cpi)
            right_indent_chars = int(self.right_indent * page_cpi)
            right_margin_pos = page_width_chars - right_indent_chars

            left_margin_chars = int(self.left_indent * page_cpi) if self.left_indent > 0 else 0
            if right_margin_pos > left_margin_chars and right_margin_pos <= MAX_MARGIN_CHARS:
                commands.append(b"\x1b\x51" + bytes([right_margin_pos]))
                right_margin_set = True

        # 5. Space before
        if self.space_before > 0:
            lines_before = self._calculate_lines_for_space(self.space_before)
            if lines_before > 0:
                commands.append(b"\n" * lines_before)

        # === BODY (wrapped lines) ===
        for i, line in enumerate(wrapped_lines):
            # Apply justification for non-last lines
            if self.alignment == Alignment.JUSTIFY and not line.is_last:
                line_runs = self._justify_line(line, max_width_chars)
            else:
                line_runs = line.runs

            # First line indent (only on first line)
            if i == 0 and self.first_line_indent > 0:
                first_line_spaces = int(self.first_line_indent * page_cpi)
                commands.append(b" " * first_line_spaces)

            # Output runs
            for run in line_runs:
                commands.append(run.to_escp())

            # Line break
            commands.append(b"\r\n")

        # 6. Space after
        if self.space_after > 0:
            lines_after = self._calculate_lines_for_space(self.space_after)
            if lines_after > 0:
                commands.append(b"\n" * lines_after)

        # 7. Reset margins
        if reset_margins:
            if left_margin_set:
                commands.append(b"\x1b\x6c\x00")
            if right_margin_set:
                commands.append(b"\x1b\x51\x00")

        result = b"".join(commands)
        logger.info(f"Generated wrapped ESC/P: {len(wrapped_lines)} lines, {len(result)} bytes")
        return result

    # =========================================================================
    # METRICS AND CALCULATIONS
    # =========================================================================

    def calculate_metrics(
        self,
        page_width: float = 8.5,
        page_cpi: int = 10,
        reset_margins: bool = True,
    ) -> ParagraphMetrics:
        """
        Calculate physical rendering metrics for the paragraph.

        Computes dimensions, line count, and resource usage for the paragraph
        when rendered with specified page settings. Useful for layout
        calculations, print preview, and performance optimization.

        Args:
            page_width: Page width in inches (default: 8.5" US Letter).
            page_cpi: Characters per inch (default: 10 CPI).
            reset_margins: Include margin reset commands in byte count.

        Returns:
            ParagraphMetrics with comprehensive size information.

        Example:
            >>> para = Paragraph(left_indent=1.0, right_indent=1.5)
            >>> para.add_run(Run(text="Test paragraph"))
            >>> metrics = para.calculate_metrics()
            >>> print(f"Width: {metrics.width_inches:.2f} inches")
            Width: 6.00 inches
        """
        # Calculate effective width (page width minus indents)
        effective_width = self.calculate_width(page_width)

        # Calculate line count
        line_count = 1  # Base line for paragraph content

        # Add lines for space_before
        if self.space_before > 0:
            line_count += self._calculate_lines_for_space(self.space_before)

        # Add lines for space_after
        if self.space_after > 0:
            line_count += self._calculate_lines_for_space(self.space_after)

        # Get lines per inch (LPI) for height calculation
        if self.line_spacing == LineSpacing.ONE_SIXTH_INCH:
            lpi = 6
        elif self.line_spacing == LineSpacing.ONE_EIGHTH_INCH:
            lpi = 8
        elif self.line_spacing == LineSpacing.SEVEN_SEVENTYTWOTH_INCH:
            lpi = 72 // 7  # ~10 LPI
        elif self.line_spacing == LineSpacing.CUSTOM and self.custom_line_spacing_value:
            lpi = 216 // self.custom_line_spacing_value
        else:
            lpi = 6  # Default for CUSTOM without value

        # Calculate height in inches
        height_inches = line_count / lpi

        # Calculate margin positions in characters
        left_margin_chars = int(self.left_indent * page_cpi)
        page_width_chars = int(page_width * page_cpi)
        right_indent_chars = int(self.right_indent * page_cpi)
        right_margin_chars = page_width_chars - right_indent_chars

        # Generate ESC/P to get accurate byte count
        escp = self.to_escp(page_width, page_cpi, reset_margins)

        metrics = ParagraphMetrics(
            width_inches=effective_width,
            height_inches=height_inches,
            line_count=line_count,
            character_count=len(self),
            escp_byte_count=len(escp),
            left_margin_chars=left_margin_chars,
            right_margin_chars=right_margin_chars,
        )

        logger.debug(f"Calculated metrics: {metrics}")
        return metrics

    def calculate_width(self, page_width: float) -> float:
        """
        Calculate effective text width considering indents.

        Args:
            page_width: Total page width in inches.

        Returns:
            Available width for text after subtracting indents.

        Raises:
            ValueError: If page_width is invalid or indents exceed page width.

        Example:
            >>> para = Paragraph(left_indent=1.0, right_indent=1.5)
            >>> para.calculate_width(8.5)
            6.0
        """
        if page_width <= 0:
            raise ValueError(f"page_width must be positive, got {page_width}")

        effective_width = page_width - self.left_indent - self.right_indent

        if effective_width <= 0:
            raise ValueError(
                f"Indents ({self.left_indent:.3f} + {self.right_indent:.3f}) "
                f"exceed page width ({page_width:.3f})"
            )

        return effective_width

    def optimize_runs(self) -> None:
        """
        Optimize runs by merging consecutive runs with identical formatting.

        Modifies the paragraph in-place by replacing runs with merged versions.
        This reduces ESC/P command overhead and improves printing efficiency.

        Example:
            >>> para = Paragraph()
            >>> para.add_run(Run(text="Hello", style=TextStyle.BOLD))
            >>> para.add_run(Run(text=" ", style=TextStyle.BOLD))
            >>> para.add_run(Run(text="World", style=TextStyle.BOLD))
            >>> para.optimize_runs()
            >>> len(para.runs)
            1
        """
        if len(self.runs) <= 1:
            return

        original_count = len(self.runs)
        self.runs = merge_consecutive_runs(self.runs)
        optimized_count = len(self.runs)

        if optimized_count < original_count:
            self.invalidate_escp_cache()
            logger.info(f"Optimized paragraph: {original_count} runs → {optimized_count} runs")

    # =========================================================================
    # SERIALIZATION
    # =========================================================================

    def copy(self) -> "Paragraph":
        """
        Create a deep copy of the paragraph.

        Creates new instances of all runs and copies all formatting attributes.

        Returns:
            A new Paragraph with copied runs and formatting.

        Example:
            >>> para = Paragraph()
            >>> para.add_run(Run(text="Test"))
            >>> para_copy = para.copy()
            >>> para_copy is not para
            True
        """
        return Paragraph(
            runs=[run.copy() for run in self.runs],
            alignment=self.alignment,
            first_line_indent=self.first_line_indent,
            left_indent=self.left_indent,
            right_indent=self.right_indent,
            line_spacing=self.line_spacing,
            custom_line_spacing_value=self.custom_line_spacing_value,
            space_before=self.space_before,
            space_after=self.space_after,
            tab_stops=[TabStop(position=t.position, alignment=t.alignment) for t in self.tab_stops],
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize paragraph to dictionary."""
        # Map LineSpacing enum to short string values for serialization
        spacing_map = {
            LineSpacing.ONE_SIXTH_INCH: "1/6",
            LineSpacing.ONE_EIGHTH_INCH: "1/8",
            LineSpacing.SEVEN_SEVENTYTWOTH_INCH: "7/72",
            LineSpacing.CUSTOM: "custom",
        }
        line_spacing_value = spacing_map.get(self.line_spacing, self.line_spacing.value)

        return {
            "runs": [run.to_dict() for run in self.runs],
            "alignment": self.alignment.value,
            "first_line_indent": self.first_line_indent,
            "left_indent": self.left_indent,
            "right_indent": self.right_indent,
            "line_spacing": line_spacing_value,  # ← ИСПОЛЬЗУЕМ КОРОТКОЕ ЗНАЧЕНИЕ
            "custom_line_spacing_value": self.custom_line_spacing_value,
            "space_before": self.space_before,
            "space_after": self.space_after,
            "tab_stops": [tab.to_dict() for tab in self.tab_stops],
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
            ValueError: If enum values are invalid.

        Example:
            >>> data = {"runs": [], "alignment": "left"}
            >>> para = Paragraph.from_dict(data)
            >>> para.alignment
            <Alignment.LEFT: 'left'>
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

        # Parse line spacing
        line_spacing_str = data.get("line_spacing", "1/6")  # ← DEFAULT КОРОТКИЙ
        try:
            # Map short names to full enum values
            spacing_reverse_map = {
                "1/6": LineSpacing.ONE_SIXTH_INCH,
                "1/8": LineSpacing.ONE_EIGHTH_INCH,
                "7/72": LineSpacing.SEVEN_SEVENTYTWOTH_INCH,
                "custom": LineSpacing.CUSTOM,
            }

            # Try short name first, then try as full enum value
            if line_spacing_str in spacing_reverse_map:
                line_spacing = spacing_reverse_map[line_spacing_str]
            else:
                # Fallback to direct enum lookup (for backward compatibility)
                line_spacing = LineSpacing(line_spacing_str)
        except ValueError as exc:
            raise ValueError(f"Invalid line_spacing value: {line_spacing_str!r}") from exc

        # Parse tab stops
        tab_stops_data = data.get("tab_stops", [])
        tab_stops = [TabStop.from_dict(tab_data) for tab_data in tab_stops_data]

        return Paragraph(
            runs=runs,
            alignment=alignment,
            first_line_indent=data.get("first_line_indent", 0.0),
            left_indent=data.get("left_indent", 0.0),
            right_indent=data.get("right_indent", 0.0),
            line_spacing=line_spacing,
            custom_line_spacing_value=data.get("custom_line_spacing_value"),
            space_before=data.get("space_before", 0.0),
            space_after=data.get("space_after", 0.0),
            tab_stops=tab_stops,
        )

    # =========================================================================
    # MAGIC METHODS
    # =========================================================================

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
            and self.custom_line_spacing_value == other.custom_line_spacing_value
            and self.space_before == other.space_before
            and self.space_after == other.space_after
            and self.tab_stops == other.tab_stops
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


# =============================================================================
# MODULE-LEVEL UTILITY FUNCTIONS
# =============================================================================


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
        custom_line_spacing_value=paragraph.custom_line_spacing_value,
        space_before=paragraph.space_before,
        space_after=paragraph.space_after,
        tab_stops=[
            TabStop(position=t.position, alignment=t.alignment) for t in paragraph.tab_stops
        ],
    )

    # Create second paragraph with runs from split point onward
    second = Paragraph(
        runs=[run.copy() for run in paragraph.runs[run_index:]],
        alignment=paragraph.alignment,
        first_line_indent=paragraph.first_line_indent,
        left_indent=paragraph.left_indent,
        right_indent=paragraph.right_indent,
        line_spacing=paragraph.line_spacing,
        custom_line_spacing_value=paragraph.custom_line_spacing_value,
        space_before=paragraph.space_before,
        space_after=paragraph.space_after,
        tab_stops=[
            TabStop(position=t.position, alignment=t.alignment) for t in paragraph.tab_stops
        ],
    )

    logger.info(
        f"Split paragraph at run {run_index}: "
        f"{len(paragraph.runs)} runs → {len(first.runs)} + {len(second.runs)}"
    )

    return first, second
