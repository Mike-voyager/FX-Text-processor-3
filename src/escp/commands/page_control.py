"""
Page layout and control commands for Epson FX-890.

Contains commands for margins, page length, tabs, and form control.
All commands verified for FX-890.

Reference: Epson FX-890 Technical Reference Manual, Chapter 6
"""

from typing import Final

__all__ = [
    "set_left_margin",
    "set_right_margin",
    "set_page_length",
    "set_horizontal_tabs",
    "set_vertical_tabs",
    "cancel_horizontal_tabs",
    "cancel_vertical_tabs",
]

# =============================================================================
# MARGIN CONTROL
# =============================================================================


def set_left_margin(columns: int) -> bytes:
    """
    Set left margin position.

    Command: ESC l n
    Hex: 1B 6C n

    Args:
        columns: Left margin position in characters (0-255).
                 0 = leftmost position (no margin).

    Returns:
        ESC/P command bytes.

    Raises:
        ValueError: If columns is out of range.

    Note:
        Margin is measured from left edge of paper.
        At 10 CPI: 1 column = 0.1 inches.
        At 8.5" paper width: max useful margin ~75 columns.

    Example:
        >>> # Set 1 inch left margin (10 columns at 10 CPI)
        >>> cmd = set_left_margin(10)
        >>> printer.send(cmd)
        >>> printer.send(b"Text with 1 inch left margin\r\n")
    """
    if not (0 <= columns <= 255):
        raise ValueError(f"Left margin must be 0-255, got {columns}")

    return b"\x1bl" + bytes([columns])


def set_right_margin(columns: int) -> bytes:
    """
    Set right margin position.

    Command: ESC Q n
    Hex: 1B 51 n

    Args:
        columns: Right margin position in characters (0-255).
                 0 = no right margin (full width).

    Returns:
        ESC/P command bytes.

    Raises:
        ValueError: If columns is out of range.

    Note:
        Margin is measured from left edge of paper.
        Right margin must be greater than left margin.
        At 10 CPI on 8.5" paper: typical right margin = 80-85 columns.

    Example:
        >>> # Set right margin at 80 columns (8 inches at 10 CPI)
        >>> cmd = set_right_margin(80)
        >>> printer.send(cmd)
        >>> printer.send(b"Text will wrap at 80 columns\r\n")
    """
    if not (0 <= columns <= 255):
        raise ValueError(f"Right margin must be 0-255, got {columns}")

    return b"\x1bQ" + bytes([columns])


# =============================================================================
# PAGE LENGTH
# =============================================================================


def set_page_length(lines: int = 66, units: str = "lines") -> bytes:
    """
    Set page length.

    Command: ESC C n  (in lines)
             ESC C NUL n  (in inches)
    Hex: 1B 43 n  OR  1B 43 00 n

    Args:
        lines: Page length value.
               If units="lines": Number of lines (1-127).
               If units="inches": Number of inches (1-22).
        units: Unit type - "lines" or "inches".

    Returns:
        ESC/P command bytes.

    Raises:
        ValueError: If parameters are invalid.

    Note:
        Standard page lengths:
        - US Letter (11"): 66 lines at 1/6" spacing
        - A4 (11.7"): 70 lines at 1/6" spacing
        - Continuous forms: Set to match form length

    Example:
        >>> # Set 11 inch page length (US Letter)
        >>> cmd = set_page_length(66, units="lines")
        >>> printer.send(cmd)

        >>> # Set 11 inch page (direct inches)
        >>> cmd = set_page_length(11, units="inches")
        >>> printer.send(cmd)
    """
    if units == "lines":
        if not (1 <= lines <= 127):
            raise ValueError(f"Page length must be 1-127 lines, got {lines}")
        return b"\x1bC" + bytes([lines])

    elif units == "inches":
        if not (1 <= lines <= 22):
            raise ValueError(f"Page length must be 1-22 inches, got {lines}")
        return b"\x1bC\x00" + bytes([lines])

    else:
        raise ValueError(f"Invalid units: {units!r}, must be 'lines' or 'inches'")


# =============================================================================
# TAB STOPS
# =============================================================================


def set_horizontal_tabs(positions: list[int]) -> bytes:
    """
    Set horizontal tab stop positions.

    Command: ESC D n1 n2 ... nk NUL
    Hex: 1B 44 n1 n2 ... nk 00

    Args:
        positions: List of tab stop positions in columns (1-255).
                   Must be in ascending order.
                   Maximum 32 tab stops.

    Returns:
        ESC/P command bytes.

    Raises:
        ValueError: If positions are invalid or out of order.

    Note:
        Positions are absolute column numbers from left margin.
        Default tabs (before setting custom): Every 8 columns.
        HT character (0x09) moves to next tab stop.

    Example:
        >>> # Set tabs at columns 10, 20, 30, 40
        >>> cmd = set_horizontal_tabs([10, 20, 30, 40])
        >>> printer.send(cmd)
        >>>
        >>> # Use tabs for columnar data
        >>> printer.send(b"Name\tAge\tCity\r\n")
        >>> printer.send(b"John\t25\tNYC\r\n")
    """
    if not positions:
        raise ValueError("At least one tab position required")

    if len(positions) > 32:
        raise ValueError(f"Maximum 32 tab stops, got {len(positions)}")

    # Validate ascending order
    for i in range(len(positions) - 1):
        if positions[i] >= positions[i + 1]:
            raise ValueError(f"Tab positions must be ascending, got {positions}")

    # Validate range
    for pos in positions:
        if not (1 <= pos <= 255):
            raise ValueError(f"Tab position must be 1-255, got {pos}")

    # Build command: ESC D n1 n2 ... nk NUL
    cmd = b"\x1bD" + bytes(positions) + b"\x00"
    return cmd


def set_vertical_tabs(positions: list[int]) -> bytes:
    """
    Set vertical tab stop positions.

    Command: ESC B n1 n2 ... nk NUL
    Hex: 1B 42 n1 n2 ... nk 00

    Args:
        positions: List of tab stop positions in lines (1-255).
                   Must be in ascending order.
                   Maximum 16 vertical tab stops.

    Returns:
        ESC/P command bytes.

    Raises:
        ValueError: If positions are invalid or out of order.

    Note:
        Positions are absolute line numbers from top of page.
        VT character (0x0B) advances to next vertical tab.
        Commonly used for forms with fixed field positions.

    Example:
        >>> # Set vertical tabs at lines 10, 20, 30 (for forms)
        >>> cmd = set_vertical_tabs([10, 20, 30])
        >>> printer.send(cmd)
        >>>
        >>> # Jump to line 10
        >>> printer.send(b"Section 1\x0b")  # VT = 0x0B
        >>> printer.send(b"Section 2\x0b")  # Jump to line 20
    """
    if not positions:
        raise ValueError("At least one vertical tab position required")

    if len(positions) > 16:
        raise ValueError(f"Maximum 16 vertical tabs, got {len(positions)}")

    # Validate ascending order
    for i in range(len(positions) - 1):
        if positions[i] >= positions[i + 1]:
            raise ValueError(f"Vertical tab positions must be ascending, got {positions}")

    # Validate range
    for pos in positions:
        if not (1 <= pos <= 255):
            raise ValueError(f"Vertical tab position must be 1-255, got {pos}")

    # Build command: ESC B n1 n2 ... nk NUL
    cmd = b"\x1bB" + bytes(positions) + b"\x00"
    return cmd


def cancel_horizontal_tabs() -> bytes:
    """
    Cancel all horizontal tab stops.

    Command: ESC D NUL
    Hex: 1B 44 00

    Returns:
        ESC/P command bytes.

    Note:
        After cancellation, HT (tab) character has no effect.
        Resets to default tabs (every 8 columns) after printer reset.

    Example:
        >>> # Remove all horizontal tabs
        >>> printer.send(cancel_horizontal_tabs())
        >>> printer.send(b"Tab\tCharacter\tIgnored\r\n")  # No tab action
    """
    return b"\x1bD\x00"


def cancel_vertical_tabs() -> bytes:
    """
    Cancel all vertical tab stops.

    Command: ESC B NUL
    Hex: 1B 42 00

    Returns:
        ESC/P command bytes.

    Note:
        After cancellation, VT character has no effect.
        Vertical tabs are empty by default (must be set explicitly).

    Example:
        >>> # Remove all vertical tabs
        >>> printer.send(cancel_vertical_tabs())
    """
    return b"\x1bB\x00"


# =============================================================================
# USAGE EXAMPLES
# =============================================================================

"""
STANDARD DOCUMENT MARGINS:
    Typical 1 inch margins on 8.5" paper:

    >>> # Left margin: 1" = 10 columns at 10 CPI
    >>> printer.send(set_left_margin(10))
    >>>
    >>> # Right margin: 7.5" = 75 columns at 10 CPI (leaving 1" on right)
    >>> printer.send(set_right_margin(75))

PAGE LENGTH SETUP:
    US Letter (11 inches):
    >>> printer.send(set_page_length(66, units="lines"))  # 66 lines at 1/6" spacing
    >>> # OR
    >>> printer.send(set_page_length(11, units="inches"))

    A4 Paper (11.7 inches):
    >>> printer.send(set_page_length(70, units="lines"))
    >>> # OR
    >>> printer.send(set_page_length(12, units="inches"))

COLUMNAR LAYOUT WITH TABS:
    Create aligned columns:

    >>> # Set tabs for 4-column layout
    >>> printer.send(set_horizontal_tabs([0, 20, 40, 60]))
    >>>
    >>> # Print table
    >>> printer.send(b"Name\tAge\tCity\tCountry\r\n")
    >>> printer.send(b"-" * 80 + b"\r\n")
    >>> printer.send(b"John\t25\tNYC\tUSA\r\n")
    >>> printer.send(b"Jane\t30\tLA\tUSA\r\n")

FORM PRINTING WITH VERTICAL TABS:
    Pre-printed forms with fixed fields:

    >>> # Form layout: Name at line 5, Address at line 10, Signature at line 30
    >>> printer.send(set_vertical_tabs([5, 10, 30]))
    >>>
    >>> # Fill form
    >>> printer.send(b"Name: John Doe\x0b")     # Jump to line 10
    >>> printer.send(b"Address: 123 Main St\x0b")  # Jump to line 30
    >>> printer.send(b"Signature: __________\x0c")  # Form feed to next page

INVOICE LAYOUT:
    Professional invoice with margins and tabs:

    >>> # Setup
    >>> printer.send(set_left_margin(5))
    >>> printer.send(set_right_margin(75))
    >>> printer.send(set_horizontal_tabs([0, 30, 50, 65]))
    >>>
    >>> # Header
    >>> printer.send(b"INVOICE #12345\r\n\r\n")
    >>>
    >>> # Items
    >>> printer.send(b"Item\tQuantity\tPrice\tTotal\r\n")
    >>> printer.send(b"-" * 70 + b"\r\n")
    >>> printer.send(b"Widget A\t5\t$10.00\t$50.00\r\n")
    >>> printer.send(b"Widget B\t2\t$25.00\t$50.00\r\n")

CONTINUOUS FORM ALIGNMENT:
    Match page length to form size:

    >>> # 5 inch continuous form
    >>> printer.send(set_page_length(5, units="inches"))
    >>>
    >>> # Print form
    >>> for i in range(10):
    ...     printer.send(f"Form #{i+1}\r\n".encode())
    ...     printer.send(b"\x0c")  # Form feed to next form

RESET TO DEFAULTS:
    >>> # Clear all custom settings
    >>> from src.escp.commands.hardware import ESC_INIT_PRINTER
    >>> printer.send(ESC_INIT_PRINTER)
    >>>
    >>> # Defaults after reset:
    >>> # - Left margin: 0
    >>> # - Right margin: 80 (at 10 CPI)
    >>> # - Page length: 66 lines
    >>> # - Horizontal tabs: Every 8 columns
    >>> # - Vertical tabs: None

MARGIN CALCULATION:
    At different CPI values:

    10 CPI (pica):
        1 inch margin = 10 columns
        8.5" paper = 85 columns total
        1" margins both sides = 10 left, 75 right

    12 CPI (elite):
        1 inch margin = 12 columns
        8.5" paper = 102 columns total
        1" margins both sides = 12 left, 90 right

    15 CPI (condensed):
        1 inch margin = 15 columns
        8.5" paper = 127 columns total
        1" margins both sides = 15 left, 112 right

TAB SPACING PATTERNS:
    >>> # Every 10 columns (1 inch at 10 CPI)
    >>> tabs = list(range(10, 81, 10))  # [10, 20, 30, ..., 80]
    >>> printer.send(set_horizontal_tabs(tabs))
    >>>
    >>> # Custom spacing
    >>> tabs = [5, 15, 35, 60, 75]
    >>> printer.send(set_horizontal_tabs(tabs))

TROUBLESHOOTING:
    If margins don't work:
    1. Check values are within printer's paper width
    2. Verify right margin > left margin
    3. Reset printer if settings seem stuck
    4. Check DIP switch settings (may override software margins)

    If tabs don't work:
    1. Verify tab positions are in ascending order
    2. Check tab positions are within margins
    3. Ensure using HT character (0x09) not spaces
    4. Reset tabs with cancel_horizontal_tabs() first

    If page length is wrong:
    1. Check units (lines vs inches)
    2. Verify matches physical form size
    3. Check line spacing setting (affects lines per page)
    4. Test with single form feed (0x0C) to verify
"""
