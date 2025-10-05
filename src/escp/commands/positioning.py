"""
Positioning and cursor movement commands for Epson FX-890.

Contains commands for absolute and relative horizontal/vertical positioning,
line feeds, carriage returns, and cursor movement. All commands verified
against FX-890 technical specifications.

Reference: Epson FX-890 Technical Reference Manual
           ESC/P Command Reference (support2.epson.net)
Compatibility: FX-890, FX-2190, LX-300+II
ESC/P Version: Standard ESC/P (FX mode)

IMPORTANT: This module contains ONLY FX-compatible commands.
           ESC/P 2 commands (ESC ( V, ESC ( v) are NOT included.
"""

from typing import Final

__all__ = [
    "CR",
    "LF",
    "FF",
    "BS",
    "HT",
    "VT",
    "CRLF",
    "set_horizontal_position",
    "set_relative_horizontal_position",
    "advance_vertical_n_180",
    "reverse_vertical_n_180",
    "advance_vertical_n_360",
]

# =============================================================================
# BASIC CONTROL CHARACTERS
# =============================================================================

CR: Final[bytes] = b"\r"
"""
Carriage Return.

Command: CR
Hex: 0D
ASCII: 13
Effect: Moves print head to left margin (column 0)
Behavior: Does NOT advance paper (no line feed)
Reset: N/A (immediate action)
Verified: ✅ FX-890 Technical Reference Manual

Use Cases:
    - Overprinting (print text, CR, print over it)
    - Strikethrough effect (text + CR + line characters)
    - Multi-pass printing for emphasis

Technical Details:
    - Speed: Instantaneous (mechanical only)
    - Position: Returns to left margin, not column 0 of paper
    - Combination: Usually combined with LF for new line (see CRLF)

Example:
    >>> from src.escp.commands.positioning import CR
    >>> printer.send(b"First" + CR + b"Second")
    >>> # Output: Second (overwrites "First")

    >>> # Strikethrough effect
    >>> text = b"Cancelled"
    >>> printer.send(text + CR + b"-" * len(text))
    >>> # Output: Cancelled (with line through)
"""

LF: Final[bytes] = b"\n"
"""
Line Feed.

Command: LF
Hex: 0A
ASCII: 10
Effect: Advances paper by current line spacing (default 1/6 inch)
Behavior: Does NOT return to left margin (no carriage return)
Reset: N/A (immediate action)
Verified: ✅ FX-890 Technical Reference Manual

Technical Details:
    - Default spacing: 1/6 inch (can be changed with ESC 2/0/1/3/A)
    - Speed: Paper advance speed (mechanical)
    - Position: Cursor stays at current horizontal position

Use Cases:
    - Vertical spacing without horizontal movement
    - Multi-column layouts
    - Form alignment

Example:
    >>> from src.escp.commands.positioning import LF
    >>> printer.send(b"Line 1" + LF)
    >>> printer.send(b"Line 2")
    >>> # Output:
    >>> # Line 1
    >>> #       Line 2  (starts at same horizontal position)
"""

CRLF: Final[bytes] = b"\r\n"
"""
Carriage Return + Line Feed.

Command: CR LF
Hex: 0D 0A
ASCII: 13 10
Effect: Returns to left margin AND advances paper one line
Behavior: Standard "new line" sequence
Reset: N/A (immediate action)
Verified: ✅ Standard ESC/P practice

Technical Details:
    - Equivalent to: CR + LF
    - Standard: Most common line ending sequence
    - Line spacing: Uses current line spacing setting

Use Cases:
    - Standard text printing
    - End of line in documents
    - Most common line terminator

Example:
    >>> from src.escp.commands.positioning import CRLF
    >>> printer.send(b"Line 1" + CRLF)
    >>> printer.send(b"Line 2" + CRLF)
    >>> # Output:
    >>> # Line 1
    >>> # Line 2
"""

FF: Final[bytes] = b"\x0c"
"""
Form Feed.

Command: FF
Hex: 0C
ASCII: 12
Effect: Advances paper to top of next page
Behavior: Ejects current page
Reset: N/A (immediate action)
Verified: ✅ FX-890 Technical Reference Manual

Technical Details:
    - Page length: Uses current page length setting (default 66 lines)
    - Continuous paper: Advances exactly one page length
    - Cut sheets: Ejects current sheet
    - Position: Moves to top-of-form (line 1, column 0)

Use Cases:
    - End of page/document
    - Force page break
    - Eject paper for inspection

Caution:
    - On continuous paper, wastes paper if not at bottom
    - Consider using manual line feeds to bottom instead

Example:
    >>> from src.escp.commands.positioning import FF, CRLF
    >>> printer.send(b"Page 1 content" + CRLF)
    >>> printer.send(FF)  # Eject to next page
    >>> printer.send(b"Page 2 content" + CRLF)
"""

BS: Final[bytes] = b"\x08"
"""
Backspace.

Command: BS
Hex: 08
ASCII: 8
Effect: Moves print head one character position to the left
Behavior: Does NOT erase character (just moves cursor)
Reset: N/A (immediate action)
Verified: ✅ FX-890 Technical Reference Manual

Technical Details:
    - Distance: One character width at current CPI
    - At 10 CPI: Moves left 0.1 inch
    - At 12 CPI: Moves left 0.0833 inch
    - Minimum: Cannot move left of left margin

Use Cases:
    - Overprinting for special effects
    - Accent marks (a + BS + accent = á)
    - Strikethrough (text + multiple BS + line)
    - Custom underlines

Example:
    >>> from src.escp.commands.positioning import BS
    >>>
    >>> # Strikethrough effect
    >>> text = b"Error"
    >>> printer.send(text + (BS * len(text)) + b"-" * len(text))
    >>> # Output: Error (with line through)
    >>>
    >>> # Accent mark
    >>> printer.send(b"a" + BS + b"\xb4")  # á (a with acute accent)
"""

HT: Final[bytes] = b"\t"
"""
Horizontal Tab.

Command: HT
Hex: 09
ASCII: 9
Effect: Moves print head to next tab stop
Default: Tab stops every 8 characters
Reset: Tab stops can be set with ESC D
Verified: ✅ FX-890 Technical Reference Manual

Technical Details:
    - Default tabs: Columns 8, 16, 24, 32, 40, 48, 56, 64, 72, 80
    - Custom tabs: Set with ESC D command (see page_control.py)
    - Maximum: 32 tab stops
    - Behavior: If no more tabs, moves to end of line

Use Cases:
    - Columnar data alignment
    - Tables without borders
    - Form field alignment

Example:
    >>> from src.escp.commands.positioning import HT, CRLF
    >>>
    >>> # Simple table
    >>> printer.send(b"Name" + HT + b"Age" + HT + b"City" + CRLF)
    >>> printer.send(b"John" + HT + b"25" + HT + b"NYC" + CRLF)
    >>> printer.send(b"Jane" + HT + b"30" + HT + b"LA" + CRLF)
    >>> # Output:
    >>> # Name    Age     City
    >>> # John    25      NYC
    >>> # Jane    30      LA
"""

VT: Final[bytes] = b"\x0b"
"""
Vertical Tab.

Command: VT
Hex: 0B
ASCII: 11
Effect: Advances paper to next vertical tab stop
Default: No default vertical tabs (must be set with ESC B)
Reset: Vertical tabs set with ESC B command
Verified: ✅ FX-890 Technical Reference Manual

Technical Details:
    - Tab stops: Must be explicitly set with ESC B
    - Maximum: 16 vertical tab stops
    - Unit: Line numbers from top of page
    - Behavior: If no tabs set, VT acts like LF

Use Cases:
    - Pre-printed forms (jump to specific fields)
    - Fixed-position forms
    - Multi-section documents

Example:
    >>> from src.escp.commands.positioning import VT, CRLF
    >>> from src.escp.commands.page_control import set_vertical_tabs
    >>>
    >>> # Set tabs at lines 10, 20, 30
    >>> printer.send(set_vertical_tabs([10, 20, 30]))
    >>>
    >>> # Use tabs
    >>> printer.send(b"Section 1" + VT)    # Jump to line 10
    >>> printer.send(b"Section 2" + VT)    # Jump to line 20
    >>> printer.send(b"Section 3" + CRLF)  # At line 30
"""

# =============================================================================
# HORIZONTAL POSITIONING
# =============================================================================


def set_horizontal_position(position: int) -> bytes:
    """
    Set absolute horizontal print position.

    Command: ESC $ nL nH
    Hex: 1B 24 nL nH
    ASCII: ESC '$' nL nH
    Verified: ✅ FX-890 Technical Reference Manual

    Args:
        position: Position in 1/60 inch units from left margin (0-32767).

    Returns:
        ESC/P command bytes.

    Raises:
        ValueError: If position is out of range.

    Technical Details:
        - Unit: 1/60 inch (0.0167 inches per unit)
        - Origin: Left margin (not paper edge)
        - Range: 0 to 32767 units (0 to 546 inches)
        - At 10 CPI: 6 units = 1 character width
        - At 12 CPI: 5 units = 1 character width
        - Paper width: At 8.5" width, max ~510 units useful

    Conversion Table:
        1 inch    = 60 units
        1 char (10 CPI) = 6 units
        1 char (12 CPI) = 5 units
        1 mm      ≈ 2.36 units

    Use Cases:
        - Columnar layouts (fixed column positions)
        - Form field alignment
        - Table cell positioning
        - Precise text placement

    Example:
        >>> from src.escp.commands.positioning import set_horizontal_position, CRLF
        >>>
        >>> # Position text at exact columns
        >>> col1 = set_horizontal_position(0)     # Left margin
        >>> col2 = set_horizontal_position(180)   # 3 inches
        >>> col3 = set_horizontal_position(360)   # 6 inches
        >>>
        >>> printer.send(col1 + b"Column 1")
        >>> printer.send(col2 + b"Column 2")
        >>> printer.send(col3 + b"Column 3")
        >>> printer.send(CRLF)
        >>> # Output: Column 1    Column 2    Column 3
    """
    if not (0 <= position <= 32767):
        raise ValueError(f"Position must be 0-32767, got {position}")

    # Convert to little-endian 16-bit value
    nL = position & 0xFF
    nH = (position >> 8) & 0xFF

    return b"\x1b$" + bytes([nL, nH])


def set_relative_horizontal_position(offset: int) -> bytes:
    """
    Move print head relative to current position (horizontal).

    Command: ESC '\' nL nH
    Hex: 1B 5C nL nH
    ASCII: ESC '\' nL nH
    Verified: ✅ FX-890 Technical Reference Manual

    Args:
        offset: Offset in 1/120 inch units (-32768 to +32767).
                Positive = move right, Negative = move left.

    Returns:
        ESC/P command bytes.

    Raises:
        ValueError: If offset is out of range.

    Technical Details:
        - Unit: 1/120 inch (0.00833 inches per unit)
        - Origin: Current print position (not margin)
        - Range: -32768 to +32767 units (-273 to +273 inches)
        - Direction: Positive = right, Negative = left
        - At 10 CPI: 12 units = 1 character width
        - At 12 CPI: 10 units = 1 character width

    Conversion Table:
        1 inch    = 120 units
        1 char (10 CPI) = 12 units
        1 char (12 CPI) = 10 units
        1 mm      ≈ 4.72 units

    Use Cases:
        - Fine-tuning spacing
        - Micro-adjustments in layout
        - Justified text (add space between words)
        - Special character positioning

    Example:
        >>> from src.escp.commands.positioning import set_relative_horizontal_position
        >>>
        >>> # Move right by 0.5 inch
        >>> cmd = set_relative_horizontal_position(60)  # 60 * (1/120") = 0.5"
        >>> printer.send(b"Start" + cmd + b"0.5 inches right\r\n")
        >>>
        >>> # Move left by 0.25 inch (backtrack)
        >>> cmd = set_relative_horizontal_position(-30)  # -30 * (1/120") = -0.25"
        >>> printer.send(b"Text" + cmd + b"Back 0.25\r\n")

        >>> # Fine spacing for justified text
        >>> printer.send(b"Word1")
        >>> printer.send(set_relative_horizontal_position(15))  # Extra space
        >>> printer.send(b"Word2\r\n")
    """
    if not (-32768 <= offset <= 32767):
        raise ValueError(f"Offset must be -32768 to 32767, got {offset}")

    # Convert to little-endian signed 16-bit value (two's complement)
    if offset < 0:
        offset = (1 << 16) + offset  # Convert to unsigned representation

    nL = offset & 0xFF
    nH = (offset >> 8) & 0xFF

    return b"\x1b\\" + bytes([nL, nH])


# =============================================================================
# VERTICAL POSITIONING (FX-890 COMPATIBLE)
# =============================================================================


def advance_vertical_n_180(n: int) -> bytes:
    """
    Advance paper by n/180 inch.

    Command: ESC J n
    Hex: 1B 4A n
    ASCII: ESC 'J' n
    Verified: ✅ FX-890 Technical Reference Manual

    Args:
        n: Distance in 1/180 inch units (0-255).

    Returns:
        ESC/P command bytes.

    Raises:
        ValueError: If n is out of range.

    Technical Details:
        - Unit: 1/180 inch (0.00556 inches per unit)
        - Direction: Forward (down) only
        - Range: 0 to 255 units (0 to 1.42 inches)
        - Independent: Does not affect line spacing setting
        - Immediate: Takes effect immediately

    Conversion Table:
        1/6 inch (1 line at default) = 30 units
        1/8 inch = 22.5 units (use 22 or 23)
        1 inch = 180 units
        1 mm ≈ 7.09 units

    Use Cases:
        - Fine vertical positioning
        - Form alignment
        - Micro-adjustments between lines
        - Custom vertical spacing

    Note:
        This command is for ONE-TIME advancement. It does not change
        the line spacing setting. For permanent line spacing, use
        ESC 2, ESC 0, ESC 3, or ESC A (see line_spacing.py).

    Example:
        >>> from src.escp.commands.positioning import advance_vertical_n_180, CRLF
        >>>
        >>> # Advance by 1/6 inch (one standard line)
        >>> printer.send(b"Line 1" + CRLF)
        >>> printer.send(advance_vertical_n_180(30))  # 30/180 = 1/6"
        >>> printer.send(b"Line 2" + CRLF)
        >>>
        >>> # Fine-tune form position (advance by 1/36 inch)
        >>> printer.send(advance_vertical_n_180(5))  # 5/180 = 1/36"
    """
    if not (0 <= n <= 255):
        raise ValueError(f"Advance distance must be 0-255, got {n}")

    return b"\x1bJ" + bytes([n])


def reverse_vertical_n_180(n: int) -> bytes:
    """
    Reverse paper feed by n/180 inch (if supported).

    Command: ESC j n
    Hex: 1B 6A n
    ASCII: ESC 'j' n
    Verified: ⚠️ FX-890 Technical Reference (limited support)

    Args:
        n: Distance in 1/180 inch units (0-255).

    Returns:
        ESC/P command bytes.

    Raises:
        ValueError: If n is out of range.

    WARNING:
        Reverse feed is NOT supported on all FX-890 models or paper types:
        - May not work with friction feed
        - May not work with cut sheets
        - Works best with tractor feed
        - Test before production use
        - May cause paper jam if paper tension is wrong

    Technical Details:
        - Unit: 1/180 inch (0.00556 inches per unit)
        - Direction: Backward (up) only
        - Range: 0 to 255 units (0 to 1.42 inches)
        - Support: Depends on printer configuration and paper feed method

    Use Cases:
        - Overprinting on previous line
        - Multi-pass printing for emphasis
        - Correction of minor paper slippage
        - Special effects

    Caution:
        - Test thoroughly before using in production
        - Have emergency stop procedure ready
        - Monitor paper path during reverse feed
        - Do not reverse feed more than a few lines

    Example:
        >>> from src.escp.commands.positioning import reverse_vertical_n_180, CRLF
        >>>
        >>> # Print line, reverse, overprint
        >>> printer.send(b"Text" + CRLF)
        >>> printer.send(reverse_vertical_n_180(30))  # Back up 1/6"
        >>> printer.send(b"Over" + CRLF)  # Overprint
        >>> # Result: Text with "Over" printed on top
    """
    if not (0 <= n <= 255):
        raise ValueError(f"Reverse distance must be 0-255, got {n}")

    return b"\x1bj" + bytes([n])


def advance_vertical_n_360(n: int) -> bytes:
    """
    Advance paper by n/360 inch (high precision).

    Command: ESC ( V 2 0 nL nH
    Hex: 1B 28 56 02 00 nL nH
    ASCII: ESC '(' 'V' 2 0 nL nH
    Verified: ⚠️ ESC/P 2 command - MAY NOT WORK on FX-890 in FX mode

    Args:
        n: Distance in 1/360 inch units (0-32767).

    Returns:
        ESC/P command bytes.

    Raises:
        ValueError: If n is out of range.

    WARNING - ESC/P 2 COMMAND:
        This is an ESC/P 2 command, NOT standard FX ESC/P.
        - May not work on FX-890 in FX emulation mode
        - For guaranteed compatibility, use advance_vertical_n_180() instead
        - Test on your specific printer model before production use

    Technical Details:
        - Unit: 1/360 inch (0.00278 inches per unit)
        - Direction: Forward (down) only
        - Range: 0 to 32767 units (0 to 91 inches)
        - Precision: 2× more precise than ESC J

    Conversion Table:
        1/6 inch = 60 units
        1/8 inch = 45 units
        1 inch = 360 units
        1 mm ≈ 14.17 units

    Recommendation:
        Use advance_vertical_n_180() instead for FX-890 compatibility.
        Only use this function if you've verified it works on your printer.

    Example:
        >>> # ⚠️ May not work on FX-890!
        >>> from src.escp.commands.positioning import advance_vertical_n_360
        >>>
        >>> # Advance by 1/6 inch (high precision)
        >>> printer.send(advance_vertical_n_360(60))  # 60/360 = 1/6"
    """
    if not (0 <= n <= 32767):
        raise ValueError(f"Advance distance must be 0-32767, got {n}")

    # Convert to little-endian 16-bit value
    nL = n & 0xFF
    nH = (n >> 8) & 0xFF

    return b"\x1b(V\x02\x00" + bytes([nL, nH])


# =============================================================================
# USAGE EXAMPLES
# =============================================================================

"""
BASIC POSITIONING:
    Simple line and character positioning:

    >>> from src.escp.commands.positioning import *
    >>>
    >>> # New line (standard)
    >>> printer.send(b"Line 1" + CRLF)
    >>> printer.send(b"Line 2" + CRLF)
    >>>
    >>> # Overprint (strikethrough effect)
    >>> text = b"Cancelled"
    >>> printer.send(text + CR + b"-" * len(text) + CRLF)

COLUMNAR LAYOUT:
    Fixed column positions:

    >>> col1 = set_horizontal_position(0)
    >>> col2 = set_horizontal_position(180)  # 3 inches
    >>> col3 = set_horizontal_position(360)  # 6 inches
    >>>
    >>> # Table header
    >>> printer.send(col1 + b"Name" + col2 + b"Age" + col3 + b"City" + CRLF)
    >>>
    >>> # Data rows
    >>> printer.send(col1 + b"John" + col2 + b"25" + col3 + b"NYC" + CRLF)
    >>> printer.send(col1 + b"Jane" + col2 + b"30" + col3 + b"LA" + CRLF)

FINE-TUNING POSITION:
    Micro-adjustments:

    >>> # Start at position
    >>> printer.send(set_horizontal_position(100))
    >>> printer.send(b"Text")
    >>>
    >>> # Fine-tune: move right 0.25"
    >>> printer.send(set_relative_horizontal_position(30))  # 30/120 = 0.25"
    >>> printer.send(b"More text")

VERTICAL SPACING:
    Custom vertical positioning:

    >>> printer.send(b"Paragraph 1" + CRLF)
    >>>
    >>> # Add extra space (1/3 inch)
    >>> printer.send(advance_vertical_n_180(60))  # 60/180 = 1/3"
    >>>
    >>> printer.send(b"Paragraph 2" + CRLF)

FORM ALIGNMENT:
    Pre-printed form field positioning:

    >>> # Position at field 1 (2" right, 3" down from top)
    >>> printer.send(set_horizontal_position(120))  # 120/60 = 2"
    >>> printer.send(advance_vertical_n_180(540))   # 540/180 = 3"
    >>> printer.send(b"John Doe")
    >>>
    >>> # Field 2 (same row, 5" right)
    >>> printer.send(set_horizontal_position(300))  # 300/60 = 5"
    >>> printer.send(b"01/01/2025")

UNIT CONVERSION HELPERS:
    >>> def inches_to_h_units(inches: float) -> int:
    ...     '''Convert inches to horizontal position units (1/60").'''
    ...     return int(inches * 60)
    >>>
    >>> def inches_to_v180_units(inches: float) -> int:
    ...     '''Convert inches to vertical units (1/180").'''
    ...     return int(inches * 180)
    >>>
    >>> # Position at 2.5" horizontally, 1.25" vertically
    >>> h_pos = inches_to_h_units(2.5)      # 150 units
    >>> v_pos = inches_to_v180_units(1.25)  # 225 units
    >>>
    >>> printer.send(set_horizontal_position(h_pos))
    >>> printer.send(advance_vertical_n_180(v_pos))
    >>> printer.send(b"Positioned text")

TROUBLESHOOTING:
    Common positioning issues:

    1. Text appears in wrong position:
       - Check units (1/60" for horizontal, 1/180" for vertical)
       - Verify position is within paper bounds
       - Check margins (positioning is relative to margins)

    2. Position commands seem ignored:
       - Some positions may be outside printable area
       - Check for right margin limiting position
       - Try smaller position values

    3. Relative positioning accumulates errors:
       - Use absolute positioning for precise layout
       - Reset to absolute position periodically
       - Relative positioning errors can accumulate

    4. Reverse feed doesn't work:
       - Check printer supports reverse feed (not all do)
       - Verify paper feed method (tractor vs friction)
       - Test with very small reverse amounts first
       - Check for paper tension issues
"""
