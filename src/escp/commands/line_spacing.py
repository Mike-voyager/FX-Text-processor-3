"""
Line spacing commands for Epson FX-890.

Contains commands for controlling vertical line spacing (line feed distance).
All commands verified for FX-890.

Reference: Epson FX-890 Technical Reference Manual, Chapter 6
"""

from typing import Final

__all__ = [
    "ESC_LINE_SPACING_1_6",
    "ESC_LINE_SPACING_1_8",
    "ESC_LINE_SPACING_7_72",
    "set_line_spacing_n_216",
    "set_line_spacing_n_72",
]

# =============================================================================
# STANDARD LINE SPACING
# =============================================================================

ESC_LINE_SPACING_1_6: Final[bytes] = b"\x1b2"
"""
Set line spacing to 1/6 inch.

Command: ESC 2
Hex: 1B 32
Effect: Standard line spacing (6 lines per inch)
Common Use: Default setting for most text documents
Lines Per Page: 66 lines on 11" paper
Reset: Default state after printer reset

Example:
    >>> printer.send(ESC_LINE_SPACING_1_6)
    >>> printer.send(b"Line 1\r\n")
    >>> printer.send(b"Line 2\r\n")  # 1/6" spacing between lines
"""

ESC_LINE_SPACING_1_8: Final[bytes] = b"\x1b0"
"""
Set line spacing to 1/8 inch.

Command: ESC 0
Hex: 1B 30
Effect: Tighter line spacing (8 lines per inch)
Common Use: Compact documents, more lines per page
Lines Per Page: 88 lines on 11" paper
Reset: Changed by other line spacing commands or printer reset

Example:
    >>> printer.send(ESC_LINE_SPACING_1_8)
    >>> printer.send(b"Tight line 1\r\n")
    >>> printer.send(b"Tight line 2\r\n")  # 1/8" spacing
"""

ESC_LINE_SPACING_7_72: Final[bytes] = b"\x1b1"
"""
Set line spacing to 7/72 inch.

Command: ESC 1
Hex: 1B 31
Effect: Very specific spacing (approximately 10.29 lines per inch)
Common Use: Specialized forms, precise alignment
Origin: Compatible with older Epson printers
Reset: Changed by other line spacing commands or printer reset

Note: 7/72 inch = 0.0972 inches per line

Example:
    >>> printer.send(ESC_LINE_SPACING_7_72)
    >>> printer.send(b"Precisely spaced line 1\r\n")
    >>> printer.send(b"Precisely spaced line 2\r\n")
"""

# =============================================================================
# CUSTOM LINE SPACING
# =============================================================================


def set_line_spacing_n_216(n: int) -> bytes:
    """
    Set line spacing to n/216 inch.

    Command: ESC 3 n
    Hex: 1B 33 n

    Args:
        n: Line spacing in 216ths of an inch (0-255).
           Examples:
           - n=36  → 36/216 = 1/6 inch (standard)
           - n=27  → 27/216 = 1/8 inch
           - n=72  → 72/216 = 1/3 inch

    Returns:
        ESC/P command bytes.

    Raises:
        ValueError: If n is out of range.

    Note:
        This is the most precise line spacing control available.
        Resolution: 1/216 inch = 0.00463 inches per unit.

    Common Values:
        - 18 (1/12 inch) = double-spaced at 12 LPI
        - 27 (1/8 inch)  = 8 lines per inch
        - 36 (1/6 inch)  = standard 6 LPI
        - 54 (1/4 inch)  = 4 lines per inch
        - 72 (1/3 inch)  = 3 lines per inch

    Example:
        >>> # Set 1/4 inch line spacing
        >>> cmd = set_line_spacing_n_216(54)
        >>> printer.send(cmd)
        >>> printer.send(b"Widely spaced line 1\r\n")
        >>> printer.send(b"Widely spaced line 2\r\n")
    """
    if not (0 <= n <= 255):
        raise ValueError(f"Line spacing must be 0-255, got {n}")

    return b"\x1b3" + bytes([n])


def set_line_spacing_n_72(n: int) -> bytes:
    """
    Set line spacing to n/72 inch.

    Command: ESC A n
    Hex: 1B 41 n

    Args:
        n: Line spacing in 72nds of an inch (0-85).
           Examples:
           - n=12 → 12/72 = 1/6 inch (standard)
           - n=9  → 9/72  = 1/8 inch
           - n=24 → 24/72 = 1/3 inch

    Returns:
        ESC/P command bytes.

    Raises:
        ValueError: If n is out of range.

    Note:
        Resolution: 1/72 inch = 0.0139 inches per unit.
        Less precise than set_line_spacing_n_216() but simpler values.
        Maximum: 85/72 inch ≈ 1.18 inches (very wide spacing).

    Common Values:
        - 6  (1/12 inch) = 12 lines per inch
        - 9  (1/8 inch)  = 8 lines per inch
        - 12 (1/6 inch)  = standard 6 LPI
        - 18 (1/4 inch)  = 4 lines per inch
        - 24 (1/3 inch)  = 3 lines per inch

    Example:
        >>> # Set 1/3 inch line spacing
        >>> cmd = set_line_spacing_n_72(24)
        >>> printer.send(cmd)
        >>> printer.send(b"Very wide spacing\r\n")
    """
    if not (0 <= n <= 85):
        raise ValueError(f"Line spacing must be 0-85, got {n}")

    return b"\x1bA" + bytes([n])


# =============================================================================
# USAGE EXAMPLES
# =============================================================================

"""
CHOOSING LINE SPACING METHOD:
    - Use ESC_LINE_SPACING_1_6 for standard documents (default)
    - Use ESC_LINE_SPACING_1_8 for compact layout
    - Use set_line_spacing_n_216() for precise control
    - Use set_line_spacing_n_72() for simple fractional spacing

CALCULATING LINES PER PAGE:
    At 11 inch page length:

    1/6 inch spacing:  11 / (1/6)  = 66 lines
    1/8 inch spacing:  11 / (1/8)  = 88 lines
    1/4 inch spacing:  11 / (1/4)  = 44 lines
    1/3 inch spacing:  11 / (1/3)  = 33 lines

CONVERSION BETWEEN UNITS:
    1/216 inch to 1/72 inch:
    >>> n_216 = 36  # 36/216 = 1/6 inch
    >>> n_72 = int(n_216 / 3)  # 12/72 = 1/6 inch

    1/72 inch to 1/216 inch:
    >>> n_72 = 12   # 12/72 = 1/6 inch
    >>> n_216 = n_72 * 3  # 36/216 = 1/6 inch

DOUBLE-HEIGHT COMPATIBILITY:
    When using double-height characters, adjust line spacing:

    >>> from src.escp.commands.sizing import ESC_DOUBLE_HEIGHT_ON
    >>>
    >>> # Double the line spacing for double-height text
    >>> printer.send(set_line_spacing_n_216(72))  # 72/216 = 1/3"
    >>> printer.send(ESC_DOUBLE_HEIGHT_ON + b"TALL TEXT\r\n")
    >>>
    >>> # Return to normal
    >>> printer.send(ESC_LINE_SPACING_1_6)
    >>> printer.send(b"Normal text\r\n")

FORM ALIGNMENT:
    Use precise spacing for pre-printed forms:

    >>> # Form fields at exact 1/4 inch intervals
    >>> printer.send(set_line_spacing_n_216(54))  # 54/216 = 1/4"
    >>>
    >>> for field in ["Name:", "Address:", "City:", "ZIP:"]:
    ...     printer.send(field.encode() + b"\r\n")

COMPACT MULTI-COLUMN LAYOUT:
    Tight spacing for newspaper-style columns:

    >>> printer.send(ESC_LINE_SPACING_1_8)  # 8 LPI
    >>> printer.send(b"Compact line 1\r\n")
    >>> printer.send(b"Compact line 2\r\n")
    >>> printer.send(b"Compact line 3\r\n")

SPACING EQUIVALENTS:
    Different ways to achieve same spacing:

    1/6 inch:
        - ESC_LINE_SPACING_1_6
        - set_line_spacing_n_216(36)
        - set_line_spacing_n_72(12)

    1/8 inch:
        - ESC_LINE_SPACING_1_8
        - set_line_spacing_n_216(27)
        - set_line_spacing_n_72(9)

PERFORMANCE NOTES:
    - Line spacing has NO performance impact
    - Printer advances paper at same speed regardless of spacing
    - Only affects distance between lines, not print speed

TROUBLESHOOTING:
    If spacing seems wrong:
    1. Check for conflicting line spacing commands
    2. Verify printer is advancing paper correctly
    3. Check paper feed mechanism (friction vs tractor)
    4. Reset printer to clear any stuck settings

    If lines overlap:
    1. Increase line spacing value
    2. Check for double-height text without adjusted spacing
    3. Verify paper isn't slipping in feed mechanism
"""
