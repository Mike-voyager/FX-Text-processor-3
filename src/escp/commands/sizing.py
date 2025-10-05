"""
Character sizing commands for Epson FX-890.

Contains commands for condensed, double-width, and double-height character
modes. All commands verified for FX-890.

Reference: Epson FX-890 Technical Reference Manual, Chapter 4
"""

from typing import Final

__all__ = [
    "SI",
    "DC2",
    "ESC_CONDENSED_ON",
    "ESC_CONDENSED_OFF",
    "ESC_DOUBLE_WIDTH_ON",
    "ESC_DOUBLE_WIDTH_OFF",
    "ESC_DOUBLE_HEIGHT_ON",
    "ESC_DOUBLE_HEIGHT_OFF",
]

# =============================================================================
# CONDENSED MODE
# =============================================================================

SI: Final[bytes] = b"\x0f"
"""
Enable condensed printing (Shift-In).

Command: SI
Hex: 0F
Effect: Reduces character width to ~60% of normal (approximately 17 CPI from 10 CPI)
Mode: Can combine with bold, italic, underline
Performance: No speed penalty
Reset: Cancelled by DC2 or ESC P/M/g (CPI commands)

Example:
    >>> printer.send(SI + b"Condensed narrow text" + DC2)
"""

DC2: Final[bytes] = b"\x12"
"""
Disable condensed printing (Device Control 2).

Command: DC2
Hex: 12
Effect: Returns to normal character width
Default: Normal width is default state
Reset: Default state after printer reset

Example:
    >>> printer.send(b"Normal " + SI + b"Condensed " + DC2 + b"Normal")
"""

ESC_CONDENSED_ON: Final[bytes] = b"\x0f"
"""
Enable condensed printing (alternate name for SI).

This is an alias for SI for clarity in code that uses ESC/P naming convention.
See SI for full documentation.

Example:
    >>> printer.send(ESC_CONDENSED_ON + b"Condensed" + ESC_CONDENSED_OFF)
"""

ESC_CONDENSED_OFF: Final[bytes] = b"\x12"
"""
Disable condensed printing (alternate name for DC2).

This is an alias for DC2 for clarity in code that uses ESC/P naming convention.
See DC2 for full documentation.

Example:
    >>> printer.send(ESC_CONDENSED_ON + b"Narrow" + ESC_CONDENSED_OFF + b" Normal")
"""

# =============================================================================
# DOUBLE-WIDTH MODE
# =============================================================================

ESC_DOUBLE_WIDTH_ON: Final[bytes] = b"\x1bW\x01"
"""
Enable double-width printing.

Command: ESC W 1
Hex: 1B 57 01
Effect: Characters printed at 2× normal width
Interaction: Reduces effective CPI (10 CPI becomes 5 CPI)
Mode: Can combine with bold, italic, underline, double-height
Performance: Slight speed reduction (~10-15%)
Reset: Cancelled by ESC W 0 or printer reset

Example:
    >>> printer.send(ESC_DOUBLE_WIDTH_ON + b"WIDE TEXT" + ESC_DOUBLE_WIDTH_OFF)
"""

ESC_DOUBLE_WIDTH_OFF: Final[bytes] = b"\x1bW\x00"
"""
Disable double-width printing.

Command: ESC W 0
Hex: 1B 57 00
Effect: Returns to normal character width
Default: Normal width is default state
Reset: Default state after printer reset

Example:
    >>> printer.send(b"Normal " + ESC_DOUBLE_WIDTH_ON + b"WIDE " + ESC_DOUBLE_WIDTH_OFF + b"Normal")
"""

# =============================================================================
# DOUBLE-HEIGHT MODE
# =============================================================================

ESC_DOUBLE_HEIGHT_ON: Final[bytes] = b"\x1bw\x01"
"""
Enable double-height printing (for current line).

Command: ESC w 1
Hex: 1B 77 01
Effect: Characters printed at 2× normal height
Scope: Affects only current line (resets at line feed)
Mode: Can combine with bold, italic, underline, double-width
Performance: No speed penalty per character, but uses 2 print passes
Reset: Automatically cancelled at next LF/CR, or by ESC w 0

Important: Double-height is LINE-SPECIFIC, not persistent like other modes.

Example:
    >>> printer.send(ESC_DOUBLE_HEIGHT_ON + b"TALL TEXT\r\n")
    >>> printer.send(b"Normal text again\r\n")  # Automatically normal height
"""

ESC_DOUBLE_HEIGHT_OFF: Final[bytes] = b"\x1bw\x00"
"""
Disable double-height printing.

Command: ESC w 0
Hex: 1B 77 00
Effect: Returns to normal character height
Note: Usually not needed since double-height auto-resets at line feed
Default: Normal height is default state

Example:
    >>> # Explicit cancellation (rare case: mid-line change)
    >>> printer.send(ESC_DOUBLE_HEIGHT_ON + b"TALL" + ESC_DOUBLE_HEIGHT_OFF + b" normal")
"""

# =============================================================================
# USAGE EXAMPLES
# =============================================================================

"""
COMBINING DOUBLE-WIDTH AND DOUBLE-HEIGHT:
    Create 4× size characters:

    >>> cmd = ESC_DOUBLE_WIDTH_ON + ESC_DOUBLE_HEIGHT_ON
    >>> cmd += b"HUGE TEXT\r\n"
    >>> cmd += ESC_DOUBLE_WIDTH_OFF  # Height auto-resets after \n
    >>> printer.send(cmd)

CONDENSED MODE INTERACTIONS:
    Condensed mode is affected by CPI commands:

    >>> # Condensed mode cancelled by ESC P (10 CPI)
    >>> printer.send(SI + b"Condensed ")
    >>> printer.send(ESC_10CPI + b"Normal 10 CPI")  # Condensed cancelled!

    >>> # To maintain condensed, don't use CPI commands
    >>> printer.send(SI + b"Condensed throughout" + DC2)

LINE WIDTH CALCULATIONS:
    At 8.5" paper width with 10 CPI base:

    - Normal (10 CPI):        85 characters
    - Condensed (~17 CPI):   ~145 characters
    - Double-width (5 CPI):   42 characters
    - Condensed + DW:        ~72 characters

DOUBLE-HEIGHT LINE SPACING:
    Double-height requires 2 line positions:

    >>> # Good: Proper spacing
    >>> printer.send(ESC_DOUBLE_HEIGHT_ON + b"Line 1\r\n")
    >>> printer.send(b"\r\n")  # Skip one line for proper spacing
    >>> printer.send(ESC_DOUBLE_HEIGHT_ON + b"Line 2\r\n")

    >>> # Bad: Lines overlap
    >>> printer.send(ESC_DOUBLE_HEIGHT_ON + b"Line 1\r\n")
    >>> printer.send(ESC_DOUBLE_HEIGHT_ON + b"Line 2\r\n")  # TOO CLOSE!

PERFORMANCE NOTES:
    - Condensed: No performance impact
    - Double-width: ~10-15% slower (more dot firing)
    - Double-height: Uses 2 print passes (50% slower for that line)
    - Combined DW+DH: ~60% slower than normal

BANNER PRINTING:
    Create large banner text across multiple lines:

    >>> from src.escp.commands.text_formatting import ESC_BOLD_ON
    >>>
    >>> banner = ESC_BOLD_ON + ESC_DOUBLE_WIDTH_ON + ESC_DOUBLE_HEIGHT_ON
    >>> banner += b"SALE!\r\n\r\n"  # Extra \n for spacing
    >>> banner += b"50% OFF\r\n"
    >>> printer.send(banner)

TROUBLESHOOTING:
    If sizing doesn't appear:
    1. Check that condensed isn't being cancelled by CPI commands
    2. For double-height, ensure adequate line spacing
    3. Verify paper width can accommodate wide text
    4. Check printer settings (page layout may override)

    If text is cut off:
    1. Calculate effective CPI after sizing
    2. Reduce line length or adjust margins
    3. Consider switching to condensed mode for wide content
"""
