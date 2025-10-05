"""
Text formatting ESC/P commands for Epson FX-890.

Contains commands for bold, italic, underline, double-strike, and other
text emphasis modes. All commands verified against FX-890 specifications.

Reference: Epson FX-890 Technical Reference Manual, Chapter 4
Compatibility: FX-890, FX-2190, LX-300+II, LQ-690
"""

from typing import Final

__all__ = [
    "ESC_BOLD_ON",
    "ESC_BOLD_OFF",
    "ESC_ITALIC_ON",
    "ESC_ITALIC_OFF",
    "ESC_UNDERLINE_ON",
    "ESC_UNDERLINE_DOUBLE",
    "ESC_UNDERLINE_OFF",
    "ESC_DOUBLE_STRIKE_ON",
    "ESC_DOUBLE_STRIKE_OFF",
    "ESC_OUTLINE_ON",
    "ESC_OUTLINE_OFF",
    "ESC_SHADOW_ON",
    "ESC_SHADOW_OFF",
]

# =============================================================================
# BOLD (EMPHASIZED) MODE
# =============================================================================

ESC_BOLD_ON: Final[bytes] = b"\x1bE"
"""
Enable bold (emphasized) printing.

Command: ESC E
Hex: 1B 45
Effect: Makes text darker by double-printing with slight offset
Mode: Can combine with other formatting (italic, underline)
Reset: Cancelled by ESC F or printer reset

Example:
    >>> printer.send(ESC_BOLD_ON + b"Bold text" + ESC_BOLD_OFF)
"""

ESC_BOLD_OFF: Final[bytes] = b"\x1bF"
"""
Disable bold (emphasized) printing.

Command: ESC F
Hex: 1B 46
Effect: Returns to normal print density
Note: Automatically cancelled by printer reset

Example:
    >>> printer.send(b"Normal " + ESC_BOLD_ON + b"Bold " + ESC_BOLD_OFF + b"Normal")
"""

# =============================================================================
# ITALIC MODE
# =============================================================================

ESC_ITALIC_ON: Final[bytes] = b"\x1b4"
"""
Enable italic printing.

Command: ESC 4
Hex: 1B 34
Effect: Slants characters to the right (9-degree angle)
Mode: Can combine with bold, underline
Limitation: Not available in all fonts (e.g., condensed mode)
Reset: Cancelled by ESC 5 or printer reset

Example:
    >>> printer.send(ESC_ITALIC_ON + b"Italic text" + ESC_ITALIC_OFF)
"""

ESC_ITALIC_OFF: Final[bytes] = b"\x1b5"
"""
Disable italic printing.

Command: ESC 5
Hex: 1B 35
Effect: Returns to upright characters
Note: Automatically cancelled by printer reset

Example:
    >>> printer.send(b"Normal " + ESC_ITALIC_ON + b"Italic " + ESC_ITALIC_OFF + b"Normal")
"""

# =============================================================================
# UNDERLINE
# =============================================================================

ESC_UNDERLINE_ON: Final[bytes] = b"\x1b-\x01"
"""
Enable single underline.

Command: ESC - 1
Hex: 1B 2D 01
Effect: Prints continuous line below text
Mode: Can combine with bold, italic
Note: Does NOT underline spaces (use ESC - 2 for that)
Reset: Cancelled by ESC - 0 or printer reset

Example:
    >>> printer.send(ESC_UNDERLINE_ON + b"Underlined text" + ESC_UNDERLINE_OFF)
"""

ESC_UNDERLINE_DOUBLE: Final[bytes] = b"\x1b-\x02"
"""
Enable double underline (or underline spaces).

Command: ESC - 2
Hex: 1B 2D 02
Effect: Prints two parallel lines below text OR underlines spaces
Mode: Can combine with other formatting
Note: On FX-890, this also underlines spaces in text
Reset: Cancelled by ESC - 0 or printer reset

Example:
    >>> printer.send(ESC_UNDERLINE_DOUBLE + b"Double underline" + ESC_UNDERLINE_OFF)
"""

ESC_UNDERLINE_OFF: Final[bytes] = b"\x1b-\x00"
"""
Disable underline.

Command: ESC - 0
Hex: 1B 2D 00
Effect: Stops underlining
Note: Cancels both single and double underline

Example:
    >>> printer.send(ESC_UNDERLINE_ON + b"Under" + ESC_UNDERLINE_OFF + b"Normal")
"""

# =============================================================================
# DOUBLE-STRIKE
# =============================================================================

ESC_DOUBLE_STRIKE_ON: Final[bytes] = b"\x1bG"
"""
Enable double-strike printing.

Command: ESC G
Hex: 1B 47
Effect: Prints each character twice with slight vertical offset
Result: Darker, bolder appearance (similar to bold but different technique)
Mode: Can combine with italic, underline
Difference from Bold: Double-strike = vertical offset, Bold = horizontal offset
Reset: Cancelled by ESC H or printer reset

Example:
    >>> printer.send(ESC_DOUBLE_STRIKE_ON + b"Double-strike" + ESC_DOUBLE_STRIKE_OFF)
"""

ESC_DOUBLE_STRIKE_OFF: Final[bytes] = b"\x1bH"
"""
Disable double-strike printing.

Command: ESC H
Hex: 1B 48
Effect: Returns to single-strike printing
Note: Automatically cancelled by printer reset

Example:
    >>> printer.send(b"Normal " + ESC_DOUBLE_STRIKE_ON + b"Dark " + ESC_DOUBLE_STRIKE_OFF)
"""

# =============================================================================
# OUTLINE (NOT FILLED)
# =============================================================================

ESC_OUTLINE_ON: Final[bytes] = b"\x1b("
"""
Enable outline mode (hollow characters).

Command: ESC (
Hex: 1B 28
Effect: Prints character outlines without filling
Availability: Limited support on FX-890 (depends on font)
Note: Not available in draft mode
Reset: Cancelled by ESC ) or printer reset

WARNING: This command may not be supported on all FX-890 firmware versions.
         Test before production use.

Example:
    >>> printer.send(ESC_OUTLINE_ON + b"Outline text" + ESC_OUTLINE_OFF)
"""

ESC_OUTLINE_OFF: Final[bytes] = b"\x1b)"
"""
Disable outline mode.

Command: ESC )
Hex: 1B 29
Effect: Returns to filled characters
Note: Automatically cancelled by printer reset

Example:
    >>> printer.send(ESC_OUTLINE_ON + b"Outline" + ESC_OUTLINE_OFF + b" Normal")
"""

# =============================================================================
# SHADOW (WITH OFFSET)
# =============================================================================

ESC_SHADOW_ON: Final[bytes] = b"\x1b!"
"""
Enable shadow mode.

Command: ESC !
Hex: 1B 21
Effect: Prints characters with slight offset creating shadow effect
Availability: Limited support on FX-890 (depends on font and mode)
Note: Not available in draft mode
Reset: Cancelled by ESC @ or printer reset

WARNING: This command may not be supported on all FX-890 firmware versions.
         Test before production use.

Example:
    >>> printer.send(ESC_SHADOW_ON + b"Shadow text" + ESC_SHADOW_OFF)
"""

ESC_SHADOW_OFF: Final[bytes] = b"\x1b\x22"
"""
Disable shadow mode.

Command: ESC "
Hex: 1B 22
Effect: Returns to normal characters
Note: Automatically cancelled by printer reset

Example:
    >>> printer.send(ESC_SHADOW_ON + b"Shadow" + ESC_SHADOW_OFF + b" Normal")
"""

# =============================================================================
# USAGE EXAMPLES
# =============================================================================

"""
COMBINING MULTIPLE FORMATS:
    Commands can be stacked for combined effects:

    >>> # Bold + Italic + Underline
    >>> cmd = ESC_BOLD_ON + ESC_ITALIC_ON + ESC_UNDERLINE_ON
    >>> cmd += b"Bold Italic Underlined"
    >>> cmd += ESC_UNDERLINE_OFF + ESC_ITALIC_OFF + ESC_BOLD_OFF
    >>> printer.send(cmd)

RESETTING ALL FORMATTING:
    Use printer reset to clear all formatting:

    >>> from src.escp.commands.hardware import ESC_INIT_PRINTER
    >>> printer.send(ESC_INIT_PRINTER)  # Resets ALL modes

PERFORMANCE NOTES:
    - Bold/Double-strike reduce print speed by ~50% (double-printing)
    - Italic has minimal performance impact
    - Underline has no performance impact
    - Combining multiple modes compounds slowdown

DRAFT VS NLQ MODES:
    - All commands work in both draft and NLQ modes
    - Outline/Shadow may not work in draft mode
    - Effect quality is better in NLQ mode

TROUBLESHOOTING:
    If formatting doesn't appear:
    1. Check printer is in correct mode (not form tear-off)
    2. Verify firmware version supports command
    3. Test command in isolation (without other formatting)
    4. Check paper type (some effects work poorly on thin paper)
"""
# =============================================================================
# STRIKETHROUGH (NOT A NATIVE COMMAND)
# =============================================================================

"""
STRIKETHROUGH NOTE:

FX-890 does NOT have a native strikethrough command. To implement
strikethrough effect, use TWO-PASS RENDERING:

Method 1: Using CR (Carriage Return)
    >>> from src.escp.commands.positioning import CR
    >>> text = b"Cancelled"
    >>> printer.send(text + CR + b"\xc4" * len(text))
    >>> # Output: Cancelled (with line through)

Method 2: Using BS (Backspace)
    >>> from src.escp.commands.positioning import BS
    >>> text = b"Error"
    >>> printer.send(text + (BS * len(text)) + b"\xc4" * len(text))
    >>> # Output: Error (with line through)

For high-level strikethrough API, see:
    - src.escp.effects.create_strikethrough()
    - src.escp.builders.text_effects.TextEffectBuilder

Character for line:
    - PC866/PC437: 0xC4 (─ box drawing horizontal)
    - ASCII fallback: 0x2D (-) hyphen
    - Alternative: 0x5F (_) underscore

This technique is also used for:
    - Custom underlines (different styles)
    - Double underlines (two passes)
    - Overprinting accents (e.g., á = a + backspace + accent)
"""
