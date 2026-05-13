"""
Font selection and CPI (Characters Per Inch) commands for Epson FX-890.

Contains commands for switching fonts, setting character pitch, and
configuring proportional spacing. All commands verified for FX-890.

Reference: Epson FX-890 Technical Reference Manual, Chapter 5
"""

from typing import Final

__all__ = [
    "ESC_FONT_ROMAN",
    "ESC_FONT_SANS_SERIF",
    "ESC_10CPI",
    "ESC_12CPI",
    "ESC_15CPI",
    "ESC_PROPORTIONAL_ON",
    "ESC_PROPORTIONAL_OFF",
    "ESC_MASTER_SELECT",
    "MASTER_12_CPI",
    "MASTER_PROPORTIONAL",
    "MASTER_CONDENSED",
    "MASTER_BOLD",
    "MASTER_DOUBLE_STRIKE",
    "MASTER_DOUBLE_WIDTH",
    "MASTER_ITALIC",
    "MASTER_UNDERLINE",
    "set_cpi",
    "set_character_spacing",
    "set_extra_spacing",
    "master_select",
]

# =============================================================================
# FONT SELECTION
# =============================================================================

# NOTE: ESC k command only works in NLQ mode (ESC x 1) for selecting
# typeface. Draft font (ESC x 0) does NOT support font selection.
#
# Draft mode is activated via ESC x 0, NOT via ESC k.
# See print_quality.py for mode selection.

ESC_FONT_ROMAN: Final[bytes] = b"\x1bk\x00"
"""
Select Roman font (serif, NLQ quality only).

Command: ESC k 0
Hex: 1B 6B 00
Effect: Roman serif font with serifs (NLQ mode required)
Speed: ~104 cps at 10 CPI, ~125 cps at 12 CPI (NLQ mode)
Quality: Near Letter Quality
Requirement: Printer must be in NLQ mode (ESC x 1)
Reset: Changed by other font commands or printer reset

Note:
    This command ONLY works in NLQ mode (ESC x 1).
    In Draft mode (ESC x 0), NLQ fonts are unavailable.
    Draft mode is selected via ESC x 0, NOT ESC k.

Example:
    >>> from src.escp.commands.print_quality import ESC_SELECT_LQ
    >>> printer.send(ESC_SELECT_LQ + ESC_FONT_ROMAN + b"Roman serif text")
"""

ESC_FONT_SANS_SERIF: Final[bytes] = b"\x1bk\x01"
"""
Select Sans Serif font (clean, NLQ quality only).

Command: ESC k 1
Hex: 1B 6B 01
Effect: Sans serif font without serifs (NLQ mode required)
Speed: ~104 cps at 10 CPI, ~125 cps at 12 CPI (NLQ mode)
Quality: Near Letter Quality
Requirement: Printer must be in NLQ mode (ESC x 1)
Reset: Changed by other font commands or printer reset

Note:
    This command ONLY works in NLQ mode (ESC x 1).
    Value 0 = Roman, 1 = Sans Serif (no other values supported).
    Draft mode is selected via ESC x 0, NOT ESC k.

Example:
    >>> from src.escp.commands.print_quality import ESC_SELECT_LQ
    >>> printer.send(ESC_SELECT_LQ + ESC_FONT_SANS_SERIF + b"Clean sans serif")
"""

# =============================================================================
# CHARACTER PITCH (CPI)
# =============================================================================

ESC_10CPI: Final[bytes] = b"\x1bP"
"""
Set 10 characters per inch (pica).

Command: ESC P
Hex: 1B 50
Effect: Standard character pitch (10 CPI)
Width: 0.1 inch per character
Compatibility: Works with all fonts
Reset: Changed by other CPI commands or printer reset

Example:
    >>> printer.send(ESC_10CPI + b"10 CPI text")
"""

ESC_12CPI: Final[bytes] = b"\x1bM"
"""
Set 12 characters per inch (elite).

Command: ESC M
Hex: 1B 4D
Effect: Narrower character pitch (12 CPI)
Width: 0.0833 inch per character
Compatibility: Works with all fonts
Reset: Changed by other CPI commands or printer reset

Example:
    >>> printer.send(ESC_12CPI + b"12 CPI narrower text")
"""

ESC_15CPI: Final[bytes] = b"\x1bg"
"""
Set 15 characters per inch (condensed).

Command: ESC g
Hex: 1B 67
Effect: Very narrow character pitch (15 CPI)
Width: 0.0667 inch per character
Compatibility: Works with all fonts
Note: Similar to condensed mode but fixed at 15 CPI
Reset: Changed by other CPI commands or printer reset

Example:
    >>> printer.send(ESC_15CPI + b"15 CPI very narrow text")
"""

# =============================================================================
# PROPORTIONAL SPACING
# =============================================================================

ESC_PROPORTIONAL_ON: Final[bytes] = b"\x1bp\x01"
"""
Enable proportional spacing.

Command: ESC p 1
Hex: 1B 70 01
Effect: Character width varies based on character (e.g., 'i' narrower than 'm')
Requirement: NLQ mode
Quality: More natural appearance, like typeset text
Speed: Slightly slower due to variable spacing calculations
Reset: Cancelled by ESC p 0 or printer reset

Example:
    >>> from src.escp.commands.print_quality import ESC_SELECT_LQ
    >>> printer.send(ESC_SELECT_LQ + ESC_PROPORTIONAL_ON + b"Proportional text")
"""

ESC_PROPORTIONAL_OFF: Final[bytes] = b"\x1bp\x00"
"""
Disable proportional spacing (monospace).

Command: ESC p 0
Hex: 1B 70 00
Effect: All characters same width (monospace/fixed-width)
Default: FX-890 defaults to monospace
Reset: Default state after printer reset

Example:
    >>> printer.send(ESC_PROPORTIONAL_OFF + b"Monospace text")
"""

# =============================================================================
# CUSTOM CPI SETTING
# =============================================================================


def set_cpi(cpi: int) -> bytes:
    """
    Set character pitch (CPI).

    Command: ESC x n
    Hex: 1B 78 n

    Args:
        cpi: Characters per inch. FX-890 supports only:
             - 10 CPI (pica, standard)
             - 12 CPI (elite)
             - 15 CPI (condensed)

    Returns:
        ESC/P command bytes.

    Raises:
        ValueError: If cpi is not 10, 12, or 15.

    Note:
        FX-890 only supports 10, 12, and 15 CPI.
        Use ESC P, ESC M, ESC g shortcuts for these values.

    Example:
        >>> cmd = set_cpi(12)  # 12 CPI (elite)
        >>> printer.send(cmd + b"12 CPI text")
    """
    if cpi not in (10, 12, 15):
        raise ValueError(f"FX-890 supports only 10, 12, or 15 CPI, got {cpi}")

    return b"\x1bx" + bytes([cpi])


def set_character_spacing(spacing: int) -> bytes:
    """
    Set additional spacing between characters.

    Command: ESC SP n
    Hex: 1B 20 n

    Args:
        spacing: Extra dots between characters (0-127).
                0 = no extra spacing (default).

    Returns:
        ESC/P command bytes.

    Raises:
        ValueError: If spacing is out of range.

    Note:
        Spacing is measured in 1/120 inch units.
        This adds space WITHOUT changing CPI setting.

    Example:
        >>> cmd = set_character_spacing(10)  # Add 10/120" between chars
        >>> printer.send(ESC_12CPI + cmd + b"Spaced text")
    """
    if not (0 <= spacing <= 127):
        raise ValueError(f"Spacing must be 0-127, got {spacing}")

    return b"\x1b " + bytes([spacing])


# =============================================================================
# MASTER SELECT (ESC !)
# =============================================================================

ESC_MASTER_SELECT: Final[bytes] = b"\x1b!"
"""
Master Select command prefix.

Command: ESC ! n
Hex: 1B 21 n
Effect: Combined font attribute selection via bit flags.

Bit flags for Master Select:
    Bit 0 (0x01): 12 CPI (elite) - if 0, uses 10 CPI
    Bit 1 (0x02): Proportional spacing
    Bit 2 (0x04): Condensed mode
    Bit 3 (0x08): Bold
    Bit 4 (0x10): Double-strike
    Bit 5 (0x20): Double-width
    Bit 6 (0x40): Italic
    Bit 7 (0x80): Underline

Note:
    This command combines multiple attributes in a single byte.
    Some combinations may be mutually exclusive or hardware-dependent.

Example:
    >>> # Bold + Italic + 12 CPI
    >>> flags = MASTER_BOLD | MASTER_ITALIC | MASTER_12_CPI
    >>> printer.send(master_select(flags))
"""

# Master Select bit flags
MASTER_12_CPI: Final[int] = 0x01
MASTER_PROPORTIONAL: Final[int] = 0x02
MASTER_CONDENSED: Final[int] = 0x04
MASTER_BOLD: Final[int] = 0x08
MASTER_DOUBLE_STRIKE: Final[int] = 0x10
MASTER_DOUBLE_WIDTH: Final[int] = 0x20
MASTER_ITALIC: Final[int] = 0x40
MASTER_UNDERLINE: Final[int] = 0x80


def master_select(flags: int) -> bytes:
    """
    Master Select - combined font attribute selection.

    Command: ESC ! n
    Hex: 1B 21 n

    Args:
        flags: Bit mask of attributes (0-255).
               Use MASTER_* constants to build the mask.

    Returns:
        ESC/P command bytes.

    Raises:
        ValueError: If flags is out of range.

    Bit flags:
        MASTER_12_CPI (0x01): 12 CPI elite (default is 10 CPI)
        MASTER_PROPORTIONAL (0x02): Enable proportional spacing
        MASTER_CONDENSED (0x04): Condensed mode
        MASTER_BOLD (0x08): Bold text
        MASTER_DOUBLE_STRIKE (0x10): Double-strike
        MASTER_DOUBLE_WIDTH (0x20): Double-width
        MASTER_ITALIC (0x40): Italic
        MASTER_UNDERLINE (0x80): Underline

    Example:
        >>> # Bold + Italic + Underline + 12 CPI
        >>> flags = MASTER_BOLD | MASTER_ITALIC | MASTER_UNDERLINE | MASTER_12_CPI
        >>> printer.send(master_select(flags))
        >>> printer.send(b"Formatted text")
    """
    if not (0 <= flags <= 255):
        raise ValueError(f"Flags must be 0-255, got {flags}")

    return b"\x1b!" + bytes([flags])


def set_extra_spacing(dots: int) -> bytes:
    """
    Set extra intercharacter spacing.

    Command: ESC Space n
    Hex: 1B 20 n

    Args:
        dots: Extra spacing in 1/120 inch units (0-127).
              0 = no extra spacing (default).

    Returns:
        ESC/P command bytes.

    Raises:
        ValueError: If dots is out of range.

    Note:
        Adds n/120 inch to the right of each character.
        Independent of CPI setting.

    Example:
        >>> cmd = set_extra_spacing(10)  # Add 10/120" spacing
        >>> printer.send(cmd + b"Spaced text")
    """
    if not (0 <= dots <= 127):
        raise ValueError(f"Spacing must be 0-127, got {dots}")

    return b"\x1b " + bytes([dots])


# =============================================================================
# USAGE EXAMPLES
# =============================================================================

"""
COMBINING FONT AND CPI:
    Font and CPI are independent settings:

    >>> # Roman font at 12 CPI
    >>> cmd = ESC_SELECT_LQ + ESC_FONT_ROMAN + ESC_12CPI
    >>> printer.send(cmd + b"Roman 12 CPI")

PROPORTIONAL SPACING REQUIREMENTS:
    Proportional spacing REQUIRES NLQ mode:

    >>> from src.escp.commands.print_quality import ESC_SELECT_LQ
    >>> cmd = ESC_SELECT_LQ + ESC_PROPORTIONAL_ON
    >>> printer.send(cmd + b"Proportional text")

MAXIMUM LINE WIDTH:
    At 8.5" paper width:
    - 10 CPI: 85 characters per line
    - 12 CPI: 102 characters per line
    - 15 CPI: 127 characters per line

FONT AVAILABILITY:
    - Draft fonts: Available in Draft mode (ESC x 0 or ESC_SELECT_DRAFT)
    - Roman/Sans Serif: Only in NLQ mode (ESC x 1 or ESC_SELECT_LQ)
    - ESC k only works in NLQ mode

PERFORMANCE CONSIDERATIONS:
    - Draft mode: ~419 cps at 10 CPI, ~503 cps at 12 CPI
    - NLQ mode: ~104 cps at 10 CPI, ~125 cps at 12 CPI
    - Proportional: Slightly slower than fixed-width

MASTER SELECT EXAMPLES:
    Combined attribute selection:

    >>> # Bold + 12 CPI
    >>> printer.send(master_select(MASTER_BOLD | MASTER_12_CPI))
    >>> printer.send(b"Bold elite text")

    >>> # Italic + Underline
    >>> printer.send(master_select(MASTER_ITALIC | MASTER_UNDERLINE))
    >>> printer.send(b"Italic underlined text")

TROUBLESHOOTING:
    If font doesn't appear:
    1. Check printer mode (ESC x 0 = Draft, ESC x 1 = NLQ)
    2. Roman/Sans Serif require NLQ mode
    3. ESC k only works in NLQ mode
    4. Reset printer and try again
"""
