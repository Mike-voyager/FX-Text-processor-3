"""
Font selection and CPI (Characters Per Inch) commands for Epson FX-890.

Contains commands for switching fonts, setting character pitch, and
configuring proportional spacing. All commands verified for FX-890.

Reference: Epson FX-890 Technical Reference Manual, Chapter 5
"""

from typing import Final

__all__ = [
    "ESC_FONT_DRAFT",
    "ESC_FONT_ROMAN",
    "ESC_FONT_SANS_SERIF",
    "ESC_10CPI",
    "ESC_12CPI",
    "ESC_15CPI",
    "ESC_PROPORTIONAL_ON",
    "ESC_PROPORTIONAL_OFF",
    "set_cpi",
    "set_character_spacing",
]

# =============================================================================
# FONT SELECTION
# =============================================================================

ESC_FONT_DRAFT: Final[bytes] = b"\x1bk\x00"
"""
Select draft font (fast printing).

Command: ESC k 0
Hex: 1B 6B 00
Effect: High-speed draft quality font
Speed: ~680 cps (characters per second)
Quality: Standard readability
Reset: Changed by other font commands or printer reset

Example:
    >>> printer.send(ESC_FONT_DRAFT + b"Fast draft text")
"""

ESC_FONT_ROMAN: Final[bytes] = b"\x1bk\x01"
"""
Select Roman font (serif, NLQ quality).

Command: ESC k 1
Hex: 1B 6B 01
Effect: Roman serif font with serifs (NLQ mode required)
Speed: ~227 cps (slower due to higher quality)
Quality: Near Letter Quality
Requirement: Printer must be in NLQ mode
Reset: Changed by other font commands or printer reset

Example:
    >>> from src.escp.commands.print_quality import ESC_SELECT_LQ
    >>> printer.send(ESC_SELECT_LQ + ESC_FONT_ROMAN + b"Roman serif text")
"""

ESC_FONT_SANS_SERIF: Final[bytes] = b"\x1bk\x02"
"""
Select Sans Serif font (clean, NLQ quality).

Command: ESC k 2
Hex: 1B 6B 02
Effect: Sans serif font without serifs (NLQ mode required)
Speed: ~227 cps
Quality: Near Letter Quality
Requirement: Printer must be in NLQ mode
Reset: Changed by other font commands or printer reset

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
    Set custom character pitch.

    Command: ESC x n
    Hex: 1B 78 n

    Args:
        cpi: Characters per inch (5-20 supported on FX-890).

    Returns:
        ESC/P command bytes.

    Raises:
        ValueError: If cpi is out of supported range.

    Note:
        Not all CPI values may render well. Standard values are:
        10 CPI (pica), 12 CPI (elite), 15 CPI (condensed).

    Example:
        >>> cmd = set_cpi(17)  # 17 characters per inch
        >>> printer.send(cmd + b"Custom 17 CPI text")
    """
    if not (5 <= cpi <= 20):
        raise ValueError(f"CPI must be 5-20, got {cpi}")

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
    - Draft font: Always available
    - Roman/Sans Serif: NLQ mode only
    - Some fonts may not support all CPI values

PERFORMANCE CONSIDERATIONS:
    - Draft mode: ~680 cps
    - NLQ mode: ~227 cps
    - Proportional: Slightly slower than fixed-width

TROUBLESHOOTING:
    If font doesn't appear:
    1. Check printer mode (draft vs NLQ)
    2. Verify font is supported in current mode
    3. Reset printer and try again
    4. Check paper type (some effects work poorly on thermal paper)
"""
