"""
Print quality mode commands for Epson FX-890.

Contains commands for switching between draft and Near Letter Quality (NLQ)
print modes. All commands verified for FX-890.

Reference: Epson FX-890 Technical Reference Manual, Chapter 3
"""

from typing import Final

__all__ = [
    "ESC_DRAFT_MODE",
    "ESC_LQ_MODE",
    "ESC_SELECT_LQ",
    "ESC_SELECT_DRAFT",
    "ESC_DRAFT_SPEED_NORMAL",
    "ESC_DRAFT_SPEED_HIGH",
    "ESC_DRAFT_SPEED_ULTRA",
    "set_draft_speed",
]

# =============================================================================
# PRINT QUALITY MODES
# =============================================================================

ESC_DRAFT_MODE: Final[bytes] = b"\x1bx\x00"
"""
Select draft quality mode.

Command: ESC x 0
Hex: 1B 78 00
Effect: High-speed draft printing
Speed: ~419 cps (10 CPI), ~503 cps (12 CPI) - Normal speed
       ~471 cps (10 CPI), ~566 cps (12 CPI) - High speed
       ~566 cps (10 CPI), ~680 cps (12 CPI) - Ultra high speed
Quality: Standard readability, visible dot matrix pattern
Font Availability: Draft fonts only (Roman/Sans Serif unavailable)
Use Case: High-volume printing, internal documents, drafts
Reset: Changed by ESC x 1 or printer reset (default is draft)

Note:
    Draft speed can be adjusted with ESC y command.
    Use set_draft_speed() or ESC_DRAFT_SPEED_* constants.

Example:
    >>> printer.send(ESC_DRAFT_MODE)
    >>> printer.send(b"Fast draft quality text")
"""

ESC_LQ_MODE: Final[bytes] = b"\x1bx\x01"
"""
Select Near Letter Quality (NLQ) mode.

Command: ESC x 1
Hex: 1B 78 01
Effect: Higher quality printing with multiple passes
Speed: ~104 cps (10 CPI), ~125 cps (12 CPI)
Quality: Smoother characters, less visible dot matrix
Font Availability: All fonts (Draft, Roman, Sans Serif)
Use Case: Final documents, external correspondence, presentations
Reset: Changed by ESC x 0

Example:
    >>> printer.send(ESC_LQ_MODE)
    >>> printer.send(b"High quality NLQ text")
"""

# =============================================================================
# DRAFT SPEED SELECTION (ESC y)
# =============================================================================

ESC_DRAFT_SPEED_NORMAL: Final[bytes] = b"\x1by\x00"
"""
Normal draft speed.

Command: ESC y 0
Hex: 1B 79 00
Effect: Normal draft printing speed
Speed: ~419 cps at 10 CPI, ~503 cps at 12 CPI
Quality: Standard draft quality
Default: Normal speed after printer reset

Example:
    >>> printer.send(ESC_DRAFT_MODE + ESC_DRAFT_SPEED_NORMAL)
    >>> printer.send(b"Normal speed draft")
"""

ESC_DRAFT_SPEED_HIGH: Final[bytes] = b"\x1by\x01"
"""
High Speed Draft (HSD).

Command: ESC y 1
Hex: 1B 79 01
Effect: Increased draft printing speed
Speed: ~471 cps at 10 CPI, ~566 cps at 12 CPI
Quality: Slightly lower than normal draft

Example:
    >>> printer.send(ESC_DRAFT_MODE + ESC_DRAFT_SPEED_HIGH)
    >>> printer.send(b"High speed draft")
"""

ESC_DRAFT_SPEED_ULTRA: Final[bytes] = b"\x1by\x02"
"""
Ultra High Speed Draft (UHSD).

Command: ESC y 2
Hex: 1B 79 02
Effect: Maximum draft printing speed
Speed: ~566 cps at 10 CPI, ~680 cps at 12 CPI
Quality: Fastest draft mode, lower quality

Note:
    Only available in draft mode (ESC x 0).
    No effect in NLQ mode.

Example:
    >>> printer.send(ESC_DRAFT_MODE + ESC_DRAFT_SPEED_ULTRA)
    >>> printer.send(b"Ultra high speed draft")
"""


def set_draft_speed(speed: int) -> bytes:
    """
    Set draft printing speed.

    Command: ESC y n
    Hex: 1B 79 n

    Args:
        speed: Speed level (0, 1, or 2).
               0 = Normal Draft (~419/503 cps at 10/12 CPI)
               1 = High Speed Draft (~471/566 cps at 10/12 CPI)
               2 = Ultra High Speed Draft (~566/680 cps at 10/12 CPI)

    Returns:
        ESC/P command bytes.

    Raises:
        ValueError: If speed is not 0, 1, or 2.

    Note:
        Only affects draft mode (ESC x 0).
        Has no effect in NLQ mode.

    Example:
        >>> cmd = set_draft_speed(1)  # High speed
        >>> printer.send(ESC_DRAFT_MODE + cmd)
        >>> printer.send(b"Fast draft text")
    """
    if speed not in (0, 1, 2):
        raise ValueError("Speed must be 0 (normal), 1 (HSD), or 2 (UHSD)")

    return b"\x1by" + bytes([speed])


# Aliases for clarity
ESC_SELECT_LQ: Final[bytes] = ESC_LQ_MODE
"""
Alias for ESC_LQ_MODE.

Select Near Letter Quality mode (same as ESC_LQ_MODE).
Provided for code readability.

Example:
    >>> printer.send(ESC_SELECT_LQ)
    >>> printer.send(b"NLQ quality")
"""

ESC_SELECT_DRAFT: Final[bytes] = ESC_DRAFT_MODE
"""
Alias for ESC_DRAFT_MODE.

Select draft quality mode (same as ESC_DRAFT_MODE).
Provided for code readability.

Example:
    >>> printer.send(ESC_SELECT_DRAFT)
    >>> printer.send(b"Draft quality")
"""

# =============================================================================
# USAGE EXAMPLES
# =============================================================================

"""
SPEED VS QUALITY TRADEOFF:
    Draft Mode:
        - Normal Speed: 419 cps (10 CPI), 503 cps (12 CPI)
        - High Speed: 471 cps (10 CPI), 566 cps (12 CPI)
        - Ultra Speed: 566 cps (10 CPI), 680 cps (12 CPI)
        - Quality: Visible dot matrix
        - Fonts: Draft only
        - Use: Internal documents, high-volume

    NLQ Mode:
        - Speed: 104 cps (10 CPI), 125 cps (12 CPI)
        - Quality: Smooth, professional
        - Fonts: Draft, Roman, Sans Serif
        - Use: Final documents, external communication

SWITCHING MODES MID-DOCUMENT:
    Can switch between modes for mixed-quality documents:

    >>> # Draft for body text
    >>> printer.send(ESC_SELECT_DRAFT)
    >>> printer.send(b"Body text in draft mode\r\n" * 10)
    >>>
    >>> # NLQ for important summary
    >>> printer.send(ESC_SELECT_LQ)
    >>> printer.send(b"IMPORTANT SUMMARY\r\n")
    >>> printer.send(b"High quality conclusions\r\n")

FONT COMPATIBILITY:
    Only draft fonts work in draft mode:

    >>> # This WON'T work (Roman font requires NLQ)
    >>> from src.escp.commands.fonts import ESC_FONT_ROMAN
    >>> printer.send(ESC_DRAFT_MODE + ESC_FONT_ROMAN)  # Roman ignored!

    >>> # This WILL work
    >>> printer.send(ESC_SELECT_LQ + ESC_FONT_ROMAN)
    >>> printer.send(b"Roman font in NLQ mode")

PROPORTIONAL SPACING:
    Proportional spacing requires NLQ mode:

    >>> from src.escp.commands.fonts import ESC_PROPORTIONAL_ON
    >>>
    >>> # Must enable NLQ first
    >>> printer.send(ESC_SELECT_LQ + ESC_PROPORTIONAL_ON)
    >>> printer.send(b"Proportional spacing text")

PERFORMANCE OPTIMIZATION:
    For large documents, consider draft for bulk:

    >>> # Fast bulk printing
    >>> printer.send(ESC_SELECT_DRAFT)
    >>> for i in range(1000):
    ...     printer.send(f"Line {i}\r\n".encode())
    >>>
    >>> # Switch to NLQ for final page
    >>> printer.send(b"\x0c")  # Form feed
    >>> printer.send(ESC_SELECT_LQ)
    >>> printer.send(b"SUMMARY (high quality)\r\n")

PRINT TIME ESTIMATES:
    At 80 characters per line, 60 lines per page:

    Draft Mode (Normal Speed):
        - Lines per minute: ~314 lines (419 cps / 80 chars at 10 CPI)
        - Pages per minute: ~5.2 pages
        - Time for 100 pages: ~19 minutes

    Draft Mode (Ultra Speed):
        - Lines per minute: ~425 lines (566 cps / 80 chars at 10 CPI)
        - Pages per minute: ~7.1 pages
        - Time for 100 pages: ~14 minutes

    NLQ Mode:
        - Lines per minute: ~78 lines (104 cps / 80 chars at 10 CPI)
        - Pages per minute: ~1.3 pages
        - Time for 100 pages: ~77 minutes

QUALITY COMPARISON:
    Draft:  ••• ••• •••  (visible individual dots)

    NLQ:    ▓▓▓ ▓▓▓ ▓▓▓  (smoother, filled appearance)

DEFAULT BEHAVIOR:
    FX-890 defaults to draft mode after:
    - Power on
    - Printer reset (ESC @)
    - Paper jam recovery

TROUBLESHOOTING:
    If NLQ doesn't appear different:
    1. Check printer is actually in NLQ mode (test with Roman font)
    2. Verify ribbon is fresh (worn ribbon reduces quality difference)
    3. Check paper quality (cheap paper may not show NLQ benefits)
    4. Clean print head if quality is degraded

    If printing is too slow:
    1. Switch to draft mode for non-critical text
    2. Consider draft for internal documents
    3. Use NLQ only for final output or important sections
"""
