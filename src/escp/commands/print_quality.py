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
Speed: ~680 characters per second
Quality: Standard readability, visible dot matrix pattern
Font Availability: Draft fonts only (Roman/Sans Serif unavailable)
Use Case: High-volume printing, internal documents, drafts
Reset: Changed by ESC x 1 or printer reset (default is draft)

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
Speed: ~227 characters per second (3× slower than draft)
Quality: Smoother characters, less visible dot matrix
Font Availability: All fonts (Draft, Roman, Sans Serif)
Use Case: Final documents, external correspondence, presentations
Reset: Changed by ESC x 0

Example:
    >>> printer.send(ESC_LQ_MODE)
    >>> printer.send(b"High quality NLQ text")
"""

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
        - Speed: 680 cps
        - Quality: Visible dot matrix
        - Fonts: Draft only
        - Use: Internal documents, high-volume

    NLQ Mode:
        - Speed: 227 cps (~33% of draft speed)
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

    Draft Mode:
        - Lines per minute: ~510 lines (680 cps / 80 chars)
        - Pages per minute: ~8.5 pages (510 / 60 lines)
        - Time for 100 pages: ~12 minutes

    NLQ Mode:
        - Lines per minute: ~170 lines (227 cps / 80 chars)
        - Pages per minute: ~2.8 pages (170 / 60 lines)
        - Time for 100 pages: ~36 minutes

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
