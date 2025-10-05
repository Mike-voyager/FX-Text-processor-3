"""
Shading and fill patterns for Epson FX-890/ESC/P.

Provides byte values for classic "shading" symbols (░▒▓█) and similar on dot-matrix printers.
These patterns are used for tables, pseudo-graphics, block fills and decorative frames,
and correspond to code points in PC437, PC866, PC850 tables.

Reference:
- IBM PC437 (Code page 437), PC866
- Epson FX-890 Technical Reference
"""

from typing import Final

__all__ = [
    "SHADE_LIGHT",
    "SHADE_MEDIUM",
    "SHADE_DARK",
    "SHADE_SOLID",
    "SHADE_LIST",
    "get_shade_byte",
]

# =============================================================================
# SHADING SYMBOL CONSTANTS
# =============================================================================

# Common code points for shading (PC437, PC866, PC850)
SHADE_LIGHT: Final[int] = 0xB0  # ░ Light shade
SHADE_MEDIUM: Final[int] = 0xB1  # ▒ Medium shade
SHADE_DARK: Final[int] = 0xB2  # ▓ Dark shade
SHADE_SOLID: Final[int] = 0xDB  # █ Solid block (commonly used as "full fill")

# For quick access: a list of all ASCII bytes (for table rendering)
SHADE_LIST: Final[list[int]] = [SHADE_LIGHT, SHADE_MEDIUM, SHADE_DARK, SHADE_SOLID]


def get_shade_byte(level: int) -> int:
    """
    Get code point for shading symbol by level (0=light, 1=medium, 2=dark, 3=solid).
    Args:
        level: 0-light, 1-medium, 2-dark, 3-solid/fill

    Returns:
        Byte value (int, 0..255) for encoding to printer.

    Example:
        >>> # Print a dark shade
        >>> printer.send(bytes([get_shade_byte(2)] * 80) + b"\r\n")
    """
    return SHADE_LIST[max(0, min(level, 3))]


# =============================================================================
# USAGE EXAMPLES
# =============================================================================

"""
EXAMPLES OF USAGE

# Print a "bar" of medium shading:
>>> from src.escp.commands.shading import SHADE_MEDIUM
>>> printer.send(bytes([SHADE_MEDIUM] * 60) + b"\r\n")

# Print all shades (block demo):
>>> for shade in SHADE_LIST:
...     printer.send(bytes([shade] * 20) + b"\r\n")

# Draw a table cell with dark fill:
>>> printer.send(b"|" + bytes([SHADE_DARK] * 10) + b"|\r\n")

Compatibility:
    - Works in PC437, PC866, PC850 (default Epson tables)
    - Characters ░▒▓█ map to bytes 0xB0, 0xB1, 0xB2, 0xDB in these tables
    - For other codepages, check mapping table

Tips:
    - Combine with PC866 for Russian/box drawing tables
    - For borders use ║═╔╗╚╝ (see code points in box drawing reference)

If you need Unicode → codepage mapping:
    >>> def unicode_shade_to_byte(shade_char: str) -> int:
    ...     lookup = {'░': 0xB0, '▒': 0xB1, '▓': 0xB2, '█': 0xDB}
    ...     return lookup.get(shade_char, ord(shade_char))
"""

# You may also extend to include box-drawing characters if needed,
# for full table/ASCII art rendering.
