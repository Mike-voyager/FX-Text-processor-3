"""
ESC/P command constants for Epson FX-890 dot matrix printer.

This package contains low-level ESC/P command constants verified against
the Epson FX-890 technical reference manual. All commands are tested and
confirmed to work with FX-890 hardware.

Module Structure:
    commands/
    ├── __init__.py             # This file (public API exports)
    ├── text_formatting.py      # Bold, italic, underline, strike
    ├── fonts.py                # Font selection, CPI, typeface
    ├── sizing.py               # Double-width/height, condensed
    ├── positioning.py          # Horizontal/vertical positioning
    ├── line_spacing.py         # Line feed, custom spacing
    ├── print_quality.py        # Draft/LQ/NLQ modes
    ├── graphics.py             # Bit-image and raster graphics
    ├── barcode.py              # Barcode generation
    ├── page_control.py         # Margins, page length, tabs
    ├── hardware.py             # Printer control, reset, beep
    ├── charset.py              # Character tables, international sets
    └── special_effects.py      # Superscript, subscript, proportional

Version: 1.0
Target Printer: Epson FX-890 (9-pin dot matrix)
ESC/P Version: Standard ESC/P (not ESC/P2)
Character Set: PC866 (Cyrillic) primary, with dynamic switching

Compatibility Notes:
    - FX-890 uses classic ESC/P (not ESC/P2)
    - Maximum resolution: 240×144 DPI
    - Monochrome only (black & white)
    - 9-pin print head (400M character life)
    - Supports both draft and NLQ (Near Letter Quality)

Usage:
    >>> from src.escp.commands import ESC_BOLD_ON, ESC_BOLD_OFF
    >>> command = ESC_BOLD_ON + b"Bold text" + ESC_BOLD_OFF
    >>> printer.send(command)

Public API:
    All command constants are re-exported from this module for convenience.
    Import either from specific modules or from this package root.

Example:
    >>> # Import from package root
    >>> from src.escp.commands import ESC_BOLD_ON, ESC_ITALIC_ON
    >>>
    >>> # Or from specific module
    >>> from src.escp.commands.text_formatting import ESC_BOLD_ON
"""

# Text formatting commands
from src.escp.commands.text_formatting import (
    ESC_BOLD_ON,
    ESC_BOLD_OFF,
    ESC_ITALIC_ON,
    ESC_ITALIC_OFF,
    ESC_UNDERLINE_ON,
    ESC_UNDERLINE_DOUBLE,
    ESC_UNDERLINE_OFF,
    ESC_DOUBLE_STRIKE_ON,
    ESC_DOUBLE_STRIKE_OFF,
)

# Shading commands
from src.escp.commands.shading import (
    SHADE_LIGHT,
    SHADE_MEDIUM,
    SHADE_DARK,
    SHADE_SOLID,
    SHADE_LIST,
    get_shade_byte,
)

# Font and CPI commands
from src.escp.commands.fonts import (
    ESC_FONT_DRAFT,
    ESC_FONT_ROMAN,
    ESC_FONT_SANS_SERIF,
    ESC_10CPI,
    ESC_12CPI,
    ESC_15CPI,
    ESC_PROPORTIONAL_ON,
    ESC_PROPORTIONAL_OFF,
    set_cpi,
    set_character_spacing,
)

# Sizing commands
from src.escp.commands.sizing import (
    SI,
    DC2,
    ESC_CONDENSED_ON,
    ESC_CONDENSED_OFF,
    ESC_DOUBLE_WIDTH_ON,
    ESC_DOUBLE_WIDTH_OFF,
    ESC_DOUBLE_HEIGHT_ON,
    ESC_DOUBLE_HEIGHT_OFF,
)

# Positioning commands
from src.escp.commands.positioning import (
    CR,
    LF,
    FF,
    BS,
    HT,
    VT,
    CRLF,
    set_horizontal_position,
    set_relative_horizontal_position,
)

# Line spacing commands
from src.escp.commands.line_spacing import (
    ESC_LINE_SPACING_1_6,
    ESC_LINE_SPACING_1_8,
    ESC_LINE_SPACING_7_72,
    set_line_spacing_n_216,
    set_line_spacing_n_72,
)

# Print quality commands
from src.escp.commands.print_quality import (
    ESC_DRAFT_MODE,
    ESC_LQ_MODE,
    ESC_SELECT_LQ,
    ESC_SELECT_DRAFT,
)

# Graphics commands
from src.escp.commands.graphics import (
    GraphicsMode,
    print_bit_image,
    print_raster_graphics,
)

# Barcode commands
from src.escp.commands.barcode import (
    BarcodeType,
    BarcodeHRI,
    print_barcode,
)

# Page control commands
from src.escp.commands.page_control import (
    set_left_margin,
    set_right_margin,
    set_page_length,
    set_horizontal_tabs,
    set_vertical_tabs,
    cancel_horizontal_tabs,
    cancel_vertical_tabs,
)

# Hardware control commands
from src.escp.commands.hardware import (
    ESC_INIT_PRINTER,
    ESC_BEEP,
    ESC_ONLINE,
    ESC_OFFLINE,
)

# Character set commands
from src.escp.commands.charset import (
    CharacterTable,
    InternationalCharset,
    set_character_table,
    set_international_charset,
)

# Special effects commands
from src.escp.commands.special_effects import (
    ESC_SUPERSCRIPT_ON,
    ESC_SUBSCRIPT_ON,
    ESC_SUPER_SUB_OFF,
)

__all__ = [
    # Text formatting
    "ESC_BOLD_ON",
    "ESC_BOLD_OFF",
    "ESC_ITALIC_ON",
    "ESC_ITALIC_OFF",
    "ESC_UNDERLINE_ON",
    "ESC_UNDERLINE_DOUBLE",
    "ESC_UNDERLINE_OFF",
    "ESC_DOUBLE_STRIKE_ON",
    "ESC_DOUBLE_STRIKE_OFF",
    # Fonts
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
    # Shading
    "SHADE_LIGHT",
    "SHADE_MEDIUM",
    "SHADE_DARK",
    "SHADE_SOLID",
    "SHADE_LIST",
    "get_shade_byte",
    # Sizing
    "SI",
    "DC2",
    "ESC_CONDENSED_ON",
    "ESC_CONDENSED_OFF",
    "ESC_DOUBLE_WIDTH_ON",
    "ESC_DOUBLE_WIDTH_OFF",
    "ESC_DOUBLE_HEIGHT_ON",
    "ESC_DOUBLE_HEIGHT_OFF",
    # Positioning
    "CR",
    "LF",
    "FF",
    "BS",
    "HT",
    "VT",
    "CRLF",
    "set_horizontal_position",
    "set_relative_horizontal_position",
    # Line spacing
    "ESC_LINE_SPACING_1_6",
    "ESC_LINE_SPACING_1_8",
    "ESC_LINE_SPACING_7_72",
    "set_line_spacing_n_216",
    "set_line_spacing_n_72",
    # Print quality
    "ESC_DRAFT_MODE",
    "ESC_LQ_MODE",
    "ESC_SELECT_LQ",
    "ESC_SELECT_DRAFT",
    # Graphics
    "GraphicsMode",
    "print_bit_image",
    "print_raster_graphics",
    # Barcode
    "BarcodeType",
    "BarcodeHRI",
    "print_barcode",
    # Page control
    "set_left_margin",
    "set_right_margin",
    "set_page_length",
    "set_horizontal_tabs",
    "set_vertical_tabs",
    "cancel_horizontal_tabs",
    "cancel_vertical_tabs",
    # Hardware
    "ESC_INIT_PRINTER",
    "ESC_BEEP",
    "ESC_ONLINE",
    "ESC_OFFLINE",
    # Charset
    "CharacterTable",
    "InternationalCharset",
    "set_character_table",
    "set_international_charset",
    # Special effects
    "ESC_SUPERSCRIPT_ON",
    "ESC_SUBSCRIPT_ON",
    "ESC_SUPER_SUB_OFF",
]
