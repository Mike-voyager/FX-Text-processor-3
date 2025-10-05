"""
Special text effects commands for Epson FX-890.

Contains commands for superscript, subscript, and proportional spacing.
All commands verified for FX-890.

Reference: Epson FX-890 Technical Reference Manual, Chapter 4
"""

from typing import Final

__all__ = [
    "ESC_SUPERSCRIPT_ON",
    "ESC_SUBSCRIPT_ON",
    "ESC_SUPER_SUB_OFF",
]

# =============================================================================
# SUPERSCRIPT AND SUBSCRIPT
# =============================================================================

ESC_SUPERSCRIPT_ON: Final[bytes] = b"\x1bS\x00"
"""
Enable superscript mode.

Command: ESC S 0
Hex: 1B 53 00
Effect: Prints characters above normal baseline (e.g., x²)
Size: Characters are reduced in size (approximately 60%)
Position: Raised above baseline
Reset: Cancelled by ESC T or ESC_SUPER_SUB_OFF

Use Cases:
    - Mathematical exponents (x², y³)
    - Footnote markers (¹, ²)
    - Ordinal indicators (1ˢᵗ, 2ⁿᵈ)
    - Chemical formulas (H₂O needs subscript, not superscript)

Example:
    >>> # Print "E = mc²"
    >>> printer.send(b"E = mc")
    >>> printer.send(ESC_SUPERSCRIPT_ON)
    >>> printer.send(b"2")
    >>> printer.send(ESC_SUPER_SUB_OFF)
"""

ESC_SUBSCRIPT_ON: Final[bytes] = b"\x1bS\x01"
"""
Enable subscript mode.

Command: ESC S 1
Hex: 1B 53 01
Effect: Prints characters below normal baseline (e.g., H₂O)
Size: Characters are reduced in size (approximately 60%)
Position: Lowered below baseline
Reset: Cancelled by ESC T or ESC_SUPER_SUB_OFF

Use Cases:
    - Chemical formulas (H₂O, CO₂)
    - Mathematical notation (aₙ)
    - Variable subscripts (xᵢ, yⱼ)
    - Array indices (A₁, B₂)

Example:
    >>> # Print "H₂O"
    >>> printer.send(b"H")
    >>> printer.send(ESC_SUBSCRIPT_ON)
    >>> printer.send(b"2")
    >>> printer.send(ESC_SUPER_SUB_OFF)
    >>> printer.send(b"O")
"""

ESC_SUPER_SUB_OFF: Final[bytes] = b"\x1bT"
"""
Disable superscript/subscript mode.

Command: ESC T
Hex: 1B 54
Effect: Returns to normal baseline position
Size: Returns to normal character size
Reset: Default state after printer reset

Example:
    >>> # Print "x² + y²"
    >>> printer.send(b"x")
    >>> printer.send(ESC_SUPERSCRIPT_ON + b"2" + ESC_SUPER_SUB_OFF)
    >>> printer.send(b" + y")
    >>> printer.send(ESC_SUPERSCRIPT_ON + b"2" + ESC_SUPER_SUB_OFF)
"""

# =============================================================================
# USAGE EXAMPLES
# =============================================================================

"""
MATHEMATICAL FORMULAS:
    Powers and exponents:

    >>> # x² + y³ = z
    >>> printer.send(b"x")
    >>> printer.send(ESC_SUPERSCRIPT_ON + b"2" + ESC_SUPER_SUB_OFF)
    >>> printer.send(b" + y")
    >>> printer.send(ESC_SUPERSCRIPT_ON + b"3" + ESC_SUPER_SUB_OFF)
    >>> printer.send(b" = z\r\n")

    >>> # aⁿ where n > 0
    >>> printer.send(b"a")
    >>> printer.send(ESC_SUPERSCRIPT_ON + b"n" + ESC_SUPER_SUB_OFF)
    >>> printer.send(b" where n > 0\r\n")

CHEMICAL FORMULAS:
    >>> # H₂SO₄ (Sulfuric acid)
    >>> printer.send(b"H")
    >>> printer.send(ESC_SUBSCRIPT_ON + b"2" + ESC_SUPER_SUB_OFF)
    >>> printer.send(b"SO")
    >>> printer.send(ESC_SUBSCRIPT_ON + b"4" + ESC_SUPER_SUB_OFF)
    >>> printer.send(b"\r\n")

    >>> # CO₂ (Carbon dioxide)
    >>> printer.send(b"CO")
    >>> printer.send(ESC_SUBSCRIPT_ON + b"2" + ESC_SUPER_SUB_OFF)
    >>> printer.send(b"\r\n")

FOOTNOTE MARKERS:
    >>> # Main text with footnote reference
    >>> printer.send(b"This is the main text")
    >>> printer.send(ESC_SUPERSCRIPT_ON + b"1" + ESC_SUPER_SUB_OFF)
    >>> printer.send(b".\r\n\r\n")
    >>>
    >>> # Footnote at bottom
    >>> printer.send(ESC_SUPERSCRIPT_ON + b"1" + ESC_SUPER_SUB_OFF)
    >>> printer.send(b" This is the footnote text.\r\n")

ORDINAL INDICATORS:
    >>> # 1st, 2nd, 3rd, 4th
    >>> ordinals = [
    ...     ("1", "st"),
    ...     ("2", "nd"),
    ...     ("3", "rd"),
    ...     ("4", "th"),
    ... ]
    >>>
    >>> for num, suffix in ordinals:
    ...     printer.send(num.encode())
    ...     printer.send(ESC_SUPERSCRIPT_ON)
    ...     printer.send(suffix.encode())
    ...     printer.send(ESC_SUPER_SUB_OFF)
    ...     printer.send(b" place\r\n")

MATHEMATICAL SEQUENCES:
    >>> # aₙ = a₁ + (n-1)d
    >>> printer.send(b"a")
    >>> printer.send(ESC_SUBSCRIPT_ON + b"n" + ESC_SUPER_SUB_OFF)
    >>> printer.send(b" = a")
    >>> printer.send(ESC_SUBSCRIPT_ON + b"1" + ESC_SUPER_SUB_OFF)
    >>> printer.send(b" + (n-1)d\r\n")

COMPLEX EXPRESSIONS:
    Combining superscripts and subscripts:

    >>> # xᵢ² + yⱼ²
    >>> printer.send(b"x")
    >>> printer.send(ESC_SUBSCRIPT_ON + b"i" + ESC_SUPER_SUB_OFF)
    >>> printer.send(ESC_SUPERSCRIPT_ON + b"2" + ESC_SUPER_SUB_OFF)
    >>> printer.send(b" + y")
    >>> printer.send(ESC_SUBSCRIPT_ON + b"j" + ESC_SUPER_SUB_OFF)
    >>> printer.send(ESC_SUPERSCRIPT_ON + b"2" + ESC_SUPER_SUB_OFF)

UNITS OF MEASUREMENT:
    >>> # Area: 100 m² (square meters)
    >>> printer.send(b"Area: 100 m")
    >>> printer.send(ESC_SUPERSCRIPT_ON + b"2" + ESC_SUPER_SUB_OFF)
    >>> printer.send(b"\r\n")
    >>>
    >>> # Volume: 50 m³ (cubic meters)
    >>> printer.send(b"Volume: 50 m")
    >>> printer.send(ESC_SUPERSCRIPT_ON + b"3" + ESC_SUPER_SUB_OFF)
    >>> printer.send(b"\r\n")

SCIENTIFIC NOTATION:
    >>> # 6.02 × 10²³ (Avogadro's number)
    >>> printer.send(b"6.02 x 10")
    >>> printer.send(ESC_SUPERSCRIPT_ON + b"23" + ESC_SUPER_SUB_OFF)
    >>> printer.send(b"\r\n")

MULTIPLE SUBSCRIPTS:
    Array notation:

    >>> # A₁₂ (element at row 1, column 2)
    >>> printer.send(b"A")
    >>> printer.send(ESC_SUBSCRIPT_ON + b"12" + ESC_SUPER_SUB_OFF)
    >>> printer.send(b"\r\n")

SIZE AND POSITIONING NOTES:
    Superscript/subscript characteristics:
    - Character size: ~60% of normal size
    - Vertical offset: ~33% of character height
    - Width: Proportional to reduced size
    - Spacing: Automatically adjusted

COMBINING WITH OTHER FORMATTING:
    Super/subscript works with other formatting:

    >>> from src.escp.commands.text_formatting import ESC_BOLD_ON, ESC_BOLD_OFF
    >>>
    >>> # Bold superscript
    >>> printer.send(b"x")
    >>> printer.send(ESC_BOLD_ON + ESC_SUPERSCRIPT_ON)
    >>> printer.send(b"2")
    >>> printer.send(ESC_SUPER_SUB_OFF + ESC_BOLD_OFF)

AVOIDING OVERLAP:
    Ensure adequate line spacing:

    >>> from src.escp.commands.line_spacing import set_line_spacing_n_216
    >>>
    >>> # Increase line spacing for super/subscripts
    >>> printer.send(set_line_spacing_n_216(45))  # ~1/5 inch
    >>> printer.send(b"x")
    >>> printer.send(ESC_SUPERSCRIPT_ON + b"2" + ESC_SUPER_SUB_OFF)
    >>> printer.send(b"\r\n")
    >>> printer.send(b"y")
    >>> printer.send(ESC_SUBSCRIPT_ON + b"2" + ESC_SUPER_SUB_OFF)
    >>> printer.send(b"\r\n")

NLQ MODE RECOMMENDATION:
    Better quality for small super/subscripts:

    >>> from src.escp.commands.print_quality import ESC_SELECT_LQ
    >>>
    >>> # Use NLQ for better readability
    >>> printer.send(ESC_SELECT_LQ)
    >>> printer.send(b"H")
    >>> printer.send(ESC_SUBSCRIPT_ON + b"2" + ESC_SUPER_SUB_OFF)
    >>> printer.send(b"O\r\n")

PERFORMANCE NOTES:
    - No speed penalty for super/subscript
    - Character size reduction handled by font ROM
    - Positioning is automatic

LIMITATIONS:
    - Cannot nest super/subscripts (e.g., no (x²)³)
    - Size is fixed at ~60% (not adjustable)
    - Vertical offset is fixed (not adjustable)
    - May be difficult to read at small sizes

TROUBLESHOOTING:
    If super/subscript doesn't appear:
    1. Check ESC_SUPER_SUB_OFF is called to return to normal
    2. Verify printer supports super/subscript (all FX-890 do)
    3. Try NLQ mode for better visibility
    4. Increase line spacing if overlapping

    If characters are too small:
    1. This is expected behavior (~60% reduction)
    2. Use NLQ mode for better quality
    3. Consider using normal size with positioning commands instead
    4. Increase font size before enabling super/subscript (e.g., 12 CPI)

    If spacing looks wrong:
    1. Check line spacing setting
    2. Increase spacing for documents with many super/subscripts
    3. Add extra line feed if needed
"""
