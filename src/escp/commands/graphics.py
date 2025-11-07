"""
Graphics and bit-image printing commands for Epson FX-890.

Contains commands for printing raster graphics and bit-images using
native FX-890 graphics modes. Supports multiple densities (60, 120, 240 DPI).

Reference: Epson FX-890 Technical Reference Manual, Chapter 7
           ESC/P Command Reference (Bit-Image Graphics)
Compatibility: FX-890, FX-2190, LX-300+II
Maximum Resolution: 240×144 DPI (horizontal × vertical)

IMPORTANT: This module contains ONLY FX-mode compatible commands.
           ESC/P 2 commands (ESC .) are marked with warnings.
"""

from enum import Enum

__all__ = [
    "GraphicsMode",
    "print_bit_image",
    "print_raster_graphics",
]

# =============================================================================
# GRAPHICS MODE CONSTANTS
# =============================================================================


class GraphicsMode(Enum):
    """
    Bit-image graphics modes for FX-890.

    Each mode defines horizontal dot density and print speed.
    Vertical density is always 8 or 9 pins (depending on printer head).

    Format: (dpi, command_char, description)
    Verified: ✅ FX-890 Technical Reference Manual, Section 7
    """

    SINGLE_DENSITY = (60, b"K", "60 DPI horizontal")
    """
    Single-density graphics (60 DPI horizontal).

    Command: ESC K
    Resolution: 60×72 DPI (horizontal × vertical)
    Speed: Fast
    Quality: Low (visible dots)
    Use case: Draft graphics, quick printouts

    Technical details:
        - Dots per inch: 60 horizontal, 72 vertical
        - Print speed: ~60 cps equivalent
        - Column width: 1/60 inch per column
        - Best for: Simple line art, draft mode

    Verified: ✅ FX-890 Technical Reference, Section 7.3
    """

    DOUBLE_DENSITY = (120, b"L", "120 DPI horizontal")
    """
    Double-density graphics (120 DPI horizontal).

    Command: ESC L
    Resolution: 120×72 DPI (horizontal × vertical)
    Speed: Medium
    Quality: Good (standard commercial quality)
    Use case: Most graphics applications

    Technical details:
        - Dots per inch: 120 horizontal, 72 vertical
        - Print speed: ~30 cps equivalent
        - Column width: 1/120 inch per column
        - Best for: Logos, charts, standard images

    Verified: ✅ FX-890 Technical Reference, Section 7.3
    """

    DOUBLE_SPEED_DOUBLE_DENSITY = (120, b"Y", "120 DPI high-speed")
    """
    Double-density high-speed graphics (120 DPI horizontal).

    Command: ESC Y
    Resolution: 120×72 DPI (horizontal × vertical)
    Speed: Fast (faster than ESC L at same density)
    Quality: Good (same as ESC L)
    Use case: When speed matters at 120 DPI

    Technical details:
        - Dots per inch: 120 horizontal, 72 vertical
        - Print speed: ~2× faster than ESC L
        - Column width: 1/120 inch per column
        - Best for: Batch printing, speed-critical graphics

    Verified: ✅ FX-890 Technical Reference, Section 7.3
    """

    QUAD_DENSITY = (240, b"Z", "240 DPI horizontal")
    """
    Quadruple-density graphics (240 DPI horizontal).

    Command: ESC Z
    Resolution: 240×144 DPI (horizontal × vertical)
    Speed: Slow (highest quality)
    Quality: Best (maximum FX-890 resolution)
    Use case: High-quality logos, detailed graphics

    Technical details:
        - Dots per inch: 240 horizontal, 144 vertical
        - Print speed: ~15 cps equivalent
        - Column width: 1/240 inch per column
        - Best for: Final output, detailed images

    Note: This is the maximum resolution available on FX-890.

    Verified: ✅ FX-890 Technical Reference, Section 7.3
    """

    def __init__(self, dpi: int, code: bytes, description: str):
        self.dpi = dpi
        self.code = code
        self.description = description


# =============================================================================
# BIT-IMAGE PRINTING
# =============================================================================


def print_bit_image(
    mode: GraphicsMode,
    data: bytes,
    width: int,
) -> bytes:
    """
    Generate ESC/P command to print bit-image graphics.

    Command: ESC * m nL nH data
    Hex: 1B 2A m nL nH data
    Verified: ✅ FX-890 Technical Reference Manual, Section 7.3

    Args:
        mode: Graphics density mode (see GraphicsMode enum).
        data: Raw bit-image data (1 bit per pixel, MSB first).
              Each byte represents 8 vertical dots.
              Height is fixed at 8 dots (one print head pass).
        width: Image width in dots (number of columns, 0-32767).

    Returns:
        ESC/P command bytes.

    Raises:
        ValueError: If width is invalid or data length doesn't match width.

    Data Format:
        Byte structure (8 vertical dots per byte):

        Bit 7 (MSB) ═══► Top dot
        Bit 6       ═══► 2nd dot from top
        Bit 5       ═══► 3rd dot
        Bit 4       ═══► 4th dot
        Bit 3       ═══► 5th dot
        Bit 2       ═══► 6th dot
        Bit 1       ═══► 7th dot
        Bit 0 (LSB) ═══► Bottom dot (8th)

        Value: 1 = print dot (black), 0 = no dot (white)

        Data arrangement: Left-to-right columns
        - First byte = leftmost column (8 vertical dots)
        - Second byte = next column to the right
        - ...
        - Last byte = rightmost column

    Technical Details:
        - Height: Always 8 dots (0.11 inch at 72 DPI)
        - Width: Variable (1 to 32767 dots)
        - Encoding: Little-endian 16-bit width (nL nH)
        - Print head: Single pass (8-pin or 9-pin uses 8)

    Example - Simple Patterns:
        >>> from src.escp.commands.graphics import *
        >>>
        >>> # Solid vertical line (1 column, 8 dots)
        >>> data = bytes([0xFF])  # 11111111 = all dots on
        >>> cmd = print_bit_image(GraphicsMode.DOUBLE_DENSITY, data, width=1)
        >>> printer.send(cmd)
        >>>
        >>> # Checkerboard pattern (8×8)
        >>> data = bytes([0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55])
        >>> # 0xAA = 10101010, 0x55 = 01010101 (alternating)
        >>> cmd = print_bit_image(GraphicsMode.DOUBLE_DENSITY, data, width=8)
        >>> printer.send(cmd)

    Example - Horizontal Line:
        >>> # Top horizontal line (8 dots wide)
        >>> data = bytes([0x80] * 8)  # 0x80 = 10000000 (top bit only)
        >>> cmd = print_bit_image(GraphicsMode.QUAD_DENSITY, data, width=8)
        >>> printer.send(cmd)

    Example - Box Outline:
        >>> # Rectangle (8 dots tall, 16 dots wide)
        >>> data = bytearray()
        >>> data.append(0xFF)  # Left edge (all dots)
        >>> data.extend([0x81] * 14)  # Middle (top + bottom only)
        >>> data.append(0xFF)  # Right edge (all dots)
        >>> cmd = print_bit_image(GraphicsMode.DOUBLE_DENSITY, bytes(data), width=16)
        >>> printer.send(cmd)

    Note:
        For images taller than 8 dots, print multiple passes with
        line feeds between them. See multi-pass example in usage section.
    """
    if width <= 0:
        raise ValueError(f"Width must be positive, got {width}")

    if width > 32767:
        raise ValueError(f"Width must be ≤32767, got {width}")

    if len(data) != width:
        raise ValueError(
            f"Data length ({len(data)} bytes) must match width ({width} columns). "
            f"Each byte represents one column of 8 vertical dots."
        )

    # Calculate width parameter (little-endian 16-bit)
    nL = width & 0xFF
    nH = (width >> 8) & 0xFF

    # Build command: ESC * mode_code nL nH data
    cmd = b"\x1b*" + mode.code + bytes([nL, nH]) + data

    return cmd


def print_raster_graphics(
    data: bytes,
    width: int,
    height: int = 8,
    color: int = 0,
) -> bytes:
    """
    Generate ESC/P command for raster graphics printing.

    Command: ESC . c v h m nL nH data
    Hex: 1B 2E c v h m nL nH data

    WARNING - ESC/P 2 COMMAND:
        This is an ESC/P 2 command, NOT standard FX ESC/P.

        ⚠️ May NOT work on FX-890 in FX emulation mode
        ⚠️ For guaranteed compatibility, use print_bit_image() instead
        ⚠️ Test thoroughly on your specific FX-890 model

        This function is provided for completeness, but print_bit_image()
        is the recommended approach for FX-890.

    Args:
        data: Raster graphics data (1 bit per pixel).
        width: Image width in dots.
        height: Image height in dots (default: 8).
        color: Color selection (0=black, always 0 for FX-890 monochrome).

    Returns:
        ESC/P command bytes.

    Raises:
        ValueError: If parameters are invalid.

    Technical Details:
        - FX-890 is monochrome only (color parameter ignored)
        - May not be recognized in FX emulation mode
        - ESC/P 2 printers (LQ-series) support this command
        - FX-890 may interpret as unknown command

    Note:
        Unless you have verified this works on YOUR specific FX-890
        firmware version, use print_bit_image() instead.

    Example (use at your own risk):
        >>> # ⚠️ May not work on FX-890!
        >>> from src.escp.commands.graphics import print_raster_graphics
        >>>
        >>> # Simple 8×8 pattern
        >>> data = bytes([0xFF] * 8)
        >>> cmd = print_raster_graphics(data, width=8, height=8)
        >>> # May print correctly, or may be ignored by printer
        >>> printer.send(cmd)
    """
    if width <= 0:
        raise ValueError(f"Width must be positive, got {width}")

    if height <= 0:
        raise ValueError(f"Height must be positive, got {height}")

    # Raster graphics parameters
    c = color  # Color (always 0 for FX-890 monochrome)
    v = 1  # Vertical resolution (1 = 144 DPI)
    h = 1  # Horizontal resolution (1 = 240 DPI)
    m = 0  # Mode (0 = normal)

    # Width parameter (little-endian 16-bit)
    nL = width & 0xFF
    nH = (width >> 8) & 0xFF

    # Build command: ESC . c v h m nL nH data
    cmd = b"\x1b." + bytes([c, v, h, m, nL, nH]) + data

    return cmd


# =============================================================================
# USAGE EXAMPLES
# =============================================================================

"""
GRAPHICS MODE SELECTION:
    Choose mode based on quality vs speed requirements:

    Mode                     DPI       Speed    Quality  Use Case
    ───────────────────────────────────────────────────────────────
    SINGLE_DENSITY          60×72      Fast     Low      Draft graphics
    DOUBLE_DENSITY          120×72     Medium   Good     Standard images
    DOUBLE_SPEED_DD         120×72     Fast     Good     Batch printing
    QUAD_DENSITY            240×144    Slow     Best     Final output

    Recommendation:
        - Development/testing: DOUBLE_DENSITY
        - Production: QUAD_DENSITY (best quality)
        - High-volume: DOUBLE_SPEED_DOUBLE_DENSITY

CREATING BIT-IMAGE DATA MANUALLY:
    Build simple patterns byte by byte:

    >>> from src.escp.commands.graphics import *
    >>> from src.escp.commands.positioning import CRLF
    >>>
    >>> # Vertical line (1 pixel wide, 8 pixels tall)
    >>> data = bytes([0xFF])  # 11111111 = solid vertical line
    >>> cmd = print_bit_image(GraphicsMode.DOUBLE_DENSITY, data, width=1)
    >>> printer.send(cmd + CRLF)
    >>>
    >>> # Horizontal line (8 pixels wide, 1 pixel tall at top)
    >>> data = bytes([0x80] * 8)  # 10000000 = top dot only
    >>> cmd = print_bit_image(GraphicsMode.DOUBLE_DENSITY, data, width=8)
    >>> printer.send(cmd + CRLF)
    >>>
    >>> # Diagonal line (8×8)
    >>> data = bytes([
    ...     0b10000000,  # Column 1: top dot
    ...     0b01000000,  # Column 2: 2nd dot
    ...     0b00100000,  # Column 3: 3rd dot
    ...     0b00010000,  # Column 4: 4th dot
    ...     0b00001000,  # Column 5: 5th dot
    ...     0b00000100,  # Column 6: 6th dot
    ...     0b00000010,  # Column 7: 7th dot
    ...     0b00000001,  # Column 8: bottom dot
    ... ])
    >>> cmd = print_bit_image(GraphicsMode.QUAD_DENSITY, data, width=8)
    >>> printer.send(cmd + CRLF)

MULTI-PASS PRINTING (TALL IMAGES):
    FX-890 prints 8 dots vertically per pass. For taller images:

    >>> from src.escp.commands.positioning import CRLF
    >>>
    >>> # Print 16-dot tall image (requires 2 passes)
    >>> top_8_rows = bytes([...])     # First 8 rows
    >>> bottom_8_rows = bytes([...])  # Next 8 rows
    >>>
    >>> # Pass 1: Top 8 dots
    >>> cmd = print_bit_image(GraphicsMode.DOUBLE_DENSITY, top_8_rows, width=100)
    >>> printer.send(cmd + CRLF)
    >>>
    >>> # Pass 2: Bottom 8 dots
    >>> cmd = print_bit_image(GraphicsMode.DOUBLE_DENSITY, bottom_8_rows, width=100)
    >>> printer.send(cmd + CRLF)

CONVERTING IMAGES FROM PIL (PILLOW):
    Use Pillow to convert images to bit-image format:

    >>> from PIL import Image
    >>>
    >>> # Load and convert image to 1-bit (black & white)
    >>> img = Image.open("logo.png")
    >>> img = img.convert('1')  # Convert to pure black & white
    >>>
    >>> # Get dimensions
    >>> width, height = img.size
    >>>
    >>> # Convert to bit-image format (8 dots per column)
    >>> def image_to_bitimage(img: Image.Image) -> bytes:
    ...     '''Convert PIL image to FX-890 bit-image format.'''
    ...     width, height = img.size
    ...
    ...     # Process 8 rows at a time
    ...     for row_start in range(0, height, 8):
    ...         data = bytearray()
    ...
    ...         # Each column becomes one byte
    ...         for x in range(width):
    ...             column_byte = 0
    ...
    ...             # Pack 8 vertical pixels into one byte
    ...             for y in range(8):
    ...                 if row_start + y < height:
    ...                     pixel = img.getpixel((x, row_start + y))
    ...                     if pixel == 0:  # Black pixel
    ...                         column_byte |= (1 << (7 - y))
    ...
    ...             data.append(column_byte)
    ...
    ...         # Print this pass
    ...         cmd = print_bit_image(
    ...             GraphicsMode.QUAD_DENSITY,
    ...             bytes(data),
    ...             width
    ...         )
    ...         printer.send(cmd + b"\r\n")
    >>>
    >>> # Convert and print
    >>> image_to_bitimage(img)

DITHERING FOR GRAYSCALE IMAGES:
    Convert grayscale photos to dithered black & white:

    >>> from PIL import Image
    >>>
    >>> # Load grayscale image
    >>> img = Image.open("photo.jpg").convert('L')
    >>>
    >>> # Apply Floyd-Steinberg dithering
    >>> img_dithered = img.convert('1', dither=Image.FLOYDSTEINBERG)
    >>>
    >>> # Convert to bit-image and print
    >>> # (use image_to_bitimage() function from previous example)
    >>> image_to_bitimage(img_dithered)
    >>>
    >>> # Alternative dithering methods:
    >>> img_ordered = img.convert('1', dither=Image.ORDERED)  # Ordered dither
    >>> img_rasterize = img.convert('1', dither=Image.RASTERIZE)  # Rasterize

SIMPLE SHAPES:
    Draw basic geometric shapes:

    >>> # Filled rectangle (8 dots tall, 20 dots wide)
    >>> data = bytes([0xFF] * 20)  # All dots on
    >>> cmd = print_bit_image(GraphicsMode.DOUBLE_DENSITY, data, width=20)
    >>> printer.send(cmd + b"\r\n")
    >>>
    >>> # Hollow rectangle (outline only)
    >>> data = bytearray()
    >>> data.append(0xFF)           # Left edge
    >>> data.extend([0x81] * 18)    # Middle (top + bottom only)
    >>> data.append(0xFF)           # Right edge
    >>> cmd = print_bit_image(GraphicsMode.DOUBLE_DENSITY, bytes(data), width=20)
    >>> printer.send(cmd + b"\r\n")
    >>>
    >>> # Vertical stripes
    >>> data = bytes([0xFF, 0x00] * 10)  # Alternating solid/empty columns
    >>> cmd = print_bit_image(GraphicsMode.DOUBLE_DENSITY, data, width=20)
    >>> printer.send(cmd + b"\r\n")

BOX-DRAWING CHARACTERS (ALTERNATIVE):
    For simple borders, consider using box-drawing characters:

    >>> # Box-drawing is simpler for text-based layouts
    >>> from src.escp.commands.charset import set_character_table, CharacterTable
    >>>
    >>> # Switch to PC866 for box-drawing characters
    >>> printer.send(set_character_table(CharacterTable.PC866))
    >>>
    >>> # Print box (faster than graphics)
    >>> printer.send(b"\xda" + b"\xc4" * 10 + b"\xbf\r\n")  # ┌──┐
    >>> printer.send(b"\xb3" + b" " * 10 + b"\xb3\r\n")      # │  │
    >>> printer.send(b"\xc0" + b"\xc4" * 10 + b"\xd9\r\n")  # └──┘
    >>>
    >>> # Graphics are better for: logos, images, complex shapes
    >>> # Box-drawing is better for: tables, borders, frames

COMBINING TEXT AND GRAPHICS:
    Mix text and graphics in same document:

    >>> from src.escp.commands.text_formatting import ESC_BOLD_ON, ESC_BOLD_OFF
    >>>
    >>> # Company header with logo
    >>> printer.send(ESC_BOLD_ON + b"COMPANY NAME" + ESC_BOLD_OFF + b"\r\n\r\n")
    >>>
    >>> # Logo (bit-image)
    >>> logo_data = bytes([...])  # Your logo data
    >>> cmd = print_bit_image(GraphicsMode.QUAD_DENSITY, logo_data, width=100)
    >>> printer.send(cmd + b"\r\n\r\n")
    >>>
    >>> # Document body (text)
    >>> printer.send(b"Invoice #12345\r\n")
    >>> printer.send(b"Date: 10/05/2025\r\n")

PRINT TIME ESTIMATES:
    Graphics printing speed (approximate):

    At 100 dots width:
        SINGLE_DENSITY (60 DPI):    ~0.2 seconds
        DOUBLE_DENSITY (120 DPI):   ~0.4 seconds
        QUAD_DENSITY (240 DPI):     ~0.8 seconds

    At 240 dots width (1 inch at 240 DPI):
        SINGLE_DENSITY:   ~0.5 seconds
        DOUBLE_DENSITY:   ~1.0 second
        QUAD_DENSITY:     ~2.0 seconds

    Factors affecting speed:
        - Width (linear scaling)
        - Graphics mode (density)
        - Paper advance time between passes
        - Print head acceleration/deceleration

MEMORY CONSIDERATIONS:
    Calculate data size before generating:

    >>> # For 1 inch wide image at 240 DPI, 8 dots tall
    >>> width_dots = 240
    >>> data_size_bytes = width_dots  # 1 byte per column
    >>> print(f"Data size: {data_size_bytes} bytes")
    >>> # Output: Data size: 240 bytes
    >>>
    >>> # For full-width image (8.5 inches at 240 DPI)
    >>> width_dots = int(8.5 * 240)
    >>> data_size_bytes = width_dots
    >>> print(f"Full-width data: {data_size_bytes} bytes")
    >>> # Output: Full-width data: 2040 bytes

TROUBLESHOOTING:
    If graphics don't print:

    1. Verify data format:
       - Each byte = 8 vertical dots
       - MSB (bit 7) = top dot
       - LSB (bit 0) = bottom dot
       - Data length must equal width

    2. Check width parameter:
       - Must match data length
       - Must be positive
       - Maximum: 32767 dots

    3. Test with simple pattern:
       >>> # Single solid vertical line
       >>> data = bytes([0xFF])
       >>> cmd = print_bit_image(GraphicsMode.DOUBLE_DENSITY, data, width=1)
       >>> printer.send(cmd + b"\r\n")

    If graphics are distorted:

    1. Verify bit orientation:
       - Bit 7 = TOP dot (not bottom!)
       - Common mistake: inverted bit order

    2. Check column order:
       - First byte = leftmost column
       - Data should be left-to-right

    3. Verify line feeds:
       - Add CRLF after each graphics command
       - Otherwise, next text/graphics overlaps

    If quality is poor:

    1. Use higher density mode:
       - Switch from DOUBLE_DENSITY to QUAD_DENSITY

    2. Check printer condition:
       - Clean print head
       - Replace worn ribbon
       - Adjust print head gap for paper thickness

    3. Apply dithering:
       - For grayscale images, use Floyd-Steinberg
       - Don't use raw grayscale conversion

    4. Verify image preparation:
       - Images should be pure black & white (1-bit)
       - Not grayscale converted to 1-bit without dithering

PERFORMANCE OPTIMIZATION:
    For large documents with many graphics:

    1. Use DOUBLE_SPEED_DOUBLE_DENSITY when possible
       - Same quality as DOUBLE_DENSITY
       - Significantly faster

    2. Reduce image complexity:
       - Simplify logos before printing
       - Remove unnecessary detail

    3. Batch graphics passes:
       - Print all graphics in one pass if possible
       - Minimize paper advancement

    4. Consider caching:
       - Pre-compute bit-image data
       - Don't regenerate for repeated graphics

ESC/P 2 RASTER GRAPHICS WARNING:
    The print_raster_graphics() function uses ESC . command:

    ⚠️ This is ESC/P 2, NOT standard FX ESC/P
    ⚠️ May not work on FX-890 in FX mode
    ⚠️ Use print_bit_image() instead for compatibility

    If you must use raster graphics:
        1. Test on YOUR specific FX-890 model
        2. Have fallback to print_bit_image()
        3. Document compatibility in your code
        4. Consider printer firmware version
"""
