"""
Character set and encoding commands for Epson FX-890.

Contains commands for selecting character tables and international character
sets. Critical for multi-language support, especially Cyrillic (PC866).

Reference: Epson FX-890 Technical Reference Manual, Chapter 9
Primary Encoding: PC866 (Cyrillic)
"""

from enum import Enum

__all__ = [
    "CharacterTable",
    "InternationalCharset",
    "set_character_table",
    "set_international_charset",
]

# =============================================================================
# CHARACTER TABLE CONSTANTS
# =============================================================================


class CharacterTable(Enum):
    """
    Character tables (code pages) supported by FX-890.

    Each table defines character mapping for codes 128-255.
    Codes 0-127 are standard ASCII.
    """

    PC437 = 0  # US/Standard (default)
    """PC437 - US/Standard (IBM PC original character set)."""

    PC850 = 2  # Multilingual (Latin 1)
    """PC850 - Multilingual (Latin 1, Western European)."""

    PC860 = 3  # Portuguese
    """PC860 - Portuguese."""

    PC863 = 4  # Canadian-French
    """PC863 - Canadian-French."""

    PC865 = 5  # Nordic
    """PC865 - Nordic (Danish, Norwegian, Swedish)."""

    PC866 = 6  # Cyrillic (Russian)
    """PC866 - Cyrillic (Russian, primary for this project)."""

    PC852 = 9  # Eastern European (Latin 2)
    """PC852 - Eastern European (Latin 2, Polish, Czech, Hungarian)."""

    PC858 = 13  # Multilingual with Euro
    """PC858 - PC850 with Euro symbol."""


class InternationalCharset(Enum):
    """
    International character sets (affects codes 35, 36, 64, 91-96, 123-126).

    Modifies specific ASCII positions for localized characters.
    """

    USA = 0
    """USA - Standard ASCII characters."""

    FRANCE = 1
    """France - French-specific characters (é, à, ç, etc.)."""

    GERMANY = 2
    """Germany - German-specific characters (ä, ö, ü, ß)."""

    UK = 3
    """United Kingdom - British pound sign (£)."""

    DENMARK_I = 4
    """Denmark I - Danish characters (æ, ø, å)."""

    SWEDEN = 5
    """Sweden - Swedish characters (å, ä, ö)."""

    ITALY = 6
    """Italy - Italian characters (è, é, ù)."""

    SPAIN_I = 7
    """Spain I - Spanish characters (ñ, ¿, ¡)."""

    JAPAN = 8
    """Japan - Japanese characters (Katakana)."""

    NORWAY = 9
    """Norway - Norwegian characters (æ, ø, å)."""

    DENMARK_II = 10
    """Denmark II - Alternative Danish mapping."""

    SPAIN_II = 11
    """Spain II - Alternative Spanish mapping."""

    LATIN_AMERICA = 12
    """Latin America - Latin American Spanish."""

    KOREA = 13
    """Korea - Korean characters (Hangul)."""

    LEGAL = 64
    """Legal - Legal symbols (§, ¶, ©, ®, ™)."""


# =============================================================================
# CHARACTER SET COMMANDS
# =============================================================================


def set_character_table(table: CharacterTable) -> bytes:
    """
    Select character table (code page).

    Command: ESC t n
    Hex: 1B 74 n

    Args:
        table: Character table to select (see CharacterTable enum).

    Returns:
        ESC/P command bytes.

    Note:
        Character table affects codes 128-255 (extended ASCII).
        Codes 0-127 remain standard ASCII regardless of table.
        For Russian text, use PC866.

    Example:
        >>> # Switch to Cyrillic (PC866) for Russian text
        >>> cmd = set_character_table(CharacterTable.PC866)
        >>> printer.send(cmd)
        >>>
        >>> # Print Russian text
        >>> russian_text = "Привет мир"
        >>> printer.send(russian_text.encode("cp866"))
        >>>
        >>> # Switch back to US for English
        >>> cmd = set_character_table(CharacterTable.PC437)
        >>> printer.send(cmd)
        >>> printer.send(b"Hello World")
    """
    return b"\x1bt" + bytes([table.value])


def set_international_charset(charset: InternationalCharset) -> bytes:
    """
    Select international character set.

    Command: ESC R n
    Hex: 1B 52 n

    Args:
        charset: International charset to select (see InternationalCharset enum).

    Returns:
        ESC/P command bytes.

    Note:
        International charset modifies specific ASCII positions:
        #, $, @, [, '\', ], ^, `, {, |, }, ~ # type: ignore

        This allows localized symbols without changing full character table.
        For example, UK charset replaces # with £ (pound sign).

    Example:
        >>> # Use German charset for umlauts
        >>> cmd = set_international_charset(InternationalCharset.GERMANY)
        >>> printer.send(cmd)
        >>>
        >>> # Print German text
        >>> german_text = "Schön grüß"
        >>> printer.send(german_text.encode("cp850"))
        >>>
        >>> # Reset to USA
        >>> cmd = set_international_charset(InternationalCharset.USA)
        >>> printer.send(cmd)
    """
    return b"\x1bR" + bytes([charset.value])


# =============================================================================
# USAGE EXAMPLES
# =============================================================================

"""
RUSSIAN TEXT PRINTING (PRIMARY USE CASE):
    This project primarily uses PC866 for Russian:

    >>> # Setup for Russian
    >>> printer.send(set_character_table(CharacterTable.PC866))
    >>>
    >>> # Print Russian text
    >>> russian_text = "Добрый день! Как дела?"
    >>> printer.send(russian_text.encode("cp866"))
    >>> printer.send(b"\r\n")
    >>>
    >>> # Mixed Russian and English
    >>> printer.send("Имя: ".encode("cp866"))
    >>> printer.send(b"John Smith\r\n")

MULTILINGUAL DOCUMENTS:
    Switch between character tables as needed:

    >>> # English section
    >>> printer.send(set_character_table(CharacterTable.PC437))
    >>> printer.send(b"Introduction\r\n\r\n")
    >>>
    >>> # Russian section
    >>> printer.send(set_character_table(CharacterTable.PC866))
    >>> printer.send("Введение\r\n\r\n".encode("cp866"))
    >>>
    >>> # German section
    >>> printer.send(set_character_table(CharacterTable.PC850))
    >>> printer.send("Einführung\r\n\r\n".encode("cp850"))

EUROPEAN CHARACTERS:
    For Western European languages:

    >>> # Setup for French
    >>> printer.send(set_character_table(CharacterTable.PC850))
    >>> printer.send(set_international_charset(InternationalCharset.FRANCE))
    >>>
    >>> # Print French text
    >>> french_text = "Bonjour! Comment ça va?"
    >>> printer.send(french_text.encode("cp850"))

CYRILLIC CHARACTER MAP (PC866):
    Mapping for codes 128-255 in PC866:

    А Б В Г Д Е Ж З И Й К Л М Н О П  (128-143)
    Р С Т У Ф Х Ц Ч Ш Щ Ъ Ы Ь Э Ю Я  (144-159)
    а б в г д е ж з и й к л м н о п  (160-175)
    р с т у ф х ц ч ш щ ъ ы ь э ю я  (176-191)
    [Box drawing and special chars]   (192-255)

BOX DRAWING CHARACTERS:
    PC437, PC850, PC866 include box drawing characters:

    >>> # Print box using PC866 box-drawing chars
    >>> printer.send(set_character_table(CharacterTable.PC866))
    >>>
    >>> # ┌─┐
    >>> # │ │
    >>> # └─┘
    >>> printer.send(b"\xda\xc4\xbf\r\n")  # ┌─┐
    >>> printer.send(b"\xb3 \xb3\r\n")      # │ │
    >>> printer.send(b"\xc0\xc4\xd9\r\n")  # └─┘

DYNAMIC CHARACTER TABLE SWITCHING:
    Switch tables mid-document:

    >>> # Function to print multilingual table
    >>> def print_greeting_table():
    ...     # Header (English)
    ...     printer.send(set_character_table(CharacterTable.PC437))
    ...     printer.send(b"Language | Greeting\r\n")
    ...     printer.send(b"---------+---------\r\n")
    ...
    ...     # English
    ...     printer.send(b"English  | Hello\r\n")
    ...
    ...     # Russian
    ...     printer.send(set_character_table(CharacterTable.PC866))
    ...     printer.send("Russian  | Привет\r\n".encode("cp866"))
    ...
    ...     # French
    ...     printer.send(set_character_table(CharacterTable.PC850))
    ...     printer.send("French   | Bonjour\r\n".encode("cp850"))

ENCODING DETECTION:
    Automatically select correct table for text:

    >>> def auto_select_charset(text: str) -> CharacterTable:
    ...     # Detect encoding based on character range
    ...     if any(ord(c) >= 0x400 and ord(c) < 0x500 for c in text):
    ...         return CharacterTable.PC866  # Cyrillic
    ...     else:
    ...         return CharacterTable.PC437  # Default
    >>>
    >>> text = "Привет"
    >>> table = auto_select_charset(text)
    >>> printer.send(set_character_table(table))
    >>> printer.send(text.encode("cp866"))

INTERNATIONAL CHARSET FOR SYMBOLS:
    Use international charsets for specific symbols:

    >>> # Print UK pound sign
    >>> printer.send(set_international_charset(InternationalCharset.UK))
    >>> printer.send(b"Price: #100\r\n")  # # becomes £
    >>>
    >>> # Legal symbols
    >>> printer.send(set_international_charset(InternationalCharset.LEGAL))
    >>> printer.send(b"Copyright @ 2025\r\n")  # @ becomes ©

FORM PRINTING WITH CYRILLIC:
    Russian invoice example:

    >>> # Setup
    >>> printer.send(set_character_table(CharacterTable.PC866))
    >>>
    >>> # Header
    >>> printer.send("СЧЕТ-ФАКТУРА №12345\r\n\r\n".encode("cp866"))
    >>>
    >>> # Items
    >>> printer.send("Наименование\tКол-во\tЦена\r\n".encode("cp866"))
    >>> printer.send(b"-" * 40 + b"\r\n")
    >>> printer.send("Товар А\t5\t100.00\r\n".encode("cp866"))
    >>> printer.send("Товар Б\t2\t250.00\r\n".encode("cp866"))

CHARACTER TABLE DEFAULTS:
    FX-890 defaults after power-on or reset:
    - Character table: PC437 (US)
    - International charset: USA

    Must explicitly set PC866 for Russian text.

COMPATIBILITY NOTES:
    PC866 (Cyrillic):
        - Standard for Russian text in DOS/Windows
        - Compatible with most Russian software
        - Includes box-drawing characters
        - Preferred encoding for this project

    PC850 (Multilingual):
        - Western European languages
        - French, German, Spanish, Italian
        - Does NOT include Cyrillic

    PC437 (US):
        - Original IBM PC character set
        - English + box-drawing + some symbols
        - No Cyrillic or extended European chars

TROUBLESHOOTING:
    If Russian text appears as gibberish:
    1. Check character table is set to PC866
    2. Verify text is encoded with cp866
    3. Ensure printer supports PC866 (all FX-890 models do)
    4. Reset printer if charset seems stuck

    If accented characters are wrong:
    1. Check character table matches encoding
    2. PC850 for Western European (not PC437)
    3. Set correct international charset if needed
    4. Verify source text encoding matches printer encoding

    If box-drawing characters are wrong:
    1. Check character table (PC437/PC866/PC850 all have boxes)
    2. Verify correct character codes for table
    3. PC866 has different codes than PC437 for some boxes
"""
