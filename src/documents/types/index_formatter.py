"""Index formatting utilities.

Provides:
- int_to_roman: Convert integer to roman numerals
- roman_to_int: Convert roman numerals to integer
- format_index: Format index from segments
- parse_index: Parse index string to segments
"""

import re
from typing import Any

# Mapping for roman numerals
_ROMAN_NUMERALS: list[tuple[int, str]] = [
    (1000, "M"),
    (900, "CM"),
    (500, "D"),
    (400, "CD"),
    (100, "C"),
    (90, "XC"),
    (50, "L"),
    (40, "XL"),
    (10, "X"),
    (9, "IX"),
    (5, "V"),
    (4, "IV"),
    (1, "I"),
]

# Reverse mapping for parsing
_ROMAN_TO_INT: dict[str, int] = {v: k for k, v in _ROMAN_NUMERALS}


def int_to_roman(num: int) -> str:
    """Преобразует целое число в римские цифры.

    Args:
        num: Положительное целое число (>= 1).

    Returns:
        Римское число в верхнем регистре.

    Raises:
        ValueError: Если число меньше 1.

    Examples:
        >>> int_to_roman(1)
        'I'
        >>> int_to_roman(9)
        'IX'
        >>> int_to_roman(42)
        'XLII'
        >>> int_to_roman(1999)
        'MCMXCIX'
    """
    if num < 1:
        raise ValueError("Roman numerals must be positive integers >= 1")

    result = ""
    remaining = num

    for value, numeral in _ROMAN_NUMERALS:
        while remaining >= value:
            result += numeral
            remaining -= value

    return result


def roman_to_int(roman: str) -> int:
    """Преобразует римские цифры в целое число.

    Args:
        roman: Римское число в верхнем или нижнем регистре.

    Returns:
        Целое число.

    Raises:
        ValueError: Если строка не является валидным римским числом.

    Examples:
        >>> roman_to_int('I')
        1
        >>> roman_to_int('IX')
        9
        >>> roman_to_int('XLII')
        42
        >>> roman_to_int('MCMXCIX')
        1999
    """
    roman = roman.upper()
    if not roman:
        raise ValueError("Empty string is not a valid roman numeral")

    # Validate characters
    valid_chars = set("IVXLCDM")
    if not all(c in valid_chars for c in roman):
        raise ValueError(f"Invalid roman numeral characters: {roman}")

    # Parse using greedy algorithm
    total = 0
    i = 0
    length = len(roman)

    while i < length:
        # Check for subtractive notation
        if i + 1 < length:
            current = _ROMAN_TO_INT.get(roman[i], 0)
            next_val = _ROMAN_TO_INT.get(roman[i + 1], 0)

            if current < next_val:
                total += next_val - current
                i += 2
                continue

        total += _ROMAN_TO_INT.get(roman[i], 0)
        i += 1

    # Verify by converting back
    if int_to_roman(total) != roman.upper():
        raise ValueError(f"Invalid roman numeral: {roman}")

    return total


def format_index(
    segments: list[str], separator: str = "-"
) -> str:
    """Собирает полный индекс из сегментов.

    Args:
        segments: Список сегментов индекса.
        separator: Разделитель между сегментами (по умолчанию "-").

    Returns:
        Собранный индекс, например "DVN-44-K53-IX".

    Examples:
        >>> format_index(["DVN", "44", "K53", "IX"])
        'DVN-44-K53-IX'
        >>> format_index(["INV", "XLI"])
        'INV-XLI'
    """
    return separator.join(segments)


def parse_index(
    index: str, separator: str = "-"
) -> list[str]:
    """Разбирает индекс на сегменты.

    Args:
        index: Строка индекса.
        separator: Разделитель между сегментами (по умолчанию "-").

    Returns:
        Список сегментов.

    Examples:
        >>> parse_index("DVN-44-K53-IX")
        ['DVN', '44', 'K53', 'IX']
        >>> parse_index("INV-XLI")
        ['INV', 'XLI']
    """
    return index.split(separator)


def validate_index_segment(
    value: str, pattern: str, allowed_values: list[str] | None = None
) -> bool:
    """Валидирует значение сегмента индекса.

    Args:
        value: Значение сегмента для валидации.
        pattern: Regex-паттерн для проверки.
        allowed_values: Список допустимых значений (опционально).

    Returns:
        True если значение валидно, False в противном случае.
    """
    if not re.match(pattern, value):
        return False

    if allowed_values is not None and value not in allowed_values:
        return False

    return True