"""CodepageValidator — компонент валидации совместимости с PC866.

Модуль предоставляет валидатор для проверки текста на совместимость
с кодовой страницей PC866 (CP866), используемой в принтерах Epson FX-890.

Features:
- Проверка каждого символа на поддержку PC866
- Карта замен для несовместимых символов
- Автоматическое исправление текста
- Детальные отчёты о невалидных символах

Example:
    >>> from src.gui.components.codepage_validator import CodepageValidator
    >>> validator = CodepageValidator()
    >>> result = validator.validate("Hello — world")
    >>> fixed = validator.fix_all("Hello — world")
    >>> print(fixed)  # "Hello - world"

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Dict, FrozenSet, List, Optional


@dataclass(frozen=True)
class ValidationResult:
    """Результат валидации отдельного символа.

    Attributes:
        char: Исходный невалидный символ.
        position: Позиция символа в тексте (0-indexed).
        replacement: Предлагаемая замена или None.
        is_valid: False для невалидных символов (всегда False для этого результата).

    Example:
        >>> result = ValidationResult(char='—', position=6, replacement='-', is_valid=False)
        >>> print(f"Invalid char '{result.char}' at pos {result.position}")
    """

    char: str
    position: int
    replacement: Optional[str]
    is_valid: bool


class CodepageValidator:
    """Валидатор совместимости текста с кодовой страницей PC866.

    Проверяет текст на наличие символов, которые не могут быть
    закодированы в PC866 (CP866), используемой в Epson FX-890.

    PC866 включает:
    - ASCII 0-127 (0x00-0x7F)
    - Кириллица и псевдографика 128-255 (0x80-0xFF)

    Attributes:
        PC866_SUPPORTED: Множество всех символов, поддерживаемых PC866.
        REPLACEMENT_MAP: Карта замен несовместимых символов.

    Example:
        >>> validator = CodepageValidator()
        >>> validator.is_valid_char('а')  # True
        >>> validator.is_valid_char('ё')  # False (требует замены)
        >>> validator.get_replacement('ё')  # 'е'
        >>> validator.fix_all('ёлка — "test"')  # 'елка - "test"'
    """

    # =============================================================================
    # CLASS CONSTANTS
    # =============================================================================

    PC866_SUPPORTED: ClassVar[FrozenSet[str]] = frozenset(
        # ASCII 0-127 (все printable + control)
        "".join(chr(i) for i in range(128))
        # Cyrillic block in PC866 (0x80-0xAF, 0xE0-0xEF, 0xF0-0xFF)
        # NOTE: ё and Ё (U+0451, U+0401) are NOT in PC866, they need replacement
        + "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"  # 0x80-0x9F (uppercase, без Ё)
        + "абвгдежзийклмнопрстуфхцчшщъыьэюя"  # 0xA0-0xAF (lowercase, без ё)
        + "°·"  # Degree and middle dot
        + "≡±≥≤÷≈°"  # Math symbols
        + "²³¹"  # Superscripts
        + "₤"  # Currency
        + "─│┌┐└┘├┤┬┴┼"  # Box drawing
        + "═║╔╗╚╝╠╣╦╩╬"  # Double line box drawing
    )

    REPLACEMENT_MAP: ClassVar[Dict[str, str]] = {
        # Russian letter variations (U+0451, U+0401)
        "\u0451": "\u0435",  # ё → е
        "\u0401": "\u0415",  # Ё → Е
        # Typography dashes (U+2014, U+2013)
        "\u2014": "-",  # em-dash → hyphen
        "\u2013": "-",  # en-dash → hyphen
        # Smart quotes (U+201C, U+201D, U+2018, U+2019)
        "\u201c": '"',  # left double quotation → ASCII double quote
        "\u201d": '"',  # right double quotation → ASCII double quote
        "\u2018": "'",  # left single quotation → ASCII apostrophe
        "\u2019": "'",  # right single quotation → ASCII apostrophe
        # Other symbols
        "\u2116": "N",  # numero sign (U+2116) → N
        "\u00ab": '"',  # left-pointing double angle (U+00AB) → ASCII double quote
        "\u00bb": '"',  # right-pointing double angle (U+00BB) → ASCII double quote
        "\u2026": "...",  # horizontal ellipsis (U+2026) → three dots
        "\u2022": "-",  # bullet (U+2022) → hyphen
        "\u2192": "->",  # rightwards arrow (U+2192) → ASCII arrow
        "\u2190": "<-",  # leftwards arrow (U+2190) → ASCII arrow
        "\u2191": "^",  # upwards arrow (U+2191) → caret
        "\u2193": "v",  # downwards arrow (U+2193) → v
        # Additional typographic
        "\u2032": "'",  # prime (U+2032) → apostrophe
        "\u2033": '"',  # double prime (U+2033) → double quote
        "\u201e": '"',  # double low-9 quotation (U+201E) → double quote
        "\u201a": "'",  # single low-9 quotation (U+201A) → apostrophe
        # Currency and math
        "\u20ac": "EUR",  # euro sign (U+20AC)
        "\u2122": "(TM)",  # trademark (U+2122)
        "\u00a9": "(C)",  # copyright (U+00A9)
        "\u00ae": "(R)",  # registered (U+00AE)
        "\u00d7": "x",  # multiplication sign (U+00D7) → x
        "\u00f7": "/",  # division sign (U+00F7) → slash
    }

    # =============================================================================
    # CONSTRUCTOR
    # =============================================================================

    def __init__(self) -> None:
        """Инициализация валидатора.

        Создаёт экземпляр валидатора с предзагруженными константами.

        Example:
            >>> validator = CodepageValidator()
            >>> # Ready to use
        """
        # Constants are class-level, instance just provides access
        pass

    # =============================================================================
    # PUBLIC METHODS
    # =============================================================================

    def is_valid_char(self, char: str) -> bool:
        """Проверяет, поддерживается ли символ в PC866.

        Args:
            char: Символ для проверки. Должен быть строкой длиной 1.

        Returns:
            True если символ поддерживается PC866, False иначе.

        Raises:
            ValueError: Если char не является одиночным символом.

        Example:
            >>> validator = CodepageValidator()
            >>> validator.is_valid_char('A')   # True
            >>> validator.is_valid_char('ё')   # False
            >>> validator.is_valid_char('—')   # False
        """
        if len(char) != 1:
            raise ValueError(f"Ожидался одиночный символ, получено: {len(char)}")
        return char in self.PC866_SUPPORTED

    def get_replacement(self, char: str) -> Optional[str]:
        """Возвращает замену для несовместимого символа.

        Args:
            char: Символ для поиска замены.

        Returns:
            Строка-замена или None если замена не определена.

        Raises:
            ValueError: Если char не является одиночным символом.

        Example:
            >>> validator = CodepageValidator()
            >>> validator.get_replacement('ё')   # 'е'
            >>> validator.get_replacement('—')   # '-'
            >>> validator.get_replacement('X')   # None (valid char)
        """
        if len(char) != 1:
            raise ValueError(f"Ожидался одиночный символ, получено: {len(char)}")
        return self.REPLACEMENT_MAP.get(char)

    def validate(self, text: str) -> List[ValidationResult]:
        """Валидирует текст и возвращает список невалидных символов.

        Проверяет каждый символ текста на совместимость с PC866.
        Возвращает детальную информацию о каждом невалидном символе.

        Args:
            text: Текст для валидации.

        Returns:
            Список ValidationResult для всех невалидных символов.
            Пустой список если текст полностью валиден.

        Example:
            >>> validator = CodepageValidator()
            >>> results = validator.validate("Test—123")
            >>> len(results)
            1
            >>> results[0].char
            '—'
            >>> results[0].replacement
            '-'
        """
        results: List[ValidationResult] = []

        for position, char in enumerate(text):
            if not self.is_valid_char(char):
                replacement = self.get_replacement(char)
                results.append(
                    ValidationResult(
                        char=char,
                        position=position,
                        replacement=replacement,
                        is_valid=False,
                    )
                )

        return results

    def fix_all(self, text: str) -> str:
        """Применяет все возможные замены к тексту.

        Заменяет несовместимые с PC866 символы на их ASCII-эквиваленты.
        Символы без определённой замены остаются без изменений.

        Args:
            text: Исходный текст.

        Returns:
            Текст с применёнными заменами.

        Example:
            >>> validator = CodepageValidator()
            >>> validator.fix_all('ёлка — "test"')
            'елка - "test"'
            >>> validator.fix_all('№ документа: «123»')
            'N документа: "123"'
        """
        result_chars: List[str] = []

        for char in text:
            if self.is_valid_char(char):
                result_chars.append(char)
            else:
                replacement = self.get_replacement(char)
                if replacement is not None:
                    result_chars.append(replacement)
                else:
                    # Keep original char if no replacement defined
                    result_chars.append(char)

        return "".join(result_chars)

    def count_invalid(self, text: str) -> int:
        """Подсчитывает количество невалидных символов в тексте.

        Args:
            text: Текст для анализа.

        Returns:
            Количество символов, не поддерживаемых PC866.

        Example:
            >>> validator = CodepageValidator()
            >>> validator.count_invalid("Hello World")  # 0
            >>> validator.count_invalid("Test—123")     # 1
            >>> validator.count_invalid("ёлка—"")         # 3
        """
        return sum(1 for char in text if not self.is_valid_char(char))

    def has_replacement(self, char: str) -> bool:
        """Проверяет, есть ли замена для символа.

        Args:
            char: Символ для проверки.

        Returns:
            True если для символа определена замена.

        Raises:
            ValueError: Если char не является одиночным символом.

        Example:
            >>> validator = CodepageValidator()
            >>> validator.has_replacement('ё')  # True
            >>> validator.has_replacement('X')  # False
        """
        if len(char) != 1:
            raise ValueError(f"Ожидался одиночный символ, получено: {len(char)}")
        return char in self.REPLACEMENT_MAP

    def get_valid_chars(self) -> FrozenSet[str]:
        """Возвращает множество всех валидных символов PC866.

        Returns:
            Копия множества поддерживаемых символов.

        Example:
            >>> validator = CodepageValidator()
            >>> 'А' in validator.get_valid_chars()
            True
        """
        return frozenset(self.PC866_SUPPORTED)

    def get_replacement_chars(self) -> FrozenSet[str]:
        """Возвращает множество символов с определёнными заменами.

        Returns:
            Множество символов, для которых есть замены.

        Example:
            >>> validator = CodepageValidator()
            >>> 'ё' in validator.get_replacement_chars()
            True
        """
        return frozenset(self.REPLACEMENT_MAP.keys())
