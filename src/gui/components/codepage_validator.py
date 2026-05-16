"""Валидатор символов Codepage для FX Text Processor 3.

Проверяет текст на соответствие PC866 (OEM Russian) и другим
поддерживаемым кодовым страницам. Возвращает результаты валидации
с информацией о заменах.

Example:
    >>> from src.gui.components.codepage_validator import CodepageValidator
    >>> validator = CodepageValidator()
    >>> results = validator.validate("Hello")
    >>> len(results)
    0

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

__author__ = "FX Text Processor Team"
__date__ = "April 2026"
__version__ = "1.0"

__all__ = [
    "CodepageValidator",
    "ValidationResult",
]


@dataclass(frozen=True)
class ValidationResult:
    """Результат валидации одного символа.

    Attributes:
        char: Проблемный символ.
        position: Позиция в тексте.
        replacement: Замена или None если невозможно заменить.
        is_valid: Флаг валидности (всегда False для результата).

    Example:
        >>> result = ValidationResult(char="é", position=5, replacement="e")
        >>> result.replacement
        'e'
    """

    char: str
    position: int
    replacement: Optional[str] = None
    is_valid: bool = False


class CodepageValidator:
    """Валидатор текста на соответствие кодовой странице.

    Проверяет каждый символ текста на принадлежность к PC866.
    Возвращает список невалидных символов с возможными заменами.

    Example:
        >>> validator = CodepageValidator()
        >>> results = validator.validate("Test")
        >>> assert len(results) == 0
    """

    # Таблица замен для распространённых символов
    REPLACEMENT_MAP: dict[str, str] = {
        "ё": "е",  # ё -> е
        "Ё": "Е",  # Ё -> Е
        "—": "-",  # — (em-dash)
        "–": "-",  # – (en-dash)
        "“": '"',  # " (left double quote)
        "”": '"',  # " (right double quote)
        "‘": "'",  # ' (left single quote)
        "’": "'",  # ' (right single quote)
        "№": "N",  # №
        "«": '"',  # «
        "»": '"',  # »
        "…": "...",  # …
        "•": "-",  # •
        "→": "->",  # →
        "←": "<-",  # ←
        "€": "EUR",  # €
    }

    # Множество поддерживаемых символов PC866 (строится один раз).
    # Построено из всех байт 0x00–0xFF, декодированных через cp866,
    # за исключением ё/Ё — они считаются невалидными для замены на е/Е.
    PC866_SUPPORTED: frozenset[str] = frozenset(
        {bytes([b]).decode("cp866", errors="ignore") for b in range(256)} - {"", "ё", "Ё", "№"}
    )

    def __init__(self, codepage: str = "pc866") -> None:
        """Инициализация валидатора.

        Args:
            codepage: Имя кодовой страницы (по умолчанию 'pc866').
        """
        self._codepage = codepage
        # Перестроить поддерживаемые символы если кодовая страница отличается
        if codepage != "pc866":
            self._valid_chars: frozenset[str] = frozenset(
                {b""}
                if False
                else set(bytes([b]).decode(codepage, errors="ignore") for b in range(256)) - {""}
            )
        else:
            self._valid_chars = self.PC866_SUPPORTED

    def is_valid_char(self, char: str) -> bool:
        """Проверяет, поддерживается ли символ кодовой страницей.

        Args:
            char: Символ для проверки (должен быть ровно 1 символ).

        Returns:
            True если символ валиден для кодовой страницы.

        Raises:
            ValueError: Если передана пустая строка или более 1 символа.
        """
        if len(char) != 1:
            raise ValueError("char must be exactly one character")
        return char in self._valid_chars

    def get_replacement(self, char: str) -> Optional[str]:
        """Возвращает замену для невалидного символа.

        Args:
            char: Символ, не поддерживаемый кодовой страницей.

        Returns:
            Строка-замена или None если замена невозможна.

        Raises:
            ValueError: Если передана пустая строка или более 1 символа.
        """
        if len(char) != 1:
            raise ValueError("char must be exactly one character")
        return self.REPLACEMENT_MAP.get(char)

    def has_replacement(self, char: str) -> bool:
        """Проверяет, есть ли замена для символа.

        Args:
            char: Символ для проверки.

        Returns:
            True если для символа определена замена.

        Raises:
            ValueError: Если передана пустая строка или более 1 символа.
        """
        if len(char) != 1:
            raise ValueError("char must be exactly one character")
        return char in self.REPLACEMENT_MAP

    def get_valid_chars(self) -> frozenset[str]:
        """Возвращает множество валидных символов.

        Returns:
            frozenset поддерживаемых символов.
        """
        return self._valid_chars

    def get_replacement_chars(self) -> frozenset[str]:
        """Возвращает множество символов, для которых есть замена.

        Returns:
            frozenset символов с заменами.
        """
        return frozenset(self.REPLACEMENT_MAP.keys())

    def validate(self, text: str) -> list[ValidationResult]:
        """Валидирует текст на соответствие кодовой странице.

        Args:
            text: Текст для валидации.

        Returns:
            Список результатов валидации для невалидных символов.
                Пустой список означает что все символы валидны.
        """
        results: list[ValidationResult] = []
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
        """Заменяет все невалидные символы на их замены.

        Args:
            text: Исходный текст.

        Returns:
            Текст с заменёнными символами.
        """
        result: list[str] = []
        for char in text:
            if self.is_valid_char(char):
                result.append(char)
            else:
                replacement = self.get_replacement(char)
                result.append(replacement if replacement is not None else char)
        return "".join(result)

    def count_invalid(self, text: str) -> int:
        """Считает количество невалидных символов в тексте.

        Args:
            text: Текст для проверки.

        Returns:
            Количество невалидных символов.
        """
        return sum(1 for char in text if not self.is_valid_char(char))
