"""Модуль масок ввода для полей форм.

Предоставляет:
- InputMask: Класс для форматирования ввода с поддержкой маскирующих символов

Модуль реализует маски ввода с поддержкой различных типов символов:
- цифр, букв, римских цифр, буквенно-цифровых символов.

Маски используются для форматирования полей ввода в реальном времени,
обеспечивая единообразие данных (например, номер документа DVN-44-K53-IX).

Example:
    >>> from src.documents.constructor.input_mask import InputMask
    >>> mask = InputMask("##.##.####")
    >>> mask.apply("25122026")
    '25.12.2026'
    >>> mask.is_complete("25.12.2026")
    True
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from src.documents.types.index_template import IndexSegmentDef, IndexTemplate

# Import SegmentType for runtime use in _segment_to_mask
from src.documents.types.index_template import SegmentType

logger: Final = logging.getLogger(__name__)

# Символы маски
_MASK_DIGIT: Final[str] = "#"
_MASK_LETTER: Final[str] = "A"  # Латинская буква
_MASK_ROMAN: Final[str] = "R"  # Римская цифра (IVXLCDM)
_MASK_ANY_LETTER: Final[str] = "L"  # Любая буква
_MASK_ALPHANUM: Final[str] = "N"  # Буква или цифра
_MASK_SEPARATOR: Final[str] = "-"

# Паттерны для валидации символов маски
_VALID_MASK_CHARS: Final[set[str]] = {
    _MASK_DIGIT,
    _MASK_LETTER,
    _MASK_ROMAN,
    _MASK_ANY_LETTER,
    _MASK_ALPHANUM,
}

# Паттерны для проверки типов символов
_RE_DIGIT: Final = re.compile(r"^[0-9]$")
_RE_LETTER: Final = re.compile(r"^[A-Za-z]$")
_RE_ROMAN: Final = re.compile(r"^[IVXLCDM]$")


@dataclass(frozen=True)
class InputMask:
    """Маска ввода с поддержкой динамического форматирования.

    Маска определяет формат ввода, где специальные символы представляют
    определённые типы символов:
    - # — цифра (0-9)
    - A — латинская буква (A-Z, a-z)
    - R — римская цифра (I, V, X, L, C, D, M)
    - L — любая буква
    - N — буква или цифра
    - любой другой символ — литерал (например, '.', '-', ' ')

    Attributes:
        pattern: Строка маски, например "##.##.####" для даты.
        placeholder: Символ для незаполненных позиций (по умолчанию "_").

    Example:
        >>> mask = InputMask("AAA-##-A##-RR")
        >>> mask.apply("DVN44K53IX")
        'DVN-44-K53-IX'
        >>> mask = InputMask("+7 (###) ###-##-##")
        >>> mask.apply("4951234567")
        '+7 (495) 123-45-67'
    """

    pattern: str
    placeholder: str = "_"

    def __post_init__(self) -> None:
        """Валидация параметров после инициализации."""
        if not isinstance(self.pattern, str):
            raise TypeError(f"pattern должен быть str, получен {type(self.pattern).__name__}")
        if not self.pattern:
            raise ValueError("pattern не может быть пустым")
        if not isinstance(self.placeholder, str):
            raise TypeError(
                f"placeholder должен быть str, получен {type(self.placeholder).__name__}"
            )
        if len(self.placeholder) != 1:
            raise ValueError(
                f"placeholder должен быть одним символом, получено: '{self.placeholder}'"
            )

        # Проверка валидности символов маски
        for char in self.pattern:
            if char not in _VALID_MASK_CHARS and not char.isalnum():
                # Буквенно-цифровые символы в маске — это литералы
                if char.isalpha():
                    continue
            elif char in _VALID_MASK_CHARS:
                continue
            # Допускаем любые другие символы как литералы

    def apply(self, raw: str) -> str:
        """Применяет маску к сырому вводу.

        Форматирует сырой ввод согласно маске, вставляя литералы маски
        и заменяя placeholder'ы в незаполненных позициях.

        Args:
            raw: Сырой ввод без форматирования.

        Returns:
            Отформатированная строка с маской.

        Example:
            >>> mask = InputMask("##.##.####")
            >>> mask.apply("2512")
            '25.12.__.____'
            >>> mask.apply("25122026")
            '25.12.2026'
        """
        if not isinstance(raw, str):
            raise TypeError(f"raw должен быть str, получен {type(raw).__name__}")

        result: list[str] = []
        raw_index = 0

        for mask_char in self.pattern:
            if self._is_mask_char(mask_char):
                # Это символ маски (требует ввода)
                if raw_index < len(raw):
                    char = raw[raw_index]
                    if self._validate_char(char, mask_char):
                        result.append(char.upper() if mask_char == _MASK_ROMAN else char)
                        raw_index += 1
                    else:
                        # Невалидный символ для позиции — placeholder
                        result.append(self.placeholder)
                        raw_index += 1
                else:
                    # Нет больше ввода — placeholder
                    result.append(self.placeholder)
            else:
                # Это литерал маски
                result.append(mask_char)

        return "".join(result)

    def strip(self, masked: str) -> str:
        """Удаляет маску, оставляя только значимые символы.

        Args:
            masked: Отформатированная строка с маской.

        Returns:
            Строка без литералов маски и placeholder'ов.

        Example:
            >>> mask = InputMask("##.##.####")
            >>> mask.strip("25.12.2026")
            '25122026'
            >>> mask.strip("25.12.__.____")
            '2512'
        """
        if not isinstance(masked, str):
            raise TypeError(f"masked должен быть str, получен {type(masked).__name__}")

        result: list[str] = []
        mask_index = 0

        for char in masked:
            if mask_index >= len(self.pattern):
                # Лишние символы — пропускаем
                break

            mask_char = self.pattern[mask_index]

            if self._is_mask_char(mask_char):
                # Это позиция маски
                if char != self.placeholder:
                    result.append(char)
                mask_index += 1
            else:
                # Это литерал маски — пропускаем
                mask_index += 1

        return "".join(result)

    def is_complete(self, masked: str) -> bool:
        """Проверяет, заполнена ли маска полностью.

        Args:
            masked: Отформатированная строка с маской.

        Returns:
            True если все позиции маски заполнены (нет placeholder'ов).

        Example:
            >>> mask = InputMask("##.##.####")
            >>> mask.is_complete("25.12.__.____")
            False
            >>> mask.is_complete("25.12.2026")
            True
        """
        if not isinstance(masked, str):
            raise TypeError(f"masked должен быть str, получен {type(masked).__name__}")

        mask_index = 0

        for char in masked:
            if mask_index >= len(self.pattern):
                break

            mask_char = self.pattern[mask_index]

            if self._is_mask_char(mask_char):
                if char == self.placeholder:
                    return False
                mask_index += 1
            elif char == mask_char:
                mask_index += 1

        # Проверяем, все ли позиции маски обработаны
        remaining_mask = self.pattern[mask_index:]
        return not any(self._is_mask_char(c) for c in remaining_mask)

    def validate(self, raw: str) -> bool:
        """Проверяет, соответствует ли сырой ввод маске.

        Args:
            raw: Сырой ввод для проверки.

        Returns:
            True если ввод соответствует маске по длине и типам символов.

        Example:
            >>> mask = InputMask("AAA-##")
            >>> mask.validate("ABC12")
            True
            >>> mask.validate("12345")
            False
        """
        if not isinstance(raw, str):
            return False

        # Считаем количество позиций ввода в маске
        mask_positions = sum(1 for c in self.pattern if self._is_mask_char(c))

        if len(raw) != mask_positions:
            return False

        # Проверяем каждый символ
        raw_index = 0
        for mask_char in self.pattern:
            if self._is_mask_char(mask_char):
                if raw_index >= len(raw):
                    return False
                if not self._validate_char(raw[raw_index], mask_char):
                    return False
                raw_index += 1

        return True

    def _is_mask_char(self, char: str) -> bool:
        """Проверяет, является ли символ спецификатором маски.

        Args:
            char: Символ для проверки.

        Returns:
            True если символ — спецификатор маски.
        """
        return char in _VALID_MASK_CHARS

    def _validate_char(self, char: str, mask_char: str) -> bool:
        """Проверяет, соответствует ли символ спецификатору маски.

        Args:
            char: Введённый символ.
            mask_char: Спецификатор маски (#, A, R, L, N).

        Returns:
            True если символ соответствует маске.
        """
        if mask_char == _MASK_DIGIT:
            return bool(_RE_DIGIT.match(char))
        elif mask_char == _MASK_LETTER:
            return bool(_RE_LETTER.match(char))
        elif mask_char == _MASK_ROMAN:
            return bool(_RE_ROMAN.match(char.upper()))
        elif mask_char == _MASK_ANY_LETTER:
            return char.isalpha()
        elif mask_char == _MASK_ALPHANUM:
            return char.isalnum()
        return False

    @staticmethod
    def build_from_template(index_template: IndexTemplate) -> "InputMask":
        """Строит маску для document_index из IndexTemplate.

        Анализирует IndexTemplate и создаёт соответствующую маску ввода:
        - ROOT_CODE (например, DVN) → AAA
        - SUBTYPE (например, 44) → ##
        - SERIES (например, K53) → A##
        - CUSTOM → зависит от паттерна
        - SEQUENCE (римские цифры) → RR

        Args:
            index_template: Шаблон индекса для анализа.

        Returns:
            InputMask, соответствующий шаблону индекса.

        Example:
            >>> from src.documents.types.index_template import (
            ...     IndexTemplate, IndexSegmentDef, SegmentType
            ... )
            >>> template = IndexTemplate(segments=(
            ...     IndexSegmentDef("type", SegmentType.ROOT_CODE, "Тип", "Type", r"DVN"),
            ...     IndexSegmentDef(
            ...         "subtype", SegmentType.SUBTYPE, "Подтип", "Subtype", r"\\d{2}"
            ...     ),
            ...     IndexSegmentDef(
            ...         "series", SegmentType.SERIES, "Серия", "Series", r"[A-Z]\\d{2}"
            ...     ),
            ...     IndexSegmentDef(
            ...         "seq", SegmentType.SEQUENCE, "Номер", "Number", r"[IVXLCDM]+"
            ...     ),
            ... ))
            >>> mask = InputMask.build_from_template(template)
            >>> mask.pattern
            'AAA-##-A##-RR'
        """
        if not hasattr(index_template, "segments"):
            raise TypeError("index_template должен иметь атрибут segments")

        parts: list[str] = []

        for i, segment in enumerate(index_template.segments):
            segment_mask = InputMask._segment_to_mask(segment)
            parts.append(segment_mask)

            # Добавляем разделитель между сегментами (кроме последнего)
            if i < len(index_template.segments) - 1:
                separator = getattr(index_template, "separator", "-")
                parts.append(separator)

        pattern = "".join(parts)
        return InputMask(pattern=pattern, placeholder="_")

    @staticmethod
    def _segment_to_mask(segment: IndexSegmentDef) -> str:
        """Преобразует один сегмент IndexTemplate в маску.

        Args:
            segment: Определение сегмента.

        Returns:
            Строка маски для сегмента.
        """
        segment_type = segment.segment_type
        pattern = segment.pattern

        if segment_type == SegmentType.ROOT_CODE:
            # Код типа: DVN, INV — буквы
            # Извлекаем длину из паттерна или используем значение по умолчанию
            # Поддерживает {n} и {min,max} форматы
            match = re.search(r"\{(\d+)(?:,(\d+))?\}", pattern)
            if match:
                # Если есть group(2) — используем max (group(2)), иначе exact (group(1))
                length = int(match.group(2)) if match.group(2) else int(match.group(1))
            else:
                # Оценка длины по примеру в паттерне
                length = len([c for c in pattern if c.isalpha()]) or 3
            return _MASK_LETTER * max(2, min(length, 5))

        elif segment_type == SegmentType.SUBTYPE:
            # Подтип: 44, 01 — цифры
            # Поддерживает {n} и {min,max} форматы
            match = re.search(r"\\d\{(\d+)(?:,(\d+))?\}", pattern)
            if match:
                # Если есть group(2) — используем max (group(2)), иначе exact (group(1))
                length = int(match.group(2)) if match.group(2) else int(match.group(1))
            else:
                length = len([c for c in pattern if c.isdigit() or c == "\\d"]) or 2
            return _MASK_DIGIT * max(1, min(length, 4))

        elif segment_type == SegmentType.SERIES:
            # Серия: K53 — буква + цифры
            # Пример: [A-Z]\d{2} → буква + 2 цифры
            letters = len(re.findall(r"\[A-Z\]", pattern))
            digits_match = re.search(r"\\d\{(\d+)\}", pattern)
            digits = int(digits_match.group(1)) if digits_match else 2
            return _MASK_LETTER * max(1, letters) + _MASK_DIGIT * max(1, min(digits, 4))

        elif segment_type == SegmentType.CUSTOM:
            # Произвольный сегмент — анализируем паттерн
            if "\\d" in pattern and "[A-Z]" in pattern:
                # Буквы и цифры
                return _MASK_ALPHANUM * 3
            elif "\\d" in pattern:
                return _MASK_DIGIT * 3
            elif "[A-Z]" in pattern:
                return _MASK_LETTER * 3
            else:
                return _MASK_ALPHANUM * 3

        elif segment_type == SegmentType.SEQUENCE:
            # Порядковый номер — римские цифры
            # Обычно 1-4 символа (I, II, III, IV, ..., XLII)
            return _MASK_ROMAN * 4

        return _MASK_ALPHANUM * 3  # Значение по умолчанию

    def get_expected_length(self) -> int:
        """Возвращает ожидаемую длину ввода (количество позиций маски).

        Returns:
            Количество символов ввода, требуемых маской.
        """
        return sum(1 for c in self.pattern if self._is_mask_char(c))

    def __repr__(self) -> str:
        """Строковое представление для отладки."""
        return f"InputMask(pattern='{self.pattern}', placeholder='{self.placeholder}')"
