"""Thread-safe Singleton реестр типов документов.

Централизованное хранилище всех типов документов с иерархической
индексацией. Обеспечивает генерацию и парсинг составных индексов
в формате DVN-44-K53-I.

Example:
    >>> from src.documents.types.type_registry import TypeRegistry
    >>> registry = TypeRegistry.get_instance()
    >>> doc_type = registry.get_type("DVN")
    >>> index = registry.generate_index("DVN", "44", "K53")
    >>> print(index)
    DVN-44-K53-I
    >>> components = registry.parse_index("DVN-44-K53-IX")
    >>> print(components.sequence)
    IX

Thread Safety:
    Все публичные методы thread-safe благодаря RLock.
    Можно безопасно вызывать из разных потоков.
"""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass
from typing import ClassVar, Dict, List, Optional

from src.documents.types.document_type import DocumentType, Series, Subtype

logger = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

ROMAN_NUMERAL_PATTERN = re.compile(
    r"^M{0,4}(CM|CD|D?C{0,3})(XC|XL|L?X{0,3})(IX|IV|V?I{0,3})$",
    re.IGNORECASE,
)

ROMAN_TO_INT = {
    "I": 1,
    "V": 5,
    "X": 10,
    "L": 50,
    "C": 100,
    "D": 500,
    "M": 1000,
}

INT_TO_ROMAN = [
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


# =============================================================================
# EXCEPTIONS
# =============================================================================


class RegistryError(Exception):
    """Базовая ошибка реестра типов документов."""

    pass


class TypeRegistryError(RegistryError):
    """Ошибка операции с TypeRegistry."""

    pass


class UnknownTypeError(TypeRegistryError):
    """Ошибка: тип документа не найден."""

    pass


class UnknownSubtypeError(TypeRegistryError):
    """Ошибка: подтип не найден."""

    pass


class UnknownSeriesError(TypeRegistryError):
    """Ошибка: серия не найдена."""

    pass


class InvalidIndexError(TypeRegistryError):
    """Ошибка: неверный формат индекса."""

    pass


# =============================================================================
# DATACLASSES
# =============================================================================


@dataclass(frozen=True)
class IndexComponents:
    """Компоненты составного индекса документа.

    Представляет разобранный индекс вида DVN-44-K53-IX.

    Attributes:
        root_code: Корневой код типа (например, "DVN")
        subtype_code: Код подтипа (например, "44")
        series_code: Код серии (например, "K53")
        custom: Пользовательский сегмент (опционально)
        sequence: SEQUENCE в римских цифрах (например, "IX")

    Example:
        >>> components = IndexComponents(
        ...     root_code="DVN",
        ...     subtype_code="44",
        ...     series_code="K53",
        ...     sequence="IX",
        ... )
        >>> print(components.full_index())
        DVN-44-K53-IX
    """

    root_code: str
    subtype_code: str
    series_code: str
    sequence: str
    custom: Optional[str] = None

    def full_index(self) -> str:
        """Собрать полный индекс из компонентов.

        Returns:
            Строка индекса в формате ROOT-SUBTYPE-SERIES-SEQUENCE
            или ROOT-SUBTYPE-SERIES-CUSTOM-SEQUENCE если есть custom
        """
        parts = [
            self.root_code,
            self.subtype_code,
            self.series_code,
        ]
        if self.custom:
            parts.append(self.custom)
        parts.append(self.sequence)
        return "-".join(parts)

    def __str__(self) -> str:
        """Строковое представление компонентов."""
        return self.full_index()


# =============================================================================
# TYPE REGISTRY
# =============================================================================


class TypeRegistry:
    """Thread-safe Singleton реестр типов документов.

    Централизованное хранилище всех типов документов с поддержкой:
    - Регистрации типов документов
    - Генерации составных индексов
    - Парсинга индексов
    - Валидации индексов
    - Поиска по иерархии

    Attributes:
        _instance: Singleton instance
        _lock: RLock для thread-safety
        _types: Словарь {root_code -> DocumentType}
        _initialized: Флаг инициализации

    Example:
        >>> registry = TypeRegistry.get_instance()
        >>> registry.register_type(doc_type)
        >>> index = registry.generate_index("DVN", "44", "K53")
        >>> print(index)
        DVN-44-K53-I

    Thread Safety:
        Все публичные методы thread-safe благодаря RLock.
    """

    # Singleton instance (class-level)
    _instance: Optional[TypeRegistry] = None
    _lock: ClassVar[threading.RLock] = threading.RLock()

    def __init__(self) -> None:
        """Приватный конструктор (используйте get_instance()).

        Raises:
            RuntimeError: Если попытка создать второй экземпляр
        """
        if TypeRegistry._instance is not None:
            raise RuntimeError("TypeRegistry is a singleton. Use TypeRegistry.get_instance()")

        # Реестр: {root_code -> DocumentType}
        self._types: Dict[str, DocumentType] = {}

        # Флаг инициализации
        self._initialized: bool = False

        logger.info("TypeRegistry initialized")

    @classmethod
    def get_instance(cls) -> TypeRegistry:
        """Получить singleton instance реестра.

        Returns:
            Единственный экземпляр TypeRegistry

        Thread Safety:
            Thread-safe double-checked locking

        Example:
            >>> registry = TypeRegistry.get_instance()
            >>> registry2 = TypeRegistry.get_instance()
            >>> registry is registry2
            True
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
                    # Автоматически регистрируем встроенные типы
                    cls._instance._register_builtin_types()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Сбросить singleton (только для тестов).

        WARNING:
            Используйте только в unit-тестах!
            В production коде вызов этого метода может
            нарушить работу системы.
        """
        with cls._lock:
            cls._instance = None
            logger.warning("TypeRegistry instance reset (testing only!)")

    def _register_builtin_types(self) -> None:
        """Зарегистрировать встроенные типы документов.

        Регистрирует стандартные типы:
        - DVN (Verbal Note) с подтипами 44, 45
        - INV (Invoice) с подтипами I, II
        """
        with self._lock:
            if self._initialized:
                return

            # DVN - Verbal Note
            dvn_series_44 = [
                Series("K53", "Standard Series K53", True, "ROMAN"),
                Series("K54", "Standard Series K54", True, "ROMAN"),
            ]
            dvn_series_45 = [
                Series("K60", "Series K60", True, "ROMAN"),
            ]
            dvn_subtypes = [
                Subtype("44", "Verbal Note Type 44", dvn_series_44),
                Subtype("45", "Verbal Note Type 45", dvn_series_45),
            ]
            dvn = DocumentType(
                root_code="DVN",
                name="Verbal Note",
                description="Official verbal note document",
                icon="📄",
                subtypes=dvn_subtypes,
            )
            self._types["DVN"] = dvn

            # INV - Invoice
            inv_series = [
                Series("K01", "Invoice Series K01", False, "ROMAN"),
            ]
            inv_subtypes = [
                Subtype("I", "Invoice Type I", inv_series),
                Subtype("II", "Invoice Type II", inv_series),
            ]
            inv = DocumentType(
                root_code="INV",
                name="Invoice",
                description="Commercial invoice document",
                icon="🧾",
                subtypes=inv_subtypes,
            )
            self._types["INV"] = inv

            self._initialized = True
            logger.info(f"Registered {len(self._types)} built-in document types")

    def register_type(self, doc_type: DocumentType) -> None:
        """Зарегистрировать тип документа в реестре.

        Args:
            doc_type: Тип документа для регистрации

        Raises:
            TypeError: Если doc_type не DocumentType
            ValueError: Если тип с таким root_code уже существует

        Example:
            >>> doc_type = DocumentType(
            ...     root_code="NEW",
            ...     name="New Type",
            ...     description="Description",
            ...     icon="📋",
            ...     subtypes=[],
            ... )
            >>> registry.register_type(doc_type)

        Thread Safety:
            Thread-safe с RLock
        """
        with self._lock:
            if not isinstance(doc_type, DocumentType):
                raise TypeError(f"Expected DocumentType, got {type(doc_type).__name__}")

            root_code = doc_type.root_code
            if root_code in self._types:
                raise ValueError(f"Тип документа '{root_code}' уже зарегистрирован")

            self._types[root_code] = doc_type
            logger.info(f"Registered document type: {root_code}")

    def get_type(self, root_code: str) -> DocumentType:
        """Получить тип документа по root_code.

        Args:
            root_code: Корневой код типа (case-insensitive)

        Returns:
            DocumentType для данного root_code

        Raises:
            UnknownTypeError: Если тип не найден

        Example:
            >>> doc_type = registry.get_type("DVN")
            >>> print(doc_type.name)
            Verbal Note

        Thread Safety:
            Thread-safe с RLock
        """
        with self._lock:
            code_upper = root_code.upper()
            if code_upper not in self._types:
                available = ", ".join(sorted(self._types.keys()))
                raise UnknownTypeError(
                    f"Тип документа '{root_code}' не найден. Доступные: {available}"
                )
            return self._types[code_upper]

    def get_subtype(self, root_code: str, subtype_code: str) -> Subtype:
        """Получить подтип по кодам типа и подтипа.

        Args:
            root_code: Корневой код типа
            subtype_code: Код подтипа

        Returns:
            Subtype для данной комбинации

        Raises:
            UnknownTypeError: Если тип не найден
            UnknownSubtypeError: Если подтип не найден

        Example:
            >>> subtype = registry.get_subtype("DVN", "44")
            >>> print(subtype.name)
            Verbal Note Type 44

        Thread Safety:
            Thread-safe с RLock
        """
        with self._lock:
            doc_type = self.get_type(root_code)
            subtype = doc_type.get_subtype(subtype_code)
            if subtype is None:
                available = ", ".join(doc_type.list_subtype_codes())
                raise UnknownSubtypeError(
                    f"Подтип '{subtype_code}' не найден для типа '{root_code}'. "
                    f"Доступные: {available}"
                )
            return subtype

    def get_series(self, root_code: str, subtype_code: str, series_code: str) -> Series:
        """Получить серию по кодам типа, подтипа и серии.

        Args:
            root_code: Корневой код типа
            subtype_code: Код подтипа
            series_code: Код серии

        Returns:
            Series для данной комбинации

        Raises:
            UnknownTypeError: Если тип не найден
            UnknownSubtypeError: Если подтип не найден
            UnknownSeriesError: Если серия не найдена

        Example:
            >>> series = registry.get_series("DVN", "44", "K53")
            >>> print(series.name)
            Standard Series K53

        Thread Safety:
            Thread-safe с RLock
        """
        with self._lock:
            subtype = self.get_subtype(root_code, subtype_code)
            series = subtype.get_series(series_code)
            if series is None:
                available = ", ".join(subtype.list_series_codes())
                raise UnknownSeriesError(
                    f"Серия '{series_code}' не найдена для "
                    f"'{root_code}-{subtype_code}'. "
                    f"Доступные: {available}"
                )
            return series

    def generate_index(
        self,
        root_code: str,
        subtype_code: str,
        series_code: str,
        custom: Optional[str] = None,
        sequence: Optional[str] = None,
    ) -> str:
        """Сгенерировать составной индекс документа.

        Формат индекса: ROOT-SUBTYPE-SERIES-SEQUENCE
        или ROOT-SUBTYPE-SERIES-CUSTOM-SEQUENCE если custom указан

        SEQUENCE автоматически генерируется (начиная с "I") если не указан.
        Для получения следующего SEQUENCE используйте parse_index + инкремент.

        Args:
            root_code: Корневой код типа
            subtype_code: Код подтипа
            series_code: Код серии
            custom: Пользовательский сегмент (опционально)
            sequence: SEQUENCE в римских цифрах (по умолчанию "I")

        Returns:
            Строка составного индекса

        Raises:
            UnknownTypeError: Если тип не найден
            UnknownSubtypeError: Если подтип не найден
            UnknownSeriesError: Если серия не найдена

        Example:
            >>> index = registry.generate_index("DVN", "44", "K53")
            >>> print(index)
            DVN-44-K53-I
            >>> index = registry.generate_index("DVN", "44", "K53", custom="X")
            >>> print(index)
            DVN-44-K53-X-I

        Thread Safety:
            Thread-safe с RLock
        """
        with self._lock:
            # Валидация существования
            self.get_series(root_code, subtype_code, series_code)

            seq = sequence if sequence else "I"
            if not self._is_valid_roman(seq):
                raise InvalidIndexError(
                    f"Неверный формат SEQUENCE: {seq}. Ожидаются римские цифры."
                )

            parts = [root_code.upper(), subtype_code.upper(), series_code.upper()]
            if custom:
                parts.append(custom.upper())
            parts.append(seq.upper())

            return "-".join(parts)

    def parse_index(self, index: str) -> IndexComponents:
        """Разобрать составной индекс на компоненты.

        Разбирает индекс формата ROOT-SUBTYPE-SERIES-SEQUENCE
        или ROOT-SUBTYPE-SERIES-CUSTOM-SEQUENCE.

        Args:
            index: Строка индекса

        Returns:
            IndexComponents с разобранными частями

        Raises:
            InvalidIndexError: Если формат индекса неверный
            UnknownTypeError: Если тип не найден

        Example:
            >>> components = registry.parse_index("DVN-44-K53-IX")
            >>> print(components.root_code)
            DVN
            >>> print(components.sequence)
            IX

        Thread Safety:
            Thread-safe с RLock
        """
        with self._lock:
            if not index or not index.strip():
                raise InvalidIndexError("Индекс не может быть пустым")

            parts = index.strip().upper().split("-")
            if len(parts) < 4:
                raise InvalidIndexError(
                    f"Неверный формат индекса: {index}. "
                    "Ожидается: ROOT-SUBTYPE-SERIES-SEQUENCE "
                    "или ROOT-SUBTYPE-SERIES-CUSTOM-SEQUENCE"
                )

            # Последний сегмент всегда SEQUENCE (римские цифры)
            sequence = parts[-1]
            if not self._is_valid_roman(sequence):
                raise InvalidIndexError(f"SEQUENCE должен быть римскими цифлами: {sequence}")

            # Проверка валидности типа
            root_code = parts[0]
            if root_code not in self._types:
                raise UnknownTypeError(f"Неизвестный тип документа: {root_code}")

            # Разбор оставшихся сегментов
            subtype_code = parts[1]
            series_code = parts[2]
            custom = None

            # Если 5 частей: ROOT-SUBTYPE-SERIES-CUSTOM-SEQUENCE
            if len(parts) == 5:
                custom = parts[3]
            elif len(parts) > 5:
                raise InvalidIndexError(f"Слишком много сегментов в индексе: {index}")

            return IndexComponents(
                root_code=root_code,
                subtype_code=subtype_code,
                series_code=series_code,
                custom=custom,
                sequence=sequence,
            )

    def validate_index(self, index: str) -> bool:
        """Проверить валидность составного индекса.

        Проверяет:
        1. Формат индекса (минимум 4 сегмента)
        2. SEQUENCE - римские цифлы
        3. Существование типа в реестре

        Args:
            index: Строка индекса для проверки

        Returns:
            True если индекс валидный, False иначе

        Example:
            >>> registry.validate_index("DVN-44-K53-IX")
            True
            >>> registry.validate_index("INVALID-INDEX")
            False

        Thread Safety:
            Thread-safe с RLock
        """
        with self._lock:
            try:
                components = self.parse_index(index)
                # Проверяем существование в иерархии
                self.get_series(
                    components.root_code,
                    components.subtype_code,
                    components.series_code,
                )
                return True
            except (
                InvalidIndexError,
                UnknownTypeError,
                UnknownSubtypeError,
                UnknownSeriesError,
            ):
                return False
            except TypeError:
                return False

    def list_all_types(self) -> List[DocumentType]:
        """Получить список всех зарегистрированных типов.

        Returns:
            Список DocumentType (отсортирован по root_code)

        Example:
            >>> types = registry.list_all_types()
            >>> print([t.root_code for t in types])
            ['DVN', 'INV']

        Thread Safety:
            Thread-safe с RLock
        """
        with self._lock:
            return sorted(self._types.values(), key=lambda t: t.root_code)

    def list_type_codes(self) -> List[str]:
        """Получить список кодов всех типов.

        Returns:
            Список root_code (отсортирован)

        Example:
            >>> codes = registry.list_type_codes()
            >>> print(codes)
            ['DVN', 'INV']

        Thread Safety:
            Thread-safe с RLock
        """
        with self._lock:
            return sorted(self._types.keys())

    def is_registered(self, root_code: str) -> bool:
        """Проверить, зарегистрирован ли тип.

        Args:
            root_code: Корневой код типа

        Returns:
            True если тип зарегистрирован

        Example:
            >>> registry.is_registered("DVN")
            True
            >>> registry.is_registered("UNKNOWN")
            False

        Thread Safety:
            Thread-safe с RLock
        """
        with self._lock:
            return root_code.upper() in self._types

    def unregister_type(self, root_code: str) -> None:
        """Удалить тип документа из реестра.

        WARNING:
            Используйте с осторожностью! Удаление типа
            может нарушить работу зависимого кода.

        Args:
            root_code: Корневой код типа

        Raises:
            UnknownTypeError: Если тип не найден

        Thread Safety:
            Thread-safe с RLock
        """
        with self._lock:
            code_upper = root_code.upper()
            if code_upper not in self._types:
                raise UnknownTypeError(f"Тип '{root_code}' не найден в реестре")
            del self._types[code_upper]
            logger.warning(f"Unregistered document type: {root_code}")

    @staticmethod
    def _is_valid_roman(value: str) -> bool:
        """Проверить, является ли строка валидной римской цифрой.

        Args:
            value: Строка для проверки

        Returns:
            True если валидная римская цифра
        """
        if not value:
            return False
        upper = value.upper()
        if not ROMAN_NUMERAL_PATTERN.match(upper):
            return False
        # Дополнительная проверка: не более 3 одинаковых подряд
        # (кроме M, которых может быть до 4)
        for char in ["I", "X", "C"]:
            if char * 4 in upper:
                return False
        return True

    @staticmethod
    def roman_to_int(roman: str) -> int:
        """Конвертировать римскую цифлу в целое число.

        Args:
            roman: Римская цифра (например, "IX", "XLII")

        Returns:
            Целое число

        Raises:
            InvalidIndexError: Если римская цифра невалидна

        Example:
            >>> TypeRegistry.roman_to_int("IX")
            9
            >>> TypeRegistry.roman_to_int("XLII")
            42
        """
        if not TypeRegistry._is_valid_roman(roman):
            raise InvalidIndexError(f"Неверная римская цифла: {roman}")

        total = 0
        prev_value = 0
        for char in reversed(roman.upper()):
            value = ROMAN_TO_INT.get(char, 0)
            if value < prev_value:
                total -= value
            else:
                total += value
            prev_value = value
        return total

    @staticmethod
    def int_to_roman(num: int) -> str:
        """Конвертировать целое число в римскую цифлу.

        Args:
            num: Целое число (1-3999)

        Returns:
            Римская цифла

        Raises:
            InvalidIndexError: Если число вне диапазона

        Example:
            >>> TypeRegistry.int_to_roman(9)
            IX
            >>> TypeRegistry.int_to_roman(42)
            XLII
        """
        if not (1 <= num <= 3999):
            raise InvalidIndexError(f"Число {num} вне диапазона 1-3999 для римских цифл")

        result = ""
        for value, symbol in INT_TO_ROMAN:
            while num >= value:
                result += symbol
                num -= value
        return result

    def next_sequence(self, current_sequence: str) -> str:
        """Получить следующую SEQUENCE после текущей.

        Args:
            current_sequence: Текущая SEQUENCE (римские цифлы)

        Returns:
            Следующая SEQUENCE

        Raises:
            InvalidIndexError: Если текущая SEQUENCE невалидна

        Example:
            >>> registry.next_sequence("I")
            II
            >>> registry.next_sequence("IX")
            X

        Thread Safety:
            Thread-safe (stateless operation)
        """
        current_num = self.roman_to_int(current_sequence)
        return self.int_to_roman(current_num + 1)
