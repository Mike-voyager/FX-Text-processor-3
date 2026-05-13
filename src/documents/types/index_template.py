"""Шаблоны полей для типов документов.

Определяет структуру полей, валидацию и правила для каждого типа документа.
Каждый тип документа имеет свой IndexTemplate с набором TemplateField.

Example:
    >>> from src.documents.types.index_template import (
    ...     IndexTemplate, TemplateField, FieldType, ValidationRule
    ... )
    >>> field = TemplateField(
    ...     field_id="recipient",
    ...     name="Recipient Name",
    ...     field_type=FieldType.TEXT,
    ...     required=True,
    ... )
    >>> template = IndexTemplate(
    ...     type_code="DVN",
    ...     fields=[field],
    ...     validation_rules=[],
    ... )
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple


class SegmentType(str, Enum):
    """Типы сегментов в иерархическом индексе документа.

    Attributes:
        ROOT_CODE: Корневой код типа документа.
        SUBTYPE: Подтип документа.
        SERIES: Серия документа.
        CUSTOM: Пользовательский сегмент.
        SEQUENCE: Порядковый номер (римские цифры).
    """

    ROOT_CODE = "root"
    SUBTYPE = "subtype"
    SERIES = "series"
    CUSTOM = "custom"
    SEQUENCE = "sequence"


class FieldType(Enum):
    """Типы полей в шаблоне документа.

    Attributes:
        TEXT: Текстовое поле
        NUMBER: Числовое поле (целое или дробное)
        DATE: Поле даты
        DROPDOWN: Выпадающий список
        TABLE: Таблица
        SIGNATURE: Поле подписи
        STAMP: Поле штампа
        BARCODE: Штрих-код
        QR: QR-код
        MULTILINE: Многострочный текст
        CURRENCY: Денежное поле
        PERCENT: Процентное поле
        EMAIL: Email адрес
        PHONE: Телефонный номер
        CUSTOM: Пользовательский тип
    """

    TEXT = "TEXT"
    NUMBER = "NUMBER"
    DATE = "DATE"
    DROPDOWN = "DROPDOWN"
    TABLE = "TABLE"
    SIGNATURE = "SIGNATURE"
    STAMP = "STAMP"
    BARCODE = "BARCODE"
    QR = "QR"
    MULTILINE = "MULTILINE"
    CURRENCY = "CURRENCY"
    PERCENT = "PERCENT"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    CUSTOM = "CUSTOM"


class ValidationOperator(Enum):
    """Операторы для правил валидации.

    Attributes:
        EQUALS: Равно (=)
        NOT_EQUALS: Не равно (!=)
        GREATER_THAN: Больше (>)
        LESS_THAN: Меньше (<)
        GREATER_EQUAL: Больше или равно (>=)
        LESS_EQUAL: Меньше или равно (<=)
        CONTAINS: Содержит подстроку
        STARTS_WITH: Начинается с
        ENDS_WITH: Заканчивается на
        MATCHES: Соответствует регулярному выражению
        IN_LIST: В списке значений
        NOT_EMPTY: Не пустое
    """

    EQUALS = "EQUALS"
    NOT_EQUALS = "NOT_EQUALS"
    GREATER_THAN = "GREATER_THAN"
    LESS_THAN = "LESS_THAN"
    GREATER_EQUAL = "GREATER_EQUAL"
    LESS_EQUAL = "LESS_EQUAL"
    CONTAINS = "CONTAINS"
    STARTS_WITH = "STARTS_WITH"
    ENDS_WITH = "ENDS_WITH"
    MATCHES = "MATCHES"
    IN_LIST = "IN_LIST"
    NOT_EMPTY = "NOT_EMPTY"


@dataclass(frozen=True)
class IndexSegmentDef:
    """Определение сегмента в иерархическом индексе документа.

    Attributes:
        name: Имя сегмента (идентификатор).
        segment_type: Тип сегмента из SegmentType.
        label: Локализованная метка (русский).
        label_en: Локализованная метка (английский).
        pattern: Regex паттерн для валидации.
        allowed_values: Допустимые значения (опционально).
        auto_increment: Автоинкремент для SEQUENCE.

    Example:
        >>> segment = IndexSegmentDef(
        ...     name="type",
        ...     segment_type=SegmentType.ROOT_CODE,
        ...     label="Тип",
        ...     label_en="Type",
        ...     pattern=r"[A-Z]{3}",
        ... )
    """

    name: str
    segment_type: SegmentType
    label: str
    label_en: str
    pattern: str
    allowed_values: tuple[str, ...] | None = None
    auto_increment: bool = False

    def __post_init__(self) -> None:
        """Валидация после инициализации."""
        if not self.name or not self.name.strip():
            raise ValueError("name не может быть пустым")
        if not self.label or not self.label.strip():
            raise ValueError("label не может быть пустым")
        if not self.label_en or not self.label_en.strip():
            raise ValueError("label_en не может быть пустым")
        if not self.pattern or not self.pattern.strip():
            raise ValueError("pattern не может быть пустым")


@dataclass(frozen=True)
class ValidationRule:
    """Правило валидации для поля или шаблона.

    Attributes:
        rule_id: Уникальный идентификатор правила
        field_id: ID поля для валидации (None для правил уровня шаблона)
        operator: Оператор сравнения
        value: Значение для сравнения (зависит от оператора)
        error_message: Сообщение об ошибке при нарушении правила
        error_code: Код ошибки для программной обработки

    Example:
        >>> rule = ValidationRule(
        ...     rule_id="recipient_required",
        ...     field_id="recipient",
        ...     operator=ValidationOperator.NOT_EMPTY,
        ...     value=None,
        ...     error_message="Получатель обязателен",
        ...     error_code="ERR_RECIPIENT_EMPTY",
        ... )
    """

    rule_id: str
    operator: ValidationOperator
    field_id: Optional[str] = None
    value: Optional[str] = None
    error_message: str = ""
    error_code: str = ""

    def __post_init__(self) -> None:
        """Валидация правила после инициализации."""
        if not self.rule_id or not self.rule_id.strip():
            raise ValueError("ID правила не может быть пустым")
        if self.operator in (
            ValidationOperator.EQUALS,
            ValidationOperator.NOT_EQUALS,
            ValidationOperator.GREATER_THAN,
            ValidationOperator.LESS_THAN,
            ValidationOperator.GREATER_EQUAL,
            ValidationOperator.LESS_EQUAL,
            ValidationOperator.MATCHES,
            ValidationOperator.IN_LIST,
        ):
            if self.value is None:
                raise ValueError(f"Оператор {self.operator.value} требует значения")


@dataclass(frozen=True)
class TemplateField:
    """Поле в шаблоне документа.

    Определяет свойства поля для ввода данных в форме.

    Attributes:
        field_id: Уникальный идентификатор поля
        name: Отображаемое название поля
        field_type: Тип поля (FieldType)
        required: Обязательное ли поле
        default_value: Значение по умолчанию
        validation_pattern: Regex паттерн для валидации
        max_length: Максимальная длина (для текстовых полей)
        min_value: Минимальное значение (для числовых полей)
        max_value: Максимальное значение (для числовых полей)
        options: Опции для DROPDOWN (список значений)
        placeholder: Placeholder текст для пустого поля
        help_text: Вспомогательный текст под полем
        order: Порядок отображения поля

    Example:
        >>> field = TemplateField(
        ...     field_id="recipient",
        ...     name="Recipient Name",
        ...     field_type=FieldType.TEXT,
        ...     required=True,
        ...     max_length=100,
        ...     placeholder="Enter recipient name",
        ... )
    """

    field_id: str
    name: str
    field_type: FieldType
    required: bool = False
    default_value: Optional[str] = None
    validation_pattern: Optional[str] = None
    max_length: Optional[int] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    options: List[str] = field(default_factory=list)
    placeholder: str = ""
    help_text: str = ""
    order: int = 0

    def __post_init__(self) -> None:
        """Валидация поля после инициализации."""
        if not self.field_id or not self.field_id.strip():
            raise ValueError("ID поля не может быть пустым")
        if not self.name or not self.name.strip():
            raise ValueError("Название поля не может быть пустым")
        if self.max_length is not None and self.max_length <= 0:
            raise ValueError("max_length должен быть положительным")
        if self.min_value is not None and self.max_value is not None:
            if self.min_value > self.max_value:
                raise ValueError("min_value не может быть больше max_value")

    def validate_value(self, value: Optional[str]) -> List[str]:
        """Валидировать значение поля.

        Args:
            value: Значение для проверки

        Returns:
            Список сообщений об ошибках (пустой если валидно)

        Example:
            >>> errors = field.validate_value("")
            >>> print(errors)
            ['Поле обязательно для заполнения']
        """
        errors: List[str] = []

        # Проверка обязательности
        if self.required and (value is None or value.strip() == ""):
            errors.append(f"Поле '{self.name}' обязательно для заполнения")
            return errors  # Дальше не проверяем если пустое обязательное поле

        if value is None or value.strip() == "":
            return errors  # Необязательное пустое поле

        val = value.strip()

        # Проверка длины
        if self.max_length is not None and len(val) > self.max_length:
            errors.append(
                f"Длина поля '{self.name}' не должна превышать {self.max_length} символов"
            )

        # Проверка паттерна
        if self.validation_pattern:
            import re

            if not re.match(self.validation_pattern, val):
                errors.append(f"Значение поля '{self.name}' не соответствует требуемому формату")

        # Проверка числового значения
        if self.field_type == FieldType.NUMBER and val:
            try:
                num_val = float(val)
                if self.min_value is not None and num_val < self.min_value:
                    errors.append(
                        f"Значение поля '{self.name}' должно быть не менее {self.min_value}"
                    )
                if self.max_value is not None and num_val > self.max_value:
                    errors.append(
                        f"Значение поля '{self.name}' должно быть не более {self.max_value}"
                    )
            except ValueError:
                errors.append(f"Поле '{self.name}' должно быть числом")

        return errors


@dataclass
class IndexTemplate:
    """Шаблон полей для типа документа.

    Определяет структуру формы для конкретного типа документа.
    Каждый тип документа имеет свой IndexTemplate.

    Attributes:
        segments: Кортеж определений сегментов индекса (новый API)
        separator: Разделитель сегментов индекса
        type_code: Код типа документа (например, "DVN") (устаревшее)
        fields: Список полей шаблона (устаревшее)
        validation_rules: Список правил валидации уровня шаблона (устаревшее)
        description: Описание шаблона (устаревшее)
        version: Версия шаблона (устаревшее)

    Example:
        >>> template = IndexTemplate(
        ...     segments=(
        ...         IndexSegmentDef(
        ...             name="type",
        ...             segment_type=SegmentType.ROOT_CODE,
        ...             label="Тип",
        ...             label_en="Type",
        ...             pattern=r"[A-Z]{3}",
        ...         ),
        ...     ),
        ...     separator="-",
        ... )
    """

    segments: Tuple[IndexSegmentDef, ...] = field(default_factory=tuple)
    separator: str = "-"
    type_code: str = ""
    fields: List[TemplateField] = field(default_factory=list)
    validation_rules: List[ValidationRule] = field(default_factory=list)
    description: str = ""
    version: str = "1.0"

    def __post_init__(self) -> None:
        """Валидация шаблона после инициализации."""
        # Если используется новый API с segments
        if self.segments:
            # Проверка что есть хотя бы один сегмент
            if len(self.segments) == 0:
                raise ValueError("must have at least one segment")
            # Проверка что последний сегмент - SEQUENCE
            if self.segments[-1].segment_type != SegmentType.SEQUENCE:
                raise ValueError("Last segment must be SEQUENCE")
            # Проверка уникальности имен сегментов
            names = [s.name for s in self.segments]
            if len(names) != len(set(names)):
                raise ValueError("Имена сегментов должны быть уникальными")
            return

        # Устаревший API с type_code/fields - не пустые segments обязательны
        raise ValueError("must have at least one segment")
        self.type_code = self.type_code.strip().upper()

        # Проверка уникальности field_id
        field_ids = [f.field_id for f in self.fields]
        if len(field_ids) != len(set(field_ids)):
            raise ValueError("ID полей должны быть уникальными")

        # Проверка уникальности rule_id
        rule_ids = [r.rule_id for r in self.validation_rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("ID правил должны быть уникальными")

    @property
    def sequence_segment(self) -> IndexSegmentDef:
        """Возвращает последний сегмент (SEQUENCE).

        Returns:
            Последний сегмент шаблона.
        """
        return self.segments[-1]

    @property
    def non_sequence_segments(self) -> Tuple[IndexSegmentDef, ...]:
        """Возвращает все сегменты кроме последнего (SEQUENCE).

        Returns:
            Кортеж сегментов, исключая SEQUENCE.
        """
        return self.segments[:-1]

    def _int_to_roman(self, num: int) -> str:
        """Конвертирует целое число в римские цифры.

        Args:
            num: Число от 1 до 3999.

        Returns:
            Римские цифры в верхнем регистре.

        Raises:
            ValueError: Если число вне диапазона 1-3999.
        """
        if not 1 <= num <= 3999:
            raise ValueError(f"Number must be between 1 and 3999, got {num}")

        val = [1000, 900, 500, 400, 100, 90, 50, 40, 10, 9, 5, 4, 1]
        syms = ["M", "CM", "D", "CD", "C", "XC", "L", "XL", "X", "IX", "V", "IV", "I"]

        roman = ""
        i = 0
        while num > 0:
            for _ in range(num // val[i]):
                roman += syms[i]
                num -= val[i]
            i += 1
        return roman

    def _roman_to_int(self, roman: str) -> int:
        """Конвертирует римские цифры в целое число.

        Args:
            roman: Римские цифры в верхнем регистре.

        Returns:
            Целое число.

        Raises:
            ValueError: Если строка не является валидными римскими цифрами.
        """
        roman = roman.upper().strip()
        if not roman:
            raise ValueError("Empty roman numeral")

        roman_map = {"I": 1, "V": 5, "X": 10, "L": 50, "C": 100, "D": 500, "M": 1000}

        total = 0
        prev_value = 0

        for char in reversed(roman):
            if char not in roman_map:
                raise ValueError(f"Invalid roman numeral character: {char}")
            value = roman_map[char]
            if value < prev_value:
                total -= value
            else:
                total += value
            prev_value = value

        return total

    def format(self, values: dict[str, str], sequence: int) -> str:
        """Форматирует индекс из значений сегментов.

        Args:
            values: Словарь {имя_сегмента: значение}.
            sequence: Порядковый номер (преобразуется в римские цифры).

        Returns:
            Сформированный индекс.

        Raises:
            ValueError: Если отсутствует значение для обязательного сегмента.
        """
        import re

        segments: list[str] = []

        for segment in self.non_sequence_segments:
            if segment.name not in values:
                raise ValueError(f"Missing required segment value: {segment.name}")
            value = values[segment.name]
            # Проверка паттерна
            if not re.match(segment.pattern, value):
                raise ValueError(f"Value '{value}' doesn't match pattern {segment.pattern}")
            segments.append(value)

        # Добавляем SEQUENCE (римские цифры)
        segments.append(self._int_to_roman(sequence))

        return self.separator.join(segments)

    def parse(self, index_str: str) -> dict[str, str]:
        """Парсит индекс в значения сегментов.

        Args:
            index_str: Строка индекса.

        Returns:
            Словарь {имя_сегмента: значение} без SEQUENCE.

        Raises:
            ValueError: Если индекс не соответствует шаблону.
        """
        import re

        parts = index_str.split(self.separator)
        expected = len(self.segments)

        if len(parts) != expected:
            raise ValueError(f"Index '{index_str}' has {len(parts)} segments, expected {expected}")

        values: dict[str, str] = {}

        # Парсим все кроме SEQUENCE (последний)
        for i, segment in enumerate(self.non_sequence_segments):
            value = parts[i]
            # Проверка паттерна
            if not re.match(segment.pattern, value):
                raise ValueError(f"Segment '{value}' doesn't match pattern {segment.pattern}")
            # Проверка allowed_values
            if segment.allowed_values and value not in segment.allowed_values:
                raise ValueError(f"Value '{value}' not in allowed values: {segment.allowed_values}")
            values[segment.name] = value

        # Проверяем SEQUENCE
        seq_value = parts[-1]
        seq_segment = self.sequence_segment
        if not re.match(seq_segment.pattern, seq_value):
            raise ValueError(f"Sequence '{seq_value}' doesn't match pattern {seq_segment.pattern}")

        return values

    def validate(self, index_str: str) -> bool:
        """Проверяет соответствие индекса шаблону.

        Args:
            index_str: Строка индекса.

        Returns:
            True если индекс валиден, False иначе.
        """
        try:
            self.parse(index_str)
            return True
        except ValueError:
            return False

    def get_field(self, field_id: str) -> Optional[TemplateField]:
        """Получить поле по ID.

        Args:
            field_id: Идентификатор поля

        Returns:
            TemplateField или None если не найдено

        Example:
            >>> field = template.get_field("recipient")
            >>> print(field.name if field else "Not found")
            Recipient
        """
        for fld in self.fields:
            if fld.field_id == field_id:
                return fld
        return None

    def get_required_fields(self) -> List[TemplateField]:
        """Получить список обязательных полей.

        Returns:
            Список обязательных полей

        Example:
            >>> required = template.get_required_fields()
            >>> print([f.name for f in required])
            ['Recipient', 'Date']
        """
        return [f for f in self.fields if f.required]

    def validate_data(self, data: dict[str, str]) -> List[str]:
        """Валидировать данные формы.

        Проверяет все поля и правила валидации шаблона.

        Args:
            data: Словарь {field_id: value}

        Returns:
            Список ошибок валидации (пустой если валидно)

        Example:
            >>> data = {"recipient": "John Doe", "date": "2026-04-05"}
            >>> errors = template.validate_data(data)
            >>> print(errors)
            []
        """
        errors: List[str] = []

        # Валидация каждого поля
        for fld in self.fields:
            value = data.get(fld.field_id)
            field_errors = fld.validate_value(value)
            errors.extend(field_errors)

        # Валидация правил уровня шаблона
        for rule in self.validation_rules:
            if rule.field_id:
                # Правило для конкретного поля
                field = self.get_field(rule.field_id)
                if field:
                    value = data.get(rule.field_id)
                    if not self._check_rule(rule, value):
                        errors.append(rule.error_message or f"Ошибка валидации: {rule.rule_id}")

        return errors

    def _check_rule(self, rule: ValidationRule, value: Optional[str]) -> bool:
        """Проверить значение по правилу валидации.

        Args:
            rule: Правило валидации
            value: Значение для проверки

        Returns:
            True если правило выполнено
        """
        import re

        op = rule.operator
        val = value.strip() if value else ""
        ref = rule.value or ""

        if op == ValidationOperator.NOT_EMPTY:
            return len(val) > 0
        if op == ValidationOperator.EQUALS:
            return val == ref
        if op == ValidationOperator.NOT_EQUALS:
            return val != ref
        if op == ValidationOperator.CONTAINS:
            return ref in val
        if op == ValidationOperator.STARTS_WITH:
            return val.startswith(ref)
        if op == ValidationOperator.ENDS_WITH:
            return val.endswith(ref)
        if op == ValidationOperator.MATCHES:
            return bool(re.match(ref, val))
        if op == ValidationOperator.IN_LIST:
            options = [v.strip() for v in ref.split(",")]
            return val in options

        # Числовые операции
        try:
            num_val = float(val) if val else 0.0
            num_ref = float(ref)
            if op == ValidationOperator.GREATER_THAN:
                return num_val > num_ref
            if op == ValidationOperator.LESS_THAN:
                return num_val < num_ref
            if op == ValidationOperator.GREATER_EQUAL:
                return num_val >= num_ref
            if op == ValidationOperator.LESS_EQUAL:
                return num_val <= num_ref
        except ValueError:
            return False

        return True

    def to_dict(self) -> dict:
        """Сериализовать шаблон в словарь.

        Returns:
            Словарь с данными шаблона

        Example:
            >>> data = template.to_dict()
            >>> print(data["type_code"])
            DVN
        """
        return {
            "type_code": self.type_code,
            "description": self.description,
            "version": self.version,
            "fields": [
                {
                    "field_id": f.field_id,
                    "name": f.name,
                    "field_type": f.field_type.value,
                    "required": f.required,
                    "default_value": f.default_value,
                    "validation_pattern": f.validation_pattern,
                    "max_length": f.max_length,
                    "min_value": f.min_value,
                    "max_value": f.max_value,
                    "options": f.options,
                    "placeholder": f.placeholder,
                    "help_text": f.help_text,
                    "order": f.order,
                }
                for f in self.fields
            ],
            "validation_rules": [
                {
                    "rule_id": r.rule_id,
                    "field_id": r.field_id,
                    "operator": r.operator.value,
                    "value": r.value,
                    "error_message": r.error_message,
                    "error_code": r.error_code,
                }
                for r in self.validation_rules
            ],
        }

    @classmethod
    def from_dict(cls, data: dict) -> IndexTemplate:
        """Создать шаблон из словаря.

        Args:
            data: Словарь с данными шаблона

        Returns:
            IndexTemplate

        Example:
            >>> data = {"type_code": "DVN", "fields": [], "validation_rules": []}
            >>> template = IndexTemplate.from_dict(data)
        """
        fields = [
            TemplateField(
                field_id=f["field_id"],
                name=f["name"],
                field_type=FieldType(f["field_type"]),
                required=f.get("required", False),
                default_value=f.get("default_value"),
                validation_pattern=f.get("validation_pattern"),
                max_length=f.get("max_length"),
                min_value=f.get("min_value"),
                max_value=f.get("max_value"),
                options=f.get("options", []),
                placeholder=f.get("placeholder", ""),
                help_text=f.get("help_text", ""),
                order=f.get("order", 0),
            )
            for f in data.get("fields", [])
        ]

        rules = [
            ValidationRule(
                rule_id=r["rule_id"],
                field_id=r.get("field_id"),
                operator=ValidationOperator(r["operator"]),
                value=r.get("value"),
                error_message=r.get("error_message", ""),
                error_code=r.get("error_code", ""),
            )
            for r in data.get("validation_rules", [])
        ]

        return cls(
            type_code=data["type_code"],
            fields=fields,
            validation_rules=rules,
            description=data.get("description", ""),
            version=data.get("version", "1.0"),
        )
