"""Type registry - singleton registry for document types.

Provides thread-safe singleton access to all registered document types.
"""

from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Iterator

from src.documents.types.document_type import DocumentSubtype, DocumentType


@dataclass
class TypeRegistry:
    """Singleton реестр всех зарегистрированных типов документов.

    Thread-safe: все мутации через Lock.
    Загружает встроенные типы при инициализации.

    Example:
        >>> registry = TypeRegistry.get_instance()
        >>> dvn = registry.get("DVN")
        >>> print(dvn.name)
        'Вербальная нота'
        >>> subtypes = registry.list_children("DVN")
        >>> for st in subtypes:
        ...     print(st.name)
    """

    _instance: "TypeRegistry | None" = None
    _lock: Lock = Lock()

    # Internal storage
    _types: dict[str, DocumentType] = field(default_factory=dict)
    _subtypes: dict[str, list[DocumentSubtype]] = field(default_factory=dict)
    _initialized: bool = field(default=False, init=False)

    def __new__(cls) -> "TypeRegistry":
        """Создаёт singleton экземпляр."""
        if cls._instance is None:
            with cls._lock:
                # Double-checked locking
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._types = {}
                    cls._instance._subtypes = {}
                    cls._instance._initialized = False
        return cls._instance

    @classmethod
    def get_instance(cls) -> "TypeRegistry":
        """Возвращает единственный экземпляр реестра.

        При первом вызове загружает встроенные типы документов.
        """
        instance = cls()
        if not instance._initialized:
            instance._initialize_builtin_types()
            instance._initialized = True
        return instance

    def _initialize_builtin_types(self) -> None:
        """Загружает встроенные типы документов."""
        # Import here to avoid circular imports
        from src.documents.types.builtin.base import DOC
        from src.documents.types.builtin.invoice import INV
        from src.documents.types.builtin.verbal_note import DVN

        # Register built-in types
        self.register_type(DOC)
        self.register_type(INV)
        self.register_type(DVN)

    def register_type(self, doc_type: DocumentType) -> DocumentType:
        """Регистрирует новый тип документа.

        Args:
            doc_type: Тип документа для регистрации.

        Returns:
            Зарегистрированный тип.

        Raises:
            ValueError: Если тип с таким кодом уже зарегистрирован.
        """
        with self._lock:
            if doc_type.code in self._types:
                raise ValueError(
                    f"Document type '{doc_type.code}' is already registered"
                )

            self._types[doc_type.code] = doc_type

            # Инициализируем список подтипов
            if doc_type.code not in self._subtypes:
                self._subtypes[doc_type.code] = []

            # Если есть подтипы в DocumentType, добавляем их
            for subtype in doc_type.subtypes:
                self._subtypes[doc_type.code].append(subtype)

        return doc_type

    def register_subtype(
        self,
        parent_code: str,
        subtype: DocumentSubtype,
    ) -> DocumentSubtype:
        """Регистрирует подтип для существующего типа документа.

        Args:
            parent_code: Код родительского типа.
            subtype: Подтип для регистрации.

        Returns:
            Зарегистрированный подтип.

        Raises:
            KeyError: Если родительский тип не найден.
        """
        with self._lock:
            if parent_code not in self._types:
                raise KeyError(f"Parent document type '{parent_code}' not found")

            if parent_code not in self._subtypes:
                self._subtypes[parent_code] = []

            self._subtypes[parent_code].append(subtype)

            # Обновляем тип с новым подтипом
            parent_type = self._types[parent_code]
            updated_subtypes = list(parent_type.subtypes) + [subtype]

            # Создаём новый экземпляр с обновлёнными подтипами
            self._types[parent_code] = DocumentType(
                code=parent_type.code,
                name=parent_type.name,
                parent_code=parent_type.parent_code,
                index_template=parent_type.index_template,
                field_schema=parent_type.field_schema,
                subtypes=tuple(updated_subtypes),
                metadata=parent_type.metadata,
            )

        return subtype

    def get(self, code: str) -> DocumentType:
        """Возвращает тип по коду.

        Args:
            code: Код типа документа.

        Returns:
            Тип документа.

        Raises:
            KeyError: Если тип не найден.
        """
        with self._lock:
            if code not in self._types:
                raise KeyError(f"Document type '{code}' not found")
            return self._types[code]

    def get_or_none(self, code: str) -> DocumentType | None:
        """Возвращает тип по коду или None если не найден.

        Args:
            code: Код типа документа.

        Returns:
            Тип документа или None.
        """
        with self._lock:
            return self._types.get(code)

    def list_children(self, parent_code: str) -> list[DocumentType]:
        """Возвращает все подтипы указанного родительского типа.

        Args:
            parent_code: Код родительского типа.

        Returns:
            Список подтипов (все имеют parent_code = parent_code).
        """
        with self._lock:
            return [
                doc_type
                for doc_type in self._types.values()
                if doc_type.parent_code == parent_code
            ]

    def list_subtypes(self, parent_code: str) -> list[DocumentSubtype]:
        """Возвращает все подтипы (DocumentSubtype) для родительского типа.

        Args:
            parent_code: Код родительского типа.

        Returns:
            Список подтипов.
        """
        with self._lock:
            return self._subtypes.get(parent_code, [])

    def list_all(self) -> list[DocumentType]:
        """Возвращает список всех зарегистрированных типов.

        Returns:
            Список всех типов документов.
        """
        with self._lock:
            return list(self._types.values())

    def list_roots(self) -> list[DocumentType]:
        """Возвращает только корневые типы (без родителя).

        Returns:
            Список корневых типов.
        """
        with self._lock:
            return [
                doc_type
                for doc_type in self._types.values()
                if doc_type.parent_code is None
            ]

    def unregister(self, code: str) -> bool:
        """Удаляет тип документа из реестра.

        Не работает для встроенных типов (DVN, INV, DOC).

        Args:
            code: Код типа для удаления.

        Returns:
            True если удалён, False если не найден или защищён.
        """
        protected = {"DVN", "INV", "DOC"}
        if code in protected:
            return False

        with self._lock:
            if code in self._types:
                del self._types[code]
                if code in self._subtypes:
                    del self._subtypes[code]
                return True
            return False

    def __contains__(self, code: str) -> bool:
        """Проверяет наличие типа в реестре."""
        with self._lock:
            return code in self._types

    def __iter__(self) -> Iterator[DocumentType]:
        """Итератор по всем типам."""
        with self._lock:
            return iter(list(self._types.values()))

    def __len__(self) -> int:
        """Количество зарегистрированных типов."""
        with self._lock:
            return len(self._types)

    @classmethod
    def reset_instance(cls) -> None:
        """Сбрасывает экземпляр (для тестирования).

        Warning: Не использовать в production коде.
        """
        with cls._lock:
            cls._instance = None