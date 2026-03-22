"""Сервис для работы со штрихкодами.

Отделяет бизнес-логику рендеринга и валидации от модели Barcode.
Модель (src/model/barcodegen.py) содержит только данные и простую валидацию полей.
Этот сервис отвечает за:
- Получение генератора по типу штрихкода
- Валидацию с рендерингом (проверка возможности генерации)
- Manifest поддерживаемых типов

Module: src/services/barcode_service.py
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, ClassVar, Dict, Optional, Tuple, Type, Union

if TYPE_CHECKING:
    from src.barcodegen.barcode_generator import BarcodeGenerator
    from src.barcodegen.matrix2d_generator import Matrix2DCodeGenerator
    from src.model.barcodegen import Barcode
    from src.model.enums import BarcodeType, Matrix2DCodeType

logger = logging.getLogger(__name__)


class BarcodeService:
    """Сервис для работы со штрихкодами.

    Содержит бизнес-логику, вынесенную из модели Barcode:
    - Manifest поддерживаемых типов и генераторов
    - Получение генератора для рендеринга
    - Валидация с вызовом внешнего рендерера

    Модель Barcode остаётся чистой dataclass без внешних зависимостей.

    Example:
        >>> from src.services.barcode_service import BarcodeService
        >>> from src.model.barcodegen import Barcode
        >>> barcode = Barcode(type=BarcodeType.EAN13, data="978014300723")
        >>> ok, error = BarcodeService.validate_with_render(barcode)
        >>> if not ok:
        ...     print(f"Ошибка: {error}")
        >>> generator = BarcodeService.get_renderer(barcode)
    """

    # Central manifest: levels, allowlist, generators
    _GENERATOR_MANIFEST: ClassVar[Dict[str, Dict[str, Any]]] = {
        "1d": {
            "types": None,  # Заполняется лениво при первом обращении
            "generator": None,  # Заполняется лениво
            "err": None,  # Заполняется лениво
            "level": "soft",
            "options_allowlist": {"show_label", "foreground", "background"},
        },
        "2d": {
            "types": None,  # Заполняется лениво
            "generator": None,  # Заполняется лениво
            "err": None,  # Заполняется лениво
            "level": "soft",
            "options_allowlist": {"gs1_mode", "caption", "foreground", "background"},
        },
        "escp": {
            "types": set(),  # ESC/P barcode types, to be filled in production
            "generator": None,  # e.g. ESCBarcodeGenerator
            "err": None,  # e.g. ESCGenErrorException
            "level": "hard",
            "options_allowlist": {"border", "padding", "caption"},
        },
    }

    @classmethod
    def _lazy_import_generators(cls) -> None:
        """Ленивый импорт генераторов для избежания циклических зависимостей."""
        if cls._GENERATOR_MANIFEST["1d"]["generator"] is None:
            try:
                from src.barcodegen.barcode_generator import BarcodeGenerator, BarcodeGenError
                from src.barcodegen.matrix2d_generator import (
                    Matrix2DCodeGenerator,
                    Matrix2DCodeGenError,
                )

                cls._GENERATOR_MANIFEST["1d"]["types"] = BarcodeGenerator.supported_types()
                cls._GENERATOR_MANIFEST["1d"]["generator"] = BarcodeGenerator
                cls._GENERATOR_MANIFEST["1d"]["err"] = BarcodeGenError

                cls._GENERATOR_MANIFEST["2d"]["types"] = Matrix2DCodeGenerator.all_supported_types()
                cls._GENERATOR_MANIFEST["2d"]["generator"] = Matrix2DCodeGenerator
                cls._GENERATOR_MANIFEST["2d"]["err"] = Matrix2DCodeGenError
            except ImportError as e:
                logger.warning(f"Не удалось импортировать генераторы штрихкодов: {e}")

    @classmethod
    def supported_matrix(cls) -> Dict[str, Dict[str, Any]]:
        """Возвращает manifest поддерживаемых типов.

        Используется для API/GUI autodocs/checklists.

        Returns:
            Словарь с информацией о каждом поддерживаемом типе:
            - layer: Категория (1d, 2d, escp)
            - support_level: Уровень поддержки (soft/hard)
            - options_allowlist: Разрешённые опции
            - generator: Класс генератора
            - err: Класс ошибки
        """
        cls._lazy_import_generators()
        result: Dict[str, Dict[str, Any]] = {}
        for key, entry in cls._GENERATOR_MANIFEST.items():
            types = entry.get("types") or set()
            for t in types:
                result[str(t)] = {
                    "layer": key,
                    "support_level": entry.get("level", "soft"),
                    "options_allowlist": list(entry.get("options_allowlist", [])),
                    "generator": entry["generator"],
                    "err": entry["err"],
                }
        return result

    @classmethod
    def get_renderer(
        cls, barcode: "Barcode"
    ) -> Optional[Union["BarcodeGenerator", "Matrix2DCodeGenerator", Any]]:
        """Возвращает генератор для указанного штрихкода.

        Args:
            barcode: Объект Barcode с типом и данными

        Returns:
            Экземпляр генератора для рендеринга

        Raises:
            ValueError: Если тип штрихкода не поддерживается

        Example:
            >>> generator = BarcodeService.get_renderer(barcode)
            >>> image = generator.renderimage(width=200, height=100)
        """
        cls._lazy_import_generators()
        btype = barcode.type
        for gen_key, entry in cls._GENERATOR_MANIFEST.items():
            types = entry.get("types") or set()
            if btype in types:
                gen_cls: Type[Any] = entry["generator"]
                extra: Dict[str, Any] = {}
                if gen_key == "2d" and hasattr(barcode, "gs1_mode"):
                    extra["gs1_mode"] = barcode.gs1_mode or False
                return gen_cls(btype, barcode.data, barcode.options, **extra)
        raise ValueError(f"Barcode type {btype} is not supported by any generator.")

    @classmethod
    def validate_with_render(
        cls, barcode: "Barcode", preview_size: Tuple[int, int] = (32, 32)
    ) -> Tuple[bool, Optional[str]]:
        """Валидирует штрихкод с попыткой рендеринга.

        Проверяет:
        - Поддержку типа штрихкода
        - Корректность данных
        - Возможность рендеринга (пробный рендер)

        Args:
            barcode: Объект Barcode для валидации
            preview_size: Размер превью для пробного рендера

        Returns:
            Кортеж (success, error_message):
            - success: True если валидация прошла успешно
            - error_message: Сообщение об ошибке или None
        """
        logger.info("Validating Barcode with render: type=%r data=%r", barcode.type, barcode.data)
        try:
            # Проверяем тип в manifest
            result = cls.supported_matrix().get(str(barcode.type), None)
            if not result:
                return False, f"Barcode type {barcode.type} not found in manifest or not supported."

            # Проверяем опции
            allowlist: set[str] = set(result["options_allowlist"])
            for k in barcode.options:
                if k not in allowlist:
                    return False, f"Option '{k}' not allowed for barcode type {barcode.type}"

            # Получаем рендерер и валидируем
            renderer: Any = cls.get_renderer(barcode)
            if hasattr(renderer, "validate"):
                renderer.validate()

            # Пробный рендер
            if hasattr(renderer, "renderimage"):
                _img: Any = renderer.renderimage(
                    width=preview_size[0], height=preview_size[1], options={"preview": True}
                )
                if _img is None:
                    return False, "Generator failed to return image"

            return True, None

        except Exception as ex:
            msg: str = str(ex)
            logger.warning("Barcode validation error: %s", msg)
            return False, msg

    @classmethod
    def get_support_level(cls, barcode_type: Union["BarcodeType", "Matrix2DCodeType"]) -> str:
        """Возвращает уровень поддержки типа штрихкода.

        Args:
            barcode_type: Тип штрихкода

        Returns:
            Уровень поддержки: "soft" (экспериментальный) или "hard" (стабильный)
        """
        matrix = cls.supported_matrix()
        info = matrix.get(str(barcode_type), {})
        level = info.get("support_level", "unknown")
        return str(level) if level else "unknown"

    @classmethod
    def get_allowed_options(cls, barcode_type: Union["BarcodeType", "Matrix2DCodeType"]) -> list[str]:
        """Возвращает список разрешённых опций для типа штрихкода.

        Args:
            barcode_type: Тип штрихкода

        Returns:
            Список разрешённых имён опций
        """
        matrix = cls.supported_matrix()
        info = matrix.get(str(barcode_type), {})
        allowlist = info.get("options_allowlist", [])
        return list(allowlist) if isinstance(allowlist, (list, tuple)) else []


__all__ = [
    "BarcodeService",
]