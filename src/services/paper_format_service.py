"""Сервис форматов бумаги.

Управление профилями бумаги для печати.
Стандартные форматы и пользовательские профили.

Module: src/services/paper_format_service.py
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Типы и константы
# ---------------------------------------------------------------------------


class PaperSize(Enum):
    """Стандартные размеры бумаги."""

    # Серия A
    A3 = ("A3", 297, 420, "mm")
    A4 = ("A4", 210, 297, "mm")
    A5 = ("A5", 148, 210, "mm")
    A6 = ("A6", 105, 148, "mm")

    # Серия B
    B4 = ("B4", 250, 353, "mm")
    B5 = ("B5", 176, 250, "mm")

    # Letter/Legal
    LETTER = ("Letter", 8.5, 11, "inch")
    LEGAL = ("Legal", 8.5, 14, "inch")

    # Tractor feed (Epson FX-890)
    TRACTOR_FULL = ("Tractor Full", 210, 305, "mm")
    TRACTOR_HALF = ("Tractor Half", 210, 152.5, "mm")
    TRACTOR_TRIPLET = ("Tractor Triplet", 210, 101.6, "mm")

    # Envelopes
    ENVELOPE_DL = ("Envelope DL", 110, 220, "mm")
    ENVELOPE_C5 = ("Envelope C5", 162, 229, "mm")

    # Custom
    CUSTOM = ("Custom", 0, 0, "mm")

    def __init__(self, name: str, width: float, height: float, unit: str) -> None:
        self._display_name = name
        self._width = width
        self._height = height
        self._unit = unit

    @property
    def width_mm(self) -> float:
        """Ширина в мм."""
        if self._unit == "inch":
            return self._width * 25.4
        return self._width

    @property
    def height_mm(self) -> float:
        """Высота в мм."""
        if self._unit == "inch":
            return self._height * 25.4
        return self._height


class Orientation(Enum):
    """Ориентация страницы."""

    PORTRAIT = "portrait"  # Книжная
    LANDSCAPE = "landscape"  # Альбомная


class PaperType(Enum):
    """Тип бумаги."""

    PLAIN = "plain"  # Обычная
    THIN = "thin"  # Тонкая
    THICK = "thick"  # Толстая
    CARBON = "carbon"  # Копировальная
    CONTINUOUS = "continuous"  # Рулонная
    LABELS = "labels"  # Этикетки
    ENVELOPE = "envelope"  # Конверт


class TrayType(Enum):
    """Тип лотка."""

    MANUAL = "manual"  # Ручная подача
    TRAY_1 = "tray_1"  # Лоток 1
    TRAY_2 = "tray_2"  # Лоток 2
    AUTO = "auto"  # Автоматический выбор


# ---------------------------------------------------------------------------
# Модели данных
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Margins:
    """Отступы страницы.

    Attrs:
        top: Верхний отступ (мм)
        right: Правый отступ (мм)
        bottom: Нижний отступ (мм)
        left: Левый отступ (мм)
    """

    top: float = 10.0
    right: float = 10.0
    bottom: float = 10.0
    left: float = 10.0

    @classmethod
    def all(cls, value: float) -> "Margins":
        """Создаёт одинаковые отступы со всех сторон.

        Args:
            value: Значение отступа (мм)

        Returns:
            Margins с одинаковыми отступами
        """
        return cls(top=value, right=value, bottom=value, left=value)


@dataclass(frozen=True)
class PrintableArea:
    """Печатная область.

    Attrs:
        x: X координата (мм)
        y: Y координата (мм)
        width: Ширина (мм)
        height: Высота (мм)
    """

    x: float
    y: float
    width: float
    height: float


@dataclass(frozen=True)
class PaperProfile:
    """Профиль бумаги.

    Attrs:
        id: Идентификатор
        name: Имя профиля
        paper_size: Размер бумаги
        orientation: Ориентация
        paper_type: Тип бумаги
        weight: Вес бумаги (г/м²)
        margins: Отступы
        printable_area: Печатная область (optional)
        tray: Тип лотка
        is_default: Профиль по умолчанию
        is_custom: Пользовательский профиль
        metadata: Дополнительные метаданные
    """

    id: str = ""
    name: str = ""
    paper_size: PaperSize = PaperSize.A4
    orientation: Orientation = Orientation.PORTRAIT
    paper_type: PaperType = PaperType.PLAIN
    weight: int = 80  # г/м²
    margins: Margins = field(default_factory=Margins)
    printable_area: Optional[PrintableArea] = None
    tray: TrayType = TrayType.AUTO
    is_default: bool = False
    is_custom: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def width_mm(self) -> float:
        """Ширина бумаги в мм."""
        if self.orientation == Orientation.PORTRAIT:
            return self.paper_size.width_mm
        return self.paper_size.height_mm

    @property
    def height_mm(self) -> float:
        """Высота бумаги в мм."""
        if self.orientation == Orientation.PORTRAIT:
            return self.paper_size.height_mm
        return self.paper_size.width_mm

    def get_printable_area(self) -> PrintableArea:
        """Вычисляет печатную область.

        Returns:
            Печатная область
        """
        if self.printable_area:
            return self.printable_area

        return PrintableArea(
            x=self.margins.left,
            y=self.margins.top,
            width=self.width_mm - self.margins.left - self.margins.right,
            height=self.height_mm - self.margins.top - self.margins.bottom,
        )


# ---------------------------------------------------------------------------
# PaperFormatService
# ---------------------------------------------------------------------------


class PaperFormatService:
    """Сервис форматов бумаги.

    Предоставляет:
    - Стандартные форматы бумаги
    - Пользовательские профили
    - Расчёт печатной области
    - Импорт/экспорт профилей

    Пример:
        >>> service = PaperFormatService()
        >>> profile = service.get_profile("a4_portrait")
        >>> print(f"Printable area: {profile.get_printable_area()}")
    """

    def __init__(self, config_dir: Optional[Path] = None) -> None:
        """Инициализирует сервис.

        Args:
            config_dir: Директория для пользовательских профилей (optional)
        """
        self._config_dir = config_dir
        self._profiles: Dict[str, PaperProfile] = {}
        self._custom_profiles: Dict[str, PaperProfile] = {}

        # Загружаем стандартные профили
        self._init_standard_profiles()

        # Загружаем пользовательские профили
        if self._config_dir:
            self._load_custom_profiles()

    def _init_standard_profiles(self) -> None:
        """Инициализирует стандартные профили."""
        # A4 Portrait
        self._profiles["a4_portrait"] = PaperProfile(
            id="a4_portrait",
            name="A4 Portrait",
            paper_size=PaperSize.A4,
            orientation=Orientation.PORTRAIT,
            paper_type=PaperType.PLAIN,
            weight=80,
            margins=Margins.all(10.0),
            is_default=True,
        )

        # A4 Landscape
        self._profiles["a4_landscape"] = PaperProfile(
            id="a4_landscape",
            name="A4 Landscape",
            paper_size=PaperSize.A4,
            orientation=Orientation.LANDSCAPE,
            paper_type=PaperType.PLAIN,
            weight=80,
            margins=Margins.all(10.0),
        )

        # A3 Portrait
        self._profiles["a3_portrait"] = PaperProfile(
            id="a3_portrait",
            name="A3 Portrait",
            paper_size=PaperSize.A3,
            orientation=Orientation.PORTRAIT,
            paper_type=PaperType.PLAIN,
            weight=80,
            margins=Margins.all(15.0),
        )

        # A3 Landscape
        self._profiles["a3_landscape"] = PaperProfile(
            id="a3_landscape",
            name="A3 Landscape",
            paper_size=PaperSize.A3,
            orientation=Orientation.LANDSCAPE,
            paper_type=PaperType.PLAIN,
            weight=80,
            margins=Margins.all(15.0),
        )

        # Letter Portrait
        self._profiles["letter_portrait"] = PaperProfile(
            id="letter_portrait",
            name="Letter Portrait",
            paper_size=PaperSize.LETTER,
            orientation=Orientation.PORTRAIT,
            paper_type=PaperType.PLAIN,
            weight=80,
            margins=Margins.all(0.5 * 25.4),  # 0.5 inch
        )

        # Legal Portrait
        self._profiles["legal_portrait"] = PaperProfile(
            id="legal_portrait",
            name="Legal Portrait",
            paper_size=PaperSize.LEGAL,
            orientation=Orientation.PORTRAIT,
            paper_type=PaperType.PLAIN,
            weight=80,
            margins=Margins.all(0.5 * 25.4),
        )

        # Continuous Form (для матричных принтеров)
        self._profiles["continuous_80"] = PaperProfile(
            id="continuous_80",
            name="Continuous 80mm",
            paper_size=PaperSize.CUSTOM,
            orientation=Orientation.PORTRAIT,
            paper_type=PaperType.CONTINUOUS,
            weight=60,
            margins=Margins(top=12.7, right=5.0, bottom=12.7, left=5.0),
            metadata={"custom_width": 80.0, "custom_height": 297.0},
        )

        # Continuous Form 136 columns
        self._profiles["continuous_136"] = PaperProfile(
            id="continuous_136",
            name="Continuous 136 cols",
            paper_size=PaperSize.CUSTOM,
            orientation=Orientation.PORTRAIT,
            paper_type=PaperType.CONTINUOUS,
            weight=60,
            margins=Margins(top=12.7, right=5.0, bottom=12.7, left=5.0),
            metadata={
                "custom_width": 14.85 * 136 / 25.4 * 25.4,
                "custom_height": 279.4,
            },  # ~14.85" x 11"
        )

        # Envelope DL
        self._profiles["envelope_dl"] = PaperProfile(
            id="envelope_dl",
            name="Envelope DL",
            paper_size=PaperSize.CUSTOM,
            orientation=Orientation.LANDSCAPE,
            paper_type=PaperType.ENVELOPE,
            weight=100,
            margins=Margins.all(10.0),
            metadata={"custom_width": 110.0, "custom_height": 220.0},
        )

    def _load_custom_profiles(self) -> None:
        """Загружает пользовательские профили."""
        if self._config_dir is None:
            return

        profiles_file = self._config_dir / "paper_profiles.json"
        if not profiles_file.exists():
            return

        try:
            data = json.loads(profiles_file.read_text(encoding="utf-8"))
            for profile_data in data.get("profiles", []):
                profile = self._deserialize_profile(profile_data)
                if profile:
                    self._custom_profiles[profile.id] = profile
                    self._profiles[profile.id] = profile

            logger.info("Загружено %d пользовательских профилей", len(self._custom_profiles))

        except Exception as exc:
            logger.error("Ошибка загрузки пользовательских профилей: %s", exc)

    # ---------- Управление профилями ----------

    def get_profile(self, profile_id: str) -> Optional[PaperProfile]:
        """Возвращает профиль по ID.

        Args:
            profile_id: ID профиля

        Returns:
            Профиль или None
        """
        return self._profiles.get(profile_id)

    def get_all_profiles(self) -> List[PaperProfile]:
        """Возвращает все профили.

        Returns:
            Список профилей
        """
        return list(self._profiles.values())

    def get_standard_profiles(self) -> List[PaperProfile]:
        """Возвращает стандартные профили.

        Returns:
            Список стандартных профилей
        """
        return [p for p in self._profiles.values() if not p.is_custom]

    def get_custom_profiles(self) -> List[PaperProfile]:
        """Возвращает пользовательские профили.

        Returns:
            Список пользовательских профилей
        """
        return list(self._custom_profiles.values())

    def get_default_profile(self) -> PaperProfile:
        """Возвращает профиль по умолчанию.

        Returns:
            Профиль по умолчанию
        """
        for profile in self._profiles.values():
            if profile.is_default:
                return profile

        # Fallback на A4 Portrait
        return self._profiles["a4_portrait"]

    def create_custom_profile(
        self,
        name: str,
        width_mm: float,
        height_mm: float,
        margins: Optional[Margins] = None,
        paper_type: PaperType = PaperType.PLAIN,
        orientation: Orientation = Orientation.PORTRAIT,
    ) -> PaperProfile:
        """Создаёт пользовательский профиль.

        Args:
            name: Имя профиля
            width_mm: Ширина (мм)
            height_mm: Высота (мм)
            margins: Отступы (optional)
            paper_type: Тип бумаги
            orientation: Ориентация

        Returns:
            Созданный профиль
        """
        import uuid

        profile_id = f"custom_{uuid.uuid4().hex[:8]}"

        profile = PaperProfile(
            id=profile_id,
            name=name,
            paper_size=PaperSize.CUSTOM,
            orientation=orientation,
            paper_type=paper_type,
            margins=margins or Margins.all(10.0),
            is_custom=True,
            metadata={"custom_width": width_mm, "custom_height": height_mm},
        )

        self._custom_profiles[profile_id] = profile
        self._profiles[profile_id] = profile

        logger.info("Создан пользовательский профиль: %s", profile_id)
        return profile

    def delete_custom_profile(self, profile_id: str) -> bool:
        """Удаляет пользовательский профиль.

        Args:
            profile_id: ID профиля

        Returns:
            True если успешно
        """
        if profile_id not in self._custom_profiles:
            return False

        del self._custom_profiles[profile_id]
        del self._profiles[profile_id]

        logger.info("Удалён пользовательский профиль: %s", profile_id)
        return True

    def set_default_profile(self, profile_id: str) -> bool:
        """Устанавливает профиль по умолчанию.

        Args:
            profile_id: ID профиля

        Returns:
            True если успешно
        """
        if profile_id not in self._profiles:
            return False

        # Сбрасываем старый default
        for profile in self._profiles.values():
            if profile.is_default:
                # Создаём копию без is_default
                self._profiles[profile.id] = PaperProfile(
                    id=profile.id,
                    name=profile.name,
                    paper_size=profile.paper_size,
                    orientation=profile.orientation,
                    paper_type=profile.paper_type,
                    weight=profile.weight,
                    margins=profile.margins,
                    printable_area=profile.printable_area,
                    tray=profile.tray,
                    is_default=False,
                    is_custom=profile.is_custom,
                    metadata=profile.metadata,
                )

        # Устанавливаем новый default
        old_profile = self._profiles[profile_id]
        self._profiles[profile_id] = PaperProfile(
            id=old_profile.id,
            name=old_profile.name,
            paper_size=old_profile.paper_size,
            orientation=old_profile.orientation,
            paper_type=old_profile.paper_type,
            weight=old_profile.weight,
            margins=old_profile.margins,
            printable_area=old_profile.printable_area,
            tray=old_profile.tray,
            is_default=True,
            is_custom=old_profile.is_custom,
            metadata=old_profile.metadata,
        )

        logger.info("Установлен профиль по умолчанию: %s", profile_id)
        return True

    # ---------- Расчёты ----------

    def calculate_printable_area(
        self,
        profile: PaperProfile,
    ) -> PrintableArea:
        """Вычисляет печатную область.

        Args:
            profile: Профиль бумаги

        Returns:
            Печатная область
        """
        return profile.get_printable_area()

    def calculate_characters_per_line(
        self,
        profile: PaperProfile,
        characters_per_inch: float = 10.0,
    ) -> int:
        """Вычисляет количество символов в строке.

        Args:
            profile: Профиль бумаги
            characters_per_inch: Символов на дюйм (CPI)

        Returns:
            Количество символов
        """
        printable = profile.get_printable_area()
        # Ширина в дюймах
        width_inch = printable.width / 25.4
        return int(width_inch * characters_per_inch)

    def calculate_lines_per_page(
        self,
        profile: PaperProfile,
        lines_per_inch: float = 6.0,
    ) -> int:
        """Вычисляет количество строк на странице.

        Args:
            profile: Профиль бумаги
            lines_per_inch: Строк на дюйм (LPI)

        Returns:
            Количество строк
        """
        printable = profile.get_printable_area()
        # Высота в дюймах
        height_inch = printable.height / 25.4
        return int(height_inch * lines_per_inch)

    def get_paper_size_for_cpi(
        self,
        cpi: int,
        lpi: int = 66,
    ) -> PaperSize:
        """Подбирает размер бумаги для заданного CPI.

        Args:
            cpi: Символов на дюйм (обычно 10, 12, 15, 17)
            lpi: Строк на дюйм (обычно 6)

        Returns:
            Размер бумаги
        """
        # Стандартные ширины для матричных принтеров
        if cpi <= 80:
            return PaperSize.A4
        if cpi <= 132:
            return PaperSize.A3
        # Custom для больших форматов
        return PaperSize.CUSTOM

    # ---------- Импорт/экспорт ----------

    def export_profiles(self) -> Dict[str, Any]:
        """Экспортирует все профили.

        Returns:
            Словарь с профилями
        """
        return {
            "version": 1,
            "profiles": [self._serialize_profile(p) for p in self._profiles.values()],
        }

    def import_profiles(self, data: Dict[str, Any]) -> int:
        """Импортирует профили.

        Args:
            data: Словарь с профилями

        Returns:
            Количество импортированных профилей
        """
        version = data.get("version", 1)
        if version != 1:
            logger.warning("Неподдерживаемая версия профилей: %s", version)
            return 0

        imported = 0
        for profile_data in data.get("profiles", []):
            profile = self._deserialize_profile(profile_data)
            if profile:
                self._profiles[profile.id] = profile
                if profile.is_custom:
                    self._custom_profiles[profile.id] = profile
                imported += 1

        logger.info("Импортировано %d профилей", imported)
        return imported

    def save_custom_profiles(self) -> bool:
        """Сохраняет пользовательские профили.

        Returns:
            True если успешно
        """
        if self._config_dir is None:
            return False

        try:
            self._config_dir.mkdir(parents=True, exist_ok=True)
            profiles_file = self._config_dir / "paper_profiles.json"

            data = {
                "version": 1,
                "profiles": [self._serialize_profile(p) for p in self._custom_profiles.values()],
            }

            profiles_file.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

            logger.info("Сохранено %d пользовательских профилей", len(self._custom_profiles))
            return True

        except Exception as exc:
            logger.error("Ошибка сохранения профилей: %s", exc)
            return False

    # ---------- Внутренние методы ----------

    def _serialize_profile(self, profile: PaperProfile) -> Dict[str, Any]:
        """Сериализует профиль в словарь.

        Args:
            profile: Профиль

        Returns:
            Словарь
        """
        return {
            "id": profile.id,
            "name": profile.name,
            "paper_size": profile.paper_size.name,
            "orientation": profile.orientation.value,
            "paper_type": profile.paper_type.value,
            "weight": profile.weight,
            "margins": {
                "top": profile.margins.top,
                "right": profile.margins.right,
                "bottom": profile.margins.bottom,
                "left": profile.margins.left,
            },
            "is_default": profile.is_default,
            "is_custom": profile.is_custom,
            "metadata": profile.metadata,
        }

    def _deserialize_profile(self, data: Dict[str, Any]) -> Optional[PaperProfile]:
        """Десериализует профиль из словаря.

        Args:
            data: Словарь

        Returns:
            Профиль или None
        """
        try:
            paper_size = PaperSize[data["paper_size"]]
            orientation = Orientation(data.get("orientation", "portrait"))
            paper_type = PaperType(data.get("paper_type", "plain"))
            tray = TrayType(data.get("tray", "auto"))

            margins_data = data.get("margins", {})
            margins = Margins(
                top=margins_data.get("top", 10.0),
                right=margins_data.get("right", 10.0),
                bottom=margins_data.get("bottom", 10.0),
                left=margins_data.get("left", 10.0),
            )

            return PaperProfile(
                id=data["id"],
                name=data["name"],
                paper_size=paper_size,
                orientation=orientation,
                paper_type=paper_type,
                weight=data.get("weight", 80),
                margins=margins,
                tray=tray,
                is_default=data.get("is_default", False),
                is_custom=data.get("is_custom", False),
                metadata=data.get("metadata", {}),
            )

        except Exception as exc:
            logger.error("Ошибка десериализации профиля: %s", exc)
            return None


__all__ = [
    "PaperFormatService",
    "PaperProfile",
    "PaperSize",
    "Orientation",
    "PaperType",
    "TrayType",
    "Margins",
    "PrintableArea",
]
