"""Сервис профилей бумаги для FX-890.

Управление профилями бумаги с поддержкой favorites, непрерывных форм
и пользовательских настроек.

Features:
    - Избранные профили (max 6)
    - Поддержка tear-off perforation для непрерывных форм
    - Расчёт печатной области в реальном времени
    - Персистентность favorites в JSON

Example:
    >>> service = PaperProfileService()
    >>> profile = service.get_profile("a4_tractor")
    >>> print(f"Printable: {profile.printable_width_mm:.1f}mm")

Module: src/services/paper_profile_service.py
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Final, List, Literal, Optional

from src.model.enums import FontFamily, PaperType

logger = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

DEFAULT_LEFT_MARGIN_MM: Final[float] = 13.0
DEFAULT_RIGHT_MARGIN_MM: Final[float] = 13.0
DEFAULT_TOP_MARGIN_MM: Final[float] = 4.2
DEFAULT_BOTTOM_MARGIN_MM: Final[float] = 4.2
TEAR_OFF_EXTRA_MM: Final[float] = 10.0
DEFAULT_CPI: Final[int] = 10
DEFAULT_LPI: Final[int] = 6
MM_TO_INCH: Final[float] = 25.4

MAX_FAVORITES: Final[int] = 6
FAVORITES_FILENAME: Final[str] = "favorites.json"
CONFIG_DIR: Final[str] = ".fxtextprocessor"


# =============================================================================
# PaperProfile
# =============================================================================


@dataclass(frozen=True)
class PaperProfile:
    """Профиль бумаги с настраиваемыми margins.

    Attrs:
        id: Уникальный идентификатор профиля
        name: Отображаемое имя (EN)
        name_ru: Отображаемое имя (RU)
        category: Категория профиля
        paper_type: Тип бумаги (CONTINUOUS_TRACTOR, SHEET_FEED, ENVELOPE)
        width_mm: Ширина бумаги в мм
        height_mm: Высота бумаги в мм
        left_margin_mm: Левый отступ в мм
        right_margin_mm: Правый отступ в мм
        top_margin_mm: Верхний отступ в мм
        bottom_margin_mm: Нижний отступ в мм
        tear_off_perforation: Флаг отрывной перфорации
        tear_off_extra_mm: Дополнительный отступ для tear-off
        default_cpi: CPI по умолчанию
        default_lpi: LPI по умолчанию
        default_font: Шрифт по умолчанию
        is_custom: Пользовательский профиль
        metadata: Дополнительные метаданные

    Example:
        >>> profile = PaperProfile(
        ...     id="a4_tractor",
        ...     name="A4 Tractor",
        ...     name_ru="A4 Тракторная",
        ...     category="continuous",
        ...     paper_type=PaperType.CONTINUOUS_TRACTOR,
        ...     width_mm=210.0,
        ...     height_mm=297.0,
        ... )
        >>> print(f"Cols: {profile.calculate_cols()}")
    """

    id: str
    name: str
    name_ru: str
    category: Literal["favorites", "continuous", "sheet", "envelope"]
    paper_type: PaperType
    width_mm: float
    height_mm: float

    # Editable margins (user-configurable)
    left_margin_mm: float = DEFAULT_LEFT_MARGIN_MM
    right_margin_mm: float = DEFAULT_RIGHT_MARGIN_MM
    top_margin_mm: float = DEFAULT_TOP_MARGIN_MM
    bottom_margin_mm: float = DEFAULT_BOTTOM_MARGIN_MM

    # Tear-off perforation (continuous only)
    tear_off_perforation: bool = False
    tear_off_extra_mm: float = TEAR_OFF_EXTRA_MM  # Fixed bonus

    # Defaults
    default_cpi: int = DEFAULT_CPI
    default_lpi: int = DEFAULT_LPI
    default_font: FontFamily = FontFamily.ROMAN

    # Custom profile flag
    is_custom: bool = False

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def effective_left_margin(self) -> float:
        """Эффективный левый margin (base + tear-off).

        Returns:
            Левый отступ в мм с учётом tear-off.
        """
        if self.tear_off_perforation and self.is_continuous:
            return self.left_margin_mm + self.tear_off_extra_mm
        return self.left_margin_mm

    @property
    def effective_right_margin(self) -> float:
        """Эффективный правый margin.

        Returns:
            Правый отступ в мм с учётом tear-off.
        """
        if self.tear_off_perforation and self.is_continuous:
            return self.right_margin_mm + self.tear_off_extra_mm
        return self.right_margin_mm

    @property
    def is_continuous(self) -> bool:
        """Проверяет, является ли профиль непрерывным.

        Returns:
            True если CONTINUOUS_TRACTOR.
        """
        return self.paper_type == PaperType.CONTINUOUS_TRACTOR

    @property
    def printable_width_mm(self) -> float:
        """Ширина печатной области.

        Returns:
            Ширина в мм за вычетом отступов.
        """
        return self.width_mm - self.effective_left_margin - self.effective_right_margin

    @property
    def printable_height_mm(self) -> float:
        """Высота печатной области.

        Returns:
            Высота в мм за вычетом отступов.
        """
        return self.height_mm - self.top_margin_mm - self.bottom_margin_mm

    def get_printable_area(self) -> object:
        """Возвращает печатную область как объект с атрибутами width и height.

        Returns:
            Объект с атрибутами width и height (в мм) и x, y (смещение).
        """

        class PrintableArea:
            def __init__(self, x: float, y: float, width: float, height: float) -> None:
                self.x = x
                self.y = y
                self.width = width
                self.height = height

        return PrintableArea(
            x=self.effective_left_margin,
            y=self.top_margin_mm,
            width=self.printable_width_mm,
            height=self.printable_height_mm,
        )

    def calculate_cols(self, cpi: Optional[int] = None) -> int:
        """Рассчитывает количество колонок.

        Args:
            cpi: Символов на дюйм (optional, использует default_cpi)

        Returns:
            Количество колонок.
        """
        cpi_value = cpi or self.default_cpi
        width_inches = self.printable_width_mm / MM_TO_INCH
        return int(width_inches * cpi_value)

    def calculate_rows(self, lpi: Optional[int] = None) -> int:
        """Рассчитывает количество строк.

        Args:
            lpi: Строк на дюйм (optional, использует default_lpi)

        Returns:
            Количество строк.
        """
        lpi_value = lpi or self.default_lpi
        height_inches = self.printable_height_mm / MM_TO_INCH
        return int(height_inches * lpi_value)

    def get_printable_area_display(self) -> str:
        """Возвращает строку с описанием печатной области.

        Returns:
            Строка формата "XXX×YYY mm (AA cols × BB rows @ 10 CPI)"
        """
        cols = self.calculate_cols()
        rows = self.calculate_rows()
        return (
            f"{self.printable_width_mm:.1f}×{self.printable_height_mm:.1f} mm "
            f"({cols} cols × {rows} rows @ {self.default_cpi} CPI)"
        )

    def with_updated_margins(
        self,
        left: Optional[float] = None,
        right: Optional[float] = None,
        top: Optional[float] = None,
        bottom: Optional[float] = None,
    ) -> "PaperProfile":
        """Создаёт копию профиля с обновлёнными margins.

        Args:
            left: Новый левый отступ
            right: Новый правый отступ
            top: Новый верхний отступ
            bottom: Новый нижний отступ

        Returns:
            Новый экземпляр PaperProfile.
        """
        return PaperProfile(
            id=self.id,
            name=self.name,
            name_ru=self.name_ru,
            category=self.category,
            paper_type=self.paper_type,
            width_mm=self.width_mm,
            height_mm=self.height_mm,
            left_margin_mm=left if left is not None else self.left_margin_mm,
            right_margin_mm=right if right is not None else self.right_margin_mm,
            top_margin_mm=top if top is not None else self.top_margin_mm,
            bottom_margin_mm=bottom if bottom is not None else self.bottom_margin_mm,
            tear_off_perforation=self.tear_off_perforation,
            tear_off_extra_mm=self.tear_off_extra_mm,
            default_cpi=self.default_cpi,
            default_lpi=self.default_lpi,
            default_font=self.default_font,
            is_custom=self.is_custom,
            metadata=self.metadata.copy(),
        )

    def with_tear_off(self, enabled: bool) -> "PaperProfile":
        """Создаёт копию профиля с изменённым tear_off_perforation.

        Args:
            enabled: Новое значение tear-off.

        Returns:
            Новый экземпляр PaperProfile.
        """
        return PaperProfile(
            id=self.id,
            name=self.name,
            name_ru=self.name_ru,
            category=self.category,
            paper_type=self.paper_type,
            width_mm=self.width_mm,
            height_mm=self.height_mm,
            left_margin_mm=self.left_margin_mm,
            right_margin_mm=self.right_margin_mm,
            top_margin_mm=self.top_margin_mm,
            bottom_margin_mm=self.bottom_margin_mm,
            tear_off_perforation=enabled,
            tear_off_extra_mm=self.tear_off_extra_mm,
            default_cpi=self.default_cpi,
            default_lpi=self.default_lpi,
            default_font=self.default_font,
            is_custom=self.is_custom,
            metadata=self.metadata.copy(),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Сериализует профиль в словарь.

        Returns:
            Словарь с данными профиля.
        """
        return {
            "id": self.id,
            "name": self.name,
            "name_ru": self.name_ru,
            "category": self.category,
            "paper_type": self.paper_type.value,
            "width_mm": self.width_mm,
            "height_mm": self.height_mm,
            "left_margin_mm": self.left_margin_mm,
            "right_margin_mm": self.right_margin_mm,
            "top_margin_mm": self.top_margin_mm,
            "bottom_margin_mm": self.bottom_margin_mm,
            "tear_off_perforation": self.tear_off_perforation,
            "tear_off_extra_mm": self.tear_off_extra_mm,
            "default_cpi": self.default_cpi,
            "default_lpi": self.default_lpi,
            "default_font": self.default_font.value,
            "is_custom": self.is_custom,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PaperProfile":
        """Десериализует профиль из словаря.

        Args:
            data: Словарь с данными профиля.

        Returns:
            Экземпляр PaperProfile.

        Raises:
            ValueError: Если данные некорректны.
        """
        try:
            return cls(
                id=data["id"],
                name=data["name"],
                name_ru=data.get("name_ru", data["name"]),
                category=data.get("category", "sheet"),
                paper_type=PaperType(data["paper_type"]),
                width_mm=float(data["width_mm"]),
                height_mm=float(data["height_mm"]),
                left_margin_mm=float(data.get("left_margin_mm", DEFAULT_LEFT_MARGIN_MM)),
                right_margin_mm=float(data.get("right_margin_mm", DEFAULT_RIGHT_MARGIN_MM)),
                top_margin_mm=float(data.get("top_margin_mm", DEFAULT_TOP_MARGIN_MM)),
                bottom_margin_mm=float(data.get("bottom_margin_mm", DEFAULT_BOTTOM_MARGIN_MM)),
                tear_off_perforation=bool(data.get("tear_off_perforation", False)),
                tear_off_extra_mm=float(data.get("tear_off_extra_mm", TEAR_OFF_EXTRA_MM)),
                default_cpi=int(data.get("default_cpi", DEFAULT_CPI)),
                default_lpi=int(data.get("default_lpi", DEFAULT_LPI)),
                default_font=FontFamily(data.get("default_font", FontFamily.ROMAN.value)),
                is_custom=bool(data.get("is_custom", False)),
                metadata=dict(data.get("metadata", {})),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise ValueError(f"Invalid profile data: {exc}") from exc


# =============================================================================
# PaperProfileService
# =============================================================================


class PaperProfileService:
    """Сервис для управления paper profiles.

    Предоставляет:
    - Встроенные профили для стандартных размеров бумаги
    - Избранные профили (favorites, max 6)
    - Пользовательские профили
    - Персистентность favorites в JSON

    Example:
        >>> service = PaperProfileService()
        >>> favorites = service.get_favorites()
        >>> print(f"Favorites: {len(favorites)}")
    """

    MAX_FAVORITES: Final[int] = MAX_FAVORITES
    FAVORITES_FILENAME: Final[str] = FAVORITES_FILENAME

    def __init__(self, config_dir: Optional[Path] = None) -> None:
        """Инициализирует сервис.

        Args:
            config_dir: Директория для хранения favorites (optional).
                        По умолчанию ~/.fxtextprocessor
        """
        self._config_dir = config_dir or Path.home() / CONFIG_DIR
        self._builtin_profiles: Dict[str, PaperProfile] = {}
        self._custom_profiles: Dict[str, PaperProfile] = {}
        self._favorites: List[str] = []
        self._on_change_callbacks: List[Callable[[], None]] = []

        # Инициализация
        self._init_builtin_profiles()
        self._load_favorites()

    def _init_builtin_profiles(self) -> None:
        """Инициализирует встроенные профили."""
        # Continuous forms
        self._builtin_profiles["a4_tractor"] = PaperProfile(
            id="a4_tractor",
            name="A4 Tractor",
            name_ru="A4 Тракторная",
            category="continuous",
            paper_type=PaperType.CONTINUOUS_TRACTOR,
            width_mm=210.0,
            height_mm=297.0,
        )

        self._builtin_profiles["letter_tractor"] = PaperProfile(
            id="letter_tractor",
            name="Letter Tractor",
            name_ru="Letter Тракторная",
            category="continuous",
            paper_type=PaperType.CONTINUOUS_TRACTOR,
            width_mm=215.9,  # 8.5 inch
            height_mm=279.4,  # 11 inch
        )

        self._builtin_profiles["legal_tractor"] = PaperProfile(
            id="legal_tractor",
            name="Legal Tractor",
            name_ru="Legal Тракторная",
            category="continuous",
            paper_type=PaperType.CONTINUOUS_TRACTOR,
            width_mm=215.9,  # 8.5 inch
            height_mm=355.6,  # 14 inch
        )

        self._builtin_profiles["half_210_152"] = PaperProfile(
            id="half_210_152",
            name="Half-Letter (210×152.5)",
            name_ru="Половина A4 (210×152.5)",
            category="continuous",
            paper_type=PaperType.CONTINUOUS_TRACTOR,
            width_mm=210.0,
            height_mm=152.5,
        )

        self._builtin_profiles["triplicate_210_102"] = PaperProfile(
            id="triplicate_210_102",
            name="Triplicate (210×101.7)",
            name_ru="Трипликат (210×101.7)",
            category="continuous",
            paper_type=PaperType.CONTINUOUS_TRACTOR,
            width_mm=210.0,
            height_mm=101.7,
        )

        self._builtin_profiles["fanfold_8_5"] = PaperProfile(
            id="fanfold_8_5",
            name='Fanfold 8.5"',
            name_ru='Фанфолд 8.5"',
            category="continuous",
            paper_type=PaperType.CONTINUOUS_TRACTOR,
            width_mm=215.9,
            height_mm=279.4,
        )

        self._builtin_profiles["fanfold_9_5"] = PaperProfile(
            id="fanfold_9_5",
            name='Fanfold 9.5"',
            name_ru='Фанфолд 9.5"',
            category="continuous",
            paper_type=PaperType.CONTINUOUS_TRACTOR,
            width_mm=241.3,
            height_mm=279.4,
        )

        # Sheet feed
        self._builtin_profiles["a4_sheet"] = PaperProfile(
            id="a4_sheet",
            name="A4 Sheet",
            name_ru="A4 Листовая",
            category="sheet",
            paper_type=PaperType.SHEET_FEED,
            width_mm=210.0,
            height_mm=297.0,
        )

        self._builtin_profiles["a5_sheet"] = PaperProfile(
            id="a5_sheet",
            name="A5 Sheet",
            name_ru="A5 Листовая",
            category="sheet",
            paper_type=PaperType.SHEET_FEED,
            width_mm=148.0,
            height_mm=210.0,
        )

        self._builtin_profiles["letter_sheet"] = PaperProfile(
            id="letter_sheet",
            name="Letter Sheet",
            name_ru="Letter Листовая",
            category="sheet",
            paper_type=PaperType.SHEET_FEED,
            width_mm=215.9,
            height_mm=279.4,
        )

        self._builtin_profiles["legal_sheet"] = PaperProfile(
            id="legal_sheet",
            name="Legal Sheet",
            name_ru="Legal Листовая",
            category="sheet",
            paper_type=PaperType.SHEET_FEED,
            width_mm=215.9,
            height_mm=355.6,
        )

        # Envelopes
        self._builtin_profiles["e65_envelope"] = PaperProfile(
            id="e65_envelope",
            name="E65/DL Envelope",
            name_ru="E65/DL Конверт",
            category="envelope",
            paper_type=PaperType.ENVELOPE,
            width_mm=220.0,
            height_mm=110.0,
            default_cpi=12,
        )

        self._builtin_profiles["c5_envelope"] = PaperProfile(
            id="c5_envelope",
            name="C5 Envelope",
            name_ru="C5 Конверт",
            category="envelope",
            paper_type=PaperType.ENVELOPE,
            width_mm=229.0,
            height_mm=162.0,
            default_cpi=12,
        )

        self._builtin_profiles["c4_envelope"] = PaperProfile(
            id="c4_envelope",
            name="C4 Envelope",
            name_ru="C4 Конверт",
            category="envelope",
            paper_type=PaperType.ENVELOPE,
            width_mm=324.0,
            height_mm=229.0,
            default_cpi=10,
        )

    def _get_favorites_file(self) -> Path:
        """Возвращает путь к файлу favorites.

        Returns:
            Путь к favorites.json.
        """
        return self._config_dir / FAVORITES_FILENAME

    def _load_favorites(self) -> None:
        """Загружает favorites из файла."""
        favorites_file = self._get_favorites_file()
        if not favorites_file.exists():
            self._favorites = []
            return

        try:
            data = json.loads(favorites_file.read_text(encoding="utf-8"))
            self._favorites = [
                fid
                for fid in data.get("favorites", [])
                if fid in self._builtin_profiles or fid in self._custom_profiles
            ][:MAX_FAVORITES]
            logger.debug("Загружено %d избранных профилей", len(self._favorites))
        except (json.JSONDecodeError, IOError, OSError) as exc:
            logger.warning("Ошибка загрузки favorites: %s", exc)
            self._favorites = []

    def _save_favorites(self) -> bool:
        """Сохраняет favorites в файл.

        Returns:
            True если успешно.
        """
        try:
            self._config_dir.mkdir(parents=True, exist_ok=True)
            favorites_file = self._get_favorites_file()
            data = {"favorites": self._favorites[:MAX_FAVORITES]}
            favorites_file.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            # Устанавливаем restrictive permissions
            os.chmod(favorites_file, 0o600)
            return True
        except (IOError, OSError) as exc:
            logger.error("Ошибка сохранения favorites: %s", exc)
            return False

    def _notify_change(self) -> None:
        """Уведомляет подписчиков об изменении."""
        for callback in self._on_change_callbacks:
            try:
                callback()
            except Exception as exc:
                logger.warning("Ошибка в callback on_change: %s", exc)

    def add_on_change_callback(self, callback: Callable[[], None]) -> None:
        """Добавляет callback на изменение favorites.

        Args:
            callback: Функция без аргументов.
        """
        self._on_change_callbacks.append(callback)

    def remove_on_change_callback(self, callback: Callable[[], None]) -> None:
        """Удаляет callback.

        Args:
            callback: Ранее добавленный callback.
        """
        if callback in self._on_change_callbacks:
            self._on_change_callbacks.remove(callback)

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def get_profile(self, profile_id: str) -> Optional[PaperProfile]:
        """Возвращает профиль по ID.

        Args:
            profile_id: Идентификатор профиля.

        Returns:
            PaperProfile или None.
        """
        if profile_id in self._custom_profiles:
            return self._custom_profiles[profile_id]
        return self._builtin_profiles.get(profile_id)

    def get_favorites(self) -> List[PaperProfile]:
        """Возвращает избранные профили.

        Returns:
            Список избранных профилей (max 6).
        """
        result: List[PaperProfile] = []
        for fid in self._favorites:
            profile = self.get_profile(fid)
            if profile:
                result.append(profile)
        return result

    def set_favorites(self, profile_ids: List[str]) -> bool:
        """Устанавливает избранные профили.

        Args:
            profile_ids: Список ID профилей (max 6).

        Returns:
            True если успешно.
        """
        # Валидируем все ID
        valid_ids: List[str] = []
        for pid in profile_ids[:MAX_FAVORITES]:
            if self.get_profile(pid) is not None:
                valid_ids.append(pid)

        self._favorites = valid_ids
        saved = self._save_favorites()
        self._notify_change()
        return saved

    def add_to_favorites(self, profile_id: str) -> bool:
        """Добавляет профиль в избранное.

        Args:
            profile_id: ID профиля.

        Returns:
            True если добавлен (False если уже в избранном или лимит достигнут).
        """
        if profile_id in self._favorites:
            return False
        if len(self._favorites) >= MAX_FAVORITES:
            return False
        if self.get_profile(profile_id) is None:
            return False

        self._favorites.append(profile_id)
        saved = self._save_favorites()
        self._notify_change()
        return saved

    def remove_from_favorites(self, profile_id: str) -> bool:
        """Удаляет профиль из избранного.

        Args:
            profile_id: ID профиля.

        Returns:
            True если удалён.
        """
        if profile_id not in self._favorites:
            return False

        self._favorites.remove(profile_id)
        saved = self._save_favorites()
        self._notify_change()
        return saved

    def is_favorite(self, profile_id: str) -> bool:
        """Проверяет, является ли профиль избранным.

        Args:
            profile_id: ID профиля.

        Returns:
            True если в избранном.
        """
        return profile_id in self._favorites

    def get_builtin_profiles(self) -> List[PaperProfile]:
        """Возвращает все встроенные профили.

        Returns:
            Список встроенных профилей.
        """
        return list(self._builtin_profiles.values())

    def get_all_profiles(self) -> List[PaperProfile]:
        """Возвращает все профили (избранные + остальные).

        Избранные идут первыми, затем остальные builtin по категориям.

        Returns:
            Список всех профилей.
        """
        # Избранные первыми
        favorites = self.get_favorites()
        favorite_ids = {p.id for p in favorites}

        # Затем остальные builtin
        others = [p for p in self._builtin_profiles.values() if p.id not in favorite_ids]

        # Сортируем по категории
        category_order = {"continuous": 0, "sheet": 1, "envelope": 2}
        others.sort(key=lambda p: (category_order.get(p.category, 99), p.name_ru))

        return favorites + others

    def get_profiles_by_category(
        self, category: Literal["continuous", "sheet", "envelope"]
    ) -> List[PaperProfile]:
        """Возвращает профили по категории.

        Args:
            category: Категория профилей.

        Returns:
            Список профилей.
        """
        builtin = [p for p in self._builtin_profiles.values() if p.category == category]
        custom = [p for p in self._custom_profiles.values() if p.category == category]
        return builtin + custom

    def create_custom_profile(
        self,
        name: str,
        name_ru: str,
        category: Literal["continuous", "sheet", "envelope"],
        paper_type: PaperType,
        width_mm: float,
        height_mm: float,
        **kwargs: Any,
    ) -> PaperProfile:
        """Создаёт пользовательский профиль.

        Args:
            name: Отображаемое имя (EN).
            name_ru: Отображаемое имя (RU).
            category: Категория.
            paper_type: Тип бумаги.
            width_mm: Ширина в мм.
            height_mm: Высота в мм.
            **kwargs: Дополнительные параметры.

        Returns:
            Созданный профиль.
        """
        import uuid

        profile_id = f"custom_{uuid.uuid4().hex[:8]}"

        profile = PaperProfile(
            id=profile_id,
            name=name,
            name_ru=name_ru,
            category=category,
            paper_type=paper_type,
            width_mm=width_mm,
            height_mm=height_mm,
            is_custom=True,
            **kwargs,
        )

        self._custom_profiles[profile_id] = profile
        logger.info("Создан пользовательский профиль: %s", profile_id)
        return profile

    def update_profile(
        self,
        profile_id: str,
        **kwargs: Any,
    ) -> Optional[PaperProfile]:
        """Обновляет существующий профиль.

        Args:
            profile_id: ID профиля.
            **kwargs: Новые значения полей.

        Returns:
            Обновленный профиль или None.
        """
        profile = self.get_profile(profile_id)
        if profile is None:
            return None

        # Создаём новый профиль с обновлёнными полями
        new_profile = PaperProfile(
            id=profile.id,
            name=kwargs.get("name", profile.name),
            name_ru=kwargs.get("name_ru", profile.name_ru),
            category=kwargs.get("category", profile.category),
            paper_type=kwargs.get("paper_type", profile.paper_type),
            width_mm=kwargs.get("width_mm", profile.width_mm),
            height_mm=kwargs.get("height_mm", profile.height_mm),
            left_margin_mm=kwargs.get("left_margin_mm", profile.left_margin_mm),
            right_margin_mm=kwargs.get("right_margin_mm", profile.right_margin_mm),
            top_margin_mm=kwargs.get("top_margin_mm", profile.top_margin_mm),
            bottom_margin_mm=kwargs.get("bottom_margin_mm", profile.bottom_margin_mm),
            tear_off_perforation=kwargs.get("tear_off_perforation", profile.tear_off_perforation),
            tear_off_extra_mm=kwargs.get("tear_off_extra_mm", profile.tear_off_extra_mm),
            default_cpi=kwargs.get("default_cpi", profile.default_cpi),
            default_lpi=kwargs.get("default_lpi", profile.default_lpi),
            default_font=kwargs.get("default_font", profile.default_font),
            is_custom=profile.is_custom,
            metadata=kwargs.get("metadata", profile.metadata.copy()),
        )

        if profile_id in self._custom_profiles:
            self._custom_profiles[profile_id] = new_profile
        else:
            # Для builtin профилей создаём кастомную копию
            self._custom_profiles[profile_id] = new_profile

        self._notify_change()
        logger.info("Обновлён профиль: %s", profile_id)
        return new_profile

    def delete_custom_profile(self, profile_id: str) -> bool:
        """Удаляет пользовательский профиль.

        Args:
            profile_id: ID профиля.

        Returns:
            True если удалён.
        """
        if profile_id not in self._custom_profiles:
            return False

        del self._custom_profiles[profile_id]

        # Удаляем из favorites если там есть
        if profile_id in self._favorites:
            self._favorites.remove(profile_id)
            self._save_favorites()

        self._notify_change()
        logger.info("Удалён пользовательский профиль: %s", profile_id)
        return True

    def export_profiles(self) -> Dict[str, Any]:
        """Экспортирует все пользовательские профили.

        Returns:
            Словарь с данными профилей.
        """
        return {
            "version": 1,
            "profiles": [p.to_dict() for p in self._custom_profiles.values()],
            "favorites": self._favorites,
        }

    def import_profiles(self, data: Dict[str, Any]) -> int:
        """Импортирует профили.

        Args:
            data: Словарь с данными профилей.

        Returns:
            Количество импортированных профилей.
        """
        version = data.get("version", 1)
        if version != 1:
            logger.warning("Неподдерживаемая версия профилей: %s", version)
            return 0

        imported = 0
        for profile_data in data.get("profiles", []):
            try:
                profile = PaperProfile.from_dict(profile_data)
                profile = PaperProfile(
                    id=profile.id,
                    name=profile.name,
                    name_ru=profile.name_ru,
                    category=profile.category,
                    paper_type=profile.paper_type,
                    width_mm=profile.width_mm,
                    height_mm=profile.height_mm,
                    left_margin_mm=profile.left_margin_mm,
                    right_margin_mm=profile.right_margin_mm,
                    top_margin_mm=profile.top_margin_mm,
                    bottom_margin_mm=profile.bottom_margin_mm,
                    tear_off_perforation=profile.tear_off_perforation,
                    tear_off_extra_mm=profile.tear_off_extra_mm,
                    default_cpi=profile.default_cpi,
                    default_lpi=profile.default_lpi,
                    default_font=profile.default_font,
                    is_custom=True,  # Force custom
                    metadata=profile.metadata,
                )
                self._custom_profiles[profile.id] = profile
                imported += 1
            except ValueError as exc:
                logger.warning("Ошибка импорта профиля: %s", exc)

        # Импортируем favorites
        for fid in data.get("favorites", []):
            if fid not in self._favorites and len(self._favorites) < MAX_FAVORITES:
                if self.get_profile(fid) is not None:
                    self._favorites.append(fid)

        self._save_favorites()
        self._notify_change()
        logger.info("Импортировано %d профилей", imported)
        return imported


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "PaperProfile",
    "PaperProfileService",
    "DEFAULT_LEFT_MARGIN_MM",
    "DEFAULT_RIGHT_MARGIN_MM",
    "DEFAULT_TOP_MARGIN_MM",
    "DEFAULT_BOTTOM_MARGIN_MM",
    "TEAR_OFF_EXTRA_MM",
    "MAX_FAVORITES",
]
