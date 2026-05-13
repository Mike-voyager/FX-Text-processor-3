"""Сервис водяных знаков.

Управление водяными знаками для документов.
Поддержка текстовых и графических водяных знаков.

Module: src/services/watermark_service.py
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from src.model.document import Document

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Типы и константы
# ---------------------------------------------------------------------------


class WatermarkType(Enum):
    """Тип водяного знака."""

    TEXT = "text"  # Текстовый
    IMAGE = "image"  # Графический
    PATTERN = "pattern"  # Паттерн


class WatermarkPosition(Enum):
    """Позиция водяного знака."""

    CENTER = "center"
    TOP_LEFT = "top_left"
    TOP_CENTER = "top_center"
    TOP_RIGHT = "top_right"
    MIDDLE_LEFT = "middle_left"
    MIDDLE_RIGHT = "middle_right"
    BOTTOM_LEFT = "bottom_left"
    BOTTOM_CENTER = "bottom_center"
    BOTTOM_RIGHT = "bottom_right"
    DIAGONAL = "diagonal"  # По диагонали
    TILE = "tile"  # Мозаика


class WatermarkBlendMode(Enum):
    """Режим наложения."""

    NORMAL = "normal"
    MULTIPLY = "multiply"
    SCREEN = "screen"
    OVERLAY = "overlay"
    DARKEN = "darken"
    LIGHTEN = "lighten"


# ---------------------------------------------------------------------------
# Модели данных
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TextStyle:
    """Стиль текста.

    Attrs:
        font_family: Шрифт
        font_size: Размер (pt)
        font_weight: Насыщенность (normal/bold)
        font_style: Стиль (normal/italic)
        color: Цвет (hex)
        alpha: Прозрачность (0-255)
    """

    font_family: str = "Arial"
    font_size: int = 48
    font_weight: str = "normal"
    font_style: str = "normal"
    color: str = "#000000"
    alpha: int = 128  # 0-255, 128 = 50% прозрачность


@dataclass(frozen=True)
class TextWatermark:
    """Текстовый водяной знак.

    Attrs:
        id: Идентификатор
        text: Текст водяного знака
        style: Стиль текста
        position: Позиция
        rotation: Угол поворота (градусы)
        opacity: Непрозрачность (0.0-1.0)
    """

    id: UUID = field(default_factory=uuid4)
    text: str = "DRAFT"
    style: TextStyle = field(default_factory=TextStyle)
    position: WatermarkPosition = WatermarkPosition.DIAGONAL
    rotation: float = -45.0
    opacity: float = 0.3


@dataclass(frozen=True)
class ImageWatermark:
    """Графический водяной знак.

    Attrs:
        id: Идентификатор
        image_path: Путь к изображению
        position: Позиция
        scale: Масштаб (0.0-1.0)
        opacity: Непрозрачность (0.0-1.0)
        blend_mode: Режим наложения
    """

    id: UUID = field(default_factory=uuid4)
    image_path: Optional[Path] = None
    image_data: bytes = field(default_factory=bytes)
    position: WatermarkPosition = WatermarkPosition.CENTER
    scale: float = 1.0
    opacity: float = 0.3
    blend_mode: WatermarkBlendMode = WatermarkBlendMode.NORMAL


@dataclass(frozen=True)
class PatternWatermark:
    """Паттерн водяного знака.

    Attrs:
        id: Идентификатор
        pattern_type: Тип паттерна
        size: Размер паттерна
        color: Цвет
        opacity: Непрозрачность
    """

    id: UUID = field(default_factory=uuid4)
    pattern_type: str = "dots"  # dots, lines, grid, etc.
    size: int = 10
    color: str = "#808080"
    opacity: float = 0.1


@dataclass(frozen=True)
class WatermarkConfig:
    """Конфигурация водяного знака.

    Attrs:
        watermark: Водяной знак (text/image/pattern)
        apply_to_all_pages: Применить ко всем страницам
        page_range: Диапазон страниц (optional)
        layer: Слой (background/foreground)
    """

    watermark: TextWatermark | ImageWatermark | PatternWatermark = field(
        default_factory=TextWatermark
    )
    apply_to_all_pages: bool = True
    page_range: Optional[Tuple[int, int]] = None
    layer: str = "background"  # background/foreground


@dataclass(frozen=True)
class WatermarkResult:
    """Результат применения водяного знака.

    Attrs:
        success: Успешность операции
        watermark_id: ID водяного знака
        applied_pages: Применённые страницы
        error: Сообщение об ошибке (optional)
    """

    success: bool
    watermark_id: UUID
    applied_pages: List[int] = field(default_factory=list)
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# WatermarkService
# ---------------------------------------------------------------------------


class WatermarkService:
    """Сервис водяных знаков.

    Предоставляет:
    - Создание текстовых водяных знаков
    - Создание графических водяных знаков
    - Применение к документам
    - Удаление водяных знаков
    - Предпросмотр

    Пример:
        >>> service = WatermarkService()
        >>> watermark = TextWatermark(text="CONFIDENTIAL", opacity=0.3)
        >>> result = service.apply(document, watermark)
        >>> if result.success:
        ...     print(f"Applied to {len(result.applied_pages)} pages")
    """

    def __init__(self) -> None:
        """Инициализирует сервис."""
        # Кэш водяных знаков: document_id -> list of watermarks
        self._watermarks: Dict[UUID, List[WatermarkConfig]] = {}

        # Предустановленные водяные знаки
        self._presets = self._create_presets()

    def _create_presets(self) -> Dict[str, WatermarkConfig]:
        """Создаёт предустановленные водяные знаки.

        Returns:
            Словарь предустановок
        """
        return {
            "draft": WatermarkConfig(
                watermark=TextWatermark(
                    text="DRAFT",
                    style=TextStyle(font_size=72, color="#808080"),
                    position=WatermarkPosition.DIAGONAL,
                    rotation=-45.0,
                    opacity=0.2,
                ),
            ),
            "confidential": WatermarkConfig(
                watermark=TextWatermark(
                    text="CONFIDENTIAL",
                    style=TextStyle(font_size=60, color="#FF0000"),
                    position=WatermarkPosition.DIAGONAL,
                    rotation=-45.0,
                    opacity=0.3,
                ),
            ),
            "copy": WatermarkConfig(
                watermark=TextWatermark(
                    text="COPY",
                    style=TextStyle(font_size=48, color="#000080"),
                    position=WatermarkPosition.CENTER,
                    rotation=0.0,
                    opacity=0.25,
                ),
            ),
            "sample": WatermarkConfig(
                watermark=TextWatermark(
                    text="SAMPLE",
                    style=TextStyle(font_size=80, color="#808080"),
                    position=WatermarkPosition.DIAGONAL,
                    rotation=-30.0,
                    opacity=0.15,
                ),
            ),
        }

    # ---------- Создание водяных знаков ----------

    def create_text_watermark(
        self,
        text: str,
        font_size: int = 48,
        color: str = "#000000",
        opacity: float = 0.3,
        position: WatermarkPosition = WatermarkPosition.DIAGONAL,
        rotation: float = -45.0,
    ) -> TextWatermark:
        """Создаёт текстовый водяной знак.

        Args:
            text: Текст
            font_size: Размер шрифта
            color: Цвет
            opacity: Непрозрачность
            position: Позиция
            rotation: Угол поворота

        Returns:
            Текстовый водяной знак
        """
        return TextWatermark(
            text=text,
            style=TextStyle(font_size=font_size, color=color),
            position=position,
            rotation=rotation,
            opacity=opacity,
        )

    def create_image_watermark(
        self,
        image_path: Path,
        position: WatermarkPosition = WatermarkPosition.CENTER,
        scale: float = 1.0,
        opacity: float = 0.3,
    ) -> ImageWatermark:
        """Создаёт графический водяной знак.

        Args:
            image_path: Путь к изображению
            position: Позиция
            scale: Масштаб
            opacity: Непрозрачность

        Returns:
            Графический водяной знак
        """
        return ImageWatermark(
            image_path=image_path,
            position=position,
            scale=scale,
            opacity=opacity,
        )

    def create_pattern_watermark(
        self,
        pattern_type: str,
        size: int = 10,
        color: str = "#808080",
        opacity: float = 0.1,
    ) -> PatternWatermark:
        """Создаёт паттерн водяного знака.

        Args:
            pattern_type: Тип паттерна
            size: Размер
            color: Цвет
            opacity: Непрозрачность

        Returns:
            Паттерн водяного знака
        """
        return PatternWatermark(
            pattern_type=pattern_type,
            size=size,
            color=color,
            opacity=opacity,
        )

    # ---------- Применение водяных знаков ----------

    def apply(
        self,
        document: "Document",
        watermark: TextWatermark | ImageWatermark | PatternWatermark,
        apply_to_all_pages: bool = True,
        page_range: Optional[Tuple[int, int]] = None,
    ) -> WatermarkResult:
        """Применяет водяной знак к документу.

        Args:
            document: Документ
            watermark: Водяной знак
            apply_to_all_pages: Применить ко всем страницам
            page_range: Диапазон страниц

        Returns:
            Результат операции
        """
        try:
            config = WatermarkConfig(
                watermark=watermark,
                apply_to_all_pages=apply_to_all_pages,
                page_range=page_range,
            )

            # Определяем страницы
            if apply_to_all_pages:
                pages = self._get_all_pages(document)
            elif page_range:
                pages = list(range(page_range[0], page_range[1] + 1))
            else:
                pages = [1]  # Только первая страница

            # Добавляем в кэш
            if document.id not in self._watermarks:
                self._watermarks[document.id] = []
            self._watermarks[document.id].append(config)

            logger.info(
                "Водяной знак применён к документу %s: %d страниц",
                document.id,
                len(pages),
            )

            return WatermarkResult(
                success=True,
                watermark_id=watermark.id,
                applied_pages=pages,
            )

        except Exception as exc:
            logger.error("Ошибка применения водяного знака: %s", exc)
            return WatermarkResult(
                success=False,
                watermark_id=watermark.id,
                error=str(exc),
            )

    def apply_preset(
        self,
        document: "Document",
        preset_name: str,
    ) -> WatermarkResult:
        """Применяет предустановленный водяной знак.

        Args:
            document: Документ
            preset_name: Имя предустановки

        Returns:
            Результат операции
        """
        preset = self._presets.get(preset_name)
        if preset is None:
            return WatermarkResult(
                success=False,
                watermark_id=uuid4(),
                error=f"Предустановка не найдена: {preset_name}",
            )

        return self.apply(document, preset.watermark)

    def remove(
        self,
        document: "Document",
        watermark_id: Optional[UUID] = None,
    ) -> int:
        """Удаляет водяные знаки с документа.

        Args:
            document: Документ
            watermark_id: ID конкретного водяного знака (optional)

        Returns:
            Количество удалённых водяных знаков
        """
        if document.id not in self._watermarks:
            return 0

        if watermark_id:
            # Удаляем конкретный
            original_count = len(self._watermarks[document.id])
            self._watermarks[document.id] = [
                w for w in self._watermarks[document.id] if w.watermark.id != watermark_id
            ]
            removed = original_count - len(self._watermarks[document.id])
        else:
            # Удаляем все
            removed = len(self._watermarks[document.id])
            del self._watermarks[document.id]

        logger.info("Удалено %d водяных знаков с документа %s", removed, document.id)
        return removed

    # ---------- Запросы ----------

    def get_watermarks(self, document_id: UUID) -> List[WatermarkConfig]:
        """Возвращает водяные знаки документа.

        Args:
            document_id: ID документа

        Returns:
            Список конфигураций водяных знаков
        """
        return self._watermarks.get(document_id, [])

    def get_presets(self) -> Dict[str, WatermarkConfig]:
        """Возвращает предустановленные водяные знаки.

        Returns:
            Словарь предустановок
        """
        return self._presets.copy()

    def has_watermarks(self, document_id: UUID) -> bool:
        """Проверяет наличие водяных знаков.

        Args:
            document_id: ID документа

        Returns:
            True если есть водяные знаки
        """
        return document_id in self._watermarks and len(self._watermarks[document_id]) > 0

    # ---------- Генерация ESC/P ----------

    def generate_escp_commands(
        self,
        watermark: TextWatermark | ImageWatermark | PatternWatermark,
        page_width: int = 80,
        page_height: int = 66,
        supports_graphics: bool = False,
    ) -> bytes:
        """Генерирует ESC/P команды для водяного знака.

        Args:
            watermark: Водяной знак
            page_width: Ширина страницы (символы)
            page_height: Высота страницы (строки)
            supports_graphics: Поддержка графики принтером

        Returns:
            ESC/P команды
        """
        # Для ESC/P текстовые водяные знаки - самые простые
        if isinstance(watermark, TextWatermark):
            return self._generate_text_escp(watermark, page_width, page_height)

        if isinstance(watermark, PatternWatermark):
            return self._generate_pattern_escp(
                watermark, page_width, page_height, supports_graphics
            )

        # Графические водяные знаки требуют поддержки графики
        # (не все ESC/P принтеры поддерживают)
        logger.warning("Графические водяные знаки не поддерживаются в ESC/P")
        return b""

    def _generate_text_escp(
        self,
        watermark: TextWatermark,
        page_width: int,
        page_height: int,
    ) -> bytes:
        """Генерирует ESC/P для текстового водяного знака.

        Args:
            watermark: Текстовый водяной знак
            page_width: Ширина страницы
            page_height: Высота страницы

        Returns:
            ESC/P команды
        """
        commands = bytearray()

        # ESC/P заголовок
        commands.extend(b"\x1b@")  # Инициализация

        # Определяем позицию
        text_len = len(watermark.text)
        x, y = self._calculate_position(
            watermark.position,
            page_width,
            page_height,
            text_len,
        )

        # Перемещаем курсор
        if y > 0:
            commands.extend(b"\x1b" + b"(" + y.to_bytes(2, "little"))
        if x > 0:
            commands.extend(b"\x1b" + b"$" + x.to_bytes(2, "little"))

        # Устанавливаем стиль текста
        # Bold
        if watermark.style.font_weight == "bold":
            commands.extend(b"\x1bE")  # Bold on

        # Italic
        if watermark.style.font_style == "italic":
            commands.extend(b"\x1b4")  # Italic on

        # Пишем текст
        commands.extend(watermark.text.encode("pc866", errors="replace"))

        # Восстанавливаем стиль
        if watermark.style.font_weight == "bold":
            commands.extend(b"\x1bF")  # Bold off
        if watermark.style.font_style == "italic":
            commands.extend(b"\x1b5")  # Italic off

        return bytes(commands)

    def _generate_pattern_escp(
        self,
        watermark: PatternWatermark,
        page_width: int,
        page_height: int,
        supports_graphics: bool = False,
    ) -> bytes:
        """Генерирует ESC/P для паттерна водяного знака.

        Args:
            watermark: Паттерн водяного знака
            page_width: Ширина страницы (символы)
            page_height: Высота страницы (строки)
            supports_graphics: Поддержка графики принтером

        Returns:
            ESC/P команды
        """
        if watermark.pattern_type == "dots":
            pattern_char = "*"
        elif watermark.pattern_type == "lines":
            pattern_char = "-"
        elif watermark.pattern_type == "grid":
            pattern_char = "+"
        else:
            pattern_char = "·"

        commands = bytearray()

        if supports_graphics:
            # Графический паттерн из звёздочек/точек
            for y in range(0, page_height, watermark.size + 1):
                if y > 0:
                    # Прогонка строки
                    commands.extend(b"\x1b" + b"J" + b"\x00")
                for x in range(0, page_width, watermark.size + 1):
                    # Перемещение в позицию
                    if x > 0:
                        commands.extend(b"\x1b" + b"$" + x.to_bytes(2, "little"))
                    # Вывод символа паттерна
                    commands.extend(pattern_char.encode("ascii"))
            return bytes(commands)

        # Текстовый паттерн для принтеров без графики
        for y in range(0, page_height, watermark.size + 1):
            # Перемещаем курсор на нужную строку
            if y > 0:
                for _ in range(y):
                    commands.extend(b"\n")
            # Проверяем позицию X по абсолютным координатам
            if watermark.position == WatermarkPosition.CENTER:
                x = (page_width - (page_width // watermark.size) * watermark.size) // 2
            else:
                x = 0
            # Используем ESC/P для позиционирования
            if x > 0:
                commands.extend(b"\x1b" + b"$" + x.to_bytes(2, "little"))
            line = ""
            for i in range(0, page_width, watermark.size + 1):
                line += pattern_char + " " * watermark.size
            commands.extend(line[:page_width].encode("ascii"))
        return bytes(commands)

    def _calculate_position(
        self,
        position: WatermarkPosition,
        page_width: int,
        page_height: int,
        text_len: int,
    ) -> Tuple[int, int]:
        """Вычисляет позицию для водяного знака.

        Args:
            position: Позиция
            page_width: Ширина страницы
            page_height: Высота страницы
            text_len: Длина текста

        Returns:
            (x, y) координаты
        """
        center_x = (page_width - text_len) // 2
        center_y = page_height // 2

        positions = {
            WatermarkPosition.CENTER: (center_x, center_y),
            WatermarkPosition.TOP_LEFT: (0, 0),
            WatermarkPosition.TOP_CENTER: (center_x, 0),
            WatermarkPosition.TOP_RIGHT: (page_width - text_len, 0),
            WatermarkPosition.MIDDLE_LEFT: (0, center_y),
            WatermarkPosition.MIDDLE_RIGHT: (page_width - text_len, center_y),
            WatermarkPosition.BOTTOM_LEFT: (0, page_height - 1),
            WatermarkPosition.BOTTOM_CENTER: (center_x, page_height - 1),
            WatermarkPosition.BOTTOM_RIGHT: (page_width - text_len, page_height - 1),
            WatermarkPosition.DIAGONAL: (page_width // 4, page_height // 4),
            WatermarkPosition.TILE: (0, 0),
        }

        return positions.get(position, (center_x, center_y))

    def _get_all_pages(self, document: "Document") -> List[int]:
        """Возвращает все страницы документа.

        Args:
            document: Документ

        Returns:
            Список номеров страниц
        """
        lines_per_page: int = document.page_settings.lines_per_page
        paragraphs: int = sum(
            len(section.paragraphs) for section in document.sections
        )
        if paragraphs == 0:
            return [1]
        total_pages: int = math.ceil(paragraphs / lines_per_page)
        return list(range(1, total_pages + 1))

    # ---------- Предпросмотр ----------

    def preview(
        self,
        watermark: TextWatermark | ImageWatermark | PatternWatermark,
        width: int = 200,
        height: int = 100,
    ) -> List[str]:
        """Генерирует текстовый предпросмотр водяного знака.

        Args:
            watermark: Водяной знак
            width: Ширина (символы)
            height: Высота (строки)

        Returns:
            Список строк предпросмотра
        """
        lines = [" " * width for _ in range(height)]

        if isinstance(watermark, TextWatermark):
            text = watermark.text
            x, y = self._calculate_position(
                watermark.position,
                width,
                height,
                len(text),
            )

            # Размещаем текст
            if 0 <= y < height:
                line = lines[y]
                # Обрезаем если выходит за границы
                end_x = min(x + len(text), width)
                if end_x > x:
                    new_line = line[:x] + text[: end_x - x] + line[end_x:]
                    lines[y] = new_line

        elif isinstance(watermark, PatternWatermark):
            # Паттерн - заполняем символами
            char = "·"
            for i in range(0, height, watermark.size):
                if i < len(lines):
                    new_line = ""
                    for _j in range(0, width, watermark.size):
                        new_line += char + " " * (watermark.size - 1)
                    lines[i] = new_line[:width]

        return lines


__all__ = [
    "WatermarkService",
    "WatermarkType",
    "WatermarkPosition",
    "WatermarkBlendMode",
    "TextStyle",
    "TextWatermark",
    "ImageWatermark",
    "PatternWatermark",
    "WatermarkConfig",
    "WatermarkResult",
]
