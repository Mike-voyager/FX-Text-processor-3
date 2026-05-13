"""
Абзац (Paragraph): расширенная промышленная модель для текстообработки и бизнес-логики редакторов.

- Поддержка коллекции runs с форматированием и вложенностью;
- Многоуровневые списки: буллеты (bullet), нумерация (numbering), вложенные списки (list_level), стили маркера (marker_style);
- Табуляторы и отступы (tabstops, indent, spacing);
- Встроенные объекты и закладки (embedded, bookmarks);
- Расширяемые пользовательские данные (user_data);
- Методы копирования, слияния, разбиения, сериализации, валидации, сравнения и представления.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Type, Union

if TYPE_CHECKING:
    pass

from src.model.enums import Alignment, CharSize, FontFamily, PrintQuality
from src.model.run import Run


@dataclass(frozen=True, slots=True)
class EmbeddedObject:
    """
    Встроенный объект в абзаце — для изображений, UDC, закладок и т. д.

    Note: Это локальный EmbeddedObject для paragraph. Для run-level объектов
    используйте src.model.run.EmbeddedObject.
    """

    obj_type: str
    data: Union[bytes, str, None] = None
    position: int = 0  # Позиция относительно runs
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "obj_type": self.obj_type,
            "data": self.data,
            "position": self.position,
            "description": self.description,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "EmbeddedObject":
        return EmbeddedObject(
            obj_type=data["obj_type"],
            data=data.get("data"),
            position=data.get("position", 0),
            description=data.get("description"),
        )


@dataclass(slots=True)
class Paragraph:
    """
    Абзац текста с форматированием, табуляцией, списками и поддержкой вложенных объектов.

    Attributes:
        runs: Список Run'ов с текстом и форматированием
        alignment: Выравнивание параграфа (Span-уровень)
        indent: Отступ параграфа
        spacing: Межстрочный интервал как множитель (1.0, 1.5, 2.0)
        tabstops: Позиции табуляторов

        # Line-уровень (ESC/P LineStyle)
        quality: Качество печати (Draft/NLQ)
        font_family: Шрифт (Draft/Roman/Sans Serif - только для NLQ)
        char_size: Размер символа (Normal/Double-width/Double-height)
        line_spacing: Межстрочный интервал в n/216 дюйма (None = использовать PageSettings)

        # Списки и маркеры
        bullet: Символ маркера списка
        numbering: Номер в нумерованном списке
        list_level: Уровень вложенности списка
        marker_style: Стиль маркера

        # Вложенные объекты и метаданные
        embedded: Встроенные объекты
        bookmarks: Закладки в параграфе
        user_data: Пользовательские данные
    """

    runs: List[Run] = field(default_factory=list)
    alignment: Alignment = Alignment.LEFT
    first_line_indent: float = 0.0
    left_indent: float = 0.0
    right_indent: float = 0.0
    indent: float = 0.0
    spacing: float = 1.0
    tabstops: List[float] = field(default_factory=list)

    # Line-уровень (ESC/P LineStyle) - НОВЫЕ ПОЛЯ
    quality: PrintQuality = PrintQuality.DRAFT
    font_family: FontFamily = FontFamily.DRAFT
    char_size: CharSize = CharSize.NORMAL
    line_spacing: Optional[int] = None  # n/216 дюйма, None = использовать PageSettings

    bullet: Optional[str] = None
    numbering: Optional[int] = None
    list_level: int = 0
    marker_style: Optional[str] = None

    embedded: List[EmbeddedObject] = field(default_factory=list)
    bookmarks: List[str] = field(default_factory=list)
    user_data: Dict[str, Any] = field(default_factory=dict)

    def add_run(self, run: Run) -> None:
        if not isinstance(run, Run):
            raise TypeError("Ожидается тип Run")
        self.runs.append(run)

    def insert_run(self, index: int, run: Run) -> None:
        if not isinstance(run, Run):
            raise TypeError("Ожидается тип Run")
        self.runs.insert(index, run)

    def remove_run(self, index: int) -> Run:
        return self.runs.pop(index)

    def clear_runs(self) -> None:
        self.runs.clear()

    def add_tabstop(self, position: float) -> None:
        self.tabstops.append(position)

    def clear_tabstops(self) -> None:
        self.tabstops.clear()

    def add_embedded(self, embedded: EmbeddedObject) -> None:
        self.embedded.append(embedded)

    def merge(self, other: "Paragraph") -> "Paragraph":
        """
        Объединить два абзаца (для join потока текста).
        """
        out = self.copy()
        out.runs.extend(r.copy() for r in other.runs)
        out.embedded.extend(e for e in other.embedded)
        out.bookmarks.extend(other.bookmarks)
        return out

    def split_at(self, run_index: int) -> tuple["Paragraph", "Paragraph"]:
        """
        Разбить абзац на два по индексу runs (аналог split_paragraph_at).
        """
        if not (0 < run_index < len(self.runs)):
            raise ValueError("Индекс для split вне диапазона")
        first = self.copy()
        second = self.copy()
        first.runs = self.runs[:run_index]
        second.runs = self.runs[run_index:]
        # В реальной реализации embedded/bookmarks делить по смыслу!
        return first, second

    def get_text(self) -> str:
        return "".join(run.text for run in self.runs)

    def get_run_count(self) -> int:
        return len(self.runs)

    def validate(self) -> None:
        # Проверка базовых enum-типов и структуры
        if not isinstance(self.alignment, Alignment):
            raise TypeError("alignment должен быть Alignment")
        if not isinstance(self.quality, PrintQuality):
            raise TypeError("quality должен быть PrintQuality")
        if not isinstance(self.font_family, FontFamily):
            raise TypeError("font_family должен быть FontFamily")
        if not isinstance(self.char_size, CharSize):
            raise TypeError("char_size должен быть CharSize")
        if self.line_spacing is not None and not (
            isinstance(self.line_spacing, int) and 0 < self.line_spacing <= 255
        ):
            raise ValueError("line_spacing должен быть int 1-255 или None")
        if self.numbering is not None and not (
            isinstance(self.numbering, int) and self.numbering >= 0
        ):
            raise ValueError("numbering должен быть положительным int или None")
        if not (isinstance(self.list_level, int) and self.list_level >= 0):
            raise ValueError("list_level должен быть >=0")
        for run in self.runs:
            run.validate()
        for obj in self.embedded:
            obj.to_dict()  # для сериализации

    def copy(self) -> "Paragraph":
        return Paragraph(
            runs=[r.copy() for r in self.runs],
            alignment=self.alignment,
            first_line_indent=self.first_line_indent,
            left_indent=self.left_indent,
            right_indent=self.right_indent,
            indent=self.indent,
            spacing=self.spacing,
            tabstops=list(self.tabstops),
            # LineStyle fields
            quality=self.quality,
            font_family=self.font_family,
            char_size=self.char_size,
            line_spacing=self.line_spacing,
            bullet=self.bullet,
            numbering=self.numbering,
            list_level=self.list_level,
            marker_style=self.marker_style,
            embedded=[EmbeddedObject.from_dict(e.to_dict()) for e in self.embedded],
            bookmarks=list(self.bookmarks),
            user_data=dict(self.user_data),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "runs": [run.to_dict() for run in self.runs],
            "alignment": self.alignment.value,
            "first_line_indent": self.first_line_indent,
            "left_indent": self.left_indent,
            "right_indent": self.right_indent,
            "indent": self.indent,
            "spacing": self.spacing,
            "tabstops": self.tabstops,
            # LineStyle fields
            "quality": self.quality.value,
            "font_family": self.font_family.value,
            "char_size": self.char_size.value,
            "line_spacing": self.line_spacing,
            "bullet": self.bullet,
            "numbering": self.numbering,
            "list_level": self.list_level,
            "marker_style": self.marker_style,
            "embedded": [e.to_dict() for e in self.embedded],
            "bookmarks": self.bookmarks,
            "user_data": self.user_data,
        }

    def __len__(self) -> int:
        """Возвращает число символов в тексте абзаца."""
        total = 0
        for run in self.runs:
            if hasattr(run, "text") and isinstance(run.text, str):
                total += len(run.text)
        return total

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "Paragraph":
        # Helper to safely get enum values
        from src.model.enums import StringEnumMixin

        def get_enum_value(enum_class: Type[StringEnumMixin], value: Any, default: Any) -> Any:
            if value is None:
                return default
            if isinstance(value, enum_class):
                return value
            try:
                result = enum_class.from_string(value)
                return result if result is not None else default
            except (ValueError, TypeError):
                return default

        return Paragraph(
            runs=[Run.from_dict(r) for r in data.get("runs", [])],
            alignment=get_enum_value(Alignment, data.get("alignment"), Alignment.LEFT),
            first_line_indent=float(data.get("first_line_indent", 0.0)),
            left_indent=float(data.get("left_indent", 0.0)),
            right_indent=float(data.get("right_indent", 0.0)),
            indent=float(data.get("indent", 0.0)),
            spacing=float(data.get("spacing", 1.0)),
            tabstops=list(data.get("tabstops", [])),
            # LineStyle fields
            quality=get_enum_value(PrintQuality, data.get("quality"), PrintQuality.DRAFT),
            font_family=get_enum_value(FontFamily, data.get("font_family"), FontFamily.DRAFT),
            char_size=get_enum_value(CharSize, data.get("char_size"), CharSize.NORMAL),
            line_spacing=data.get("line_spacing"),
            bullet=data.get("bullet"),
            numbering=data.get("numbering"),
            list_level=data.get("list_level", 0),
            marker_style=data.get("marker_style"),
            embedded=[EmbeddedObject.from_dict(e) for e in data.get("embedded", [])],
            bookmarks=list(data.get("bookmarks", [])),
            user_data=dict(data.get("user_data", {})),
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Paragraph):
            return NotImplemented
        return self.to_dict() == other.to_dict()

    def __repr__(self) -> str:
        title = self.get_text()[:20]
        return (
            f"Paragraph(runs={len(self.runs)}, align={self.alignment.name}, "
            f"indent={self.indent:.2f}, bullet={self.bullet!r}, num={self.numbering}, "
            f"level={self.list_level}, embedded={len(self.embedded)}, "
            f"quality={self.quality.value}, font={self.font_family.value}, "
            f"size={self.char_size.value}, text='{title}...')"
        )
