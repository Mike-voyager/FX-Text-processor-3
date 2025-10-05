"""
Абзац (Paragraph): расширенная промышленная модель для текстообработки и бизнес-логики редакторов.

- Поддержка коллекции runs с форматированием и вложенностью;
- Многоуровневые списки: буллеты (bullet), нумерация (numbering), вложенные списки (list_level), стили маркера (marker_style);
- Табуляторы и отступы (tabstops, indent, spacing);
- Встроенные объекты и закладки (embedded, bookmarks);
- Расширяемые пользовательские данные (user_data);
- Методы копирования, слияния, разбиения, сериализации, валидации, сравнения и представления.
"""

from dataclasses import dataclass, field
from typing import Any, List, Optional, Dict

from src.model.run import Run
from src.model.enums import Alignment, LineSpacing, TabAlignment


@dataclass(slots=True)
class EmbeddedObject:
    """
    Встроенный объект в абзаце — для изображений, UDC, закладок и т. д.
    """

    obj_type: str
    data: Any
    position: int  # Позиция относительно runs
    description: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "obj_type": self.obj_type,
            "data": self.data,
            "position": self.position,
            "description": self.description,
        }

    @staticmethod
    def from_dict(data: dict) -> "EmbeddedObject":
        return EmbeddedObject(
            obj_type=data["obj_type"],
            data=data["data"],
            position=data["position"],
            description=data.get("description"),
        )


@dataclass(slots=True)
class Paragraph:
    """
    Абзац текста с форматированием, табуляцией, списками и поддержкой вложенных объектов.
    """

    runs: List[Run] = field(default_factory=list)
    alignment: Alignment = Alignment.LEFT
    indent: float = 0.0
    spacing: float = 1.0
    tabstops: List[float] = field(default_factory=list)

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
            indent=self.indent,
            spacing=self.spacing,
            tabstops=list(self.tabstops),
            bullet=self.bullet,
            numbering=self.numbering,
            list_level=self.list_level,
            marker_style=self.marker_style,
            embedded=[EmbeddedObject.from_dict(e.to_dict()) for e in self.embedded],
            bookmarks=list(self.bookmarks),
            user_data=dict(self.user_data),
        )

    def to_dict(self) -> dict:
        return {
            "runs": [run.to_dict() for run in self.runs],
            "alignment": self.alignment.value,
            "indent": self.indent,
            "spacing": self.spacing,
            "tabstops": self.tabstops,
            "bullet": self.bullet,
            "numbering": self.numbering,
            "list_level": self.list_level,
            "marker_style": self.marker_style,
            "embedded": [e.to_dict() for e in self.embedded],
            "bookmarks": self.bookmarks,
            "user_data": self.user_data,
        }

    @staticmethod
    def from_dict(data: dict) -> "Paragraph":
        return Paragraph(
            runs=[Run.from_dict(r) for r in data.get("runs", [])],
            alignment=Alignment(data.get("alignment", "left")),
            indent=float(data.get("indent", 0.0)),
            spacing=float(data.get("spacing", 1.0)),
            tabstops=list(data.get("tabstops", [])),
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
            f"level={self.list_level}, embedded={len(self.embedded)}, text='{title}...')"
        )
