import pytest

from src.model.enums import Alignment
from src.model.paragraph import EmbeddedObject, Paragraph
from src.model.run import Run

# ---------- BASIC RUNS MANAGEMENT ----------


def test_add_and_get_runs() -> None:
    para = Paragraph()
    run1 = Run(text="Hello, ")
    run2 = Run(text="world!")
    para.add_run(run1)
    para.add_run(run2)
    assert para.get_text() == "Hello, world!"
    assert len(para) == len("Hello, world!")
    assert para.get_run_count() == 2


def test_insert_and_remove_run() -> None:
    para = Paragraph()
    r1 = Run(text="1")
    r2 = Run(text="3")
    para.add_run(r1)
    para.insert_run(1, r2)
    r_insert = Run(text="2")
    para.insert_run(1, r_insert)
    assert para.get_text() == "123"
    removed = para.remove_run(1)
    assert removed.text == "2"
    assert para.get_text() == "13"


def test_clear_runs() -> None:
    para = Paragraph()
    para.add_run(Run(text="data"))
    para.clear_runs()
    assert len(para.runs) == 0


def test_add_run_type_error() -> None:
    para = Paragraph()
    with pytest.raises(TypeError):
        para.add_run("not a run")  # type: ignore


# ---------- BULLET, NUMBERING, LIST LEVEL ----------


def test_bullet_and_numbering_fields() -> None:
    para = Paragraph(bullet="•", numbering=1, list_level=2)
    assert para.bullet == "•"
    assert para.numbering == 1
    assert para.list_level == 2


def test_marker_style_and_user_data() -> None:
    para = Paragraph(marker_style="square", user_data={"custom": 42})
    assert para.marker_style == "square"
    assert para.user_data["custom"] == 42


# ---------- EMBEDDED OBJECTS AND BOOKMARKS ----------


def test_embedded_and_bookmarks() -> None:
    para = Paragraph()
    obj = EmbeddedObject(obj_type="image", data="xyz", position=0)
    para.add_embedded(obj)
    assert len(para.embedded) == 1
    para.bookmarks.append("foo")
    assert "foo" in para.bookmarks


def test_copy_paragraph_full() -> None:
    para = Paragraph(
        runs=[Run(text="abc")],
        alignment=Alignment.CENTER,
        bullet="•",
        numbering=2,
        list_level=1,
        tabstops=[1.0, 2.5],
        marker_style="circle",
        embedded=[EmbeddedObject(obj_type="bookmark", data=None, position=0)],
        bookmarks=["bmk"],
        user_data={"k": "v"},
    )
    clone = para.copy()
    assert clone is not para
    assert clone == para
    assert clone.to_dict() == para.to_dict()


# ---------- MERGE / SPLIT ----------


def test_paragraph_merge() -> None:
    p1 = Paragraph(runs=[Run(text="abc")], bookmarks=["p1"])
    p2 = Paragraph(runs=[Run(text="def")], bookmarks=["p2"])
    merged = p1.merge(p2)
    assert merged.get_text() == "abcdef"
    assert "p1" in merged.bookmarks and "p2" in merged.bookmarks


def test_paragraph_split_at_valid_and_invalid() -> None:
    para = Paragraph()
    para.add_run(Run(text="a"))
    para.add_run(Run(text="b"))
    para.add_run(Run(text="c"))
    left, right = para.split_at(1)
    assert left.get_text() == "a"
    assert right.get_text() == "bc"
    with pytest.raises(ValueError):
        para.split_at(0)
    with pytest.raises(ValueError):
        para.split_at(3)  # upper bound


# ---------- TABSTOPS ----------


def test_tabstops_add_and_clear() -> None:
    para = Paragraph()
    para.add_tabstop(2.0)
    para.add_tabstop(3.5)
    assert 2.0 in para.tabstops
    para.clear_tabstops()
    assert len(para.tabstops) == 0


# ---------- SERIALIZATION ----------


def test_to_dict_from_dict_roundtrip() -> None:
    para = Paragraph(
        runs=[Run(text="hi")],
        bullet="*",
        numbering=4,
        list_level=1,
        tabstops=[1.2, 2.3],
        user_data={"meta": "yes"},
    )
    d = para.to_dict()
    restored = Paragraph.from_dict(d)
    assert para == restored
    assert restored.list_level == 1
    assert restored.user_data["meta"] == "yes"


# ---------- VALIDATION ----------


def test_validation_success_and_errors() -> None:
    para = Paragraph(runs=[Run(text="a")], alignment=Alignment.LEFT)
    para.validate()  # Should not raise
    para.numbering = -5  # invalid
    with pytest.raises(ValueError):
        para.validate()
    para.numbering = 10
    para.list_level = -2
    with pytest.raises(ValueError):
        para.validate()
    para.list_level = 0
    para.alignment = "not_aln"  # type: ignore
    with pytest.raises(TypeError):
        para.validate()


# ---------- EQ / REPR ----------


def test_eq_and_repr() -> None:
    para1 = Paragraph(runs=[Run(text="z")])
    para2 = Paragraph(runs=[Run(text="z")])
    assert para1 == para2
    assert para1.__repr__().startswith("Paragraph(runs=1")


def test_insert_run_type_error() -> None:
    para = Paragraph()
    with pytest.raises(TypeError):
        para.insert_run(0, "not a run")  # type: ignore


def test_validate_with_embedded() -> None:
    para = Paragraph()
    para.embedded.append(EmbeddedObject(obj_type="bookmark", data=None, position=0))
    # Не должен выбрасывать исключения
    para.validate()


def test_len_paragraph_with_wrong_run_object() -> None:
    para = Paragraph()

    class Dummy:
        pass

    # Добавим чужой объект руками
    para.runs.append(Dummy())  # type: ignore
    # НЕ выбросит ошибку, просто пропустит
    assert len(para) == 0


def test_eq_not_paragraph() -> None:
    para = Paragraph()
    # Должен вернуть NotImplemented
    result = para.__eq__("not_para")
    assert result is NotImplemented
