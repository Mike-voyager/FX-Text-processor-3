import logging
from typing import Any

import pytest

from src.model.table import (
    BarCode,
    BorderChars,
    Cell,
    CellAlignment,
    CellBorders,
    CellDataType,
    CellStyle,
    ConditionalRule,
    PaperSettings,
    Paragraph,
    Run,
    Table,
    TableBorder,
    TableMetrics,
    VerticalAlignment,
)

# ----------- BASIC STRUCTURE -----------


def test_add_and_get_cell() -> None:
    c = Cell(text="A1")
    t = Table(rows=[[c]])
    assert t.get_cell(0, 0).text == "A1"


def test_add_row_type_error() -> None:
    t = Table(rows=[[Cell()]])
    with pytest.raises(TypeError):
        t.add_row("not a list")  # type: ignore


def test_add_row_length_error() -> None:
    t = Table(rows=[[Cell(), Cell()]])
    with pytest.raises(ValueError):
        t.add_row([Cell()])


def test_insert_row_and_index_error() -> None:
    t = Table(rows=[[Cell(), Cell()]])
    with pytest.raises(IndexError):
        t.insert_row(2, [Cell(), Cell()])  # out of range


def test_merge_and_split_cells() -> None:
    t = Table(rows=[[Cell(), Cell()], [Cell(), Cell()]])
    t.merge_cells(0, 0, 2, 2)
    assert t.get_cell(0, 0).rowspan == 2
    assert t.get_cell(0, 0).colspan == 2
    t.split_cell(0, 0)
    assert t.get_cell(0, 0).rowspan == 1
    assert t.get_cell(0, 0).colspan == 1
    # остальные ячейки после разъединения должны быть Cell с кол-спан/роу-спан = 1
    assert all(
        t.get_cell(i, j).rowspan == 1 and t.get_cell(i, j).colspan == 1
        for i in range(2)
        for j in range(2)
    )


def test_add_column_and_swap_column_errors() -> None:
    t = Table(rows=[[Cell()]])
    with pytest.raises(ValueError):
        Table(rows=[]).add_column()
    t.add_column()
    assert len(t.rows[0]) == 2
    t.add_column(index=0)
    assert len(t.rows[0]) == 3
    with pytest.raises(IndexError):
        t.swap_columns(0, 10)


def test_borderchars_for_all_styles() -> None:
    for style in [
        TableBorder.SINGLE,
        TableBorder.DOUBLE,
        TableBorder.ASCII_ART,
        TableBorder.NONE,
    ]:
        chars = BorderChars.for_style(style)
        assert isinstance(chars, BorderChars)


def test_is_any_visible_and_merged_and_nested() -> None:
    cb = CellBorders(
        TableBorder.SINGLE, TableBorder.NONE, TableBorder.NONE, TableBorder.NONE
    )
    assert cb.is_any_visible()
    cell = Cell()
    assert cell.is_merged() is False
    cell.colspan = 2
    assert cell.is_merged() is True
    cell.colspan, cell.rowspan = 1, 2
    assert cell.is_merged() is True
    cell.colspan, cell.rowspan = 1, 1
    cell.nested_table = Table(rows=[[Cell()]])
    assert cell.hasnestedtable() is True


def test_as_dict_all_options() -> None:
    # paragraph и runs вместе, nested_table flat/nonflat
    para = Paragraph(runs=[Run("a")], alignment=CellAlignment.RIGHT, indent=2)
    c = Cell(text="t", paragraph=para, runs=[Run("b")])
    c.nested_table = Table(rows=[[Cell(text="inn")]])
    no_flat = c.as_dict()
    flat = c.as_dict(flatten=True)
    assert "paragraph" in no_flat
    assert "runs" in no_flat
    assert no_flat["nested_table"] == "<table>"
    assert "nested_table" in flat and isinstance(flat["nested_table"], dict)


def test_paginate_empty_and_no_header() -> None:
    t = Table(rows=[[Cell()]])
    # paginate из одной строки, без repeat_header
    pages = t.paginate(10, repeat_header=False)
    assert len(pages) == 1
    # paginate пустой таблицы — не бросает
    t_empty = Table(rows=[])
    pages_empty = t_empty.paginate(10)
    assert pages_empty == []


def test_aggregate_valueerror_branch() -> None:
    t = Table(rows=[[Cell(text="xx")]])
    # Пропускает ошибку ValueError
    assert t.aggregate(0) == 0.0
    # Unknown method causes ValueError
    with pytest.raises(ValueError):
        t.aggregate(0, method="MAX")


def test_create_from_template_and_invalid_dict() -> None:
    base = Table(rows=[[Cell(text="a")]])
    new = Table().create_from_template(base)
    assert isinstance(new, Table)


def test_ascii_preview_max_depth_and_nested() -> None:
    t = Table(rows=[[Cell(text="X")]])
    c_nested = Cell(text="Y", nested_table=t)
    t2 = Table(rows=[[c_nested]])
    assert "<max depth reached>" in t2.ascii_preview(-1)
    _ = t2.ascii_preview()


def test_footprint_types_and_styles() -> None:
    cell1 = Cell(text="1", data_type=CellDataType.NUMBER, style=CellStyle(bold=True))
    cell2 = Cell(text="t", data_type=CellDataType.TEXT, style=None)
    t = Table(rows=[[cell1, cell2]])
    fp = t.footprint()
    assert fp["type_histogram"]["number"] == 1
    assert fp["style_histogram"][str(cell1.style)] == 1


def test_cell_statistics_all_fields() -> None:
    bc = BarCode(data="123")
    c = Cell(text="1", data_type=CellDataType.NUMBER, formula="=", barcode=bc)
    t = Table(rows=[[c]])
    stats = t.cell_statistics()
    assert stats["numeric_cells"] == 1
    assert stats["formula_cells"] == 1
    assert stats["barcode_cells"] == 1


def test_validate_span_and_types() -> None:
    t = Table(rows=[[Cell(colspan=101)]])  # MAX_SPAN==100
    assert t.validate() is False
    t = Table(rows=[[Cell(rowspan=101)]])
    assert t.validate() is False
    t = Table(rows=[[Cell(data_type="badtype")]])  # type: ignore
    assert t.validate() is False


# ----------- SERIALIZATION -----------


def test_cell_as_dict_and_flatten() -> None:
    cell = Cell(text="txt", align=CellAlignment.CENTER, valign=VerticalAlignment.BOTTOM)
    d = cell.as_dict(flatten=False)
    assert d["text"] == "txt"
    assert d["align"] == "center"
    table = Table(rows=[[cell]])
    ser = table.serialize(flatten=True)
    assert isinstance(ser, dict)


def test_table_from_dict_and_json_roundtrip() -> None:
    t = Table(rows=[[Cell(text="x")]])
    ser = t.serialize()
    t2 = Table.from_dict(ser)
    assert t2.rows[0][0].text == "x"
    # JSON
    js = t.to_json()
    Table.from_json(js)


# ----------- NESTED STRUCTURE -----------


def test_nested_table_flat() -> None:
    inner = Table(rows=[[Cell(text="in")]])
    cell = Cell(text="out", nested_table=inner)
    t = Table(rows=[[cell]])
    assert next(t.traverse()) == t
    assert inner in t.flatten()


def test_validate_span_coverage() -> None:
    t = Table(rows=[[Cell(), Cell()], [Cell(), Cell()]])
    assert t.validate_span_coverage() is True
    t.get_cell(0, 0).colspan = 2
    t.get_cell(0, 0).rowspan = 2
    assert t.validate_span_coverage() is False


# ----------- METRICS, AGG, UTIL -----------


def test_aggregate_and_groupby() -> None:
    t = Table(
        rows=[
            [Cell(text="1"), Cell(text="A")],
            [Cell(text="2"), Cell(text="A")],
            [Cell(text="3"), Cell(text="B")],
        ]
    )
    assert t.aggregate(0, method="SUM") == 6
    assert t.aggregate(0, method="AVG") == 2
    with pytest.raises(ValueError):
        t.aggregate(0, method="XYZ")
    by = t.groupby(1)
    assert by["A"][0][0].text == "1"
    assert by["B"][0][0].text == "3"


def test_ascii_preview() -> None:
    t = Table(rows=[[Cell(text="X")]])
    preview = t.ascii_preview()
    assert isinstance(preview, str)


def test_table_metrics_and_borders() -> None:
    cells = [Cell(text=str(i)) for i in range(3)]
    t = Table(rows=[cells for _ in range(3)])
    pages = t.paginate(max_rows_per_page=2)
    assert len(pages) > 0
    t.set_padding(1, 2, 3, 4)
    for page in pages:
        assert isinstance(page, Table)


def test_apply_conditional_formatting() -> None:
    style = CellStyle(bold=True)
    cond = lambda txt: txt == "42"
    rule = ConditionalRule(condition=cond, style=style)
    cell = Cell(text="42", conditional_rules=[rule])
    t = Table(rows=[[cell]])
    t.apply_conditional_formatting()
    assert t.get_cell(0, 0).style == style


def test_transpose_and_swap_columns() -> None:
    t = Table(rows=[[Cell(text="A"), Cell(text="B")], [Cell(text="C"), Cell(text="D")]])
    t.transpose()
    assert t.rows[0][0].text == "A"
    t.swap_columns(0, 1)
    assert t.rows[0][1].text == "A"


def test_table_validation_and_cycles() -> None:
    t = Table(rows=[[Cell(), Cell()], [Cell(), Cell()]])
    assert t.validate() is True
    t.rows.append([Cell()])  # uneven
    assert t.validate() is False
    # цикл
    loop = Table(rows=[[Cell()]])
    loop.rows[0][0].nested_table = loop
    assert loop.validate() is False


def test_table_flatten_methods_and_stats() -> None:
    t = Table(rows=[[Cell(text="A")]])
    assert "A" in t.flatten_text()
    fp = t.footprint()
    cs = t.cell_statistics()
    es = t.export_stats()
    assert fp["cell_count"] == 1
    assert cs["total_length"] == 1
    assert es["cell_statistics"]["total_length"] == 1


def test_table_paper_metrics() -> None:
    paper = PaperSettings(width_mm=210, height_mm=297)
    tm = TableMetrics(rows=2, columns=2, width_mm=210, height_mm=297)
    t = Table(rows=[[Cell(), Cell()], [Cell(), Cell()]], paper=paper, metrics=tm)
    assert t.paper is not None and t.paper.width_mm == 210
    assert t.metrics is not None and t.metrics.width_mm == 210


def test_apply_conditional_formatting_with_error() -> None:
    def cond(txt: Any) -> bool:
        raise Exception("fail")

    style = CellStyle()
    rule = ConditionalRule(condition=cond, style=style)
    cell = Cell(text="err", conditional_rules=[rule])
    t = Table(rows=[[cell]])
    # Ошибка не останавливает application
    t.apply_conditional_formatting()


def test_cell_copy() -> None:
    c = Cell(text="X")
    c2 = c.copy()
    assert c2 is not c
    assert c2.text == "X"


def test_add_row_success_and_logging(caplog: Any) -> None:
    t = Table(rows=[[Cell(), Cell()]])
    with caplog.at_level(logging.DEBUG):
        t.add_row([Cell(), Cell()])
    assert "Added row of 2 cells" in caplog.text
    assert len(t.rows) == 2


def test_insert_row_success_and_logging(caplog: Any) -> None:
    t = Table(rows=[[Cell(), Cell()]])
    with caplog.at_level(logging.DEBUG):
        t.insert_row(1, [Cell(), Cell()])
    assert "Inserted row at 1, 2 cells" in caplog.text
    assert len(t.rows) == 2


def test_insert_row_errors() -> None:
    t = Table(rows=[[Cell(), Cell()]])
    with pytest.raises(TypeError):
        t.insert_row(1, "abc")  # type: ignore
    with pytest.raises(ValueError):
        t.insert_row(1, [Cell()])


def test_split_cell_nothing_to_do() -> None:
    t = Table(rows=[[Cell()]])
    t.split_cell(0, 0)  # cell.colspan/rowspan == 1, ничего не делает, но ветка покрыта
    assert t.get_cell(0, 0).colspan == 1


def test_set_paper_logging(caplog: Any) -> None:
    p = PaperSettings(width_mm=100, height_mm=150)
    t = Table(rows=[[Cell()]])
    with caplog.at_level(logging.INFO):
        t.set_paper(p)
    assert t.paper is p
    assert "Paper set to" in caplog.text


def test_apply_conditional_formatting_full_cycle() -> None:
    style = CellStyle(bold=True)
    cond = lambda txt: True
    rule = ConditionalRule(condition=cond, style=style)
    cell = Cell(text="1", conditional_rules=[rule])
    t = Table(rows=[[cell]])
    t.apply_conditional_formatting()
    assert cell.style is not None and cell.style.bold is True


def test_validate_span_coverage_nested() -> None:
    t = Table(rows=[[Cell(colspan=2, rowspan=2), Cell()], [Cell(), Cell()]])
    assert not t.validate_span_coverage()


def test_check_cycles_branch() -> None:
    t1 = Table(rows=[[Cell()]])
    t2 = Table(rows=[[Cell(nested_table=t1)]])
    t1.rows[0][0].nested_table = t2  # цикл
    assert t1.validate() is False
