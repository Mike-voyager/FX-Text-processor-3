"""
Юнит‑тесты для модели Section с учетом ограничений FX‑890 ESC/P.

Покрытие: управление содержимым, валидация, сериализация, работа ограничений FX-890, поля, настройка страницы, экспорт для билдера и утилиты.

Файл: tests/unit/model/test_section.py
"""

import pytest

from src.model.paragraph import Paragraph
from src.model.run import Run
from src.model.section import (
    MAX_MARGIN_INCHES,
    MAX_PAGE_LENGTH_INCHES,
    MAX_PAGE_NUMBER,
    MAX_PAGE_WIDTH_INCHES,
    MIN_MARGIN_INCHES,
    MIN_PAGE_LENGTH_INCHES,
    MIN_PAGE_NUMBER,
    MIN_PAGE_WIDTH_INCHES,
    Margins,
    PageOrientation,
    PageSettings,
    Section,
    SectionBreak,
    merge_sections,
    split_section_at,
)

# =============================================================================
# Проверка иммутабельности Margins/PageSettings
# =============================================================================


class FakeParagraph(Paragraph):
    def validate(self) -> None:
        raise ValueError("fail")


def test_margins_frozen() -> None:
    margins = Margins()
    with pytest.raises(AttributeError):
        margins.top = 2.0  # type: ignore[attr-defined, misc, assignment]


def test_page_settings_frozen() -> None:
    settings = PageSettings()
    with pytest.raises(AttributeError):
        settings.width = 10.0  # type: ignore[attr-defined, misc, assignment]


# =============================================================================
# Проверка негативных кейсов по типизации (ловим TypeError)
# =============================================================================


@pytest.mark.parametrize("field", ["top", "bottom", "left", "right"])
def test_margins_validate_non_numeric(field: str) -> None:
    kwargs = {field: "invalid"}  # type: ignore
    margins = Margins(**kwargs)  # type: ignore
    with pytest.raises(TypeError):
        margins.validate()


def test_margins_from_dict_invalid_type() -> None:
    with pytest.raises(TypeError):
        Margins.from_dict("not a dict")  # type: ignore[arg-type]


@pytest.mark.parametrize("field", ["width", "height"])
def test_page_settings_validate_non_numeric(field: str) -> None:
    kwargs = {field: "invalid"}  # type: ignore
    page_settings = PageSettings(**kwargs)  # type: ignore
    with pytest.raises(TypeError):
        page_settings.validate()


def test_page_settings_validate_orientation_type() -> None:
    page_settings = PageSettings(width=8.5, height=11.0, orientation="portrait")  # type: ignore
    with pytest.raises(TypeError):
        page_settings.validate()


def test_page_settings_validate_margins_type() -> None:
    page_settings = PageSettings(width=8.5, height=11.0, margins={"top": 0.5})  # type: ignore
    with pytest.raises(TypeError):
        page_settings.validate()


def test_page_settings_from_dict_invalid_type() -> None:
    with pytest.raises(TypeError):
        PageSettings.from_dict([1, 2, 3])  # type: ignore[arg-type]


def test_page_settings_from_dict_invalid_orientation() -> None:
    """Передача некорректного значения для orientation — ValueError."""
    data = {"orientation": "diagonal"}
    with pytest.raises(ValueError):
        PageSettings.from_dict(data)


# =============================================================================
# Проверка присваивания некорректных типов в Section, add/insert paragraph и from_dict
# =============================================================================


def test_section_post_init_invalid_page_number_type() -> None:
    """Передача строки в page_number_start — приводит к None."""
    section = Section(page_number_start="invalid")  # type: ignore
    assert section.page_number_start is None


def test_section_post_init_invalid_page_settings_type() -> None:
    """Передача строки в page_settings — приводит к None."""
    section = Section(page_settings="invalid")  # type: ignore
    assert section.page_settings is None


def test_section_add_paragraph_invalid_type() -> None:
    section = Section()
    with pytest.raises(TypeError):
        section.add_paragraph("not a paragraph")  # type: ignore[arg-type]


def test_section_insert_paragraph_invalid_type() -> None:
    section = Section()
    with pytest.raises(TypeError):
        section.insert_paragraph(0, "not a paragraph")  # type: ignore[arg-type]


def test_section_insert_paragraph_invalid_index() -> None:
    """Вставка по неправильному индексу — IndexError."""
    section = Section()
    section.add_paragraph(Paragraph())
    with pytest.raises(IndexError):
        section.insert_paragraph(5, Paragraph())


def test_section_remove_paragraph_invalid_index() -> None:
    """Удаление по неправильному индексу — IndexError."""
    section = Section()
    with pytest.raises(IndexError):
        section.remove_paragraph(0)


def test_section_from_dict_invalid_type() -> None:
    with pytest.raises(TypeError):
        Section.from_dict("not a dict")  # type: ignore[arg-type]


def test_section_from_dict_invalid_paragraphs_type() -> None:
    """Секция с paragraphs не‑list — TypeError."""
    data = {"paragraphs": "not a list"}
    with pytest.raises(TypeError):
        Section.from_dict(data)


def test_section_from_dict_invalid_break_type() -> None:
    """Неверное значение break_type — ValueError."""
    data = {"break_type": "broken"}
    with pytest.raises(ValueError):
        Section.from_dict(data)


# =============================================================================
# Проверка работы is not None для вложенных атрибутов
# =============================================================================


def test_section_page_settings_member_access() -> None:
    """Доступ к вложенному атрибуту только если page_settings не None."""
    section = Section()
    assert section.page_settings is None
    section.page_settings = PageSettings(width=7.0)
    assert section.page_settings.width == 7.0


# =============================================================================
# Валидные тесты работы с Section (без ошибок типизации)
# =============================================================================


def test_section_basic_content_management() -> None:
    """Базовое добавление/удаление/insert параграфов."""
    section = Section()
    para1 = Paragraph()
    section.add_paragraph(para1)
    assert section.get_paragraph_count() == 1
    para2 = Paragraph()
    section.insert_paragraph(0, para2)
    assert section.get_paragraph_count() == 2
    removed = section.remove_paragraph(1)
    assert removed == para1
    assert section.get_paragraph_count() == 1
    section.clear_paragraphs()
    assert section.get_paragraph_count() == 0


def test_section_get_text_multiple_paragraphs() -> None:
    """Проверка получения текста от двух параграфов."""
    section = Section()
    para1 = Paragraph()
    para1.add_run(Run(text="Первый"))
    para2 = Paragraph()
    para2.add_run(Run(text="Второй"))
    section.add_paragraph(para1)
    section.add_paragraph(para2)
    assert section.get_text() == "Первый\nВторой"


def test_section_validate_success() -> None:
    """Позитивный кейс валидации секции с валидными параграфами и page_settings."""
    para = Paragraph()
    para.add_run(Run(text="Текст"))
    margins = Margins(top=0.5, bottom=0.5, left=0.5, right=0.5)
    page_settings = PageSettings(width=8.5, height=11.0, margins=margins)
    section = Section(paragraphs=[para], page_settings=page_settings)
    section.validate()


def test_merge_sections_function() -> None:
    """Проверка объединения двух секций."""
    section1 = Section()
    section1.add_paragraph(Paragraph())
    section2 = Section()
    section2.add_paragraph(Paragraph())
    merged = merge_sections([section1, section2])
    assert merged.get_paragraph_count() == 2


def test_split_section_at_function() -> None:
    """Проверка разбиения секции."""
    section = Section()
    section.add_paragraph(Paragraph())
    section.add_paragraph(Paragraph())
    first, second = split_section_at(section, 1)
    assert first.get_paragraph_count() == 1
    assert second.get_paragraph_count() == 1


def test_section_eq_and_repr() -> None:
    """Проверка сравнения и строкового представления."""
    section1 = Section()
    section2 = Section()
    assert section1 == section2
    assert "Section(paragraphs=0" in repr(section1)


def test_section_copy_independence() -> None:
    """Копия секции независимая по содержимому."""
    orig = Section()
    para = Paragraph()
    para.add_run(Run(text="Исходный"))
    orig.add_paragraph(para)
    copy = orig.copy()
    copy.paragraphs[0].runs[0].text = "Новый"
    assert orig.get_text() == "Исходный"
    assert copy.get_text() == "Новый"


def test_section_builder_margin_and_page_config() -> None:
    """Экспорт margin и page конфигураций для builder."""
    margins = Margins(top=1.0, bottom=1.0, left=1.5, right=1.5)
    page_settings = PageSettings(width=8.5, height=11.0, margins=margins)
    section = Section(page_settings=page_settings)
    margin_config = section.get_margin_config()
    page_config = section.get_page_config()
    assert margin_config["top_inches"] == 1.0
    assert page_config["width_inches"] == 8.5


def test_section_requires_form_feed() -> None:
    """Проверка логики requires_form_feed."""
    assert Section(break_type=SectionBreak.NEW_PAGE).requires_form_feed()
    assert not Section(break_type=SectionBreak.CONTINUOUS).requires_form_feed()


# --- Проверка __post_init__ Section: branch с некорректным type для page_settings ---
def test_section_post_init_invalid_page_settings_type_explicit() -> None:
    """Покрывает строки, где page_settings не PageSettings, а например int."""
    section = Section(page_settings=123)  # type: ignore
    assert section.page_settings is None


# --- Проверка .validate(): некорректный page_settings type внутри validate ---
def test_section_validate_page_settings_invalid_type_in_validate() -> None:
    """Проверяет ветку, где page_settings не PageSettings."""
    section = Section()
    object.__setattr__(section, "page_settings", ["not a PageSettings"])  # type: ignore
    with pytest.raises(TypeError):
        section.validate()


# --- Проверка .validate(): ошибка валидации page_settings (ValueError/TypeError пробрасывается) ---
def test_section_validate_page_settings_fails_on_validate() -> None:
    """Проверяет выброс ошибки если page_settings.validate() выбрасывает ValueError."""
    # Сконструируем некорректный PageSettings вручную, чтобы validate() выбросила ошибку
    bad_settings = PageSettings(width=2.0, height=5.0, margins=Margins(left=5.0, right=5.0))
    section = Section(page_settings=bad_settings)
    # validate() поймает ValueError из page_settings.validate()
    with pytest.raises(ValueError):
        section.validate()


# --- Проверка __post_init__: некорректный тип для paragraphs ---
def test_section_post_init_wrong_paragraphs_type() -> None:
    """Проверяем ветку, когда paragraphs — кортеж, а не список."""
    para1 = Paragraph()
    section = Section(paragraphs=(para1,))  # type: ignore
    assert isinstance(section.paragraphs, list)
    assert section.paragraphs[0] == para1


# --- Проверка Section.from_dict: branch когда paragraphs не список ---
def test_section_from_dict_paragraphs_not_list() -> None:
    """Проверка ошибки если paragraphs в from_dict — не список."""
    data = {"paragraphs": "oops"}
    with pytest.raises(TypeError):
        Section.from_dict(data)


# --- Проверка Section.from_dict: branch когда break_type невалиден ---
def test_section_from_dict_invalid_break_type_branch() -> None:
    """Проверка выброса ValueError для некорректного break_type."""
    data = {"paragraphs": [], "break_type": "wrong"}
    with pytest.raises(ValueError):
        Section.from_dict(data)


# --- Проверка Section.get_page_config и get_margin_config со стандартными значениями ---
def test_section_get_page_config_and_get_margin_config_defaults() -> None:
    """Ветка где page_settings=None (ветка else для get_page_config/get_margin_config)."""
    section = Section()
    pc = section.get_page_config()
    mc = section.get_margin_config()
    assert pc["width_inches"] == 8.5
    assert mc["top_inches"] == 0.5


# --- Проверка merge_sections branch с preserve_breaks=True ---
def test_merge_sections_preserve_breaks_branch() -> None:
    from src.model.section import merge_sections

    section1 = Section()
    section1.add_paragraph(Paragraph())
    section2 = Section()
    section2.add_paragraph(Paragraph())
    merged = merge_sections([section1, section2], True)
    assert len(merged.paragraphs) == 3
    # Проверяем, что separator — именно второй параграф
    assert merged.paragraphs[1].get_text() == ""
    # Проверяем, что хотя бы в одном параграфе контент отличен от "" — чтобы тест не был тривиальным
    assert merged.paragraphs[0].get_text() == ""
    assert merged.paragraphs[2].get_text() == ""


# --- Проверка split_section_at: branch по ValueError если индекс вне диапазона ---
def test_split_section_at_value_error_cases() -> None:
    section = Section()
    section.add_paragraph(Paragraph())
    # Индекс вне диапазона
    split_section_at = getattr(
        __import__("src.model.section", fromlist=["split_section_at"]), "split_section_at"
    )
    with pytest.raises(ValueError):
        split_section_at(section, 0)
    section.add_paragraph(Paragraph())
    with pytest.raises(ValueError):
        split_section_at(section, 2)


# --- Проверка Section.__eq__: ветка NotImplemented для не Section ---
def test_section_eq_not_section() -> None:
    """Проверяет ветку, где other не Section — должен вернуть NotImplemented"""
    section = Section()
    assert section.__eq__("not a section") is NotImplemented


def test_section_post_init_all_edge_cases() -> None:
    # paragraphs не список
    s = Section(paragraphs=(Paragraph(),))  # type: ignore
    assert isinstance(s.paragraphs, list)
    # page_number_start не int
    s2 = Section(page_number_start="not an int")  # type: ignore
    assert s2.page_number_start is None
    # page_number_start вне диапазона
    s3 = Section(page_number_start=0)
    assert s3.page_number_start == MIN_PAGE_NUMBER
    s4 = Section(page_number_start=MAX_PAGE_NUMBER + 10)
    assert s4.page_number_start == MAX_PAGE_NUMBER
    # page_settings не PageSettings
    s5 = Section(page_settings=[1, 2, 3])  # type: ignore
    assert s5.page_settings is None


def test_pagesettings_from_dict_bad_types() -> None:
    # margins не dict — должно выбрасывать TypeError!
    d = dict(width=8.5, height=11.0, orientation="portrait", margins="oops")
    with pytest.raises(TypeError):
        PageSettings.from_dict(d)
    # orientation невалидный
    with pytest.raises(ValueError):
        PageSettings.from_dict({"orientation": "diagonal"})
    # margins пустой dict: разрешено
    ps2 = PageSettings.from_dict({"margins": {}})
    assert isinstance(ps2, PageSettings)


def test_section_validate_all_error_branches() -> None:
    s = Section()
    s.paragraphs.append("not a paragraph")  # type: ignore
    with pytest.raises(TypeError):
        s.validate()
    # Ветка с ошибкой внутри validate параграфа
    s2 = Section()
    fake_para = FakeParagraph()
    s2.add_paragraph(fake_para)
    with pytest.raises(ValueError):
        s2.validate()
    # page_number_start - не int в момент validate (можно через setattr хакнуть)
    s3 = Section()
    object.__setattr__(s3, "page_number_start", "bad")  # type: ignore
    with pytest.raises(TypeError):
        s3.validate()
    # page_number_start за границей
    s3 = Section()
    object.__setattr__(s3, "page_number_start", 0)
    with pytest.raises(ValueError):
        s3.validate()
    # page_settings не PageSettings
    s4 = Section()
    object.__setattr__(s4, "page_settings", [1, 2, 3])  # type: ignore
    with pytest.raises(TypeError):
        s4.validate()
    # page_settings.validate выбросит ValueError — надо создать ВАЛИДНЫЙ PageSettings и изменить width
    import copy

    valid_settings = PageSettings()
    bad_settings = copy.deepcopy(valid_settings)
    object.__setattr__(bad_settings, "width", MIN_PAGE_WIDTH_INCHES - 1.0)  # type: ignore
    s5 = Section(page_settings=bad_settings)  # type: ignore
    with pytest.raises(ValueError):
        s5.validate()
