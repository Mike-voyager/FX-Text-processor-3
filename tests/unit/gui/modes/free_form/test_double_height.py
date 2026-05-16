"""Тесты для double-height row индикаторов в FreeForm режиме.

Модуль содержит тесты для визуальных индикаторов строк
с символами двойной высоты (CharSize.DOUBLE_HEIGHT).

Coverage target: >=90%
"""

import tkinter as tk
from typing import Generator, Set
from unittest.mock import MagicMock

import pytest

from src.gui.modes.free_form.renderer import (
    DOUBLE_HEIGHT_MARKER,
    DOUBLE_HEIGHT_TAG,
    ROW_MARKER_TAG,
    SHADOW_ROW_BG_COLOR,
    FreeFormModeRenderer,
)
from src.gui.renderers.free_form_renderer import FreeFormDocument, FormatRange
from src.gui.core.exceptions import LifecycleError


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Fixture для Tk root окна."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def free_form_renderer(tk_root: tk.Tk) -> Generator[FreeFormModeRenderer, None, None]:
    """Fixture для FreeFormModeRenderer."""
    renderer = FreeFormModeRenderer(widget_id="test_ff_renderer")
    renderer.mount(tk_root)
    yield renderer
    renderer.unmount()


# Deferred import to avoid circular import
@pytest.fixture
def navigator(tk_root: tk.Tk) -> Generator:
    """Fixture для Navigator."""
    from src.gui.components.navigator import Navigator
    nav = Navigator(
        widget_id="test_navigator",
        initial_line=1,
        initial_column=1,
        initial_total_lines=100,
    )
    nav.mount(tk_root)
    yield nav


# =============================================================================
# TEST: FreeFormModeRenderer Double-Height Initialization
# =============================================================================


class TestDoubleHeightInitialization:
    """Тесты инициализации double-height функциональности."""

    def test_renderer_initialization(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Рендерер инициализируется с пустыми множествами."""
        assert free_form_renderer.get_double_height_rows() == set()
        assert free_form_renderer.get_shadow_row_lines() == set()

    def test_constants_defined(self) -> None:
        """Константы определены корректно."""
        assert DOUBLE_HEIGHT_TAG == "double_height_row"
        assert ROW_MARKER_TAG == "double_height_marker"
        assert SHADOW_ROW_BG_COLOR == "#e8e8e8"
        assert DOUBLE_HEIGHT_MARKER == "📏"

    def test_row_style_tags_configured(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Теги стилей настроены при монтировании."""
        text_widget = free_form_renderer.get_text_widget()
        assert text_widget is not None

        # Проверяем что теги существуют
        tags = text_widget.tag_names()
        assert DOUBLE_HEIGHT_TAG in tags
        assert "shadow_row" in tags
        assert ROW_MARKER_TAG in tags

    def test_unmount_clears_references(self, tk_root: tk.Tk) -> None:
        """Unmount очищает ссылки на текстовый виджет."""
        renderer = FreeFormModeRenderer(widget_id="test_unmount")
        renderer.mount(tk_root)
        renderer.unmount()

        # После unmount текстовый виджет недоступен
        assert renderer._base_renderer._tk_text is None

    def test_get_text_widget_returns_none_when_unmounted(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """get_text_widget() возвращает None когда демонтирован."""
        # Сначала смонтирован
        text_widget = free_form_renderer.get_text_widget()
        assert text_widget is not None

        # Тестируем что _base_renderer._tk_text может быть None
        # (тестируем защиту от None)
        free_form_renderer._base_renderer._tk_text = None
        assert free_form_renderer.get_text_widget() is None

        # Восстанавливаем для cleanup
        free_form_renderer._base_renderer._tk_text = text_widget

    def test_get_text_widget_returns_widget_when_mounted(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """get_text_widget() возвращает виджет когда смонтирован."""
        widget = free_form_renderer.get_text_widget()
        assert widget is not None
        assert isinstance(widget, tk.Text)


# =============================================================================
# TEST: Double-Height Row Styling
# =============================================================================


class TestDoubleHeightRowStyling:
    """Тесты стилизации строк с double-height."""

    def test_apply_row_styles_single_line(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Применение стиля к одной строке."""
        text_widget = free_form_renderer.get_text_widget()
        assert text_widget is not None

        # Добавляем текст
        text_widget.insert("1.0", "Line 1\nLine 2\nLine 3")

        # Применяем стили для строки 1
        free_form_renderer._apply_row_styles({1})

        # Проверяем что строка 1 имеет тег double_height_row
        assert DOUBLE_HEIGHT_TAG in text_widget.tag_names("1.0")

        # Проверяем что строка 2 (shadow row) имеет соответствующий тег
        assert "shadow_row" in text_widget.tag_names("2.0")

    def test_apply_row_styles_multiple_lines(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Применение стилей к нескольким строкам."""
        text_widget = free_form_renderer.get_text_widget()
        assert text_widget is not None

        text_widget.insert("1.0", "Line 1\nLine 2\nLine 3\nLine 4\nLine 5")

        # Применяем стили для строк 1 и 3
        free_form_renderer._apply_row_styles({1, 3})

        # Проверяем строку 1 и её shadow row (строка 2)
        assert DOUBLE_HEIGHT_TAG in text_widget.tag_names("1.0")
        assert "shadow_row" in text_widget.tag_names("2.0")

        # Проверяем строку 3 и её shadow row (строка 4)
        assert DOUBLE_HEIGHT_TAG in text_widget.tag_names("3.0")
        assert "shadow_row" in text_widget.tag_names("4.0")

    def test_clear_row_styles(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Очистка стилей строк."""
        text_widget = free_form_renderer.get_text_widget()
        assert text_widget is not None

        text_widget.insert("1.0", "Line 1\nLine 2\nLine 3")

        # Применяем стили
        free_form_renderer._apply_row_styles({1})
        assert DOUBLE_HEIGHT_TAG in text_widget.tag_names("1.0")

        # Очищаем стили
        free_form_renderer._clear_row_styles()

        # Проверяем что теги удалены
        assert DOUBLE_HEIGHT_TAG not in text_widget.tag_names("1.0")
        assert "shadow_row" not in text_widget.tag_names("2.0")

    def test_get_double_height_rows(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Получение множества double-height строк."""
        free_form_renderer._apply_row_styles({1, 3, 5})

        rows = free_form_renderer.get_double_height_rows()
        assert rows == {1, 3, 5}

    def test_get_shadow_row_lines(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Получение множества shadow row строк."""
        text_widget = free_form_renderer.get_text_widget()
        assert text_widget is not None

        text_widget.insert("1.0", "Line 1\nLine 2\nLine 3\nLine 4")

        free_form_renderer._apply_row_styles({1, 3})

        shadow_rows = free_form_renderer.get_shadow_row_lines()
        assert shadow_rows == {2, 4}

    def test_is_line_double_height(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Проверка является ли строка double-height."""
        free_form_renderer._apply_row_styles({2, 4})

        assert free_form_renderer.is_line_double_height(2) is True
        assert free_form_renderer.is_line_double_height(4) is True
        assert free_form_renderer.is_line_double_height(1) is False
        assert free_form_renderer.is_line_double_height(3) is False

    def test_shadow_row_nonexistent_line(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Shadow row не создаётся для несуществующей строки."""
        text_widget = free_form_renderer.get_text_widget()
        assert text_widget is not None

        text_widget.insert("1.0", "Line 1")  # Только одна строка

        # Применяем стиль к строке 1 - shadow row 2 не будет создана
        free_form_renderer._apply_row_styles({1})

        # Проверяем что double-height применён
        assert DOUBLE_HEIGHT_TAG in text_widget.tag_names("1.0")

    def test_apply_row_styles_updates_tracking(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Применение стилей обновляет внутреннее отслеживание."""
        free_form_renderer._apply_row_styles({1, 2})
        assert free_form_renderer.get_double_height_rows() == {1, 2}

        # Применяем новый набор - старый должен быть заменён
        free_form_renderer._apply_row_styles({3})
        assert free_form_renderer.get_double_height_rows() == {3}

    def test_clear_row_styles_with_none_text_widget(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Очистка стилей когда text_widget is None не вызывает ошибок."""
        # Сохраняем ссылку
        text_widget = free_form_renderer._base_renderer._tk_text

        # Устанавливаем None
        free_form_renderer._base_renderer._tk_text = None

        # Не должно вызывать исключений
        free_form_renderer._clear_row_styles()

        # Восстанавливаем
        free_form_renderer._base_renderer._tk_text = text_widget

    def test_apply_row_styles_with_none_text_widget(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Применение стилей когда text_widget is None не вызывает ошибок."""
        # Сохраняем ссылку
        text_widget = free_form_renderer._base_renderer._tk_text

        # Устанавливаем None
        free_form_renderer._base_renderer._tk_text = None

        # Не должно вызывать исключений
        free_form_renderer._apply_row_styles({1, 2, 3})

        # Восстанавливаем
        free_form_renderer._base_renderer._tk_text = text_widget

    def test_get_shadow_row_lines_returns_copy(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """get_shadow_row_lines() возвращает копию множества."""
        text_widget = free_form_renderer.get_text_widget()
        assert text_widget is not None

        text_widget.insert("1.0", "Line 1\nLine 2")
        free_form_renderer._apply_row_styles({1})

        rows1 = free_form_renderer.get_shadow_row_lines()
        rows2 = free_form_renderer.get_shadow_row_lines()

        # Должны быть разные объекты
        assert rows1 is not rows2
        # Но с одинаковым содержимым
        assert rows1 == rows2


# =============================================================================
# TEST: Set Line Double-Height
# =============================================================================


class TestSetLineDoubleHeight:
    """Тесты установки double-height для строк."""

    def test_set_line_double_height_true(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Установка double-height для строки."""
        text_widget = free_form_renderer.get_text_widget()
        assert text_widget is not None

        text_widget.insert("1.0", "Line 1\nLine 2")

        free_form_renderer.set_line_double_height(1, True)

        assert DOUBLE_HEIGHT_TAG in text_widget.tag_names("1.0")
        assert "shadow_row" in text_widget.tag_names("2.0")
        assert free_form_renderer.is_line_double_height(1)

    def test_set_line_double_height_false(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Снятие double-height со строки."""
        text_widget = free_form_renderer.get_text_widget()
        assert text_widget is not None

        text_widget.insert("1.0", "Line 1\nLine 2")

        # Устанавливаем и снимаем
        free_form_renderer.set_line_double_height(1, True)
        free_form_renderer.set_line_double_height(1, False)

        assert not free_form_renderer.is_line_double_height(1)
        # Shadow row должен быть удалён при переприменении
        assert "shadow_row" not in text_widget.tag_names("2.0")

    def test_set_line_double_height_invalid_line_raises(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Установка для невалидной строки вызывает ValueError."""
        with pytest.raises(ValueError, match="Номер строки должен быть >= 1"):
            free_form_renderer.set_line_double_height(0, True)

    def test_set_line_double_height_unmounted_raises(self) -> None:
        """Установка для несмонтированного рендерера вызывает LifecycleError."""
        renderer = FreeFormModeRenderer(widget_id="unmounted_renderer")

        with pytest.raises(LifecycleError, match="Widget not mounted"):
            renderer.set_line_double_height(1, True)


# =============================================================================
# TEST: Clear Double-Height Rows
# =============================================================================


class TestClearDoubleHeightRows:
    """Тесты очистки всех double-height строк."""

    def test_clear_double_height_rows(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Очистка всех double-height строк."""
        free_form_renderer._apply_row_styles({1, 3, 5})
        assert len(free_form_renderer.get_double_height_rows()) == 3

        free_form_renderer.clear_double_height_rows()

        assert free_form_renderer.get_double_height_rows() == set()
        assert free_form_renderer.get_shadow_row_lines() == set()


# =============================================================================
# TEST: Callback Row Style Change
# =============================================================================


class TestRowStyleChangeCallback:
    """Тесты callback при изменении стиля строки."""

    def test_callback_called_on_apply(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Callback вызывается при применении стилей."""
        callback_called = False
        received_line = 0
        received_is_double = False

        def on_row_style_change(line: int, is_double: bool) -> None:
            nonlocal callback_called, received_line, received_is_double
            callback_called = True
            received_line = line
            received_is_double = is_double

        free_form_renderer.set_on_row_style_change_callback(on_row_style_change)

        # Устанавливаем позицию курсора
        text_widget = free_form_renderer.get_text_widget()
        assert text_widget is not None
        text_widget.insert("1.0", "Line 1\nLine 2")

        # Применяем стили - callback должен быть вызван
        free_form_renderer._apply_row_styles({1})

        assert callback_called is True

    def test_callback_setter(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Установка callback через setter."""
        callback = MagicMock()
        free_form_renderer.set_on_row_style_change_callback(callback)

        # callback сохранён
        assert free_form_renderer._on_row_style_change_callback == callback

    def test_callback_none(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Установка None callback."""
        free_form_renderer.set_on_row_style_change_callback(None)
        assert free_form_renderer._on_row_style_change_callback is None


# =============================================================================
# TEST: Navigator Double-Height Indicator
# =============================================================================


class TestNavigatorDoubleHeightIndicator:
    """Тесты индикатора double-height в Navigator."""

    @pytest.fixture(autouse=True)
    def setup_navigator(self, navigator) -> None:
        """Setup Navigator instance for each test."""
        self.navigator = navigator

    def test_indicator_initially_hidden(self) -> None:
        """Индикатор скрыт по умолчанию."""
        from src.gui.components.navigator import Navigator
        assert isinstance(self.navigator, Navigator)
        assert self.navigator.is_double_height_indicator_active() is False

    def test_set_double_height_indicator_true(self) -> None:
        """Показ индикатора double-height."""
        from src.gui.components.navigator import (
            DOUBLE_HEIGHT_INDICATOR_BG,
            DOUBLE_HEIGHT_INDICATOR_FG,
        )
        self.navigator.set_double_height_indicator(True)

        assert self.navigator.is_double_height_indicator_active() is True
        assert self.navigator._double_height_indicator is not None
        assert self.navigator._double_height_indicator.cget("bg") == DOUBLE_HEIGHT_INDICATOR_BG
        assert self.navigator._double_height_indicator.cget("fg") == DOUBLE_HEIGHT_INDICATOR_FG

    def test_set_double_height_indicator_false(self) -> None:
        """Скрытие индикатора double-height."""
        from src.gui.components.navigator import NAVIGATOR_BG_COLOR
        # Сначала показываем
        self.navigator.set_double_height_indicator(True)
        # Затем скрываем
        self.navigator.set_double_height_indicator(False)

        assert self.navigator.is_double_height_indicator_active() is False
        assert self.navigator._double_height_indicator is not None
        assert self.navigator._double_height_indicator.cget("bg") == NAVIGATOR_BG_COLOR
        assert self.navigator._double_height_indicator.cget("fg") == NAVIGATOR_BG_COLOR

    def test_indicator_state_preserved(self) -> None:
        """Состояние индикатора сохраняется."""
        self.navigator.set_double_height_indicator(True)
        assert self.navigator._is_current_line_double_height is True

        self.navigator.set_double_height_indicator(False)
        assert self.navigator._is_current_line_double_height is False


# =============================================================================
# TEST: Document Integration
# =============================================================================


class TestDocumentIntegration:
    """Тесты интеграции с документом."""

    def test_update_row_styles_from_document(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Обновление стилей из документа."""
        text_widget = free_form_renderer.get_text_widget()
        assert text_widget is not None

        # Создаём документ с форматированием double_height
        doc = FreeFormDocument(
            content="Line 1\nLine 2",
            cpi=10,
            formatting=[
                FormatRange("1.0", "1.5", "double_height"),
            ],
        )

        free_form_renderer.update_row_styles_from_document(doc)

        # Строка 1 должна иметь double-height тег
        assert free_form_renderer.is_line_double_height(1)

    def test_update_row_styles_multiple_ranges(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Обновление стилей из документа с несколькими ranges."""
        doc = FreeFormDocument(
            content="Line 1\nLine 2\nLine 3",
            cpi=10,
            formatting=[
                FormatRange("1.0", "1.5", "double_height"),
                FormatRange("3.0", "3.5", "double_wh"),
            ],
        )

        free_form_renderer.update_row_styles_from_document(doc)

        assert free_form_renderer.is_line_double_height(1)
        assert free_form_renderer.is_line_double_height(3)
        assert not free_form_renderer.is_line_double_height(2)

    def test_update_row_styles_invalid_range(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Невалидный range не вызывает ошибок."""
        # Создаём документ с невалидным форматированием (без атрибутов start/end)
        doc = FreeFormDocument(content="Line 1\nLine 2", cpi=10, formatting=[])

        # Не должно вызывать исключений
        free_form_renderer.update_row_styles_from_document(doc)
        assert free_form_renderer.get_double_height_rows() == set()

    def test_update_row_styles_no_double_height_tags(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Другие теги не влияют на double-height."""
        doc = FreeFormDocument(
            content="Line 1\nLine 2",
            cpi=10,
            formatting=[
                FormatRange("1.0", "1.5", "bold"),  # Не double-height
                FormatRange("2.0", "2.5", "italic"),  # Не double-height
            ],
        )

        free_form_renderer.update_row_styles_from_document(doc)

        # Ни одна строка не должна быть double-height
        assert free_form_renderer.get_double_height_rows() == set()


# =============================================================================
# TEST: Shadow Row Effect
# =============================================================================


class TestShadowRowEffect:
    """Тесты shadow row эффекта."""

    def test_shadow_row_background_color(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Shadow row имеет правильный цвет фона."""
        text_widget = free_form_renderer.get_text_widget()
        assert text_widget is not None

        text_widget.insert("1.0", "Line 1\nLine 2")
        free_form_renderer._apply_row_styles({1})

        # Проверяем конфигурацию тега shadow_row
        bg_color = text_widget.tag_cget("shadow_row", "background")
        assert bg_color == SHADOW_ROW_BG_COLOR

    def test_shadow_row_only_for_next_line(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Shadow row создаётся только для следующей строки."""
        text_widget = free_form_renderer.get_text_widget()
        assert text_widget is not None

        text_widget.insert("1.0", "Line 1\nLine 2\nLine 3")
        free_form_renderer._apply_row_styles({1})

        # Только строка 2 (следующая за 1) должна иметь shadow_row
        assert "shadow_row" in text_widget.tag_names("2.0")
        assert "shadow_row" not in text_widget.tag_names("3.0")


# =============================================================================
# TEST: Edge Cases
# =============================================================================


class TestEdgeCases:
    """Тесты граничных случаев."""

    def test_empty_double_height_rows(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Пустое множество double-height строк."""
        text_widget = free_form_renderer.get_text_widget()
        assert text_widget is not None

        text_widget.insert("1.0", "Line 1\nLine 2")
        free_form_renderer._apply_row_styles(set())

        assert free_form_renderer.get_double_height_rows() == set()
        assert "shadow_row" not in text_widget.tag_names("1.0")

    def test_large_line_number(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Большой номер строки."""
        text_widget = free_form_renderer.get_text_widget()
        assert text_widget is not None

        # Добавляем много строк
        content = "\n".join([f"Line {i}" for i in range(1, 101)])
        text_widget.insert("1.0", content)

        free_form_renderer._apply_row_styles({50, 100})

        assert free_form_renderer.is_line_double_height(50)
        assert free_form_renderer.is_line_double_height(100)

    def test_consecutive_double_height_rows(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """Подряд идущие double-height строки."""
        text_widget = free_form_renderer.get_text_widget()
        assert text_widget is not None

        text_widget.insert("1.0", "L1\nL2\nL3\nL4\nL5")

        free_form_renderer._apply_row_styles({1, 2})

        # Строка 1 - double_height, строка 2 - и double_height и shadow от 1
        assert DOUBLE_HEIGHT_TAG in text_widget.tag_names("1.0")
        assert DOUBLE_HEIGHT_TAG in text_widget.tag_names("2.0")
        assert "shadow_row" in text_widget.tag_names("2.0")  # shadow от строки 1
        assert "shadow_row" in text_widget.tag_names("3.0")  # shadow от строки 2

    def test_get_double_height_rows_returns_copy(self, free_form_renderer: FreeFormModeRenderer) -> None:
        """get_double_height_rows() возвращает копию множества."""
        free_form_renderer._apply_row_styles({1, 2})

        rows1 = free_form_renderer.get_double_height_rows()
        rows2 = free_form_renderer.get_double_height_rows()

        # Должны быть разные объекты
        assert rows1 is not rows2
        # Но с одинаковым содержимым
        assert rows1 == rows2


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__ = [
    "TestDoubleHeightInitialization",
    "TestDoubleHeightRowStyling",
    "TestSetLineDoubleHeight",
    "TestClearDoubleHeightRows",
    "TestRowStyleChangeCallback",
    "TestNavigatorDoubleHeightIndicator",
    "TestDocumentIntegration",
    "TestShadowRowEffect",
    "TestEdgeCases",
]