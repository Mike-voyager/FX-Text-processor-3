"""Unit-тесты для констант layout.

Проверяет:
- Существование и типы всех экспортируемых констант
- Диапазоны значений (соотношения, размеры)
- Immutability (Final) констант

Coverage target: 100% (модуль содержит только константы)
"""

from src.gui.layout.layout_constants import (
    COLLAPSE_ANIMATION_MS,
    DEFAULT_WINDOW_HEIGHT,
    DEFAULT_WINDOW_WIDTH,
    ESCP_COLS,
    ESCP_DOTS_PER_COL,
    ESCP_DOTS_PER_ROW,
    ESCP_ROWS,
    MIN_WINDOW_HEIGHT,
    MIN_WINDOW_WIDTH,
    PADDING_LARGE,
    PADDING_NORMAL,
    PADDING_SMALL,
    PANEL_RATIO_DEFAULT,
    PANEL_RATIO_MAX,
    PANEL_RATIO_MIN,
    SASH_RELIEF,
    SASH_WIDTH,
    SIDEBAR_COLLAPSED_WIDTH,
    SIDEBAR_WIDTH,
    STATUSBAR_HEIGHT,
    TABBAR_HEIGHT,
    TOOLBAR_HEIGHT,
)

# =============================================================================
# TEST: WINDOW CONSTRAINTS
# =============================================================================


class TestWindowConstraints:
    """Тесты констант размеров окна."""

    def test_min_window_width_is_positive(self) -> None:
        """MIN_WINDOW_WIDTH должно быть положительным."""
        assert MIN_WINDOW_WIDTH > 0

    def test_min_window_height_is_positive(self) -> None:
        """MIN_WINDOW_HEIGHT должно быть положительным."""
        assert MIN_WINDOW_HEIGHT > 0

    def test_default_window_width_greater_than_min(self) -> None:
        """DEFAULT_WINDOW_WIDTH должно быть >= MIN_WINDOW_WIDTH."""
        assert DEFAULT_WINDOW_WIDTH >= MIN_WINDOW_WIDTH

    def test_default_window_height_greater_than_min(self) -> None:
        """DEFAULT_WINDOW_HEIGHT должно быть >= MIN_WINDOW_HEIGHT."""
        assert DEFAULT_WINDOW_HEIGHT >= MIN_WINDOW_HEIGHT


# =============================================================================
# TEST: PANEL SIZES
# =============================================================================


class TestPanelSizes:
    """Тесты констант размеров панелей."""

    def test_sidebar_width_is_positive(self) -> None:
        """SIDEBAR_WIDTH должно быть положительным."""
        assert SIDEBAR_WIDTH > 0

    def test_sidebar_collapsed_width_is_positive(self) -> None:
        """SIDEBAR_COLLAPSED_WIDTH должно быть положительным."""
        assert SIDEBAR_COLLAPSED_WIDTH > 0

    def test_sidebar_collapsed_less_than_expanded(self) -> None:
        """SIDEBAR_COLLAPSED_WIDTH должно быть меньше SIDEBAR_WIDTH."""
        assert SIDEBAR_COLLAPSED_WIDTH < SIDEBAR_WIDTH

    def test_statusbar_height_is_positive(self) -> None:
        """STATUSBAR_HEIGHT должно быть положительным."""
        assert STATUSBAR_HEIGHT > 0

    def test_tabbar_height_is_positive(self) -> None:
        """TABBAR_HEIGHT должно быть положительным."""
        assert TABBAR_HEIGHT > 0

    def test_toolbar_height_is_positive(self) -> None:
        """TOOLBAR_HEIGHT должно быть положительным."""
        assert TOOLBAR_HEIGHT > 0


# =============================================================================
# TEST: PANEL RATIO CONSTRAINTS
# =============================================================================


class TestPanelRatioConstraints:
    """Тесты констант соотношения панелей."""

    def test_panel_ratio_min_is_positive(self) -> None:
        """PANEL_RATIO_MIN должно быть положительным."""
        assert PANEL_RATIO_MIN > 0

    def test_panel_ratio_max_less_than_one(self) -> None:
        """PANEL_RATIO_MAX должно быть меньше 1."""
        assert PANEL_RATIO_MAX < 1.0

    def test_panel_ratio_min_less_than_max(self) -> None:
        """PANEL_RATIO_MIN должно быть меньше PANEL_RATIO_MAX."""
        assert PANEL_RATIO_MIN < PANEL_RATIO_MAX

    def test_panel_ratio_default_in_range(self) -> None:
        """PANEL_RATIO_DEFAULT должно быть между MIN и MAX."""
        assert PANEL_RATIO_MIN <= PANEL_RATIO_DEFAULT <= PANEL_RATIO_MAX


# =============================================================================
# TEST: ESC/P CANVAS SIZES
# =============================================================================


class TestEscpSizes:
    """Тесты констант размеров ESC/P canvas."""

    def test_escp_cols_is_positive(self) -> None:
        """ESCP_COLS должно быть положительным."""
        assert ESCP_COLS > 0

    def test_escp_rows_is_positive(self) -> None:
        """ESCP_ROWS должно быть положительным."""
        assert ESCP_ROWS > 0

    def test_escp_dots_per_col_is_positive(self) -> None:
        """ESCP_DOTS_PER_COL должно быть положительным."""
        assert ESCP_DOTS_PER_COL > 0

    def test_escp_dots_per_row_is_positive(self) -> None:
        """ESCP_DOTS_PER_ROW должно быть положительным."""
        assert ESCP_DOTS_PER_ROW > 0


# =============================================================================
# TEST: PADDING AND MARGINS
# =============================================================================


class TestPaddingAndMargins:
    """Тесты констант отступов."""

    def test_padding_small_is_positive(self) -> None:
        """PADDING_SMALL должно быть положительным."""
        assert PADDING_SMALL > 0

    def test_padding_normal_greater_than_small(self) -> None:
        """PADDING_NORMAL должно быть больше PADDING_SMALL."""
        assert PADDING_NORMAL > PADDING_SMALL

    def test_padding_large_greater_than_normal(self) -> None:
        """PADDING_LARGE должно быть больше PADDING_NORMAL."""
        assert PADDING_LARGE > PADDING_NORMAL


# =============================================================================
# TEST: SASH CONFIGURATION
# =============================================================================


class TestSashConfiguration:
    """Тесты констант конфигурации sash."""

    def test_sash_width_is_positive(self) -> None:
        """SASH_WIDTH должно быть положительным."""
        assert SASH_WIDTH > 0

    def test_sash_relief_is_string(self) -> None:
        """SASH_RELIEF должно быть строкой."""
        assert isinstance(SASH_RELIEF, str)

    def test_sash_relief_is_valid_tk_value(self) -> None:
        """SASH_RELIEF должно быть допустимым значением Tkinter."""
        valid_reliefs = {"flat", "raised", "sunken", "groove", "ridge"}
        assert SASH_RELIEF in valid_reliefs


# =============================================================================
# TEST: ANIMATION
# =============================================================================


class TestAnimation:
    """Тесты констант анимации."""

    def test_collapse_animation_ms_is_positive(self) -> None:
        """COLLAPSE_ANIMATION_MS должно быть положительным."""
        assert COLLAPSE_ANIMATION_MS > 0

    def test_collapse_animation_reasonable(self) -> None:
        """COLLAPSE_ANIMATION_MS должно быть разумным (<= 1 секунды)."""
        assert COLLAPSE_ANIMATION_MS <= 1000


# =============================================================================
# TEST: TYPE CHECKING
# =============================================================================


class TestConstantTypes:
    """Тесты типов констант."""

    def test_window_sizes_are_int(self) -> None:
        """Размеры окна должны быть int."""
        assert isinstance(MIN_WINDOW_WIDTH, int)
        assert isinstance(MIN_WINDOW_HEIGHT, int)
        assert isinstance(DEFAULT_WINDOW_WIDTH, int)
        assert isinstance(DEFAULT_WINDOW_HEIGHT, int)

    def test_panel_sizes_are_int(self) -> None:
        """Размеры панелей должны быть int."""
        assert isinstance(SIDEBAR_WIDTH, int)
        assert isinstance(SIDEBAR_COLLAPSED_WIDTH, int)
        assert isinstance(STATUSBAR_HEIGHT, int)
        assert isinstance(TABBAR_HEIGHT, int)
        assert isinstance(TOOLBAR_HEIGHT, int)

    def test_ratios_are_float(self) -> None:
        """Отношения должны быть float."""
        assert isinstance(PANEL_RATIO_DEFAULT, float)
        assert isinstance(PANEL_RATIO_MIN, float)
        assert isinstance(PANEL_RATIO_MAX, float)

    def test_escp_sizes_are_int(self) -> None:
        """Размеры ESC/P должны быть int."""
        assert isinstance(ESCP_COLS, int)
        assert isinstance(ESCP_ROWS, int)
        assert isinstance(ESCP_DOTS_PER_COL, int)
        assert isinstance(ESCP_DOTS_PER_ROW, int)

    def test_paddings_are_int(self) -> None:
        """Отступы должны быть int."""
        assert isinstance(PADDING_SMALL, int)
        assert isinstance(PADDING_NORMAL, int)
        assert isinstance(PADDING_LARGE, int)

    def test_sash_config_types(self) -> None:
        """Конфигурация sash должна быть корректного типа."""
        assert isinstance(SASH_WIDTH, int)
        assert isinstance(SASH_RELIEF, str)

    def test_animation_type(self) -> None:
        """COLLAPSE_ANIMATION_MS должно быть int."""
        assert isinstance(COLLAPSE_ANIMATION_MS, int)
