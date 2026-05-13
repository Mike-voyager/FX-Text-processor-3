"""Тесты для режима FreeForm.

Модуль содержит тесты для режима свободного редактирования,
позволяющего размещать текстовые блоки в произвольных позициях.
"""

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock

import pytest

from src.gui.core.exceptions import LifecycleError
from src.gui.modes.free_form.renderer import FreeFormModeRenderer
from src.gui.modes.free_form.toolbar import FreeFormToolbar
from src.gui.renderers.free_form_renderer import FreeFormDocument
from src.model.enums import FontFamily


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Fixture для Tk root окна."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


class TestFreeFormModeRenderer:
    """Тесты для рендерера режима FreeForm."""

    def test_renderer_initialization(self) -> None:
        """Тест инициализации рендерера."""
        renderer = FreeFormModeRenderer(widget_id="ff_renderer")
        assert renderer.widget_id == "ff_renderer"
        assert not renderer.is_mounted()
        assert renderer.get_cpi() == 10
        assert renderer.is_grid_snap_enabled()

    def test_text_block_positioning(self, tk_root: tk.Tk) -> None:
        """Тест позиционирования текстового блока."""
        renderer = FreeFormModeRenderer(widget_id="ff_renderer")
        renderer.mount(tk_root)
        try:
            renderer.set_content("Hello World")
            renderer.set_cursor_position(1, 6)
            pos = renderer.get_cursor_position()
            assert pos == (1, 6)
        finally:
            renderer.unmount()

    def test_multiple_blocks_rendering(self, tk_root: tk.Tk) -> None:
        """Тест отрисовки нескольких блоков."""
        renderer = FreeFormModeRenderer(widget_id="ff_renderer")
        renderer.mount(tk_root)
        try:
            doc = FreeFormDocument(content="Line1\nLine2\nLine3", cpi=12)
            renderer.render(doc)
            assert renderer.get_content() == "Line1\nLine2\nLine3"
            assert renderer.get_cpi() == 12
        finally:
            renderer.unmount()

    def test_block_selection_highlight(self, tk_root: tk.Tk) -> None:
        """Тест подсветки выбранного блока."""
        renderer = FreeFormModeRenderer(widget_id="ff_renderer")
        renderer.mount(tk_root)
        try:
            renderer.set_content("Hello World")
            renderer.apply_format("bold", "1.0", "1.5")
            formatting = renderer.get_formatting()
            assert any(f.tag == "bold" for f in formatting)
            renderer.remove_format("bold", "1.0", "1.5")
            formatting = renderer.get_formatting()
            assert not any(f.tag == "bold" for f in formatting)
        finally:
            renderer.unmount()

    def test_apply_cpi_valid(self, tk_root: tk.Tk) -> None:
        """apply_cpi с валидным значением."""
        renderer = FreeFormModeRenderer(widget_id="ff_renderer")
        renderer.mount(tk_root)
        try:
            renderer.apply_cpi(15)
            assert renderer.get_cpi() == 15
        finally:
            renderer.unmount()

    def test_apply_cpi_invalid_raises(self, tk_root: tk.Tk) -> None:
        """apply_cpi с невалидным CPI вызывает ValueError."""
        renderer = FreeFormModeRenderer(widget_id="ff_renderer")
        renderer.mount(tk_root)
        try:
            with pytest.raises(ValueError, match="Invalid CPI"):
                renderer.apply_cpi(99)
        finally:
            renderer.unmount()

    def test_apply_cpi_not_mounted_raises(self) -> None:
        """apply_cpi без mount вызывает LifecycleError."""
        renderer = FreeFormModeRenderer(widget_id="ff_renderer")
        with pytest.raises(LifecycleError, match="не смонтирован"):
            renderer.apply_cpi(12)

    def test_set_grid_snap(self) -> None:
        """Тест включения/отключения grid snap."""
        renderer = FreeFormModeRenderer(widget_id="ff_renderer")
        renderer.set_grid_snap_enabled(False)
        assert not renderer.is_grid_snap_enabled()
        renderer.set_grid_snap_enabled(True)
        assert renderer.is_grid_snap_enabled()

    def test_attach_detach_grid_canvas(self) -> None:
        """Тест присоединения/отсоединения Grid Canvas."""
        renderer = FreeFormModeRenderer(widget_id="ff_renderer")
        canvas = MagicMock()
        renderer.attach_grid_canvas(canvas)
        assert renderer._grid_canvas is canvas
        renderer.detach_grid_canvas()
        assert renderer._grid_canvas is None

    def test_set_line_double_height(self, tk_root: tk.Tk) -> None:
        """Тест установки double-height для строки."""
        renderer = FreeFormModeRenderer(widget_id="ff_renderer")
        renderer.mount(tk_root)
        try:
            renderer.set_line_double_height(1, True)
            assert renderer.is_line_double_height(1)
            renderer.set_line_double_height(1, False)
            assert not renderer.is_line_double_height(1)
        finally:
            renderer.unmount()

    def test_clear_double_height_rows(self, tk_root: tk.Tk) -> None:
        """Тест очистки double-height строк."""
        renderer = FreeFormModeRenderer(widget_id="ff_renderer")
        renderer.mount(tk_root)
        try:
            renderer.set_line_double_height(2, True)
            renderer.clear_double_height_rows()
            assert not renderer.get_double_height_rows()
        finally:
            renderer.unmount()

    def test_double_height_invalid_line_raises(self, tk_root: tk.Tk) -> None:
        """set_line_double_height с невалидной строкой вызывает ValueError."""
        renderer = FreeFormModeRenderer(widget_id="ff_renderer")
        renderer.mount(tk_root)
        try:
            with pytest.raises(ValueError, match=">= 1"):
                renderer.set_line_double_height(0, True)
        finally:
            renderer.unmount()

    def test_snap_to_grid(self) -> None:
        """Тест snap к grid."""
        renderer = FreeFormModeRenderer(widget_id="ff_renderer")
        renderer._grid_snap_enabled = True
        renderer._grid_column_width = 8
        assert renderer._snap_to_grid(10) == 8
        assert renderer._snap_to_grid(16) == 16
        renderer._grid_snap_enabled = False
        assert renderer._snap_to_grid(10) == 10

    def test_callbacks_setters(self) -> None:
        """Тест установки callbacks."""
        renderer = FreeFormModeRenderer(widget_id="ff_renderer")
        cpi_cb = MagicMock()
        content_cb = MagicMock()
        cursor_cb = MagicMock()
        renderer.set_on_cpi_change_callback(cpi_cb)
        renderer.set_on_content_change_callback(content_cb)
        renderer.set_on_cursor_move_callback(cursor_cb)
        assert renderer._on_cpi_change_callback is cpi_cb
        assert renderer._on_content_change_callback is content_cb
        assert renderer._on_cursor_move_callback is cursor_cb

    def test_unmount(self, tk_root: tk.Tk) -> None:
        """Тест размонтирования рендерера."""
        renderer = FreeFormModeRenderer(widget_id="ff_renderer")
        renderer.mount(tk_root)
        renderer.unmount()
        assert not renderer.is_mounted()


class TestFreeFormToolbar:
    """Тесты для панели инструментов FreeForm."""

    def test_toolbar_initialization(self) -> None:
        """Тест инициализации панели инструментов."""
        toolbar = FreeFormToolbar(widget_id="ff_toolbar")
        assert toolbar.widget_id == "ff_toolbar"
        assert not toolbar.is_mounted()
        assert toolbar.get_cpi() == 10
        assert toolbar.get_font() == FontFamily.DRAFT
        assert toolbar.get_active_formats() == set()

    def test_toolbar_mount(self, tk_root: tk.Tk) -> None:
        """Тест монтирования панели инструментов."""
        toolbar = FreeFormToolbar(widget_id="ff_toolbar")
        toolbar.mount(tk_root)
        try:
            assert toolbar.is_mounted()
            assert toolbar._tk_frame is not None
            assert toolbar._cpi_var is not None
            assert toolbar._font_var is not None
            assert len(toolbar._buttons) == 5
        finally:
            toolbar.unmount()

    def test_cpi_selector_callback(self, tk_root: tk.Tk) -> None:
        """Тест выбора CPI из dropdown."""
        callback = MagicMock()
        toolbar = FreeFormToolbar(widget_id="ff_toolbar", on_cpi_change=callback)
        toolbar.mount(tk_root)
        try:
            toolbar._on_cpi_selected("12")
            assert toolbar.get_cpi() == 12
            callback.assert_called_once_with(12)
        finally:
            toolbar.unmount()

    def test_format_toggle_button(self, tk_root: tk.Tk) -> None:
        """Тест переключения форматирования."""
        callback = MagicMock()
        toolbar = FreeFormToolbar(widget_id="ff_toolbar", on_format_toggle=callback)
        toolbar.mount(tk_root)
        try:
            toolbar._on_format_button_click("bold")
            assert "bold" in toolbar.get_active_formats()
            callback.assert_called_with("bold", True)
            toolbar._on_format_button_click("bold")
            assert "bold" not in toolbar.get_active_formats()
            callback.assert_called_with("bold", False)
        finally:
            toolbar.unmount()

    def test_format_buttons_toggle_state(self, tk_root: tk.Tk) -> None:
        """Тест состояния кнопок форматирования."""
        toolbar = FreeFormToolbar(widget_id="ff_toolbar")
        toolbar.mount(tk_root)
        try:
            toolbar.toggle_format("bold", True)
            assert "bold" in toolbar.get_active_formats()
            toolbar.toggle_format("bold", False)
            assert "bold" not in toolbar.get_active_formats()
        finally:
            toolbar.unmount()

    def test_set_cpi(self, tk_root: tk.Tk) -> None:
        """Тест установки CPI."""
        toolbar = FreeFormToolbar(widget_id="ff_toolbar")
        toolbar.mount(tk_root)
        try:
            toolbar.set_cpi(15)
            assert toolbar.get_cpi() == 15
            assert toolbar._cpi_var.get() == "15"
        finally:
            toolbar.unmount()

    def test_set_cpi_invalid_raises(self, tk_root: tk.Tk) -> None:
        """set_cpi с невалидным значением вызывает ValueError."""
        toolbar = FreeFormToolbar(widget_id="ff_toolbar")
        toolbar.mount(tk_root)
        try:
            with pytest.raises(ValueError, match="Invalid CPI"):
                toolbar.set_cpi(99)
        finally:
            toolbar.unmount()

    def test_set_cpi_not_mounted_raises(self) -> None:
        """set_cpi без mount вызывает LifecycleError."""
        toolbar = FreeFormToolbar(widget_id="ff_toolbar")
        with pytest.raises(LifecycleError, match="не смонтирован"):
            toolbar.set_cpi(12)

    def test_set_font(self, tk_root: tk.Tk) -> None:
        """Тест установки шрифта."""
        toolbar = FreeFormToolbar(widget_id="ff_toolbar")
        toolbar.mount(tk_root)
        try:
            toolbar.set_font(FontFamily.COURIER)
            assert toolbar.get_font() == FontFamily.COURIER
        finally:
            toolbar.unmount()

    def test_clear_active_formats(self, tk_root: tk.Tk) -> None:
        """Тест очистки активных форматов."""
        toolbar = FreeFormToolbar(widget_id="ff_toolbar")
        toolbar.mount(tk_root)
        try:
            toolbar.toggle_format("bold", True)
            toolbar.toggle_format("italic", True)
            toolbar.clear_active_formats()
            assert toolbar.get_active_formats() == set()
        finally:
            toolbar.unmount()

    def test_set_enabled(self, tk_root: tk.Tk) -> None:
        """Тест включения/отключения элементов управления."""
        toolbar = FreeFormToolbar(widget_id="ff_toolbar")
        toolbar.mount(tk_root)
        try:
            toolbar.set_enabled(False)
            assert toolbar._cpi_dropdown is not None
            assert toolbar._cpi_dropdown.cget("state") == "disabled"
            toolbar.set_enabled(True)
            assert toolbar._cpi_dropdown.cget("state") == "normal"
        finally:
            toolbar.unmount()

    def test_controller_dispatch_on_cpi(self, tk_root: tk.Tk) -> None:
        """Тест dispatch через контроллер при изменении CPI."""
        controller = MagicMock()
        toolbar = FreeFormToolbar(
            widget_id="ff_toolbar",
            controller=controller,
        )
        toolbar.mount(tk_root)
        try:
            toolbar._on_cpi_selected("12")
            controller.dispatch.assert_called_once_with(
                "freeform_cpi_changed",
                cpi=12,
            )
        finally:
            toolbar.unmount()

    def test_unmount(self, tk_root: tk.Tk) -> None:
        """Тест размонтирования панели."""
        toolbar = FreeFormToolbar(widget_id="ff_toolbar")
        toolbar.mount(tk_root)
        toolbar.unmount()
        assert not toolbar.is_mounted()


class TestFreeFormInteractions:
    """Тесты взаимодействий в режиме FreeForm."""

    def test_grid_snap(self) -> None:
        """Тест grid snap для позиционирования курсора."""
        renderer = FreeFormModeRenderer(widget_id="ff_renderer")
        renderer._grid_snap_enabled = True
        renderer._grid_column_width = 8
        assert renderer._snap_to_grid(10) == 8

    def test_attach_detach_grid_canvas(self) -> None:
        """Тест присоединения/отсоединения Grid Canvas."""
        renderer = FreeFormModeRenderer(widget_id="ff_renderer")
        canvas = MagicMock()
        renderer.attach_grid_canvas(canvas)
        assert renderer._grid_canvas is canvas
        renderer.detach_grid_canvas()
        assert renderer._grid_canvas is None

    def test_double_height_rows(self, tk_root: tk.Tk) -> None:
        """Тест управления double-height строками."""
        renderer = FreeFormModeRenderer(widget_id="ff_renderer")
        renderer.mount(tk_root)
        try:
            renderer.set_line_double_height(1, True)
            renderer.set_line_double_height(3, True)
            assert renderer.get_double_height_rows() == {1, 3}
            assert renderer.get_shadow_row_lines() == {2, 4}
            renderer.set_line_double_height(1, False)
            assert 1 not in renderer.get_double_height_rows()
        finally:
            renderer.unmount()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.modes.free_form"])
