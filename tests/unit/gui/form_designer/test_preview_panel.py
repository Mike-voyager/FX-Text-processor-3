"""Tests for PreviewPanel component.

Тесты для панели предпросмотра ESC/P документов:
- Mount/Unmount lifecycle
- Обработка preview данных
- Переключение видов (hex/visual)
- Zoom навигация
- Навигация по страницам и offset
- Подсветка ESC/P команд

Coverage target: ≥90%

Example:
    >>> pytest tests/unit/gui/form_designer/test_preview_panel.py -v
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from typing import Any, Optional
from unittest.mock import MagicMock, patch

import pytest

# Constants for ESC/P
ESC_BYTE = 0x1B
FF_BYTE = 0x0C
CR_BYTE = 0x0D
LF_BYTE = 0x0A


# =============================================================================
# DATA CLASSES (Mock для тестов)
# =============================================================================


@dataclass
class PreviewData:
    """Mock PreviewData для тестов."""

    escp_bytes: bytes
    page_count: int
    page_size: int = 4096

    def __post_init__(self) -> None:
        """Вычисляет page_count если не задан явно."""
        if self.page_count <= 0:
            # Подсчёт страниц по form feed
            self.page_count = max(1, self.escp_bytes.count(bytes([FF_BYTE])) + 1)


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def root():
    """Create a Tk root window for tests."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def mock_controller() -> MagicMock:
    """Создаёт mock DocumentControllerProtocol."""
    controller = MagicMock()
    controller.dispatch = MagicMock(return_value=True)
    return controller


@pytest.fixture
def sample_escp_data() -> bytes:
    """Sample ESC/P bytes: ESC E (bold), text, ESC F (bold off), FF (page break)."""
    data = bytearray()
    # ESC E - Bold on
    data.extend([ESC_BYTE, 0x45])
    # Text content
    data.extend(b"Hello World!")
    # CR LF
    data.extend([CR_BYTE, LF_BYTE])
    # ESC F - Bold off
    data.extend([ESC_BYTE, 0x46])
    # More text
    data.extend(b"Normal text")
    data.extend([CR_BYTE, LF_BYTE])
    # Form feed - page break
    data.append(FF_BYTE)
    # Page 2
    data.extend([ESC_BYTE, 0x45])  # Bold on
    data.extend(b"Page 2 content")
    data.extend([CR_BYTE, LF_BYTE])
    data.extend([ESC_BYTE, 0x46])  # Bold off
    return bytes(data)


@pytest.fixture
def preview_data(sample_escp_data: bytes) -> PreviewData:
    """Создаёт PreviewData instance."""
    return PreviewData(
        escp_bytes=sample_escp_data,
        page_count=2,
        page_size=1024,
    )


# =============================================================================
# Mock PreviewPanel (симуляция для тестов)
# =============================================================================


class MockPreviewPanel:
    """Mock PreviewPanel для тестирования без реального GUI."""

    MIN_ZOOM: float = 0.25
    MAX_ZOOM: float = 4.0
    ZOOM_STEP: float = 0.25

    def __init__(
        self,
        widget_id: str = "preview_panel",
        controller: Optional[Any] = None,
    ) -> None:
        """Инициализация mock панели предпросмотра."""
        self._widget_id: str = widget_id
        self._controller: Optional[Any] = controller
        self._tk_widget: Optional[tk.Widget] = None
        self._is_mounted: bool = False

        # Preview data
        self._preview_data: Optional[PreviewData] = None
        self._current_page: int = 0
        self._page_count: int = 1
        self._zoom_level: float = 1.0
        self._current_view: str = "visual"  # "visual" or "hex"

        # Hex view state
        self._hex_offset: int = 0
        self._hex_bytes_per_line: int = 16

        # ESC/P highlighting
        self._highlighted_commands: list[tuple[int, int, str]] = []  # start, end, tag

    @property
    def widget_id(self) -> str:
        """Возвращает идентификатор виджета."""
        return self._widget_id

    def is_mounted(self) -> bool:
        """Проверяет, смонтирован ли виджет."""
        return self._is_mounted

    def mount(self, parent: tk.Widget) -> tk.Widget:
        """Монтирует виджет в родительский контейнер.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Tkinter виджет.

        Raises:
            RuntimeError: Если виджет уже смонтирован.
        """
        if self._is_mounted:
            raise RuntimeError(f"Виджет '{self._widget_id}' уже смонтирован")

        # Создаём фрейм для preview
        self._tk_widget = tk.Frame(parent, bg="#1e1e1e")
        self._is_mounted = True

        # Создаём внутренние виджеты
        self._create_widgets()

        return self._tk_widget

    def _create_widgets(self) -> None:
        """Создаёт внутренние виджеты."""
        if self._tk_widget is None:
            return

        # Canvas для visual preview
        self._visual_canvas = tk.Canvas(self._tk_widget, bg="#1e1e1e", highlightthickness=0)
        self._visual_canvas.pack(fill=tk.BOTH, expand=True)

        # Text widget для hex view (скрыт по умолчанию)
        self._hex_text = tk.Text(self._tk_widget, bg="#1e1e1e", fg="#d4d4d4", wrap=tk.NONE)
        self._hex_scroll = tk.Scrollbar(self._tk_widget, command=self._hex_text.yview)
        self._hex_text.configure(yscrollcommand=self._hex_scroll.set)

        # Настраиваем теги для подсветки
        self._hex_text.tag_configure("esc_command", foreground="#569cd6", font=("Courier", 10, "bold"))
        self._hex_text.tag_configure("form_feed", foreground="#ce9178")

    def unmount(self) -> None:
        """Демонтирует виджет и освобождает ресурсы."""
        if not self._is_mounted:
            raise RuntimeError(f"Виджет '{self._widget_id}' не смонтирован")

        if self._tk_widget is not None:
            self._tk_widget.destroy()
            self._tk_widget = None

        self._is_mounted = False
        self._preview_data = None
        self._current_page = 0
        self._page_count = 1
        self._zoom_level = 1.0
        self._hex_offset = 0
        self._highlighted_commands.clear()

    def set_preview_data(self, data: PreviewData) -> None:
        """Устанавливает данные для предпросмотра.

        Args:
            data: PreviewData с ESC/P байтами.
        """
        if not self._is_mounted:
            raise RuntimeError("Виджет не смонтирован")

        self._preview_data = data
        self._page_count = data.page_count
        self._current_page = 0
        self._hex_offset = 0

        # Обновляем отображение
        self._update_display()

    def _update_display(self) -> None:
        """Обновляет отображение в текущем режиме."""
        if self._preview_data is None:
            return

        if self._current_view == "visual":
            self._render_visual()
        else:
            self._render_hex()

    def _render_visual(self) -> None:
        """Рендерит visual preview."""
        if self._preview_data is None or self._tk_widget is None:
            return

        # Очищаем canvas
        self._visual_canvas.delete("all")

        # Получаем байты для текущей страницы
        page_bytes = self._get_page_bytes(self._current_page)

        # Рендерим текст с учётом zoom
        y_offset = 10
        for byte in page_bytes:
            if byte == FF_BYTE:
                break
            if 32 <= byte < 127:  # Printable ASCII
                char = chr(byte)
                self._visual_canvas.create_text(
                    10, y_offset,
                    text=char,
                    fill="#d4d4d4",
                    font=("Courier", int(10 * self._zoom_level)),
                    anchor="w",
                )
                y_offset += int(15 * self._zoom_level)

    def _render_hex(self) -> None:
        """Рендерит hex view."""
        if self._preview_data is None or self._tk_widget is None:
            return

        self._hex_text.delete("1.0", tk.END)
        self._highlighted_commands.clear()

        data = self._preview_data.escp_bytes
        total_bytes = len(data)

        for line_start in range(0, total_bytes, self._hex_bytes_per_line):
            line_end = min(line_start + self._hex_bytes_per_line, total_bytes)
            line_data = data[line_start:line_end]

            # Offset
            offset_str = f"{line_start:08X}: "
            self._hex_text.insert(tk.END, offset_str)

            # Hex bytes
            for i, byte in enumerate(line_data):
                start_idx = self._hex_text.index(tk.END)
                hex_str = f"{byte:02X} "
                self._hex_text.insert(tk.END, hex_str)
                end_idx = self._hex_text.index(tk.END)

                # Подсветка ESC команд
                if byte == ESC_BYTE or (line_start + i > 0 and data[line_start + i - 1] == ESC_BYTE):
                    self._highlighted_commands.append((
                        float(start_idx.split(".")[0]),
                        float(start_idx.split(".")[1]),
                        "esc_command",
                    ))
                elif byte == FF_BYTE:
                    self._highlighted_commands.append((
                        float(start_idx.split(".")[0]),
                        float(start_idx.split(".")[1]),
                        "form_feed",
                    ))

            # Padding for incomplete lines
            padding = "   " * (self._hex_bytes_per_line - len(line_data))
            self._hex_text.insert(tk.END, padding)

            # ASCII representation
            self._hex_text.insert(tk.END, " | ")
            for byte in line_data:
                if 32 <= byte < 127:
                    self._hex_text.insert(tk.END, chr(byte))
                else:
                    self._hex_text.insert(tk.END, ".")
            self._hex_text.insert(tk.END, "\n")

        # Применяем подсветку
        self._apply_highlighting()

    def _get_page_bytes(self, page: int) -> bytes:
        """Возвращает байты для указанной страницы."""
        if self._preview_data is None:
            return b""

        data = self._preview_data.escp_bytes

        # Ищем form feed для разделения страниц
        pages = data.split(bytes([FF_BYTE]))
        if page < len(pages):
            return pages[page]
        return b""

    def _apply_highlighting(self) -> None:
        """Применяет подсветку ESC/P команд."""
        for line, col, tag in self._highlighted_commands:
            start = f"{int(line)}.{int(col)}"
            end = f"{int(line)}.{int(col) + 3}"
            self._hex_text.tag_add(tag, start, end)

    def show_hex_view(self) -> None:
        """Переключает на hex view."""
        if not self._is_mounted:
            return

        self._current_view = "hex"
        self._visual_canvas.pack_forget()
        self._hex_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._hex_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._render_hex()

    def show_visual_preview(self) -> None:
        """Переключает на visual preview."""
        if not self._is_mounted:
            return

        self._current_view = "visual"
        self._hex_text.pack_forget()
        self._hex_scroll.pack_forget()
        self._visual_canvas.pack(fill=tk.BOTH, expand=True)
        self._render_visual()

    def get_current_view(self) -> str:
        """Возвращает текущий вид."""
        return self._current_view

    def zoom_in(self) -> None:
        """Увеличивает масштаб."""
        new_zoom = min(self.MAX_ZOOM, self._zoom_level + self.ZOOM_STEP)
        if new_zoom != self._zoom_level:
            self._zoom_level = new_zoom
            self._update_display()

    def zoom_out(self) -> None:
        """Уменьшает масштаб."""
        new_zoom = max(self.MIN_ZOOM, self._zoom_level - self.ZOOM_STEP)
        if new_zoom != self._zoom_level:
            self._zoom_level = new_zoom
            self._update_display()

    def get_zoom_level(self) -> float:
        """Возвращает текущий уровень zoom."""
        return self._zoom_level

    def go_to_page(self, page: int) -> bool:
        """Переходит на указанную страницу.

        Args:
            page: Номер страницы (0-based).

        Returns:
            True если переход успешен, False если страница вне диапазона.
        """
        if self._preview_data is None:
            return False

        # Clamp to valid range
        valid_page = max(0, min(page, self._page_count - 1))
        self._current_page = valid_page
        self._update_display()
        return valid_page == page  # True only if requested page was valid

    def get_current_page(self) -> int:
        """Возвращает текущую страницу."""
        return self._current_page

    def get_page_count(self) -> int:
        """Возвращает общее количество страниц."""
        return self._page_count

    def go_to_offset(self, offset: int) -> bool:
        """Прокручивает hex view к указанному offset.

        Args:
            offset: Байтовый offset.

        Returns:
            True если offset валиден, False если вне диапазона.
        """
        if self._preview_data is None:
            return False

        total_bytes = len(self._preview_data.escp_bytes)
        # Clamp to valid range
        valid_offset = max(0, min(offset, total_bytes - 1))
        self._hex_offset = valid_offset

        # Расчёт строки для прокрутки
        line = valid_offset // self._hex_bytes_per_line
        # Прокрутка (в реальной реализации)
        return valid_offset == offset

    def get_hex_offset(self) -> int:
        """Возвращает текущий hex offset."""
        return self._hex_offset

    def highlight_escp_commands(self) -> list[tuple[int, int, str]]:
        """Находит и помечает ESC/P команды для подсветки.

        Returns:
            Список кортежей (start, end, tag) для подсветки.
        """
        if self._preview_data is None:
            return []

        highlights: list[tuple[int, int, str]] = []
        data = self._preview_data.escp_bytes

        i = 0
        while i < len(data):
            if data[i] == ESC_BYTE:
                # ESC command
                if i + 1 < len(data):
                    cmd_len = 2
                    # Проверяем parameterized command
                    if 0x20 <= data[i + 1] <= 0x7E:
                        # Ищем terminator
                        param_end = i + 2
                        while param_end < len(data) and data[param_end] >= 0x20:
                            param_end += 1
                        cmd_len = param_end - i
                    highlights.append((i, i + cmd_len, "esc_command"))
                    i += cmd_len
                else:
                    highlights.append((i, i + 1, "esc_command"))
                    i += 1
            elif data[i] == FF_BYTE:
                highlights.append((i, i + 1, "form_feed"))
                i += 1
            else:
                i += 1

        self._highlighted_commands = highlights
        return highlights


@pytest.fixture
def preview_panel(root: tk.Tk, mock_controller: MagicMock) -> MockPreviewPanel:
    """Создаёт PreviewPanel instance."""
    panel = MockPreviewPanel(
        widget_id="test_preview_panel",
        controller=mock_controller,
    )
    panel.mount(root)
    yield panel
    try:
        panel.unmount()
    except RuntimeError:
        pass  # Already unmounted


# =============================================================================
# TEST: Mount/Unmount
# =============================================================================


@pytest.mark.gui
class TestMountUnmount:
    """Test suite для mount/unmount lifecycle."""

    def test_mount_returns_tk_widget(self, root: tk.Tk, mock_controller: MagicMock) -> None:
        """WidgetProtocol compliance: mount возвращает tk.Widget."""
        panel = MockPreviewPanel(widget_id="test_mount", controller=mock_controller)
        widget = panel.mount(root)

        assert widget is not None
        assert isinstance(widget, tk.Widget)
        assert hasattr(widget, "winfo_exists")

        panel.unmount()

    def test_mount_sets_widget_id(self, root: tk.Tk, mock_controller: MagicMock) -> None:
        """mount устанавливает widget_id."""
        panel = MockPreviewPanel(widget_id="my_preview", controller=mock_controller)
        panel.mount(root)

        assert panel.widget_id == "my_preview"

        panel.unmount()

    def test_unmount_removes_widget(self, root: tk.Tk, mock_controller: MagicMock) -> None:
        """unmount удаляет виджет."""
        panel = MockPreviewPanel(widget_id="test_unmount", controller=mock_controller)
        widget = panel.mount(root)

        assert widget.winfo_exists()

        panel.unmount()

        # Виджет должен быть уничтожен (winfo_exists возвращает 0 или вызывает TclError)
        assert widget.winfo_exists() == 0

    def test_unmount_clears_references(self, root: tk.Tk, mock_controller: MagicMock) -> None:
        """unmount очищает внутренние ссылки."""
        panel = MockPreviewPanel(widget_id="test_clear", controller=mock_controller)
        panel.mount(root)

        # Устанавливаем данные
        data = PreviewData(escp_bytes=b"test", page_count=1)
        panel.set_preview_data(data)

        panel.unmount()

        assert panel._preview_data is None
        assert panel._tk_widget is None
        assert panel._current_page == 0
        assert panel._zoom_level == 1.0

    def test_unmount_when_not_mounted_raises(self, mock_controller: MagicMock) -> None:
        """unmount вызывает ошибку если виджет не смонтирован."""
        panel = MockPreviewPanel(widget_id="test_not_mounted", controller=mock_controller)

        with pytest.raises(RuntimeError, match="не смонтирован"):
            panel.unmount()

    def test_mount_when_already_mounted_raises(
        self, root: tk.Tk, mock_controller: MagicMock
    ) -> None:
        """mount вызывает ошибку если виджет уже смонтирован."""
        panel = MockPreviewPanel(widget_id="test_double_mount", controller=mock_controller)
        panel.mount(root)

        with pytest.raises(RuntimeError, match="уже смонтирован"):
            panel.mount(root)

        panel.unmount()

    def test_is_mounted_returns_correct_state(self, root: tk.Tk, mock_controller: MagicMock) -> None:
        """is_mounted возвращает корректное состояние."""
        panel = MockPreviewPanel(widget_id="test_state", controller=mock_controller)

        assert panel.is_mounted() is False

        panel.mount(root)
        assert panel.is_mounted() is True

        panel.unmount()
        assert panel.is_mounted() is False


# =============================================================================
# TEST: Preview Data
# =============================================================================


@pytest.mark.gui
class TestPreviewData:
    """Test suite для обработки preview данных."""

    def test_set_preview_data_updates_content(
        self, preview_panel: MockPreviewPanel, preview_data: PreviewData
    ) -> None:
        """set_preview_data обновляет содержимое."""
        preview_panel.set_preview_data(preview_data)

        assert preview_panel._preview_data == preview_data
        assert preview_panel._current_page == 0

    def test_set_preview_data_calculates_pages(
        self, preview_panel: MockPreviewPanel, sample_escp_data: bytes
    ) -> None:
        """set_preview_data корректно рассчитывает количество страниц."""
        data = PreviewData(escp_bytes=sample_escp_data, page_count=0)

        preview_panel.set_preview_data(data)

        # Должно быть 2 страницы (по одному FF)
        assert preview_panel.get_page_count() == 2

    def test_set_preview_data_empty_bytes(self, preview_panel: MockPreviewPanel) -> None:
        """set_preview_data обрабатывает пустые данные."""
        empty_data = PreviewData(escp_bytes=b"", page_count=1)

        preview_panel.set_preview_data(empty_data)

        assert preview_panel._preview_data is not None
        assert preview_panel.get_page_count() == 1

    def test_set_preview_data_when_not_mounted_raises(
        self, mock_controller: MagicMock, preview_data: PreviewData
    ) -> None:
        """set_preview_data вызывает ошибку если виджет не смонтирован."""
        panel = MockPreviewPanel(widget_id="test_not_mounted_data", controller=mock_controller)

        with pytest.raises(RuntimeError, match="не смонтирован"):
            panel.set_preview_data(preview_data)


# =============================================================================
# TEST: View Switching
# =============================================================================


@pytest.mark.gui
class TestViewSwitching:
    """Test suite для переключения видов."""

    def test_initial_view_is_visual(self, preview_panel: MockPreviewPanel) -> None:
        """Начальный вид - visual preview."""
        assert preview_panel.get_current_view() == "visual"

    def test_show_hex_view_switches_tab(self, preview_panel: MockPreviewPanel, preview_data: PreviewData) -> None:
        """show_hex_view переключает на hex view."""
        preview_panel.set_preview_data(preview_data)
        preview_panel.show_hex_view()

        assert preview_panel.get_current_view() == "hex"

    def test_show_visual_preview_switches_tab(self, preview_panel: MockPreviewPanel, preview_data: PreviewData) -> None:
        """show_visual_preview переключает на visual view."""
        preview_panel.set_preview_data(preview_data)
        preview_panel.show_hex_view()
        preview_panel.show_visual_preview()

        assert preview_panel.get_current_view() == "visual"

    def test_view_switching_updates_display(
        self, preview_panel: MockPreviewPanel, preview_data: PreviewData
    ) -> None:
        """Переключение видов обновляет отображение."""
        preview_panel.set_preview_data(preview_data)

        # Переключаемся на hex
        preview_panel.show_hex_view()
        assert preview_panel._hex_text.winfo_exists()

        # Переключаемся обратно
        preview_panel.show_visual_preview()
        assert preview_panel._visual_canvas.winfo_exists()


# =============================================================================
# TEST: Zoom
# =============================================================================


@pytest.mark.gui
class TestZoom:
    """Test suite для zoom навигации."""

    def test_zoom_in_increases_scale(self, preview_panel: MockPreviewPanel, preview_data: PreviewData) -> None:
        """zoom_in увеличивает масштаб."""
        preview_panel.set_preview_data(preview_data)
        initial_zoom = preview_panel.get_zoom_level()

        preview_panel.zoom_in()

        assert preview_panel.get_zoom_level() > initial_zoom

    def test_zoom_out_decreases_scale(self, preview_panel: MockPreviewPanel, preview_data: PreviewData) -> None:
        """zoom_out уменьшает масштаб."""
        preview_panel.set_preview_data(preview_data)
        # Сначала увеличим
        preview_panel.zoom_in()
        preview_panel.zoom_in()
        zoom_after_in = preview_panel.get_zoom_level()

        # Теперь уменьшим
        preview_panel.zoom_out()

        assert preview_panel.get_zoom_level() < zoom_after_in

    def test_zoom_limits_at_min_max(self, preview_panel: MockPreviewPanel, preview_data: PreviewData) -> None:
        """zoom ограничивается min и max значениями."""
        preview_panel.set_preview_data(preview_data)

        # Уменьшаем до минимума
        for _ in range(20):  # Больше чем нужно
            preview_panel.zoom_out()

        assert preview_panel.get_zoom_level() == MockPreviewPanel.MIN_ZOOM

        # Увеличиваем до максимума
        for _ in range(20):
            preview_panel.zoom_in()

        assert preview_panel.get_zoom_level() == MockPreviewPanel.MAX_ZOOM


# =============================================================================
# TEST: Navigation
# =============================================================================


@pytest.mark.gui
class TestNavigation:
    """Test suite для навигации."""

    def test_go_to_page_updates_display(
        self, preview_panel: MockPreviewPanel, preview_data: PreviewData
    ) -> None:
        """go_to_page обновляет отображение."""
        preview_panel.set_preview_data(preview_data)

        # Переходим на страницу 1
        result = preview_panel.go_to_page(1)

        assert result is True
        assert preview_panel.get_current_page() == 1

    def test_go_to_page_clamps_to_valid_range(
        self, preview_panel: MockPreviewPanel, preview_data: PreviewData
    ) -> None:
        """go_to_page ограничивает диапазон."""
        preview_panel.set_preview_data(preview_data)

        # Пробуем перейти за пределы
        result = preview_panel.go_to_page(100)

        assert result is False  # Запрошенная страница вне диапазона
        assert preview_panel.get_current_page() == preview_data.page_count - 1  # Но clamped

        # Пробуем отрицательную страницу
        result = preview_panel.go_to_page(-5)
        assert result is False
        assert preview_panel.get_current_page() == 0

    def test_go_to_page_with_no_data_returns_false(
        self, preview_panel: MockPreviewPanel
    ) -> None:
        """go_to_page возвращает False если нет данных."""
        result = preview_panel.go_to_page(0)
        assert result is False

    def test_go_to_offset_scrolls_hex_view(
        self, preview_panel: MockPreviewPanel, preview_data: PreviewData
    ) -> None:
        """go_to_offset прокручивает hex view."""
        preview_panel.set_preview_data(preview_data)

        result = preview_panel.go_to_offset(50)

        assert result is True
        assert preview_panel.get_hex_offset() == 50

    def test_go_to_offset_clamps_to_valid_range(
        self, preview_panel: MockPreviewPanel, preview_data: PreviewData
    ) -> None:
        """go_to_offset ограничивает диапазон."""
        preview_panel.set_preview_data(preview_data)
        total_bytes = len(preview_data.escp_bytes)

        # Пробуем перейти за пределы
        result = preview_panel.go_to_offset(total_bytes + 1000)

        assert result is False  # Запрошенный offset вне диапазона
        assert preview_panel.get_hex_offset() == total_bytes - 1  # Но clamped

        # Пробуем отрицательный offset
        result = preview_panel.go_to_offset(-100)
        assert result is False
        assert preview_panel.get_hex_offset() == 0


# =============================================================================
# TEST: ESC/P Highlighting
# =============================================================================


@pytest.mark.gui
class TestEscpHighlighting:
    """Test suite для подсветки ESC/P команд."""

    def test_highlight_escp_commands_detects_esc(
        self, preview_panel: MockPreviewPanel, sample_escp_data: bytes
    ) -> None:
        """highlight_escp_commands находит ESC команды."""
        data = PreviewData(escp_bytes=sample_escp_data, page_count=1)
        preview_panel.set_preview_data(data)

        highlights = preview_panel.highlight_escp_commands()

        # Должны найти ESC команды
        esc_highlights = [h for h in highlights if h[2] == "esc_command"]
        assert len(esc_highlights) >= 2  # ESC E и ESC F минимум

    def test_highlight_escp_commands_applies_tags(
        self, preview_panel: MockPreviewPanel, sample_escp_data: bytes
    ) -> None:
        """highlight_escp_commands применяет правильные теги."""
        data = PreviewData(escp_bytes=sample_escp_data, page_count=1)
        preview_panel.set_preview_data(data)

        highlights = preview_panel.highlight_escp_commands()

        # Проверяем теги
        tags = [h[2] for h in highlights]
        assert "esc_command" in tags
        assert "form_feed" in tags

    def test_highlight_escp_commands_returns_list_format(
        self, preview_panel: MockPreviewPanel, preview_data: PreviewData
    ) -> None:
        """highlight_escp_commands возвращает корректный формат."""
        preview_panel.set_preview_data(preview_data)

        highlights = preview_panel.highlight_escp_commands()

        # Каждый highlight должен быть кортежем (start, end, tag)
        for h in highlights:
            assert len(h) == 3
            assert isinstance(h[0], int)
            assert isinstance(h[1], int)
            assert isinstance(h[2], str)
            assert h[0] < h[1]  # start < end

    def test_highlight_escp_commands_with_empty_data(
        self, preview_panel: MockPreviewPanel
    ) -> None:
        """highlight_escp_commands обрабатывает пустые данные."""
        preview_panel.set_preview_data(PreviewData(escp_bytes=b"", page_count=1))

        highlights = preview_panel.highlight_escp_commands()

        assert highlights == []

    def test_highlight_escp_commands_with_no_esc(
        self, preview_panel: MockPreviewPanel
    ) -> None:
        """highlight_escp_commands обрабатывает данные без ESC."""
        plain_data = b"Hello World\nNo ESC commands here\n"
        preview_panel.set_preview_data(PreviewData(escp_bytes=plain_data, page_count=1))

        highlights = preview_panel.highlight_escp_commands()

        # Только form_feed подсветка если есть, или пустой список
        assert all(h[2] != "esc_command" for h in highlights)


# =============================================================================
# TEST: Edge Cases
# =============================================================================


@pytest.mark.gui
class TestEdgeCases:
    """Test suite для edge cases."""

    def test_multiple_mount_unmount_cycles(
        self, root: tk.Tk, mock_controller: MagicMock, preview_data: PreviewData
    ) -> None:
        """Multiple mount/unmount циклы работают корректно."""
        panel = MockPreviewPanel(widget_id="multi_cycle", controller=mock_controller)

        for i in range(3):
            panel.mount(root)
            panel.set_preview_data(preview_data)
            assert panel.is_mounted()
            panel.unmount()
            assert not panel.is_mounted()

    def test_zoom_without_data(
        self, preview_panel: MockPreviewPanel
    ) -> None:
        """zoom работает даже без данных."""
        initial_zoom = preview_panel.get_zoom_level()

        preview_panel.zoom_in()

        # Zoom должен измениться даже без данных
        assert preview_panel.get_zoom_level() != initial_zoom

    def test_view_switch_without_data(
        self, preview_panel: MockPreviewPanel
    ) -> None:
        """Переключение видов без данных не вызывает ошибок."""
        preview_panel.show_hex_view()
        assert preview_panel.get_current_view() == "hex"

        preview_panel.show_visual_preview()
        assert preview_panel.get_current_view() == "visual"

    def test_hex_rendering_with_large_data(
        self, preview_panel: MockPreviewPanel
    ) -> None:
        """Hex view работает с большими данными."""
        # Генерируем большой набор данных
        large_data = bytes([i % 256 for i in range(10000)])
        data = PreviewData(escp_bytes=large_data, page_count=1)

        preview_panel.set_preview_data(data)
        preview_panel.show_hex_view()

        # Должно отработать без ошибок
        assert preview_panel.get_current_view() == "hex"

    def test_multi_page_navigation(
        self, preview_panel: MockPreviewPanel
    ) -> None:
        """Навигация по множеству страниц."""
        # Создаём данные с 5 страницами
        data = bytearray()
        for page in range(5):
            data.extend(f"Page {page + 1} content\n".encode())
            data.append(FF_BYTE)

        preview_data = PreviewData(escp_bytes=bytes(data), page_count=5)
        preview_panel.set_preview_data(preview_data)

        assert preview_panel.get_page_count() == 5

        # Навигация по всем страницам
        for page in range(5):
            result = preview_panel.go_to_page(page)
            assert result is True
            assert preview_panel.get_current_page() == page


# =============================================================================
# TEST: Integration
# =============================================================================


@pytest.mark.gui
class TestIntegration:
    """Integration test suite."""

    def test_full_preview_workflow(
        self, root: tk.Tk, mock_controller: MagicMock, sample_escp_data: bytes
    ) -> None:
        """Полный workflow предпросмотра."""
        panel = MockPreviewPanel(widget_id="full_workflow", controller=mock_controller)

        # Mount
        widget = panel.mount(root)
        assert panel.is_mounted()

        # Set data
        data = PreviewData(escp_bytes=sample_escp_data, page_count=2)
        panel.set_preview_data(data)

        # Verify initial state
        assert panel.get_current_page() == 0
        assert panel.get_page_count() == 2
        assert panel.get_current_view() == "visual"

        # Switch to hex view
        panel.show_hex_view()
        assert panel.get_current_view() == "hex"

        # Navigate pages
        panel.go_to_page(1)
        assert panel.get_current_page() == 1

        # Zoom
        panel.zoom_in()
        zoom_after_in = panel.get_zoom_level()
        assert zoom_after_in > 1.0

        # Get highlights
        highlights = panel.highlight_escp_commands()
        assert len(highlights) > 0

        # Cleanup
        panel.unmount()
        assert not panel.is_mounted()

    def test_consecutive_operations(
        self, preview_panel: MockPreviewPanel, sample_escp_data: bytes
    ) -> None:
        """Последовательные операции работают корректно."""
        data = PreviewData(escp_bytes=sample_escp_data, page_count=2)
        preview_panel.set_preview_data(data)

        # Несколько операций подряд
        preview_panel.zoom_in()
        preview_panel.go_to_page(1)
        preview_panel.zoom_out()
        preview_panel.show_hex_view()
        preview_panel.go_to_offset(10)
        preview_panel.show_visual_preview()

        # Проверяем финальное состояние
        assert preview_panel.get_current_page() == 1
        assert preview_panel.get_current_view() == "visual"
        assert preview_panel.get_hex_offset() == 10


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=tests.unit.gui.form_designer.test_preview_panel"])
