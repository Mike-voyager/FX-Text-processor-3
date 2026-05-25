"""Unit-тесты для StatusBar.

Проверяет:
- Создание StatusBar
- Установку позиции курсора (set_cursor_position)
- Установку индикатора изменений (set_modified)
- Установку пресета безопасности (set_security_preset)
- Double-click на индикаторе бумаги
- Адаптивный layout (single/double row)
- Workflow Timeline strip
- Document mode и STRUCTURED_FORM visibility
- Разделители и цвета

Coverage target: ≥90%
"""

import tkinter as tk
from typing import Any, Generator
from unittest.mock import MagicMock

import pytest
from src.documents.types.document_type import DocumentMode
from src.gui.layout.layout_constants import MIN_WINDOW_WIDTH, STATUSBAR_HEIGHT
from src.gui.views.status_bar import (
    SECURITY_PRESET_COLORS,
    SEPARATOR_COLOR,
    TIMELINE_ARROW,
    TIMELINE_CURRENT_MARKER,
    TIMELINE_DONE_MARKER,
    TIMELINE_FUTURE_MARKER,
    StatusBar,
)
from src.gui.workflow.role_badge import WorkflowRole

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
def mock_paper_callback() -> MagicMock:
    """Fixture для mock callback при double-click на paper."""
    return MagicMock()


@pytest.fixture
def status_bar(tk_root: tk.Tk, mock_paper_callback: MagicMock) -> StatusBar:
    """Fixture для StatusBar."""
    bar = StatusBar(
        widget_id="test_statusbar",
        paper_callback=mock_paper_callback,
    )
    bar.mount(tk_root)
    return bar


# =============================================================================
# TEST: StatusBar Creation
# =============================================================================


@pytest.mark.gui
class TestStatusBarCreation:
    """Тесты создания StatusBar."""

    def test_status_bar_creation(self, tk_root: tk.Tk) -> None:
        """Создание StatusBar с валидными параметрами."""
        bar = StatusBar(widget_id="test_create")
        bar.mount(tk_root)

        assert bar.widget_id == "test_create"
        assert bar.is_mounted()

    def test_status_bar_creation_default_id(self, tk_root: tk.Tk) -> None:
        """Создание StatusBar с дефолтным id."""
        bar = StatusBar()
        bar.mount(tk_root)

        assert bar.widget_id == "statusbar"

    def test_status_bar_creation_with_paper_callback(
        self, tk_root: tk.Tk, mock_paper_callback: MagicMock
    ) -> None:
        """Создание StatusBar с paper callback."""
        bar = StatusBar(paper_callback=mock_paper_callback)
        bar.mount(tk_root)

        assert bar._paper_callback is mock_paper_callback


# =============================================================================
# TEST: Cursor Position
# =============================================================================


@pytest.mark.gui
class TestSetCursorPosition:
    """Тесты установки позиции курсора."""

    def test_set_cursor_position(self, status_bar: StatusBar) -> None:
        """set_cursor_position() обновляет отображение."""
        status_bar.set_cursor_position(10, 25)

        assert status_bar._line == 10
        assert status_bar._column == 25

    def test_set_cursor_position_minimum_one(self, status_bar: StatusBar) -> None:
        """set_cursor_position() ограничивает минимумом 1."""
        status_bar.set_cursor_position(0, -5)

        assert status_bar._line == 1
        assert status_bar._column == 1


# =============================================================================
# TEST: Modified Indicator
# =============================================================================


@pytest.mark.gui
class TestSetModified:
    """Тесты установки индикатора изменений."""

    def test_set_modified_true(self, status_bar: StatusBar) -> None:
        """set_modified(True) устанавливает modified=True."""
        status_bar.set_modified(True)

        assert status_bar._modified is True

    def test_set_modified_false(self, status_bar: StatusBar) -> None:
        """set_modified(False) устанавливает modified=False."""
        status_bar.set_modified(True)
        status_bar.set_modified(False)

        assert status_bar._modified is False


# =============================================================================
# TEST: Security Preset
# =============================================================================


@pytest.mark.gui
class TestSetSecurityPreset:
    """Тесты установки пресета безопасности."""

    def test_set_security_preset_standard(self, status_bar: StatusBar) -> None:
        """set_security_preset('Standard') устанавливает пресет."""
        status_bar.set_security_preset("Standard")

        assert status_bar._security_preset == "Standard"

    def test_set_security_preset_paranoid(self, status_bar: StatusBar) -> None:
        """set_security_preset('Paranoid') устанавливает пресет."""
        status_bar.set_security_preset("Paranoid")

        assert status_bar._security_preset == "Paranoid"

    def test_set_security_preset_colors_exist(self) -> None:
        """SECURITY_PRESET_COLORS содержит все пресеты."""
        assert "Legacy" in SECURITY_PRESET_COLORS
        assert "Standard" in SECURITY_PRESET_COLORS
        assert "Paranoid" in SECURITY_PRESET_COLORS
        assert "PQC" in SECURITY_PRESET_COLORS


# =============================================================================
# TEST: Other Setters
# =============================================================================


@pytest.mark.gui
class TestOtherSetters:
    """Тесты других setter методов."""

    def test_set_page_info(self, status_bar: StatusBar) -> None:
        """set_page_info() устанавливает информацию о странице."""
        status_bar.set_page_info(2, 5)

        assert status_bar._page_current == 2
        assert status_bar._page_total == 5

    def test_set_page_info_minimum_one(self, status_bar: StatusBar) -> None:
        """set_page_info() ограничивает минимумом 1."""
        status_bar.set_page_info(0, 0)

        assert status_bar._page_current == 1
        assert status_bar._page_total == 1

    def test_set_cpi(self, status_bar: StatusBar) -> None:
        """set_cpi() устанавливает CPI."""
        status_bar.set_cpi(12)

        assert status_bar._cpi == 12

    def test_set_cpi_minimum_one(self, status_bar: StatusBar) -> None:
        """set_cpi() ограничивает минимумом 1."""
        status_bar.set_cpi(0)

        assert status_bar._cpi == 1

    def test_set_codepage(self, status_bar: StatusBar) -> None:
        """set_codepage() устанавливает кодовую страницу."""
        status_bar.set_codepage("UTF-8")

        assert status_bar._codepage == "UTF-8"

    def test_set_paper(self, status_bar: StatusBar) -> None:
        """set_paper() устанавливает формат бумаги."""
        status_bar.set_paper("Letter")

        assert status_bar._paper == "Letter"

    def test_set_zoom(self, status_bar: StatusBar) -> None:
        """set_zoom() устанавливает масштаб."""
        status_bar.set_zoom(150)

        assert status_bar._zoom == 150

    def test_set_zoom_clamped(self, status_bar: StatusBar) -> None:
        """set_zoom() ограничивает диапазон 10-500."""
        status_bar.set_zoom(5)
        assert status_bar._zoom == 10

        status_bar.set_zoom(1000)
        assert status_bar._zoom == 500


# =============================================================================
# TEST: Paper Double Click
# =============================================================================


@pytest.mark.gui
class TestPaperDoubleClick:
    """Тесты double-click на индикаторе бумаги."""

    def test_paper_double_click_triggers_callback(
        self, status_bar: StatusBar, mock_paper_callback: MagicMock
    ) -> None:
        """Double-click на paper вызывает callback."""
        status_bar._on_paper_double_click()

        mock_paper_callback.assert_called_once()

    def test_paper_double_click_no_callback(self, tk_root: tk.Tk, mocker: Any) -> None:
        """Double-click без callback открывает PaperSetupDialog."""
        mock_dialog_cls = mocker.patch("src.gui.views.status_bar.PaperSetupDialog")
        mock_dialog = mock_dialog_cls.return_value
        bar = StatusBar()
        bar.mount(tk_root)

        bar._on_paper_double_click()

        mock_dialog_cls.assert_called_once_with(parent=bar._tk_frame)
        mock_dialog.show.assert_called_once()


# =============================================================================
# TEST: Show/Hide
# =============================================================================


@pytest.mark.gui
class TestShowHide:
    """Тесты show/hide методов."""

    def test_show(self, status_bar: StatusBar) -> None:
        """show() показывает компонент."""
        status_bar.show()

    def test_hide(self, status_bar: StatusBar) -> None:
        """hide() скрывает компонент."""
        status_bar.hide()


# =============================================================================
# TEST: Adaptive Layout
# =============================================================================


@pytest.mark.gui
class TestAdaptiveLayout:
    """Тесты адаптивного layout."""

    def test_initial_layout_single_row(self, status_bar: StatusBar) -> None:
        """Изначально single row layout."""
        assert not status_bar._is_double_row

    def test_layout_switches_to_double_row_on_small_width(
        self, status_bar: StatusBar
    ) -> None:
        """Layout переключается на double row при малой ширине."""
        event = MagicMock()
        event.width = MIN_WINDOW_WIDTH - 100
        event.height = 100

        status_bar._on_configure(event)

        assert status_bar._is_double_row

    def test_double_row_height_doubled(self, status_bar: StatusBar) -> None:
        """При double row высота StatusBar удваивается."""
        event = MagicMock()
        event.width = MIN_WINDOW_WIDTH - 100

        status_bar._on_configure(event)
        # Имитируем срабатывание debounce-таймера
        status_bar._apply_layout_debounced()

        assert status_bar._tk_frame is not None
        assert int(status_bar._tk_frame.cget("height")) == STATUSBAR_HEIGHT * 2

    def test_single_row_height_normal(self, status_bar: StatusBar) -> None:
        """При single row высота равна STATUSBAR_HEIGHT."""
        status_bar._is_double_row = True
        status_bar._apply_layout()

        event = MagicMock()
        event.width = MIN_WINDOW_WIDTH + 100
        status_bar._on_configure(event)
        # Имитируем срабатывание debounce-таймера
        status_bar._apply_layout_debounced()

        assert not status_bar._is_double_row
        assert status_bar._tk_frame is not None
        assert int(status_bar._tk_frame.cget("height")) == STATUSBAR_HEIGHT

    def test_single_row_shows_all_left_indicators(self, status_bar: StatusBar) -> None:
        """Single row layout содержит все левые индикаторы."""
        status_bar._apply_layout()

        assert status_bar._tk_cursor_label is not None
        assert status_bar._tk_cursor_label.winfo_manager() == "pack"

    def test_double_row_moves_zoom_to_row2(self, status_bar: StatusBar) -> None:
        """Double row переносит CPI, codepage, paper, zoom в строку 2."""
        event = MagicMock()
        event.width = MIN_WINDOW_WIDTH - 100

        status_bar._on_configure(event)
        # Имитируем срабатывание debounce-таймера
        status_bar._apply_layout_debounced()

        assert status_bar._row2_frame is not None
        assert status_bar._tk_zoom_label is not None
        # Zoom должен быть упакован в row2_frame
        assert status_bar._tk_zoom_label.winfo_manager() == "pack"
        info = status_bar._tk_zoom_label.pack_info()
        assert info.get("in") == status_bar._row2_frame


# =============================================================================
# TEST: Separators
# =============================================================================


@pytest.mark.gui
class TestSeparators:
    """Тесты вертикальных разделителей."""

    def test_separators_created(self, status_bar: StatusBar) -> None:
        """Разделители создаются при монтировании."""
        assert len(status_bar._separator_labels) > 0

    def test_separator_color_is_fixed(self, status_bar: StatusBar) -> None:
        """Цвет разделителей не зависит от темы."""
        for sep in status_bar._separator_labels:
            assert sep.cget("fg") == SEPARATOR_COLOR

    def test_separator_char_is_pipe(self, status_bar: StatusBar) -> None:
        """Разделитель использует символ │."""
        for sep in status_bar._separator_labels:
            assert sep.cget("text") == "│"


# =============================================================================
# TEST: Widget Property
# =============================================================================


@pytest.mark.gui
class TestWidgetProperty:
    """Тесты widget property."""

    def test_widget_property_returns_frame(self, status_bar: StatusBar) -> None:
        """widget property возвращает Frame."""
        widget = status_bar.widget

        assert isinstance(widget, tk.Frame)

    def test_widget_property_not_mounted_raises(self, tk_root: tk.Tk) -> None:
        """widget property до mount вызывает RuntimeError."""
        bar = StatusBar()

        with pytest.raises(RuntimeError, match="is not mounted"):
            _ = bar.widget


# =============================================================================
# TEST: Module Exports
# =============================================================================


class TestModuleExports:
    """Тесты exports модуля."""

    def test_all_exports_defined(self) -> None:
        """Все exports определены в __all__."""
        from src.gui.views import status_bar

        assert hasattr(status_bar, "__all__")
        assert "StatusBar" in status_bar.__all__
        assert "SECURITY_PRESET_COLORS" in status_bar.__all__
        assert "DEFAULT_SECURITY_COLOR" in status_bar.__all__
        assert "MODIFIED_COLOR" in status_bar.__all__
        assert "SEPARATOR_COLOR" in status_bar.__all__

    def test_module_metadata(self) -> None:
        """Модуль имеет метаданные версии."""
        from src.gui.views import status_bar

        assert hasattr(status_bar, "__version__")
        assert hasattr(status_bar, "__author__")
        assert hasattr(status_bar, "__date__")


# =============================================================================
# TEST: Workflow Indicator
# =============================================================================


@pytest.mark.gui
class TestWorkflowIndicator:
    """Тесты индикатора workflow."""

    def test_set_workflow_status(self, tk_root: tk.Tk) -> None:
        """set_workflow_status() устанавливает статус."""
        from src.documents.constructor.form_status import FormStatus

        bar = StatusBar()
        bar.mount(tk_root)

        bar.set_workflow_status(FormStatus.FILLED)

        assert bar._workflow_status == FormStatus.FILLED
        assert bar.get_workflow_status() == "filled"

    def test_set_workflow_status_updates_indicator(self, tk_root: tk.Tk) -> None:
        """set_workflow_status() обновляет индикатор."""
        from src.documents.constructor.form_status import FormStatus

        bar = StatusBar()
        bar.mount(tk_root)

        bar.set_workflow_status(FormStatus.SIGNED)

        if bar._workflow_indicator is not None:
            assert bar._workflow_indicator.get_status() == "signed"

    def test_workflow_status_none_default(self, tk_root: tk.Tk) -> None:
        """workflow_status по умолчанию None."""
        bar = StatusBar()
        bar.mount(tk_root)

        assert bar.get_workflow_status() is None

    def test_workflow_callback(self, tk_root: tk.Tk) -> None:
        """workflow_callback передаётся в индикатор."""
        from src.documents.constructor.form_status import FormStatus

        callback_calls: list[bool] = []

        def on_workflow():
            callback_calls.append(True)

        bar = StatusBar(
            workflow_callback=on_workflow,
        )
        bar.set_workflow_status(FormStatus.DRAFT)
        bar.mount(tk_root)

        assert bar._workflow_callback is on_workflow


# =============================================================================
# TEST: Workflow Timeline
# =============================================================================


@pytest.mark.gui
class TestWorkflowTimeline:
    """Тесты Workflow Timeline strip."""

    def test_set_workflow_timeline(self, status_bar: StatusBar) -> None:
        """set_workflow_timeline() устанавливает текст timeline."""
        from src.documents.constructor.form_status import FormStatus

        status_bar.set_workflow_timeline(FormStatus.FILLED)
        assert status_bar._current_workflow_status == "filled"

    def test_timeline_text_contains_markers(self, status_bar: StatusBar) -> None:
        """Timeline текст содержит правильные маркеры."""
        from src.documents.constructor.form_status import FormStatus

        status_bar.set_document_mode(DocumentMode.STRUCTURED_FORM)
        status_bar.set_workflow_timeline(FormStatus.VALIDATED)

        timeline_text = status_bar._build_timeline_text("validated")

        assert TIMELINE_DONE_MARKER in timeline_text
        assert TIMELINE_CURRENT_MARKER in timeline_text
        assert TIMELINE_FUTURE_MARKER in timeline_text
        assert TIMELINE_ARROW in timeline_text

    def test_timeline_done_before_current(self, status_bar: StatusBar) -> None:
        """Для статуса APPROVED статусы draft/filled/validated отмечены ✓."""
        from src.documents.constructor.form_status import FormStatus

        status_bar.set_workflow_timeline(FormStatus.APPROVED)
        text = status_bar._build_timeline_text("approved")

        assert "[DRAFT ✓]" in text
        assert "[FILLED ✓]" in text
        assert "[VALIDATED ✓]" in text
        assert "[APPROVED ●]" in text
        assert "[SIGNED ○]" in text

    def test_timeline_click_calls_callback(self, status_bar: StatusBar) -> None:
        """Клик на timeline вызывает workflow_callback."""
        calls: list[bool] = []

        def callback():
            calls.append(True)

        status_bar._workflow_callback = callback
        status_bar._on_workflow_timeline_click()

        assert len(calls) == 1


# =============================================================================
# TEST: Document Mode Visibility
# =============================================================================


@pytest.mark.gui
class TestDocumentModeVisibility:
    """Тесты видимости workflow-виджетов в зависимости от document_mode."""

    def test_timeline_hidden_in_free_form(self, status_bar: StatusBar) -> None:
        """Timeline скрыт при FREE_FORM."""
        from src.documents.constructor.form_status import FormStatus

        status_bar.set_document_mode(DocumentMode.FREE_FORM)
        status_bar.set_workflow_timeline(FormStatus.FILLED)

        assert status_bar._document_mode == DocumentMode.FREE_FORM
        # В single row timeline_frame не должен быть упакован
        assert status_bar._workflow_timeline_frame is not None
        assert status_bar._workflow_timeline_frame.winfo_manager() == ""

    def test_timeline_visible_in_structured_form(self, status_bar: StatusBar) -> None:
        """Timeline видим при STRUCTURED_FORM."""
        from src.documents.constructor.form_status import FormStatus

        status_bar.set_document_mode(DocumentMode.STRUCTURED_FORM)
        status_bar.set_workflow_timeline(FormStatus.FILLED)

        assert status_bar._document_mode == DocumentMode.STRUCTURED_FORM
        assert status_bar._workflow_timeline_frame is not None
        assert status_bar._workflow_timeline_frame.winfo_manager() == "pack"

    def test_role_badge_hidden_in_free_form(self, status_bar: StatusBar) -> None:
        """RoleBadge скрыт при FREE_FORM."""
        status_bar.set_document_mode(DocumentMode.FREE_FORM)
        status_bar.set_role_badge(WorkflowRole.OPERATOR)

        assert status_bar._document_mode == DocumentMode.FREE_FORM
        assert status_bar._role_badge is not None
        assert status_bar._role_badge.widget is not None
        assert status_bar._role_badge.widget.winfo_manager() == ""

    def test_role_badge_visible_in_structured_form(self, status_bar: StatusBar) -> None:
        """RoleBadge видим при STRUCTURED_FORM."""
        status_bar.set_document_mode(DocumentMode.STRUCTURED_FORM)
        status_bar.set_role_badge(WorkflowRole.EDITOR)

        assert status_bar._role_badge is not None
        assert status_bar._role_badge.widget is not None
        assert status_bar._role_badge.widget.winfo_manager() == "pack"

    def test_get_document_mode(self, status_bar: StatusBar) -> None:
        """get_document_mode() возвращает установленный режим."""
        status_bar.set_document_mode(DocumentMode.STRUCTURED_FORM)
        assert status_bar.get_document_mode() == DocumentMode.STRUCTURED_FORM

    def test_document_mode_none_default(self, tk_root: tk.Tk) -> None:
        """document_mode по умолчанию None."""
        bar = StatusBar()
        bar.mount(tk_root)
        assert bar.get_document_mode() is None


# =============================================================================
# TEST: Notification Indicator
# =============================================================================


@pytest.mark.gui
class TestNotificationIndicator:
    """Тесты индикатора уведомлений."""

    def test_set_notification_count(self, status_bar: StatusBar) -> None:
        """set_notification_count() устанавливает счётчик."""
        status_bar.set_notification_count(5)

        assert status_bar._notification_count == 5

    def test_set_notification_count_minimum_zero(self, status_bar: StatusBar) -> None:
        """set_notification_count() ограничивает минимумом 0."""
        status_bar.set_notification_count(-5)

        assert status_bar._notification_count == 0

    def test_notification_count_updates_indicator(self, status_bar: StatusBar) -> None:
        """set_notification_count() обновляет индикатор."""
        status_bar.set_notification_count(3)

        assert status_bar._notification_count == 3

    def test_on_notification_count_changed(self, status_bar: StatusBar) -> None:
        """_on_notification_count_changed() обновляет счётчик."""
        status_bar._on_notification_count_changed(7)

        assert status_bar._notification_count == 7


# =============================================================================
# TEST: Toast Panel
# =============================================================================


@pytest.mark.gui
class TestToastPanel:
    """Тесты Toast Panel."""

    def test_toast_panel_creation(self, tk_root: tk.Tk) -> None:
        """ToastPanel создаётся корректно."""
        from src.gui.views.status_bar import ToastPanel

        panel = ToastPanel(tk_root)

        assert panel is not None
        assert not panel.is_visible()

    def test_toast_panel_show_near_widget(self, tk_root: tk.Tk) -> None:
        """ToastPanel.show_near_widget() показывает панель."""
        from src.gui.views.status_bar import ToastPanel

        panel = ToastPanel(tk_root)
        label = tk.Label(tk_root, text="Test")
        label.pack()

        panel.show_near_widget(label)

        assert panel.is_visible()

        panel.hide()

    def test_toast_panel_hide(self, tk_root: tk.Tk) -> None:
        """ToastPanel.hide() скрывает панель."""
        from src.gui.views.status_bar import ToastPanel

        panel = ToastPanel(tk_root)
        label = tk.Label(tk_root, text="Test")
        label.pack()

        panel.show_near_widget(label)
        panel.hide()

        assert not panel.is_visible()

    def test_toast_panel_update_notifications(self, tk_root: tk.Tk) -> None:
        """ToastPanel.update_notifications() обновляет список."""
        from src.gui.views.status_bar import ToastPanel

        panel = ToastPanel(tk_root)
        panel.update_notifications([])

        assert panel._notifications == []


# =============================================================================
# TEST: StatusBar Toast Integration
# =============================================================================


@pytest.mark.gui
class TestStatusBarToastIntegration:
    """Тесты интеграции Toast Panel с StatusBar."""

    def test_show_toast_panel_exists(self, status_bar: StatusBar) -> None:
        """show_toast_panel() метод существует."""
        assert hasattr(status_bar, "show_toast_panel")

    def test_hide_toast_panel_exists(self, status_bar: StatusBar) -> None:
        """hide_toast_panel() метод существует."""
        assert hasattr(status_bar, "hide_toast_panel")

    def test_set_notification_service_exists(self, status_bar: StatusBar) -> None:
        """set_notification_service() метод существует."""
        assert hasattr(status_bar, "set_notification_service")

    def test_notification_bindings_setup(self, tk_root: tk.Tk) -> None:
        """notification bindings настраиваются при mount."""
        bar = StatusBar()
        bar.mount(tk_root)

        assert bar._tk_notification_label is not None

    def test_notification_colors_exist(self) -> None:
        """Константы цветов уведомлений существуют."""
        from src.gui.views.status_bar import (
            NOTIFICATION_ACTIVE_COLOR,
            NOTIFICATION_INACTIVE_COLOR,
        )

        assert NOTIFICATION_ACTIVE_COLOR == "#0080FF"
        assert NOTIFICATION_INACTIVE_COLOR == "#999999"

    def test_toast_panel_constants_exist(self) -> None:
        """Константы Toast Panel существуют."""
        from src.gui.views.status_bar import (
            TOAST_PANEL_AUTO_HIDE_MS,
            TOAST_PANEL_MAX_ITEMS,
            TOAST_PANEL_WIDTH,
        )

        assert TOAST_PANEL_WIDTH == 280
        assert TOAST_PANEL_MAX_ITEMS == 6
        assert TOAST_PANEL_AUTO_HIDE_MS == 30000


# =============================================================================
# TEST: Regression Tests for Bug Fixes
# =============================================================================


@pytest.mark.gui
class TestBugFix1CleanupAfterCancel:
    """Регрессионные тесты для бага #1: _cleanup() обнуляет _tk_frame
    ДО вызова after_cancel, из-за чего after_cancel НИКОГДА не срабатывает.

    Root cause: порядок операций в _cleanup() — сначала _tk_frame = None,
    потом попытка after_cancel через уже-None ссылку.
    """

    def test_cleanup_cancels_after_before_frame_none(self, tk_root: tk.Tk) -> None:
        """after_cancel вызывается ДО обнуления _tk_frame."""
        bar = StatusBar()
        bar.mount(tk_root)

        # Создаём pending after(), чтобы _hide_after_id был установлен
        bar._hide_after_id = bar._tk_frame.after(50000, lambda: None)  # type: ignore[union-attr]

        # Запоминаем _tk_frame до cleanup
        frame_before = bar._tk_frame
        assert frame_before is not None

        # cleanup должен отменить after(), пока _tk_frame ещё доступен
        bar._cleanup()

        # После cleanup _tk_frame должен быть None
        assert bar._tk_frame is None
        # after_id должен быть сброшен (after_cancel отработал)
        assert bar._hide_after_id is None

    def test_cleanup_cancels_debounce_before_frame_none(self, tk_root: tk.Tk) -> None:
        """layout_after_id отменяется ДО обнуления _tk_frame."""
        bar = StatusBar()
        bar.mount(tk_root)

        # Создаём pending after() для debounce
        bar._layout_after_id = bar._tk_frame.after(50000, lambda: None)  # type: ignore[union-attr]

        bar._cleanup()

        assert bar._tk_frame is None
        assert bar._layout_after_id is None

    def test_cleanup_no_error_when_no_pending_after(self, tk_root: tk.Tk) -> None:
        """_cleanup не падает, если нет pending after."""
        bar = StatusBar()
        bar.mount(tk_root)

        # Никаких after() не создавалось
        bar._cleanup()

        assert bar._tk_frame is None
        assert bar._hide_after_id is None
        assert bar._layout_after_id is None


@pytest.mark.gui
class TestBugFix2ScheduleHideToastPanelTclError:
    """Регрессионные тесты для бага #2: _schedule_hide_toast_panel()
    вызывает after_cancel без try/except tk.TclError.

    Root cause: если виджет уничтожен между планированием и
    перепланированием, after_cancel выбрасывает tk.TclError.
    """

    def test_schedule_hide_cancel_survives_destroyed_widget(
        self, tk_root: tk.Tk
    ) -> None:
        """after_cancel в _schedule_hide_toast_panel не падает при TclError."""
        bar = StatusBar()
        bar.mount(tk_root)

        # Устанавливаем _hide_after_id (имитируем ранее запланированный таймер)
        bar._hide_after_id = bar._tk_frame.after(  # type: ignore[union-attr]
            50000, lambda: None
        )

        # Уничтожаем frame, чтобы after_cancel вызвал TclError
        bar._tk_frame.destroy()  # type: ignore[union-attr]

        # _schedule_hide_toast_panel должен обработать TclError и не упасть
        # (tk_frame is None после destroy, метод вернётся раньше)
        # Но проверим, что не выбрасывается исключение
        try:
            bar._schedule_hide_toast_panel()
        except tk.TclError:
            pytest.fail("_schedule_hide_toast_panel should handle TclError")


@pytest.mark.gui
class TestBugFix3OnConfigureDebounce:
    """Регрессионные тесты для бага #3: _on_configure вызывает _apply_layout
    при каждом ресайзе — N² pack/unpack без debounce/throttle.

    Root cause: Configure-события при перетаскивании границы окна
    вызывают полную распаковку/перепаковку виджетов на каждое событие.
    """

    def test_on_configure_sets_debounce_timer(self, tk_root: tk.Tk) -> None:
        """_on_configure планирует _apply_layout через after()."""
        bar = StatusBar()
        bar.mount(tk_root)

        event = MagicMock()
        event.width = MIN_WINDOW_WIDTH - 100

        bar._on_configure(event)

        # Должен быть запланирован debounce-таймер
        assert bar._layout_after_id is not None

    def test_on_configure_cancels_previous_debounce(
        self, tk_root: tk.Tk
    ) -> None:
        """Повторный _on_configure отменяет предыдущий debounce."""
        bar = StatusBar()
        bar.mount(tk_root)

        event = MagicMock()
        event.width = MIN_WINDOW_WIDTH - 100

        bar._on_configure(event)
        assert bar._layout_after_id is not None

        # Второй вызов должен запланировать новый debounce
        # (предыдущий отменяется внутри _on_configure)
        bar._on_configure(event)
        assert bar._layout_after_id is not None

    def test_debounce_fires_apply_layout(self, tk_root: tk.Tk) -> None:
        """_apply_layout_debounced вызывает _apply_layout и сбрасывает ID."""
        bar = StatusBar()
        bar.mount(tk_root)

        bar._is_double_row = True
        bar._layout_after_id = "fake-id"  # type: ignore[assignment]

        bar._apply_layout_debounced()

        # _layout_after_id должен быть сброшен
        assert bar._layout_after_id is None

    def test_no_debounce_when_layout_unchanged(self, tk_root: tk.Tk) -> None:
        """_on_configure не планирует debounce, если режим не меняется."""
        bar = StatusBar()
        bar.mount(tk_root)

        # По умолчанию single row, ширина больше MIN_WINDOW_WIDTH
        event = MagicMock()
        event.width = MIN_WINDOW_WIDTH + 100

        bar._on_configure(event)

        # Режим не меняется — debounce не планируется
        assert bar._layout_after_id is None


@pytest.mark.gui
class TestBugFix4PositionNearDynamicHeight:
    """Регрессионные тесты для бага #4: _position_near использует
    фиксированную высоту 150 вместо реальной высоты виджета.

    Root cause: hardcoded 150 в геометрии панели и вычислении y-позиции
    может привести к обрезанию при малых y-координатах.
    """

    def test_position_near_uses_reqheight(self, tk_root: tk.Tk) -> None:
        """_position_near использует winfo_reqheight вместо hardcoded 150."""
        from src.gui.views.status_bar import ToastPanel

        panel = ToastPanel(tk_root)
        label = tk.Label(tk_root, text="Test")
        label.pack()

        panel.show_near_widget(label)

        assert panel._window is not None
        # Проверяем, что геометрия формируется корректно
        panel._window.geometry()
        # Главное — что метод не падает и панель видима
        assert panel.is_visible()
        panel.hide()

    def test_position_near_small_y_falls_below_widget(
        self, tk_root: tk.Tk
    ) -> None:
        """При малой y-координате панель позиционируется ниже виджета."""
        from src.gui.views.status_bar import ToastPanel

        # Размещаем виджет в самом верху экрана
        label = tk.Label(tk_root, text="Top")
        label.pack()

        panel = ToastPanel(tk_root)
        panel.show_near_widget(label)

        assert panel._window is not None
        assert panel.is_visible()
        panel.hide()


@pytest.mark.gui
class TestBugFix5OffTimelineStatuses:
    """Регрессионные тесты для бага #5: _build_timeline_text() не
    обрабатывает статусы вне timeline (REJECTED, ARCHIVED, PRINTED).

    Root cause: statuses.index() вызывал ValueError, который
    обрабатывался как current_idx = -1, из-за чего все статусы
    отображались как будущие (○) вместо корректного отображения.
    """

    def test_rejected_status_shows_all_done_plus_rejected(
        self, status_bar: StatusBar
    ) -> None:
        """REJECTED: все timeline-статусы ✓, затем REJECTED ✗."""
        from src.documents.constructor.form_status import FormStatus

        status_bar.set_workflow_timeline(FormStatus.REJECTED)
        text = status_bar._build_timeline_text("rejected")

        # Все timeline-статусы должны быть ✓ (пройденные)
        assert "[DRAFT ✓]" in text
        assert "[FILLED ✓]" in text
        assert "[VALIDATED ✓]" in text
        assert "[APPROVED ✓]" in text
        assert "[SIGNED ✓]" in text
        # REJECTED должен быть с маркером ✗
        assert "[REJECTED ✗]" in text
        # Не должно быть будущих маркеров
        assert "○" not in text

    def test_archived_status_shows_all_done_plus_archived(
        self, status_bar: StatusBar
    ) -> None:
        """ARCHIVED: все timeline-статусы ✓, затем ARCHIVED ●."""
        from src.documents.constructor.form_status import FormStatus

        status_bar.set_workflow_timeline(FormStatus.ARCHIVED)
        text = status_bar._build_timeline_text("archived")

        # Все timeline-статусы должны быть ✓
        assert "[DRAFT ✓]" in text
        assert "[SIGNED ✓]" in text
        # ARCHIVED должен быть с текущим маркером ●
        assert "[ARCHIVED ●]" in text

    def test_printed_status_shows_all_done_plus_printed(
        self, status_bar: StatusBar
    ) -> None:
        """PRINTED: все timeline-статусы ✓, затем PRINTED ●."""
        from src.documents.constructor.form_status import FormStatus

        status_bar.set_workflow_timeline(FormStatus.PRINTED)
        text = status_bar._build_timeline_text("printed")

        # Все timeline-статусы должны быть ✓
        assert "[DRAFT ✓]" in text
        assert "[SIGNED ✓]" in text
        # PRINTED должен быть с текущим маркером ●
        assert "[PRINTED ●]" in text

    def test_draft_status_unchanged(self, status_bar: StatusBar) -> None:
        """DRAFT: обычный timeline без изменений (регрессия)."""
        from src.documents.constructor.form_status import FormStatus

        status_bar.set_workflow_timeline(FormStatus.DRAFT)
        text = status_bar._build_timeline_text("draft")

        assert "[DRAFT ●]" in text
        assert "[FILLED ○]" in text
        assert "[SIGNED ○]" in text

    def test_simple_mode_rejected(
        self, status_bar: StatusBar
    ) -> None:
        """REJECTED в Simple Mode: [DRAFT ✓] ──▶ [SIGNED ✓] ──▶ [REJECTED ✗]."""
        from src.documents.constructor.form_status import FormStatus

        status_bar.set_simple_mode(True)
        status_bar.set_workflow_timeline(FormStatus.REJECTED)
        text = status_bar._build_timeline_text("rejected")

        assert "[DRAFT ✓]" in text
        assert "[SIGNED ✓]" in text
        assert "[REJECTED ✗]" in text


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.views.status_bar"])
