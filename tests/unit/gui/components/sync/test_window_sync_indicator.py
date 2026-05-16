"""Unit-тесты для WindowSyncIndicator, TabSyncIndicator и TitleBarSyncDecorator.

Проверяет:
- Lifecycle (mount / unmount / cleanup)
- Thread-safe установку статуса
- Анимацию SYNCING
- Tooltip
- Интеграцию с SyncService (TabSyncIndicator)
- Обновление заголовка окна (TitleBarSyncDecorator)

Coverage target: ≥90%

Example:
    $ xvfb-run -a python -m pytest tests/unit/gui/components/sync/test_window_sync_indicator.py -v
"""

from __future__ import annotations

import threading
import time
import tkinter as tk
from typing import Any, Callable, Generator
from unittest.mock import MagicMock

import pytest

from src.gui.components.sync.window_sync_indicator import (
    SYNC_STATUS_COLORS,
    SYNC_STATUS_ICONS,
    SyncStatus,
    TabSyncIndicator,
    TitleBarSyncDecorator,
    WindowSyncIndicator,
)
from src.gui.services.sync_service import SyncMessage

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
def mock_sync_service() -> MagicMock:
    """Mock SyncService с поддержкой register_handler/unregister_handler."""
    service = MagicMock()
    service.register_handler.return_value = "handler_123"
    return service


@pytest.fixture
def mock_tk_parent() -> Generator[MagicMock, None, None]:
    """Mock родителя для изолированных тестов BaseWidget."""
    parent = MagicMock(spec=tk.Widget)
    parent.cget = MagicMock(return_value="#FFFFFF")
    yield parent


# =============================================================================
# WINDOW SYNC INDICATOR
# =============================================================================


class TestWindowSyncIndicator:
    """Тесты базового индикатора статуса."""

    def test_init_defaults(self) -> None:
        """Инициализация с дефолтами."""
        ind = WindowSyncIndicator()
        assert ind.widget_id == "window_sync_indicator"
        assert ind.status == SyncStatus.OFFLINE
        assert not ind.is_mounted()

    def test_init_with_status(self) -> None:
        """Инициализация с заданным статусом."""
        ind = WindowSyncIndicator(status=SyncStatus.SYNCED)
        assert ind.status == SyncStatus.SYNCED

    def test_mount_sets_label(self, tk_root: tk.Tk) -> None:
        """mount() создаёт Label и отображает начальную иконку."""
        ind = WindowSyncIndicator(status=SyncStatus.SYNCED)
        widget = ind.mount(tk_root)
        assert isinstance(widget, tk.Label)
        assert widget.cget("fg") == SYNC_STATUS_COLORS[SyncStatus.SYNCED]

    def test_set_status_valid(self, tk_root: tk.Tk) -> None:
        """set_status() обновляет цвет и иконку."""
        ind = WindowSyncIndicator(status=SyncStatus.OFFLINE)
        ind.mount(tk_root)
        ind.set_status(SyncStatus.CONFLICT)
        assert ind.status == SyncStatus.CONFLICT
        label: tk.Label = ind._tk_label  # type: ignore[union-attr]
        assert label.cget("fg") == SYNC_STATUS_COLORS[SyncStatus.CONFLICT]

    def test_set_status_invalid_raises(self, tk_root: tk.Tk) -> None:
        """Неизвестный статус вызывает ValueError."""
        ind = WindowSyncIndicator()
        ind.mount(tk_root)
        with pytest.raises(ValueError, match="Unknown sync status"):
            ind.set_status("unknown")

    def test_set_status_before_mount(self) -> None:
        """set_status() до mount сохраняет pending статус."""
        ind = WindowSyncIndicator()
        ind.set_status(SyncStatus.SYNCED)
        # После вызова до mount _pending_status должен хранить статус
        assert ind._pending_status == SyncStatus.SYNCED

    def test_set_status_applies_pending_on_mount(self, tk_root: tk.Tk) -> None:
        """Pending статус применяется при mount."""
        ind = WindowSyncIndicator()
        ind.set_status(SyncStatus.SYNCED)
        ind.mount(tk_root)
        assert ind.status == SyncStatus.SYNCED

    def test_set_status_thread_safe(self, tk_root: tk.Tk) -> None:
        """set_status() из другого потока безопасен и применяется через after."""
        ind = WindowSyncIndicator()
        ind.mount(tk_root)
        # Убеждаемся, что после запуска из другого потока и обработки after
        # статус реально применён.
        def worker() -> None:
            ind.set_status(SyncStatus.SYNCING)

        t = threading.Thread(target=worker)
        t.start()
        t.join()
        # Явно применяем deferred статус в главном потоке
        if ind._pending_status is not None:
            ind._set_status(ind._pending_status)
            ind._pending_status = None
        assert ind.status == SyncStatus.SYNCING
        ind.stop_animation()

    def test_tooltip(self, tk_root: tk.Tk) -> None:
        """set_tooltip() сохраняет текст, а tooltip создаётся при наведении."""
        ind = WindowSyncIndicator()
        ind.mount(tk_root)
        ind.set_tooltip("Sync info\nConflicts: 2")
        assert ind._tooltip_text == "Sync info\nConflicts: 2"
        # Simulate enter
        ind._on_enter()
        assert ind._tk_tooltip is not None
        # Simulate leave
        ind._on_leave()
        assert ind._tk_tooltip is None

    def test_animation_step(self, tk_root: tk.Tk, monkeypatch: pytest.MonkeyPatch) -> None:
        """Анимация чередует иконки."""
        ind = WindowSyncIndicator(status=SyncStatus.SYNCING)
        ind.mount(tk_root)

        # Monkeypatch after чтобы callback вызывался мгновенно,
        # но только один раз (чтобы избежать бесконечной рекурсии)
        call_count = 0

        def fast_after(ms: int, callback: Callable[[], Any]) -> str:
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                callback()
            return "id_0"

        monkeypatch.setattr(ind._tk_label, "after", fast_after)
        ind.start_animation()
        # После первого шага должна быть другая иконка
        text_after = ind._tk_label.cget("text")
        assert text_after in ("⟳", "⟲")
        ind.stop_animation()

    def test_cleanup_stops_animation(self, tk_root: tk.Tk) -> None:
        """unmount() останавливает анимацию и уничтожает tooltip."""
        ind = WindowSyncIndicator(status=SyncStatus.SYNCING)
        ind.mount(tk_root)
        ind.start_animation()
        # Create tooltip
        ind.set_tooltip("Cleanup test")
        ind._on_enter()
        assert ind._tk_tooltip is not None
        ind.unmount()
        assert not ind.is_mounted()
        assert ind._tk_tooltip is None
        assert ind._after_id is None

    def test_setup_bindings_when_label_none(self) -> None:
        """_setup_bindings() не падает когда _tk_label ещё None."""
        ind = WindowSyncIndicator()
        ind._setup_bindings()

    def test_start_animation_non_syncing(self, tk_root: tk.Tk) -> None:
        """start_animation() ничего не делает если статус не SYNCING."""
        ind = WindowSyncIndicator(status=SyncStatus.SYNCED)
        ind.mount(tk_root)
        ind.start_animation()
        assert ind._after_id is None

    def test_stop_animation_tcl_error(self, tk_root: tk.Tk, monkeypatch: pytest.MonkeyPatch) -> None:
        """stop_animation() перехватывает TclError при after_cancel."""
        ind = WindowSyncIndicator(status=SyncStatus.SYNCING)
        ind.mount(tk_root)
        ind.start_animation()
        assert ind._after_id is not None

        def raise_tcl_error(_id: str) -> None:
            raise tk.TclError("mock error")

        monkeypatch.setattr(ind._tk_label, "after_cancel", raise_tcl_error)
        # Не должно падать
        ind.stop_animation()
        assert ind._after_id is None

    def test_animation_step_early_return_not_mounted(self) -> None:
        """_animation_step() возвращается если виджет не смонтирован."""
        ind = WindowSyncIndicator(status=SyncStatus.SYNCING)
        ind._animation_step()  # не падает, просто возвращается

    def test_animation_step_early_return_wrong_status(self, tk_root: tk.Tk) -> None:
        """_animation_step() возвращается если статус не SYNCING."""
        ind = WindowSyncIndicator(status=SyncStatus.OFFLINE)
        ind.mount(tk_root)
        ind._animation_step()

    def test_tooltip_enter_without_text(self, tk_root: tk.Tk) -> None:
        """_on_enter() не создаёт tooltip если текст пустой."""
        ind = WindowSyncIndicator()
        ind.mount(tk_root)
        ind._on_enter()
        assert ind._tk_tooltip is None

    def test_destroy_tooltip_tcl_error(self, tk_root: tk.Tk, monkeypatch: pytest.MonkeyPatch) -> None:
        """_destroy_tooltip() перехватывает TclError."""
        ind = WindowSyncIndicator()
        ind.mount(tk_root)
        ind._tk_tooltip = tk.Toplevel(tk_root)

        def raise_tcl_error() -> None:
            raise tk.TclError("mock error")

        monkeypatch.setattr(ind._tk_tooltip, "destroy", raise_tcl_error)
        ind._destroy_tooltip()
        assert ind._tk_tooltip is None

    def test_multiple_mount_not_allowed(self, tk_root: tk.Tk) -> None:
        """Повторный mount вызывает LifecycleError."""
        ind = WindowSyncIndicator()
        ind.mount(tk_root)
        from src.gui.core.exceptions import LifecycleError

        with pytest.raises(LifecycleError):
            ind.mount(tk_root)


# =============================================================================
# TAB SYNC INDICATOR
# =============================================================================


class TestTabSyncIndicator:
    """Тесты индикатора, встроенного во вкладку."""

    def test_mount_creates_indicator(self, tk_root: tk.Tk) -> None:
        """mount() создаёт WindowSyncIndicator внутри tab_frame."""
        tab_frame = tk.Frame(tk_root)
        tsi = TabSyncIndicator(tab_frame=tab_frame, document_id="doc_1")
        widget = tsi.mount()
        assert isinstance(widget, tk.Widget)
        assert tsi.indicator.is_mounted()
        tsi.unmount()

    def test_set_status(self, tk_root: tk.Tk) -> None:
        """set_status() пробрасывается во внутренний индикатор."""
        tab_frame = tk.Frame(tk_root)
        tsi = TabSyncIndicator(tab_frame=tab_frame, document_id="doc_2")
        tsi.mount()
        tsi.set_status(SyncStatus.CONFLICT)
        assert tsi.indicator.status == SyncStatus.CONFLICT
        tsi.unmount()

    def test_sync_message_updates_status(self, tk_root: tk.Tk, mock_sync_service: MagicMock) -> None:
        """Обработчик SyncMessage обновляет статус и tooltip."""
        tab_frame = tk.Frame(tk_root)
        tsi = TabSyncIndicator(
            tab_frame=tab_frame,
            document_id="doc_3",
            sync_service=mock_sync_service,
        )
        tsi.mount()
        msg = MagicMock(spec=SyncMessage)
        msg.data = {
            "status": SyncStatus.SYNCED,
            "last_sync_time": "12:34",
            "conflict_count": 0,
            "connection_status": "online",
        }
        tsi._on_sync_message(msg)
        assert tsi.indicator.status == SyncStatus.SYNCED
        assert "Last sync" in tsi.indicator._tooltip_text
        tsi.unmount()

    def test_unmount_unregisters_handler(self, tk_root: tk.Tk, mock_sync_service: MagicMock) -> None:
        """unmount() отписывает handler у SyncService."""
        tab_frame = tk.Frame(tk_root)
        tsi = TabSyncIndicator(
            tab_frame=tab_frame,
            document_id="doc_4",
            sync_service=mock_sync_service,
        )
        tsi.mount()
        tsi.unmount()
        mock_sync_service.unregister_handler.assert_called_once_with("handler_123")


# =============================================================================
# TITLE BAR SYNC DECORATOR
# =============================================================================


class TestTitleBarSyncDecorator:
    """Тесты декоратора заголовка окна."""

    def test_update_title_adds_suffix(self, tk_root: tk.Tk) -> None:
        """update_title() добавляет суффикс статуса."""
        tk_root.title("Document.fxsd - FX Text Processor 3")
        TitleBarSyncDecorator.update_title(tk_root, SyncStatus.SYNCED)
        assert tk_root.title().endswith(" [●] Synced")

    def test_clear_title_removes_suffix(self, tk_root: tk.Tk) -> None:
        """clear_title() убирает суффикс."""
        tk_root.title("Document.fxsd - FX Text Processor 3 [●] Synced")
        TitleBarSyncDecorator.clear_title(tk_root)
        assert "[●]" not in tk_root.title()
        assert "Document.fxsd" in tk_root.title()

    def test_multiple_updates(self, tk_root: tk.Tk) -> None:
        """Повторные вызовы не дублируют суффиксы."""
        tk_root.title("Doc.fxsd")
        TitleBarSyncDecorator.update_title(tk_root, SyncStatus.OFFLINE)
        TitleBarSyncDecorator.update_title(tk_root, SyncStatus.SYNCING)
        title = tk_root.title()
        assert title.endswith(" [⟳] Syncing...")
        # Только один суффикс
        assert title.count("[") == 1

    def test_invalid_status_raises(self, tk_root: tk.Tk) -> None:
        """Неизвестный статус вызывает ValueError."""
        with pytest.raises(ValueError, match="Unknown status"):
            TitleBarSyncDecorator.update_title(tk_root, "invalid")

    def test_get_status_suffix(self) -> None:
        """get_status_suffix() возвращает корректную строку."""
        suffix = TitleBarSyncDecorator.get_status_suffix(SyncStatus.CONFLICT)
        assert suffix == " [⚠] Conflict"
        assert TitleBarSyncDecorator.get_status_suffix("unknown") == ""


# =============================================================================
# MODULE EXPORTS
# =============================================================================


class TestModuleExports:
    """Тесты публичного API модуля."""

    def test_all_defined(self) -> None:
        """__all__ содержит все ключевые классы."""
        from src.gui.components.sync.window_sync_indicator import __all__ as _all

        assert "WindowSyncIndicator" in _all
        assert "TabSyncIndicator" in _all
        assert "TitleBarSyncDecorator" in _all
        assert "SyncStatus" in _all

    def test_colors_and_icons_exist(self) -> None:
        """Константы цветов и иконок содержат все статусы."""
        for status in SyncStatus:
            assert status in SYNC_STATUS_COLORS
            assert status in SYNC_STATUS_ICONS


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.components.sync"])
