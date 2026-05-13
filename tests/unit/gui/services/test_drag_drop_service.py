"""Unit-тесты для DragDropService сервиса.

Проверяет:
- Инициацию drag-and-drop операций
- Регистрацию и удаление целевых зон drop
- Управление состоянием перетаскивания
- Отмену операций drag-and-drop
- Валидацию drop операций
- Обновление визуальной обратной связи
- Граничные случаи и обработку ошибок

Coverage target: ≥90%
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Generator, Optional
from unittest.mock import MagicMock, patch

import pytest

# DragDropService будет импортирован из предполагаемого расположения
pytest.importorskip(
    "src.gui.services.drag_drop_service",
    reason="DragDropService not implemented yet"
)

from src.gui.services.drag_drop_service import (
    DragDropService,
    DragData,
    DropOperation,
    DropTarget,
)


# =============================================================================
# TEST DATA CLASSES
# =============================================================================


class DropOperation(Enum):
    """Операции drag-and-drop.

    Attributes:
        MOVE: Перемещение элемента.
        COPY: Копирование элемента.
        LINK: Создание ссылки.
    """

    MOVE = auto()
    COPY = auto()
    LINK = auto()


@dataclass(frozen=True)
class DragData:
    """Данные для drag-and-drop операции.

    Attributes:
        data_type: Тип данных ("text", "file", "document").
        content: Содержимое данных.
        source_window_id: Идентификатор исходного окна.
        operations: Допустимые операции (MOVE, COPY, LINK).

    Example:
        >>> data = DragData(
        ...     data_type="text",
        ...     content="Hello World",
        ...     source_window_id="win_001",
        ...     operations={DropOperation.MOVE, DropOperation.COPY}
        ... )
    """

    data_type: str
    content: Any
    source_window_id: str
    operations: frozenset[DropOperation] = field(
        default_factory=lambda: frozenset({DropOperation.MOVE})
    )


@dataclass
class DropTarget:
    """Целевая зона для drop операции.

    Attributes:
        target_id: Уникальный идентификатор целевой зоны.
        widget: Связанный Tkinter виджет.
        accepted_types: Множество принимаемых типов данных.
        accepted_operations: Множество принимаемых операций.
        on_drop: Callback функция при drop.
        on_enter: Callback функция при входе курсора.
        on_leave: Callback функция при выходе курсора.

    Example:
        >>> target = DropTarget(
        ...     target_id="target_001",
        ...     widget=canvas_widget,
        ...     accepted_types={"text", "document"},
        ...     accepted_operations={DropOperation.MOVE},
        ...     on_drop=lambda data: print(f"Dropped: {data}")
        ... )
    """

    target_id: str
    widget: tk.Widget
    accepted_types: frozenset[str]
    accepted_operations: frozenset[DropOperation]
    on_drop: Callable[[DragData], bool]
    on_enter: Optional[Callable[[], None]] = None
    on_leave: Optional[Callable[[], None]] = None


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def mock_window_manager() -> MagicMock:
    """Создаёт мок WindowManager.

    Returns:
        MagicMock с методами управления окнами.
    """
    wm = MagicMock()
    wm.get_window.return_value = MagicMock()
    wm.get_window_list.return_value = []
    return wm


@pytest.fixture
def mock_sync_service() -> MagicMock:
    """Создаёт мок SyncService для синхронизации между окнами.

    Returns:
        MagicMock с методом broadcast для отправки сообщений.
    """
    sync = MagicMock()
    sync.broadcast.return_value = None
    sync.send_to_window.return_value = None
    return sync


@pytest.fixture
def drag_drop_service(
    mock_window_manager: MagicMock,
    mock_sync_service: MagicMock,
) -> DragDropService:
    """Создаёт экземпляр DragDropService для тестов.

    Args:
        mock_window_manager: Мок менеджера окон.
        mock_sync_service: Мок сервиса синхронизации.

    Returns:
        Инициализированный DragDropService.
    """
    return DragDropService(
        window_manager=mock_window_manager,
        sync_service=mock_sync_service,
    )


@pytest.fixture
def sample_drag_data() -> DragData:
    """Создаёт образец данных для drag-and-drop.

    Returns:
        DragData с типом "text".
    """
    return DragData(
        data_type="text",
        content="Test content for drag",
        source_window_id="win_source_001",
        operations=frozenset({DropOperation.MOVE, DropOperation.COPY}),
    )


@pytest.fixture
def sample_drop_target() -> DropTarget:
    """Создаёт образец целевой зоны для drop.

    Returns:
        DropTarget с настроенными callback.
    """
    mock_widget = MagicMock(spec=tk.Widget)
    return DropTarget(
        target_id="target_001",
        widget=mock_widget,
        accepted_types=frozenset({"text", "document"}),
        accepted_operations=frozenset({DropOperation.MOVE, DropOperation.COPY}),
        on_drop=MagicMock(return_value=True),
        on_enter=MagicMock(),
        on_leave=MagicMock(),
    )


@pytest.fixture
def mock_root() -> Generator[tk.Tk, None, None]:
    """Создаёт mock root окно для тестов.

    Returns:
        Tk root window в скрытом состоянии.
    """
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def mock_toplevel(mock_root: tk.Tk) -> Generator[tk.Toplevel, None, None]:
    """Создаёт mock Toplevel окно для тестов.

    Args:
        mock_root: Корневое окно приложения.

    Yields:
        Toplevel окно для тестирования.
    """
    window = tk.Toplevel(mock_root)
    window.withdraw()
    yield window
    try:
        window.destroy()
    except tk.TclError:
        pass


# =============================================================================
# TEST: Drag Initiation
# =============================================================================


@pytest.mark.gui
class TestDragInitiation:
    """Тесты инициации drag-and-drop операций."""

    def test_start_drag_sets_dragging_state(
        self,
        drag_drop_service: DragDropService,
        sample_drag_data: DragData,
    ) -> None:
        """start_drag устанавливает состояние перетаскивания.

        Проверяет, что после вызова start_drag метод is_dragging
        возвращает True.
        """
        assert not drag_drop_service.is_dragging()

        drag_drop_service.start_drag(
            source_window_id="win_001",
            data=sample_drag_data,
        )

        assert drag_drop_service.is_dragging()

    def test_start_drag_creates_ghost_window(
        self,
        drag_drop_service: DragDropService,
        sample_drag_data: DragData,
    ) -> None:
        """start_drag создаёт ghost окно для визуальной обратной связи.

        Проверяет, что при начале drag создаётся окно-призрак
        для отображения перетаскиваемого элемента.
        """
        with patch.object(
            drag_drop_service, "_create_ghost_window"
        ) as mock_create_ghost:
            drag_drop_service.start_drag(
                source_window_id="win_001",
                data=sample_drag_data,
            )

            mock_create_ghost.assert_called_once()

    def test_start_drag_stores_drag_data(
        self,
        drag_drop_service: DragDropService,
        sample_drag_data: DragData,
    ) -> None:
        """start_drag сохраняет данные перетаскивания.

        Проверяет, что данные drag доступны через get_drag_data.
        """
        drag_drop_service.start_drag(
            source_window_id="win_001",
            data=sample_drag_data,
        )

        stored_data = drag_drop_service.get_drag_data()

        assert stored_data is not None
        assert stored_data.data_type == sample_drag_data.data_type
        assert stored_data.content == sample_drag_data.content
        assert stored_data.source_window_id == sample_drag_data.source_window_id

    def test_start_drag_sends_sync_message(
        self,
        drag_drop_service: DragDropService,
        mock_sync_service: MagicMock,
        sample_drag_data: DragData,
    ) -> None:
        """start_drag отправляет сообщение синхронизации.

        Проверяет, что при начале drag отправляется broadcast
        сообщение для синхронизации с другими окнами.
        """
        drag_drop_service.start_drag(
            source_window_id="win_001",
            data=sample_drag_data,
        )

        mock_sync_service.broadcast.assert_called_once()
        call_args = mock_sync_service.broadcast.call_args
        assert call_args[0][0] == "win_001"  # source_window_id
        assert "drag_start" in call_args[0][1]  # data_type


# =============================================================================
# TEST: Drop Target Registration
# =============================================================================


@pytest.mark.gui
class TestDropTargetRegistration:
    """Тесты регистрации и удаления целевых зон drop."""

    def test_register_drop_target_returns_valid_id(
        self,
        drag_drop_service: DragDropService,
        mock_root: tk.Tk,
    ) -> None:
        """register_drop_target возвращает валидный идентификатор.

        Проверяет, что метод возвращает непустую строку ID.
        """
        mock_widget = tk.Label(mock_root)
        target = DropTarget(
            target_id="",
            widget=mock_widget,
            accepted_types=frozenset({"text"}),
            accepted_operations=frozenset({DropOperation.MOVE}),
            on_drop=MagicMock(return_value=True),
        )

        target_id = drag_drop_service.register_drop_target(
            widget=mock_widget,
            target=target,
        )

        assert isinstance(target_id, str)
        assert len(target_id) > 0

    def test_register_drop_target_stores_callback(
        self,
        drag_drop_service: DragDropService,
        sample_drop_target: DropTarget,
    ) -> None:
        """register_drop_target сохраняет callback функцию.

        Проверяет, что зарегистрированный callback вызывается
        при drop на целевую зону.
        """
        target_id = drag_drop_service.register_drop_target(
            widget=sample_drop_target.widget,
            target=sample_drop_target,
        )

        # Проверяем, что цель зарегистрирована
        assert drag_drop_service.is_target_registered(target_id)

    def test_unregister_drop_target_removes_from_registry(
        self,
        drag_drop_service: DragDropService,
        sample_drop_target: DropTarget,
    ) -> None:
        """unregister_drop_target удаляет цель из реестра.

        Проверяет, что после удаления цель больше не доступна.
        """
        target_id = drag_drop_service.register_drop_target(
            widget=sample_drop_target.widget,
            target=sample_drop_target,
        )

        assert drag_drop_service.is_target_registered(target_id)

        drag_drop_service.unregister_drop_target(target_id)

        assert not drag_drop_service.is_target_registered(target_id)


# =============================================================================
# TEST: Drag State
# =============================================================================


@pytest.mark.gui
class TestDragState:
    """Тесты состояния drag-and-drop операции."""

    def test_is_dragging_returns_true_after_start(
        self,
        drag_drop_service: DragDropService,
        sample_drag_data: DragData,
    ) -> None:
        """is_dragging возвращает True после start_drag.

        Проверяет, что состояние перетаскивания активно после
        инициации drag.
        """
        assert not drag_drop_service.is_dragging()

        drag_drop_service.start_drag(
            source_window_id="win_001",
            data=sample_drag_data,
        )

        assert drag_drop_service.is_dragging()

    def test_is_dragging_returns_false_after_cancel(
        self,
        drag_drop_service: DragDropService,
        sample_drag_data: DragData,
    ) -> None:
        """is_dragging возвращает False после cancel_drag.

        Проверяет, что состояние перетаскивания сбрасывается
        при отмене операции.
        """
        drag_drop_service.start_drag(
            source_window_id="win_001",
            data=sample_drag_data,
        )
        assert drag_drop_service.is_dragging()

        drag_drop_service.cancel_drag()

        assert not drag_drop_service.is_dragging()

    def test_is_dragging_returns_false_after_drop(
        self,
        drag_drop_service: DragDropService,
        sample_drag_data: DragData,
        sample_drop_target: DropTarget,
    ) -> None:
        """is_dragging возвращает False после успешного drop.

        Проверяет, что состояние перетаскивания сбрасывается
        после завершения drop.
        """
        drag_drop_service.start_drag(
            source_window_id="win_001",
            data=sample_drag_data,
        )

        target_id = drag_drop_service.register_drop_target(
            widget=sample_drop_target.widget,
            target=sample_drop_target,
        )

        # Симулируем drop
        drag_drop_service.drop(target_id=target_id)

        assert not drag_drop_service.is_dragging()

    def test_get_drag_data_returns_current_data(
        self,
        drag_drop_service: DragDropService,
        sample_drag_data: DragData,
    ) -> None:
        """get_drag_data возвращает текущие данные drag.

        Проверяет, что метод возвращает актуальные данные
        перетаскивания.
        """
        drag_drop_service.start_drag(
            source_window_id="win_001",
            data=sample_drag_data,
        )

        current_data = drag_drop_service.get_drag_data()

        assert current_data == sample_drag_data

    def test_get_drag_data_returns_none_when_not_dragging(
        self,
        drag_drop_service: DragDropService,
    ) -> None:
        """get_drag_data возвращает None когда drag не активен.

        Проверяет, что метод возвращает None до начала drag
        и после его завершения.
        """
        assert drag_drop_service.get_drag_data() is None


# =============================================================================
# TEST: Cancel
# =============================================================================


@pytest.mark.gui
class TestCancel:
    """Тесты отмены drag-and-drop операции."""

    def test_cancel_drag_destroys_ghost(
        self,
        drag_drop_service: DragDropService,
        sample_drag_data: DragData,
    ) -> None:
        """cancel_drag уничтожает ghost окно.

        Проверяет, что при отмене drag удаляется окно-призрак.
        """
        drag_drop_service.start_drag(
            source_window_id="win_001",
            data=sample_drag_data,
        )

        with patch.object(
            drag_drop_service, "_destroy_ghost_window"
        ) as mock_destroy_ghost:
            drag_drop_service.cancel_drag()

            mock_destroy_ghost.assert_called_once()

    def test_cancel_drag_clears_dragging_state(
        self,
        drag_drop_service: DragDropService,
        sample_drag_data: DragData,
    ) -> None:
        """cancel_drag очищает состояние перетаскивания.

        Проверяет, что после отмены состояние drag сбрасывается.
        """
        drag_drop_service.start_drag(
            source_window_id="win_001",
            data=sample_drag_data,
        )
        assert drag_drop_service.is_dragging()
        assert drag_drop_service.get_drag_data() is not None

        drag_drop_service.cancel_drag()

        assert not drag_drop_service.is_dragging()
        assert drag_drop_service.get_drag_data() is None

    def test_cancel_drag_sends_sync_message(
        self,
        drag_drop_service: DragDropService,
        mock_sync_service: MagicMock,
        sample_drag_data: DragData,
    ) -> None:
        """cancel_drag отправляет сообщение синхронизации.

        Проверяет, что при отмене drag отправляется broadcast
        для синхронизации с другими окнами.
        """
        drag_drop_service.start_drag(
            source_window_id="win_001",
            data=sample_drag_data,
        )

        # Сбрасываем счётчик вызовов
        mock_sync_service.reset_mock()

        drag_drop_service.cancel_drag()

        mock_sync_service.broadcast.assert_called_once()
        call_args = mock_sync_service.broadcast.call_args
        assert "drag_cancel" in call_args[0][1]  # data_type


# =============================================================================
# TEST: Drop Validation
# =============================================================================


@pytest.mark.gui
class TestDropValidation:
    """Тесты валидации drop операций."""

    def test_drop_checks_accepted_types(
        self,
        drag_drop_service: DragDropService,
    ) -> None:
        """drop проверяет соответствие типов данных.

        Проверяет, что drop отклоняется если тип данных
        не входит в accepted_types цели.
        """
        # Создаём drag с типом "image"
        drag_data = DragData(
            data_type="image",
            content=b"image_data",
            source_window_id="win_001",
            operations=frozenset({DropOperation.MOVE}),
        )

        # Создаём цель, принимающую только "text" и "document"
        mock_widget = MagicMock(spec=tk.Widget)
        callback = MagicMock(return_value=True)
        target = DropTarget(
            target_id="target_001",
            widget=mock_widget,
            accepted_types=frozenset({"text", "document"}),
            accepted_operations=frozenset({DropOperation.MOVE}),
            on_drop=callback,
        )

        drag_drop_service.start_drag(
            source_window_id="win_001",
            data=drag_data,
        )

        target_id = drag_drop_service.register_drop_target(
            widget=mock_widget,
            target=target,
        )

        # Пытаемся выполнить drop
        result = drag_drop_service.drop(target_id=target_id)

        assert result is False
        callback.assert_not_called()

    def test_drop_checks_accepted_operations(
        self,
        drag_drop_service: DragDropService,
    ) -> None:
        """drop проверяет допустимость операции.

        Проверяет, что drop отклоняется если операция
        не входит в accepted_operations цели.
        """
        # Создаём drag с операцией LINK
        drag_data = DragData(
            data_type="text",
            content="test",
            source_window_id="win_001",
            operations=frozenset({DropOperation.LINK}),
        )

        # Создаём цель, принимающую только MOVE и COPY
        mock_widget = MagicMock(spec=tk.Widget)
        callback = MagicMock(return_value=True)
        target = DropTarget(
            target_id="target_001",
            widget=mock_widget,
            accepted_types=frozenset({"text"}),
            accepted_operations=frozenset({DropOperation.MOVE, DropOperation.COPY}),
            on_drop=callback,
        )

        drag_drop_service.start_drag(
            source_window_id="win_001",
            data=drag_data,
        )

        target_id = drag_drop_service.register_drop_target(
            widget=mock_widget,
            target=target,
        )

        # Пытаемся выполнить drop
        result = drag_drop_service.drop(target_id=target_id)

        assert result is False
        callback.assert_not_called()

    def test_drop_calls_callback_on_match(
        self,
        drag_drop_service: DragDropService,
        sample_drag_data: DragData,
    ) -> None:
        """drop вызывает callback при совпадении типа и операции.

        Проверяет, что callback вызывается когда тип данных
        и операция соответствуют ограничениям цели.
        """
        mock_widget = MagicMock(spec=tk.Widget)
        callback = MagicMock(return_value=True)
        target = DropTarget(
            target_id="target_001",
            widget=mock_widget,
            accepted_types=frozenset({"text", "document"}),
            accepted_operations=frozenset({DropOperation.MOVE, DropOperation.COPY}),
            on_drop=callback,
        )

        drag_drop_service.start_drag(
            source_window_id="win_001",
            data=sample_drag_data,
        )

        target_id = drag_drop_service.register_drop_target(
            widget=mock_widget,
            target=target,
        )

        result = drag_drop_service.drop(target_id=target_id)

        assert result is True
        callback.assert_called_once()
        # Проверяем, что callback вызван с данными drag
        call_args = callback.call_args[0][0]
        assert call_args.data_type == sample_drag_data.data_type
        assert call_args.content == sample_drag_data.content

    def test_drop_ignores_invalid_target(
        self,
        drag_drop_service: DragDropService,
        sample_drag_data: DragData,
    ) -> None:
        """drop игнорирует несуществующую цель.

        Проверяет, что при указании невалидного target_id
        операция завершается с ошибкой.
        """
        drag_drop_service.start_drag(
            source_window_id="win_001",
            data=sample_drag_data,
        )

        # Пытаемся выполнить drop на несуществующую цель
        result = drag_drop_service.drop(target_id="invalid_target_id")

        assert result is False


# =============================================================================
# TEST: Feedback
# =============================================================================


@pytest.mark.gui
class TestFeedback:
    """Тесты визуальной обратной связи при drag."""

    def test_update_feedback_changes_cursor(
        self,
        drag_drop_service: DragDropService,
        sample_drag_data: DragData,
    ) -> None:
        """update_feedback изменяет курсор мыши.

        Проверяет, что при перемещении курсора над целью
        курсор изменяется в соответствии с возможностью drop.
        """
        mock_widget = MagicMock(spec=tk.Widget)

        drag_drop_service.start_drag(
            source_window_id="win_001",
            data=sample_drag_data,
        )

        with patch.object(drag_drop_service, "_set_cursor") as mock_set_cursor:
            drag_drop_service.update_feedback(
                x=100,
                y=100,
                target_widget=mock_widget,
            )

            mock_set_cursor.assert_called_once()

    def test_update_feedback_on_can_drop_true(
        self,
        drag_drop_service: DragDropService,
        sample_drag_data: DragData,
    ) -> None:
        """update_feedback показывает доступность drop.

        Проверяет, что когда drop возможен, отображается
        индикатор "можно бросить".
        """
        mock_widget = MagicMock(spec=tk.Widget)
        target = DropTarget(
            target_id="target_001",
            widget=mock_widget,
            accepted_types=frozenset({"text"}),
            accepted_operations=frozenset({DropOperation.MOVE}),
            on_drop=MagicMock(return_value=True),
        )

        drag_drop_service.start_drag(
            source_window_id="win_001",
            data=sample_drag_data,
        )

        drag_drop_service.register_drop_target(
            widget=mock_widget,
            target=target,
        )

        with patch.object(
            drag_drop_service, "_show_drop_allowed_indicator"
        ) as mock_allowed:
            with patch.object(
                drag_drop_service, "_show_drop_denied_indicator"
            ) as mock_denied:
                drag_drop_service.update_feedback(
                    x=100,
                    y=100,
                    target_widget=mock_widget,
                )

                mock_allowed.assert_called_once()
                mock_denied.assert_not_called()

    def test_update_feedback_on_can_drop_false(
        self,
        drag_drop_service: DragDropService,
    ) -> None:
        """update_feedback показывает недоступность drop.

        Проверяет, что когда drop невозможен, отображается
        индикатор "нельзя бросить".
        """
        # Создаём drag с неподдерживаемым типом
        drag_data = DragData(
            data_type="unsupported_type",
            content="test",
            source_window_id="win_001",
            operations=frozenset({DropOperation.MOVE}),
        )

        mock_widget = MagicMock(spec=tk.Widget)
        target = DropTarget(
            target_id="target_001",
            widget=mock_widget,
            accepted_types=frozenset({"text"}),
            accepted_operations=frozenset({DropOperation.MOVE}),
            on_drop=MagicMock(return_value=True),
        )

        drag_drop_service.start_drag(
            source_window_id="win_001",
            data=drag_data,
        )

        drag_drop_service.register_drop_target(
            widget=mock_widget,
            target=target,
        )

        with patch.object(
            drag_drop_service, "_show_drop_allowed_indicator"
        ) as mock_allowed:
            with patch.object(
                drag_drop_service, "_show_drop_denied_indicator"
            ) as mock_denied:
                drag_drop_service.update_feedback(
                    x=100,
                    y=100,
                    target_widget=mock_widget,
                )

                mock_allowed.assert_not_called()
                mock_denied.assert_called_once()


# =============================================================================
# TEST: Edge Cases
# =============================================================================


@pytest.mark.gui
class TestEdgeCases:
    """Тесты граничных случаев."""

    def test_drop_without_active_drag(
        self,
        drag_drop_service: DragDropService,
        sample_drop_target: DropTarget,
    ) -> None:
        """drop без активного drag возвращает False.

        Проверяет, что попытка выполнить drop без начала
        drag возвращает ошибку.
        """
        target_id = drag_drop_service.register_drop_target(
            widget=sample_drop_target.widget,
            target=sample_drop_target,
        )

        result = drag_drop_service.drop(target_id=target_id)

        assert result is False
        sample_drop_target.on_drop.assert_not_called()

    def test_start_drag_while_already_dragging(
        self,
        drag_drop_service: DragDropService,
        sample_drag_data: DragData,
    ) -> None:
        """start_drag при активном drag отменяет предыдущий.

        Проверяет, что при попытке начать новый drag во время
        активного предыдущего, старый drag отменяется.
        """
        first_data = DragData(
            data_type="text",
            content="first",
            source_window_id="win_001",
            operations=frozenset({DropOperation.MOVE}),
        )
        second_data = DragData(
            data_type="document",
            content="second",
            source_window_id="win_002",
            operations=frozenset({DropOperation.COPY}),
        )

        drag_drop_service.start_drag(
            source_window_id="win_001",
            data=first_data,
        )

        assert drag_drop_service.get_drag_data() == first_data

        # Начинаем второй drag - первый должен быть отменён
        with patch.object(drag_drop_service, "cancel_drag") as mock_cancel:
            drag_drop_service.start_drag(
                source_window_id="win_002",
                data=second_data,
            )

            mock_cancel.assert_called_once()

        # Проверяем, что активен второй drag
        assert drag_drop_service.is_dragging()
        assert drag_drop_service.get_drag_data() == second_data

    def test_unregister_nonexistent_target_raises_error(
        self,
        drag_drop_service: DragDropService,
    ) -> None:
        """unregister_drop_target вызывает ошибку для несуществующего ID.

        Проверяет, что попытка удалить несуществующую цель
        приводит к исключению.
        """
        with pytest.raises(KeyError, match="target"):
            drag_drop_service.unregister_drop_target("nonexistent_target_id")

    def test_multiple_targets_same_widget(
        self,
        drag_drop_service: DragDropService,
        mock_root: tk.Tk,
    ) -> None:
        """Можно зарегистрировать несколько целей на один виджет.

        Проверяет, что один виджет может иметь несколько
        целевых зон с разными ограничениями.
        """
        mock_widget = tk.Label(mock_root)

        target1 = DropTarget(
            target_id="",
            widget=mock_widget,
            accepted_types=frozenset({"text"}),
            accepted_operations=frozenset({DropOperation.MOVE}),
            on_drop=MagicMock(return_value=True),
        )
        target2 = DropTarget(
            target_id="",
            widget=mock_widget,
            accepted_types=frozenset({"document"}),
            accepted_operations=frozenset({DropOperation.COPY}),
            on_drop=MagicMock(return_value=True),
        )

        id1 = drag_drop_service.register_drop_target(
            widget=mock_widget,
            target=target1,
        )
        id2 = drag_drop_service.register_drop_target(
            widget=mock_widget,
            target=target2,
        )

        assert id1 != id2
        assert drag_drop_service.is_target_registered(id1)
        assert drag_drop_service.is_target_registered(id2)

    def test_drag_data_immutable(
        self,
        sample_drag_data: DragData,
    ) -> None:
        """DragData является immutable.

        Проверяет, что данные drag нельзя изменить после создания.
        """
        with pytest.raises((AttributeError, FrozenInstanceError)):
            sample_drag_data.data_type = "modified"  # type: ignore[misc]

    def test_sync_message_sent_on_drop(
        self,
        drag_drop_service: DragDropService,
        mock_sync_service: MagicMock,
        sample_drag_data: DragData,
    ) -> None:
        """drop отправляет сообщение синхронизации.

        Проверяет, что при успешном drop отправляется broadcast
        для синхронизации с другими окнами.
        """
        mock_widget = MagicMock(spec=tk.Widget)
        target = DropTarget(
            target_id="target_001",
            widget=mock_widget,
            accepted_types=frozenset({"text"}),
            accepted_operations=frozenset({DropOperation.MOVE}),
            on_drop=MagicMock(return_value=True),
        )

        drag_drop_service.start_drag(
            source_window_id="win_001",
            data=sample_drag_data,
        )

        target_id = drag_drop_service.register_drop_target(
            widget=mock_widget,
            target=target,
        )

        # Сбрасываем счётчик вызовов (start_drag уже отправил сообщение)
        mock_sync_service.reset_mock()

        drag_drop_service.drop(target_id=target_id)

        mock_sync_service.broadcast.assert_called_once()
        call_args = mock_sync_service.broadcast.call_args
        assert "drag_drop" in call_args[0][1]  # data_type

    def test_target_enter_leave_callbacks(
        self,
        drag_drop_service: DragDropService,
        sample_drag_data: DragData,
    ) -> None:
        """Целевая зона вызывает enter/leave callbacks.

        Проверяет, что при входе и выходе курсора из зоны
        вызываются соответствующие callbacks.
        """
        enter_callback = MagicMock()
        leave_callback = MagicMock()

        mock_widget = MagicMock(spec=tk.Widget)
        target = DropTarget(
            target_id="target_001",
            widget=mock_widget,
            accepted_types=frozenset({"text"}),
            accepted_operations=frozenset({DropOperation.MOVE}),
            on_drop=MagicMock(return_value=True),
            on_enter=enter_callback,
            on_leave=leave_callback,
        )

        drag_drop_service.start_drag(
            source_window_id="win_001",
            data=sample_drag_data,
        )

        drag_drop_service.register_drop_target(
            widget=mock_widget,
            target=target,
        )

        # Симулируем вход курсора
        drag_drop_service._on_target_enter("target_001")
        enter_callback.assert_called_once()

        # Симулируем выход курсора
        drag_drop_service._on_target_leave("target_001")
        leave_callback.assert_called_once()


# Import для type checking
from dataclasses import FrozenInstanceError
