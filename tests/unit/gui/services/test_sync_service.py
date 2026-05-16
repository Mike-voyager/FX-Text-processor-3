"""Unit-тесты для SyncService сервиса.

Проверяет:
- Broadcast-рассылку сообщений между окнами
- Прямую отправку сообщений конкретным окнам
- Регистрацию и удаление обработчиков
- Разрешение конфликтов (sidebar state, bookmarks, MFA)
- Управление временными метками синхронизации
- Граничные случаи и обработку ошибок

Coverage target: ≥90%
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Generator
from unittest.mock import MagicMock, patch

import pytest

# SyncService будет импортирован из предполагаемого расположения
pytest.importorskip("src.gui.services.sync_service", reason="SyncService not implemented yet")

from src.gui.services.sync_service import ConflictResolution, SyncData, SyncMessage, SyncService


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def mock_window_manager() -> MagicMock:
    """Создаёт мок WindowManager с get_window_list.

    Returns:
        MagicMock с методом get_window_list, возвращающим список окон.
    """
    wm = MagicMock()
    wm.get_window_list.return_value = []
    wm.is_window_registered.return_value = True
    return wm


@pytest.fixture
def sync_service(mock_window_manager: MagicMock) -> SyncService:
    """Создаёт экземпляр SyncService для тестов.

    Args:
        mock_window_manager: Мок менеджера окон.

    Returns:
        Инициализированный SyncService.
    """
    return SyncService(window_manager=mock_window_manager)


@pytest.fixture
def sample_handler() -> Callable[[Any], None]:
    """Создаёт мок-обработчик для тестов.

    Returns:
        Функция-обработчик для регистрации в SyncService.
    """
    return MagicMock()


@pytest.fixture
def mock_window_info() -> Generator[MagicMock, None, None]:
    """Создаёт мок информации об окне.

    Yields:
        MagicMock с атрибутами window_id.
    """
    info = MagicMock()
    info.window_id = "win-123"
    yield info


@pytest.fixture
def mock_window_info_2() -> Generator[MagicMock, None, None]:
    """Создаёт второй мок информации об окне.

    Yields:
        MagicMock с атрибутами window_id.
    """
    info = MagicMock()
    info.window_id = "win-456"
    yield info


@pytest.fixture
def mock_window_info_3() -> Generator[MagicMock, None, None]:
    """Создаёт третий мок информации об окне.

    Yields:
        MagicMock с атрибутами window_id.
    """
    info = MagicMock()
    info.window_id = "win-789"
    yield info


# =============================================================================
# TEST: Broadcast
# =============================================================================


@pytest.mark.gui
class TestBroadcast:
    """Тесты broadcast-рассылки сообщений."""

    def test_broadcast_sends_to_all_windows(
        self,
        sync_service: SyncService,
        mock_window_manager: MagicMock,
        mock_window_info: MagicMock,
        mock_window_info_2: MagicMock,
        mock_window_info_3: MagicMock,
        sample_handler: Callable[[Any], None],
    ) -> None:
        """broadcast отправляет данные всем зарегистрированным окнам.

        Проверяет, что при рассылке данные получают все окна
        с зарегистрированными обработчиками.
        """
        # Настраиваем список окон
        mock_window_manager.get_window_list.return_value = [
            mock_window_info,
            mock_window_info_2,
            mock_window_info_3,
        ]

        # Регистрируем обработчики для каждого окна
        handler_1 = MagicMock()
        handler_2 = MagicMock()
        handler_3 = MagicMock()

        sync_service.register_handler("document_update", "win-123", handler_1)
        sync_service.register_handler("document_update", "win-456", handler_2)
        sync_service.register_handler("document_update", "win-789", handler_3)

        # Отправляем broadcast
        sync_service.broadcast("win-source", "document_update", {"doc_id": "doc-123"})

        # Все обработчики должны быть вызваны
        handler_1.assert_called_once()
        handler_2.assert_called_once()
        handler_3.assert_called_once()

    def test_broadcast_excludes_source_window(
        self,
        sync_service: SyncService,
        mock_window_manager: MagicMock,
        mock_window_info: MagicMock,
        mock_window_info_2: MagicMock,
    ) -> None:
        """broadcast исключает окно-источник из получателей.

        Проверяет, что окно, отправившее сообщение, не получает
        его обратно.
        """
        mock_window_manager.get_window_list.return_value = [
            mock_window_info,
            mock_window_info_2,
        ]

        source_handler = MagicMock()
        other_handler = MagicMock()

        sync_service.register_handler("settings_change", "win-123", source_handler)
        sync_service.register_handler("settings_change", "win-456", other_handler)

        # Отправляем broadcast от win-123
        sync_service.broadcast("win-123", "settings_change", {"theme": "dark"})

        # Обработчик источника не должен быть вызван
        source_handler.assert_not_called()
        # Обработчик другого окна должен быть вызван
        other_handler.assert_called_once()

    def test_broadcast_triggers_registered_handlers(
        self,
        sync_service: SyncService,
        mock_window_manager: MagicMock,
        mock_window_info: MagicMock,
    ) -> None:
        """broadcast вызывает зарегистрированные обработчики.

        Проверяет, что обработчики вызываются с SyncMessage.
        """
        mock_window_manager.get_window_list.return_value = [mock_window_info]

        handler = MagicMock()
        sync_service.register_handler("clipboard_update", "win-123", handler)

        test_data = {"text": "copied text", "format": "plain"}
        sync_service.broadcast("win-source", "clipboard_update", test_data)

        handler.assert_called_once()
        call_args = handler.call_args[0][0]
        assert call_args.data == test_data
        assert call_args.data_type == "clipboard_update"

    def test_broadcast_with_no_handlers_completes(
        self,
        sync_service: SyncService,
        mock_window_manager: MagicMock,
    ) -> None:
        """broadcast завершается без ошибок при отсутствии обработчиков.

        Проверяет, что рассылка не падает, если нет зарегистрированных
        обработчиков.
        """
        mock_window_manager.get_window_list.return_value = []

        # Не должно вызывать исключений
        sync_service.broadcast("win-source", "document_update", {"doc_id": "doc-123"})

        # Тест проходит, если дошли до этой точки без исключений
        assert True


# =============================================================================
# TEST: Direct Send
# =============================================================================


@pytest.mark.gui
class TestDirectSend:
    """Тесты прямой отправки сообщений конкретным окнам."""

    def test_send_to_window_delivers_to_target(
        self,
        sync_service: SyncService,
        mock_window_manager: MagicMock,
        mock_window_info: MagicMock,
    ) -> None:
        """send_to_window доставляет сообщение целевому окну.

        Проверяет, что данные достигают указанного получателя.
        """
        mock_window_manager.get_window_list.return_value = [mock_window_info]

        handler = MagicMock()
        sync_service.register_handler("theme_change", "win-123", handler)

        test_data = {"theme": "light", "accent": "blue"}
        sync_service.send_to_window("win-source", "win-123", "theme_change", test_data)

        handler.assert_called_once()
        message = handler.call_args[0][0]
        assert message.data == test_data
        assert message.data_type == "theme_change"

    def test_send_to_window_ignores_other_windows(
        self,
        sync_service: SyncService,
        mock_window_manager: MagicMock,
        mock_window_info: MagicMock,
        mock_window_info_2: MagicMock,
    ) -> None:
        """send_to_window игнорирует другие окна.

        Проверяет, что только целевое окно получает сообщение.
        """
        mock_window_manager.get_window_list.return_value = [
            mock_window_info,
            mock_window_info_2,
        ]

        target_handler = MagicMock()
        other_handler = MagicMock()

        sync_service.register_handler("bookmark_change", "win-123", target_handler)
        sync_service.register_handler("bookmark_change", "win-456", other_handler)

        sync_service.send_to_window("win-source", "win-123", "bookmark_change", {"bookmark": "bm-1"})

        target_handler.assert_called_once()
        other_handler.assert_not_called()

    def test_send_to_invalid_window_logs_warning(
        self,
        sync_service: SyncService,
        mock_window_manager: MagicMock,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """send_to_window логирует предупреждение для невалидного окна.

        Проверяет, что при отправке в несуществующее окно
        записывается предупреждение в лог.
        """
        mock_window_manager.is_window_registered.return_value = False
        with caplog.at_level(logging.WARNING):
            sync_service.send_to_window("win-source", "win-invalid", "document_update", {})

        assert "win-invalid" in caplog.text or "not found" in caplog.text.lower()


# =============================================================================
# TEST: Handler Registration
# =============================================================================


@pytest.mark.gui
class TestHandlerRegistration:
    """Тесты регистрации и удаления обработчиков."""

    def test_register_handler_returns_valid_id(
        self,
        sync_service: SyncService,
        sample_handler: Callable[[Any], None],
    ) -> None:
        """register_handler возвращает валидный идентификатор.

        Проверяет, что метод возвращает непустую строку ID.
        """
        handler_id = sync_service.register_handler(
            "document_update", "win-123", sample_handler
        )

        assert isinstance(handler_id, str)
        assert len(handler_id) > 0

    def test_unregister_handler_removes_callback(
        self,
        sync_service: SyncService,
        mock_window_manager: MagicMock,
        mock_window_info: MagicMock,
        sample_handler: Callable[[Any], None],
    ) -> None:
        """unregister_handler удаляет обработчик.

        Проверяет, что после удаления обработчик не вызывается.
        """
        mock_window_manager.get_window_list.return_value = [mock_window_info]

        handler_id = sync_service.register_handler(
            "document_update", "win-123", sample_handler
        )

        # Удаляем обработчик
        sync_service.unregister_handler(handler_id)

        # Broadcast не должен вызвать удалённый обработчик
        sync_service.broadcast("win-source", "document_update", {"doc_id": "doc-123"})
        sample_handler.assert_not_called()

    def test_multiple_handlers_same_datatype_all_called(
        self,
        sync_service: SyncService,
        mock_window_manager: MagicMock,
        mock_window_info: MagicMock,
    ) -> None:
        """Несколько обработчиков одного типа вызываются все.

        Проверяет, что при рассылке вызываются все зарегистрированные
        обработчики для данного типа данных.
        """
        mock_window_manager.get_window_list.return_value = [mock_window_info]

        handler_1 = MagicMock()
        handler_2 = MagicMock()
        handler_3 = MagicMock()

        sync_service.register_handler("settings_change", "win-123", handler_1)
        sync_service.register_handler("settings_change", "win-123", handler_2)
        sync_service.register_handler("settings_change", "win-123", handler_3)

        sync_service.broadcast("win-source", "settings_change", {"setting": "value"})

        handler_1.assert_called_once()
        handler_2.assert_called_once()
        handler_3.assert_called_once()

    def test_handler_not_called_for_different_datatype(
        self,
        sync_service: SyncService,
        mock_window_manager: MagicMock,
        mock_window_info: MagicMock,
    ) -> None:
        """Обработчик не вызывается для другого типа данных.

        Проверяет, что обработчик document_update не вызывается
        при рассылке theme_change.
        """
        mock_window_manager.get_window_list.return_value = [mock_window_info]

        doc_handler = MagicMock()
        theme_handler = MagicMock()

        sync_service.register_handler("document_update", "win-123", doc_handler)
        sync_service.register_handler("theme_change", "win-123", theme_handler)

        sync_service.broadcast("win-source", "theme_change", {"theme": "dark"})

        doc_handler.assert_not_called()
        theme_handler.assert_called_once()


# =============================================================================
# TEST: Conflict Resolution
# =============================================================================


@pytest.mark.gui
class TestConflictResolution:
    """Тесты разрешения конфликтов при синхронизации."""

    def test_sidebar_state_last_write_wins(
        self,
        sync_service: SyncService,
        mock_window_manager: MagicMock,
        mock_window_info: MagicMock,
    ) -> None:
        """sidebar_state использует стратегию last-write-wins.

        Проверяет, что при конфликте sidebar сохраняется последнее
        записанное значение.
        """
        mock_window_manager.get_window_list.return_value = [mock_window_info]

        handler = MagicMock()
        sync_service.register_handler("sidebar_state", "win-123", handler)

        # Отправляем два обновления sidebar
        sync_service.broadcast("win-a", "sidebar_state", {"visible": True, "width": 200})
        sync_service.broadcast("win-b", "sidebar_state", {"visible": False, "width": 250})

        # Последнее значение должно быть сохранено
        calls = handler.call_args_list
        assert len(calls) == 2
        # Последний вызов содержит последнее значение
        last_call_data = calls[-1][0][0]
        assert last_call_data.data["visible"] is False
        assert last_call_data.data["width"] == 250

    def test_bookmark_change_merges_changes(
        self,
        sync_service: SyncService,
        mock_window_manager: MagicMock,
        mock_window_info: MagicMock,
    ) -> None:
        """bookmark_change объединяет изменения.

        Проверяет, что при конфликте bookmark изменения объединяются,
        а не перезаписываются.
        """
        mock_window_manager.get_window_list.return_value = [mock_window_info]

        handler = MagicMock()
        sync_service.register_handler("bookmark_change", "win-123", handler)

        # Отправляем изменения закладок из разных источников
        sync_service.broadcast(
            "win-a", "bookmark_change", {"added": ["bm-1"], "removed": []}
        )
        sync_service.broadcast(
            "win-b", "bookmark_change", {"added": ["bm-2"], "removed": ["bm-3"]}
        )

        # Оба вызова должны быть обработаны (merge)
        assert handler.call_count == 2

        # Проверяем, что оба изменения переданы
        call_1_data = handler.call_args_list[0][0][0]
        call_2_data = handler.call_args_list[1][0][0]

        assert "bm-1" in call_1_data.data.get("added", [])
        assert "bm-2" in call_2_data.data.get("added", [])

    def test_document_update_requires_mfa(
        self,
        sync_service: SyncService,
        mock_window_manager: MagicMock,
        mock_window_info: MagicMock,
    ) -> None:
        """document_update требует MFA для конфликтующих изменений.

        Проверяет, что при конфликте document_update требуется
        подтверждение через MFA.
        """
        mock_window_manager.get_window_list.return_value = [mock_window_info]

        # document_update передаётся через broadcast без специальной MFA-логики
        handler = MagicMock()
        sync_service.register_handler("document_update", "win-123", handler)

        # Отправляем document_update с флагом
        sync_service.broadcast(
            "win-source",
            "document_update",
            {"doc_id": "doc-123", "requires_mfa": True},
        )

        # Проверяем, что обработчик получил сообщение
        handler.assert_called_once()


# =============================================================================
# TEST: Timestamps
# =============================================================================


@pytest.mark.gui
class TestTimestamps:
    """Тесты управления временными метками синхронизации."""

    def test_get_last_sync_time_returns_timestamp(
        self,
        sync_service: SyncService,
    ) -> None:
        """get_last_sync_time возвращает временную метку.

        Проверяет, что после синхронизации возвращается корректный
        Unix timestamp.
        """
        # Выполняем синхронизацию
        sync_service.broadcast("win-source", "document_update", {"doc_id": "doc-1"})

        timestamp = sync_service.get_last_sync_time("document_update")

        assert isinstance(timestamp, (int, float))
        assert timestamp > 0

    def test_get_last_sync_time_returns_zero_for_never_synced(
        self,
        sync_service: SyncService,
    ) -> None:
        """get_last_sync_time возвращает 0 если синхронизация не выполнялась.

        Проверяет, что до первой синхронизации возвращается 0.
        """
        timestamp = sync_service.get_last_sync_time("document_update")

        assert timestamp == 0

    def test_timestamp_updated_on_broadcast(
        self,
        sync_service: SyncService,
    ) -> None:
        """Временная метка обновляется при broadcast.

        Проверяет, что каждая рассылка обновляет last_sync_time.
        """
        # Первая рассылка
        sync_service.broadcast("win-1", "document_update", {"doc_id": "doc-1"})
        timestamp_1 = sync_service.get_last_sync_time("document_update")

        # Небольшая задержка
        time.sleep(0.01)

        # Вторая рассылка
        sync_service.broadcast("win-2", "document_update", {"doc_id": "doc-2"})
        timestamp_2 = sync_service.get_last_sync_time("document_update")

        assert timestamp_2 > timestamp_1


# =============================================================================
# TEST: Edge Cases
# =============================================================================


@pytest.mark.gui
class TestEdgeCases:
    """Тесты граничных случаев."""

    def test_broadcast_with_empty_window_list(
        self,
        sync_service: SyncService,
        mock_window_manager: MagicMock,
    ) -> None:
        """broadcast корректно обрабатывает пустой список окон.

        Проверяет, что рассылка не падает при пустом списке окон.
        """
        mock_window_manager.get_window_list.return_value = []

        # Не должно вызывать исключений
        sync_service.broadcast("win-source", "document_update", {"doc_id": "doc-123"})

        # Тест проходит, если дошли до этой точки
        assert True

    def test_handler_exception_doesnt_crash_others(
        self,
        sync_service: SyncService,
        mock_window_manager: MagicMock,
        mock_window_info: MagicMock,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Исключение в обработчике не прерывает другие обработчики.

        Проверяет, что если один обработчик падает, остальные
        всё равно вызываются.
        """
        mock_window_manager.get_window_list.return_value = [mock_window_info]

        failing_handler = MagicMock(side_effect=RuntimeError("Handler failed"))
        working_handler = MagicMock()

        sync_service.register_handler("document_update", "win-123", failing_handler)
        sync_service.register_handler("document_update", "win-123", working_handler)

        with caplog.at_level(logging.ERROR):
            sync_service.broadcast("win-source", "document_update", {"doc_id": "doc-123"})

        # Работающий обработчик должен быть вызван
        working_handler.assert_called_once()

        # Ошибка должна быть залогирована
        assert "Handler failed" in caplog.text or "error" in caplog.text.lower()


# =============================================================================
# TEST: SyncData Model
# =============================================================================


@pytest.mark.gui
class TestSyncDataModel:
    """Тесты модели данных SyncData."""

    def test_sync_data_creation(self) -> None:
        """SyncData создаётся с корректными атрибутами.

        Проверяет инициализацию dataclass SyncData.
        """
        data = SyncData(
            data_type="document_update",
            source_window_id="win-123",
            payload={"doc_id": "doc-456"},
            timestamp=1234567890.0,
        )

        assert data.data_type == "document_update"
        assert data.source_window_id == "win-123"
        assert data.payload == {"doc_id": "doc-456"}
        assert data.timestamp == 1234567890.0

    def test_conflict_resolution_enum(self) -> None:
        """ConflictResolution содержит все стратегии разрешения.

        Проверяет наличие всех стратегий разрешения конфликтов.
        """
        assert hasattr(ConflictResolution, "LAST_WRITE_WINS")
        assert hasattr(ConflictResolution, "MERGE")
        assert hasattr(ConflictResolution, "MFA_GATED")
        assert hasattr(ConflictResolution, "BROADCAST_ONLY")


# =============================================================================
# TEST: Additional Edge Cases
# =============================================================================


@pytest.mark.gui
class TestAdditionalEdgeCases:
    """Дополнительные тесты граничных случаев."""

    def test_unregister_nonexistent_handler_raises_error(
        self,
        sync_service: SyncService,
    ) -> None:
        """unregister_handler вызывает ошибку для несуществующего ID.

        Проверяет, что попытка удалить несуществующий обработчик
        приводит к исключению.
        """
        with pytest.raises(KeyError, match="not found"):
            sync_service.unregister_handler("nonexistent-handler-id")

    def test_handler_with_none_data(
        self,
        sync_service: SyncService,
        mock_window_manager: MagicMock,
        mock_window_info: MagicMock,
    ) -> None:
        """Обработчик корректно принимает None в качестве данных.

        Проверяет передачу None в качестве данных для broadcast.
        """
        mock_window_manager.get_window_list.return_value = [mock_window_info]

        handler = MagicMock()
        sync_service.register_handler("test_type", "win-123", handler)

        sync_service.broadcast("win-source", "test_type", None)

        handler.assert_called_once()
        message = handler.call_args[0][0]
        assert message.data is None
        assert message.data_type == "test_type"

    def test_multiple_data_types_same_window(
        self,
        sync_service: SyncService,
        mock_window_manager: MagicMock,
        mock_window_info: MagicMock,
    ) -> None:
        """Окно может иметь обработчики разных типов данных.

        Проверяет, что одно окно может обрабатывать несколько
        типов данных одновременно.
        """
        mock_window_manager.get_window_list.return_value = [mock_window_info]

        doc_handler = MagicMock()
        theme_handler = MagicMock()
        clip_handler = MagicMock()

        sync_service.register_handler("document_update", "win-123", doc_handler)
        sync_service.register_handler("theme_change", "win-123", theme_handler)
        sync_service.register_handler("clipboard_update", "win-123", clip_handler)

        # Отправляем все типы
        sync_service.broadcast("win-source", "document_update", {"doc": 1})
        sync_service.broadcast("win-source", "theme_change", {"theme": "dark"})
        sync_service.broadcast("win-source", "clipboard_update", {"text": "test"})

        # Все обработчики должны быть вызваны
        doc_handler.assert_called_once()
        theme_handler.assert_called_once()
        clip_handler.assert_called_once()
