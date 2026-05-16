"""Unit-тесты для ToastService.

Проверяет:
- Создание ToastService
- Показ уведомления (show)
- Закрытие уведомления (close_toast)
- Закрытие всех уведомлений (close_all)
- Ограничение длины сообщения
- Ограничение размера очереди

Coverage target: ≥90%
"""

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest
from src.gui.services.toast_service import (
    AUTO_CLOSE_MS,
    MAX_MESSAGE_LENGTH,
    MAX_QUEUE_SIZE,
    ToastConfig,
    ToastService,
    ToastWindow,
)
from src.gui.views import ToastLevel, ToastMessage


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
def toast_service(tk_root: tk.Tk) -> ToastService:
    """Fixture для ToastService."""
    return ToastService(root=tk_root)


# =============================================================================
# TEST: ToastService Creation
# =============================================================================


@pytest.mark.gui
class TestToastServiceCreation:
    """Тесты создания ToastService."""

    def test_toast_service_creation(self, tk_root: tk.Tk) -> None:
        """Создание ToastService с валидными параметрами."""
        service = ToastService(root=tk_root)

        assert service._root is tk_root
        assert len(service._toasts) == 0
        assert len(service._messages) == 0


# =============================================================================
# TEST: Show Toast
# =============================================================================


@pytest.mark.gui
class TestShowToast:
    """Тесты показа уведомлений."""

    def test_show_toast(self, toast_service: ToastService) -> None:
        """show() создаёт уведомление и возвращает toast_id."""
        toast_id = toast_service.show("Test message")

        assert isinstance(toast_id, str)
        assert toast_id in toast_service._toasts
        assert toast_id in toast_service._messages

    def test_show_toast_stores_message_info(self, toast_service: ToastService) -> None:
        """show() сохраняет информацию о сообщении."""
        toast_id = toast_service.show("Test message", ToastLevel.SUCCESS)

        message = toast_service._messages[toast_id]
        assert isinstance(message, ToastMessage)
        assert message.message == "Test message"
        assert message.level == ToastLevel.SUCCESS

    def test_show_toast_default_level_info(self, toast_service: ToastService) -> None:
        """show() по умолчанию использует INFO level."""
        toast_id = toast_service.show("Test message")

        assert toast_service._messages[toast_id].level == ToastLevel.INFO

    def test_show_toast_no_auto_close(self, toast_service: ToastService) -> None:
        """show() с auto_close=False не закрывает автоматически."""
        toast_id = toast_service.show("Test message", auto_close=False)

        assert toast_id in toast_service._toasts


# =============================================================================
# TEST: Close Toast
# =============================================================================


@pytest.mark.gui
class TestCloseToast:
    """Тесты закрытия уведомлений."""

    def test_close_toast(self, toast_service: ToastService) -> None:
        """close_toast() закрывает уведомление."""
        toast_id = toast_service.show("Test message")

        toast_service.close_toast(toast_id)

        assert toast_id not in toast_service._toasts

    def test_close_toast_unknown_id_noop(self, toast_service: ToastService) -> None:
        """close_toast() с неизвестным id не вызывает ошибок."""
        toast_service.close_toast("nonexistent")  # Should not raise


# =============================================================================
# TEST: Close All
# =============================================================================


@pytest.mark.gui
class TestCloseAll:
    """Тесты закрытия всех уведомлений."""

    def test_close_all(self, toast_service: ToastService) -> None:
        """close_all() закрывает все уведомления."""
        toast_service.show("Message 1")
        toast_service.show("Message 2")
        toast_service.show("Message 3")

        toast_service.close_all()

        assert len(toast_service._toasts) == 0
        assert len(toast_service._messages) == 0

    def test_close_all_empty_noop(self, toast_service: ToastService) -> None:
        """close_all() когда нет уведомлений не вызывает ошибок."""
        toast_service.close_all()  # Should not raise


# =============================================================================
# TEST: Message Length Limit
# =============================================================================


@pytest.mark.gui
class TestMessageLengthLimit:
    """Тесты ограничения длины сообщения."""

    def test_message_length_limit_constant(self) -> None:
        """MAX_MESSAGE_LENGTH имеет разумное значение."""
        assert MAX_MESSAGE_LENGTH > 0
        assert MAX_MESSAGE_LENGTH >= 100  # Should be at least 100 chars

    def test_show_toast_exceeds_length_raises(self, toast_service: ToastService) -> None:
        """show() с длинным сообщением вызывает ValueError."""
        long_message = "A" * (MAX_MESSAGE_LENGTH + 1)

        with pytest.raises(ValueError, match="exceeds maximum length"):
            toast_service.show(long_message)

    def test_show_toast_max_length_ok(self, toast_service: ToastService) -> None:
        """show() с сообщением максимальной длины работает."""
        max_message = "A" * MAX_MESSAGE_LENGTH

        toast_id = toast_service.show(max_message)

        assert toast_id in toast_service._toasts


# =============================================================================
# TEST: Queue Size Limit
# =============================================================================


@pytest.mark.gui
class TestQueueSizeLimit:
    """Тесты ограничения размера очереди."""

    def test_queue_size_limit_constant(self) -> None:
        """MAX_QUEUE_SIZE имеет разумное значение."""
        assert MAX_QUEUE_SIZE > 0
        assert MAX_QUEUE_SIZE < 20  # Should be reasonable

    def test_cleanup_old_toasts_when_exceeds_limit(self, toast_service: ToastService) -> None:
        """Старые уведомления удаляются при превышении лимита."""
        # Fill queue to limit
        for i in range(MAX_QUEUE_SIZE):
            toast_service.show(f"Message {i}")

        # Verify queue is full
        assert len(toast_service._toasts) == MAX_QUEUE_SIZE

        # Add one more - should trigger cleanup
        toast_service.show("Extra message")

        # Queue should still be within limit
        assert len(toast_service._toasts) <= MAX_QUEUE_SIZE


# =============================================================================
# TEST: Toast Levels
# =============================================================================


@pytest.mark.gui
class TestToastLevels:
    """Тесты разных уровней уведомлений."""

    def test_show_toast_info(self, toast_service: ToastService) -> None:
        """show() с INFO level работает."""
        toast_id = toast_service.show("Info message", ToastLevel.INFO)
        assert toast_service._messages[toast_id].level == ToastLevel.INFO

    def test_show_toast_success(self, toast_service: ToastService) -> None:
        """show() с SUCCESS level работает."""
        toast_id = toast_service.show("Success message", ToastLevel.SUCCESS)
        assert toast_service._messages[toast_id].level == ToastLevel.SUCCESS

    def test_show_toast_warning(self, toast_service: ToastService) -> None:
        """show() с WARNING level работает."""
        toast_id = toast_service.show("Warning message", ToastLevel.WARNING)
        assert toast_service._messages[toast_id].level == ToastLevel.WARNING

    def test_show_toast_error(self, toast_service: ToastService) -> None:
        """show() с ERROR level работает."""
        toast_id = toast_service.show("Error message", ToastLevel.ERROR)
        assert toast_service._messages[toast_id].level == ToastLevel.ERROR


# =============================================================================
# TEST: ToastConfig
# =============================================================================


class TestToastConfig:
    """Тесты ToastConfig."""

    def test_toast_config_creation(self) -> None:
        """Создание ToastConfig."""
        config = ToastConfig(
            bg_color="#ffffff",
            fg_color="#000000",
            icon_text="I",
        )

        assert config.bg_color == "#ffffff"
        assert config.fg_color == "#000000"
        assert config.icon_text == "I"


# =============================================================================
# TEST: Constants
# =============================================================================


class TestConstants:
    """Тесты констант модуля."""

    def test_auto_close_ms_positive(self) -> None:
        """AUTO_CLOSE_MS положительное число."""
        assert AUTO_CLOSE_MS > 0


# =============================================================================
# TEST: Module Exports
# =============================================================================


class TestModuleExports:
    """Тесты exports модуля."""

    def test_module_imports(self) -> None:
        """Модуль импортируется без ошибок."""
        from src.gui.services import toast_service

        assert toast_service is not None

    def test_toast_service_available(self) -> None:
        """ToastService доступен из модуля."""
        from src.gui.services.toast_service import ToastService

        assert ToastService is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.services.toast_service"])
