"""Тесты для StatusBar.

Покрытие:
- Инициализация
- Методы set_status, set_cursor_position, set_modified, set_cpi
- Toast уведомления
- Интеграция с NotificationService
"""

from __future__ import annotations

import tkinter as tk
from unittest.mock import MagicMock

import pytest

from src.view.status_bar import StatusBar


class TestStatusBarInit:
    """Тесты инициализации StatusBar."""

    def test_create_default(self) -> None:
        """Создание с настройками по умолчанию."""
        root = tk.Tk()
        root.withdraw()  # Скрываем окно для тестов

        try:
            status_bar = StatusBar(root)
            assert status_bar._theme == "classic_green"
        finally:
            root.destroy()

    def test_create_with_theme(self) -> None:
        """Создание с указанной темой."""
        root = tk.Tk()
        root.withdraw()

        try:
            status_bar = StatusBar(root, theme="amber")
            assert status_bar._theme == "amber"
        finally:
            root.destroy()


class TestStatusBarMethods:
    """Тесты методов StatusBar."""

    def test_set_status(self) -> None:
        """Установка статуса."""
        root = tk.Tk()
        root.withdraw()

        try:
            status_bar = StatusBar(root)
            status_bar.set_status("Готов")

            # Проверяем, что текст установлен
            assert status_bar._status_label.cget("text") == "Готов"
        finally:
            root.destroy()

    def test_set_cursor_position(self) -> None:
        """Установка позиции курсора."""
        root = tk.Tk()
        root.withdraw()

        try:
            status_bar = StatusBar(root)
            status_bar.set_cursor_position(5, 10)

            assert status_bar._cursor_label.cget("text") == "Стр: 5, Стб: 10"
        finally:
            root.destroy()

    def test_set_modified_true(self) -> None:
        """Установка статуса модификации (изменён)."""
        root = tk.Tk()
        root.withdraw()

        try:
            status_bar = StatusBar(root)
            status_bar.set_modified(True)

            assert status_bar._modified is True
            assert status_bar._modified_label.cget("text") == "[*] "
        finally:
            root.destroy()

    def test_set_modified_false(self) -> None:
        """Установка статуса модификации (не изменён)."""
        root = tk.Tk()
        root.withdraw()

        try:
            status_bar = StatusBar(root)
            status_bar.set_modified(False)

            assert status_bar._modified is False
            assert status_bar._modified_label.cget("text") == ""
        finally:
            root.destroy()

    def test_set_cpi(self) -> None:
        """Установка CPI."""
        root = tk.Tk()
        root.withdraw()

        try:
            status_bar = StatusBar(root)
            status_bar.set_cpi(12)

            assert status_bar._cpi_label.cget("text") == "12 CPI"
        finally:
            root.destroy()


class TestStatusBarToast:
    """Тесты toast уведомлений."""

    def test_show_toast(self) -> None:
        """Показ toast уведомления."""
        root = tk.Tk()
        root.withdraw()

        try:
            status_bar = StatusBar(root)
            status_bar.show_toast("Тестовое сообщение", duration_ms=100)

            # Toast должен быть показан
            # (в реальном тесте нужно использовать mock.after)
        finally:
            root.destroy()

    def test_hide_toast(self) -> None:
        """Скрытие toast уведомления."""
        root = tk.Tk()
        root.withdraw()

        try:
            status_bar = StatusBar(root)
            status_bar.show_toast("Тест", duration_ms=5000)
            status_bar.hide_toast()

            # Toast_id должен быть None
            assert status_bar._toast_id is None
        finally:
            root.destroy()


class TestStatusBarNotificationIntegration:
    """Тесты интеграции с NotificationService."""

    def test_notification_callback(self) -> None:
        """Callback при получении уведомления."""
        root = tk.Tk()
        root.withdraw()

        try:
            # Мок NotificationService
            notification_service = MagicMock()

            status_bar = StatusBar(root, notification_service=notification_service)

            # Проверяем, что подписка была выполнена
            notification_service.subscribe.assert_called_once()
        finally:
            root.destroy()

    def test_show_notification(self) -> None:
        """Показ уведомления через callback."""
        root = tk.Tk()
        root.withdraw()

        try:
            status_bar = StatusBar(root)

            # Мок Notification
            notification = MagicMock()
            notification.type = MagicMock()
            notification.type.value = "info"
            notification.title = "Тест"
            notification.message = "Тестовое сообщение"

            status_bar._show_notification(notification)

            # Toast должен быть показан (проверяем, что toast_label.pack был вызван)
            # В реальном тесте нужно проверить состояние
        finally:
            root.destroy()


class TestStatusBarDestroy:
    """Тесты уничтожения StatusBar."""

    def test_destroy(self) -> None:
        """Уничтожение статусной строки."""
        root = tk.Tk()
        root.withdraw()

        try:
            notification_service = MagicMock()
            status_bar = StatusBar(root, notification_service=notification_service)
            status_bar.destroy()

            # Проверяем, что отписка была выполнена
            notification_service.unsubscribe.assert_called_once()
        finally:
            root.destroy()

    def test_destroy_without_notification_service(self) -> None:
        """Уничтожение без NotificationService."""
        root = tk.Tk()
        root.withdraw()

        try:
            status_bar = StatusBar(root)
            status_bar.destroy()

            # Не должно быть ошибки
        finally:
            root.destroy()