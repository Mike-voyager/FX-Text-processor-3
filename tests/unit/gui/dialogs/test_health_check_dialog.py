# -*- coding: utf-8 -*-
"""Тесты для HealthCheckDialog.

Version: 1.0
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

try:
    import tkinter as tk
    from tkinter import ttk
    from src.gui.security.health_check_dialog import (
        HealthCheckDialog,
        COLOR_CRITICAL,
        COLOR_WARNING,
        COLOR_PASS,
        COLOR_NEUTRAL,
    )
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False


@pytest.fixture
def root() -> Generator[tk.Tk, None, None]:
    """Создаёт real Tk окно для GUI тестов."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def mock_health_checker() -> MagicMock:
    """Создание мока HealthChecker."""
    mock = MagicMock()
    from src.security.monitoring.models import HealthCheckReport, HealthCheckResult, HealthCheckStatus
    
    mock.run_all.return_value = HealthCheckReport(
        checks=[
            HealthCheckResult.healthy("entropy"),
            HealthCheckResult.healthy("keystore"),
        ],
        overall_status=HealthCheckStatus.HEALTHY,
    )
    mock.run_critical.return_value = HealthCheckReport(
        checks=[
            HealthCheckResult.healthy("entropy"),
        ],
        overall_status=HealthCheckStatus.HEALTHY,
    )
    return mock


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestHealthCheckDialogCreation:
    """Тесты создания HealthCheckDialog."""

    def test_dialog_creation(self, root: tk.Tk, mock_health_checker: MagicMock) -> None:
        """Проверка создания диалога."""
        dialog = HealthCheckDialog(
            parent=root,
            health_checker=mock_health_checker,
        )
        try:
            assert dialog._parent is root
            assert dialog._health_checker is mock_health_checker
            assert dialog._report is None
            assert not dialog._is_running
            assert not dialog._cancelled
        finally:
            dialog.destroy()

    def test_dialog_creation_without_health_checker(self, root: tk.Tk) -> None:
        """Проверка создания без HealthChecker."""
        dialog = HealthCheckDialog(
            parent=root,
            health_checker=None,
        )
        try:
            assert dialog._health_checker is None
            assert dialog._report is None
        finally:
            dialog.destroy()


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestHealthCheckDialogSync:
    """Тесты синхронного запуска проверок."""

    def test_run_checks_sync(self, root: tk.Tk, mock_health_checker: MagicMock) -> None:
        """Проверка синхронного запуска проверок."""
        dialog = HealthCheckDialog(
            parent=root,
            health_checker=mock_health_checker,
        )
        try:
            report = dialog.run_checks()
            
            assert report is not None
            mock_health_checker.run_all.assert_called_once()
            assert dialog._report is report
        finally:
            dialog.destroy()

    def test_run_checks_sync_raises_without_checker(self, root: tk.Tk) -> None:
        """Проверка что run_checks raises без HealthChecker."""
        dialog = HealthCheckDialog(
            parent=root,
            health_checker=None,
        )
        try:
            with pytest.raises(RuntimeError, match="HealthChecker not provided"):
                dialog.run_checks()
        finally:
            dialog.destroy()


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestHealthCheckDialogAsync:
    """Тесты асинхронного запуска проверок."""

    def test_run_checks_async(self, root: tk.Tk, mock_health_checker: MagicMock) -> None:
        """Проверка асинхронного запуска проверок."""
        with patch('threading.Thread') as mock_thread:
            
            mock_thread_instance = MagicMock()
            mock_thread.return_value = mock_thread_instance
            
            dialog = HealthCheckDialog(
                parent=root,
                health_checker=mock_health_checker,
            )
            try:
                callback_called = [False]
                
                def on_complete(report) -> None:
                    callback_called[0] = True
                
                dialog.run_checks_async(on_complete=on_complete)
                
                assert dialog._is_running
                mock_thread.assert_called_once()
                mock_thread_instance.start.assert_called_once()
            finally:
                dialog.destroy()

    def test_run_checks_async_already_running(self, root: tk.Tk, mock_health_checker: MagicMock) -> None:
        """Проверка что повторный запуск игнорируется."""
        with patch('threading.Thread') as mock_thread:
            
            dialog = HealthCheckDialog(
                parent=root,
                health_checker=mock_health_checker,
            )
            try:
                # Устанавливаем флаг running
                dialog._is_running = True
                
                dialog.run_checks_async()
                
                # Thread не должен быть создан
                mock_thread.assert_not_called()
            finally:
                dialog.destroy()


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestHealthCheckDialogStatus:
    """Тесты проверки статуса результатов."""

    def test_is_healthy(self, root: tk.Tk) -> None:
        """Проверка is_healthy() с healthy report."""
        from src.security.monitoring.models import HealthCheckReport, HealthCheckResult, HealthCheckStatus
        
        dialog = HealthCheckDialog(
            parent=root,
            health_checker=None,
        )
        try:
            # Устанавливаем healthy report
            dialog._report = HealthCheckReport(
                checks=[HealthCheckResult.healthy("entropy")],
                overall_status=HealthCheckStatus.HEALTHY,
            )
            
            assert dialog.is_healthy() is True
        finally:
            dialog.destroy()

    def test_is_healthy_no_report(self, root: tk.Tk) -> None:
        """Проверка is_healthy() без report."""
        dialog = HealthCheckDialog(
            parent=root,
            health_checker=None,
        )
        try:
            assert dialog.is_healthy() is False
        finally:
            dialog.destroy()

    def test_has_critical_failures(self, root: tk.Tk) -> None:
        """Проверка has_critical_failures()."""
        from src.security.monitoring.models import HealthCheckReport, HealthCheckResult, HealthCheckStatus
        
        dialog = HealthCheckDialog(
            parent=root,
            health_checker=None,
        )
        try:
            # Без отчёта - нет критических ошибок
            assert dialog.has_critical_failures() is False
            
            # С healthy report
            dialog._report = HealthCheckReport(
                checks=[HealthCheckResult.healthy("entropy")],
                overall_status=HealthCheckStatus.HEALTHY,
            )
            assert dialog.has_critical_failures() is False
            
            # С unhealthy report
            dialog._report = HealthCheckReport(
                checks=[HealthCheckResult.unhealthy("entropy", "Low entropy")],
                overall_status=HealthCheckStatus.UNHEALTHY,
            )
            assert dialog.has_critical_failures() is True
        finally:
            dialog.destroy()

    def test_has_warnings(self, root: tk.Tk) -> None:
        """Проверка has_warnings()."""
        from src.security.monitoring.models import HealthCheckReport, HealthCheckResult, HealthCheckStatus
        
        dialog = HealthCheckDialog(
            parent=root,
            health_checker=None,
        )
        try:
            # Без отчёта - нет предупреждений
            assert dialog.has_warnings() is False
            
            # С healthy report
            dialog._report = HealthCheckReport(
                checks=[HealthCheckResult.healthy("entropy")],
                overall_status=HealthCheckStatus.HEALTHY,
            )
            assert dialog.has_warnings() is False
            
            # С degraded report
            dialog._report = HealthCheckReport(
                checks=[HealthCheckResult.degraded("entropy", "Minor issue")],
                overall_status=HealthCheckStatus.DEGRADED,
            )
            assert dialog.has_warnings() is True
        finally:
            dialog.destroy()


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestHealthCheckDialogColors:
    """Тесты цветовых констант."""

    def test_color_constants(self) -> None:
        """Проверка цветовых констант."""
        assert COLOR_CRITICAL == "#e74c3c"
        assert COLOR_WARNING == "#f39c12"
        assert COLOR_PASS == "#27ae60"
        assert COLOR_NEUTRAL == "#7f8c8d"


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestHealthCheckDialogReport:
    """Тесты работы с отчётом."""

    def test_get_report(self, root: tk.Tk) -> None:
        """Проверка get_report()."""
        from src.security.monitoring.models import HealthCheckReport, HealthCheckResult, HealthCheckStatus
        
        dialog = HealthCheckDialog(
            parent=root,
            health_checker=None,
        )
        try:
            # Без отчёта - None
            assert dialog.get_report() is None
            
            # Устанавливаем отчёт
            report = HealthCheckReport(
                checks=[HealthCheckResult.healthy("entropy")],
                overall_status=HealthCheckStatus.HEALTHY,
            )
            dialog._report = report
            
            assert dialog.get_report() is report
        finally:
            dialog.destroy()


__all__ = [
    "TestHealthCheckDialogCreation",
    "TestHealthCheckDialogSync",
    "TestHealthCheckDialogAsync",
    "TestHealthCheckDialogStatus",
    "TestHealthCheckDialogColors",
    "TestHealthCheckDialogReport",
]
