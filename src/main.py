"""Точка входа приложения FX Text Processor 3.

Запуск:
    python -m src.main
    python src/main.py
"""

from __future__ import annotations

import logging
import sys

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)

logger = logging.getLogger(__name__)


def main() -> int:
    """Главная точка входа.

    Returns:
        Код выхода (0 = успех)
    """
    logger.info("Инициализация FX Text Processor 3...")

    # Импортируем здесь для избежания циклических импортов
    from src.controller.app_controller import AppController
    from src.documents.format.document_format import DocumentFormat
    from src.gui.views.main_window import MainWindow
    from src.services.clipboard_service import ClipboardService
    from src.services.document_manager_service import DocumentManagerService
    from src.services.key_bindings_service import KeyBindingsService
    from src.services.notification_service import NotificationService
    from src.services.print_queue_service import PrintQueueService

    # Инициализируем сервисы (non-GUI layer)
    document_format = DocumentFormat()
    document_manager = DocumentManagerService(format=document_format)
    notification = NotificationService()
    key_bindings = KeyBindingsService()
    clipboard = ClipboardService()
    _print_queue = PrintQueueService()

    logger.info("Сервисы инициализированы")

    # --- Dependency Injection: GUI-сервисы создаются ДО MainWindow ---
    import tkinter as tk

    from src.gui.security.mode_manager import ModeManager
    from src.gui.services.drag_drop_service import DragDropService
    from src.gui.services.notification_service import (
        NotificationService as GUINotificationService,
    )
    from src.gui.services.sync_service import SyncService
    from src.gui.services.toast_service import ToastService
    from src.gui.services.window_manager import WindowManager

    root = tk.Tk()
    window_manager = WindowManager(root)
    toast_service = ToastService(root)
    sync_service = SyncService(window_manager)
    gui_notification = GUINotificationService(root, window_manager)
    drag_drop_service = DragDropService(root, window_manager, sync_service)
    mode_manager = ModeManager()

    # Создаём AppController
    app_controller = AppController(
        document_manager=document_manager,
        notification=notification,
        key_bindings=key_bindings,
        clipboard=clipboard,
    )

    logger.info("AppController создан")

    # Создаём MainWindow с явным DI через конструктор
    main_window = MainWindow(
        controller=app_controller,
        window_manager=window_manager,
        toast_service=toast_service,
        sync_service=sync_service,
        notification_service=gui_notification,
        drag_drop_service=drag_drop_service,
        mode_manager=mode_manager,
    )
    main_window.initialize()

    logger.info("MainWindow создана")

    # Устанавливаем связь между контроллером и MainWindow
    app_controller.set_main_window(main_window)

    # Создаём начальный документ
    app_controller.new_document("Новый документ")

    logger.info("Приложение запущено")

    # Запускаем главный цикл
    main_window.run()

    return 0


if __name__ == "__main__":
    sys.exit(main())
