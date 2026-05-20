"""Точка входа приложения FX Text Processor 3.

Запуск:
    python -m src.main
    python src/main.py

Переменные окружения:
    FX_DEBUG_MODE=1 — обойти MFA (только для отладки, УДАЛИТЬ перед релизом)
"""

from __future__ import annotations

import logging
import os
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

# Debug mode: обходит MFA, показывает индикатор в UI
DEBUG_MODE = os.getenv("FX_DEBUG_MODE", "0") == "1"


def _init_auth_services() -> tuple[object | None, object | None, object | None]:
    """Инициализирует сервисы аутентификации.

    Returns:
        Кортеж (password_service, session_manager, mfa_manager).
        Элементы могут быть None, если сервисы недоступны.
    """
    password_service = None
    session_manager = None
    mfa_manager = None

    try:
        from src.security.auth.password_service import PasswordService
        from src.security.auth.user_storage import JsonUserStorage

        storage = JsonUserStorage()
        password_service = PasswordService(user_storage=storage)
        logger.info("PasswordService инициализирован (JsonUserStorage)")
    except Exception as e:
        logger.warning("PasswordService недоступен: %s", e)

    try:
        from src.security.auth.session import SessionManager

        session_manager = SessionManager()
        logger.info("SessionManager инициализирован")
    except Exception as e:
        logger.warning("SessionManager недоступен: %s", e)

    try:
        from src.app_context import _InMemoryStore
        from src.security.auth.second_factor import SecondFactorManager

        keystore = _InMemoryStore()
        mfa_manager = SecondFactorManager(storage=keystore)
        logger.info("SecondFactorManager инициализирован")
    except Exception as e:
        logger.warning("SecondFactorManager недоступен: %s", e)

    return password_service, session_manager, mfa_manager


def _check_first_run(password_service: object) -> bool:
    """Проверяет, является ли запуск первым.

    Args:
        password_service: Сервис паролей.

    Returns:
        True если это первый запуск (нет пользователей).
    """
    if password_service is not None:
        try:
            storage = getattr(password_service, "storage", None)
            if storage is not None and hasattr(storage, "user_ids") and callable(storage.user_ids):
                return len(storage.user_ids()) == 0
            if (
                storage is not None
                and hasattr(storage, "get_password_hash")
                and callable(
                    storage.get_password_hash,
                )
            ):
                return storage.get_password_hash("operator") is None
        except (AttributeError, TypeError):
            pass
    return True


def main() -> int:
    """Главная точка входа.

    Returns:
        Код выхода (0 = успех)
    """
    try:
        return _run_app()
    except Exception as exc:
        logger.critical("Необработанная ошибка: %s", exc, exc_info=True)
        return 1


def _run_app() -> int:
    """Внутренняя реализация запуска приложения."""
    logger.info("Инициализация FX Text Processor 3...")

    if DEBUG_MODE:
        logger.warning("⚠ FX_DEBUG_MODE=1 — MFA обойдён! НЕ ИСПОЛЬЗОВАТЬ В ПРОДАКШЕНЕ!")

    # Регистрируем виджеты по умолчанию в WidgetRegistry
    try:
        from src.gui.core.registry_defaults import register_default_widgets

        register_default_widgets()
        logger.info("WidgetRegistry: виджеты по умолчанию зарегистрированы")
    except Exception as e:
        logger.warning("WidgetRegistry defaults недоступны: %s", e)

    # Регистрируем рендереры документов в RendererFactory
    try:
        from src.gui.renderers.factory import register_default_renderers

        register_default_renderers()
        logger.info("RendererFactory: рендереры по умолчанию зарегистрированы")
    except Exception as e:
        logger.warning("RendererFactory defaults недоступны: %s", e)

    # Импортируем здесь для избежания циклических импортов
    from src.controller.app_controller import AppController
    from src.documents.format.document_format import DocumentFormat
    from src.gui.views.main_window import MainWindow
    from src.services.clipboard_service import ClipboardService
    from src.services.document_manager_service import DocumentManagerService
    from src.services.key_bindings_service import KeyBindingsService
    from src.services.notification_service import NotificationService

    # Инициализируем сервисы (non-GUI layer)
    document_format = DocumentFormat()
    document_manager = DocumentManagerService(format=document_format)
    notification = NotificationService()
    key_bindings = KeyBindingsService()
    clipboard = ClipboardService()

    # Инициализируем сервисы аутентификации
    password_service, session_manager, mfa_manager = _init_auth_services()

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

    # Проверяем первый запуск
    is_first = _check_first_run(password_service)

    if is_first:
        logger.info("Первый запуск — показываем FirstRunWizard")
        from src.gui.security.first_run_wizard import FirstRunWizard

        wizard_completed = False
        user_id = ""

        def on_wizard_complete(uid: str) -> None:
            nonlocal wizard_completed, user_id
            wizard_completed = True
            user_id = uid

        def on_wizard_cancel() -> None:
            nonlocal wizard_completed
            wizard_completed = False

        wizard = FirstRunWizard(
            parent=root,
            password_service=password_service,
            session_manager=session_manager,
            mfa_manager=mfa_manager,
            on_complete=on_wizard_complete,
            on_cancel=on_wizard_cancel,
        )
        wizard.show()
        root.wait_window(wizard._window)  # noqa: SLF001 — блокируем до закрытия wizard

        if not wizard_completed:
            logger.info("Wizard отменён — выходим")
            root.destroy()
            return 1

        logger.info("Пользователь '%s' создан через wizard", user_id)

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
    main_window.initialize(root=root)

    # Передаём сервисы аутентификации в MainWindow
    if password_service is not None:
        main_window.set_password_service(password_service)
    if mfa_manager is not None:
        main_window.set_mfa_manager(mfa_manager)
    if session_manager is not None:
        main_window.set_session_manager(session_manager)

    # Подключаем ModeIntegration для кэширования режимов
    try:
        from src.gui.modes.mode_integration import ModeIntegration

        mode_integration = ModeIntegration()
        main_window.set_mode_integration(mode_integration)
        logger.info("ModeIntegration подключён")
    except Exception as e:
        logger.warning("ModeIntegration недоступен: %s", e)

    # Подключаем WorkflowManager для видимости действий
    try:
        from src.gui.workflow.workflow_manager import WorkflowManager

        workflow_manager = WorkflowManager()
        main_window.set_workflow_manager(workflow_manager)
        logger.info("WorkflowManager подключён")
    except Exception as e:
        logger.warning("WorkflowManager недоступен: %s", e)

    # Подключаем ModeToggle для визуального переключения режимов
    try:
        from src.gui.security.mode_toggle import ModeToggle

        if main_window._root is not None and mode_manager is not None:  # noqa: SLF001
            mode_toggle = ModeToggle(
                parent=main_window._root,  # type: ignore[arg-type]  # noqa: SLF001
                mode_manager=mode_manager,
                mfa_gate=None,
                on_mode_changed=lambda m: main_window._update_mode_ui(  # noqa: SLF001
                    m.value
                ),
            )
            main_window.set_mode_toggle(mode_toggle)
            logger.info("ModeToggle подключён")
    except Exception as e:
        logger.warning("ModeToggle недоступен: %s", e)

    # Подключаем WorkflowController и WorkflowUIFactory
    try:
        from src.controller.workflow_controller import WorkflowController
        from src.gui.security.mfa_gate import MFAGate
        from src.gui.workflow.integration import WorkflowUIBuilder

        workflow_controller = WorkflowController()

        # MFAGate требует auth_service, совместимый с AuthServiceProtocol
        class _MinimalAuthService:
            """Минимальная реализация AuthServiceProtocol для MFAGate."""

            def is_mfa_verified(self) -> bool:
                return False

            def mark_mfa_satisfied(self) -> bool:
                return True

            def get_current_user(self) -> str | None:
                return "operator"

            def verify_totp(self, user_id: str, code: str) -> bool:
                return False

            def verify_backup_code(self, user_id: str, code: str) -> bool:
                return False

        mfa_gate = MFAGate(auth_service=_MinimalAuthService())

        workflow_ui_factory = (
            WorkflowUIBuilder(workflow_controller, mfa_gate)
            .with_undo_redo(max_steps=50)
            .with_free_role_mode(enabled=True)
            .build()
        )
        main_window.set_workflow_ui_factory(workflow_ui_factory)
        logger.info("WorkflowUIFactory подключён")
    except Exception as e:
        logger.warning("WorkflowUIFactory недоступен: %s", e)

    logger.info("MainWindow создана")

    # Устанавливаем связь между контроллером и MainWindow
    app_controller.set_main_window(main_window)

    # Создаём начальный документ
    app_controller.new_document("Новый документ")

    # Индикатор debug mode в заголовке
    if DEBUG_MODE and main_window._root is not None:  # noqa: SLF001
        main_window._root.title(  # noqa: SLF001
            f"{main_window._root.title()} [DEBUG MODE]",  # noqa: SLF001
        )

    logger.info("Приложение запущено")

    # Запускаем главный цикл
    main_window.run()

    return 0


if __name__ == "__main__":
    sys.exit(main())
