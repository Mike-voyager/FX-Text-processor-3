"""Протокольные интерфейсы для GUI подсистемы.

Определяет Protocol классы для компонентов GUI согласно GUI_ARCHITECTURE_1.0.md:
- EventProtocol: базовый протокол для всех событий
- WidgetProtocol: базовый протокол для всех виджетов
- SmartWidgetProtocol: виджеты с локальным состоянием редактирования
- ControllerProtocol: базовый протокол для контроллеров
- DocumentControllerProtocol: контроллер для работы с документами

Модуль использует typing.Protocol для определения контрактов, что обеспечивает
structural subtyping без явного наследования. Все Protocol классы помечены
@runtime_checkable для поддержки isinstance() проверок.

Example:
    >>> from src.gui.components.base.widget import BaseWidget
    >>> widget = BaseWidget(widget_id="test_01")
    >>> isinstance(widget, WidgetProtocol)
    True

Version: 1.0
Date: April 6, 2026
Priority: 🔴 CRITICAL (Phase 1)
"""

from __future__ import annotations

__author__ = "FX Text Processor Team"
__date__ = "April 2026"
__version__ = "1.0"

import tkinter as tk
from pathlib import Path
from typing import (
    Any,
    Callable,
    Optional,
    Protocol,
    runtime_checkable,
)

# ==============================================================================
# EVENT PROTOCOL
# ==============================================================================


@runtime_checkable
class EventProtocol(Protocol):
    """Базовый протокол для всех событий GUI.

    Все события в системе должны реализовывать этот протокол,
    обеспечивая единый интерфейс для отслеживания источника и времени события.

    Attributes:
        timestamp: Временная метка создания события (Unix timestamp).
        source_widget_id: Идентификатор виджета-источника события.
        event_type: Тип события (например, "value_changed", "focus_lost").

    Example:
        >>> event = ValueChangedEvent(
        ...     source_widget_id="field_01",
        ...     old_value="old",
        ...     new_value="new"
        ... )
        >>> isinstance(event, EventProtocol)
        True
        >>> event.timestamp > 0
        True
    """

    timestamp: float
    source_widget_id: str
    event_type: str

    def get_data(self) -> dict[str, Any]:
        """Возвращает данные события в виде словаря.

        Returns:
            Словарь с данными события, специфичными для конкретного типа.

        Example:
            >>> data = event.get_data()
            >>> "old_value" in data
            True
        """
        ...

    def is_propagation_stopped(self) -> bool:
        """Проверяет, остановлено ли распространение события.

        Returns:
            True если событие не должно передаваться дальше.

        Note:
            Используется для реализации event.stopPropagation() аналога.
        """
        ...

    def stop_propagation(self) -> None:
        """Останавливает распространение события.

        После вызова этого метода событие не будет передаваться
        родительским виджетам или контроллерам.

        Example:
            >>> def handle_click(event: EventProtocol) -> None:
            ...     if should_stop:
            ...         event.stop_propagation()
        """
        ...


@runtime_checkable
class FormFieldProtocol(Protocol):
    """Протокол для FormField composite widget.

    Позволяет renderers работать с FormField без прямого импорта класса,
    разрывая circular import между components и renderers.

    Attributes:
        field_id: Идентификатор поля (через field_def.field_id).

    Example:
        >>> isinstance(form_field, FormFieldProtocol)
        True
    """

    def set_value(self, value: Any) -> None:
        """Устанавливает значение поля.

        Args:
            value: Новое значение для поля.
        """
        ...

    def get_value(self) -> Any:
        """Возвращает текущее значение поля.

        Returns:
            Текущее значение поля в зависимости от типа.
        """
        ...

    def validate(self) -> tuple[bool, Optional[str]]:
        """Валидирует значение поля.

        Returns:
            Кортеж (is_valid, error_message).
        """
        ...

    def set_error(self, message: Optional[str]) -> None:
        """Устанавливает состояние ошибки.

        Args:
            message: Сообщение об ошибке или None для очистки.
        """
        ...

    def clear_error(self) -> None:
        """Очищает состояние ошибки."""
        ...

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные поля.

        Security:
            Очищает значение поля, внутренние ссылки и содержимое
            виджетов ввода.
        """
        ...

    def pack(self, **kwargs: Any) -> None:
        """Упаковывает виджет в родительский контейнер.

        Args:
            **kwargs: Параметры layout (fill, expand, padx, pady и т.д.).
        """
        ...


# ==============================================================================
# WIDGET PROTOCOL
# ==============================================================================


@runtime_checkable
class WidgetProtocol(Protocol):
    """Базовый протокол для всех виджетов GUI.

    Определяет жизненный цикл виджета: mount → handle_event → unmount.
    Все виджеты должны иметь уникальный идентификатор и поддерживать
    явное управление жизненным циклом.

    Attributes:
        widget_id: Уникальный идентификатор виджета в иерархии GUI.

    Lifecycle:
        1. mount(parent) — создание и регистрация в родителе
        2. handle_event(event) — обработка событий
        3. unmount() — удаление и освобождение ресурсов

    Example:
        >>> widget = BaseWidget(widget_id="editor_01")
        >>> widget.widget_id
        'editor_01'
        >>> root = tk.Tk()
        >>> tk_widget = widget.mount(root)
        >>> isinstance(tk_widget, tk.Widget)
        True
        >>> widget.unmount()
    """

    widget_id: str

    def mount(self, parent: Any) -> Any:
        """Монтирует виджет в родительский контейнер.

        Создаёт и возвращает Tkinter виджет, регистрирует обработчики событий.
        Вызывается один раз при создании виджета.

        Args:
            parent: Родительский Tkinter виджет (tk.Widget).

        Returns:
            Созданный Tkinter виджет (tk.Widget).

        Raises:
            GUIError: Если виджет уже смонтирован или parent невалиден.

        Example:
            >>> root = tk.Tk()
            >>> frame = tk.Frame(root)
            >>> tk_widget = widget.mount(frame)
            >>> tk_widget.pack()
        """
        ...

    def unmount(self) -> None:
        """Демонтирует виджет и освобождает ресурсы.

        Удаляет Tkinter виджет, отписывается от событий, очищает ссылки.
        После вызова виджет не может быть использован повторно.

        Security:
            При демонтировании sensitive виджетов должна выполняться
            очистка памяти (secure_zero) для чувствительных данных.

        Example:
            >>> widget.unmount()
            >>> # Виджет больше не доступен
        """
        ...

    def handle_event(self, event: EventProtocol) -> bool:
        """Обрабатывает входящее событие.

        Args:
            event: Событие для обработки (реализует EventProtocol).

        Returns:
            True если событие было обработано (consumed),
            False для передачи события дальше.

        Example:
            >>> result = widget.handle_event(click_event)
            >>> if result:
            ...     print("Событие обработано")
        """
        ...

    def is_mounted(self) -> bool:
        """Проверяет, смонтирован ли виджет.

        Returns:
            True если виджет смонтирован и активен.

        Example:
            >>> widget.is_mounted()
            False
            >>> widget.mount(parent)
            >>> widget.is_mounted()
            True
        """
        ...


# ==============================================================================
# SMART WIDGET PROTOCOL
# ==============================================================================


@runtime_checkable
class SmartWidgetProtocol(WidgetProtocol, Protocol):
    """Протокол для виджетов с локальным состоянием редактирования.

    Расширяет WidgetProtocol, добавляя режим редактирования с явным
    входом/выходом и синхронизацией с моделью. Используется для
    компонентов, требующих локального состояния (Text, Entry и т.д.).

    Состояния:
        - VIEW_MODE: отображение значения из модели
        - EDIT_MODE: локальное редактирование, sync отключен

    Пример использования:
        Smart-виджеты используются для Text Editor (WYSIWYG) и Form Fields,
        где требуется производительный ввод без постоянной синхронизации.

    Attributes:
        widget_id: Унаследован от WidgetProtocol.
        is_editing: Флаг режима редактирования (True = EDIT_MODE).

    Example:
        >>> editor = SmartTextEditor(widget_id="doc_editor")
        >>> isinstance(editor, SmartWidgetProtocol)
        True
        >>> editor.enter_edit_mode()
        >>> editor.is_editing
        True
        >>> editor.sync_to_model()
        >>> editor.is_editing
        False
    """

    is_editing: bool

    def enter_edit_mode(self) -> None:
        """Входит в режим редактирования.

        В этом режиме виджет работает автономно:
        - Сохраняется начальное значение для сравнения
        - Отключается синхронизация с моделью
        - Пользователь может свободно редактировать

        Note:
            Метод вызывается при FocusIn или явном входе в редактирование.

        Example:
            >>> editor.enter_edit_mode()
            >>> # Пользователь редактирует текст
        """
        ...

    def exit_edit_mode(self) -> None:
        """Выходит из режима редактирования.

        При выходе из режима:
        - Сравнивается текущее значение с начальным
        - Если есть изменения — вызывается sync_to_model()
        - Возобновляется синхронизация с моделью

        Note:
            Метод вызывается при FocusOut или явном выходе из редактирования.
            Если значение изменилось — автоматически вызывается sync_to_model().

        Example:
            >>> editor.exit_edit_mode()
            >>> # Если текст изменился, sync_to_model() вызван автоматически
        """
        ...

    def sync_to_model(self) -> bool:
        """Синхронизирует локальное состояние с моделью.

        Передаёт текущее значение виджета в Controller/Model через callback.
        Создаёт Command для undo/redo менеджера.

        Returns:
            True если синхронизация выполнена (значение изменилось),
            False если изменений не было.

        Example:
            >>> changed = editor.sync_to_model()
            >>> if changed:
            ...     print("Модель обновлена, undo добавлен в историю")
        """
        ...

    def get_edit_value(self) -> str:
        """Возвращает текущее значение в режиме редактирования.

        Returns:
            Текущее значение виджета (строка).

        Example:
            >>> editor.enter_edit_mode()
            >>> # Пользователь ввёл "Hello"
            >>> editor.get_edit_value()
            'Hello'
        """
        ...

    def set_edit_value(self, value: str) -> None:
        """Устанавливает значение в режиме редактирования.

        Args:
            value: Новое значение для виджета.

        Note:
            Метод не синхронизируется с моделью — только локальное изменение.

        Example:
            >>> editor.set_edit_value("New text")
            >>> editor.get_edit_value()
            'New text'
        """
        ...


# ==============================================================================
# CONTROLLER PROTOCOL
# ==============================================================================


@runtime_checkable
class ControllerProtocol(Protocol):
    """Базовый протокол для GUI контроллеров.

    Контроллеры отвечают за маршрутизацию между View и Service Layer.
    НЕ содержат сложной бизнес-логики — только координацию вызовов.

    Архитектура:
        View → Controller.dispatch() → Service Layer → Model
        Service Layer → Controller.notify_view_update() → View

    Attributes:
        controller_id: Уникальный идентификатор контроллера.

    Example:
        >>> controller = DocumentController(service=doc_service)
        >>> isinstance(controller, ControllerProtocol)
        True
        >>> controller.dispatch(action)
    """

    controller_id: str

    def dispatch(self, action: str, **kwargs: Any) -> Optional[Any]:
        """Диспетчирует действие в Service Layer.

        Args:
            action: Идентификатор действия (например, "save", "open").
            **kwargs: Параметры действия.

        Returns:
            Результат выполнения действия или None.

        Raises:
            ControllerError: Если действие неизвестно или невалидно.

        Example:
            >>> result = controller.dispatch("save", path="/tmp/doc.fxsd")
            >>> if result:
            ...     print("Сохранено успешно")
        """
        ...

    def notify_view_update(self, widget_id: str, data: Any) -> None:
        """Уведомляет View об изменениях в Model.

        Вызывается Service Layer для обновления отображения.
        Контроллер маршрутизирует уведомление соответствующему виджету.

        Args:
            widget_id: Идентификатор виджета для обновления.
            data: Данные для обновления (специфичны для виджета).

        Example:
            >>> controller.notify_view_update(
            ...     widget_id="status_bar",
            ...     data={"modified": True}
            ... )
        """
        ...

    def register_view(self, widget_id: str, callback: Callable[..., None]) -> None:
        """Регистрирует callback для обновления View.

        Args:
            widget_id: Идентификатор виджета.
            callback: Функция обратного вызова для уведомлений.

        Example:
            >>> controller.register_view("editor", editor.update_callback)
        """
        ...

    def unregister_view(self, widget_id: str) -> None:
        """Отменяет регистрацию View callback.

        Args:
            widget_id: Идентификатор виджета.

        Example:
            >>> controller.unregister_view("editor")
        """
        ...


# ==============================================================================
# DOCUMENT CONTROLLER PROTOCOL
# ==============================================================================


@runtime_checkable
class DocumentControllerProtocol(ControllerProtocol, Protocol):
    """Протокол для контроллера документов.

    Расширяет ControllerProtocol, добавляя специфичные для документов методы.
    Обрабатывает FREE_FORM (текст) и STRUCTURED_FORM (формы) режимы.

    Действия:
        - on_text_changed: изменение текста в FREE_FORM режиме
        - on_field_changed: изменение поля в STRUCTURED_FORM режиме
        - on_save: сохранение документа (может потребовать MFA)
        - on_print: печать документа

    Security:
        Некоторые операции (save, print) могут требовать MFA-верификации.
        Контроллер использует MFAGate для защищённых операций.

    Example:
        >>> controller = DocumentController(service=doc_service)
        >>> isinstance(controller, DocumentControllerProtocol)
        True
        >>> controller.on_text_changed("New document content")
    """

    def on_text_changed(self, text: str) -> None:
        """Обрабатывает изменение текста в FREE_FORM режиме.

        Вызывается SmartWidget при выходе из режима редактирования
        или по таймеру автосохранения.

        Args:
            text: Новый текст документа.

        Note:
            Контроллер передаёт изменение в DocumentService,
            который обновляет Model и логирует в AuditService.

        Example:
            >>> controller.on_text_changed("Hello, World!")
            >>> # DocumentService.update_content() вызван автоматически
        """
        ...

    def on_field_changed(self, field_id: str, value: str) -> None:
        """Обрабатывает изменение поля в STRUCTURED_FORM режиме.

        Args:
            field_id: Идентификатор изменённого поля.
            value: Новое значение поля.

        Note:
            Автоматически запускает валидацию поля и пересчёт формул,
            если поле используется в вычислениях.

        Example:
            >>> controller.on_field_changed("field_01", "New value")
            >>> # Валидация и обновление зависимых полей
        """
        ...

    def on_save(self) -> bool:
        """Сохраняет текущий документ.

        Для зашифрованных документов может потребоваться MFA.

        Returns:
            True если сохранение успешно, False при ошибке или отмене.

        Raises:
            SaveError: При ошибке записи (после MFA-диалога).

        Security:
            Документы с SecurityPreset.PARANOID/PQC требуют MFA.
            Используется MFAGate для проверки.

        Example:
            >>> if controller.on_save():
            ...     print("Документ сохранён")
            ... else:
            ...     print("Сохранение отменено или ошибка")
        """
        ...

    def on_print(self) -> bool:
        """Печатает текущий документ.

        Открывает PrintDialog, формирует ESC/P команды,
        отправляет на принтер через PrinterService.

        Returns:
            True если печать успешно запущена, False при отмене.

        Security:
            Для подписанных документов печать может требовать MFA
            для генерации QR-кода подтверждения.

        Example:
            >>> if controller.on_print():
            ...     print("Задание отправлено на печать")
        """
        ...

    def on_undo(self) -> bool:
        """Отменяет последнее действие.

        Returns:
            True если отмена выполнена, False если история пуста.

        Example:
            >>> while controller.on_undo():
            ...     print("Отменено одно действие")
        """
        ...

    def on_redo(self) -> bool:
        """Повторяет отменённое действие.

        Returns:
            True если повтор выполнен, False если redo-история пуста.

        Example:
            >>> controller.on_redo()
            True
        """
        ...


# ==============================================================================
# WORKFLOW CONTROLLER PROTOCOL (Phase 5)
# ==============================================================================


@runtime_checkable
class WorkflowControllerProtocol(ControllerProtocol, Protocol):
    """Протокол для контроллера workflow управления.

    Расширяет ControllerProtocol, добавляя специфичные для workflow методы.
    Обрабатывает переходы между состояниями документа и смену ролей с MFA защитой.

    Действия:
        - on_workflow_transition: переход в новое состояние документа
        - on_role_switch: смена роли пользователя в workflow

    Security:
        Переходы между состояниями и смена ролей могут требовать MFA.
        Используется MFAGate для защищённых операций.

    Example:
        >>> controller = WorkflowController(workflow_service=workflow_svc, mfa_gate=mfa_gate)
        >>> isinstance(controller, WorkflowControllerProtocol)
        True
        >>> controller.on_workflow_transition(FormStatus.DRAFT)
    """

    def on_workflow_transition(self, new_state: Any) -> bool:
        """Выполняет переход workflow в новое состояние.

        Args:
            new_state: Целевое состояние документа.

        Returns:
            True если переход выполнен успешно, False при отмене или ошибке.

        Security:
            Некоторые переходы (например, DRAFT -> SIGNED) требуют MFA.
            Проверяется через MFAGate.

        Example:
            >>> if controller.on_workflow_transition(FormStatus.SIGNED):
            ...     print("Состояние изменено")
        """
        ...

    def on_role_switch(self, new_role: Any) -> bool:
        """Выполняет смену роли пользователя.

        Args:
            new_role: Новая роль пользователя.

        Returns:
            True если смена роли успешна, False при отмене.

        Security:
            Смена роли требует MFA верификации.

        Example:
            >>> if controller.on_role_switch(WorkflowRole.CREATOR):
            ...     print("Роль изменена")
        """
        ...


# ==============================================================================
# TEMPLATE CONTROLLER PROTOCOL (Phase 6)
# ==============================================================================


@runtime_checkable
class TemplateControllerProtocol(ControllerProtocol, Protocol):
    """Протокол для контроллера управления шаблонами.

    Расширяет ControllerProtocol, добавляя специфичные для шаблонов методы.
    Обрабатывает импорт, экспорт и загрузку шаблонов (.fxstpl).

    Действия:
        - on_import_template: импорт шаблона из файла
        - on_export_template: экспорт шаблона в файл
        - on_load_template: загрузка шаблона в редактор

    Example:
        >>> controller = TemplateController(template_service=template_svc)
        >>> isinstance(controller, TemplateControllerProtocol)
        True
        >>> controller.on_import_template()
    """

    def on_import_template(self) -> bool:
        """Импортирует шаблон из файла.

        Returns:
            True если импорт успешен, False при отмене или ошибке.

        Example:
            >>> if controller.on_import_template():
            ...     print("Шаблон импортирован")
        """
        ...

    def on_export_template(self) -> bool:
        """Экспортирует текущий шаблон в файл.

        Returns:
            True если экспорт успешен, False при отмене или ошибке.

        Example:
            >>> if controller.on_export_template():
            ...     print("Шаблон экспортирован")
        """
        ...

    def on_load_template(self, template_id: str) -> bool:
        """Загружает шаблон в редактор.

        Args:
            template_id: Идентификатор загружаемого шаблона.

        Returns:
            True если загрузка успешна, False при ошибке.

        Example:
            >>> if controller.on_load_template("tpl-123"):
            ...     print("Шаблон загружен")
        """
        ...


# ==============================================================================
# WINDOW MANAGER PROTOCOL (Phase 7)
# ==============================================================================


@runtime_checkable
class WindowManagerProtocol(Protocol):
    """Протокол для управления окнами приложения.

    Обеспечивает централизованное управление всеми окнами приложения:
    регистрацию, фокусировку, минимизацию/восстановление, закрытие.
    Поддерживает передачу документов между окнами.

    Attributes:
        windows: Словарь зарегистрированных окон {window_id: window_info}.

    Example:
        >>> wm = WindowManager()
        >>> isinstance(wm, WindowManagerProtocol)
        True
        >>> window = tk.Toplevel()
        >>> wid = wm.register_window(window, "Document 1", Path("doc.fxsd"))
        >>> wm.bring_to_front(wid)
    """

    def register_window(
        self,
        window: tk.Toplevel,
        title: str,
        document_path: Optional[Path] = None,
        is_modal: bool = False,
    ) -> str:
        """Регистрирует новое окно в менеджере.

        Args:
            window: Окно верхнего уровня Tkinter.
            title: Заголовок окна.
            document_path: Путь к открытому документу (опционально).
            is_modal: True если окно модальное (блокирует родителя).

        Returns:
            Уникальный идентификатор окна (window_id).

        Security:
            Путь к документу используется только для отображения.
            Фактическое открытие выполняется через DocumentService.

        Example:
            >>> window = tk.Toplevel()
            >>> wid = wm.register_window(window, "Invoice", Path("inv.fxsd"))
            >>> print(f"Window registered: {wid}")
        """
        ...

    def unregister_window(self, window_id: str) -> None:
        """Удаляет окно из менеджера.

        Args:
            window_id: Идентификатор окна для удаления.

        Note:
            Не закрывает само окно — только удаляет из внутреннего реестра.
            Для закрытия окна используйте window.destroy() перед вызовом.

        Example:
            >>> wm.unregister_window("window_001")
        """
        ...

    def get_window(self, window_id: str) -> Optional[tk.Toplevel]:
        """Возвращает окно по идентификатору.

        Args:
            window_id: Идентификатор окна.

        Returns:
            Окно tk.Toplevel или None если not found.

        Example:
            >>> window = wm.get_window("window_001")
            >>> if window:
            ...     window.title()
        """
        ...

    def bring_to_front(self, window_id: str) -> None:
        """Выводит окно на передний план.

        Args:
            window_id: Идентификатор окна.

        Raises:
            WindowNotFoundError: Если окно не существует.

        Example:
            >>> wm.bring_to_front("window_001")
            >>> # Окно активно и в фокусе
        """
        ...

    def minimize_all(self) -> None:
        """Сворачивает все окна в иконку.

        Example:
            >>> wm.minimize_all()
            >>> # Все окна свёрнуты
        """
        ...

    def restore_all(self) -> None:
        """Восстанавливает все свёрнутые окна.

        Example:
            >>> wm.restore_all()
            >>> # Все окна восстановлены
        """
        ...

    def close_all_except_main(self) -> None:
        """Закрывает все окна кроме главного.

        Security:
            Перед закрытием проверяет unsaved_changes у каждого окна.
            Показывает диалог подтверждения если есть несохранённые изменения.

        Example:
            >>> wm.close_all_except_main()
            >>> # Закрыты только вспомогательные окна
        """
        ...

    def get_window_list(self) -> list[Any]:
        """Возвращает список всех зарегистрированных окон.

        Returns:
            Список словарей с информацией об окнах:
            [{"window_id": str, "title": str, "is_modal": bool, ...}]

        Example:
            >>> windows = wm.get_window_list()
            >>> for w in windows:
            ...     print(f"{w['title']}: {w['window_id']}")
        """
        ...

    def transfer_document(self, from_id: str, to_id: str, doc_id: str) -> bool:
        """Передаёт документ между окнами.

        Args:
            from_id: Идентификатор исходного окна.
            to_id: Идентификатор целевого окна.
            doc_id: Идентификатор документа для передачи.

        Returns:
            True если передача выполнена успешно.

        Security:
            Проверяет права доступа к документу через DocumentLockService.
            Требует MFA для зашифрованных документов с пресетом PARANOID.

        Example:
            >>> success = wm.transfer_document("win_001", "win_002", "doc_123")
            >>> if success:
            ...     print("Документ передан")
        """
        ...


# ==============================================================================
# NOTIFICATION SERVICE PROTOCOL (Phase 7)
# ==============================================================================


@runtime_checkable
class NotificationServiceProtocol(Protocol):
    """Протокол для сервиса уведомлений.

    Управляет системой уведомлений приложения: создание, отображение,
    хранение истории, фильтрация по категориям и приоритетам.

    Categories:
        - "info": Информационные уведомления
        - "warning": Предупреждения
        - "error": Ошибки
        - "security": Security-события (MFA, подпись, шифрование)

    Priorities:
        - LOW: Фоновые уведомления
        - NORMAL: Обычные уведомления
        - HIGH: Требуют внимания
        - CRITICAL: Блокирующие, требуют действия

    Example:
        >>> ns = NotificationService()
        >>> isinstance(ns, NotificationServiceProtocol)
        True
        >>> nid = ns.notify("Документ сохранён", "info", Priority.NORMAL)
    """

    def notify(self, message: str, category: str, priority: Any) -> str:
        """Создаёт и отображает уведомление.

        Args:
            message: Текст уведомления.
            category: Категория уведомления ("info", "warning", "error", "security").
            priority: Приоритет (LOW, NORMAL, HIGH, CRITICAL).

        Returns:
            Идентификатор созданного уведомления.

        Security:
            Категория "security" используется только для MFA, подписи,
            шифрования. Не используется для обычных операций.

        Example:
            >>> nid = ns.notify("MFA верификация успешна", "security", Priority.HIGH)
            >>> ns.mark_as_read(nid)
        """
        ...

    def get_history(self, category: Optional[str] = None) -> list[Any]:
        """Возвращает историю уведомлений.

        Args:
            category: Фильтр по категории (None = все категории).

        Returns:
            Список уведомлений в хронологическом порядке (новые сначала).

        Example:
            >>> history = ns.get_history("security")
            >>> for n in history:
            ...     print(f"{n['timestamp']}: {n['message']}")
        """
        ...

    def mark_as_read(self, notification_id: str) -> None:
        """Отмечает уведомление как прочитанное.

        Args:
            notification_id: Идентификатор уведомления.

        Example:
            >>> ns.mark_as_read("notif_001")
        """
        ...

    def get_unread_count(self, category: Optional[str] = None) -> int:
        """Возвращает количество непрочитанных уведомлений.

        Args:
            category: Фильтр по категории (None = все категории).

        Returns:
            Количество непрочитанных уведомлений.

        Example:
            >>> count = ns.get_unread_count("security")
            >>> if count > 0:
            ...     print(f"{count} непрочитанных security-уведомлений")
        """
        ...


# ==============================================================================
# SYNC SERVICE PROTOCOL (Phase 7)
# ==============================================================================


@runtime_checkable
class SyncServiceProtocol(Protocol):
    """Протокол для синхронизации между окнами.

    Обеспечивает обмен данными между окнами приложения через
    broadcast-рассылку и зарегистрированные обработчики.

    Data Types:
        - "document_update": Обновление документа
        - "settings_change": Изменение настроек
        - "theme_change": Смена темы
        - "clipboard_update": Обновление буфера обмена

    Example:
        >>> ss = SyncService()
        >>> isinstance(ss, SyncServiceProtocol)
        True
        >>> handler_id = ss.register_handler("document_update", "win_001", on_update)
    """

    def broadcast(self, source_window_id: str, data_type: str, data: Any) -> None:
        """Рассылает данные всем зарегистрированным обработчикам.

        Args:
            source_window_id: Идентификатор окна-источника.
            data_type: Тип данных ("document_update", "settings_change", ...).
            data: Данные для передачи (специфичны для типа).

        Security:
            Данные передаются без шифрования между окнами (shared memory).
            Для sensitive data используйте DocumentService с шифрованием.

        Example:
            >>> ss.broadcast("win_001", "document_update", {"doc_id": "doc_123"})
        """
        ...

    def register_handler(self, data_type: str, window_id: str, handler: Callable[..., None]) -> str:
        """Регистрирует обработчик для типа данных.

        Args:
            data_type: Тип данных для обработки.
            window_id: Идентификатор окна-получателя.
            handler: Функция-обработчик (принимает data: Any).

        Returns:
            Идентификатор обработчика (handler_id).

        Example:
            >>> def on_update(data):
            ...     print(f"Updated: {data}")
            >>> hid = ss.register_handler("document_update", "win_001", on_update)
        """
        ...

    def unregister_handler(self, handler_id: str) -> None:
        """Удаляет зарегистрированный обработчик.

        Args:
            handler_id: Идентификатор обработчика.

        Example:
            >>> ss.unregister_handler("handler_001")
        """
        ...


# ==============================================================================
# DRAG-DROP SERVICE PROTOCOL (Phase 7)
# ==============================================================================


@runtime_checkable
class DragDropServiceProtocol(Protocol):
    """Протокол для drag-and-drop сервиса.

    Управляет drag-and-drop операциями между виджетами и окнами.
    Поддерживает начало перетаскивания, регистрацию целевых зон,
    отмену операции.

    Data Types:
        - "text": Текстовые данные
        - "file": Пути к файлам
        - "document": Ссылки на документы

    Example:
        >>> dds = DragDropService()
        >>> isinstance(dds, DragDropServiceProtocol)
        True
        >>> dds.start_drag("win_001", {"type": "text", "content": "Hello"})
    """

    def start_drag(self, source_window_id: str, data: Any) -> None:
        """Начинает операцию перетаскивания.

        Args:
            source_window_id: Идентификатор исходного окна.
            data: Данные для перетаскивания (содержит type и content).

        Security:
            Данные drag-and-drop не шифруются в процессе перетаскивания.
            Не используйте для передачи sensitive данных без шифрования.

        Example:
            >>> dds.start_drag("win_001", {
            ...     "type": "document",
            ...     "doc_id": "doc_123",
            ...     "preview": "Document preview..."
            ... })
        """
        ...

    def register_drop_target(self, widget: tk.Widget, target: Any) -> str:
        """Регистрирует виджет как целевую зону для drop.

        Args:
            widget: Tkinter виджет для регистрации.
            target: Объект-цель с методом on_drop(data).

        Returns:
            Идентификатор целевой зоны (target_id).

        Example:
            >>> target = DropTarget(on_drop=lambda d: print(d))
            >>> tid = dds.register_drop_target(widget, target)
        """
        ...

    def unregister_drop_target(self, target_id: str) -> None:
        """Удаляет регистрацию целевой зоны.

        Args:
            target_id: Идентификатор целевой зоны.

        Example:
            >>> dds.unregister_drop_target("target_001")
        """
        ...

    def is_dragging(self) -> bool:
        """Проверяет, выполняется ли операция перетаскивания.

        Returns:
            True если drag активен.

        Example:
            >>> if dds.is_dragging():
            ...     print("Drag in progress...")
        """
        ...

    def cancel_drag(self) -> None:
        """Отменяет текущую операцию перетаскивания.

        Example:
            >>> dds.cancel_drag()
            >>> assert not dds.is_dragging()
        """
        ...


# ==============================================================================
# PREVIEW PANEL PROTOCOL (Phase 7)
# ==============================================================================


@runtime_checkable
class PreviewPanelProtocol(Protocol):
    """Протокол для панели предпросмотра документа.

    Отображает визуальный предпросмотр документа с поддержкой
    двух режимов: hex-просмотр и визуальный предпросмотр.

    View Modes:
        - HEX_VIEW: Шестнадцатеричное представление данных
        - VISUAL_PREVIEW: Визуальный рендеринг документа

    Example:
        >>> panel = PreviewPanel()
        >>> isinstance(panel, PreviewPanelProtocol)
        True
        >>> panel.mount(parent_frame)
        >>> panel.set_preview_data(document_data)
    """

    def mount(self, parent: tk.Widget) -> tk.Widget:
        """Монтирует панель предпросмотра в родительский контейнер.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданная панель предпросмотра.

        Example:
            >>> frame = tk.Frame(root)
            >>> panel = preview.mount(frame)
            >>> panel.pack(fill=tk.BOTH, expand=True)
        """
        ...

    def unmount(self) -> None:
        """Демонтирует панель и освобождает ресурсы.

        Security:
            При демонтировании очищается отображаемый контент
            для предотвращения утечки sensitive данных.

        Example:
            >>> preview.unmount()
        """
        ...

    def set_preview_data(self, data: Any) -> None:
        """Устанавливает данные для предпросмотра.

        Args:
            data: Данные документа (bytes, Document, или специфичный формат).

        Security:
            Данные могут содержать sensitive информацию.
            Убедитесь что панель очищается при закрытии документа.

        Example:
            >>> preview.set_preview_data(document.to_bytes())
        """
        ...

    def show_hex_view(self) -> None:
        """Переключает панель в режим hex-просмотра.

        Отображает данные в шестнадцатеричном формате с
        адресами и ASCII-представлением.

        Example:
            >>> preview.show_hex_view()
            >>> # Отображается hex-дамп документа
        """
        ...

    def show_visual_preview(self) -> None:
        """Переключает панель в режим визуального предпросмотра.

        Отображает рендеринг документа как при печати,
        с форматированием и разметкой страницы.

        Example:
            >>> preview.show_visual_preview()
            >>> # Отображается WYSIWYG предпросмотр
        """
        ...


# ==============================================================================
# DOCUMENT VIEW PROTOCOL
# ==============================================================================


@runtime_checkable
class DocumentViewProtocol(Protocol):
    """Протокол для адаптации модели Document к View слою.

    Разрывает прямую зависимость View от Model, предоставляя
    интерфейс для доступа к данным документа без знания
    внутренней структуры Document.

    Совместим с DocumentProtocol из document_view.py: свойство `id`
    удовлетворяет оба протокола.

    Attributes:
        id: Уникальный идентификатор документа (строка).
        title: Заголовок документа для отображения.
        mode: Режим документа (DocumentMode).
        is_encrypted: Флаг зашифрованности документа.
        is_readonly: Флаг только для чтения.
        is_modified: Флаг наличия несохранённых изменений.

    Example:
        >>> view_data = DocumentViewAdapter(document)
        >>> isinstance(view_data, DocumentViewProtocol)
        True
        >>> view_data.title
        'Отчёт'
    """

    @property
    def id(self) -> str:
        """Уникальный идентификатор документа."""
        ...

    @property
    def title(self) -> str:
        """Заголовок документа для отображения во вкладке."""
        ...

    @property
    def mode(self) -> Any:
        """Режим документа (DocumentMode)."""
        ...

    @property
    def is_encrypted(self) -> bool:
        """Флаг зашифрованности документа."""
        ...

    @property
    def is_readonly(self) -> bool:
        """Флаг только для чтения."""
        ...

    @property
    def is_modified(self) -> bool:
        """Флаг наличия несохранённых изменений."""
        ...

    def get_content(self) -> str:
        """Возвращает текстовое содержимое документа.

        Returns:
            Текст из всех параграфов секций.
        """
        ...

    def get_cpi(self) -> int:
        """Возвращает CPI (characters per inch) документа.

        Returns:
            Количество символов на дюйм, по умолчанию 10.
        """
        ...

    def get_metadata(self) -> Any:
        """Возвращает метаданные документа (опционально).

        Returns:
            Объект метаданных или None.
        """
        ...

    def get_sections(self) -> list[Any]:
        """Возвращает список секций документа.

        Returns:
            Список секций (может быть пустым).
        """
        ...

    # Псевдоним doc_id для удобства (возвращает self.id)
    @property
    def doc_id(self) -> str:
        """Псевдоним id для использования в MainWindow.

        Возвращает тот же уникальный идентификатор документа,
        что и свойство id (для совместимости с DocumentProtocol).
        """
        ...


# ==============================================================================
# PASSWORD SERVICE PROTOCOL
# ==============================================================================


@runtime_checkable
class PasswordServiceProtocol(Protocol):
    """Протокол для сервиса паролей.

    Используется View для session lock без прямой зависимости
    от конкретной реализации PasswordService.

    Example:
        >>> isinstance(password_svc, PasswordServiceProtocol)
        True
    """

    def verify(self, user_id: str, password: str) -> bool:
        """Верифицирует пароль пользователя.

        Args:
            user_id: Идентификатор пользователя.
            password: Пароль для проверки.

        Returns:
            True если пароль верный.
        """
        ...


# ==============================================================================
# MFA MANAGER PROTOCOL
# ==============================================================================


@runtime_checkable
class MFAManagerProtocol(Protocol):
    """Протокол для менеджера MFA (SecondFactorManager).

    Используется View для session lock без прямой зависимости
    от конкретной реализации.

    Example:
        >>> isinstance(mfa_mgr, MFAManagerProtocol)
        True
    """

    def verify_totp(self, user_id: str, token: str) -> bool:
        """Верифицирует TOTP токен.

        Args:
            user_id: Идентификатор пользователя.
            token: TOTP код.

        Returns:
            True если токен валиден.
        """
        ...

    def verify_backup_code(self, user_id: str, code: str) -> bool:
        """Верифицирует резервный код.

        Args:
            user_id: Идентификатор пользователя.
            code: Резервный код.

        Returns:
            True если код валиден.
        """
        ...


# ==============================================================================
# MODE INTEGRATION PROTOCOL
# ==============================================================================


@runtime_checkable
class ModeIntegrationProtocol(Protocol):
    """Протокол для ModeIntegration (переключение рендереров).

    Используется View для смены режима Normal/Special
    без прямой зависимости от конкретной реализации.
    """

    def switch_mode(self, mode: Any, root: Any, controller: Any) -> None:
        """Переключает режим рендеринга.

        Args:
            mode: Целевой режим (DocumentMode).
            root: Корневое окно Tkinter.
            controller: Контроллер приложения.
        """
        ...


# ==============================================================================
# WORKFLOW STATE MANAGER PROTOCOL
# ==============================================================================


@runtime_checkable
class WorkflowStateManagerProtocol(Protocol):
    """Протокол для WorkflowStateManager.

    Обеспечивает интерфейс для управления состоянием workflow
    без прямой зависимости от конкретной реализации.
    """

    def set_simple_mode(self, simple: bool) -> None:
        """Переключает режим workflow (упрощённый/полный).

        Args:
            simple: True для упрощённого режима.
        """
        ...

    def get_last_undo_description(self) -> Optional[str]:
        """Возвращает описание последнего действия для undo.

        Returns:
            Описание действия или None.
        """
        ...

    def get_last_redo_description(self) -> Optional[str]:
        """Возвращает описание последнего действия для redo.

        Returns:
            Описание действия или None.
        """
        ...


# ==============================================================================
# HEALTH CHECK DIALOG PROTOCOL
# ==============================================================================


@runtime_checkable
class HealthCheckDialogProtocol(Protocol):
    """Протокол для HealthCheckDialog.

    Используется View для отображения диалога проверки здоровья
    без прямой зависимости от конкретной реализации.
    """

    def show(self) -> None:
        """Показывает диалог."""
        ...

    def destroy(self) -> None:
        """Уничтожает диалог."""
        ...


# ==============================================================================
# UNDO REDO MENU ITEMS PROTOCOL
# ==============================================================================


@runtime_checkable
class UndoRedoMenuItemsProtocol(Protocol):
    """Протокол для UndoRedoMenuItems.

    Используется View для добавления динамических пунктов undo/redo
    в меню workflow.
    """

    def add_to_menu(self, menu: tk.Menu) -> None:
        """Добавляет пункты undo/redo в меню.

        Args:
            menu: Tkinter Menu для добавления пунктов.
        """
        ...


# ==============================================================================
# MODE TOGGLE PROTOCOL
# ==============================================================================


@runtime_checkable
class ModeToggleProtocol(Protocol):
    """Протокол для виджета ModeToggle.

    Используется View для визуального переключения режимов
    без прямой зависимости от конкретной реализации.
    """

    def pack(self, **kwargs: Any) -> None:
        """Упаковывает виджет в контейнер."""
        ...


# ==============================================================================
# WORKFLOW MANAGER PROTOCOL
# ==============================================================================


@runtime_checkable
class WorkflowManagerProtocol(Protocol):
    """Протокол для WorkflowManager.

    Используется View для управления видимостью действий workflow
    и получения текущей роли.
    """

    @property
    def current_role(self) -> Any:
        """Текущая роль в workflow."""
        ...


# ==============================================================================
# WORKFLOW UI FACTORY PROTOCOL
# ==============================================================================


@runtime_checkable
class WorkflowUIFactoryProtocol(Protocol):
    """Протокол для WorkflowUIFactory.

    Используется View для создания диалогов workflow с MFA.
    """

    def create_dialog(self, parent: Any, dialog_type: str, **kwargs: Any) -> Any:
        """Создаёт диалог workflow с MFA защитой.

        Args:
            parent: Родительское окно.
            dialog_type: Тип диалога.
            **kwargs: Параметры диалога.

        Returns:
            Созданный диалог.
        """
        ...


# ==============================================================================
# SESSION MANAGER PROTOCOL
# ==============================================================================


@runtime_checkable
class SessionManagerProtocol(Protocol):
    """Протокол для SessionManager.

    Используется View для управления сессиями аутентификации.
    """

    def issue(self, user_id: str) -> Any:
        """Выпускает токен сессии.

        Args:
            user_id: Идентификатор пользователя.

        Returns:
            TokenBundle с session_id.
        """
        ...


# ==============================================================================
# MAIN TOOLBAR PROTOCOL
# ==============================================================================


@runtime_checkable
class MainToolbarProtocol(Protocol):
    """Протокол для MainToolbar.

    Используется View для работы с тулбаром без прямой зависимости.
    """

    def mount(self, parent: Any) -> Any:
        """Монтирует тулбар в родительский контейнер."""
        ...


# ==============================================================================
# MODULE METADATA
# ==============================================================================

__all__: list[str] = [
    "EventProtocol",
    "WidgetProtocol",
    "SmartWidgetProtocol",
    "ControllerProtocol",
    "DocumentControllerProtocol",
    "WorkflowControllerProtocol",
    "TemplateControllerProtocol",
    "WindowManagerProtocol",
    "NotificationServiceProtocol",
    "SyncServiceProtocol",
    "DragDropServiceProtocol",
    "PreviewPanelProtocol",
    "FormFieldProtocol",
    "DocumentViewProtocol",
    "PasswordServiceProtocol",
    "MFAManagerProtocol",
    "ModeIntegrationProtocol",
    "WorkflowStateManagerProtocol",
    "HealthCheckDialogProtocol",
    "UndoRedoMenuItemsProtocol",
    "ModeToggleProtocol",
    "WorkflowManagerProtocol",
    "WorkflowUIFactoryProtocol",
    "SessionManagerProtocol",
    "MainToolbarProtocol",
]
