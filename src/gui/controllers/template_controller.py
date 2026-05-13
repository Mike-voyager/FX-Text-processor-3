"""Контроллер для управления шаблонами (.fxstpl).

Связывает GUI компоненты с сервисным слоем TemplateManager.
Обрабатывает импорт, экспорт и загрузку шаблонов.

Module: src/gui/controllers/template_controller.py
Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import logging
from pathlib import Path
from tkinter import filedialog
from typing import Any, Optional

from src.gui.core.protocols import TemplateControllerProtocol
from src.services.template_manager import TemplateManager

logger = logging.getLogger(__name__)


class TemplateController(TemplateControllerProtocol):
    """Контроллер для управления шаблонами.

    Управляет жизненным циклом шаблонов:
    - Импорт из файла (.fxstpl)
    - Экспорт в файл
    - Загрузка в редактор
    - Создание новых шаблонов

    Принимает TemplateManager через DI в конструктор.

    Attributes:
        controller_id: Уникальный идентификатор контроллера.
        _service: Сервис управления шаблонами.

    Example:
        >>> from src.gui.controllers.template_controller import TemplateController
        >>> controller = TemplateController(template_manager)
        >>> controller.dispatch("import_template", source_path=Path("template.fxs.tpl"))
    """

    def __init__(
        self,
        service: TemplateManager,
    ) -> None:
        """Инициализирует контроллер шаблонов.

        Args:
            service: Сервис управления шаблонами.
        """
        self.controller_id = "template_controller"
        self._service: TemplateManager = service
        self._views: dict[str, Any] = {}

    # --- Диспетчеризация ---

    def dispatch(self, action: str, **kwargs: Any) -> Optional[Any]:
        """Диспетчирует действие в подметоды контроллера.

        Реализует только маршрутизацию — NO бизнес-логики.

        Args:
            action: Идентификатор действия ("import_template", "export_template", "load_template").
            **kwargs: Параметры действия.

        Returns:
            Результат выполнения или None.

        Example:
            >>> controller.dispatch("on_import_template")
        """
        if action == "on_import_template":
            return self.on_import_template(**kwargs)
        elif action == "on_export_template":
            return self.on_export_template(**kwargs)
        elif action == "on_load_template":
            return self.on_load_template(**kwargs)
        return None

    # --- TemplateControllerProtocol реализация ---

    def on_import_template(self, source_path: Optional[Path] = None) -> bool:
        """Импортирует шаблон из файла.

        Открывает диалог загрузки файла, импортирует шаблон
        и сохраняет в менеджер шаблонов.

        Args:
            source_path: Путь к исходному файлу (опционально, если None — диалог).

        Returns:
            True если импорт успешен, False при отмене или ошибке.

        Example:
            >>> if controller.on_import_template():
            ...     print("Шаблон импортирован")
        """
        if source_path is None:
            # Show file dialog to select template file
            file_path = filedialog.askopenfilename(
                title="Выберите шаблон для импорта",
                filetypes=[
                    ("Шаблоны FX", "*.fxstpl"),
                    ("Все файлы", "*.*"),
                ],
            )
            if not file_path:
                # User cancelled the dialog
                return False
            source_path = Path(file_path)

        assert source_path is not None

        if source_path.suffix.lower() != ".fxstpl":
            self._notify_views(
                "import_status",
                {
                    "success": False,
                    "error": "Неверное расширение файла. Ожидается .fxstpl",
                },
            )
            return False

        try:
            template = self._service.import_template(source_path)
            logger.info("Template imported: %s", template.template_id)
            self._notify_views(
                "import_status",
                {
                    "success": True,
                    "template_id": template.template_id,
                    "name": template.name,
                },
            )
            return True
        except FileNotFoundError:
            logger.error("Template file not found: %s", source_path)
            self._notify_views(
                "import_status",
                {"success": False, "error": "Файл не найден"},
            )
            return False
        except PermissionError:
            logger.error("Permission denied for template file: %s", source_path)
            self._notify_views(
                "import_status",
                {"success": False, "error": "Нет доступа к файлу"},
            )
            return False
        except ValueError as e:
            logger.error("Template validation error: %s", e)
            self._notify_views(
                "import_status",
                {"success": False, "error": "Ошибка формата шаблона"},
            )
            return False

    def on_export_template(
        self,
        template_id: Optional[str] = None,
        dest_path: Optional[Path] = None,
    ) -> bool:
        """Экспортирует шаблон в файл.

        Открывает диалог сохранения, экспортирует указанный
        или текущий шаблон в файл.

        Args:
            template_id: ID шаблона для экспорта (опционально).
            dest_path: Путь назначения (опционально, если None — диалог).

        Returns:
            True если экспорт успешен, False при отмене или ошибке.

        Example:
            >>> if controller.on_export_template("tpl-123"):
            ...     print("Шаблон экспортирован")
        """
        if template_id is None:
            logger.warning("No template ID specified for export")
            self._notify_views(
                "export_status",
                {"success": False, "error": "Не указан ID шаблона"},
            )
            return False

        if dest_path is None:
            file_path = filedialog.asksaveasfilename(
                title="Сохранить шаблон",
                defaultextension=".fxstpl",
                filetypes=[
                    ("Шаблоны FX", "*.fxstpl"),
                    ("Все файлы", "*.*"),
                ],
                initialfile=f"{template_id}.fxstpl",
            )
            if not file_path:
                return False
            dest_path = Path(file_path)

        assert dest_path is not None

        try:
            self._service.export_template(template_id, dest_path)
            logger.info("Template exported: %s", template_id)
            self._notify_views(
                "export_status",
                {
                    "success": True,
                    "template_id": template_id,
                    "path": str(dest_path),
                },
            )
            return True
        except FileNotFoundError:
            logger.error("Template not found for export: %s", template_id)
            self._notify_views(
                "export_status",
                {"success": False, "error": "Шаблон не найден"},
            )
            return False
        except PermissionError:
            logger.error("Permission denied for export: %s", dest_path)
            self._notify_views(
                "export_status",
                {"success": False, "error": "Нет доступа к файлу"},
            )
            return False
        except ValueError as e:
            logger.error("Template export validation error: %s", e)
            self._notify_views(
                "export_status",
                {"success": False, "error": "Ошибка шаблона"},
            )
            return False

    def on_load_template(self, template_id: str) -> bool:
        """Загружает шаблон в редактор.

        Загружает указанный шаблон и передаёт его в View
        для отображения в редакторе шаблонов.

        Args:
            template_id: Идентификатор загружаемого шаблона.

        Returns:
            True если загрузка успешна, False при ошибке.

        Example:
            >>> if controller.on_load_template("tpl-123"):
            ...     print("Шаблон загружен")
        """
        try:
            template = self._service.load_template(template_id)
            logger.info("Template loaded: %s", template_id)
            self._notify_views(
                "template_editor",
                {
                    "template": template,
                    "template_id": template_id,
                },
            )
            return True
        except Exception as e:
            logger.error("Failed to load template: %s", e, exc_info=True)
            self._notify_views(
                "template_editor",
                {
                    "success": False,
                    "error": str(e),
                },
            )
            return False

    def on_create_template(
        self,
        name: str,
        name_ru: str,
        doc_type: str,
    ) -> bool:
        """Создаёт новый шаблон.

        Создаёт пустой шаблон и инициализирует его в редакторе.

        Args:
            name: Название шаблона (англ.).
            name_ru: Название шаблона (рус.).
            doc_type: Код типа документа.

        Returns:
            True если создание успешное.

        Example:
            >>> controller.on_create_template("Invoice", "Накладная", "DVN-44-K53")
        """
        try:
            template = self._service.create_template(name, name_ru, doc_type)
            logger.info("Template created: %s", template.template_id)
            self._notify_views(
                "template_editor",
                {
                    "template": template,
                    "template_id": template.template_id,
                    "new": True,
                },
            )
            return True
        except Exception as e:
            logger.error("Failed to create template: %s", e, exc_info=True)
            return False

    # --- Internal helpers ---

    def _notify_views(self, widget_id: str, data: Any) -> None:
        """Уведомляет зарегистрированные View об изменениях.

        Args:
            widget_id: Идентификатор виджета.
            data: Данные для обновления.
        """
        callback = self._views.get(widget_id)
        if callback is not None:
            callback(widget_id, data)

    # --- ControllerProtocol реализация ---

    def notify_view_update(self, widget_id: str, data: Any) -> None:
        """Уведомляет View об изменениях в Model.

        Реализует ControllerProtocol.notify_view_update().

        Args:
            widget_id: Идентификатор виджета для обновления.
            data: Данные для обновления.
        """
        self._notify_views(widget_id, data)

    def register_view(self, widget_id: str, callback: Any) -> None:
        """Регистрирует callback для обновления View.

        Реализует ControllerProtocol.register_view().

        Args:
            widget_id: Идентификатор виджета.
            callback: Функция обратного вызова.
        """
        self._views[widget_id] = callback

    def unregister_view(self, widget_id: str) -> None:
        """Отменяет регистрацию View callback.

        Реализует ControllerProtocol.unregister_view().

        Args:
            widget_id: Идентификатор виджета.
        """
        if widget_id in self._views:
            del self._views[widget_id]
