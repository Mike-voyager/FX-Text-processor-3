"""Интеграция валидации кодировки для FreeForm редактора.

Модуль предоставляет FreeFormValidationController — контроллер для координации
валидации PC866 между рендерером, валидатором и панелью инструментов.

Features:
- Автоматическая валидация текста при изменении
- Подсветка невалидных символов
- Кнопка "Исправить" с бейджем счётчика
- Toast уведомления о результатах валидации

Example:
    >>> from src.gui.modes.free_form.validation_integration import FreeFormValidationController
    >>> controller = FreeFormValidationController(
    ...     renderer=renderer,
    ...     toolbar=toolbar,
    ...     toast_service=toast_service,
    ... )
    >>> controller.on_text_changed("Hello — world")
    >>> controller.get_invalid_count()
    1
    >>> controller.fix_all()  # "Hello - world"

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from src.gui.components.codepage_validator import CodepageValidator, ValidationResult
from src.gui.views import ToastLevel

if TYPE_CHECKING:
    from src.gui.components.format_toolbar import FormatToolbar
    from src.gui.modes.free_form.renderer import FreeFormModeRenderer
    from src.gui.views import ToastServiceProtocol


class FreeFormValidationController:
    """Контроллер валидации кодировки для FreeForm редактора.

    Координирует работу между:
    - FreeFormModeRenderer (подсветка невалидных символов)
    - CodepageValidator (проверка PC866 совместимости)
    - FormatToolbar (UI: кнопка исправления, бейдж счётчика)

    Attributes:
        _renderer: Ссылка на рендерер для подсветки.
        _toolbar: Ссылка на панель инструментов.
        _validator: Экземпляр CodepageValidator.
        _toast_service: Опциональный сервис уведомлений.
        _current_invalid_count: Текущее количество невалидных символов.
        _validation_results: Последние результаты валидации.

    Example:
        >>> controller = FreeFormValidationController(renderer, toolbar)
        >>> controller.on_text_changed("Test — 123")
        >>> controller.get_invalid_count()
        1
        >>> controller.fix_all()  # Заменяет em-dash на hyphen
    """

    def __init__(
        self,
        renderer: FreeFormModeRenderer,
        toolbar: FormatToolbar,
        toast_service: Optional[ToastServiceProtocol] = None,
    ) -> None:
        """Инициализация контроллера валидации.

        Args:
            renderer: Рендерер FreeForm для подсветки.
            toolbar: Панель инструментов для обновления UI.
            toast_service: Опциональный сервис уведомлений.

        Example:
            >>> controller = FreeFormValidationController(
            ...     renderer=renderer,
            ...     toolbar=toolbar,
            ...     toast_service=main_window.get_toast_service(),
            ... )
        """
        self._renderer: FreeFormModeRenderer = renderer
        self._toolbar: FormatToolbar = toolbar
        self._validator: CodepageValidator = CodepageValidator()
        self._toast_service: Optional[ToastServiceProtocol] = toast_service
        self._current_invalid_count: int = 0
        self._validation_results: list[ValidationResult] = []
        self._last_fixed_count: int = 0

        # Устанавливаем callback для кнопки исправления
        self._toolbar.set_on_fix_validation_callback(self._on_fix_clicked)

        # Изначально отключаем кнопку исправления
        self._toolbar.set_fix_validation_enabled(False)
        self._toolbar.set_validation_badge(0)

    def on_text_changed(self, text: str) -> None:
        """Обрабатывает изменение текста и запускает валидацию.

        Вызывается при каждом изменении текста в редакторе.
        Выполняет валидацию, обновляет подсветку и UI.

        Args:
            text: Текущий текст редактора.

        Example:
            >>> controller.on_text_changed("Hello — world")
            >>> # Подсвечивает em-dash, обновляет бейдж
        """
        # Очищаем предыдущие подсветки
        self._renderer.clear_validation_highlights()

        # Выполняем валидацию
        self._validation_results = self._validator.validate(text)
        self._current_invalid_count = len(self._validation_results)

        # Применяем подсветку
        for result in self._validation_results:
            self._renderer.highlight_invalid_char(result.position, len(result.char))

        # Обновляем UI панели инструментов
        self._update_toolbar_ui()

        # Показываем toast если обнаружены невалидные символы
        if self._current_invalid_count > 0 and self._toast_service is not None:
            self._show_validation_detected_toast()

    def _update_toolbar_ui(self) -> None:
        """Обновляет UI панели инструментов на основе результатов валидации.

        Обновляет:
        - Бейдж с количеством невалидных символов
        - Состояние кнопки "Исправить" (enabled/disabled)
        """
        self._toolbar.set_validation_badge(self._current_invalid_count)
        self._toolbar.set_fix_validation_enabled(self._current_invalid_count > 0)

    def fix_all(self) -> str:
        """Применяет все возможные замены к текущему тексту.

        Использует CodepageValidator.fix_all() для замены несовместимых
        символов на их ASCII-эквиваленты. Обновляет текст в редакторе.

        Returns:
            Исправленный текст.

        Example:
            >>> text = "ёлка — \"test\""
            >>> fixed = controller.fix_all()
            >>> print(fixed)  # 'елка - "test"'
        """
        # Получаем текущий текст
        current_text = self._renderer.get_content()

        # Считаем сколько было невалидных символов
        old_invalid_count = self._current_invalid_count

        # Применяем замены
        fixed_text = self._validator.fix_all(current_text)

        # Обновляем текст в редакторе (через set_content)
        self._renderer.set_content(fixed_text)

        # Очищаем подсветку
        self._renderer.clear_validation_highlights()

        # Перевалидируем исправленный текст
        self._validation_results = self._validator.validate(fixed_text)
        self._current_invalid_count = len(self._validation_results)
        self._last_fixed_count = old_invalid_count - self._current_invalid_count

        # Обновляем UI
        self._update_toolbar_ui()

        # Показываем toast о результате
        if self._toast_service is not None and self._last_fixed_count > 0:
            self._show_fix_applied_toast()

        return fixed_text

    def get_invalid_count(self) -> int:
        """Возвращает количество невалидных символов в текущем тексте.

        Returns:
            Количество символов, не поддерживаемых PC866.

        Example:
            >>> controller.on_text_changed("Test — 123")
            >>> controller.get_invalid_count()
            1
        """
        return self._current_invalid_count

    def get_validation_results(self) -> list[ValidationResult]:
        """Возвращает детальные результаты валидации.

        Returns:
            Список ValidationResult для всех невалидных символов.

        Example:
            >>> results = controller.get_validation_results()
            >>> for r in results:
            ...     print(f"{r.char} at {r.position} -> {r.replacement}")
        """
        return self._validation_results.copy()

    def has_invalid_chars(self) -> bool:
        """Проверяет, есть ли невалидные символы в тексте.

        Returns:
            True если есть несовместимые с PC866 символы.

        Example:
            >>> controller.on_text_changed("Hello")
            >>> controller.has_invalid_chars()
            False
        """
        return self._current_invalid_count > 0

    def _on_fix_clicked(self) -> None:
        """Обработчик нажатия на кнопку "Исправить".

        Вызывается когда пользователь нажимает кнопку исправления
        в панели инструментов.
        """
        self.fix_all()

    def _show_validation_detected_toast(self) -> None:
        """Показывает toast об обнаружении невалидных символов.

        Сообщение: "Обнаружены символы не из PC866"
        """
        if self._toast_service is not None:
            self._toast_service.show(
                message="Обнаружены символы не из PC866",
                level=ToastLevel.WARNING,
            )

    def _show_fix_applied_toast(self) -> None:
        """Показывает toast о применённых исправлениях.

        Сообщение: "Исправлено N символов"
        """
        if self._toast_service is not None:
            count = self._last_fixed_count
            if count == 0:
                message = "Символы для исправления не найдены"
            elif count == 1:
                message = "Исправлен 1 символ"
            else:
                message = f"Исправлено {count} символов"
            self._toast_service.show(
                message=message,
                level=ToastLevel.SUCCESS,
            )

    def set_toast_service(self, toast_service: Optional[ToastServiceProtocol]) -> None:
        """Устанавливает или обновляет сервис уведомлений.

        Args:
            toast_service: Новый сервис уведомлений или None.

        Example:
            >>> controller.set_toast_service(main_window.get_toast_service())
        """
        self._toast_service = toast_service

    def clear_validation(self) -> None:
        """Очищает все результаты валидации и подсветки.

        Вызывается при закрытии документа или смене контекста.
        """
        self._renderer.clear_validation_highlights()
        self._validation_results = []
        self._current_invalid_count = 0
        self._update_toolbar_ui()


__all__: list[str] = [
    "FreeFormValidationController",
]
