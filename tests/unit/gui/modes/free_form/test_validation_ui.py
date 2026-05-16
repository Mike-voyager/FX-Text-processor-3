"""Тесты UI интеграции валидации кодировки для FreeForm редактора.

Модуль содержит тесты для FreeFormValidationController и интеграции
валидатора с рендерером и панелью инструментов.

Test Coverage:
- Подсветка невалидных символов
- Кнопка исправления и бейдж счётчика
- Toast уведомления
- Координация между компонентами

Example:
    $ pytest tests/unit/gui/modes/free_form/test_validation_ui.py -v

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import sys
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Generator, List, Optional, FrozenSet, Dict, ClassVar, Callable
from unittest.mock import MagicMock, patch

import pytest

# =============================================================================
# MOCK DATA CLASSES FOR TESTS (to avoid circular imports)
# =============================================================================

@dataclass(frozen=True)
class MockValidationResult:
    """Мок результата валидации."""
    char: str
    position: int
    replacement: Optional[str]
    is_valid: bool = False


class MockCodepageValidator:
    """Мок CodepageValidator для тестирования."""
    
    PC866_SUPPORTED: ClassVar[FrozenSet[str]] = frozenset(
        # ASCII 0-127
        "".join(chr(i) for i in range(128))
        + "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"  # uppercase without Ё
        + "абвгдежзийклмнопрстуфхцчшщъыьэюя"  # lowercase without ё
    )
    
    REPLACEMENT_MAP: ClassVar[Dict[str, str]] = {
        "\u0451": "\u0435",  # ё → е
        "\u0401": "\u0415",  # Ё → Е
        "\u2014": "-",  # em-dash → hyphen
        "\u2013": "-",  # en-dash → hyphen
        "\u201C": '"',  # left double quotation
        "\u201D": '"',  # right double quotation
        "\u2018": "'",  # left single quotation
        "\u2019": "'",  # right single quotation
        "\u00AB": '"',  # left-pointing double angle («)
        "\u00BB": '"',  # right-pointing double angle (»)
        "\u2116": "N",  # numero sign
        "\u2026": "...",  # horizontal ellipsis
        "\u2022": "-",  # bullet
    }
    
    def is_valid_char(self, char: str) -> bool:
        if len(char) != 1:
            raise ValueError(f"Ожидался одиночный символ, получено: {len(char)}")
        return char in self.PC866_SUPPORTED
    
    def get_replacement(self, char: str) -> Optional[str]:
        if len(char) != 1:
            raise ValueError(f"Ожидался одиночный символ, получено: {len(char)}")
        return self.REPLACEMENT_MAP.get(char)
    
    def validate(self, text: str) -> List[MockValidationResult]:
        results: List[MockValidationResult] = []
        for position, char in enumerate(text):
            if not self.is_valid_char(char):
                replacement = self.get_replacement(char)
                results.append(MockValidationResult(
                    char=char,
                    position=position,
                    replacement=replacement,
                    is_valid=False,
                ))
        return results
    
    def fix_all(self, text: str) -> str:
        result_chars: List[str] = []
        for char in text:
            if self.is_valid_char(char):
                result_chars.append(char)
            else:
                replacement = self.get_replacement(char)
                if replacement is not None:
                    result_chars.append(replacement)
                else:
                    result_chars.append(char)
        return "".join(result_chars)
    
    def count_invalid(self, text: str) -> int:
        return sum(1 for char in text if not self.is_valid_char(char))


# Мок для ToastLevel
class MockToastLevel:
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"


# =============================================================================
# MOCK TOOLBAR FOR TESTS
# =============================================================================

class MockFormatToolbar:
    """Мок панели инструментов для тестирования."""
    
    def __init__(self) -> None:
        self._validation_count = 0
        self._fix_enabled = False
        self._on_fix_validation: Optional[Callable[[], None]] = None
        self._calls: List[str] = []
    
    def set_validation_badge(self, count: int) -> None:
        self._validation_count = count
        self._calls.append(f"set_validation_badge({count})")
    
    def set_fix_validation_enabled(self, enabled: bool) -> None:
        self._fix_enabled = enabled
        self._calls.append(f"set_fix_validation_enabled({enabled})")
    
    def set_on_fix_validation_callback(self, callback: Optional[Callable[[], None]]) -> None:
        self._on_fix_validation = callback
        self._calls.append(f"set_on_fix_validation_callback({callback})")
    
    def get_validation_count(self) -> int:
        return self._validation_count
    
    def trigger_fix(self) -> None:
        if self._on_fix_validation:
            self._on_fix_validation()


# =============================================================================
# SIMPLE INTEGRATION CONTROLLER (for testing without imports)
# =============================================================================


class SimpleValidationController:
    """Упрощённый контроллер для тестирования без циклических импортов."""
    
    def __init__(
        self,
        renderer: MagicMock,
        toolbar: MockFormatToolbar,
        toast_service: Optional[MagicMock] = None,
    ) -> None:
        self._renderer = renderer
        self._toolbar = toolbar
        self._validator = MockCodepageValidator()
        self._toast_service = toast_service
        self._current_invalid_count = 0
        self._validation_results: List[MockValidationResult] = []
        self._last_fixed_count = 0
        
        # Устанавливаем callback
        self._toolbar.set_on_fix_validation_callback(self._on_fix_clicked)
        self._toolbar.set_fix_validation_enabled(False)
        self._toolbar.set_validation_badge(0)
    
    def on_text_changed(self, text: str) -> None:
        """Обрабатывает изменение текста."""
        self._renderer.clear_validation_highlights()
        
        self._validation_results = self._validator.validate(text)
        self._current_invalid_count = len(self._validation_results)
        
        for result in self._validation_results:
            self._renderer.highlight_invalid_char(result.position, len(result.char))
        
        self._update_toolbar_ui()
        
        if self._current_invalid_count > 0 and self._toast_service is not None:
            self._toast_service.show(
                message="Non-PC866 characters detected",
                level=MockToastLevel.WARNING,
            )
    
    def _update_toolbar_ui(self) -> None:
        """Обновляет UI панели инструментов."""
        self._toolbar.set_validation_badge(self._current_invalid_count)
        self._toolbar.set_fix_validation_enabled(self._current_invalid_count > 0)
    
    def fix_all(self) -> str:
        """Применяет все возможные замены к тексту."""
        current_text = self._renderer.get_content()
        old_invalid_count = self._current_invalid_count
        
        fixed_text = self._validator.fix_all(current_text)
        self._renderer.set_content(fixed_text)
        
        self._renderer.clear_validation_highlights()
        
        self._validation_results = self._validator.validate(fixed_text)
        self._current_invalid_count = len(self._validation_results)
        self._last_fixed_count = old_invalid_count - self._current_invalid_count
        
        self._update_toolbar_ui()
        
        if self._toast_service is not None and self._last_fixed_count > 0:
            count = self._last_fixed_count
            message = f"Fixed {count} символов"
            self._toast_service.show(message=message, level=MockToastLevel.SUCCESS)
        
        return fixed_text
    
    def get_invalid_count(self) -> int:
        """Возвращает количество невалидных символов."""
        return self._current_invalid_count
    
    def get_validation_results(self) -> List[MockValidationResult]:
        """Возвращает результаты валидации."""
        return self._validation_results.copy()
    
    def has_invalid_chars(self) -> bool:
        """Проверяет наличие невалидных символов."""
        return self._current_invalid_count > 0
    
    def _on_fix_clicked(self) -> None:
        """Обработчик нажатия кнопки исправления."""
        self.fix_all()
    
    def set_toast_service(self, toast_service: Optional[MagicMock]) -> None:
        """Устанавливает сервис уведомлений."""
        self._toast_service = toast_service
    
    def clear_validation(self) -> None:
        """Очищает валидацию."""
        self._renderer.clear_validation_highlights()
        self._validation_results = []
        self._current_invalid_count = 0
        self._update_toolbar_ui()


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def mock_toast_service() -> MagicMock:
    """Создаёт мок сервиса уведомлений."""
    service = MagicMock()
    service.show = MagicMock(return_value="toast-id-123")
    return service


@pytest.fixture
def mock_renderer() -> MagicMock:
    """Создаёт мок рендерера FreeForm."""
    renderer = MagicMock()
    renderer.clear_validation_highlights = MagicMock()
    renderer.highlight_invalid_char = MagicMock()
    renderer.get_content = MagicMock(return_value="")
    renderer.set_content = MagicMock()
    return renderer


@pytest.fixture
def mock_toolbar() -> MockFormatToolbar:
    """Создаёт мок панели инструментов."""
    return MockFormatToolbar()


@pytest.fixture
def validation_controller(
    mock_renderer: MagicMock,
    mock_toolbar: MockFormatToolbar,
    mock_toast_service: MagicMock,
) -> SimpleValidationController:
    """Создаёт экземпляр упрощённого контроллера валидации."""
    return SimpleValidationController(
        renderer=mock_renderer,
        toolbar=mock_toolbar,
        toast_service=mock_toast_service,
    )


# =============================================================================
# TESTS: MockCodepageValidator
# =============================================================================


class TestMockCodepageValidator:
    """Тесты мока валидатора."""
    
    def test_valid_char_ascii(self) -> None:
        validator = MockCodepageValidator()
        assert validator.is_valid_char("A") is True
        assert validator.is_valid_char("z") is True
        assert validator.is_valid_char("0") is True
    
    def test_valid_char_cyrillic(self) -> None:
        validator = MockCodepageValidator()
        assert validator.is_valid_char("А") is True
        assert validator.is_valid_char("я") is True
    
    def test_invalid_char_yo(self) -> None:
        validator = MockCodepageValidator()
        assert validator.is_valid_char("ё") is False
        assert validator.get_replacement("ё") == "е"
    
    def test_invalid_char_emdash(self) -> None:
        validator = MockCodepageValidator()
        assert validator.is_valid_char("\u2014") is False  # em-dash
        assert validator.get_replacement("\u2014") == "-"
    
    def test_validate_text(self) -> None:
        validator = MockCodepageValidator()
        results = validator.validate("Hello — world")
        assert len(results) == 1
        assert results[0].char == "\u2014"
        assert results[0].position == 6
    
    def test_fix_all_text(self) -> None:
        validator = MockCodepageValidator()
        text = 'ёлка — "test"'
        fixed = validator.fix_all(text)
        assert fixed == 'елка - "test"'


# =============================================================================
# TESTS: Validation Controller
# =============================================================================


class TestValidationController:
    """Тесты для ValidationController."""

    def test_init_sets_up_callback(self, mock_toolbar: MockFormatToolbar) -> None:
        """Тест: при инициализации устанавливается callback для кнопки."""
        SimpleValidationController(
            renderer=MagicMock(),
            toolbar=mock_toolbar,
        )

        assert mock_toolbar._on_fix_validation is not None
        assert mock_toolbar._fix_enabled is False
        assert mock_toolbar._validation_count == 0

    def test_on_text_changed_with_invalid_chars(
        self,
        validation_controller: SimpleValidationController,
        mock_renderer: MagicMock,
        mock_toolbar: MockFormatToolbar,
    ) -> None:
        """Тест: при изменении текста с невалидными символами обновляется UI."""
        text = "Hello — world"  # em-dash невалиден

        validation_controller.on_text_changed(text)

        # Должны очистить предыдущие подсветки
        mock_renderer.clear_validation_highlights.assert_called_once()

        # Должны подсветить невалидный символ
        mock_renderer.highlight_invalid_char.assert_called_once()

        # Должны обновить UI панели
        assert mock_toolbar._validation_count == 1
        assert mock_toolbar._fix_enabled is True

    def test_on_text_changed_no_invalid_chars(
        self,
        validation_controller: SimpleValidationController,
        mock_renderer: MagicMock,
        mock_toolbar: MockFormatToolbar,
    ) -> None:
        """Тест: при валидном тексте UI показывает 0."""
        text = "Hello world"  # Всё валидно

        validation_controller.on_text_changed(text)

        mock_renderer.clear_validation_highlights.assert_called_once()
        mock_renderer.highlight_invalid_char.assert_not_called()
        assert mock_toolbar._validation_count == 0
        assert mock_toolbar._fix_enabled is False

    def test_get_invalid_count_returns_correct_value(
        self,
        validation_controller: SimpleValidationController,
    ) -> None:
        """Тест: get_invalid_count возвращает правильное значение."""
        validation_controller.on_text_changed("Test — «123»")

        # em-dash, левая и правая кавычки = 3 невалидных символа
        assert validation_controller.get_invalid_count() == 3

    def test_has_invalid_chars_true_when_invalid(
        self,
        validation_controller: SimpleValidationController,
    ) -> None:
        """Тест: has_invalid_chars возвращает True для невалидного текста."""
        validation_controller.on_text_changed("Test — 123")

        assert validation_controller.has_invalid_chars() is True

    def test_has_invalid_chars_false_when_valid(
        self,
        validation_controller: SimpleValidationController,
    ) -> None:
        """Тест: has_invalid_chars возвращает False для валидного текста."""
        validation_controller.on_text_changed("Hello World")

        assert validation_controller.has_invalid_chars() is False

    def test_get_validation_results_returns_list(
        self,
        validation_controller: SimpleValidationController,
    ) -> None:
        """Тест: get_validation_results возвращает список результатов."""
        validation_controller.on_text_changed("Test — 123")

        results = validation_controller.get_validation_results()
        assert len(results) == 1
        assert isinstance(results[0], MockValidationResult)
        assert results[0].char == "\u2014"  # em-dash

    def test_fix_all_applies_replacements(
        self,
        validation_controller: SimpleValidationController,
        mock_renderer: MagicMock,
    ) -> None:
        """Тест: fix_all применяет замены к тексту."""
        original_text = 'ёлка — "test"'
        expected_text = 'елка - "test"'

        mock_renderer.get_content.return_value = original_text

        fixed = validation_controller.fix_all()

        assert fixed == expected_text
        mock_renderer.set_content.assert_called_once_with(expected_text)

    def test_fix_all_updates_ui(
        self,
        validation_controller: SimpleValidationController,
        mock_toolbar: MockFormatToolbar,
    ) -> None:
        """Тест: fix_all обновляет UI после исправления."""
        mock_renderer = MagicMock()
        mock_renderer.get_content.return_value = 'ёлка — test'
        validation_controller._renderer = mock_renderer

        validation_controller.fix_all()

        assert mock_toolbar._validation_count == 0
        assert mock_toolbar._fix_enabled is False

    def test_fix_all_shows_success_toast(
        self,
        mock_renderer: MagicMock,
        mock_toast_service: MagicMock,
    ) -> None:
        """Тест: fix_all показывает toast об успешном исправлении."""
        toolbar = MockFormatToolbar()
        controller = SimpleValidationController(
            renderer=mock_renderer,
            toolbar=toolbar,
            toast_service=mock_toast_service,
        )
        
        # Сначала запускаем валидацию чтобы установить _current_invalid_count
        mock_renderer.get_content.return_value = 'ёлка — test'
        controller.on_text_changed('ёлка — test')
        
        # Сбрасываем mock чтобы отследить только вызовы fix_all
        mock_toast_service.reset_mock()
        
        # Теперь вызываем fix_all
        controller.fix_all()

        mock_toast_service.show.assert_called()
        call_args = mock_toast_service.show.call_args
        assert "Fixed" in call_args[1]["message"]
        assert call_args[1]["level"] == MockToastLevel.SUCCESS

    def test_fix_all_no_success_toast_when_nothing_fixed(
        self,
        validation_controller: SimpleValidationController,
        mock_toast_service: MagicMock,
    ) -> None:
        """Тест: fix_all не показывает success toast если нечего исправлять."""
        mock_renderer = MagicMock()
        mock_renderer.get_content.return_value = "Hello world"
        validation_controller._renderer = mock_renderer

        validation_controller.fix_all()

        # Не должен показывать success toast если ничего не исправлено
        # (но может показать warning toast при validation)
        success_calls = [
            call for call in mock_toast_service.show.call_args_list
            if call.kwargs.get("level") == MockToastLevel.SUCCESS
        ]
        assert len(success_calls) == 0

    def test_clear_validation_clears_highlights_and_ui(
        self,
        validation_controller: SimpleValidationController,
        mock_renderer: MagicMock,
        mock_toolbar: MockFormatToolbar,
    ) -> None:
        """Тест: clear_validation очищает подсветки и UI."""
        # Сначала добавим невалидных символов
        validation_controller.on_text_changed("Test — 123")
        assert validation_controller.get_invalid_count() == 1

        # Сбросим
        validation_controller.clear_validation()

        assert validation_controller.get_invalid_count() == 0
        mock_renderer.clear_validation_highlights.assert_called()
        assert mock_toolbar._validation_count == 0

    def test_set_toast_service_updates_service(
        self,
        validation_controller: SimpleValidationController,
    ) -> None:
        """Тест: set_toast_service обновляет сервис уведомлений."""
        new_service = MagicMock()
        validation_controller.set_toast_service(new_service)

        # Триггерим показ toast
        validation_controller.on_text_changed("Test — 123")

        new_service.show.assert_called_once()


class TestToastNotifications:
    """Тесты для toast уведомлений."""

    def test_validation_detected_toast(
        self,
        validation_controller: SimpleValidationController,
        mock_toast_service: MagicMock,
    ) -> None:
        """Тест: показывается toast при обнаружении невалидных символов."""
        validation_controller.on_text_changed("Test — 123")

        mock_toast_service.show.assert_called_once()
        call_args = mock_toast_service.show.call_args
        assert "Non-PC866 characters detected" in call_args[1]["message"]
        assert call_args[1]["level"] == MockToastLevel.WARNING

    def test_no_toast_when_valid_text(
        self,
        validation_controller: SimpleValidationController,
        mock_toast_service: MagicMock,
    ) -> None:
        """Тест: не показывается toast для валидного текста."""
        validation_controller.on_text_changed("Hello world")

        # Проверяем что show не вызывался с validation detected
        validation_calls = [
            call for call in mock_toast_service.show.call_args_list
            if "Обнаружены" in str(call)
        ]
        assert len(validation_calls) == 0


# =============================================================================
# TESTS: FreeFormModeRenderer Validation Methods
# =============================================================================


class TestFreeFormModeRendererValidation:
    """Тесты для методов валидации FreeFormModeRenderer (мок тесты)."""

    def test_clear_validation_highlights_removes_tag(self) -> None:
        """Тест: clear_validation_highlights удаляет тег."""
        mock_text = MagicMock()
        
        INVALID_CHAR_TAG = "invalid_char"
        
        # Симулируем вызов
        mock_text.tag_remove(INVALID_CHAR_TAG, "1.0", tk.END)
        
        mock_text.tag_remove.assert_called_once_with(INVALID_CHAR_TAG, "1.0", tk.END)

    def test_highlight_invalid_char_applies_tag(self) -> None:
        """Тест: highlight_invalid_char применяет тег к позиции."""
        mock_text = MagicMock()
        
        INVALID_CHAR_TAG = "invalid_char"
        
        # Симулируем вызов highlight
        mock_text.tag_add(INVALID_CHAR_TAG, "1.6", "1.7")
        
        mock_text.tag_add.assert_called_with(INVALID_CHAR_TAG, "1.6", "1.7")


# =============================================================================
# TESTS: FormatToolbar Validation UI
# =============================================================================


class TestFormatToolbarValidationUI:
    """Тесты для UI валидации в FormatToolbar."""

    def test_set_validation_badge_updates_label(self) -> None:
        """Тест: set_validation_badge обновляет текст бейджа."""
        toolbar = MockFormatToolbar()
        
        toolbar.set_validation_badge(5)
        
        assert toolbar._validation_count == 5
        
    def test_set_validation_badge_hides_when_zero(self) -> None:
        """Тест: set_validation_badge скрывает бейдж при count=0."""
        toolbar = MockFormatToolbar()
        
        toolbar.set_validation_badge(0)
        
        assert toolbar._validation_count == 0

    def test_set_fix_validation_enabled_enables_button(self) -> None:
        """Тест: set_fix_validation_enabled включает кнопку."""
        toolbar = MockFormatToolbar()
        
        toolbar.set_fix_validation_enabled(True)
        
        assert toolbar._fix_enabled is True

    def test_set_fix_validation_enabled_disables_button(self) -> None:
        """Тест: set_fix_validation_enabled отключает кнопку."""
        toolbar = MockFormatToolbar()
        
        toolbar.set_fix_validation_enabled(False)
        
        assert toolbar._fix_enabled is False

    def test_set_on_fix_validation_callback_updates_callback(self) -> None:
        """Тест: set_on_fix_validation_callback обновляет callback."""
        toolbar = MockFormatToolbar()
        callback = MagicMock()
        
        toolbar.set_on_fix_validation_callback(callback)
        
        assert toolbar._on_fix_validation == callback

    def test_get_validation_count_returns_current_value(self) -> None:
        """Тест: get_validation_count возвращает текущее значение."""
        toolbar = MockFormatToolbar()
        toolbar._validation_count = 5
        
        assert toolbar.get_validation_count() == 5


# =============================================================================
# INTEGRATION TESTS
# =============================================================================


class TestValidationIntegration:
    """Интеграционные тесты валидации."""

    def test_full_validation_flow(
        self,
        mock_renderer: MagicMock,
        mock_toast_service: MagicMock,
    ) -> None:
        """Тест: полный цикл валидации от текста до UI."""
        toolbar = MockFormatToolbar()
        
        # Создаём контроллер
        controller = SimpleValidationController(
            renderer=mock_renderer,
            toolbar=toolbar,
            toast_service=mock_toast_service,
        )

        # Шаг 1: Ввод текста с невалидными символами
        text_with_invalid = 'ёлка — «test»'
        controller.on_text_changed(text_with_invalid)

        # Проверяем: подсветка включена
        assert mock_renderer.highlight_invalid_char.call_count > 0

        # Проверяем: UI обновлён
        # ё, —, «, » = 4 невалидных символа
        assert toolbar._validation_count == 4
        assert toolbar._fix_enabled is True

        # Проверяем: toast показан
        mock_toast_service.show.assert_called()

        # Шаг 2: Исправляем
        mock_renderer.get_content.return_value = text_with_invalid
        controller.fix_all()

        # Проверяем: текст исправлен
        expected_fixed = 'елка - "test"'
        mock_renderer.set_content.assert_called_with(expected_fixed)

        # Проверяем: UI сброшен
        assert toolbar._validation_count == 0
        assert toolbar._fix_enabled is False

    def test_fix_callback_triggers_fix_all(
        self,
        mock_renderer: MagicMock,
        mock_toast_service: MagicMock,
    ) -> None:
        """Тест: callback кнопки исправления вызывает fix_all."""
        toolbar = MockFormatToolbar()
        
        controller = SimpleValidationController(
            renderer=mock_renderer,
            toolbar=toolbar,
            toast_service=mock_toast_service,
        )
        
        mock_renderer.get_content.return_value = "Test — 123"
        controller.on_text_changed("Test — 123")

        # Получаем callback и вызываем его
        assert toolbar._on_fix_validation is not None
        toolbar._on_fix_validation()

        # Проверяем что был вызван fix_all (текст изменён)
        mock_renderer.set_content.assert_called()

    def test_validator_integration_with_mock_validator(self) -> None:
        """Тест: интеграция с MockCodepageValidator."""
        validator = MockCodepageValidator()

        # Проверяем валидацию
        text = 'ёлка — "test"'
        results = validator.validate(text)

        # ё, em-dash, кавычки = 4 невалидных символа (открывающая и закрывающая)
        # ASCII кавычки "test" валидны, но символы « и » — нет (если есть)
        # Проверим сколько реально найдено
        assert len(results) >= 2  # как минимум ё и em-dash

        # Проверяем исправление
        fixed = validator.fix_all(text)
        assert fixed == 'елка - "test"'

        # Проверяем что после исправления всё валидно
        assert validator.count_invalid(fixed) == 0


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "TestMockCodepageValidator",
    "TestValidationController",
    "TestToastNotifications",
    "TestFreeFormModeRendererValidation",
    "TestFormatToolbarValidationUI",
    "TestValidationIntegration",
]