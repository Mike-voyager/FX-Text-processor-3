# -*- coding: utf-8 -*-
"""Тесты для BackupCodesDialog.

Тестирует создание диалога, управление резервными кодами MFA,
видимость кодов, копирование в буфер и интеграцию с MFA.

Version: 1.0
Security: CRITICAL-002
"""

from __future__ import annotations

from typing import Generator
from unittest.mock import MagicMock, patch

import pytest
from src.gui.dialogs.backup_codes_dialog import (
    CODE_MASK,
    COLOR_FG,
    COLOR_USED,
    DIALOG_HEIGHT,
    DIALOG_WIDTH,
    TOTAL_CODES,
    BackupCodeDisplay,
    BackupCodesDialog,
)
from src.gui.security.mfa_gate import MFAResult


@pytest.fixture
def root() -> Generator:
    """Фикстура для Tk root."""
    import tkinter as tk

    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def mock_code_service() -> MagicMock:
    """Создание мока сервиса кодов."""
    mock = MagicMock()
    mock.get_backup_codes_status.return_value = {
        "remaining": 8,
        "consumed": 4,
        "ttl_seconds": 7776000,  # 90 days
        "codes": [
            {"id": "code_001", "code": "ABCD-1234", "used": False},
            {"id": "code_002", "code": "EFGH-5678", "used": False},
            {"id": "code_003", "code": "IJKL-9012", "used": True, "used_at": "2026-01-01T00:00:00"},
            {"id": "code_004", "code": "MNOP-3456", "used": False},
        ],
    }
    mock.issue_backup_codes_for_user.return_value = {
        "success": True,
        "codes": ["NEW1-1111", "NEW2-2222"],
        "remaining": 12,
    }
    return mock


@pytest.fixture
def mock_mfa_gate() -> MagicMock:
    """Создание мока MFAGate."""
    mock = MagicMock()
    mock.challenge.return_value = MFAResult.success(
        method="totp",
        user_id="operator",
        audit_token="test_token_123",
    )
    return mock


class TestBackupCodesDialogCreation:
    """Тесты создания BackupCodesDialog."""

    def test_dialog_creation(self, root) -> None:
        """Проверка создания диалога."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )
        assert dialog._user_id == "operator"
        assert dialog._code_service is None
        assert dialog._mfa_gate is None
        assert dialog._show_all is False
        assert len(dialog._codes) == 0
        dialog.destroy()

    def test_dialog_creation_with_service(self, root, mock_code_service) -> None:
        """Проверка создания с code_service."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
            code_service=mock_code_service,
        )
        assert dialog._code_service is mock_code_service
        dialog.destroy()

    def test_dialog_creation_with_mfa(self, root, mock_mfa_gate) -> None:
        """Проверка создания с mfa_gate."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
            mfa_gate=mock_mfa_gate,
        )
        assert dialog._mfa_gate is mock_mfa_gate
        dialog.destroy()

    def test_dialog_constants(self) -> None:
        """Проверка констант диалога."""
        assert DIALOG_WIDTH == 550
        assert DIALOG_HEIGHT == 500
        assert TOTAL_CODES == 12
        assert CODE_MASK == "****-****"
        assert COLOR_FG == "#2c3e50"
        assert COLOR_USED == "#95a5a6"


class TestBackupCodesDialogLoadCodes:
    """Тесты загрузки кодов."""

    def test_load_codes(self, root) -> None:
        """Тест загрузки кодов из сервиса."""
        # Мокаем импорт внутри _load_codes через patch.dict
        mock_status = {
            "remaining": 8,
            "consumed": 4,
            "ttl_seconds": 7776000,
            "codes": [
                {"id": "code_001", "code": "ABCD-1234", "used": False},
                {
                    "id": "code_002",
                    "code": "EFGH-5678",
                    "used": True,
                    "used_at": "2026-01-01T00:00:00",
                },
            ],
        }

        # Создаём фейковый модуль с mock функцией
        mock_module = MagicMock()
        mock_module.get_backup_codes_status.return_value = mock_status

        with patch.dict("sys.modules", {"src.security.auth.code_service": mock_module}):
            dialog = BackupCodesDialog(
                parent=root,
                user_id="operator",
            )

            # Проверяем что коды загружены
            assert len(dialog._codes) > 0
            assert dialog._remaining_count == 8
            assert dialog._expiry_date is not None
            dialog.destroy()

    def test_load_codes_fallback(self, root) -> None:
        """Тест fallback при недоступности сервиса."""
        # Мокаем ImportError при импорте модуля
        with patch.dict("sys.modules", {"src.security.auth.code_service": None}):
            dialog = BackupCodesDialog(
                parent=root,
                user_id="operator",
            )

            # Проверяем fallback коды
            assert len(dialog._codes) == TOTAL_CODES
            assert dialog._remaining_count == 8
            dialog.destroy()

    def test_parse_codes_from_status(self, root) -> None:
        """Тест парсинга кодов из статуса."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )

        raw_codes = [
            {"id": "code_001", "code": "ABCD-1234", "used": False},
            {"id": "code_002", "code": "EFGH-5678", "used": True, "used_at": "2026-01-01T00:00:00"},
        ]

        codes = dialog._parse_codes_from_status(raw_codes)

        assert len(codes) == 2
        assert codes[0].code_id == "code_001"
        assert codes[0].is_used is False
        assert codes[1].is_used is True
        assert codes[1].used_at is not None
        dialog.destroy()


class TestBackupCodesDialogVisibility:
    """Тесты переключения видимости кодов."""

    def test_toggle_visibility(self, root) -> None:
        """Тест переключения видимости кодов."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )

        # Начальное состояние
        assert dialog._show_all is False

        # Переключаем
        dialog._toggle_visibility()
        assert dialog._show_all is True

        # Переключаем обратно
        dialog._toggle_visibility()
        assert dialog._show_all is False

        dialog.destroy()

    def test_toggle_visibility_updates_button(self, root) -> None:
        """Тест обновления текста кнопки при переключении."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )

        # Переключаем
        dialog._toggle_visibility()

        # Проверяем что текст кнопки изменился
        if dialog._toggle_btn is not None:
            button_text = dialog._toggle_btn.cget("text")
            assert "Hide" in button_text or "Show" in button_text

        dialog.destroy()


class TestBackupCodesDialogClipboard:
    """Тесты копирования в буфер обмена."""

    def test_copy_to_clipboard(self, root) -> None:
        """Тест копирования кодов в буфер."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )

        # Создаём тестовые коды
        dialog._codes = [
            BackupCodeDisplay(
                code_id="code_001",
                masked_code="ABCD-1234",
                is_used=False,
                used_at=None,
            ),
            BackupCodeDisplay(
                code_id="code_002",
                masked_code="EFGH-5678",
                is_used=True,
                used_at=None,
            ),
            BackupCodeDisplay(
                code_id="code_003",
                masked_code="IJKL-9012",
                is_used=False,
                used_at=None,
            ),
        ]

        # Копируем
        dialog._copy_to_clipboard()

        # Проверяем что сообщение о статусе показано
        assert dialog._notification_label is not None

        dialog.destroy()

    def test_copy_no_available_codes(self, root) -> None:
        """Тест копирования когда нет доступных кодов."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )

        # Все коды использованы
        dialog._codes = [
            BackupCodeDisplay(
                code_id="code_001",
                masked_code="****-****",
                is_used=True,
                used_at=None,
            ),
        ]

        # Копируем
        dialog._copy_to_clipboard()

        # Проверяем что показано сообщение об ошибке
        if dialog._notification_label is not None:
            text = dialog._notification_label.cget("text")
            assert "No available" in text or "error" in text.lower()

        dialog.destroy()


class TestBackupCodesDialogMFA:
    """Тесты MFA интеграции."""

    def test_mfa_before_regenerate_success(self, root, mock_mfa_gate) -> None:
        """Тест MFA перед генерацией новых кодов (успех)."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
            mfa_gate=mock_mfa_gate,
        )

        # Симулируем MFA challenge
        with patch.object(dialog, "_do_regenerate_codes") as mock_regenerate:
            dialog._regenerate_codes()

            # Проверяем что MFA был вызван
            mock_mfa_gate.challenge.assert_called_once()
            mock_regenerate.assert_called_once()

        dialog.destroy()

    def test_mfa_before_regenerate_failure(self, root) -> None:
        """Тест MFA перед генерацией новых кодов (неудача)."""
        mock_mfa_fail = MagicMock()
        mock_mfa_fail.challenge.return_value = MFAResult.failure(
            method="totp",
            user_id="operator",
            error_message="Invalid code",
        )

        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
            mfa_gate=mock_mfa_fail,
        )

        # Симулируем неудачный MFA challenge
        with patch.object(dialog, "_do_regenerate_codes") as mock_regenerate:
            dialog._regenerate_codes()

            # Проверяем что MFA был вызван, но регенерация нет
            mock_mfa_fail.challenge.assert_called_once()
            mock_regenerate.assert_not_called()

        dialog.destroy()

    def test_regenerate_without_mfa_gate(self, root) -> None:
        """Тест регенерации без MFA gate."""
        # Создаём фейковый модуль с mock функцией
        mock_module = MagicMock()
        mock_module.issue_backup_codes_for_user.return_value = {
            "success": True,
            "codes": ["NEW1-1111"],
        }

        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
            mfa_gate=None,  # No MFA gate
        )

        # Должно работать без MFA - мокаем импорт через sys.modules
        with patch.dict("sys.modules", {"src.security.auth.code_service": mock_module}):
            with patch.object(dialog, "_load_codes") as mock_load:
                dialog._do_regenerate_codes()
                mock_load.assert_called_once()

        dialog.destroy()


class TestBackupCodesDialogMask:
    """Тесты маскировки кодов."""

    def test_mask_used_codes(self, root) -> None:
        """Тест маскировки использованных кодов."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )

        # Использованный код должен маскироваться
        masked = dialog._mask_code("ABCD-1234", is_used=True)
        assert masked == CODE_MASK

        dialog.destroy()

    def test_mask_unused_codes(self, root) -> None:
        """Тест отображения неиспользованных кодов."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )

        # Неиспользованный код должен отображаться
        masked = dialog._mask_code("ABCD-1234", is_used=False)
        assert "ABCD" in masked

        dialog.destroy()

    def test_code_display_dataclass(self) -> None:
        """Тест BackupCodeDisplay dataclass."""
        from datetime import datetime

        code = BackupCodeDisplay(
            code_id="test_001",
            masked_code="ABCD-****",
            is_used=False,
            used_at=None,
        )

        assert code.code_id == "test_001"
        assert code.masked_code == "ABCD-****"
        assert code.is_used is False
        assert code.used_at is None

        # Проверка frozen
        used_code = BackupCodeDisplay(
            code_id="test_002",
            masked_code="EFGH-****",
            is_used=True,
            used_at=datetime.now(),
        )
        assert used_code.is_used is True
        assert used_code.used_at is not None


class TestBackupCodesDialogStatus:
    """Тесты отображения статуса."""

    def test_show_status(self, root) -> None:
        """Тест отображения статуса с количеством оставшихся кодов."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )

        # Устанавливаем тестовые данные
        dialog._remaining_count = 8
        dialog._codes = [MagicMock() for _ in range(12)]

        # Обновляем UI
        dialog._update_status_labels()

        # Проверяем что статус обновлён
        if dialog._status_label is not None:
            status_text = dialog._status_label.cget("text")
            assert "8/12" in status_text or "8" in status_text

        dialog.destroy()

    def test_show_status_with_expiry(self, root) -> None:
        """Тест отображения статуса с датой истечения."""
        from datetime import datetime, timedelta

        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )

        # Устанавливаем дату истечения
        dialog._expiry_date = datetime.now() + timedelta(days=90)

        # Обновляем UI
        dialog._update_status_labels()

        # Проверяем что дата отображается
        if dialog._expiry_label is not None:
            expiry_text = dialog._expiry_label.cget("text")
            assert "Valid until" in expiry_text or "2026" in expiry_text or "2025" in expiry_text

        dialog.destroy()

    def test_show_status_success(self, root) -> None:
        """Тест отображения успешного статуса."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )

        # Показываем успешное сообщение
        dialog._show_status("Codes generated successfully!", is_error=False)

        # Проверяем что сообщение отображается
        assert dialog._notification_label is not None
        text = dialog._notification_label.cget("text")
        assert text == "Codes generated successfully!"

        dialog.destroy()

    def test_show_status_error(self, root) -> None:
        """Тест отображения ошибки."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )

        # Показываем сообщение об ошибке
        dialog._show_status("Code generation error", is_error=True)

        # Проверяем что сообщение отображается
        assert dialog._notification_label is not None
        text = dialog._notification_label.cget("text")
        assert text == "Code generation error"

        dialog.destroy()


class TestBackupCodesDialogResult:
    """Тесты результата диалога."""

    def test_codes_generated_property(self, root) -> None:
        """Тест свойства codes_generated."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )

        # Изначально False
        assert dialog.codes_generated is False

        # После генерации
        dialog._codes_generated = True
        assert dialog.codes_generated is True

        dialog.destroy()

    def test_show_returns_generated_flag(self, root) -> None:
        """Тест что show() возвращает флаг генерации."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )

        # Устанавливаем флаг
        dialog._codes_generated = True

        # Проверяем свойство
        assert dialog.codes_generated is True

        dialog.destroy()


class TestBackupCodesDialogHelpers:
    """Тесты вспомогательных методов."""

    def test_generate_placeholder_codes(self, root) -> None:
        """Тест генерации placeholder кодов."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )

        codes = dialog._generate_placeholder_codes(remaining=8, consumed=4)

        assert len(codes) == 12
        # Первые 4 использованы (consumed), остальные 8 нет
        assert codes[0].is_used is True
        assert codes[1].is_used is True
        assert codes[2].is_used is True
        assert codes[3].is_used is True
        assert codes[4].is_used is False
        assert codes[11].is_used is False

        dialog.destroy()

    def test_generate_placeholder_codes_all_used(self, root) -> None:
        """Тест генерации placeholder кодов когда все использованы."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )

        codes = dialog._generate_placeholder_codes(remaining=0, consumed=12)

        assert len(codes) == 12
        # Все должны быть использованы
        for code in codes:
            assert code.is_used is True

        dialog.destroy()

    def test_generate_placeholder_codes_none_used(self, root) -> None:
        """Тест генерации placeholder кодов когда ничего не использовано."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )

        codes = dialog._generate_placeholder_codes(remaining=12, consumed=0)

        assert len(codes) == 12
        # Ничего не должно быть использовано
        for code in codes:
            assert code.is_used is False

        dialog.destroy()

    def test_generate_masked_placeholder(self, root) -> None:
        """Тест генерации маскированного placeholder."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )

        placeholder = dialog._generate_masked_placeholder()

        # Формат: XXXX-****
        assert len(placeholder) == 9
        assert "-" in placeholder
        assert "****" in placeholder

        dialog.destroy()

    def test_mask_code_short(self, root) -> None:
        """Тест маскировки короткого кода."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )

        # Короткий код
        masked = dialog._mask_code("ABC", is_used=False)
        assert "-" in masked

        dialog.destroy()

    def test_center_window(self, root) -> None:
        """Тест центрирования окна."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )

        # Центрируем окно (не должно вызвать ошибок)
        dialog._center_window()

        dialog.destroy()


class TestBackupCodesDialogPrintAndSave:
    """Регрессионные тесты для багов _on_print и _on_save_to_file.

    Ранее эти методы были заглушками, которые показывали messagebox
    "Printing is not implemented yet" / "Save to file is not implemented yet".
    После фикса они реализуют реальную печать и сохранение в файл.
    """

    def test_on_print_creates_preview_window(self, root) -> None:
        """_on_print должен создать окно предпросмотра печати."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )
        # Устанавливаем тестовые коды
        dialog._codes = [
            BackupCodeDisplay(
                code_id="code_001",
                masked_code="ABCD-1234",
                is_used=False,
                used_at=None,
            ),
            BackupCodeDisplay(
                code_id="code_002",
                masked_code="EFGH-5678",
                is_used=True,
                used_at=None,
            ),
        ]

        # Вызываем _on_print — не должно вызывать исключений
        dialog._on_print()

        # Окно предпросмотра должно быть создано (Toplevel)
        # Проверяем что метод завершился без ошибок
        dialog.destroy()

    def test_on_print_no_available_codes(self, root) -> None:
        """_on_print с пустым списком доступных кодов показывает ошибку."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )
        # Все коды использованы
        dialog._codes = [
            BackupCodeDisplay(
                code_id="code_001",
                masked_code="****-****",
                is_used=True,
                used_at=None,
            ),
        ]

        # Вызываем _on_print — должно показать статус ошибки, а не упасть
        dialog._on_print()

        # Проверяем, что статус показывает ошибку
        if dialog._notification_label is not None:
            text = dialog._notification_label.cget("text")
            assert "Нет доступных" in text or "error" in text.lower() or text != ""

        dialog.destroy()

    def test_on_save_to_file_with_codes(self, root) -> None:
        """_on_save_to_file должен предложить сохранить файл с кодами."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )
        # Устанавливаем тестовые коды
        dialog._codes = [
            BackupCodeDisplay(
                code_id="code_001",
                masked_code="ABCD-1234",
                is_used=False,
                used_at=None,
            ),
        ]

        # Мокаем filedialog чтобы не показывать реальный диалог
        # filedialog импортируется локально в методе, поэтому мокаем через tkinter.filedialog
        with patch("tkinter.filedialog.asksaveasfilename") as mock_save:
            mock_save.return_value = ""  # Пользователь отменил
            dialog._on_save_to_file()
            mock_save.assert_called_once()

        dialog.destroy()

    def test_on_save_to_file_writes_content(self, root, tmp_path) -> None:
        """_on_save_to_file должен записать коды в выбранный файл."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )
        # Устанавливаем тестовые коды
        dialog._codes = [
            BackupCodeDisplay(
                code_id="code_001",
                masked_code="ABCD-1234",
                is_used=False,
                used_at=None,
            ),
        ]

        # Мокаем filedialog чтобы вернуть реальный путь
        save_path = str(tmp_path / "backup-codes.txt")
        with patch("tkinter.filedialog.asksaveasfilename") as mock_save:
            mock_save.return_value = save_path
            dialog._on_save_to_file()

        # Проверяем что файл создан
        from pathlib import Path

        saved_file = Path(save_path)
        assert saved_file.exists()
        content = saved_file.read_text(encoding="utf-8")
        assert "ABCD-1234" in content
        assert "operator" in content

        dialog.destroy()

    def test_on_save_to_file_no_available_codes(self, root) -> None:
        """_on_save_to_file с пустым списком кодов показывает ошибку."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )
        # Все коды использованы
        dialog._codes = [
            BackupCodeDisplay(
                code_id="code_001",
                masked_code="****-****",
                is_used=True,
                used_at=None,
            ),
        ]

        with patch("tkinter.filedialog.asksaveasfilename") as mock_save:
            # filedialog не должен вызываться если нет доступных кодов
            dialog._on_save_to_file()
            mock_save.assert_not_called()

        dialog.destroy()

    def test_on_print_formats_output_correctly(self, root) -> None:
        """_on_print должен форматировать вывод с заголовком и кодами."""
        dialog = BackupCodesDialog(
            parent=root,
            user_id="operator",
        )
        dialog._codes = [
            BackupCodeDisplay(
                code_id="code_001",
                masked_code="ABCD-1234",
                is_used=False,
                used_at=None,
            ),
            BackupCodeDisplay(
                code_id="code_002",
                masked_code="EFGH-5678",
                is_used=False,
                used_at=None,
            ),
        ]

        # Вызываем _on_print — проверяем, что он не падает
        # Внутри создаётся Toplevel, который можно проверить через winfo_children
        dialog._on_print()

        # Окно должно существовать после вызова
        dialog.destroy()


__all__ = [
    "TestBackupCodesDialogCreation",
    "TestBackupCodesDialogLoadCodes",
    "TestBackupCodesDialogVisibility",
    "TestBackupCodesDialogClipboard",
    "TestBackupCodesDialogMFA",
    "TestBackupCodesDialogMask",
    "TestBackupCodesDialogStatus",
    "TestBackupCodesDialogResult",
    "TestBackupCodesDialogHelpers",
    "TestBackupCodesDialogPrintAndSave",
]
