"""Тесты для диалогов workflow.

Тесты для AddCommentDialog, RejectDialog, TemplateImportDialog,
TrustChainVerificationDialog, FloppyOptimizerDialog, PrefillDialog,
QRCodeSettingsDialog.
"""

from __future__ import annotations

import pytest
import tkinter as tk

from src.documents.constructor.form_status import FormStatus


@pytest.fixture
def root():
    """Фикстура для Tk root."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


class TestAddCommentDialog:
    """Тесты для диалога добавления комментария."""

    def test_dialog_init(self, root):
        """Тест инициализации диалога."""
        from src.view.dialogs.add_comment_dialog import AddCommentDialog

        dialog = AddCommentDialog(root, field_id="field_1")
        assert dialog._field_id == "field_1"
        assert dialog._existing_comment is None

    def test_dialog_with_existing(self, root):
        """Тест инициализации с существующим комментарием."""
        from src.view.dialogs.add_comment_dialog import AddCommentDialog

        dialog = AddCommentDialog(
            root,
            field_id="field_1",
            existing_comment="Test comment",
            existing_severity=CommentSeverity.WARNING,
        )
        assert dialog._existing_comment == "Test comment"
        assert dialog._existing_severity == CommentSeverity.WARNING


class TestRejectDialog:
    """Тесты для диалога отклонения."""

    def test_dialog_init(self, root):
        """Тест инициализации диалога."""
        from src.view.dialogs.reject_dialog import RejectDialog
        from src.documents.constructor.form_status import FormStatus

        dialog = RejectDialog(
            root,
            current_status=FormStatus.VALIDATED,
        )
        assert dialog._current_status == FormStatus.VALIDATED


class TestTemplateImportDialog:
    """Тесты для диалога импорта шаблонов."""

    def test_dialog_init(self, root):
        """Тест инициализации диалога."""
        from src.view.dialogs.template_import_dialog import TemplateImportDialog

        dialog = TemplateImportDialog(root)
        assert dialog._templates == []
        assert dialog._source_var.get() == "floppy"


class TestFloppyOptimizerDialog:
    """Тесты для диалога оптимизации."""

    def test_dialog_init(self, root):
        """Тест инициализации диалога."""
        from src.view.dialogs.floppy_optimizer_dialog import FloppyOptimizerDialog

        dialog = FloppyOptimizerDialog(root, template_id="TPL-001", current_size=2_100_000)
        assert dialog._template_id == "TPL-001"
        assert dialog._current_size == 2_100_000

    def test_size_formatting(self, root):
        """Тест форматирования размера."""
        from src.view.dialogs.floppy_optimizer_dialog import FloppyOptimizerDialog

        dialog = FloppyOptimizerDialog(root, template_id="TPL-001")

        assert dialog._format_size(500) == "500 B"
        assert dialog._format_size(1024) == "1.0 KB"
        assert dialog._format_size(2_100_000) == "2.00 MB"

    def test_max_floppy_bytes(self, root):
        """Тест константы максимального размера."""
        from src.view.dialogs.floppy_optimizer_dialog import FloppyOptimizerDialog

        assert FloppyOptimizerDialog.MAX_FLOPPY_BYTES == 1_340_000


class TestPrefillDialog:
    """Тесты для диалога предзаполнения."""

    def test_dialog_init(self, root):
        """Тест инициализации диалога."""
        from src.view.dialogs.prefill_dialog import PrefillDialog

        fields = {"client_name": "ООО Ромашка", "order_number": "12345"}
        dialog = PrefillDialog(root, previous_doc_id="DOC-001", field_values=fields)
        assert dialog._previous_doc_id == "DOC-001"
        assert dialog._field_values == fields


class TestQRCodeSettingsDialog:
    """Тесты для диалога настройки QR-кода."""

    def test_dialog_init(self, root):
        """Тест инициализации диалога."""
        from src.view.dialogs.qr_settings_dialog import QRCodeSettingsDialog

        dialog = QRCodeSettingsDialog(root, initial_data="test_data")
        assert dialog._initial_data == "test_data"

    def test_error_levels(self, root):
        """Тест уровней коррекции ошибок."""
        from src.view.dialogs.qr_settings_dialog import QRCodeSettingsDialog

        expected_levels = ["L", "M", "Q", "H"]
        assert list(QRCodeSettingsDialog.ERROR_LEVELS.keys()) == expected_levels


class TestTrustChainVerificationDialog:
    """Тесты для диалога проверки цепочки доверия."""

    def test_dialog_init(self, root):
        """Тест инициализации диалога."""
        from src.view.dialogs.trust_chain_dialog import (
            TrustChainVerificationDialog,
            CertificateInfo,
        )

        cert = CertificateInfo(
            id="CERT-001",
            subject="Test Subject",
            issuer="Test Issuer",
            fingerprint="ABCDEF123456",
            not_before="2024-01-01",
            not_after="2025-01-01",
            is_whitelisted=True,
        )

        dialog = TrustChainVerificationDialog(root, certificate=cert)
        assert dialog._certificate == cert


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
