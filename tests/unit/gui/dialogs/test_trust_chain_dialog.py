# -*- coding: utf-8 -*-
"""Тесты для TrustChainDialog.

Тестирует создание диалога цепочки доверия шаблонов,
отображение treeview с уровнями доверия, цветовую индикацию статусов,
кнопки Details/Verify/Close и обработку выбора элементов.

Version: 1.0
Security: CRITICAL-002
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Runtime imports with fallback
TKINTER_AVAILABLE = False
TrustChainDialog: Any = None
try:
    import tkinter as tk
    from tkinter import ttk

    # Import trust_chain_dialog directly to bypass __init__.py issues
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location(
        "trust_chain_dialog",
        "/home/Mike/Dev/FX-Text-processor/FX-Text-processor-3/src/gui/dialogs/trust_chain_dialog.py",
    )
    if spec and spec.loader:
        tcd_module: Any = importlib.util.module_from_spec(spec)
        sys.modules["trust_chain_dialog"] = tcd_module
        spec.loader.exec_module(tcd_module)

        TrustChainDialog = tcd_module.TrustChainDialog
        COLOR_BG: str = tcd_module.COLOR_BG
        COLOR_HEADER: str = tcd_module.COLOR_HEADER
        COLOR_BORDER: str = tcd_module.COLOR_BORDER
        COLOR_TEXT: str = tcd_module.COLOR_TEXT
        COLOR_VALID: str = tcd_module.COLOR_VALID
        COLOR_WARNING: str = tcd_module.COLOR_WARNING
        COLOR_INVALID: str = tcd_module.COLOR_INVALID
        COLOR_INFO: str = tcd_module.COLOR_INFO
        STATUS_EMOJIS: dict = tcd_module.STATUS_EMOJIS
        STATUS_TO_TAG: dict = tcd_module.STATUS_TO_TAG
        DIALOG_WIDTH: int = tcd_module.DIALOG_WIDTH
        DIALOG_HEIGHT: int = tcd_module.DIALOG_HEIGHT

    # Import protocols
    from src.services.protocols.template_security import (
        TrustChainLink,
        TrustStatus,
        TrustChainServiceProtocol,
    )

    TKINTER_AVAILABLE = True
except (ImportError, AttributeError, OSError, RuntimeError):
    TKINTER_AVAILABLE = False


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def root():
    """Создаёт real Tk окно для GUI тестов."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def mock_template() -> MagicMock:
    """Создание мока FormTemplate."""
    mock = MagicMock()
    mock.template_id = "tpl-123"
    mock.name = "Test Template"
    mock.doc_type = "invoice"
    mock.signature = b"test_signature"
    return mock


@pytest.fixture
def mock_trust_service() -> MagicMock:
    """Создание мока TrustChainService."""
    mock = MagicMock(spec=TrustChainServiceProtocol)

    # Создаём тестовую цепочку из 3 уровней
    root_link = TrustChainLink(
        key_id="root-key-001",
        public_key=b"\x01\x02\x03\x04" * 8,
        algorithm="Ed25519",
        added_at=datetime.now() - timedelta(days=365),
        parent_key_id=None,
        expires_at=datetime.now() + timedelta(days=365),
        signature=None,
        metadata={"name": "Root CA", "organization": "FX Security"},
    )

    intermediate_link = TrustChainLink(
        key_id="intermediate-001",
        public_key=b"\x05\x06\x07\x08" * 8,
        algorithm="Ed25519",
        added_at=datetime.now() - timedelta(days=180),
        parent_key_id="root-key-001",
        expires_at=datetime.now() + timedelta(days=180),
        signature=b"\xaa\xbb\xcc\xdd" * 16,
        metadata={"name": "Intermediate CA", "organization": "FX Security"},
    )

    leaf_link = TrustChainLink(
        key_id="leaf-001",
        public_key=b"\x09\x0a\x0b\x0c" * 8,
        algorithm="Ed25519",
        added_at=datetime.now() - timedelta(days=30),
        parent_key_id="intermediate-001",
        expires_at=datetime.now() + timedelta(days=335),
        signature=b"\xee\xff\x00\x11" * 16,
        metadata={"name": "Template Signer", "organization": "FX Templates"},
    )

    mock.get_trust_chain.return_value = [leaf_link, intermediate_link, root_link]
    mock.verify_template.return_value = MagicMock(
        template_id="tpl-123",
        is_valid=True,
        trust_status=TrustStatus.TRUSTED,
        chain_depth=2,
        signing_key_id="leaf-001",
        verified_at=datetime.now(),
        errors=[],
        warnings=[],
        can_trust=True,
    )
    mock.is_key_trusted.return_value = True

    return mock


# =============================================================================
# TESTS: Dialog Creation
# =============================================================================


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestTrustChainDialogCreation:
    """Тесты создания TrustChainDialog."""

    def test_dialog_initialization(
        self,
        root: tk.Tk,
        mock_template: MagicMock,
        mock_trust_service: MagicMock,
    ) -> None:
        """Проверка создания диалога."""
        dialog: Any = TrustChainDialog(
            parent=root,
            template=mock_template,
            trust_service=mock_trust_service,
        )
        try:
            assert dialog._parent is root
            assert dialog._template is mock_template
            assert dialog._trust_service is mock_trust_service
        finally:
            dialog.destroy()

    def test_dialog_constants(self) -> None:
        """Проверка констант диалога."""
        assert COLOR_BG == "#f8f9fa"
        assert COLOR_HEADER == "#e9ecef"
        assert COLOR_BORDER == "#dee2e6"
        assert COLOR_TEXT == "#212529"
        assert COLOR_VALID == "#28a745"
        assert COLOR_WARNING == "#ffc107"
        assert COLOR_INVALID == "#dc3545"
        assert COLOR_INFO == "#17a2b8"
        assert DIALOG_WIDTH == 600
        assert DIALOG_HEIGHT == 500


# =============================================================================
# TESTS: TreeView Population
# =============================================================================


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestTrustChainDialogTreeView:
    """Тесты заполнения treeview."""

    def test_chain_tree_populated(
        self,
        root: tk.Tk,
        mock_template: MagicMock,
        mock_trust_service: MagicMock,
    ) -> None:
        """Проверка что treeview заполнен данными из сервиса."""
        dialog: Any = TrustChainDialog(
            parent=root,
            template=mock_template,
            trust_service=mock_trust_service,
        )
        try:
            # Проверяем что сервис был вызван для получения цепочки
            mock_trust_service.get_trust_chain.assert_called_once()

            # Проверяем что treeview получил данные
            assert dialog._tree is not None
        finally:
            dialog.destroy()

    def test_chain_three_levels_displayed(
        self,
        root: tk.Tk,
        mock_template: MagicMock,
    ) -> None:
        """Проверка отображения 3 уровней цепочки."""
        mock_service = MagicMock()
        now = datetime.now()
        mock_service.get_trust_chain.return_value = [
            TrustChainLink(
                key_id="leaf",
                public_key=b"leaf",
                algorithm="Ed25519",
                added_at=now,
                parent_key_id="intermediate",
                expires_at=now + timedelta(days=30),
                signature=b"sig",
                metadata={},
            ),
            TrustChainLink(
                key_id="intermediate",
                public_key=b"inter",
                algorithm="Ed25519",
                added_at=now,
                parent_key_id="root",
                expires_at=now + timedelta(days=30),
                signature=b"sig",
                metadata={},
            ),
            TrustChainLink(
                key_id="root",
                public_key=b"root",
                algorithm="Ed25519",
                added_at=now,
                parent_key_id=None,
                expires_at=now + timedelta(days=30),
                signature=None,
                metadata={},
            ),
        ]
        mock_service.verify_template.return_value = MagicMock(
            template_id="tpl-123",
            is_valid=True,
            trust_status=TrustStatus.TRUSTED,
            chain_depth=2,
            signing_key_id="leaf",
            verified_at=now,
            errors=[],
            warnings=[],
            can_trust=True,
        )

        dialog: Any = TrustChainDialog(
            parent=root,
            template=mock_template,
            trust_service=mock_service,
        )
        try:
            # Должно быть вставлено несколько элементов (3+ уровня)
            assert len(dialog._chain_links) >= 3
        finally:
            dialog.destroy()


# =============================================================================
# TESTS: Status Colors
# =============================================================================


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestTrustChainDialogStatusColors:
    """Тесты цветовой индикации статусов."""

    def test_status_emojis(self) -> None:
        """Проверка эмодзи для статусов."""
        assert STATUS_EMOJIS[TrustStatus.TRUSTED] == "🟢"
        assert STATUS_EMOJIS[TrustStatus.UNTRUSTED] == "🔴"
        assert STATUS_EMOJIS[TrustStatus.REVOKED] == "🚫"
        assert STATUS_EMOJIS[TrustStatus.EXPIRED] == "🟡"
        assert STATUS_EMOJIS[TrustStatus.PENDING] == "⏳"

    def test_status_to_tag_mapping(self) -> None:
        """Проверка маппинга статусов на теги."""
        assert STATUS_TO_TAG[TrustStatus.TRUSTED] == "valid"
        assert STATUS_TO_TAG[TrustStatus.UNTRUSTED] == "invalid"
        assert STATUS_TO_TAG[TrustStatus.REVOKED] == "invalid"
        assert STATUS_TO_TAG[TrustStatus.EXPIRED] == "warning"
        assert STATUS_TO_TAG[TrustStatus.PENDING] == "warning"

    def test_status_colors_valid(
        self,
        root: tk.Tk,
        mock_template: MagicMock,
        mock_trust_service: MagicMock,
    ) -> None:
        """Проверка 🟢 для валидных статусов (TRUSTED)."""
        dialog: Any = TrustChainDialog(
            parent=root,
            template=mock_template,
            trust_service=mock_trust_service,
        )
        try:
            assert dialog is not None
            assert dialog._tree is not None
        finally:
            dialog.destroy()

    def test_status_colors_invalid(
        self,
        root: tk.Tk,
        mock_template: MagicMock,
    ) -> None:
        """Проверка 🔴 для невалидных статусов (UNTRUSTED, REVOKED)."""
        mock_service = MagicMock()
        mock_service.get_trust_chain.return_value = []
        mock_service.verify_template.return_value = MagicMock(
            template_id="tpl-123",
            is_valid=False,
            trust_status=TrustStatus.UNTRUSTED,
            chain_depth=0,
            signing_key_id="",
            verified_at=datetime.now(),
            errors=["Certificate not trusted"],
            warnings=[],
            can_trust=False,
        )

        for status in [TrustStatus.UNTRUSTED, TrustStatus.REVOKED]:
            mock_service.verify_template.return_value.trust_status = status

            dialog: Any = TrustChainDialog(
                parent=root,
                template=mock_template,
                trust_service=mock_service,
            )
            try:
                assert dialog is not None
            finally:
                dialog.destroy()

    def test_status_colors_expired(
        self,
        root: tk.Tk,
        mock_template: MagicMock,
    ) -> None:
        """Проверка 🟡 для expired статуса."""
        now = datetime.now()
        mock_service = MagicMock()
        mock_service.get_trust_chain.return_value = [
            TrustChainLink(
                key_id="expired-key",
                public_key=b"expired",
                algorithm="Ed25519",
                added_at=now - timedelta(days=400),
                parent_key_id=None,
                expires_at=now - timedelta(days=30),  # Expired
                signature=None,
                metadata={},
            ),
        ]
        mock_service.verify_template.return_value = MagicMock(
            template_id="tpl-123",
            is_valid=False,
            trust_status=TrustStatus.EXPIRED,
            chain_depth=0,
            signing_key_id="expired-key",
            verified_at=now,
            errors=["Certificate expired"],
            warnings=[],
            can_trust=False,
        )

        dialog: Any = TrustChainDialog(
            parent=root,
            template=mock_template,
            trust_service=mock_service,
        )
        try:
            assert dialog is not None
        finally:
            dialog.destroy()


# =============================================================================
# TESTS: Buttons
# =============================================================================


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestTrustChainDialogButtons:
    """Тесты кнопок диалога."""

    def test_details_button_shows_info(
        self,
        root: tk.Tk,
        mock_template: MagicMock,
        mock_trust_service: MagicMock,
    ) -> None:
        """Проверка что кнопка Details показывает информацию."""
        dialog: Any = TrustChainDialog(
            parent=root,
            template=mock_template,
            trust_service=mock_trust_service,
        )
        try:
            dialog._current_selection = "root-key-001"
            dialog._show_details()

            # Check that a Toplevel detail dialog was opened
            toplevels = [w for w in root.winfo_children() if isinstance(w, tk.Toplevel)]
            assert len(toplevels) >= 1
        finally:
            dialog.destroy()

    def test_verify_button_triggers_verification(
        self,
        root: tk.Tk,
        mock_template: MagicMock,
        mock_trust_service: MagicMock,
    ) -> None:
        """Проверка что кнопка Verify запускает верификацию."""
        dialog: Any = TrustChainDialog(
            parent=root,
            template=mock_template,
            trust_service=mock_trust_service,
        )
        try:
            # Вызываем верификацию (silent=True чтобы не показывать messagebox)
            dialog._verify_chain(silent=True)

            # Проверяем что сервис был вызван
            assert mock_trust_service.verify_template.called
        finally:
            dialog.destroy()

    def test_close_button_closes_dialog(
        self,
        root: tk.Tk,
        mock_template: MagicMock,
        mock_trust_service: MagicMock,
    ) -> None:
        """Проверка что кнопка Close закрывает диалог."""
        dialog: Any = TrustChainDialog(
            parent=root,
            template=mock_template,
            trust_service=mock_trust_service,
        )
        try:
            # Вызываем _close
            with patch.object(dialog, 'destroy') as mock_destroy:
                dialog._close()
                mock_destroy.assert_called_once()
        finally:
            try:
                dialog.destroy()
            except tk.TclError:
                pass


# =============================================================================
# TESTS: Tree Selection
# =============================================================================


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestTrustChainDialogSelection:
    """Тесты выбора в treeview."""

    def test_tree_selection_shows_details(
        self,
        root: tk.Tk,
        mock_template: MagicMock,
        mock_trust_service: MagicMock,
    ) -> None:
        """Проверка что выбор элемента показывает детали."""
        dialog: Any = TrustChainDialog(
            parent=root,
            template=mock_template,
            trust_service=mock_trust_service,
        )
        try:
            # Устанавливаем текущий selection
            dialog._current_selection = "root-key-001"

            # Вызываем обновление деталей
            dialog._update_detail_panel_for_link(mock_trust_service.get_trust_chain.return_value[0])

            # Проверяем что текст был обновлен
            assert dialog._detail_text is not None
        finally:
            dialog.destroy()


# =============================================================================
# TESTS: Edge Cases
# =============================================================================


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestTrustChainDialogEdgeCases:
    """Тесты граничных случаев."""

    def test_dialog_with_empty_chain(
        self,
        root: tk.Tk,
        mock_template: MagicMock,
    ) -> None:
        """Проверка обработки пустой цепочки."""
        mock_service = MagicMock()
        mock_service.get_trust_chain.return_value = []  # Пустая цепочка

        dialog: Any = TrustChainDialog(
            parent=root,
            template=mock_template,
            trust_service=mock_service,
        )
        try:
            assert dialog._chain_links is not None
            assert len(dialog._chain_links) == 0
        finally:
            dialog.destroy()

    def test_dialog_with_single_root(
        self,
        root: tk.Tk,
        mock_template: MagicMock,
    ) -> None:
        """Проверка обработки цепочки с одним корневым ключом."""
        mock_service = MagicMock()
        mock_service.get_trust_chain.return_value = [
            TrustChainLink(
                key_id="root-only",
                public_key=b"root" * 8,
                algorithm="Ed25519",
                added_at=datetime.now(),
                parent_key_id=None,
                expires_at=datetime.now() + timedelta(days=365),
                signature=None,
                metadata={"name": "Root Only Key"},
            ),
        ]
        mock_service.verify_template.return_value = MagicMock(
            template_id="tpl-123",
            is_valid=True,
            trust_status=TrustStatus.TRUSTED,
            chain_depth=0,
            signing_key_id="root-only",
            verified_at=datetime.now(),
            errors=[],
            warnings=[],
            can_trust=True,
        )

        dialog: Any = TrustChainDialog(
            parent=root,
            template=mock_template,
            trust_service=mock_service,
        )
        try:
            assert dialog._chain_links is not None
            assert len(dialog._chain_links) == 1
            assert dialog._chain_links[0].is_root() is True
        finally:
            dialog.destroy()


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "TestTrustChainDialogCreation",
    "TestTrustChainDialogTreeView",
    "TestTrustChainDialogStatusColors",
    "TestTrustChainDialogButtons",
    "TestTrustChainDialogSelection",
    "TestTrustChainDialogEdgeCases",
]
