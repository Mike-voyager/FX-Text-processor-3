"""Интеграционные тесты Trust Chain для шаблонов.

Тестирует полный цикл работы с цепочками доверия шаблонов:
- Создание ключей и подписей
- Построение иерархии Root → Master → Template
- Верификацию через TrustChainService
- Обработку истёкших и отозванных ключей

Требования:
    - Запускать через: pytest tests/integration/test_template_trust_chain.py
    - Используются реальные сервисы (не моки)
    - Временная директория для ключей

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Generator, Tuple

import pytest

# Mark all tests as integration and security tests
pytestmark = [
    pytest.mark.integration,
    pytest.mark.security,
    pytest.mark.slow,
]


# =============================================================================
# IMPORTS - Deferred to avoid import errors in headless environments
# =============================================================================


def _import_signing() -> Any:
    """Lazy import Ed25519Signer."""
    from src.security.crypto.algorithms.signing import Ed25519Signer

    return Ed25519Signer


def _import_trust_service() -> Any:
    """Lazy import TrustChainService."""
    from src.services.trust_chain_service import TrustChainService

    return TrustChainService


def _import_protocols() -> Any:
    """Lazy import TrustStatus."""
    from src.services.protocols.template_security import TrustStatus

    return TrustStatus


def _import_template_manager() -> Tuple[Any, Any, Any]:
    """Lazy import FormTemplate, TemplateManager, TemplatePage."""
    from src.services.template_manager import FormTemplate, TemplateManager, TemplatePage

    return FormTemplate, TemplateManager, TemplatePage


def _import_field_def() -> Tuple[Any, Any]:
    """Lazy import FieldDefinition, FieldType."""
    from src.documents.types.type_schema import FieldDefinition, FieldType

    return FieldDefinition, FieldType


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def temp_keystore_dir() -> Generator[Path, None, None]:
    """Создаёт временную директорию для хранилища ключей.

    Yields:
        Path: Путь к временной директории.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def audit_secret_key() -> bytes:
    """Возвращает тестовый секретный ключ для аудита.

    Returns:
        bytes: 32 байта для HMAC.
    """
    return b"test_audit_secret_key_32_bytes!!"


@pytest.fixture
def ed25519_keys() -> Tuple[bytes, bytes]:
    """Генерирует пару ключей Ed25519.

    Returns:
        Tuple[bytes, bytes]: (private_key_der, public_key_der).
    """
    Ed25519Signer = _import_signing()
    signer: Any = Ed25519Signer()
    result: Tuple[bytes, bytes] = signer.generate_keypair()
    return result


@pytest.fixture
def root_key(ed25519_keys: Tuple[bytes, bytes]) -> dict[str, Any]:
    """Создаёт корневой ключ для цепочки доверия.

    Args:
        ed25519_keys: Кортеж (private_key, public_key).

    Returns:
        dict: Словарь с данными корневого ключа.
    """
    private_key, public_key = ed25519_keys
    return {
        "key_id": "root-authority",
        "private_key": private_key,
        "public_key": public_key,
        "algorithm": "Ed25519",
        "metadata": {"name": "Root CA", "organization": "FX Text Processor"},
    }


@pytest.fixture
def master_key(ed25519_keys: Tuple[bytes, bytes]) -> dict[str, Any]:
    """Создаёт master ключ для цепочки доверия.

    Args:
        ed25519_keys: Кортеж (private_key, public_key).

    Returns:
        dict: Словарь с данными master ключа.
    """
    private_key, public_key = ed25519_keys
    return {
        "key_id": "master-signer",
        "private_key": private_key,
        "public_key": public_key,
        "algorithm": "Ed25519",
        "parent_key_id": "root-authority",
        "metadata": {"name": "Master Signer", "organization": "Templates Division"},
    }


@pytest.fixture
def template_key(ed25519_keys: Tuple[bytes, bytes]) -> dict[str, Any]:
    """Создаёт ключ для подписи шаблонов.

    Args:
        ed25519_keys: Кортеж (private_key, public_key).

    Returns:
        dict: Словарь с данными ключа шаблона.
    """
    private_key, public_key = ed25519_keys
    return {
        "key_id": "template-signer",
        "private_key": private_key,
        "public_key": public_key,
        "algorithm": "Ed25519",
        "parent_key_id": "master-signer",
        "metadata": {"name": "Template Signer", "organization": "Production"},
    }


@pytest.fixture
def trust_service(
    temp_keystore_dir: Path,
    audit_secret_key: bytes,
) -> Generator[Any, None, None]:
    """Создаёт TrustChainService для тестирования.

    Args:
        temp_keystore_dir: Временная директория для хранилища.
        audit_secret_key: Секретный ключ для аудита.

    Yields:
        TrustChainService: Инициализированный сервис.
    """
    TrustChainService = _import_trust_service()
    service = TrustChainService(
        keystore_path=temp_keystore_dir,
        audit_secret_key=audit_secret_key,
    )
    yield service


@pytest.fixture
def template_manager(temp_keystore_dir: Path) -> Generator[Any, None, None]:
    """Создаёт TemplateManager для тестирования.

    Args:
        temp_keystore_dir: Временная директория.

    Yields:
        TemplateManager: Инициализированный менеджер.
    """
    _, TemplateManager, _ = _import_template_manager()
    templates_dir = temp_keystore_dir / "templates"
    templates_dir.mkdir(exist_ok=True)
    manager = TemplateManager(templates_dir=templates_dir)
    yield manager


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def _create_signed_template(
    template_id: str,
    signing_key: dict[str, Any],
) -> Any:
    """Создаёт подписанный шаблон.

    Args:
        template_id: ID шаблона.
        signing_key: Словарь с ключом подписи.

    Returns:
        FormTemplate: Подписанный шаблон.
    """
    FormTemplate, _, TemplatePage = _import_template_manager()
    FieldDefinition, FieldType = _import_field_def()
    Ed25519Signer = _import_signing()
    import base64

    # Создаём поле
    field = FieldDefinition(
        field_id="test_field",
        field_type=FieldType.TEXT_INPUT,
        label="Test Field",
    )

    # Создаём страницу
    page = TemplatePage(
        index=0,
        paper_profile_id="A4-10cpi",
        fields=[field],
    )

    # Создаём шаблон
    template = FormTemplate(
        template_id=template_id,
        name="Test Template",
        name_ru="Тестовый шаблон",
        doc_type="DVN-44-K53",
        pages=[page],
        author="test_author",
    )

    # Подписываем шаблон
    signer = Ed25519Signer()
    message = template_id.encode("utf-8")
    signature = signer.sign(signing_key["private_key"], message)

    # Добавляем метаданные подписи к шаблону через object.__setattr__ для frozen dataclass
    object.__setattr__(template, "signature", base64.b64encode(signature).decode("ascii"))
    object.__setattr__(template, "signing_key_id", signing_key["key_id"])
    object.__setattr__(template, "signing_public_key", signing_key["public_key"])
    object.__setattr__(template, "signing_algorithm", "Ed25519")

    return template


# =============================================================================
# TESTS
# =============================================================================


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="GUI тесты требуют X11 на Windows",
)
class TestTemplateTrustChainIntegration:
    """Интеграционные тесты для Trust Chain шаблонов.

    Тестирует полный цикл работы с цепочками доверия:
    - Создание ключей и подписей
    - Построение иерархии Root → Master → Template
    - Верификацию через TrustChainService
    - Обработку истёкших и отозванных ключей
    """

    def test_01_valid_template_with_trust_chain(
        self,
        trust_service: Any,
        root_key: dict[str, Any],
        master_key: dict[str, Any],
    ) -> None:
        """Импорт валидного шаблона с проверенной цепочкой.

        Сценарий:
            1. Создать корневой ключ (Root)
            2. Добавить его в trust service
            3. Создать master ключ (Master)
            4. Добавить его в trust service с parent=Root
            5. Создать шаблон с подписью Master ключом
            6. Верифицировать программно
            7. Проверить что статус = TRUSTED
        """
        TrustStatus = _import_protocols()

        # 1. Добавляем корневой ключ
        trust_service.add_trusted_key(
            key_id=root_key["key_id"],
            public_key=root_key["public_key"],
            algorithm=root_key["algorithm"],
            metadata=root_key["metadata"],
        )

        # 2. Добавляем master ключ (связан с root)
        trust_service.add_trusted_key(
            key_id=master_key["key_id"],
            public_key=master_key["public_key"],
            algorithm=master_key["algorithm"],
            parent_key_id=root_key["key_id"],
            metadata=master_key["metadata"],
        )

        # 3. Создаём шаблон с подписью Master ключом
        template = _create_signed_template(
            template_id="test-template-001",
            signing_key=master_key,
        )

        # 4. Верифицируем программно
        result = trust_service.verify_template(template)

        # 5. Проверяем что результат валиден
        assert result.is_valid is True
        assert result.trust_status == TrustStatus.TRUSTED
        assert result.can_trust is True
        assert result.chain_depth == 2
        assert result.signing_key_id == master_key["key_id"]

        # Проверяем цепочку доверия
        chain = trust_service.get_trust_chain(master_key["key_id"])
        assert len(chain) == 2  # Master -> Root
        assert chain[0].key_id == master_key["key_id"]
        assert chain[1].key_id == root_key["key_id"]

        # Проверяем что ключи доверенные
        assert trust_service.is_key_trusted(root_key["key_id"]) is True
        assert trust_service.is_key_trusted(master_key["key_id"]) is True

    def test_02_reject_unknown_key(
        self,
        trust_service: Any,
        template_key: dict[str, Any],
    ) -> None:
        """Отклонение шаблона с неизвестным ключом.

        Сценарий:
            1. Создать шаблон с подписью неизвестным ключом
            2. Попытаться верифицировать
            3. Убедиться что ключ не найден (UNTRUSTED)
        """
        TrustStatus = _import_protocols()

        # НЕ добавляем ключ в trust service

        # Создаём шаблон с подписью неизвестным ключом
        template = _create_signed_template(
            template_id="test-template-002",
            signing_key=template_key,
        )

        # Верифицируем
        result = trust_service.verify_template(template)

        # Проверяем что верификация не удалась
        assert result.is_valid is False
        assert result.can_trust is False
        assert result.trust_status == TrustStatus.UNTRUSTED

        # Цепочка должна быть пустой (ключ неизвестен)
        chain = trust_service.get_trust_chain(template_key["key_id"])
        assert len(chain) == 0

    def test_03_expired_key(
        self,
        trust_service: Any,
        root_key: dict[str, Any],
    ) -> None:
        """Обработка истёкшего ключа.

        Сценарий:
            1. Создать корневой ключ с истёкшим сроком (вчера)
            2. Добавить в trust service
            3. Создать шаблон с подписью этим ключом
            4. Проверить что статус = EXPIRED
        """
        TrustStatus = _import_protocols()

        # Создаём ключ с истёкшим сроком (вчера)
        yesterday = datetime.now(timezone.utc) - timedelta(days=1)

        trust_service.add_trusted_key(
            key_id=root_key["key_id"],
            public_key=root_key["public_key"],
            algorithm=root_key["algorithm"],
            expires_at=yesterday,
            metadata=root_key["metadata"],
        )

        # Создаём шаблон с подписью
        template = _create_signed_template(
            template_id="test-template-003",
            signing_key=root_key,
        )

        # Верифицируем
        result = trust_service.verify_template(template)

        # Проверяем что статус EXPIRED
        assert result.trust_status == TrustStatus.EXPIRED
        assert result.can_trust is False
        assert len(result.errors) > 0

    def test_04_revoked_key(
        self,
        trust_service: Any,
        root_key: dict[str, Any],
        master_key: dict[str, Any],
    ) -> None:
        """Отзыв ключа и повторная проверка.

        Сценарий:
            1. Создать корневой ключ
            2. Создать master ключ с родителем Root
            3. Подписать шаблон Master ключом
            4. Отозвать Master ключ
            5. Проверить что статус = REVOKED
        """
        TrustStatus = _import_protocols()

        # Добавляем корневой ключ
        trust_service.add_trusted_key(
            key_id=root_key["key_id"],
            public_key=root_key["public_key"],
            algorithm=root_key["algorithm"],
            metadata=root_key["metadata"],
        )

        # Добавляем master ключ
        trust_service.add_trusted_key(
            key_id=master_key["key_id"],
            public_key=master_key["public_key"],
            algorithm=master_key["algorithm"],
            parent_key_id=root_key["key_id"],
            metadata=master_key["metadata"],
        )

        # Создаём шаблон
        template = _create_signed_template(
            template_id="test-template-004",
            signing_key=master_key,
        )

        # Отзываем master ключ (root может отозвать)
        trust_service.revoke_key(
            key_id=master_key["key_id"],
            reason="Приватный ключ скомпрометирован",
            revoked_by=root_key["key_id"],
        )

        # Проверяем что ключ отозван
        assert trust_service.is_key_trusted(master_key["key_id"]) is False

        # Верифицируем шаблон
        result = trust_service.verify_template(template)

        # Проверяем статус REVOKED
        assert result.trust_status == TrustStatus.REVOKED
        assert result.can_trust is False
        assert len(result.errors) > 0

    def test_05_full_chain_root_master_template(
        self,
        trust_service: Any,
        root_key: dict[str, Any],
        master_key: dict[str, Any],
        template_key: dict[str, Any],
    ) -> None:
        """Полная цепочка Root → Master → Template.

        Сценарий:
            1. Создать иерархию из 3 ключей: Root, Master, Template
            2. Добавить все в trust service
            3. Подписать шаблон Template ключом
            4. Проверить программно
            5. Убедиться что все звенья валидны (TRUSTED)
        """
        TrustStatus = _import_protocols()

        # Добавляем корневой ключ (Root)
        trust_service.add_trusted_key(
            key_id=root_key["key_id"],
            public_key=root_key["public_key"],
            algorithm=root_key["algorithm"],
            metadata=root_key["metadata"],
        )

        # Добавляем master ключ (Master, подчинён Root)
        trust_service.add_trusted_key(
            key_id=master_key["key_id"],
            public_key=master_key["public_key"],
            algorithm=master_key["algorithm"],
            parent_key_id=root_key["key_id"],
            metadata=master_key["metadata"],
        )

        # Добавляем template ключ (Template, подчинён Master)
        trust_service.add_trusted_key(
            key_id=template_key["key_id"],
            public_key=template_key["public_key"],
            algorithm=template_key["algorithm"],
            parent_key_id=master_key["key_id"],
            metadata=template_key["metadata"],
        )

        # Создаём шаблон с подписью Template ключом
        template = _create_signed_template(
            template_id="test-template-005",
            signing_key=template_key,
        )

        # Проверяем цепочку
        chain = trust_service.get_trust_chain(template_key["key_id"])
        assert len(chain) == 3  # Template -> Master -> Root
        assert chain[0].key_id == template_key["key_id"]
        assert chain[1].key_id == master_key["key_id"]
        assert chain[2].key_id == root_key["key_id"]
        assert chain[2].is_root() is True

        # Все ключи должны быть доверенными
        assert trust_service.is_key_trusted(root_key["key_id"]) is True
        assert trust_service.is_key_trusted(master_key["key_id"]) is True
        assert trust_service.is_key_trusted(template_key["key_id"]) is True

        # Верифицируем шаблон
        result = trust_service.verify_template(template)

        # Проверяем что всё валидно
        assert result.is_valid is True
        assert result.trust_status == TrustStatus.TRUSTED
        assert result.can_trust is True
        assert result.chain_depth == 3
        assert result.signing_key_id == template_key["key_id"]

    def test_06_trust_chain_service_operations(
        self,
        trust_service: Any,
        root_key: dict[str, Any],
        master_key: dict[str, Any],
    ) -> None:
        """Тест операций TrustChainService.

        Сценарий:
            1. Проверить что сервис пуст
            2. Добавить ключи
            3. Проверить count и get_all_key_ids
            4. Проверить get_root_keys
            5. Проверить get_key_entry
        """
        # Изначально пусто
        assert trust_service.get_key_count() == 0
        assert trust_service.get_all_key_ids() == []

        # Добавляем корневой ключ
        trust_service.add_trusted_key(
            key_id=root_key["key_id"],
            public_key=root_key["public_key"],
            algorithm=root_key["algorithm"],
            metadata=root_key["metadata"],
        )

        # Добавляем master ключ
        trust_service.add_trusted_key(
            key_id=master_key["key_id"],
            public_key=master_key["public_key"],
            algorithm=master_key["algorithm"],
            parent_key_id=root_key["key_id"],
            metadata=master_key["metadata"],
        )

        # Проверяем count
        assert trust_service.get_key_count() == 2

        # Проверяем get_all_key_ids
        all_ids = trust_service.get_all_key_ids()
        assert len(all_ids) == 2
        assert root_key["key_id"] in all_ids
        assert master_key["key_id"] in all_ids

        # Проверяем get_root_keys (только root)
        roots = trust_service.get_root_keys()
        assert len(roots) == 1
        assert roots[0].key_id == root_key["key_id"]

        # Проверяем get_key_entry
        root_entry = trust_service.get_key_entry(root_key["key_id"])
        assert root_entry is not None
        assert root_entry.link.key_id == root_key["key_id"]
        assert root_entry.revoked is False

        master_entry = trust_service.get_key_entry(master_key["key_id"])
        assert master_entry is not None
        assert master_entry.link.parent_key_id == root_key["key_id"]


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "TestTemplateTrustChainIntegration",
]
