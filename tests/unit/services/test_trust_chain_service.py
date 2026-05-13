"""Tests for TrustChainService.

Tests template trust chain verification, key management,
and thread safety operations.

Coverage target: ≥95%
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Generator, Optional, Protocol
from unittest.mock import MagicMock

import pytest

from src.security.crypto.algorithms.signing import Ed25519Signer
from src.services.protocols.template_security import (
    TrustChainLink,
    TrustChainServiceProtocol,
    TrustStatus,
    TrustVerificationResult,
)


# =============================================================================
# MOCK IMPLEMENTATION (for testing before actual service is ready)
# =============================================================================


@dataclass
class _KeyEntry:
    """Internal key storage entry."""

    link: TrustChainLink
    revoked: bool = False
    revoked_at: Optional[datetime] = None
    revoked_by: Optional[str] = None
    revoke_reason: Optional[str] = None


class MockTrustChainService:
    """Mock implementation of TrustChainServiceProtocol for testing.

    Full implementation with thread-safe operations.
    """

    def __init__(self, storage_path: Optional[Path] = None) -> None:
        """Initialize service.

        Args:
            storage_path: Optional path for persistent storage.
        """
        self._keys: dict[str, _KeyEntry] = {}
        self._lock = threading.RLock()
        self._storage_path = storage_path
        self._signer = Ed25519Signer()
        self._audit_log: list[dict[str, Any]] = []

        if storage_path:
            self._load_from_storage()

    def _load_from_storage(self) -> None:
        """Load keys from storage file."""
        if not self._storage_path or not self._storage_path.exists():
            return

        try:
            with open(self._storage_path, "r", encoding="utf-8") as f:
                data: dict[str, Any] = json.load(f)

            for key_id, entry_data in data.get("keys", {}).items():
                link_data = entry_data["link"]
                link = TrustChainLink(
                    key_id=link_data["key_id"],
                    parent_key_id=link_data.get("parent_key_id"),
                    public_key=bytes.fromhex(link_data["public_key"]),
                    algorithm=link_data["algorithm"],
                    added_at=datetime.fromisoformat(link_data["added_at"]),
                    expires_at=(
                        datetime.fromisoformat(link_data["expires_at"])
                        if link_data.get("expires_at")
                        else None
                    ),
                    signature=(
                        bytes.fromhex(link_data["signature"])
                        if link_data.get("signature")
                        else None
                    ),
                    metadata=link_data.get("metadata", {}),
                )

                entry = _KeyEntry(
                    link=link,
                    revoked=entry_data.get("revoked", False),
                    revoked_at=(
                        datetime.fromisoformat(entry_data["revoked_at"])
                        if entry_data.get("revoked_at")
                        else None
                    ),
                    revoked_by=entry_data.get("revoked_by"),
                    revoke_reason=entry_data.get("revoke_reason"),
                )
                self._keys[key_id] = entry
        except (json.JSONDecodeError, KeyError, ValueError):
            # Invalid storage format, start fresh
            pass

    def _save_to_storage(self) -> None:
        """Save keys to storage file."""
        if not self._storage_path:
            return

        data: dict[str, Any] = {"keys": {}}
        for key_id, entry in self._keys.items():
            data["keys"][key_id] = {
                "link": entry.link.to_dict(),
                "revoked": entry.revoked,
                "revoked_at": entry.revoked_at.isoformat() if entry.revoked_at else None,
                "revoked_by": entry.revoked_by,
                "revoke_reason": entry.revoke_reason,
            }

        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._storage_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _audit(self, event: str, details: dict[str, Any]) -> None:
        """Log audit event."""
        self._audit_log.append({
            "event": event,
            "timestamp": datetime.now().isoformat(),
            "details": details,
        })

    def verify_template(
        self,
        template: Any,
        trusted_keys: Optional[set[str]] = None,
        verify_chain: bool = True,
    ) -> TrustVerificationResult:
        """Verify template signature and trust chain.

        Args:
            template: Template to verify (must have signature attributes).
            trusted_keys: Set of trusted key IDs (None = all from registry).
            verify_chain: Whether to verify full chain or just signature.

        Returns:
            TrustVerificationResult with verification status.
        """
        # Get template attributes
        template_id = getattr(template, "template_id", "unknown")
        signature = getattr(template, "signature", None)
        signing_key_id = getattr(template, "signing_key_id", None)
        content = getattr(template, "content", b"")

        if not signature or not signing_key_id:
            return TrustVerificationResult(
                template_id=template_id,
                is_valid=False,
                trust_status=TrustStatus.UNTRUSTED,
                chain_depth=0,
                signing_key_id=signing_key_id or "unknown",
                errors=["Template missing signature or signing_key_id"],
            )

        # Check if key is in trusted set
        if trusted_keys is not None and signing_key_id not in trusted_keys:
            return TrustVerificationResult(
                template_id=template_id,
                is_valid=False,
                trust_status=TrustStatus.UNTRUSTED,
                chain_depth=0,
                signing_key_id=signing_key_id,
                errors=["Signing key not in trusted keys set"],
            )

        with self._lock:
            # Check if key exists
            if signing_key_id not in self._keys:
                return TrustVerificationResult(
                    template_id=template_id,
                    is_valid=False,
                    trust_status=TrustStatus.UNTRUSTED,
                    chain_depth=0,
                    signing_key_id=signing_key_id,
                    errors=["Signing key not found in registry"],
                )

            entry = self._keys[signing_key_id]

            # Check revoked
            if entry.revoked:
                return TrustVerificationResult(
                    template_id=template_id,
                    is_valid=False,
                    trust_status=TrustStatus.REVOKED,
                    chain_depth=0,
                    signing_key_id=signing_key_id,
                    errors=[f"Key {signing_key_id} has been revoked"],
                )

            # Check expired
            if entry.link.is_expired():
                return TrustVerificationResult(
                    template_id=template_id,
                    is_valid=False,
                    trust_status=TrustStatus.EXPIRED,
                    chain_depth=0,
                    signing_key_id=signing_key_id,
                    errors=[f"Key {signing_key_id} has expired"],
                )

            # Verify signature
            public_key = entry.link.public_key
            try:
                is_sig_valid = self._signer.verify(public_key, content, signature)
            except (RuntimeError, ValueError, TypeError, OSError):
                is_sig_valid = False

            if not is_sig_valid:
                return TrustVerificationResult(
                    template_id=template_id,
                    is_valid=False,
                    trust_status=TrustStatus.UNTRUSTED,
                    chain_depth=0,
                    signing_key_id=signing_key_id,
                    errors=["Invalid signature"],
                )

            # Verify chain if requested
            chain_depth = 0
            if verify_chain:
                chain = self.get_trust_chain(signing_key_id)
                chain_depth = len(chain)

                # Check chain validity
                for link in chain:
                    if link.key_id in self._keys:
                        link_entry = self._keys[link.key_id]
                        if link_entry.revoked:
                            return TrustVerificationResult(
                                template_id=template_id,
                                is_valid=False,
                                trust_status=TrustStatus.REVOKED,
                                chain_depth=chain_depth,
                                signing_key_id=signing_key_id,
                                errors=[f"Chain contains revoked key: {link.key_id}"],
                            )

            self._audit("TEMPLATE_VERIFIED", {
                "template_id": template_id,
                "signing_key_id": signing_key_id,
                "chain_depth": chain_depth,
            })

            return TrustVerificationResult(
                template_id=template_id,
                is_valid=True,
                trust_status=TrustStatus.TRUSTED,
                chain_depth=chain_depth,
                signing_key_id=signing_key_id,
            )

    def get_trust_chain(
        self,
        key_id: str,
        include_revoked: bool = False,
    ) -> list[TrustChainLink]:
        """Get trust chain from key to root.

        Args:
            key_id: Key ID to build chain for.
            include_revoked: Whether to include revoked keys.

        Returns:
            List of TrustChainLink from key to root.
        """
        chain: list[TrustChainLink] = []
        visited: set[str] = set()

        with self._lock:
            current_id = key_id

            while current_id and current_id not in visited:
                visited.add(current_id)

                if current_id not in self._keys:
                    break

                entry = self._keys[current_id]

                if entry.revoked and not include_revoked:
                    break

                chain.append(entry.link)

                if entry.link.is_root():
                    break

                parent_key_id: Optional[str] = entry.link.parent_key_id
                if parent_key_id is None:
                    break
                current_id = parent_key_id

        return chain

    def add_trusted_key(
        self,
        key_id: str,
        public_key: bytes,
        algorithm: str,
        parent_key_id: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> TrustChainLink:
        """Add new trusted key.

        Args:
            key_id: Unique key identifier.
            public_key: Public key bytes.
            algorithm: Signature algorithm (e.g., "Ed25519").
            parent_key_id: Parent key ID (None for root).
            expires_at: Expiration time (None for no expiration).
            metadata: Additional metadata.

        Returns:
            Created TrustChainLink.

        Raises:
            ValueError: If key_id already exists.
            KeyError: If parent_key_id not found.
        """
        with self._lock:
            if key_id in self._keys:
                raise ValueError(f"Key {key_id} already exists")

            if parent_key_id is not None and parent_key_id not in self._keys:
                raise KeyError(f"Parent key {parent_key_id} not found")

            # Sign key if has parent (parent attests to this key)
            signature: Optional[bytes] = None
            if parent_key_id:
                # In real implementation, would sign with parent private key
                # Here we just create a mock signature
                signature = hashlib.sha256(
                    key_id.encode() + public_key
                ).digest()

            link = TrustChainLink(
                key_id=key_id,
                parent_key_id=parent_key_id,
                public_key=public_key,
                algorithm=algorithm,
                added_at=datetime.now(),
                expires_at=expires_at,
                signature=signature,
                metadata=metadata or {},
            )

            self._keys[key_id] = _KeyEntry(link=link)
            self._save_to_storage()

            self._audit("KEY_ADDED", {
                "key_id": key_id,
                "parent_key_id": parent_key_id,
                "algorithm": algorithm,
            })

            return link

    def revoke_key(
        self,
        key_id: str,
        reason: str,
        revoked_by: str,
    ) -> bool:
        """Revoke a key.

        Args:
            key_id: Key ID to revoke.
            reason: Revocation reason.
            revoked_by: Key ID of revoker.

        Returns:
            True if revoked successfully.

        Raises:
            KeyError: If key_id not found.
            ValueError: If revoked_by has no authority.
        """
        with self._lock:
            if key_id not in self._keys:
                raise KeyError(f"Key {key_id} not found")

            # Check if revoker has authority (is root or parent)
            entry = self._keys[key_id]
            if entry.link.parent_key_id and entry.link.parent_key_id != revoked_by:
                # Check if revoked_by is root
                if revoked_by not in self._keys or not self._keys[revoked_by].link.is_root():
                    raise ValueError(f"Key {revoked_by} has no authority to revoke {key_id}")

            entry.revoked = True
            entry.revoked_at = datetime.now()
            entry.revoked_by = revoked_by
            entry.revoke_reason = reason

            self._save_to_storage()

            self._audit("KEY_REVOKED", {
                "key_id": key_id,
                "revoked_by": revoked_by,
                "reason": reason,
            })

            return True

    def is_key_trusted(
        self,
        key_id: str,
        at_time: Optional[datetime] = None,
    ) -> bool:
        """Check if key is trusted.

        Args:
            key_id: Key ID to check.
            at_time: Time to check at (None = current time).

        Returns:
            True if key is trusted and valid.
        """
        check_time = at_time or datetime.now()

        with self._lock:
            if key_id not in self._keys:
                return False

            entry = self._keys[key_id]

            if entry.revoked:
                return False

            if entry.link.expires_at and check_time > entry.link.expires_at:
                return False

            # Verify chain to root
            chain = self.get_trust_chain(key_id)
            for link in chain:
                if link.key_id in self._keys:
                    link_entry = self._keys[link.key_id]
                    if link_entry.revoked:
                        return False
                    if link_entry.link.expires_at and check_time > link_entry.link.expires_at:
                        return False

            return True

    def get_root_keys(self) -> list[TrustChainLink]:
        """Get all root keys.

        Returns:
            List of root key links.
        """
        with self._lock:
            return [
                entry.link for entry in self._keys.values()
                if entry.link.is_root()
            ]


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def temp_dir() -> "Generator[Path, None, None]":
    """Create temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def ed25519_signer() -> Ed25519Signer:
    """Create Ed25519 signer for key generation."""
    return Ed25519Signer()


@pytest.fixture
def trust_chain_service(temp_dir: Path) -> MockTrustChainService:
    """Create TrustChainService instance."""
    storage_path = temp_dir / "trust_chain.json"
    return MockTrustChainService(storage_path=storage_path)


@pytest.fixture
def sample_keypair(ed25519_signer: Ed25519Signer) -> tuple[bytes, bytes]:
    """Generate sample Ed25519 keypair."""
    private_key, public_key = ed25519_signer.generate_keypair()
    return private_key, public_key


@pytest.fixture
def root_key(trust_chain_service: MockTrustChainService, sample_keypair: tuple[bytes, bytes]) -> TrustChainLink:
    """Create and add root key to service."""
    _, public_key = sample_keypair
    return trust_chain_service.add_trusted_key(
        key_id="root-key-1",
        public_key=public_key,
        algorithm="Ed25519",
        metadata={"name": "Root Key", "role": "root"},
    )


class SignedTemplateFactoryProtocol(Protocol):
    """Protocol for signed template factory."""

    def __call__(
        self,
        *,
        template_id: str,
        content: bytes,
        signing_key_id: str,
        signature: bytes,
    ) -> MagicMock:
        ...


@pytest.fixture
def signed_template_factory() -> SignedTemplateFactoryProtocol:
    """Factory for creating signed templates."""
    def _create(*, template_id: str, content: bytes, signing_key_id: str, signature: bytes) -> MagicMock:
        """Create mock template with signature."""
        template = MagicMock()
        template.template_id = template_id
        template.content = content
        template.signing_key_id = signing_key_id
        template.signature = signature
        return template
    return _create


# =============================================================================
# TEST: Verify Template Valid Signature
# =============================================================================


@pytest.mark.security
class TestVerifyTemplateValid:
    """Test valid template signature verification."""

    def test_verify_template_valid_signature(
        self,
        trust_chain_service: MockTrustChainService,
        sample_keypair: tuple[bytes, bytes],
        signed_template_factory: SignedTemplateFactoryProtocol,
    ) -> None:
        """Test verification of valid template signature."""
        private_key, public_key = sample_keypair

        # Add root key
        trust_chain_service.add_trusted_key(
            key_id="signing-key",
            public_key=public_key,
            algorithm="Ed25519",
        )

        # Create signed content
        content = b"Test template content"
        signer = Ed25519Signer()
        signature = signer.sign(private_key, content)

        # Create template
        template_factory = signed_template_factory
        template = template_factory(
            template_id="tpl-123",
            content=content,
            signing_key_id="signing-key",
            signature=signature,
        )

        # Verify
        result = trust_chain_service.verify_template(template)

        assert result.is_valid is True
        assert result.trust_status == TrustStatus.TRUSTED
        assert result.can_trust is True
        assert result.template_id == "tpl-123"
        assert result.signing_key_id == "signing-key"
        assert result.chain_depth == 1  # Root key only

    def test_verify_template_with_chain(
        self,
        trust_chain_service: MockTrustChainService,
        ed25519_signer: Ed25519Signer,
        signed_template_factory: SignedTemplateFactoryProtocol,
    ) -> None:
        """Test verification with multi-level chain."""
        # Create root key
        root_private, root_public = ed25519_signer.generate_keypair()
        trust_chain_service.add_trusted_key(
            key_id="root-key",
            public_key=root_public,
            algorithm="Ed25519",
        )

        # Create intermediate key
        intermediate_private, intermediate_public = ed25519_signer.generate_keypair()
        trust_chain_service.add_trusted_key(
            key_id="intermediate-key",
            public_key=intermediate_public,
            algorithm="Ed25519",
            parent_key_id="root-key",
        )

        # Create signing key
        signing_private, signing_public = ed25519_signer.generate_keypair()
        trust_chain_service.add_trusted_key(
            key_id="signing-key",
            public_key=signing_public,
            algorithm="Ed25519",
            parent_key_id="intermediate-key",
        )

        # Sign template
        content = b"Test content"
        signature = ed25519_signer.sign(signing_private, content)

        template_factory = signed_template_factory
        template = template_factory(
            template_id="tpl-456",
            content=content,
            signing_key_id="signing-key",
            signature=signature,
        )

        result = trust_chain_service.verify_template(template)

        assert result.is_valid is True
        assert result.trust_status == TrustStatus.TRUSTED
        assert result.chain_depth == 3  # signing -> intermediate -> root


# =============================================================================
# TEST: Verify Template Invalid Signature
# =============================================================================


@pytest.mark.security
class TestVerifyTemplateInvalid:
    """Test invalid template signature verification."""

    def test_verify_template_invalid_signature(
        self,
        trust_chain_service: MockTrustChainService,
        sample_keypair: tuple[bytes, bytes],
        signed_template_factory: SignedTemplateFactoryProtocol,
    ) -> None:
        """Test verification fails with invalid signature."""
        _, public_key = sample_keypair

        trust_chain_service.add_trusted_key(
            key_id="signing-key",
            public_key=public_key,
            algorithm="Ed25519",
        )

        content = b"Test content"
        wrong_signature = b"X" * 64  # Invalid signature

        template_factory = signed_template_factory
        template = template_factory(
            template_id="tpl-invalid",
            content=content,
            signing_key_id="signing-key",
            signature=wrong_signature,
        )

        result = trust_chain_service.verify_template(template)

        assert result.is_valid is False
        assert result.trust_status == TrustStatus.UNTRUSTED
        assert result.can_trust is False
        assert any("Invalid signature" in e for e in result.errors)

    def test_verify_template_wrong_key(
        self,
        trust_chain_service: MockTrustChainService,
        ed25519_signer: Ed25519Signer,
        signed_template_factory: SignedTemplateFactoryProtocol,
    ) -> None:
        """Test verification fails when signed with different key."""
        # Add key to registry
        _, public_key1 = ed25519_signer.generate_keypair()
        trust_chain_service.add_trusted_key(
            key_id="key-1",
            public_key=public_key1,
            algorithm="Ed25519",
        )

        # Sign with different key
        private_key2, _ = ed25519_signer.generate_keypair()
        content = b"Test content"
        signature = ed25519_signer.sign(private_key2, content)

        template_factory = signed_template_factory
        template = template_factory(
            template_id="tpl-wrong",
            content=content,
            signing_key_id="key-1",
            signature=signature,
        )

        result = trust_chain_service.verify_template(template)

        assert result.is_valid is False
        assert "Invalid signature" in result.errors


# =============================================================================
# TEST: Verify Template Expired Key
# =============================================================================


@pytest.mark.security
class TestVerifyTemplateExpired:
    """Test expired key handling."""

    def test_verify_template_expired_key(
        self,
        trust_chain_service: MockTrustChainService,
        sample_keypair: tuple[bytes, bytes],
        signed_template_factory: SignedTemplateFactoryProtocol,
    ) -> None:
        """Test verification fails with expired signing key."""
        private_key, public_key = sample_keypair

        # Add expired key
        expired_time = datetime.now() - timedelta(days=1)
        trust_chain_service.add_trusted_key(
            key_id="expired-key",
            public_key=public_key,
            algorithm="Ed25519",
            expires_at=expired_time,
        )

        content = b"Test content"
        signer = Ed25519Signer()
        signature = signer.sign(private_key, content)

        template_factory = signed_template_factory
        template = template_factory(
            template_id="tpl-expired",
            content=content,
            signing_key_id="expired-key",
            signature=signature,
        )

        result = trust_chain_service.verify_template(template)

        assert result.is_valid is False
        assert result.trust_status == TrustStatus.EXPIRED
        assert result.can_trust is False
        assert any("expired" in e.lower() for e in result.errors)


# =============================================================================
# TEST: Verify Template Revoked Key
# =============================================================================


@pytest.mark.security
class TestVerifyTemplateRevoked:
    """Test revoked key handling."""

    def test_verify_template_revoked_key(
        self,
        trust_chain_service: MockTrustChainService,
        ed25519_signer: Ed25519Signer,
        signed_template_factory: SignedTemplateFactoryProtocol,
    ) -> None:
        """Test verification fails with revoked signing key."""
        private_key, public_key = ed25519_signer.generate_keypair()

        # Add root key that will revoke
        root_private, root_public = ed25519_signer.generate_keypair()
        trust_chain_service.add_trusted_key(
            key_id="root-key",
            public_key=root_public,
            algorithm="Ed25519",
        )

        # Add key to be revoked
        trust_chain_service.add_trusted_key(
            key_id="revoked-key",
            public_key=public_key,
            algorithm="Ed25519",
            parent_key_id="root-key",
        )

        # Revoke the key
        trust_chain_service.revoke_key(
            key_id="revoked-key",
            reason="Key compromise",
            revoked_by="root-key",
        )

        content = b"Test content"
        signature = ed25519_signer.sign(private_key, content)

        template_factory = signed_template_factory
        template = template_factory(
            template_id="tpl-revoked",
            content=content,
            signing_key_id="revoked-key",
            signature=signature,
        )

        result = trust_chain_service.verify_template(template)

        assert result.is_valid is False
        assert result.trust_status == TrustStatus.REVOKED
        assert result.is_revoked is True
        assert any("revoked" in e.lower() for e in result.errors)


# =============================================================================
# TEST: Get Trust Chain
# =============================================================================


@pytest.mark.security
class TestGetTrustChain:
    """Test trust chain retrieval."""

    def test_get_trust_chain_two_levels(self, trust_chain_service: MockTrustChainService, ed25519_signer: Ed25519Signer) -> None:
        """Test chain with two levels (root -> signing)."""
        # Create root
        _, root_public = ed25519_signer.generate_keypair()
        trust_chain_service.add_trusted_key(
            key_id="root-key",
            public_key=root_public,
            algorithm="Ed25519",
        )

        # Create signing key
        _, signing_public = ed25519_signer.generate_keypair()
        trust_chain_service.add_trusted_key(
            key_id="signing-key",
            public_key=signing_public,
            algorithm="Ed25519",
            parent_key_id="root-key",
        )

        chain = trust_chain_service.get_trust_chain("signing-key")

        assert len(chain) == 2
        assert chain[0].key_id == "signing-key"
        assert chain[1].key_id == "root-key"
        assert chain[1].is_root() is True

    def test_get_trust_chain_three_levels(self, trust_chain_service: MockTrustChainService, ed25519_signer: Ed25519Signer) -> None:
        """Test chain with three levels (root -> master -> template)."""
        # Root -> Master -> Template key
        keys: list[str] = []
        for i, name in enumerate(["root-key", "master-key", "template-key"]):
            _, public = ed25519_signer.generate_keypair()
            parent = keys[-1] if keys else None
            trust_chain_service.add_trusted_key(
                key_id=name,
                public_key=public,
                algorithm="Ed25519",
                parent_key_id=parent,
            )
            keys.append(name)

        chain = trust_chain_service.get_trust_chain("template-key")

        assert len(chain) == 3
        assert chain[0].key_id == "template-key"
        assert chain[1].key_id == "master-key"
        assert chain[2].key_id == "root-key"
        assert chain[2].is_root() is True


# =============================================================================
# TEST: Add Trusted Key
# =============================================================================


@pytest.mark.security
class TestAddTrustedKey:
    """Test adding trusted keys."""

    def test_add_trusted_key_root(self, trust_chain_service: MockTrustChainService, sample_keypair: tuple[bytes, bytes]) -> None:
        """Test adding root key."""
        _, public_key = sample_keypair

        link = trust_chain_service.add_trusted_key(
            key_id="new-root",
            public_key=public_key,
            algorithm="Ed25519",
            metadata={"name": "Test Root"},
        )

        assert link.key_id == "new-root"
        assert link.is_root() is True
        assert link.parent_key_id is None
        assert link.algorithm == "Ed25519"
        assert link.metadata.get("name") == "Test Root"

    def test_add_trusted_key_with_parent(self, trust_chain_service: MockTrustChainService, ed25519_signer: Ed25519Signer) -> None:
        """Test adding key with parent."""
        # Create root
        _, root_public = ed25519_signer.generate_keypair()
        trust_chain_service.add_trusted_key(
            key_id="root",
            public_key=root_public,
            algorithm="Ed25519",
        )

        # Create child
        _, child_public = ed25519_signer.generate_keypair()
        link = trust_chain_service.add_trusted_key(
            key_id="child",
            public_key=child_public,
            algorithm="Ed25519",
            parent_key_id="root",
            metadata={"role": "intermediate"},
        )

        assert link.key_id == "child"
        assert link.is_root() is False
        assert link.parent_key_id == "root"
        assert link.signature is not None  # Signed by parent

    def test_add_trusted_key_duplicate_raises(self, trust_chain_service: MockTrustChainService, sample_keypair: tuple[bytes, bytes]) -> None:
        """Test adding duplicate key raises ValueError."""
        _, public_key = sample_keypair

        trust_chain_service.add_trusted_key(
            key_id="duplicate-key",
            public_key=public_key,
            algorithm="Ed25519",
        )

        with pytest.raises(ValueError, match="already exists"):
            trust_chain_service.add_trusted_key(
                key_id="duplicate-key",
                public_key=public_key,
                algorithm="Ed25519",
            )

    def test_add_trusted_key_missing_parent_raises(self, trust_chain_service: MockTrustChainService, sample_keypair: tuple[bytes, bytes]) -> None:
        """Test adding key with non-existent parent raises KeyError."""
        _, public_key = sample_keypair

        with pytest.raises(KeyError, match="not found"):
            trust_chain_service.add_trusted_key(
                key_id="orphan",
                public_key=public_key,
                algorithm="Ed25519",
                parent_key_id="non-existent",
            )


# =============================================================================
# TEST: Revoke Key
# =============================================================================


@pytest.mark.security
class TestRevokeKey:
    """Test key revocation."""

    def test_revoke_key_success(self, trust_chain_service: MockTrustChainService, ed25519_signer: Ed25519Signer) -> None:
        """Test successful key revocation."""
        # Create root
        _, root_public = ed25519_signer.generate_keypair()
        trust_chain_service.add_trusted_key(
            key_id="root",
            public_key=root_public,
            algorithm="Ed25519",
        )

        # Create key to revoke
        _, key_public = ed25519_signer.generate_keypair()
        trust_chain_service.add_trusted_key(
            key_id="to-revoke",
            public_key=key_public,
            algorithm="Ed25519",
            parent_key_id="root",
        )

        result = trust_chain_service.revoke_key(
            key_id="to-revoke",
            reason="Compromised",
            revoked_by="root",
        )

        assert result is True
        assert trust_chain_service._keys["to-revoke"].revoked is True
        assert trust_chain_service._keys["to-revoke"].revoke_reason == "Compromised"

    def test_revoke_key_not_found(self, trust_chain_service: MockTrustChainService) -> None:
        """Test revoking non-existent key raises KeyError."""
        with pytest.raises(KeyError, match="not found"):
            trust_chain_service.revoke_key(
                key_id="non-existent",
                reason="Test",
                revoked_by="root",
            )

    def test_revoke_key_no_authority(self, trust_chain_service: MockTrustChainService, ed25519_signer: Ed25519Signer) -> None:
        """Test revocation by unauthorized key raises ValueError."""
        # Create keys
        for name in ["root", "key-a", "key-b"]:
            _, public = ed25519_signer.generate_keypair()
            parent = "root" if name != "root" else None
            trust_chain_service.add_trusted_key(
                key_id=name,
                public_key=public,
                algorithm="Ed25519",
                parent_key_id=parent,
            )

        # key-b should not be able to revoke key-a
        with pytest.raises(ValueError, match="no authority"):
            trust_chain_service.revoke_key(
                key_id="key-a",
                reason="Test",
                revoked_by="key-b",
            )


# =============================================================================
# TEST: Is Key Trusted
# =============================================================================


@pytest.mark.security
class TestIsKeyTrusted:
    """Test key trust status checking."""

    def test_is_key_trusted_valid(self, trust_chain_service: MockTrustChainService, ed25519_signer: Ed25519Signer) -> None:
        """Test trusted key returns True."""
        _, public = ed25519_signer.generate_keypair()
        trust_chain_service.add_trusted_key(
            key_id="trusted",
            public_key=public,
            algorithm="Ed25519",
        )

        assert trust_chain_service.is_key_trusted("trusted") is True

    def test_is_key_trusted_expired(self, trust_chain_service: MockTrustChainService, ed25519_signer: Ed25519Signer) -> None:
        """Test expired key returns False."""
        _, public = ed25519_signer.generate_keypair()
        expired = datetime.now() - timedelta(days=1)
        trust_chain_service.add_trusted_key(
            key_id="expired",
            public_key=public,
            algorithm="Ed25519",
            expires_at=expired,
        )

        assert trust_chain_service.is_key_trusted("expired") is False

    def test_is_key_trusted_at_time(self, trust_chain_service: MockTrustChainService, ed25519_signer: Ed25519Signer) -> None:
        """Test trust check at specific time."""
        _, public = ed25519_signer.generate_keypair()
        expired = datetime.now() + timedelta(days=1)
        trust_chain_service.add_trusted_key(
            key_id="future-expired",
            public_key=public,
            algorithm="Ed25519",
            expires_at=expired,
        )

        # At current time should be trusted
        assert trust_chain_service.is_key_trusted("future-expired") is True

        # After expiration should not be trusted
        after_expired = expired + timedelta(days=1)
        assert trust_chain_service.is_key_trusted("future-expired", at_time=after_expired) is False


# =============================================================================
# TEST: Get Root Keys
# =============================================================================


@pytest.mark.security
class TestGetRootKeys:
    """Test root key retrieval."""

    def test_get_root_keys_empty(self, trust_chain_service: MockTrustChainService) -> None:
        """Test empty registry returns empty list."""
        roots = trust_chain_service.get_root_keys()
        assert roots == []

    def test_get_root_keys_multiple(self, trust_chain_service: MockTrustChainService, ed25519_signer: Ed25519Signer) -> None:
        """Test multiple root keys returned."""
        for i in range(3):
            _, public = ed25519_signer.generate_keypair()
            trust_chain_service.add_trusted_key(
                key_id=f"root-{i}",
                public_key=public,
                algorithm="Ed25519",
            )

        # Add some non-root keys
        for i in range(2):
            _, public = ed25519_signer.generate_keypair()
            trust_chain_service.add_trusted_key(
                key_id=f"child-{i}",
                public_key=public,
                algorithm="Ed25519",
                parent_key_id=f"root-{i}",
            )

        roots = trust_chain_service.get_root_keys()

        assert len(roots) == 3
        root_ids = {r.key_id for r in roots}
        assert root_ids == {"root-0", "root-1", "root-2"}


# =============================================================================
# TEST: Thread Safety
# =============================================================================


@pytest.mark.security
class TestThreadSafety:
    """Test thread-safe operations."""

    def test_thread_safety_concurrent_access(self, trust_chain_service: MockTrustChainService, ed25519_signer: Ed25519Signer) -> None:
        """Test concurrent access to service."""
        # Add root key
        _, root_public = ed25519_signer.generate_keypair()
        trust_chain_service.add_trusted_key(
            key_id="root",
            public_key=root_public,
            algorithm="Ed25519",
        )

        errors = []
        success_count = [0]
        lock = threading.Lock()

        def add_keys(start: int) -> None:
            """Add keys in thread."""
            try:
                for i in range(10):
                    _, public = ed25519_signer.generate_keypair()
                    key_id = f"thread-{start}-key-{i}"
                    trust_chain_service.add_trusted_key(
                        key_id=key_id,
                        public_key=public,
                        algorithm="Ed25519",
                        parent_key_id="root",
                    )
                    with lock:
                        success_count[0] += 1
            except Exception as exc:
                errors.append(exc)

        def read_keys() -> None:
            """Read keys in thread."""
            try:
                for _ in range(50):
                    _ = trust_chain_service.get_root_keys()
                    _ = trust_chain_service.get_trust_chain("root")
                    time.sleep(0.001)  # Small delay
            except Exception as exc:
                errors.append(exc)

        # Run concurrent operations
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []

            # 5 threads adding keys
            for i in range(5):
                futures.append(executor.submit(add_keys, i))

            # 5 threads reading keys
            for _ in range(5):
                futures.append(executor.submit(read_keys))

            # Wait for completion
            for future in as_completed(futures):
                future.result()

        # Check results
        assert not errors, f"Thread errors: {errors}"
        assert success_count[0] == 50  # 5 threads * 10 keys

        # Verify all keys were added
        for i in range(5):
            for j in range(10):
                key_id = f"thread-{i}-key-{j}"
                assert key_id in trust_chain_service._keys


# =============================================================================
# TEST: Persistence
# =============================================================================


@pytest.mark.security
class TestPersistence:
    """Test storage persistence."""

    def test_keys_persisted_to_storage(self, temp_dir: Path, ed25519_signer: Ed25519Signer) -> None:
        """Test keys are saved to and loaded from storage."""
        storage_path = temp_dir / "trust.json"

        # Create service and add keys
        service1 = MockTrustChainService(storage_path=storage_path)
        _, public1 = ed25519_signer.generate_keypair()
        service1.add_trusted_key(
            key_id="persisted",
            public_key=public1,
            algorithm="Ed25519",
            metadata={"test": "value"},
        )

        # Create new service instance with same storage
        service2 = MockTrustChainService(storage_path=storage_path)

        # Key should be loaded
        assert "persisted" in service2._keys
        loaded_link = service2._keys["persisted"].link
        assert loaded_link.key_id == "persisted"
        assert loaded_link.algorithm == "Ed25519"
        assert loaded_link.metadata.get("test") == "value"

    def test_revoked_keys_persisted(self, temp_dir: Path, ed25519_signer: Ed25519Signer) -> None:
        """Test revoked status is persisted."""
        storage_path = temp_dir / "trust.json"

        service1 = MockTrustChainService(storage_path=storage_path)

        # Add root and key to revoke
        _, root_public = ed25519_signer.generate_keypair()
        service1.add_trusted_key(
            key_id="root",
            public_key=root_public,
            algorithm="Ed25519",
        )
        _, key_public = ed25519_signer.generate_keypair()
        service1.add_trusted_key(
            key_id="to-revoke",
            public_key=key_public,
            algorithm="Ed25519",
            parent_key_id="root",
        )
        service1.revoke_key(
            key_id="to-revoke",
            reason="Test",
            revoked_by="root",
        )

        # New service should see revoked status
        service2 = MockTrustChainService(storage_path=storage_path)
        assert service2._keys["to-revoke"].revoked is True
        assert service2._keys["to-revoke"].revoke_reason == "Test"


# =============================================================================
# TEST: TrustVerificationResult Properties
# =============================================================================


@pytest.mark.security
class TestTrustVerificationResult:
    """Test TrustVerificationResult properties."""

    def test_can_trust_property(self) -> None:
        """Test can_trust property logic."""
        # Valid + TRUSTED = can trust
        result = TrustVerificationResult(
            template_id="test",
            is_valid=True,
            trust_status=TrustStatus.TRUSTED,
            chain_depth=1,
            signing_key_id="key",
        )
        assert result.can_trust is True

        # Valid but REVOKED = cannot trust
        result = TrustVerificationResult(
            template_id="test",
            is_valid=True,
            trust_status=TrustStatus.REVOKED,
            chain_depth=1,
            signing_key_id="key",
        )
        assert result.can_trust is False

        # Invalid + TRUSTED = cannot trust
        result = TrustVerificationResult(
            template_id="test",
            is_valid=False,
            trust_status=TrustStatus.TRUSTED,
            chain_depth=1,
            signing_key_id="key",
        )
        assert result.can_trust is False

    def test_is_revoked_property(self) -> None:
        """Test is_revoked property."""
        result = TrustVerificationResult(
            template_id="test",
            is_valid=False,
            trust_status=TrustStatus.REVOKED,
            chain_depth=1,
            signing_key_id="key",
        )
        assert result.is_revoked is True

        result = TrustVerificationResult(
            template_id="test",
            is_valid=True,
            trust_status=TrustStatus.TRUSTED,
            chain_depth=1,
            signing_key_id="key",
        )
        assert result.is_revoked is False


# =============================================================================
# TEST: TrustChainLink Methods
# =============================================================================


@pytest.mark.security
class TestTrustChainLink:
    """Test TrustChainLink methods."""

    def test_is_root_property(self) -> None:
        """Test is_root method."""
        root = TrustChainLink(
            key_id="root",
            public_key=b"pk",
            algorithm="Ed25519",
            added_at=datetime.now(),
            parent_key_id=None,
        )
        assert root.is_root() is True

        child = TrustChainLink(
            key_id="child",
            public_key=b"pk",
            algorithm="Ed25519",
            added_at=datetime.now(),
            parent_key_id="root",
        )
        assert child.is_root() is False

    def test_is_expired_method(self) -> None:
        """Test is_expired method."""
        expired = TrustChainLink(
            key_id="expired",
            public_key=b"pk",
            algorithm="Ed25519",
            added_at=datetime.now(),
            expires_at=datetime.now() - timedelta(days=1),
        )
        assert expired.is_expired() is True

        valid = TrustChainLink(
            key_id="valid",
            public_key=b"pk",
            algorithm="Ed25519",
            added_at=datetime.now(),
            expires_at=datetime.now() + timedelta(days=1),
        )
        assert valid.is_expired() is False

        no_expiry = TrustChainLink(
            key_id="no-expiry",
            public_key=b"pk",
            algorithm="Ed25519",
            added_at=datetime.now(),
            expires_at=None,
        )
        assert no_expiry.is_expired() is False

    def test_to_dict_roundtrip(self) -> None:
        """Test serialization roundtrip."""
        original = TrustChainLink(
            key_id="test",
            public_key=b"\x01\x02\x03",
            algorithm="Ed25519",
            added_at=datetime.now(),
            parent_key_id="parent",
            expires_at=datetime.now() + timedelta(days=1),
            signature=b"\xaa\xbb\xcc",
            metadata={"name": "Test"},
        )

        data = original.to_dict()
        restored = TrustChainLink.from_dict(data)

        assert restored.key_id == original.key_id
        assert restored.public_key == original.public_key
        assert restored.algorithm == original.algorithm
        assert restored.parent_key_id == original.parent_key_id
        assert restored.signature == original.signature
        assert restored.metadata == original.metadata


# =============================================================================
# TEST: TrustStatus Enum
# =============================================================================


@pytest.mark.security
class TestTrustStatus:
    """Test TrustStatus enum."""

    def test_trust_status_labels(self) -> None:
        """Test status labels."""
        assert TrustStatus.TRUSTED.label() == "Доверенный"
        assert TrustStatus.UNTRUSTED.label() == "Не доверенный"
        assert TrustStatus.REVOKED.label() == "Отозванный"
        assert TrustStatus.EXPIRED.label() == "Истёк срок"
        assert TrustStatus.PENDING.label() == "В ожидании"

    def test_trust_status_emojis(self) -> None:
        """Test status emojis."""
        assert TrustStatus.TRUSTED.emoji() == "✅"
        assert TrustStatus.UNTRUSTED.emoji() == "❌"
        assert TrustStatus.REVOKED.emoji() == "🚫"
        assert TrustStatus.EXPIRED.emoji() == "⏰"
        assert TrustStatus.PENDING.emoji() == "⏳"

    def test_trust_status_is_valid(self) -> None:
        """Test is_valid method."""
        assert TrustStatus.TRUSTED.is_valid() is True
        assert TrustStatus.UNTRUSTED.is_valid() is False
        assert TrustStatus.REVOKED.is_valid() is False
        assert TrustStatus.EXPIRED.is_valid() is False
        assert TrustStatus.PENDING.is_valid() is False


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.services"])
