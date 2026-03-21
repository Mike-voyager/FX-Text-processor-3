"""Tests for AppContext with crypto_service integration."""

import pytest
from src.app_context import AppContext, get_app_context
from src.security.crypto.service.profiles import CryptoProfile


class TestAppContextCryptoService:
    """Tests for AppContext crypto_service integration."""

    def test_app_context_init_with_default_crypto_profile(self) -> None:
        """Test AppContext initializes with default STANDARD profile."""
        ctx = AppContext()

        # Verify crypto_service is initialized
        assert hasattr(ctx, "crypto_service")
        assert ctx.crypto_service is not None
        assert ctx.crypto_service.profile == CryptoProfile.STANDARD

    def test_app_context_init_with_paranoid_profile(self) -> None:
        """Test AppContext initializes with PARANOID profile."""
        ctx = AppContext(crypto_profile=CryptoProfile.PARANOID)

        # Verify crypto_service uses PARANOID profile
        assert ctx.crypto_service.profile == CryptoProfile.PARANOID

    def test_app_context_init_with_pqc_profile(self) -> None:
        """Test AppContext initializes with PQC_STANDARD profile."""
        ctx = AppContext(crypto_profile=CryptoProfile.PQC_STANDARD)

        # Verify crypto_service uses PQC_STANDARD profile
        assert ctx.crypto_service.profile == CryptoProfile.PQC_STANDARD

    def test_app_context_crypto_service_has_correct_config(self) -> None:
        """Test crypto_service has correct ProfileConfig."""
        ctx = AppContext(crypto_profile=CryptoProfile.PARANOID)

        config = ctx.crypto_service.config

        # Verify config is for PARANOID profile
        assert config.profile == CryptoProfile.PARANOID
        assert config.signing_algorithm == "Ed448"
        assert config.symmetric_algorithm == "aes-256-gcm-siv"

    def test_get_app_context_passes_crypto_profile(self) -> None:
        """Test get_app_context passes crypto_profile to AppContext."""
        # Reset singleton to ensure fresh instance
        import src.app_context as app_ctx_module
        app_ctx_module._ctx = None

        ctx = get_app_context(crypto_profile=CryptoProfile.PQC_PARANOID)

        # Verify profile is set correctly
        assert ctx.crypto_service.profile == CryptoProfile.PQC_PARANOID

        # Reset for other tests
        app_ctx_module._ctx = None


class TestAppContextCryptoServiceIntegration:
    """Integration tests for crypto_service with other AppContext components."""

    def test_crypto_service_available_via_services_registry(self) -> None:
        """Test crypto_service can be registered in services registry."""
        ctx = AppContext(crypto_profile=CryptoProfile.STANDARD)

        # Register crypto_service in services
        ctx.register_service("crypto", ctx.crypto_service)

        # Retrieve via get_service
        retrieved = ctx.get_service("crypto")
        assert retrieved is ctx.crypto_service

    def test_mfa_manager_and_crypto_service_same_context(self) -> None:
        """Test mfa_manager and crypto_service coexist in same context."""
        ctx = AppContext(crypto_profile=CryptoProfile.STANDARD)

        # Both should be available
        assert ctx.mfa_manager is not None
        assert ctx.crypto_service is not None

        # They should be independent
        assert ctx.mfa_manager != ctx.crypto_service
