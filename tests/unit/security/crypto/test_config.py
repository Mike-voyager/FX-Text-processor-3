# -*- coding: utf-8 -*-
"""
Tests for crypto configuration module.
"""
from __future__ import annotations

import pytest

from src.security.crypto.config import Argon2Config, Argon2Profile


class TestArgon2Profile:
    """Tests for Argon2Profile enum."""

    def test_profile_values(self) -> None:
        """Test that all profiles have expected values."""
        assert Argon2Profile.DESKTOP.value == "desktop"
        assert Argon2Profile.SAFE_DESKTOP.value == "safe_desktop"
        assert Argon2Profile.CUSTOM.value == "custom"

    def test_profile_count(self) -> None:
        """Test expected number of profiles."""
        assert len(Argon2Profile) == 3


class TestArgon2ConfigCreation:
    """Tests for Argon2Config creation."""

    def test_create_with_all_params(self) -> None:
        """Test creating config with all parameters."""
        config = Argon2Config(
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            salt_length=16,
        )
        assert config.time_cost == 3
        assert config.memory_cost == 65536
        assert config.parallelism == 4
        assert config.salt_length == 16

    def test_create_with_default_salt_length(self) -> None:
        """Test creating config with default salt_length."""
        config = Argon2Config(
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
        )
        assert config.salt_length == 16

    def test_config_is_frozen(self) -> None:
        """Test that config dataclass is immutable."""
        config = Argon2Config(
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
        )
        with pytest.raises(Exception):  # FrozenInstanceError or AttributeError
            config.time_cost = 5  # type: ignore[misc]


class TestArgon2ConfigValidation:
    """Tests for Argon2Config parameter validation."""

    def test_time_cost_minimum(self) -> None:
        """Test that time_cost must be >= 2."""
        with pytest.raises(ValueError, match="time_cost must be >= 2"):
            Argon2Config(time_cost=1, memory_cost=65536, parallelism=4)

    def test_time_cost_valid_minimum(self) -> None:
        """Test that time_cost=2 is valid."""
        config = Argon2Config(time_cost=2, memory_cost=65536, parallelism=4)
        assert config.time_cost == 2

    def test_memory_cost_minimum(self) -> None:
        """Test that memory_cost must be >= 65536 KiB."""
        with pytest.raises(ValueError, match="memory_cost must be >= 65536 KiB"):
            Argon2Config(time_cost=3, memory_cost=32768, parallelism=4)

    def test_memory_cost_valid_minimum(self) -> None:
        """Test that memory_cost=65536 is valid."""
        config = Argon2Config(time_cost=3, memory_cost=65536, parallelism=4)
        assert config.memory_cost == 65536

    def test_parallelism_minimum(self) -> None:
        """Test that parallelism must be >= 1."""
        with pytest.raises(ValueError, match="parallelism must be >= 1"):
            Argon2Config(time_cost=3, memory_cost=65536, parallelism=0)

    def test_parallelism_valid_minimum(self) -> None:
        """Test that parallelism=1 is valid."""
        config = Argon2Config(time_cost=3, memory_cost=65536, parallelism=1)
        assert config.parallelism == 1

    def test_salt_length_too_small(self) -> None:
        """Test that salt_length must be >= 8."""
        with pytest.raises(
            ValueError, match="salt_length must be between 8 and 64 bytes"
        ):
            Argon2Config(time_cost=3, memory_cost=65536, parallelism=4, salt_length=7)

    def test_salt_length_too_large(self) -> None:
        """Test that salt_length must be <= 64."""
        with pytest.raises(
            ValueError, match="salt_length must be between 8 and 64 bytes"
        ):
            Argon2Config(time_cost=3, memory_cost=65536, parallelism=4, salt_length=65)

    def test_salt_length_valid_minimum(self) -> None:
        """Test that salt_length=8 is valid."""
        config = Argon2Config(
            time_cost=3, memory_cost=65536, parallelism=4, salt_length=8
        )
        assert config.salt_length == 8

    def test_salt_length_valid_maximum(self) -> None:
        """Test that salt_length=64 is valid."""
        config = Argon2Config(
            time_cost=3, memory_cost=65536, parallelism=4, salt_length=64
        )
        assert config.salt_length == 64


class TestArgon2ConfigProfiles:
    """Tests for predefined Argon2 profiles."""

    def test_desktop_profile(self) -> None:
        """Test DESKTOP profile parameters."""
        config = Argon2Config.from_profile(Argon2Profile.DESKTOP)

        assert config.time_cost == 3
        assert config.memory_cost == 65536  # 64 MiB
        assert config.parallelism == 4
        assert config.salt_length == 16

    def test_safe_desktop_profile(self) -> None:
        """Test SAFE_DESKTOP profile parameters."""
        config = Argon2Config.from_profile(Argon2Profile.SAFE_DESKTOP)

        assert config.time_cost == 5
        assert config.memory_cost == 131072  # 128 MiB
        assert config.parallelism == 8
        assert config.salt_length == 16

    def test_custom_profile(self) -> None:
        """Test CUSTOM profile parameters (same as DESKTOP)."""
        config = Argon2Config.from_profile(Argon2Profile.CUSTOM)

        assert config.time_cost == 3
        assert config.memory_cost == 65536
        assert config.parallelism == 4
        assert config.salt_length == 16

    def test_all_profiles_valid(self) -> None:
        """Test that all profiles produce valid configurations."""
        for profile in Argon2Profile:
            config = Argon2Config.from_profile(profile)

            # Should not raise validation errors
            assert config.time_cost >= 2
            assert config.memory_cost >= 65536
            assert config.parallelism >= 1
            assert 8 <= config.salt_length <= 64


class TestArgon2ConfigComparison:
    """Tests for comparing configurations."""

    def test_same_configs_equal(self) -> None:
        """Test that identical configs are equal."""
        config1 = Argon2Config(time_cost=3, memory_cost=65536, parallelism=4)
        config2 = Argon2Config(time_cost=3, memory_cost=65536, parallelism=4)

        assert config1 == config2

    def test_different_configs_not_equal(self) -> None:
        """Test that different configs are not equal."""
        config1 = Argon2Config(time_cost=3, memory_cost=65536, parallelism=4)
        config2 = Argon2Config(time_cost=5, memory_cost=131072, parallelism=8)

        assert config1 != config2

    def test_profile_configs_equal(self) -> None:
        """Test that same profile produces equal configs."""
        config1 = Argon2Config.from_profile(Argon2Profile.DESKTOP)
        config2 = Argon2Config.from_profile(Argon2Profile.DESKTOP)

        assert config1 == config2


class TestArgon2ConfigEdgeCases:
    """Tests for edge cases and extreme values."""

    def test_very_high_parameters(self) -> None:
        """Test with very high (but valid) parameters."""
        config = Argon2Config(
            time_cost=10,
            memory_cost=1048576,  # 1 GiB
            parallelism=16,
            salt_length=32,
        )

        assert config.time_cost == 10
        assert config.memory_cost == 1048576
        assert config.parallelism == 16
        assert config.salt_length == 32

    def test_config_repr(self) -> None:
        """Test that config has useful representation."""
        config = Argon2Config(time_cost=3, memory_cost=65536, parallelism=4)
        repr_str = repr(config)

        assert "Argon2Config" in repr_str
        assert "time_cost=3" in repr_str
        assert "memory_cost=65536" in repr_str
        assert "parallelism=4" in repr_str


class TestArgon2ConfigDocstrings:
    """Tests based on docstring examples."""

    def test_docstring_example_from_profile(self) -> None:
        """Test example from from_profile docstring."""
        config = Argon2Config.from_profile(Argon2Profile.DESKTOP)
        assert config.memory_cost == 65536

    def test_docstring_example_direct_creation(self) -> None:
        """Test example from class docstring."""
        config = Argon2Config(time_cost=5, memory_cost=131072, parallelism=8)
        assert config.time_cost == 5
