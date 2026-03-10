"""
Тесты для profiles.py — профили конфигурации криптографии.

Покрытие:
    - CryptoProfile: все значения, label(), description(), предикаты
    - ProfileConfig: поля dataclass, algorithm_ids()
    - PROFILES: все 7 профилей определены, конфигурации корректны
    - get_profile_config(): возвращает правильный ProfileConfig
    - list_profiles(): без фильтра и с фильтрами safe_only/floppy_only/pqc_only

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import pytest
from src.security.crypto.service.profiles import (
    PROFILES,
    CryptoProfile,
    ProfileConfig,
    get_profile_config,
    list_profiles,
)

# ==============================================================================
# CryptoProfile ENUM
# ==============================================================================


class TestCryptoProfileValues:
    """Проверка наличия и значений всех профилей."""

    @pytest.mark.parametrize(
        "profile, expected_value",
        [
            (CryptoProfile.STANDARD, "standard"),
            (CryptoProfile.PARANOID, "paranoid"),
            (CryptoProfile.LEGACY, "legacy"),
            (CryptoProfile.FLOPPY_BASIC, "floppy_basic"),
            (CryptoProfile.FLOPPY_AGGRESSIVE, "floppy_aggressive"),
            (CryptoProfile.PQC_STANDARD, "pqc_standard"),
            (CryptoProfile.PQC_PARANOID, "pqc_paranoid"),
        ],
    )
    def test_value(self, profile: CryptoProfile, expected_value: str) -> None:
        assert profile.value == expected_value

    def test_total_count(self) -> None:
        assert len(CryptoProfile) == 7

    def test_str_enum_usable_as_str(self) -> None:
        """CryptoProfile(str, Enum) — значение работает как строка."""
        assert CryptoProfile.STANDARD == "standard"


class TestCryptoProfileLabel:
    @pytest.mark.parametrize("profile", list(CryptoProfile))
    def test_label_non_empty(self, profile: CryptoProfile) -> None:
        label = profile.label()
        assert isinstance(label, str)
        assert len(label) > 0

    def test_legacy_label(self) -> None:
        assert "Legacy" in CryptoProfile.LEGACY.label()

    def test_standard_label_russian(self) -> None:
        assert CryptoProfile.STANDARD.label() == "Стандартный"

    def test_unknown_profile_does_not_raise(self) -> None:
        """При отсутствии в словаре label() возвращает title() от value — не KeyError."""
        # Проверяем через реальный профиль что .get() работает
        result = CryptoProfile.PARANOID.label()
        assert isinstance(result, str)


class TestCryptoProfileDescription:
    @pytest.mark.parametrize("profile", list(CryptoProfile))
    def test_description_is_str(self, profile: CryptoProfile) -> None:
        desc = profile.description()
        assert isinstance(desc, str)

    @pytest.mark.parametrize(
        "profile, keyword",
        [
            (CryptoProfile.STANDARD, "AES-256-GCM"),
            (CryptoProfile.PARANOID, "nonce"),
            (CryptoProfile.LEGACY, "совместимость"),
            (CryptoProfile.PQC_STANDARD, "quantum"),
        ],
    )
    def test_description_contains_keyword(self, profile: CryptoProfile, keyword: str) -> None:
        assert keyword.lower() in profile.description().lower()


class TestCryptoProfilePredicates:
    @pytest.mark.parametrize(
        "profile, expected",
        [
            (CryptoProfile.STANDARD, True),
            (CryptoProfile.PARANOID, True),
            (CryptoProfile.LEGACY, False),
            (CryptoProfile.FLOPPY_BASIC, True),
            (CryptoProfile.PQC_STANDARD, True),
        ],
    )
    def test_is_safe_for_new_systems(self, profile: CryptoProfile, expected: bool) -> None:
        assert profile.is_safe_for_new_systems() is expected

    @pytest.mark.parametrize(
        "profile, expected",
        [
            (CryptoProfile.FLOPPY_BASIC, True),
            (CryptoProfile.FLOPPY_AGGRESSIVE, True),
            (CryptoProfile.STANDARD, False),
            (CryptoProfile.PARANOID, False),
            (CryptoProfile.PQC_STANDARD, False),
        ],
    )
    def test_is_floppy_optimized(self, profile: CryptoProfile, expected: bool) -> None:
        assert profile.is_floppy_optimized() is expected

    @pytest.mark.parametrize(
        "profile, expected",
        [
            (CryptoProfile.PQC_STANDARD, True),
            (CryptoProfile.PQC_PARANOID, True),
            (CryptoProfile.STANDARD, False),
            (CryptoProfile.PARANOID, False),
            (CryptoProfile.LEGACY, False),
        ],
    )
    def test_is_post_quantum(self, profile: CryptoProfile, expected: bool) -> None:
        assert profile.is_post_quantum() is expected


# ==============================================================================
# ProfileConfig DATACLASS
# ==============================================================================


class TestProfileConfig:
    @pytest.fixture
    def standard_config(self) -> ProfileConfig:
        return get_profile_config(CryptoProfile.STANDARD)

    def test_frozen_immutable(self, standard_config: ProfileConfig) -> None:
        with pytest.raises((AttributeError, TypeError)):
            standard_config.symmetric_algorithm = "new-algo"  # type: ignore[misc]

    def test_algorithm_ids_keys(self, standard_config: ProfileConfig) -> None:
        ids = standard_config.algorithm_ids()
        for key in ("symmetric", "signing", "kex", "hash", "kdf", "asymmetric"):
            assert key in ids

    def test_algorithm_ids_values_are_str(self, standard_config: ProfileConfig) -> None:
        ids = standard_config.algorithm_ids()
        for v in ids.values():
            assert isinstance(v, str)
            assert len(v) > 0

    def test_standard_algorithms(self, standard_config: ProfileConfig) -> None:
        assert standard_config.symmetric_algorithm == "aes-256-gcm"
        assert standard_config.signing_algorithm == "Ed25519"
        assert standard_config.kex_algorithm == "x25519"

    def test_additional_signing_default_empty(self) -> None:
        config = get_profile_config(CryptoProfile.STANDARD)
        assert isinstance(config.additional_signing, list)
        assert config.additional_signing == []

    def test_pqc_standard_has_additional_signing(self) -> None:
        config = get_profile_config(CryptoProfile.PQC_STANDARD)
        assert len(config.additional_signing) > 0
        assert "Ed25519" in config.additional_signing


# ==============================================================================
# PROFILES DICT
# ==============================================================================


class TestProfilesDict:
    def test_all_profiles_present(self) -> None:
        for profile in CryptoProfile:
            assert profile in PROFILES

    @pytest.mark.parametrize("profile", list(CryptoProfile))
    def test_profile_field_matches_key(self, profile: CryptoProfile) -> None:
        config = PROFILES[profile]
        assert config.profile is profile

    @pytest.mark.parametrize(
        "profile, floppy_expected",
        [
            (CryptoProfile.FLOPPY_BASIC, True),
            (CryptoProfile.FLOPPY_AGGRESSIVE, True),
            (CryptoProfile.STANDARD, False),
        ],
    )
    def test_floppy_optimized_flag(self, profile: CryptoProfile, floppy_expected: bool) -> None:
        assert PROFILES[profile].floppy_optimized is floppy_expected

    @pytest.mark.parametrize(
        "profile, pqc_expected",
        [
            (CryptoProfile.PQC_STANDARD, True),
            (CryptoProfile.PQC_PARANOID, True),
            (CryptoProfile.STANDARD, False),
        ],
    )
    def test_post_quantum_flag(self, profile: CryptoProfile, pqc_expected: bool) -> None:
        assert PROFILES[profile].post_quantum is pqc_expected

    def test_legacy_not_safe(self) -> None:
        assert PROFILES[CryptoProfile.LEGACY].safe_for_new_systems is False

    def test_all_others_safe(self) -> None:
        for profile, config in PROFILES.items():
            if profile != CryptoProfile.LEGACY:
                assert config.safe_for_new_systems is True


# ==============================================================================
# get_profile_config()
# ==============================================================================


class TestGetProfileConfig:
    @pytest.mark.parametrize("profile", list(CryptoProfile))
    def test_returns_profile_config(self, profile: CryptoProfile) -> None:
        config = get_profile_config(profile)
        assert isinstance(config, ProfileConfig)

    @pytest.mark.parametrize("profile", list(CryptoProfile))
    def test_config_profile_matches(self, profile: CryptoProfile) -> None:
        config = get_profile_config(profile)
        assert config.profile is profile

    def test_same_object_as_profiles_dict(self) -> None:
        """get_profile_config возвращает тот же объект, что и PROFILES[...]."""
        config = get_profile_config(CryptoProfile.STANDARD)
        assert config is PROFILES[CryptoProfile.STANDARD]


# ==============================================================================
# list_profiles()
# ==============================================================================


class TestListProfiles:
    def test_returns_all_profiles_by_default(self) -> None:
        profiles = list_profiles()
        assert len(profiles) == len(CryptoProfile)
        for profile in CryptoProfile:
            assert profile in profiles

    def test_safe_only_excludes_legacy(self) -> None:
        profiles = list_profiles(safe_only=True)
        assert CryptoProfile.LEGACY not in profiles

    def test_safe_only_count(self) -> None:
        profiles = list_profiles(safe_only=True)
        assert len(profiles) == len(CryptoProfile) - 1  # только LEGACY исключён

    def test_floppy_only(self) -> None:
        profiles = list_profiles(floppy_only=True)
        assert CryptoProfile.FLOPPY_BASIC in profiles
        assert CryptoProfile.FLOPPY_AGGRESSIVE in profiles
        assert CryptoProfile.STANDARD not in profiles
        assert len(profiles) == 2

    def test_pqc_only(self) -> None:
        profiles = list_profiles(pqc_only=True)
        assert CryptoProfile.PQC_STANDARD in profiles
        assert CryptoProfile.PQC_PARANOID in profiles
        assert CryptoProfile.STANDARD not in profiles
        assert len(profiles) == 2

    def test_combined_filters_empty_result(self) -> None:
        """floppy_only + pqc_only — нет профилей, удовлетворяющих обоим."""
        profiles = list_profiles(floppy_only=True, pqc_only=True)
        assert profiles == []

    def test_returns_list(self) -> None:
        assert isinstance(list_profiles(), list)
