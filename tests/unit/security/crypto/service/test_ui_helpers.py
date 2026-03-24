"""
Тесты для ui_helpers.py — UI-вспомогательные функции криптографии.

Покрытие:
    - get_security_badge(): все уровни безопасности
    - get_floppy_badge(): все уровни floppy_friendly
    - get_status_badge(): все статусы + fallback для unknown
    - format_algorithm_short(): формат «значок name — описание»
    - format_algorithm_info(): секции, флаги AEAD/PQC, предупреждения
    - format_key_sizes(): форматирование каждого поля, пустая строка если нет данных
    - list_recommended_algorithms(): категории, фильтрация, сортировка, invalid raises
    - get_algorithm_warning(): None для safe, строки для broken/legacy/deprecated/experimental
    - get_profile_summary(): корректный формат, unknown profile

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from src.security.crypto.core.metadata import (
    AlgorithmCategory,
    AlgorithmMetadata,
    FloppyFriendly,
    ImplementationStatus,
    SecurityLevel,
)
from src.security.crypto.service.ui_helpers import (
    format_algorithm_info,
    format_algorithm_short,
    format_key_sizes,
    get_algorithm_warning,
    get_floppy_badge,
    get_profile_summary,
    get_security_badge,
    get_status_badge,
    list_recommended_algorithms,
)

# ==============================================================================
# HELPERS
# ==============================================================================


def _make_meta(
    *,
    name: str = "TEST-ALGO",
    # KDF — единственная категория без обязательных size-полей
    category: AlgorithmCategory = AlgorithmCategory.KDF,
    security_level: SecurityLevel = SecurityLevel.STANDARD,
    floppy_friendly: FloppyFriendly = FloppyFriendly.EXCELLENT,
    status: ImplementationStatus = ImplementationStatus.STABLE,
    is_aead: bool = False,
    is_post_quantum: bool = False,
    key_size: int | None = None,
    public_key_size: int | None = None,
    private_key_size: int | None = None,
    signature_size: int | None = None,
    nonce_size: int | None = None,
    digest_size: int | None = None,
    max_plaintext_size: int | None = None,
    description_ru: str = "",
    use_cases: list[str] | None = None,
) -> AlgorithmMetadata:
    # Автозаполнение обязательных полей по категории
    if category == AlgorithmCategory.SYMMETRIC_CIPHER:
        key_size = key_size or 32
        nonce_size = nonce_size or 12
    elif category == AlgorithmCategory.SIGNATURE:
        signature_size = signature_size or 64
    elif category == AlgorithmCategory.HASH:
        digest_size = digest_size or 32

    # is_post_quantum требует QUANTUM_RESISTANT
    if is_post_quantum:
        security_level = SecurityLevel.QUANTUM_RESISTANT

    return AlgorithmMetadata(
        name=name,
        category=category,
        protocol_class=object,
        library="hashlib",
        implementation_class="TestImpl",
        security_level=security_level,
        floppy_friendly=floppy_friendly,
        status=status,
        is_aead=is_aead,
        is_post_quantum=is_post_quantum,
        key_size=key_size,
        public_key_size=public_key_size,
        private_key_size=private_key_size,
        signature_size=signature_size,
        nonce_size=nonce_size,
        digest_size=digest_size,
        max_plaintext_size=max_plaintext_size,
        description_ru=description_ru,
        use_cases=use_cases or [],
    )


# ==============================================================================
# get_security_badge
# ==============================================================================


class TestGetSecurityBadge:
    @pytest.mark.parametrize(
        "level, expected",
        [
            (SecurityLevel.BROKEN, "[X]"),
            (SecurityLevel.LEGACY, "[!]"),
            (SecurityLevel.STANDARD, "[OK]"),
            (SecurityLevel.HIGH, "[★]"),
            (SecurityLevel.QUANTUM_RESISTANT, "[QP]"),
        ],
    )
    def test_returns_expected_badge(self, level: SecurityLevel, expected: str) -> None:
        meta = _make_meta(security_level=level)
        assert get_security_badge(meta) == expected

    def test_returns_string(self) -> None:
        meta = _make_meta()
        assert isinstance(get_security_badge(meta), str)


# ==============================================================================
# get_floppy_badge
# ==============================================================================


class TestGetFloppyBadge:
    @pytest.mark.parametrize(
        "floppy, expected",
        [
            (FloppyFriendly.EXCELLENT, "💚"),
            (FloppyFriendly.ACCEPTABLE, "💛"),
            (FloppyFriendly.POOR, "❌"),
        ],
    )
    def test_returns_expected_badge(self, floppy: FloppyFriendly, expected: str) -> None:
        meta = _make_meta(floppy_friendly=floppy)
        assert get_floppy_badge(meta) == expected

    def test_returns_string(self) -> None:
        meta = _make_meta()
        assert isinstance(get_floppy_badge(meta), str)


# ==============================================================================
# get_status_badge
# ==============================================================================


class TestGetStatusBadge:
    @pytest.mark.parametrize(
        "status, expected",
        [
            (ImplementationStatus.STABLE, "✅"),
            (ImplementationStatus.EXPERIMENTAL, "🧪"),
            (ImplementationStatus.DEPRECATED, "⚠️"),
        ],
    )
    def test_known_status(self, status: ImplementationStatus, expected: str) -> None:
        meta = _make_meta(status=status)
        assert get_status_badge(meta) == expected

    def test_unknown_status_fallback(self) -> None:
        """Неизвестный статус возвращает fallback '❓'."""
        meta = _make_meta()
        meta_mock = MagicMock(spec=AlgorithmMetadata)
        meta_mock.status = MagicMock()  # не в словаре
        result = get_status_badge(meta_mock)
        assert isinstance(result, str)


# ==============================================================================
# format_algorithm_short
# ==============================================================================


class TestFormatAlgorithmShort:
    def test_contains_name(self) -> None:
        meta = _make_meta(name="AES-256-GCM")
        result = format_algorithm_short(meta)
        assert "AES-256-GCM" in result

    def test_contains_badge(self) -> None:
        meta = _make_meta(security_level=SecurityLevel.STANDARD)
        result = format_algorithm_short(meta)
        assert "[OK]" in result

    def test_contains_description_when_present(self) -> None:
        meta = _make_meta(description_ru="Тестовое описание")
        result = format_algorithm_short(meta)
        assert "Тестовое описание" in result

    def test_no_dash_when_no_description(self) -> None:
        meta = _make_meta(description_ru="")
        result = format_algorithm_short(meta)
        assert "—" not in result

    def test_format_with_dash_separator(self) -> None:
        meta = _make_meta(name="Ed25519", description_ru="Описание")
        result = format_algorithm_short(meta)
        assert "—" in result


# ==============================================================================
# format_algorithm_info
# ==============================================================================


class TestFormatAlgorithmInfo:
    def test_contains_name(self) -> None:
        meta = _make_meta(name="ChaCha20")
        result = format_algorithm_info(meta)
        assert "ChaCha20" in result

    def test_contains_category(self) -> None:
        meta = _make_meta(category=AlgorithmCategory.HASH)
        result = format_algorithm_info(meta)
        assert "Хеширование" in result

    def test_contains_security_section(self) -> None:
        meta = _make_meta()
        result = format_algorithm_info(meta)
        assert "Безопасность" in result

    def test_contains_floppy_section(self) -> None:
        meta = _make_meta()
        result = format_algorithm_info(meta)
        assert "Дискета" in result

    def test_contains_status_section(self) -> None:
        meta = _make_meta()
        result = format_algorithm_info(meta)
        assert "Статус" in result

    def test_contains_library(self) -> None:
        meta = _make_meta()
        result = format_algorithm_info(meta)
        assert "Библиотека" in result

    def test_aead_flag_shown(self) -> None:
        meta = _make_meta(is_aead=True)
        result = format_algorithm_info(meta)
        assert "AEAD" in result

    def test_pqc_flag_shown(self) -> None:
        meta = _make_meta(is_post_quantum=True)
        result = format_algorithm_info(meta)
        assert "Post-Quantum" in result

    def test_no_aead_flag_when_false(self) -> None:
        meta = _make_meta(is_aead=False)
        result = format_algorithm_info(meta)
        assert "AEAD" not in result

    def test_warning_shown_for_broken(self) -> None:
        meta = _make_meta(security_level=SecurityLevel.BROKEN)
        result = format_algorithm_info(meta)
        assert "ВНИМАНИЕ" in result

    def test_no_warning_for_standard(self) -> None:
        meta = _make_meta(security_level=SecurityLevel.STANDARD)
        result = format_algorithm_info(meta)
        assert "ВНИМАНИЕ" not in result

    def test_use_cases_shown(self) -> None:
        meta = _make_meta(use_cases=["Шифрование файлов", "TLS"])
        result = format_algorithm_info(meta)
        assert "Применение" in result
        assert "Шифрование файлов" in result

    def test_sizes_section_shown_when_present(self) -> None:
        meta = _make_meta(key_size=32, nonce_size=12)
        result = format_algorithm_info(meta)
        assert "Размеры" in result

    def test_no_sizes_section_when_absent(self) -> None:
        meta = _make_meta()
        result = format_algorithm_info(meta)
        assert "Размеры" not in result


# ==============================================================================
# format_key_sizes
# ==============================================================================


class TestFormatKeySizes:
    def test_empty_when_no_sizes(self) -> None:
        meta = _make_meta()
        assert format_key_sizes(meta) == ""

    def test_key_size_shown(self) -> None:
        meta = _make_meta(key_size=32)
        result = format_key_sizes(meta)
        assert "32 байт" in result
        assert "Ключ" in result

    def test_public_key_size_shown(self) -> None:
        meta = _make_meta(public_key_size=32)
        result = format_key_sizes(meta)
        assert "Публичный ключ: 32 байт" in result

    def test_private_key_size_shown(self) -> None:
        meta = _make_meta(private_key_size=64)
        result = format_key_sizes(meta)
        assert "Приватный ключ: 64 байт" in result

    def test_signature_size_shown(self) -> None:
        meta = _make_meta(signature_size=64)
        result = format_key_sizes(meta)
        assert "Подпись: 64 байт" in result

    def test_nonce_size_shown(self) -> None:
        meta = _make_meta(nonce_size=12)
        result = format_key_sizes(meta)
        assert "Nonce/IV: 12 байт" in result

    def test_digest_size_shown(self) -> None:
        meta = _make_meta(digest_size=32)
        result = format_key_sizes(meta)
        assert "Дайджест: 32 байт" in result

    def test_max_plaintext_size_shown_in_mb(self) -> None:
        meta = _make_meta(max_plaintext_size=64 * 1024 * 1024)
        result = format_key_sizes(meta)
        assert "64 MB" in result

    def test_multiple_sizes_multiline(self) -> None:
        meta = _make_meta(key_size=32, nonce_size=12, digest_size=16)
        result = format_key_sizes(meta)
        lines = result.strip().split("\n")
        assert len(lines) == 3


# ==============================================================================
# list_recommended_algorithms
# ==============================================================================


class TestListRecommendedAlgorithms:
    def _make_mock_registry(self, algorithms: dict[str, AlgorithmMetadata]) -> MagicMock:
        registry = MagicMock()
        registry.list_algorithms.return_value = list(algorithms.values())
        registry.get_metadata.side_effect = lambda name: algorithms[name]
        return registry

    def test_invalid_category_raises(self) -> None:
        with pytest.raises(ValueError, match="Неизвестная категория"):
            list_recommended_algorithms("invalid-cat")

    @pytest.mark.parametrize(
        "category",
        ["symmetric", "signing", "asymmetric", "kex", "hash", "kdf"],
    )
    def test_valid_category_returns_list(self, category: str) -> None:
        with patch(
            "src.security.crypto.service.ui_helpers.AlgorithmRegistry.get_instance"
        ) as mock_get:
            mock_get.return_value = self._make_mock_registry({})
            result = list_recommended_algorithms(category)
            assert isinstance(result, list)

    def test_broken_excluded(self) -> None:
        algo_meta = {
            "safe": _make_meta(
                name="SAFE",
                category=AlgorithmCategory.SYMMETRIC_CIPHER,
                security_level=SecurityLevel.STANDARD,
            ),
            "broken": _make_meta(
                name="BROKEN",
                category=AlgorithmCategory.SYMMETRIC_CIPHER,
                security_level=SecurityLevel.BROKEN,
            ),
        }
        with patch(
            "src.security.crypto.service.ui_helpers.AlgorithmRegistry.get_instance"
        ) as mock_get:
            mock_get.return_value = self._make_mock_registry(algo_meta)
            result = list_recommended_algorithms("symmetric")
        assert "broken" not in result
        assert "safe" in result

    def test_legacy_excluded_by_default(self) -> None:
        algo_meta = {
            "safe": _make_meta(
                name="SAFE",
                category=AlgorithmCategory.SYMMETRIC_CIPHER,
                security_level=SecurityLevel.STANDARD,
            ),
            "legacy": _make_meta(
                name="LEGACY",
                category=AlgorithmCategory.SYMMETRIC_CIPHER,
                security_level=SecurityLevel.LEGACY,
            ),
        }
        with patch(
            "src.security.crypto.service.ui_helpers.AlgorithmRegistry.get_instance"
        ) as mock_get:
            mock_get.return_value = self._make_mock_registry(algo_meta)
            result = list_recommended_algorithms("symmetric")
        assert "legacy" not in result

    def test_legacy_included_with_flag(self) -> None:
        algo_meta = {
            "legacy": _make_meta(
                name="LEGACY",
                category=AlgorithmCategory.SYMMETRIC_CIPHER,
                security_level=SecurityLevel.LEGACY,
            ),
        }
        with patch(
            "src.security.crypto.service.ui_helpers.AlgorithmRegistry.get_instance"
        ) as mock_get:
            mock_get.return_value = self._make_mock_registry(algo_meta)
            result = list_recommended_algorithms("symmetric", include_legacy=True)
        assert "legacy" in result

    def test_category_filter_applied(self) -> None:
        algo_meta = {
            "sym": _make_meta(
                name="SYM",
                category=AlgorithmCategory.SYMMETRIC_CIPHER,
                security_level=SecurityLevel.STANDARD,
            ),
            "sig": _make_meta(
                name="SIG",
                category=AlgorithmCategory.SIGNATURE,
                security_level=SecurityLevel.STANDARD,
            ),
        }
        with patch(
            "src.security.crypto.service.ui_helpers.AlgorithmRegistry.get_instance"
        ) as mock_get:
            mock_get.return_value = self._make_mock_registry(algo_meta)
            result = list_recommended_algorithms("symmetric")
        assert "sym" in result
        assert "sig" not in result

    def test_stable_before_experimental(self) -> None:
        algo_meta = {
            "exp": _make_meta(
                name="EXP",
                category=AlgorithmCategory.SYMMETRIC_CIPHER,
                security_level=SecurityLevel.STANDARD,
                status=ImplementationStatus.EXPERIMENTAL,
            ),
            "stable": _make_meta(
                name="STABLE",
                category=AlgorithmCategory.SYMMETRIC_CIPHER,
                security_level=SecurityLevel.STANDARD,
                status=ImplementationStatus.STABLE,
            ),
        }
        with patch(
            "src.security.crypto.service.ui_helpers.AlgorithmRegistry.get_instance"
        ) as mock_get:
            mock_get.return_value = self._make_mock_registry(algo_meta)
            result = list_recommended_algorithms("symmetric")
        assert result.index("stable") < result.index("exp")

    def test_pqc_first_when_post_quantum_flag(self) -> None:
        algo_meta = {
            "classical": _make_meta(
                name="CLASSICAL",
                category=AlgorithmCategory.SIGNATURE,
                security_level=SecurityLevel.STANDARD,
                is_post_quantum=False,
            ),
            "pqc": _make_meta(
                name="PQC",
                category=AlgorithmCategory.SIGNATURE,
                security_level=SecurityLevel.QUANTUM_RESISTANT,
                is_post_quantum=True,
            ),
        }
        with patch(
            "src.security.crypto.service.ui_helpers.AlgorithmRegistry.get_instance"
        ) as mock_get:
            mock_get.return_value = self._make_mock_registry(algo_meta)
            result = list_recommended_algorithms("signing", post_quantum=True)
        assert result.index("pqc") < result.index("classical")


# ==============================================================================
# get_algorithm_warning
# ==============================================================================


class TestGetAlgorithmWarning:
    def test_none_for_standard_stable(self) -> None:
        meta = _make_meta(
            security_level=SecurityLevel.STANDARD,
            status=ImplementationStatus.STABLE,
        )
        assert get_algorithm_warning(meta) is None

    def test_none_for_high_level(self) -> None:
        meta = _make_meta(security_level=SecurityLevel.HIGH)
        assert get_algorithm_warning(meta) is None

    def test_none_for_quantum_resistant(self) -> None:
        meta = _make_meta(security_level=SecurityLevel.QUANTUM_RESISTANT)
        assert get_algorithm_warning(meta) is None

    def test_warning_for_broken(self) -> None:
        meta = _make_meta(security_level=SecurityLevel.BROKEN)
        warning = get_algorithm_warning(meta)
        assert warning is not None
        assert (
            "взломанным" in warning.lower()
            or "нe используйте" in warning.lower()
            or "не используйте" in warning.lower()
        )

    def test_warning_for_legacy(self) -> None:
        meta = _make_meta(security_level=SecurityLevel.LEGACY)
        warning = get_algorithm_warning(meta)
        assert warning is not None
        assert isinstance(warning, str)

    def test_warning_for_deprecated_status(self) -> None:
        meta = _make_meta(status=ImplementationStatus.DEPRECATED)
        warning = get_algorithm_warning(meta)
        assert warning is not None
        assert "DEPRECATED" in warning

    def test_warning_for_experimental_status(self) -> None:
        meta = _make_meta(status=ImplementationStatus.EXPERIMENTAL)
        warning = get_algorithm_warning(meta)
        assert warning is not None
        assert "экспериментальный" in warning.lower()

    def test_broken_takes_priority_over_deprecated(self) -> None:
        """SecurityLevel.BROKEN — первый приоритет."""
        meta = _make_meta(
            security_level=SecurityLevel.BROKEN,
            status=ImplementationStatus.DEPRECATED,
        )
        warning = get_algorithm_warning(meta)
        assert warning is not None
        # Должно содержать сообщение о broken, а не deprecated
        assert "DEPRECATED" not in warning


# ==============================================================================
# get_profile_summary
# ==============================================================================


class TestGetProfileSummary:
    def test_contains_label(self) -> None:
        result = get_profile_summary("standard")
        assert "Стандартный" in result

    def test_contains_symmetric_algo(self) -> None:
        result = get_profile_summary("standard")
        assert "AES-256-GCM" in result

    def test_contains_signing_algo(self) -> None:
        result = get_profile_summary("standard")
        assert "Ed25519" in result

    def test_contains_kex_algo(self) -> None:
        result = get_profile_summary("standard")
        assert "X25519" in result

    def test_pqc_tag_present(self) -> None:
        result = get_profile_summary("pqc_standard")
        assert "[PQC]" in result

    def test_no_pqc_tag_for_standard(self) -> None:
        result = get_profile_summary("standard")
        assert "[PQC]" not in result

    def test_floppy_tag_present(self) -> None:
        result = get_profile_summary("floppy_basic")
        assert "💾" in result

    def test_unknown_profile_returns_error_string(self) -> None:
        result = get_profile_summary("nonexistent-profile")
        assert "Неизвестный профиль" in result

    @pytest.mark.parametrize(
        "profile_name",
        [
            "standard",
            "paranoid",
            "legacy",
            "floppy_basic",
            "floppy_aggressive",
            "pqc_standard",
            "pqc_paranoid",
        ],
    )
    def test_all_profiles_return_non_empty(self, profile_name: str) -> None:
        result = get_profile_summary(profile_name)
        assert isinstance(result, str)
        assert len(result) > 0
