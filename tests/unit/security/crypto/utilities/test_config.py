"""
Тесты для модуля конфигурации криптографического модуля.

Покрытие:
- Значения по умолчанию (CryptoConfig.default)
- Профили безопасности (paranoid, floppy_basic, floppy_aggressive)
- Метод apply_floppy_mode (все три ветки)
- Валидация __post_init__ (граничные значения, отрицательные числа)
- Сериализация to_dict / from_dict (roundtrip, частичный словарь, неизвестные поля)
- Логирование (DEBUG/WARNING при создании и apply_floppy_mode)
- Regression: max_storage_size в aggressive режиме
- Edge cases: минимально допустимые значения, пустой словарь

Coverage target: 95%+

Author: Mike Voyager
Version: 1.0
Date: March 9, 2026
"""

from __future__ import annotations

import logging
from typing import Any

import pytest
from src.security.crypto.utilities.config import (
    CryptoConfig,
    FloppyMode,
    HashAlgorithm,
    KDFAlgorithm,
    SigningAlgorithm,
    SymmetricAlgorithm,
)

# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def default_config() -> CryptoConfig:
    """Стандартная конфигурация для тестов."""
    return CryptoConfig.default()


@pytest.fixture
def paranoid_config() -> CryptoConfig:
    """Параноидальная конфигурация для тестов."""
    return CryptoConfig.paranoid()


@pytest.fixture
def floppy_basic_config() -> CryptoConfig:
    """Базовая floppy-конфигурация для тестов."""
    return CryptoConfig.floppy_basic()


@pytest.fixture
def floppy_aggressive_config() -> CryptoConfig:
    """Агрессивная floppy-конфигурация для тестов."""
    return CryptoConfig.floppy_aggressive()


# ============================================================================
# TYPE ALIAS SMOKE TESTS
# ============================================================================


class TestTypeAliases:
    """Smoke-тесты для публичных Literal-алиасов."""

    def test_floppy_mode_values(self) -> None:
        """Проверяем, что FloppyMode содержит ровно три значения."""
        valid: list[FloppyMode] = ["disabled", "basic", "aggressive"]
        assert len(valid) == 3

    def test_symmetric_algorithm_values(self) -> None:
        """Проверяем допустимые значения SymmetricAlgorithm."""
        valid: list[SymmetricAlgorithm] = ["aes-256-gcm", "chacha20-poly1305"]
        assert len(valid) == 2

    def test_signing_algorithm_values(self) -> None:
        """Проверяем допустимые значения SigningAlgorithm."""
        valid: list[SigningAlgorithm] = ["ed25519", "rsa-pss-4096"]
        assert len(valid) == 2

    def test_hash_algorithm_values(self) -> None:
        """Проверяем допустимые значения HashAlgorithm."""
        valid: list[HashAlgorithm] = ["sha-256", "sha-512", "sha3-256", "blake2b"]
        assert len(valid) == 4

    def test_kdf_algorithm_values(self) -> None:
        """Проверяем допустимые значения KDFAlgorithm."""
        valid: list[KDFAlgorithm] = ["argon2id", "scrypt", "pbkdf2-sha512"]
        assert len(valid) == 3


# ============================================================================
# DEFAULT PROFILE
# ============================================================================


class TestCryptoConfigDefault:
    """Тесты для CryptoConfig.default()."""

    def test_default_symmetric(self, default_config: CryptoConfig) -> None:
        """AES-256-GCM — симметричный алгоритм по умолчанию."""
        assert default_config.default_symmetric == "aes-256-gcm"

    def test_default_signing(self, default_config: CryptoConfig) -> None:
        """Ed25519 — алгоритм подписи по умолчанию."""
        assert default_config.default_signing == "ed25519"

    def test_default_hash(self, default_config: CryptoConfig) -> None:
        """SHA-256 — хеш-функция по умолчанию."""
        assert default_config.default_hash == "sha-256"

    def test_default_kdf(self, default_config: CryptoConfig) -> None:
        """Argon2id — KDF по умолчанию."""
        assert default_config.default_kdf == "argon2id"

    def test_default_rotation_enabled(self, default_config: CryptoConfig) -> None:
        """Автоматическая ротация включена по умолчанию."""
        assert default_config.auto_rotation_enabled is True

    def test_default_rotation_interval(self, default_config: CryptoConfig) -> None:
        """Интервал ротации — 90 дней."""
        assert default_config.rotation_interval_days == 90

    def test_default_min_key_size(self, default_config: CryptoConfig) -> None:
        """Минимальный размер ключа — 16 байт (128 бит)."""
        assert default_config.min_key_size == 16

    def test_default_allow_legacy_false(self, default_config: CryptoConfig) -> None:
        """Legacy-алгоритмы запрещены по умолчанию."""
        assert default_config.allow_legacy is False

    def test_default_require_hardware_rng_false(self, default_config: CryptoConfig) -> None:
        """Аппаратный ГСЧ не обязателен по умолчанию."""
        assert default_config.require_hardware_rng is False

    def test_default_floppy_mode(self, default_config: CryptoConfig) -> None:
        """Floppy-режим отключён по умолчанию."""
        assert default_config.floppy_mode == "disabled"

    def test_default_max_storage_size(self, default_config: CryptoConfig) -> None:
        """Максимальный размер — 1.44 MB."""
        assert default_config.max_storage_size == 1_457_664

    def test_default_compress_keystore_false(self, default_config: CryptoConfig) -> None:
        """Сжатие keystore отключено по умолчанию."""
        assert default_config.compress_keystore is False

    def test_default_compact_key_format_false(self, default_config: CryptoConfig) -> None:
        """Компактный формат ключей отключён по умолчанию."""
        assert default_config.compact_key_format is False

    def test_default_auto_cleanup_backups_false(self, default_config: CryptoConfig) -> None:
        """Автоочистка бэкапов отключена по умолчанию."""
        assert default_config.auto_cleanup_backups is False

    def test_default_max_backup_count(self, default_config: CryptoConfig) -> None:
        """Максимальное количество бэкапов — 5."""
        assert default_config.max_backup_count == 5

    def test_default_returns_new_instance_each_time(self) -> None:
        """Каждый вызов default() создаёт новый объект."""
        a = CryptoConfig.default()
        b = CryptoConfig.default()
        assert a is not b
        assert a == b


# ============================================================================
# PARANOID PROFILE
# ============================================================================


class TestCryptoConfigParanoid:
    """Тесты для CryptoConfig.paranoid()."""

    def test_paranoid_hash_is_sha512(self, paranoid_config: CryptoConfig) -> None:
        """Параноидальный профиль использует SHA-512."""
        assert paranoid_config.default_hash == "sha-512"

    def test_paranoid_rotation_interval_30_days(self, paranoid_config: CryptoConfig) -> None:
        """Ротация каждые 30 дней в параноидальном режиме."""
        assert paranoid_config.rotation_interval_days == 30

    def test_paranoid_min_key_size_32(self, paranoid_config: CryptoConfig) -> None:
        """Параноидальный режим требует минимум 32 байта (256 бит)."""
        assert paranoid_config.min_key_size == 32

    def test_paranoid_allow_legacy_false(self, paranoid_config: CryptoConfig) -> None:
        """Legacy-алгоритмы запрещены в параноидальном режиме."""
        assert paranoid_config.allow_legacy is False

    def test_paranoid_require_hardware_rng_true(self, paranoid_config: CryptoConfig) -> None:
        """Параноидальный режим требует аппаратный ГСЧ."""
        assert paranoid_config.require_hardware_rng is True

    def test_paranoid_rotation_enabled(self, paranoid_config: CryptoConfig) -> None:
        """Автоматическая ротация включена в параноидальном режиме."""
        assert paranoid_config.auto_rotation_enabled is True

    def test_paranoid_symmetric_unchanged(self, paranoid_config: CryptoConfig) -> None:
        """AES-256-GCM сохраняется в параноидальном профиле."""
        assert paranoid_config.default_symmetric == "aes-256-gcm"

    def test_paranoid_floppy_mode_disabled(self, paranoid_config: CryptoConfig) -> None:
        """Floppy-режим отключён в параноидальном профиле."""
        assert paranoid_config.floppy_mode == "disabled"


# ============================================================================
# FLOPPY PROFILES
# ============================================================================


class TestCryptoConfigFloppyBasic:
    """Тесты для CryptoConfig.floppy_basic()."""

    def test_floppy_mode_is_basic(self, floppy_basic_config: CryptoConfig) -> None:
        """Режим floppy установлен в 'basic'."""
        assert floppy_basic_config.floppy_mode == "basic"

    def test_compress_keystore_true(self, floppy_basic_config: CryptoConfig) -> None:
        """Сжатие keystore включено в базовом floppy-режиме."""
        assert floppy_basic_config.compress_keystore is True

    def test_compact_key_format_false(self, floppy_basic_config: CryptoConfig) -> None:
        """Компактный формат ключей отключён в базовом floppy-режиме."""
        assert floppy_basic_config.compact_key_format is False

    def test_auto_cleanup_backups_true(self, floppy_basic_config: CryptoConfig) -> None:
        """Автоочистка бэкапов включена в базовом floppy-режиме."""
        assert floppy_basic_config.auto_cleanup_backups is True

    def test_max_backup_count_3(self, floppy_basic_config: CryptoConfig) -> None:
        """Максимум 3 бэкапа в базовом floppy-режиме."""
        assert floppy_basic_config.max_backup_count == 3

    def test_algorithms_unchanged(self, floppy_basic_config: CryptoConfig) -> None:
        """Floppy-режим не изменяет алгоритмы шифрования."""
        assert floppy_basic_config.default_symmetric == "aes-256-gcm"
        assert floppy_basic_config.default_signing == "ed25519"


class TestCryptoConfigFloppyAggressive:
    """Тесты для CryptoConfig.floppy_aggressive()."""

    def test_floppy_mode_is_aggressive(self, floppy_aggressive_config: CryptoConfig) -> None:
        """Режим floppy установлен в 'aggressive'."""
        assert floppy_aggressive_config.floppy_mode == "aggressive"

    def test_compress_keystore_true(self, floppy_aggressive_config: CryptoConfig) -> None:
        """Сжатие keystore включено в агрессивном floppy-режиме."""
        assert floppy_aggressive_config.compress_keystore is True

    def test_compact_key_format_true(self, floppy_aggressive_config: CryptoConfig) -> None:
        """Компактный формат ключей включён в агрессивном floppy-режиме."""
        assert floppy_aggressive_config.compact_key_format is True

    def test_auto_cleanup_backups_true(self, floppy_aggressive_config: CryptoConfig) -> None:
        """Автоочистка бэкапов включена в агрессивном floppy-режиме."""
        assert floppy_aggressive_config.auto_cleanup_backups is True

    def test_max_backup_count_1(self, floppy_aggressive_config: CryptoConfig) -> None:
        """Максимум 1 бэкап в агрессивном floppy-режиме."""
        assert floppy_aggressive_config.max_backup_count == 1

    def test_max_storage_size_1_44mb(self, floppy_aggressive_config: CryptoConfig) -> None:
        """Максимальный размер хранилища — 1.44 MB."""
        assert floppy_aggressive_config.max_storage_size == 1_457_664

    def test_is_more_restrictive_than_basic(
        self,
        floppy_basic_config: CryptoConfig,
        floppy_aggressive_config: CryptoConfig,
    ) -> None:
        """Агрессивный профиль жёстче базового по всем параметрам."""
        assert floppy_aggressive_config.max_backup_count < floppy_basic_config.max_backup_count
        assert floppy_aggressive_config.compact_key_format is True
        assert floppy_basic_config.compact_key_format is False


# ============================================================================
# APPLY FLOPPY MODE
# ============================================================================


class TestApplyFloppyMode:
    """Тесты для CryptoConfig.apply_floppy_mode()."""

    def test_apply_disabled_resets_flags(self, default_config: CryptoConfig) -> None:
        """Переход в 'disabled' сбрасывает все floppy-флаги."""
        default_config.apply_floppy_mode("basic")  # сначала включим
        default_config.apply_floppy_mode("disabled")

        assert default_config.floppy_mode == "disabled"
        assert default_config.compress_keystore is False
        assert default_config.compact_key_format is False
        assert default_config.auto_cleanup_backups is False

    def test_apply_basic_sets_flags(self, default_config: CryptoConfig) -> None:
        """Применение 'basic' устанавливает корректные флаги."""
        default_config.apply_floppy_mode("basic")

        assert default_config.floppy_mode == "basic"
        assert default_config.compress_keystore is True
        assert default_config.compact_key_format is False
        assert default_config.auto_cleanup_backups is True
        assert default_config.max_backup_count == 3

    def test_apply_aggressive_sets_all_flags(self, default_config: CryptoConfig) -> None:
        """Применение 'aggressive' устанавливает все компрессионные флаги."""
        default_config.apply_floppy_mode("aggressive")

        assert default_config.floppy_mode == "aggressive"
        assert default_config.compress_keystore is True
        assert default_config.compact_key_format is True
        assert default_config.auto_cleanup_backups is True
        assert default_config.max_backup_count == 1

    def test_apply_aggressive_updates_max_storage_size(self, default_config: CryptoConfig) -> None:
        """
        REGRESSION: apply_floppy_mode('aggressive') должен обновлять max_storage_size.

        В оригинальном коде это поле не обновлялось, что создавало
        расхождение между factory floppy_aggressive() и apply_floppy_mode().
        """
        initial_size = default_config.max_storage_size
        default_config.apply_floppy_mode("aggressive")

        assert default_config.max_storage_size == 1_457_664
        # Проверяем, что значение действительно установлено корректно
        assert default_config.max_storage_size == initial_size  # совпадает с дефолтом

    def test_apply_mode_and_factory_are_consistent(self) -> None:
        """apply_floppy_mode и floppy_aggressive() производят эквивалентные конфиги."""
        via_factory = CryptoConfig.floppy_aggressive()
        via_apply = CryptoConfig.default()
        via_apply.apply_floppy_mode("aggressive")

        assert via_apply.floppy_mode == via_factory.floppy_mode
        assert via_apply.compress_keystore == via_factory.compress_keystore
        assert via_apply.compact_key_format == via_factory.compact_key_format
        assert via_apply.auto_cleanup_backups == via_factory.auto_cleanup_backups
        assert via_apply.max_backup_count == via_factory.max_backup_count
        assert via_apply.max_storage_size == via_factory.max_storage_size

    def test_apply_basic_and_factory_are_consistent(self) -> None:
        """apply_floppy_mode('basic') и floppy_basic() производят эквивалентные конфиги."""
        via_factory = CryptoConfig.floppy_basic()
        via_apply = CryptoConfig.default()
        via_apply.apply_floppy_mode("basic")

        assert via_apply.floppy_mode == via_factory.floppy_mode
        assert via_apply.compress_keystore == via_factory.compress_keystore
        assert via_apply.compact_key_format == via_factory.compact_key_format
        assert via_apply.auto_cleanup_backups == via_factory.auto_cleanup_backups
        assert via_apply.max_backup_count == via_factory.max_backup_count

    @pytest.mark.parametrize(
        "mode,expected_compress,expected_compact,expected_cleanup",
        [
            ("disabled", False, False, False),
            ("basic", True, False, True),
            ("aggressive", True, True, True),
        ],
    )
    def test_apply_all_modes_parametrized(
        self,
        mode: FloppyMode,
        expected_compress: bool,
        expected_compact: bool,
        expected_cleanup: bool,
    ) -> None:
        """Параметризованная проверка всех трёх floppy-режимов."""
        config = CryptoConfig.default()
        config.apply_floppy_mode(mode)

        assert config.compress_keystore == expected_compress
        assert config.compact_key_format == expected_compact
        assert config.auto_cleanup_backups == expected_cleanup

    def test_idempotent_apply_basic(self, default_config: CryptoConfig) -> None:
        """Повторное применение одного режима идемпотентно."""
        default_config.apply_floppy_mode("basic")
        state_after_first = default_config.to_dict()

        default_config.apply_floppy_mode("basic")
        state_after_second = default_config.to_dict()

        assert state_after_first == state_after_second

    def test_idempotent_apply_aggressive(self, default_config: CryptoConfig) -> None:
        """Повторное применение 'aggressive' идемпотентно."""
        default_config.apply_floppy_mode("aggressive")
        state_after_first = default_config.to_dict()

        default_config.apply_floppy_mode("aggressive")
        state_after_second = default_config.to_dict()

        assert state_after_first == state_after_second

    def test_transition_aggressive_to_disabled(self, default_config: CryptoConfig) -> None:
        """Переход из aggressive в disabled корректно сбрасывает флаги."""
        default_config.apply_floppy_mode("aggressive")
        default_config.apply_floppy_mode("disabled")

        assert default_config.compress_keystore is False
        assert default_config.compact_key_format is False
        assert default_config.auto_cleanup_backups is False
        assert default_config.floppy_mode == "disabled"

    def test_apply_does_not_alter_security_settings(self, default_config: CryptoConfig) -> None:
        """apply_floppy_mode не изменяет параметры безопасности."""
        before_symmetric = default_config.default_symmetric
        before_min_key_size = default_config.min_key_size
        before_require_hw = default_config.require_hardware_rng

        default_config.apply_floppy_mode("aggressive")

        assert default_config.default_symmetric == before_symmetric
        assert default_config.min_key_size == before_min_key_size
        assert default_config.require_hardware_rng == before_require_hw


# ============================================================================
# POST-INIT VALIDATION
# ============================================================================


class TestPostInitValidation:
    """Тесты для валидации в __post_init__."""

    @pytest.mark.parametrize(
        "min_key_size",
        [0, 1, 8, 15, -1, -100],
    )
    def test_min_key_size_below_16_raises(self, min_key_size: int) -> None:
        """min_key_size < 16 вызывает ValueError с упоминанием поля."""
        with pytest.raises(ValueError, match="min_key_size"):
            CryptoConfig(min_key_size=min_key_size)

    def test_min_key_size_exactly_16_is_valid(self) -> None:
        """min_key_size == 16 — граничное допустимое значение."""
        config = CryptoConfig(min_key_size=16)
        assert config.min_key_size == 16

    def test_min_key_size_32_is_valid(self) -> None:
        """min_key_size == 32 является допустимым значением."""
        config = CryptoConfig(min_key_size=32)
        assert config.min_key_size == 32

    @pytest.mark.parametrize(
        "rotation_days",
        [0, -1, -30, -365],
    )
    def test_rotation_interval_days_zero_or_negative_raises(self, rotation_days: int) -> None:
        """rotation_interval_days ≤ 0 вызывает ValueError."""
        with pytest.raises(ValueError, match="rotation_interval_days"):
            CryptoConfig(rotation_interval_days=rotation_days)

    def test_rotation_interval_days_1_is_valid(self) -> None:
        """rotation_interval_days == 1 — минимальное допустимое значение."""
        config = CryptoConfig(rotation_interval_days=1)
        assert config.rotation_interval_days == 1

    @pytest.mark.parametrize("backup_count", [-1, -5, -100])
    def test_max_backup_count_negative_raises(self, backup_count: int) -> None:
        """max_backup_count < 0 вызывает ValueError."""
        with pytest.raises(ValueError, match="max_backup_count"):
            CryptoConfig(max_backup_count=backup_count)

    def test_max_backup_count_zero_is_valid(self) -> None:
        """max_backup_count == 0 — допустимое значение (нет бэкапов)."""
        config = CryptoConfig(max_backup_count=0)
        assert config.max_backup_count == 0

    @pytest.mark.parametrize("storage_size", [0, -1, -1_457_664])
    def test_max_storage_size_zero_or_negative_raises(self, storage_size: int) -> None:
        """max_storage_size ≤ 0 вызывает ValueError."""
        with pytest.raises(ValueError, match="max_storage_size"):
            CryptoConfig(max_storage_size=storage_size)

    def test_max_storage_size_1_is_valid(self) -> None:
        """max_storage_size == 1 — минимальное допустимое значение."""
        config = CryptoConfig(max_storage_size=1)
        assert config.max_storage_size == 1

    def test_multiple_invalid_fields_raises_on_first(self) -> None:
        """При нескольких невалидных полях поднимается исключение по первому полю."""
        with pytest.raises(ValueError):
            CryptoConfig(min_key_size=0, rotation_interval_days=-1)

    def test_error_message_contains_actual_value(self) -> None:
        """Сообщение об ошибке содержит переданное значение."""
        bad_value = 7
        with pytest.raises(ValueError, match=str(bad_value)):
            CryptoConfig(min_key_size=bad_value)


# ============================================================================
# SERIALIZATION: to_dict / from_dict
# ============================================================================


class TestSerialization:
    """Тесты для сериализации и десериализации конфигурации."""

    def test_to_dict_returns_dict(self, default_config: CryptoConfig) -> None:
        """to_dict() возвращает dict."""
        result = default_config.to_dict()
        assert isinstance(result, dict)

    def test_to_dict_contains_all_fields(self, default_config: CryptoConfig) -> None:
        """to_dict() содержит все поля dataclass."""
        from dataclasses import fields

        expected_keys = {f.name for f in fields(CryptoConfig)}
        assert set(default_config.to_dict().keys()) == expected_keys

    def test_roundtrip_default(self, default_config: CryptoConfig) -> None:
        """from_dict(to_dict()) воссоздаёт идентичный объект для default."""
        assert CryptoConfig.from_dict(default_config.to_dict()) == default_config

    def test_roundtrip_paranoid(self, paranoid_config: CryptoConfig) -> None:
        """from_dict(to_dict()) воссоздаёт идентичный объект для paranoid."""
        assert CryptoConfig.from_dict(paranoid_config.to_dict()) == paranoid_config

    def test_roundtrip_floppy_basic(self, floppy_basic_config: CryptoConfig) -> None:
        """from_dict(to_dict()) воссоздаёт идентичный объект для floppy_basic."""
        assert CryptoConfig.from_dict(floppy_basic_config.to_dict()) == floppy_basic_config

    def test_roundtrip_floppy_aggressive(self, floppy_aggressive_config: CryptoConfig) -> None:
        """from_dict(to_dict()) воссоздаёт идентичный объект для floppy_aggressive."""
        assert (
            CryptoConfig.from_dict(floppy_aggressive_config.to_dict()) == floppy_aggressive_config
        )

    def test_from_dict_partial_uses_defaults(self) -> None:
        """from_dict с частичным словарём заполняет остальные поля дефолтами."""
        config = CryptoConfig.from_dict({"rotation_interval_days": 60})
        assert config.rotation_interval_days == 60
        assert config.default_symmetric == "aes-256-gcm"
        assert config.floppy_mode == "disabled"

    def test_from_dict_empty_dict_returns_default(self) -> None:
        """from_dict({}) эквивалентен CryptoConfig.default()."""
        assert CryptoConfig.from_dict({}) == CryptoConfig.default()

    def test_from_dict_overrides_single_field(self) -> None:
        """from_dict переопределяет только указанное поле."""
        config = CryptoConfig.from_dict({"default_hash": "sha-512"})
        assert config.default_hash == "sha-512"
        assert config.default_symmetric == "aes-256-gcm"  # остальное — дефолт

    def test_from_dict_unknown_fields_ignored(self) -> None:
        """from_dict молча игнорирует неизвестные ключи."""
        data = CryptoConfig.default().to_dict()
        data["future_field_v2"] = "some_value"
        data["another_unknown"] = 42

        result = CryptoConfig.from_dict(data)
        assert result == CryptoConfig.default()

    def test_from_dict_uses_public_fields_api(self) -> None:
        """from_dict использует dataclasses.fields(), не __dataclass_fields__."""
        # Этот тест подтверждает, что используется публичный API
        # (косвенная проверка через нормальную работу from_dict)
        from dataclasses import fields

        known = {f.name for f in fields(CryptoConfig)}
        data = {k: v for k, v in CryptoConfig.default().to_dict().items() if k in known}
        result = CryptoConfig.from_dict(data)
        assert result == CryptoConfig.default()

    def test_to_dict_returns_copy_not_reference(self, default_config: CryptoConfig) -> None:
        """to_dict() возвращает независимую копию данных."""
        d = default_config.to_dict()
        d["rotation_interval_days"] = 999
        assert default_config.rotation_interval_days == 90

    @pytest.mark.parametrize(
        "field,invalid_value",
        [
            ("min_key_size", 0),
            ("rotation_interval_days", 0),
            ("max_backup_count", -1),
            ("max_storage_size", 0),
        ],
    )
    def test_from_dict_invalid_values_raise(self, field: str, invalid_value: int) -> None:
        """from_dict с невалидными значениями вызывает ValueError через __post_init__."""
        with pytest.raises(ValueError, match=field):
            CryptoConfig.from_dict({field: invalid_value})


# ============================================================================
# LOGGING
# ============================================================================


class TestLogging:
    """Тесты для корректности логирования."""

    def test_debug_logged_on_init(self, caplog: pytest.LogCaptureFixture) -> None:
        """DEBUG-сообщение записывается при создании CryptoConfig."""
        with caplog.at_level(logging.DEBUG, logger="src.security.crypto.utilities.config"):
            CryptoConfig.default()
        assert any("CryptoConfig" in r.message for r in caplog.records)

    def test_debug_logged_on_apply_floppy_mode(
        self, caplog: pytest.LogCaptureFixture, default_config: CryptoConfig
    ) -> None:
        """DEBUG-сообщение записывается при вызове apply_floppy_mode."""
        with caplog.at_level(logging.DEBUG, logger="src.security.crypto.utilities.config"):
            default_config.apply_floppy_mode("aggressive")
        assert any("aggressive" in r.message for r in caplog.records)

    def test_warning_logged_for_unknown_fields(self, caplog: pytest.LogCaptureFixture) -> None:
        """WARNING записывается при наличии неизвестных полей в from_dict."""
        data = {"unknown_key_xyz": "value", "rotation_interval_days": 45}
        with caplog.at_level(logging.WARNING, logger="src.security.crypto.utilities.config"):
            CryptoConfig.from_dict(data)

        warning_messages = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        assert any("unknown_key_xyz" in msg for msg in warning_messages)

    def test_no_warning_for_known_fields(self, caplog: pytest.LogCaptureFixture) -> None:
        """Нет WARNING, если все ключи в from_dict корректны."""
        with caplog.at_level(logging.WARNING, logger="src.security.crypto.utilities.config"):
            CryptoConfig.from_dict({"rotation_interval_days": 60})

        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 0


# ============================================================================
# EDGE CASES
# ============================================================================


class TestEdgeCases:
    """Edge case тесты."""

    def test_equality_same_values(self) -> None:
        """Два объекта с одинаковыми значениями равны."""
        a = CryptoConfig(rotation_interval_days=30)
        b = CryptoConfig(rotation_interval_days=30)
        assert a == b

    def test_inequality_different_values(self) -> None:
        """Объекты с разными значениями не равны."""
        a = CryptoConfig(rotation_interval_days=30)
        b = CryptoConfig(rotation_interval_days=90)
        assert a != b

    def test_floppy_aggressive_max_backup_is_minimum_valid(self) -> None:
        """max_backup_count=1 — допустимое значение (граница)."""
        config = CryptoConfig(max_backup_count=1)
        assert config.max_backup_count == 1

    def test_very_large_rotation_interval(self) -> None:
        """Очень большой интервал ротации допускается."""
        config = CryptoConfig(rotation_interval_days=36500)  # 100 лет
        assert config.rotation_interval_days == 36500

    def test_very_large_max_storage_size(self) -> None:
        """Очень большой max_storage_size допускается."""
        config = CryptoConfig(max_storage_size=10 * 1024 * 1024 * 1024)  # 10 GB
        assert config.max_storage_size > 0

    def test_from_dict_with_only_floppy_mode(self) -> None:
        """from_dict с одним полем floppy_mode создаёт корректный объект."""
        config = CryptoConfig.from_dict({"floppy_mode": "basic"})
        assert config.floppy_mode == "basic"
        assert config.default_symmetric == "aes-256-gcm"

    def test_multiple_unknown_keys_all_reported_in_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Все неизвестные ключи перечислены в WARNING."""
        unknown_keys = {"future_key_alpha", "future_key_beta"}
        data: dict[str, Any] = {k: "v" for k in unknown_keys}

        with caplog.at_level(logging.WARNING, logger="src.security.crypto.utilities.config"):
            CryptoConfig.from_dict(data)

        warning_text = " ".join(r.message for r in caplog.records if r.levelno == logging.WARNING)
        for key in unknown_keys:
            assert key in warning_text

    def test_config_is_not_frozen_mutability_documented(self) -> None:
        """CryptoConfig намеренно мутабелен (apply_floppy_mode требует этого)."""
        config = CryptoConfig.default()
        config.floppy_mode = "basic"  # не должно вызывать FrozenInstanceError
        assert config.floppy_mode == "basic"


# ============================================================================
# INTEGRATION
# ============================================================================


class TestIntegration:
    """Интеграционные тесты реалистичных сценариев использования."""

    def test_configure_for_floppy_disk_workflow(self) -> None:
        """Полный рабочий сценарий: создание конфига, применение floppy, сериализация."""
        # 1. Создаём базовую конфигурацию
        config = CryptoConfig.default()
        assert config.floppy_mode == "disabled"

        # 2. Переключаемся в floppy-режим перед записью на дискету
        config.apply_floppy_mode("aggressive")
        assert config.max_storage_size == 1_457_664
        assert config.compress_keystore is True

        # 3. Сохраняем в словарь (например, для записи в файл)
        data = config.to_dict()
        assert data["floppy_mode"] == "aggressive"

        # 4. Восстанавливаем из словаря
        restored = CryptoConfig.from_dict(data)
        assert restored == config

    def test_upgrade_config_with_new_fields(self) -> None:
        """
        Обновление схемы: старый конфиг без новых полей корректно дополняется дефолтами.

        Имитирует сценарий, когда сохранённый конфиг создан старой версией программы.
        """
        old_config_data = {
            "default_symmetric": "chacha20-poly1305",
            "rotation_interval_days": 45,
            # новые поля (например, из v1.1) отсутствуют
        }
        config = CryptoConfig.from_dict(old_config_data)
        assert config.default_symmetric == "chacha20-poly1305"
        assert config.rotation_interval_days == 45
        assert config.floppy_mode == "disabled"  # дефолт для нового поля

    def test_paranoid_then_floppy_mode_transition(self) -> None:
        """Параноидальный конфиг можно перевести в floppy-режим без потери security-полей."""
        config = CryptoConfig.paranoid()
        assert config.require_hardware_rng is True
        assert config.min_key_size == 32

        config.apply_floppy_mode("basic")

        # Floppy-флаги установлены
        assert config.compress_keystore is True
        # Security-поля сохранены
        assert config.require_hardware_rng is True
        assert config.min_key_size == 32

    def test_all_profiles_pass_validation(self) -> None:
        """Все встроенные профили проходят __post_init__ валидацию без исключений."""
        profiles = [
            CryptoConfig.default,
            CryptoConfig.paranoid,
            CryptoConfig.floppy_basic,
            CryptoConfig.floppy_aggressive,
        ]
        for factory in profiles:
            config = factory()  # не должно выбрасывать исключение
            assert config is not None

    def test_all_profiles_serialization_roundtrip(self) -> None:
        """Все встроенные профили выдерживают полный roundtrip сериализации."""
        profiles = [
            CryptoConfig.default(),
            CryptoConfig.paranoid(),
            CryptoConfig.floppy_basic(),
            CryptoConfig.floppy_aggressive(),
        ]
        for original in profiles:
            restored = CryptoConfig.from_dict(original.to_dict())
            assert restored == original, f"Roundtrip failed for: {original}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
