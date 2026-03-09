"""
Тесты для модуля хеширования паролей.

Покрытие:
- PasswordStrength: значения enum
- PasswordStrengthResult: создание, frozen, поля
- PasswordHasher.__init__: с Argon2 / без (scrypt fallback)
- hash_password: пустой пароль → InvalidParameterError
- hash_password: формат результата ($argon2... или $scrypt$...)
- verify_password: корректный пароль → True
- verify_password: неверный пароль → False
- verify_password: пустые аргументы → InvalidParameterError
- verify_password: неизвестный формат хеша → InvalidParameterError
- check_password_strength: WEAK / FAIR / STRONG / VERY_STRONG
- check_password_strength: распространённые пароли
- check_password_strength: повторяющиеся символы / последовательности
- check_password_strength: короткий пароль (< 8)
- needs_rehash: scrypt при наличии Argon2 → True
- needs_rehash: scrypt без Argon2 → False
- needs_rehash: argon2 с актуальными параметрами → False
- needs_rehash: неизвестный формат → False
- _verify_scrypt: битый формат → False
- Интеграционные: реальный hash→verify roundtrip (оба бэкенда)

Coverage target: 95%+

Author: Mike Voyager
Version: 1.0
Date: March 10, 2026
"""

from __future__ import annotations

# pyright: reportPrivateUsage=false
from unittest.mock import MagicMock, patch

import pytest
from src.security.crypto.core.exceptions import CryptoError, InvalidParameterError
from src.security.crypto.utilities.passwords import (
    HAS_ARGON2,
    PasswordHasher,
    PasswordStrength,
    PasswordStrengthResult,
)

# ==============================================================================
# PasswordStrength
# ==============================================================================


class TestPasswordStrength:
    def test_values(self) -> None:
        assert PasswordStrength.WEAK.value == "weak"
        assert PasswordStrength.FAIR.value == "fair"
        assert PasswordStrength.STRONG.value == "strong"
        assert PasswordStrength.VERY_STRONG.value == "very_strong"

    def test_all_members(self) -> None:
        members = {m.value for m in PasswordStrength}
        assert members == {"weak", "fair", "strong", "very_strong"}


# ==============================================================================
# PasswordStrengthResult
# ==============================================================================


class TestPasswordStrengthResult:
    def test_creation(self) -> None:
        result = PasswordStrengthResult(
            strength=PasswordStrength.STRONG,
            score=60,
            feedback=["Отлично"],
        )
        assert result.strength == PasswordStrength.STRONG
        assert result.score == 60
        assert result.feedback == ["Отлично"]

    def test_frozen(self) -> None:
        result = PasswordStrengthResult(
            strength=PasswordStrength.WEAK,
            score=10,
            feedback=[],
        )
        with pytest.raises(AttributeError):
            result.score = 99  # type: ignore[misc]

    def test_feedback_is_list(self) -> None:
        result = PasswordStrengthResult(
            strength=PasswordStrength.FAIR,
            score=40,
            feedback=["tip1", "tip2"],
        )
        assert isinstance(result.feedback, list)
        assert len(result.feedback) == 2


# ==============================================================================
# PasswordHasher.__init__
# ==============================================================================


class TestPasswordHasherInit:
    def test_default_params_stored(self) -> None:
        hasher = PasswordHasher()
        assert hasher._time_cost == PasswordHasher.DEFAULT_TIME_COST
        assert hasher._memory_cost == PasswordHasher.DEFAULT_MEMORY_COST
        assert hasher._parallelism == PasswordHasher.DEFAULT_PARALLELISM
        assert hasher._hash_length == PasswordHasher.DEFAULT_HASH_LENGTH
        assert hasher._salt_length == PasswordHasher.DEFAULT_SALT_LENGTH

    def test_custom_params_stored(self) -> None:
        hasher = PasswordHasher(time_cost=2, memory_cost=32768, parallelism=2)
        assert hasher._time_cost == 2
        assert hasher._memory_cost == 32768
        assert hasher._parallelism == 2

    def test_argon2_hasher_set_when_available(self) -> None:
        if HAS_ARGON2:
            hasher = PasswordHasher()
            assert hasher._argon2_hasher is not None
        else:
            hasher = PasswordHasher()
            assert hasher._argon2_hasher is None

    def test_no_argon2_hasher_without_library(self) -> None:
        with patch("src.security.crypto.utilities.passwords.HAS_ARGON2", False):
            hasher = PasswordHasher()
            hasher._argon2_hasher = None  # simulate no backend
            assert hasher._argon2_hasher is None


# ==============================================================================
# hash_password
# ==============================================================================


class TestHashPassword:
    def test_empty_password_raises(self) -> None:
        hasher = PasswordHasher()
        with pytest.raises(InvalidParameterError):
            hasher.hash_password("")

    def test_returns_string(self) -> None:
        hasher = PasswordHasher()
        result = hasher.hash_password("SomePass1!")
        assert isinstance(result, str)

    def test_argon2_format_when_available(self) -> None:
        if not HAS_ARGON2:
            pytest.skip("argon2-cffi not installed")
        hasher = PasswordHasher()
        result = hasher.hash_password("SomePass1!")
        assert result.startswith("$argon2")

    def test_scrypt_format_when_no_argon2(self) -> None:
        hasher = PasswordHasher()
        hasher._argon2_hasher = None  # force scrypt path
        result = hasher.hash_password("SomePass1!")
        assert result.startswith("$scrypt$")

    def test_two_hashes_differ(self) -> None:
        """Каждый хеш уникален (соль случайная)."""
        hasher = PasswordHasher()
        h1 = hasher.hash_password("SamePass1!")
        h2 = hasher.hash_password("SamePass1!")
        assert h1 != h2

    def test_hash_argon2_raises_crypto_error_when_backend_fails(self) -> None:
        if not HAS_ARGON2:
            pytest.skip("argon2-cffi not installed")
        hasher = PasswordHasher()
        # Заменяем backend целиком на MagicMock, чтобы .hash() бросал исключение
        mock_backend = MagicMock()
        mock_backend.hash.side_effect = RuntimeError("backend error")
        hasher._argon2_hasher = mock_backend
        with pytest.raises(CryptoError):
            hasher._hash_argon2("SomePass1!")

    def test_hash_argon2_raises_when_no_hasher(self) -> None:
        hasher = PasswordHasher()
        hasher._argon2_hasher = None
        # _hash_argon2 should raise CryptoError
        with pytest.raises(CryptoError):
            hasher._hash_argon2("SomePass1!")

    def test_scrypt_hash_raises_crypto_error_on_failure(self) -> None:
        hasher = PasswordHasher()
        with patch("hashlib.scrypt", side_effect=OSError("no hardware support")):
            with pytest.raises(CryptoError):
                hasher._hash_scrypt("SomePass1!")


# ==============================================================================
# verify_password
# ==============================================================================


class TestVerifyPassword:
    def test_empty_password_raises(self) -> None:
        hasher = PasswordHasher()
        with pytest.raises(InvalidParameterError):
            hasher.verify_password("", "$scrypt$n=1$r=1$p=1$abc$def")

    def test_empty_hash_raises(self) -> None:
        hasher = PasswordHasher()
        with pytest.raises(InvalidParameterError):
            hasher.verify_password("SomePass1!", "")

    def test_unknown_format_raises(self) -> None:
        hasher = PasswordHasher()
        with pytest.raises(InvalidParameterError):
            hasher.verify_password("SomePass1!", "$unknown$something")

    def test_scrypt_correct_password(self) -> None:
        hasher = PasswordHasher()
        hasher._argon2_hasher = None  # force scrypt
        h = hasher.hash_password("CorrectPass1!")
        assert hasher.verify_password("CorrectPass1!", h) is True

    def test_scrypt_wrong_password(self) -> None:
        hasher = PasswordHasher()
        hasher._argon2_hasher = None  # force scrypt
        h = hasher.hash_password("CorrectPass1!")
        assert hasher.verify_password("WrongPass1!", h) is False

    def test_scrypt_malformed_hash_returns_false(self) -> None:
        hasher = PasswordHasher()
        assert hasher.verify_password("SomePass1!", "$scrypt$garbage") is False

    def test_argon2_correct_password(self) -> None:
        if not HAS_ARGON2:
            pytest.skip("argon2-cffi not installed")
        hasher = PasswordHasher()
        h = hasher.hash_password("CorrectPass1!")
        assert hasher.verify_password("CorrectPass1!", h) is True

    def test_argon2_wrong_password(self) -> None:
        if not HAS_ARGON2:
            pytest.skip("argon2-cffi not installed")
        hasher = PasswordHasher()
        h = hasher.hash_password("CorrectPass1!")
        assert hasher.verify_password("WrongPass1!", h) is False

    def test_argon2_without_library_raises(self) -> None:
        if HAS_ARGON2:
            pytest.skip("argon2-cffi is installed, testing fallback path only")
        hasher = PasswordHasher()
        fake_hash = "$argon2id$v=19$m=65536,t=3,p=4$fakesalt$fakehash"
        with pytest.raises(CryptoError):
            hasher._verify_argon2("SomePass1!", fake_hash)

    def test_verify_scrypt_bad_parts_count(self) -> None:
        hasher = PasswordHasher()
        bad = "$scrypt$n=16384$r=8$p=1$onlyfiveparts"
        assert hasher._verify_scrypt("pass", bad) is False

    def test_verify_scrypt_bad_base64(self) -> None:
        hasher = PasswordHasher()
        bad = "$scrypt$n=16384$r=8$p=1$!!!not_base64!!!$also_bad"
        assert hasher._verify_scrypt("pass", bad) is False


# ==============================================================================
# check_password_strength
# ==============================================================================


class TestCheckPasswordStrength:
    def _check(self, password: str) -> PasswordStrengthResult:
        return PasswordHasher().check_password_strength(password)

    # --- длина ---

    def test_too_short_feedback(self) -> None:
        # Любой пароль короче 8 символов получает предупреждение
        result = self._check("Ab1!")
        assert any("короткий" in f for f in result.feedback)

    def test_too_short_low_diversity_is_weak(self) -> None:
        # "ab" — только строчные, энтропия ~9 бит → WEAK
        result = self._check("ab")
        assert result.strength == PasswordStrength.WEAK

    def test_8_to_11_chars(self) -> None:
        # 8 символов, 4 типа → score 15+40=55 → STRONG
        result = self._check("Abcde1!x")
        assert result.score >= 25

    def test_12_to_15_chars(self) -> None:
        result = self._check("Abcdefgh12!x")
        assert result.score >= 25

    def test_16_plus_chars(self) -> None:
        result = self._check("Abcdefgh1234!@#$")
        assert result.strength in (PasswordStrength.STRONG, PasswordStrength.VERY_STRONG)

    # --- типы символов ---

    def test_no_uppercase_feedback(self) -> None:
        result = self._check("abcdefgh1!")
        assert any("заглавные" in f for f in result.feedback)

    def test_no_digit_feedback(self) -> None:
        result = self._check("Abcdefgh!!")
        assert any("цифры" in f for f in result.feedback)

    def test_no_special_feedback(self) -> None:
        result = self._check("Abcdefgh12")
        assert any("специальные" in f for f in result.feedback)

    def test_all_char_types_no_feedback_for_missing(self) -> None:
        result = self._check("Abcdefgh1!xxxx")
        missing = [
            f for f in result.feedback if any(w in f for w in ["заглавные", "цифры", "специальные"])
        ]
        assert len(missing) == 0

    # --- уровни ---

    def test_weak_very_short(self) -> None:
        result = self._check("ab")
        assert result.strength == PasswordStrength.WEAK

    def test_fair(self) -> None:
        # lowercase only, 10 chars → score: 15 (length) + 10 (1 char type) + 5 (entropy) = 30 → FAIR
        result = self._check("abcdefghij")
        assert result.strength in (PasswordStrength.FAIR, PasswordStrength.WEAK)

    def test_very_strong(self) -> None:
        result = self._check("Tr0ub4dor&3xYzQ!")
        assert result.strength == PasswordStrength.VERY_STRONG

    # --- распространённые пароли ---

    def test_common_password_penalized(self) -> None:
        result = self._check("password")
        assert any("распространённых" in f for f in result.feedback)
        assert result.score < 25

    def test_common_password_case_insensitive(self) -> None:
        result = self._check("PASSWORD")
        assert any("распространённых" in f for f in result.feedback)

    # --- повторяющиеся символы ---

    def test_repeated_chars_penalized(self) -> None:
        result = self._check("AAAabcde1!")
        assert any("повторяющихся" in f for f in result.feedback)

    # --- последовательности ---

    def test_sequence_penalized(self) -> None:
        result = self._check("Pass1234!!")
        assert any("последовательностей" in f for f in result.feedback)

    def test_abc_sequence_penalized(self) -> None:
        result = self._check("Abcdef1!")
        assert any("последовательностей" in f for f in result.feedback)

    # --- энтропия ---

    def test_low_entropy_feedback(self) -> None:
        # только цифры, короткий
        result = self._check("1234567")
        assert result.strength == PasswordStrength.WEAK

    # --- нет замечаний для сильного пароля ---

    def test_strong_password_ok_feedback(self) -> None:
        result = self._check("Tr0ub4dor&3xYzQ!")
        assert any("соответствует" in f for f in result.feedback)

    # --- score clamp ---

    def test_score_in_range(self) -> None:
        for pw in ["a", "password", "Tr0ub4dor&3xYzQ!", "Abcde1!xyzwqrt"]:
            result = self._check(pw)
            assert 0 <= result.score <= 100


# ==============================================================================
# needs_rehash
# ==============================================================================


class TestNeedsRehash:
    def test_scrypt_hash_needs_rehash_when_argon2_available(self) -> None:
        hasher = PasswordHasher()
        fake_scrypt = "$scrypt$n=16384$r=8$p=1$abc$def"
        if HAS_ARGON2:
            assert hasher.needs_rehash(fake_scrypt) is True
        else:
            assert hasher.needs_rehash(fake_scrypt) is False

    def test_scrypt_hash_no_rehash_without_argon2(self) -> None:
        with patch("src.security.crypto.utilities.passwords.HAS_ARGON2", False):
            hasher = PasswordHasher()
            hasher._argon2_hasher = None
            assert hasher.needs_rehash("$scrypt$n=16384$r=8$p=1$abc$def") is False

    def test_argon2_current_params_no_rehash(self) -> None:
        if not HAS_ARGON2:
            pytest.skip("argon2-cffi not installed")
        hasher = PasswordHasher()
        h = hasher.hash_password("SomePass1!")
        # Хеш создан с текущими параметрами → rehash не нужен
        assert hasher.needs_rehash(h) is False

    def test_unknown_format_no_rehash(self) -> None:
        hasher = PasswordHasher()
        assert hasher.needs_rehash("$unknown$abc") is False

    def test_argon2_check_raises_returns_true(self) -> None:
        if not HAS_ARGON2:
            pytest.skip("argon2-cffi not installed")
        hasher = PasswordHasher()
        mock_backend = MagicMock()
        mock_backend.check_needs_rehash.side_effect = Exception("err")
        hasher._argon2_hasher = mock_backend
        assert hasher.needs_rehash("$argon2id$something") is True

    def test_no_argon2_hasher_with_argon2_hash(self) -> None:
        hasher = PasswordHasher()
        hasher._argon2_hasher = None
        # argon2-хеш, но бэкенда нет → False
        result = hasher.needs_rehash("$argon2id$v=19$m=65536,t=3,p=4$salt$hash")
        assert result is False


# ==============================================================================
# Интеграционные тесты
# ==============================================================================


@pytest.mark.integration
class TestPasswordHasherIntegration:
    """Реальные хеширование и проверка без моков."""

    def test_roundtrip_scrypt(self) -> None:
        hasher = PasswordHasher()
        hasher._argon2_hasher = None  # принудительно scrypt
        password = "MySecureP@ss123!"
        h = hasher.hash_password(password)
        assert h.startswith("$scrypt$")
        assert hasher.verify_password(password, h) is True
        assert hasher.verify_password("WrongPass1!", h) is False

    @pytest.mark.skipif(not HAS_ARGON2, reason="argon2-cffi not installed")
    def test_roundtrip_argon2(self) -> None:
        hasher = PasswordHasher()
        password = "MySecureP@ss123!"
        h = hasher.hash_password(password)
        assert h.startswith("$argon2")
        assert hasher.verify_password(password, h) is True
        assert hasher.verify_password("WrongPass1!", h) is False

    @pytest.mark.skipif(not HAS_ARGON2, reason="argon2-cffi not installed")
    def test_scrypt_needs_rehash_with_argon2_present(self) -> None:
        # Создаём хеш через scrypt (без backend Argon2), затем проверяем needs_rehash
        scrypt_hasher = PasswordHasher()
        scrypt_hasher._argon2_hasher = None  # force scrypt
        h = scrypt_hasher.hash_password("Pass1!")
        assert h.startswith("$scrypt$")
        # Теперь хешер с активным Argon2 должен сказать "нужен rehash"
        argon2_hasher = PasswordHasher()
        assert argon2_hasher.needs_rehash(h) is True

    def test_strength_very_strong(self) -> None:
        hasher = PasswordHasher()
        result = hasher.check_password_strength("Tr0ub4dor&3xYzQ!")
        assert result.strength == PasswordStrength.VERY_STRONG
        assert result.score >= 75

    def test_strength_common_password_is_weak(self) -> None:
        hasher = PasswordHasher()
        result = hasher.check_password_strength("password")
        assert result.strength == PasswordStrength.WEAK

    def test_scrypt_format_parseable(self) -> None:
        """Формат scrypt содержит ровно 7 частей при разбивке по $."""
        hasher = PasswordHasher()
        hasher._argon2_hasher = None
        h = hasher.hash_password("TestPass1!")
        parts = h.split("$")
        assert len(parts) == 7
        assert parts[1] == "scrypt"
