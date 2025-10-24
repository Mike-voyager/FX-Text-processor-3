# -*- coding: utf-8 -*-
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import pytest

from security.crypto import utils as U


def test_generate_random_bytes_basic_and_bounds() -> None:
    out = U.generate_random_bytes(32)
    assert isinstance(out, bytes) and len(out) == 32
    out2 = U.generate_random_bytes(32)
    assert out != out2
    with pytest.raises(ValueError):
        U.generate_random_bytes(0)
    with pytest.raises(ValueError):
        U.generate_random_bytes(11 * 1024 * 1024)


def test_generate_random_bytes_entropy_large_sample() -> None:
    out = U.generate_random_bytes(256)
    assert isinstance(out, bytes) and len(out) == 256


def test_generate_salt_and_range() -> None:
    s = U.generate_salt(16)
    assert isinstance(s, bytes) and len(s) == 16
    s2 = U.generate_salt(16)
    assert s != s2
    for bad in (0, 4, 65, -1):
        with pytest.raises(ValueError):
            U.generate_salt(bad)


def test_zero_memory_wipes_bytearray() -> None:
    buf = bytearray(b"supersecret")
    U.zero_memory(buf)
    assert all(b == 0 for b in buf)
    buf2: Optional[bytearray] = None
    U.zero_memory(buf2)


def test_secure_compare_semantics() -> None:
    assert U.secure_compare(b"a", b"a") is True
    assert U.secure_compare(b"a", b"b") is False
    assert U.secure_compare(b"abc", b"ab") is False


def test_codecs_roundtrip_b64_and_hex() -> None:
    data = os.urandom(32)
    b64 = U.b64_encode(data)
    back = U.b64_decode(b64)
    assert back == data
    hx = U.hex_encode(data)
    back2 = U.hex_decode(hx)
    assert back2 == data


def test_validations_raise() -> None:
    with pytest.raises(ValueError):
        U.validate_key_length(b"a" * 16, 32)
    with pytest.raises(ValueError):
        U.validate_nonce_length(b"\x00" * 8, 12)
    with pytest.raises(ValueError):
        U.validate_non_empty(b"", "payload")


def test_set_secure_file_permissions_is_best_effort(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fp = tmp_path / "secret.bin"
    fp.write_bytes(b"x")

    calls: dict[str, int] = {"n": 0}

    def fake_chmod(path: str, mode: int) -> None:
        calls["n"] += 1
        raise PermissionError("denied")

    import os as _os

    monkeypatch.setattr(_os, "chmod", fake_chmod, raising=True)
    U.set_secure_file_permissions(str(fp))
    assert calls["n"] == 1


def test_entropy_warning_branch(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Форсируем низкую «оценку» энтропии, чтобы попасть в ветку warning
    monkeypatch.setattr(U, "_shannon_entropy", lambda data: 6.50, raising=True)
    caplog.clear()
    out = U.generate_random_bytes(256)
    assert isinstance(out, bytes) and len(out) == 256
    assert any("Entropy check low" in rec.getMessage() for rec in caplog.records)


def test_rng_rct_degenerate_all_equal() -> None:
    with pytest.raises(ValueError):
        U._rct_apt_checks(b"\x00" * 64)  # приватная, но доступная в тестах


def test_rng_apt_dominance_over_threshold() -> None:
    # 85% одного байта, 15% другого — должно триггернуть APT-порог 0.80
    data = b"\xaa" * 85 + b"\xbb" * 15
    with pytest.raises(ValueError):
        U._rct_apt_checks(data)


def test_zero_memory_swallows_write_errors() -> None:
    # Неправильный тип (bytes) вызовет TypeError при buf[i] = 0, который должен проглотиться
    U.zero_memory(b"immutable")  # type: ignore[arg-type]


def test_set_secure_file_permissions_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fp = tmp_path / "ok.bin"
    fp.write_bytes(b"x")
    calls: dict[str, int] = {"n": 0}

    def ok_chmod(path: str, mode: int) -> None:
        calls["n"] += 1
        return

    import os as _os

    monkeypatch.setattr(_os, "chmod", ok_chmod, raising=True)
    U.set_secure_file_permissions(str(fp))
    assert calls["n"] == 1


def test_validate_success_paths() -> None:
    U.validate_key_length(b"a" * 32, 32)
    U.validate_nonce_length(b"\x00" * 12, 12)
    U.validate_non_empty(b"x", "payload")


def test_rng_apt_threshold_not_triggered_on_exact_boundary() -> None:
    # Ровно 80% одного байта, 20% другого — не должно падать
    data = b"\xaa" * 80 + b"\xbb" * 20
    # len(data) = 100 >= 32, но max_prop == 0.80, порог строгий '>'
    U._rct_apt_checks(data)


def test_rng_apt_small_sample_skips_check() -> None:
    # len(data) < _SMALL_APT_MIN_N -> ветка APT пропускается,
    # но не используем вырожденную последовательность.
    data = b"\xaa" * 30 + b"\xbb"  # длина 31, два значения
    # Не должно бросать (проваливаемся через первые два санити-чека и минуем APT-ветку)
    U._rct_apt_checks(data)
