import logging
from typing import FrozenSet, Tuple

import pytest

from security.auth.session import (
    SessionManager,
    TokenBundle,
    ValidationResult,
    InvalidToken,
    TokenExpired,
    TokenRevoked,
    DeviceMismatch,
    DEFAULT_ACCESS_TTL_SECONDS,
    DEFAULT_REFRESH_TTL_SECONDS,
    DEFAULT_IDLE_TIMEOUT_SECONDS,
    REMEMBER_REFRESH_TTL_SECONDS,
    TokenExpired,
    InvalidToken,
)


class Clock:
    def __init__(self, start: int) -> None:
        self.t = start

    def now(self) -> int:
        return self.t

    def add(self, seconds: int) -> None:
        self.t += seconds


@pytest.fixture
def clock() -> Clock:
    return Clock(start=1_700_000_000)


@pytest.fixture
def mgr(clock: Clock) -> SessionManager:
    logging.getLogger("security.auth.session").setLevel(logging.DEBUG)
    # Strict local policy: no remember, short idle for tests determinism
    return SessionManager(
        clock=clock.now,
        allow_remember=False,
        idle_timeout_seconds=DEFAULT_IDLE_TIMEOUT_SECONDS,
    )


def test_issue_and_validate(mgr: SessionManager) -> None:
    b = mgr.issue(
        "alice",
        scopes=frozenset({"read"}),
        mfa_required=True,
        device_fingerprint="dev1",
        ip="127.0.0.1",
    )
    assert isinstance(b, TokenBundle)
    v = mgr.validate_access(b.access_token, device_fingerprint="dev1", ip="127.0.0.1")
    assert isinstance(v, ValidationResult)
    assert v.valid is True and v.user_id == "alice"
    assert v.mfa_ok is False and v.mfa_required is True


def test_access_expiration(mgr: SessionManager, clock: Clock) -> None:
    b = mgr.issue("u1")
    clock.add(DEFAULT_ACCESS_TTL_SECONDS + 1)
    with pytest.raises(TokenExpired):
        mgr.validate_access(b.access_token)


def test_idle_timeout_independent_of_access_ttl(clock: Clock) -> None:
    # Make access TTL very long but idle short to ensure idle triggers
    mgr = SessionManager(
        clock=clock.now, access_ttl_seconds=10_000, idle_timeout_seconds=60
    )
    b = mgr.issue("u2")
    clock.add(61)
    with pytest.raises(TokenExpired):
        mgr.validate_access(b.access_token)


def test_refresh_one_time_rotation_and_new_access(mgr: SessionManager) -> None:
    b = mgr.issue("u3", scopes=frozenset({"write"}), device_fingerprint="fp3")
    new = mgr.refresh(b.refresh_token, device_fingerprint="fp3")
    assert new.session_id == b.session_id
    # Old refresh is invalid now
    with pytest.raises(InvalidToken):
        mgr.refresh(b.refresh_token, device_fingerprint="fp3")
    # New access works
    v = mgr.validate_access(new.access_token, device_fingerprint="fp3")
    assert "write" in v.scopes


def test_refresh_expiration(mgr: SessionManager, clock: Clock) -> None:
    b = mgr.issue("u4")
    clock.add(DEFAULT_REFRESH_TTL_SECONDS + 1)
    with pytest.raises(TokenExpired):
        mgr.refresh(b.refresh_token)


def test_device_binding(mgr: SessionManager) -> None:
    b = mgr.issue("u5", device_fingerprint="fp5", ip="10.0.0.1")
    # Wrong device
    with pytest.raises(DeviceMismatch):
        mgr.validate_access(b.access_token, device_fingerprint="wrong", ip="10.0.0.1")
    # Wrong IP
    with pytest.raises(DeviceMismatch):
        mgr.validate_access(b.access_token, device_fingerprint="fp5", ip="10.0.0.2")
    # Correct
    v = mgr.validate_access(b.access_token, device_fingerprint="fp5", ip="10.0.0.1")
    assert v.valid is True


def test_revoke_by_session_and_all_user(mgr: SessionManager) -> None:
    a = mgr.issue("u6")
    b = mgr.issue("u6")
    # Revoke single
    ok = mgr.revoke_by_session_id(a.session_id)
    assert ok is True
    with pytest.raises(InvalidToken):
        mgr.validate_access(a.access_token)
    # Revoke all
    num = mgr.revoke_all_user_sessions("u6")
    assert num >= 1
    with pytest.raises(InvalidToken):
        mgr.validate_access(b.access_token)


def test_purge_expired_by_refresh_and_idle(mgr: SessionManager, clock: Clock) -> None:
    b1 = mgr.issue("u7")
    b2 = mgr.issue("u7")
    # Force idle expire
    clock.add(DEFAULT_IDLE_TIMEOUT_SECONDS + 1)
    purged = mgr.purge_expired()
    assert purged >= 2
    cnt, _ = mgr.list_active_sessions("u7")
    assert cnt == 0
    # New sessions then refresh-expire
    b3 = mgr.issue("u7")
    clock.add(DEFAULT_REFRESH_TTL_SECONDS + 1)
    purged2 = mgr.purge_expired()
    assert purged2 >= 1
    cnt2, _ = mgr.list_active_sessions("u7")
    assert cnt2 == 0


def test_mfa_satisfied_and_require_fresh(clock: Clock) -> None:
    mgr = SessionManager(clock=clock.now, mfa_freshness_seconds=120)
    b = mgr.issue("u8", mfa_required=True)
    # Not yet satisfied
    with pytest.raises(PermissionError):
        mgr.require_mfa(b.session_id)
    mgr.mark_mfa_satisfied(b.session_id)
    # Fresh within window
    mgr.require_mfa(b.session_id)
    # Expire freshness
    clock.add(121)
    with pytest.raises(PermissionError):
        mgr.require_mfa(b.session_id)


def test_update_scopes_elevation_requires_fresh_mfa(clock: Clock) -> None:
    mgr = SessionManager(clock=clock.now, mfa_freshness_seconds=60)
    b = mgr.issue("u9", scopes=frozenset({"read"}), mfa_required=True)
    # Elevation without MFA
    with pytest.raises(PermissionError):
        mgr.update_scopes(b.session_id, frozenset({"read", "write"}))
    # Satisfy MFA and elevate
    mgr.mark_mfa_satisfied(b.session_id)
    mgr.update_scopes(b.session_id, frozenset({"read", "write"}))
    # Narrowing is always allowed, even if freshness is stale
    clock.add(61)
    mgr.update_scopes(b.session_id, frozenset({"read"}))


def test_list_active_sessions_filters(mgr: SessionManager, clock: Clock) -> None:
    b1 = mgr.issue("u10")
    b2 = mgr.issue("u10")
    cnt, ids = mgr.list_active_sessions("u10")
    assert cnt == 2 and b1.session_id in ids and b2.session_id in ids
    # Idle them out
    clock.add(DEFAULT_IDLE_TIMEOUT_SECONDS + 1)
    cnt2, _ = mgr.list_active_sessions("u10")
    assert cnt2 == 0


def test_limit_sessions_per_user_eviction(clock: Clock) -> None:
    mgr = SessionManager(clock=clock.now, max_sessions_per_user=3)
    b1 = mgr.issue("u11")
    clock.add(1)
    b2 = mgr.issue("u11")
    clock.add(1)
    b3 = mgr.issue("u11")
    # Creating 4th should evict least-recently-accessed (b1)
    clock.add(1)
    b4 = mgr.issue("u11")
    # Oldest should be revoked
    with pytest.raises(InvalidToken):
        mgr.validate_access(b1.access_token)
    # New ones are valid
    mgr.validate_access(b4.access_token)


def test_validate_errors_on_unknown_and_mismatch(mgr: SessionManager) -> None:
    with pytest.raises(InvalidToken):
        mgr.validate_access("non-existent-token")
    b = mgr.issue("u12", device_fingerprint="fp12")
    with pytest.raises(DeviceMismatch):
        mgr.validate_access(b.access_token, device_fingerprint="wrong")


def test_refresh_errors_on_unknown_and_expired(
    mgr: SessionManager, clock: Clock
) -> None:
    with pytest.raises(InvalidToken):
        mgr.refresh("non-existent-refresh")
    b = mgr.issue("u13")
    clock.add(DEFAULT_REFRESH_TTL_SECONDS + 1)
    with pytest.raises(TokenExpired):
        mgr.refresh(b.refresh_token)


def test_snapshot_contains_fields(mgr: SessionManager) -> None:
    b = mgr.issue(
        "u14", scopes=frozenset({"r", "w"}), mfa_required=True, device_fingerprint="fp"
    )
    snap = mgr.get_snapshot(b.session_id)
    assert snap["session_id"] == b.session_id
    assert snap["user_id"] == "u14"
    assert snap["mfa_required"] is True
    assert snap["mfa_satisfied"] is False
    assert snap["device_bound"] is True


def test_invalid_user_id_raises(mgr: SessionManager) -> None:
    with pytest.raises(ValueError):
        mgr.issue("")



def test_issue_with_remember_respects_policy(clock: Clock) -> None:
    # allow_remember=False -> игнорируем remember и используем базовый refresh TTL
    mgr = SessionManager(clock=clock.now, allow_remember=False, refresh_ttl_seconds=7 * 24 * 3600)
    b = mgr.issue("uR", remember=True)
    assert (b.refresh_expires_at - clock.now()) == 7 * 24 * 3600

    # allow_remember=True -> применяется REMEMBER_REFRESH_TTL_SECONDS
    mgr2 = SessionManager(clock=clock.now, allow_remember=True)
    b2 = mgr2.issue("uR2", remember=True)
    assert (b2.refresh_expires_at - clock.now()) == REMEMBER_REFRESH_TTL_SECONDS


def test_require_mfa_with_custom_freshness(clock: Clock) -> None:
    mgr = SessionManager(clock=clock.now, mfa_freshness_seconds=300)  # дефолт 5 мин, но переопределим в вызове
    b = mgr.issue("uF", mfa_required=True)
    # Не удовлетворена MFA
    with pytest.raises(PermissionError):
        mgr.require_mfa(b.session_id, freshness_seconds=10)
    mgr.mark_mfa_satisfied(b.session_id)
    # Свежо при окне 10 сек
    mgr.require_mfa(b.session_id, freshness_seconds=10)
    # Просрочим свежесть
    clock.add(11)
    with pytest.raises(PermissionError):
        mgr.require_mfa(b.session_id, freshness_seconds=10)


def test_update_scopes_fails_when_refresh_expired(clock: Clock) -> None:
    mgr = SessionManager(clock=clock.now, refresh_ttl_seconds=30)
    b = mgr.issue("uS", mfa_required=False, scopes=frozenset({"read"}))
    # Истекаем refresh
    clock.add(31)
    with pytest.raises(TokenExpired):
        mgr.update_scopes(b.session_id, frozenset({"read", "write"}))


def test_list_active_sessions_mixed_states(clock: Clock) -> None:
    # idle_timeout=60s, refresh_ttl=120s
    mgr = SessionManager(clock=clock.now, idle_timeout_seconds=60, refresh_ttl_seconds=120)

    # Создаём три сессии одного пользователя
    alive = mgr.issue("uMix")
    idle = mgr.issue("uMix")
    revoked = mgr.issue("uMix")

    # Шаг 1: немного ждём, чтобы создать разрыв по last_access_at
    clock.add(30)

    # «Оживим» alive сейчас — его last_access_at станет t+30
    mgr.validate_access(alive.access_token)

    # Шаг 2: доводим до истечения idle для "idle" (ещё +31 = суммарно 61 от момента создания idle)
    clock.add(31)

    # Ревокаем третью сессию
    mgr.revoke_by_session_id(revoked.session_id)

    # Проверяем, что активна только «живая» сессия
    cnt, ids = mgr.list_active_sessions("uMix")
    assert cnt == 1
    assert alive.session_id in ids

    # Дополнительно подтвердим, что validate_access по alive проходит,
    # а по idle — падает по idle timeout
    mgr.validate_access(alive.access_token)
    with pytest.raises(TokenExpired):
        mgr.validate_access(idle.access_token)

    # Истекаем refresh и убеждаемся, что активных больше нет
    clock.add(120)
    cnt2, _ = mgr.list_active_sessions("uMix")
    assert cnt2 == 0



def test_validate_access_ip_mapping_and_literal(clock: Clock) -> None:
    mgr = SessionManager(clock=clock.now)
    # Нормализуем IPv4 и пробуем разные представления
    b = mgr.issue("uIP", ip="127.0.0.1")
    # Совпадение как строка
    mgr.validate_access(b.access_token, ip="127.0.0.1")
    # Непарсимый IP трактуется как литерал и не совпадает -> InvalidToken? Нет, здесь именно DeviceMismatch.
    with pytest.raises(Exception) as e:
        mgr.validate_access(b.access_token, ip="not-an-ip")
    assert "mismatch" in str(e.value).lower()

    # Проверим, что неизвестный токен остаётся InvalidToken, а не DeviceMismatch
    with pytest.raises(InvalidToken):
        mgr.validate_access("nope", ip="127.0.0.1")

def test_revoke_idempotent_and_noop_purge(clock: Clock) -> None:
    logging.getLogger("security.auth.session").setLevel(logging.DEBUG)
    mgr = SessionManager(clock=clock.now)
    b = mgr.issue("uR")
    # первый revoke — помечает сессию revoked и снимает индексы
    assert mgr.revoke_by_session_id(b.session_id) is True
    # повторный revoke — идемпотентен, остаётся True
    assert mgr.revoke_by_session_id(b.session_id) is True
    # purge удаляет уже revoked запись => возвращает >=1
    assert mgr.purge_expired() >= 1


def test_purge_handles_missing_record_between_iter_and_get(clock: Clock) -> None:
    mgr = SessionManager(clock=clock.now)
    b = mgr.issue("uPX")
    sid = b.session_id
    # Эмулируем «гонку»: удаляем запись напрямую из стора между итерацией и get
    # В тесте допускается прямой доступ к внутреннему in-memory стора
    mgr._storage.delete(sid)  # type: ignore[attr-defined]
    # purge не должен падать, а просто пропустить None
    assert mgr.purge_expired() >= 0


def test_ip_bound_missing_ip_raises_mismatch(clock: Clock) -> None:
    mgr = SessionManager(clock=clock.now)
    b = mgr.issue("uIP3", ip="127.0.0.1")
    # Не передаём ip — должен сработать mismatch-ветка
    with pytest.raises(Exception) as e:
        mgr.validate_access(b.access_token)
    assert "ip mismatch" in str(e.value).lower()


def test_update_scopes_elevation_without_fresh_mfa_allowed_when_flag_off(clock: Clock) -> None:
    # mfa_freshness_seconds=1, но будем повышать с require_fresh_mfa=False
    mgr = SessionManager(clock=clock.now, mfa_freshness_seconds=1)

    # Стартуем сессии с базовыми скоупами и требованием MFA
    b = mgr.issue("uSC2", scopes=frozenset({"read"}), mfa_required=True)

    # Отмечаем прохождение MFA
    mgr.mark_mfa_satisfied(b.session_id)

    # Даём свежести истечь
    clock.add(2)

    # Повышение прав без свежего MFA должно быть разрешено при require_fresh_mfa=False
    mgr.update_scopes(
        b.session_id,
        new_scopes=frozenset({"read", "write"}),
        require_fresh_mfa=False,
    )

    # Проверяем, что новые скоупы применились; снапшот возвращает итерируемое
    snap = mgr.get_snapshot(b.session_id)
    scopes: Tuple[str, ...] = tuple(snap["scopes"])  # type: ignore
    assert tuple(sorted(scopes)) == ("read", "write")


def test_issue_with_allow_remember_affects_refresh_ttl(clock: Clock) -> None:
    # allow_remember=True — применяет REMEMBER_REFRESH_TTL_SECONDS
    mgr = SessionManager(clock=clock.now, allow_remember=True)
    b = mgr.issue("uRR", remember=True)
    assert (b.refresh_expires_at - clock.now()) == REMEMBER_REFRESH_TTL_SECONDS


def test_validate_access_after_idle_but_before_refresh(clock: Clock) -> None:
    # idle короткий, refresh длинный — validate должен падать по idle
    mgr = SessionManager(clock=clock.now, idle_timeout_seconds=30, refresh_ttl_seconds=3600)
    b = mgr.issue("uIdle")
    # Превысим idle, но далеко не refresh
    clock.add(31)
    with pytest.raises(TokenExpired):
        mgr.validate_access(b.access_token)


def test_refresh_after_idle_still_checks_idle(clock: Clock) -> None:
    # refresh должен проверять idle — при неактивности тоже падать
    mgr = SessionManager(clock=clock.now, idle_timeout_seconds=30, refresh_ttl_seconds=3600)
    b = mgr.issue("uIdleRef")
    clock.add(31)
    with pytest.raises(TokenExpired):
        mgr.refresh(b.refresh_token)
