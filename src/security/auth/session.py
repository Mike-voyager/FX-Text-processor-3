# -*- coding: utf-8 -*-
"""
RU: Менеджер сессий аутентификации для локального приложения: выпуск access/refresh токенов,
их ротация, контроль TTL, привязка к устройству/IP, idle timeout, свежесть MFA (MFA-freshness),
ограничение числа одновременных сессий на пользователя, отзыв и сборка мусора. Хранение состояния — только в памяти
(после перезапуска требуется повторный вход), потокобезопасность через RLock, DI‑дружественный интерфейс хранилища.

EN: Authentication session manager for a local product. Issues access/refresh tokens, rotates refresh on use,
enforces TTLs, optional device/IP binding, idle timeout, MFA freshness window, per-user session limit, revocation,
and garbage collection. In-memory only (no persistence across restarts), thread-safe via instance-level RLock,
and designed for DI with a pluggable storage protocol.

Notes:
- This module does not verify passwords or second factors; use password and MFA services for that.
- Sessions only encapsulate lifecycle/policy and the MFA-satisfied flag with optional freshness checks.

Examples:
    >>> from security.auth.session import SessionManager
    >>> mgr = SessionManager(allow_remember=False, idle_timeout_seconds=30*60, mfa_freshness_seconds=15*60)
    >>> bundle = mgr.issue("alice", scopes=frozenset({"read"}), mfa_required=True, device_fingerprint="dev1", ip="127.0.0.1")
    >>> v = mgr.validate_access(bundle.access_token, device_fingerprint="dev1", ip="127.0.0.1")
    >>> (v.valid, v.mfa_ok)
    (True, False)
    >>> mgr.mark_mfa_satisfied(v.session_id)
    >>> mgr.require_mfa(v.session_id)  # no exception, fresh by default
    >>> new = mgr.refresh(bundle.refresh_token, device_fingerprint="dev1", ip="127.0.0.1")
    >>> mgr.revoke_all_user_sessions("alice")

"""

from __future__ import annotations

import ipaddress
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from hashlib import blake2b
from typing import (
    Callable,
    Dict,
    Final,
    FrozenSet,
    Mapping,
    Optional,
    Protocol,
    Set,
    Tuple,
)

__all__ = [
    "SessionManager",
    "SessionStorageProtocol",
    "TokenBundle",
    "ValidationResult",
    "SessionError",
    "InvalidToken",
    "TokenExpired",
    "TokenRevoked",
    "DeviceMismatch",
    "DEFAULT_ACCESS_TTL_SECONDS",
    "DEFAULT_REFRESH_TTL_SECONDS",
    "REMEMBER_REFRESH_TTL_SECONDS",
    "DEFAULT_IDLE_TIMEOUT_SECONDS",
]

LOG = logging.getLogger("security.auth.session")


# -------------------- Constants/Defaults --------------------

DEFAULT_ACCESS_TTL_SECONDS: Final[int] = 15 * 60  # 15 minutes
DEFAULT_REFRESH_TTL_SECONDS: Final[int] = 30 * 24 * 60 * 60  # 30 days
REMEMBER_REFRESH_TTL_SECONDS: Final[int] = (
    60 * 24 * 60 * 60
)  # 60 days (can be disabled via allow_remember=False)
DEFAULT_IDLE_TIMEOUT_SECONDS: Final[int] = (
    30 * 60
)  # 30 minutes idle timeout (independent of access TTL)
DEFAULT_MFA_FRESHNESS_SECONDS: Final[int] = 15 * 60  # 15 minutes
DEFAULT_MAX_SESSIONS_PER_USER: Final[int] = 10  # hard ceiling to reduce attack surface

TOKEN_BYTES: Final[int] = 32  # 256-bit entropy for tokens (url-safe)
BLAKE2B_DIGEST: Final[int] = 32  # 256-bit digest for token hash


# -------------------- Exceptions --------------------


class SessionError(Exception):
    """Base exception for session manager errors."""


class InvalidToken(SessionError):
    """Raised when a token/session id is unknown or malformed."""


class TokenExpired(SessionError):
    """Raised when access or refresh token is expired (includes idle timeout)."""


class TokenRevoked(SessionError):
    """Raised when a session was revoked and tokens should not be accepted."""


class DeviceMismatch(SessionError):
    """Raised when provided device/IP does not match session binding policy."""


# -------------------- Utilities --------------------


def _now() -> int:
    """Return current Unix time in seconds as int."""
    return int(time.time())


def _hash_str(value: str) -> str:
    """Hash a string with BLAKE2b-256 and return hex digest."""
    h = blake2b(digest_size=BLAKE2B_DIGEST)
    h.update(value.encode("utf-8"))
    return h.hexdigest()


def _hash_token(token: str) -> str:
    """Hash a token string; never log or store the raw token."""
    return _hash_str(token)


def _normalize_device_fp(fp: Optional[str]) -> Optional[str]:
    """Normalize and hash device fingerprint to avoid storing raw identifiers."""
    if fp is None:
        return None
    s = fp.strip()
    if not s:
        return None
    return _hash_str(s)


def _normalize_ip(ip: Optional[str]) -> Optional[str]:
    """Normalize textual IP (handles IPv4-mapped IPv6) or return None if missing."""
    if ip is None:
        return None
    s = ip.strip()
    if not s:
        return None
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        # If IP cannot be parsed, treat as provided literal to enforce exact match.
        return s


# -------------------- Types & Protocols --------------------


class SessionStorageProtocol(Protocol):
    """Protocol for server-side session storage and token indexes (process-bound, no I/O)."""

    def get(self, session_id: str) -> Optional["SessionRecord"]: ...

    def put(self, record: "SessionRecord") -> None: ...

    def delete(self, session_id: str) -> None: ...

    def list_by_user(self, user_id: str) -> Tuple[str, ...]: ...

    def index_access_add(self, token_hash: str, session_id: str) -> None: ...

    def index_access_remove(self, token_hash: str) -> None: ...

    def index_access_get(self, token_hash: str) -> Optional[str]: ...

    def index_refresh_add(self, token_hash: str, session_id: str) -> None: ...

    def index_refresh_pop(self, token_hash: str) -> Optional[str]: ...

    def index_refresh_get(self, token_hash: str) -> Optional[str]: ...

    def iter_ids(self) -> Tuple[str, ...]: ...


@dataclass(frozen=True, slots=True)
class TokenBundle:
    """Issued tokens and expiration timestamps.

    Attributes:
        session_id: Stable session identifier.
        user_id: Subject identity.
        access_token: Short-lived bearer token.
        refresh_token: Long-lived token; rotated on use.
        access_expires_at: Epoch seconds for access token expiry.
        refresh_expires_at: Epoch seconds for refresh token expiry.
    """

    session_id: str
    user_id: str
    access_token: str
    refresh_token: str
    access_expires_at: int
    refresh_expires_at: int


@dataclass(frozen=True, slots=True)
class ValidationResult:
    """Access token validation result."""

    valid: bool
    user_id: str
    session_id: str
    scopes: FrozenSet[str]
    mfa_ok: bool
    mfa_required: bool
    expires_at: int
    reason: Optional[str]


@dataclass(slots=True)
class SessionRecord:
    """Internal session state stored server-side."""

    session_id: str
    user_id: str
    scopes: FrozenSet[str]
    created_at: int
    last_access_at: int
    access_ttl: int
    refresh_ttl: int
    access_expires_at: int
    refresh_expires_at: int
    mfa_required: bool
    mfa_satisfied: bool
    mfa_last_verified_at: Optional[int]
    device_fp_hash: Optional[str]
    ip: Optional[str]  # normalized textual IP if bound
    revoked: bool
    refresh_token_hash: str
    access_token_hash: str
    rotation: int = field(default=0)


# -------------------- Storage (In-Memory) --------------------


class InMemorySessionStorage(SessionStorageProtocol):
    """In-memory storage; concurrency guarded by SessionManager's lock."""

    def __init__(self) -> None:
        self._records: Dict[str, SessionRecord] = {}
        self._by_user: Dict[str, Set[str]] = {}
        self._idx_access: Dict[str, str] = {}
        self._idx_refresh: Dict[str, str] = {}

    def get(self, session_id: str) -> Optional[SessionRecord]:
        return self._records.get(session_id)

    def put(self, record: SessionRecord) -> None:
        self._records[record.session_id] = record
        self._by_user.setdefault(record.user_id, set()).add(record.session_id)

    def delete(self, session_id: str) -> None:
        rec = self._records.pop(session_id, None)
        if rec is not None:
            ids = self._by_user.get(rec.user_id)
            if ids is not None:
                ids.discard(session_id)
                if not ids:
                    self._by_user.pop(rec.user_id, None)

    def list_by_user(self, user_id: str) -> Tuple[str, ...]:
        return tuple(sorted(self._by_user.get(user_id, set())))

    def index_access_add(self, token_hash: str, session_id: str) -> None:
        self._idx_access[token_hash] = session_id

    def index_access_remove(self, token_hash: str) -> None:
        self._idx_access.pop(token_hash, None)

    def index_access_get(self, token_hash: str) -> Optional[str]:
        return self._idx_access.get(token_hash)

    def index_refresh_add(self, token_hash: str, session_id: str) -> None:
        self._idx_refresh[token_hash] = session_id

    def index_refresh_pop(self, token_hash: str) -> Optional[str]:
        return self._idx_refresh.pop(token_hash, None)

    def index_refresh_get(self, token_hash: str) -> Optional[str]:
        return self._idx_refresh.get(token_hash)

    def iter_ids(self) -> Tuple[str, ...]:
        return tuple(self._records.keys())


# -------------------- Session Manager --------------------


class SessionManager:
    """Issue and manage access/refresh tokens with device/IP binding, idle timeout and MFA freshness.

    All public methods are thread-safe via an instance-level RLock. Tokens are opaque; only BLAKE2b hashes are stored.
    """

    def __init__(
        self,
        storage: Optional[SessionStorageProtocol] = None,
        access_ttl_seconds: int = DEFAULT_ACCESS_TTL_SECONDS,
        refresh_ttl_seconds: int = DEFAULT_REFRESH_TTL_SECONDS,
        idle_timeout_seconds: int = DEFAULT_IDLE_TIMEOUT_SECONDS,
        mfa_freshness_seconds: int = DEFAULT_MFA_FRESHNESS_SECONDS,
        max_sessions_per_user: int = DEFAULT_MAX_SESSIONS_PER_USER,
        allow_remember: bool = False,
        clock: Callable[[], int] = _now,
    ) -> None:
        """Initialize session manager.

        Args:
            storage: Storage implementation; defaults to in-memory.
            access_ttl_seconds: Access token TTL.
            refresh_ttl_seconds: Refresh token TTL (base; sliding on each refresh).
            idle_timeout_seconds: Max inactivity before session considered expired.
            mfa_freshness_seconds: Required freshness for sensitive operations.
            max_sessions_per_user: Maximum simultaneous sessions per user.
            allow_remember: If False, ignore 'remember' flag on issue.
            clock: Time source for testing.
        """
        self._storage: SessionStorageProtocol = storage or InMemorySessionStorage()
        self._access_ttl: Final[int] = int(access_ttl_seconds)
        self._refresh_ttl_default: Final[int] = int(refresh_ttl_seconds)
        self._idle_timeout: Final[int] = int(idle_timeout_seconds)
        self._mfa_fresh_default: Final[int] = int(mfa_freshness_seconds)
        self._max_sessions: Final[int] = int(max_sessions_per_user)
        self._allow_remember: Final[bool] = bool(allow_remember)
        self._clock: Callable[[], int] = clock
        self._lock = threading.RLock()

    # ---------- Core API ----------

    def issue(
        self,
        user_id: str,
        scopes: FrozenSet[str] = frozenset(),
        mfa_required: bool = False,
        device_fingerprint: Optional[str] = None,
        ip: Optional[str] = None,
        remember: bool = False,
    ) -> TokenBundle:
        """Issue new session with access/refresh tokens."""
        if not isinstance(user_id, str) or not user_id.strip():
            raise ValueError("user_id must be a non-empty string.")
        now = self._clock()
        with self._lock:
            # Enforce per-user session limit (LRU eviction by last_access_at).
            self._enforce_user_session_limit(user_id)

            session_id = secrets.token_urlsafe(18)
            access_token = secrets.token_urlsafe(TOKEN_BYTES)
            refresh_token = secrets.token_urlsafe(TOKEN_BYTES)

            access_hash = _hash_token(access_token)
            refresh_hash = _hash_token(refresh_token)
            device_hash = _normalize_device_fp(device_fingerprint)
            norm_ip = _normalize_ip(ip)

            chosen_refresh_ttl = (
                REMEMBER_REFRESH_TTL_SECONDS
                if (remember and self._allow_remember)
                else self._refresh_ttl_default
            )

            rec = SessionRecord(
                session_id=session_id,
                user_id=user_id,
                scopes=frozenset(scopes),
                created_at=now,
                last_access_at=now,
                access_ttl=self._access_ttl,
                refresh_ttl=chosen_refresh_ttl,
                access_expires_at=now + self._access_ttl,
                refresh_expires_at=now + chosen_refresh_ttl,
                mfa_required=bool(mfa_required),
                mfa_satisfied=(not mfa_required),
                mfa_last_verified_at=(now if not mfa_required else None),
                device_fp_hash=device_hash,
                ip=norm_ip,
                revoked=False,
                refresh_token_hash=refresh_hash,
                access_token_hash=access_hash,
                rotation=0,
            )

            self._storage.put(rec)
            self._storage.index_access_add(access_hash, session_id)
            self._storage.index_refresh_add(refresh_hash, session_id)
            LOG.info("Session issued user=%s sid=%s", user_id, session_id)

            return TokenBundle(
                session_id=session_id,
                user_id=user_id,
                access_token=access_token,
                refresh_token=refresh_token,
                access_expires_at=rec.access_expires_at,
                refresh_expires_at=rec.refresh_expires_at,
            )

    def validate_access(
        self,
        token: str,
        device_fingerprint: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> ValidationResult:
        """Validate access token and enforce binding and idle timeout."""
        now = self._clock()
        th = _hash_token(token)
        with self._lock:
            sid = self._storage.index_access_get(th)
            if not sid:
                raise InvalidToken("Unknown access token.")
            rec = self._require_record(sid)
            self._enforce_not_revoked(rec)
            self._enforce_access_not_expired(rec, now)
            self._enforce_idle(rec, now)
            self._enforce_bindings(rec, device_fingerprint, ip)

            # Touch last access (no sliding access TTL).
            rec.last_access_at = now

            return ValidationResult(
                valid=True,
                user_id=rec.user_id,
                session_id=rec.session_id,
                scopes=rec.scopes,
                mfa_ok=rec.mfa_satisfied,
                mfa_required=rec.mfa_required,
                expires_at=rec.access_expires_at,
                reason=None,
            )

    def refresh(
        self,
        refresh_token: str,
        device_fingerprint: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> TokenBundle:
        """Rotate refresh token and issue new access token (single-use refresh)."""
        now = self._clock()
        rh = _hash_token(refresh_token)
        with self._lock:
            sid = self._storage.index_refresh_pop(
                rh
            )  # pop => single-use rotation regardless of outcome
            if not sid:
                raise InvalidToken("Unknown or already used refresh token.")
            rec = self._require_record(sid)
            self._enforce_not_revoked(rec)
            self._enforce_refresh_not_expired(rec, now)
            self._enforce_idle(rec, now)
            self._enforce_bindings(rec, device_fingerprint, ip)

            # Generate new tokens and re-index
            new_access = secrets.token_urlsafe(TOKEN_BYTES)
            new_refresh = secrets.token_urlsafe(TOKEN_BYTES)
            new_access_h = _hash_token(new_access)
            new_refresh_h = _hash_token(new_refresh)

            rec.access_expires_at = now + rec.access_ttl
            # Sliding window: extend refresh to base ttl from 'now'
            rec.refresh_expires_at = now + rec.refresh_ttl
            rec.access_token_hash = new_access_h
            rec.refresh_token_hash = new_refresh_h
            rec.rotation += 1
            rec.last_access_at = now

            self._storage.index_access_add(new_access_h, sid)
            self._storage.index_refresh_add(new_refresh_h, sid)

            LOG.info("Session refreshed sid=%s rotation=%d", sid, rec.rotation)

            return TokenBundle(
                session_id=sid,
                user_id=rec.user_id,
                access_token=new_access,
                refresh_token=new_refresh,
                access_expires_at=rec.access_expires_at,
                refresh_expires_at=rec.refresh_expires_at,
            )

    def revoke_by_session_id(self, session_id: str) -> bool:
        """Revoke session and drop token indexes; idempotent."""
        with self._lock:
            rec = self._storage.get(session_id)
            if rec is None:
                return False
            if not rec.revoked:
                rec.revoked = True
                self._storage.index_access_remove(rec.access_token_hash)
                self._storage.index_refresh_pop(rec.refresh_token_hash)
                LOG.warning(
                    "Session revoked sid=%s user=%s", rec.session_id, rec.user_id
                )
            return True

    def revoke_all_user_sessions(self, user_id: str) -> int:
        """Revoke all sessions for a user and drop indexes."""
        n = 0
        with self._lock:
            for sid in tuple(self._storage.list_by_user(user_id)):
                if self.revoke_by_session_id(sid):
                    n += 1
        return n

    # ---------- MFA Helpers ----------

    def mark_mfa_satisfied(self, session_id: str) -> None:
        """Mark session MFA as satisfied and record verification time (idempotent)."""
        now = self._clock()
        with self._lock:
            rec = self._require_record(session_id)
            if not rec.mfa_satisfied:
                rec.mfa_satisfied = True
                rec.mfa_last_verified_at = now
                LOG.info("MFA satisfied sid=%s user=%s", rec.session_id, rec.user_id)

    def require_mfa(
        self, session_id: str, freshness_seconds: Optional[int] = None
    ) -> None:
        """Ensure session has MFA satisfied and fresh within the given window; raise on violation."""
        now = self._clock()
        window = (
            self._mfa_fresh_default
            if freshness_seconds is None
            else int(freshness_seconds)
        )
        with self._lock:
            rec = self._require_record(session_id)
            self._enforce_not_revoked(rec)
            if not rec.mfa_required:
                return
            if not rec.mfa_satisfied:
                raise PermissionError("MFA not satisfied for this session.")
            if (
                rec.mfa_last_verified_at is None
                or (now - rec.mfa_last_verified_at) > window
            ):
                raise PermissionError("MFA freshness window exceeded.")

    # ---------- Scopes Management ----------

    def update_scopes(
        self,
        session_id: str,
        new_scopes: FrozenSet[str],
        require_fresh_mfa: bool = True,
        freshness_seconds: Optional[int] = None,
    ) -> None:
        """Update session scopes. Scope elevation optionally requires fresh MFA; narrowing is always allowed."""
        if not isinstance(new_scopes, frozenset):
            raise ValueError("new_scopes must be a frozenset[str].")
        now = self._clock()
        with self._lock:
            rec = self._require_record(session_id)
            self._enforce_not_revoked(rec)
            self._enforce_refresh_not_expired(rec, now)
            # Determine elevation vs narrowing
            is_elevation = not rec.scopes.issuperset(new_scopes)
            if is_elevation and require_fresh_mfa and rec.mfa_required:
                window = (
                    self._mfa_fresh_default
                    if freshness_seconds is None
                    else int(freshness_seconds)
                )
                if (
                    (not rec.mfa_satisfied)
                    or (rec.mfa_last_verified_at is None)
                    or (now - rec.mfa_last_verified_at > window)
                ):
                    raise PermissionError("Scope elevation requires fresh MFA.")
            rec.scopes = frozenset(new_scopes)  # type: ignore[misc]
            LOG.info(
                "Session scopes updated sid=%s elevation=%s",
                rec.session_id,
                is_elevation,
            )

    # ---------- Diagnostics/Maintenance ----------

    def get_snapshot(self, session_id: str) -> Mapping[str, object]:
        """Return a diagnostic snapshot of session state."""
        with self._lock:
            rec = self._require_record(session_id)
            return {
                "session_id": rec.session_id,
                "user_id": rec.user_id,
                "scopes": tuple(sorted(rec.scopes)),
                "created_at": rec.created_at,
                "last_access_at": rec.last_access_at,
                "access_expires_at": rec.access_expires_at,
                "refresh_expires_at": rec.refresh_expires_at,
                "mfa_required": rec.mfa_required,
                "mfa_satisfied": rec.mfa_satisfied,
                "mfa_last_verified_at": rec.mfa_last_verified_at,
                "device_bound": rec.device_fp_hash is not None,
                "ip_bound": rec.ip is not None,
                "revoked": rec.revoked,
                "rotation": rec.rotation,
            }

    def list_active_sessions(self, user_id: str) -> Tuple[int, Tuple[str, ...]]:
        """List non-revoked, non-expired (by refresh and idle) sessions for a user."""
        now = self._clock()
        with self._lock:
            active: list[str] = []
            for sid in self._storage.list_by_user(user_id):
                rec = self._storage.get(sid)
                if rec is None:
                    continue
                if rec.revoked:
                    continue
                if now >= rec.refresh_expires_at:
                    continue
                if (now - rec.last_access_at) > self._idle_timeout:
                    continue
                active.append(sid)
            active.sort()
            return len(active), tuple(active)

    def purge_expired(self) -> int:
        """Remove sessions expired by refresh or idle, and revoked ones; drop indexes accordingly."""
        now = self._clock()
        purged = 0
        with self._lock:
            for sid in tuple(self._storage.iter_ids()):
                rec = self._storage.get(sid)
                if rec is None:
                    continue
                if (
                    rec.revoked
                    or now >= rec.refresh_expires_at
                    or (now - rec.last_access_at) > self._idle_timeout
                ):
                    self._storage.index_access_remove(rec.access_token_hash)
                    self._storage.index_refresh_pop(rec.refresh_token_hash)
                    self._storage.delete(sid)
                    purged += 1
        if purged:
            LOG.info("Purged sessions count=%d", purged)
        return purged

    # ---------- Internals ----------

    def _require_record(self, session_id: str) -> SessionRecord:
        rec = self._storage.get(session_id)
        if rec is None:
            raise InvalidToken("Unknown session id.")
        return rec

    @staticmethod
    def _enforce_not_revoked(rec: SessionRecord) -> None:
        if rec.revoked:
            raise TokenRevoked("Session revoked.")

    @staticmethod
    def _enforce_access_not_expired(rec: SessionRecord, now: int) -> None:
        if now >= rec.access_expires_at:
            raise TokenExpired("Access token expired.")

    @staticmethod
    def _enforce_refresh_not_expired(rec: SessionRecord, now: int) -> None:
        if now >= rec.refresh_expires_at:
            raise TokenExpired("Refresh token expired.")

    def _enforce_idle(self, rec: SessionRecord, now: int) -> None:
        if (now - rec.last_access_at) > self._idle_timeout:
            raise TokenExpired("Session idle timeout.")

    @staticmethod
    def _enforce_bindings(
        rec: SessionRecord,
        device_fingerprint: Optional[str],
        ip: Optional[str],
    ) -> None:
        if rec.device_fp_hash is not None:
            if _normalize_device_fp(device_fingerprint) != rec.device_fp_hash:
                raise DeviceMismatch("Device fingerprint mismatch.")
        if rec.ip is not None:
            if _normalize_ip(ip) != rec.ip:
                raise DeviceMismatch("IP mismatch or missing IP for bound session.")

    def _enforce_user_session_limit(self, user_id: str) -> None:
        """Ensure user has less than max sessions; evict least recently accessed if needed."""
        if self._max_sessions <= 0:
            return
        current_ids = list(self._storage.list_by_user(user_id))
        if len(current_ids) < self._max_sessions:
            return
        # Evict LRU until below limit - 1 (space for the new session)
        needed = (len(current_ids) - self._max_sessions) + 1
        records: list[Tuple[str, int]] = []
        for sid in current_ids:
            rec = self._storage.get(sid)
            if rec is None or rec.revoked:
                continue
            records.append((sid, rec.last_access_at))
        # Sort ascending by last_access_at
        records.sort(key=lambda x: x[1])
        to_evict = [sid for sid, _ in records[:needed]]
        for sid in to_evict:
            self.revoke_by_session_id(sid)
            LOG.info(
                "Evicted LRU session due to per-user limit sid=%s user=%s", sid, user_id
            )
