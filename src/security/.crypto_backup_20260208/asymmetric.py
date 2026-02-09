# -*- coding: utf-8 -*-
"""
Асимметричная криптография: Ed25519, RSA-4096, ECDSA P-256.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Callable, Dict, Final, Optional, Union

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

logger: Final = logging.getLogger(__name__)

# Type aliases for key types
PrivateKeyTypes = Union[
    ed25519.Ed25519PrivateKey,
    rsa.RSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    None,
]

PublicKeyTypes = Union[
    ed25519.Ed25519PublicKey,
    rsa.RSAPublicKey,
    ec.EllipticCurvePublicKey,
]

SUPPORTED_ALGORITHMS: Final[tuple[str, ...]] = ("ed25519", "rsa4096", "ecdsa_p256")
DEFAULT_RSA_KEYSIZE: Final[int] = 4096


_SENSITIVE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"\bpasswo?r?d\b",  # password, passwd
        r"\bpwd\b",  # pwd отдельно - не покрывается passwo?r?d
        r"\bprivate[_\s]?key\b",  # private_key, privateKey, private key
        r"\bpublic[_\s]?key\b",  # public_key, publicKey (для полноты)
        r"\bsecret\b",  # secret, SECRET
        r"\bsecret[_\s]",  # secret_token, secret_key (после secret может быть _ или пробел)
        r"\btoken\b",  # token, TOKEN
        r"\bapi[_\s]?key\b",  # api_key, apiKey, API_KEY
        r"\bauth\b",  # auth, AUTH
        r"\bauth[_\s]",  # auth_header, auth_token (после auth может быть _ или пробел)
        r"\bcredential\b",  # credential, credentials
        r"\b(priv|sec|pass)\b",  # сокращения: priv, sec, pass
        r"\bpem\b",  # PEM содержимое
        r"\bsalt\b",  # криптографическая соль
        r"\bnonce\b",  # одноразовый номер
        r"\biv\b",  # initialization vector
        r"\bcipher\b",  # шифротекст может содержать чувствительные данные
    ]
)


def _contains_sensitive_data(text: str) -> bool:
    """
    Проверка текста на наличие чувствительных данных через regex-паттерны.

    Args:
        text: Строка для проверки

    Returns:
        True если найдены чувствительные ключевые слова

    Examples:
        >>> _contains_sensitive_data("Loading privateKey")
        True
        >>> _contains_sensitive_data("Algorithm: ed25519")
        False
        >>> _contains_sensitive_data("Setting API_KEY")
        True
    """
    return any(pattern.search(text) for pattern in _SENSITIVE_PATTERNS)


def _secure_log(msg: str, *args: Any) -> None:
    """
    Безопасное логирование без утечки секретов.

    Проверяет сообщение и аргументы на наличие чувствительных ключевых слов
    через regex-паттерны. Блокирует логирование при обнаружении.

    Args:
        msg: Форматная строка сообщения
        *args: Аргументы для форматирования

    Examples:
        >>> _secure_log("Generating keypair: algorithm=%s", "ed25519")  # ✅ Логируется
        >>> _secure_log("Loaded private_key for user=%s", "admin")  # ❌ Блокируется
    """
    # Собираем полный текст сообщения для проверки
    try:
        full_text = msg % args if args else msg
    except (TypeError, ValueError):
        # Если форматирование не удалось, проверяем по частям
        full_text = msg + " ".join(str(arg) for arg in args)

    if _contains_sensitive_data(full_text):
        # Не логируем, но можем увеличить счётчик подавленных сообщений (опционально)
        return

    logger.info(msg, *args)


class UnsupportedAlgorithmError(ValueError):
    """Unsupported asymmetric algorithm."""


class KeyFormatError(ValueError):
    """Key encoding/format error."""


def _rsa_oaep_overhead(hash_alg: hashes.HashAlgorithm = hashes.SHA256()) -> int:
    h = hash_alg.digest_size
    return int(h * 2 + 2)


@dataclass(frozen=True)
class AsymmetricKeyPair:
    """
    Immutable wrapper for asymmetric key pairs.

    Example:
        >>> kp = AsymmetricKeyPair.generate("ed25519")
        >>> sig = kp.sign(b"hello")
        >>> assert kp.verify(b"hello", sig)
    """

    private_key: PrivateKeyTypes
    public_key: PublicKeyTypes
    algorithm: str

    @staticmethod
    def generate(algorithm: str, key_size: Optional[int] = None) -> "AsymmetricKeyPair":
        _secure_log("Generating keypair: algorithm=%s", algorithm)
        priv: Union[
            ed25519.Ed25519PrivateKey, rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey
        ]
        if algorithm == "ed25519":
            priv = ed25519.Ed25519PrivateKey.generate()
        elif algorithm == "rsa4096":
            ks = key_size or DEFAULT_RSA_KEYSIZE
            if ks < 2048 or ks % 256 != 0:
                raise ValueError("RSA key_size must be >= 2048 and divisible by 256")
            priv = rsa.generate_private_key(public_exponent=65537, key_size=ks)
        elif algorithm == "ecdsa_p256":
            priv = ec.generate_private_key(ec.SECP256R1())
        else:
            logger.error("Unsupported algorithm: %s", algorithm)
            raise UnsupportedAlgorithmError(f"Unsupported algorithm: {algorithm}")
        return AsymmetricKeyPair(priv, priv.public_key(), algorithm)

    @staticmethod
    def from_private_bytes(
        data: bytes, algorithm: str, password: Optional[str] = None
    ) -> "AsymmetricKeyPair":
        _secure_log(
            "Loading key: algorithm=%s [protected=%s]",
            algorithm,
            "yes" if password else "no",
        )
        if algorithm not in SUPPORTED_ALGORITHMS:
            logger.error("Unsupported algorithm: %s", algorithm)
            raise UnsupportedAlgorithmError(f"Unsupported algorithm: {algorithm}")
        pw = password.encode("utf-8") if password else None
        try:
            pk = serialization.load_pem_private_key(data, password=pw)
            if algorithm == "ed25519" and isinstance(pk, ed25519.Ed25519PrivateKey):
                return AsymmetricKeyPair(pk, pk.public_key(), algorithm)
            if algorithm == "rsa4096" and isinstance(pk, rsa.RSAPrivateKey):
                return AsymmetricKeyPair(pk, pk.public_key(), algorithm)
            if algorithm == "ecdsa_p256" and isinstance(pk, ec.EllipticCurvePrivateKey):
                return AsymmetricKeyPair(pk, pk.public_key(), algorithm)
            raise KeyFormatError("PEM does not match declared algorithm")
        except (ValueError, TypeError, UnsupportedAlgorithm) as e:
            logger.error(
                "Key import failed: %s [details suppressed for security]",
                type(e).__name__,
            )
            raise KeyFormatError(
                "Failed to import private key [details suppressed]"
            ) from e

    @staticmethod
    def from_public_bytes(data: bytes, algorithm: str) -> "AsymmetricKeyPair":
        _secure_log("Loading public-only key: algorithm=%s", algorithm)
        if algorithm not in SUPPORTED_ALGORITHMS:
            logger.error("Unsupported algorithm: %s", algorithm)
            raise UnsupportedAlgorithmError(f"Unsupported algorithm: {algorithm}")
        try:
            pk = serialization.load_pem_public_key(data)
            if algorithm == "ed25519" and isinstance(pk, ed25519.Ed25519PublicKey):
                return AsymmetricKeyPair(None, pk, algorithm)
            if algorithm == "rsa4096" and isinstance(pk, rsa.RSAPublicKey):
                return AsymmetricKeyPair(None, pk, algorithm)
            if algorithm == "ecdsa_p256" and isinstance(pk, ec.EllipticCurvePublicKey):
                return AsymmetricKeyPair(None, pk, algorithm)
            raise KeyFormatError("PEM public key does not match declared algorithm")
        except (ValueError, TypeError, UnsupportedAlgorithm) as e:
            logger.error(
                "Public key import failed: %s [details suppressed]", type(e).__name__
            )
            raise KeyFormatError(
                "Failed to import public key [details suppressed]"
            ) from e

    def export_private_bytes(self, password: Optional[str] = None) -> bytes:
        if self.private_key is None:
            raise NotImplementedError("No private key present.")
        enc = (
            serialization.BestAvailableEncryption(password.encode("utf-8"))
            if password
            else serialization.NoEncryption()
        )
        return bytes(
            self.private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                enc,
            )
        )

    def export_public_bytes(self) -> bytes:
        if self.public_key is None:
            raise NotImplementedError("No public key present.")
        return bytes(
            self.public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    def sign(self, data: bytes) -> bytes:
        if self.private_key is None:
            raise NotImplementedError("No private key present.")
        if isinstance(self.private_key, ed25519.Ed25519PrivateKey):
            return bytes(self.private_key.sign(data))
        if isinstance(self.private_key, rsa.RSAPrivateKey):
            return bytes(
                self.private_key.sign(
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            )
        if isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            return bytes(self.private_key.sign(data, ec.ECDSA(hashes.SHA256())))
        raise UnsupportedAlgorithmError(f"Unsupported algorithm: {self.algorithm}")

    def verify(self, data: bytes, signature: bytes) -> bool:
        if self.public_key is None:
            raise NotImplementedError("No public key present.")
        try:
            if isinstance(self.public_key, ed25519.Ed25519PublicKey):
                self.public_key.verify(signature, data)
                return True
            if isinstance(self.public_key, rsa.RSAPublicKey):
                self.public_key.verify(
                    signature,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
                return True
            if isinstance(self.public_key, ec.EllipticCurvePublicKey):
                self.public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
                return True
            raise UnsupportedAlgorithmError(f"Unsupported algorithm: {self.algorithm}")
        except InvalidSignature:
            return False

    def encrypt(self, data: bytes) -> bytes:
        if self.public_key is None:
            raise NotImplementedError("No public key present.")
        if isinstance(self.public_key, rsa.RSAPublicKey):
            # Расчёт overhead ОБЯЗАН совпадать с алгоритмом хеширования в padding ниже (SHA-256)
            overhead = _rsa_oaep_overhead(hashes.SHA256())
            limit = self.public_key.key_size // 8 - overhead
            if len(data) > limit:
                raise ValueError(f"RSA plain length must be <= {limit} bytes for key")
            return bytes(
                self.public_key.encrypt(
                    data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
            )
        raise NotImplementedError(f"{self.algorithm} does not support encryption.")

    def decrypt(self, data: bytes) -> bytes:
        if self.private_key is None:
            raise NotImplementedError("No private key present.")
        if isinstance(self.private_key, rsa.RSAPrivateKey):
            return bytes(
                self.private_key.decrypt(
                    data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
            )
        raise NotImplementedError(f"{self.algorithm} does not support decryption.")

    def get_public_fingerprint(self) -> str:
        if self.public_key is None:
            raise NotImplementedError("No public key present.")
        return sha256(self.export_public_bytes()).hexdigest()

    def equals_public(self, other: object) -> bool:
        if not isinstance(other, AsymmetricKeyPair):
            return False
        return self.get_public_fingerprint() == other.get_public_fingerprint()


AlgorithmFactory: Dict[str, Callable[..., AsymmetricKeyPair]] = {
    "ed25519": lambda **_: AsymmetricKeyPair.generate("ed25519"),
    "rsa4096": lambda **kw: AsymmetricKeyPair.generate(
        "rsa4096", kw.get("key_size", DEFAULT_RSA_KEYSIZE)
    ),
    "ecdsa_p256": lambda **_: AsymmetricKeyPair.generate("ecdsa_p256"),
}


__all__ = [
    "AsymmetricKeyPair",
    "UnsupportedAlgorithmError",
    "KeyFormatError",
    "AlgorithmFactory",
]
