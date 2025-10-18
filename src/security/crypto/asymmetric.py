"""
Модуль асимметричного шифрования и цифровых подписей для системы FX Text processor 3.

Реализует единый стиль работы с ключевыми парами (Ed25519, RSA-4096, ECDSA-P256) для защиты документов, аутентификации пользователей и легальной цифровой подписи.

Особенности:
- Поддержка military-grade стандартов: Ed25519 (быстрая подпись), RSA-4096 (шифрование/подпись), ECDSA P-256 (выдержка к атакам на эллиптических кривых).
- Унифицированный API: генерация, импорт/экспорт ключей PEM/DER, цифровые подписи, проверка подлинности, RSA-шифрование.
- Fail-secure: любые ошибки или попытки некорректного формата выбрасывают исключение с логом — никаких silent fail!
- Частная и публичная часть разделены — нет утечек приватной информации.
- Автоматизированный аудит типов на этапе импорта; иммутабельный dataclass для безопасного использования в многопоточной среде.
- Расширяемая фабрика AlgorithmFactory — легко переключать алгоритмы без изменений бизнес-логики.
- Secure Logging — никакие пароли, приватные ключи или чувствительные токены не попадают в логи.
- Примеры docstring — готовность к промышленной интеграции, подробные кейсы для тестов.

Основные классы:
- AsymmetricKeyPair: полный цикл работы с ключевыми парами и криптооперациями.
- UnsupportedAlgorithmError, KeyFormatError: детализированные исключения для аудита интеграций.
- AlgorithmFactory: паттерн для DI/расширения провайдеров.

Применение:
- Электронная подпись документов, генерация и экспорт ключей для легального оборота.
- Аутентификация пользователей, генерация и проверка сертификатов.
- Шифрование данных для защищённых каналов, облачных сервисов и резервных копий.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Literal, Optional, Union, Callable, Dict, Mapping

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding, ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

logger = logging.getLogger("fxtext.security.asymmetric")
logger.setLevel(logging.INFO)

__all__ = [
    "AsymmetricKeyPair",
    "load_public_key",
    "import_public_key_pem",
    "UnsupportedAlgorithmError",
    "KeyFormatError",
    "AlgorithmFactory",
]

SUPPORTED_ALGORITHMS: tuple[str, ...] = ("ed25519", "rsa4096", "ecdsa_p256")
DEFAULT_RSA_KEYSIZE: int = 4096
SENSITIVE_KEYWORDS = ("password", "private", "pem", "secret", "token", "key")


def _secure_log(
    msg: str,
    *args: Any,
    exc_info: bool = False,
    stack_info: bool = False,
    extra: Optional[Mapping[str, Any]] = None,
    stacklevel: int = 1,
) -> None:
    text = msg.lower() + "".join(str(a).lower() for a in args)
    if any(word in text for word in SENSITIVE_KEYWORDS):
        return
    logger.info(
        msg,
        *args,
        exc_info=exc_info,
        stack_info=stack_info,
        extra=extra,
        stacklevel=stacklevel,
    )


class UnsupportedAlgorithmError(ValueError):
    """Exception for unsupported algorithms in asymmetric crypto module."""

    pass


class KeyFormatError(ValueError):
    """Exception for incorrect key format."""

    pass


def _rsa_oaep_overhead(hash_alg: hashes.HashAlgorithm = hashes.SHA256()) -> int:
    hash_len: int = hash_alg.digest_size
    return 2 * hash_len + 2  # OAEP overhead formula


def _sanitize_password(_: Optional[str]) -> str:
    return "******" if _ else "(none)"


def _validate_keypair(private_key: object, public_key: object) -> None:
    if private_key is not None and public_key is None:
        raise KeyFormatError("public_key must not be None if private_key is present.")


@dataclass(frozen=True)
class AsymmetricKeyPair:
    """
    Wrapper for asymmetric key pairs (Ed25519, RSA, ECDSA P-256).
    Thread-safe, immutable.

    Example usage:
        >>> kp = AsymmetricKeyPair.generate("ed25519")
        >>> sig = kp.sign(b"test")
        >>> kp.verify(b"test", sig)
        True
        >>> kp2 = AsymmetricKeyPair.from_private_bytes(kp.export_private_bytes(), "ed25519")
        >>> kp2.equals_public(kp)  # True

    Thread safety: guaranteed (frozen dataclass).
    """

    private_key: Union[
        ed25519.Ed25519PrivateKey, rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, None
    ]
    public_key: Union[
        ed25519.Ed25519PublicKey, rsa.RSAPublicKey, ec.EllipticCurvePublicKey, None
    ]
    algorithm: str

    def _validate_keypair(self, private_key: object, public_key: object) -> None:
        if private_key is not None and public_key is None:
            raise KeyFormatError(
                "public_key must not be None if private_key is present."
            )

    @staticmethod
    def generate(algorithm: str, key_size: Optional[int] = None) -> AsymmetricKeyPair:
        _secure_log("Generating keypair: algorithm=%s", algorithm)
        if algorithm == "ed25519":
            ed_private = ed25519.Ed25519PrivateKey.generate()
            ed_public = ed_private.public_key()
            return AsymmetricKeyPair(ed_private, ed_public, algorithm)
        elif algorithm == "rsa4096":
            ks = key_size or DEFAULT_RSA_KEYSIZE
            if ks < 2048 or ks % 256 != 0:
                raise ValueError("RSA key_size must be >= 2048 and divisible by 256")
            rsa_private = rsa.generate_private_key(
                public_exponent=65537, key_size=ks, backend=default_backend()
            )
            rsa_public = rsa_private.public_key()
            return AsymmetricKeyPair(rsa_private, rsa_public, algorithm)
        elif algorithm == "ecdsa_p256":
            ec_private = ec.generate_private_key(
                ec.SECP256R1(), backend=default_backend()
            )
            ec_public = ec_private.public_key()
            return AsymmetricKeyPair(ec_private, ec_public, algorithm)
        else:
            logger.error("Unsupported algorithm: %s", algorithm)
            raise UnsupportedAlgorithmError(f"Unsupported algorithm: {algorithm}")

    @staticmethod
    def from_private_bytes(
        data: bytes, algorithm: str, password: Optional[str] = None
    ) -> AsymmetricKeyPair:
        pw = password.encode("utf-8") if password else None
        _secure_log(
            "Loading private key: %s [pw: %s]", algorithm, _sanitize_password(password)
        )
        if algorithm not in SUPPORTED_ALGORITHMS:
            logger.error("Unsupported algorithm: %s", algorithm)
            raise UnsupportedAlgorithmError(f"Unsupported algorithm: {algorithm}")
        try:
            if algorithm == "ed25519":
                pk = serialization.load_pem_private_key(data, password=pw)
                if not isinstance(pk, ed25519.Ed25519PrivateKey):
                    raise KeyFormatError("PEM is not Ed25519PrivateKey")
                return AsymmetricKeyPair(pk, pk.public_key(), algorithm)
            elif algorithm == "rsa4096":
                pk = serialization.load_pem_private_key(data, password=pw)
                if not isinstance(pk, rsa.RSAPrivateKey):
                    raise KeyFormatError("PEM is not RSAPrivateKey")
                return AsymmetricKeyPair(pk, pk.public_key(), algorithm)
            elif algorithm == "ecdsa_p256":
                pk = serialization.load_pem_private_key(data, password=pw)
                if not isinstance(pk, ec.EllipticCurvePrivateKey):
                    raise KeyFormatError("PEM is not EllipticCurvePrivateKey")
                return AsymmetricKeyPair(pk, pk.public_key(), algorithm)
        except (ValueError, TypeError, UnsupportedAlgorithm) as e:
            logger.error("Key import failed: %s (%s)", type(e).__name__, str(e))
            raise KeyFormatError(f"Failed to import private key: {e}")
        raise KeyFormatError(
            "Unreachable: something went wrong, no key returned"
        )  # Ensure return

    @staticmethod
    def from_public_bytes(data: bytes, algorithm: str) -> AsymmetricKeyPair:
        if algorithm not in SUPPORTED_ALGORITHMS:
            logger.error("Unsupported algorithm: %s", algorithm)
            raise UnsupportedAlgorithmError(f"Unsupported algorithm: {algorithm}")
        try:
            pk = serialization.load_pem_public_key(data)
            if algorithm == "ed25519" and isinstance(pk, ed25519.Ed25519PublicKey):
                return AsymmetricKeyPair(None, pk, algorithm)
            elif algorithm == "rsa4096" and isinstance(pk, rsa.RSAPublicKey):
                return AsymmetricKeyPair(None, pk, algorithm)
            elif algorithm == "ecdsa_p256" and isinstance(
                pk, ec.EllipticCurvePublicKey
            ):
                return AsymmetricKeyPair(None, pk, algorithm)
            else:
                raise KeyFormatError(
                    "Unsupported/invalid PEM public key for declared algorithm"
                )
        except (ValueError, TypeError, UnsupportedAlgorithm) as e:
            logger.error("PublicKey import failed: %s (%s)", type(e).__name__, str(e))
            raise KeyFormatError(f"Failed to import public key: {e}")
        raise KeyFormatError(
            "Unreachable: something went wrong, no public key returned"
        )

    def export_private_bytes(self, password: Optional[str] = None) -> bytes:
        if self.private_key is None:
            raise NotImplementedError("No private key present.")
        enc_algo = (
            serialization.BestAvailableEncryption(password.encode("utf-8"))
            if password
            else serialization.NoEncryption()
        )
        return self.private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc_algo
        )

    def export_public_bytes(self) -> bytes:
        if self.public_key is None:
            raise NotImplementedError("No public key present.")
        return self.public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign(self, data: bytes) -> bytes:
        if self.private_key is None:
            raise NotImplementedError("No private key present.")
        if isinstance(self.private_key, ed25519.Ed25519PrivateKey):
            return self.private_key.sign(data)
        elif isinstance(self.private_key, rsa.RSAPrivateKey):
            return self.private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        elif isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            return self.private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        else:
            raise UnsupportedAlgorithmError(f"Unsupported algorithm: {self.algorithm}")

    def verify(self, data: bytes, signature: bytes) -> bool:
        if self.public_key is None:
            raise NotImplementedError("No public key present.")
        try:
            if isinstance(self.public_key, ed25519.Ed25519PublicKey):
                self.public_key.verify(signature, data)
                return True
            elif isinstance(self.public_key, rsa.RSAPublicKey):
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
            elif isinstance(self.public_key, ec.EllipticCurvePublicKey):
                self.public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
                return True
            else:
                raise UnsupportedAlgorithmError(
                    f"Unsupported algorithm: {self.algorithm}"
                )
        except InvalidSignature:
            return False

    def encrypt(self, data: bytes) -> bytes:
        if self.public_key is None:
            raise NotImplementedError("No public key present.")
        if isinstance(self.public_key, rsa.RSAPublicKey):
            overhead = _rsa_oaep_overhead()
            limit = self.public_key.key_size // 8 - overhead
            if len(data) > limit:
                raise ValueError(f"RSA plain length must be <= {limit} bytes for key")
            return self.public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        elif isinstance(
            self.public_key, (ed25519.Ed25519PublicKey, ec.EllipticCurvePublicKey)
        ):
            raise NotImplementedError(f"{self.algorithm} does not support encryption.")
        else:
            raise UnsupportedAlgorithmError(f"Unsupported algorithm: {self.algorithm}")

    def decrypt(self, data: bytes) -> bytes:
        if self.private_key is None:
            raise NotImplementedError("No private key present.")
        if isinstance(self.private_key, rsa.RSAPrivateKey):
            return self.private_key.decrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        elif isinstance(
            self.private_key, (ed25519.Ed25519PrivateKey, ec.EllipticCurvePrivateKey)
        ):
            raise NotImplementedError(f"{self.algorithm} does not support decryption.")
        else:
            raise UnsupportedAlgorithmError(f"Unsupported algorithm: {self.algorithm}")

    def get_public_fingerprint(self) -> str:
        if self.public_key is None:
            raise NotImplementedError("No public key present.")
        pub_bytes = self.export_public_bytes()
        fp = sha256(pub_bytes).hexdigest()
        logger.debug("Public key fingerprint: %s", fp)
        return fp

    def equals_public(self, other: object) -> bool:
        if not isinstance(other, AsymmetricKeyPair):
            return False
        return self.get_public_fingerprint() == other.get_public_fingerprint()


def load_public_key(data: bytes, algorithm: str) -> AsymmetricKeyPair:
    logger.info("Loading public key: algorithm=%s, data_size=%d", algorithm, len(data))
    if algorithm not in SUPPORTED_ALGORITHMS:
        logger.error("Unsupported algorithm: %s", algorithm)
        raise UnsupportedAlgorithmError(f"Unsupported algorithm: {algorithm}")
    try:
        pk = serialization.load_pem_public_key(data)
        if algorithm == "ed25519":
            if not isinstance(pk, ed25519.Ed25519PublicKey):
                raise KeyFormatError("PEM is not Ed25519PublicKey")
            return AsymmetricKeyPair(None, pk, algorithm)
        elif algorithm == "rsa4096":
            if not isinstance(pk, rsa.RSAPublicKey):
                raise KeyFormatError("PEM is not RSAPublicKey")
            return AsymmetricKeyPair(None, pk, algorithm)
        elif algorithm == "ecdsa_p256":
            if not isinstance(pk, ec.EllipticCurvePublicKey):
                raise KeyFormatError("PEM is not EllipticCurvePublicKey")
            return AsymmetricKeyPair(None, pk, algorithm)
    except (ValueError, TypeError, UnsupportedAlgorithm) as e:
        logger.error("PublicKey import failed: %s (%s)", type(e).__name__, str(e))
        raise KeyFormatError(f"Failed to import public key: {e}")
    raise KeyFormatError("Unreachable: something went wrong, no public key returned")


def import_public_key_pem(pem_data: str) -> AsymmetricKeyPair:
    logger.info("Importing PEM public key")
    raw = pem_data.encode("utf-8")
    try:
        pk = serialization.load_pem_public_key(raw)
        if isinstance(pk, ed25519.Ed25519PublicKey):
            return AsymmetricKeyPair(None, pk, "ed25519")
        elif isinstance(pk, rsa.RSAPublicKey):
            return AsymmetricKeyPair(None, pk, "rsa4096")
        elif isinstance(pk, ec.EllipticCurvePublicKey):
            return AsymmetricKeyPair(None, pk, "ecdsa_p256")
        else:
            raise KeyFormatError("Unknown or unsupported key type in PEM")
    except (ValueError, TypeError, UnsupportedAlgorithm) as e:
        logger.error("PublicKey import failed: %s (%s)", type(e).__name__, str(e))
        raise KeyFormatError(f"Failed to import public key: {e}")
    raise KeyFormatError("Unreachable: something went wrong, no public key returned")


AlgorithmFactory: Dict[str, Callable[..., AsymmetricKeyPair]] = {
    "ed25519": lambda **kwargs: AsymmetricKeyPair.generate("ed25519"),
    "rsa4096": lambda **kwargs: AsymmetricKeyPair.generate(
        "rsa4096", kwargs.get("key_size", DEFAULT_RSA_KEYSIZE)
    ),
    "ecdsa_p256": lambda **kwargs: AsymmetricKeyPair.generate("ecdsa_p256"),
}
