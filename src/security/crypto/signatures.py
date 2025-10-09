# Модуль для цифровых подписей Ed25519 в документообороте ESC/P Text Editor.
"""
Digital signature utilities for Ed25519. For secure document, blank, and audit authentication.
All logic is type-safe, logger-integrated, with strict error handling.

Usage:
    signer = Ed25519Signer(private_key_bytes)
    signature = signer.sign(b'data')

    verifier = Ed25519Verifier(signer.public_key())
    if verifier.verify(b'data', signature):
        print("Signature valid")

Raises SignatureError on failed verification or invalid key formats.
"""

import logging
import hashlib
from typing import Final, Literal, Optional, List
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

logger: Final = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class SignatureError(Exception):
    """
    Исключение для ошибок, связанных с созданием/проверкой подписей.
    """


class Ed25519Signer:
    """
    Генератор цифровых подписей Ed25519.

    Args:
        private_key (bytes): приватный ключ Ed25519 (32 байта).
        alias (Optional[str]): опциональный идентификатор ключа/оператора для аудита.

    Raises:
        SignatureError: при некорректном ключе.

    Thread safety:
        Нет внутреннего состояния; безопасен для одновременных использований.

    Example:
        signer = Ed25519Signer(priv_bytes, alias='operator-01')
        signature = signer.sign(b"test")
        pub = signer.public_key("hex")
        fp = signer.get_fingerprint()
    """

    def __init__(self, private_key: bytes, alias: Optional[str] = None) -> None:
        if len(private_key) != 32:
            logger.error("Invalid Ed25519 private key length: %d", len(private_key))
            raise SignatureError("Ed25519 private key must be 32 bytes")
        try:
            self._sk = Ed25519PrivateKey.from_private_bytes(private_key)
            self.alias = alias
        except Exception as exc:
            logger.error("Failed to initialize Ed25519PrivateKey: %s", exc)
            raise SignatureError(f"Invalid Ed25519 private key: {exc}")

    def sign(self, message: bytes) -> bytes:
        """
        Подписать сообщение приватным ключом.

        Args:
            message (bytes): данные для подписи.

        Returns:
            bytes: подпись.

        Raises:
            SignatureError: при ошибках.
        """
        try:
            signature = self._sk.sign(message)
            logger.debug(
                "Message signed successfully%s.",
                f" [Alias: {self.alias}]" if self.alias else "",
            )
            return signature
        except Exception as exc:
            logger.error("Signing failed: %s", exc)
            raise SignatureError(f"Signing failed: {exc}")

    def public_key(self, encoding: Literal["raw", "hex"] = "raw") -> bytes | str:
        """
        Экспортировать публичный ключ.

        Args:
            encoding: "raw" — 32 байта, "hex" — hex строка.

        Returns:
            bytes | str: публичный ключ (raw или hex).
        """
        # Используем правильные параметры для public_bytes()
        raw_pk = self._sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        logger.debug("Ed25519 public key exported [%s].", encoding)
        if encoding == "raw":
            return raw_pk
        elif encoding == "hex":
            return raw_pk.hex()
        raise ValueError("Invalid encoding: choose 'raw' or 'hex'.")

    def get_fingerprint(self) -> str:
        """
        Получить SHA256 хэш публичного ключа (fingerprint).

        Returns:
            str: fingerprint (hex SHA256).
        """
        # Явно приводим к bytes для hashlib
        raw_key = self.public_key("raw")
        assert isinstance(raw_key, bytes)
        fingerprint = hashlib.sha256(raw_key).hexdigest()
        logger.debug(
            "Ed25519 public key fingerprint calculated%s.",
            f" [Alias: {self.alias}]" if self.alias else "",
        )
        return fingerprint

    @staticmethod
    def save_key_bytes(filepath: str, key_bytes: bytes) -> None:
        """
        Сохранить bytes ключа в файл.

        Args:
            filepath: путь для сохранения.
            key_bytes: 32 байта ключа.

        Raises:
            OSError: ошибки записи.
        """
        with open(filepath, "wb") as f:
            f.write(key_bytes)
        logger.info("Key bytes saved to %s.", filepath)

    @staticmethod
    def load_key_bytes(filepath: str) -> bytes:
        """
        Загрузить bytes ключа из файла.

        Args:
            filepath: откуда читать.

        Returns:
            bytes: прочитанный ключ.

        Raises:
            OSError: ошибки чтения.
            SignatureError: некорректная длина.
        """
        with open(filepath, "rb") as f:
            key_bytes = f.read()
        if len(key_bytes) != 32:
            raise SignatureError("Loaded key must be 32 bytes Ed25519.")
        logger.info("Key bytes loaded from %s.", filepath)
        return key_bytes


class Ed25519Verifier:
    """
    Проверка цифровых подписей Ed25519.

    Args:
        public_key (bytes): публичный ключ Ed25519 (32 байта).
        alias (Optional[str]): опциональный идентификатор для аудита.

    Raises:
        SignatureError: при некорректном ключе.

    Thread safety:
        Нет внутреннего состояния; безопасен для одновременных использований.

    Example:
        verifier = Ed25519Verifier(pub_bytes, alias="userA")
        valid = verifier.verify(b"msg", signature)
    """

    def __init__(self, public_key: bytes, alias: Optional[str] = None) -> None:
        if len(public_key) != 32:
            logger.error("Invalid Ed25519 public key length: %d", len(public_key))
            raise SignatureError("Ed25519 public key must be 32 bytes")
        try:
            self._pk = Ed25519PublicKey.from_public_bytes(public_key)
            self.alias = alias
        except Exception as exc:
            logger.error("Failed to initialize Ed25519PublicKey: %s", exc)
            raise SignatureError(f"Invalid Ed25519 public key: {exc}")

    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Проверить подпись сообщения.

        Args:
            message (bytes): оригинальные данные.
            signature (bytes): подпись для проверки.

        Returns:
            bool: True — подпись валидна, False — нет.

        Raises:
            SignatureError: при ошибках валидации/разбора.
        """
        if len(signature) != 64:
            logger.warning("Signature length incorrect: %d bytes", len(signature))
            return False
        try:
            self._pk.verify(signature, message)
            logger.info(
                "Signature verified successfully%s.",
                f" [Alias: {self.alias}]" if self.alias else "",
            )
            return True
        except InvalidSignature:
            logger.warning(
                "Invalid signature for message%s.", f" [Alias: {self.alias}]" if self.alias else ""
            )
            return False
        except Exception as exc:
            logger.error("Verification failed: %s", exc)
            raise SignatureError(f"Verification error: {exc}")

    def verify_batch(self, message: bytes, signatures: List[bytes]) -> List[bool]:
        """
        Проверить сразу несколько подписей одного сообщения.

        Args:
            message (bytes): исходные данные.
            signatures (List[bytes]): подряд подписи.

        Returns:
            List[bool]: для каждой подписи — True/False.
        """
        results: List[bool] = []
        for sig in signatures:
            results.append(self.verify(message, sig))
        logger.debug(
            "Batch verification completed for %d signatures%s.",
            len(signatures),
            f" [Alias: {self.alias}]" if self.alias else "",
        )
        return results

    def get_fingerprint(self) -> str:
        """
        Получить fingerprint ключа (SHA256 hex).

        Returns:
            str: fingerprint.
        """
        # Используем правильные параметры для public_bytes()
        pk_bytes = self._pk.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        fingerprint = hashlib.sha256(pk_bytes).hexdigest()
        logger.debug(
            "Ed25519 verifier public key fingerprint calculated%s.",
            f" [Alias: {self.alias}]" if self.alias else "",
        )
        return fingerprint

    @staticmethod
    def save_key_bytes(filepath: str, key_bytes: bytes) -> None:
        """
        Сохранить bytes ключа в файл.

        Args:
            filepath: путь для сохранения.
            key_bytes: 32 байта ключа.

        Raises:
            OSError: ошибки записи.
        """
        with open(filepath, "wb") as f:
            f.write(key_bytes)
        logger.info("Verifier key bytes saved to %s.", filepath)

    @staticmethod
    def load_key_bytes(filepath: str) -> bytes:
        """
        Загрузить bytes ключа из файла.

        Args:
            filepath: откуда читать.

        Returns:
            bytes: прочитанный ключ.

        Raises:
            OSError: ошибки чтения.
            SignatureError: некорректная длина.
        """
        with open(filepath, "rb") as f:
            key_bytes = f.read()
        if len(key_bytes) != 32:
            raise SignatureError("Loaded verifier key must be 32 bytes Ed25519.")
        logger.info("Verifier key loaded from %s.", filepath)
        return key_bytes
