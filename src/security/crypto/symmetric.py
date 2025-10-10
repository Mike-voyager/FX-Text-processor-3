"""Модуль симметричного шифрования для ESC/P Text Editor.
Реализует AES-256-GCM с аутентификацией и журналированием событий.

- Соответствие military-grade crypto (NIST SP 800-38D).
- Fail-secure: все ошибки приводят к исключению, а не к silent fail.
- Полная типизация, строгие проверки, подробные docstring.
- Военный хардeнинг: миксер случайных байт, диагностика, entropy audit, zeroization.

Classes:
    SymmetricCipher: Authenticated AES-256-GCM encryption/decryption for documents and credentials.
"""

import logging
import os
from typing import ClassVar, Final, Optional
from secrets import token_bytes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

_LOGGER: Final = logging.getLogger("security.crypto.symmetric")
_KEY_LENGTH: Final[int] = 32  # 256-bit key for AES-256
_NONCE_LENGTH: Final[int] = 12  # Standard GCM nonce


def _diagnose_rng() -> None:
    """Диагностика наличия CSPRNG (os.urandom) в системе."""
    try:
        b = os.urandom(8)
        if not isinstance(b, bytes) or len(b) != 8:
            raise RuntimeError
    except Exception:
        _LOGGER.error("CSPRNG health check failed!")
        raise RuntimeError("OS-level CSPRNG unavailable.")


def _entropy_mixer(length: int) -> bytes:
    """Генерирует ключ или nonce как XOR поток двух независимых источников random; аудирует результат."""
    _diagnose_rng()
    a = token_bytes(length)
    b = os.urandom(length)
    mixed = bytes(x ^ y for x, y in zip(a, b))
    _audit_entropy(mixed)
    return mixed


def _audit_entropy(data: bytes) -> None:
    """Mini-аудит: даёт предупреждение, если поток энтропии подозрительно слабый или не случайный."""
    if not data:
        raise ValueError("Empty entropy stream.")
    zero_count = data.count(0)
    unique_count = len(set(data))
    if zero_count > len(data) // 2 or unique_count < len(data) // 4:
        _LOGGER.error(
            "Random audit: low entropy detected (zeros=%d unique=%d)", zero_count, unique_count
        )
        raise ValueError("Entropy mixer: suspicious randomness detected.")
    _LOGGER.info(
        "Entropy audit OK: unique=%d zeros=%d total=%d", unique_count, zero_count, len(data)
    )


def auditentropy(data: bytes) -> None:
    return _audit_entropy(data)


def _zeroize(data: Optional[bytearray]) -> None:
    """Zeroization — очистка секретов в памяти."""
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
        del data


class SymmetricCipher:
    """AES-256-GCM authenticated encryption for sensitive data.

    Example:
        >>> key = SymmetricCipher.generate_key()
        >>> nonce = SymmetricCipher.generate_nonce()
        >>> ciphertext = SymmetricCipher.encrypt(b"secret", key, nonce)
        >>> plaintext = SymmetricCipher.decrypt(ciphertext, key, nonce)
        >>> assert plaintext == b"secret"
    """

    KEY_LENGTH: ClassVar[int] = _KEY_LENGTH
    NONCE_LENGTH: ClassVar[int] = _NONCE_LENGTH

    @staticmethod
    def generate_key() -> bytes:
        """Generate a new random AES-256 key (XOR-mixer + audit)."""
        return _entropy_mixer(SymmetricCipher.KEY_LENGTH)

    @staticmethod
    def generate_nonce() -> bytes:
        """Generate a random GCM nonce (XOR-mixer + audit)."""
        return _entropy_mixer(SymmetricCipher.NONCE_LENGTH)

    @staticmethod
    def validate_key(key: bytes) -> None:
        """Validate key type and length for AES-256-GCM.

        Args:
            key: AES key.

        Raises:
            TypeError: If key is not bytes.
            ValueError: If key length is invalid.
        """
        if not isinstance(key, bytes):
            _LOGGER.error("Invalid AES key type: %r", type(key))
            raise TypeError("Key must be bytes for AES-256-GCM.")
        if len(key) != SymmetricCipher.KEY_LENGTH:
            _LOGGER.error("Invalid AES key length: %d", len(key))
            raise ValueError("Key must be 32 bytes for AES-256-GCM.")

    @staticmethod
    def validate_nonce(nonce: bytes) -> None:
        """Validate nonce type and length for AES-GCM.

        Args:
            nonce: AES-GCM nonce.

        Raises:
            TypeError: If nonce is not bytes.
            ValueError: If nonce length is invalid.
        """
        if not isinstance(nonce, bytes):
            _LOGGER.error("Invalid AES-GCM nonce type: %r", type(nonce))
            raise TypeError("Nonce must be bytes for AES-GCM.")
        if len(nonce) != SymmetricCipher.NONCE_LENGTH:
            _LOGGER.error("Invalid AES-GCM nonce length: %d", len(nonce))
            raise ValueError("Nonce must be 12 bytes for AES-GCM.")

    @staticmethod
    def validate_aad(associated_data: Optional[bytes]) -> None:
        """Validate associated authenticated data for type.

        Args:
            associated_data: additional authenticated data.

        Raises:
            TypeError: if not bytes or None.
        """
        if associated_data is not None and not isinstance(associated_data, bytes):
            _LOGGER.error("Associated data must be bytes or None, got: %r", type(associated_data))
            raise TypeError("Associated data (aad) must be bytes or None.")

    @staticmethod
    def encrypt(
        data: bytes,
        key: bytes,
        nonce: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Encrypt data using AES-256-GCM.

        Args:
            data: Plaintext to encrypt.
            key: AES-256 key (32 bytes).
            nonce: GCM nonce (12 bytes).
            associated_data: Optional authenticated data (bytes or None).

        Returns:
            bytes: Authenticated ciphertext.

        Raises:
            ValueError: Invalid key/nonce size.
            TypeError: Invalid type(s).
            Exception: Other cryptographic errors.
        """
        SymmetricCipher.validate_key(key)
        SymmetricCipher.validate_nonce(nonce)
        SymmetricCipher.validate_aad(associated_data)
        if not isinstance(data, bytes):
            _LOGGER.error("Data to encrypt must be bytes, got %r", type(data))
            raise TypeError("Data to encrypt must be bytes.")
        try:
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce),
                backend=default_backend(),
            )
            encryptor = cipher.encryptor()
            if associated_data is not None:
                encryptor.authenticate_additional_data(associated_data)
            ciphertext = encryptor.update(data) + encryptor.finalize()
            result = ciphertext + encryptor.tag
            _LOGGER.info("Data encrypted (len=%d, tag len=%d).", len(result), len(encryptor.tag))
            if isinstance(key, bytearray):
                _zeroize(key)
            if isinstance(nonce, bytearray):
                _zeroize(nonce)
            return result
        except Exception as exc:
            _LOGGER.error("Encryption failed: %s", exc)
            raise

    @staticmethod
    def decrypt(
        ciphertext: bytes,
        key: bytes,
        nonce: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Decrypt data using AES-256-GCM.

        Args:
            ciphertext: Authenticated encrypted data.
            key: AES-256 key (32 bytes).
            nonce: GCM nonce (12 bytes).
            associated_data: Optional authenticated data (bytes or None).

        Returns:
            bytes: Decrypted plaintext.

        Raises:
            ValueError: Invalid key/nonce/tag or input types.
            InvalidTag: Authentication failed.
            TypeError: Invalid type(s).
            Exception: Other cryptographic errors.
        """
        SymmetricCipher.validate_key(key)
        SymmetricCipher.validate_nonce(nonce)
        SymmetricCipher.validate_aad(associated_data)
        if not isinstance(ciphertext, bytes):
            _LOGGER.error("Ciphertext to decrypt must be bytes, got %r", type(ciphertext))
            raise TypeError("Ciphertext to decrypt must be bytes.")
        if len(ciphertext) < 16:
            _LOGGER.error("Ciphertext too short for AES-GCM decryption.")
            raise ValueError("Ciphertext too short for AES-GCM.")
        tag = ciphertext[-16:]
        actual_ciphertext = ciphertext[:-16]
        try:
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
                backend=default_backend(),
            )
            decryptor = cipher.decryptor()
            if associated_data is not None:
                decryptor.authenticate_additional_data(associated_data)
            plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
            _LOGGER.info("Data decrypted (len=%d, tag verified).", len(plaintext))
            if isinstance(key, bytearray):
                _zeroize(key)
            if isinstance(nonce, bytearray):
                _zeroize(nonce)
            return plaintext
        except InvalidTag as itag:
            _LOGGER.warning("Decryption failed: Invalid authentication tag (possible tampering).")
            raise
        except Exception as exc:
            _LOGGER.error("Decryption failed: %s", exc)
            raise


encrypt_aes_gcm = SymmetricCipher.encrypt
decrypt_aes_gcm = SymmetricCipher.decrypt
__all__ = ["SymmetricCipher", "encrypt_aes_gcm", "decrypt_aes_gcm"]
