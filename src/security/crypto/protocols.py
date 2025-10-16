"""
Протоколы для криптографических провайдеров.

Определяют контракты для:
- Симметричного шифрования (AES-GCM)
- Ассиметричных операций (Ed25519, RSA)
- Key Derivation (Argon2id)
- Хранилища ключей
- Хеширования

Используются для DI в CryptoService.
"""

from typing import Protocol, Optional


class SymmetricCipherProtocol(Protocol):
    """Симметричное шифрование с AEAD."""

    ...


class SigningProtocol(Protocol):
    """Цифровые подписи."""

    ...


class KdfProtocol(Protocol):
    """Key Derivation Function."""

    ...


class KeyStoreProtocol(Protocol):
    """Хранилище ключей."""

    ...


class HashingProtocol(Protocol):
    """Хеширование и HMAC."""

    ...
