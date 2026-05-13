"""Реализация разделения секрета Шамира для FX Text Processor.

Предоставляет криптографически безопасное разделение мастер-ключа
по схеме (N, K) где необходимо K из N долей для восстановления.
"""

from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass
from typing import Protocol

import base58


class ShareEncoder(Protocol):
    """Протокол кодировщика долей."""

    def encode(self, data: bytes) -> str:
        """Кодирует bytes в строку."""
        ...

    def decode(self, encoded: str) -> bytes:
        """Декодирует строку в bytes."""
        ...


@dataclass(frozen=True)
class ShamirShare:
    """Часть секрета Shamir.

    Attributes:
        index: Номер части (1-based)
        value: Значение части (bytes)
    """

    index: int
    value: bytes

    def __post_init__(self) -> None:
        """Валидация данных доли."""
        if self.index < 1:
            raise ValueError("Index должен быть >= 1")
        if not self.value:
            raise ValueError("Value не может быть пустым")

    def to_base58(self) -> str:
        """Кодирует долю в Base58 для записи.

        Формат: index (2 bytes) + value (variable) в Base58

        Returns:
            Base58 строка с долей
        """
        # Кодируем индекс как 2 байта big-endian + value
        payload = struct.pack(">H", self.index) + self.value
        return base58.b58encode(payload).decode("ascii")

    @classmethod
    def from_base58(cls, encoded: str) -> "ShamirShare":
        """Декодирует долю из Base58.

        Args:
            encoded: Base58 строка с долей

        Returns:
            Объект ShamirShare

        Raises:
            ValueError: При неверном формате
        """
        try:
            payload = base58.b58decode(encoded)
            if len(payload) < 3:
                raise ValueError("Слишком короткая строка")

            index = struct.unpack(">H", payload[:2])[0]
            value = payload[2:]
            return cls(index=index, value=value)
        except Exception as e:
            raise ValueError(f"Неверный формат доли: {e}")

    def to_string(self) -> str:
        """Сериализует долю в строку (для совместимости).

        Returns:
            Строковое представление
        """
        return f"{self.index:04d}:{self.value.hex()}"

    @classmethod
    def from_string(cls, share_str: str) -> "ShamirShare":
        """Десериализует долю из строки.

        Args:
            share_str: Строка в формате index:value_hex

        Returns:
            Объект ShamirShare
        """
        try:
            idx_str, value_hex = share_str.split(":", 1)
            index = int(idx_str)
            value = bytes.fromhex(value_hex)
            return cls(index=index, value=value)
        except Exception as e:
            raise ValueError(f"Неверный формат доли: {e}")

    def __str__(self) -> str:
        """Строковое представление для отображения."""
        return f"ShamirShare(index={self.index}, value_len={len(self.value)})"


@dataclass(frozen=True)
class ShamirConfig:
    """Конфигурация разделения секрета.

    Attributes:
        total_shares: Общее количество долей (N)
        threshold: Порог для восстановления (K)
        prime_bits: Размер поля в битах (по умолчанию 256)
    """

    total_shares: int = 5
    threshold: int = 3
    prime_bits: int = 256

    def __post_init__(self) -> None:
        """Валидация конфигурации."""
        if self.total_shares < 2:
            raise ValueError("N должен быть не менее 2")
        if self.threshold < 2:
            raise ValueError("K должен быть не менее 2")
        if self.threshold > self.total_shares:
            raise ValueError("K не может быть больше N")
        if self.prime_bits not in {128, 256, 512}:
            raise ValueError("Размер поля должен быть 128, 256 или 512 бит")

    def validate(self) -> tuple[bool, str]:
        """Проверяет конфигурацию на соответствие рекомендациям.

        Returns:
            Кортеж (валидно, сообщение)
        """
        if self.total_shares > 10:
            return False, "Более 10 долей усложняет управление"
        if self.threshold == self.total_shares:
            return False, "K == N не даёт преимуществ резервирования"
        if self.threshold == 2 and self.total_shares > 5:
            return (
                False,
                "K=2 при большом N снижает безопасность",
            )
        return True, "Конфигурация рекомендуется"


class ShamirSecretSharing:
    """Реализация Shamir's Secret Sharing.

    Использует конечное поле GF(2^256) для операций.
    Генерирует случайный полином степени k-1.
    Вычисляет n точек на полиноме.

    Example:
        >>> sss = ShamirSecretSharing()
        >>> shares = sss.split(
        ...     secret=b"my_secret_key_32_bytes!",
        ...     n=5,
        ...     k=3
        ... )
        >>> recovered = sss.combine(shares[:3])
    """

    # Простое число для поля (близко к 2^256)
    _PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

    def split(
        self,
        secret: bytes,
        n: int,
        k: int,
        field_size: int = 256,
    ) -> list[ShamirShare]:
        """Разделяет секрет на N частей, K нужны для восстановления.

        Args:
            secret: Секретные данные (до 32 байт для 256-bit)
            n: Всего частей
            k: Нужно для восстановления
            field_size: Размер поля в битах

        Returns:
            Список из N долей

        Raises:
            ValueError: При неверных параметрах
        """
        config = ShamirConfig(total_shares=n, threshold=k, prime_bits=field_size)

        # Преобразуем секрет в число
        secret_int = int.from_bytes(secret.ljust(32, b"\x00"), "big")

        # Создаём полином: secret + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
        coefficients = [secret_int] + [secrets.randbelow(self._PRIME) for _ in range(k - 1)]

        shares = []
        for i in range(1, n + 1):
            # Вычисляем значение полинома в точке x = i
            y = self._evaluate_polynomial(coefficients, i)
            share = ShamirShare(
                index=i,
                value=y.to_bytes(32, "big"),
            )
            shares.append(share)

        return shares

    def combine(self, shares: list[ShamirShare]) -> bytes:
        """Восстанавливает секрет из >= K частей с использованием
        Lagrange interpolation.

        Args:
            shares: Список долей (минимум K)

        Returns:
            Восстановленный секрет

        Raises:
            ValueError: При недостаточном количестве долей
        """
        if not shares:
            raise ValueError("Необходимо предоставить доли")

        # Проверяем что достаточно уникальных долей
        unique_indices = {s.index for s in shares}
        if len(unique_indices) != len(shares):
            raise ValueError("Найдены дублирующиеся доли")

        # Для восстановления нужно хотя бы 2 доли
        if len(shares) < 2:
            raise ValueError("Для восстановления нужно минимум 2 доли")

        # Интерполяция Лагранжа
        secret_int = self._lagrange_interpolation(shares)

        # Конвертируем обратно в bytes
        return secret_int.to_bytes(32, "big").rstrip(b"\x00")

    def _evaluate_polynomial(self, coefficients: list[int], x: int) -> int:
        """Вычисляет значение полинома в точке x по модулю P."""
        result = 0
        x_power = 1
        for coeff in coefficients:
            result = (result + coeff * x_power) % self._PRIME
            x_power = (x_power * x) % self._PRIME
        return result

    def _lagrange_interpolation(self, shares: list[ShamirShare]) -> int:
        """Интерполяция Лагранжа для восстановления секрета."""
        secret = 0
        k = len(shares)

        for i, share_i in enumerate(shares):
            numerator = 1
            denominator = 1

            for j, share_j in enumerate(shares):
                if i != j:
                    numerator = (numerator * (-share_j.index)) % self._PRIME
                    denominator = (denominator * (share_i.index - share_j.index)) % self._PRIME

            # Умножение на y_i и сложение
            value = int.from_bytes(share_i.value, "big")
            term = (value * numerator * self._mod_inverse(denominator, self._PRIME)) % self._PRIME
            secret = (secret + term) % self._PRIME

        return secret

    def _mod_inverse(self, a: int, m: int) -> int:
        """Вычисляет модульное обратное a^-1 mod m."""

        def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y

        _, x, _ = extended_gcd(a % m, m)
        return (x + m) % m
