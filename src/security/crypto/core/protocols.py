"""
Протокольные интерфейсы для криптографической подсистемы.

Определяет 8 Protocol классов для 46 криптографических алгоритмов
согласно CRYPTO_MASTER_PLAN v2.3:
- 10 симметричных шифров (SymmetricCipherProtocol)
- 17 алгоритмов подписи (SignatureProtocol)
- 3 асимметричных шифра (AsymmetricEncryptionProtocol)
- 8 алгоритмов обмена ключами (KeyExchangeProtocol)
- 8 хеш-функций (HashProtocol)
- 4 KDF функции (KDFProtocol)
- Утилиты: NonceManager, SecureMemory

Модуль использует typing.Protocol для определения контрактов, что обеспечивает
structural subtyping без явного наследования. Все Protocol классы помечены
@runtime_checkable для поддержки isinstance() проверок.

Example:
    >>> from src.security.crypto.algorithms.symmetric import AES256GCM
    >>> cipher = AES256GCM()
    >>> isinstance(cipher, SymmetricCipherProtocol)
    True

Version: 1.0
Date: February 9, 2026
Priority: 🔴 CRITICAL (Phase 1, Day 1-2)
"""

from __future__ import annotations

from typing import (
    Iterable,
    Optional,
    Protocol,
    Tuple,
    runtime_checkable,
)

# ==============================================================================
# SYMMETRIC ENCRYPTION PROTOCOL
# ==============================================================================


@runtime_checkable
class SymmetricCipherProtocol(Protocol):
    """
    Протокол для симметричного шифрования.

    Поддерживает AEAD (Authenticated Encryption with Associated Data) и
    non-AEAD режимы шифрования. Используется для реализации 10 симметричных
    шифров из CRYPTO_MASTER_PLAN v2.3.

    Алгоритмы (10):
        AEAD:
            - AES-128-GCM, AES-256-GCM, AES-256-GCM-SIV
            - ChaCha20-Poly1305, XChaCha20-Poly1305
            - AES-256-SIV, AES-256-OCB
        Legacy:
            - 3DES-EDE3, DES
        Non-AEAD:
            - AES-256-CTR

    Attributes:
        algorithm_name: Название алгоритма (например, "AES-256-GCM")
        key_size: Размер ключа в байтах
        nonce_size: Размер nonce/IV в байтах
        is_aead: True если поддерживается аутентифицированное шифрование

    Validation Rules:
        - key: длина должна быть == key_size
        - nonce: если указан, длина == nonce_size, иначе генерируется CSPRNG
        - plaintext: минимум 1 байт, максимум зависит от алгоритма
          (для GCM ≤ 2^39 - 256 бит)
        - associated_data: только для AEAD (is_aead=True), иначе игнорируется

    Example:
        >>> cipher = AES256GCM()
        >>> cipher.algorithm_name
        'AES-256-GCM'
        >>> cipher.key_size
        32
        >>> cipher.nonce_size
        12
        >>> cipher.is_aead
        True
        >>> key = cipher.generate_key()
        >>> plaintext = b"Sensitive data"
        >>> ciphertext, tag = cipher.encrypt(key, plaintext)
        >>> decrypted = cipher.decrypt(key, ciphertext, tag)
        >>> decrypted == plaintext
        True
    """

    algorithm_name: str
    key_size: int
    nonce_size: int
    is_aead: bool

    def encrypt(
        self,
        key: bytes,
        plaintext: bytes,
        *,
        nonce: Optional[bytes] = None,
        associated_data: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """
        Зашифровать данные.

        Args:
            key: Ключ шифрования (длина = key_size байт)
            plaintext: Открытый текст для шифрования (минимум 1 байт)
            nonce: Nonce/IV (если None — генерируется автоматически).
                   ВНИМАНИЕ: Для AEAD алгоритмов НИКОГДА не используйте
                   один и тот же nonce с одним ключом дважды!
            associated_data: Дополнительные данные для AEAD
                            (только для AEAD алгоритмов, где is_aead=True)

        Returns:
            Tuple[ciphertext, nonce_or_tag]:
                - ciphertext: Зашифрованные данные
                - nonce_or_tag: для AEAD — authentication tag,
                               для non-AEAD — использованный nonce

        Raises:
            ValueError: Некорректная длина ключа или nonce
            TypeError: Неверный тип данных
            EncryptionError: Ошибка шифрования

        Note:
            Для AEAD алгоритмов возвращается authentication tag,
            для non-AEAD — использованный nonce для последующей расшифровки.

        Example:
            >>> key = cipher.generate_key()
            >>> plaintext = b"Secret message"
            >>> # AEAD: возвращает (ciphertext, tag)
            >>> ciphertext, tag = cipher.encrypt(key, plaintext)
            >>> # non-AEAD: возвращает (ciphertext, nonce)
            >>> ciphertext, nonce = cipher.encrypt(key, plaintext)
        """
        ...

    def decrypt(
        self,
        key: bytes,
        ciphertext: bytes,
        nonce: bytes,
        *,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Расшифровать данные.

        Args:
            key: Ключ шифрования (тот же, что использовался для encrypt)
            ciphertext: Зашифрованные данные
            nonce_or_tag: для AEAD — authentication tag,
                         для non-AEAD — nonce
            associated_data: Дополнительные данные для AEAD
                            (должны совпадать с теми, что были при encrypt)

        Returns:
            Расшифрованный plaintext

        Raises:
            ValueError: Аутентификация не прошла (для AEAD) или
                       некорректные параметры
            DecryptionError: Ошибка расшифрования

        Security:
            Для AEAD алгоритмов перед расшифровкой проверяется
            authentication tag. Если tag не совпадает, данные были
            изменены или использован неправильный ключ — выбрасывается
            ValueError.

        Example:
            >>> # AEAD
            >>> plaintext = cipher.decrypt(key, ciphertext, tag)
            >>> # non-AEAD
            >>> plaintext = cipher.decrypt(key, ciphertext, nonce)
        """
        ...

    def generate_key(self) -> bytes:
        """
        Генерация криптографически стойкого ключа.

        Использует CSPRNG (Cryptographically Secure Pseudo-Random Number
        Generator) для генерации случайного ключа требуемой длины.

        Returns:
            Ключ длины key_size байт

        Security:
            Ключ генерируется с использованием secrets.token_bytes()
            (Python 3.6+), который использует os.urandom() на Unix
            и CryptGenRandom() на Windows.

        Example:
            >>> key = cipher.generate_key()
            >>> len(key) == cipher.key_size
            True
        """
        ...


# ==============================================================================
# DIGITAL SIGNATURE PROTOCOL
# ==============================================================================


@runtime_checkable
class SignatureProtocol(Protocol):
    """
    Протокол для цифровых подписей.

    Поддерживает классические (EdDSA, ECDSA, RSA) и постквантовые
    (Dilithium, FALCON, SPHINCS+) алгоритмы подписи.

    Алгоритмы (17):
        EdDSA:
            - Ed25519, Ed448
        ECDSA:
            - P-256, P-384, P-521, secp256k1
        RSA:
            - RSA-PSS-2048, RSA-PSS-3072, RSA-PSS-4096
            - RSA-PKCS1v15 (legacy)
        Post-Quantum:
            - Dilithium2, Dilithium3, Dilithium5
            - FALCON-512, FALCON-1024
            - SPHINCS+-128s, SPHINCS+-256s

    Attributes:
        algorithm_name: Название алгоритма (например, "Ed25519")
        signature_size: Размер подписи в байтах (может быть переменным)
        public_key_size: Размер публичного ключа в байтах
        private_key_size: Размер приватного ключа в байтах
        is_post_quantum: True если постквантовый алгоритм

    Validation Rules:
        - private_key, public_key: должны соответствовать
          private_key_size, public_key_size
        - message: любая длина (≥ 0 байт)
        - verify() возвращает bool, НЕ выбрасывает исключения при
          невалидной подписи

    Example:
        >>> signer = Ed25519Signer()
        >>> signer.algorithm_name
        'Ed25519'
        >>> signer.signature_size
        64
        >>> signer.public_key_size
        32
        >>> signer.private_key_size
        32
        >>> signer.is_post_quantum
        False
        >>> private_key, public_key = signer.generate_keypair()
        >>> message = b"Document to sign"
        >>> signature = signer.sign(private_key, message)
        >>> signer.verify(public_key, message, signature)
        True
    """

    algorithm_name: str
    signature_size: int
    public_key_size: int
    private_key_size: int
    is_post_quantum: bool

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Генерация пары ключей.

        Генерирует новую пару ключей (приватный, публичный) с использованием
        криптографически стойкого генератора случайных чисел.

        Returns:
            Tuple[private_key, public_key]:
                - private_key: Приватный ключ (private_key_size байт)
                - public_key: Публичный ключ (public_key_size байт)

        Security:
            Приватный ключ должен храниться в безопасном месте и
            НИКОГДА не передаваться по незащищенным каналам.
            Рекомендуется использовать SecureStorage для хранения.

        Example:
            >>> private_key, public_key = signer.generate_keypair()
            >>> len(private_key) == signer.private_key_size
            True
            >>> len(public_key) == signer.public_key_size
            True
        """
        ...

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """
        Подписать сообщение.

        Args:
            private_key: Приватный ключ (длина = private_key_size)
            message: Сообщение для подписи (любая длина)

        Returns:
            Цифровая подпись (длина ≈ signature_size)

        Raises:
            ValueError: Некорректный формат приватного ключа
            SigningError: Ошибка подписи

        Security:
            Подпись гарантирует:
            1. Аутентичность: сообщение подписано владельцем private_key
            2. Целостность: сообщение не было изменено
            3. Non-repudiation: владелец ключа не может отрицать подпись

        Example:
            >>> message = b"Important document"
            >>> signature = signer.sign(private_key, message)
            >>> len(signature) == signer.signature_size
            True
        """
        ...

    def verify(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> bool:
        """
        Проверить подпись.

        Args:
            public_key: Публичный ключ (длина = public_key_size)
            message: Исходное сообщение
            signature: Подпись для проверки

        Returns:
            True если подпись валидна, False иначе

        Note:
            Метод НЕ выбрасывает исключения при невалидной подписи —
            вместо этого возвращает False. Это упрощает использование
            в условных выражениях.

        Security:
            Проверка выполняется в constant time (защита от timing attacks).

        Example:
            >>> is_valid = signer.verify(public_key, message, signature)
            >>> if is_valid:
            ...     print("Signature valid")
            ... else:
            ...     print("Signature invalid or tampered")
        """
        ...


# ==============================================================================
# ASYMMETRIC ENCRYPTION PROTOCOL
# ==============================================================================


@runtime_checkable
class AsymmetricEncryptionProtocol(Protocol):
    """
    Протокол для асимметричного шифрования.

    Используется для RSA-OAEP с разными размерами ключей.
    Асимметричное шифрование позволяет зашифровать данные публичным
    ключом получателя, и только получатель с приватным ключом может
    расшифровать.

    Алгоритмы (3):
        - RSA-OAEP-2048
        - RSA-OAEP-3072
        - RSA-OAEP-4096

    Attributes:
        algorithm_name: Название алгоритма (например, "RSA-OAEP-2048")
        key_size: Размер ключа в битах (2048, 3072, 4096)
        max_plaintext_size: Максимальный размер plaintext в байтах
                           (зависит от key_size и padding)

    Validation Rules:
        - plaintext: длина ≤ max_plaintext_size
        - key_size: определяет max_plaintext_size
          (например, для RSA-2048 с OAEP-SHA256 ≈ 190 байт)

    Security Note:
        Асимметричное шифрование медленное и ограничено по размеру.
        Для шифрования больших данных используйте гибридное шифрование:
        1. Сгенерировать случайный симметричный ключ (например, AES-256)
        2. Зашифровать данные симметричным ключом
        3. Зашифровать симметричный ключ асимметричным алгоритмом

    Example:
        >>> rsa = RSAOAEP2048()
        >>> rsa.algorithm_name
        'RSA-OAEP-2048'
        >>> rsa.key_size
        2048
        >>> rsa.max_plaintext_size
        190
        >>> private_key, public_key = rsa.generate_keypair()
        >>> plaintext = b"Secret key"
        >>> ciphertext = rsa.encrypt(public_key, plaintext)
        >>> decrypted = rsa.decrypt(private_key, ciphertext)
        >>> decrypted == plaintext
        True
    """

    algorithm_name: str
    key_size: int
    max_plaintext_size: int

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Генерация пары ключей.

        Returns:
            Tuple[private_key, public_key]:
                - private_key: Приватный ключ (PEM или DER формат)
                - public_key: Публичный ключ (PEM или DER формат)

        Security:
            RSA генерация ключей — медленная операция (особенно для
            RSA-4096). Рекомендуется выполнять асинхронно или с
            индикацией прогресса.

        Example:
            >>> private_key, public_key = rsa.generate_keypair()
            >>> # Приватный ключ нужно надежно сохранить
            >>> # Публичный ключ можно свободно распространять
        """
        ...

    def encrypt(self, public_key: bytes, plaintext: bytes) -> bytes:
        """
        Шифрование открытым ключом.

        Args:
            public_key: Публичный ключ получателя (PEM или DER формат)
            plaintext: Данные для шифрования (≤ max_plaintext_size)

        Returns:
            Зашифрованные данные (размер = key_size в байтах)

        Raises:
            ValueError: plaintext слишком длинный
                       (> max_plaintext_size)
            EncryptionError: Ошибка шифрования

        Example:
            >>> plaintext = b"Symmetric key: " + os.urandom(32)
            >>> ciphertext = rsa.encrypt(public_key, plaintext)
            >>> len(ciphertext) == rsa.key_size // 8
            True
        """
        ...

    def decrypt(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """
        Расшифрование приватным ключом.

        Args:
            private_key: Приватный ключ (PEM или DER формат)
            ciphertext: Зашифрованные данные

        Returns:
            Расшифрованный plaintext

        Raises:
            DecryptionError: Ошибка расшифрования (неправильный ключ
                            или поврежденные данные)

        Example:
            >>> plaintext = rsa.decrypt(private_key, ciphertext)
        """
        ...


# ==============================================================================
# KEY EXCHANGE PROTOCOL
# ==============================================================================


@runtime_checkable
class KeyExchangeProtocol(Protocol):
    """
    Протокол для обмена ключами (KEX/KEM).

    Поддерживает классический Diffie-Hellman (X25519, X448, ECDH) и
    постквантовые KEM (Key Encapsulation Mechanisms) — Kyber.

    Алгоритмы (8):
        Classical:
            - X25519, X448
            - ECDH-P256, ECDH-P384, ECDH-P521
        Post-Quantum KEM:
            - Kyber512, Kyber768, Kyber1024

    Attributes:
        algorithm_name: Название алгоритма (например, "X25519")
        shared_secret_size: Размер общего секрета в байтах
        is_post_quantum: True если постквантовый алгоритм

    Validation Rules:
        - shared_secret: всегда shared_secret_size байт
        - keypair: размеры зависят от алгоритма

    Use Case:
        Key Exchange используется для установления общего секрета между
        двумя сторонами по незащищенному каналу (например, TLS handshake).

    Example:
        >>> kex = X25519KeyExchange()
        >>> kex.algorithm_name
        'X25519'
        >>> kex.shared_secret_size
        32
        >>> kex.is_post_quantum
        False
        >>> # Алиса
        >>> alice_private, alice_public = kex.generate_keypair()
        >>> # Боб
        >>> bob_private, bob_public = kex.generate_keypair()
        >>> # Обмен публичными ключами (по незащищенному каналу)
        >>> # Алиса вычисляет общий секрет
        >>> alice_secret = kex.derive_shared_secret(alice_private, bob_public)
        >>> # Боб вычисляет общий секрет
        >>> bob_secret = kex.derive_shared_secret(bob_private, alice_public)
        >>> # Секреты совпадают!
        >>> alice_secret == bob_secret
        True
    """

    algorithm_name: str
    shared_secret_size: int
    is_post_quantum: bool

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Генерация ephemeral keypair для обмена.

        Returns:
            Tuple[private_key, public_key]:
                - private_key: Приватный ключ (хранится локально)
                - public_key: Публичный ключ (отправляется собеседнику)

        Security:
            Для Perfect Forward Secrecy (PFS) рекомендуется генерировать
            новую пару ключей для каждой сессии и удалять приватные ключи
            после завершения.

        Example:
            >>> private_key, public_key = kex.generate_keypair()
            >>> # Отправить public_key собеседнику
        """
        ...

    def derive_shared_secret(
        self,
        private_key: bytes,
        peer_public_key: bytes,
    ) -> bytes:
        """
        Вычисление общего секрета.

        Args:
            private_key: Локальный приватный ключ
            peer_public_key: Публичный ключ собеседника

        Returns:
            Общий секрет (shared_secret_size байт)

        Raises:
            ValueError: Некорректный формат ключа
            KeyExchangeError: Ошибка вычисления секрета

        Security:
            Общий секрет НЕ следует использовать напрямую как ключ
            шифрования. Рекомендуется применить KDF (например, HKDF):

            >>> shared_secret = kex.derive_shared_secret(private_key, peer_public)
            >>> from src.security.crypto.algorithms.kdf import HKDF
            >>> kdf = HKDF()
            >>> encryption_key = kdf.derive_key(
            ...     password=shared_secret,
            ...     salt=b"unique_salt",
            ...     length=32
            ... )

        Example:
            >>> shared_secret = kex.derive_shared_secret(
            ...     private_key,
            ...     peer_public_key
            ... )
            >>> len(shared_secret) == kex.shared_secret_size
            True
        """
        ...


# ==============================================================================
# HASH PROTOCOL
# ==============================================================================


@runtime_checkable
class HashProtocol(Protocol):
    """
    Протокол для криптографических хеш-функций.

    Хеш-функции преобразуют данные произвольной длины в фиксированный
    digest (дайджест). Криптографические хеш-функции обладают свойствами:
    - Детерминированность: одинаковый вход → одинаковый выход
    - Односторонность: невозможно восстановить вход из хеша
    - Collision resistance: сложно найти два разных входа с одним хешем

    Алгоритмы (8):
        SHA-2:
            - SHA-256, SHA-384, SHA-512
        SHA-3:
            - SHA3-256, SHA3-512
        BLAKE:
            - BLAKE2b, BLAKE2s, BLAKE3

    Attributes:
        algorithm_name: Название алгоритма (например, "SHA-256")
        digest_size: Размер дайджеста в байтах

    Use Cases:
        - Проверка целостности данных
        - Хранение паролей (с солью!)
        - Digital signatures (хеш подписывается, а не весь документ)
        - Content addressing (IPFS, Git)

    Example:
        >>> hasher = SHA256Hash()
        >>> hasher.algorithm_name
        'SHA-256'
        >>> hasher.digest_size
        32
        >>> data = b"Hello, World!"
        >>> digest = hasher.hash(data)
        >>> len(digest) == hasher.digest_size
        True
        >>> # Хеш детерминирован
        >>> hasher.hash(data) == hasher.hash(data)
        True
    """

    algorithm_name: str
    digest_size: int

    def hash(self, data: bytes) -> bytes:
        """
        Вычислить хеш.

        Args:
            data: Данные для хеширования (любая длина)

        Returns:
            Хеш-дайджест (digest_size байт)

        Example:
            >>> data = b"Message to hash"
            >>> digest = hasher.hash(data)
            >>> len(digest) == hasher.digest_size
            True
        """
        ...

    def hash_stream(self, stream: Iterable[bytes]) -> bytes:
        """
        Хеширование потока данных.

        Полезно для больших файлов — не нужно загружать весь файл в память,
        можно читать и хешировать по частям (chunk-by-chunk).

        Args:
            stream: Итератор, возвращающий блоки данных (bytes)

        Returns:
            Хеш-дайджест (digest_size байт)

        Example:
            >>> with open("large_file.bin", "rb") as f:
            ...     # Читаем по 8 КБ
            ...     chunks = iter(lambda: f.read(8192), b"")
            ...     digest = hasher.hash_stream(chunks)
            >>> len(digest) == hasher.digest_size
            True

        Example (генератор):
            >>> def read_in_chunks(file_path: str) -> Iterator[bytes]:
            ...     with open(file_path, "rb") as f:
            ...         while chunk := f.read(8192):
            ...             yield chunk
            >>> digest = hasher.hash_stream(read_in_chunks("file.bin"))
        """
        ...


# ==============================================================================
# KEY DERIVATION FUNCTION PROTOCOL
# ==============================================================================


@runtime_checkable
class KDFProtocol(Protocol):
    """
    Протокол для Key Derivation Functions.

    KDF функции используются для:
    1. Хеширование паролей (Argon2id, PBKDF2, Scrypt)
    2. Расширение ключей (HKDF)
    3. Вывод ключей из общего секрета (после Key Exchange)

    Алгоритмы (4):
        Password Hashing:
            - Argon2id (рекомендуется для паролей)
            - PBKDF2-SHA256
            - Scrypt
        Key Expansion:
            - HKDF-SHA256

    Attributes:
        algorithm_name: Название алгоритма (например, "Argon2id")
        recommended_iterations: Рекомендованное количество итераций
                               (для PBKDF2/Scrypt)
        recommended_memory_cost: Рекомендованный объём памяти в КБ
                                (для Argon2id/Scrypt)

    Security Notes:
        - Соль (salt) ДОЛЖНА быть уникальной для каждого пароля
        - Минимальная длина соли: 16 байт (128 бит)
        - Для паролей используйте Argon2id (защита от GPU/ASIC атак)
        - Для расширения ключей используйте HKDF

    Example:
        >>> kdf = Argon2idKDF()
        >>> kdf.algorithm_name
        'Argon2id'
        >>> kdf.recommended_iterations
        3
        >>> kdf.recommended_memory_cost
        65536
        >>> password = b"user_password"
        >>> salt = os.urandom(16)  # Уникальная соль
        >>> derived_key = kdf.derive_key(
        ...     password=password,
        ...     salt=salt,
        ...     length=32
        ... )
        >>> len(derived_key)
        32
    """

    algorithm_name: str
    recommended_iterations: int
    recommended_memory_cost: Optional[int]

    def derive_key(
        self,
        password: bytes,
        salt: bytes,
        length: int,
        *,
        iterations: Optional[int] = None,
        memory_cost: Optional[int] = None,
        parallelism: Optional[int] = None,
    ) -> bytes:
        """
        Вывести ключ из пароля.

        Args:
            password: Пароль/входной материал (любая длина)
            salt: Соль (минимум 16 байт). ДОЛЖНА быть уникальной!
            length: Желаемая длина ключа в байтах (обычно 32 для AES-256)
            iterations: Количество итераций (если None — использовать
                       recommended_iterations)
            memory_cost: Объём памяти в КБ (для Argon2id/Scrypt)
                        (если None — использовать recommended_memory_cost)
            parallelism: Степень параллелизма (для Argon2id, обычно 4)

        Returns:
            Выведенный ключ (length байт)

        Raises:
            ValueError: salt слишком короткий (<16 байт) или
                       некорректные параметры

        Security:
            Для хранения паролей:
            1. Сгенерировать уникальную соль: salt = os.urandom(16)
            2. Вывести ключ с рекомендованными параметрами
            3. Сохранить: (algorithm_id, salt, derived_key)
            4. При проверке: повторить вывод с той же солью и сравнить

        Example (хранение пароля):
            >>> password = b"user_password"
            >>> salt = os.urandom(16)
            >>> key = kdf.derive_key(password, salt, length=32)
            >>> # Сохранить: ("argon2id", salt.hex(), key.hex())

        Example (проверка пароля):
            >>> # Загрузить: (algorithm_id, salt_hex, stored_key_hex)
            >>> salt = bytes.fromhex(salt_hex)
            >>> input_password = b"user_password"
            >>> derived = kdf.derive_key(input_password, salt, length=32)
            >>> # Constant-time сравнение
            >>> import secrets
            >>> is_valid = secrets.compare_digest(derived, stored_key)

        Example (расширение ключа):
            >>> # После Key Exchange
            >>> shared_secret = x25519.derive_shared_secret(priv, peer_pub)
            >>> # Расширить в ключи шифрования/MAC
            >>> hkdf = HKDF()
            >>> key_material = hkdf.derive_key(
            ...     password=shared_secret,
            ...     salt=b"unique_context",
            ...     length=64  # 32 для AES + 32 для HMAC
            ... )
            >>> encryption_key = key_material[:32]
            >>> mac_key = key_material[32:]
        """
        ...


# ==============================================================================
# UTILITY PROTOCOLS
# ==============================================================================


@runtime_checkable
class NonceManagerProtocol(Protocol):
    """
    Управление nonce/IV для предотвращения повторного использования.

    КРИТИЧНО для AEAD режимов (GCM, CCM, etc.): повторное использование
    nonce с тем же ключом = ПОЛНЫЙ ВЗЛОМ шифрования и аутентификации!

    Nonce (Number used ONCE) должен быть уникальным для каждого
    сообщения, зашифрованного одним ключом.

    Example:
        >>> manager = NonceManager()
        >>> key_id = "user_123_aes_key"
        >>> # Генерация nonce
        >>> nonce = manager.generate_nonce(size=12)
        >>> len(nonce)
        12
        >>> # Отслеживание использования
        >>> manager.track_nonce(key_id, nonce)
        >>> # Попытка повторно использовать nonce
        >>> manager.track_nonce(key_id, nonce)
        Traceback (most recent call last):
        ...
        NonceReuseError: Nonce already used with key 'user_123_aes_key'
    """

    def generate_nonce(self, size: int) -> bytes:
        """
        Генерация криптографически стойкого nonce.

        Args:
            size: Размер nonce в байтах
                 (обычно 12 для GCM, 24 для XChaCha20)

        Returns:
            Случайный nonce (size байт)

        Security:
            Использует CSPRNG (secrets.token_bytes()) для генерации.

        Example:
            >>> nonce = manager.generate_nonce(size=12)
            >>> len(nonce)
            12
        """
        ...

    def track_nonce(self, key_id: str, nonce: bytes) -> None:
        """
        Отслеживание использованных nonce для ключа.

        Регистрирует nonce как использованный с данным ключом.
        Если nonce уже использовался с этим key_id, выбрасывается
        NonceReuseError.

        Args:
            key_id: Идентификатор ключа (уникальная строка)
            nonce: Nonce для отслеживания

        Raises:
            NonceReuseError: Если nonce уже использовался с этим key_id

        Security:
            КРИТИЧНО: Этот метод ДОЛЖЕН вызываться перед каждым
            шифрованием в AEAD режимах. Повторное использование
            nonce позволяет восстановить ключ!

        Example:
            >>> manager.track_nonce("key_1", nonce1)  # OK
            >>> manager.track_nonce("key_1", nonce2)  # OK (другой nonce)
            >>> manager.track_nonce("key_2", nonce1)  # OK (другой ключ)
            >>> manager.track_nonce("key_1", nonce1)  # ERROR!
        """
        ...


@runtime_checkable
class SecureMemoryProtocol(Protocol):
    """
    Безопасная работа с чувствительными данными в памяти.

    Проблема: Ключи и другие секретные данные остаются в RAM после
    использования. Дампы памяти, swap файлы, core dumps могут раскрыть
    конфиденциальные данные.

    Решение:
    1. Гарантированное обнуление памяти после использования
    2. Constant-time сравнение (защита от timing attacks)
    3. Memory locking (опционально, для предотвращения swap)

    Example:
        >>> memory = SecureMemory()
        >>> # Обнуление ключа после использования
        >>> key = bytearray(os.urandom(32))
        >>> # ... использование key ...
        >>> memory.secure_zero(key)
        >>> key  # Все нули
        bytearray(b'\\x00\\x00\\x00...')
        >>> # Constant-time сравнение MAC/tag
        >>> tag1 = b"authentication_tag_1"
        >>> tag2 = b"authentication_tag_2"
        >>> memory.constant_time_compare(tag1, tag2)
        False
    """

    def secure_zero(self, data: bytearray) -> None:
        """
        Гарантированное обнуление памяти.

        Перезаписывает содержимое bytearray нулями таким образом, что
        компилятор/интерпретатор не может оптимизировать операцию.
        Предотвращает извлечение ключей из дампов памяти.

        Args:
            data: Байтовый массив для обнуления (bytearray, НЕ bytes!)

        Security:
            После вызова data будет содержать только нули.
            Используйте перед удалением переменной с ключом:

            >>> key = bytearray(cipher.generate_key())
            >>> # ... использование key ...
            >>> memory.secure_zero(key)
            >>> del key  # Теперь безопасно удалить

        Example:
            >>> sensitive = bytearray(b"secret_key_12345")
            >>> memory.secure_zero(sensitive)
            >>> sensitive
            bytearray(b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00')
        """
        ...

    def constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """
        Сравнение в постоянном времени.

        Защита от timing attacks при проверке MAC/authentication tags.
        Обычное сравнение (==) прерывается на первом несовпадающем байте,
        что позволяет атакующему восстановить значение по времени выполнения.

        Args:
            a: Первая последовательность байт
            b: Вторая последовательность байт

        Returns:
            True если a == b, False иначе

        Security:
            Время выполнения зависит ТОЛЬКО от длины данных, НЕ от
            того, где находится первое отличие.

        Example:
            >>> tag1 = b"correct_tag_value"
            >>> tag2 = b"correct_tag_value"
            >>> memory.constant_time_compare(tag1, tag2)
            True
            >>> tag3 = b"incorrect_tag_val"
            >>> memory.constant_time_compare(tag1, tag3)
            False

        Use Case (проверка HMAC):
            >>> expected_hmac = compute_hmac(message, key)
            >>> received_hmac = get_from_network()
            >>> # WRONG: if expected_hmac == received_hmac  (timing attack!)
            >>> # CORRECT:
            >>> if memory.constant_time_compare(expected_hmac, received_hmac):
            ...     print("HMAC valid")
        """
        ...


# ==============================================================================
# MODULE METADATA
# ==============================================================================

__all__: list[str] = [
    "SymmetricCipherProtocol",
    "SignatureProtocol",
    "AsymmetricEncryptionProtocol",
    "KeyExchangeProtocol",
    "HashProtocol",
    "KDFProtocol",
    "NonceManagerProtocol",
    "SecureMemoryProtocol",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-02-09"
