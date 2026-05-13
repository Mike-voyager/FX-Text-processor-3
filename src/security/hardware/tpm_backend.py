"""
TPM (Trusted Platform Module) 2.0 backend.

Реализует интерфейс к TPM 2.0 для криптографических операций:
генерация ключей, подпись, seal/unseal данных к PCR state.

Поддерживаемые TPM:
    - Дискретные TPM (Infineon, Nuvoton, STMicro)
    - fTPM (Intel PTT, AMD PSP)
    - Software TPM (IBM SW TPM, Microsoft TPM Simulator)

Зависимости (опциональные):
    - tpm2-pytss>=1.0.0 (основной backend)
    - tpm2-tools (CLI fallback)

Ограничения:
    - Для seal/unseal требуется PCR policy или auth value.
    - Некоторые TPM не поддерживают Ed25519 (требуется проверка).

Security Notes:
    - Приватные ключи TPM никогда не экспортируются.
    - Seal операции привязаны к PCR values (platform state).
    - Auth values хранятся только во время операции.

Example:
    >>> backend = TPMBackend("/dev/tpm0")
    >>> if backend.is_available():
    ...     # Create key
    ...     pub_key = backend.create_key("my_sign_key")
    ...     # Sign data
    ...     sig = backend.sign("my_sign_key", b"data_hash")
    ...     # Seal secret
    ...     sealed = backend.seal(b"secret", policy={"pcr": [0, 1, 2]})

Version: 1.0.0
Date: 2026-04-05
Author: Mike Voyager
"""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Final

from src.security.crypto.core.exceptions import (
    AlgorithmNotAvailableError,
    DeviceCommunicationError,
    DeviceNotFoundError,
    HardwareDeviceError,
    InvalidKeyError,
    KeyGenerationError,
)

# Optional dependency handling
try:
    from tpm2_pytss import TpmContext as TSS2_Context
    from tpm2_pytss import TSS2_Exception
    from tpm2_pytss.binding import (
        TPM2_ALG_ECDSA,
        TPM2_ALG_RSA,
        TPM2_ALG_SHA256,
        TPM2_ECC_NIST_P256,
        TPM2_ECC_NIST_P384,
    )

    HAS_TPM2_PYTSS = True
except ImportError:
    HAS_TPM2_PYTSS = False
    TSS2_Context = None  # type: ignore[misc, assignment]
    TSS2_Exception = None  # type: ignore[misc, assignment]
    TPM2_ALG_ECDSA = None  # type: ignore[misc, assignment]
    TPM2_ALG_RSA = None  # type: ignore[misc, assignment]
    TPM2_ALG_SHA256 = None  # type: ignore[misc, assignment]
    TPM2_ECC_NIST_P256 = None  # type: ignore[misc, assignment]
    TPM2_ECC_NIST_P384 = None  # type: ignore[misc, assignment]


logger = logging.getLogger(__name__)

# ==============================================================================
# CONSTANTS
# ==============================================================================

DEFAULT_TPM_PATH: Final[str] = "/dev/tpm0"
TPM_RM_PATH: Final[str] = "/dev/tpmrm0"  # Resource manager

# TPM Algorithms
TPM_ALG_RSA: Final[int] = 0x0001
TPM_ALG_SHA256: Final[int] = 0x000B
TPM_ALG_SHA384: Final[int] = 0x000C
TPM_ALG_ECDSA: Final[int] = 0x0018
TPM_ALG_ECC: Final[int] = 0x0023
TPM_ALG_SYMCIPHER: Final[int] = 0x0025
TPM_ALG_KDF1_SP800_56A: Final[int] = 0x0020

# ECC Curves
TPM_ECC_NIST_P256: Final[int] = 0x0003
TPM_ECC_NIST_P384: Final[int] = 0x0004

# Object Attributes
TPMA_OBJECT_FIXEDTPM: Final[int] = 0x00000002
TPMA_OBJECT_STCLEAR: Final[int] = 0x00000004
TPMA_OBJECT_FIXEDPARENT: Final[int] = 0x00000008
TPMA_OBJECT_SENSITIVEDATAORIGIN: Final[int] = 0x00000010
TPMA_OBJECT_USERWITHAUTH: Final[int] = 0x00000040
TPMA_OBJECT_SIGN_ENCRYPT: Final[int] = 0x00040000
TPMA_OBJECT_DECRYPT: Final[int] = 0x00020000

# PCR Banks
PCR_BANK_SHA256: Final[int] = 0x000B
PCR_BANK_SHA384: Final[int] = 0x000C


# ==============================================================================
# ENUMS
# ==============================================================================


class TPMKeyType(Enum):
    """Типы ключей TPM."""

    RSA_2048 = "rsa-2048"
    RSA_3072 = "rsa-3072"
    ECC_P256 = "ecc-p256"
    ECC_P384 = "ecc-p384"


class TPMSealType(Enum):
    """Типы seal операций TPM."""

    PCR = "pcr"  # Seal to PCR values
    AUTH = "auth"  # Seal to authorization
    POLICY = "policy"  # Seal to policy


# ==============================================================================
# DATACLASSES
# ==============================================================================


@dataclass(frozen=True)
class TPMKeyInfo:
    """
    Информация о ключе TPM.

    Attributes:
        key_name: Имя ключа (пользовательское).
        key_handle: TPM handle (persistent или transient).
        key_type: Тип ключа (RSA, ECC).
        key_size: Размер ключа в битах.
        public_key: Публичный ключ (DER/PEM формат).
        attributes: TPM object attributes.
        creation_data: Данные создания ключа.

    Example:
        >>> info = TPMKeyInfo(
        ...     key_name="sign_key",
        ...     key_handle=0x81000001,
        ...     key_type="ECC-P256",
        ...     key_size=256,
        ...     public_key=b"...",
        ... )
    """

    key_name: str
    key_handle: int
    key_type: str
    key_size: int
    public_key: bytes
    attributes: int = 0
    creation_data: bytes = b""


@dataclass
class TPMPolicy:
    """
    Policy для seal/unseal операций.

    Attributes:
        pcr_selection: Список PCR индексов (например, [0, 1, 2]).
        pcr_digest: Ожидаемый PCR digest (если None — текущие значения).
        auth_value: Дополнительный auth value для seal.
        policy_digest: Pre-computed policy digest (опционально).

    Example:
        >>> policy = TPMPolicy(
        ...     pcr_selection=[0, 1, 2, 7],
        ...     auth_value=b"optional_auth",
        ... )
    """

    pcr_selection: list[int] = field(default_factory=list)
    pcr_digest: bytes | None = None
    auth_value: bytes | None = None
    policy_digest: bytes | None = None


@dataclass(frozen=True)
class TPMCapabilities:
    """
    Возможности TPM устройства.

    Attributes:
        manufacturer: Производитель TPM.
        firmware_version: Версия прошивки.
        supported_algorithms: Поддерживаемые алгоритмы.
        max_key_size: Максимальный размер ключа.
        pcr_count: Количество PCR registers.
        pcr_banks: Доступные PCR banks.

    Example:
        >>> caps = TPMCapabilities(
        ...     manufacturer="INFINEON",
        ...     firmware_version="7.85.4555.0",
        ...     supported_algorithms=["RSA", "ECC", "SHA256"],
        ... )
    """

    manufacturer: str
    firmware_version: str
    supported_algorithms: tuple[str, ...]
    max_key_size: int
    pcr_count: int
    pcr_banks: tuple[str, ...]


# ==============================================================================
# TPM BACKEND
# ==============================================================================


class TPMBackend:
    """
    TPM 2.0 backend для ключей и криптографических операций.

    Предоставляет единый интерфейс для работы с TPM 2.0 устройствами.
    Использует tpm2-pytss если доступен, иначе fallback на tpm2-tools CLI.

    Основные операции:
        - create_key: Создание ключевой пары в TPM.
        - sign: Подпись данных через TPM ключ.
        - seal: Seal данных к PCR state.
        - unseal: Распаковка sealed данных.
        - get_random: Получение случайных байтов от TPM TRNG.

    Example:
        >>> backend = TPMBackend("/dev/tpm0")
        >>> if backend.is_available():
        ...     # Create signing key
        ...     pub = backend.create_key("sign_key", {"type": "ecc-p256"})
        ...     # Sign data
        ...     digest = hashlib.sha256(b"data").digest()
        ...     sig = backend.sign("sign_key", digest)

    Security Note:
        Приватные ключи никогда не покидают TPM.
    """

    def __init__(self, tpm_path: str = DEFAULT_TPM_PATH):
        """
        Инициализация TPM backend.

        Args:
            tpm_path: Путь к TPM устройству (default: /dev/tpm0).

        Raises:
            DeviceNotFoundError: TPM устройство не найдено.
        """
        self._tpm_path = tpm_path
        self._ctx: Any | None = None
        self._keys: dict[str, TPMKeyInfo] = {}  # Cache of loaded keys

        # Check if TPM exists
        if not os.path.exists(tpm_path):
            raise DeviceNotFoundError(
                device_id=tpm_path,
                reason=f"TPM device not found: {tpm_path}",
            )

        logger.debug("TPMBackend initialized: path=%s", tpm_path)

    def __enter__(self) -> TPMBackend:
        """Контекстный менеджер."""
        self._ensure_context()
        return self

    def __exit__(self, *_: object) -> None:
        """Контекстный менеджер cleanup."""
        self.close()

    def __repr__(self) -> str:
        """Строковое представление."""
        status = "initialized" if self._ctx else "not initialized"
        return f"TPMBackend(path={self._tpm_path!r}, {status})"

    # ------------------------------------------------------------------
    # CONTEXT MANAGEMENT
    # ------------------------------------------------------------------

    def _ensure_context(self) -> Any:
        """Убедиться, что TPM context инициализирован."""
        if self._ctx is not None:
            return self._ctx

        if HAS_TPM2_PYTSS:
            try:
                self._ctx = TSS2_Context(self._tpm_path)
                logger.debug("TPM context created via tpm2-pytss")
                return self._ctx
            except Exception as exc:
                logger.warning("Failed to create TPM context: %s", exc)
                raise DeviceCommunicationError(
                    device_id=self._tpm_path,
                    reason=f"Failed to initialize TPM: {exc}",
                ) from exc
        else:
            logger.warning("tpm2-pytss not available, using CLI fallback")
            self._ctx = "cli_fallback"
            return self._ctx

    def close(self) -> None:
        """Закрытие TPM context и очистка ресурсов."""
        if self._ctx is not None and HAS_TPM2_PYTSS:
            try:
                if hasattr(self._ctx, "close"):
                    self._ctx.close()
            except Exception as exc:
                logger.debug("Error closing TPM context: %s", exc)
        self._ctx = None
        self._keys.clear()
        logger.debug("TPMBackend closed")

    def is_available(self) -> bool:
        """Проверка доступности TPM устройства."""
        if not os.path.exists(self._tpm_path):
            return False

        try:
            # Try to get capabilities
            self.get_random(1)
            return True
        except Exception as exc:
            logger.debug("TPM availability check failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # KEY OPERATIONS
    # ------------------------------------------------------------------

    def create_key(self, key_name: str, policy: dict[str, Any] | None = None) -> bytes:
        """
        Создание ключа в TPM.

        Создаёт primary key и возвращает публичный ключ.
        Приватный ключ генерируется в TPM и никогда не экспортируется.

        Args:
            key_name: Имя ключа для идентификации.
            policy: Policy параметры:
                - type: "rsa-2048", "rsa-3072", "ecc-p256", "ecc-p384" (default: ecc-p256)
                - persistent: bool — сохранить в NV (default: True)
                - auth: str — auth value (default: None)
                - sign: bool — ключ для подписи (default: True)
                - decrypt: bool — ключ для расшифровки (default: False)

        Returns:
            Публичный ключ в формате SubjectPublicKeyInfo (DER).

        Raises:
            KeyGenerationError: Ошибка генерации ключа.
            InvalidKeyError: Неподдерживаемый тип ключа.

        Example:
            >>> backend = TPMBackend("/dev/tpm0")
            >>> pub_key = backend.create_key("my_key", {"type": "ecc-p256"})
            >>> print(f"Created key: {len(pub_key)} bytes")
        """
        policy = policy or {}
        key_type = policy.get("type", "ecc-p256").lower()
        persistent = policy.get("persistent", True)
        auth_value = policy.get("auth")
        sign = policy.get("sign", True)
        decrypt = policy.get("decrypt", False)

        # Validate key type
        valid_types = ["rsa-2048", "rsa-3072", "ecc-p256", "ecc-p384"]
        if key_type not in valid_types:
            raise InvalidKeyError(
                f"Unsupported key type: {key_type}. Valid: {', '.join(valid_types)}",
                algorithm=key_type,
            )

        if HAS_TPM2_PYTSS:
            return self._create_key_pytss(key_name, key_type, persistent, auth_value, sign, decrypt)
        else:
            return self._create_key_cli(key_name, key_type, persistent, auth_value, sign, decrypt)

    def _create_key_pytss(
        self,
        key_name: str,
        key_type: str,
        persistent: bool,
        auth_value: str | None,
        sign: bool,
        decrypt: bool,
    ) -> bytes:
        """Create key using tpm2-pytss."""
        # Implementation would use actual TSS2 API
        # This is a placeholder for the actual implementation
        raise NotImplementedError("tpm2-pytss integration requires additional implementation")

    def _create_key_cli(
        self,
        key_name: str,
        key_type: str,
        persistent: bool,
        auth_value: str | None,
        sign: bool,
        decrypt: bool,
    ) -> bytes:
        """Create key using tpm2-tools CLI."""
        # Map key type to tpm2-tools options
        type_map = {
            "rsa-2048": "rsa2048",
            "rsa-3072": "rsa3072",
            "ecc-p256": "ecc256",
            "ecc-p384": "ecc384",
        }

        tpm_type = type_map.get(key_type, "ecc256")

        # Build command
        # Use tempfile for secure temporary file storage
        ctx_file = tempfile.NamedTemporaryFile(
            prefix=f"tpm_{key_name}_", suffix=".ctx", delete=False
        )
        ctx_file.close()
        ctx_path = ctx_file.name

        cmd = [
            "tpm2_createprimary",
            "-T",
            f"device:{self._tpm_path}",
            "-C",
            "o",  # Owner hierarchy
            "-g",
            "sha256",
            "-G",
            tpm_type,
            "-c",
            ctx_path,
        ]

        if auth_value:
            cmd.extend(["-p", auth_value])

        if sign:
            cmd.append("-a")
            cmd.append("sign")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            logger.info("TPM key created via CLI: %s", key_name)

            # Read public key using tempfile
            pub_temp = tempfile.NamedTemporaryFile(
                prefix=f"tpm_{key_name}_", suffix=".pub", delete=False
            )
            pub_temp.close()
            pub_path = pub_temp.name
            pub_cmd = [
                "tpm2_readpublic",
                "-T",
                f"device:{self._tpm_path}",
                "-c",
                ctx_path,
                "-o",
                pub_path,
            ]
            subprocess.run(pub_cmd, capture_output=True, check=True)

            with open(pub_path, "rb") as f:
                public_key = f.read()

            # Cleanup temp files after reading
            try:
                os.unlink(ctx_path)
                os.unlink(pub_path)
            except OSError:
                pass

            # Make persistent if requested
            if persistent:
                # Find first available persistent handle
                persist_cmd = [
                    "tpm2_evictcontrol",
                    "-T",
                    f"device:{self._tpm_path}",
                    "-C",
                    "o",
                    "-c",
                    ctx_path,
                    "-o",
                    "0x81000001",  # Fixed for demo, should find available
                ]
                try:
                    subprocess.run(persist_cmd, capture_output=True, check=True)
                except subprocess.CalledProcessError:
                    logger.warning("Failed to make key persistent")

            return public_key

        except subprocess.CalledProcessError as exc:
            raise KeyGenerationError(
                f"TPM key creation failed: {exc.stderr}",
                algorithm=key_type,
            ) from exc
        except FileNotFoundError as exc:
            raise AlgorithmNotAvailableError(
                algorithm="TPM",
                reason="tpm2-tools not installed",
                required_library="tpm2-tools",
            ) from exc

    def sign(self, key_handle: str | int, data: bytes) -> bytes:
        """
        Подпись через TPM.

        Args:
            key_handle: Имя ключа или TPM handle.
            data: Данные для подписи (digest).

        Returns:
            Подпись в соответствующем формате.

        Raises:
            HardwareDeviceError: Ошибка подписи.

        Example:
            >>> backend = TPMBackend("/dev/tpm0")
            >>> digest = hashlib.sha256(b"data").digest()
            >>> sig = backend.sign("my_key", digest)
        """
        if HAS_TPM2_PYTSS:
            return self._sign_pytss(key_handle, data)
        else:
            return self._sign_cli(key_handle, data)

    def _sign_pytss(self, key_handle: str | int, data: bytes) -> bytes:
        """Sign using tpm2-pytss."""
        raise NotImplementedError("tpm2-pytss sign requires additional implementation")

    def _sign_cli(self, key_handle: str | int, data: bytes) -> bytes:
        """Sign using tpm2-tools CLI."""
        # Use tempfile for secure temporary file storage
        ctx_temp = tempfile.NamedTemporaryFile(
            prefix=f"tpm_{key_handle}_", suffix=".ctx", delete=False
        )
        ctx_temp.close()
        ctx_path = ctx_temp.name

        # Write data to temp file
        data_temp = tempfile.NamedTemporaryFile(prefix="tpm_sign_", suffix=".in", delete=False)
        data_temp.close()
        data_path = data_temp.name
        with open(data_path, "wb") as f:
            f.write(data)

        sig_temp = tempfile.NamedTemporaryFile(prefix="tpm_sign_", suffix=".sig", delete=False)
        sig_temp.close()
        sig_path = sig_temp.name

        try:
            cmd = [
                "tpm2_sign",
                "-T",
                f"device:{self._tpm_path}",
                "-c",
                ctx_path,
                "-g",
                "sha256",
                "-o",
                sig_path,
                data_path,
            ]
            subprocess.run(cmd, capture_output=True, check=True)

            with open(sig_path, "rb") as f:
                signature = f.read()

            logger.info("TPM sign complete: sig_len=%d", len(signature))
            return signature

        except subprocess.CalledProcessError as exc:
            raise HardwareDeviceError(
                f"TPM sign failed: {exc.stderr}",
                device_id=str(key_handle),
            ) from exc
        finally:
            # Cleanup
            for f in [ctx_path, data_path, sig_path]:
                try:
                    os.remove(f)
                except FileNotFoundError:
                    pass

    # ------------------------------------------------------------------
    # SEAL/UNSEAL
    # ------------------------------------------------------------------

    def seal(self, data: bytes, policy: dict[str, Any]) -> bytes:
        """
        Seal данных к PCR state.

        Шифрует данные так, что они могут быть расшифрованы только
        при определённых значениях PCR (Platform Configuration Registers).

        Args:
            data: Данные для seal (макс 128 байт для большинства TPM).
            policy: Policy для seal:
                - pcr: список PCR индексов [0, 1, 2, ...]
                - auth: дополнительный auth value
                - hash: hash algorithm (default: sha256)

        Returns:
            Sealed blob (TPM2B_PRIVATE + TPM2B_PUBLIC).

        Raises:
            HardwareDeviceError: Ошибка seal.

        Example:
            >>> backend = TPMBackend("/dev/tpm0")
            >>> sealed = backend.seal(
            ...     b"secret",
            ...     policy={"pcr": [0, 1, 2, 7]}
            ... )
        """
        pcr_list = policy.get("pcr", [])
        auth_value = policy.get("auth")
        hash_alg = policy.get("hash", "sha256")

        if len(data) > 128:
            raise HardwareDeviceError(
                "Data too large for TPM seal (max 128 bytes)",
                device_id=self._tpm_path,
            )

        if HAS_TPM2_PYTSS:
            return self._seal_pytss(data, pcr_list, auth_value, hash_alg)
        else:
            return self._seal_cli(data, pcr_list, auth_value, hash_alg)

    def _seal_pytss(
        self, data: bytes, pcr_list: list[int], auth_value: str | None, hash_alg: str
    ) -> bytes:
        """Seal using tpm2-pytss."""
        raise NotImplementedError("tpm2-pytss seal requires additional implementation")

    def _seal_cli(
        self, data: bytes, pcr_list: list[int], auth_value: str | None, hash_alg: str
    ) -> bytes:
        """Seal using tpm2-tools CLI."""
        # Use tempfile for secure temporary file storage
        data_temp = tempfile.NamedTemporaryFile(prefix="tpm_seal_", suffix=".in", delete=False)
        data_temp.close()
        data_file = data_temp.name

        sealed_temp = tempfile.NamedTemporaryFile(prefix="tpm_seal_", suffix=".priv", delete=False)
        sealed_temp.close()
        sealed_file = sealed_temp.name

        pub_temp = tempfile.NamedTemporaryFile(prefix="tpm_seal_", suffix=".pub", delete=False)
        pub_temp.close()
        pub_file = pub_temp.name

        with open(data_file, "wb") as f:
            f.write(data)

        policy_file = None
        try:
            # Create policy if PCRs specified
            if pcr_list:
                policy_temp = tempfile.NamedTemporaryFile(
                    prefix="tpm_seal_", suffix=".pcr", delete=False
                )
                policy_temp.close()
                policy_file = policy_temp.name
                pcr_str = "sha256:" + ",".join(str(p) for p in pcr_list)
                cmd = [
                    "tpm2_policypcr",
                    "-T",
                    f"device:{self._tpm_path}",
                    "-l",
                    pcr_str,
                    "-L",
                    policy_file,
                ]
                subprocess.run(cmd, capture_output=True, check=True)

            # Create sealed object
            cmd = [
                "tpm2_create",
                "-T",
                f"device:{self._tpm_path}",
                "-C",
                "o",  # Owner hierarchy
                "-i",
                data_file,
                "-r",
                sealed_file,
                "-u",
                pub_file,
            ]

            if policy_file:
                cmd.extend(["-L", policy_file])
            if auth_value:
                cmd.extend(["-p", auth_value])

            subprocess.run(cmd, capture_output=True, check=True)

            # Read sealed data
            with open(sealed_file, "rb") as f:
                sealed_private = f.read()
            with open(pub_file, "rb") as f:
                sealed_public = f.read()

            # Return combined blob
            result = len(sealed_private).to_bytes(2, "big") + sealed_private
            result += len(sealed_public).to_bytes(2, "big") + sealed_public

            logger.info("TPM seal complete: sealed_len=%d", len(result))
            return result

        except subprocess.CalledProcessError as exc:
            raise HardwareDeviceError(
                f"TPM seal failed: {exc.stderr}",
                device_id=self._tpm_path,
            ) from exc
        finally:
            # Cleanup
            for f in [data_file, sealed_file, pub_file, policy_file]:
                if f:
                    try:
                        os.remove(f)
                    except FileNotFoundError:
                        pass

    def unseal(self, sealed_data: bytes) -> bytes:
        """
        Unseal данных.

        Расшифровывает данные, ранее sealed через seal().
        Требует соответствия PCR values (если использовался PCR policy).

        Args:
            sealed_data: Sealed blob от seal().

        Returns:
            Исходные данные.

        Raises:
            HardwareDeviceError: Ошибка unseal (PCR mismatch и т.д.).

        Example:
            >>> backend = TPMBackend("/dev/tpm0")
            >>> sealed = backend.seal(b"secret", policy={"pcr": [0, 1]})
            >>> # ... после перезагрузки с теми же PCR values ...
            >>> secret = backend.unseal(sealed)
        """
        if HAS_TPM2_PYTSS:
            return self._unseal_pytss(sealed_data)
        else:
            return self._unseal_cli(sealed_data)

    def _unseal_pytss(self, sealed_data: bytes) -> bytes:
        """Unseal using tpm2-pytss."""
        raise NotImplementedError("tpm2-pytss unseal requires additional implementation")

    def _unseal_cli(self, sealed_data: bytes) -> bytes:
        """Unseal using tpm2-tools CLI."""
        # Use tempfile for secure temporary file storage
        priv_temp = tempfile.NamedTemporaryFile(prefix="tpm_unseal_", suffix=".priv", delete=False)
        priv_temp.close()
        priv_file = priv_temp.name

        pub_temp = tempfile.NamedTemporaryFile(prefix="tpm_unseal_", suffix=".pub", delete=False)
        pub_temp.close()
        pub_file = pub_temp.name

        ctx_temp = tempfile.NamedTemporaryFile(prefix="tpm_unseal_", suffix=".ctx", delete=False)
        ctx_temp.close()
        ctx_file = ctx_temp.name

        out_temp = tempfile.NamedTemporaryFile(prefix="tpm_unseal_", suffix=".out", delete=False)
        out_temp.close()
        out_file = out_temp.name

        try:
            # Parse sealed data
            priv_len = int.from_bytes(sealed_data[:2], "big")
            priv_data = sealed_data[2 : 2 + priv_len]
            pub_offset = 2 + priv_len
            pub_len = int.from_bytes(sealed_data[pub_offset : pub_offset + 2], "big")
            pub_data = sealed_data[pub_offset + 2 : pub_offset + 2 + pub_len]

            with open(priv_file, "wb") as f:
                f.write(priv_data)
            with open(pub_file, "wb") as f:
                f.write(pub_data)

            # Load sealed object
            cmd = [
                "tpm2_load",
                "-T",
                f"device:{self._tpm_path}",
                "-C",
                "o",
                "-r",
                priv_file,
                "-u",
                pub_file,
                "-c",
                ctx_file,
            ]
            subprocess.run(cmd, capture_output=True, check=True)

            # Unseal
            cmd = [
                "tpm2_unseal",
                "-T",
                f"device:{self._tpm_path}",
                "-c",
                ctx_file,
                "-o",
                out_file,
            ]
            subprocess.run(cmd, capture_output=True, check=True)

            with open(out_file, "rb") as f:
                result = f.read()

            logger.info("TPM unseal complete: data_len=%d", len(result))
            return result

        except subprocess.CalledProcessError as exc:
            raise HardwareDeviceError(
                f"TPM unseal failed: {exc.stderr}",
                device_id=self._tpm_path,
            ) from exc
        finally:
            # Cleanup
            for f in [priv_file, pub_file, ctx_file, out_file]:
                try:
                    os.remove(f)
                except FileNotFoundError:
                    pass

    # ------------------------------------------------------------------
    # UTILITY
    # ------------------------------------------------------------------

    def get_random(self, num_bytes: int) -> bytes:
        """
        Получение случайных байтов от TPM TRNG.

        Использует аппаратный генератор случайных чисел TPM.

        Args:
            num_bytes: Количество байт (обычно макс 32 за раз).

        Returns:
            Случайные байты.

        Raises:
            HardwareDeviceError: Ошибка получения случайных данных.

        Example:
            >>> backend = TPMBackend("/dev/tpm0")
            >>> random_bytes = backend.get_random(32)
            >>> print(f"Got {len(random_bytes)} random bytes")
        """
        if HAS_TPM2_PYTSS:
            return self._get_random_pytss(num_bytes)
        else:
            return self._get_random_cli(num_bytes)

    def _get_random_pytss(self, num_bytes: int) -> bytes:
        """Get random using tpm2-pytss."""
        raise NotImplementedError("tpm2-pytss get_random requires additional implementation")

    def _get_random_cli(self, num_bytes: int) -> bytes:
        """Get random using tpm2-tools CLI."""
        # tpm2_getrandom outputs hex
        try:
            cmd = [
                "tpm2_getrandom",
                "-T",
                f"device:{self._tpm_path}",
                "--hex",
                str(num_bytes),
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            random_hex = result.stdout.strip()
            return bytes.fromhex(random_hex)
        except subprocess.CalledProcessError as exc:
            raise HardwareDeviceError(
                f"TPM get_random failed: {exc.stderr}",
                device_id=self._tpm_path,
            ) from exc
        except FileNotFoundError as exc:
            raise AlgorithmNotAvailableError(
                algorithm="TPM",
                reason="tpm2-tools not installed",
                required_library="tpm2-tools",
            ) from exc

    def get_capabilities(self) -> TPMCapabilities:
        """
        Получение возможностей TPM.

        Returns:
            TPMCapabilities с информацией об устройстве.

        Raises:
            HardwareDeviceError: Ошибка чтения capabilities.
        """
        try:
            cmd = [
                "tpm2_getcap",
                "-T",
                f"device:{self._tpm_path}",
                "properties-fixed",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            output = result.stdout

            # Parse manufacturer
            manufacturer = "Unknown"
            if "TPM2_PT_MANUFACTURER" in output:
                for line in output.split("\n"):
                    if "manufacturer" in line.lower():
                        parts = line.split(":")
                        if len(parts) > 1:
                            manufacturer = parts[1].strip()
                            break

            # Parse firmware
            firmware = "Unknown"
            if "TPM2_PT_FIRMWARE_VERSION" in output:
                for line in output.split("\n"):
                    if "firmware" in line.lower():
                        parts = line.split(":")
                        if len(parts) > 1:
                            firmware = parts[1].strip()
                            break

            return TPMCapabilities(
                manufacturer=manufacturer,
                firmware_version=firmware,
                supported_algorithms=("RSA", "ECC", "SHA256", "SHA384"),
                max_key_size=4096,
                pcr_count=24,
                pcr_banks=("SHA256",),
            )

        except subprocess.CalledProcessError as exc:
            raise HardwareDeviceError(
                f"Failed to get TPM capabilities: {exc.stderr}",
                device_id=self._tpm_path,
            ) from exc


# ==============================================================================
# EXPORTS
# ==============================================================================

__all__ = [
    "TPMBackend",
    "TPMKeyInfo",
    "TPMPolicy",
    "TPMCapabilities",
    "TPMKeyType",
    "TPMSealType",
    "DEFAULT_TPM_PATH",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-04-05"
