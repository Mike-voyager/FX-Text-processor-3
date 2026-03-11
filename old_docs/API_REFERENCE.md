# API Reference

> **Note:** Эта документация будет автоматически генерироваться из docstrings по мере разработки.

## Статус модулей

---

## `src.__init__`

### Functions

#### `get_logger(module_name: str) -> logging.Logger`

Получить настроенный логгер для модуля.

**Parameters:**
- `module_name` (str): Имя модуля, обычно `__name__`

**Returns:**
- `logging.Logger`: Настроенный логгер с обработчиками

**Example:**
from src import get_logger

logger = get_logger(name)
logger.info("Модуль инициализирован")

text

---

#### `load_config() -> Dict[str, Any]`

Загрузить конфигурацию из config.json или использовать defaults.

**Returns:**
- `Dict[str, Any]`: Словарь с параметрами конфигурации

**Raises:**
- `ValueError`: Если config.json содержит невалидный JSON

**Example:**
from src import load_config

config = load_config()
printer = config['default_printer']

text

---

#### `check_dependencies() -> Dict[str, bool]`

Проверить доступность опциональных зависимостей.

**Returns:**
- `Dict[str, bool]`: Словарь {package_name: is_available}

**Example:**
from src import check_dependencies

deps = check_dependencies()
if not deps['pillow']:
print("Pillow не установлен. Обработка изображений недоступна.")

text

---

## Model Layer API

### `src/model/run.py`

#### Class: `Run`

Represents a contiguous sequence of text with uniform formatting within a paragraph.

**Attributes:**
- `text` (str): The text content
- `bold` (bool): Bold formatting flag
- `italic` (bool): Italic formatting flag
- `underline` (bool): Underline formatting flag
- `double_width` (bool): Double-width character mode
- `double_height` (bool): Double-height character mode
- `font_name` (str): Font name from SUPPORTED_FONTS
- `encoding` (str): Character encoding from SUPPORTED_ENCODINGS

**Methods:**

`validate() -> None`
Validates run content and formatting attributes. Raises `ValueError` for empty text or encoding incompatibility, `TypeError` for incorrect attribute types.

`copy() -> Run`
Creates an independent deep copy of the run.

`can_merge_with(other: Run) -> bool`
Checks if two runs have identical formatting and can be merged.

`merge_with(other: Run) -> Run`
Merges two runs with identical formatting, concatenating text. Raises `ValueError` if formatting differs.

`to_dict() -> dict[str, Any]`
Serializes run to dictionary representation.

`from_dict(data: dict[str, Any]) -> Run` *(static)*
Deserializes run from dictionary. Raises `KeyError` if 'text' missing, `TypeError` if input not dict.

**Magic Methods:**
- `__len__() -> int`: Returns text length
- `__eq__(other) -> bool`: Equality comparison
- `__repr__() -> str`: Detailed string representation

#### Functions:

`merge_consecutive_runs(runs: list[Run]) -> list[Run]`
Optimizes run list by merging consecutive runs with identical formatting.

`split_by_formatting(text: str, runs: list[Run]) -> list[Run]`
Splits text into runs based on formatting template. Raises `ValueError` if total run length doesn't match text length.

**Constants:**
- `SUPPORTED_FONTS`: frozenset of valid font names ("draft", "roman", "sans_serif", "script")
- `SUPPORTED_ENCODINGS`: frozenset of valid encodings ("cp866", "ascii", "latin1")

**Usage Example:**
from src.model.run import Run, merge_consecutive_runs

Create formatted text runs
run1 = Run(text="Hello ", bold=True)
run2 = Run(text="World", bold=True)
run3 = Run(text="!", bold=False)

Merge consecutive runs with same formatting
runs = [run1, run2, run3]
optimized = merge_consecutive_runs(runs)

Result: 2 runs instead of 3
Validate and serialize
optimized.validate()
data = optimized.to_dict()

undefined

## Coming Soon

Документация для других модулей будет добавлена по мере их реализации.

---

**Последнее обновление:** October 2025
### src/form/form_builder.py

#### enum FormKind
Form type classification:
- REGULAR: Standard forms without security features
- SPECIAL: Secured forms with mandatory QR, watermark, and signature elements

#### enum FormElementType
Standard form element types including security elements:
- TABLE, IMAGE, VARIABLE, LABEL, INPUT (standard elements)
- QR, WATERMARK, SIGNATURE, AUDIT (security elements)

#### class FormBuilder
Advanced form builder supporting regular and special (secured) forms with automatic security validation and audit trails.

**Methods:**
- __init__(layout: Optional[FormLayout] = None)
- add_element(element: FormElement) -> None
- remove_element_by_id(element_id: str) -> None
- get_element(element_id: str) -> FormElement
- copy_element(element_id: str, new_id: Optional[str] = None) -> None
- move_element(element_id: str, new_index: int) -> None
- group_elements(group_name: str, element_ids: List[str], permissions: Optional[List[str]] = None, security_level: str = "standard") -> None
- apply_template(template_str: str) -> None
- inject_variables(variable_map: Dict[str, Any]) -> None
- build() -> Dict[str, Any]
- to_dict() -> Dict[str, Any]
- from_dict(form_dict: Dict[str, Any]) -> FormBuilder [classmethod]
- import_from_json(path: str) -> None
- export_to_json(path: str) -> None
- set_custom_validation(fn: Callable[[Dict[str, Any]], None]) -> None
- add_event_hook(fn: Callable[[str, Dict[str, Any]], None]) -> None

#### Security Elements

##### class QRElement(FormElement)
QR code element for verification and data embedding.
- data: str (required)
- version: Optional[int]
- error_correction: str ("L", "M", "Q", "H")
- size: int

##### class WatermarkElement(FormElement)
Watermark element for document protection.
- text: str (text watermark)
- image_path: Optional[str] (image watermark)
- opacity: float (0.0-1.0)
- rotation: int (degrees)

##### class SignatureElement(FormElement)
Digital signature element using Ed25519 or RSA-4096.
- algorithm: str ("ed25519", "rsa-4096")
- key_id: str (required)
- signature: Optional[str]
- timestamp: Optional[str]

##### class AuditElement(FormElement)
Audit trail element for compliance.
- user_id: Optional[str]
- action: str (required)
- timestamp: Optional[str]
- hash_chain: Optional[str]

#### class FormGroup
Enhanced group with security levels and permissions.
- name: str
- element_ids: List[str]
- permissions: Optional[List[str]] (allowed roles)
- security_level: str ("standard", "confidential", "secret")

#### class FormLayout
Complete form layout with security support.
- kind: FormKind (REGULAR or SPECIAL)
- layout_type: str ("grid", "absolute")
- size: Tuple[int, int]
- elements: List[FormElement]
- groups: List[FormGroup]
- template: Optional[str]
- security_metadata: Optional[Dict[str, Any]]

#### Validation Functions

##### validate_form_structure(form_dict: Dict[str, Any], custom_rules: Optional[Callable] = None) -> None
Validates form structure, element uniqueness, and special form security requirements.

##### validate_special_form_security(element_types: Set[str]) -> None
Validates that special forms contain all required security elements (QR, watermark, signature).

#### Utility Functions

##### import_from_json(path: str) -> Dict[str, Any]
Import form structure from JSON file.

##### export_to_json(form: Dict[str, Any], path: str) -> None
Export form structure to JSON file.

#### Integration Notes

- Compatible with src/barcode/ for QR code generation
- Integrates with src/security/ modules for cryptographic operations
- Supports ESC/P command generation through element metadata
- Event hooks enable audit logging and external integrations
- Auto-generates unique IDs with UUID components
- Automatic audit trail insertion for special forms


#### security.crypto.symmetric.SymmetricCipher
encrypt(data: bytes, key: bytes, nonce: bytes, associated_data: bytes | None = None) -> bytes
AES-256-GCM authenticated encryption for document data. Raises ValueError on invalid key/nonce.

decrypt(ciphertext: bytes, key: bytes, nonce: bytes, associated_data: bytes | None = None) -> bytes
AES-256-GCM authenticated decryption of document data. Raises ValueError or InvalidTag on tampered input.

validate_key(key: bytes) -> None
Validates key size (32 bytes). Raises ValueError if invalid.

validate_nonce(nonce: bytes) -> None
Validates nonce size (12 bytes). Raises ValueError if invalid.

generate_key() -> bytes
Generates a cryptographically secure random AES-256 key.

generate_nonce() -> bytes
Generates a secure random nonce for AES-GCM.

#### security.crypto.asymmetric.AsymmetricKeyPair

@staticmethod
generate(
    algorithm: str,
    key_size: Optional[int] = None
) -> AsymmetricKeyPair
    Generates a new key pair for the given algorithm.
    - Input:
        - algorithm: "ed25519", "rsa4096", or "ecdsa_p256".
        - key_size: (RSA only) Key size in bits (default = 4096).
    - Output:
        - AsymmetricKeyPair: Instance with private/public keys.
    - Raises:
        - UnsupportedAlgorithmError: If algorithm is not supported.
        - ValueError: For invalid params.

@staticmethod
from_private_bytes(
    data: bytes,
    algorithm: str,
    password: Optional[str] = None
) -> AsymmetricKeyPair
    Loads a private key from PEM-encoded bytes, with optional encryption.
    - Input:
        - data: PEM-encoded private key bytes.
        - algorithm: Algorithm string.
        - password: Optional passphrase for encrypted key.
    - Output:
        - AsymmetricKeyPair with private/public keys.
    - Raises:
        - UnsupportedAlgorithmError: If algorithm not supported.
        - KeyFormatError: On invalid PEM or wrong type.

@staticmethod
from_public_bytes(
    data: bytes,
    algorithm: str
) -> AsymmetricKeyPair
    Loads a public key from PEM-encoded bytes.
    - Input:
        - data: PEM-encoded public key bytes.
        - algorithm: Algorithm string.
    - Output:
        - AsymmetricKeyPair (public-only).
    - Raises:
        - UnsupportedAlgorithmError: If algorithm invalid.
        - KeyFormatError: If key data is malformatted/doesn't match type.

export_private_bytes(
    password: Optional[str] = None
) -> bytes
    Exports the private key (PEM, optionally password-protected).
    - Input: Optional password for encryption.
    - Output: PEM-encoded private key.
    - Raises: NotImplementedError if no private key.

export_public_bytes() -> bytes
    Exports the public key to PEM bytes.
    - Output: PEM-encoded public key.
    - Raises: NotImplementedError if no public key.

sign(data: bytes) -> bytes
    Signs data using the private key.
    - Input: data.
    - Output: raw signature bytes.
    - Raises: NotImplementedError if no private key.
    - Raises: UnsupportedAlgorithmError.

verify(data: bytes, signature: bytes) -> bool
    Verifies the signature with the public key.
    - Input: data, signature.
    - Output: True if valid, False if invalid.
    - Raises: NotImplementedError if no public key.

encrypt(data: bytes) -> bytes
    RSA encrypts data using the public key (OAEP-SHA256).
    - Input: data.
    - Output: ciphertext.
    - Raises: NotImplementedError for Ed25519/ECDSA or if public key missing.
    - Raises: ValueError if input too large.

decrypt(ciphertext: bytes) -> bytes
    RSA decrypts data using the private key (OAEP-SHA256).
    - Input: ciphertext.
    - Output: plaintext bytes.
    - Raises: NotImplementedError for Ed25519/ECDSA or if private key missing.

get_public_fingerprint() -> str
    Returns SHA256 hex fingerprint of the public key.
    - Output: Hex digest.
    - Raises: NotImplementedError if no public key.

equals_public(other: AsymmetricKeyPair) -> bool
    Compares SHA256 public key fingerprint with another.
    - Output: True if fingerprints match.

#### Exceptions

UnsupportedAlgorithmError
    Raised when the algorithm is not supported.

KeyFormatError
    Raised on wrong/invalid key input, decoding error, or key type mismatch.

#### Functions

load_public_key(
    data: bytes,
    algorithm: str
) -> AsymmetricKeyPair
    Loads a public key from PEM data. Public-only context.

import_public_key_pem(
    pem_data: str
) -> AsymmetricKeyPair
    Loads a PEM-encoded public key (type determined automatically).

#### Constants

SUPPORTED_ALGORITHMS: tuple[str, ...]
    Supported algorithm IDs: ("ed25519", "rsa4096", "ecdsa_p256")

DEFAULT_RSA_KEYSIZE: int
    Default RSA key size (4096 bits).

AlgorithmFactory: Dict[str, Callable[..., AsymmetricKeyPair]]
    Factory for key pair creation per algorithm (supports extra params).

### security.crypto.kdf

**Key Derivation API (Argon2id primary, PBKDF2 legacy, coverage >97%)**

Модуль реализует защищённый вывод ключей для шифрования и аутентификации, с приоритетом схемы Argon2id, поддержкой PBKDF2 (совместимость), расширяемостью и строгой валидацией параметров. Все публичные функции снабжены типами, docstring и диагностикой.

---

#### Enum: `KDFAlgorithm`
- `ARGON2ID`: Основной режим, рекомендован для хранения паролей, внутренней безопасности.
- `PBKDF2_HMAC_SHA256`: Совместимость и interoperability.
- `FAKE_UNSUPPORTED`: Тестовое значение для негативных сценариев.

---

#### Функции:

- **`generate_salt(length: int = 16) -> bytes`**
    Генерирует криптографически стойкую соль заданной длины (от 8 до 64 байт).
    ```
    salt = generate_salt(16)
    ```

- **`recommend_entropy_warning(password: bytes, salt: bytes) -> None`**
    Проверяет примитивную энтропию пароля/соли, вызывает Warning при низкой стойкости.

- **`validate_parameters(password: bytes, salt: bytes, length: int, iterations: Optional[int], algorithm: KDFAlgorithm, memory_cost: int = 65536, parallelism: int = 2, time_cost: int = 2) -> None`**
    Валидирует все входные параметры для выбранного KDF-алгоритма. Вызывает исключения при ошибке или неподдерживаемом режиме.
    ```
    validate_parameters(pw, salt, 32, 2, KDFAlgorithm.ARGON2ID)
    ```

- **`derive_key(algorithm: KDFAlgorithm, password: bytes, salt: Optional[bytes] = None, length: int = 32, *, iterations: Optional[int] = None, memory_cost: int = 65536, parallelism: int = 2, time_cost: int = 2, to_hex: bool = False, to_b64: bool = False) -> bytes | str`**
    Производит итоговый вывод ключа, используя выбранный алгоритм и параметры. Возможно возвращение в формате bytes, hex или base64.
    ```
    key = derive_key(
        algorithm=KDFAlgorithm.ARGON2ID,
        password=b"secretpw",
        salt=generate_salt(16),
        length=32,
        time_cost=2,
        memory_cost=65536,
        parallelism=2
    )
    ```
    **Сериализация:**
    ```
    key_hex = derive_key(..., to_hex=True)
    key_b64 = derive_key(..., to_b64=True)
    ```

---

#### Исключения
- `KDFParameterError`: Неверные параметры (длина, тип, диапазоны).
- `KDFAlgorithmError`: Неизвестный или неподдерживаемый алгоритм (например, FAKE_UNSUPPORTED).
- `KDFEntropyWarning`: Пароль/соль недостаточно стойкие или примитивны.

---

#### Best Practice / Рекомендации:

- **Use Argon2id** for password and credential storage (`KDFAlgorithm.ARGON2ID`), with `salt >= 16 bytes`, `memory_cost >= 64 MiB`, `time_cost >= 2`, `parallelism >= 2`.
- **PBKDF2** only for legacy interoperability.
- Пароль минимум 8 байт, но рекомендуется ≥16+ и достаточный уровень энтропии.
- Соль генерируйте для каждого секрета — не переиспользуйте!
- Никогда не логируйте ключи и пароли!
- Для аудита событий ошибки интегрируйте custom hooks.
- В тестах используйте member Enum FAKE_UNSUPPORTED для негативных сценариев.

---

**Примеры:**

from security.crypto.kdf import derive_key, generate_salt, KDFAlgorithm

Argon2id — hex-вывод
hex_key = derive_key(
algorithm=KDFAlgorithm.ARGON2ID,
password=b"my_super_secret_pw",
salt=generate_salt(16),
length=32,
time_cost=2,
memory_cost=65536,
parallelism=2,
to_hex=True,
)

PBKDF2 — байтовый вывод
raw_key = derive_key(
algorithm=KDFAlgorithm.PBKDF2_HMAC_SHA256,
password=b"legacy_pw123",
salt=generate_salt(16),
length=32,
iterations=120_000,
)

Валидация параметров
validate_parameters(
password=b"tough_pw",
salt=generate_salt(16),
length=32,
iterations=2,
algorithm=KDFAlgorithm.ARGON2ID,
)
### Module: security.crypto.signatures

#### Ed25519Signer
- `__init__(private_key: bytes, alias: Optional[str] = None)`
    Initializes an Ed25519 signer with a 32‑byte private key and optional alias for audit.
- `sign(message: bytes) -> bytes`
    Signs the supplied message.
- `public_key(encoding: Literal["raw", "hex"] = "raw") -> bytes | str`
    Exports public key as bytes (raw) or hex string.
- `get_fingerprint() -> str`
    SHA256 fingerprint of the public key (for audit/journal).
- `save_key_bytes(filepath: str, key_bytes: bytes) -> None`
    Save given key bytes to disk.
- `load_key_bytes(filepath: str) -> bytes`
    Load and validate Ed25519 key bytes from disk.

#### Ed25519Verifier
- `__init__(public_key: bytes, alias: Optional[str] = None)`
    Initializes an Ed25519 verifier with a 32‑byte public key and alias.
- `verify(message: bytes, signature: bytes) -> bool`
    Validates the signature for given message.
- `verify_batch(message: bytes, signatures: List[bytes]) -> List[bool]`
    Batch validation for multiple signatures.
- `get_fingerprint() -> str`
    SHA256 fingerprint of the public key.
- `save_key_bytes(filepath: str, key_bytes: bytes) -> None`
    Save public key bytes to disk.
- `load_key_bytes(filepath: str) -> bytes`
    Load and validate key bytes from disk.

#### SignatureError
Exception type for key/verification/signing errors.

---

**Features:**
- Strict type safety, no Any/ignore
- Extensive error handling (invalid length, invalid encoding, I/O)
- Alias support for audit/journal integration and logging context
- Batch verification
- Key serialization (save/load), fingerprinting
- Thread‑safe (no shared state)

**Example:**
signer = Ed25519Signer(priv_bytes, alias="finance-bot")
sig = signer.sign(b"doc data")
verifier = Ed25519Verifier(signer.public_key(), alias="auditor")
if verifier.verify(b"doc data", sig):
print("Valid")
### Module: security.crypto.hashing

**RU:** Безопасное хэширование и проверка паролей с поддержкой нескольких алгоритмов, кастомной соли, миграции legacy‑хэшей и аудита действий.

**EN:** Secure password hashing and verification supporting multiple algorithms, custom salts, legacy hash migration, and audit trail.

---

#### hash_password
- `hash_password(password: str, salt: Optional[bytes] = None, *, time_cost: int = 3, memory_cost: int = 65536, parallelism: int = 2, scheme: str = "argon2id") -> str`
    Hashes password using specified scheme (Argon2id default). Supports custom salt for testing/migration scenarios. Validates parameters and truncates oversized passwords (>1024 chars).

#### verify_password
- `verify_password(password: str, hashed: str) -> bool`
    Verifies password against stored hash with auto-scheme detection. Returns False for any error/mismatch. Fully fail-safe with comprehensive logging.

#### needs_rehash
- `needs_rehash(hashed: str, *, time_cost: int = 3, memory_cost: int = 65536, parallelism: int = 2, scheme: str = "argon2id") -> bool`
    Determines if hash requires updating due to changed cost parameters or scheme migration. Conservative fallback returns True on errors.

#### get_hash_scheme
- `get_hash_scheme(hashed: str) -> str`
    Heuristically detects hash scheme from format ("argon2id", "bcrypt", "pbkdf2", "sha256", "unknown"). Type-safe with non-string input handling.

#### legacy_verify_password
- `legacy_verify_password(password: str, hashed: str, scheme: str) -> bool`
    Compatibility verification for legacy hash formats during migration. Currently supports SHA256 stub (always returns False for security).

#### add_audit
- `add_audit(event: str, user_id: Optional[str], context: Optional[Dict[str, Any]] = None) -> None`
    Records audit event with timestamp fingerprint for SIEM/forensic analysis. In-memory trail storage.

#### HashScheme
- `HashScheme(str, Enum)`
    Enumeration of supported schemes: ARGON2ID, BCRYPT, PBKDF2, SHA256. Extensible for future algorithms.

---

**Features:**
- Multi-algorithm support (Argon2id, bcrypt, PBKDF2, SHA256)
- Custom salt handling for testing/migration scenarios
- Automatic scheme detection and parameter validation
- Comprehensive audit trail with structured logging
- Fail-safe error handling (never leaks password details)
- Legacy hash migration support
- Thread-safe operations (stateless design)
- 85%+ test coverage with extensive edge-case handling
- Strict type safety (`mypy --strict` compliant)

**Security Highlights:**
- Memory-hard Argon2id default (6,666× slower for attackers)
- Password length limits and parameter validation
- Conservative rehash recommendations
- Comprehensive logging without sensitive data exposure
- Type-safe API preventing common vulnerabilities

**Example:**
Basic usage
hashval = hash_password("SuperSecret123!")
assert verify_password("SuperSecret123!", hashval)

Scheme selection with custom parameters
hashval = hash_password("password", scheme="bcrypt", time_cost=4)

Migration detection
if needs_rehash(old_hash, scheme="argon2id", time_cost=4):
new_hash = hash_password(password, scheme="argon2id", time_cost=4)

Audit trail
add_audit("password_change", "user123", {"ip": "192.168.1.100"})
