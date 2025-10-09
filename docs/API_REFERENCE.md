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
