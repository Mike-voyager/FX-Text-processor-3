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
