# RU: Домейн-модель штрихкода с fail-fast валидацией, manifest уровней поддержки/опций, автогенератором и опциональным error recording.
# EN: Domain barcode/QR/ESC/P model with fail-fast validation, manifest for support/option allowlist, auto-generator, and optional error recording.

import base64
import logging
from dataclasses import asdict, dataclass, field
from typing import Any, ClassVar, Dict, Optional, Tuple, Type, Union

from src.barcodegen.barcode_generator import BarcodeGenerator, BarcodeGenError
from src.barcodegen.matrix2d_generator import (
    Matrix2DCodeGenerator,
    Matrix2DCodeGenError,
)

from .enums import BarcodeType, Matrix2DCodeType

logger = logging.getLogger(__name__)


@dataclass
class Barcode:
    """
    Domain-level dataclass for barcode/QR/2D/ESC/P code with:
        - Multi-layer validation (syntax, renderer, manifest)
        - Manifest: support level ("soft"/"hard"), generator, allowed options
        - Defensive validation: fail fast on invalid type/options
        - GUI-/API-friendly: errors recordable instead of throwing
        - Ready for signature/crypto validation and automated API docs

    Examples (integration):
        bc = Barcode(type=BarcodeType.EAN13, data="978014300723")
        ok = bc.validate(record_error=True)
        if not ok:
            print(bc.validation_error_message)
        # API autodocs
        manifest = Barcode.supported_matrix()
    """

    schema_version: ClassVar[str] = "1.0"

    type: Union[BarcodeType, Matrix2DCodeType]
    data: str
    caption: Optional[str] = None
    options: Dict[str, Any] = field(default_factory=dict)
    position: Optional[Tuple[int, int]] = None
    size: Optional[Tuple[int, int]] = None
    rotation: Optional[float] = None
    showlabel: bool = True
    foreground: Optional[str] = None
    background: Optional[str] = None
    gs1mode: Optional[bool] = None
    border: Optional[Dict[str, Any]] = None
    padding: Optional[Tuple[int, int, int, int]] = None
    opacity: Optional[float] = None
    zorder: Optional[int] = None

    parent_section: Optional[str] = None
    parent_table: Optional[str] = None
    anchor_id: Optional[str] = None
    user_label: Optional[str] = None
    object_id: Optional[str] = None
    readonly: bool = False
    hidden: bool = False

    datasource: Optional[str] = None
    auto_regenerate_on_save: bool = False

    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    created_by: Optional[str] = None
    updated_by: Optional[str] = None

    validation_state: Optional[str] = None
    validation_error_message: Optional[str] = None

    issignature: bool = False
    signaturetype: Optional[str] = None
    signature_payload: Optional[bytes] = None
    signer_info: Optional[str] = None
    signing_datetime: Optional[str] = None
    certificate_thumbprint: Optional[str] = None
    validation_status: Optional[str] = None
    validation_message: Optional[str] = None
    crypto_metadata: Dict[str, Any] = field(default_factory=dict)

    metadata: Dict[str, Any] = field(default_factory=dict)
    custom_fields: Dict[str, Any] = field(default_factory=dict)

    # ---- Central manifest: levels, allowlist, generators ----
    _GENERATOR_MANIFEST: ClassVar[Dict[str, Dict[str, Any]]] = {
        "1d": {
            "types": BarcodeGenerator.supported_types(),
            "generator": BarcodeGenerator,
            "err": BarcodeGenError,
            "level": "soft",
            "options_allowlist": {"showlabel", "foreground", "background"},
        },
        "2d": {
            "types": Matrix2DCodeGenerator.all_supported_types(),
            "generator": Matrix2DCodeGenerator,
            "err": Matrix2DCodeGenError,
            "level": "soft",
            "options_allowlist": {"gs1mode", "caption", "foreground", "background"},
        },
        "escp": {
            "types": set(),  # ESC/P barcode types, to be filled in production
            "generator": None,  # e.g. ESCBarcodeGenerator
            "err": None,  # e.g. ESCGenErrorException
            "level": "hard",
            "options_allowlist": {"border", "padding", "caption"},
        },
    }

    @classmethod
    def supported_matrix(cls) -> Dict[str, Dict[str, Any]]:
        """
        Returns the manifest: for each supported barcode type,
        its support level, generator key, allowed options, and other metadata.
        Used for API/GUI autodocs/checklists.
        """
        result: Dict[str, Dict[str, Any]] = {}
        for key, entry in cls._GENERATOR_MANIFEST.items():
            for t in entry["types"]:
                result[str(t)] = {
                    "layer": key,
                    "support_level": entry.get("level", "soft"),
                    "options_allowlist": list(entry.get("options_allowlist", [])),
                    "generator": entry["generator"],
                    "err": entry["err"],
                }
        return result

    def get_renderer(self) -> Any:
        """
        Returns the generator instance for this barcode type.
        Raises ValueError if not supported anywhere.
        """
        btype = self.type
        for gen_key, entry in self._GENERATOR_MANIFEST.items():
            if btype in entry["types"]:
                gen_cls: Type[Any] = entry["generator"]
                extra: Dict[str, Any] = {}
                if gen_key == "2d" and hasattr(self, "gs1mode"):
                    extra["gs1mode"] = self.gs1mode or False
                return gen_cls(btype, self.data, self.options, **extra)
        raise ValueError(f"Barcode type {btype} is not supported by any generator.")

    def _validate_options(self, allowlist: set[str]) -> None:
        """Defensive: ensure that options contains only allowlisted keys."""
        for k in self.options:
            if k not in allowlist:
                raise ValueError(
                    f"Option '{k}' not allowed for barcode type {self.type}"
                )

    def validate(self, record_error: bool = False) -> bool:
        """
        Validates the barcode object:
        - Syntax/field validation
        - Option allowlist validation from manifest
        - Attempt rendering using the proper generator (fail fast, production safe)
        - If record_error: on error, sets self.validation_error_message instead of raising

        Returns: True if ok, False if error (when record_error)
        Raises: ValueError if error and not record_error
        """
        logger.info("Validating Barcode: type=%r data=%r", self.type, self.data)
        try:
            result = self.supported_matrix().get(str(self.type), None)
            if not result:
                raise ValueError(
                    f"Barcode type {self.type} not found in manifest or not supported."
                )
            allowlist: set[str] = set(result["options_allowlist"])
            self._validate_options(allowlist)

            if not isinstance(self.type, (BarcodeType, Matrix2DCodeType)):
                raise ValueError(f"Invalid type: {self.type}")
            if not isinstance(self.data, str) or not self.data.strip():
                raise ValueError("Data must be a non-empty string")
            if self.position is not None and (
                not isinstance(self.position, tuple)
                or len(self.position) != 2
                or not all(isinstance(x, int) and x >= 0 for x in self.position)
            ):
                raise ValueError(f"Invalid position: {self.position}")
            if self.size is not None and (
                not isinstance(self.size, tuple)
                or len(self.size) != 2
                or not all(isinstance(x, int) and x > 0 for x in self.size)
            ):
                raise ValueError(f"Invalid size: {self.size}")
            if self.padding is not None and (
                not isinstance(self.padding, tuple)
                or len(self.padding) != 4
                or not all(isinstance(x, int) and x >= 0 for x in self.padding)
            ):
                raise ValueError(f"Invalid padding: {self.padding}")
            if self.opacity is not None and (
                not isinstance(self.opacity, float) or not (0.0 <= self.opacity <= 1.0)
            ):
                raise ValueError(f"Invalid opacity: {self.opacity}")
            if self.foreground is not None and not isinstance(self.foreground, str):
                raise ValueError(f"Invalid foreground color: {self.foreground}")
            if self.background is not None and not isinstance(self.background, str):
                raise ValueError(f"Invalid background color: {self.background}")

            renderer: Any = self.get_renderer()
            if hasattr(renderer, "validate"):
                renderer.validate()
            if hasattr(renderer, "renderimage"):
                _img: Any = renderer.renderimage(
                    width=32, height=32, options={"preview": True}
                )
                if _img is None:
                    raise ValueError("Generator failed to return image")

            self.validation_state = "ok"
            self.validation_error_message = None
            return True
        except Exception as ex:
            msg: str = str(ex)
            logger.warning("Barcode validation error: %s", msg)
            self.validation_state = "invalid"
            self.validation_error_message = msg
            if record_error:
                return False
            raise

    def to_dict(self) -> Dict[str, Any]:
        dct: Dict[str, Any] = asdict(self)
        dct["schema_version"] = self.schema_version
        if self.signature_payload is not None:
            dct["signature_payload"] = base64.b64encode(self.signature_payload).decode(
                "ascii"
            )
        return dct

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Barcode":
        d = dict(d)
        if "schema_version" in d and d["schema_version"] != cls.schema_version:
            logger.warning(
                "Schema version mismatch (expected %s, got %s)",
                cls.schema_version,
                d["schema_version"],
            )
        if "signature_payload" in d and d["signature_payload"]:
            d["signature_payload"] = base64.b64decode(d["signature_payload"])
        d.pop("schema_version", None)
        return cls(**d)

    def __str__(self) -> str:
        siginfo: str = "SIG" if self.issignature else ""
        datashow: str = self.data[:16] + ("..." if len(self.data) > 16 else "")
        return f"Barcode({self.type}, data={datashow}{siginfo})"
