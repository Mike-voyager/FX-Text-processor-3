# RU: Экспорт/импорт форм FX-Text-processor-3 (.fxsf, .fxsfs); floppy-валидатор, meta, checksum, secure-интеграция;
# плюс: версии, миграция, расширенная валидация, пакетная обработка, Protected Blanks, компрессия, резерв, форматы, локализация, диагностика, метрики.
"""Export/import for FX-Text-processor-3 forms (.fxsf – open, .fxsfs – secure), floppy validator, meta, checksum, seamless secure integration, versioning, migration, advanced validation, batch ops, Protected Blanks, compression, backup, external formats, localization, diagnostics, analytics."""

import base64
import gzip
import hashlib
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from src.form.form_schema import FormSchema

try:
    from src.security.blanks import BlankManager  # type: ignore
    from src.security.crypto import decrypt_bytes, encrypt_bytes  # type: ignore
except ImportError:
    encrypt_bytes = None
    decrypt_bytes = None
    BlankManager = None

MAX_FLOPPY_BYTES: int = 1_340_000  # 1.44 Mb floppy
MAX_IMAGE_EMBED: int = 100_000  # max image base64 size for floppy (100Kb)
SUPPORTED_VERSIONS: List[str] = ["1.0", "1.1"]


class ExportImportError(Exception):
    """Ошибка импорта/экспорта форм .fxsf/.fxsfs"""


def _get_now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ----- Версионирование -----
def migrate_form_version(form: dict, from_version: str, to_version: str) -> dict:
    """Мигрирует form между версиями схемы (stub)."""
    # Add actual migration logic here later
    result = dict(form)
    result["_migrated_from"] = from_version
    result["_migrated_to"] = to_version
    logging.info("Form migrated: %s → %s", from_version, to_version)
    return result


def get_supported_versions() -> List[str]:
    return list(SUPPORTED_VERSIONS)


def is_version_compatible(version: str) -> bool:
    return version in SUPPORTED_VERSIONS


# ----- Расширенная валидация -----
def validate_form_references(form: dict) -> List[str]:
    """Проверяет корректность ссылок: возвращает список ID несвязанных элементов."""
    bad = []
    ids = {el.get("id") for el in form.get("elements", []) if "id" in el}
    for el in form.get("elements", []):
        refs = el.get("refs", [])
        for rid in refs:
            if rid not in ids:
                bad.append(rid)
    if bad:
        logging.warning("Unresolved references: %s", bad)
    return bad


def check_circular_dependencies(form: dict) -> bool:
    """True если найдены циклические зависимости (stub, O(n))."""
    # Simple detection for 'refs' fields, more robust graph traversal can be added
    visited: Set[str] = set()
    stack: Set[str] = set()

    def visit(el: dict) -> bool:
        eid = el.get("id")
        if eid in stack:
            return True
        if eid:
            stack.add(eid)
        for rid in el.get("refs", []):
            rels = [e for e in form.get("elements", []) if e.get("id") == rid]
            for rel in rels:
                if visit(rel):
                    return True
        if eid:
            stack.remove(eid)
        return False

    for el in form.get("elements", []):
        if visit(el):
            logging.warning("Circular dependency found at %s", el.get("id"))
            return True
    return False


def validate_resource_availability(form: dict) -> Dict[str, bool]:
    """Проверяет, доступны ли ресурсы: embedded images/fonts."""
    ok = {}
    for el in form.get("elements", []):
        if el.get("type") == "image" and "base64" in el:
            try:
                base64.b64decode(el["base64"].encode())
                ok[el.get("id", "img")] = True
            except Exception:
                ok[el.get("id", "img")] = False
        if el.get("type") == "font":
            # font validation stub
            ok[el.get("id", "font")] = "name" in el and el["name"] != ""
    return ok


# ----- Компрессия и оптимизация -----
def compress_form_data(form: dict, level: int = 6) -> dict:
    """Компрессирует payload изображений gzip (base64), только большие элементы."""
    result = dict(form)
    compressed_elements = []
    for el in result.get("elements", []):
        el_copy = dict(el)
        if el_copy.get("type") == "image" and "base64" in el_copy:
            try:
                b = base64.b64decode(el_copy["base64"])
                if len(b) > MAX_IMAGE_EMBED // 2:
                    c = gzip.compress(b, compresslevel=level)
                    el_copy["base64_gzip"] = base64.b64encode(c).decode()
            except Exception:
                pass  # Keep original if compression fails
        compressed_elements.append(el_copy)
    result["elements"] = compressed_elements
    return result


def optimize_for_floppy(form: dict) -> dict:
    """Модифицирует форму, урезая embedded‑ресурсы и metadata до ограничений floppy."""
    optimized = dict(form)
    # Remove unused metadata, shrink images
    for el in optimized.get("elements", []):
        if el.get("type") == "image" and "base64" in el:
            try:
                img_data = base64.b64decode(el["base64"])
                if len(img_data) > MAX_IMAGE_EMBED:
                    el["base64"] = base64.b64encode(img_data[:MAX_IMAGE_EMBED]).decode()
            except Exception:
                pass  # Keep original if processing fails
    # Keep only essential metadata
    if "meta" in optimized:
        optimized["meta"] = {
            k: optimized["meta"][k]
            for k in optimized.get("meta", {})
            if k in {"id", "author"}
        }
    logging.info("Form optimized for floppy.")
    return optimized


# ----- Batch-операции и архивы -----
def export_form_batch(forms: List[Tuple[dict, str]], **kwargs: Any) -> List[bool]:
    """Пакетный экспорт нескольких форм на диск."""
    results = []
    for form, path in forms:
        try:
            export_form(form, path, **kwargs)
            results.append(True)
        except Exception as e:
            logging.error("Batch export failed:%s", e)
            results.append(False)
    return results


def import_form_batch(paths: List[str], **kwargs: Any) -> List[dict]:
    """Пакетный импорт нескольких форм с диска."""
    forms = []
    for p in paths:
        try:
            forms.append(import_form(p, **kwargs))
        except Exception as e:
            logging.error("Batch import failed:%s", e)
            forms.append({})
    return forms


def create_form_archive(forms: Dict[str, dict], archive_path: str) -> None:
    """Создаёт архив форм (.fxsa) — простой zip форм."""
    import zipfile

    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for fn, form in forms.items():
            data = serialize_fxsf(form)
            zf.writestr(f"{fn}.fxsf", data)
    logging.info("Form archive created: %s", archive_path)


# ----- Protected Blanks -----
def export_as_protected_blank(form: dict, blank_series: str, **kwargs: Any) -> str:
    """Экспортирует форму как защищённый бланк с использованием BlankManager (stub)."""
    if BlankManager is None:
        raise ExportImportError("BlankManager is unavailable")
    blank_mgr = BlankManager()
    blank_id = blank_mgr.issue_blank_series(blank_series, count=1, blank_type="form")
    blank_mgr.print_blank(
        blank_id, document=form, user_id=kwargs.get("user_id", "system")
    )
    logging.info("Form exported as protected blank: %s", blank_id)
    return str(blank_id)


def validate_blank_integrity(form: dict, blank_id: str) -> bool:
    """Проверяет целостность защищённого бланка через BlankManager (stub)."""
    if BlankManager is None:
        raise ExportImportError("BlankManager is unavailable")
    result = BlankManager().verify_blank(blank_id, form)
    return bool(result)


def track_blank_usage(blank_id: str, action: str) -> None:
    """Записывает событие использования бланка для аудита."""
    if BlankManager is None:
        raise ExportImportError("BlankManager is unavailable")
    BlankManager().track_usage(blank_id, action)
    logging.info("Blank %s usage tracked for action %s", blank_id, action)


# ----- Метрики и аналитика -----
def collect_export_metrics(form: dict, path: str) -> None:
    """Обновляет метрики по экспортируемой форме (stub)."""
    size = len(json.dumps(form).encode())
    logging.info("Export metrics: form_size=%d path=%s", size, path)
    # Integrate with monitoring if needed


def analyze_form_complexity(form: dict) -> Dict[str, float]:
    """Анализирует сложность формы: размер, количество элементов, вложенность (stub)."""
    elems = form.get("elements", [])
    depth = max([el.get("depth", 1) for el in elems], default=1)
    return {
        "element_count": float(len(elems)),
        "max_depth": float(depth),
        "form_bytes": float(len(json.dumps(form).encode())),
    }


def generate_compatibility_report(form: dict) -> Dict[str, Any]:
    """Генерирует отчёт по совместимости формы с редактором/принтером."""
    report = {
        "schema_version": form.get("schema_version", "unknown"),
        "floppy_fit": len(json.dumps(form).encode()) <= MAX_FLOPPY_BYTES,
        "image_embeds": [
            el for el in form.get("elements", []) if el.get("type") == "image"
        ],
        "unsupported_fields": [],
    }
    # Add more checks here as needed
    return report


# ----- Локализация и кодировки -----
def detect_form_encoding(form: dict) -> str:
    """Пытается выявить кодировку формы (stub)."""
    # Assume cp866 for Russian
    if any(
        "\u0400" <= ch <= "\u04ff"
        for el in form.get("elements", [])
        for ch in str(el.get("value", ""))
    ):
        return "cp866"
    return "utf-8"


def convert_form_encoding(form: dict, from_enc: str, to_enc: str) -> dict:
    """Конвертирует значения элементов между кодировками (stub)."""
    result = dict(form)
    for el in result.get("elements", []):
        if "value" in el:
            try:
                el["value"] = el["value"].encode(from_enc).decode(to_enc)
            except Exception:
                pass
    return result


def validate_charset_compatibility(form: dict, target_charset: str) -> List[str]:
    """Проверка на совместимость с target_charset (stub)."""
    bad = []
    for el in form.get("elements", []):
        if "value" in el:
            try:
                el["value"].encode(target_charset)
            except Exception:
                bad.append(el.get("id", "unknown"))
    return bad


# ----- Резервное копирование и восстановление -----
def create_form_backup(form: dict, backup_dir: str) -> str:
    """Создаёт резервную копию формы в директории backup_dir."""
    os.makedirs(backup_dir, exist_ok=True)
    fname = f"form_backup_{_get_now_iso().replace(':', '-')}.fxsf"
    path = os.path.join(backup_dir, fname)
    with open(path, "wb") as f:
        f.write(serialize_fxsf(form))
    logging.info("Form backup created at %s", path)
    return path


def restore_form_from_backup(backup_path: str) -> dict:
    """Восстанавливает форму из резервной копии."""
    return import_form(backup_path)


def cleanup_old_backups(backup_dir: str, retention_days: int) -> int:
    """Удаляет резервные копии старше retention_days дней."""
    if not os.path.exists(backup_dir):
        return 0
    now = datetime.utcnow().timestamp()
    c = 0
    for fname in os.listdir(backup_dir):
        if fname.startswith("form_backup_") and fname.endswith(".fxsf"):
            path = os.path.join(backup_dir, fname)
            ts = os.path.getmtime(path)
            if now - ts > retention_days * 86400:
                os.remove(path)
                c += 1
                logging.info("Backup deleted: %s", path)
    return c


# ----- Внешние форматы -----
def export_to_external_format(form: dict, format: str) -> bytes:
    """Экспортирует форму во внешний формат (PDF/RTF/HTML — stub)."""
    if format.lower() == "json":
        return json.dumps(form, ensure_ascii=False, indent=2).encode("utf-8")
    # For PDF/RTF/HTML, integrate converters later
    raise ExportImportError(f"Format {format} not supported yet")


def import_from_external(path: str, format: str) -> Dict[str, Any]:
    """Импортирует форму из внешнего файла."""
    if format.lower() == "json":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict):
                raise ExportImportError("Invalid format: expected dict in JSON")
            return data
    raise ExportImportError(f"Format {format} not supported yet")


def sync_with_cloud_storage(form: dict, cloud_config: dict) -> bool:
    """Синхронизирует форму с облачным хранилищем (stub)."""
    # Placeholder for real sync logic
    logging.info("Sync to cloud storage: %s", cloud_config.get("provider", "unknown"))
    return True


# ----- Диагностика и предложения -----
def diagnose_export_issues(form: dict, **kwargs: Any) -> List[str]:
    """Проверяет типичные ошибки перед экспортом."""
    issues = []
    if not form.get("elements"):
        issues.append("Form has no elements.")
    if len(json.dumps(form).encode()) > MAX_FLOPPY_BYTES:
        issues.append("Form too big for floppy.")
    issues.extend(validate_form_references(form))
    if check_circular_dependencies(form):
        issues.append("Circular dependencies found.")
    bad_chars = validate_charset_compatibility(form, "cp866")
    if bad_chars:
        issues.append(f"Charset incompatible elements: {bad_chars}")
    return issues


def suggest_optimizations(form: dict) -> List[str]:
    """Предлагает оптимизации для формы (stub)."""
    suggestions = []
    if len(json.dumps(form).encode()) > MAX_FLOPPY_BYTES // 2:
        suggestions.append("Enable compression of embedded images.")
    if check_circular_dependencies(form):
        suggestions.append("Restructure form to remove circular dependencies.")
    return suggestions


def validate_printer_compatibility(form: dict, printer_model: str) -> Dict[str, bool]:
    """Проверяет совместимость формы с указанной моделью принтера (stub)."""
    # Placeholder: always compatible for demonstration
    return {"compatible": True}


# --- Основные функции ---
def serialize_fxsf(
    form: dict,
    meta: Optional[dict] = None,
    sign: bool = False,
    encrypted: bool = False,
    encryption_algo: Optional[str] = None,
) -> bytes:
    """Serializes form+metadata into FXSF/FXSFS JSON.

    Args:
        form: Form dictionary structure.
        meta: Optional metadata dict.
        sign: If True, signs structure (stub).
        encrypted: If True, marks as encrypted.
        encryption_algo: Optional encryption alg name.

    Returns:
        Bytes of serialized FXSF file (UTF-8).

    Example:
        >>> out = serialize_fxsf({"title": "Test"}, {"author": "user"})
        >>> assert b'"form_id"' in out
    """
    fxsf_obj: Dict[str, Any] = {
        "fxsf_version": "1.0",
        "form_id": (
            meta.get("id")
            if meta and "id" in meta
            else hashlib.sha1(json.dumps(form, sort_keys=True).encode()).hexdigest()[:8]
        ),
        "created": (
            meta.get("created") if meta and "created" in meta else _get_now_iso()
        ),
        "author": (
            meta.get("author")
            if meta and "author" in meta
            else os.environ.get("USERNAME", "unknown")
        ),
        "schema_version": (
            meta.get("schema_version") if meta and "schema_version" in meta else "1.1"
        ),
        "meta": meta if meta else {},
        "encrypted": bool(encrypted),
        "encryption_algo": encryption_algo if encrypted else None,
        "body": form if not encrypted else None,
    }
    raw = json.dumps(fxsf_obj, ensure_ascii=False, sort_keys=True, indent=2).encode(
        "utf-8"
    )
    fxsf_obj["checksum"] = _sha256_bytes(raw)
    fxsf_obj["sig"] = "<not_implemented>" if sign else None
    final_raw = json.dumps(
        fxsf_obj, ensure_ascii=False, sort_keys=True, indent=2
    ).encode("utf-8")
    logging.info("Form serialized. id=%s encrypted=%s", fxsf_obj["form_id"], encrypted)
    return final_raw


def _validate_image_embeds(form: dict, max_img_bytes: int = MAX_IMAGE_EMBED) -> None:
    """Validates embedded images for floppy-size constraints."""
    for el in form.get("elements", []):
        if el.get("type") == "image" and "base64" in el:
            img_b64 = el["base64"]
            try:
                sz = len(base64.b64decode(img_b64.encode()))
            except Exception:
                logging.error("Invalid base64 in image element %s", el.get("id"))
                raise ExportImportError(
                    f"Invalid base64 in image element {el.get('id')}"
                )
            if sz > max_img_bytes:
                logging.warning(
                    "Image element %s too large for floppy: %d bytes", el.get("id"), sz
                )
                raise ExportImportError(
                    f"Image too large for floppy in element {el.get('id')}, size={sz} bytes"
                )


def validate_fxsf_structure(
    obj: dict,
    schema: Optional[FormSchema],
    floppy: bool = False,
    max_bytes: int = MAX_FLOPPY_BYTES,
) -> None:
    """Validates the FXSF structure for size, images, and schema.

    Args:
        obj: Serialized FXSF structure.
        schema: Optional FormSchema validator.
        floppy: If True, checks floppy size limits.
        max_bytes: Max allowed bytes (default 1.44Mb).

    Raises:
        ExportImportError: Various errors for size/image/schema.

    Example:
        >>> validate_fxsf_structure({'body': {'elements': []}}, None)
    """
    if floppy:
        raw_bytes = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        if len(raw_bytes) > max_bytes:
            logging.warning("Form structure exceeds floppy: %d bytes", len(raw_bytes))
            raise ExportImportError(
                f"Form .fxsf structure exceeds floppy size ({len(raw_bytes)} bytes > {max_bytes})"
            )
        if obj.get("encrypted"):
            if "body_enc" in obj:
                try:
                    enc_size = len(base64.b64decode(obj["body_enc"]))
                    if enc_size > max_bytes:
                        raise ExportImportError("Encrypted body too large for floppy.")
                except Exception:
                    raise ExportImportError("Invalid encrypted body format.")
        else:
            _validate_image_embeds(obj.get("body", {}), MAX_IMAGE_EMBED)
    if schema is not None:
        try:
            schema.validate_form(obj.get("body", {}))
        except Exception as ex:
            logging.error("Schema validation failed: %s", ex)
            raise ExportImportError(f"Schema validation failed on export/import: {ex}")


def export_form(
    form: dict,
    path: str,
    schema: Optional[FormSchema] = None,
    meta: Optional[dict] = None,
    sign: bool = False,
    encrypt: bool = False,
    encryption_profile: Optional[dict] = None,
    floppy: bool = False,
    max_bytes: int = MAX_FLOPPY_BYTES,
) -> None:
    """Exports form: open (.fxsf) or secure (.fxsfs) with floppy/meta/csum/signature/crypto.

    Args:
        form: Form dict.
        path: Output filepath (.fxsf or .fxsfs).
        schema: Optional FormSchema for validation.
        meta: Metadata dict.
        sign: If True, sign structure (stub).
        encrypt: If True, encrypt body.
        encryption_profile: Encryption profile for security.crypto.
        floppy: Floppy validation mode.
        max_bytes: Floppy byte limit.

    Example:
        >>> export_form({"title": "Demo"}, "demo.fxsf")
    """
    _, ext = os.path.splitext(path)
    ext = ext.lower()
    use_encrypt = encrypt or ext == ".fxsfs"
    raw: bytes

    if use_encrypt:
        if encrypt_bytes is None:
            raise ExportImportError("Security module not available for encryption.")
        fxsf_obj: Dict[str, Any] = {
            "fxsf_version": "1.0",
            "form_id": (
                meta.get("id")
                if meta and "id" in meta
                else hashlib.sha1(
                    json.dumps(form, sort_keys=True).encode()
                ).hexdigest()[:8]
            ),
            "created": (
                meta.get("created") if meta and "created" in meta else _get_now_iso()
            ),
            "author": (
                meta.get("author")
                if meta and "author" in meta
                else os.environ.get("USERNAME", "unknown")
            ),
            "schema_version": (
                meta.get("schema_version")
                if meta and "schema_version" in meta
                else "1.1"
            ),
            "meta": meta if meta else {},
            "encrypted": True,
            "encryption_algo": (
                encryption_profile.get("algo") if encryption_profile else "AES-256-GCM"
            ),
            "body": None,
        }
        plain_body = json.dumps(form, ensure_ascii=False, sort_keys=True).encode(
            "utf-8"
        )
        body_enc_bytes = encrypt_bytes(plain_body, profile=encryption_profile)
        fxsf_obj["body_enc"] = base64.b64encode(body_enc_bytes).decode()

        meta_blob = json.dumps(
            {k: fxsf_obj[k] for k in fxsf_obj if k != "checksum" and k != "sig"},
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        ).encode("utf-8")
        fxsf_obj["checksum"] = _sha256_bytes(meta_blob)
        fxsf_obj["sig"] = "<not_implemented>" if sign else None
        raw = json.dumps(fxsf_obj, ensure_ascii=False, sort_keys=True, indent=2).encode(
            "utf-8"
        )
        logging.info(
            "Form exported as secure .fxsfs; id=%s algo=%s",
            fxsf_obj["form_id"],
            fxsf_obj["encryption_algo"],
        )
    else:
        raw = serialize_fxsf(form, meta, sign, encrypted=False)
        logging.info("Form exported as open .fxsf; path=%s", path)

    obj = json.loads(raw.decode("utf-8"))
    validate_fxsf_structure(obj, schema, floppy=floppy, max_bytes=max_bytes)
    collect_export_metrics(form, path)

    with open(path, "wb") as f:
        f.write(raw)


def import_form(
    path: str,
    schema: Optional[FormSchema] = None,
    validate_checksum: bool = True,
    verify_signature: bool = False,
    decrypt: bool = False,
    decryption_profile: Optional[dict] = None,
    floppy: bool = False,
) -> dict:
    """Imports from .fxsf or .fxsfs, with optional decrypt/validate/schema.

    Args:
        path: FXSF file path.
        schema: Optional FormSchema validator.
        validate_checksum: If True, check SHA256.
        verify_signature: If True, check signature (stub).
        decrypt: Force decryption.
        decryption_profile: Security profile.
        floppy: If True, floppy-size validation.

    Returns:
        Form dictionary (body).

    Raises:
        ExportImportError: On decode, csum, decrypt, structure errors.

    Example:
        >>> form = import_form("demo.fxsf")
        >>> assert "elements" in form
    """
    _, ext = os.path.splitext(path)
    ext = ext.lower()
    use_decrypt = decrypt or ext == ".fxsfs"

    with open(path, "rb") as f:
        raw = f.read()

    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception as ex:
        logging.error("Failed to decode FXSF: %s", ex)
        raise ExportImportError(f"Failed to decode .fxsf(s): {ex}")

    # Checksum validation
    if validate_checksum:
        stored = obj.get("checksum")
        chk_obj = dict(obj)
        if "checksum" in chk_obj:
            del chk_obj["checksum"]
        if "sig" in chk_obj:
            del chk_obj["sig"]
        meta_blob = json.dumps(
            chk_obj, ensure_ascii=False, sort_keys=True, indent=2
        ).encode("utf-8")
        calc = _sha256_bytes(meta_blob)
        if stored != calc:
            logging.error("Checksum mismatch: stored=%s, calculated=%s", stored, calc)
            raise ExportImportError(
                f"Checksum mismatch: stored={stored}, calculated={calc}"
            )

    body: dict = {}
    if use_decrypt:
        if decrypt_bytes is None:
            raise ExportImportError("Security module not available for decryption.")
        enc_data_b64 = obj.get("body_enc")
        if not enc_data_b64:
            logging.error("Encrypted FXSF missing 'body_enc'.")
            raise ExportImportError("Encrypted .fxsfs missing 'body_enc'.")
        enc_data = base64.b64decode(enc_data_b64.encode())
        plain_bytes = decrypt_bytes(enc_data, profile=decryption_profile)
        try:
            body = json.loads(plain_bytes.decode("utf-8"))
        except Exception as ex:
            logging.error("Decrypted body parse fail: %s", ex)
            raise ExportImportError(f"Decrypted body parse fail: {ex}")
    else:
        body = obj.get("body", {})

    validate_fxsf_structure(
        {**obj, "body": body}, schema, floppy=floppy, max_bytes=MAX_FLOPPY_BYTES
    )

    if verify_signature and obj.get("sig") not in [None, "<not_implemented>"]:
        raise ExportImportError("Signature verification not implemented")

    logging.info(
        "Form imported; id=%s encrypted=%s",
        obj.get("form_id", None),
        obj.get("encrypted", False),
    )
    return body
