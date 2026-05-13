import base64
import json
import os
import tempfile
import zipfile
from datetime import datetime

import pytest

from src.form.export_import import (
    MAX_FLOPPY_BYTES,
    MAX_IMAGE_EMBED,
    ExportImportError,
    analyze_form_complexity,
    check_circular_dependencies,
    cleanup_old_backups,
    collect_export_metrics,
    compress_form_data,
    convert_form_encoding,
    create_form_archive,
    create_form_backup,
    detect_form_encoding,
    diagnose_export_issues,
    export_form,
    export_form_batch,
    export_to_external_format,
    generate_compatibility_report,
    get_supported_versions,
    import_form,
    import_form_batch,
    import_from_external,
    is_version_compatible,
    migrate_form_version,
    optimize_for_floppy,
    restore_form_from_backup,
    serialize_fxsf,
    suggest_optimizations,
    sync_with_cloud_storage,
    validate_charset_compatibility,
    validate_form_references,
    validate_fxsf_structure,
    validate_printer_compatibility,
    validate_resource_availability,
)
from src.form.form_schema import FormSchema


class DummySchema(FormSchema):
    def validate_form(self, body: dict) -> bool:
        if "fail" in body:
            raise Exception("Dummy failure")
        return True


@pytest.fixture
def simple_form() -> dict:
    return {"elements": [{"id": "e1", "type": "text", "value": "hello"}]}


@pytest.fixture
def complex_form() -> dict:
    return {
        "elements": [
            {"id": "e1", "type": "text", "value": "hello", "refs": ["e2"]},
            {"id": "e2", "type": "text", "value": "world"},
            {
                "id": "e3",
                "type": "image",
                "base64": base64.b64encode(b"x" * 1000).decode(),
            },
        ]
    }


@pytest.fixture
def circular_form() -> dict:
    return {
        "elements": [
            {"id": "e1", "type": "text", "refs": ["e2"]},
            {"id": "e2", "type": "text", "refs": ["e1"]},
        ]
    }


def test_serialize_fxsf(simple_form: dict) -> None:
    out = serialize_fxsf(simple_form, {"author": "test"})
    assert isinstance(out, bytes)
    assert b'"form_id"' in out


def test_validate_fxsf_structure_pass(simple_form: dict) -> None:
    validate_fxsf_structure({"body": simple_form}, None)


def test_export_import_roundtrip(simple_form: dict) -> None:
    with tempfile.TemporaryDirectory() as td:
        fp = os.path.join(td, "t.fxsf")
        export_form(simple_form, fp)
        out = import_form(fp)
        assert "elements" in out
        assert isinstance(out, dict)


def test_migrate_form_version(simple_form: dict) -> None:
    migrated = migrate_form_version(simple_form, "1.0", "1.1")
    assert migrated["_migrated_from"] == "1.0"
    assert migrated["_migrated_to"] == "1.1"


def test_get_supported_versions() -> None:
    versions = get_supported_versions()
    assert isinstance(versions, list)
    assert "1.0" in versions


def test_is_version_compatible() -> None:
    assert is_version_compatible("1.0")
    assert not is_version_compatible("2.0")


def test_validate_form_references(complex_form: dict) -> None:
    bad_refs = validate_form_references(complex_form)
    assert len(bad_refs) == 0


def test_validate_form_references_bad() -> None:
    form: dict = {"elements": [{"id": "e1", "refs": ["missing"]}]}
    bad_refs = validate_form_references(form)
    assert "missing" in bad_refs


def test_check_circular_dependencies_false(complex_form: dict) -> None:
    assert not check_circular_dependencies(complex_form)


def test_check_circular_dependencies_true(circular_form: dict) -> None:
    assert check_circular_dependencies(circular_form)


def test_validate_resource_availability(complex_form: dict) -> None:
    resources = validate_resource_availability(complex_form)
    assert "e3" in resources
    assert resources["e3"] is True


def test_compress_form_data(complex_form: dict) -> None:
    compressed = compress_form_data(complex_form)
    assert "elements" in compressed


def test_optimize_for_floppy(complex_form: dict) -> None:
    optimized = optimize_for_floppy(complex_form)
    assert "elements" in optimized


def test_export_form_batch(simple_form: dict) -> None:
    with tempfile.TemporaryDirectory() as td:
        forms = [
            (simple_form, os.path.join(td, "f1.fxsf")),
            (simple_form, os.path.join(td, "f2.fxsf")),
        ]
        results = export_form_batch(forms)
        assert all(results)


def test_import_form_batch(simple_form: dict) -> None:
    with tempfile.TemporaryDirectory() as td:
        fp1 = os.path.join(td, "f1.fxsf")
        fp2 = os.path.join(td, "f2.fxsf")
        export_form(simple_form, fp1)
        export_form(simple_form, fp2)
        forms = import_form_batch([fp1, fp2])
        assert len(forms) == 2


def test_create_form_archive(simple_form: dict) -> None:
    with tempfile.TemporaryDirectory() as td:
        archive_path = os.path.join(td, "archive.fxsa")
        forms = {"form1": simple_form, "form2": simple_form}
        create_form_archive(forms, archive_path)
        assert os.path.exists(archive_path)
        with zipfile.ZipFile(archive_path, "r") as zf:
            assert "form1.fxsf" in zf.namelist()
            assert "form2.fxsf" in zf.namelist()


def test_collect_export_metrics(simple_form: dict) -> None:
    collect_export_metrics(simple_form, "test.fxsf")


def test_analyze_form_complexity(complex_form: dict) -> None:
    complexity = analyze_form_complexity(complex_form)
    assert "element_count" in complexity
    assert complexity["element_count"] == 3.0


def test_generate_compatibility_report(simple_form: dict) -> None:
    report = generate_compatibility_report(simple_form)
    assert "floppy_fit" in report
    assert report["floppy_fit"] is True


def test_detect_form_encoding() -> None:
    form_cyrillic: dict = {"elements": [{"value": "Привет"}]}
    encoding = detect_form_encoding(form_cyrillic)
    assert encoding == "cp866"


def test_convert_form_encoding(simple_form: dict) -> None:
    converted = convert_form_encoding(simple_form, "utf-8", "cp866")
    assert "elements" in converted


def test_validate_charset_compatibility(simple_form: dict) -> None:
    bad_chars = validate_charset_compatibility(simple_form, "ascii")
    assert isinstance(bad_chars, list)


def test_create_form_backup(simple_form: dict) -> None:
    with tempfile.TemporaryDirectory() as td:
        backup_path = create_form_backup(simple_form, td)
        assert os.path.exists(backup_path)
        assert backup_path.endswith(".fxsf")


def test_restore_form_from_backup(simple_form: dict) -> None:
    with tempfile.TemporaryDirectory() as td:
        backup_path = create_form_backup(simple_form, td)
        restored = restore_form_from_backup(backup_path)
        assert "elements" in restored


def test_cleanup_old_backups(simple_form: dict) -> None:
    with tempfile.TemporaryDirectory() as td:
        create_form_backup(simple_form, td)
        cleaned = cleanup_old_backups(td, retention_days=0)
        assert cleaned >= 0


def test_export_to_external_format_json(simple_form: dict) -> None:
    data = export_to_external_format(simple_form, "json")
    assert isinstance(data, bytes)
    parsed = json.loads(data.decode("utf-8"))
    assert "elements" in parsed


def test_export_to_external_format_unsupported(simple_form: dict) -> None:
    with pytest.raises(ExportImportError):
        export_to_external_format(simple_form, "pdf")


def test_import_from_external_json(simple_form: dict) -> None:
    with tempfile.TemporaryDirectory() as td:
        fp = os.path.join(td, "test.json")
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(simple_form, f)
        imported = import_from_external(fp, "json")
        assert "elements" in imported


def test_sync_with_cloud_storage(simple_form: dict) -> None:
    result = sync_with_cloud_storage(simple_form, {"provider": "test"})
    assert result is True


def test_diagnose_export_issues(simple_form: dict) -> None:
    issues = diagnose_export_issues(simple_form)
    assert isinstance(issues, list)


def test_diagnose_export_issues_empty_form() -> None:
    empty_form: dict = {"elements": []}
    issues = diagnose_export_issues(empty_form)
    assert "Form has no elements." in issues


def test_suggest_optimizations(simple_form: dict) -> None:
    suggestions = suggest_optimizations(simple_form)
    assert isinstance(suggestions, list)


def test_validate_printer_compatibility(simple_form: dict) -> None:
    compatibility = validate_printer_compatibility(simple_form, "FX-890")
    assert "compatible" in compatibility
    assert compatibility["compatible"] is True


def test_floppy_limit_exceeded() -> None:
    large_form: dict = {
        "elements": [{"type": "text", "value": "x" * (MAX_FLOPPY_BYTES)}]
    }
    with pytest.raises(ExportImportError):
        validate_fxsf_structure({"body": large_form}, None, floppy=True)


def test_invalid_base64_image() -> None:
    bad_form: dict = {
        "elements": [{"id": "img1", "type": "image", "base64": "invalid_base64!"}]
    }
    with pytest.raises(ExportImportError):
        validate_fxsf_structure({"body": bad_form}, None, floppy=True)


def test_schema_validation_fail() -> None:
    with pytest.raises(ExportImportError):
        validate_fxsf_structure({"body": {"fail": True}}, DummySchema(spec={}))


def test_checksum_validation_fail(simple_form: dict) -> None:
    with tempfile.TemporaryDirectory() as td:
        fp = os.path.join(td, "t.fxsf")
        export_form(simple_form, fp)
        with open(fp, "rb") as f:
            data = f.read()
        corrupted = data.replace(b"hello", b"broken")
        with open(fp, "wb") as f:
            f.write(corrupted)
        with pytest.raises(ExportImportError):
            import_form(fp)


def test_missing_security_module_encryption(
    monkeypatch: pytest.MonkeyPatch, simple_form: dict
) -> None:
    import src.form.export_import as mod

    monkeypatch.setattr(mod, "encrypt_bytes", None)
    with tempfile.TemporaryDirectory() as td:
        fp = os.path.join(td, "t.fxsfs")
        with pytest.raises(ExportImportError, match="Security module not available"):
            export_form(simple_form, fp, encrypt=True)


def test_missing_security_module_decryption(
    monkeypatch: pytest.MonkeyPatch, simple_form: dict
) -> None:
    import src.form.export_import as mod

    with tempfile.TemporaryDirectory() as td:
        fp = os.path.join(td, "t.fxsfs")
        # Сначала экспорт: encrypt_bytes должен существовать!
        export_form(simple_form, fp, encrypt=True)
        # Только теперь monkeypatch для decrypt_bytes:
        monkeypatch.setattr(mod, "decrypt_bytes", None)
        with pytest.raises(ExportImportError, match="Security module not available"):
            import_form(fp, decrypt=True)
