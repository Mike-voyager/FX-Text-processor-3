import json
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

from src.form.template_manager import (
    DEFAULT_SECURITY_CONFIG,
    TemplateManager,
    TemplateManagerError,
)

BASIC_TEMPLATE = {
    "kind": "regular",
    "layout_type": "grid",
    "elements": [{"type": "label", "label": "Test"}],
}
AUTHOR = "unit-tester"


def create_manager(
    tmp_path: Path,
    config: Optional[Dict[str, Any]] = None,
    user: Optional[Dict[str, Any]] = None,
) -> TemplateManager:
    if config is None:
        config = DEFAULT_SECURITY_CONFIG
    if user is None:
        user = {"user_id": AUTHOR, "role": "admin"}
    return TemplateManager(str(tmp_path), security_config=config, user_context=user)


def test_create_save_and_reload(tmp_path: Path) -> None:
    mgr = create_manager(tmp_path)
    ver = mgr.save_template("doc1", BASIC_TEMPLATE, AUTHOR, comment="init")
    assert ver == 1
    mgr2 = create_manager(tmp_path)
    assert "doc1" in mgr2.list_templates()
    loaded = mgr2.get_template("doc1")
    assert loaded.latest() == BASIC_TEMPLATE


def test_invalid_name_and_path_traversal(tmp_path: Path) -> None:
    mgr = create_manager(tmp_path)
    with pytest.raises(TemplateManagerError):
        mgr.save_template("../bad", BASIC_TEMPLATE, AUTHOR)
    with pytest.raises(TemplateManagerError):
        mgr.save_template("doc/evil", BASIC_TEMPLATE, AUTHOR)
    with pytest.raises(TemplateManagerError):
        mgr.save_template("CON", BASIC_TEMPLATE, AUTHOR)


def test_template_structure_validation(tmp_path: Path) -> None:
    mgr = create_manager(tmp_path)
    bad = {"bad": 1}
    with pytest.raises(TemplateManagerError):
        mgr.save_template("struct", bad, AUTHOR)


def test_duplicate_storage_and_deduplicate(tmp_path: Path) -> None:
    mgr = create_manager(tmp_path)
    mgr.save_template("dup", BASIC_TEMPLATE, AUTHOR)
    assert mgr.save_template("dup", BASIC_TEMPLATE, AUTHOR) is None
    new_data = {**BASIC_TEMPLATE, "elements": [{"type": "label", "label": "Another"}]}
    assert mgr.save_template("dup", new_data, AUTHOR) == 2


def test_delete_restore_and_hard_delete(tmp_path: Path) -> None:
    mgr = create_manager(tmp_path)
    mgr.save_template("ttt", BASIC_TEMPLATE, AUTHOR)
    mgr.delete_template("ttt")
    assert "ttt" not in mgr.list_templates()
    assert "ttt" in mgr.list_templates(include_deleted=True)
    mgr.restore_template("ttt")
    assert "ttt" in mgr.list_templates()
    mgr.delete_template("ttt", force=True)
    assert "ttt" not in mgr.list_templates(include_deleted=True)


def test_promote_and_version_history(tmp_path: Path) -> None:
    mgr = create_manager(tmp_path)
    mgr.save_template("foo", BASIC_TEMPLATE, AUTHOR)
    data2 = {**BASIC_TEMPLATE, "elements": [{"type": "label", "label": "V2"}]}
    mgr.save_template("foo", data2, AUTHOR, comment="2nd version")
    assert mgr.get_template("foo").latest()["elements"][0]["label"] == "V2"
    mgr.promote_version("foo", 1, AUTHOR, "rollback")
    assert mgr.get_template("foo").latest()["elements"][0]["label"] == "Test"
    assert len(mgr.get_template("foo").history()) == 3


def test_soft_delete_locked_protected(tmp_path: Path) -> None:
    mgr = create_manager(tmp_path)
    meta = {"locked": True}
    mgr.save_template("locked", BASIC_TEMPLATE, AUTHOR, metadata=meta)
    with pytest.raises(TemplateManagerError):
        mgr.delete_template("locked")
    mgr.delete_template("locked", force=True)
    assert "locked" not in mgr.list_templates(include_deleted=True)


def test_batch_migrate(tmp_path: Path) -> None:
    mgr = create_manager(tmp_path)
    mgr.save_template("b1", BASIC_TEMPLATE, AUTHOR)
    mgr.save_template("b2", BASIC_TEMPLATE, AUTHOR)

    def migrate_stub(tpl: Dict[str, Any]) -> Dict[str, Any]:
        d = tpl.copy()
        d["meta"] = "v2"
        return d

    result = mgr.batch_migrate(migrate_stub, AUTHOR, comment="batch")
    assert "b1" in result and "b2" in result
    b1_ver = mgr.get_template("b1").latest()
    assert b1_ver["meta"] == "v2"


def test_search_and_metadata(tmp_path: Path) -> None:
    mgr = create_manager(tmp_path)
    mgr.save_template(
        "search1", BASIC_TEMPLATE, AUTHOR, metadata={"category": "contract"}
    )
    mgr.save_template(
        "search2", BASIC_TEMPLATE, AUTHOR, metadata={"category": "specform"}
    )
    res = mgr.search("contract")
    assert "search1" in res
    meta = mgr.get_template_metadata("search2")
    assert meta["category"] == "specform"


def test_html_escape_variable_substitution(tmp_path: Path) -> None:
    mgr = create_manager(tmp_path)
    tpl = {
        **BASIC_TEMPLATE,
        "elements": [
            {"type": "label", "label": "{{x}}&<tag>"},
            {"type": "label", "label": "{{y}}"},
        ],
    }
    mgr.save_template("ssub", tpl, AUTHOR)
    result = mgr.render_template("ssub", variables={"x": "<script>", "y": "мир"})
    labels = [el["label"] for el in result["elements"]]
    assert "&lt;script&gt;" in labels[0]
    assert "мир" in labels[1]


def test_rate_limit(tmp_path: Path) -> None:
    cfg = {**DEFAULT_SECURITY_CONFIG, "rate_limit_requests_per_hour": 2}
    mgr = create_manager(
        tmp_path, config=cfg, user={"user_id": "rater", "role": "admin"}
    )
    mgr.save_template("ratel", BASIC_TEMPLATE, AUTHOR)
    mgr.save_template("ratel2", BASIC_TEMPLATE, AUTHOR)
    with pytest.raises(TemplateManagerError):
        mgr.save_template("ratel3", BASIC_TEMPLATE, AUTHOR)


def test_rbac_check(tmp_path: Path) -> None:
    admin_user = {"user_id": "admin", "role": "admin"}
    mgr_admin = create_manager(tmp_path, user=admin_user, config={"require_auth": True})
    mgr_admin.save_template("open", BASIC_TEMPLATE, AUTHOR)

    guest_user = {"user_id": "guest", "role": "guest"}
    mgr_guest = create_manager(tmp_path, user=guest_user, config={"require_auth": True})
    with pytest.raises(TemplateManagerError):
        mgr_guest.get_template("open")
    with pytest.raises(TemplateManagerError):
        mgr_guest.delete_template("open")

    mgr_guest.user_context["role"] = "admin"
    mgr_guest.delete_template("open", force=True)
    assert "open" not in mgr_guest.list_templates(include_deleted=True)


def test_checksum_integrity(tmp_path: Path) -> None:
    mgr = create_manager(tmp_path)
    mgr.save_template("sum1", BASIC_TEMPLATE, AUTHOR)
    file = Path(tmp_path) / "sum1.json"
    with file.open("r+", encoding="utf-8") as f:
        d = json.load(f)
        f.seek(0)
        d["kind"] = "tampered"
        json.dump(d, f, ensure_ascii=False, indent=2)
        f.truncate()
    mgr2 = create_manager(tmp_path)
    assert "sum1" not in mgr2.list_templates(include_deleted=True)


def test_max_nesting_and_size_limits(tmp_path: Path) -> None:
    cfg = {
        **DEFAULT_SECURITY_CONFIG,
        "max_nesting_depth": 3,
        "max_template_size_mb": 0.0001,
    }
    mgr = create_manager(tmp_path, config=cfg)
    too_deep = {"kind": "x", "layout_type": "g", "elements": [[[[1]]]]}
    with pytest.raises(TemplateManagerError):
        mgr.save_template("deep", too_deep, AUTHOR)
    large = {"kind": "x", "layout_type": "g", "elements": ["x" * 100_000]}
    with pytest.raises(TemplateManagerError):
        mgr.save_template("biggy", large, AUTHOR)


def test_load_corrupt_json(tmp_path: Path) -> None:
    file = Path(tmp_path) / "corrupt.json"
    # Запишем сломанный JSON
    file.write_text('{"name": "bad", "invalid": ')
    # Не должно поднимать error, шаблон просто игнорируется при загрузке
    mgr = create_manager(tmp_path)
    assert "corrupt" not in mgr.list_templates(include_deleted=True)


def test_checksum_mismatch(tmp_path: Path) -> None:
    mgr = create_manager(tmp_path)
    mgr.save_template("badchk", BASIC_TEMPLATE, AUTHOR)
    file = Path(tmp_path) / "badchk.json"
    j = json.loads(file.read_text(encoding="utf-8"))
    j["_checksum"] = "wrongvalue"
    file.write_text(json.dumps(j, ensure_ascii=False, indent=2), encoding="utf-8")
    # Должен логировать ошибку и игнорировать этот шаблон
    mgr2 = create_manager(tmp_path)
    assert "badchk" not in mgr2.list_templates(include_deleted=True)


def test_audit_log_and_restore(tmp_path: Path) -> None:
    mgr = create_manager(tmp_path, config={"enable_audit_log": True})
    mgr.save_template("audit", BASIC_TEMPLATE, AUTHOR)
    mgr.delete_template("audit")
    mgr.restore_template("audit")
    # Должен существовать security.log и быть непустым
    log = Path(tmp_path) / "security.log"
    assert log.exists()
    txt = log.read_text(encoding="utf-8")
    actions = ["save_template", "soft_delete", "restore"]
    for act in actions:
        assert act in txt


def test_batch_migrate_invalid(tmp_path: Path) -> None:
    mgr = create_manager(tmp_path)
    mgr.save_template("m1", BASIC_TEMPLATE, AUTHOR)

    # Migration breaks the template (removes required keys)
    def bad_migrate(tpl: Dict[str, Any]) -> Dict[str, Any]:
        return {"foo": "bar"}

    result = mgr.batch_migrate(bad_migrate, AUTHOR)
    # Миграция должна быть пропущена (нет версий)
    assert "m1" not in result or mgr.get_template("m1").latest() == BASIC_TEMPLATE


def test_soft_hard_delete_with_backup(tmp_path: Path) -> None:
    cfg = {**DEFAULT_SECURITY_CONFIG, "backup_on_delete": True}
    mgr = create_manager(tmp_path, config=cfg)
    mgr.save_template("bdel", BASIC_TEMPLATE, AUTHOR)
    file = Path(tmp_path) / "bdel.json"
    trash_dir = Path(tmp_path) / "_trash"
    mgr.delete_template("bdel", force=True)
    assert not file.exists()
    backups = list(trash_dir.glob("bdel.*.bak"))
    assert backups


def test_promote_unknown_version(tmp_path: Path) -> None:
    mgr = create_manager(tmp_path)
    mgr.save_template("zzz", BASIC_TEMPLATE, AUTHOR)
    with pytest.raises(TemplateManagerError):
        mgr.promote_version("zzz", 100, AUTHOR)


def test_restore_non_existent(tmp_path: Path) -> None:
    mgr = create_manager(tmp_path)
    # restore for non-existent returns error
    with pytest.raises(TemplateManagerError):
        mgr.restore_template("nosuch")


def test_search_deleted_filtered(tmp_path: Path) -> None:
    mgr = create_manager(tmp_path)
    mgr.save_template("srch1", BASIC_TEMPLATE, AUTHOR)
    mgr.save_template("srch2", BASIC_TEMPLATE, AUTHOR)
    mgr.delete_template("srch2")
    # Поиск по удалённым
    with_deleted = mgr.search("srch", include_deleted=True)
    no_deleted = mgr.search("srch", include_deleted=False)
    assert "srch2" in with_deleted
    assert "srch2" not in no_deleted


def test_invalid_variable_types_in_substitute(tmp_path: Path) -> None:
    mgr = create_manager(tmp_path)
    tpl = {
        **BASIC_TEMPLATE,
        "elements": [
            {"type": "label", "label": "{{n}}"},
        ],
    }
    mgr.save_template("varsubs", tpl, AUTHOR)
    # Передаём нестандартные типы в variables (int, None)
    result = mgr.render_template("varsubs", variables={"n": 12345, "z": None})
    label = result["elements"][0]["label"]
    assert "12345" in label


def test_hierachy_roles(tmp_path: Path) -> None:
    # Тут editor может удалить шаблон, user — нет
    mgr_admin = create_manager(
        tmp_path,
        user={"user_id": "aaa", "role": "admin"},
        config={"require_auth": True},
    )
    mgr_admin.save_template("hrole", BASIC_TEMPLATE, AUTHOR)
    mgr_admin.templates["hrole"].metadata["delete_role"] = "editor"
    mgr_admin._persist_template("hrole")
    mgr_user = create_manager(
        tmp_path, user={"user_id": "uuu", "role": "user"}, config={"require_auth": True}
    )
    with pytest.raises(TemplateManagerError):
        mgr_user.delete_template("hrole")
    mgr_editor = create_manager(
        tmp_path,
        user={"user_id": "eee", "role": "editor"},
        config={"require_auth": True},
    )
    mgr_editor.delete_template("hrole", force=True)
    assert "hrole" not in mgr_editor.list_templates(include_deleted=True)
