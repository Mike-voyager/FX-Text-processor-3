"""RU: Безопасный и проверенный менеджер шаблонов для FX-Text-processor-3.
Версионирование, контроль целостности, audit trail, ограничения размера/глубины, safe variable substitution,
soft-delete, базовый RBAC, rate-limit и строгая mypy/pylance-совместимость."""

import hashlib
import html
import json
import logging
import os
import time
from collections import defaultdict
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, DefaultDict, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_SECURITY_CONFIG: Dict[str, Any] = {
    "max_template_size_mb": 1,
    "max_nesting_depth": 50,
    "max_versions_per_template": 100,
    "enable_audit_log": True,
    "rate_limit_requests_per_hour": 1000,
    "require_auth": False,
    "backup_on_delete": True,
}


class TemplateManagerError(Exception):
    pass


class TemplateVersion:
    def __init__(
        self,
        version: int,
        author: str,
        timestamp: str,
        template: Dict[str, Any],
        comment: Optional[str] = None,
    ) -> None:
        self.version = version
        self.author = author
        self.timestamp = timestamp
        self.template = template
        self.comment = comment or ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "author": self.author,
            "timestamp": self.timestamp,
            "template": deepcopy(self.template),
            "comment": self.comment,
        }


class Template:
    def __init__(
        self,
        name: str,
        data: Dict[str, Any],
        author: str,
        comment: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.name = name
        self.author = author
        self.comment = comment or ""
        self.created_at = datetime.now().isoformat(timespec="seconds")
        self.metadata = metadata or {}
        self.versions: List[TemplateVersion] = []
        self.deleted: bool = False
        self.add_version(data, author, comment)

    def add_version(
        self,
        data: Dict[str, Any],
        author: Optional[str] = None,
        comment: Optional[str] = None,
    ) -> Optional[int]:
        latest = self.versions[-1].template if self.versions else None
        if latest is not None and self._is_duplicate(latest, data):
            logger.info("Template %s: no changes detected, not saved.", self.name)
            return None
        if len(self.versions) >= DEFAULT_SECURITY_CONFIG["max_versions_per_template"]:
            logger.warning("Max versions exceeded for %s, cleaning oldest.", self.name)
            self.versions = self.versions[1:]
        version = len(self.versions) + 1
        timestamp = datetime.now().isoformat(timespec="seconds")
        real_author = author if author is not None else self.author
        self.versions.append(
            TemplateVersion(
                version=version,
                author=real_author,
                timestamp=timestamp,
                template=deepcopy(data),
                comment=comment,
            )
        )
        logger.info(
            "Template %s: version %d saved by %s", self.name, version, real_author
        )
        return version

    def _is_duplicate(self, a: Dict[str, Any], b: Dict[str, Any]) -> bool:
        return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)

    def latest(self) -> Dict[str, Any]:
        if not self.versions:
            raise TemplateManagerError(f"No versions for template {self.name}")
        return deepcopy(self.versions[-1].template)

    def promote_version(
        self, version_num: int, author: str, comment: Optional[str] = None
    ) -> int:
        for v in self.versions:
            if v.version == version_num:
                self.add_version(
                    deepcopy(v.template),
                    author,
                    comment or f"rollback to v{version_num}",
                )
                logger.info(
                    "Template %s: rolled back to version %d", self.name, version_num
                )
                return len(self.versions)
        raise TemplateManagerError(
            f"Version {version_num} not found in template {self.name}"
        )

    def history(self) -> List[Dict[str, Any]]:
        return [v.as_dict() for v in self.versions]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "author": self.author,
            "comment": self.comment,
            "created_at": self.created_at,
            "metadata": self.metadata,
            "deleted": self.deleted,
            "versions": [v.as_dict() for v in self.versions],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Template":
        tmpl = cls(
            data["name"],
            deepcopy(data["versions"][-1]["template"]),
            data["author"],
            data.get("comment"),
            data.get("metadata"),
        )
        tmpl.versions = [TemplateVersion(**v) for v in data["versions"]]
        tmpl.created_at = data.get("created_at", tmpl.created_at)
        tmpl.deleted = data.get("deleted", False)
        return tmpl


class TemplateManager:
    INVALID_CHARS = set(r'\/:*?"<>|')

    def __init__(
        self,
        storage_dir: str = "./templates",
        user_context: Optional[Dict[str, Any]] = None,
        security_config: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.templates: Dict[str, Template] = {}
        self.security_config: Dict[str, Any] = {
            **DEFAULT_SECURITY_CONFIG,
            **(security_config or {}),
        }
        self.user_context: Dict[str, Any] = user_context or {}
        self._rate_limits: DefaultDict[str, List[float]] = defaultdict(list)
        self._load_all()

    def _security_log(
        self, action: str, template_name: Optional[str], details: Optional[Dict] = None
    ) -> None:
        if not self.security_config["enable_audit_log"]:
            return
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "template": template_name or "",
            "user": self.user_context.get("user_id", "unknown"),
            "ip": self.user_context.get("ip_address"),
            "details": details or {},
        }
        security_log_file = self.storage_dir / "security.log"
        with security_log_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")

    def _check_permission(self, template_name: Optional[str], action: str) -> None:
        if not self.security_config["require_auth"]:
            return
        required_role = "user"
        tmpl = self.templates.get(template_name) if template_name else None
        if tmpl:
            required_role = tmpl.metadata.get(f"{action}_role", "user")
        user_role = self.user_context.get("role", "guest")
        hierarchy = {"guest": 0, "user": 1, "editor": 2, "admin": 3}
        if hierarchy.get(user_role, 0) < hierarchy.get(required_role, 1):
            self._security_log(
                "access_denied",
                template_name or "",
                {"action": action, "user_role": user_role},
            )
            raise TemplateManagerError(f"Access denied: {action} on {template_name}")

    def _check_rate_limit(
        self,
        user_id: str,
        max_requests: Optional[int] = None,
        window_seconds: int = 3600,
    ) -> None:
        max_requests_val = (
            max_requests
            if max_requests is not None
            else self.security_config["rate_limit_requests_per_hour"]
        )
        now = time.time()
        user_requests = self._rate_limits[user_id]
        self._rate_limits[user_id] = [
            t for t in user_requests if now - t < window_seconds
        ]
        if len(self._rate_limits[user_id]) >= max_requests_val:
            self._security_log("rate_limit", "", {"user_id": user_id})
            raise TemplateManagerError(f"Rate limit exceeded for user {user_id}")
        self._rate_limits[user_id].append(now)

    def _backup_deleted(self, name: str) -> None:
        if not self.security_config["backup_on_delete"]:
            return
        file = self.storage_dir / f"{name}.json"
        trash_dir = self.storage_dir / "_trash"
        trash_dir.mkdir(exist_ok=True)
        if file.exists():
            backup = trash_dir / (name + f".{int(time.time())}.bak")
            file.replace(backup)

    def _validate_name(self, name: str) -> None:
        if (
            not name
            or any(c in name for c in self.INVALID_CHARS)
            or name.strip() == ""
            or name.lower() in ["con", "nul", "prn"]
            or ".." in name
            or name.startswith("/")
            or name.startswith("\\")
        ):
            raise TemplateManagerError(f"Invalid template name: {name!r}")
        normalized = os.path.normpath(name)
        if normalized != name:
            raise TemplateManagerError(f"Invalid path characters in name: {name!r}")

    def _calculate_checksum(self, data: Dict[str, Any]) -> str:
        content = json.dumps(data, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def _load_all(self) -> None:
        for file in self.storage_dir.glob("*.json"):
            try:
                with file.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                stored_checksum = data.pop("_checksum", None)
                if stored_checksum:
                    calculated = self._calculate_checksum(data)
                    if stored_checksum != calculated:
                        logger.error(
                            "Checksum mismatch for %s - file may be corrupted", file
                        )
                        continue
                tmpl = Template.from_dict(data)
                self.templates[tmpl.name] = tmpl
                logger.info("Loaded template: %s", tmpl.name)
            except Exception as ex:
                logger.warning("Failed to load template from %r: %s", str(file), ex)

    def list_templates(self, include_deleted: bool = False) -> List[str]:
        return sorted(
            [
                n
                for n, tmpl in self.templates.items()
                if (not tmpl.deleted or include_deleted)
            ]
        )

    def get_template(self, name: str, include_deleted: bool = False) -> Template:
        self._check_permission(name, "read")
        if name not in self.templates or (
            self.templates[name].deleted and not include_deleted
        ):
            raise TemplateManagerError(f"Template '{name}' not found")
        return self.templates[name]

    def save_template(
        self,
        name: str,
        data: Dict[str, Any],
        author: str,
        comment: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[int]:
        self._check_rate_limit(self.user_context.get("user_id", "global"))
        self._check_permission(None, "create")
        self._validate_name(name)
        self.validate_template_struct(data, raise_exc=True)
        if name in self.templates:
            tmpl = self.templates[name]
            version = tmpl.add_version(data, author, comment)
            if metadata:
                tmpl.metadata.update(metadata)
        else:
            self.templates[name] = Template(name, data, author, comment, metadata)
            version = 1
        self._persist_template(name)
        self._security_log(
            "save_template", name, {"author": author, "comment": comment}
        )
        return version

    def _persist_template(self, name: str) -> None:
        tmpl = self.get_template(name, include_deleted=True)
        data = tmpl.to_dict()
        data["_checksum"] = self._calculate_checksum(data)
        file = self.storage_dir / f"{name}.json"
        with file.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info("Template %s persisted to %s", name, file)

    def delete_template(self, name: str, force: bool = False) -> None:
        self._check_permission(name, "delete")
        if name not in self.templates:
            raise TemplateManagerError(f"Template '{name}' not found")
        tmpl = self.templates[name]
        if tmpl.metadata.get("locked") and not force:
            raise TemplateManagerError(
                f"Template '{name}' is locked and cannot be deleted (set force=True to override)."
            )
        tmpl.deleted = True
        self._persist_template(name)
        logger.info("Template %s soft-deleted", name)
        self._security_log("soft_delete", name)
        if force:
            self._backup_deleted(name)
            file = self.storage_dir / f"{name}.json"
            if file.exists():
                file.unlink()
            del self.templates[name]
            logger.info("Template %s hard-deleted from disk", name)
            self._security_log("hard_delete", name)

    def restore_template(self, name: str) -> None:
        self._check_permission(name, "restore")
        tmpl = self.get_template(name, include_deleted=True)
        tmpl.deleted = False
        self._persist_template(name)
        logger.info("Template %s restored from trash", name)
        self._security_log("restore", name)

    def safe_substitute(
        self, obj: Any, variables: Dict[str, Any], max_var_size: int = 10000
    ) -> Any:
        """Безопасная подстановка с HTML-escape, защитой от DoS и длины переменных."""
        if isinstance(obj, str):
            for k, v in variables.items():
                safe_v = html.escape(str(v)) if isinstance(v, str) else str(v)
                if len(safe_v) > max_var_size:
                    safe_v = safe_v[:max_var_size] + "..."
                obj = obj.replace("{{" + k + "}}", safe_v)
            return obj
        elif isinstance(obj, dict):
            return {
                k: self.safe_substitute(v, variables, max_var_size)
                for k, v in obj.items()
            }
        elif isinstance(obj, list):
            return [self.safe_substitute(x, variables, max_var_size) for x in obj]
        else:
            return obj

    def render_template(
        self,
        name: str,
        variables: Optional[Dict[str, Any]] = None,
        postprocessor: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        version_number: Optional[int] = None,
    ) -> Dict[str, Any]:
        self._check_rate_limit(self.user_context.get("user_id", "global"))
        self._check_permission(name, "read")
        tmpl = self.get_template(name)
        if version_number is not None:
            template: Dict[str, Any] = {}
            for v in tmpl.versions:
                if v.version == version_number:
                    template = deepcopy(v.template)
                    break
            else:
                raise TemplateManagerError(
                    f"Version {version_number} not found in template {name}"
                )
        else:
            template = tmpl.latest()
        if variables:
            template = self.safe_substitute(template, variables)
        if postprocessor:
            template = postprocessor(template)
        self._security_log(
            "render", name, {"variables": list(variables.keys()) if variables else []}
        )
        return template

    def search(
        self, query: str, limit: int = 20, include_deleted: bool = False
    ) -> List[str]:
        self._check_permission(None, "read")
        q = query.lower()
        result = [
            name
            for name, tmpl in self.templates.items()
            if (not tmpl.deleted or include_deleted)
            and (
                q in name.lower()
                or q in tmpl.author.lower()
                or q in (tmpl.comment or "").lower()
                or q in json.dumps(tmpl.metadata).lower()
            )
        ]
        return sorted(result)[:limit]

    def validate_template_struct(
        self, data: Dict[str, Any], raise_exc: bool = False
    ) -> bool:
        if (
            len(json.dumps(data))
            > self.security_config["max_template_size_mb"] * 1_000_000
        ):
            msg = "Template too large."
            if raise_exc:
                raise TemplateManagerError(msg)
            return False

        def check_depth(obj: Any, depth: int = 0) -> None:
            if depth > self.security_config["max_nesting_depth"]:
                raise TemplateManagerError("Template structure too deeply nested")
            if isinstance(obj, dict):
                for v in obj.values():
                    check_depth(v, depth + 1)
            elif isinstance(obj, list):
                for item in obj:
                    check_depth(item, depth + 1)

        check_depth(data)
        required_keys = {"kind", "layout_type", "elements"}
        valid = isinstance(data, dict) and required_keys.issubset(data.keys())
        if not valid and raise_exc:
            raise TemplateManagerError(
                f"Invalid form template structure, missing required keys: {required_keys - set(data.keys())}"
            )
        return valid

    def promote_version(
        self, name: str, version_number: int, author: str, comment: Optional[str] = None
    ) -> int:
        self._check_permission(name, "write")
        tmpl = self.get_template(name)
        new_ver = tmpl.promote_version(version_number, author, comment)
        self._persist_template(name)
        self._security_log(
            "promote_version", name, {"version": version_number, "by": author}
        )
        return new_ver

    def batch_migrate(
        self,
        migrate_fn: Callable[[Dict[str, Any]], Dict[str, Any]],
        author: str,
        comment: Optional[str] = None,
        include_deleted: bool = False,
    ) -> Dict[str, int]:
        self._check_permission(None, "write")
        out: Dict[str, int] = {}
        for name, tmpl in self.templates.items():
            if tmpl.deleted and not include_deleted:
                continue
            old = tmpl.latest()
            try:
                new = migrate_fn(deepcopy(old))
                if not self.validate_template_struct(new, raise_exc=False):
                    logger.warning(
                        "Migration function produced invalid structure in '%s': skipped",
                        name,
                    )
                    continue
                ver = tmpl.add_version(new, author, comment or "migration")
                if ver:
                    self._persist_template(name)
                    self._security_log(
                        "batch_migrate",
                        name,
                        {"new_version": ver, "by": author, "comment": comment},
                    )
                    out[name] = ver
            except Exception as ex:
                logger.warning("Failed to migrate template '%s': %s", name, ex)
        return out

    def get_template_metadata(self, name: str) -> Dict[str, Any]:
        tmpl = self.get_template(name)
        d = dict(tmpl.metadata) if tmpl.metadata else {}
        d["created_at"] = tmpl.created_at
        return d
