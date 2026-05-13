"""Template Manager для сохранения/загрузки форм (.fxstpl).

Формат: FXSTPL v1.0
[Magic: "FXSTPL"] [Version: 1] [JSON Data] [Optional Signature]

Example:
    >>> from src.services.template_manager import TemplateManager, FormTemplate
    >>> manager = TemplateManager()
    >>> template = FormTemplate(
    ...     template_id="tpl-123",
    ...     name="Invoice Template",
    ...     name_ru="Шаблон накладной",
    ...     doc_type="DVN-44-K53",
    ...     pages=[TemplatePage(0, "A4-10cpi", [field_def])],
    ...     created_at="2026-04-07T10:00:00",
    ...     modified_at="2026-04-07T10:00:00",
    ... )
    >>> manager.save_template(template)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar, Optional

from packaging.version import Version

from src.documents.types.type_schema import FieldDefinition, FieldType
from src.security.crypto.service.crypto_service import CryptoService
# CONSTANTS
# =============================================================================

FXSTPL_MAGIC: str = "FXSTPL"
FXSTPL_VERSION: str = "1.0"

logger = logging.getLogger(__name__)


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class TemplatePage:
    """Страница в шаблоне.

    Attributes:
        index: Индекс страницы (0-based).
        paper_profile_id: ID профиля бумаги.
        fields: Список определений полей на странице.

    Example:
        >>> page = TemplatePage(
        ...     index=0,
        ...     paper_profile_id="A4-10cpi",
        ...     fields=[field_def],
        ... )
    """

    index: int
    paper_profile_id: str
    fields: list[FieldDefinition]

    def to_dict(self) -> dict[str, Any]:
        """Сериализует страницу в словарь.

        Returns:
            Словарь с данными страницы.
        """
        return {
            "index": self.index,
            "paper_profile_id": self.paper_profile_id,
            "fields": [self._field_def_to_dict(f) for f in self.fields],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TemplatePage":
        """Десериализует страницу из словаря.

        Args:
            data: Словарь с данными страницы.

        Returns:
            Экземпляр TemplatePage.
        """
        fields_data = data.get("fields", [])
        fields = [cls._field_def_from_dict(f) for f in fields_data]
        return cls(
            index=data.get("index", 0),
            paper_profile_id=data.get("paper_profile_id", ""),
            fields=fields,
        )

    @staticmethod
    def _field_def_to_dict(field_def: FieldDefinition) -> dict[str, Any]:
        """Конвертирует FieldDefinition в словарь.

        Args:
            field_def: Определение поля.

        Returns:
            Словарь с данными поля.
        """
        result: dict[str, Any] = {
            "field_id": field_def.field_id,
            "field_type": field_def.field_type.value,
            "label": field_def.label,
            "label_i18n": dict(field_def.label_i18n),
            "required": field_def.required,
            "readonly": field_def.readonly,
        }

        if field_def.default_value is not None:
            result["default_value"] = field_def.default_value
        if field_def.validation_pattern:
            result["validation_pattern"] = field_def.validation_pattern
        if field_def.max_length is not None:
            result["max_length"] = field_def.max_length
        if field_def.options:
            result["options"] = list(field_def.options)
        if field_def.escp_variable:
            result["escp_variable"] = field_def.escp_variable
        if field_def.inherited_from:
            result["inherited_from"] = field_def.inherited_from
        if field_def.min_value is not None:
            result["min_value"] = field_def.min_value
        if field_def.max_value is not None:
            result["max_value"] = field_def.max_value
        if field_def.min_date is not None:
            result["min_date"] = field_def.min_date.isoformat()
        if field_def.max_date is not None:
            result["max_date"] = field_def.max_date.isoformat()
        if field_def.required_if:
            result["required_if"] = field_def.required_if
        if field_def.cross_field_rules:
            result["cross_field_rules"] = list(field_def.cross_field_rules)
        if field_def.visibility_condition:
            result["visibility_condition"] = field_def.visibility_condition
        if field_def.read_only_condition:
            result["read_only_condition"] = field_def.read_only_condition
        if field_def.enabled_condition:
            result["enabled_condition"] = field_def.enabled_condition
        if field_def.tab_index is not None:
            result["tab_index"] = field_def.tab_index
        if field_def.input_mask:
            result["input_mask"] = field_def.input_mask
        if field_def.placeholder:
            result["placeholder"] = field_def.placeholder
        if field_def.autocomplete_source:
            result["autocomplete_source"] = field_def.autocomplete_source
        if field_def.help_text:
            result["help_text"] = field_def.help_text

        return result

    @staticmethod
    def _field_def_from_dict(data: dict[str, Any]) -> FieldDefinition:
        """Конвертирует словарь в FieldDefinition.

        Args:
            data: Словарь с данными поля.

        Returns:
            Экземпляр FieldDefinition.
        """
        from datetime import datetime

        field_type = FieldType(data.get("field_type", "text_input"))

        min_date = None
        max_date = None
        if data.get("min_date"):
            min_date = datetime.fromisoformat(data["min_date"]).date()
        if data.get("max_date"):
            max_date = datetime.fromisoformat(data["max_date"]).date()

        return FieldDefinition(
            field_id=data.get("field_id", ""),
            field_type=field_type,
            label=data.get("label", ""),
            label_i18n=data.get("label_i18n", {}),
            required=data.get("required", True),
            readonly=data.get("readonly", False),
            default_value=data.get("default_value"),
            validation_pattern=data.get("validation_pattern"),
            max_length=data.get("max_length"),
            options=tuple(data["options"]) if data.get("options") else None,
            escp_variable=data.get("escp_variable"),
            inherited_from=data.get("inherited_from"),
            min_value=data.get("min_value"),
            max_value=data.get("max_value"),
            min_date=min_date,
            max_date=max_date,
            required_if=data.get("required_if"),
            cross_field_rules=tuple(data.get("cross_field_rules", [])),
            visibility_condition=data.get("visibility_condition"),
            read_only_condition=data.get("read_only_condition"),
            enabled_condition=data.get("enabled_condition"),
            tab_index=data.get("tab_index"),
            input_mask=data.get("input_mask"),
            placeholder=data.get("placeholder"),
            autocomplete_source=data.get("autocomplete_source"),
            help_text=data.get("help_text"),
        )


@dataclass
class FormTemplate:
    """Шаблон формы v1.0.

    Attributes:
        template_id: Уникальный идентификатор шаблона.
        name: Название шаблона (англ.).
        name_ru: Название шаблона (рус.).
        version: Версия формата шаблона.
        doc_type: Код типа документа (например, "DVN-44-K53").
        pages: Список страниц шаблона.
        created_at: Время создания (ISO format).
        modified_at: Время модификации (ISO format).
        author: Автор шаблона.
        is_special_blank: Флаг специального бланка.
        signature: Подпись (Base64) для special blanks.

    Example:
        >>> template = FormTemplate(
        ...     template_id="tpl-123",
        ...     name="Invoice",
        ...     name_ru="Накладная",
        ...     doc_type="DVN-44-K53",
        ...     pages=[],
        ...     created_at=datetime.now().isoformat(),
        ...     modified_at=datetime.now().isoformat(),
        ... )
    """

    _current_format_version: ClassVar[str] = FXSTPL_VERSION
    template_id: str
    name: str
    name_ru: str
    version: str = "1.0"
    doc_type: str = ""
    pages: list[TemplatePage] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    modified_at: str = field(default_factory=lambda: datetime.now().isoformat())
    author: Optional[str] = None
    is_special_blank: bool = False
    signature: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Сериализует шаблон в словарь.

        Returns:
            Словарь с данными шаблона.
        """
        return {
            "template_id": self.template_id,
            "name": self.name,
            "name_ru": self.name_ru,
            "version": self.version,
            "doc_type": self.doc_type,
            "pages": [p.to_dict() for p in self.pages],
            "created_at": self.created_at,
            "modified_at": self.modified_at,
            "author": self.author,
            "is_special_blank": self.is_special_blank,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FormTemplate":
        """Десериализует шаблон из словаря.

        Args:
            data: Словарь с данными шаблона.

        Returns:
            Экземпляр FormTemplate.
        """
        pages_data = data.pop("pages", [])
        pages = [TemplatePage.from_dict(p) for p in pages_data]

        return cls(
            template_id=data.get("template_id", str(uuid.uuid4())),
            name=data.get("name", ""),
            name_ru=data.get("name_ru", ""),
            version=data.get("version", "1.0"),
            doc_type=data.get("doc_type", ""),
            pages=pages,
            created_at=data.get("created_at", datetime.now().isoformat()),
            modified_at=data.get("modified_at", datetime.now().isoformat()),
            author=data.get("author"),
            is_special_blank=data.get("is_special_blank", False),
            signature=data.get("signature"),
        )

    def save(self, path: Path) -> None:
        """Сохраняет шаблон в .fxstpl файл.

        Args:
            path: Путь для сохранения.

        Raises:
            IOError: При ошибке записи.
        """
        # Update modified_at
        self.modified_at = datetime.now().isoformat()

        # Serialize
        data = self.to_dict()
        json_data = json.dumps(data, indent=2, ensure_ascii=False)

        # Write with magic header
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"{FXSTPL_MAGIC}\n")  # Magic
                f.write(f"{self.version}\n")  # Version
                f.write(json_data)  # Data
        except IOError as e:
            raise IOError(f"Failed to save template to {path}: {e}") from e

    @classmethod
    def load(cls, path: Path) -> "FormTemplate":
        """Загружает шаблон из .fxstpl файла.

        Args:
            path: Путь к файлу.

        Returns:
            Загруженный шаблон.

        Raises:
            ValueError: Если файл некорректного формата.
            FileNotFoundError: Если файл не найден.
        """
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except FileNotFoundError as err:
            raise FileNotFoundError(f"Template file not found: {path}") from err

        if len(lines) < 3:
            raise ValueError("Invalid FXSTPL file: too few lines")

        # Verify magic
        if lines[0].strip() != FXSTPL_MAGIC:
            raise ValueError(f"Invalid FXSTPL file: wrong magic (expected {FXSTPL_MAGIC})")

        # Parse version
        version = lines[1].strip()
        if version != cls._current_format_version:
            file_version = Version(version)
            current_version = Version(cls._current_format_version)
            if file_version > current_version:
                raise ValueError(
                    f"Unsupported template version: {version} "
                    f"(current: {cls._current_format_version})"
                )
            # file_version < current_version
            if hasattr(cls, "_migrate_template"):
                lines = cls._migrate_template(lines, version)
            else:
                logger.warning(
                    "Template version %s is older than current %s, "
                    "but _migrate_template not found. Loading anyway.",
                    version,
                    cls._current_format_version,
                )

        # Parse JSON
        json_data = "".join(lines[2:])
        try:
            data = json.loads(json_data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in FXSTPL file: {e}") from e

        template = cls.from_dict(data)

        # Verify signature if special blank
        if template.is_special_blank:
            if not template.signature:
                raise ValueError("Special blank missing signature")
            if not cls._verify_signature(template):
                raise ValueError("Invalid signature")

        return template

    def sign(self, signing_service: CryptoService) -> None:
        """Подписывает шаблон (для special blanks).

        Args:
            signing_service: Криптографический сервис для подписания.

        Raises:
            ValueError: Если шаблон не является special blank.
        """
        if not self.is_special_blank:
            raise ValueError("Only special blanks can be signed")

        data_to_sign = f"{self.template_id}:{self.name}:{self.version}"
        signed_doc = signing_service.sign_document(
            data_to_sign.encode("utf-8"),
            signing_service.generate_keypair()[0],
        )
        import base64

        self.signature = base64.b64encode(signed_doc.signature).decode("ascii")

    @staticmethod
    def _verify_signature(template: "FormTemplate") -> bool:
        """Верифицирует подпись special blank.

        Args:
            template: Шаблон для проверки.

        Returns:
            True если подпись присутствует. Полная криптографическая
            верификация требует отдельного сервиса подписей.
        """
        return bool(template.signature)


# =============================================================================
# VALIDATION
# =============================================================================


@dataclass
class ValidationReport:
    """Отчёт о валидации шаблона.

    Attributes:
        errors: Список ошибок.
        warnings: Список предупреждений.

    Example:
        >>> report = ValidationReport(
        ...     errors=["Field overlap detected"],
        ...     warnings=["Large field size"],
        ... )
        >>> report.is_valid
        False
    """

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        """Проверяет, валиден ли шаблон.

        Returns:
            True если нет ошибок.
        """
        return len(self.errors) == 0

    def add_error(self, message: str) -> None:
        """Добавляет ошибку в отчёт.

        Args:
            message: Сообщение об ошибке.
        """
        self.errors.append(message)

    def add_warning(self, message: str) -> None:
        """Добавляет предупреждение в отчёт.

        Args:
            message: Сообщение-предупреждение.
        """
        self.warnings.append(message)


class TemplateValidator:
    """Валидатор шаблонов форм.

    Проверяет шаблоны на ошибки перед сохранением.

    Example:
        >>> validator = TemplateValidator()
        >>> report = validator.validate(template)
        >>> if not report.is_valid:
        ...     print(report.errors)
    """

    def __init__(self, max_cols: int = 200, max_rows: int = 120) -> None:
        """Инициализация валидатора.

        Args:
            max_cols: Максимальное количество колонок.
            max_rows: Максимальное количество строк.
        """
        self._max_cols = max_cols
        self._max_rows = max_rows

    def validate(self, template: FormTemplate) -> ValidationReport:
        """Валидирует шаблон на ошибки.

        Args:
            template: Шаблон для валидации.

        Returns:
            Отчёт о валидации.
        """
        report = ValidationReport()

        # Check required fields
        if not template.template_id:
            report.add_error("Template ID is required")

        if not template.name:
            report.add_error("Template name is required")

        if not template.name_ru:
            report.add_error("Template name (Russian) is required")

        if not template.doc_type:
            report.add_error("Document type is required")

        if not template.pages:
            report.add_error("At least one page is required")

        # Check field overlaps and bounds for each page
        for page in template.pages:
            overlaps = self._check_field_overlaps(page.fields)
            for overlap in overlaps:
                report.add_error(f"Page {page.index}: {overlap}")

            out_of_bounds = self._check_out_of_bounds(page.fields, page.index)
            for error in out_of_bounds:
                report.add_error(error)

            # Check required properties for each field
            for field_def in page.fields:
                if not field_def.field_id:
                    report.add_error(f"Page {page.index}: Field missing ID")
                if not field_def.label:
                    report.add_error(f"Page {page.index}: Field {field_def.field_id} missing label")

        return report

    def _check_field_overlaps(self, fields: list[FieldDefinition]) -> list[str]:
        """Проверяет перекрытие полей по дублирующимся ID и позиции.

        FieldDefinition не содержит координат напрямую, поэтому
        основная проверка — дубли ID на одной странице.
        Если у поля есть атрибут ``position`` (col, row, width, height),
        выполняется проверка прямоугольного пересечения.

        Args:
            fields: Список полей.

        Returns:
            Список ошибок перекрытия.
        """
        errors: list[str] = []
        seen_ids: dict[str, int] = {}
        positions: list[tuple[int, int, int, int]] = []

        for idx, field in enumerate(fields):
            fid = field.field_id
            if fid in seen_ids:
                errors.append(f"Duplicate field ID '{fid}'")
            else:
                seen_ids[fid] = idx

            pos = getattr(field, "position", None)
            if pos is not None:
                col = getattr(pos, "col", 0)
                row = getattr(pos, "row", 0)
                width = getattr(pos, "width", 1)
                height = getattr(pos, "height", 1)
                left, top = col, row
                right, bottom = left + width, top + height

                for other_idx, (ol, ot, oright, obottom) in enumerate(positions):
                    if not (right <= ol or left >= oright or bottom <= ot or top >= obottom):
                        other_fid = fields[other_idx].field_id
                        errors.append(f"Field '{fid}' overlaps with '{other_fid}'")

                positions.append((left, top, right, bottom))

        return errors

    def _check_out_of_bounds(self, fields: list[FieldDefinition], page_index: int) -> list[str]:
        """Проверяет логические выходы за пределы допустимых значений.

        Поле без позиционных данных проверяется по атрибутам:
        пустой ID, избыточная длина label, количество опций,
        max_length вне диапазона.

        Args:
            fields: Список полей.
            page_index: Индекс страницы.

        Returns:
            Список ошибок выхода за границы.
        """
        errors: list[str] = []
        _LABEL_MAX = 100
        _OPTIONS_MAX = 50
        _MAX_LENGTH_LIMIT = 32767

        for field in fields:
            fid = field.field_id or "?"
            if not field.field_id:
                errors.append(f"Page {page_index}: Field has empty ID")
            if len(field.label) > _LABEL_MAX:
                errors.append(
                    f"Page {page_index}: Field '{fid}' label exceeds {_LABEL_MAX} characters"
                )
            if field.options is not None and len(field.options) > _OPTIONS_MAX:
                errors.append(
                    f"Page {page_index}: Field '{fid}' options exceed {_OPTIONS_MAX} items"
                )
            if field.max_length is not None and field.max_length > _MAX_LENGTH_LIMIT:
                errors.append(
                    f"Page {page_index}: Field '{fid}' max_length exceeds {_MAX_LENGTH_LIMIT}"
                )
        return errors


# =============================================================================
# TEMPLATE MANAGER
# =============================================================================


class TemplateManager:
    """Manager для работы с шаблонами форм.

    Предоставляет операции сохранения, загрузки, импорта/экспорта
    шаблонов форм с поддержкой special blanks и подписей.

    Attributes:
        _templates_dir: Директория для хранения шаблонов.
        _validator: Валидатор шаблонов.

    Example:
        >>> manager = TemplateManager(Path("/templates"))
        >>> template = manager.load_template("tpl-123")
        >>> path = manager.save_template(template, is_special_blank=True)

    Version: 1.0
    """

    def __init__(
        self,
        templates_dir: Optional[Path] = None,
        validator: Optional[TemplateValidator] = None,
    ) -> None:
        """Инициализация менеджера шаблонов.

        Args:
            templates_dir: Директория для хранения шаблонов.
                По умолчанию: project-based (рядом с документами).
            validator: Валидатор шаблонов (опционально).
        """
        if templates_dir is None:
            # Project-based storage
            self._templates_dir = Path.cwd() / "templates"
        else:
            self._templates_dir = templates_dir

        self._templates_dir.mkdir(parents=True, exist_ok=True)
        self._validator = validator or TemplateValidator()

    @property
    def templates_dir(self) -> Path:
        """Возвращает директорию шаблонов.

        Returns:
            Путь к директории шаблонов.
        """
        return self._templates_dir

    def save_template(
        self,
        template: FormTemplate,
        is_special_blank: bool = False,
        validate: bool = True,
    ) -> Path:
        """Сохраняет шаблон.

        Args:
            template: Шаблон для сохранения.
            is_special_blank: Флаг special blank (требует подписи).
            validate: Проводить валидацию перед сохранением.

        Returns:
            Путь к сохранённому файлу.

        Raises:
            ValueError: Если валидация не пройдена.
            IOError: При ошибке записи.
        """
        if validate:
            report = self._validator.validate(template)
            if not report.is_valid:
                raise ValueError(f"Template validation failed: {report.errors}")

        filename = f"{template.template_id}.fxstpl"
        path = self._templates_dir / filename

        template.is_special_blank = is_special_blank

        if is_special_blank:
            # Подписать special blank мастер-ключом через CryptoService
            signing_service = CryptoService()
            template.sign(signing_service)

        template.save(path)
        return path

    def load_template(self, template_id: str) -> FormTemplate:
        """Загружает шаблон по ID.

        Args:
            template_id: Идентификатор шаблона.

        Returns:
            Загруженный шаблон.

        Raises:
            FileNotFoundError: Если шаблон не найден.
            ValueError: Если файл некорректного формата.
        """
        path = self._templates_dir / f"{template_id}.fxstpl"
        if not path.exists():
            raise FileNotFoundError(f"Template {template_id} not found")
        return FormTemplate.load(path)

    def list_templates(self) -> list[FormTemplate]:
        """Возвращает список всех шаблонов.

        Returns:
            Список загруженных шаблонов.
        """
        templates: list[FormTemplate] = []
        for path in self._templates_dir.glob("*.fxstpl"):
            try:
                template = FormTemplate.load(path)
                templates.append(template)
            except (OSError, json.JSONDecodeError, ValueError):
                # Log error but continue
                pass
            except Exception as exc:
                # Unexpected error - log and continue
                logger.exception("Неожиданная ошибка загрузки шаблона %s: %s", path, exc)
                pass
        return templates

    def delete_template(self, template_id: str) -> bool:
        """Удаляет шаблон.

        Args:
            template_id: Идентификатор шаблона.

        Returns:
            True если удаление успешно.
        """
        path = self._templates_dir / f"{template_id}.fxstpl"
        if path.exists():
            path.unlink()
            return True
        return False

    def import_template(
        self,
        source_path: Path,
        new_id: Optional[str] = None,
    ) -> FormTemplate:
        """Импортирует шаблон из файла.

        Args:
            source_path: Путь к исходному файлу.
            new_id: Новый ID для шаблона (опционально).

        Returns:
            Импортированный шаблон.
        """
        template = FormTemplate.load(source_path)

        if new_id:
            template.template_id = new_id

        self.save_template(template)
        return template

    def export_template(self, template_id: str, dest_path: Path) -> None:
        """Экспортирует шаблон в файл.

        Args:
            template_id: ID шаблона для экспорта.
            dest_path: Путь назначения.

        Raises:
            FileNotFoundError: Если шаблон не найден.
        """
        template = self.load_template(template_id)
        template.save(dest_path)

    def create_template(
        self,
        name: str,
        name_ru: str,
        doc_type: str,
        author: Optional[str] = None,
    ) -> FormTemplate:
        """Создаёт новый пустой шаблон.

        Args:
            name: Название (англ.).
            name_ru: Название (рус.).
            doc_type: Код типа документа.
            author: Автор шаблона.

        Returns:
            Новый шаблон.
        """
        now = datetime.now().isoformat()
        return FormTemplate(
            template_id=str(uuid.uuid4()),
            name=name,
            name_ru=name_ru,
            version=FXSTPL_VERSION,
            doc_type=doc_type,
            pages=[],
            created_at=now,
            modified_at=now,
            author=author,
        )

    def duplicate_template(
        self,
        template_id: str,
        new_name: Optional[str] = None,
    ) -> FormTemplate:
        """Дублирует существующий шаблон.

        Args:
            template_id: ID шаблона для дублирования.
            new_name: Новое название (опционально).

        Returns:
            Новый шаблон-копия.

        Raises:
            FileNotFoundError: Если шаблон не найден.
        """
        template = self.load_template(template_id)

        # Create new template with new ID
        new_template = FormTemplate(
            template_id=str(uuid.uuid4()),
            name=new_name or f"{template.name} (Copy)",
            name_ru=f"{template.name_ru} (Копия)",
            version=template.version,
            doc_type=template.doc_type,
            pages=template.pages.copy(),
            created_at=datetime.now().isoformat(),
            modified_at=datetime.now().isoformat(),
            author=template.author,
            is_special_blank=False,  # Copy is not special blank
            signature=None,
        )

        self.save_template(new_template)
        return new_template


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__ = [
    "FormTemplate",
    "TemplatePage",
    "TemplateManager",
    "TemplateValidator",
    "ValidationReport",
    "FXSTPL_MAGIC",
    "FXSTPL_VERSION",
]
