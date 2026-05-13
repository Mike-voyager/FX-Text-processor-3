"""FormController для управления структурированными формами (Super Docs).

Контроллер управляет полным жизненным циклом форм:
- Дизайнер форм (FormDesignerWindow) — создание и редактирование шаблонов
- Конструктор форм (FormConstructor) — создание экземпляров из шаблонов
- Валидатор полей (FormValidator) — проверка значений полей
- Менеджер статусов (FormStatus) — DRAFT → FILLED → VALIDATED → SIGNED → ARCHIVED
- Защищённые бланки (BlankManager) — криптографическая защита документов

Architecture:
    Controller → координация View ↔ Service, NO сложная бизнес-логика
    Service Layer → FormConstructor, FormValidator, BlankManager
    View → FormDesignerWindow через callbacks

Dependencies (DI через конструктор):
    - FormDesignerWindow: UI для дизайна форм (опционально)
    - TypeRegistry: реестр типов документов
    - FormConstructor: создание форм из шаблонов
    - BlankManager: управление защищёнными бланками (опционально)

Example:
    >>> from src.controller.form_controller import FormController
    >>> controller = FormController(
    ...     type_registry=type_registry,
    ...     form_constructor=form_constructor,
    ...     blank_manager=blank_manager,
    ... )
    >>>
    >>> # Открыть дизайнер форм
    >>> controller.open_form_designer(template_id="DVN")
    >>>
    >>> # Создать форму
    >>> result = controller.create_form("DVN")
    >>> if result.success:
    ...     form = result.data
    ...     print(f"Создана форма: {form.index}")
    >>>
    >>> # Валидировать
    >>> report = controller.validate_form(form.form_id)
    >>> if report.is_valid:
    ...     controller.sign_form(form.form_id, device_id="YubiKey-001")
"""

from __future__ import annotations

import logging
import re
import tkinter as tk
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Protocol,
    Tuple,
)
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from src.view.form_designer.form_designer_window import FormDesignerWindow


# =============================================================================
# CONSTANTS
# =============================================================================

TEMPLATE_EXTENSION = ".fxstpl"
FORM_EXTENSION = ".fxsd"
MAX_FORM_FIELDS = 1000


# =============================================================================
# ENUMS
# =============================================================================


class FormStatus(Enum):
    """Состояния жизненного цикла формы.

    Состояния:
        DRAFT: Черновик — редактирование разрешено.
        FILLED: Заполнена — ожидает валидации.
        VALIDATED: Проверена — ожидает подписи.
        SIGNED: Подписана — поля заблокированы.
        ARCHIVED: Архивирована — терминальное состояние.
        REJECTED: Отклонена — возврат для исправления.
    """

    DRAFT = "draft"
    FILLED = "filled"
    VALIDATED = "validated"
    SIGNED = "signed"
    ARCHIVED = "archived"
    REJECTED = "rejected"

    @property
    def is_editable(self) -> bool:
        """Разрешено ли редактирование в этом состоянии."""
        return self == FormStatus.DRAFT

    @property
    def is_terminal(self) -> bool:
        """Является ли состояние терминальным."""
        return self == FormStatus.ARCHIVED


class Severity(Enum):
    """Уровень серьёзности ошибки валидации."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class FieldType(Enum):
    """Типы полей формы."""

    TEXT = "text"
    NUMBER = "number"
    DATE = "date"
    DROPDOWN = "dropdown"
    CHECKBOX = "checkbox"
    TEXTAREA = "textarea"
    TABLE = "table"
    SIGNATURE = "signature"


# =============================================================================
# PROTOCOLS (Service Layer Interfaces)
# =============================================================================


class TypeRegistryProtocol(Protocol):
    """Протокол реестра типов документов."""

    def get(self, type_code: str) -> "DocumentTypeProtocol":
        """Возвращает тип документа по коду."""
        ...

    def list_types(self) -> List[Tuple[str, str]]:
        """Возвращает список (code, name) доступных типов."""
        ...

    def __contains__(self, type_code: str) -> bool:
        """Проверяет существование типа."""
        ...


class DocumentTypeProtocol(Protocol):
    """Протокол типа документа."""

    code: str
    name: str
    description: str


class FormConstructorProtocol(Protocol):
    """Протокол конструктора форм."""

    def create_from_type(
        self,
        type_code: str,
        **initial_values: Any,
    ) -> Dict[str, Any]:
        """Создаёт форму из типа документа."""
        ...

    def get_form_schema(self, type_code: str) -> "FormSchemaProtocol":
        """Возвращает схему полей для типа."""
        ...

    def list_available_types(self) -> List[Tuple[str, str]]:
        """Возвращает список доступных типов."""
        ...


class FormSchemaProtocol(Protocol):
    """Протокол схемы формы."""

    fields: List["FieldDefinitionProtocol"]


class FieldDefinitionProtocol(Protocol):
    """Протокол определения поля."""

    field_id: str
    field_type: FieldType
    label: str
    required: bool
    validation_rules: List[Dict[str, Any]]


class FormValidatorProtocol(Protocol):
    """Протокол валидатора форм."""

    def validate_field(
        self,
        field_id: str,
        value: Any,
        field_def: FieldDefinitionProtocol,
    ) -> List["ValidationResultProtocol"]:
        """Валидирует отдельное поле."""
        ...

    def validate_cross_fields(
        self,
        field_values: Dict[str, Any],
        schema: FormSchemaProtocol,
    ) -> List["ValidationResultProtocol"]:
        """Выполняет кросс-полевую валидацию."""
        ...


class ValidationResultProtocol(Protocol):
    """Протокол результата валидации."""

    field_id: Optional[str]
    severity: Severity
    code: str
    message: str


class BlankManagerProtocol(Protocol):
    """Протокол менеджера защищённых бланков."""

    def issue_blank(
        self,
        series: str,
        number: int,
        blank_type: str,
        security_preset: str = "standard",
    ) -> "ProtectedBlankProtocol":
        """Выпускает новый защищённый бланк."""
        ...

    def get_blank_by_series_number(
        self,
        series: str,
        number: str,
    ) -> Optional["ProtectedBlankProtocol"]:
        """Находит бланк по серии и номеру."""
        ...

    def sign_blank(
        self,
        blank_id: str,
        document_content: bytes,
        device_id: Optional[str] = None,
        pin: Optional[str] = None,
    ) -> Tuple["ProtectedBlankProtocol", bytes, "QRVerificationDataProtocol"]:
        """Подписывает документ на бланке."""
        ...


class ProtectedBlankProtocol(Protocol):
    """Протокол защищённого бланка."""

    blank_id: str
    series: str
    number: int
    status: str


class QRVerificationDataProtocol(Protocol):
    """Протокол данных QR-кода для верификации."""

    verification_url: str
    verification_code: str


class FormDesignerWindowProtocol(Protocol):
    """Протокол окна дизайнера форм."""

    def destroy(self) -> None:
        """Уничтожает окно."""
        ...

    def run(self) -> None:
        """Запускает главный цикл."""
        ...

    def lift(self) -> None:
        """Поднимает окно на передний план."""
        ...

    def focus_force(self) -> None:
        """Принудительно устанавливает фокус на окно."""
        ...


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass(frozen=True)
class FormTemplate:
    """Шаблон формы.

    Attributes:
        template_id: Уникальный идентификатор шаблона (UUID)
        type_code: Код типа документа (DVN, INV, и т.д.)
        name: Название шаблона
        description: Описание шаблона
        field_layout: Расположение полей на форме
        validation_rules: Правила валидации
        created_at: ISO timestamp создания
        modified_at: ISO timestamp изменения
        signature: Подпись шаблона (для проверки целостности)
    """

    template_id: str
    type_code: str
    name: str
    description: str = ""
    field_layout: Dict[str, Any] = field(default_factory=dict)
    validation_rules: List[Dict[str, Any]] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: "__import__('datetime').datetime.now().isoformat()"
    )
    modified_at: str = field(
        default_factory=lambda: "__import__('datetime').datetime.now().isoformat()"
    )
    signature: bytes = field(default_factory=bytes)

    def __post_init__(self) -> None:
        """Валидация после инициализации."""
        if not self.template_id:
            object.__setattr__(self, "template_id", str(uuid4()))


@dataclass(frozen=True)
class FormInstance:
    """Экземпляр заполненной формы.

    Attributes:
        form_id: Уникальный идентификатор формы (UUID)
        template_id: ID шаблона, на основе которого создана
        type_code: Код типа документа
        status: Текущий статус формы
        index: Полный индекс формы (DVN-44-K53-I)
        field_values: Значения полей {field_id: value}
        created_at: ISO timestamp создания
        modified_at: ISO timestamp изменения
        signed_at: ISO timestamp подписания (или None)
        signed_by: Кем подписано (или None)
    """

    form_id: UUID
    template_id: str
    type_code: str
    status: FormStatus
    index: str = ""
    field_values: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(
        default_factory=lambda: "__import__('datetime').datetime.now().isoformat()"
    )
    modified_at: str = field(
        default_factory=lambda: "__import__('datetime').datetime.now().isoformat()"
    )
    signed_at: Optional[str] = None
    signed_by: Optional[str] = None


@dataclass(frozen=True)
class ValidationResult:
    """Результат валидации поля.

    Attributes:
        field_id: ID поля (None для общих ошибок)
        severity: Уровень серьёзности
        code: Код ошибки
        message: Сообщение об ошибке
    """

    field_id: Optional[str]
    severity: Severity
    code: str
    message: str


@dataclass
class ValidationReport:
    """Отчёт о валидации формы.

    Attributes:
        form_id: ID формы
        is_valid: True если нет критических ошибок
        errors: Список критических ошибок
        warnings: Список предупреждений
        info: Информационные сообщения
    """

    form_id: UUID
    is_valid: bool
    errors: List[ValidationResult] = field(default_factory=list)
    warnings: List[ValidationResult] = field(default_factory=list)
    info: List[ValidationResult] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        """Есть ли критические ошибки."""
        return len(self.errors) > 0

    @property
    def has_warnings(self) -> bool:
        """Есть ли предупреждения."""
        return len(self.warnings) > 0

    @property
    def total_issues(self) -> int:
        """Общее количество проблем."""
        return len(self.errors) + len(self.warnings) + len(self.info)


@dataclass
class FormControllerResult:
    """Результат операции контроллера форм.

    Attributes:
        success: True при успехе
        data: Данные результата (тип зависит от операции)
        error: Сообщение об ошибке (или None)
    """

    success: bool
    data: Any = None
    error: Optional[str] = None

    def unwrap(self) -> Any:
        """Возвращает данные или выбрасывает исключение."""
        if not self.success:
            raise FormControllerError(self.error or "Unknown error")
        return self.data


# =============================================================================
# EXCEPTIONS
# =============================================================================


class FormControllerError(Exception):
    """Базовое исключение контроллера форм."""

    pass


class FormNotFoundError(FormControllerError):
    """Форма не найдена."""

    pass


class TemplateNotFoundError(FormControllerError):
    """Шаблон не найден."""

    pass


class StatusTransitionError(FormControllerError):
    """Недопустимый переход статуса."""

    pass


class ValidationError(FormControllerError):
    """Ошибка валидации формы."""

    pass


class BlankManagerNotConfiguredError(FormControllerError):
    """BlankManager не настроен."""

    pass


class BlankIssuanceError(FormControllerError):
    """Ошибка выпуска бланков."""

    pass


class FormSigningError(FormControllerError):
    """Ошибка подписи формы."""

    pass


class FormValidationError(FormControllerError):
    """Ошибка валидации формы."""

    pass


class InvalidTemplateError(FormControllerError):
    """Неверный шаблон формы."""

    pass


# =============================================================================
# FORM STATUS MANAGER
# =============================================================================


class FormStatusManager:
    """Менеджер статусов форм.

    Управляет допустимыми переходами между статусами форм.
    """

    # Допустимые переходы: from -> list of to
    _ALLOWED_TRANSITIONS: Dict[FormStatus, List[FormStatus]] = {
        FormStatus.DRAFT: [FormStatus.FILLED, FormStatus.REJECTED],
        FormStatus.FILLED: [
            FormStatus.VALIDATED,
            FormStatus.DRAFT,
            FormStatus.REJECTED,
        ],
        FormStatus.VALIDATED: [
            FormStatus.SIGNED,
            FormStatus.FILLED,
            FormStatus.REJECTED,
        ],
        FormStatus.SIGNED: [FormStatus.ARCHIVED, FormStatus.VALIDATED],
        FormStatus.REJECTED: [FormStatus.DRAFT],
        FormStatus.ARCHIVED: [],  # Терминальное состояние
    }

    def can_transition(self, from_status: FormStatus, to_status: FormStatus) -> bool:
        """Проверяет возможность перехода между статусами.

        Args:
            from_status: Исходный статус
            to_status: Целевой статус

        Returns:
            True если переход допустим
        """
        allowed = self._ALLOWED_TRANSITIONS.get(from_status, [])
        return to_status in allowed

    def get_allowed_transitions(self, status: FormStatus) -> List[FormStatus]:
        """Возвращает список допустимых переходов из статуса.

        Args:
            status: Текущий статус

        Returns:
            Список допустимых целевых статусов
        """
        return self._ALLOWED_TRANSITIONS.get(status, []).copy()

    def validate_transition(self, from_status: FormStatus, to_status: FormStatus) -> None:
        """Валидирует переход, выбрасывает исключение при ошибке.

        Args:
            from_status: Исходный статус
            to_status: Целевой статус

        Raises:
            StatusTransitionError: Если переход недопустим
        """
        if not self.can_transition(from_status, to_status):
            allowed = self.get_allowed_transitions(from_status)
            allowed_names = [s.value for s in allowed]
            raise StatusTransitionError(
                f"Недопустимый переход из {from_status.value} в {to_status.value}. "
                f"Допустимые переходы: {allowed_names}"
            )


# =============================================================================
# FORM CONTROLLER
# =============================================================================


class FormController:
    """Контроллер управления структурированными формами.

    Управляет полным жизненным циклом форм от создания шаблонов
    до архивации подписанных документов.

    Attributes:
        _type_registry: Реестр типов документов
        _form_constructor: Конструктор форм из шаблонов
        _form_validator: Валидатор полей форм
        _status_manager: Менеджер статусов форм
        _blank_manager: Менеджер защищённых бланков (опционально)
        _templates: Кэш загруженных шаблонов
        _forms: Кэш открытых экземпляров форм
        _designer_window: Окно дизайнера форм
        _callbacks: Callback-функции для событий
        _logger: Логгер

    Example:
        >>> controller = FormController(
        ...     type_registry=type_registry,
        ...     form_constructor=form_constructor,
        ... )
        >>>
        >>> # Создать форму
        >>> result = controller.create_form("DVN")
        >>> if result.success:
        ...     form = result.data
        ...     print(f"Создана форма: {form.index}")
    """

    def __init__(
        self,
        type_registry: TypeRegistryProtocol,
        form_constructor: FormConstructorProtocol,
        form_validator: Optional[FormValidatorProtocol] = None,
        blank_manager: Optional[BlankManagerProtocol] = None,
        parent_window: Optional[tk.Tk] = None,
        theme: str = "classic_green",
    ) -> None:
        """Инициализирует FormController.

        Args:
            type_registry: Реестр типов документов
            form_constructor: Конструктор форм
            form_validator: Валидатор полей (опционально)
            blank_manager: Менеджер защищённых бланков (опционально)
            parent_window: Родительское окно для дизайнера (опционально)
            theme: Тема оформления
        """
        self._type_registry = type_registry
        self._form_constructor = form_constructor
        self._form_validator = form_validator
        self._status_manager = FormStatusManager()
        self._blank_manager = blank_manager
        self._parent_window = parent_window
        self._theme = theme

        # Кэш
        self._templates: Dict[str, FormTemplate] = {}
        self._forms: Dict[UUID, FormInstance] = {}

        # UI компоненты
        self._designer_window: Optional[FormDesignerWindow] = None

        # Callbacks
        self._callbacks: Dict[str, Callable[..., Any]] = {}

        # Логгер
        self._logger = logging.getLogger(__name__)
        self._logger.debug("FormController инициализирован")

    # -------------------------------------------------------------------------
    # Form Designer Operations
    # -------------------------------------------------------------------------

    def open_form_designer(
        self,
        template_id: Optional[str] = None,
        form_id: Optional[UUID] = None,
    ) -> bool:
        """Открывает дизайнер форм.

        Открывает FormDesignerWindow для редактирования шаблона
        или существующей формы.

        Args:
            template_id: ID шаблона для редактирования (опционально)
            form_id: ID существующей формы (опционально)

        Returns:
            True если дизайнер открыт успешно

        Example:
            >>> # Создать новую форму по шаблону DVN
            >>> controller.open_form_designer(template_id="DVN")
            >>>
            >>> # Открыть существующую форму для редактирования
            >>> controller.open_form_designer(form_id=form_uuid)
        """
        try:
            if self._designer_window is not None:
                # Дизайнер уже открыт - активируем
                self._logger.debug("Дизайнер уже открыт")
                self._designer_window.lift()
                self._designer_window.focus_force()
                self._show_error("Дизайнер форм уже открыт")
                return True

            if self._parent_window is None:
                self._logger.error("Нет родительского окна для дизайнера")
                return False

            # Импортируем здесь для избежания циклических зависимостей
            from src.view.form_designer.form_designer_window import (
                FormDesignerWindow,
            )

            # Создаём окно дизайнера
            self._designer_window = FormDesignerWindow(
                title="Form Designer - FX Text Processor 3",
                theme=self._theme,
            )

            # Регистрируем callbacks
            self._designer_window.register_callback("on_save", self._on_designer_save)
            self._designer_window.register_callback("on_export", self._on_designer_export)
            self._designer_window.register_callback("on_close", self._on_designer_close)

            # Загружаем данные
            if form_id and form_id in self._forms:
                form = self._forms[form_id]
                if not form.status.is_editable:
                    self._logger.warning(
                        f"Форма {form_id} в статусе {form.status.value}, "
                        "открываем только для чтения"
                    )
            elif template_id and template_id in self._templates:
                template = self._templates[template_id]
                self._logger.debug(f"Загружен шаблон: {template.name}")

            self._invoke_callback("on_designer_open", template_id, form_id)
            self._logger.info(f"Открыт дизайнер форм (template={template_id}, form={form_id})")
            return True

        except Exception as e:
            self._logger.error(f"Ошибка открытия дизайнера: {e}")
            return False

    def close_form_designer(self) -> bool:
        """Закрывает дизайнер форм.

        Returns:
            True если дизайнер закрыт успешно
        """
        if self._designer_window is None:
            return True

        try:
            self._designer_window.destroy()
            self._designer_window = None
            self._invoke_callback("on_designer_close")
            return True
        except Exception as e:
            self._logger.error(f"Ошибка закрытия дизайнера: {e}")
            return False

    def is_designer_open(self) -> bool:
        """Проверяет, открыт ли дизайнер.

        Returns:
            True если дизайнер открыт
        """
        return self._designer_window is not None

    # -------------------------------------------------------------------------
    # Template Operations
    # -------------------------------------------------------------------------

    def load_template(self, path: Path) -> FormControllerResult:
        """Загружает шаблон формы из файла.

        Args:
            path: Путь к файлу шаблона (.fxstpl)

        Returns:
            FormControllerResult с загруженным FormTemplate

        Example:
            >>> result = controller.load_template(Path("/templates/invoice.fxstpl"))
            >>> if result.success:
            ...     template = result.data
            ...     print(f"Загружен: {template.name}")
        """
        try:
            if not path.exists():
                return FormControllerResult(
                    success=False,
                    error=f"Файл шаблона не найден: {path}",
                )

            if path.suffix != TEMPLATE_EXTENSION:
                return FormControllerResult(
                    success=False,
                    error=f"Неверное расширение файла: {path.suffix}. "
                    f"Ожидается: {TEMPLATE_EXTENSION}",
                )

            import json

            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            template = FormTemplate(
                template_id=data.get("template_id", str(uuid4())),
                type_code=data.get("type_code", ""),
                name=data.get("name", path.stem),
                description=data.get("description", ""),
                field_layout=data.get("field_layout", {}),
                validation_rules=data.get("validation_rules", []),
                created_at=data.get("created_at", ""),
                modified_at=data.get("modified_at", ""),
                signature=bytes.fromhex(data.get("signature", ""))
                if data.get("signature")
                else b"",
            )

            self._templates[template.template_id] = template

            self._logger.info(f"Шаблон загружен: {path}")
            return FormControllerResult(success=True, data=template)

        except json.JSONDecodeError as e:
            self._logger.error(f"Некорректный JSON в шаблоне: {e}")
            return FormControllerResult(success=False, error=f"Некорректный JSON: {e}")
        except Exception as e:
            self._logger.error(f"Ошибка загрузки шаблона: {e}")
            return FormControllerResult(success=False, error=str(e))

    def save_template(
        self,
        form_id: UUID,
        path: Path,
        name: Optional[str] = None,
    ) -> FormControllerResult:
        """Сохраняет форму как шаблон.

        Args:
            form_id: ID формы для сохранения
            path: Путь для сохранения
            name: Имя шаблона (опционально)

        Returns:
            FormControllerResult с сохранённым FormTemplate
        """
        try:
            if form_id not in self._forms:
                return FormControllerResult(success=False, error=f"Форма не найдена: {form_id}")

            form = self._forms[form_id]

            # Генерируем ID шаблона
            template_id = str(uuid4())

            # Генерируем имя если не указано
            template_name = name or f"Шаблон {form.index or form.form_id}"

            template = FormTemplate(
                template_id=template_id,
                type_code=form.type_code,
                name=template_name,
                field_layout=form.field_values,
            )

            import json

            # Сериализуем
            data = {
                "template_id": template.template_id,
                "type_code": template.type_code,
                "name": template.name,
                "description": template.description,
                "field_layout": template.field_layout,
                "validation_rules": template.validation_rules,
                "created_at": template.created_at,
                "modified_at": template.modified_at,
                "signature": template.signature.hex() if template.signature else "",
            }

            # Добавляем расширение если нужно
            if not path.suffix:
                path = path.with_suffix(TEMPLATE_EXTENSION)

            path.parent.mkdir(parents=True, exist_ok=True)

            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            self._templates[template_id] = template

            self._logger.info(f"Шаблон сохранён: {path}")
            return FormControllerResult(success=True, data=template)

        except Exception as e:
            self._logger.error(f"Ошибка сохранения шаблона: {e}")
            return FormControllerResult(success=False, error=str(e))

    def get_template(self, template_id: str) -> Optional[FormTemplate]:
        """Возвращает шаблон по ID.

        Args:
            template_id: ID шаблона

        Returns:
            FormTemplate или None если не найден
        """
        return self._templates.get(template_id)

    def list_templates(self) -> List[FormTemplate]:
        """Возвращает список всех загруженных шаблонов.

        Returns:
            Список FormTemplate
        """
        return list(self._templates.values())

    def remove_template(self, template_id: str) -> bool:
        """Удаляет шаблон из кэша.

        Args:
            template_id: ID шаблона для удаления

        Returns:
            True если удалён
        """
        if template_id in self._templates:
            del self._templates[template_id]
            self._logger.debug(f"Шаблон удалён из кэша: {template_id}")
            return True
        return False

    # -------------------------------------------------------------------------
    # Form Instance Operations
    # -------------------------------------------------------------------------

    def create_form(
        self,
        type_code: str,
        template_id: Optional[str] = None,
        initial_values: Optional[Dict[str, Any]] = None,
    ) -> FormControllerResult:
        """Создаёт новый экземпляр формы.

        Args:
            type_code: Код типа документа (DVN, INV, и т.д.)
            template_id: ID шаблона (опционально)
            initial_values: Начальные значения полей

        Returns:
            FormControllerResult с созданным FormInstance

        Example:
            >>> result = controller.create_form("DVN", initial_values={"title": "Note #1"})
            >>> if result.success:
            ...     form = result.data
            ...     print(f"Создана: {form.form_id}")
        """
        try:
            # Проверяем существование типа
            if type_code not in self._type_registry:
                return FormControllerResult(
                    success=False, error=f"Тип документа не найден: {type_code}"
                )

            # Создаём через FormConstructor
            doc_data = self._form_constructor.create_from_type(type_code, **(initial_values or {}))

            # Генерируем UUID
            form_id = uuid4()

            # Генерируем индекс
            index = self._generate_form_index(type_code, template_id)

            form = FormInstance(
                form_id=form_id,
                template_id=template_id or "",
                type_code=type_code,
                status=FormStatus.DRAFT,
                index=index,
                field_values=doc_data.get("fields", {}),
            )

            self._forms[form_id] = form

            self._logger.info(f"Форма создана: {form_id} (type={type_code})")
            self._invoke_callback("on_form_created", form)

            return FormControllerResult(success=True, data=form)

        except KeyError as e:
            self._logger.error(f"Тип не найден: {e}")
            return FormControllerResult(success=False, error=f"Тип не найден: {e}")
        except Exception as e:
            self._logger.error(f"Ошибка создания формы: {e}")
            return FormControllerResult(success=False, error=str(e))

    def get_form(self, form_id: UUID) -> Optional[FormInstance]:
        """Возвращает экземпляр формы по ID.

        Args:
            form_id: UUID формы

        Returns:
            FormInstance или None
        """
        return self._forms.get(form_id)

    def update_form_fields(
        self,
        form_id: UUID,
        field_values: Dict[str, Any],
    ) -> FormControllerResult:
        """Обновляет значения полей формы.

        Args:
            form_id: ID формы
            field_values: Новые значения полей

        Returns:
            FormControllerResult с обновлённой формой
        """
        form = self._forms.get(form_id)
        if not form:
            return FormControllerResult(success=False, error="Форма не найдена")

        if not form.status.is_editable:
            return FormControllerResult(
                success=False,
                error=f"Нельзя редактировать форму в статусе {form.status.value}",
            )

        try:
            # Обновляем значения
            updated_values = {**form.field_values, **field_values}

            # Создаём новый экземпляр (immutable)
            import datetime

            new_form = FormInstance(
                form_id=form.form_id,
                template_id=form.template_id,
                type_code=form.type_code,
                status=form.status,
                index=form.index,
                field_values=updated_values,
                created_at=form.created_at,
                modified_at=datetime.datetime.now().isoformat(),
            )

            self._forms[form_id] = new_form

            self._logger.debug(f"Поля формы обновлены: {form_id}")
            self._invoke_callback("on_form_updated", form_id, new_form)

            return FormControllerResult(success=True, data=new_form)

        except Exception as e:
            self._logger.error(f"Ошибка обновления полей: {e}")
            return FormControllerResult(success=False, error=str(e))

    def list_forms(
        self,
        type_code: Optional[str] = None,
        status: Optional[FormStatus] = None,
    ) -> List[FormInstance]:
        """Возвращает список форм с фильтрацией.

        Args:
            type_code: Фильтр по типу документа (опционально)
            status: Фильтр по статусу (опционально)

        Returns:
            Список FormInstance
        """
        forms = self._forms.values()

        if type_code:
            forms = [f for f in forms if f.type_code == type_code]

        if status:
            forms = [f for f in forms if f.status == status]

        return list(forms)

    def delete_form(self, form_id: UUID) -> bool:
        """Удаляет форму.

        Args:
            form_id: ID формы

        Returns:
            True если удалена
        """
        if form_id in self._forms:
            form = self._forms[form_id]
            # Разрешаем удаление только в DRAFT или ARCHIVED
            if form.status in (FormStatus.DRAFT, FormStatus.ARCHIVED):
                del self._forms[form_id]
                self._logger.info(f"Форма удалена: {form_id}")
                return True
            else:
                self._logger.warning(f"Нельзя удалить форму в статусе {form.status.value}")
        return False

    # -------------------------------------------------------------------------
    # Validation Operations
    # -------------------------------------------------------------------------

    def validate_form(self, form_id: UUID) -> ValidationReport:
        """Валидирует поля формы.

        Выполняет трёхуровневую валидацию:
        1. Уровень поля (validate_field)
        2. Уровень формы (validate_form)
        3. Уровень кросс-полей (validate_cross_fields)

        Args:
            form_id: ID формы для валидации

        Returns:
            ValidationReport с результатами

        Example:
            >>> report = controller.validate_form(form_id)
            >>> if not report.is_valid:
            ...     for error in report.errors:
            ...         print(f"Ошибка: {error.message}")
        """
        form = self._forms.get(form_id)
        if not form:
            return ValidationReport(
                form_id=form_id,
                is_valid=False,
                errors=[
                    ValidationResult(
                        field_id=None,
                        severity=Severity.ERROR,
                        code="form_not_found",
                        message=f"Форма не найдена: {form_id}",
                    )
                ],
            )

        if not self._form_validator:
            # Валидатор не настроен - считаем валидным
            return ValidationReport(
                form_id=form_id,
                is_valid=True,
                info=[
                    ValidationResult(
                        field_id=None,
                        severity=Severity.INFO,
                        code="validator_not_configured",
                        message="Валидатор не настроен, пропускаем проверку",
                    )
                ],
            )

        errors: List[ValidationResult] = []
        warnings: List[ValidationResult] = []
        info: List[ValidationResult] = []

        try:
            # Получаем схему для типа
            schema = self._form_constructor.get_form_schema(form.type_code)

            # Валидируем каждое поле
            for field_id, value in form.field_values.items():
                field_def = next((f for f in schema.fields if f.field_id == field_id), None)
                if field_def:
                    field_errors = self._form_validator.validate_field(field_id, value, field_def)
                    for err in field_errors:
                        result = ValidationResult(
                            field_id=err.field_id,
                            severity=err.severity,
                            code=err.code,
                            message=err.message,
                        )
                        if err.severity == Severity.ERROR:
                            errors.append(result)
                        elif err.severity == Severity.WARNING:
                            warnings.append(result)
                        else:
                            info.append(result)

            # Кросс-полевая валидация
            cross_errors = self._form_validator.validate_cross_fields(form.field_values, schema)
            for err in cross_errors:
                result = ValidationResult(
                    field_id=err.field_id,
                    severity=err.severity,
                    code=err.code,
                    message=err.message,
                )
                if err.severity == Severity.ERROR:
                    errors.append(result)
                elif err.severity == Severity.WARNING:
                    warnings.append(result)
                else:
                    info.append(result)

            is_valid = len(errors) == 0

            if is_valid:
                self._logger.info(f"Валидация формы успешна: {form_id}")
            else:
                self._logger.warning(
                    f"Валидация формы не пройдена: {form_id} ({len(errors)} ошибок)"
                )

            return ValidationReport(
                form_id=form_id,
                is_valid=is_valid,
                errors=errors,
                warnings=warnings,
                info=info,
            )

        except Exception as e:
            self._logger.error(f"Ошибка валидации: {e}")
            return ValidationReport(
                form_id=form_id,
                is_valid=False,
                errors=[
                    ValidationResult(
                        field_id=None,
                        severity=Severity.ERROR,
                        code="validation_error",
                        message=str(e),
                    )
                ],
            )

    def validate_field(
        self,
        form_id: UUID,
        field_id: str,
        value: Any,
    ) -> List[ValidationResult]:
        """Валидирует отдельное поле формы.

        Args:
            form_id: ID формы
            field_id: ID поля
            value: Значение для валидации

        Returns:
            Список ValidationResult
        """
        form = self._forms.get(form_id)
        if not form:
            return [
                ValidationResult(
                    field_id=field_id,
                    severity=Severity.ERROR,
                    code="form_not_found",
                    message="Форма не найдена",
                )
            ]

        if not self._form_validator:
            return [
                ValidationResult(
                    field_id=field_id,
                    severity=Severity.INFO,
                    code="validator_not_configured",
                    message="Валидатор не настроен",
                )
            ]

        try:
            schema = self._form_constructor.get_form_schema(form.type_code)
            field_def = next((f for f in schema.fields if f.field_id == field_id), None)

            if not field_def:
                return [
                    ValidationResult(
                        field_id=field_id,
                        severity=Severity.ERROR,
                        code="field_not_found",
                        message=f"Поле не найдено: {field_id}",
                    )
                ]

            results = self._form_validator.validate_field(field_id, value, field_def)
            return [
                ValidationResult(
                    field_id=r.field_id,
                    severity=r.severity,
                    code=r.code,
                    message=r.message,
                )
                for r in results
            ]

        except Exception as e:
            self._logger.error(f"Ошибка валидации поля: {e}")
            return [
                ValidationResult(
                    field_id=field_id,
                    severity=Severity.ERROR,
                    code="validation_error",
                    message=str(e),
                )
            ]

    # -------------------------------------------------------------------------
    # Form Lifecycle / Status Management
    # -------------------------------------------------------------------------

    def set_form_status(
        self,
        form_id: UUID,
        status: FormStatus,
    ) -> FormControllerResult:
        """Изменяет статус формы.

        Проверяет допустимость перехода через FormStatusManager.
        Для перехода в SIGNED требуется валидация формы.

        Args:
            form_id: ID формы
            status: Целевой статус

        Returns:
            FormControllerResult с обновлённой формой
        """
        form = self._forms.get(form_id)
        if not form:
            return FormControllerResult(success=False, error="Форма не найдена")

        # Проверяем возможность перехода
        if not self._status_manager.can_transition(form.status, status):
            return FormControllerResult(
                success=False,
                error=f"Нельзя перейти из {form.status.value} в {status.value}",
            )

        # Для перехода в SIGNED требуется валидация
        if status == FormStatus.SIGNED:
            report = self.validate_form(form_id)
            if not report.is_valid:
                return FormControllerResult(
                    success=False,
                    error="Нельзя подписать: форма содержит ошибки валидации",
                )

        try:
            import datetime

            # Выполняем переход
            new_form = FormInstance(
                form_id=form.form_id,
                template_id=form.template_id,
                type_code=form.type_code,
                status=status,
                index=form.index,
                field_values=form.field_values,
                created_at=form.created_at,
                modified_at=datetime.datetime.now().isoformat(),
            )

            self._forms[form_id] = new_form

            self._logger.info(f"Статус формы изменён: {form_id} -> {status.value}")
            self._invoke_callback("on_status_changed", form_id, form.status, status)

            return FormControllerResult(success=True, data=new_form)

        except StatusTransitionError as e:
            self._logger.error(f"Ошибка перехода статуса: {e}")
            return FormControllerResult(success=False, error=str(e))

    def get_form_status(self, form_id: UUID) -> Optional[FormStatus]:
        """Возвращает текущий статус формы.

        Args:
            form_id: ID формы

        Returns:
            FormStatus или None
        """
        form = self._forms.get(form_id)
        return form.status if form else None

    def can_change_status(
        self,
        form_id: UUID,
        target_status: FormStatus,
    ) -> Tuple[bool, Optional[str]]:
        """Проверяет возможность изменения статуса.

        Args:
            form_id: ID формы
            target_status: Целевой статус

        Returns:
            Кортеж (возможно ли, сообщение об ошибке)
        """
        form = self._forms.get(form_id)
        if not form:
            return False, "Форма не найдена"

        if not self._status_manager.can_transition(form.status, target_status):
            return (
                False,
                f"Недопустимый переход: {form.status.value} -> {target_status.value}",
            )

        return True, None

    # -------------------------------------------------------------------------
    # Protected Blanks Operations
    # -------------------------------------------------------------------------

    def sign_form(
        self,
        form_id: UUID,
        device_id: Optional[str] = None,
        pin: Optional[str] = None,
    ) -> FormControllerResult:
        """Подписывает форму на защищённом бланке.

        Переводит форму в статус SIGNED и создаёт запись в BlankManager.

        Args:
            form_id: ID формы
            device_id: ID устройства подписи (опционально)
            pin: PIN код (опционально)

        Returns:
            FormControllerResult с результатом подписи
        """
        if not self._blank_manager:
            return FormControllerResult(success=False, error="BlankManager не настроен")

        form = self._forms.get(form_id)
        if not form:
            return FormControllerResult(success=False, error="Форма не найдена")

        # Сначала меняем статус
        status_result = self.set_form_status(form_id, FormStatus.SIGNED)
        if not status_result.success:
            return status_result

        try:
            # Получаем бланк для подписи
            blank = self._blank_manager.get_blank_by_series_number(
                series=form.type_code,
                number=form.index,
            )

            if not blank:
                # Создаём новый бланк если не найден
                number = self._extract_number_from_index(form.index) or 0
                blank = self._blank_manager.issue_blank(
                    series=form.type_code,
                    number=number,
                    blank_type=form.type_code,
                    security_preset="standard",
                )

            # Подписываем
            document_content = self._form_to_bytes(form)
            signed_blank, signature, qr_data = self._blank_manager.sign_blank(
                blank_id=blank.blank_id,
                document_content=document_content,
                device_id=device_id,
                pin=pin,
            )

            self._logger.info(f"Форма подписана: {form_id}")
            self._invoke_callback("on_form_signed", form_id, signed_blank, qr_data)

            return FormControllerResult(
                success=True,
                data={
                    "blank": signed_blank,
                    "qr_data": qr_data,
                    "signature": signature,
                },
            )

        except Exception as e:
            self._logger.error(f"Ошибка подписи: {e}")
            # Откатываем статус
            self.set_form_status(form_id, FormStatus.VALIDATED)
            return FormControllerResult(success=False, error=str(e))

    def issue_blank_series(
        self,
        series: str,
        count: int,
        type_code: str,
        security_preset: str = "standard",
    ) -> FormControllerResult:
        """Выпускает серию защищённых бланков.

        Args:
            series: Серия бланков (например, "DVN-2026-A")
            count: Количество бланков в серии
            type_code: Код типа документа
            security_preset: Пресет безопасности

        Returns:
            FormControllerResult со списком созданных бланков
        """
        if not self._blank_manager:
            return FormControllerResult(success=False, error="BlankManager не настроен")

        if count <= 0:
            return FormControllerResult(
                success=False, error="Количество бланков должно быть больше 0"
            )

        try:
            blanks = []
            for i in range(1, count + 1):
                blank = self._blank_manager.issue_blank(
                    series=series,
                    number=i,
                    blank_type=type_code,
                    security_preset=security_preset,
                )
                blanks.append(blank)

            self._logger.info(f"Выпущено {count} бланков в серии {series}")
            return FormControllerResult(success=True, data=blanks)

        except Exception as e:
            self._logger.error(f"Ошибка выпуска серии бланков: {e}")
            return FormControllerResult(success=False, error=str(e))

    def verify_blank(self, form_id: UUID) -> FormControllerResult:
        """Проверяет подлинность бланка формы.

        Args:
            form_id: ID формы

        Returns:
            FormControllerResult с результатом проверки
        """
        if not self._blank_manager:
            return FormControllerResult(success=False, error="BlankManager не настроен")

        form = self._forms.get(form_id)
        if not form:
            return FormControllerResult(success=False, error="Форма не найдена")

        if form.status != FormStatus.SIGNED:
            return FormControllerResult(
                success=False,
                error=f"Форма не подписана, статус: {form.status.value}",
            )

        try:
            blank = self._blank_manager.get_blank_by_series_number(
                series=form.type_code,
                number=form.index,
            )

            if not blank:
                return FormControllerResult(success=False, error="Бланк не найден")

            return FormControllerResult(success=True, data={"blank": blank, "valid": True})

        except Exception as e:
            self._logger.error(f"Ошибка верификации: {e}")
            return FormControllerResult(success=False, error=str(e))

    # -------------------------------------------------------------------------
    # Index Operations
    # -------------------------------------------------------------------------

    def get_form_index(self, form_id: UUID) -> str:
        """Возвращает полный индекс формы.

        Индекс формируется по шаблону: DVN-44-K53-I
        (Type-Subtype-Series-Sequence)

        Args:
            form_id: ID формы

        Returns:
            Строка индекса или пустая строка
        """
        form = self._forms.get(form_id)
        return form.index if form else ""

    def set_form_index(
        self,
        form_id: UUID,
        index: str,
    ) -> FormControllerResult:
        """Устанавливает индекс формы.

        Args:
            form_id: ID формы
            index: Новый индекс

        Returns:
            FormControllerResult
        """
        form = self._forms.get(form_id)
        if not form:
            return FormControllerResult(success=False, error="Форма не найдена")

        if not form.status.is_editable:
            return FormControllerResult(
                success=False,
                error="Нельзя изменить индекс: форма не в статусе DRAFT",
            )

        try:
            import datetime

            new_form = FormInstance(
                form_id=form.form_id,
                template_id=form.template_id,
                type_code=form.type_code,
                status=form.status,
                index=index,
                field_values=form.field_values,
                created_at=form.created_at,
                modified_at=datetime.datetime.now().isoformat(),
            )

            self._forms[form_id] = new_form
            return FormControllerResult(success=True, data=new_form)

        except Exception as e:
            self._logger.error(f"Ошибка установки индекса: {e}")
            return FormControllerResult(success=False, error=str(e))

    # -------------------------------------------------------------------------
    # Type Registry Integration
    # -------------------------------------------------------------------------

    def get_available_types(self) -> List[Tuple[str, str]]:
        """Возвращает список доступных типов документов.

        Returns:
            Список кортежей (code, name)
        """
        return self._form_constructor.list_available_types()

    def get_type_info(self, type_code: str) -> Optional[DocumentTypeProtocol]:
        """Возвращает информацию о типе документа.

        Args:
            type_code: Код типа

        Returns:
            DocumentType или None
        """
        try:
            return self._type_registry.get(type_code)
        except KeyError:
            return None

    def get_type_schema(self, type_code: str) -> Optional[FormSchemaProtocol]:
        """Возвращает схему полей для типа.

        Args:
            type_code: Код типа

        Returns:
            FormSchema или None
        """
        try:
            return self._form_constructor.get_form_schema(type_code)
        except KeyError:
            return None

    # -------------------------------------------------------------------------
    # Callbacks
    # -------------------------------------------------------------------------

    def register_callback(self, event: str, callback: Callable[..., Any]) -> None:
        """Регистрирует callback для события.

        Args:
            event: Имя события
            callback: Функция-обработчик
        """
        self._callbacks[event] = callback

    def unregister_callback(self, event: str) -> None:
        """Удаляет callback для события.

        Args:
            event: Имя события
        """
        self._callbacks.pop(event, None)

    def _invoke_callback(self, event: str, *args: Any, **kwargs: Any) -> Any:
        """Вызывает callback для события.

        Args:
            event: Имя события
            *args: Позиционные аргументы
            **kwargs: Именованные аргументы

        Returns:
            Результат callback или None
        """
        callback = self._callbacks.get(event)
        if callback:
            try:
                return callback(*args, **kwargs)
            except Exception as e:
                self._logger.error(f"Ошибка в callback '{event}': {e}")
        return None

    def _show_error(self, message: str) -> None:
        """Показывает сообщение об ошибке.

        Args:
            message: Текст сообщения об ошибке.
        """
        self._logger.warning(message)
        try:
            from tkinter import messagebox

            messagebox.showerror("Ошибка", message)
        except Exception as e:
            self._logger.error(f"Не удалось показать ошибку: {e}")

    # -------------------------------------------------------------------------
    # Designer Callbacks
    # -------------------------------------------------------------------------

    def _on_designer_save(self, form_data: Any) -> None:
        """Callback сохранения из дизайнера."""
        self._logger.debug("Callback сохранения из дизайнера")
        self._invoke_callback("on_designer_save", form_data)

    def _on_designer_export(self, form_data: Any) -> None:
        """Callback экспорта из дизайнера."""
        self._logger.debug("Callback экспорта из дизайнера")
        self._invoke_callback("on_designer_export", form_data)

    def _on_designer_close(self) -> None:
        """Callback закрытия дизайнера."""
        self._logger.debug("Callback закрытия дизайнера")
        self._designer_window = None
        self._invoke_callback("on_designer_close")

    # -------------------------------------------------------------------------
    # Helper Methods
    # -------------------------------------------------------------------------

    def _generate_form_index(
        self,
        type_code: str,
        template_id: Optional[str] = None,
    ) -> str:
        """Генерирует индекс формы.

        Формат: DVN-44-K53-I
        - Тип (DVN, INV, и т.д.)
        - Подтип (числовой код)
        - Серия (буквенно-цифровая)
        - Порядковый номер (римские цифры)

        Args:
            type_code: Код типа документа
            template_id: ID шаблона (опционально)

        Returns:
            Строка индекса
        """
        import datetime
        import random

        # Генерируем случайные компоненты
        subtype = random.randint(1, 99)
        series = f"K{random.randint(1, 99):02d}"

        # Текущий год для номера
        current_year = datetime.datetime.now().year % 100
        sequence = self._int_to_roman(random.randint(1, 50))

        return f"{type_code}-{subtype}-{series}-{sequence}"

    def _extract_number_from_index(self, index: str) -> Optional[int]:
        """Извлекает числовой номер из индекса.

        Args:
            index: Индекс формы

        Returns:
            Число или None
        """
        if not index:
            return None

        # Ищем число в индексе
        match = re.search(r"\d+", index)
        return int(match.group()) if match else None

    def _int_to_roman(self, num: int) -> str:
        """Конвертирует целое число в римские цифры.

        Args:
            num: Число для конвертации

        Returns:
            Римские цифры
        """
        val = [1000, 900, 500, 400, 100, 90, 50, 40, 10, 9, 5, 4, 1]
        syb = ["M", "CM", "D", "CD", "C", "XC", "L", "XL", "X", "IX", "V", "IV", "I"]
        roman_num = ""
        i = 0
        while num > 0:
            for _ in range(num // val[i]):
                roman_num += syb[i]
                num -= val[i]
            i += 1
        return roman_num

    def _form_to_bytes(self, form: FormInstance) -> bytes:
        """Конвертирует форму в байты для подписи.

        Args:
            form: Экземпляр формы

        Returns:
            JSON в байтах
        """
        import json

        data = {
            "form_id": str(form.form_id),
            "type_code": form.type_code,
            "index": form.index,
            "fields": form.field_values,
            "created_at": form.created_at,
        }
        return json.dumps(data, sort_keys=True).encode("utf-8")


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    "FormController",
    "FormTemplate",
    "FormInstance",
    "FormStatus",
    "Severity",
    "FieldType",
    "ValidationResult",
    "ValidationReport",
    "FormControllerResult",
    "FormStatusManager",
    "FormControllerError",
    "FormNotFoundError",
    "TemplateNotFoundError",
    "StatusTransitionError",
    "ValidationError",
    "BlankManagerNotConfiguredError",
    # Protocols
    "TypeRegistryProtocol",
    "FormConstructorProtocol",
    "FormValidatorProtocol",
    "BlankManagerProtocol",
    "FormDesignerWindowProtocol",
]
