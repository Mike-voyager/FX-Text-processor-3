# Approval Workflow (Single Operator)

**Version:** 1.0
**Date:** March 2026
**Status:** Living Document
**Module:** `src/documents/constructor/approval_workflow.py`

---

## Overview

Approval Workflow — система согласования документов для **single-operator** среды. В отличие от традиционных workflow-систем, предназначенных для многопользовательских сред, этот workflow реализует переключение **режимов работы** одного оператора для предотвращения ошибок и обеспечения качества документов.

**Принцип:** Один оператор последовательно переключается между ролями, явно подтверждая переходы MFA.

**Цель:** Предотвратить пропуск важных этапов обработки документа по невнимательности.

---

## Workflow States

### State Machine

```
┌─────────┐     ┌─────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────┐
│  DRAFT  │────▶│ FILLED  │────▶│  VALIDATED  │────▶│  APPROVED   │────▶│ SIGNED  │
└────┬────┘     └────┬────┘     └──────┬──────┘     └──────┬──────┘     └────┬────┘
     │               │              │                │               │
     ▼               ▼              ▼                ▼               ▼
  OPERATOR         EDITOR       SUPERVISOR       SIGNATORY      SIGNATORY
  (заполнение)    (проверка)    (согласование)   (подписание)   (печать)
     │               │              │                │               │
     └───────────────┴──────────────┴────────────────┴───────────────┘
                                      │
                                      ▼
                                ┌─────────┐
                                │ ARCHIVED│
                                └─────────┘
```

### States Description

| State | Role | Description | MFA Required |
|-------|------|-------------|--------------|
| **DRAFT** | OPERATOR | Черновик — начальное заполнение формы | No |
| **FILLED** | EDITOR | Заполнена — проверка корректности данных | Yes |
| **VALIDATED** | SUPERVISOR | Проверена — согласование на подпись | Yes |
| **APPROVED** | SIGNATORY | Согласована — разрешение на подпись | Yes |
| **SIGNED** | SIGNATORY | Подписана — криптографическая подпись | Yes |
| **PRINTED** | OPERATOR | Напечатана — физическая копия создана | No |
| **ARCHIVED** | — | Архивирована — документ в архиве | No |

### Rejected Path

```
FILLED ──────▶ REJECTED (возврат на доработку)
   │
VALIDATED ────▶ REJECTED (возврат к редактору)
   │
APPROVED ─────▶ REJECTED (возврат к супервизору)
```

---

## Workflow Roles

### Single Operator, Multiple Modes

```python
class WorkflowRole(Enum):
    """Роли внутри single-operator workflow.

    Это не разные пользователи, а режимы работы
    одного оператора с разными правами.
    """
    OPERATOR = "operator"       # Заполнение формы
    EDITOR = "editor"           # Редактирование/проверка
    SUPERVISOR = "supervisor"   # Согласование
    SIGNATORY = "signatory"     # Подписание
```

### Role Switching

```python
class ApprovalWorkflow:
    """State machine для workflow."""

    def switch_role(self, role: WorkflowRole) -> None:
        """Переключает текущую роль оператора.

        Требует MFA для перехода в привилегированные роли.
        """
        if role in [WorkflowRole.SUPERVISOR, WorkflowRole.SIGNATORY]:
            # Требуем MFA для высокопривилегированных ролей
            if not self.auth.verify_mfa():
                raise MFAVerificationError("MFA required for this role")

        self.current_role = role
        self.audit.log_event(
            AuditEventType.WORKFLOW_ROLE_SWITCHED,
            details={"role": role.value}
        )
```

**Переходы между ролями:**

```python
ROLE_TRANSITIONS = {
    # Можно переключаться в любую роль, но некоторые требуют MFA
    WorkflowRole.OPERATOR: {
        WorkflowRole.EDITOR: {"mfa": False},
        WorkflowRole.SUPERVISOR: {"mfa": True},
        WorkflowRole.SIGNATORY: {"mfa": True},
    },
    WorkflowRole.EDITOR: {
        WorkflowRole.OPERATOR: {"mfa": False},
        WorkflowRole.SUPERVISOR: {"mfa": True},
    },
    # ... и так далее
}
```

---

## State Transitions

### Transition Rules

```python
@dataclass(frozen=True)
class TransitionRule:
    """Правило перехода между состояниями."""
    from_state: FormStatus
    to_state: FormStatus
    required_role: WorkflowRole
    mfa_required: bool = True
    validation_required: bool = True

TRANSITION_RULES: list[TransitionRule] = [
    # DRAFT -> FILLED
    TransitionRule(
        from_state=FormStatus.DRAFT,
        to_state=FormStatus.FILLED,
        required_role=WorkflowRole.EDITOR,
        mfa_required=False,
        validation_required=True
    ),
    # FILLED -> VALIDATED
    TransitionRule(
        from_state=FormStatus.FILLED,
        to_state=FormStatus.VALIDATED,
        required_role=WorkflowRole.SUPERVISOR,
        mfa_required=True,
        validation_required=True
    ),
    # VALIDATED -> APPROVED
    TransitionRule(
        from_state=FormStatus.VALIDATED,
        to_state=FormStatus.APPROVED,
        required_role=WorkflowRole.SUPERVISOR,
        mfa_required=True,
        validation_required=False
    ),
    # APPROVED -> SIGNED
    TransitionRule(
        from_state=FormStatus.APPROVED,
        to_state=FormStatus.SIGNED,
        required_role=WorkflowRole.SIGNATORY,
        mfa_required=True,
        validation_required=True
    ),
    # SIGNED -> PRINTED
    TransitionRule(
        from_state=FormStatus.SIGNED,
        to_state=FormStatus.PRINTED,
        required_role=WorkflowRole.SIGNATORY,
        mfa_required=False,
        validation_required=False
    ),
]
```

### Performing Transitions

```python
def transition(
    self,
    document: Document,
    to_state: FormStatus,
    mfa_token: str | None = None
) -> None:
    """Выполняет переход документа в новое состояние.

    Args:
        document: Документ для перехода
        to_state: Целевое состояние
        mfa_token: MFA токен (если требуется)

    Raises:
        InvalidTransitionError: Если переход запрещён
        InsufficientRoleError: Если роль недостаточна
        MFAVerificationError: Если MFA не пройден
    """
    from_state = document.status

    # Проверяем правило перехода
    rule = self._find_transition_rule(from_state, to_state)
    if not rule:
        raise InvalidTransitionError(
            f"Cannot transition from {from_state} to {to_state}"
        )

    # Проверяем роль
    if self.current_role != rule.required_role:
        raise InsufficientRoleError(
            f"Role {rule.required_role.value} required, "
            f"current role is {self.current_role.value}"
        )

    # Проверяем MFA
    if rule.mfa_required:
        if not mfa_token or not self._verify_mfa(mfa_token):
            raise MFAVerificationError("Valid MFA token required")

    # Валидация перед переходом
    if rule.validation_required:
        errors = self.validator.validate_form(document)
        if errors:
            raise ValidationError(f"Validation failed: {errors}")

    # Выполняем переход
    document.status = to_state
    document.workflow_history.append(WorkflowTransition(
        from_state=from_state,
        to_state=to_state,
        timestamp=datetime.now(),
        role=self.current_role,
        signature=self._sign_transition(document, to_state)
    ))

    # Логируем
    self.audit.log_event(
        AuditEventType.WORKFLOW_TRANSITION,
        details={
            "document_id": document.id,
            "from": from_state.value,
            "to": to_state.value,
            "role": self.current_role.value
        }
    )
```

---

## Field Annotations

### Comments on Fields

```python
@dataclass(frozen=True)
class FieldAnnotation:
    """Комментарий к полю в контексте workflow."""
    annotation_id: str
    field_id: str
    comment: str
    author_role: WorkflowRole
    created_at: datetime
    resolved: bool = False
    resolved_at: datetime | None = None
    resolved_by: WorkflowRole | None = None
```

### Adding Comments

```python
def add_comment(
    self,
    document: Document,
    field_id: str,
    comment: str
) -> FieldAnnotation:
    """Добавляет комментарий к полю.

    Комментарии не попадают в печать,
    но сохраняются в Audit Trail.
    """
    annotation = FieldAnnotation(
        annotation_id=str(uuid4()),
        field_id=field_id,
        comment=comment,
        author_role=self.current_role,
        created_at=datetime.now()
    )

    document.annotations[field_id].append(annotation)

    # Логируем
    self.audit.log_event(
        AuditEventType.WORKFLOW_COMMENT_ADDED,
        details={
            "document_id": document.id,
            "field_id": field_id,
            "role": self.current_role.value,
            "comment": comment
        }
    )

    return annotation
```

### Resolving Comments

```python
def resolve_comment(
    self,
    document: Document,
    annotation_id: str
) -> None:
    """Отмечает комментарий как разрешённый."""
    for field_id, annotations in document.annotations.items():
        for annotation in annotations:
            if annotation.annotation_id == annotation_id:
                annotation.resolved = True
                annotation.resolved_at = datetime.now()
                annotation.resolved_by = self.current_role

                self.audit.log_event(
                    AuditEventType.WORKFLOW_COMMENT_RESOLVED,
                    details={
                        "document_id": document.id,
                        "annotation_id": annotation_id
                    }
                )
                return

    raise AnnotationNotFoundError(f"Annotation {annotation_id} not found")
```

---

## UI Integration

### Role Indicator

```python
class RoleIndicatorWidget(Frame):
    """Виджет отображения текущей роли."""

    ROLE_COLORS = {
        WorkflowRole.OPERATOR: "#3498db",    # Blue
        WorkflowRole.EDITOR: "#2ecc71",      # Green
        WorkflowRole.SUPERVISOR: "#f39c12", # Orange
        WorkflowRole.SIGNATORY: "#e74c3c",  # Red
    }

    def __init__(self, parent: Widget, workflow: ApprovalWorkflow):
        super().__init__(parent)
        self.workflow = workflow

        self.label = Label(self, text="Role:", font=("Arial", 10))
        self.label.pack(side=LEFT)

        self.role_var = StringVar()
        self.role_display = Label(
            self,
            textvariable=self.role_var,
            font=("Arial", 12, "bold"),
            foreground="white",
            padding=5
        )
        self.role_display.pack(side=LEFT)

        self._update_display()

    def _update_display(self):
        role = self.workflow.current_role
        self.role_var.set(role.value.upper())
        self.role_display.configure(
            background=self.ROLE_COLORS[role]
        )
```

### State Indicator

```python
class StateIndicatorWidget(Frame):
    """Виджет отображения текущего состояния документа."""

    def __init__(self, parent: Widget, document: Document):
        super().__init__(parent)
        self.document = document

        # Progress bar через состояния
        self.states = [
            FormStatus.DRAFT,
            FormStatus.FILLED,
            FormStatus.VALIDATED,
            FormStatus.APPROVED,
            FormStatus.SIGNED,
            FormStatus.PRINTED,
        ]

        for i, state in enumerate(self.states):
            Label(self, text=state.value).grid(row=0, column=i)
            # Индикатор прохождения
            indicator = Canvas(self, width=20, height=20)
            indicator.grid(row=1, column=i)

            if self._is_state_reached(state):
                indicator.create_oval(2, 2, 18, 18, fill="green")
            else:
                indicator.create_oval(2, 2, 18, 18, fill="gray")
```

### Transition Dialog

```python
class TransitionDialog(Toplevel):
    """Диалог подтверждения перехода состояния."""

    def __init__(
        self,
        parent: Widget,
        from_state: FormStatus,
        to_state: FormStatus,
        mfa_required: bool
    ):
        super().__init__(parent)
        self.title("Confirm Transition")

        Label(
            self,
            text=f"Transition from {from_state.value} to {to_state.value}?",
            font=("Arial", 12)
        ).pack(pady=10)

        if mfa_required:
            Label(self, text="MFA required:").pack()
            self.mfa_entry = Entry(self, show="*")
            self.mfa_entry.pack()

        Button(self, text="Confirm", command=self.confirm).pack(pady=10)
        Button(self, text="Cancel", command=self.destroy).pack()
```

---

## Security

### MFA for Transitions

```python
def _verify_mfa(self, token: str) -> bool:
    """Верифицирует MFA токен."""
    # FIDO2
    if self.fido2.verify(token):
        return True

    # TOTP
    if self.totp.verify(token):
        return True

    # Backup code
    if self.backup_codes.verify(token):
        return True

    return False
```

### Audit Trail

Каждый переход логируется:

```json
{
  "event_type": "workflow.transition",
  "timestamp": "2026-03-21T10:30:00Z",
  "document_id": "doc-uuid",
  "from_state": "FILLED",
  "to_state": "VALIDATED",
  "role": "SUPERVISOR",
  "mfa_verified": true,
  "signature": "base64..."
}
```

### Preventing Skip

```python
def can_skip_to_state(self, document: Document, target: FormStatus) -> bool:
    """Проверяет, можно ли пропустить промежуточные состояния."""
    # Нельзя пропускать состояния
    # Только последовательные переходы
    return False
```

---

## Usage Examples

### Complete Workflow

```python
from src.documents.constructor.approval_workflow import ApprovalWorkflow

workflow = ApprovalWorkflow(audit_log=audit)

# 1. Создаём документ (DRAFT)
document = Document.create(type_code="INV")
assert document.status == FormStatus.DRAFT

# 2. Переключаемся в EDITOR
workflow.switch_role(WorkflowRole.EDITOR)

# 3. Заполняем поля
document.fill_field("amount", "150000.00")
document.fill_field("client", "ООО Ромашка")

# 4. Переходим в FILLED
workflow.transition(document, FormStatus.FILLED)

# 5. Переключаемся в SUPERVISOR (требует MFA)
workflow.switch_role(WorkflowRole.SUPERVISOR, mfa_token="123456")

# 6. Добавляем комментарий к полю
workflow.add_comment(document, "amount", "Проверить НДС")

# 7. Переходим в VALIDATED
workflow.transition(document, FormStatus.VALIDATED, mfa_token="123456")

# 8. Согласуем
workflow.transition(document, FormStatus.APPROVED, mfa_token="123456")

# 9. Переключаемся в SIGNATORY
workflow.switch_role(WorkflowRole.SIGNATORY, mfa_token="123456")

# 10. Подписываем
workflow.transition(document, FormStatus.SIGNED, mfa_token="123456")

# 11. Печатаем
workflow.transition(document, FormStatus.PRINTED)

# Готово!
print(f"Document archived: {document.status}")
```

### Rejection Example

```python
# EDITOR находит ошибку
workflow.switch_role(WorkflowRole.EDITOR)

# Добавляет комментарий
workflow.add_comment(
    document,
    "amount",
    "Ошибка: сумма не соответствует договору"
)

# Отклоняет — документ возвращается к OPERATOR
workflow.reject(document, mfa_token="123456")

assert document.status == FormStatus.DRAFT
```

---

## Related Documents

- [ARCHITECTURE.md](./ARCHITECTURE.md) — Общая архитектура
- [SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md) — Безопасность и MFA
- [form_designer.md](./form_designer.md) — Визуальный конструктор
