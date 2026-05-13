# GUI Critical Issues - Quick Reference

**Для быстрого доступа к критичным проблемам**

---

## 🔴 CRITICAL - Исправить немедленно

### Безопасность

| ID | Файл | Строка | Проблема | Действие |
|----|------|--------|----------|----------|
| CRIT-001 | main_window.py | 917 | MFA разблокировка обходится | Интегрировать MFAGate |
| CRIT-002 | totp_setup_dialog.py | 460 | Любой 6-цифровой код принимается | Реализовать pyotp |
| CRIT-003 | fido2_setup_dialog.py | 530 | FIDO2 имитируется | Интегрировать fido2 lib |
| CRIT-004 | reject_dialog.py | 564 | MFA заглушка | Интегрировать MFAGate |

### Функциональность

| ID | Файл | Строка | Проблема | Действие |
|----|------|--------|----------|----------|
| CRIT-005 | document_view.py | 867+ | Cut/Copy/Paste не работает | pyperclip |
| CRIT-006 | document_view.py | 510 | Preview mode placeholder | ESC/P pipeline |
| CRIT-008 | structured_form_renderer.py | 701 | get_form_data возвращает None | Сбор из виджетов |
| CRIT-009 | designer_tab.py | 988+ | Template save/load не работает | DocumentFormat |
| CRIT-010 | property_panel.py | 1112+ | Property editors - stubs | Реализовать диалоги |
| CRIT-011 | structured_form_renderer.py | 668 | Cross-page move не работает | Реализовать |
| CRIT-012 | structured_form_renderer.py | 713 | Form validation пустая | Реальная проверка |

---

## 🟠 HIGH - Исправить в приоритете

### Безопасность
- **HIGH-001** totp_setup_dialog.py:340 - Предсказуемый RNG для QR
- **HIGH-003** reject_dialog.py:580 - Дублирование MFA кода

### Производительность
- **HIGH-005** form_canvas.py:669 - O(n*m) отрисовка сетки
- **HIGH-007** table_widget.py:186 - Delete всех items при обновлении

### Код
- **HIGH-011** main_window.py:340 - type: ignore[arg-type]
- **HIGH-008** designer_tab.py:582 - Пустые tooltip методы

---

## Основные файлы для правки

```
src/gui/views/main_window.py              # CRIT-001, HIGH-011
src/gui/views/document_view.py              # CRIT-005, CRIT-006
src/gui/dialogs/totp_setup_dialog.py        # CRIT-002, HIGH-001
src/gui/dialogs/fido2_setup_dialog.py       # CRIT-003
src/gui/dialogs/reject_dialog.py            # CRIT-004, HIGH-003
src/gui/renderers/structured_form_renderer.py  # CRIT-008, CRIT-011, CRIT-012
src/gui/form_designer/designer_tab.py       # CRIT-009
src/gui/form_designer/property_panel.py     # CRIT-010
src/gui/form_designer/form_canvas.py        # HIGH-005
```

---

## Библиотеки для установки

```bash
pip install pyperclip pyotp fido2 pytest-tkinter
```

---

## Тестирование исправлений

### MFA
```python
# Должно отклонять неправильный TOTP код
assert not verify_totp("000000", secret)  # PASS
assert verify_totp(correct_code, secret)     # PASS

# Должно требовать MFA для разблокировки
with patch('gui.security.mfa_gate.MFAGate') as mock:
    mock.verify.return_value = False
    assert not unlock_session(password, token)  # PASS
```

### Clipboard
```python
# Cut должен копировать в clipboard
editor.select_range("1.0", "1.10")
cut()
assert clipboard.get() == selected_text  # PASS

# Paste должен вставлять из clipboard
clipboard.set("test")
paste()
assert "test" in editor.get("1.0", "end")  # PASS
```

---

## Архитектурные задачи

### Document Mode Strategy Pattern
```python
class DocumentModeRenderer(Protocol):
    def create_toolbar(self, parent: tk.Widget) -> tk.Widget: ...
    def create_editor(self, parent: tk.Widget) -> tk.Widget: ...
    def supports_workflow(self) -> bool: ...
    def display_document(self, document: Document) -> None: ...

class FreeFormRenderer(DocumentModeRenderer): ...
class StructuredFormRenderer(DocumentModeRenderer): ...
```

### MFAGate Pattern
```python
class MFAGate:
    def execute(self, operation: Callable[[], T], requires_mfa: bool) -> T | None:
        if requires_mfa and not self._auth.is_mfa_verified():
            if not self._show_mfa_dialog():
                return None
        return operation()
```

---

## Метрики текущего состояния

| Метрика | Значение | Целевое |
|---------|----------|---------|
| Критичных проблем | 12 | 0 |
| Высоких проблем | 20 | 0 |
| STUB методов | 8 | 0 |
| TODO/FIXME | 15 | 0 |
| type: ignore | 5 | 0 |
| Coverage | ~60% | >=90% |
| Готовность | 62% | 95% |

---

## План: 8 недель

| Неделя | Фокус | Результат |
|--------|-------|-----------|
| 1 | Security fixes | MFA работает реально |
| 2 | Critical features | Clipboard, Preview работают |
| 3 | Form Designer | Templates сохраняются |
| 4 | Architecture | Strategy Pattern |
| 5 | Performance | <100ms операции |
| 6 | Code quality | 90% coverage |
| 7-8 | Dialogs | Все диалоги UI_SPEC |

---

*Полные отчеты: GUI_AUDIT_REPORT.md, PRODUCTION_READINESS_PLAN.md*
