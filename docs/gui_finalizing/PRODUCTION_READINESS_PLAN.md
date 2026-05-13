# План доведения GUI до продакшена

**FX Text Processor 3 - GUI Finalizing Plan**
**Дата:** 2026-04-08
**Текущая готовность:** 62%
**Целевая готовность:** 95%

---

## Фаза 1: Исправление критичных проблем безопасности (Неделя 1)

**Цель:** Устранить все CRITICAL уязвимости перед любым деплоем

### Задачи

#### 1.1 MFA Разблокировка сессии [CRITICAL-001]
- **Файл:** `src/gui/views/main_window.py:917`
- **Работа:**
  - Интегрировать MFAGate перед unlock_session()
  - Добавить диалог выбора метода MFA
  - Верификация через AuthService.verify_mfa()
- **Проверка:** Разблокировка без MFA токена невозможна
- **Оценка:** 4 часа

#### 1.2 Реальная верификация TOTP [CRITICAL-002]
- **Файл:** `src/gui/dialogs/totp_setup_dialog.py:460-461`
- **Работа:**
  - Интегрировать pyotp или аналог
  - Реальная верификация TOTP кода
  - Сохранение секрета в KeyStore
- **Проверка:** Неверный код не принимается
- **Оценка:** 6 часов

#### 1.3 Реальная интеграция FIDO2 [CRITICAL-003]
- **Файл:** `src/gui/dialogs/fido2_setup_dialog.py:530-561`
- **Работа:**
  - Интегрировать fido2 библиотеку
  - Реальное создание credential
  - Сохранение в KeyStore
- **Проверка:** Регистрация работает с реальным ключом
- **Оценка:** 8 часов

#### 1.4 MFA в диалоге отклонения [CRITICAL-004]
- **Файл:** `src/gui/dialogs/reject_dialog.py:564-565`
- **Работа:**
  - Интегрировать MFAGate
  - Реальная верификация перед отклонением
- **Проверка:** Без MFA нельзя отклонить документ
- **Оценка:** 2 часа

### Результат фазы
- [ ] Все MFA операции реальные, не имитированные
- [ ] Security тесты проходят
- [ ] Ревью security архитектором

---

## Фаза 2: Исправление критичных функций (Неделя 2)

### Задачи

#### 2.1 Clipboard операции [CRITICAL-005]
- **Файл:** `src/gui/views/document_view.py:867, 881, 892`
- **Работа:**
  - Интеграция с system clipboard (pyperclip)
  - Cut/Cut с сохранением в clipboard
  - Paste вставка из clipboard
- **Проверка:** Работают Ctrl+X/C/V
- **Оценка:** 6 часов

#### 2.2 Preview Mode [CRITICAL-006]
- **Файл:** `src/gui/views/document_view.py:510`
- **Работа:**
  - Интеграция с ESC/P render pipeline
  - Отображение рендереного документа
  - Переключение между edit/preview
- **Проверка:** Preview показывает реальный ESC/P вывод
- **Оценка:** 8 часов

#### 2.3 Form Data Collection [CRITICAL-008]
- **Файл:** `src/gui/renderers/structured_form_renderer.py:701`
- **Работа:**
  - Получение значений из всех виджетов полей
  - Валидация перед сбором
  - Сериализация в Document
- **Проверка:** Данные формы сохраняются корректно
- **Оценка:** 6 часов

#### 2.4 Template Serialization [CRITICAL-009]
- **Файл:** `src/gui/form_designer/designer_tab.py:988-1007, 1027-1034`
- **Работа:**
  - Интеграция с DocumentFormat сервисом
  - Сериализация шаблона в .fxstpl
  - Десериализация обратно
- **Проверка:** Шаблоны сохраняются и загружаются
- **Оценка:** 10 часов

### Результат фазы
- [ ] Все CRITICAL функции работают
- [ ] Тесты проходят

---

## Фаза 3: Form Designer завершение (Неделя 3)

### Задачи

#### 3.1 Property Editors
- **Файл:** `src/gui/form_designer/property_panel.py:1112, 1123`
- **Работа:**
  - Реализация ConditionsEditorDialog
  - Реализация OptionsEditorDialog
  - Интеграция с PropertyPanel
- **Оценка:** 10 часов

#### 3.2 Cross-Page Field Move
- **Файл:** `src/gui/renderers/structured_form_renderer.py:668`
- **Работа:**
  - Реализация перемещения между страницами
  - Обновление координат
  - Undo/redo поддержка
- **Оценка:** 6 часов

#### 3.3 Form Validation
- **Файл:** `src/gui/renderers/structured_form_renderer.py:713-718`
- **Работа:**
  - Реальная валидация каждого поля
  - Сбор ошибок
  - Отображение пользователю
- **Оценка:** 4 часа

#### 3.4 Tooltip System
- **Файл:** `src/gui/form_designer/designer_tab.py:582-587`
- **Работа:**
  - Реализация _show_tooltip/_hide_tooltip
  - Интеграция с canvas
- **Оценка:** 3 часа

### Результат фазы
- [ ] Form Designer полностью функционален
- [ ] Можно создавать, редактировать, сохранять шаблоны

---

## Фаза 4: Архитектурные улучшения (Неделя 4)

### Задачи

#### 4.1 Document Mode Strategy Pattern
- **Файлы:** `src/gui/renderers/`
- **Работа:**
  - Создать DocumentModeRenderer Protocol
  - Рефакторинг FreeFormRenderer
  - Рефакторинг StructuredFormRenderer
  - DocumentView использует Strategy
- **Оценка:** 12 часов

#### 4.2 MFAGate Pattern
- **Файлы:** `src/gui/dialogs/`
- **Работа:**
  - Создать единый MFAGate класс
  - Рефакторинг всех диалогов для использования MFAGate
  - Удаление дублирования
- **Оценка:** 6 часов

#### 4.3 Error Handling
- **Файл:** `src/gui/views/main_window.py:626-628`
- **Работа:**
  - Убрать silent exception handling
  - Добавить логирование через AuditService
  - Graceful degradation
- **Оценка:** 4 часа

### Результат фазы
- [ ] Архитектура соответствует GUI_ARCHITECTURE.md
- [ ] Код ревью пройден

---

## Фаза 5: Производительность (Неделя 5)

### Задачи

#### 5.1 Canvas Buffering
- **Файл:** `src/gui/form_designer/form_canvas.py`
- **Работа:**
  - Буферизация grid линий
  - Оптимизация _draw_field через itemconfig
  - Профилирование и измерение
- **Оценка:** 8 часов

#### 5.2 Spatial Index
- **Файлы:** `src/gui/form_designer/`
- **Работа:**
  - Реализация grid-based spatial index
  - Оптимизация validate_field_position
  - Оптимизация get_field_at
  - Оптимизация _fields_overlap
- **Оценка:** 10 часов

#### 5.3 Table Widget Optimization
- **Файл:** `src/gui/modes/structured_form/widgets/table_widget.py:186`
- **Работа:**
  - Diff-based обновление Treeview
  - Буферизация данных
- **Оценка:** 6 часов

#### 5.4 Sidebar Optimization
- **Файл:** `src/gui/renderers/structured_form_renderer.py:958`
- **Работа:**
  - Обновление только измененных thumbnails
  - Lazy loading
- **Оценка:** 4 часа

### Результат фазы
- [ ] UI отзывчив с >100 полями
- [ ] Профилирование показывает <100ms на операцию

---

## Фаза 6: Качество кода (Неделя 6)

### Задачи

#### 6.1 Type Hints
- **Файлы:** Все GUI файлы
- **Работа:**
  - Убрать все type: ignore
  - Добавить недостающие type hints
  - mypy --strict проходит
- **Оценка:** 8 часов

#### 6.2 Docstrings
- **Файлы:** Все GUI файлы
- **Работа:**
  - Добавить недостающие docstrings
  - Соответствие Google style
  - На русском языке
- **Оценка:** 6 часов

#### 6.3 Test Coverage
- **Файлы:** tests/unit/gui/
- **Работа:**
  - Довести coverage до 90%
  - Добавить интеграционные тесты
  - GUI тесты с pytest-tkinter
- **Оценка:** 20 часов

#### 6.4 Code Cleanup
- **Файлы:** Все GUI файлы
- **Работа:**
  - Убрать хардкод версии
  - Убрать временные комментарии
  - Рефакторинг дублирования
- **Оценка:** 6 часов

### Результат фазы
- [ ] check.sh проходит без предупреждений
- [ ] Coverage >= 90%
- [ ] Code review пройден

---

## Фаза 7: Отсутствующие диалоги (Недели 7-8)

### Задачи

#### 7.1 FIDO2/TOTP/Backup Setup Dialogs
- **Статус:** Заглушки реализованы, нужна реальная интеграция
- **Оценка:** 16 часов (включено в Фазу 1)

#### 7.2 Template Import/Export Dialogs
- **Файлы:** Новые
- **Работа:**
  - TemplateImportDialog с Trust Chain
  - TemplatePreviewPanel
  - TrustChainVerificationDialog
  - FloppyOptimizerDialog
- **Оценка:** 20 часов

#### 7.3 Barcode/QR Dialogs
- **Файлы:** Новые
- **Работа:**
  - BarcodeTypeSelector
  - BarcodeSettingsPanel
  - QRCodeSettingsDialog
  - BarcodeTypeConflictWarning
- **Оценка:** 16 часов

#### 7.4 Navigation Dialogs
- **Файлы:** Новые
- **Работа:**
  - GotoDialog
  - BookmarksDialog
  - PageSetupDialog
- **Оценка:** 12 часов

#### 7.5 Workflow Dialogs
- **Файлы:** Новые/доработка
- **Работа:**
  - Workflow Timeline Dialog (улучшить)
  - AddCommentDialog
  - PrefillDialog
  - Cross-Document Lookup Panel
- **Оценка:** 16 часов

### Результат фазы
- [ ] Все диалоги из UI_SPEC реализованы
- [ ] Интеграция с бэкендом работает

---

## Итоговый график

| Фаза | Неделя | Результат | Оценка трудоемкости |
|------|--------|-----------|---------------------|
| 1 | 1 | Security fixes | 20 часов |
| 2 | 2 | Critical features | 20 часов |
| 3 | 3 | Form Designer | 23 часа |
| 4 | 4 | Architecture | 22 часа |
| 5 | 5 | Performance | 28 часов |
| 6 | 6 | Code quality | 40 часов |
| 7 | 7-8 | Dialogs | 64 часов |
| **Итого** | **8 недель** | **Готовность 95%** | **~217 часов** |

---

## Чек-лист готовности к продакшену

### Безопасность
- [ ] Все MFA операции реальные
- [ ] Нет обхода аутентификации
- [ ] Audit logging работает
- [ ] SecureMemory wipe реализован
- [ ] Session lock функционирует

### Функциональность
- [ ] Cut/Copy/Paste работают
- [ ] Preview mode показывает реальный ESC/P
- [ ] Form Designer сохраняет/загружает шаблоны
- [ ] Все поля форм редактируются
- [ ] Data collection работает

### Архитектура
- [ ] Document Mode Strategy Pattern
- [ ] MFAGate Pattern
- [ ] Protocol-based DI
- [ ] Command Pattern для undo/redo

### Качество
- [ ] mypy --strict проходит
- [ ] Coverage >= 90%
- [ ] Все type: ignore убраны
- [ ] Документация актуальна

### Производительность
- [ ] UI отзывчив с >100 полями
- [ ] Нет утечек памяти
- [ ] Canvas оптимизирован

---

## Риски

| Риск | Вероятность | Влияние | Митигация |
|------|-------------|---------|-----------|
| FIDO2 интеграция сложнее ожидаемого | Средняя | Высокое | Запланировать buffer time |
| Performance оптимизации требуют rework | Средняя | Среднее | Раннее профилирование |
| Тесты GUI сложны в автоматизации | Высокая | Среднее | Ручное тестирование + интеграционные |
| Scope creep на диалогах | Высокая | Среднее | Фиксировать MVP для каждого диалога |

---

## Ресурсы

### Необходимые библиотеки
- `pyperclip` - system clipboard
- `pyotp` - TOTP verification
- `fido2` - WebAuthn/FIDO2
- `pytest-tkinter` - GUI testing

### Инструменты
- `mypy` - type checking
- `pytest` - testing
- `pytest-cov` - coverage
- `bandit` - security linting

---

## Контрольные точки

### Неделя 2 (Конец фазы 2)
- Демо работающего MFA
- Демо clipboard операций
- Демо preview mode

### Неделя 4 (Конец фазы 4)
- Code review архитектуры
- Security review
- Демо Form Designer

### Неделя 6 (Конец фазы 6)
- Полный проход check.sh
- Coverage report
- Performance benchmarks

### Неделя 8 (Конец фазы 7)
- Полная интеграция
- Acceptance testing
- Go/No-go decision
