# План исправления Priority 1: Critical Blockers (Fix Immediately)
## Задачи 9–13 — полная реализация, без заглушек

---

## Задача 9. Fix FormDesigner DummyDoc issue — использовать реальную модель в workflow transitions

### Проблема
`src/gui/renderers/structured_form_renderer.py` дважды определяет inline-класс `DummyDoc`:
- `transition_status` (~строка 1107–1120)
- `_do_transition` (~строка 2495–2508)

Оба метода передают `DummyDoc` в `FormStatusManager.transition()`, который ожидает протокол `StatusableDocument` с атрибутами `.id` и `.status`.

### Решение
1. Добавить в `StructuredFormDocument` (строка 157–171) property-алиас `id`:
   ```python
   @property
   def id(self) -> str:
       return self.form_id
   ```
2. В `transition_status` заменить inline `DummyDoc` на реальный объект:
   ```python
   doc = StructuredFormDocument(
       form_id=self._form_id or "",
       status=self._form_status,
       pages=[],
       document_index=self._document_index,
   )
   ```
3. В `_do_transition` сделать аналогичную замену.
4. Удалить inline-классы `DummyDoc` полностью.
5. Убедиться, что `mfa_credentials` продолжают корректно передаваться.

### Критерий приёмки
- `mypy --strict` проходит.
- `pytest tests/unit/gui/renderers/` проходит (включить xvfb если нужно).
- В `transition_status` и `_do_transition` больше нет `DummyDoc`; используется `StructuredFormDocument`.

---

## Задача 10. Fix PrefillDialog и CrossDocumentLookupPanel search — реальный поиск

### Проблема
- `PrefillDialog._on_search()` (строка 413–420) использует `sample_matches` (жёстко зашитые данные).
- `CrossDocumentLookupPanel._on_search()` (строка 556–563) использует `sample_results`.
- `src/services/autocomplete_service.py` — stub, возвращает `[]`.
- Нет реализации `DocumentServiceProtocol` для поиска по полям документов.

### Решение (многофайловое)
#### A. Новый сервис — `src/services/prefill_search_service.py`
Создать сервис, реализующий логику поиска значений полей:
- Импортировать `IndexSearchService` (существующий, функциональный).
- Метод `search_field_values(field_id: str, query: str, limit: int = 10) -> list[PrefillMatch]`:
  - Строить `SearchQuery` с `query` и `field_id`.
  - Делегировать в `IndexSearchService.search(...)`.
  - Извлекать значения полей из найденных документов.
  - Возвращать `list[PrefillMatch]` с confidence на основе frequency/ freshness.
- Регистрировать сервис как Singleton (или DI в Controller).

#### B. Изменить `PrefillDialog`
- Добавить в `__init__` параметр `search_service: Optional[PrefillSearchService] = None`.
- В `_on_search`:
  ```python
  if self._search_service is not None:
      results = self._search_service.search_field_values(...)
  else:
      results = []  # или fallback message
  ```
- Очистить `Treeview` и заполнить результатами.

#### C. Изменить `CrossDocumentLookupPanel`
- Аналогично добавить `document_service: Optional[PrefillSearchService] = None`.
- В `_on_search` вызывать сервис с `field_id + value`.

#### D. Обратная совместимость
- Если сервис не передан — показывать пустой список и `messagebox` "Сервис поиска не настроен".

### Критерий приёмки
- `mypy --strict` проходит.
- `pytest tests/unit/gui/dialogs/` проходит.
- Новые unit-тесты для `PrefillSearchService` (≥90% coverage).
- `PrefillDialog` и `CrossDocumentLookupPanel` при наличии сервиса показывают реальные результаты (при наличии проиндексированных документов).
- Нет `sample_matches` / `sample_results` в продакшен-коде.

---

## Задача 11. Fix PaperSetupDialog — убедиться, что он открывается и работает

### Проблема
В `src/gui/views/status_bar.py` (строка 1550–1563) определён inline-стаб `PaperSetupDialog` с методом `show() = pass`. При double-click на индикаторе бумаги вызывается `self._paper_callback()`, но если callback не установлен, диалог не откроется. Модуль `src/gui/dialogs/paper_setup.py` содержит полноценную реализацию (1121 строка).

### Решение
1. **Удалить** inline-стаб `class PaperSetupDialog` из `status_bar.py`.
2. **Добавить import**:
   ```python
   from src.gui.dialogs.paper_setup import PaperSetupDialog as _RealPaperSetupDialog
   ```
   (алиас `_Real...` чтобы избежать конфликта с импортированным именем, если оно экспортируется в `__all__`)
3. В `_on_paper_double_click` добавить fallback:
   ```python
   if self._paper_callback is not None:
       self._paper_callback()
   elif self._tk_frame is not None:
       dialog = _RealPaperSetupDialog(parent=self._tk_frame)
       dialog.show()
   ```
4. Обновить docstring-example в `StatusBar` (строка 464–465), чтобы он использовал реальный диалог.
5. Убедиться, что `__all__` экспортирует `PaperSetupDialog` (пусть через import или оставить alias).

### Критерий приёмки
- Double-click по индикатору бумаги в `StatusBar` открывает реальный `PaperSetupDialog`.
- `mypy --strict` проходит.
- GUI-тесты `status_bar` проходят (xvfb-run).

---

## Задача 12. Fix BarcodeDialog preview — реальный предпросмотр

### Проблема
`BarcodeDialog._on_preview()` (строка 531–545) выводит `messagebox.showinfo()` вместо визуального предпросмотра.

### Решение
1. В `_create_ui()` добавить inline preview Canvas после секции данных:
   ```python
   preview_frame = ttk.LabelFrame(main_frame, text="Предпросмотр", padding="5")
   preview_frame.pack(fill=tk.X, pady=(10, 0))
   self._preview_canvas = tk.Canvas(
       preview_frame, height=130, bg="white",
       highlightthickness=1, highlightbackground="#cccccc"
   )
   self._preview_canvas.pack(fill=tk.X, expand=True)
   self._preview_renderer = SoftwareBarcodeRenderer(self._preview_canvas)
   ```
2. Переписать `_on_preview`:
   ```python
   def _on_preview(self) -> None:
       data = self._data_var.get().strip()
       if not data or not self._selected_type:
           return
       self._preview_renderer.clear()
       self._preview_renderer.render(
           barcode_type=self._selected_type,
           data=data,
           x=10, y=10,
           width=350, height=110,
           show_text=True,
       )
   ```
3. Для режима Hardware добавить overlay-текст на Canvas: `"📠 Hardware (ESC/P)"` (можно через `self._preview_canvas.create_text(...)` после `render`).
4. Убедиться, что `SoftwareBarcodeRenderer` уже хранит `PhotoImage` внутри себя (не пропадёт GC).

### Критерий приёмки
- `mypy --strict` проходит.
- При нажатии "Preview" отрисовывается реальный штрих-код на Canvas.
- Hardware и Software режимы оба показывают визуальный preview.
- Тест `test_barcode_dialog` проходит (с xvfb).

---

## Задача 13. Fix FIDO2 Setup Dialog print/save codes — реализация или удаление demo mode

### Проблема
`_on_print_codes` (строка 870–877) и `_on_save_codes` (строка 879–887) показывают `messagebox` с демо-режимом. Это не реализация.

### Решение (Zero Trust + Air-Gap)
- **Печать** заменить на **Copy to clipboard** (как в `BackupCodesDialog`):
  ```python
  def _on_copy_codes(self) -> None:
      self._parent.clipboard_clear()
      self._parent.clipboard_append("\n".join(self._backup_codes))
      self._parent.update()
      self._show_status("Коды скопированы. Очистите буфер обмена после использования.")
  ```
- Кнопку "Print" переименовать в "Copy to clipboard" (или добавить оба).
- **Сохранение** — реальный `filedialog.asksaveasfilename`:
  ```python
  def _on_save_codes(self) -> None:
      from tkinter import filedialog
      path = filedialog.asksaveasfilename(
          defaultextension=".txt",
          filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
          title="Сохранить резервные коды"
      )
      if path:
          with open(path, "w", encoding="utf-8") as f:
              f.write("# Резервные коды FIDO2\n")
              f.write("# Сохраните в безопасном месте. Каждый код используется ОДИН раз.\n")
              f.write("\n".join(self._backup_codes))
          messagebox.showwarning(
              "Безопасность",
              "Файл содержит резервные коды. Сохраните его на съёмный носитель и удалите с локального диска."
          )
  ```
- Убедиться, что `self._backup_codes` не пуст перед операциями.

### Критерий приёмки
- Нет `messagebox` с текстом "Demo mode".
- Кнопка "Copy" копирует коды в буфер обмена.
- Кнопка "Save" открывает диалог сохранения, записывает файл, выдаёт security warning.
- `mypy --strict` проходит.
- GUI-тесты `fido2_setup_dialog` проходят.

---

## Делегирование
Каждая задача будет передана отдельному агенту с детальным промптом, содержащим:
- точные пути файлов,
- номера строк,
- фрагменты кода (oldString / newString),
- архитектурные ограничения (Zero Trust, air-gap, MVC),
- тестовые команды (`check.sh`, `pytest` с `xvfb-run`).

Перед делегированием план требует вашего утверждения.
