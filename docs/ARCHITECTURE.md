# ESC/P Text Editor - Архитектура

## Обзор

ESC/P Text Editor следует строгой архитектуре MVC (Model-View-Controller) с чётким разделением ответственности.

## Слои приложения

### Model Layer (`src/model/`)

**Назначение:** Структуры данных и бизнес-сущности

**Ключевые классы:**
- `Document`: Корневой контейнер документа
- `Section`: Настройки страницы и группировка контента
- `Paragraph`: Текстовый блок с выравниванием
- `Run`: Форматированный текстовый фрагмент
- `Table`: Структура таблицы с ячейками
- `Enums`: Перечисления (Alignment, FontFamily и т.д.)

**Зависимости:** Model слой полностью независим от View и Controller

### View Layer (`src/view/`)

**Назначение:** UI компоненты и рендеринг

**Технология:** Tkinter

**Ключевые компоненты:**
- `MainWindow`: Главное окно приложения
- `PagedCanvas`: WYSIWYG рендеринг
- `FormatToolbar`: Панель форматирования
- `Dialogs`: Настройки, вставка таблиц и т.д.

### Controller Layer (`src/controller/`)

**Назначение:** Бизнес-логика и обработка событий

**Паттерны:**
- Command pattern (Undo/Redo)
- Observer pattern (изменения документа)

**Ключевые классы:**
- `DocumentController`: Манипуляция документом
- `CommandManager`: Стек Undo/Redo

### ESC/P Layer (`src/escp/`)

**Назначение:** Генерация ESC/P команд

**Ключевые классы:**
- `EscpCommandBuilder`: Генератор команд
- Специализированные builders для шрифтов, позиционирования и т.д.

## Поток данных

Ввод пользователя → View → Controller → Model → ESC/P Builder → Принтер
↑ ↓
└────── Observer ──────┘

text

## Зависимости модулей

view → controller → model
↓
escp → printer

text

## Формат файлов

Документы хранятся в JSON со следующей структурой:

{
"version": "0.1.0",
"metadata": {
"title": "Document Title",
"author": "Author Name",
"created": "2025-10-02T22:00:00"
},
"sections": [
{
"page_settings": {
"paper_type": "A4",
"orientation": "portrait",
"margins": {"top": 20, "bottom": 20, "left": 15, "right": 15}
},
"paragraphs": [
{
"alignment": "left",
"runs": [
{"text": "Hello", "bold": true, "cpi": 12}
]
}
]
}
]
}

text

## Принципы проектирования

### 1. Separation of Concerns
Каждый слой имеет чёткую ответственность и не зависит от других слоёв напрямую.

### 2. Dependency Injection
Controller получает Model через конструктор, View получает Controller.

### 3. Immutability
Model объекты максимально immutable, изменения через методы.

### 4. Type Safety
Все модули строго типизированы (mypy strict).

### 5. Testability
Каждый модуль тестируется изолированно с моками зависимостей.

## Расширяемость

### Добавление нового формата вывода

1. Создать новый builder в `src/output_format/`
2. Реализовать интерфейс `OutputBuilder`
3. Зарегистрировать в `OutputFactory`

### Добавление нового типа элемента

1. Создать класс в `src/model/`
2. Добавить в `Document.elements`
3. Реализовать рендеринг в `PagedCanvas`
4. Добавить генерацию команд в `EscpBuilder`

## Производительность

### Критичные операции

- **Рендеринг Canvas**: используется кэширование растрированных страниц
- **Генерация ESC/P**: commands собираются в `bytearray` для минимизации аллокаций
- **Undo/Redo**: используется Command pattern с memento
- **Загрузка документов**: lazy loading секций

### Оптимизации

- Растеризация страниц в фоновом потоке
- Инкрементальный рендеринг (только изменённые области)
- Пул объектов для Run instances
- Кэширование ESC/P команд для повторяющихся фрагментов

## Безопасность

- Валидация всех пользовательских вводов
- Sanitization путей файлов
- Ограничение размера загружаемых изображений (10 MB)
- Timeout для printer operations (30 секунд)

---

**Последнее обновление:** October 2025
**Версия:** 0.1.0
