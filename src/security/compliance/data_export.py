"""
Экспорт данных (GDPR Art. 20 - Right to data portability).

DataExportService предоставляет функциональность для:
- Экспорта данных субъекта данных
- Поддержки форматов: JSON, XML, CSV
- Анонимизации PII при экспорте

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import csv
import io
import json
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

from src.security.compliance.anonymization import PIIAnonymizer
from src.security.compliance.exceptions import DataExportError
from src.security.compliance.models import DataCategory, DataExportRequest

if TYPE_CHECKING:
    from src.security.audit import AuditLog

LOG = logging.getLogger(__name__)


@dataclass
class DataExportService:
    """
    Сервис экспорта данных.

    Реализует GDPR Art. 20 - Right to data portability.

    Attributes:
        data_provider: Функция для получения данных субъекта
        anonymizer: PIIAnonymizer для анонимизации
        audit_log: Опциональный AuditLog для логирования
        export_dir: Директория для экспорта

    Example:
        >>> def get_user_data(user_id: str) -> List[Dict]:
        ...     return database.query("SELECT * FROM data WHERE user_id = ?", user_id)
        >>>
        >>> service = DataExportService(data_provider=get_user_data)
        >>> result = service.export_data(user_id, format="json")
    """

    data_provider: Optional[Callable[[str], List[Dict[str, Any]]]] = None
    anonymizer: PIIAnonymizer = field(default_factory=PIIAnonymizer)
    audit_log: Optional["AuditLog"] = None
    export_dir: Optional[Path] = None

    # Поддерживаемые форматы
    SUPPORTED_FORMATS: List[str] = field(
        default_factory=lambda: ["json", "xml", "csv"],
        init=False,
    )

    def export_data(
        self,
        subject_id: str,
        format: str = "json",
        *,
        anonymize_pii: bool = True,
        include_metadata: bool = True,
        categories: Optional[List[DataCategory]] = None,
    ) -> Dict[str, Any]:
        """
        Экспортировать данные субъекта.

        Args:
            subject_id: Идентификатор субъекта данных
            format: Формат экспорта (json, xml, csv)
            anonymize_pii: Анонимизировать PII
            include_metadata: Включить метаданные
            categories: Фильтр по категориям данных

        Returns:
            Словарь с экспортированными данными

        Raises:
            DataExportError: Ошибка экспорта
        """
        if format not in self.SUPPORTED_FORMATS:
            raise DataExportError(
                f"Unsupported format: {format}",
                export_format=format,
            )

        if not self.data_provider:
            raise DataExportError("Data provider not configured")

        try:
            # Получаем данные
            raw_data = self.data_provider(subject_id)

            # Фильтруем по категориям
            if categories:
                raw_data = [
                    record for record in raw_data
                    if DataCategory(record.get("category", "internal")) in categories
                ]

            # Анонимизируем PII
            if anonymize_pii:
                data = self.anonymizer.anonymize_list(raw_data)
            else:
                data = raw_data

            # Формируем результат
            result: Dict[str, Any] = {
                "subject_id": subject_id,
                "export_format": format,
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "record_count": len(data),
                "anonymized": anonymize_pii,
            }

            if include_metadata:
                result["metadata"] = self._generate_metadata(data, categories)

            # Сериализуем данные в нужном формате
            if format == "json":
                result["data"] = data
                result["serialized"] = json.dumps(data, indent=2, ensure_ascii=False)
            elif format == "xml":
                result["data"] = data
                result["serialized"] = self._to_xml(data, subject_id)
            elif format == "csv":
                result["data"] = data
                result["serialized"] = self._to_csv(data)

            # Логируем
            self._log_export(result)

            return result

        except DataExportError:
            raise
        except Exception as e:
            raise DataExportError(
                f"Export failed: {e}",
                export_format=format,
            ) from e

    def export_to_file(
        self,
        subject_id: str,
        format: str = "json",
        output_path: Optional[Path] = None,
        *,
        anonymize_pii: bool = True,
        include_metadata: bool = True,
    ) -> Path:
        """
        Экспортировать данные в файл.

        Args:
            subject_id: Идентификатор субъекта данных
            format: Формат экспорта
            output_path: Путь к файлу (опционально)
            anonymize_pii: Анонимизировать PII
            include_metadata: Включить метаданные

        Returns:
            Путь к созданному файлу

        Raises:
            DataExportError: Ошибка экспорта
        """
        # Экспортируем данные
        result = self.export_data(
            subject_id,
            format=format,
            anonymize_pii=anonymize_pii,
            include_metadata=include_metadata,
        )

        # Определяем путь
        if output_path:
            path = output_path
        elif self.export_dir:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"export_{subject_id}_{timestamp}.{format}"
            path = self.export_dir / filename
        else:
            raise DataExportError("No output path or export_dir configured")

        # Создаём директорию если нужно
        path.parent.mkdir(parents=True, exist_ok=True)

        # Записываем файл
        serialized = result.get("serialized", "")
        try:
            if format == "json":
                # Для JSON добавляем метаданные
                full_data = {
                    "export_info": {
                        "subject_id": result["subject_id"],
                        "exported_at": result["exported_at"],
                        "record_count": result["record_count"],
                        "anonymized": result["anonymized"],
                    },
                    "metadata": result.get("metadata", {}),
                    "data": result["data"],
                }
                path.write_text(json.dumps(full_data, indent=2, ensure_ascii=False), encoding="utf-8")
            else:
                path.write_text(str(serialized), encoding="utf-8")

            LOG.info("Exported data to: %s", path)
            return path

        except Exception as e:
            raise DataExportError(
                f"Failed to write export file: {e}",
                export_format=format,
            ) from e

    def _generate_metadata(
        self,
        data: List[Dict[str, Any]],
        categories: Optional[List[DataCategory]] = None,
    ) -> Dict[str, Any]:
        """Генерировать метаданные экспорта."""
        metadata: Dict[str, Any] = {
            "total_records": len(data),
            "fields": set(),
            "categories": {},
            "date_range": None,
        }

        if not data:
            return metadata

        # Собираем статистику
        dates: List[datetime] = []
        for record in data:
            # Поля
            metadata["fields"].update(record.keys())

            # Категории
            cat = record.get("category", "internal")
            metadata["categories"][cat] = metadata["categories"].get(cat, 0) + 1

            # Даты
            if "created_at" in record:
                try:
                    dates.append(datetime.fromisoformat(str(record["created_at"])))
                except (ValueError, TypeError):
                    pass

        # Преобразуем set в list для сериализации
        metadata["fields"] = list(metadata["fields"])

        # Диапазон дат
        if dates:
            metadata["date_range"] = {
                "earliest": min(dates).isoformat(),
                "latest": max(dates).isoformat(),
            }

        return metadata

    def _to_xml(self, data: List[Dict[str, Any]], subject_id: str) -> str:
        """Преобразовать данные в XML."""
        root = ET.Element("data_export")
        root.set("subject_id", subject_id)
        root.set("exported_at", datetime.now(timezone.utc).isoformat())

        for i, record in enumerate(data):
            record_elem = ET.SubElement(root, "record")
            record_elem.set("index", str(i))

            for key, value in record.items():
                field_elem = ET.SubElement(record_elem, "field")
                field_elem.set("name", key)
                field_elem.text = str(value) if value is not None else ""

        return ET.tostring(root, encoding="unicode")

    def _to_csv(self, data: List[Dict[str, Any]]) -> str:
        """Преобразовать данные в CSV."""
        if not data:
            return ""

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)

        return output.getvalue()

    def _log_export(self, result: Dict[str, Any]) -> None:
        """Логировать экспорт в audit."""
        if not self.audit_log:
            return

        try:
            from src.security.audit import AuditEventType

            self.audit_log.log_event(
                AuditEventType.FORM_HISTORY_ENTRY_ADDED,
                details={
                    "action": "data_export",
                    "subject_id": result["subject_id"],
                    "record_count": result["record_count"],
                    "format": result["export_format"],
                    "anonymized": result["anonymized"],
                },
            )

        except Exception as e:
            LOG.warning("Failed to log export: %s", e)

    def create_export_request(
        self,
        subject_id: str,
        format: str = "json",
        anonymize_pii: bool = True,
    ) -> DataExportRequest:
        """
        Создать запрос на экспорт данных.

        Args:
            subject_id: Идентификатор субъекта
            format: Формат экспорта
            anonymize_pii: Анонимизировать PII

        Returns:
            DataExportRequest
        """
        import uuid

        return DataExportRequest(
            request_id=str(uuid.uuid4()),
            subject_id=subject_id,
            export_format=format,
            anonymize_pii=anonymize_pii,
        )


__all__: list[str] = [
    "DataExportService",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-24"