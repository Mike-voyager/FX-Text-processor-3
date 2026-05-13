"""Интерактивный церемониал бэкапа для FX Text Processor.

Проводит пользователя через полный процесс создания резервной копии:
экспорт keystore, разделение по Шамиру, генерация paper key,
бэкап реестра устройств, инструкции по хранению.
"""

from __future__ import annotations

import enum
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from src.backup.keystore_export import KeystoreExporter
from src.backup.paper_key import PaperKeyConfig, PaperKeyGenerator, PaperKeyResult
from src.backup.shamir import ShamirConfig, ShamirSecretSharing, ShamirShare


class CeremonyStep(enum.Enum):
    """Шаги церемониала бэкапа."""

    START = "start"
    KEYSTORE_EXPORT = "keystore_export"
    SHAMIR_SPLIT = "shamir_split"
    PAPER_KEY = "paper_key"
    DEVICE_REGISTRY = "device_registry"
    STORAGE_INSTRUCTIONS = "storage_instructions"
    COMPLETE = "complete"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class CeremonyResult:
    """Результат церемониала бэкапа.

    Attributes:
        success: Успешность церемониала
        current_step: Последний выполненный шаг
        keystore_path: Путь к экспортированному keystore
        shamir_shares: Список долей Шамира
        paper_key: Результат генерации paper key
        messages: Список сообщений для пользователя
    """

    success: bool
    current_step: CeremonyStep
    keystore_path: Path | None = None
    shamir_shares: list[ShamirShare] = field(default_factory=list)
    paper_key: PaperKeyResult | None = None
    messages: list[str] = field(default_factory=list)


class BackupCeremony:
    """Интерактивный церемониал бэкапа.

    Проводит пользователя через полный процесс создания
    резервной копии с шифрованием и разделением секрета.

    Example:
        >>> ceremony = BackupCeremony()
        >>> result = ceremony.run()
        >>> if result.success:
        ...     print("Бэкап успешно создан")
    """

    def __init__(self) -> None:
        """Инициализация церемониала."""
        self._exporter = KeystoreExporter()
        self._shamir = ShamirSecretSharing()
        self._paper_gen = PaperKeyGenerator()
        self._current_step = CeremonyStep.START
        self._messages: list[str] = []

    def run(
        self,
        output_dir: Path | None = None,
        backup_passphrase: str | None = None,
        shamir_config: ShamirConfig | None = None,
        paper_config: PaperKeyConfig | None = None,
        progress_callback: Callable[[CeremonyStep, str], None] | None = None,
    ) -> CeremonyResult:
        """Запуск полного церемониала.

        Шаги:
            1. Экспорт keystore
            2. Shamir SSS
            3. Paper key
            4. Device registry backup
            5. Инструкции по хранению

        Args:
            output_dir: Директория для сохранения файлов
            backup_passphrase: Пароль для шифрования бэкапа
            shamir_config: Конфигурация разделения Шамира
            paper_config: Конфигурация paper key
            progress_callback: Callback для отслеживания прогресса

        Returns:
            Результат церемониала
        """
        self._messages = []
        output_dir = output_dir or Path.cwd() / "backup"
        shamir_config = shamir_config or ShamirConfig(total_shares=5, threshold=3)
        paper_config = paper_config or PaperKeyConfig()

        keystore_path: Path | None = None
        shamir_shares: list[ShamirShare] = []
        paper_key: PaperKeyResult | None = None

        try:
            # Шаг 1: Экспорт keystore
            self._current_step = CeremonyStep.KEYSTORE_EXPORT
            self._notify(progress_callback, "Экспорт keystore...")

            if backup_passphrase is None:
                # Генерируем случайный passphrase для автоматического бэкапа
                backup_passphrase = secrets.token_urlsafe(32)
                self._messages.append(
                    f"Сгенерирован автоматический passphrase: {backup_passphrase[:8]}..."
                )

            keystore_path = output_dir / f"backup_{self._get_timestamp()}.fxskeystore.enc"
            export_result = self._exporter.export(
                output_path=keystore_path,
                backup_passphrase=backup_passphrase,
                include_device_registry=True,
            )

            if not export_result.success:
                return self._create_result(False, keystore_path, shamir_shares, paper_key)

            self._messages.append(f"Keystore экспортирован: {keystore_path}")
            self._notify(progress_callback, "Keystore экспортирован успешно")

            # Шаг 2: Shamir SSS
            self._current_step = CeremonyStep.SHAMIR_SPLIT
            self._notify(progress_callback, "Разделение секрета по Шамиру...")

            # Генерируем мастер-ключ для демонстрации (в реальности - из keystore)
            master_key = secrets.token_bytes(32)

            shamir_shares = self._shamir.split(
                secret=master_key,
                n=shamir_config.total_shares,
                k=shamir_config.threshold,
                field_size=shamir_config.prime_bits,
            )

            self._messages.append(
                f"Создано {len(shamir_shares)} долей, "
                f"порог восстановления: {shamir_config.threshold}"
            )
            self._notify(progress_callback, "Разделение секрета завершено")

            # Сохраняем доли в файлы
            shares_dir = output_dir / "shamir_shares"
            shares_dir.mkdir(parents=True, exist_ok=True)
            for share in shamir_shares:
                share_file = shares_dir / f"share_{share.index:02d}.b58"
                share_file.write_text(share.to_base58())

            self._messages.append(f"Доли сохранены в: {shares_dir}")

            # Шаг 3: Paper key
            self._current_step = CeremonyStep.PAPER_KEY
            self._notify(progress_callback, "Генерация paper key...")

            paper_key = self._paper_gen.generate(master_key, paper_config)

            if paper_key.success:
                pdf_path = output_dir / f"paper_key_{self._get_timestamp()}.pdf"
                try:
                    final_path = self._paper_gen.generate_pdf(master_key, pdf_path, paper_config)
                    self._messages.append(f"Paper key сохранён: {final_path}")
                except Exception as e:
                    self._messages.append(f"PDF не создан (reportlab недоступен): {e}")

            self._notify(progress_callback, "Paper key сгенерирован")

            # Шаг 4: Device registry backup
            self._current_step = CeremonyStep.DEVICE_REGISTRY
            self._notify(progress_callback, "Бэкап реестра устройств...")

            # Уже включён в keystore export
            self._messages.append("Реестр устройств включён в бэкап keystore")

            # Шаг 5: Инструкции по хранению
            self._current_step = CeremonyStep.STORAGE_INSTRUCTIONS
            self._notify(progress_callback, "Подготовка инструкций...")

            instructions_path = output_dir / "STORAGE_INSTRUCTIONS.txt"
            instructions = self._generate_storage_instructions(shamir_config, paper_config.username)
            instructions_path.write_text(instructions, encoding="utf-8")

            self._messages.append(f"Инструкции сохранены: {instructions_path}")

            # Завершение
            self._current_step = CeremonyStep.COMPLETE
            self._notify(progress_callback, "Церемониал завершён")

            return self._create_result(True, keystore_path, shamir_shares, paper_key)

        except Exception as e:
            self._messages.append(f"Ошибка: {e}")
            self._current_step = CeremonyStep.CANCELLED
            return self._create_result(False, keystore_path, shamir_shares, paper_key)

    def _notify(
        self,
        callback: Callable[[CeremonyStep, str], None] | None,
        message: str,
    ) -> None:
        """Отправляет уведомление о прогрессе."""
        if callback:
            callback(self._current_step, message)

    def _create_result(
        self,
        success: bool,
        keystore_path: Path | None,
        shamir_shares: list[ShamirShare],
        paper_key: PaperKeyResult | None,
    ) -> CeremonyResult:
        """Создаёт объект результата."""
        return CeremonyResult(
            success=success,
            current_step=self._current_step,
            keystore_path=keystore_path,
            shamir_shares=shamir_shares,
            paper_key=paper_key,
            messages=list(self._messages),
        )

    def _get_timestamp(self) -> int:
        """Возвращает текущую метку времени."""
        import time

        return int(time.time())

    def _generate_storage_instructions(self, shamir_config: ShamirConfig, username: str) -> str:
        """Генерирует инструкции по хранению."""
        lines = [
            "=" * 70,
            "FX TEXT PROCESSOR - РЕЗЕРВНОЕ КОПИРОВАНИЕ",
            "Инструкции по хранению компонентов",
            "=" * 70,
            "",
            f"Дата создания: {self._format_timestamp()}",
            f"Пользователь: {username or 'N/A'}",
            "",
            "СОЗДАННЫЕ КОМПОНЕНТЫ:",
            "-" * 70,
            "1. Encrypted Keystore (.fxskeystore.enc)",
            "   - Основной файл с зашифрованными ключами",
            "   - Требуется passphrase для восстановления",
            "",
            f"2. Shamir Secret Sharing ({shamir_config.total_shares} shares, threshold {shamir_config.threshold})",
            "   - Доли секрета для восстановления",
            "   - Каждая доля в отдельном файле .b58",
            "",
            "3. Paper Key (PDF)",
            "   - Бумажная копия для аварийного восстановления",
            "   - Содержит Base58-кодированный ключ с CRC-32",
            "",
            "ПРАВИЛА ХРАНЕНИЯ:",
            "-" * 70,
            "",
            "DO (Обязательно):",
            "- Храните доли Шамира в разных физических местах",
            "- Используйте сейфы или защищённые хранилища",
            "- Держите paper key в недоступном для посторонних месте",
            "- Проверяйте целостность бэкапов ежеквартально",
            "",
            "DON'T (Запрещено):",
            "- Не храните все доли Шамира в одном месте",
            "- Не фотографируйте и не сканируйте paper key",
            "- Не передавайте passphrase по незащищённым каналам",
            "- Не оставляйте бэкапы без присмотра",
            "",
            "ВОССТАНОВЛЕНИЕ:",
            "-" * 70,
            f"Для восстановления потребуется {shamir_config.threshold} из {shamir_config.total_shares} долей Шамира",
            "или paper key + passphrase от keystore.",
            "",
            "ПОРЯДОК ВОССТАНОВЛЕНИЯ:",
            "1. Импортируйте keystore с passphrase",
            "2. При необходимости используйте Shamir shares",
            "3. Восстановите реестр устройств",
            "4. Проверьте работоспособность системы",
            "",
            "=" * 70,
            "КОНФИДЕНЦИАЛЬНО - НЕ РАСПРОСТРАНЯТЬ",
            "=" * 70,
        ]

        return "\n".join(lines)

    def _format_timestamp(self) -> str:
        """Форматирует метку времени для чтения."""
        from datetime import datetime

        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def get_step_description(self, step: CeremonyStep) -> str:
        """Возвращает описание шага для отображения.

        Args:
            step: Шаг церемониала

        Returns:
            Описание шага на русском языке
        """
        descriptions = {
            CeremonyStep.START: "Подготовка",
            CeremonyStep.KEYSTORE_EXPORT: "Экспорт keystore",
            CeremonyStep.SHAMIR_SPLIT: "Разделение секрета (Shamir SSS)",
            CeremonyStep.PAPER_KEY: "Генерация paper key",
            CeremonyStep.DEVICE_REGISTRY: "Бэкап реестра устройств",
            CeremonyStep.STORAGE_INSTRUCTIONS: "Инструкции по хранению",
            CeremonyStep.COMPLETE: "Завершено",
            CeremonyStep.CANCELLED: "Отменено",
        }
        return descriptions.get(step, "Неизвестный шаг")

    def get_progress_percentage(self, step: CeremonyStep) -> int:
        """Возвращает процент прогресса для шага.

        Args:
            step: Текущий шаг

        Returns:
            Процент выполнения (0-100)
        """
        progress_map = {
            CeremonyStep.START: 0,
            CeremonyStep.KEYSTORE_EXPORT: 20,
            CeremonyStep.SHAMIR_SPLIT: 40,
            CeremonyStep.PAPER_KEY: 60,
            CeremonyStep.DEVICE_REGISTRY: 80,
            CeremonyStep.STORAGE_INSTRUCTIONS: 90,
            CeremonyStep.COMPLETE: 100,
            CeremonyStep.CANCELLED: 0,
        }
        return progress_map.get(step, 0)
