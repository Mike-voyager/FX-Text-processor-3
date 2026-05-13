"""Генератор бумажных ключей для FX Text Processor.

Предоставляет создание печатных резервных копий ключей в формате
QR-кода + группы Base58 для ручного ввода с CRC-32 проверкой.
"""

from __future__ import annotations

import enum
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

import base58


class PaperKeyFormat(enum.Enum):
    """Форматы бумажного ключа.

    Attributes:
        STANDARD: Стандартный формат (QR + 13 групп)
        COMPACT: Компактный формат (только QR)
        FULL: Полный формат с инструкциями
    """

    STANDARD = "standard"
    COMPACT = "compact"
    FULL = "full"


@dataclass(frozen=True)
class PaperKeyConfig:
    """Конфигурация paper key.

    Attributes:
        include_qr: Включить QR-код
        include_groups: Включить группы Base58
        username: Имя пользователя для документа
    """

    include_qr: bool = True
    include_groups: bool = True
    username: str = ""


@dataclass(frozen=True)
class PaperKeyResult:
    """Результат генерации бумажного ключа.

    Attributes:
        success: Успешность генерации
        groups: Список групп Base58
        qr_data: Данные для QR-кода
        checksum: Контрольная сумма CRC-32
        pdf_path: Путь к сгенерированному PDF
        key_id: Идентификатор ключа
    """

    success: bool
    groups: list[str]
    qr_data: str
    checksum: str
    pdf_path: Path | None
    key_id: str

    def __post_init__(self) -> None:
        """Инициализация пустого списка групп."""
        if self.groups is None:
            object.__setattr__(self, "groups", [])


class PaperKeyGenerator:
    """Генератор paper key.

    Создаёт резервные копии в формате:
    - 36-byte payload (256-bit key + 4-byte CRC-32)
    - Кодирование в Base58
    - Разбиение на 13 групп по 4 символа
    - Опционально: QR код
    """

    _VERSION_PREFIX = b"\x01"  # Версия формата
    _NUM_GROUPS = 13
    _GROUP_SIZE = 4

    def __init__(self, config: PaperKeyConfig | None = None):
        """Инициализация генератора.

        Args:
            config: Конфигурация или None для стандартной
        """
        self.config = config or PaperKeyConfig()

    def generate(self, master_key: bytes, config: PaperKeyConfig | None = None) -> PaperKeyResult:
        """Генерация paper key с CRC-32 проверкой целостности.

        Args:
            master_key: Мастер-ключ (32 bytes)
            config: Опциональная конфигурация (переопределяет конструктор)

        Returns:
            Результат генерации
        """
        cfg = config or self.config

        # Формат: version (1) + key (32) + CRC-32 (4) = 37 bytes
        if len(master_key) != 32:
            raise ValueError(f"Master key должен быть 32 байта, получено {len(master_key)}")

        crc = zlib.crc32(master_key) & 0xFFFFFFFF
        payload = self._VERSION_PREFIX + master_key + struct.pack(">I", crc)

        # Кодируем в Base58
        encoded = base58.b58encode(payload).decode("ascii")

        # Разбиваем на 13 групп по 4 символа
        groups = [
            encoded[i : i + self._GROUP_SIZE] for i in range(0, len(encoded), self._GROUP_SIZE)
        ]

        # Убеждаемся что у нас ровно нужное количество групп
        if len(groups) > self._NUM_GROUPS:
            groups = groups[: self._NUM_GROUPS]
        else:
            while len(groups) < self._NUM_GROUPS:
                groups.append("----")

        # Генерируем ID ключа (первые 16 hex символов SHA-256)
        import hashlib

        key_id = hashlib.sha256(master_key).hexdigest()[:16].upper()

        return PaperKeyResult(
            success=True,
            groups=groups,
            qr_data=encoded,
            checksum=f"{crc:08X}",
            pdf_path=None,
            key_id=key_id,
        )

    def recover_from_groups(self, groups: list[str]) -> bytes:
        """Восстановление ключа из групп.

        Сборка Base58 строки, декодирование, проверка CRC-32.

        Args:
            groups: Список групп Base58

        Returns:
            Восстановленный master key (32 bytes)

        Raises:
            ValueError: При неверном формате или контрольной сумме
        """
        # Собираем полную Base58 строку
        full_string = "".join(g for g in groups if g != "----")

        # Декодируем
        try:
            payload = base58.b58decode(full_string)
        except Exception as e:
            raise ValueError(f"Ошибка декодирования Base58: {e}")

        if len(payload) != 37:
            raise ValueError(f"Неверная длина payload: {len(payload)} != 37")

        # Проверяем версию
        version = payload[0:1]
        if version != self._VERSION_PREFIX:
            raise ValueError(f"Неверная версия: {version.hex()} != {self._VERSION_PREFIX.hex()}")

        # Извлекаем ключ и CRC
        key = payload[1:33]
        stored_crc = struct.unpack(">I", payload[33:37])[0]

        # Проверяем CRC-32
        computed_crc = zlib.crc32(key) & 0xFFFFFFFF
        if computed_crc != stored_crc:
            raise ValueError(
                f"Неверная контрольная сумма CRC-32: "
                f"ожидалось {stored_crc:08X}, получено {computed_crc:08X}"
            )

        return key

    def generate_pdf(
        self,
        master_key: bytes,
        output_path: Path,
        config: PaperKeyConfig | None = None,
    ) -> Path:
        """Генерация PDF с paper key.

        Использует reportlab для генерации PDF документа
        с форматированием для печати.

        Args:
            master_key: Мастер-ключ
            output_path: Путь для сохранения PDF
            config: Опциональная конфигурация

        Returns:
            Путь к созданному PDF
        """
        cfg = config or self.config

        # Генерируем ключ
        result = self.generate(master_key, cfg)

        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.units import mm
            from reportlab.pdfgen import canvas

            c = canvas.Canvas(str(output_path), pagesize=A4)
            width, height = A4

            # Заголовок
            c.setFont("Courier-Bold", 18)
            title = "FX Text Processor - Paper Key"
            c.drawCentredString(width / 2, height - 30 * mm, title)

            # Подзаголовок с username
            c.setFont("Courier", 10)
            if cfg.username:
                c.drawCentredString(width / 2, height - 40 * mm, f"User: {cfg.username}")

            # Key ID
            c.setFont("Courier-Bold", 12)
            c.drawCentredString(width / 2, height - 55 * mm, f"Key ID: {result.key_id}")

            # Разделитель
            c.setStrokeColorRGB(0, 0, 0)
            c.line(20 * mm, height - 60 * mm, width - 20 * mm, height - 60 * mm)

            # Группы в две колонки
            if cfg.include_groups:
                c.setFont("Courier-Bold", 14)
                y_start = height - 75 * mm
                x_left = 30 * mm
                x_right = width / 2 + 10 * mm

                for i, group in enumerate(result.groups):
                    y = y_start - (i % 7) * 10 * mm
                    x = x_left if i < 7 else x_right
                    c.drawString(x, y, f"{i + 1:2d}. {group}")

            # Инструкции
            c.setFont("Courier", 9)
            y = 80 * mm
            instructions = [
                "INSTRUCTIONS:",
                "",
                "1. This document contains your master key backup.",
                "2. Store it in a secure location (safe, lockbox).",
                "3. Do not photograph or scan this key.",
                "4. Use for recovery only if keystore is lost.",
                "5. Compromised key = compromised system.",
                "",
                f"CRC-32 Checksum: {result.checksum}",
            ]

            for line in instructions:
                c.drawString(25 * mm, y, line)
                y -= 6 * mm

            # QR код (если требуется и доступен)
            if cfg.include_qr:
                try:
                    import io

                    import qrcode
                    from reportlab.lib.utils import ImageReader

                    qr = qrcode.QRCode(
                        version=1,
                        error_correction=qrcode.constants.ERROR_CORRECT_M,
                        box_size=10,
                        border=2,
                    )
                    qr.add_data(result.qr_data)
                    qr.make(fit=True)

                    img = qr.make_image(fill_color="black", back_color="white")
                    img_bytes = io.BytesIO()
                    img.save(img_bytes, format="PNG")
                    img_bytes.seek(0)

                    qr_x = width - 60 * mm
                    qr_y = 30 * mm
                    c.drawImage(ImageReader(img_bytes), qr_x, qr_y, 40 * mm, 40 * mm)

                    c.setFont("Courier", 8)
                    c.drawCentredString(qr_x + 20 * mm, qr_y - 5 * mm, "QR Code")
                except ImportError:
                    pass  # QR не критичен

            # Водяной знак (фоновый)
            c.saveState()
            c.setFont("Courier", 60)
            c.setFillColorRGB(0.9, 0.9, 0.9)
            c.drawCentredString(width / 2, height / 2, "CONFIDENTIAL")
            c.restoreState()

            c.save()
            return output_path

        except ImportError:
            # Fallback: создаём текстовый файл с инструкциями
            text_content = self._generate_text_template(result, cfg)
            output_path = output_path.with_suffix(".txt")
            output_path.write_text(text_content, encoding="utf-8")
            return output_path

    def _generate_text_template(self, result: PaperKeyResult, config: PaperKeyConfig) -> str:
        """Генерирует текстовый шаблон при отсутствии reportlab."""
        lines = [
            "=" * 70,
            "FX TEXT PROCESSOR - PAPER KEY".center(70),
            "=" * 70,
            "",
        ]

        if config.username:
            lines.append(f"User: {config.username}")
            lines.append("")

        lines.extend(
            [
                f"Key ID: {result.key_id}",
                "",
                "PAPER KEY (Base58 Groups):",
                "-" * 70,
            ]
        )

        for i, group in enumerate(result.groups, 1):
            lines.append(f"  {i:2d}.  {group}")

        lines.extend(
            [
                "-" * 70,
                "",
                "QR CODE DATA:",
                result.qr_data[:80] + "..." if len(result.qr_data) > 80 else result.qr_data,
                "",
                "IMPORTANT:",
                "- Store this document in a secure location",
                "- Do not photograph or scan this key",
                "- If compromised, create a new backup immediately",
                "- Use for recovery only if keystore is lost",
                "",
                f"CRC-32 Checksum: {result.checksum}",
                "=" * 70,
            ]
        )

        return "\n".join(lines)

    def validate_groups(self, groups: list[str]) -> tuple[bool, str]:
        """Проверяет корректность введённых групп.

        Args:
            groups: Список групп для проверки

        Returns:
            Кортеж (валидно, сообщение)
        """
        if len(groups) != self._NUM_GROUPS:
            return False, f"Ожидается {self._NUM_GROUPS} групп, получено {len(groups)}"

        # Собираем полную строку (исключая padding)
        full_string = "".join(g for g in groups if g != "----")

        # Проверка Base58 символов
        valid_chars = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
        for char in full_string:
            if char not in valid_chars:
                return False, f"Недопустимый символ: {char}"

        # Проверка декодирования и CRC
        try:
            payload = base58.b58decode(full_string)
            if len(payload) != 37:
                return False, f"Неверная длина после декодирования: {len(payload)}"

            key = payload[1:33]
            stored_crc = struct.unpack(">I", payload[33:37])[0]
            computed_crc = zlib.crc32(key) & 0xFFFFFFFF

            if computed_crc != stored_crc:
                return False, "Неверная контрольная сумма CRC-32"

        except Exception as e:
            return False, f"Ошибка валидации: {e}"

        return True, "Группы валидны"

    def get_qr_data(self, result: PaperKeyResult) -> str:
        """Возвращает данные для QR-кода.

        Args:
            result: Результат генерации

        Returns:
            Строка для кодирования в QR
        """
        return result.qr_data
