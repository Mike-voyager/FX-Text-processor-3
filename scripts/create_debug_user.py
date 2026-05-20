#!/usr/bin/env python3
"""Утилита создания debug-пользователя для FX Text Processor 3.

Создаёт легитимного пользователя с известными креденшелами
через штатные API security-модуля. Не обходит безопасность.

Использование:
    python scripts/create_debug_user.py [--user USER] [--password PASS]

По умолчанию:
    user: debug
    password: debug

⚠ Этот скрипт НЕ включается в релизные сборки.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

# Добавляем корень проекта в путь
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)


def create_debug_user(user_id: str, password: str) -> bool:
    """Создаёт debug-пользователя через штатные API.

    Args:
        user_id: Идентификатор пользователя.
        password: Пароль.

    Returns:
        True если пользователь создан успешно.
    """
    from src.security.auth.password_service import PasswordService
    from src.security.auth.user_storage import JsonUserStorage

    storage = JsonUserStorage()
    svc = PasswordService(user_storage=storage)
    try:
        result = svc.create_password(user_id, password)
        if result:
            print(f"✅ Пользователь '{user_id}' создан успешно")
        else:
            print(f"⚠️ Не удалось создать пользователя '{user_id}'")
        return result
    except Exception as e:
        print(f"❌ Ошибка создания пользователя: {e}")
        return False


def setup_debug_mfa(user_id: str) -> None:
    """Настраивает MFA для debug-пользователя (опционально).

    Args:
        user_id: Идентификатор пользователя.
    """
    print("\nMFA настройка (опционально):")

    # TOTP
    try:
        from src.security.auth.totp_service import setup_totp_for_user

        totp_result = setup_totp_for_user(user_id, "debug-user", include_secret=True)
        secret = totp_result.get("secret", "")
        uri = totp_result.get("uri", "")
        if secret:
            print(f"  TOTP секрет: {secret}")
            print(f"  URI для QR: {uri}")
            print("  ⚠ Сохраните секрет в аутентификаторе!")
    except Exception as e:
        print(f"  TOTP: не настроен ({e})")

    # Backup codes
    try:
        from src.security.auth.code_service import issue_backup_codes_for_user

        backup_codes_result = issue_backup_codes_for_user(user_id, count=5)
        codes = (
            backup_codes_result.codes
            if hasattr(backup_codes_result, "codes")
            else backup_codes_result.get("codes", [])
        )
        if codes:
            print(f"  Backup-коды ({len(codes)}):")
            for i, code_info in enumerate(codes, 1):
                code = code_info.get("code", "") if isinstance(code_info, dict) else str(code_info)
                print(f"    {i:2d}. {code}")
            print("  ⚠ Сохраните эти коды в безопасном месте!")
    except Exception as e:
        print(f"  Backup-коды: не созданы ({e})")


def main() -> int:
    """Точка входа скрипта."""
    parser = argparse.ArgumentParser(
        description="Создание debug-пользователя для FX Text Processor 3",
    )
    parser.add_argument(
        "--user",
        "-u",
        default="debug",
        help="Имя пользователя (по умолчанию: debug)",
    )
    parser.add_argument(
        "--password",
        "-p",
        default="Debug_123",
        help="Пароль (по умолчанию: Debug_123)",
    )
    parser.add_argument(
        "--mfa",
        "-m",
        action="store_true",
        help="Настроить TOTP и backup-коды",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Подробный вывод",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    print("=" * 60)
    print("FX Text Processor 3 — Создание debug-пользователя")
    print("=" * 60)
    print(f"  Пользователь: {args.user}")
    print(f"  Пароль:       {args.password}")
    print()

    if not create_debug_user(args.user, args.password):
        return 1

    if args.mfa:
        setup_debug_mfa(args.user)

    print()
    print("Для входа в приложение используйте:")
    print(f"  Пользователь: {args.user}")
    print(f"  Пароль:       {args.password}")
    if args.mfa:
        print("  + TOTP код из аутентификатора или backup-код")

    print()
    print("⚠ Для продакшена УДАЛИТЕ этот скрипт!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
