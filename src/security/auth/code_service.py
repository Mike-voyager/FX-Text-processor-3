# -*- coding: utf-8 -*-
"""
Модуль: code_service.py

Назначение: Сервис для интеграции и управления аварийными резервными кодами (Backup/Recovery codes) в FX Text Processor 3.
- Генерирует batch резервных кодов через менеджер.
- Предоставляет API для безопасного отображения, экспорта, печати резервных кодов в UI.
- Поддерживает проверку, журналирование и TTL по SecondFactorManager.
- Использовать только из UI/контроллеров!

Пример вызова из приложения:
    codes = issue_backup_codes_for_user(user_id, count=12)
    # UI: вывести пользователю, распечатать, экспортировать (без раскрытия других backup-кодов!)
"""

from src.security.auth.second_factor import SecondFactorManager


def issue_backup_codes_for_user(user_id: str, count: int = 12, ttl_sec: int = 604800) -> list:
    """
    Запрашивает менеджер MFA на генерацию batch аварийных резервных кодов для пользователя.
    Возвращает только сами коды (без внутренней структуры для безопасности).
    """
    mfa_manager = SecondFactorManager()
    codes = mfa_manager.issue_backup_codes(user_id, count, ttl_sec)
    return codes


def validate_backup_code_for_user(user_id: str, code: str) -> bool:
    """
    Проверяет код: если актуален и не использован — будет инвалидирован.
    """
    mfa_manager = SecondFactorManager()
    return mfa_manager.verify_factor(user_id, "backup_code", code)


def get_active_backup_codes(user_id: str) -> list:
    """
    Получает все невоспользованные аварийные коды для пользователя — для UI или аудита.
    """
    mfa_manager = SecondFactorManager()
    backup_factors = mfa_manager._factors.get(user_id, {}).get("backup_code", [])
    active_codes = []
    for factor in backup_factors:
        for item in factor["state"]["codes"]:
            if not item["used"]:
                active_codes.append(item["code"])
    return active_codes


def export_backup_codes_csv(user_id: str) -> str:
    """
    Экспортирует невоспользованные коды для backup/recovery в CSV-формате.
    """
    codes = get_active_backup_codes(user_id)
    return "code\n" + "\n".join(codes)


def audit_backup_codes(user_id: str) -> list:
    """
    Возвращает журнал использования аварийных кодов (структура audit log).
    """
    mfa_manager = SecondFactorManager()
    return [
        entry
        for entry in mfa_manager._audit_log
        if entry.get("user_id") == user_id and entry.get("op") == "backup_code_used"
    ]
