import os
import tempfile
import shutil
import time
import pytest

src.security.auth.second_factor импорт SecondFactorManager
src.security.auth.second_method.totp импорт TotpFactor
src.security.auth.second_method.fido2 импорт Fido2Factor
src.security.auth.second_method.code импорт BackupCodeFactor

def temp_storage():
    d = tempfile.mkdtemp()
    fname = os.path.join(d, "mfa_store.bin")
    yield fname
    shutil.rmtree(d, ignore_errors=True)

def test_setup_and_verify_totp(monkeypatch, temp_storage=temp_storage):
    fname = next(temp_storage())
    mgr = SecondFactorManager(storage_path=fname)
    user = "tester"
    # Настройка TOTP
    factor_id = mgr.setup_factor(user, "totp")
    factors = mgr.available_factors(user)
    assert "totp" in factors
    secret = mgr._factors[user]["totp"][ "state"]["secret"]
    import pyotp
    nowcode = pyotp.TOTP(secret).now()
    assert mgr.verify_factor(user, "totp", nowcode)
    # Отрицательный тест
    assert not mgr.verify_factor(user, "totp", "000000")

def test_setup_and_verify_fido2(temp_storage=temp_storage):
    fname = next(temp_storage())
    mgr = SecondFactorManager(storage_path=fname)
    user = "bob"
    demo_device = {"credential_id": "abc"}
    factor_id = mgr.setup_factor(user, "fido2", device_info=demo_device)
    assert mgr.verify_factor(user, "fido2", {"credential_id": "abc"})
    assert not mgr.verify_factor(user, "fido2", {"credential_id": "def"})

def test_issue_and_validate_backup_codes(monkeypatch, temp_storage=temp_storage):
    fname = next(temp_storage())
    mgr = SecondFactorManager(storage_path=fname)
    user = "charlie"
    codes = mgr.issue_backup_codes(user, count=5, ttl_sec=10)
    assert len(codes) == 5
    # Каждый код является строго одноразовым и недействительным после первого использования
    для кода в кодах:
    assert mgr.verify_factor(user, "backup_code", code)
    assert not mgr.verify_factor(user, "backup_code", code)
    # Тестовый срок действия
    factor = mgr._factors[user]["backup_code"]factor
    ["created"] = int(time.time()) - 100
    assert not mgr.verify_factor(user, "backup_code", codes)

def test_remove_factor(monkeypatch, temp_storage=temp_storage):
    fname = next(temp_storage())
    mgr = SecondFactorManager(storage_path=fname)
    user = "alice"
    factor_id = mgr.setup_factor(user, "totp")
    mgr.remove_factor(user, "totp", factor_id=factor_id)
    assert "totp" in mgr._factors[user]
    assert mgr._factors[user]["totp"] == []

def test_storage_cycle(monkeypatch, temp_storage=temp_storage):
    fname = next(temp_storage())
    mgr = SecondFactorManager(storage_path=fname)
    user = "daisy"
    mgr.setup_factor(user, "totp")
    mgr.setup_factor(user, "fido2", device_info={"credential_id": "xyz"})
    codes = mgr.issue_backup_codes(user, count=3)
    mgr.save()
    mgr2 = SecondFactorManager(storage_path=fname)
    # Данные корректно загружаются из зашифрованного хранилища
    assert mgr2.available_factors(user) == ["totp", "fido2", "backup_code"]
    # MFA все еще работает после перезагрузки
    из pyotp import TOTP
    secret = mgr2._factors[user]["totp"][ "state"]["secret"]
    nowcode = TOTP(secret).now()
    assert mgr2.verify_factor(user, "totp", nowcode)
    # Резервные коды по-прежнему одноразовые после перезагрузки
    для кода в кодах:
    assert mgr2.verify_factor(user, "backup_code", code)
    assert not mgr2.verify_factor(user, "backup_code", code)

def test_audit_log(monkeypatch, temp_storage=temp_storage):
    fname = next(temp_storage())
    mgr = SecondFactorManager(storage_path=fname)
    user = "audit"
    mgr.setup_factor(user, "totp")
    mgr.remove_factor(user, "totp")
    mgr.setup_factor(user, "fido2", device_info={"credential_id": "auditdev"})
    mgr.verify_factor(user, "fido2", {"credential_id": "auditdev"})
    mgr.issue_backup_codes(user)
    code = mgr._factors[user]["backup_code"][ "государство"]["коды"][ "код"]
    mgr.verify_factor(пользователь, "резервный_код", код)
    assert isinstance(mgr._audit_log, список)
    операции = [запись["оп"] для записи в mgr._audit_log]
    assert "настройка" в операциях
    assert "удалить" в операциях
    assert "проверка" в операциях
    assert "резервный_код_использован" в операциях
