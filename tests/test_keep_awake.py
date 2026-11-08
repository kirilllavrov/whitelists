"""Запрет сна на время прогона: kernel32 подменяется, систему не трогаем."""
import sys
import types

from conftest import load

plat = load("plat_awake_mod", "platform_support.py")


def _fake_ctypes(monkeypatch, result):
    calls = []
    kernel32 = types.SimpleNamespace(
        SetThreadExecutionState=lambda flags: calls.append(flags) or result)
    fake = types.SimpleNamespace(windll=types.SimpleNamespace(kernel32=kernel32))
    monkeypatch.setitem(sys.modules, "ctypes", fake)
    return calls


def test_keep_awake_sets_continuous_system_required(monkeypatch):
    """Компьютер уснул посреди прогона: телефон-модем после пробуждения
    не вернулся, и HTTP-шаг 8 часов шёл по мёртвому каналу."""
    monkeypatch.setattr(plat, "IS_WINDOWS", True)
    calls = _fake_ctypes(monkeypatch, result=0x80000000)
    assert plat.keep_awake() is True
    assert calls == [plat.ES_CONTINUOUS | plat.ES_SYSTEM_REQUIRED]


def test_keep_awake_reports_failure(monkeypatch):
    monkeypatch.setattr(plat, "IS_WINDOWS", True)
    _fake_ctypes(monkeypatch, result=0)   # NULL — вызов не удался
    assert plat.keep_awake() is False


def test_keep_awake_noop_outside_windows(monkeypatch):
    monkeypatch.setattr(plat, "IS_WINDOWS", False)
    calls = _fake_ctypes(monkeypatch, result=1)
    assert plat.keep_awake() is False
    assert calls == []
