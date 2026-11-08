"""Проверка режима белого списка: без сети, ответы целей подставляются."""
import argparse
import asyncio
import time

import pytest

from conftest import load

mode_check = load("mode_check", "mode_check.py")
check_pairs = load("check_pairs_mode_mod", "check_pairs.py")
check = load("check_mode_mod", "check.py")


@pytest.mark.parametrize("allowed, outside, state", [
    ({"ya.ru": True}, {"1.1.1.1": False, "8.8.8.8": False}, "on"),
    ({"ya.ru": True}, {"1.1.1.1": True, "8.8.8.8": True}, "off"),
    ({"ya.ru": False}, {"1.1.1.1": True, "8.8.8.8": True}, "off"),
    # один открытый адрес вне списка — оператор мог его добавить: не судим
    ({"ya.ru": True}, {"1.1.1.1": True, "8.8.8.8": False}, "unclear"),
    ({"ya.ru": False}, {"1.1.1.1": False, "8.8.8.8": False}, "no_link"),
])
def test_classify(allowed, outside, state):
    assert mode_check.classify(allowed, outside) == state


@pytest.mark.parametrize("phase, state, stops", [
    ("on", "off", True),
    ("on", "on", False),
    ("on", "unclear", False),
    ("on", "no_link", False),   # канал пропал — это не смена режима
    ("off", "on", True),
    ("off", "off", False),
    ("unknown", "off", False),
])
def test_mismatch(phase, state, stops):
    assert bool(mode_check.mismatch(phase, state)) is stops


def _result(state):
    return {"state": state, "allowed": {"ya.ru": state != "no_link"},
            "outside": {"1.1.1.1": state == "off", "8.8.8.8": state == "off"}}


def _guard(monkeypatch, states, strikes=2):
    """Прогоняет сторожа по заданной последовательности состояний."""
    sequence = iter(states)
    monkeypatch.setattr(check_pairs.mode_check, "probe_mode",
                        lambda iface="", timeout=3.0: _result(next(sequence, "on")))
    monkeypatch.setattr(check_pairs, "SHUTDOWN_REQUESTED", False)
    monkeypatch.setattr(check_pairs, "MODE_LOST", None)
    monkeypatch.setattr(check_pairs, "BIND_INTERFACE", "")
    args = argparse.Namespace(phase="on", mode_interval=0.01, mode_strikes=strikes)
    records = []

    async def scenario():
        stop = asyncio.Event()
        task = asyncio.create_task(
            check_pairs.run_mode_guard(args, {}, stop, records.append))
        await asyncio.sleep(0.5)
        stop.set()
        await asyncio.wait_for(task, timeout=2)

    asyncio.run(scenario())
    return records


def test_guard_stops_after_two_mismatches_in_a_row(monkeypatch):
    records = _guard(monkeypatch, ["on", "off", "off"])
    assert check_pairs.SHUTDOWN_REQUESTED is True
    assert "выключен" in check_pairs.MODE_LOST
    assert [r["state"] for r in records] == ["on", "off", "off"]
    assert all(r["probe"] == "mode" for r in records)


def test_guard_single_mismatch_is_forgiven(monkeypatch):
    """Одиночный «off» между «on» — случайность, прогон продолжается."""
    _guard(monkeypatch, ["on", "off", "on", "off", "on"])
    assert check_pairs.SHUTDOWN_REQUESTED is False
    assert check_pairs.MODE_LOST is None


@pytest.mark.parametrize("states, phase, expect_reason", [
    (["off", "off"], "on", True),      # подтверждено повторной проверкой
    (["off", "on"], "on", False),      # вторая проверка не подтвердила
    (["on"], "on", False),
    (["on", "on"], "off", True),
    (["off"], "unknown", False),       # фаза не задана — не проверяем
])
def test_check_confirms_mismatch(monkeypatch, states, phase, expect_reason):
    sequence = iter(states)
    monkeypatch.setattr(check.mode_check, "probe_mode",
                        lambda iface="", timeout=3.0: _result(next(sequence, "on")))
    assert bool(check.confirm_mismatch("", phase, pause=0)) is expect_reason


@pytest.mark.parametrize("states, lost", [
    (["no_link", "no_link"], True),
    (["no_link", "on"], False),        # канал вернулся — HTTP-результат годен
    (["on"], False),
    (["off"], False),                  # канал жив; смену режима ловит confirm_mismatch
    (["unclear"], False),
])
def test_check_confirms_link_lost(monkeypatch, states, lost):
    """Компьютер уснул посреди HTTP-шага, телефон после пробуждения не
    вернулся: 236 доменов получили UNKNOWN, а прогон сохранился как обычный."""
    sequence = iter(states)
    monkeypatch.setattr(check.mode_check, "probe_mode",
                        lambda iface="", timeout=3.0: _result(next(sequence, "on")))
    assert check.confirm_link_lost("", pause=0) is lost


def test_pause_between_chunks_ends_on_shutdown(monkeypatch):
    """После остановки пустые блоки выдерживали паузы по 60 с: выход
    из прогона, остановленного в начале, растягивался на десятки минут."""
    monkeypatch.setattr(check_pairs, "SHUTDOWN_REQUESTED", True)
    started = time.monotonic()
    asyncio.run(check_pairs.interruptible_sleep(60))
    assert time.monotonic() - started < 1
