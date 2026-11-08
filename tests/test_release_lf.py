"""Списки release пишутся с LF в любой ОС.

На Windows write_text() превращает \\n в \\r\\n: список доменов приезжает
на роутер с \\r в конце строки, а git diff показывает весь файл изменённым.
"""
from conftest import load

classify = load("classify_lf_mod", "classify.py")


def test_classify_release_has_no_crlf(tmp_path, monkeypatch):
    monkeypatch.setattr(classify, "RELEASE_DIR", tmp_path)
    data = {"domains": {
        "a.ru": {"verdict": classify.VERDICT_ALLOWED,
                 "addresses": [{"ip": "192.0.2.1", "state": classify.ADR_ALLOWED}]},
        "b.ru": {"verdict": classify.VERDICT_ALLOWED,
                 "addresses": [{"ip": "192.0.2.2", "state": classify.ADR_ALLOWED}]},
    }}
    classify.write_release("mts", data, tmp_path)
    domains = (tmp_path / "whitelist-mts.txt").read_bytes()
    ips = (tmp_path / "IP-whitelist-mts.txt").read_bytes()
    assert domains == b"a.ru\nb.ru\n"
    assert ips == b"192.0.2.1\n192.0.2.2\n"
