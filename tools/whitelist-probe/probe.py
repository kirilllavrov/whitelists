#!/usr/bin/env python3
"""Проверка доменов и IP на прохождение через белый список мобильного оператора.

Запускается внутри контейнера, подключённого к macvlan-интерфейсу модема.
Общается с DNS модема и делает TLS-рукопожатие по каждому адресу.

Статусы:
  allow           TLS-рукопожатие прошло
  allow_tls       TCP и TLS есть, сервер сам разорвал рукопожатие (не блокировка сети)
  open_http       по 443 закрыто, но по 80 отдаётся контент
  http_redirect   по 80 редирект на https, который недоступен
  blocked_portal  по 80 редирект на страницу оператора «Доступ ограничен»
  blocked_tls     RST во время рукопожатия
  blocked_timeout     TCP-соединение не установилось (таймаут)
  blocked_tls_timeout TCP есть, но TLS-рукопожатие не завершилось (таймаут)
  blocked_dns     DNS вернул заглушку (8.6.112.x, 8.47.69.x, 0.0.0.0, 127.0.0.1)
  refused         соединение отклонено
  no_dns          A-записей нет (NOERROR без адресов или NXDOMAIN)
  dns_error       DNS не ответил или ответил ошибкой (SERVFAIL, REFUSED)
  error           прочее
"""

import os
import signal
import sys


def _startup_int(signum, frame):
    # Ctrl+C во время импорта модулей: выходим тихо, без traceback.
    sys.stderr.write("\nпрервано (Ctrl+C)\n")
    os._exit(130)


signal.signal(signal.SIGINT, _startup_int)

import argparse
import ipaddress
import random
import re
import socket
import ssl
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

try:
    from curl_cffi import CurlOpt
    from curl_cffi import requests as browser_requests
    HAVE_BROWSER_TLS = True
except Exception:
    CurlOpt = None
    browser_requests = None
    HAVE_BROWSER_TLS = False

IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
SINK_PREFIXES = ("8.6.112.", "8.47.69.")
SINK_EXACT = {"0.0.0.0", "127.0.0.1", "192.168.8.1"}

STATUS_ORDER = [
    "allow", "allow_tls", "open_http", "http_redirect", "blocked_portal",
    "blocked_dns", "blocked_tls", "blocked_timeout", "blocked_tls_timeout",
    "refused", "no_dns", "dns_error", "error",
]

CIDR_RE = re.compile(r"^[0-9a-fA-F:.]+/\d{1,3}$")


def is_ipv4(s):
    if not IPV4_RE.match(s):
        return False
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def norm_domain(raw):
    s = raw.strip().lower()
    if not s:
        return ""
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    s = s.split("@")[-1].split(":", 1)[0].strip(".")
    if not s:
        return ""
    try:
        s.encode("ascii")
    except UnicodeEncodeError:
        try:
            s = s.encode("idna").decode("ascii")
        except Exception:
            return ""
    return s


def dig_query(domain, resolver, timeout):
    """Один запрос A. Возвращает (rcode, адреса).

    rcode — ответ сервера (NOERROR, NXDOMAIN, SERVFAIL, REFUSED…) или "",
    если ответа не было: таймаут, недоступный сервер, сбой dig. Адреса —
    все A из ответа, включая заглушки: их распознаёт probe_tls_only.
    +short здесь не годится — он печатает одно и то же и для пустого
    ответа, и для таймаута.
    """
    try:
        p = subprocess.run(
            ["dig", "+noedns", "+time=%d" % timeout, "+tries=1",
             "A", domain, "@" + resolver],
            capture_output=True, text=True, timeout=timeout + 3,
        )
    except Exception:
        return "", []
    m = re.search(r"->>HEADER<<-.*status: ([A-Z]+)", p.stdout)
    rcode = m.group(1) if m else ""
    ips = set()
    for line in p.stdout.splitlines():
        f = line.split()
        if len(f) >= 5 and not line.startswith(";") and f[-2] == "A" and is_ipv4(f[-1]):
            ips.add(f[-1])
    return rcode, sorted(ips)


def resolve_a(domain, resolver, timeout, attempts=5):
    """До attempts запросов A, до первого ответа с адресами.

    Возвращает (rcode, адреса) последнего запроса. Повтор — при любом
    ответе без адресов: на мобильном канале запрос теряется, а DNS
    оператора иногда быстро отвечает пустым NOERROR или SERVFAIL и для
    существующих доменов (в прогоне МТС так «пропали» reg.ru и timeweb.*).
    """
    rcode, ips = "", []
    for i in range(attempts):
        if i:
            time.sleep(0.4)
        rcode, ips = dig_query(domain, resolver, timeout)
        if ips:
            break
    return rcode, ips


def browser_tls_probe(ip, sni, timeout):
    """TLS-рукопожатие с отпечатком Chrome.

    Обычный ssl-клиент Python часть банков (vtb.ru) молча блокирует на
    несколько минут: TCP проходит, а на ClientHello сервер перестаёт
    отвечать, и все следующие проверки дают blocked_timeout. Chrome-отпечаток
    проходит и блокировку не запускает.
    """
    t0 = time.time()

    def ms():
        return round((time.time() - t0) * 1000)

    # Тело ответа не читается: нужен только факт рукопожатия. Декодирование
    # выключено намеренно — некоторые серверы отдают Content-Encoding, которого
    # libcurl не знает (sber.ru: aws-chunked), и он падает с ошибкой 61 уже
    # после того, как TLS и HTTP-ответ прошли.
    curl_opts = {CurlOpt.HTTP_CONTENT_DECODING: 0}
    # домен резолвим сами: соединение — на проверяемый адрес, SNI — домен
    if not is_ipv4(sni):
        curl_opts[CurlOpt.RESOLVE] = ["%s:443:%s" % (sni, ip)]
    kwargs = dict(
        impersonate="chrome",
        verify=False,
        allow_redirects=False,
        timeout=timeout,
        stream=True,
        curl_options=curl_opts,
    )
    try:
        resp = browser_requests.get("https://%s/" % sni, **kwargs)
        resp.close()
        return "allow", ms(), ""
    except Exception as e:
        name = type(e).__name__.lower()
        text = str(e)
        low = text.lower()
        if "timeout" in name or "timed out" in low:
            return "blocked_tls_timeout", ms(), "tls handshake timeout"
        # curl 92 и 16 — ошибки уровня HTTP/2: RST_STREAM или GOAWAY пришли
        # внутри TLS-сессии, то есть рукопожатие с настоящим сервером уже
        # состоялось (без ключей сессии такой кадр не подделать). Иначе слово
        # «reset» в тексте ниже превращает это в blocked_tls. Так отвечает
        # ozone.ru: «HTTP/2 stream 1 reset by server (error 0x1 PROTOCOL_ERROR)».
        if re.search(r"curl: \((?:16|92)\)", text):
            return "allow", ms(), "TLS ok, HTTP/2 error from server"
        if "reset" in low or "recv failure" in low:
            return "blocked_tls", ms(), text[:90]
        if "refused" in low:
            return "refused", ms(), "connection refused"
        # Соединение закрыли до ответа сервера (FIN без ServerHello): так же
        # выглядит DPI, обрывающий соединение по SNI. От сервера не пришло ни
        # байта TLS, поэтому это не allow_tls.
        if "closed abruptly" in low or "ssl_error_syscall" in low or "unexpected eof" in low:
            return "blocked_tls", ms(), text[:90]
        if "ssl" in name or "certificate" in name or "tls" in low:
            return "allow_tls", ms(), text[:90]
        if "connect" in low or "connection" in low:
            return "blocked_tls", ms(), text[:90]
        # ответ сервера получен, просто тело не разобрать — сайт доступен
        if "content encoding" in low or "unrecognized" in low:
            return "allow", ms(), "server answered, body not decoded"
        return "error", ms(), text[:90]


def tls_probe(ip, sni, timeout):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t0 = time.time()
    sock = None

    def ms():
        return round((time.time() - t0) * 1000)

    try:
        # отдельно TCP: важно отличить «до хоста не дошли» от «хост молчит на TLS»
        try:
            sock = socket.create_connection((ip, 443), timeout=timeout)
        except ConnectionRefusedError:
            return "refused", ms(), "connection refused"
        except ConnectionResetError:
            return "blocked_tls", ms(), "connection reset"
        except socket.timeout:
            return "blocked_timeout", ms(), "tcp connect timeout"
        except OSError as e:
            return "error", ms(), str(e)[:90]

        if HAVE_BROWSER_TLS:
            sock.close()
            sock = None
            return browser_tls_probe(ip, sni, timeout)

        try:
            ss = ctx.wrap_socket(sock, server_hostname=sni)
            ss.close()
            return "allow", ms(), ""
        except socket.timeout:
            return "blocked_tls_timeout", ms(), "tls handshake timeout"
        except ssl.SSLEOFError:
            # закрыто до ответа сервера — см. browser_tls_probe
            return "blocked_tls", ms(), "connection closed before server reply"
        except ssl.SSLError as e:
            return "allow_tls", ms(), str(e)[:90]
        except ConnectionResetError:
            return "blocked_tls", ms(), "connection reset"
        except OSError as e:
            return "error", ms(), str(e)[:90]
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def http_probe(ip, host, timeout, portal_host):
    """Возвращает (код, location, ошибка)."""
    req = (
        "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) "
        "Chrome/131.0.0.0 Safari/537.36\r\nAccept: text/html\r\n"
        "Accept-Language: ru-RU,ru;q=0.9\r\nConnection: close\r\n\r\n" % host
    )
    t0 = time.time()
    sock = None
    try:
        sock = socket.create_connection((ip, 80), timeout=timeout)
        sock.sendall(req.encode())
        data = b""
        while len(data) < 8192:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
        head = data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", "replace")
        first = head.split("\r\n", 1)[0].split()
        code = first[1] if len(first) > 1 else ""
        loc = ""
        for line in head.split("\r\n")[1:]:
            if line.lower().startswith("location:"):
                loc = line.split(":", 1)[1].strip()
                break
        return code, loc, round((time.time() - t0) * 1000), ""
    except socket.timeout:
        return "", "", round((time.time() - t0) * 1000), "timeout"
    except ConnectionResetError:
        return "", "", round((time.time() - t0) * 1000), "connection reset"
    except OSError as e:
        return "", "", round((time.time() - t0) * 1000), str(e)[:80]
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def is_https_redirect(code, loc):
    return code in ("301", "302", "303", "307", "308") and loc.lower().startswith("https://")


def tls_round(domain, ips, args, stop_on_allow=False, timeout=None, sni=None):
    """Один проход по адресам.

    Возвращает (allowed, failed, last): allowed — список (ip, status, err),
    failed — адреса, которые не прошли, last — последняя неудача.
    """
    timeout = args.timeout if timeout is None else timeout
    if sni is None:
        sni = domain
    allowed = []
    failed = []
    last = ("error", "", "no attempts")
    for ip in ips:
        st, _, err = tls_probe(ip, sni, timeout)
        if st in ("allow", "allow_tls"):
            allowed.append((ip, st, err))
            if stop_on_allow:
                break
        else:
            failed.append(ip)
            last = (st, ip, err)
    return allowed, failed, last


# Итоги, после которых второй проход не нужен: TLS прошёл, DNS ответил
# заглушкой, либо по 80 показан портал оператора. no_dns и dns_error сюда
# не входят: пустой ответ DNS оператора бывает сбоем, и второй проход —
# уже в другое время — проверяет такой домен заново, начиная с DNS.
TERMINAL = ("allow", "allow_tls", "blocked_dns", "blocked_portal")
DNS_RECHECK = ("no_dns", "dns_error")


def probe_tls_only(name, kind, args):
    """Проход 1: DNS, TLS и — если TLS не прошёл — HTTP:80.

    HTTP нужен здесь, потому что портал оператора виден только по 80:
    по 443 блокировка выглядит как обычный таймаут или RST. Портал сразу
    даёт терминальный blocked_portal, остальные ответы по 80 — open_http
    или http_redirect. Возвращает (result, ips).
    """
    t0 = time.time()

    def ms():
        return round((time.time() - t0) * 1000)

    sni = args.sni if kind == "ip" else name

    if kind == "ip":
        ips = [name]
    else:
        rcode, raw = resolve_a(name, args.resolver, args.dns_timeout)
        if raw and all(any(x.startswith(p) for p in SINK_PREFIXES) or x in SINK_EXACT
                       for x in raw):
            return dict(status="blocked_dns", checked_ip="", ips=" ".join(raw),
                        reason="DNS sinkhole", ms=ms(), tries=1), []
        ips = [x for x in raw if not any(x.startswith(p) for p in SINK_PREFIXES)
               and x not in SINK_EXACT]
        if not ips and rcode in ("NOERROR", "NXDOMAIN"):
            return dict(status="no_dns", checked_ip="", ips="",
                        reason="NXDOMAIN" if rcode == "NXDOMAIN" else "no A records",
                        ms=ms(), tries=1), []
        if not ips:
            # DNS молчал или ответил ошибкой: про домен это ничего не говорит,
            # второй проход спросит заново
            return dict(status="dns_error", checked_ip="", ips="",
                        reason="DNS %s" % (rcode or "timeout"), ms=ms(), tries=1), []
        if args.max_ips > 0:
            ips = ips[: args.max_ips]

    allowed, _, last = tls_round(name, ips, args,
                                 stop_on_allow=not args.all_ips, sni=sni)
    if allowed:
        if args.all_ips and len(ips) > 1:
            return dict(status="allow", checked_ip=allowed[0][0],
                        allowed=" ".join(x[0] for x in allowed),
                        ips=" ".join(ips), reason="", ms=ms(), tries=1), ips
        ip, st, err = allowed[0]
        return dict(status=st, checked_ip=ip, ips=" ".join(ips), reason=err,
                    ms=ms(), tries=1), ips

    result = dict(status=last[0], checked_ip=last[1], ips=" ".join(ips),
                  reason=last[2], tries=1)
    if args.http80:
        for ip in ips:
            code, loc, _, _ = http_probe(ip, name, args.timeout, args.portal_host)
            if args.portal_host and args.portal_host in loc:
                result.update(status="blocked_portal", checked_ip=ip,
                              reason="HTTP %s -> %s" % (code, loc))
                break
            if code and code not in ("000",):
                if is_https_redirect(code, loc):
                    result.update(status="http_redirect", checked_ip=ip,
                                  reason="HTTP %s -> %s" % (code, loc))
                else:
                    result.update(status="open_http", checked_ip=ip,
                                  reason="HTTP %s %s" % (code, loc))
                break
    result["ms"] = ms()
    return result, ips


def diagnose(name, kind, prev, ips, args):
    """Проход 2: медленные повторы TLS для тех, кто не прошёл первый.

    Портал и заглушки DNS уже отсеяны в первом проходе, здесь остаются только
    неоднозначные отказы (no_dns и dns_error main проверяет заново через
    probe_tls_only, а не здесь). На мобильном канале первый отказ часто оказывается
    потерей пакета, поэтому таймаут утраивается. Если TLS прошёл — статус
    становится allow, иначе остаётся то, что дал первый проход.
    """
    t0 = time.time()
    sni = args.sni if kind == "ip" else name

    def ms():
        return round((time.time() - t0) * 1000)

    for _ in range(max(0, args.retries)):
        allowed, _, _ = tls_round(name, ips, args, stop_on_allow=not args.all_ips,
                                  timeout=args.timeout * 3, sni=sni)
        if allowed:
            if args.all_ips and len(ips) > 1:
                return dict(status="allow", checked_ip=allowed[0][0],
                            allowed=" ".join(x[0] for x in allowed),
                            ips=" ".join(ips), reason="", ms=ms())
            ip, st, err = allowed[0]
            return dict(status=st, checked_ip=ip, ips=" ".join(ips), reason=err, ms=ms())

    return dict(status=prev["status"], checked_ip=prev["checked_ip"],
                ips=prev["ips"], reason=prev["reason"], ms=ms())


def expand_targets(lines, kind, max_cidr):
    """Строка входа: «значение» или «источник<TAB>значение».

    Источник — имя файла или категория, попадает в результат отдельной колонкой.
    """
    out = []
    seen = set()
    for raw in lines:
        s = raw.rstrip("\n")
        source = ""
        if "\t" in s:
            source, s = s.split("\t", 1)
            source = source.strip()
        s = s.strip()
        if not s or s.startswith("#"):
            continue
        if "/" in s and CIDR_RE.match(s):
            try:
                net = ipaddress.ip_network(s, strict=False)
            except ValueError:
                continue
            hosts = list(net.hosts()) if net.num_addresses > 2 else [net.network_address]
            if len(hosts) > max_cidr:
                print("пропуск %s: больше %d адресов" % (s, max_cidr), file=sys.stderr)
                continue
            for h in hosts:
                key = (str(h), "ip")
                if key in seen:
                    continue
                seen.add(key)
                out.append((str(h), "ip", source))
            continue
        if is_ipv4(s):
            key = (s, "ip")
            if key in seen:
                continue
            seen.add(key)
            out.append((s, "ip", source))
            continue
        if kind == "ips":
            continue
        d = norm_domain(s)
        if d and "." in d:
            key = (d, "domain")
            if key in seen:
                continue
            seen.add(key)
            out.append((d, "domain", source))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--kind", choices=["auto", "domains", "ips"], default="auto")
    ap.add_argument("--resolver", default="192.168.8.1")
    ap.add_argument("--sni", default="gosuslugi.ru")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--dns-timeout", type=float, default=3.0)
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--delay", type=float, default=0.3,
                    help="пауза между целями, секунды (0 — без паузы)")
    ap.add_argument("--max-ips", type=int, default=0,
                    help="сколько адресов домена проверять, 0 — все")
    ap.add_argument("--retries", type=int, default=2,
                    help="медленных повторов TLS во втором проходе (0 — без второго прохода)")
    ap.add_argument("--second-pass", dest="second_pass", action="store_true", default=True,
                    help="второй проход для неоднозначных отказов (по умолчанию)")
    ap.add_argument("--no-second-pass", dest="second_pass", action="store_false",
                    help="только первый проход, без медленных повторов TLS")
    ap.add_argument("--all-ips", dest="all_ips", action="store_true", default=True,
                    help="проверять все A-записи (по умолчанию)")
    ap.add_argument("--first-ip", dest="all_ips", action="store_false",
                    help="остановиться на первом рабочем адресе")
    ap.add_argument("--max-cidr", type=int, default=1024)
    ap.add_argument("--http80", dest="http80", action="store_true", default=True)
    ap.add_argument("--no-http80", dest="http80", action="store_false")
    ap.add_argument("--portal-host", default="access.rt.ru")
    ap.add_argument("--out", default="")
    ap.add_argument("--dry-run", dest="dry_run", action="store_true")
    args = ap.parse_args()

    targets = expand_targets(open(args.input, encoding="utf-8").read().splitlines(),
                             args.kind, args.max_cidr)
    if not targets:
        print("нет целей для проверки", file=sys.stderr)
        return 2

    if args.dry_run:
        text = "".join("%s\t%s\t%s\n" % (source, kind, name)
                       for name, kind, source in targets)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(text)
        else:
            sys.stdout.write(text)
        print("итого целей: %d (из них доменов %d, ip %d)" % (
            len(targets),
            sum(1 for _, k, _ in targets if k == "domain"),
            sum(1 for _, k, _ in targets if k == "ip")), file=sys.stderr)
        return 0

    state = []        # (item, result, ips) — порядок исходного списка
    interrupted = False

    def pause():
        # небольшая неровная пауза: ровный ритм выглядит как бот
        if args.delay > 0:
            time.sleep(random.uniform(args.delay * 0.5, args.delay * 1.5))

    def finalize(item, r):
        name, kind, source = item
        r["input"] = name
        r["kind"] = kind
        r["source"] = source
        if not r.get("allowed"):
            r["allowed"] = (r["checked_ip"]
                            if r["status"] in ("allow", "allow_tls") else "")
        if r["status"] not in ("allow", "allow_tls") and r.get("tries", 1) > 1:
            note = "попыток: %d" % r["tries"]
            r["reason"] = ("%s; %s" % (r["reason"], note)) if r["reason"] else note
        return r

    # Проход 1: DNS и TLS по всему списку, без HTTP:80.
    if args.jobs > 1:
        ex = ThreadPoolExecutor(max_workers=args.jobs)
        try:
            def first_paced(item):
                r, ips = probe_tls_only(item[0], item[1], args)
                pause()
                return r, ips
            it = ex.map(first_paced, targets)
            for i, (r, ips) in enumerate(it, 1):
                item = targets[i - 1]
                state.append((item, r, ips))
                print("[1/2] [%d/%d] %s -> %s" % (i, len(targets), item[0], r["status"]),
                      file=sys.stderr, flush=True)
        except KeyboardInterrupt:
            interrupted = True
            print("\nпрервано (Ctrl+C)", file=sys.stderr, flush=True)
            ex.shutdown(wait=False, cancel_futures=True)
        else:
            ex.shutdown(wait=True)
    else:
        try:
            for i, item in enumerate(targets, 1):
                r, ips = probe_tls_only(item[0], item[1], args)
                state.append((item, r, ips))
                print("[1/2] [%d/%d] %s -> %s" % (i, len(targets), item[0], r["status"]),
                      file=sys.stderr, flush=True)
                if i < len(targets):
                    pause()
        except KeyboardInterrupt:
            interrupted = True
            print("\nпрервано (Ctrl+C)", file=sys.stderr, flush=True)

    # Проход 2: только медленные повторы TLS для неоднозначных отказов.
    if not interrupted and args.second_pass and args.retries > 0:
        need = [k for k, (_, r, _) in enumerate(state) if r["status"] not in TERMINAL]
        if need:
            print("== второй проход: %d из %d" % (len(need), len(state)),
                  file=sys.stderr, flush=True)
        try:
            for j, k in enumerate(need, 1):
                item, prev, ips = state[k]
                if prev["status"] in DNS_RECHECK:
                    # адресов нет — повторять TLS не с чем, проверяем заново с DNS
                    r, ips = probe_tls_only(item[0], item[1], args)
                else:
                    r = diagnose(item[0], item[1], prev, ips, args)
                r["ms"] += prev["ms"]
                r["tries"] = 2
                state[k] = (item, r, ips)
                print("[2/2] [%d/%d] %s -> %s" % (j, len(need), item[0], r["status"]),
                      file=sys.stderr, flush=True)
                if j < len(need):
                    pause()
        except KeyboardInterrupt:
            interrupted = True
            print("\nпрервано (Ctrl+C)", file=sys.stderr, flush=True)

    results = [finalize(item, r) for item, r, _ in state]

    header = "input\tkind\tstatus\tchecked_ip\tall_ips\treason\tms\tsource\tallowed_ips\n"
    body = "".join(
        "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n" % (
            r["input"], r["kind"], r["status"], r["checked_ip"],
            r["ips"], r["reason"].replace("\t", " ").replace("\n", " "), r["ms"],
            r["source"].replace("\t", " "), r["allowed"].replace("\t", " "))
        for r in results
    )
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(header + body)
    else:
        sys.stdout.write(header + body)

    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print("\nитого: %d%s" % (len(results),
                            " (прервано, проверено не всё)" if interrupted else ""),
          file=sys.stderr)
    for s in STATUS_ORDER:
        if counts.get(s):
            print("  %-15s %d" % (s, counts[s]), file=sys.stderr)
    if interrupted:
        print("сохранено: %d из %d целей" % (len(results), len(targets)), file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    # дальше Ctrl+C обрабатывается как KeyboardInterrupt: он нужен, чтобы
    # сохранить уже проверенное
    signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nпрервано (Ctrl+C)", file=sys.stderr)
        sys.exit(130)
