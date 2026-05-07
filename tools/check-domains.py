#!/usr/bin/env python3
"""
Browser Mode: имитация работы браузера
 - DNS
 - HTTP/3 (QUIC) → HTTP/2 → HTTP/1.1
 - без HTTP (порт 80)
 - Chrome-подобные заголовки
 - cookie-jar
 - retry-логика
 - цветной вывод
"""

import asyncio
import aiohttp
import httpx
import sys
import os
import time
import socket
import argparse
import logging
import ssl
from datetime import datetime
from typing import List, Tuple, Dict, Set
from pathlib import Path

try:
    from aioquic.asyncio.client import connect as quic_connect
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import HeadersReceived, DataReceived
    from aioquic.quic.configuration import QuicConfiguration
    HAVE_QUIC = True
except ImportError:
    HAVE_QUIC = False

logging.getLogger("aiohttp").setLevel(logging.CRITICAL)
logging.getLogger("asyncio").setLevel(logging.CRITICAL)
logging.getLogger("aiodns").setLevel(logging.CRITICAL)
logging.getLogger("httpx").setLevel(logging.CRITICAL)
logging.getLogger("httpcore").setLevel(logging.CRITICAL)

C = {
    "reset": "\033[0m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "gray": "\033[90m",
    "bold": "\033[1m",
}

STATUS_COLOR = {
    "OK": C["green"],
    "HTTP_ERR": C["yellow"],
    "SSL_ERR": C["red"],
    "RST": C["red"],
    "DNS_ERR": C["blue"],
    "TIMEOUT": C["magenta"],
    "UNKNOWN": C["gray"],
    "UNREACH": C["gray"],
    "QUIC_ERR": C["magenta"],
}

CONFIG = {
    "timeout_connect": 40,
    "timeout_total": 60,
    "timeout_dns": 20,
    "concurrency": 10,
    "retries": 2,
    "headers": {
        "User-Agent": "Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "Sec-Ch-Ua-Mobile": "?1",
        "Sec-Ch-Ua-Platform": '"Android"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Connection": "keep-alive",
    },
}

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = True
SSL_CTX.verify_mode = ssl.CERT_REQUIRED

ICONS = {
    "OK": "✅",
    "TIMEOUT": "🕐",
    "SSL_ERR": "🔐",
    "HTTP_ERR": "⚠️",
    "DNS_ERR": "🌐",
    "UNKNOWN": "❓",
    "UNREACH": "🚫",
    "QUIC_ERR": "📡",
}

DEFAULT_EXCLUDES = {"category-ru"}

OPERATORS = {
    "1": "Megafon",
    "2": "Beeline",
    "3": "MTS",
    "4": "Tele2",
    "5": "Yota",
    "6": "RT",
}

async def dns_resolve(domain: str) -> Tuple[bool, List[str]]:
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(domain, 443, type=socket.SOCK_STREAM),
            timeout=CONFIG["timeout_dns"]
        )
        ips = sorted({info[4][0] for info in infos})
        return True, ips
    except Exception:
        return False, []


def classify_error(error: Exception) -> Tuple[str, str]:
    err_str = str(error).lower()
    err_repr = repr(error).lower()

    if isinstance(error, socket.gaierror):
        return "DNS_ERR", "Domain not resolved"
    if "no address" in err_str or "name or service not known" in err_str:
        return "DNS_ERR", "Domain not resolved"
    if isinstance(error, OSError) and "timeout" in err_str:
        return "DNS_ERR", "DNS timeout"

    if isinstance(error, aiohttp.ClientResponseError):
        return "HTTP_ERR", f"Response error {error.status}"

    if ("connection reset" in err_str or "recv failure" in err_str or "errno 104" in err_str):
        return "RST", "Connection reset by peer"

    if isinstance(error, asyncio.TimeoutError) or "timeout" in err_str or "errno 110" in err_str:
        return "TIMEOUT", "Connection timed out"

    if "refused" in err_str or "errno 111" in err_str:
        return "UNREACH", "Connection refused"

    if "ssl" in err_str or "certificate" in err_str or "handshake" in err_str:
        return "SSL_ERR", "SSL handshake failed"

    if "unreachable" in err_str or "no route" in err_str:
        return "UNREACH", "Host unreachable"

    if "http2" in err_str and "protocol" in err_str:
        return "HTTP_ERR", "HTTP/2 protocol error"

    if "unexpected eof" in err_str:
        return "RST", "Unexpected EOF (server closed connection)"

    return "UNKNOWN", f"{type(error).__name__}: {str(error)}"


def extract_domain(line: str) -> str:
    line = line.strip()
    if not line or line.startswith('#'):
        return ""
    domain = line.replace('https://', '').replace('http://', '')
    return domain.split('/')[0].split('?')[0].split('#')[0].strip()


def get_files_to_process(directory: str, excludes: Set[str]) -> List[Path]:
    dir_path = Path(directory)
    if not dir_path.is_dir():
        print(f"❌ Директория '{directory}' не найдена")
        sys.exit(1)
    return sorted([f for f in dir_path.iterdir() if f.is_file() and f.stem not in excludes])


def load_domains_from_files(files: List[Path]) -> List[str]:
    domains = []
    seen = set()
    for filepath in files:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                domain = extract_domain(line)
                if domain and domain not in seen:
                    seen.add(domain)
                    domains.append(domain)
    return domains


def print_result_line(res: dict, index: int, total: int):
    icon = ICONS.get(res["status"], "❓")
    color = STATUS_COLOR.get(res["status"], C["reset"])
    print(
        f"{color}[{index}/{total}] "
        f"{icon} {res['domain']:<45} "
        f"{res['status']:<10} {res['method']:<6} {res['details']}{C['reset']}"
    )

async def check_with_quic(domain: str, ip: str | None, timeout: float) -> dict:
    res = {
        "domain": domain,
        "status": "",
        "code": 0,
        "method": "H3",
        "rtt_ms": 0,
        "details": "",
        "client": "quic",
    }

    if not HAVE_QUIC:
        res["status"] = "QUIC_ERR"
        res["details"] = "aioquic not installed"
        return res

    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
    )

    host = ip or domain
    start = time.time()

    try:
        async with quic_connect(
            host,
            443,
            configuration=configuration,
            server_name=domain,
            wait_connected=True,
        ) as client:
            h3 = H3Connection(client._quic)
            stream_id = client._quic.get_next_available_stream_id()
            headers = [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", domain.encode()),
                (b":path", b"/"),
            ]
            for k, v in CONFIG["headers"].items():
                headers.append((k.encode().lower(), v.encode()))

            h3.send_headers(stream_id, headers, end_stream=True)
            client.transmit()

            body = b""
            while True:
                event = await client.wait_for_event()
                if isinstance(event, HeadersReceived):
                    status_header = next(
                        (v for k, v in event.headers if k == b":status"),
                        b""
                    )
                    try:
                        res["code"] = int(status_header)
                    except ValueError:
                        res["code"] = 0
                elif isinstance(event, DataReceived):
                    body += event.data
                    if len(body) >= 2048:
                        break
                if client._quic._close_pending or client._quic._closed:
                    break

            res["rtt_ms"] = round((time.time() - start) * 1000, 1)
            if 200 <= res["code"] < 400:
                res["status"] = "OK"
                res["details"] = f"HTTP/3 {res['code']}"
            else:
                res["status"] = "HTTP_ERR"
                res["details"] = f"H3 status {res['code'] or 0}"

    except Exception as e:
        res["rtt_ms"] = round((time.time() - start) * 1000, 1)
        status, details = classify_error(e)
        res["status"] = "QUIC_ERR" if status == "UNKNOWN" else status
        res["details"] = f"QUIC: {details}"

    return res

async def check_with_aiohttp_h2(session: aiohttp.ClientSession, domain: str,
                                timeout: aiohttp.ClientTimeout) -> dict:
    res = {
        "domain": domain,
        "status": "",
        "code": 0,
        "method": "H2",
        "rtt_ms": 0,
        "details": "",
        "client": "aiohttp",
    }

    url = f"https://{domain}"
    start = time.time()

    try:
        async with session.get(
            url,
            allow_redirects=True,
            ssl=SSL_CTX,
            timeout=timeout,
            headers=CONFIG["headers"]
        ) as resp:
            await resp.content.read(2048)
            res["rtt_ms"] = round((time.time() - start) * 1000, 1)
            res["code"] = resp.status
            if 200 <= resp.status < 400:
                res["status"] = "OK"
                res["details"] = resp.reason or "OK"
            else:
                res["status"] = "HTTP_ERR"
                res["details"] = f"{resp.status} {resp.reason}"
    except Exception as e:
        res["rtt_ms"] = round((time.time() - start) * 1000, 1)
        res["status"], res["details"] = classify_error(e)

    return res


async def check_with_httpx_h11(domain: str, timeout: float, cookies: dict | None) -> dict:
    res = {
        "domain": domain,
        "status": "",
        "code": 0,
        "method": "H1.1",
        "rtt_ms": 0,
        "details": "",
        "client": "httpx",
    }

    url = f"https://{domain}"
    start = time.time()

    try:
        async with httpx.AsyncClient(
            http2=False,
            verify=True,
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            headers=CONFIG["headers"],
            cookies=cookies or {},
        ) as client:
            resp = await client.get(url)
            _ = resp.content[:2048]
            res["rtt_ms"] = round((time.time() - start) * 1000, 1)
            res["code"] = resp.status_code
            if 200 <= resp.status_code < 400:
                res["status"] = "OK"
                res["details"] = resp.reason_phrase or "OK"
            else:
                res["status"] = "HTTP_ERR"
                res["details"] = f"{resp.status_code} {resp.reason_phrase}"
    except Exception as e:
        res["rtt_ms"] = round((time.time() - start) * 1000, 1)
        res["status"], res["details"] = classify_error(e)

    return res


async def browser_check_domain(domain: str,
                               ips: List[str],
                               aiohttp_session: aiohttp.ClientSession,
                               aiohttp_timeout: aiohttp.ClientTimeout,
                               sem: asyncio.Semaphore) -> dict:
    async with sem:
        # 1) QUIC (HTTP/3)
        if HAVE_QUIC:
            for attempt in range(CONFIG["retries"] + 1):
                ip = ips[attempt % len(ips)] if ips else None
                quic_res = await check_with_quic(domain, ip, CONFIG["timeout_total"])
                if quic_res["status"] == "OK":
                    return quic_res

        # 2) HTTPS HTTP/2 (aiohttp)
        for attempt in range(CONFIG["retries"] + 1):
            h2_res = await check_with_aiohttp_h2(aiohttp_session, domain, aiohttp_timeout)
            if h2_res["status"] == "OK":
                return h2_res
            if h2_res["status"] in ("TIMEOUT", "RST", "SSL_ERR", "HTTP_ERR"):
                continue
            break

        # 3) HTTPS HTTP/1.1 (httpx)
        jar_cookies = {}
        for cookie in aiohttp_session.cookie_jar:
            jar_cookies[cookie.key] = cookie.value

        for attempt in range(CONFIG["retries"] + 1):
            h11_res = await check_with_httpx_h11(domain, CONFIG["timeout_total"], jar_cookies)
            if h11_res["status"] == "OK":
                return h11_res
            if h11_res["status"] in ("TIMEOUT", "RST", "SSL_ERR", "HTTP_ERR"):
                continue
            break

        return h11_res if 'h11_res' in locals() else h2_res

async def run_checker(domains: List[str],
                      connector: aiohttp.TCPConnector,
                      verbose: bool = True) -> Dict[str, dict]:
    results: Dict[str, dict] = {}

    print(f"{C['bold']}🔍 Этап 1/2: DNS‑резолв ({len(domains)} доменов)...{C['reset']}")

    dns_sem = asyncio.Semaphore(CONFIG["concurrency"] * 2)

    async def resolve_task(domain: str):
        async with dns_sem:
            ok, ips = await dns_resolve(domain)
            return domain, ok, ips

    dns_results: Dict[str, Tuple[bool, List[str]]] = {}
    completed = 0

    for coro in asyncio.as_completed([resolve_task(d) for d in domains]):
        domain, resolved, ips = await coro
        dns_results[domain] = (resolved, ips)
        completed += 1
        if verbose and completed % 50 == 0:
            print(f"  → DNS: {completed}/{len(domains)}")

    dns_ok = sum(1 for v in dns_results.values() if v[0])
    print(f"  {C['green']}✅ Резолвятся: {dns_ok}{C['reset']} | "
          f"{C['red']}❌ Не резолвятся: {len(domains) - dns_ok}{C['reset']}")

    for domain, (resolved, _) in dns_results.items():
        if not resolved:
            results[domain] = {
                "domain": domain,
                "status": "DNS_ERR",
                "code": 0,
                "method": "-",
                "rtt_ms": 0,
                "details": "Domain not resolved",
                "client": "-",
            }

    http_domains = [d for d, (ok, _) in dns_results.items() if ok]

    if http_domains:
        print(f"\n{C['bold']}🔍 Этап 2/2: Browser Mode HTTP/3 → H2 → H1.1 ({len(http_domains)} доменов)...{C['reset']}")
        print(f"   🌐 Режим: имитация браузера (без HTTP fallback)")

        aiohttp_timeout = aiohttp.ClientTimeout(
            connect=CONFIG["timeout_connect"],
            total=CONFIG["timeout_total"]
        )

        async with aiohttp.ClientSession(
            connector=connector,
            cookie_jar=aiohttp.CookieJar()
        ) as aiohttp_session:

            http_sem = asyncio.Semaphore(CONFIG["concurrency"])

            tasks = [
                browser_check_domain(
                    d,
                    dns_results[d][1],
                    aiohttp_session,
                    aiohttp_timeout,
                    http_sem
                )
                for d in http_domains
            ]

            completed = 0
            start_time = time.time()

            for coro in asyncio.as_completed(tasks):
                res = await coro
                results[res["domain"]] = res
                completed += 1

                if verbose:
                    print_result_line(res, completed, len(http_domains))

                if completed % 100 == 0:
                    elapsed = time.time() - start_time
                    speed = completed / elapsed if elapsed > 0 else 0
                    print(f"  → HTTP: {completed}/{len(http_domains)} ({speed:.1f} доменов/сек)")

    return results

def save_whitelist(successful_domains: List[str], operator_name: str,
                   output_dir: str = "../build/domains_checked"):
    timestamp = datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
    filename = f"whitelist-{timestamp}-{operator_name}.txt"
    output_file = os.path.join(output_dir, filename)

    print(f"{C['cyan']}💾 Сохранение успешных доменов в {output_file}...{C['reset']}")
    os.makedirs(output_dir, exist_ok=True)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(successful_domains) + '\n')

    print(f"{C['green']}  ✅ Whitelist сохранён{C['reset']}")


def select_operator() -> str:
    print(f"\n{C['bold']}📱 Выберите мобильного оператора:{C['reset']}")
    for key, value in OPERATORS.items():
        print(f"  {key}. {value}")

    while True:
        choice = input("Введите номер оператора (1-6): ").strip()
        if choice in OPERATORS:
            return OPERATORS[choice]
        print(f"{C['red']}❌ Неверный выбор. Пожалуйста, введите число от 1 до 6.{C['reset']}")


async def main():
    parser = argparse.ArgumentParser(description='Browser Mode: проверка доменов как браузер')
    parser.add_argument('directory', nargs='?', default='../src/domains', help='Директория со списками')
    parser.add_argument('-c', '--concurrency', type=int, default=CONFIG["concurrency"], help='Параллельных запросов')
    parser.add_argument('-q', '--quiet', action='store_true', help='Тихий режим')
    parser.add_argument('-e', '--exclude', nargs='+', default=[], help='Исключения')
    parser.add_argument('--dns', nargs='+', default=None, help='Кастомные DNS-серверы')
    args = parser.parse_args()

    CONFIG["concurrency"] = args.concurrency

    use_custom_dns = bool(args.dns)
    directory = args.directory
    excludes = DEFAULT_EXCLUDES.union(set(args.exclude))

    print(f"{C['bold']}⚙️  Конфигурация (Browser Mode):{C['reset']}")
    print(f"   timeout_connect: {CONFIG['timeout_connect']}s")
    print(f"   timeout_total:   {CONFIG['timeout_total']}s")
    print(f"   timeout_dns:     {CONFIG['timeout_dns']}s")
    print(f"   concurrency:     {CONFIG['concurrency']}")
    print(f"   retries:         {CONFIG['retries']}")
    print(f"   dns:             {'Кастомный (' + ', '.join(args.dns) + ')' if use_custom_dns else 'SYSTEM ✅'}")
    print(f"   quic:            {'ON' if HAVE_QUIC else 'OFF (aioquic not installed)'}")
    print("-" * 85)
    print(f"📂 Директория: {directory}")
    print(f"🚫 Исключения: {', '.join(excludes)}")
    print("-" * 85)

    files = get_files_to_process(directory, excludes)
    if not files:
        print(f"{C['red']}❌ Нет файлов для обработки{C['reset']}")
        sys.exit(1)

    print(f"📁 Файлов для проверки: {len(files)}")
    for f in files:
        print(f"   - {f.name}")
    print("-" * 85)

    domains = load_domains_from_files(files)
    print(f"📋 Доменов: {len(domains)} | 🚀 Потоков: {CONFIG['concurrency']}")
    print("-" * 85)

    try:
        if use_custom_dns:
            resolver = aiohttp.AsyncResolver(nameservers=args.dns)
            connector = aiohttp.TCPConnector(
                limit=CONFIG["concurrency"],
                ttl_dns_cache=300,
                use_dns_cache=True,
                resolver=resolver,
                enable_cleanup_closed=True
            )
            print(f"{C['cyan']}🌐 DNS: Кастомный ({', '.join(args.dns)}){C['reset']}")
        else:
            connector = aiohttp.TCPConnector(
                limit=CONFIG["concurrency"],
                ttl_dns_cache=300,
                use_dns_cache=True,
                enable_cleanup_closed=True
            )
            print(f"{C['cyan']}🌐 DNS: Системный резолвер (/etc/resolv.conf){C['reset']}")
    except Exception as e:
        print(f"{C['red']}❌ Ошибка создания connector: {e}{C['reset']}")
        sys.exit(1)

    try:
        start = time.time()
        results = await run_checker(domains, connector, verbose=not args.quiet)
        elapsed = time.time() - start

        print("-" * 85)
        print(f"{C['green']}✅ Готово за {elapsed:.1f} сек. "
              f"({len(domains) / max(elapsed, 0.1):.1f} доменов/сек){C['reset']}")

        successful_domains = [d for d, r in results.items() if r['status'] == 'OK']
        print(f"📋 Успешных доменов: {len(successful_domains)}")

        if successful_domains:
            operator = select_operator()
            print(f"{C['green']}✅ Выбран оператор: {operator}{C['reset']}")
            save_whitelist(successful_domains, operator)
        else:
            print(f"{C['yellow']}⚠️ Нет успешных доменов для сохранения{C['reset']}")

        print(f"\n{C['bold']}📊 Общая статистика:{C['reset']}")
        status_counts = {}
        for r in results.values():
            status_counts[r['status']] = status_counts.get(r['status'], 0) + 1

        for status, count in sorted(status_counts.items(), key=lambda x: -x[1]):
            color = STATUS_COLOR.get(status, C["reset"])
            print(f"  {color}{ICONS.get(status, '❓')} {status}: {count}{C['reset']}")

    except KeyboardInterrupt:
        print(f"\n{C['yellow']}⚠️  Прервано пользователем (Ctrl+C){C['reset']}")
    finally:
        await connector.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{C['yellow']}👋 Завершение работы...{C['reset']}")
        sys.exit(0)
