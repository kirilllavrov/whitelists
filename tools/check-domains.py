#!/usr/bin/env python3
"""
Проверка доменов на доступность при обходе блокировок.
Скрипт проверяет домены через HTTPS с эмуляцией браузера на Android.
При ошибках протокола использует fallback на httpx с HTTP/1.1.
Зависимости: pip install aiohttp httpx aiodns
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
from datetime import datetime
from typing import List, Tuple, Dict, Set
from pathlib import Path
import aiodns

# ✅ Полная тишина в логах
for logger in ('aiohttp', 'asyncio', 'aiodns', 'httpx', 'httpcore'):
    logging.getLogger(logger).setLevel(logging.CRITICAL)

# === КОНФИГУРАЦИЯ ===
CONFIG = {
    "timeout_connect": 60,
    "timeout_total": 90,
    "timeout_dns": 20,
    "concurrency": 5,
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

ICONS = {
    "OK": "✅", "RST": "❌", "TIMEOUT": "🕐",
    "SSL_ERR": "🔐", "HTTP_ERR": "⚠️", "DNS_ERR": "🌐", "UNKNOWN": "❓", "UNREACH": "🚫"
}
# ✅ Статусы для fallback (убран HTTP_ERR — 4xx/5xx не требуют повторного запроса)
FALLBACK_STATUSES = {"UNKNOWN", "TIMEOUT"}
FALLBACK_KEYWORDS = ["protocol_error", "stream was not closed", "server disconnected", "remote protocol error"]
DEFAULT_EXCLUDES = {"category-ru"}
OPERATORS = {
    "1": "Megafon", "2": "Beeline", "3": "MTS", "4": "Tele2", "5": "Yota", "6": "RT"
}

def classify_error(error: Exception) -> Tuple[str, str]:
    """Классифицирует ошибку по типу исключения (надёжнее парсинга str)."""
    err_str = str(error).lower()
    
    if isinstance(error, aiohttp.ClientResponseError):
        return "HTTP_ERR", f"Response error {error.status}"
    if isinstance(error, socket.gaierror):
        return "DNS_ERR", "Domain not resolved"
    if isinstance(error, OSError):
        if "timeout" in err_str or "timed out" in err_str:
            return "TIMEOUT", "Connection timed out"
        if "refused" in err_str:
            return "RST", "Connection refused"
        if "reset" in err_str:
            return "RST", "Connection reset by peer"
        if "unreachable" in err_str or "no route" in err_str:
            return "UNREACH", "Host unreachable"
        return "UNKNOWN", f"OSError: {error}"
    if isinstance(error, (aiohttp.ClientConnectorError, aiohttp.ServerDisconnectedError)):
        if "ssl" in err_str or "certificate" in err_str or "handshake" in err_str:
            return "SSL_ERR", "SSL handshake failed"
        return "TIMEOUT", "Connection failed"
    if isinstance(error, asyncio.TimeoutError):
        return "TIMEOUT", "Connection timed out"
    return "UNKNOWN", f"{type(error).__name__}: {error}"

def should_fallback(status: str, details: str) -> bool:
    if status not in FALLBACK_STATUSES:
        return False
    return any(kw in details.lower() for kw in FALLBACK_KEYWORDS)

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

async def check_dns_async(domain: str, resolver: aiodns.DNSResolver) -> bool:
    """Проверка DNS через aiodns (использует query_dns вместо устаревшего query)."""
    try:
        await asyncio.wait_for(resolver.query_dns(domain, 'A'), timeout=CONFIG["timeout_dns"])
        return True
    except Exception:
        try:
            await asyncio.wait_for(resolver.query_dns(domain, 'AAAA'), timeout=CONFIG["timeout_dns"])
            return True
        except Exception:
            return False

async def check_with_aiohttp(session: aiohttp.ClientSession, domain: str, timeout: aiohttp.ClientTimeout, verify_ssl: bool) -> dict:
    res = {"domain": domain, "status": "", "code": 0, "method": "GET", "rtt_ms": 0, "details": "", "client": "aiohttp"}
    url = f"https://{domain}"
    start = time.time()
    try:
        async with session.get(url, allow_redirects=True, ssl=not verify_ssl, timeout=timeout, headers=CONFIG["headers"]) as resp:
            res["rtt_ms"] = round((time.time() - start) * 1000, 1)
            res["code"] = resp.status
            res["status"] = "OK" if 200 <= resp.status < 400 else "HTTP_ERR"
            res["details"] = f"{resp.status} {resp.reason}" if resp.status >= 400 else (resp.reason or "OK")
    except Exception as e:
        res["status"], res["details"] = classify_error(e)
    return res

async def check_with_httpx(domain: str, timeout: float, verify_ssl: bool) -> dict:
    res = {"domain": domain, "status": "", "code": 0, "method": "GET", "rtt_ms": 0, "details": "", "client": "httpx/http1.1"}
    url = f"https://{domain}"
    start = time.time()
    try:
        async with httpx.AsyncClient(http2=False, verify=verify_ssl, timeout=httpx.Timeout(timeout), follow_redirects=True, headers=CONFIG["headers"]) as client:
            resp = await client.get(url)
            res["rtt_ms"] = round((time.time() - start) * 1000, 1)
            res["code"] = resp.status_code
            res["status"] = "OK" if 200 <= resp.status_code < 400 else "HTTP_ERR"
            res["details"] = f"{resp.status_code} {resp.reason_phrase}" if resp.status_code >= 400 else (resp.reason_phrase or "OK")
    except httpx.ConnectTimeout:
        res["status"], res["details"] = "TIMEOUT", "Connection timeout (httpx)"
    except httpx.ReadTimeout:
        res["status"], res["details"] = "TIMEOUT", "Read timeout (httpx)"
    except httpx.ConnectError as e:
        err_lower = str(e).lower()
        if "refused" in err_lower:
            res["status"], res["details"] = "RST", "Connection refused (httpx)"
        elif "ssl" in err_lower or "certificate" in err_lower:
            res["status"], res["details"] = "SSL_ERR", "SSL error (httpx)"
        else:
            res["status"], res["details"] = "UNKNOWN", f"Connect error: {e}"
    except httpx.RemoteProtocolError as e:
        res["status"], res["details"] = "HTTP_ERR", f"Protocol error: {e}"
    except httpx.HTTPStatusError as e:
        res["status"], res["details"] = "HTTP_ERR", f"HTTP {e.response.status_code}"
    except httpx.RequestError as e:
        res["status"], res["details"] = "UNKNOWN", f"{type(e).__name__}: {e}"
    except Exception as e:
        res["status"], res["details"] = "UNKNOWN", f"{type(e).__name__}: {e}"
    return res

async def check_domain(domain: str, session: aiohttp.ClientSession, timeout: aiohttp.ClientTimeout,
                       verify_ssl: bool, httpx_timeout: float, sem: asyncio.Semaphore) -> dict:
    async with sem:
        result = await check_with_aiohttp(session, domain, timeout, verify_ssl)
        if should_fallback(result["status"], result["details"]):
            fallback_result = await check_with_httpx(domain, httpx_timeout, verify_ssl)
            if fallback_result["status"] == "OK" and result["status"] != "OK":
                print(f"  🔁 Fallback: {domain} — {result['status']} → {fallback_result['status']} (httpx)")
            return fallback_result
        return result

async def run_checker(domains: List[str], verify_ssl: bool = False, custom_dns: List[str] = None, verbose: bool = True) -> Dict[str, dict]:
    results = {}
    
    print(f"🔍 Этап 1/2: DNS-резолв ({len(domains)} доменов)...")
    dns_sem = asyncio.Semaphore(CONFIG["concurrency"] * 2)
    dns_opts = {"nameservers": custom_dns} if custom_dns else {}
    resolver = aiodns.DNSResolver(**dns_opts)

    async def resolve_domain(d: str):
        async with dns_sem:
            return d, await check_dns_async(d, resolver)

    dns_tasks = [resolve_domain(d) for d in domains]
    dns_results = {}
    completed = 0
    for coro in asyncio.as_completed(dns_tasks):
        domain, resolved = await coro
        dns_results[domain] = resolved
        completed += 1
        if verbose and completed % 200 == 0:
            print(f"  → DNS: {completed}/{len(domains)}")

    dns_ok = sum(1 for v in dns_results.values() if v)
    print(f"  ✅ Резолвятся: {dns_ok} | ❌ Не резолвятся: {len(domains) - dns_ok}")

    for domain, resolved in dns_results.items():
        if not resolved:
            results[domain] = {"domain": domain, "status": "DNS_ERR", "code": 0, "method": "-", "rtt_ms": 0, "details": "Domain not resolved", "client": "-"}

    http_domains = [d for d, r in dns_results.items() if r]
    if not http_domains:
        return results

    print(f"\n🔍 Этап 2/2: HTTP-проверка ({len(http_domains)} доменов)...")
    print(f"   🌐 Browser GET + httpx fallback (Cookies + Keep-Alive)")

    aiohttp_timeout = aiohttp.ClientTimeout(connect=CONFIG["timeout_connect"], total=CONFIG["timeout_total"])
    connector = aiohttp.TCPConnector(limit=CONFIG["concurrency"], ttl_dns_cache=300, use_dns_cache=True, enable_cleanup_closed=True)
    
    async with aiohttp.ClientSession(connector=connector, cookie_jar=aiohttp.CookieJar()) as aiohttp_session:
        http_sem = asyncio.Semaphore(CONFIG["concurrency"])
        tasks = [check_domain(d, aiohttp_session, aiohttp_timeout, verify_ssl, CONFIG["timeout_total"], http_sem) for d in http_domains]
        completed = 0
        start_time = time.time()
        for coro in asyncio.as_completed(tasks):
            res = await coro
            results[res['domain']] = res
            completed += 1
            if verbose:
                icon = ICONS.get(res['status'], "❓")
                print(f"[{completed}/{len(http_domains)}] {icon} {res['domain']:<45} {res['status']:<10} {res['method']:<4} {res['details']}")
            if completed % 100 == 0:
                elapsed = time.time() - start_time
                speed = completed / elapsed if elapsed > 0 else 0
                print(f"  → HTTP: {completed}/{len(http_domains)} ({speed:.1f} доменов/сек)")
    return results

def save_whitelist(successful_domains: List[str], operator_name: str, output_dir: str = "../build/domains_checked"):
    timestamp = datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
    filename = f"whitelist-{timestamp}-{operator_name}.txt"
    output_file = os.path.join(output_dir, filename)
    print(f"💾 Сохранение успешных доменов в {output_file}...")
    os.makedirs(output_dir, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(successful_domains) + '\n')
    print("  ✅ Whitelist сохранен")

def select_operator() -> str:
    print("\n📱 Выберите мобильного оператора, с помощью которого проводилась проверка доменов:")
    for key, value in OPERATORS.items():
        print(f"  {key}. {value}")
    while True:
        choice = input("Введите номер оператора (1-6): ").strip()
        if choice in OPERATORS:
            return OPERATORS[choice]
        print("❌ Неверный выбор. Пожалуйста, введите число от 1 до 6.")

async def main():
    parser = argparse.ArgumentParser(description='Проверка доменов на доступность при БС')
    parser.add_argument('directory', nargs='?', default='../src/domains', help='Директория со списками')
    parser.add_argument('-c', '--concurrency', type=int, default=CONFIG["concurrency"], help='Параллельных запросов')
    parser.add_argument('-q', '--quiet', action='store_true', help='Тихий режим')
    parser.add_argument('-e', '--exclude', nargs='+', default=[], help='Исключения')
    parser.add_argument('--dns', nargs='+', default=None, help='Кастомные DNS-серверы')
    parser.add_argument('--verify-ssl', action='store_true', help='Включить проверку SSL сертификатов')
    args = parser.parse_args()
    
    CONFIG["concurrency"] = args.concurrency
    use_custom_dns = bool(args.dns)
    directory = args.directory
    excludes = DEFAULT_EXCLUDES.union(set(args.exclude))

    print("⚙️  Конфигурация:")
    print(f"   timeout_connect: {CONFIG['timeout_connect']}s")
    print(f"   timeout_total:   {CONFIG['timeout_total']}s")
    print(f"   timeout_dns:     {CONFIG['timeout_dns']}s")
    print(f"   concurrency:     {CONFIG['concurrency']}")
    print(f"   dns:             {'Кастомный (' + ', '.join(args.dns) + ')' if use_custom_dns else 'SYSTEM ✅'}")
    print(f"   verify_ssl:      {args.verify_ssl}")
    print(f"   mode:            Browser GET + httpx fallback")
    print("-" * 85)
    print(f"📂 Директория: {directory}")
    print(f"🚫 Исключения: {', '.join(excludes)}")
    print("-" * 85)

    files = get_files_to_process(directory, excludes)
    if not files:
        print("❌ Нет файлов для обработки")
        sys.exit(1)

    print(f"📁 Файлов для проверки: {len(files)}")
    for f in files: print(f"   - {f.name}")
    print("-" * 85)

    domains = load_domains_from_files(files)
    print(f"📋 Доменов: {len(domains)} | 🚀 Потоков: {CONFIG['concurrency']}")
    print("-" * 85)

    results = await run_checker(domains, verify_ssl=args.verify_ssl, custom_dns=args.dns, verbose=not args.quiet)
    return results

if __name__ == "__main__":
    try:
        results = asyncio.run(main())
        print("-" * 85)
        
        successful_domains = [d for d, r in results.items() if r['status'] == 'OK']
        print(f"✅ Проверка завершена. Успешных доменов: {len(successful_domains)}")
        
        if successful_domains:
            operator = select_operator()  # ✅ Синхронный вызов вне async-контекста
            print(f"✅ Выбран оператор: {operator}")
            save_whitelist(successful_domains, operator)
            
        print("\n📊 Общая статистика:")
        status_counts = {}
        for r in results.values():
            status_counts[r['status']] = status_counts.get(r['status'], 0) + 1
        for status, count in sorted(status_counts.items(), key=lambda x: -x[1]):
            print(f"  {ICONS.get(status, '❓')} {status}: {count}")
            
        http_err_count = status_counts.get("HTTP_ERR", 0)
        if http_err_count > 0:
            print(f"\n⚠️  HTTP_ERR ({http_err_count}) — сервер ответил, это НЕ блокировка")
            
    except KeyboardInterrupt:
        print("\n👋 Завершение работы...")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {e}")
        sys.exit(1)