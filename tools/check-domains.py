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

# ✅ Полная тишина в логах
logging.getLogger('aiohttp').setLevel(logging.CRITICAL)
logging.getLogger('asyncio').setLevel(logging.CRITICAL)
logging.getLogger('aiodns').setLevel(logging.CRITICAL)
logging.getLogger('httpx').setLevel(logging.CRITICAL)
logging.getLogger('httpcore').setLevel(logging.CRITICAL)

# === КОНФИГУРАЦИЯ ===
CONFIG = {
    "timeout_connect": 40,       # Таймаут подключения (сек)
    "timeout_total": 60,         # Общий таймаут запроса (сек)
    "timeout_dns": 10,           # Таймаут DNS-резолвинга (сек)
    "concurrency": 5,            # Количество параллельных запросов
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
    "SSL_ERR": "🔐", "HTTP_ERR": "⚠️", "DNS_ERR": "🌐", 
    "UNKNOWN": "❓", "DPI_BLOCK": "🔒", "UNREACH": "🚫"
}

# Статусы и ключевые слова для триггера fallback на httpx
FALLBACK_STATUSES = {"UNKNOWN", "TIMEOUT", "HTTP_ERR"}
FALLBACK_KEYWORDS = ["protocol_error", "stream was not closed", "server disconnected", "remote protocol error"]
DEFAULT_EXCLUDES = {"category-ru"}
OPERATORS = {
    "1": "Megafon", "2": "Beeline", "3": "MTS", "4": "Tele2", "5": "Yota", "6": "RT"
}

def classify_error(error: Exception) -> Tuple[str, str]:
    """Классифицирует ошибку и возвращает (статус, описание)."""
    err_str = str(error).lower()
    err_repr = repr(error).lower()
    
    if isinstance(error, aiohttp.ClientResponseError):
        return "HTTP_ERR", f"Response error {error.status}"
    if isinstance(error, socket.gaierror):
        return "DNS_ERR", "Domain not resolved"
    if isinstance(error, OSError) and "timeout" in err_str:
        return "DNS_ERR", "DNS timeout"
    if "no address" in err_str or "name or service not known" in err_str:
        return "DNS_ERR", "Domain not resolved"
    
    # 🔒 DPI-блокировка: только при высокой уверенности
    # Признаки: сброс + пустые детали SSL ([None]) + упоминание handshake/tls
    if isinstance(error, OSError) and ("recv failure" in err_str or "connection reset" in err_str or "соединение разорвано" in err_str):
        if "[none]" in err_repr and ("handshake" in err_repr or "tls" in err_repr or "ssl" in err_repr):
            return "DPI_BLOCK", "Connection reset during TLS handshake (likely DPI)"
        # Не помечаем как DPI обычные сбросы — это могут быть временные сбои
        return "RST", "Connection reset by peer"
    
    if isinstance(error, aiohttp.ClientConnectorError) or "Connection timeout to host" in str(error):
        return "TIMEOUT", "Connection timeout error"
    if isinstance(error, asyncio.TimeoutError) or "timeout" in err_str or "errno 110" in err_str:
        return "TIMEOUT", "Connection timed out"
    if "refused" in err_str or "errno 111" in err_str:
        return "RST", "Connection refused"
    if "ssl" in err_str or "certificate" in err_str or "handshake" in err_str:
        return "SSL_ERR", "SSL handshake failed"
    if "reset" in err_str or "errno 104" in err_str:
        return "RST", "Connection reset by peer"
    if "unreachable" in err_str or "no route" in err_str:
        return "UNREACH", "Host unreachable"
    
    return "UNKNOWN", f"{type(error).__name__}: {str(error)}"

def should_fallback(status: str, details: str) -> bool:
    """Определяет, стоит ли попробовать проверку через httpx."""
    if status not in FALLBACK_STATUSES:
        return False
    return any(kw in details.lower() for kw in FALLBACK_KEYWORDS)

def extract_domain(line: str) -> str:
    """Извлекает домен из строки."""
    line = line.strip()
    if not line or line.startswith('#'):
        return ""
    domain = line.replace('https://', '').replace('http://', '')
    return domain.split('/')[0].split('?')[0].split('#')[0].strip()

def get_files_to_process(directory: str, excludes: Set[str]) -> List[Path]:
    """Находит файлы для обработки в директории."""
    dir_path = Path(directory)
    if not dir_path.is_dir():
        print(f"❌ Директория '{directory}' не найдена")
        sys.exit(1)
    return sorted([f for f in dir_path.iterdir() if f.is_file() and f.stem not in excludes])

def load_domains_from_files(files: List[Path]) -> List[str]:
    """Загружает уникальные домены из файлов (игнорируя комментарии)."""
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

async def check_with_aiohttp(session: aiohttp.ClientSession, domain: str, timeout: aiohttp.ClientTimeout) -> dict:
    """Проверка домена через aiohttp."""
    res = {"domain": domain, "status": "", "code": 0, "method": "GET", "rtt_ms": 0, "details": "", "client": "aiohttp"}
    url = f"https://{domain}"
    start = time.time()
    try:
        async with session.get(url, allow_redirects=True, ssl=False, timeout=timeout, headers=CONFIG["headers"]) as resp:
            res["rtt_ms"] = round((time.time() - start) * 1000, 1)
            res["code"] = resp.status
            res["status"] = "OK" if 200 <= resp.status < 400 else "HTTP_ERR"
            res["details"] = f"{resp.status} {resp.reason}" if resp.status >= 400 else (resp.reason or "OK")
    except Exception as e:
        res["status"], res["details"] = classify_error(e)
    return res

async def check_with_httpx(domain: str, timeout: float) -> dict:
    """Проверка домена через httpx с HTTP/1.1 (fallback)."""
    res = {"domain": domain, "status": "", "code": 0, "method": "GET", "rtt_ms": 0, "details": "", "client": "httpx/http1.1"}
    url = f"https://{domain}"
    start = time.time()
    try:
        async with httpx.AsyncClient(http2=False, verify=False, timeout=httpx.Timeout(timeout), follow_redirects=True, headers=CONFIG["headers"]) as client:
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

async def check_domain(domain: str, aiohttp_session: aiohttp.ClientSession,
                       aiohttp_timeout: aiohttp.ClientTimeout, httpx_timeout: float,
                       sem: asyncio.Semaphore) -> dict:
    """Проверка домена с fallback на httpx при необходимости."""
    async with sem:
        result = await check_with_aiohttp(aiohttp_session, domain, aiohttp_timeout)
        if should_fallback(result["status"], result["details"]):
            fallback_result = await check_with_httpx(domain, httpx_timeout)
            if fallback_result["status"] == "OK" and result["status"] != "OK":
                print(f"  🔁 Fallback: {domain} — {result['status']} → {fallback_result['status']} (httpx)")
            return fallback_result
        return result

async def run_checker(domains: List[str], connector: aiohttp.TCPConnector, verbose: bool = True) -> Dict[str, dict]:
    """Основная функция проверки доменов."""
    results = {}
    print(f"🔍 Этап 1/2: DNS-резолв ({len(domains)} доменов)...")
    dns_sem = asyncio.Semaphore(CONFIG["concurrency"] * 2)
    
    async def resolve_with_connector(d: str):
        async with dns_sem:
            try:
                await asyncio.wait_for(connector._resolve_host(d, 443, traces=[]), timeout=CONFIG["timeout_dns"])
                return (d, True)
            except Exception:
                return (d, False)
    
    dns_results = {}
    completed = 0
    for coro in asyncio.as_completed([resolve_with_connector(d) for d in domains]):
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
    if http_domains:
        print(f"\n🔍 Этап 2/2: HTTP-проверка ({len(http_domains)} доменов)...")
        print(f"   🌐 Browser GET + httpx fallback (Cookies + Keep-Alive)")
        
        aiohttp_timeout = aiohttp.ClientTimeout(connect=CONFIG["timeout_connect"], total=CONFIG["timeout_total"])
        async with aiohttp.ClientSession(connector=connector, cookie_jar=aiohttp.CookieJar()) as aiohttp_session:
            http_sem = asyncio.Semaphore(CONFIG["concurrency"])
            tasks = [check_domain(d, aiohttp_session, aiohttp_timeout, CONFIG["timeout_total"], http_sem) for d in http_domains]
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
    """Сохраняет успешные домены в файл с датой и оператором."""
    timestamp = datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
    filename = f"whitelist-{timestamp}-{operator_name}.txt"
    output_file = os.path.join(output_dir, filename)
    print(f"💾 Сохранение успешных доменов в {output_file}...")
    os.makedirs(output_dir, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(successful_domains) + '\n')
    print("  ✅ Whitelist сохранен")

def select_operator() -> str:
    """Запрашивает у пользователя выбор оператора."""
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
    parser.add_argument('--dns', nargs='+', default=None, help='Кастомные DNS-серверы (по умолчанию — системные)')
    args = parser.parse_args()
    
    use_custom_dns = bool(args.dns)
    directory = args.directory
    excludes = DEFAULT_EXCLUDES.union(set(args.exclude))
    
    print("⚙️  Конфигурация:")
    print(f"   timeout_connect: {CONFIG['timeout_connect']}s")
    print(f"   timeout_total:   {CONFIG['timeout_total']}s")
    print(f"   timeout_dns:     {CONFIG['timeout_dns']}s")
    print(f"   concurrency:     {CONFIG['concurrency']}")
    print(f"   dns:             {'Кастомный (' + ', '.join(args.dns) + ')' if use_custom_dns else 'SYSTEM ✅'}")
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
    
    try:
        if use_custom_dns:
            resolver = aiohttp.AsyncResolver(nameservers=args.dns)
            connector = aiohttp.TCPConnector(limit=CONFIG["concurrency"], ttl_dns_cache=300, use_dns_cache=True, resolver=resolver, enable_cleanup_closed=True)
            print(f"🌐 DNS: Кастомный ({', '.join(args.dns)})")
        else:
            connector = aiohttp.TCPConnector(limit=CONFIG["concurrency"], ttl_dns_cache=300, use_dns_cache=True, enable_cleanup_closed=True)
            print("🌐 DNS: Системный резолвер (/etc/resolv.conf или эквивалент)")
    except Exception as e:
        print(f"❌ Ошибка создания connector: {e}")
        sys.exit(1)
    
    try:
        start = time.time()
        results = await run_checker(domains, connector, verbose=not args.quiet)
        elapsed = time.time() - start
        print("-" * 85)
        print(f"✅ Готово за {elapsed:.1f} сек. ({len(domains)/max(elapsed, 0.1):.1f} доменов/сек)")
        
        successful_domains = [d for d, r in results.items() if r['status'] == 'OK']
        print(f"📋 Успешных доменов: {len(successful_domains)}")
        
        if not successful_domains:
            print("⚠️  Нет успешных доменов для сохранения. Пропускаем запись whitelist.")
        else:
            operator = select_operator()
            print(f"✅ Выбран оператор: {operator}")
            save_whitelist(successful_domains, operator)
        
        print("\n📊 Общая статистика:")
        status_counts = {}
        for r in results.values():
            status_counts[r['status']] = status_counts.get(r['status'], 0) + 1
        for status, count in sorted(status_counts.items(), key=lambda x: -x[1]):
            print(f"  {ICONS.get(status, '❓')} {status}: {count}")
        
        # 🔒 Блок информирования о типах ошибок
        http_err_count = status_counts.get("HTTP_ERR", 0)
        if http_err_count > 0:
            print(f"\n⚠️  HTTP_ERR ({http_err_count}) — сервер ответил, это НЕ блокировка")
        
        dpi_count = status_counts.get("DPI_BLOCK", 0)
        if dpi_count > 0:
            print(f"\n🔒 DPI_BLOCK ({dpi_count}) — домен заблокирован на уровне провайдера (сброс при TLS-рукопожатии)")
        
    except KeyboardInterrupt:
        print("\n⚠️  Прервано пользователем (Ctrl+C)")
    finally:
        await connector.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Завершение работы...")
        sys.exit(0)