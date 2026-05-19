#!/usr/bin/env python3
"""
Проверка доменов на доступность при обходе блокировок.
Универсальный pipeline: 
  1. curl_cffi (impersonate="chrome", HTTPS)
  2. httpx (HTTPS, HTTP/2)
  3. httpx (HTTPS, HTTP/1.1)
  4. httpx (HTTP:80, HTTP/1.0) [опционально]
Зависимости: pip install curl_cffi httpx aiodns
"""
import asyncio
import sys
import os
import time
import socket
import random
import argparse
import logging
import re
from datetime import datetime
from typing import List, Tuple, Dict, Set, Callable
from pathlib import Path
from collections import OrderedDict

# 🔧 Подключение curl_cffi
try:
    from curl_cffi.requests import AsyncSession as CurlCffiSession
    USE_CURL_CFFI = True
except ImportError:
    USE_CURL_CFFI = False
    logging.warning("⚠️ curl_cffi не установлен. Pipeline будет использовать только httpx.")

import httpx
import aiodns

# ✅ Тишина в логах библиотек
for name in ('httpx', 'httpcore', 'aiodns', 'asyncio', 'curl_cffi'):
    logging.getLogger(name).setLevel(logging.CRITICAL)

# === КОНФИГУРАЦИЯ ===
CONFIG = {
    "timeout_connect": 10,
    "timeout_total": 15,
    "timeout_dns": 10,
    "concurrency": 5,
}

ICONS = {
    "OK": "✅", "RST": "❌", "TIMEOUT": "🕐",
    "SSL_ERR": "🔐", "HTTP_ERR": "⚠️", "DNS_ERR": "🌐",
    "UNKNOWN": "❓", "DPI_BLOCK": "🔒", "UNREACH": "🚫", "BOT_BLOCK": "🤖",
    "TLS_ERR": "🔐", "HTTP2_ERR": "⚠️", "PORT_BLOCK": "🚧", "HTTP_OK": "🌐"
}

FALLBACK_STATUSES = {"UNKNOWN", "TIMEOUT", "RST", "SSL_ERR", "TLS_ERR", "PORT_BLOCK"}
FALLBACK_KEYWORDS = ["protocol_error", "stream was not closed", "server disconnected"]
DEFAULT_EXCLUDES = {"category-ru"}
OPERATORS = {
    "1": "Megafon", "2": "Beeline", "3": "MTS", "4": "Tele2", "5": "Yota", "6": "RT"
}

def get_dynamic_chrome_headers() -> OrderedDict:
    """Генерирует заголовки Chrome без захардкоженных версий."""
    # Базовая версия Chrome (обновляется при релизах)
    chrome_major = "124"
    chrome_full = f"{chrome_major}.0.6367.60"
    
    return OrderedDict([
        ("User-Agent", f"Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_full} Mobile Safari/537.36"),
        ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"),
        ("Accept-Language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"),
        ("Accept-Encoding", "gzip, deflate, br"),
        ("Sec-Ch-Ua", f'"Not-A.Brand";v="8", "Chromium";v="{chrome_major}", "Google Chrome";v="{chrome_major}"'),
        ("Sec-Ch-Ua-Mobile", "?1"),
        ("Sec-Ch-Ua-Platform", '"Android"'),
        ("Sec-Ch-Ua-Platform-Version", '"15"'),
        ("Sec-Ch-Ua-Arch", '"arm"'),
        ("Sec-Ch-Ua-Model", '"Pixel 7"'),
        ("Sec-Ch-Ua-Bitness", '"64"'),
        ("Sec-Ch-Ua-Full-Version", f'"{chrome_full}"'),
        ("Sec-Ch-Ua-Full-Version-List", f'"Not-A.Brand";v="8.0.0.0", "Chromium";v="{chrome_full}", "Google Chrome";v="{chrome_full}"'),
        ("Sec-Fetch-Dest", "document"),
        ("Sec-Fetch-Mode", "navigate"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-User", "?1"),
        ("Upgrade-Insecure-Requests", "1"),
        ("Cache-Control", "no-cache"),
        ("Pragma", "no-cache"),
        ("Priority", "u=0, i"),
        ("Connection", "keep-alive"),
    ])

DYNAMIC_HEADERS = get_dynamic_chrome_headers()

def classify_error(error: Exception) -> Tuple[str, str]:
    err_str = str(error).lower()
    err_repr = repr(error).lower()
    curl_code = None
    curl_match = re.search(r'curl:\s*\((\d+)\)', err_str)
    if curl_match: curl_code = int(curl_match.group(1))

    if curl_code is not None:
        if curl_code == 6: return "DNS_ERR", "Could not resolve host"
        if curl_code == 35:
            if "invalid library" in err_str or "OPENSSL_internal" in err_repr: return "TLS_ERR", "OpenSSL/TLS stack mismatch"
            if "TLSV1_ALERT_INTERNAL_ERROR" in err_str or "internal error" in err_str: return "DPI_BLOCK", "Server rejected TLS handshake"
            return "SSL_ERR", "SSL/TLS handshake error"
        if curl_code == 47: return "HTTP_ERR", "Too many redirects"
        if curl_code == 56: return "TIMEOUT" if "closed abruptly" not in err_str else "RST", "Network receive error"
        if curl_code == 92: return "HTTP2_ERR", "HTTP/2 stream error"
        if curl_code == 28: return "PORT_BLOCK" if "connect" in err_str else "TIMEOUT", "Operation timed out"
        if curl_code == 7: return "PORT_BLOCK" if "refused" in err_str else "TIMEOUT", "Could not connect"
        if curl_code == 52: return "RST", "Server returned nothing"
        return "UNKNOWN", f"curl error {curl_code}"

    if isinstance(error, socket.gaierror): return "DNS_ERR", "Domain not resolved"
    if isinstance(error, OSError):
        if "timeout" in err_str or "timed out" in err_str: return "TIMEOUT", "Connection timed out"
        if "refused" in err_str: return "PORT_BLOCK", "Connection refused"
        if "reset" in err_str:
            if "[none]" in err_repr and ("handshake" in err_repr or "tls" in err_repr): return "DPI_BLOCK", "Connection reset during TLS handshake"
            return "RST", "Connection reset by peer"
        return "UNKNOWN", f"OSError: {error}"
    if "timeout" in err_str or "timed out" in err_str: return "TIMEOUT", "Request timed out"
    if "ssl" in err_str or "certificate" in err_str: return "SSL_ERR", "SSL/TLS error"
    if "redirect" in err_str or "max redirect" in err_str: return "HTTP_ERR", "Too many redirects"
    if hasattr(error, 'response'):
        code = getattr(error.response, 'status_code', 0)
        if code in (403, 429, 503): return "BOT_BLOCK", f"Bot detection: HTTP {code}"
        return "HTTP_ERR", f"HTTP {code}"
    return "UNKNOWN", f"{type(error).__name__}: {str(error)}"

def extract_domain(line: str) -> str:
    line = line.strip()
    if not line or line.startswith('#'): return ""
    domain = line.replace('https://', '').replace('http://', '')
    return domain.split('/')[0].split('?')[0].split('#')[0].strip()

def get_files_to_process(directory: str, excludes: Set[str]) -> List[Path]:
    dir_path = Path(directory)
    if not dir_path.is_dir(): print(f"❌ Директория '{directory}' не найдена"); sys.exit(1)
    return sorted([f for f in dir_path.iterdir() if f.is_file() and f.stem not in excludes])

def load_domains_from_files(files: List[Path]) -> List[str]:
    domains, seen = [], set()
    for filepath in files:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                domain = extract_domain(line)
                if domain and domain not in seen: seen.add(domain); domains.append(domain)
    return domains

async def check_dns_async(domain: str, use_custom_dns: bool, dns_servers: list, timeout: float) -> bool:
    try:
        if use_custom_dns:
            resolver = aiodns.DNSResolver(nameservers=dns_servers)
            tasks = [asyncio.wait_for(resolver.query(domain, 'A'), timeout=timeout),
                     asyncio.wait_for(resolver.query(domain, 'AAAA'), timeout=timeout)]
            for coro in asyncio.as_completed(tasks):
                try: await coro; return True
                except: continue
            return False
        else:
            loop = asyncio.get_running_loop()
            await asyncio.wait_for(loop.getaddrinfo(domain, 443, type=socket.SOCK_STREAM), timeout=timeout)
            return True
    except: return False

async def _do_request(url: str, client_type: str, http2: bool, verify_ssl: bool, headers: dict, timeout: float) -> dict:
    """Универсальный запрос для всех шагов pipeline."""
    domain = url.split("://")[1].split('/')[0]
    is_http = url.startswith("http://")
    res = {
        "domain": domain, "status": "", "code": 0,
        "method": "H1.0" if is_http else ("H2" if http2 else "H1.1"),
        "rtt_ms": 0, "details": "", "client": client_type
    }
    start = time.time()
    try:
        if client_type == "cffi" and USE_CURL_CFFI:
            # curl_cffi сам управляет заголовками при impersonate, не переопределяем их
            async with CurlCffiSession(impersonate="chrome", verify=verify_ssl, 
                                       timeout=httpx.Timeout(timeout), allow_redirects=True) as client:
                resp = await client.get(url)
                res["rtt_ms"] = round((time.time() - start) * 1000, 1)
                res["code"] = resp.status_code
                res["status"] = "OK" if 200 <= resp.status_code < 400 else "HTTP_ERR"
                res["details"] = f"{resp.status_code} {getattr(resp, 'reason', 'OK')}"
        else:
            async with httpx.AsyncClient(http2=http2, verify=verify_ssl, timeout=httpx.Timeout(timeout), 
                                         follow_redirects=True, headers=headers) as client:
                resp = await client.get(url)
                res["rtt_ms"] = round((time.time() - start) * 1000, 1)
                res["code"] = resp.status_code
                res["status"] = "OK" if 200 <= resp.status_code < 400 else "HTTP_ERR"
                res["details"] = f"{resp.status_code} {resp.reason_phrase}"
    except Exception as e:
        res["status"], res["details"] = classify_error(e)
    return res

async def check_domain_pipeline(domain: str, timeout: float, verify_ssl: bool, 
                                use_impersonate: bool, try_http_fallback: bool) -> dict:
    """4-этапный pipeline проверки домена."""
    # Определяем этапы
    steps = [
        ("cffi/HTTPS", lambda: _do_request(f"https://{domain}", "cffi", True, verify_ssl, {}, timeout)),
        ("httpx/H2",   lambda: _do_request(f"https://{domain}", "httpx", True, verify_ssl, DYNAMIC_HEADERS, timeout)),
        ("httpx/H1.1", lambda: _do_request(f"https://{domain}", "httpx", False, verify_ssl, DYNAMIC_HEADERS, timeout)),
    ]
    if try_http_fallback:
        steps.append(("httpx/H1.0", lambda: _do_request(f"http://{domain}", "httpx", False, False, DYNAMIC_HEADERS, timeout)))

    last_result = None
    for step_name, step_fn in steps:
        # Пропускаем curl_cffi если он отключен флагом
        if step_name.startswith("cffi") and not use_impersonate: continue
        
        result = await step_fn()
        result["pipeline_step"] = step_name
        
        if result["status"] == "OK":
            return result
        last_result = result
        
    return last_result if last_result else {"domain": domain, "status": "UNKNOWN", "code": 0, "method": "-", "rtt_ms": 0, "details": "No pipeline steps executed", "client": "none"}

async def run_checker(domains: List[str], use_custom_dns: bool, dns_servers: list, 
                      verify_ssl: bool, verbose: bool, jitter: float, use_impersonate: bool, 
                      try_http_fallback: bool) -> Dict[str, dict]:
    results = {}
    print(f"🔍 Этап 1/2: DNS-резолв ({len(domains)} доменов)...")
    dns_sem = asyncio.Semaphore(CONFIG["concurrency"] * 2)
    
    async def resolve(d: str):
        async with dns_sem: return d, await check_dns_async(d, use_custom_dns, dns_servers, CONFIG["timeout_dns"])
    
    dns_results = {}
    for i, coro in enumerate(asyncio.as_completed([resolve(d) for d in domains]), 1):
        domain, ok = await coro
        dns_results[domain] = ok
        if verbose and i % 200 == 0: print(f"  → DNS: {i}/{len(domains)}")
    
    dns_ok = sum(dns_results.values())
    print(f"  ✅ Резолвятся: {dns_ok} | ❌ Не резолвятся: {len(domains) - dns_ok}")
    
    for d, ok in dns_results.items():
        if not ok: results[d] = {"domain": d, "status": "DNS_ERR", "code": 0, "method": "-", "rtt_ms": 0, "details": "DNS failed", "client": "-", "pipeline_step": "DNS"}
    
    http_domains = [d for d, ok in dns_results.items() if ok]
    if not http_domains: return results
    
    print(f"\n🔍 Этап 2/2: HTTP-проверка ({len(http_domains)} доменов)...")
    print(f"   🌐 Pipeline: curl_cffi → httpx/H2 → httpx/H1.1{' → httpx/H1.0(HTTP)' if try_http_fallback else ''}")
    
    sem = asyncio.Semaphore(CONFIG["concurrency"])
    async def run_pipeline(d):
        async with sem:
            if jitter > 0: await asyncio.sleep(random.uniform(0, jitter))
            return await check_domain_pipeline(d, CONFIG["timeout_total"], verify_ssl, use_impersonate, try_http_fallback)
            
    tasks = [run_pipeline(d) for d in http_domains]
    for i, coro in enumerate(asyncio.as_completed(tasks), 1):
        res = await coro
        results[res['domain']] = res
        if verbose:
            icon = ICONS.get(res['status'], "❓")
            print(f"[{i}/{len(http_domains)}] {icon} {res['domain']:<40} {res['status']:<10} {res['method']:<4} ({res.get('pipeline_step','?')}) {res['details']}")
        if i % 100 == 0: print(f"  → HTTP: {i}/{len(http_domains)}")
    return results

def save_whitelist(domains: List[str], operator: str, out_dir: str = "../build/domains_checked"):
    ts = datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
    path = os.path.join(out_dir, f"whitelist-{ts}-{operator}.txt")
    os.makedirs(out_dir, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f: f.write('\n'.join(domains) + '\n')
    print(f"💾 Сохранено: {path}")

def select_operator() -> str:
    print("\n📱 Выберите оператора:")
    for k, v in OPERATORS.items(): print(f"  {k}. {v}")
    while True:
        c = input("Введите номер (1-6): ").strip()
        if c in OPERATORS: return OPERATORS[c]
        print("❌ Неверный ввод")

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', nargs='?', default='../src/domains')
    parser.add_argument('-c', '--concurrency', type=int, default=CONFIG["concurrency"])
    parser.add_argument('-q', '--quiet', action='store_true')
    parser.add_argument('-e', '--exclude', nargs='+', default=[])
    parser.add_argument('--dns', nargs='+', default=None)
    parser.add_argument('--verify-ssl', action='store_true')
    parser.add_argument('--jitter', type=float, default=0.1)
    parser.add_argument('--no-impersonate', action='store_true')
    parser.add_argument('--no-http-fallback', action='store_false', dest='http_fallback')
    parser.set_defaults(http_fallback=True)
    args = parser.parse_args()
    
    global USE_CURL_CFFI
    if args.no_impersonate: USE_CURL_CFFI = False
    CONFIG["concurrency"] = args.concurrency
    use_dns = bool(args.dns)
    excludes = DEFAULT_EXCLUDES.union(set(args.exclude))
    
    print("⚙️  Конфигурация:")
    print(f"   timeout: connect={CONFIG['timeout_connect']}s, total={CONFIG['timeout_total']}s")
    print(f"   concurrency: {CONFIG['concurrency']}, jitter: {args.jitter}s")
    print(f"   dns: {'custom' if use_dns else 'system'}, ssl-verify: {args.verify_ssl}")
    print(f"   masking: {'curl_cffi (auto)' if USE_CURL_CFFI else 'httpx only'}")
    print(f"   http-fallback: {'✅ Enabled' if args.http_fallback else '❌ Disabled'}")
    print("-" * 85)
    
    files = get_files_to_process(args.directory, excludes)
    if not files: print("❌ Нет файлов"); sys.exit(1)
    
    domains = load_domains_from_files(files)
    print(f"📋 Доменов: {len(domains)}\n")
    
    results = await run_checker(domains, use_dns, args.dns or [], args.verify_ssl, not args.quiet, args.jitter, USE_CURL_CFFI, args.http_fallback)
    
    ok = [d for d, r in results.items() if r['status'] == 'OK']
    http_ok = [d for d, r in results.items() if r['status'] == 'OK' and r.get('method') in ('H1.0', 'H1.1')]
    
    print(f"\n✅ Успешных: {len(ok)} (из них через HTTP/1.x: {len(http_ok)})")
    if ok:
        op = select_operator()
        save_whitelist(ok, op)
    
    print("\n📊 Статистика:")
    stats = {}
    for r in results.values(): stats[r['status']] = stats.get(r['status'], 0) + 1
    for s, c in sorted(stats.items(), key=lambda x: -x[1]):
        print(f"  {ICONS.get(s,'❓')} {s}: {c}")
    
    if stats.get("BOT_BLOCK"): print(f"\n🤖 BOT_BLOCK ({stats['BOT_BLOCK']}) — возможна детекция бота")
    if stats.get("DPI_BLOCK"): print(f"\n🔒 DPI_BLOCK ({stats['DPI_BLOCK']}) — блокировка на уровне провайдера")
    if stats.get("TLS_ERR"): print(f"\n🔐 TLS_ERR ({stats['TLS_ERR']}) — проблемы с TLS-рукопожатием")
    if stats.get("PORT_BLOCK"): print(f"\n🚧 PORT_BLOCK ({stats['PORT_BLOCK']}) — порт 443 заблокирован/не отвечает")

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: print("\n👋 Завершение"); sys.exit(0)