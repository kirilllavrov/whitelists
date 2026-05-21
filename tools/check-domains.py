#!/usr/bin/env python3
"""
Проверка доменов на доступность при обходе блокировок.
Все настройки берутся из configs/check-domains.json

Зависимости: pip install curl_cffi httpx aiodns tqdm
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
import signal
import json
from datetime import datetime
from typing import List, Tuple, Dict, Set, Optional, Any
from pathlib import Path

# 🔧 Подключение curl_cffi
try:
    from curl_cffi.requests import AsyncSession as CurlCffiSession
    from curl_cffi import __version__ as curl_cffi_version
    USE_CURL_CFFI = True
except ImportError:
    USE_CURL_CFFI = False
    curl_cffi_version = "not installed"

import httpx
import aiodns

# ✅ Прогресс-бар
try:
    from tqdm.asyncio import tqdm as asyncio_tqdm
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    # Создаём заглушки
    class asyncio_tqdm:
        @staticmethod
        def as_completed(coros, total=None, desc=None):
            return asyncio.as_completed(coros)
    class tqdm:
        def __init__(self, *args, **kwargs): pass
        def update(self, *args, **kwargs): pass
        def close(self, *args, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass

# ✅ Тишина в логах библиотек
for name in ('httpx', 'httpcore', 'aiodns', 'asyncio', 'curl_cffi'):
    logging.getLogger(name).setLevel(logging.CRITICAL)

# Пути
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
CONFIG_DIR = PROJECT_ROOT / "configs"
CONFIG_FILE = CONFIG_DIR / "check-domains.json"

# Глобальные переменные
SHUTDOWN_REQUESTED = False
CONFIG: Dict[str, Any] = {}

# Иконки (не зависят от конфига)
ICONS = {
    "OK": "✅", "RST": "❌", "TIMEOUT": "🕐",
    "SSL_ERR": "🔐", "HTTP_ERR": "⚠️", "DNS_ERR": "🌐",
    "UNKNOWN": "❌", "DPI_BLOCK": "🔒", "UNREACH": "🚫", "BOT_BLOCK": "🤖",
    "TLS_ERR": "🔐", "HTTP2_ERR": "⚠️", "PORT_BLOCK": "🚧", "HTTP_OK": "🌐"
}

def signal_handler(signum, frame):
    """Обработчик сигналов для graceful shutdown."""
    global SHUTDOWN_REQUESTED
    if not SHUTDOWN_REQUESTED:
        SHUTDOWN_REQUESTED = True
        print("\n⚠️  Получен сигнал завершения, останавливаемся...")

def load_config() -> Dict[str, Any]:
    """Загружает конфигурацию из JSON файла."""
    if not CONFIG_FILE.exists():
        print(f"❌ Файл конфигурации не найден: {CONFIG_FILE}")
        sys.exit(1)
    
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Ошибка загрузки конфига: {e}")
        sys.exit(1)

def get_config_value(*keys, default=None):
    """Безопасное получение значения из конфига."""
    current = CONFIG
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return default
        if current is None:
            return default
    return current

def validate_impersonate(impersonate: str) -> bool:
    """Проверяет, существует ли указанный отпечаток."""
    fingerprints = get_config_value("curl_cffi", "fingerprints", default={})
    valid_values = set(fingerprints.values())
    
    if valid_values and impersonate not in valid_values:
        print(f"⚠️  Внимание: отпечаток '{impersonate}' не найден в списке fingerprints")
        print(f"   Доступные отпечатки: {', '.join(sorted(valid_values))}")
        print(f"   Будет использован '{impersonate}' (передаётся напрямую в curl_cffi)")
        return False
    return True

def classify_error(error: Exception) -> Tuple[str, str]:
    """Классификация ошибок."""
    err_str = str(error).lower()
    err_repr = repr(error).lower()
    curl_code = None
    m = re.search(r'curl:\s*\((\d+)\)', err_str)
    if m:
        curl_code = int(m.group(1))

    if curl_code is not None:
        if curl_code == 6: return "DNS_ERR", "Could not resolve host"
        if curl_code == 35:
            if "invalid library" in err_str or "OPENSSL_internal" in err_repr:
                return "TLS_ERR", "TLS stack mismatch"
            if "TLSV1_ALERT" in err_str and "internal_error" in err_str:
                return "DPI_BLOCK", "Server rejected TLS handshake"
            return "SSL_ERR", "SSL/TLS handshake error"
        if curl_code == 28: return "TIMEOUT", "Operation timed out"
        if curl_code == 7:
            return "PORT_BLOCK" if "connection refused" in err_str else "TIMEOUT", "Could not connect"
        if curl_code == 47: return "HTTP_ERR", "Too many redirects"
        if curl_code == 52: return "RST", "Server returned nothing"
        return "UNKNOWN", f"curl error {curl_code}"

    if isinstance(error, socket.gaierror):
        return "DNS_ERR", "Domain not resolved"
    if isinstance(error, OSError):
        if "timeout" in err_str or "timed out" in err_str:
            return "TIMEOUT", "Connection timed out"
        if "connection refused" in err_str:
            return "PORT_BLOCK", "Connection refused"
        if "reset" in err_str:
            return "RST", "Connection reset"
        return "UNKNOWN", f"OSError: {error}"
    if "timeout" in err_str or "timed out" in err_str:
        return "TIMEOUT", "Request timed out"
    if "ssl" in err_str or "certificate" in err_str:
        return "SSL_ERR", "SSL/TLS error"
    if isinstance(error, httpx.HTTPStatusError):
        c = error.response.status_code
        return "BOT_BLOCK" if c in (403, 429, 503) else "HTTP_ERR", f"HTTP {c}"
    return "UNKNOWN", f"{type(error).__name__}: {error}"

def extract_domain(line: str) -> str:
    line = line.strip()
    if not line or line.startswith('#'): return ""
    domain = line.replace('https://', '').replace('http://', '')
    return domain.split('/')[0].split('?')[0].split('#')[0].strip()

def get_files_to_process(directory: str, excludes: Set[str]) -> List[Path]:
    dir_path = Path(directory)
    if not dir_path.is_dir():
        dir_path = PROJECT_ROOT / directory
        if not dir_path.is_dir():
            print(f"❌ Директория '{directory}' не найдена")
            sys.exit(1)
    return sorted([f for f in dir_path.iterdir() if f.is_file() and f.stem not in excludes])

def load_domains_from_files(files: List[Path]) -> List[str]:
    domains, seen = [], set()
    for filepath in files:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                domain = extract_domain(line)
                if domain and domain not in seen:
                    seen.add(domain)
                    domains.append(domain)
    return domains

async def check_dns_async(domain: str, use_custom_dns: bool, dns_servers: list, timeout: float) -> bool:
    try:
        if use_custom_dns and dns_servers:
            resolver = aiodns.DNSResolver(nameservers=dns_servers)
            await asyncio.wait_for(resolver.query(domain, 'A'), timeout=timeout)
            return True
        else:
            loop = asyncio.get_running_loop()
            await asyncio.wait_for(loop.getaddrinfo(domain, 443, type=socket.SOCK_STREAM), timeout=timeout)
            return True
    except:
        return False

class HTTPClientPool:
    """Пул HTTP-клиентов."""
    
    def __init__(self, verify_ssl: bool, timeout: float, headers: dict, impersonate: str):
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.headers = headers
        self.impersonate = impersonate
        self.httpx_clients: Dict[str, httpx.AsyncClient] = {}
        self.curl_client: Optional[Any] = None
        self._lock = asyncio.Lock()
    
    async def get_httpx(self, http2: bool, is_http: bool = False) -> httpx.AsyncClient:
        key = f"h2_{http2}_http_{is_http}"
        async with self._lock:
            if key not in self.httpx_clients:
                self.httpx_clients[key] = httpx.AsyncClient(
                    http2=http2 and not is_http,
                    verify=self.verify_ssl,
                    timeout=httpx.Timeout(self.timeout),
                    follow_redirects=True,
                    headers=self.headers,
                    limits=httpx.Limits(max_keepalive_connections=20)
                )
            return self.httpx_clients[key]
    
    async def get_curl(self) -> Optional[Any]:
        if not USE_CURL_CFFI or not get_config_value("curl_cffi", "enabled", default=True):
            return None
        async with self._lock:
            if self.curl_client is None:
                self.curl_client = CurlCffiSession(
                    impersonate=self.impersonate,
                    verify=self.verify_ssl,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            return self.curl_client
    
    async def close(self):
        async with self._lock:
            for client in self.httpx_clients.values():
                await client.aclose()
            self.httpx_clients.clear()
            if self.curl_client:
                await self.curl_client.close()
                self.curl_client = None

async def _do_curl_cffi(client_pool: HTTPClientPool, url: str, enable_http3: bool = True) -> dict:
    """
    Запрос через curl_cffi с браузерной эмуляцией.
    
    Args:
        client_pool: Пул HTTP-клиентов
        url: URL для запроса
        enable_http3: Пробовать HTTP/3 если поддерживается (по умолчанию True)
    """
    domain = url.split("://")[1].split('/')[0]
    start = time.time()
    res = {"domain": domain, "status": "", "code": 0, "method": "?", "rtt_ms": 0, "details": "", "client": "curl_cffi"}
    
    try:
        client = await client_pool.get_curl()
        if client is None:
            raise Exception("curl_cffi not available")
        
        # Подготовка параметров запроса
        kwargs = {"url": url}
        
        # Пробуем HTTP/3 если включено
        if enable_http3:
            kwargs["http_version"] = "v3"
        
        resp = await client.get(**kwargs)
        
        # Определяем реальную версию HTTP из ответа
        http_version = getattr(resp, 'http_version', 0)
        if http_version == 3:
            method = "H3"
        elif http_version == 2:
            method = "H2"
        else:
            method = "H1"
        
        res.update({
            "rtt_ms": round((time.time()-start)*1000, 1),
            "code": resp.status_code,
            "status": "OK" if 200 <= resp.status_code < 400 else "HTTP_ERR",
            "details": f"{resp.status_code} {getattr(resp, 'reason', 'OK')}",
            "method": method
        })
    except Exception as e:
        res["status"], res["details"] = classify_error(e)
        # Если ошибка связана с HTTP/3, пробуем без него
        if enable_http3 and "http3" in str(e).lower():
            return await _do_curl_cffi(client_pool, url, enable_http3=False)
    
    return res

async def _do_httpx(client_pool: HTTPClientPool, url: str, http2: bool) -> dict:
    domain = url.split("://")[1].split('/')[0]
    is_http = url.startswith("http://")
    res = {
        "domain": domain, "status": "", "code": 0,
        "method": "H1.0" if is_http else ("H2" if http2 else "H1.1"),
        "rtt_ms": 0, "details": "", "client": f"httpx/{'h2' if http2 else 'h1.1'}"
    }
    start = time.time()
    try:
        client = await client_pool.get_httpx(http2, is_http)
        resp = await client.get(url)
        res.update({
            "rtt_ms": round((time.time()-start)*1000, 1),
            "code": resp.status_code,
            "status": "OK" if 200 <= resp.status_code < 400 else "HTTP_ERR",
            "details": f"{resp.status_code} {resp.reason_phrase}"
        })
    except Exception as e:
        res["status"], res["details"] = classify_error(e)
    return res

async def check_domain_pipeline(domain: str, client_pool: HTTPClientPool, 
                                use_impersonate: bool, try_http_fallback: bool, 
                                max_retries: int, retriable_statuses: set,
                                enable_http3: bool = True) -> dict:
    """Многоэтапный pipeline с ретраями и поддержкой HTTP/3."""
    global SHUTDOWN_REQUESTED
    
    steps = []
    if use_impersonate and USE_CURL_CFFI:
        steps.append(("curl_cffi/HTTPS", lambda: _do_curl_cffi(client_pool, f"https://{domain}", enable_http3=enable_http3)))
    steps.append(("httpx/H2", lambda: _do_httpx(client_pool, f"https://{domain}", True)))
    steps.append(("httpx/H1.1", lambda: _do_httpx(client_pool, f"https://{domain}", False)))
    if try_http_fallback:
        steps.append(("httpx/H1.0", lambda: _do_httpx(client_pool, f"http://{domain}", False)))

    last_result = None
    for step_name, step_fn in steps:
        if SHUTDOWN_REQUESTED:
            return {"domain": domain, "status": "TIMEOUT", "method": "-", "details": "Shutdown requested"}
        
        for attempt in range(max_retries + 1):
            result = await step_fn()
            result["pipeline_step"] = step_name

            if result["status"] == "OK":
                return result

            if result["status"] in retriable_statuses and attempt < max_retries:
                await asyncio.sleep(0.5 * (attempt + 1))
                last_result = result
                continue
            else:
                last_result = result
                break
    
    return last_result if last_result else {"domain": domain, "status": "UNKNOWN", "method": "-", "details": "No steps executed"}

async def run_checker(domains: List[str], use_custom_dns: bool, dns_servers: list,
                      args: argparse.Namespace) -> Dict[str, dict]:
    global SHUTDOWN_REQUESTED
    
    results = {}
    
    # Читаем настройки из конфига
    network = get_config_value("network", default={})
    pipeline = get_config_value("pipeline", default={})
    logging_conf = get_config_value("logging", default={})
    
    timeout_dns = network.get("timeout_dns", 10)
    timeout_total = network.get("timeout_total", 15)
    concurrency = args.concurrency or network.get("concurrency", 5)
    jitter = args.jitter or network.get("jitter", 0.1)
    max_retries = args.retries or network.get("retries", 1)
    verify_ssl = args.verify_ssl or network.get("verify_ssl", False)
    use_impersonate = not args.no_impersonate and pipeline.get("use_impersonate", True) and USE_CURL_CFFI
    http_fallback = args.http_fallback if args.http_fallback is not None else pipeline.get("http_fallback", True)
    enable_http3 = args.enable_http3 if hasattr(args, 'enable_http3') else pipeline.get("enable_http3", True)
    retriable_statuses = set(get_config_value("error_classification", "retriable_statuses", default=["TIMEOUT", "PORT_BLOCK", "SSL_ERR", "TLS_ERR", "UNKNOWN", "RST"]))
    show_progress_every = logging_conf.get("show_progress_every", 100)
    verbose = not (args.quiet or logging_conf.get("quiet", False))
    
    impersonate = get_config_value("curl_cffi", "default_impersonate", default="chrome")
    validate_impersonate(impersonate)
    headers = get_config_value("headers", default={})
    
    # DNS проверка с прогресс-баром
    print(f"🔍 DNS-резолв ({len(domains)} доменов)...")
    dns_sem = asyncio.Semaphore(concurrency * 2)
    
    async def resolve(d: str):
        async with dns_sem:
            if SHUTDOWN_REQUESTED:
                return d, False
            return d, await check_dns_async(d, use_custom_dns, dns_servers, timeout_dns)
    
    dns_results = {}
    dns_tasks = [resolve(d) for d in domains]
    
    if TQDM_AVAILABLE and not args.quiet:
        pbar = tqdm(total=len(domains), desc="  DNS прогресс", unit="домен")
        for coro in asyncio.as_completed(dns_tasks):
            if SHUTDOWN_REQUESTED:
                break
            domain, ok = await coro
            dns_results[domain] = ok
            pbar.update(1)
        pbar.close()
    else:
        for i, coro in enumerate(asyncio.as_completed(dns_tasks), 1):
            if SHUTDOWN_REQUESTED:
                break
            domain, ok = await coro
            dns_results[domain] = ok
            if verbose and i % show_progress_every == 0:
                print(f"  → DNS: {i}/{len(domains)}")
    
    dns_ok = sum(dns_results.values())
    print(f"  ✅ Резолвятся: {dns_ok} | ❌ Не резолвятся: {len(domains) - dns_ok}")
    
    for d, ok in dns_results.items():
        if not ok:
            results[d] = {"domain": d, "status": "DNS_ERR", "code": 0, "method": "-", "rtt_ms": 0, "details": "DNS failed", "client": "-"}
    
    http_domains = [d for d, ok in dns_results.items() if ok]
    if not http_domains:
        return results
    
    http_note = " + HTTP:80 fallback" if http_fallback else ""
    http3_note = " + HTTP/3" if enable_http3 else ""
    print(f"\n🔍 HTTP-проверка ({len(http_domains)} доменов)...")
    print(f"   Pipeline: curl_cffi{http3_note} → httpx/H2 → httpx/H1.1{http_note} | Повторов: {max_retries}")
    
    client_pool = HTTPClientPool(verify_ssl, timeout_total, headers, impersonate)
    sem = asyncio.Semaphore(concurrency)
    
    async def run_pipeline(d):
        async with sem:
            if SHUTDOWN_REQUESTED:
                return {"domain": d, "status": "TIMEOUT", "method": "-", "details": "Shutdown requested"}
            if jitter > 0:
                await asyncio.sleep(random.uniform(0, jitter))
            return await check_domain_pipeline(d, client_pool, use_impersonate, http_fallback, max_retries, retriable_statuses, enable_http3)
    
    try:
        tasks = [run_pipeline(d) for d in http_domains]
        
        if TQDM_AVAILABLE and not args.quiet:
            pbar = tqdm(total=len(http_domains), desc="  HTTP прогресс", unit="домен")
            for coro in asyncio.as_completed(tasks):
                if SHUTDOWN_REQUESTED:
                    break
                res = await coro
                results[res['domain']] = res
                pbar.update(1)
            pbar.close()
        else:
            for i, coro in enumerate(asyncio.as_completed(tasks), 1):
                if SHUTDOWN_REQUESTED:
                    break
                res = await coro
                results[res['domain']] = res
                
                if verbose:
                    icon = ICONS.get(res['status'], "❌")
                    print(f"[{i}/{len(http_domains)}] {icon} {res['domain']:<40} {res['status']:<10} {res.get('method','?'):<4} ({res.get('pipeline_step','?')}) {res['details']}")
                
                if not verbose and i % show_progress_every == 0:
                    print(f"  → Прогресс: {i}/{len(http_domains)}")
    finally:
        await client_pool.close()
    
    return results

def save_whitelist(domains: List[str], operator: str, out_dir: str):
    """Сохраняет список успешных доменов в файл с временной меткой."""
    out_path = PROJECT_ROOT / out_dir
    out_path.mkdir(parents=True, exist_ok=True)
    
    ts = datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
    path = out_path / f"whitelist-{ts}-{operator}.txt"
    
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(domains) + '\n')
    
    print(f"💾 Сохранено: {path}")
    print(f"   Всего доменов в whitelist: {len(domains)}")

def select_operator(operators: dict) -> str:
    print("\n📱 Выберите оператора:")
    for k, v in operators.items():
        print(f"  {k}. {v}")
    
    available = ', '.join(operators.keys())
    while True:
        c = input(f"Введите номер ({available}): ").strip()
        if c in operators:
            return operators[c]
        print("❌ Неверный ввод")

async def main():
    global CONFIG, SHUTDOWN_REQUESTED
    
    CONFIG = load_config()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    parser = argparse.ArgumentParser(description='Проверка доменов на доступность')
    parser.add_argument('directory', nargs='?', help='Директория с доменами')
    parser.add_argument('-c', '--concurrency', type=int, help='Количество параллельных запросов')
    parser.add_argument('-q', '--quiet', action='store_true', help='Тихий режим')
    parser.add_argument('-e', '--exclude', nargs='+', default=[], help='Исключить категории')
    parser.add_argument('--dns', nargs='+', default=None, help='Свои DNS серверы')
    parser.add_argument('--verify-ssl', action='store_true', help='Проверять SSL')
    parser.add_argument('--jitter', type=float, help='Случайная задержка')
    parser.add_argument('--no-impersonate', action='store_true', help='Отключить impersonate')
    parser.add_argument('--no-http-fallback', action='store_false', dest='http_fallback', help='Отключить HTTP fallback')
    parser.add_argument('--no-http3', action='store_false', dest='enable_http3', help='Отключить HTTP/3')
    parser.add_argument('--retries', type=int, help='Количество ретраев')
    parser.add_argument('--show-config', action='store_true', help='Показать текущую конфигурацию')
    parser.add_argument('--show-fingerprints', action='store_true', help='Показать информацию об отпечатках curl_cffi')
    parser.set_defaults(http_fallback=None, enable_http3=True)
    args = parser.parse_args()
    
    # Режим показа конфигурации
    if args.show_config:
        print(json.dumps(CONFIG, indent=2, ensure_ascii=False))
        return
    
    # Режим показа информации об отпечатках
    if args.show_fingerprints:
        curl_config = get_config_value("curl_cffi", default={})
        print("\n🔐 Информация об отпечатках curl_cffi:")
        print(f"   Версия библиотеки: {curl_cffi_version}")
        print(f"   Используемый отпечаток: {curl_config.get('default_impersonate', 'chrome124')}")
        print(f"   Доступные отпечатки в конфиге:")
        fingerprints = curl_config.get("fingerprints", {})
        for name, fp in fingerprints.items():
            print(f"      • {name}: {fp}")
        return
    
    # Проверка установки tqdm (не критично)
    if not TQDM_AVAILABLE and not args.quiet:
        print("💡 Для красивого прогресс-бара установите tqdm: pip install tqdm")
    
    # Читаем настройки из конфига
    network = get_config_value("network", default={})
    pipeline = get_config_value("pipeline", default={})
    paths = get_config_value("paths", default={})
    
    # Определяем все переменные ДО их использования
    use_dns = bool(args.dns)
    domains_dir = args.directory or paths.get("domains_directory", "../src/domains")
    excludes = set(paths.get("exclude_categories", [])) | set(args.exclude)
    
    # Определяем параметры запуска
    use_impersonate = not args.no_impersonate and pipeline.get("use_impersonate", True) and USE_CURL_CFFI
    http_fallback = args.http_fallback if args.http_fallback is not None else pipeline.get("http_fallback", True)
    enable_http3 = args.enable_http3 and pipeline.get("enable_http3", True)
    verify_ssl = args.verify_ssl or network.get("verify_ssl", False)
    max_retries = args.retries or network.get("retries", 1)
    jitter = args.jitter or network.get("jitter", 0.1)
    concurrency = args.concurrency or network.get("concurrency", 5)
    
    # Вывод настроек
    print("⚙️  Настройки проверки:")
    print(f"   Одновременных запросов: {concurrency}")
    print(f"   Эмуляция браузера: {'✅ Вкл' if use_impersonate else '❌ Выкл'}")
    print(f"   HTTP/3: {'✅ Вкл' if enable_http3 else '❌ Выкл'}")
    print(f"   Резервный HTTP (80): {'✅ Вкл' if http_fallback else '❌ Выкл'}")
    print(f"   Проверка SSL: {'✅ Да' if verify_ssl else '❌ Нет'}")
    print(f"   Повторы при сбоях: {max_retries}")
    print(f"   Случайная пауза: {jitter} сек")
    print(f"   Прогресс-бар: {'✅ tqdm' if TQDM_AVAILABLE else '❌ стандартный'}")
    print("-" * 45)
    
    # Получаем файлы и домены
    files = get_files_to_process(domains_dir, excludes)
    if not files:
        print("❌ Нет файлов")
        sys.exit(1)
    
    print(f"📁 Файлы: {', '.join([f.name for f in files])}")
    domains = load_domains_from_files(files)
    print(f"📋 Загружено доменов: {len(domains)}\n")
    
    # Запускаем проверку
    results = await run_checker(domains, use_dns, args.dns or [], args)
    
    # Статистика и сохранение
    alive_domains = [d for d, r in results.items() if r.get('status') in ('OK', 'HTTP_ERR')]
    
    print(f"\n✅ Успешных: {len(alive_domains)}")
    
    if alive_domains:
        operators = get_config_value("operators", default={"1": "Default"})
        op = select_operator(operators)
        out_dir = paths.get("output_directory", "build/domains_checked")
        save_whitelist(alive_domains, op, out_dir)
    
    # Детальная статистика по статусам
    print("\n📊 Статистика:")
    stats = {}
    for r in results.values():
        status = r.get('status', 'UNKNOWN')
        stats[status] = stats.get(status, 0) + 1
    
    for status, count in sorted(stats.items(), key=lambda x: -x[1]):
        icon = ICONS.get(status, "❌")
        print(f"  {icon} {status}: {count}")
    
    # Дополнительная диагностика
    if stats.get("BOT_BLOCK", 0) > 0:
        print(f"\n🤖 BOT_BLOCK ({stats['BOT_BLOCK']}) — возможна детекция бота")
        print("   Попробуйте обновить curl_cffi: pip install --upgrade curl_cffi")
    
    timeout_count = stats.get("TIMEOUT", 0)
    if timeout_count > len(domains) * 0.3:
        print(f"\n⚠️  Много таймаутов ({timeout_count}) — попробуйте:")
        print(f"   - Уменьшить concurrency (сейчас {concurrency})")
        print("   - Увеличить таймауты в configs/check-domains.json")
    
    if SHUTDOWN_REQUESTED:
        print("\n⚠️  Проверка была прервана досрочно")
        if alive_domains:
            print(f"   Но {len(alive_domains)} доменов уже проверено и сохранено")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Завершение")
        sys.exit(0)