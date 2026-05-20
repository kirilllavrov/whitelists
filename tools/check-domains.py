#!/usr/bin/env python3
"""
Проверка доменов на доступность при обходе блокировок.
Все параметры конфигурации берутся из configs/check-domains.json

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
import signal
import json
import subprocess
from datetime import datetime
from typing import List, Tuple, Dict, Set, Optional, Any, Callable
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

# Глобальные переменные
SHUTDOWN_REQUESTED = False
CONFIG: Dict[str, Any] = {}
ICONS = {
    "OK": "✅", "RST": "❌", "TIMEOUT": "🕐",
    "SSL_ERR": "🔐", "HTTP_ERR": "⚠️", "DNS_ERR": "🌐",
    "UNKNOWN": "❓", "DPI_BLOCK": "🔒", "UNREACH": "🚫", "BOT_BLOCK": "🤖",
    "TLS_ERR": "🔐", "HTTP2_ERR": "⚠️", "PORT_BLOCK": "🚧", "HTTP_OK": "🌐"
}

# Пути
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
CONFIG_DIR = PROJECT_ROOT / "configs"
CONFIG_FILE = CONFIG_DIR / "check-domains.json"

def signal_handler(signum, frame):
    """Обработчик сигналов для graceful shutdown."""
    global SHUTDOWN_REQUESTED
    if not SHUTDOWN_REQUESTED:
        SHUTDOWN_REQUESTED = True
        print("\n⚠️  Получен сигнал завершения, останавливаемся...")
        print("   Нажмите Ctrl+C ещё раз для принудительного выхода")

def load_config() -> Dict[str, Any]:
    """Загружает полную конфигурацию из JSON файла."""
    default_config = {
        "network": {
            "timeout_connect": 10, "timeout_total": 15, "timeout_dns": 10,
            "concurrency": 5, "retries": 1, "jitter": 0.1, "verify_ssl": False
        },
        "pipeline": {
            "use_impersonate": True, "enable_http3": False, "http_fallback": True,
            "pipeline_order": ["curl_cffi/H2", "curl_cffi/H3", "httpx/H2", "httpx/H1.1", "httpx/H1.0"]
        },
        "curl_cffi": {
            "enabled": True, "default_impersonate": "chrome124", "fallback_impersonate": "chrome",
            "update_url": "https://fp.impersonate.pro/api/fingerprints",
            "fingerprints": {"chrome": "chrome124", "chrome_android": "chrome124"}
        },
        "headers": {},
        "paths": {"domains_directory": "../src/domains", "output_directory": "../build/domains_checked", "exclude_categories": []},
        "operators": {"1": "Megafon", "2": "Beeline", "3": "MTS", "4": "Tele2", "5": "Yota", "6": "RT"},
        "error_classification": {
            "retriable_statuses": ["TIMEOUT", "PORT_BLOCK", "SSL_ERR", "TLS_ERR", "UNKNOWN", "RST"],
            "fallback_statuses": ["UNKNOWN", "TIMEOUT", "RST", "SSL_ERR", "TLS_ERR", "PORT_BLOCK"],
            "fallback_keywords": ["protocol_error", "stream was not closed", "server disconnected"]
        },
        "logging": {"verbose": False, "quiet": False, "show_progress_every": 100}
    }
    
    if not CONFIG_FILE.exists():
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, indent=2, ensure_ascii=False)
        print(f"📝 Создан конфиг: {CONFIG_FILE}")
        print("   Отредактируйте его при необходимости и запустите скрипт снова")
        sys.exit(0)
    
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            user_config = json.load(f)
            return deep_merge(default_config, user_config)
    except Exception as e:
        print(f"❌ Ошибка загрузки конфига: {e}")
        sys.exit(1)

def deep_merge(base: Dict, override: Dict) -> Dict:
    """Рекурсивное слияние словарей."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result

def get_config_value(*keys, default=None):
    """Безопасное получение значения из конфига по цепочке ключей."""
    current = CONFIG
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return default
        if current is None:
            return default
    return current

async def update_curl_cffi_fingerprints(force: bool = False) -> bool:
    """Обновляет отпечатки curl_cffi."""
    if not USE_CURL_CFFI or not get_config_value("curl_cffi", "enabled"):
        print("❌ curl_cffi не установлен или отключён в конфиге")
        return False
    
    curl_config = get_config_value("curl_cffi", default={})
    last_update = curl_config.get("last_update")
    
    if not force and last_update:
        days_since = (datetime.now() - datetime.fromisoformat(last_update)).days
        if days_since < 7:
            print(f"ℹ️  Отпечатки обновлялись {days_since} дней назад")
            return True
    
    print("🔄 Обновление отпечатков curl_cffi...")
    
    # Пробуем через CLI
    try:
        result = await asyncio.to_thread(
            subprocess.run, [sys.executable, "-m", "curl_cffi", "update"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            curl_config["last_update"] = datetime.now().isoformat()
            CONFIG["curl_cffi"] = curl_config
            save_config(CONFIG)
            print("✅ Отпечатки обновлены")
            return True
    except Exception as e:
        print(f"⚠️ Ошибка обновления: {e}")
    
    # Пробуем через API
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(curl_config.get("update_url"), timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if "fingerprints" in data:
                        curl_config["fingerprints"] = data["fingerprints"]
                        curl_config["last_update"] = datetime.now().isoformat()
                        CONFIG["curl_cffi"] = curl_config
                        save_config(CONFIG)
                        print(f"✅ Отпечатки обновлены через API")
                        return True
    except:
        pass
    
    print("❌ Не удалось обновить отпечатки")
    return False

def save_config(config: Dict):
    """Сохраняет конфиг."""
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

def classify_error(error: Exception) -> Tuple[str, str]:
    """Классификация ошибок на основе конфига."""
    err_str = str(error).lower()
    err_repr = repr(error).lower()
    
    # Проверка curl кодов
    curl_code = None
    m = re.search(r'curl:\s*\((\d+)\)', err_str)
    if m:
        curl_code = int(m.group(1))
        if curl_code == 6: return "DNS_ERR", "Could not resolve host"
        if curl_code == 28: return "TIMEOUT", "Operation timed out"
        if curl_code == 35: return "TLS_ERR", "SSL/TLS error"
        if curl_code == 7: return "PORT_BLOCK" if "refused" in err_str else "TIMEOUT", "Connection error"
        if curl_code == 52: return "RST", "Connection reset"
    
    # Системные ошибки
    if isinstance(error, socket.gaierror): return "DNS_ERR", "DNS resolution failed"
    if isinstance(error, (httpx.ConnectTimeout, httpx.ReadTimeout, asyncio.TimeoutError)):
        return "TIMEOUT", "Timeout"
    if isinstance(error, OSError):
        if "refused" in err_str: return "PORT_BLOCK", "Connection refused"
        if "reset" in err_str: return "RST", "Connection reset"
    if isinstance(error, httpx.HTTPStatusError):
        code = error.response.status_code
        if code in (403, 429, 503): return "BOT_BLOCK", f"HTTP {code} (bot detection)"
        return "HTTP_ERR", f"HTTP {code}"
    
    return "UNKNOWN", str(error)[:100]

def extract_domain(line: str) -> str:
    """Извлекает домен из строки."""
    line = line.strip()
    if not line or line.startswith('#'): return ""
    domain = line.replace('https://', '').replace('http://', '')
    return domain.split('/')[0].split('?')[0].split('#')[0].strip()

def get_files_to_process(directory: str) -> List[Path]:
    """Получает список файлов с доменами."""
    dir_path = Path(directory)
    if not dir_path.is_dir():
        dir_path = PROJECT_ROOT / directory
        if not dir_path.is_dir():
            print(f"❌ Директория '{directory}' не найдена")
            sys.exit(1)
    
    excludes = set(get_config_value("paths", "exclude_categories", default=[]))
    return [f for f in dir_path.iterdir() if f.is_file() and f.stem not in excludes]

def load_domains(files: List[Path]) -> List[str]:
    """Загружает домены из файлов."""
    domains, seen = [], set()
    for filepath in files:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                domain = extract_domain(line)
                if domain and domain not in seen:
                    seen.add(domain)
                    domains.append(domain)
    return domains

async def check_dns(domain: str, use_custom_dns: bool, dns_servers: list) -> bool:
    """Проверяет DNS резолвинг."""
    timeout = get_config_value("network", "timeout_dns", default=10)
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
    
    def __init__(self):
        network_config = get_config_value("network", default={})
        self.verify_ssl = network_config.get("verify_ssl", False)
        self.timeout = network_config.get("timeout_total", 15)
        self.clients: Dict[str, httpx.AsyncClient] = {}
        self.curl_clients: Dict[str, CurlCffiSession] = {}
        self._lock = asyncio.Lock()
        self.impersonate = None
    
    async def get_impersonate(self) -> str:
        if not self.impersonate:
            curl_config = get_config_value("curl_cffi", default={})
            self.impersonate = curl_config.get("default_impersonate", "chrome124")
        return self.impersonate
    
    async def get_httpx(self, http2: bool, is_http: bool = False) -> httpx.AsyncClient:
        key = f"http{'2' if http2 else '1'}_{'http' if is_http else 'https'}"
        async with self._lock:
            if key not in self.clients:
                headers = get_config_value("headers", default={})
                self.clients[key] = httpx.AsyncClient(
                    http2=http2 and not is_http,
                    verify=self.verify_ssl,
                    timeout=httpx.Timeout(self.timeout),
                    follow_redirects=True,
                    headers=headers
                )
            return self.clients[key]
    
    async def get_curl(self) -> Optional[CurlCffiSession]:
        if not USE_CURL_CFFI or not get_config_value("curl_cffi", "enabled"):
            return None
        
        async with self._lock:
            if "curl" not in self.curl_clients:
                impersonate = await self.get_impersonate()
                self.curl_clients["curl"] = CurlCffiSession(
                    impersonate=impersonate,
                    verify=self.verify_ssl,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            return self.curl_clients["curl"]
    
    async def close(self):
        async with self._lock:
            for client in self.clients.values():
                await client.aclose()
            for client in self.curl_clients.values():
                await client.aclose()

async def check_curl_cffi(client_pool: HTTPClientPool, url: str, use_http3: bool = False) -> dict:
    """Проверка через curl_cffi."""
    domain = url.split("://")[1].split('/')[0]
    start = time.time()
    result = {"domain": domain, "status": "", "code": 0, "rtt_ms": 0, "details": ""}
    
    try:
        client = await client_pool.get_curl()
        if not client:
            raise Exception("curl_cffi not available")
        
        kwargs = {"url": url, "timeout": get_config_value("network", "timeout_total")}
        if use_http3 and get_config_value("pipeline", "enable_http3"):
            kwargs["http_version"] = "v3"
        
        resp = await client.get(**kwargs)
        result.update({
            "rtt_ms": round((time.time() - start) * 1000, 1),
            "code": resp.status_code,
            "status": "OK" if 200 <= resp.status_code < 400 else "HTTP_ERR",
            "details": f"HTTP {resp.status_code}"
        })
    except Exception as e:
        result["status"], result["details"] = classify_error(e)
    
    return result

async def check_httpx(client_pool: HTTPClientPool, url: str, http2: bool) -> dict:
    """Проверка через httpx."""
    domain = url.split("://")[1].split('/')[0]
    is_http = url.startswith("http://")
    start = time.time()
    
    result = {
        "domain": domain, "status": "", "code": 0,
        "rtt_ms": 0, "details": "", "method": "H2" if http2 else "H1.1"
    }
    
    try:
        client = await client_pool.get_httpx(http2, is_http)
        resp = await client.get(url)
        result.update({
            "rtt_ms": round((time.time() - start) * 1000, 1),
            "code": resp.status_code,
            "status": "OK" if 200 <= resp.status_code < 400 else "HTTP_ERR",
            "details": f"HTTP {resp.status_code}"
        })
    except Exception as e:
        result["status"], result["details"] = classify_error(e)
    
    return result

async def check_domain(domain: str, client_pool: HTTPClientPool) -> dict:
    """Полная проверка домена по всем этапам."""
    global SHUTDOWN_REQUESTED
    
    if SHUTDOWN_REQUESTED:
        return {"domain": domain, "status": "TIMEOUT", "details": "Shutdown"}
    
    pipeline_order = get_config_value("pipeline", "pipeline_order", default=[])
    max_retries = get_config_value("network", "retries", default=1)
    retriable = set(get_config_value("error_classification", "retriable_statuses", default=[]))
    
    for step in pipeline_order:
        for attempt in range(max_retries + 1):
            if step == "curl_cffi/H2":
                result = await check_curl_cffi(client_pool, f"https://{domain}", use_http3=False)
            elif step == "curl_cffi/H3":
                result = await check_curl_cffi(client_pool, f"https://{domain}", use_http3=True)
            elif step == "httpx/H2":
                result = await check_httpx(client_pool, f"https://{domain}", http2=True)
            elif step == "httpx/H1.1":
                result = await check_httpx(client_pool, f"https://{domain}", http2=False)
            elif step == "httpx/H1.0" and get_config_value("pipeline", "http_fallback"):
                result = await check_httpx(client_pool, f"http://{domain}", http2=False)
            else:
                continue
            
            result["method"] = step
            if result["status"] == "OK":
                return result
            
            if result["status"] in retriable and attempt < max_retries:
                await asyncio.sleep(0.5 * (attempt + 1))
                continue
            break
    
    return {"domain": domain, "status": "UNKNOWN", "details": "All methods failed"}

async def run_checker(domains: List[str], use_custom_dns: bool, dns_servers: list, args_override: argparse.Namespace) -> Dict:
    """Запускает проверку всех доменов."""
    global SHUTDOWN_REQUESTED
    
    results = {}
    network_config = get_config_value("network", default={})
    concurrency = args_override.concurrency or network_config.get("concurrency", 5)
    verbose = not (args_override.quiet or get_config_value("logging", "quiet"))
    jitter = args_override.jitter or network_config.get("jitter", 0.1)
    
    # DNS проверка
    print(f"🔍 DNS резолв ({len(domains)} доменов)...")
    sem = asyncio.Semaphore(concurrency * 2)
    
    async def resolve(d):
        async with sem:
            return d, await check_dns(d, use_custom_dns, dns_servers)
    
    dns_tasks = [resolve(d) for d in domains]
    for coro in asyncio.as_completed(dns_tasks):
        if SHUTDOWN_REQUESTED:
            break
        domain, ok = await coro
        if not ok:
            results[domain] = {"domain": domain, "status": "DNS_ERR", "details": "DNS failed"}
    
    http_domains = [d for d in domains if d not in results]
    if not http_domains:
        return results
    
    print(f"🔍 HTTP проверка ({len(http_domains)} доменов)...")
    client_pool = HTTPClientPool()
    
    try:
        sem = asyncio.Semaphore(concurrency)
        
        async def check_with_semaphore(d):
            async with sem:
                if jitter > 0:
                    await asyncio.sleep(random.uniform(0, jitter))
                return await check_domain(d, client_pool)
        
        tasks = [check_with_semaphore(d) for d in http_domains]
        completed = 0
        show_every = get_config_value("logging", "show_progress_every", default=100)
        
        for coro in asyncio.as_completed(tasks):
            if SHUTDOWN_REQUESTED:
                break
            result = await coro
            results[result["domain"]] = result
            completed += 1
            
            if verbose and completed % show_every == 0:
                print(f"  → Прогресс: {completed}/{len(http_domains)}")
    finally:
        await client_pool.close()
    
    return results

def save_whitelist(domains: List[str], operator: str):
    """Сохраняет whitelist."""
    out_dir = get_config_value("paths", "output_directory", default="../build/domains_checked")
    out_path = PROJECT_ROOT / out_dir
    ts = datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
    path = out_path / f"whitelist-{ts}-{operator}.txt"
    out_path.mkdir(parents=True, exist_ok=True)
    
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(domains) + '\n')
    print(f"💾 Сохранено: {path}")

def select_operator() -> str:
    """Выбор оператора из конфига."""
    operators = get_config_value("operators", default={"1": "Default"})
    print("\n📱 Выберите оператора:")
    for k, v in operators.items():
        print(f"  {k}. {v}")
    
    while True:
        choice = input("Введите номер: ").strip()
        if choice in operators:
            return operators[choice]
        print("❌ Неверный ввод")

async def main():
    """Главная функция."""
    global CONFIG
    CONFIG = load_config()
    
    # Настройка обработчиков сигналов
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    parser = argparse.ArgumentParser(description="Проверка доменов на доступность")
    parser.add_argument("directory", nargs="?", help="Директория с доменами (переопределяет config)")
    parser.add_argument("-c", "--concurrency", type=int, help="Количество одновременных запросов")
    parser.add_argument("-q", "--quiet", action="store_true", help="Тихий режим")
    parser.add_argument("--dns", nargs="+", help="Свои DNS серверы")
    parser.add_argument("--jitter", type=float, help="Случайная задержка")
    parser.add_argument("--retries", type=int, help="Количество ретраев")
    parser.add_argument("--verify-ssl", action="store_true", help="Проверять SSL")
    parser.add_argument("--update-fingerprints", action="store_true", help="Обновить отпечатки curl_cffi")
    parser.add_argument("--show-config", action="store_true", help="Показать текущую конфигурацию")
    
    args = parser.parse_args()
    
    # Специальные режимы
    if args.show_config:
        print(json.dumps(CONFIG, indent=2, ensure_ascii=False))
        return
    
    if args.update_fingerprints:
        await update_curl_cffi_fingerprints(force=True)
        return
    
    # Получаем параметры с учётом переопределения через CLI
    domains_dir = args.directory or get_config_value("paths", "domains_directory", default="../src/domains")
    files = get_files_to_process(domains_dir)
    
    if not files:
        print("❌ Нет файлов с доменами")
        sys.exit(1)
    
    domains = load_domains(files)
    print(f"📋 Загружено доменов: {len(domains)}")
    
    # Запуск проверки
    results = await run_checker(domains, bool(args.dns), args.dns or [], args)
    
    # Статистика
    ok_domains = [d for d, r in results.items() if r.get("status") == "OK"]
    stats = {}
    for r in results.values():
        stats[r.get("status", "UNKNOWN")] = stats.get(r.get("status", "UNKNOWN"), 0) + 1
    
    print(f"\n✅ Успешно: {len(ok_domains)}/{len(domains)}")
    print("\n📊 Статистика:")
    for status, count in sorted(stats.items(), key=lambda x: -x[1]):
        icon = ICONS.get(status, "❓")
        print(f"  {icon} {status}: {count}")
    
    # Сохранение результатов
    if ok_domains:
        operator = select_operator()
        save_whitelist(ok_domains, operator)
    
    # Советы
    if stats.get("BOT_BLOCK"):
        print("\n🤖 Обнаружена блокировка ботов — попробуйте обновить отпечатки:")
        print("   python check-domains.py --update-fingerprints (на машине без блокировок)")
    if stats.get("TIMEOUT", 0) > len(domains) * 0.3:
        print("\n⚠️  Много таймаутов — попробуйте уменьшить concurrency или увеличить таймауты в конфиге")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Завершено")
        sys.exit(0)