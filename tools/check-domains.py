#!/usr/bin/env python3
"""
Проверка доменов на доступность при обходе блокировок.
Все параметры конфигурации берутся из configs/check-domains.json

Обновление отпечатков curl_cffi выполняется через pip:
    pip install --upgrade curl_cffi

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
        print("\n⚠️  Получен сигнал завершения, останавливаюсь...")

def load_config() -> Dict[str, Any]:
    """Загружает конфигурацию из JSON файла."""
    if not CONFIG_FILE.exists():
        print(f"❌ Файл конфигурации не найден: {CONFIG_FILE}")
        print("\nСоздайте configs/check-domains.json с содержимым:")
        print("""
{
  "network": {
    "timeout_total": 15,
    "timeout_dns": 10,
    "concurrency": 5,
    "retries": 1,
    "jitter": 0.1,
    "verify_ssl": false
  },
  "pipeline": {
    "use_impersonate": true,
    "http_fallback": true,
    "pipeline_order": ["curl_cffi/H2", "httpx/H2", "httpx/H1.1", "httpx/H1.0"]
  },
  "curl_cffi": {
    "enabled": true,
    "default_impersonate": "chrome"
  },
  "headers": {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
  },
  "paths": {
    "domains_directory": "../src/domains",
    "output_directory": "../build/domains_checked",
    "exclude_categories": []
  },
  "operators": {
    "1": "Megafon", "2": "Beeline", "3": "MTS", "4": "Tele2", "5": "Yota", "6": "RT"
  }
}
        """)
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

def show_version_info():
    """Показывает информацию о версиях."""
    print(f"\n📦 Версия curl_cffi: {curl_cffi_version}")
    print(f"📦 Версия httpx: {httpx.__version__}")
    
    # Проверяем доступные отпечатки
    if USE_CURL_CFFI:
        print("\n🔐 Доступные отпечатки (установлены в библиотеке):")
        print("   chrome, chrome_android, safari, firefox и др.")
        print("\n💡 Для обновления отпечатков выполните:")
        print("   pip install --upgrade curl_cffi")

def classify_error(error: Exception) -> Tuple[str, str]:
    """Классификация ошибок."""
    err_str = str(error).lower()
    
    if isinstance(error, socket.gaierror): 
        return "DNS_ERR", "DNS resolution failed"
    if isinstance(error, (httpx.ConnectTimeout, httpx.ReadTimeout, asyncio.TimeoutError)):
        return "TIMEOUT", "Timeout"
    if isinstance(error, OSError):
        if "refused" in err_str: 
            return "PORT_BLOCK", "Connection refused"
        if "reset" in err_str: 
            return "RST", "Connection reset"
    if isinstance(error, httpx.HTTPStatusError):
        code = error.response.status_code
        if code in (403, 429, 503): 
            return "BOT_BLOCK", f"HTTP {code}"
        return "HTTP_ERR", f"HTTP {code}"
    
    return "UNKNOWN", str(error)[:100]

def extract_domain(line: str) -> str:
    """Извлекает домен из строки."""
    line = line.strip()
    if not line or line.startswith('#'): 
        return ""
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
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    domain = extract_domain(line)
                    if domain and domain not in seen:
                        seen.add(domain)
                        domains.append(domain)
        except Exception as e:
            print(f"⚠️ Ошибка чтения {filepath}: {e}")
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
            self.impersonate = curl_config.get("default_impersonate", "chrome")
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
                    headers=headers,
                    limits=httpx.Limits(max_keepalive_connections=20)
                )
            return self.clients[key]
    
    async def get_curl(self) -> Optional[CurlCffiSession]:
        if not USE_CURL_CFFI or not get_config_value("curl_cffi", "enabled", default=True):
            return None
        
        async with self._lock:
            if "curl" not in self.curl_clients:
                impersonate = await self.get_impersonate()
                try:
                    self.curl_clients["curl"] = CurlCffiSession(
                        impersonate=impersonate,
                        verify=self.verify_ssl,
                        timeout=self.timeout,
                        allow_redirects=True
                    )
                except Exception as e:
                    print(f"⚠️ Ошибка создания curl_cffi сессии: {e}")
                    return None
            return self.curl_clients["curl"]
    
    async def close(self):
        """Закрывает все клиенты."""
        async with self._lock:
            for client in self.clients.values():
                await client.aclose()
            self.clients.clear()
            
            for client in self.curl_clients.values():
                try:
                    await client.close()
                except:
                    pass
            self.curl_clients.clear()

async def check_curl_cffi(client_pool: HTTPClientPool, url: str) -> dict:
    """Проверка через curl_cffi."""
    domain = url.split("://")[1].split('/')[0]
    start = time.time()
    result = {"domain": domain, "status": "", "code": 0, "rtt_ms": 0, "details": "", "method": "H2"}
    
    try:
        client = await client_pool.get_curl()
        if not client:
            raise Exception("curl_cffi not available")
        
        resp = await client.get(url, timeout=get_config_value("network", "timeout_total"))
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
    
    pipeline_order = get_config_value("pipeline", "pipeline_order", default=["curl_cffi/H2", "httpx/H2", "httpx/H1.1"])
    max_retries = get_config_value("network", "retries", default=1)
    retriable = ["TIMEOUT", "PORT_BLOCK", "SSL_ERR", "TLS_ERR", "UNKNOWN", "RST"]
    http_fallback = get_config_value("pipeline", "http_fallback", default=True)
    use_impersonate = get_config_value("pipeline", "use_impersonate", default=True)
    
    for step in pipeline_order:
        # Пропускаем impersonate если отключен
        if step.startswith("curl_cffi") and not use_impersonate:
            continue
        # Пропускаем HTTP fallback если отключен
        if step == "httpx/H1.0" and not http_fallback:
            continue
            
        for attempt in range(max_retries + 1):
            if step == "curl_cffi/H2":
                result = await check_curl_cffi(client_pool, f"https://{domain}")
            elif step == "httpx/H2":
                result = await check_httpx(client_pool, f"https://{domain}", http2=True)
            elif step == "httpx/H1.1":
                result = await check_httpx(client_pool, f"https://{domain}", http2=False)
            elif step == "httpx/H1.0":
                result = await check_httpx(client_pool, f"http://{domain}", http2=False)
            else:
                continue
            
            if result["status"] == "OK":
                return result
            
            if result["status"] in retriable and attempt < max_retries:
                await asyncio.sleep(0.5 * (attempt + 1))
                continue
            break
    
    return {"domain": domain, "status": "UNKNOWN", "details": "All methods failed"}

async def run_checker(domains: List[str], use_custom_dns: bool, dns_servers: list, concurrency: int, quiet: bool) -> Dict:
    """Запускает проверку всех доменов."""
    global SHUTDOWN_REQUESTED
    
    results = {}
    show_every = 100
    jitter = get_config_value("network", "jitter", default=0.1)
    
    # DNS проверка
    print(f"🔍 DNS резолв ({len(domains)} доменов)...")
    sem = asyncio.Semaphore(concurrency * 2)
    
    async def resolve(d):
        async with sem:
            if SHUTDOWN_REQUESTED:
                return d, False
            return d, await check_dns(d, use_custom_dns, dns_servers)
    
    dns_tasks = [resolve(d) for d in domains]
    resolved_domains = []
    
    for i, coro in enumerate(asyncio.as_completed(dns_tasks), 1):
        if SHUTDOWN_REQUESTED:
            break
        domain, ok = await coro
        if ok:
            resolved_domains.append(domain)
        else:
            results[domain] = {"domain": domain, "status": "DNS_ERR", "details": "DNS failed"}
        if not quiet and i % show_every == 0:
            print(f"  → DNS прогресс: {i}/{len(domains)}")
    
    print(f"  ✅ Резолвится: {len(resolved_domains)} | ❌ Не резолвится: {len(domains) - len(resolved_domains)}")
    
    if not resolved_domains:
        return results
    
    print(f"🔍 HTTP проверка ({len(resolved_domains)} доменов)...")
    client_pool = HTTPClientPool()
    
    try:
        sem = asyncio.Semaphore(concurrency)
        
        async def check_with_semaphore(d):
            async with sem:
                if jitter > 0:
                    await asyncio.sleep(random.uniform(0, jitter))
                return await check_domain(d, client_pool)
        
        tasks = [check_with_semaphore(d) for d in resolved_domains]
        completed = 0
        
        for coro in asyncio.as_completed(tasks):
            if SHUTDOWN_REQUESTED:
                break
            result = await coro
            results[result["domain"]] = result
            completed += 1
            
            if not quiet and completed % show_every == 0:
                print(f"  → HTTP прогресс: {completed}/{len(resolved_domains)}")
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
    parser.add_argument("-e", "--exclude", nargs="+", default=[], help="Исключить категории")
    parser.add_argument("--dns", nargs="+", help="Свои DNS серверы")
    parser.add_argument("--jitter", type=float, help="Случайная задержка")
    parser.add_argument("--retries", type=int, help="Количество ретраев")
    parser.add_argument("--verify-ssl", action="store_true", help="Проверять SSL")
    parser.add_argument("--no-impersonate", action="store_true", help="Отключить impersonate")
    parser.add_argument("--no-http-fallback", action="store_true", help="Отключить HTTP fallback")
    parser.add_argument("--version", action="store_true", help="Показать версии библиотек")
    parser.add_argument("--show-config", action="store_true", help="Показать конфигурацию")
    
    args = parser.parse_args()
    
    # Специальные режимы
    if args.version:
        show_version_info()
        return
    
    if args.show_config:
        print(json.dumps(CONFIG, indent=2, ensure_ascii=False))
        return
    
    # Получаем параметры с учётом переопределения через CLI
    domains_dir = args.directory or get_config_value("paths", "domains_directory", default="../src/domains")
    
    # Временно обновляем exclude категории из CLI
    if args.exclude:
        CONFIG["paths"]["exclude_categories"] = args.exclude
    
    files = get_files_to_process(domains_dir)
    
    if not files:
        print("❌ Нет файлов с доменами")
        sys.exit(1)
    
    print(f"📁 Файлы для обработки: {', '.join([f.name for f in files])}")
    domains = load_domains(files)
    print(f"📋 Загружено доменов: {len(domains)}")
    
    # Определяем параметры запуска
    concurrency = args.concurrency or get_config_value("network", "concurrency", default=5)
    quiet = args.quiet or False
    
    # Временно обновляем конфиг для текущей сессии
    if args.verify_ssl:
        CONFIG["network"]["verify_ssl"] = True
    if args.no_impersonate:
        CONFIG["pipeline"]["use_impersonate"] = False
    if args.no_http_fallback:
        CONFIG["pipeline"]["http_fallback"] = False
    if args.retries:
        CONFIG["network"]["retries"] = args.retries
    if args.jitter:
        CONFIG["network"]["jitter"] = args.jitter
    
    # Вывод активной конфигурации
    if not quiet:
        print(f"⚙️  Конфигурация запуска:")
        print(f"   Concurrency: {concurrency}")
        print(f"   Impersonate: {'✅' if get_config_value('pipeline', 'use_impersonate', default=True) else '❌'}")
        print(f"   HTTP fallback: {'✅' if get_config_value('pipeline', 'http_fallback', default=True) else '❌'}")
        print(f"   Verify SSL: {'✅' if CONFIG['network']['verify_ssl'] else '❌'}")
        print(f"   Retries: {CONFIG['network']['retries']}")
        print(f"   Jitter: {CONFIG['network']['jitter']}s")
        print("-" * 50)
    
    # Запуск проверки
    results = await run_checker(domains, bool(args.dns), args.dns or [], concurrency, quiet)
    
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
    if stats.get("BOT_BLOCK", 0) > 0:
        print("\n🤖 Обнаружена блокировка ботов. Попробуйте обновить curl_cffi:")
        print("   pip install --upgrade curl_cffi")
    
    if stats.get("TIMEOUT", 0) > len(domains) * 0.3:
        print("\n⚠️  Много таймаутов — попробуйте уменьшить concurrency или увеличить таймауты в конфиге")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Завершено")
        sys.exit(0)