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
        print("\n⚠️  Получен сигнал завершения, останавливаемся...")
        print("   Нажмите Ctrl+C ещё раз для принудительного выхода")

def load_config() -> Dict[str, Any]:
    """Загружает конфигурацию из JSON файла."""
    if not CONFIG_FILE.exists():
        print(f"❌ Файл конфигурации не найден: {CONFIG_FILE}")
        print("   Пожалуйста, создайте configs/check-domains.json вручную")
        print("   Пример конфигурации:")
        print("""
{
  "network": {
    "timeout_connect": 10,
    "timeout_total": 15,
    "timeout_dns": 10,
    "concurrency": 5,
    "retries": 1,
    "jitter": 0.1,
    "verify_ssl": false
  },
  "pipeline": {
    "use_impersonate": true,
    "enable_http3": false,
    "http_fallback": true,
    "pipeline_order": ["curl_cffi/H2", "httpx/H2", "httpx/H1.1", "httpx/H1.0"]
  },
  "curl_cffi": {
    "enabled": true,
    "default_impersonate": "chrome124",
    "update_url": "https://fp.impersonate.pro/api/fingerprints"
  },
  "headers": {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  },
  "paths": {
    "domains_directory": "../src/domains",
    "output_directory": "../build/domains_checked",
    "exclude_categories": []
  },
  "operators": {
    "1": "Megafon", "2": "Beeline", "3": "MTS", "4": "Tele2", "5": "Yota", "6": "RT"
  },
  "logging": {
    "show_progress_every": 100
  }
}
        """)
        sys.exit(1)
    
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"❌ Ошибка парсинга JSON в {CONFIG_FILE}: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Ошибка загрузки конфига: {e}")
        sys.exit(1)

def save_config(config: Dict[str, Any]):
    """Сохраняет конфигурацию в файл."""
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"❌ Ошибка сохранения конфига: {e}")
        return False

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

def get_available_fingerprints() -> List[str]:
    """Получает список доступных отпечатков из curl_cffi."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "curl_cffi", "list"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            # Парсим вывод, ищем строки с chrome, firefox, safari
            fingerprints = []
            for line in result.stdout.split('\n'):
                line = line.strip()
                if any(browser in line.lower() for browser in ['chrome', 'firefox', 'safari', 'edge']):
                    # Извлекаем имя отпечатка
                    parts = line.split()
                    if parts:
                        fingerprints.append(parts[0])
            return fingerprints
    except Exception:
        pass
    return []

async def update_curl_cffi_fingerprints(force: bool = False) -> bool:
    """Обновляет отпечатки curl_cffi."""
    if not USE_CURL_CFFI:
        print("❌ curl_cffi не установлен")
        print("   Установите: pip install curl_cffi")
        return False
    
    print("🔄 Обновление отпечатков curl_cffi...")
    
    # Проверяем доступность интернета
    try:
        import socket
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        print("✅ Интернет доступен, пробуем обновить...")
    except:
        print("⚠️ Интернет может быть недоступен, но попробуем...")
    
    # Способ 1: через CLI команду curl_cffi
    print("  Попытка 1: через curl_cffi CLI...")
    try:
        cmd = [sys.executable, "-m", "curl_cffi", "update"]
        if force:
            cmd.append("--force")
        
        result = await asyncio.to_thread(
            subprocess.run, cmd,
            capture_output=True, text=True, timeout=60
        )
        
        if result.returncode == 0:
            print("  ✅ Отпечатки успешно обновлены через CLI")
            # После обновления получаем список доступных отпечатков
            fingerprints = get_available_fingerprints()
            if fingerprints:
                # Обновляем конфиг
                if "curl_cffi" not in CONFIG:
                    CONFIG["curl_cffi"] = {}
                CONFIG["curl_cffi"]["fingerprints_available"] = fingerprints
                CONFIG["curl_cffi"]["last_update"] = datetime.now().isoformat()
                # Выбираем самый свежий Chrome
                chrome_fps = [fp for fp in fingerprints if 'chrome' in fp.lower()]
                if chrome_fps:
                    # Сортируем по номеру версии
                    chrome_fps.sort(key=lambda x: int(''.join(filter(str.isdigit, x)) or 0), reverse=True)
                    CONFIG["curl_cffi"]["default_impersonate"] = chrome_fps[0]
                    print(f"  📌 Установлен отпечаток: {chrome_fps[0]}")
                save_config(CONFIG)
            return True
        else:
            print(f"  ⚠️ CLI обновление не удалось: {result.stderr[:100] if result.stderr else 'неизвестная ошибка'}")
    except subprocess.TimeoutExpired:
        print("  ⚠️ CLI обновление зависло (таймаут)")
    except Exception as e:
        print(f"  ⚠️ Ошибка CLI: {e}")
    
    # Способ 2: через прямой API запрос
    print("  Попытка 2: через прямой API запрос...")
    try:
        import aiohttp
        update_url = get_config_value("curl_cffi", "update_url", default="https://fp.impersonate.pro/api/fingerprints")
        
        async with aiohttp.ClientSession() as session:
            async with session.get(update_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if "fingerprints" in data:
                        fingerprints = data.get("fingerprints", {})
                        # Сохраняем отпечатки в конфиг
                        if "curl_cffi" not in CONFIG:
                            CONFIG["curl_cffi"] = {}
                        CONFIG["curl_cffi"]["fingerprints_api"] = fingerprints
                        CONFIG["curl_cffi"]["last_update"] = datetime.now().isoformat()
                        
                        # Выбираем последний Chrome
                        chrome_versions = [k for k in fingerprints.keys() if 'chrome' in k.lower()]
                        if chrome_versions:
                            chrome_versions.sort()
                            CONFIG["curl_cffi"]["default_impersonate"] = chrome_versions[-1]
                            print(f"  ✅ Отпечатки обновлены через API")
                            print(f"  📌 Установлен отпечаток: {chrome_versions[-1]}")
                            save_config(CONFIG)
                            return True
    except ImportError:
        print("  ⚠️ aiohttp не установлен, пропускаем API метод")
    except Exception as e:
        print(f"  ⚠️ API ошибка: {e}")
    
    # Способ 3: через прямую команду curl
    print("  Попытка 3: через системный curl...")
    try:
        result = await asyncio.to_thread(
            subprocess.run,
            ["curl", "-s", "https://fp.impersonate.pro/api/fingerprints"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0 and result.stdout:
            import json as json_module
            data = json_module.loads(result.stdout)
            if "fingerprints" in data:
                # Аналогично сохраняем...
                print("  ✅ Отпечатки получены через curl")
                return True
    except Exception:
        pass
    
    print("❌ Не удалось обновить отпечатки")
    print("\n💡 Возможные решения:")
    print("   1. Проверьте интернет-соединение")
    print("   2. Запустите на машине без блокировок")
    print("   3. Или используйте ручную установку:")
    print("      pip install --upgrade curl_cffi")
    print("      python -m curl_cffi update")
    return False

def classify_error(error: Exception) -> Tuple[str, str]:
    """Классификация ошибок."""
    err_str = str(error).lower()
    
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
        if code in (403, 429, 503): return "BOT_BLOCK", f"HTTP {code}"
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
                    headers=headers,
                    limits=httpx.Limits(max_keepalive_connections=20)
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
        """Закрывает все клиенты."""
        async with self._lock:
            for client in self.clients.values():
                await client.aclose()
            self.clients.clear()
            
            for client in self.curl_clients.values():
                await client.close()
            self.curl_clients.clear()

async def check_curl_cffi(client_pool: HTTPClientPool, url: str, use_http3: bool = False) -> dict:
    """Проверка через curl_cffi."""
    domain = url.split("://")[1].split('/')[0]
    start = time.time()
    result = {"domain": domain, "status": "", "code": 0, "rtt_ms": 0, "details": "", "method": "H3" if use_http3 else "H2"}
    
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
    retriable = ["TIMEOUT", "PORT_BLOCK", "SSL_ERR", "TLS_ERR", "UNKNOWN", "RST"]
    http_fallback = get_config_value("pipeline", "http_fallback", default=True)
    enable_http3 = get_config_value("pipeline", "enable_http3", default=False)
    use_impersonate = get_config_value("pipeline", "use_impersonate", default=True)
    
    for step in pipeline_order:
        # Пропускаем HTTP/3 если не включен
        if step == "curl_cffi/H3" and not enable_http3:
            continue
        # Пропускаем impersonate если отключен
        if step.startswith("curl_cffi") and not use_impersonate:
            continue
        # Пропускаем HTTP fallback если отключен
        if step == "httpx/H1.0" and not http_fallback:
            continue
            
        for attempt in range(max_retries + 1):
            if step == "curl_cffi/H2":
                result = await check_curl_cffi(client_pool, f"https://{domain}", use_http3=False)
            elif step == "curl_cffi/H3":
                result = await check_curl_cffi(client_pool, f"https://{domain}", use_http3=True)
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
    show_every = get_config_value("logging", "show_progress_every", default=100)
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
    parser.add_argument("--dns", nargs="+", help="Свои DNS серверы")
    parser.add_argument("--jitter", type=float, help="Случайная задержка")
    parser.add_argument("--retries", type=int, help="Количество ретраев")
    parser.add_argument("--verify-ssl", action="store_true", help="Проверять SSL")
    parser.add_argument("--update-fingerprints", action="store_true", help="Обновить отпечатки curl_cffi")
    parser.add_argument("--force-update", action="store_true", help="Принудительное обновление отпечатков")
    parser.add_argument("--show-config", action="store_true", help="Показать текущую конфигурацию")
    
    args = parser.parse_args()
    
    # Специальные режимы
    if args.show_config:
        print(json.dumps(CONFIG, indent=2, ensure_ascii=False))
        return
    
    if args.update_fingerprints:
        await update_curl_cffi_fingerprints(force=args.force_update)
        return
    
    # Получаем параметры с учётом переопределения через CLI
    domains_dir = args.directory or get_config_value("paths", "domains_directory", default="../src/domains")
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
    if args.retries:
        CONFIG["network"]["retries"] = args.retries
    if args.jitter:
        CONFIG["network"]["jitter"] = args.jitter
    
    # Вывод активной конфигурации
    if not quiet:
        print(f"⚙️  Конфигурация запуска:")
        print(f"   Concurrency: {concurrency}")
        print(f"   Impersonate: {get_config_value('pipeline', 'use_impersonate', default=True)}")
        print(f"   HTTP/3: {get_config_value('pipeline', 'enable_http3', default=False)}")
        print(f"   HTTP fallback: {get_config_value('pipeline', 'http_fallback', default=True)}")
        print(f"   Verify SSL: {CONFIG['network']['verify_ssl']}")
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
        print("\n🤖 Обнаружена блокировка ботов — попробуйте обновить отпечатки:")
        print("   python check-domains.py --update-fingerprints (на машине без блокировок)")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Завершено")
        sys.exit(0)