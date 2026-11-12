#!/usr/bin/env python3
"""
Проверка доменов на доступность при обходе блокировок.
Все настройки берутся из configs/check-domains.json

Что проверяется: для каждого адреса домена (все A/AAAA) выполняется
многоэтапная HTTP-проба. Проба привязана к адресу: соединение идёт на него,
а SNI и заголовок Host остаются доменом — иначе проверялся бы адрес,
который выберет системный резолвер. Домен считается доступным, если хотя бы
один адрес ответил. Отдельно детектируется подмена ответа фильтром.

Зависимости: pip install curl_cffi httpx aiodns tqdm cryptography
"""
import asyncio
import sys
import time
import socket
import ssl
import random
import argparse
import logging
import re
import signal
import json
from datetime import datetime
from typing import List, Tuple, Dict, Set, Optional, Any
from pathlib import Path
from urllib.parse import urljoin

try:
    from curl_cffi.requests import AsyncSession as CurlCffiSession
    from curl_cffi import __version__ as curl_cffi_version
    USE_CURL_CFFI = True
    try:
        from curl_cffi import CurlOpt
        CURL_RESOLVE = hasattr(CurlOpt, "RESOLVE")
    except ImportError:
        CurlOpt = None
        CURL_RESOLVE = False
except ImportError:
    USE_CURL_CFFI = False
    curl_cffi_version = "not installed"
    CurlOpt = None
    CURL_RESOLVE = False

import httpx
import aiodns

try:
    import httpcore  # зависимость httpx; нужен, чтобы привязать пробу к адресу
    HTTPCORE_AVAILABLE = True
except ImportError:
    httpcore = None
    HTTPCORE_AVAILABLE = False

try:
    from cryptography import x509
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

    class tqdm:
        def __init__(self, *args, **kwargs): pass
        def update(self, *args, **kwargs): pass
        def close(self, *args, **kwargs): pass

for name in ('httpx', 'httpcore', 'aiodns', 'asyncio', 'curl_cffi'):
    logging.getLogger(name).setLevel(logging.CRITICAL)

import platform_support as plat  # noqa: E402

SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
CONFIG_DIR = PROJECT_ROOT / "configs"
CONFIG_FILE = CONFIG_DIR / "check-domains.json"

SHUTDOWN_REQUESTED = False
CONFIG: Dict[str, Any] = {}

ICONS = {
    "OK": "✅", "RST": "❌", "TIMEOUT": "🕐",
    "SSL_ERR": "🔐", "HTTP_ERR": "⚠️", "DNS_ERR": "🌐",
    "UNKNOWN": "❌", "DPI_BLOCK": "🔒", "UNREACH": "🚫", "BOT_BLOCK": "🤖",
    "TLS_ERR": "🔐", "HTTP2_ERR": "⚠️", "PORT_BLOCK": "🚧",
    "INTERRUPTED": "⏹️", "SUSPECT_STUB": "🎭", "SUSPECT_REDIRECT": "↪️",
    "SITE_CERT_MISMATCH": "🧾", "INTERCEPT_CERT": "🛡️", "SUSPECT_EMPTY": "🕳️",
}

# Чем выше приоритет, тем «лучше» результат для домена.
STATUS_PRIORITY = {
    "OK": 100, "HTTP_ERR": 90, "BOT_BLOCK": 85,
    "SUSPECT_STUB": 70, "SUSPECT_REDIRECT": 65, "SITE_CERT_MISMATCH": 60,
    "SUSPECT_EMPTY": 58, "INTERCEPT_CERT": 55,
    "TLS_ERR": 50, "DPI_BLOCK": 45, "SSL_ERR": 40,
    "PORT_BLOCK": 35, "RST": 30, "TIMEOUT": 25, "UNREACH": 20,
    "UNKNOWN": 15, "DNS_ERR": 10, "INTERRUPTED": 0,
}
# Статусы, при которых сервер ответил: домен доступен.
ALIVE_STATUSES = {"OK", "HTTP_ERR", "BOT_BLOCK"}

# Подмена оператором: ответ пришёл, но не от сервиса. Это свидетельство
# фильтрации — ровно то, что ищем в режиме белого списка.
INTERCEPT_STATUSES = {"SUSPECT_STUB", "SUSPECT_REDIRECT", "INTERCEPT_CERT"}
# Проблема самого сайта: фильтрация тут ни при чём, домен может быть разрешён,
# но проверить его содержимое нельзя.
SITE_ISSUE_STATUSES = {"SITE_CERT_MISMATCH", "SUSPECT_EMPTY"}
SUSPECT_STATUSES = INTERCEPT_STATUSES | SITE_ISSUE_STATUSES

# Признаки оператора в издателе сертификата: значит, в соединение вклинились.
OPERATOR_ISSUER_MARKERS = ("megafon", "mts", "beeline", "vimpelcom", "tele2",
                           "rostelecom", "yota", "scartel", "t2")


def _cert_status(issuer: Optional[str]) -> str:
    """Чей сертификат: подставленный фильтром или выданный сайту.

    Эвристика: издатель с брендом оператора или без издателя — подмена
    (в мобильной сети так выглядит DPI). Сертификат от публичного УЦ на чужое
    имя — это ошибка сайта (парковка, перепутанный домен), фильтрация тут
    не участвует. Издатель всё равно пишется в details, чтобы сомнительные
    случаи можно было разобрать руками.
    """
    text = (issuer or "").strip().lower()
    if not text:
        return "INTERCEPT_CERT"
    if any(marker in text for marker in OPERATOR_ISSUER_MARKERS):
        return "INTERCEPT_CERT"
    return "SITE_CERT_MISMATCH"

# Признаки страницы-заглушки вместо запрошенного ресурса.
STUB_MARKERS = (
    "доступ к ресурсу ограничен", "доступ ограничен", "ресурс заблокирован",
    "ограничение доступа", "заблокирован в соответствии", "единый реестр",
    "по требованию роскомнадзора", "access denied by", "blocked by request",
    "zapret-info", "web-filter", "контент-фильтр", "запрещено законодательством",
)


class Settings:
    """Единое место расчёта параметров (раньше дублировалось в main и run_checker)."""

    def __init__(self, args: argparse.Namespace):
        network = get_config_value("network", default={})
        pipeline = get_config_value("pipeline", default={})
        logging_conf = get_config_value("logging", default={})

        override = getattr(args, "timeout", None)
        self.timeout_total = float(override if override is not None else network.get("timeout_total", 15))
        self.timeout_dns = float(override if override is not None else network.get("timeout_dns", 10))

        def opt(cli_value, key, default):
            # 0 — валидное значение, поэтому проверяем именно на None
            return cli_value if cli_value is not None else network.get(key, default)

        self.concurrency = int(opt(args.concurrency, "concurrency", 5))
        self.jitter = float(opt(args.jitter, "jitter", 0.1))
        self.retries = int(opt(args.retries, "retries", 1))
        self.verify_ssl = bool(args.verify_ssl or network.get("verify_ssl", False))
        self.use_impersonate = (not args.no_impersonate
                                and pipeline.get("use_impersonate", True)
                                and USE_CURL_CFFI)

        # Конфиг учитывается наравне с флагом (раньше значение из конфига игнорировалось).
        self.http_fallback = (args.http_fallback if args.http_fallback is not None
                              else pipeline.get("http_fallback", False))
        self.enable_http3 = (args.enable_http3 if args.enable_http3 is not None
                             else pipeline.get("enable_http3", False))

        self.verify_cert = not getattr(args, "no_verify_cert", False)
        self.detect_stub = not getattr(args, "no_stub_detect", False)
        self.keep_redirects = not getattr(args, "no_keep_redirects", False)

        self.interface = (getattr(args, "interface", None) or "").strip()
        self.impersonate = get_config_value("curl_cffi", "default_impersonate", default="chrome124")
        self.headers = get_config_value("headers", default={})
        self.retriable = set(get_config_value("error_classification", "retriable_statuses",
                                              default=["TIMEOUT", "PORT_BLOCK", "SSL_ERR",
                                                       "TLS_ERR", "UNKNOWN", "RST"]))
        self.show_progress_every = int(logging_conf.get("show_progress_every", 100))
        self.verbose = not (args.quiet or logging_conf.get("quiet", False))
        self.limit = int(getattr(args, "limit", 0) or 0)


def signal_handler(signum, frame):
    global SHUTDOWN_REQUESTED
    if not SHUTDOWN_REQUESTED:
        SHUTDOWN_REQUESTED = True
        print("\n⚠️  Получен сигнал завершения, останавливаемся...")


def load_config() -> Dict[str, Any]:
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
    fingerprints = get_config_value("curl_cffi", "fingerprints", default={})
    valid_values = set(fingerprints.values())
    if valid_values and impersonate not in valid_values:
        print(f"⚠️  Внимание: отпечаток '{impersonate}' не найден в списке fingerprints")
        print(f"   Доступные отпечатки: {', '.join(sorted(valid_values))}")
        return False
    return True


def classify_error(error: BaseException) -> Tuple[str, str]:
    """Классификация ошибок.

    Строки приводятся к нижнему регистру ОДИН раз, поэтому все сравнения ниже
    тоже в нижнем регистре (раньше 'TLSV1_ALERT' и 'OPENSSL_internal'
    сравнивались с уже приведённой строкой и никогда не срабатывали).
    """
    err_str = str(error).lower()
    err_repr = repr(error).lower()
    curl_code = None
    m = re.search(r'curl:\s*\((\d+)\)', err_str)
    if m:
        curl_code = int(m.group(1))

    if curl_code is not None:
        if curl_code == 6:
            return "DNS_ERR", "Could not resolve host"
        if curl_code == 35:
            if "invalid library" in err_str or "openssl_internal" in err_repr:
                return "TLS_ERR", "TLS stack mismatch"
            if "tlsv1_alert" in err_str and "internal_error" in err_str:
                return "DPI_BLOCK", "Server rejected TLS handshake"
            return "SSL_ERR", "SSL/TLS handshake error"
        if curl_code == 28:
            return "TIMEOUT", "Operation timed out"
        if curl_code == 7:
            if "connection refused" in err_str:
                return "PORT_BLOCK", "Connection refused"
            return "TIMEOUT", "Could not connect"
        if curl_code == 47:
            return "HTTP_ERR", "Too many redirects"
        if curl_code == 52:
            return "RST", "Server returned nothing"
        return "UNKNOWN", f"curl error {curl_code}"

    if isinstance(error, socket.gaierror):
        return "DNS_ERR", "Domain not resolved"
    if isinstance(error, (asyncio.TimeoutError, TimeoutError)):
        return "TIMEOUT", "Request timed out"
    if isinstance(error, ssl.SSLError):
        return "SSL_ERR", f"SSL/TLS error: {error.reason or error}"
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
    return "UNKNOWN", f"{type(error).__name__}: {error}"


# Кириллица и дефисы допустимы внутри меток: в данных есть яндекс.рф, мвд.рф,
# а также punycode вида xn--80afnfom.xn--80ahmohdapg.xn--80asehdb.
_D_LABEL = r'[a-z0-9\u0400-\u04ff]'
_D_INNER = r'[a-z0-9\u0400-\u04ff-]'
def _record_host(rr: Any) -> Optional[str]:
    """Адрес из записи DNS в любом из известных форматов.

    aiodns 3.x: records с полем host/address.
    aiodns 4.x: DNSRecord, адрес во вложенном .data (.addr или .target).
    pycares: тоже .host.
    """
    for attr in ("host", "address"):
        value = getattr(rr, attr, None)
        if value:
            return str(value)
    data = getattr(rr, "data", None)
    if data is not None:
        for attr in ("addr", "target", "address"):
            value = getattr(data, attr, None)
            if value:
                return str(value)
    return None


DOMAIN_RE = re.compile(
    r'^(?!-)'
    + r'(?:' + _D_LABEL + r'(?:' + _D_INNER + r'{0,61}' + _D_LABEL + r')?\.)+'
    + _D_LABEL + r'(?:' + _D_INNER + r'{0,61}' + _D_LABEL + r')?$'
)


def extract_domain(line: str) -> str:
    """Извлекает домен и отбрасывает мусор (раньше в проверку уходило всё)."""
    line = line.strip()
    if not line or line.startswith('#'):
        return ""
    value = line.replace('https://', '').replace('http://', '')
    value = value.split('/')[0].split('?')[0].split('#')[0].strip()
    value = value.split(':')[0] if value.count(':') == 1 else value
    value = value.lower()
    if not value or ' ' in value or '*' in value:
        return ""
    if not DOMAIN_RE.match(value):
        return ""
    # Зона короче двух символов не существует (отсекает «test.c», но пропускает
    # punycode, где дефисы внутри метки допустимы).
    return value if len(value.rsplit('.', 1)[1]) >= 2 else ""


def load_dns_cache(path: Optional[str], extra: Optional[List[str]] = None
                   ) -> Dict[str, Any]:
    """Адреса, собранные заранее (`tools/cache_dns.py`).

    `extra` — локальный слой поверх общего кэша: общий обновляет workflow,
    а локальный дополняет его и в git не попадает.
    """
    if not path:
        return {}
    cache_path = Path(path)
    if not cache_path.is_absolute():
        cache_path = PROJECT_ROOT / cache_path
    if not cache_path.exists():
        print(f"⚠️  кэш DNS не найден: {cache_path}")
        return {}
    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"⚠️  кэш DNS не прочитан: {exc}")
        return {}
    domains = data.get("domains", data)
    if not isinstance(domains, dict):
        return {}
    domains = dict(domains)
    print(f"📦 кэш DNS: {len(domains)} доменов из {cache_path.name} "
          f"(собран {data.get('generated_at', 'неизвестно')})")
    for item in extra or []:
        overlay = Path(item)
        if not overlay.is_absolute():
            overlay = PROJECT_ROOT / overlay
        if not overlay.exists():
            continue
        try:
            layer = json.loads(overlay.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"⚠️  локальный кэш {overlay.name} не прочитан: {exc}")
            continue
        layer_domains = layer.get("domains", layer)
        if not isinstance(layer_domains, dict):
            continue
        for domain, entry in layer_domains.items():
            current = domains.get(domain)
            if not isinstance(current, dict) or not isinstance(entry, dict):
                domains[domain] = entry
                continue
            for family in ("A", "AAAA"):
                merged = list(current.get(family) or [])
                merged += [value for value in (entry.get(family) or [])
                           if value not in merged]
                current[family] = merged
        print(f"   + локальный слой {overlay.name}: {len(layer_domains)} доменов")
    return domains


def get_files_to_process(directory: str, excludes: Set[str]) -> List[Path]:
    dir_path = Path(directory)
    if not dir_path.is_dir():
        dir_path = PROJECT_ROOT / directory
        if not dir_path.is_dir():
            print(f"❌ Директория '{directory}' не найдена")
            sys.exit(1)
    return sorted([f for f in dir_path.iterdir() if f.is_file() and f.stem not in excludes])


def load_domains_from_files(files: List[Path]) -> Tuple[List[str], int]:
    domains, seen, skipped = [], set(), 0
    for filepath in files:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                raw = line.strip()
                if not raw or raw.startswith('#'):
                    continue
                domain = extract_domain(raw)
                if not domain:
                    skipped += 1
                    continue
                if domain not in seen:
                    seen.add(domain)
                    domains.append(domain)
    return domains, skipped


class Resolver:
    """Один резолвер на прогон; отдаёт ВСЕ A и AAAA (раньше — только первый адрес и только A).

    Кэш адресов (`tools/cache_dns.py`) здесь так же важен, как в проверке пар:
    в режиме белого списка DNS оператора не отвечает на домены вне списка,
    и адрес просто неизвестен. Без кэша HTTP-шаг видит DNS_ERR и меряет не
    фильтрацию, а наличие DNS.
    """

    def __init__(self, dns_servers: List[str], timeout: float,
                 cache: Optional[Dict[str, Any]] = None, cache_only: bool = False):
        self.dns_servers = dns_servers
        self.timeout = timeout
        self.cache = cache or {}
        self.cache_only = cache_only
        self._aiodns = None  # создаётся внутри работающего цикла

    async def addresses(self, domain: str) -> Tuple[List[str], List[str]]:
        entry = self.cache.get(domain)
        if isinstance(entry, dict):
            cached = (list(entry.get("A") or []), list(entry.get("AAAA") or []))
            if self.cache_only or cached[0] or cached[1]:
                return cached
        if self.cache_only:
            return [], []
        if self.dns_servers:
            if self._aiodns is None:
                # aiodns привязывает резолвер к текущему циклу событий
                self._aiodns = aiodns.DNSResolver(nameservers=self.dns_servers)
            return await self._addresses_custom(domain)
        return await self._addresses_system(domain)

    async def _query(self, domain: str, rtype: str) -> List[str]:
        # aiodns 4.x: query_dns, aiodns 3.x: query — поддерживаем оба.
        # В 4.x метод возвращает Future, поэтому оборачиваем в корутину:
        # asyncio.wait_for ожидает именно её.
        method = getattr(self._aiodns, "query_dns", None) or self._aiodns.query

        async def call():
            result = method(domain, rtype)
            if asyncio.isfuture(result) or asyncio.iscoroutine(result):
                return await result
            return result

        try:
            answer = await asyncio.wait_for(call(), timeout=self.timeout)
            # aiodns 4.x отдаёт DNSResult (записи в .answer), 3.x — список записей
            records = getattr(answer, "answer", answer)
            hosts = []
            for rr in records or []:
                hosts.append(_record_host(rr))
            return [h for h in hosts if h]
        except (Exception, asyncio.CancelledError):
            return []

    async def _addresses_custom(self, domain: str) -> Tuple[List[str], List[str]]:
        return await self._query(domain, 'A'), await self._query(domain, 'AAAA')

    async def _addresses_system(self, domain: str) -> Tuple[List[str], List[str]]:
        loop = asyncio.get_running_loop()
        v4: List[str] = []
        v6: List[str] = []
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(domain, 443, family=socket.AF_INET, type=socket.SOCK_STREAM),
                timeout=self.timeout)
            v4 = sorted({info[4][0] for info in infos})
        except (asyncio.TimeoutError, socket.gaierror, OSError):
            pass
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(domain, 443, family=socket.AF_INET6, type=socket.SOCK_STREAM),
                timeout=self.timeout)
            v6 = sorted({info[4][0] for info in infos})
        except (asyncio.TimeoutError, socket.gaierror, OSError):
            pass
        return v4, v6


if HTTPCORE_AVAILABLE:
    class _PinnedBackend(httpcore.AnyIOBackend):  # type: ignore[misc]
        """TCP-подключение к проверяемому адресу вместо адреса из DNS.

        SNI и заголовок Host остаются доменом: httpcore передаёт имя отдельно
        от адреса подключения. Без этого проба «домен + адрес» измеряет адрес,
        который выберет системный резолвер, а не тот, что указан в наблюдении.
        """

        def __init__(self, ip: str):
            self.ip = ip

        async def connect_tcp(self, host: str, port: int, timeout: Optional[float] = None,
                              local_address: Optional[str] = None,
                              socket_options: Optional[Any] = None) -> Any:
            return await super().connect_tcp(self.ip, port, timeout, local_address,
                                             socket_options)


class _BoundStream:
    """Поток для httpcore поверх asyncio с привязкой к интерфейсу."""

    def __init__(self, reader: Any, writer: Any):
        self._reader = reader
        self._writer = writer

    async def read(self, max_bytes: int, timeout: Optional[float] = None) -> bytes:
        if timeout is None:
            return await self._reader.read(max_bytes)
        return await asyncio.wait_for(self._reader.read(max_bytes), timeout)

    async def write(self, buffer: Any, timeout: Optional[float] = None) -> None:
        self._writer.write(buffer)
        if timeout is None:
            await self._writer.drain()
        else:
            await asyncio.wait_for(self._writer.drain(), timeout)

    async def aclose(self) -> None:
        try:
            self._writer.close()
            await asyncio.wait_for(self._writer.wait_closed(), timeout=1)
        except Exception:
            pass

    async def start_tls(self, ssl_context: Any, server_hostname: Optional[str] = None,
                        timeout: Optional[float] = None) -> Any:
        await self._writer.start_tls(ssl_context, server_hostname=server_hostname,
                                     ssl_handshake_timeout=timeout)
        return self

    def get_extra_info(self, info: str) -> Any:
        return self._writer.get_extra_info(info)


class _BoundBackend(httpcore.AnyIOBackend):  # type: ignore[misc]
    """TCP через заданный интерфейс (SO_BINDTODEVICE) и, если задан, адрес."""

    def __init__(self, device: str, ip: Optional[str] = None):
        self.device = device
        self.ip = ip

    async def connect_tcp(self, host: str, port: int, timeout: Optional[float] = None,
                          local_address: Optional[str] = None,
                          socket_options: Optional[Any] = None) -> Any:
        target = self.ip or host
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET6 if ":" in target else socket.AF_INET,
                             socket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            if not plat.bind_to_device(sock, self.device):
                raise OSError(plat.interface_notes())
            await asyncio.wait_for(loop.sock_connect(sock, (target, port)), timeout)
            reader, writer = await asyncio.open_connection(sock=sock)
        except Exception as exc:
            sock.close()
            raise httpcore.ConnectError(str(exc)) from exc
        return _BoundStream(reader, writer)


def _pin_transport(transport: httpx.AsyncHTTPTransport, ip: str) -> bool:
    """Привязывает транспорт httpx к адресу. Возвращает признак успеха."""
    if not HTTPCORE_AVAILABLE:
        return False
    pool = getattr(transport, "_pool", None)
    if pool is None or getattr(pool, "_network_backend", None) is None:
        return False
    pool._network_backend = _PinnedBackend(ip)
    return True


AddressPin = Tuple[str, str]  # (домен, адрес): ключ привязанной пробы


class HTTPClientPool:
    """Клиенты для проб: общие и привязанные к конкретной паре (домен, адрес).

    Привязанные живут только на время пробы адреса и переиспользуют соединение
    внутри одной пробы, но не между адресами: иначе проба уедет не туда.
    """

    def __init__(self, settings: Settings):
        self.s = settings
        self.httpx_clients: Dict[str, httpx.AsyncClient] = {}
        self.pinned_httpx: Dict[str, Dict[str, httpx.AsyncClient]] = {}
        self.curl_client: Optional[Any] = None
        self.pinned_curl: Dict[str, Any] = {}
        self.warned_http_pin = False
        self.warned_curl_pin = False
        self._lock = asyncio.Lock()

    @staticmethod
    def pinning_notes() -> List[str]:
        notes = []
        if USE_CURL_CFFI and CURL_RESOLVE:
            notes.append("curl_cffi (CURLOPT_RESOLVE)")
        if HTTPCORE_AVAILABLE:
            notes.append("httpx (network backend)")
        return notes

    async def get_httpx(self, http2: bool, is_http: bool,
                        pin: Optional[AddressPin] = None) -> httpx.AsyncClient:
        key = f"h2_{http2}_http_{is_http}"
        pinned = bool(pin) and HTTPCORE_AVAILABLE
        scope = f"{pin[0]}|{pin[1]}" if pinned and pin else ""
        async with self._lock:
            if pinned:
                group = self.pinned_httpx.setdefault(scope, {})
                if key not in group:
                    group[key] = self._new_httpx(http2 and not is_http, pin[1])
                return group[key]
            if key not in self.httpx_clients:
                self.httpx_clients[key] = self._new_httpx(http2 and not is_http, None)
            return self.httpx_clients[key]

    def _new_httpx(self, http2: bool, ip: Optional[str]) -> httpx.AsyncClient:
        if not ip:
            if self.s.interface and HTTPCORE_AVAILABLE and plat.can_bind_interface():
                transport = httpx.AsyncHTTPTransport(verify=self.s.verify_ssl, http2=http2)
                pool_obj = getattr(transport, "_pool", None)
                if pool_obj is not None:
                    pool_obj._network_backend = _BoundBackend(self.s.interface, None)
                return httpx.AsyncClient(
                    transport=transport,
                    timeout=httpx.Timeout(self.s.timeout_total),
                    follow_redirects=False,
                    headers=self.s.headers,
                    limits=httpx.Limits(max_keepalive_connections=20),
                )
            return httpx.AsyncClient(
                http2=http2,
                verify=self.s.verify_ssl,
                timeout=httpx.Timeout(self.s.timeout_total),
                follow_redirects=False,
                headers=self.s.headers,
                limits=httpx.Limits(max_keepalive_connections=20),
                # без явного transport httpx берёт прокси из окружения,
                # а на Windows — и системный прокси из реестра
                trust_env=False,
            )
        transport = httpx.AsyncHTTPTransport(verify=self.s.verify_ssl, http2=http2)
        bound = bool(self.s.interface) and HTTPCORE_AVAILABLE and plat.can_bind_interface()
        if bound:
            pool_obj = getattr(transport, "_pool", None)
            if pool_obj is not None:
                pool_obj._network_backend = _BoundBackend(self.s.interface, ip)
            else:
                bound = False
        if not bound and not _pin_transport(transport, ip) and not self.warned_http_pin:
            self.warned_http_pin = True
            print(f"⚠️  нет привязки httpx к адресу {ip}: проба пойдёт по имени")
        return httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(self.s.timeout_total),
            follow_redirects=False,
            headers=self.s.headers,
            limits=httpx.Limits(max_keepalive_connections=0),
        )

    async def get_curl(self, pin: Optional[AddressPin] = None) -> Optional[Any]:
        if not USE_CURL_CFFI or not get_config_value("curl_cffi", "enabled", default=True):
            return None
        if pin and CURL_RESOLVE:
            scope = f"{pin[0]}|{pin[1]}"
            async with self._lock:
                if scope not in self.pinned_curl:
                    session = self._new_curl(pin)
                    if session is not None:
                        self.pinned_curl[scope] = session
                    elif not self.warned_curl_pin:
                        self.warned_curl_pin = True
                        print("⚠️  нет привязки curl_cffi к адресу: "
                              "CURLOPT_RESOLVE не принят, проба пойдёт по имени")
                if scope in self.pinned_curl:
                    return self.pinned_curl[scope]
        async with self._lock:
            if self.curl_client is None:
                self.curl_client = self._new_curl(None)
            return self.curl_client

    def _new_curl(self, pin: Optional[AddressPin]) -> Optional[Any]:
        options: Dict[Any, Any] = {}
        if CurlOpt is not None and hasattr(CurlOpt, "NOPROXY"):
            # libcurl сам читает http_proxy/https_proxy: замер через прокси
            # проверял бы сеть прокси, а не оператора. «*» — без прокси вообще.
            options[CurlOpt.NOPROXY] = "*"
        if pin:
            domain, ip = pin
            # CURLOPT_RESOLVE: имя из SNI/Host, соединение — на проверяемый адрес.
            options[CurlOpt.RESOLVE] = [f"{domain}:443:{ip}", f"{domain}:80:{ip}"]
        try:
            extra: Dict[str, Any] = {}
            if self.s.interface and plat.can_bind_interface():
                # Windows: libcurl не понимает имена адаптеров, только адрес.
                extra["interface"] = plat.bind_target(self.s.interface)
            return CurlCffiSession(
                impersonate=self.s.impersonate,
                verify=self.s.verify_ssl,
                timeout=self.s.timeout_total,
                allow_redirects=False,
                trust_env=False,
                **({"curl_options": options} if options else {}),
                **extra,
            )
        except Exception:
            return None

    async def release_address(self, pin: AddressPin) -> None:
        """Закрывает всё, что создавалось под одну пару (домен, адрес)."""
        scope = f"{pin[0]}|{pin[1]}"
        async with self._lock:
            session = self.pinned_curl.pop(scope, None)
            clients = list(self.pinned_httpx.pop(scope, {}).values())
        if session is not None:
            try:
                await session.close()
            except Exception:
                pass
        for client in clients:
            try:
                await client.aclose()
            except Exception:
                pass

    async def close(self):
        async with self._lock:
            for client in self.httpx_clients.values():
                await client.aclose()
            self.httpx_clients.clear()
            pinned = [c for group in self.pinned_httpx.values() for c in group.values()]
            self.pinned_httpx.clear()
            sessions = list(self.pinned_curl.values())
            self.pinned_curl.clear()
            if self.curl_client:
                await self.curl_client.close()
                self.curl_client = None
        for client in pinned:
            await client.aclose()
        for session in sessions:
            await session.close()


def _new_result(domain: str, client: str, method: str) -> Dict[str, Any]:
    return {"domain": domain, "status": "", "code": 0, "method": method,
            "rtt_ms": 0, "details": "", "client": client,
            "final_url": "", "stub": False, "cert_cn": None}


def _http_status(code: int) -> str:
    """Классификация по коду ответа (раньше BOT_BLOCK не выставлялся никогда)."""
    if 200 <= code < 400:
        return "OK"
    if code in (403, 429, 503):
        return "BOT_BLOCK"
    return "HTTP_ERR"


def _find_stub(text: str) -> Optional[str]:
    lowered = text.lower()
    for marker in STUB_MARKERS:
        if marker in lowered:
            return marker
    return None


# Куда оператор обычно перенаправляет при ограничении доступа.
# Бренды операторов, на которые ведут страницы-заглушки. Tele2/t2.ru сюда
# НЕ входят: tele2.ru легитимно редиректит на t2.ru (переезд бренда).
OPERATOR_HOSTS = (
    "megafon.ru", "mts.ru", "beeline.ru", "yota.ru",
    "motiv.ru", "sbermobile.ru", "vtbmobile.ru", "tinkoffmobile.ru",
    "megafon.pro",
)
BLOCK_URL_MARKERS = ("blocked", "block.", "zapret", "restrict", "access-denied",
                     "access_denied", "warning", "limited", "blacklist")


def _looks_like_block_redirect(host: str, url: str) -> bool:
    """Редирект похож на страницу-заглушку оператора, а не на переезд сервиса."""
    host = host.lower()
    if any(host == op or host.endswith("." + op) for op in OPERATOR_HOSTS):
        return True
    lowered = url.lower()
    return any(marker in lowered for marker in BLOCK_URL_MARKERS)


def _redirect_elsewhere(original: str, final_url: str) -> bool:
    if not final_url:
        return False
    try:
        host = final_url.split("://", 1)[1].split("/")[0].split(":")[0].lower()
    except IndexError:
        return False
    # Сайт может увести на себя же, но в punycode: гибдд.рф →
    # xn--90adear.xn--p1ai. Без нормализации это «чужой хост», и рабочий
    # домен выпадает из release как подмена.
    original = _idna(original)
    host = _idna(host)
    return not (host == original or host.endswith("." + original))


def _apply_redirect_check(res: Dict[str, Any], domain: str, code: int,
                          location: str, base_url: str) -> None:
    """3xx: подозрительно только если ведёт на оператора или блокировочную страницу.

    Обычный переезд сервиса (homecredit.ru → sovcombank.ru, pochtabank.ru →
    vtb.ru, gpb.ru → gazprombank.ru) подменой не считается — иначе теряются
    рабочие домены.
    """
    if not (300 <= code < 400 and location):
        return
    target = urljoin(base_url, location)
    res["final_url"] = target
    if not _redirect_elsewhere(domain, target):
        return
    try:
        host = target.split("://", 1)[1].split("/")[0].split(":")[0]
    except IndexError:
        host = ""
    if _looks_like_block_redirect(host, target):
        res["status"] = "SUSPECT_REDIRECT"
        res["details"] = f"редирект на страницу-заглушку: {target[:60]}"
    else:
        res["details"] = f"{res.get('details', '')} → {host[:40]}".strip()


def _apply_body_checks(res: Dict[str, Any], domain: str, code: int, snippet: str,
                       final_url: str, detect_stub: bool) -> None:
    """Признаки подмены в теле ответа: пустая страница, заглушка, чужой хост."""
    if code == 200 and not snippet.strip():
        res["status"] = "SUSPECT_EMPTY"
        res["details"] = "200 без тела"
        return
    marker = _find_stub(snippet) if detect_stub else None
    if marker and code < 400:
        res["status"] = "SUSPECT_STUB"
        res["stub"] = True
        res["details"] = f"страница-заглушка: «{marker}»"
    elif final_url and _redirect_elsewhere(domain, final_url):
        res["status"] = "SUSPECT_REDIRECT"
        res["details"] = f"редирект на чужой хост: {final_url[:60]}"


async def _read_head(client, url: str, max_bytes: int = 4096) -> Tuple[int, str, str, str]:
    """Читает только начало тела: не тянет мегабайты в мобильной сети."""
    body = b""
    location = ""
    async with client.stream("GET", url, headers={"Range": f"bytes=0-{max_bytes - 1}"}) as resp:
        final_url = str(resp.url)
        location = resp.headers.get("location") or ""
        async for chunk in resp.aiter_bytes():
            body += chunk
            if len(body) >= max_bytes:
                break
    return resp.status_code, body[:max_bytes].decode("utf-8", "ignore"), final_url, location


def _cancelled_by_us() -> bool:
    """Настоящая ли это отмена задачи, а не внутренний CancelledError библиотеки."""
    if SHUTDOWN_REQUESTED:
        return True
    task = asyncio.current_task()
    return bool(task and getattr(task, "cancelling", lambda: 0)())


async def _close_stream(resp) -> None:
    """Закрывает поток, не принимая CancelledError libcurl за отмену задачи.

    curl_cffi 0.15 бросает CancelledError при досрочном закрытии потока;
    раньше это либо роняло прогон, либо глотало настоящее прерывание.
    """
    try:
        await resp.aclose()
    except asyncio.CancelledError:
        if _cancelled_by_us():
            raise
    except Exception:
        pass


async def _curl_snippet(client, url: str, enable_http3: bool,
                        max_bytes: int = 4096) -> Optional[str]:
    """Начало тела ответа для проверки на заглушку.

    Запрашивается только для ответивших доменов и только первые килобайты:
    в мобильной сети тело целиком — это мегабайты. None — тело получить
    не удалось (тогда вывод о заглушке делать не из чего).
    """
    kwargs: Dict[str, Any] = {"url": url, "stream": True,
                              "headers": {"Range": f"bytes=0-{max_bytes - 1}"}}
    if enable_http3:
        kwargs["http_version"] = "v3"
    body = b""
    try:
        resp = await client.get(**kwargs)
    except Exception:
        return None
    try:
        async for chunk in resp.aiter_content():
            body += chunk
            if len(body) >= max_bytes:
                break
    except asyncio.CancelledError:
        if _cancelled_by_us():
            raise
    except Exception:
        pass
    await _close_stream(resp)
    return body[:max_bytes].decode("utf-8", "ignore")


async def _do_curl_cffi(pool: HTTPClientPool, url: str, enable_http3: bool,
                        pin: Optional[AddressPin] = None) -> Dict[str, Any]:
    domain = url.split("://")[1].split('/')[0]
    start = time.time()
    res = _new_result(domain, "curl_cffi", "?")
    try:
        client = await pool.get_curl(pin)
        if client is None:
            raise RuntimeError("curl_cffi not available")
        kwargs: Dict[str, Any] = {"url": url}
        if enable_http3:
            kwargs["http_version"] = "v3"
        # HEAD не тянет тело: в мобильной сети это разница в мегабайтах.
        resp = await client.head(**kwargs)
        if resp.status_code in (405, 501):
            # Сервер не поддерживает HEAD — читаем только начало ответа.
            resp = await client.get(**kwargs, stream=True)
            try:
                async for _ in resp.aiter_content():
                    break
            except asyncio.CancelledError:
                if _cancelled_by_us():
                    raise
            except Exception:
                pass
            await _close_stream(resp)
        version = getattr(resp, "http_version", 0)
        method = "H3" if version == 3 else ("H2" if version == 2 else "H1")
        final_url = str(getattr(resp, "url", ""))
        res.update({
            "rtt_ms": round((time.time() - start) * 1000, 1),
            "code": resp.status_code,
            "status": _http_status(resp.status_code),
            "details": f"{resp.status_code} {getattr(resp, 'reason', 'OK')}",
            "method": method,
            "final_url": final_url,
        })
        location = ""
        try:
            location = resp.headers.get("location") or ""
        except Exception:
            location = ""
        _apply_redirect_check(res, domain, resp.status_code, location, url)
        # HEAD возвращает ответ без тела, поэтому заглушку видно только
        # отдельным запросом — иначе детект работал бы лишь на httpx-шагах.
        if pool.s.detect_stub or resp.status_code == 200:
            snippet = await _curl_snippet(client, url, enable_http3)
            if snippet is not None:
                _apply_body_checks(res, domain, resp.status_code, snippet,
                                   final_url, pool.s.detect_stub)
    except Exception as e:
        res["status"], res["details"] = classify_error(e)
        if enable_http3 and "http3" in str(e).lower():
            return await _do_curl_cffi(pool, url, enable_http3=False, pin=pin)
    return res


async def _do_httpx(pool: HTTPClientPool, url: str, http2: bool,
                    pin: Optional[AddressPin] = None) -> Dict[str, Any]:
    domain = url.split("://")[1].split('/')[0]
    is_http = url.startswith("http://")
    start = time.time()
    res = _new_result(domain, f"httpx/{'h2' if http2 else 'h1.1'}",
                      "H1.1" if is_http else ("H2" if http2 else "H1.1"))
    try:
        client = await pool.get_httpx(http2, is_http, pin)
        code, snippet, final_url, location = await _read_head(client, url)
        res.update({
            "rtt_ms": round((time.time() - start) * 1000, 1),
            "code": code,
            "status": _http_status(code),
            "details": f"{code}",
            "final_url": final_url,
        })
        _apply_redirect_check(res, domain, code, location, url)
        _apply_body_checks(res, domain, code, snippet, final_url, pool.s.detect_stub)
    except Exception as e:
        res["status"], res["details"] = classify_error(e)
    return res


def _idna(value: Optional[str]) -> str:
    """Имя в одном алфавите: в сертификатах оно бывает в punycode, в списках — юникодом."""
    value = (value or "").strip().rstrip(".").lower()
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError:
        return value


def _cert_matches(domain: str, common_name: Optional[str], sans: List[str]) -> bool:
    domain = _idna(domain)
    names = [_idna(n) for n in ([common_name] if common_name else []) + list(sans) if n]
    for name in names:
        if name == domain:
            return True
        # *.example.com покрывает только поддомены, но не сам apex — как в RFC 6125.
        if name.startswith("*.") and "." in domain:
            if domain.split(".", 1)[1] == name[2:]:
                return True
    return False


async def fetch_cert_names(ip: str, sni: str,
                           timeout: float) -> Tuple[Optional[str], List[str], Optional[str]]:
    """Сертификат с конкретного адреса: CN, SAN и издатель.

    Издатель нужен, чтобы отличить подмену оператором от ошибки сайта:
    сертификат от публичного УЦ на чужое имя — это парковка или чужой домен,
    а не фильтрация.
    """
    if not CRYPTO_AVAILABLE:
        return None, [], None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host=ip, port=443, ssl=context, server_hostname=sni),
            timeout=timeout)
        ssl_object = writer.get_extra_info("ssl_object")
        der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        if not der:
            return None, [], None
        cert = x509.load_der_x509_certificate(der)
        cns = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        common_name = cns[0].value if cns else None
        issuer_cns = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        issuer = issuer_cns[0].value if issuer_cns else None
        sans: List[str] = []
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = san.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass
        return common_name, sans, issuer
    except Exception:
        return None, [], None
    finally:
        if writer is not None:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
            except Exception:
                pass


def _better(a: Optional[Dict[str, Any]], b: Dict[str, Any]) -> Dict[str, Any]:
    """Возвращает лучший по приоритету результат (раньше возвращался последний)."""
    if a is None:
        return b
    return b if STATUS_PRIORITY.get(b.get("status", ""), 0) > STATUS_PRIORITY.get(a.get("status", ""), 0) else a


async def check_domain_pipeline(domain: str, pool: HTTPClientPool, address: str) -> Dict[str, Any]:
    """HTTP-проба домена через конкретный адрес: SNI и Host — домен.

    Адрес привязан к пробе, иначе проверялся бы тот адрес, который выберет
    системный резолвер, и наблюдение «домен доступен» не относилось бы к паре
    (SNI, IP) из отчёта.
    """
    settings = pool.s
    pin: Optional[AddressPin] = (domain, address) if address else None
    pinned = bool(pin) and (HTTPCORE_AVAILABLE or (USE_CURL_CFFI and CURL_RESOLVE))
    steps = []
    if settings.use_impersonate:
        steps.append(("curl_cffi/HTTPS",
                      lambda: _do_curl_cffi(pool, f"https://{domain}",
                                            settings.enable_http3, pin)))
    steps.append(("httpx/H2", lambda: _do_httpx(pool, f"https://{domain}", True, pin)))
    steps.append(("httpx/H1.1", lambda: _do_httpx(pool, f"https://{domain}", False, pin)))
    if settings.http_fallback:
        steps.append(("httpx/HTTP:80", lambda: _do_httpx(pool, f"http://{domain}", False, pin)))

    # Если TCP не поднялся, остальные протоколы по тому же адресу дадут то же самое.
    DEAD_TRANSPORT = {"PORT_BLOCK", "RST", "UNREACH", "DPI_BLOCK", "DNS_ERR"}

    def empty(status: str, details: str) -> Dict[str, Any]:
        return {"domain": domain, "status": status, "method": "-", "details": details,
                "code": 0, "rtt_ms": 0, "client": "-", "final_url": "", "stub": False,
                "cert_cn": None, "pinned": pinned}

    best: Optional[Dict[str, Any]] = None
    try:
        for step_index, (step_name, step_fn) in enumerate(steps):
            if SHUTDOWN_REQUESTED:
                return empty("INTERRUPTED", "Shutdown requested")
            # Повторы имеет смысл делать только на первом шаге: остальные всё равно
            # идут по тому же адресу и протоколу.
            attempts = settings.retries + 1 if step_index == 0 else 1
            for attempt in range(attempts):
                result = await step_fn()
                result["pipeline_step"] = step_name
                result["address"] = address
                result["pinned"] = pinned
                best = _better(best, result)
                if result["status"] in ALIVE_STATUSES:
                    break
                if result["status"] in settings.retriable and attempt < attempts - 1:
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue
                break
            if best and (best["status"] in ALIVE_STATUSES
                         or best.get("status") in DEAD_TRANSPORT):
                break
    finally:
        if pin:
            await pool.release_address(pin)
    return best or empty("UNKNOWN", "No steps executed")


async def run_checker(domains: List[str], args: argparse.Namespace) -> Dict[str, Dict[str, Any]]:
    settings = Settings(args)
    resolver = Resolver(args.dns or [], settings.timeout_dns,
                        getattr(args, "dns_cache_data", None),
                        getattr(args, "cache_only", False))

    source = "кэш" if getattr(args, "dns_cache_data", None) else "живой DNS"
    print(f"🔍 DNS-резолв ({len(domains)} доменов, все A и AAAA, источник: {source})...")
    dns_sem = asyncio.Semaphore(settings.concurrency * 2)
    resolved: Dict[str, Tuple[List[str], List[str]]] = {}

    async def resolve(domain: str) -> None:
        async with dns_sem:
            if SHUTDOWN_REQUESTED:
                return
            resolved[domain] = await resolver.addresses(domain)

    await asyncio.gather(*(resolve(d) for d in domains))

    results: Dict[str, Dict[str, Any]] = {}
    targets: List[Tuple[str, List[str]]] = []
    for domain in domains:
        v4, v6 = resolved.get(domain, ([], []))
        addresses = v4 + v6
        if addresses:
            targets.append((domain, addresses))
        else:
            results[domain] = {"domain": domain, "status": "DNS_ERR", "method": "-",
                               "details": "нет A/AAAA", "code": 0, "rtt_ms": 0,
                               "client": "-", "final_url": "", "stub": False,
                               "cert_cn": None, "addresses": 0}

    total_pairs = sum(len(a) for _, a in targets)
    mode = "все адреса" if args.all_addresses else "до первого рабочего адреса"
    print(f"  ✅ с адресами: {len(targets)} | всего адресов: {total_pairs} ({mode})")

    if not targets:
        return results

    print(f"\n🔍 HTTP-проверка доменов (таймаут {settings.timeout_total} с, "
          f"параллельно {settings.concurrency})")
    pool = HTTPClientPool(settings)
    sem = asyncio.Semaphore(settings.concurrency)
    state = {"done": 0, "alive": 0, "pairs": 0}
    checked_certs: Set[str] = set()
    started_progress = time.perf_counter()
    total_domains = len(targets)

    async def progress_reporter() -> None:
        while True:
            await asyncio.sleep(5)
            elapsed = time.perf_counter() - started_progress
            rate = state["done"] / elapsed if elapsed else 0
            left = (total_domains - state["done"]) / rate if rate else 0
            print(f"  → доменов {state['done']}/{total_domains} | проб {state['pairs']} | "
                  f"доступно {state['alive']} | {rate:.1f} дом/с | осталось ~{left:.0f} с",
                  flush=True)

    async def one(domain: str, addresses: List[str]) -> None:
        if SHUTDOWN_REQUESTED:
            return
        async with sem:
            best: Optional[Dict[str, Any]] = None
            for ip in addresses:
                if SHUTDOWN_REQUESTED:
                    break
                if settings.jitter > 0:
                    await asyncio.sleep(random.uniform(0, settings.jitter))
                result = await check_domain_pipeline(domain, pool, ip)
                state["pairs"] += 1

                if settings.verify_cert and result["status"] in ALIVE_STATUSES \
                        and domain not in checked_certs:
                    checked_certs.add(domain)
                    cn, sans, issuer = await fetch_cert_names(ip, domain,
                                                              settings.timeout_total)
                    result["cert_cn"] = cn
                    result["cert_issuer"] = issuer
                    if (cn or sans) and not _cert_matches(domain, cn, sans):
                        result["status"] = _cert_status(result.get("cert_issuer"))
                        result["details"] = (f"сертификат не для домена "
                                            f"(CN={cn}, издатель={result.get('cert_issuer')})")

                best = _better(best, result)
                # Домен уже подтверждён: остальные адреса нужны только по запросу.
                if not args.all_addresses and best["status"] in ALIVE_STATUSES:
                    break

            if best is None:
                best = {"domain": domain, "status": "INTERRUPTED", "method": "-",
                        "details": "Shutdown requested", "code": 0, "rtt_ms": 0,
                        "client": "-", "final_url": "", "stub": False,
                        "cert_cn": None, "addresses": len(addresses)}
            best["addresses"] = len(addresses)
            results[domain] = best
            state["done"] += 1
            if best["status"] in ALIVE_STATUSES:
                state["alive"] += 1

    reporter = asyncio.create_task(progress_reporter())
    try:
        tasks = [one(d, a) for d, a in targets]
        if TQDM_AVAILABLE and not args.quiet:
            pbar = tqdm(total=total_domains, desc="  HTTP прогресс", unit="домен")
            for coro in asyncio.as_completed(tasks):
                await coro
                pbar.update(1)
            pbar.close()
        else:
            for coro in asyncio.as_completed(tasks):
                await coro
    finally:
        reporter.cancel()
        await pool.close()

    return results


def save_whitelist(domains: List[str], operator: str, out_dir: str) -> Path:
    out_path = PROJECT_ROOT / out_dir
    out_path.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
    path = out_path / f"whitelist-{ts}-{operator}.txt"
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(domains) + '\n')
    print(f"💾 Сохранено: {path}")
    print(f"   Всего доменов в whitelist: {len(domains)}")
    return path


def select_operator(operators: dict, name: Optional[str] = None) -> str:
    if name:
        return name
    print("\n📱 Выберите оператора:")
    for k, v in operators.items():
        print(f"  {k}. {v}")
    available = ', '.join(operators.keys())
    while True:
        c = input(f"Введите номер ({available}): ").strip()
        if c in operators:
            return operators[c]
        print("❌ Неверный ввод")


async def main() -> None:
    global CONFIG
    plat.setup_console()
    CONFIG = load_config()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    parser = argparse.ArgumentParser(description='Проверка доменов на доступность')
    parser.add_argument('directory', nargs='?', help='Директория с доменами')
    parser.add_argument('-c', '--concurrency', type=int, help='Количество параллельных запросов')
    parser.add_argument('-q', '--quiet', action='store_true', help='Тихий режим')
    parser.add_argument('-e', '--exclude', nargs='+', default=[], help='Исключить категории')
    parser.add_argument('--dns', nargs='+', default=None, help='Свои DNS серверы')
    parser.add_argument('--interface', default=None,
                        help='Интерфейс для запросов (модем): иначе запросы уйдут '
                             'по маршруту по умолчанию, возможно в чужую сеть')
    parser.add_argument('--dns-cache', default=None,
                        help='Кэш адресов (tools/cache_dns.py): нужен, когда DNS '
                             'оператора не отвечает на домены вне белого списка')
    parser.add_argument('--dns-cache-extra', action='append', default=None,
                        help='Локальный слой поверх общего кэша '
                             '(configs/dns-cache.local.json); можно несколько раз')
    parser.add_argument('--cache-only', action='store_true',
                        help='Не обращаться к DNS вовсе: только адреса из кэша')
    parser.add_argument('--verify-ssl', action='store_true', help='Проверять SSL')
    parser.add_argument('--jitter', type=float, help='Случайная задержка (0 — без паузы)')
    parser.add_argument('--retries', type=int, help='Повторы при ошибках (0 — без повторов)')
    parser.add_argument('--no-impersonate', action='store_true', help='Отключить эмуляцию браузера')
    parser.add_argument('--http-fallback', action='store_true', dest='http_fallback',
                        help='Разрешить резервную проверку по HTTP (порт 80)')
    parser.add_argument('--no-http-fallback', action='store_false', dest='http_fallback',
                        help='Отключить HTTP fallback (по умолчанию)')
    parser.add_argument('--http3', action='store_true', dest='enable_http3',
                        help='Включить HTTP/3')
    parser.add_argument('--no-http3', action='store_false', dest='enable_http3',
                        help='Отключить HTTP/3 (по умолчанию)')
    parser.add_argument('--no-verify-cert', action='store_true',
                        help='Не сверять сертификат с доменом')
    parser.add_argument('--no-stub-detect', action='store_true',
                        help='Не искать признаки страницы-заглушки')
    parser.add_argument('--limit', type=int, default=0, help='Проверить только первые N доменов')
    parser.add_argument('--timeout', type=float, default=None,
                        help='Таймаут одного запроса, сек (переопределяет конфиг)')
    parser.add_argument('--all-addresses', action='store_true',
                        help='Проверять все адреса домена даже после успеха '
                             '(по умолчанию проверка прекращается на первом рабочем)')
    parser.add_argument('--show-config', action='store_true', help='Показать текущую конфигурацию')
    parser.add_argument('--operator', default=None,
                        help='Имя оператора для имени файла (без интерактивного выбора)')
    parser.add_argument('--show-fingerprints', action='store_true',
                        help='Показать информацию об отпечатках curl_cffi')
    parser.set_defaults(http_fallback=None, enable_http3=None)
    args = parser.parse_args()

    if args.show_config:
        print(json.dumps(CONFIG, indent=2, ensure_ascii=False))
        return

    if args.show_fingerprints:
        curl_config = get_config_value("curl_cffi", default={})
        print("\n🔐 Информация об отпечатках curl_cffi:")
        print(f"   Версия библиотеки: {curl_cffi_version}")
        print(f"   Используемый отпечаток: {curl_config.get('default_impersonate', 'chrome124')}")
        for name, fp in curl_config.get("fingerprints", {}).items():
            print(f"      • {name}: {fp}")
        return

    settings = Settings(args)
    args.dns_cache_data = load_dns_cache(args.dns_cache,
                                             getattr(args, "dns_cache_extra", None))
    args.cache_only = bool(args.cache_only or get_config_value("probe", "cache_only", default=False))
    if args.cache_only and not args.dns_cache_data:
        print("❌ --cache-only требует кэш с данными (--dns-cache)")
        return
    paths = get_config_value("paths", default={})
    domains_dir = args.directory or paths.get("domains_directory", "../src/domains")
    excludes = set(paths.get("exclude_categories", [])) | set(args.exclude)

    print("⚙️  Настройки проверки:")
    print(f"   Одновременных запросов: {settings.concurrency}")
    print(f"   Эмуляция браузера: {'✅ Вкл' if settings.use_impersonate else '❌ Выкл'}")
    print(f"   HTTP/3: {'✅ Вкл' if settings.enable_http3 else '❌ Выкл'}")
    print(f"   Резервный HTTP (80): {'✅ Вкл' if settings.http_fallback else '❌ Выкл'}")
    print(f"   Проверка SSL: {'✅ Да' if settings.verify_ssl else '❌ Нет'}")
    print(f"   Сверка сертификата: {'✅ Да' if settings.verify_cert else '❌ Нет'}")
    print(f"   Детект заглушек: {'✅ Да' if settings.detect_stub else '❌ Нет'}")
    pin_notes = HTTPClientPool.pinning_notes()
    print(f"   Привязка пробы к адресу: "
          f"{'✅ ' + ', '.join(pin_notes) if pin_notes else '❌ нет (адрес выберет резолвер)'}")
    if settings.interface:
        print(f"   Интерфейс: {settings.interface} — {plat.interface_notes()}")
    print(f"   Повторы: {settings.retries} | пауза: {settings.jitter} с")
    print("-" * 45)

    files = get_files_to_process(domains_dir, excludes)
    if not files:
        print("❌ Нет файлов")
        sys.exit(1)

    print(f"📁 Файлы: {', '.join(f.name for f in files)}")
    domains, skipped = load_domains_from_files(files)
    if args.limit:
        domains = domains[:args.limit]
    if skipped:
        print(f"⚠️  Пропущено некорректных строк: {skipped}")
    print(f"📋 Загружено доменов: {len(domains)}\n")

    results = await run_checker(domains, args)

    alive = sorted(d for d, r in results.items() if r.get('status') in ALIVE_STATUSES)
    intercepted = sorted(d for d, r in results.items() if r.get('status') in INTERCEPT_STATUSES)
    site_issues = sorted(d for d, r in results.items() if r.get('status') in SITE_ISSUE_STATUSES)

    print(f"\n✅ Успешных: {len(alive)}")
    # Две разные причины «не в whitelist»: вклинился оператор или сайт сам
    # отдаёт не то. Смешивать их нельзя — выводы о фильтрации будут неверными.
    if intercepted:
        print(f"\n🛡️  Подменяет оператор: {len(intercepted)}")
        for d in intercepted[:15]:
            print(f"   {d}: {results[d].get('status')} — {results[d].get('details')}")
        if len(intercepted) > 15:
            print(f"   ... и ещё {len(intercepted) - 15}")
    if site_issues:
        print(f"\n🧾 Проблема на стороне сайта: {len(site_issues)}")
        for d in site_issues[:15]:
            print(f"   {d}: {results[d].get('status')} — {results[d].get('details')}")
        if len(site_issues) > 15:
            print(f"   ... и ещё {len(site_issues) - 15}")

    if alive:
        operators = get_config_value("operators", default={"1": "Default"})
        op = select_operator(operators, args.operator)
        out_dir = paths.get("output_directory", "build/domains_checked")
        save_whitelist(alive, op, out_dir)

    stats: Dict[str, int] = {}
    for r in results.values():
        stats[r.get('status', 'UNKNOWN')] = stats.get(r.get('status', 'UNKNOWN'), 0) + 1
    print("\n📊 Статистика по доменам:")
    for status, count in sorted(stats.items(), key=lambda x: -x[1]):
        print(f"  {ICONS.get(status, '❌')} {status}: {count}")

    if stats.get("BOT_BLOCK", 0) > 0:
        print(f"\n🤖 BOT_BLOCK ({stats['BOT_BLOCK']}) — сервер отклонил запрос (403/429/503)")
        print("   Попробуйте обновить curl_cffi: pip install --upgrade curl_cffi")
    if stats.get("TIMEOUT", 0) > len(domains) * 0.3:
        print(f"\n⚠️  Много таймаутов — уменьшите concurrency (сейчас {settings.concurrency})")
        print("   или увеличьте таймауты в configs/check-domains.json")

    if SHUTDOWN_REQUESTED:
        print("\n⚠️  Проверка прервана; домены без результата помечены INTERRUPTED")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Завершение")
        sys.exit(0)
