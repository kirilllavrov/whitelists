#!/usr/bin/env python3
"""Различия между Linux и Windows собраны в одном месте.

Что различается:
  - привязка сокета к интерфейсу: SO_BINDTODEVICE в Linux, адрес интерфейса
    или IP_UNICAST_IF в Windows (модель strong host);
  - имя интерфейса маршрута по умолчанию и список USB-интерфейсов читаются
    из `ip` (Linux) либо из `Get-Net*` в PowerShell (Windows);
  - шлюз и DNS интерфейса берутся из `ip route get` / `resolvectl` (Linux)
    или `Get-NetRoute` (Windows);
  - кэш резолвера сбрасывается `resolvectl` либо `ipconfig /flushdns`;
  - консоль Windows по умолчанию не в UTF-8, и печать эмодзи падает.

Вывод сетевых команд Windows разбирается как JSON, а не как текст: `ipconfig`
печатает в кодировке OEM (cp866), и «Основной шлюз» приходит нечитаемым.
"""
import ipaddress
import json
import os
import socket
import subprocess
import sys
from typing import Any, Dict, List, Optional

IS_WINDOWS = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")

# Имена интерфейсов, которые в Linux выглядят мобильными.
MOBILE_PREFIXES = ("ww", "ppp", "rmnet", "usb", "enx")
# Описания адаптеров Windows: так выглядят телефон-модем и свисток.
MOBILE_MARKERS = ("rndis", "remote ndis", "apple mobile", "iphone", "ipad",
                  "android", "wwan", "mobile broadband", "usb", "cellular",
                  "huawei", "zte", "quectel")
WIFI_MARKERS = ("wi-fi", "wifi", "wireless", "802.11")
_NET_CACHE: Optional[Dict[str, Any]] = None


def setup_console() -> None:
    """UTF-8 для консоли: иначе на Windows печать «✅» и кириллицы падает.

    Вызывается в начале каждой команды. errors="replace" — чтобы сломанный
    символ в чужом выводе не ронял прогон.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


# SetThreadExecutionState: держать систему без сна, пока поток не сбросит флаг.
ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001


def keep_awake() -> bool:
    """Windows: не уходить в сон по таймеру простоя, пока идёт прогон.

    Прогон длится час и больше, а сон по умолчанию — через час без ввода.
    Во сне телефон-модем отключается и после пробуждения часто не
    возвращается: остаток прогона идёт по мёртвому каналу. Флаг живёт, пока
    жив поток, и снимается сам при выходе; прав администратора не нужно.
    Сон по кнопке и закрытию крышки не отменяет. False — не Windows или
    вызов не удался.
    """
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        return bool(kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED))
    except (AttributeError, OSError):
        return False


def can_bind_interface() -> bool:
    """Привязка сокета к интерфейсу: Linux и Windows."""
    if IS_WINDOWS:
        return True
    return IS_LINUX and hasattr(socket, "SO_BINDTODEVICE")


def interface_index(iface: str) -> Optional[int]:
    """Номер интерфейса: нужен для IP_UNICAST_IF в Windows."""
    if not iface:
        return None
    if IS_WINDOWS:
        link = _windows_link(iface)
        return int(link["index"]) if link else None
    try:
        return int(Path_read(f"/sys/class/net/{iface}/ifindex"))
    except (OSError, ValueError):
        return None


def Path_read(path: str) -> str:  # noqa: N802 — читается как одна операция
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read().strip()


def bind_to_device(sock: socket.socket, iface: str) -> bool:
    """Привязывает сокет к интерфейсу. False — если система не умеет."""
    if not iface or not can_bind_interface():
        return False
    if IS_WINDOWS:
        return _bind_windows(sock, iface)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                        iface.encode() + b"\0")
        return True
    except OSError:
        return False


def _bind_windows(sock: socket.socket, iface: str) -> bool:
    """Windows: модель strong host — пакет с адресом источника уходит только
    через свой интерфейс, поэтому достаточно bind на адрес этого интерфейса.
    """
    link = _windows_link(iface)
    if not link:
        return False
    address = link["address6"] if sock.family == socket.AF_INET6 else link["address"]
    if not address:
        return False
    try:
        if sock.family == socket.AF_INET6:
            sock.bind((address, 0, 0, 0))
        else:
            sock.bind((address, 0))
        return True
    except OSError:
        return False


def bind_target(iface: str) -> str:
    """Что передать внешнему клиенту (curl_cffi) как привязку к интерфейсу.

    libcurl принимает имя интерфейса, адрес или имя хоста. На Windows надёжен
    только адрес: имена адаптеров («Ethernet 3») libcurl не разрешает.
    """
    if not iface:
        return ""
    if IS_WINDOWS:
        return interface_address(iface) or ""
    return iface


def interface_notes() -> str:
    """Короткое объяснение возможностей платформы для печати в лог."""
    if IS_WINDOWS:
        return ("привязка к интерфейсу: адрес адаптера (Windows, strong host), "
                "IP_UNICAST_IF для IPv6")
    if can_bind_interface():
        return "привязка к интерфейсу доступна"
    return "привязка к интерфейсу недоступна"


def _run(command: List[str], timeout: float = 5.0) -> str:
    try:
        return subprocess.run(command, capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              timeout=timeout).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""


_PS_NETWORK = """
$ErrorActionPreference = 'SilentlyContinue'
[pscustomobject]@{
  adapters = @(Get-NetAdapter | Select-Object ifIndex, Name, InterfaceDescription, Status)
  addresses = @(Get-NetIPAddress |
                Select-Object InterfaceIndex, IPAddress, AddressFamily)
  routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
             Select-Object InterfaceIndex, NextHop, RouteMetric)
  interfaces = @(Get-NetIPInterface -AddressFamily IPv4 |
                 Select-Object InterfaceIndex, InterfaceMetric)
} | ConvertTo-Json -Depth 4 -Compress
"""


def windows_network(refresh: bool = False) -> List[Dict[str, Any]]:
    """Подключения Windows одним списком, независимо от локали системы.

    ipconfig печатает в OEM-кодировке, и разбор его текста ломается на русской
    (и не только) Windows, поэтому данные берутся структурировано.
    """
    global _NET_CACHE
    if _NET_CACHE is not None and not refresh:
        return _NET_CACHE
    text = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 _PS_NETWORK], timeout=20.0)
    links: List[Dict[str, Any]] = []
    try:
        payload = json.loads(text) if text.strip() else {}
    except json.JSONDecodeError:
        payload = {}
    addresses: Dict[int, str] = {}
    addresses6: Dict[int, str] = {}
    for item in payload.get("addresses") or []:
        index = item.get("InterfaceIndex")
        address = (item.get("IPAddress") or "").strip()
        if index is None or not address:
            continue
        index = int(index)
        # AddressFamily не читаем: Windows PowerShell 5.1 отдаёт его числом
        # (2 — IPv4, 23 — IPv6), PowerShell 7 — строкой. Адрес однозначнее.
        if ":" in address:
            # link-local не годится как адрес источника для внешних проб.
            if address and not address.lower().startswith("fe80"):
                addresses6.setdefault(index, address)
        elif not address.startswith("169.254."):
            addresses.setdefault(index, address)
    interface_metrics: Dict[int, int] = {}
    for item in payload.get("interfaces") or []:
        index = item.get("InterfaceIndex")
        if index is not None:
            interface_metrics[int(index)] = int(item.get("InterfaceMetric") or 0)
    routes: Dict[int, str] = {}
    metrics: Dict[int, int] = {}
    for item in sorted(payload.get("routes") or [],
                       key=lambda row: (row.get("RouteMetric") or 0)):
        index = item.get("InterfaceIndex")
        next_hop = (item.get("NextHop") or "").strip()
        if index is not None and next_hop:
            index = int(index)
            if index not in routes:
                routes[index] = next_hop
                # Windows выбирает маршрут по сумме метрик маршрута и интерфейса:
                # у двух маршрутов 0.0.0.0/0 с RouteMetric 0 решает InterfaceMetric.
                metrics[index] = (int(item.get("RouteMetric") or 0)
                                  + interface_metrics.get(index, 0))
    for item in payload.get("adapters") or []:
        index = item.get("InterfaceIndex", item.get("ifIndex"))
        if index is None:
            continue
        index = int(index)
        links.append({
            "index": index,
            "name": (item.get("Name") or "").strip(),
            "description": (item.get("InterfaceDescription") or "").strip(),
            "up": (item.get("Status") or "").lower() == "up",
            "address": addresses.get(index),
            "address6": addresses6.get(index),
            "gateway": routes.get(index),
            "metric": metrics.get(index),
        })
    _NET_CACHE = links
    return links


def _windows_link(iface: str) -> Optional[Dict[str, Any]]:
    """Подключение по имени адаптера, номеру интерфейса или описанию."""
    if not iface or not IS_WINDOWS:
        return None
    value = iface.strip().lower()
    links = windows_network()
    for link in links:
        if link["name"].lower() == value:
            return link
    if value.isdigit():
        for link in links:
            if link["index"] == int(value):
                return link
    # Подстрока — только по описанию: «Ethernet» иначе совпадёт
    # с «vEthernet (Default Switch)».
    for link in links:
        if value in link["description"].lower():
            return link
    return None


def _windows_default_link() -> Optional[Dict[str, Any]]:
    """Подключение, которое Windows выберет для 0.0.0.0/0.

    Порядок адаптеров в Get-NetAdapter ничего не говорит о маршруте: при
    подключённом телефоне первым может оказаться модем, хотя трафик идёт
    в Ethernet. Решает наименьшая сумма метрик маршрута и интерфейса.
    """
    candidates = [link for link in windows_network() if link["gateway"] and link["up"]]
    if not candidates:
        return None
    return min(candidates, key=lambda link: link.get("metric") or 0)


def default_route() -> str:
    """Интерфейс маршрута по умолчанию."""
    if IS_WINDOWS:
        link = _windows_default_link()
        return link["name"] if link else ""
    if not IS_LINUX:
        return ""
    for line in _run(["ip", "route", "show", "default"]).splitlines():
        parts = line.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    return ""


def usb_interfaces() -> List[str]:
    """Мобильные интерфейсы: USB-модем, телефон-модем, WWAN."""
    if IS_WINDOWS:
        return [link["name"] for link in windows_network()
                if link["up"] and _looks_mobile(link)]
    if not IS_LINUX:
        return []
    found = []
    for line in _run(["ip", "-brief", "addr"]).splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[1].lower() == "down":
            continue
        if "/usb" in _resolve_link(f"/sys/class/net/{parts[0]}/device"):
            found.append(parts[0])
    return found


def _looks_mobile(link: Dict[str, Any]) -> bool:
    description = (link.get("description") or "").lower()
    return any(marker in description for marker in MOBILE_MARKERS)


def _resolve_link(path: str) -> str:
    try:
        return str(os.path.realpath(path))
    except OSError:
        return ""


def is_usb_network(iface: str) -> bool:
    """Мобильный канал: в Windows — по описанию адаптера, в Linux — по USB."""
    if not iface:
        return False
    if IS_WINDOWS:
        link = _windows_link(iface)
        return bool(link and _looks_mobile(link))
    if not IS_LINUX:
        return False
    return "/usb" in _resolve_link(f"/sys/class/net/{iface}/device")


def interface_kind(iface: str) -> str:
    """Тип канала: mobile, wifi, ethernet или unknown.

    Нужен, чтобы отличить сеть оператора от домашней: имя интерфейса в Linux
    (wwan0, usb0) и описание адаптера в Windows несут разный признак.
    """
    if not iface:
        return "unknown"
    if IS_WINDOWS:
        link = _windows_link(iface)
        if link is None:
            return "unknown"
        description = (link.get("description") or "").lower()
        name = (link.get("name") or "").lower()
        if _looks_mobile(link):
            return "mobile"
        if any(marker in description or marker in name for marker in WIFI_MARKERS):
            return "wifi"
        if "virtual" in description or "vethernet" in name:
            return "unknown"
        return "ethernet" if link.get("address") else "unknown"
    if iface.startswith(MOBILE_PREFIXES) or is_usb_network(iface):
        return "mobile"
    if iface.startswith(("wl", "wlan", "wifi")):
        return "wifi"
    if iface.startswith(("eth", "en", "em")):
        return "ethernet"
    return "unknown"


def interface_address(iface: str) -> Optional[str]:
    """IPv4-адрес интерфейса."""
    if not iface:
        return local_ip()
    if IS_WINDOWS:
        link = _windows_link(iface)
        return link["address"] if link else None
    if not IS_LINUX:
        return local_ip()
    for token in _run(["ip", "-4", "-o", "addr", "show", "dev", iface]).split():
        if token.count(".") == 3 and "/" in token:
            return token.split("/")[0]
    return None


def local_ip() -> Optional[str]:
    """Адрес, с которого уйдёт трафик. Работает и в Windows.

    UDP-connect пакетов не отправляет, поэтому это безопасно.
    """
    for target in (("1.1.1.1", 53), ("77.88.55.88", 443)):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(target)
            return sock.getsockname()[0]
        except OSError:
            continue
        finally:
            sock.close()
    return None


def interface_gateway(iface: str = "") -> Optional[str]:
    """Шлюз того пути, которым пойдут пробы."""
    if IS_WINDOWS:
        if iface:
            link = _windows_link(iface)
            return link["gateway"] if link else None
        link = _windows_default_link()
        return link["gateway"] if link else None
    if not IS_LINUX:
        return None
    command = ["ip", "route", "get", "1.1.1.1"]
    if iface:
        command += ["oif", iface]
    for line in _run(command).splitlines():
        parts = line.split()
        if "via" in parts:
            return parts[parts.index("via") + 1]
    return None


def interface_dns(iface: str = "") -> List[str]:
    """DNS-серверы интерфейса (Linux) или системы (Windows)."""
    if IS_LINUX and iface:
        text = _run(["resolvectl", "dns", iface])
        for token in text.replace(":", " ").split():
            if token.count(".") == 3 or ":" in token:
                return [token]
        gateway = interface_gateway(iface)
        return [gateway] if gateway else []
    return []


def flush_dns() -> bool:
    """Сброс кэша резолвера: без него ответ до включения режима живёт в кэше."""
    commands = [["resolvectl", "flush-caches"], ["systemd-resolve", "--flush-caches"]]
    if IS_WINDOWS:
        commands = [["ipconfig", "/flushdns"]]
    for command in commands:
        if _run(command):
            return True
    return False


def is_mobile_address(ip: Optional[str]) -> Optional[bool]:
    """Похож ли адрес на мобильный CGNAT (100.64.0.0/10).

    Один из признаков мобильного канала, но не решающий: при раздаче с
    телефона или HiLink-модема компьютер получает адрес локальной сети
    устройства (192.168.42.x, 172.20.10.x, 192.168.8.x), а не CGNAT.
    Основной признак — тип адаптера (см. interface_kind).
    """
    if not ip:
        return None
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network("100.64.0.0/10")
    except ValueError:
        return None


def write_text(path, text: str) -> None:
    """Запись текста с переводами строк LF в любой ОС.

    По умолчанию open() на Windows превращает \\n в \\r\\n, и список доменов
    приезжает на роутер с \\r в конце строки. pathlib.write_text(newline=...)
    появился только в 3.10, а проект обещает 3.9.
    """
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def write_lines(path, values: List[str]) -> None:
    """Список строк по одной на строку, LF, завершающий перевод строки."""
    write_text(path, "\n".join(values) + ("\n" if values else ""))
