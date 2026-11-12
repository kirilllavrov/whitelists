#!/usr/bin/env python3
"""
Проверка доменов в сети оператора — одна команда, без настроек.

    python3 tools/check.py                 # спросит оператора и сделает всё
    python3 tools/check.py -o Megafon      # без вопроса
    LIMIT=50 python3 tools/check.py        # быстрый пробный прогон

Что делает:
1. определяет оператора и предупреждает, если трафик идёт не через мобильную сеть;
2. прогоняет матрицу пар SNI × IP по всем доменам из src/domains;
3. делает HTTP-проверку вторым мнением;
4. кладёт наблюдения в runs/<оператор>/ — из них собирается release;
5. пересобирает release для этого оператора и печатает итог.

Отдельные скрипты (check_pairs.py, check-domains.py, pairs_report.py)
нужны только для ручных экспериментов; для обычной проверки хватает этой команды.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import List

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
RELEASE_CONFIG = ROOT / "configs" / "release.json"
# Прерывание пользователем: собранное всё равно сохраняем, остальные шаги — нет.
INTERRUPTED = False
DOMAINS_DIR = ROOT / "src" / "domains"
# Кэш адресов, который собирает workflow: в сети оператора DNS не отвечает,
# и без готовых адресов домен нечем проверять.
DNS_CACHE = ROOT / "configs" / "dns-cache.json"
# Локальный слой поверх общего кэша: свои адреса, не в git.
DNS_CACHE_LOCAL = ROOT / "configs" / "dns-cache.local.json"
HTTP_CONFIG = ROOT / "configs" / "check-domains.json"

# Скрипт запускают как `python3 tools/check.py`, поэтому каталог скрипта уже
# в sys.path — общие помощники лежат рядом с ним.
import platform_support as plat  # noqa: E402
import mode_check  # noqa: E402
from operators import slug  # noqa: E402

# Код выхода check_pairs.py, когда режим белого списка разошёлся с фазой.
EXIT_MODE_LOST = 3


def confirm_mismatch(iface: str, phase: str, attempts: int = 2,
                     pause: float = 5.0) -> str:
    """Причина, если режим в сети не совпадает с фазой; пусто — совпадает.

    Расхождение подтверждается повторной проверкой: один ответ может быть
    случайным, а остановка прогона — дорогое решение.
    """
    if phase not in ("on", "off"):
        return ""
    for attempt in range(attempts):
        result = mode_check.probe_mode(iface)
        reason = mode_check.mismatch(phase, result["state"])
        print(f"   режим белого списка: {mode_check.describe(result)}", flush=True)
        if not reason:
            if result["state"] in (mode_check.STATE_NO_LINK, mode_check.STATE_UNCLEAR):
                print("   ⚠️  режим не определить — прогон продолжится без этой гарантии")
            return ""
        if attempt + 1 < attempts:
            time.sleep(pause)
    return reason


# Сеть оператора по названию: нужно, чтобы прогон попал в правильную папку runs/.
NETWORKS = {
    "megafon": "250-02",
    "mts": "250-01",
    "beeline": "250-99",
    "tele2": "250-20",
    "rostelecom": "250-20",
    "yota": "250-11",
}

# Признаки оператора в поле org у ipinfo: так оператор определяется по сети,
# а не по тому, что выбрали в меню.
EGRESS_OPERATORS = (
    ("megafon", "megafon"),
    ("mts", "mts"),
    ("beeline", "beeline"),
    ("vimpelcom", "beeline"),
    ("rostelecom", "rostelecom"),
    ("tele2", "tele2"),
    ("t2", "tele2"),
    ("yota", "yota"),
    ("scartel", "yota"),
)

PHASES = ("off", "on", "unknown")


def run(cmd, title):
    """Запускает шаг и возвращает его код возврата.

    Вывод шага всегда перехватывается и дублируется через наш stdout: только
    так он попадает в журнал прогона. Прямая запись дочернего процесса в
    терминал шла бы мимо Tee, и в run.log оставался бы неполный журнал.
    """
    print(f"\n── {title} " + "─" * max(0, 60 - len(title)), flush=True)
    print("   " + " ".join(str(part) for part in cmd[1:]), flush=True)
    global INTERRUPTED
    # PYTHONUNBUFFERED: stdout потомка — pipe, и без этого Python копит вывод
    # блоками по 8 КБ. Шаг пар идёт 40–60 минут, и журнал с терминалом
    # минутами стояли пустыми, хотя пробы шли.
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    process = subprocess.Popen(cmd, cwd=str(TOOLS), stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, bufsize=1,
                               encoding="utf-8", errors="replace", env=env)
    try:
        while True:
            try:
                for line in process.stdout:
                    sys.stdout.write(line)
                break
            except KeyboardInterrupt:
                # Ctrl+C получает вся группа процессов, включая потомка:
                # он дописывает уже собранное. Если выйти сразу, потомок
                # пишет в закрытый канал и падает до записи сводки.
                if INTERRUPTED:
                    print("\n⚠️  повторное прерывание — шаг останавливается")
                    process.kill()
                    break
                INTERRUPTED = True
                print("\n⚠️  прерывание: дочитываю наблюдения "
                      "(Ctrl+C ещё раз — прервать сразу)", flush=True)
    finally:
        process.stdout.close()
        code = process.wait()
    if code != 0 and not INTERRUPTED:
        print(f"   ⚠️  шаг завершился с кодом {code}")
    return code


def default_route():
    """Интерфейс маршрута по умолчанию: по нему видно, через что пойдёт трафик."""
    return plat.default_route()


def mobile_interfaces() -> List[str]:
    """Поднятые USB/мобильные интерфейсы: среди них ищем сеть оператора."""
    found = list(plat.usb_interfaces())
    route = plat.default_route()
    if route and plat.interface_kind(route) == "mobile" and route not in found:
        found.insert(0, route)
    return found


def pick_interface(requested: str) -> str:
    """Интерфейс для проб: явный, иначе мобильный, иначе маршрут по умолчанию.

    Домашний Wi-Fi часто остаётся маршрутом по умолчанию (меньший metric),
    и без этого выбора пробы уходят в чужую сеть мимо подключённого модема.
    """
    if not plat.can_bind_interface():
        # Windows: привязать сокет к интерфейсу нельзя, поэтому «выбранный»
        # интерфейс всё равно ничего не изменит — честнее сказать об этом.
        print(f"   ℹ️  {plat.interface_notes()}")
        return ""
    if requested:
        return requested
    route_iface = default_route()
    if route_iface and plat.interface_kind(route_iface) == "mobile":
        return route_iface
    mobiles = mobile_interfaces()
    if len(mobiles) == 1:
        print(f"   ⚠️  маршрут по умолчанию — «{route_iface}», пробы идут через "
              f"модем «{mobiles[0]}»")
        return mobiles[0]
    if len(mobiles) > 1:
        print(f"   ⚠️  несколько мобильных интерфейсов ({', '.join(mobiles)}): "
              f"укажите нужный через --interface")
    if not plat.can_bind_interface():
        return ""
    return route_iface or ""


def is_usb_network(iface: str) -> bool:
    """Интерфейс висит на USB: так выглядят и телефон-модем, и HiLink-свисток."""
    return plat.is_usb_network(iface)


def check_channel(probe_iface: str = ""):
    """Предупреждает, если меряем не сеть оператора.

    Судим по тому интерфейсу, через который реально пойдут пробы: маршрут по
    умолчанию может быть домашним Wi-Fi, а пробы при этом привязаны к модему —
    тогда совет «выключите Wi-Fi» был бы вредным.
    """
    iface = probe_iface or default_route()
    if not iface:
        print("⚠️  маршрут по умолчанию не определён — проверьте подключение")
        return "unknown"
    kind = plat.interface_kind(iface)
    usb = is_usb_network(iface)
    if kind == "mobile" or usb:
        print(f"✅ мобильный интерфейс: {iface}" + (" (USB-модем)" if usb else ""))
        route = default_route()
        if probe_iface and route and route != iface:
            print(f"   маршрут по умолчанию — «{route}», но пробы привязаны к модему: "
                  f"Wi-Fi не мешает")
        return "mobile"
    if kind == "wifi":
        print(f"⚠️  Трафик идёт через «{iface}» — это НЕ сеть оператора.")
        print("   Результаты покажут доступность из домашней сети, а не белый список.")
        print("   Выключите Wi-Fi или укажите модем через --interface.")
        return "wifi"
    if kind == "ethernet":
        print(f"⚠️  Трафик идёт через «{iface}» — похоже на домашнюю сеть.")
        print("   Результаты покажут доступность не из сети оператора.")
        return "wifi"
    print(f"ℹ️  интерфейс «{iface}» — проверьте, что это модем, а не домашняя сеть")
    return "unknown"


def detect_operator(timeout: float = 8.0, iface: str = ""):
    """Оператор по внешнему IP: возвращает (ключ, org).

    ASN оператора не зависит от того, что выбрано в меню: если прогон пойдёт
    не в той сети, это видно сразу, а не по странным результатам. Запрос идёт
    через тот же интерфейс, что и пробы: иначе при домашнем Wi-Fi он покажет
    провайдера Wi-Fi и предупреждение будет ложным.
    """
    try:
        if iface:
            import check_pairs
            check_pairs.BIND_INTERFACE = iface
            raw = check_pairs.bound_https_get("https://ipinfo.io/json", timeout)
            data = json.loads(raw)
        else:
            # без прокси: иначе в ответе будет провайдер прокси, а не оператор
            direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with direct.open("https://ipinfo.io/json", timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return "", ""
    org = str(data.get("org") or "")
    lowered = org.lower()
    for marker, key in EGRESS_OPERATORS:
        if marker in lowered:
            return key, org
    return "", org


def ask_operator(preset):
    """Оператор: из флага, иначе меню. Без терминала — без вопросов."""
    if preset:
        return preset, NETWORKS.get(slug(preset), "")

    known = {}
    try:
        cfg = json.loads((ROOT / "configs" / "check-domains.json").read_text(encoding="utf-8"))
        known = cfg.get("operators", {})
    except Exception:
        pass

    if not sys.stdin.isatty():
        return "unknown", ""

    print("\nОператор, в сети которого идёт проверка:")
    items = sorted(known.items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 99)
    for key, name in items:
        print(f"   {key:>2}. {name}")
    print("   Enter — не указывать")
    choice = input("   номер или название: ").strip()
    if not choice:
        return "unknown", ""
    name = known[choice] if choice in known else choice
    return name, NETWORKS.get(slug(name), "")


def ensure_operator_in_manifest(operator):
    """Новый оператор попадает в манифест: без записи release для него не собрать."""
    try:
        manifest = json.loads(RELEASE_CONFIG.read_text(encoding="utf-8"))
    except Exception:
        return
    if operator in manifest:
        return
    manifest[operator] = {
        "title": operator,
        "mode": "min",
        "min_sources": 2,
        # В release идут только прогоны режима белого списка: наблюдения
        # с выключенным режимом лежат в соседнем каталоге и для списка
        # «что разрешает оператор» смысла не имеют.
        "sources": [f"runs/{operator}/on/*.txt"],
        "pairs": [f"runs/{operator}/on/*.tsv"],
    }
    RELEASE_CONFIG.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"   оператор «{operator}» добавлен в {RELEASE_CONFIG.relative_to(ROOT)}")


def newest(pattern):
    files = sorted(pattern.parent.glob(pattern.name), key=lambda p: p.stat().st_mtime)
    return files[-1] if files else None


def http_timeout_default() -> float:
    """Таймаут шага check-domains из его конфига.

    Это не тот же таймаут, что у пробы пары: там — одна TLS-попытка (3 с),
    здесь — весь HTTP-запрос с коннектом и TLS (15 с). Наследовать 3 с во
    второй шаг нельзя: живые сайты попали бы в TIMEOUT.
    """
    try:
        cfg = json.loads(HTTP_CONFIG.read_text(encoding="utf-8"))
        return float(cfg.get("network", {}).get("timeout_total", 15))
    except Exception:
        return 15.0


class Tee:
    """Дублирует вывод в журнал: полевой прогон может остаться без терминала."""

    def __init__(self, stream, path):
        self.stream = stream
        self.log = open(path, "a", encoding="utf-8", buffering=1)

    def write(self, text):
        self.stream.write(text)
        self.log.write(text)

    def flush(self):
        self.stream.flush()
        self.log.flush()

    def isatty(self):
        return self.stream.isatty()

    def __getattr__(self, name):
        return getattr(self.stream, name)


def main():
    plat.setup_console()
    parser = argparse.ArgumentParser(
        description="Проверка доменов в сети оператора: один запуск — готовый release")
    parser.add_argument("-o", "--operator", default=os.environ.get("OPERATOR", ""),
                        help="Оператор (иначе спросим)")
    parser.add_argument("--limit", type=int, default=int(os.environ.get("LIMIT", 0)),
                        help="Проверить только первые N доменов (на обоих шагах)")
    parser.add_argument("--repeat", type=int, default=int(os.environ.get("REPEAT", 1)),
                        help="Повторов на каждую пару: покажет стабильность фильтрации")
    parser.add_argument("--timeout", type=float,
                        default=float(os.environ.get("PROBE_TIMEOUT", 3)),
                        help="Таймаут одной пробы пары (SNI × IP), сек")
    parser.add_argument("--http-timeout", type=float,
                        default=float(os.environ.get("HTTP_TIMEOUT", 0)) or None,
                        help="Таймаут HTTP-запроса на шаге check-domains, сек "
                             "(по умолчанию — из configs/check-domains.json)")
    # Плотный поток ломает замер: модем перестаёт держать новые соединения
    # после ~110 подключений при параллельности 10 и выше, и разрешённые
    # домены выглядят заблокированными. 6 — проверенный безопасный темп.
    parser.add_argument("--concurrency", "-c", type=int,
                        default=int(os.environ.get("CONCURRENCY", 6)),
                        help="Одновременных проб (выше 8 модем начинает терять "
                             "соединения и замер врёт)")
    parser.add_argument("--dns", nargs="+", default=None,
                        help="DNS-серверы для резолва (по умолчанию системные)")
    parser.add_argument("--no-cache", action="store_true",
                        help="Не использовать кэш адресов configs/dns-cache.json")
    parser.add_argument("--no-http", action="store_true",
                        help="Не делать HTTP-проверку (быстрее, но одно мнение)")
    parser.add_argument("--http-limit", type=int, default=0,
                        help="Сколько доменов проверять по HTTP (0 — все)")
    parser.add_argument("--http-concurrency", type=int,
                        default=int(os.environ.get("HTTP_CONCURRENCY", 10)),
                        help="Одновременных HTTP-проверок на шаге check-domains")
    parser.add_argument("--no-release", action="store_true",
                        help="Только проверить, release не пересобирать")
    parser.add_argument("--interface", default=os.environ.get("INTERFACE", ""),
                        help="Интерфейс для проб (по умолчанию — интерфейс "
                             "маршрута по умолчанию)")
    parser.add_argument("--chunk", type=int,
                        default=int(os.environ.get("CHUNK", 40)),
                        help="Доменов в блоке перед паузой (0 — без блоков)")
    parser.add_argument("--chunk-pause", type=float,
                        default=float(os.environ.get("CHUNK_PAUSE", 60)),
                        help="Пауза между блоками, сек: возвращает модулю скорость")
    parser.add_argument("--pace", type=float,
                        default=float(os.environ.get("PACE", 0)),
                        help="Пауза между пробами пар, сек: снижает нагрузку на канал")
    parser.add_argument("--phase", choices=PHASES,
                        default=os.environ.get("PHASE", "unknown"),
                        help="Фаза сети: off — режим белого списка выключен, "
                             "on — включён. Отделяет базовый прогон от целевого")
    parser.add_argument("--no-mode-check", action="store_true",
                        help="Не проверять, что режим белого списка в сети совпадает "
                             "с --phase (в начале и во время прогона)")
    args = parser.parse_args()

    started = time.time()
    stamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    out = ROOT / "build" / f"run-{stamp}-{args.phase}"
    out.mkdir(parents=True, exist_ok=True)
    sys.stdout = Tee(sys.stdout, out / "run.log")
    sys.stderr = Tee(sys.stderr, out / "run.log")

    operator, mcc_mnc = ask_operator(args.operator)
    operator = slug(operator)
    print(f"\n=== Проверка доменов · оператор: {operator} · фаза: {args.phase} ===")
    iface = pick_interface(args.interface)
    channel = check_channel(iface)

    detected, org = detect_operator(iface=iface)
    if org:
        print(f"🌐 сеть по внешнему IP: {org}" + (f" → {detected}" if detected else ""))
    if not args.operator and detected:
        if operator in ("unknown", ""):
            operator = detected
            mcc_mnc = NETWORKS.get(operator, "")
            print(f"   оператор определён по сети: {operator} (переопределить: -o)")
    elif detected and detected != operator:
        print(f"   ⚠️  выбран оператор «{operator}», а трафик идёт в сети «{detected}»")
    if args.phase == "unknown":
        print("   ℹ️  фаза не указана (--phase off|on): базовый прогон и прогон "
              "белого списка будут в одной папке")

    # Режим проверяется до старта: прогон фазы on при выключенном белом
    # списке занял бы 40–60 минут и намерил бы обычную сеть.
    mode_guard = not args.no_mode_check and args.phase in ("on", "off")
    if mode_guard:
        reason = confirm_mismatch(iface, args.phase)
        if reason:
            print(f"\n⛔ {reason}.")
            print("   Прогон не запущен. Проверьте режим у оператора или фазу "
                  "(--phase); проверку можно отключить: --no-mode-check")
            return 2

    cache_args = []
    if DNS_CACHE.exists() and not args.no_cache:
        print(f"\n📦 адреса из кэша: {DNS_CACHE.name}")
        cache_args = ["--dns-cache", str(DNS_CACHE)]
        # Локальный слой: дополнения из своей сети, не трогая общий кэш,
        # который обновляет workflow (иначе следующий pull даёт конфликт).
        if DNS_CACHE_LOCAL.exists():
            print(f"   + локальный слой: {DNS_CACHE_LOCAL.name}")
            cache_args += ["--dns-cache-extra", str(DNS_CACHE_LOCAL)]
    elif not args.no_cache:
        print("\nℹ️  кэша адресов нет: домены вне белого списка получат DNS_NX")
        print("   собрать заранее (нужен обычный интернет): python3 tools/cache_dns.py")

    pairs = [sys.executable, "check_pairs.py", str(DOMAINS_DIR),
             "--out-dir", str(out / "pairs"), "--format", "both",
             "--timeout", str(args.timeout), "-c", str(args.concurrency),
             "--repeat", str(args.repeat), "--ipv6-check", "--detect-egress",
             "--dns-probe", "--link-watch",
             # Порядок доменов перемешивается: если фильтр или канал ведут себя
             # по-разному в начале и в конце прогона, сдвиг станет шумом.
             "--shuffle",
             "-o", operator, "--channel", channel, "--phase", args.phase, *cache_args]
    if mcc_mnc:
        pairs += ["--mcc-mnc", mcc_mnc]
    if args.dns:
        pairs += ["--dns"] + args.dns
    if args.pace:
        pairs += ["--pace", str(args.pace)]
    if args.chunk:
        pairs += ["--chunk", str(args.chunk), "--chunk-pause", str(args.chunk_pause)]
    if iface:
        # Привязка к интерфейсу: иначе пробы уйдут по маршруту с меньшим metric
        # (например, в домашний Wi-Fi), и измерена будет чужая сеть.
        pairs += ["--interface", iface]
        print(f"   пробы привязаны к интерфейсу: {iface}", flush=True)
    if args.limit:
        pairs += ["--limit", str(args.limit)]
    if mode_guard:
        pairs += ["--mode-guard"]
    pairs_code = run(pairs, "1/3 Проверка пар SNI × IP")
    if INTERRUPTED:
        print("\n⚠️  прогон прерван — сохраняю то, что успели собрать; "
              "HTTP-проверка и release не запускаются")
    mode_lost = ""
    if mode_guard and pairs_code == EXIT_MODE_LOST:
        mode_lost = "режим белого списка разошёлся с фазой во время проверки пар"

    jsonl = sorted((out / "pairs").glob("pairs-*.jsonl"))
    if jsonl and not INTERRUPTED and not mode_lost:
        run([sys.executable, "pairs_report.py", *map(str, jsonl),
             "-o", str(out / "report"), "--domains-dir", str(DOMAINS_DIR)],
            "2/3 Отчёт по прошедшим парам")
    elif not jsonl:
        print("\n⚠️  наблюдений нет — отчёт пропущен")

    http_file = None
    # HTTP-шаг идёт своим процессом без сторожа: режим проверяется до и после
    # него, и при расхождении его результат не сохраняется.
    if mode_guard and not mode_lost and not INTERRUPTED and not args.no_http:
        mode_lost = confirm_mismatch(iface, args.phase)
    if not args.no_http and not INTERRUPTED and not mode_lost:
        before = newest(ROOT / "build" / "domains_checked" / "*.txt")
        http_cmd = [sys.executable, "check-domains.py", str(DOMAINS_DIR),
                    "-q", "-c", str(args.http_concurrency), "--operator", operator]
        # Тот же набор доменов, что и на шаге пар: иначе HTTP-мнение
        # получат домены, которых нет в наблюдениях.
        http_limit = args.http_limit or args.limit
        if http_limit:
            http_cmd += ["--limit", str(http_limit)]
        if args.http_timeout:
            http_cmd += ["--timeout", str(args.http_timeout)]
        if args.dns:
            http_cmd += ["--dns"] + args.dns
        # Без кэша HTTP-шаг в режиме белого списка резолвит через DNS оператора
        # и получает DNS_ERR на всё, что вне списка: мерить становится нечего.
        if cache_args:
            http_cmd += cache_args
        if iface:
            http_cmd += ["--interface", iface]
        http_timeout = args.http_timeout or http_timeout_default()
        source = "флаг --http-timeout" if args.http_timeout else HTTP_CONFIG.name
        print(f"   HTTP-таймаут: {http_timeout:g} с ({source})", flush=True)
        run(http_cmd, "3/3 Проверка доменов по HTTP")
        after = newest(ROOT / "build" / "domains_checked" / "*.txt")
        if after and after != before:
            http_file = after
        if mode_guard and not INTERRUPTED:
            mode_lost = confirm_mismatch(iface, args.phase)

    saved = []
    if mode_lost:
        # Не «прерванный», а негодный прогон: часть проб снята при другом
        # режиме, и в runs/ он испортил бы вердикт всей серии.
        print(f"\n⛔ {mode_lost}: наблюдения в runs/ не сохраняются, release не собирается")
    else:
        runs_dir = ROOT / "runs" / operator / args.phase
        runs_dir.mkdir(parents=True, exist_ok=True)
        # Полные наблюдения кладём рядом: вердикт по адресам требует и провалов,
        # а pairs.tsv содержит только прошедшие пары.
        jsonl = sorted((out / "pairs").glob("pairs-*.jsonl"))
        summary_file = sorted((out / "pairs").glob("summary-*.json"))
        for source, suffix in ((out / "report" / "domains.txt", "tls.txt"),
                               (out / "report" / "pairs.tsv", "tls.tsv"),
                               (jsonl[0] if jsonl else None, "pairs.jsonl"),
                               (summary_file[0] if summary_file else None, "summary.json"),
                               (http_file, "http.txt")):
            if source and Path(source).exists():
                target = runs_dir / f"{stamp}-{suffix}"
                shutil.copyfile(source, target)
                saved.append(target)

    release_line = ""
    if saved and not args.no_release and not INTERRUPTED and not mode_lost:
        if args.phase != "on":
            print("\nℹ️  release не собирается: он строится только из прогонов "
                  "с включённым режимом белого списка (--phase on)")
        else:
            ensure_operator_in_manifest(operator)
            run([sys.executable, "build_all_release.py", "--only", operator],
                "Сборка release")
            domain_list = ROOT / "release" / f"whitelist-{operator}.txt"
            ip_list = ROOT / "release" / f"IP-whitelist-{operator}.txt"
            if domain_list.exists():
                release_line = (f"   release: {domain_list.relative_to(ROOT)} "
                                f"({len(domain_list.read_text(encoding='utf-8').split())} доменов)")
                if ip_list.exists():
                    release_line += (f", {ip_list.relative_to(ROOT)} "
                                     f"({len(ip_list.read_text(encoding='utf-8').split())} адресов)")

    elapsed = int(time.time() - started)
    print("\n" + "=" * 66, flush=True)
    print(f"Готово за {elapsed // 60} мин {elapsed % 60} с · "
          f"оператор: {operator} · фаза: {args.phase}")
    if saved:
        print(f"   наблюдения: {', '.join(t.name for t in saved)} → "
              f"runs/{operator}/{args.phase}/")
    if release_line:
        print(release_line)
    print(f"   подробности: {out.relative_to(ROOT)}")
    if mode_lost:
        print(f"   ⛔ прогон негоден: {mode_lost}. Повторите, когда режим будет "
              f"соответствовать --phase {args.phase}")
        return EXIT_MODE_LOST
    if INTERRUPTED:
        print("   ⚠️  прогон неполный: наблюдения сохранены с пометкой interrupted, "
              "в вердикты такую серию лучше не брать целиком")
        return 130
    if pairs_code != 0:
        print("   ⚠️  проверка пар завершилась с ошибкой — смотрите вывод выше")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n⚠️  прервано пользователем")
        sys.exit(130)
