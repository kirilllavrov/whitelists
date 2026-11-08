#!/usr/bin/env python3
"""Вердикт по домену: разрешён, частично, не разрешён или нестабилен.

Почему не «прошёл в N файлах»
-----------------------------
Фильтрация в режиме белого списка идёт по адресу: одно имя проходит на всех
своих адресах, другое — только на части (проверено на Ростелекоме: у ok.ru
217.20.157.145 проходит всегда, а 5.61.21.121 — никогда). Поэтому единица
наблюдения — пара (домен, адрес), а вердикт домена собирается из вердиктов
его адресов.

Правило (согласовано):
  разрешён     — каждый адрес домена проходит в ≥ --min-ratio попыток
                 И содержимое подтверждено HTTP в ≥ --min-http доле прогонов
  частично     — проходит не каждый адрес (в отчёте видно, какие проходят)
  не разрешён  — ни один адрес не прошёл ни разу
  нестабильно  — остальное: адрес проходит иногда, нужно ещё прогонов
  не измеряется— у домена не было ни одного адреса в наблюдениях

Домен, который проходит через адрес, общий с другими доменами, помечается
как «общий IP»: доступ есть, но он держится на соседстве и пропадёт, если
сервис сменит адрес (так работает wiki.freenternet.top на Yandex Cloud).

Читает полные наблюдения `runs/<оператор>/<фаза>/*-pairs.jsonl`
(их пишет check.py) и `*-http.txt` из тех же прогонов.
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

TOOLS_DIR = Path(__file__).resolve().parent
ROOT = TOOLS_DIR.parent
sys.path.insert(0, str(TOOLS_DIR))

import platform_support as plat  # noqa: E402

from build_release import read_domains  # noqa: E402
from operators import canonical_key, display, load_manifest  # noqa: E402

RELEASE_MANIFEST = ROOT / "configs" / "release.json"
CONTROL_FILE = ROOT / "configs" / "control-domains.txt"
RUNS_DIR = ROOT / "runs"
RELEASE_DIR = ROOT / "release"

VERDICT_ALLOWED = "разрешён"
VERDICT_PARTIAL = "частично"
VERDICT_CONTENT = "содержимое не подтверждено"
VERDICT_BLOCKED = "не разрешён"
VERDICT_UNSTABLE = "нестабильно"
VERDICT_UNKNOWN = "не измеряется"

ADR_ALLOWED = "разрешён"
ADR_BLOCKED = "не разрешён"
ADR_UNSTABLE = "нестабилен"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Вердикт по доменам из нескольких прогонов фазы on")
    parser.add_argument("-o", "--operator", required=True,
                        help="Оператор: ключ манифеста или каталог runs/<оператор>")
    parser.add_argument("--phase", default="on",
                        help="Фаза прогонов: on (по умолчанию) или off")
    parser.add_argument("-d", "--runs-dir", default=None,
                        help="Каталог наблюдений (по умолчанию runs/<оператор>/<фаза>)")
    parser.add_argument("--min-ratio", type=float, default=0.8,
                        help="Верхняя граница порога: доля успешных попыток, при "
                             "которой адрес считается разрешённым, когда канал "
                             "работает идеально")
    parser.add_argument("--control-file", default=None,
                        help="Эталонные домены для калибровки порога (по умолчанию "
                             "configs/control-domains.txt)")
    parser.add_argument("--control-factor", type=float, default=0.75,
                        help="Порог = доля успеха эталона × коэффициент (0.75), "
                             "но не выше --min-ratio")
    parser.add_argument("--min-http", type=float, default=0.9,
                        help="Доля прогонов, где содержимое подтверждено HTTP")
    parser.add_argument("--min-attempts", type=int, default=2,
                        help="Сколько попыток нужно, чтобы судить об адресе")
    parser.add_argument("-O", "--out-dir", default=None,
                        help="Куда положить результат (по умолчанию build/classify/<оператор>-<фаза>)")
    parser.add_argument("--write-release", action="store_true",
                        help="Обновить release/whitelist-<оператор>.txt и IP-список")
    return parser.parse_args()


def find_runs(directory: Path) -> Tuple[List[Path], List[Path]]:
    """Файлы наблюдений и файлы HTTP-подтверждений одного прогона."""
    jsonl = sorted(directory.glob("*-pairs.jsonl"))
    http = sorted(directory.glob("*-http.txt"))
    if jsonl:
        return jsonl, http
    # Старый формат: только прошедшие пары. Провалов нет, вердикт будет неполным.
    tsv = sorted(directory.glob("*-tls.tsv"))
    if tsv:
        print("⚠️  найдены только pairs.tsv (без провалов): "
              "адреса «не разрешён» и «нестабилен» определить нельзя")
    return tsv, http


def load_unresolved(paths: List[Path]) -> Set[str]:
    """Домены, у которых в прогонах не оказалось ни одного адреса.

    Записи есть (DNS_NX), но `load_run` их отбрасывает: без адреса пары нет.
    Без этого списка такие домены молча выпадают из отчёта.
    """
    result: Set[str] = set()
    for path in paths:
        if path.suffix == ".tsv":
            continue
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("probe") != "matrix":
                    continue
                domain = (record.get("domain") or "").strip().lower()
                if domain and not (record.get("ip") or "").strip():
                    result.add(domain)
    return result


def load_run(path: Path) -> Dict[Tuple[str, str], List[int]]:
    """Пары (домен, адрес) → [успехов, попыток] в одном прогоне."""
    result: Dict[Tuple[str, str], List[int]] = defaultdict(lambda: [0, 0])
    if path.suffix == ".tsv":
        import csv
        with open(path, "r", encoding="utf-8") as handle:
            for row in csv.DictReader(handle, delimiter="\t"):
                domain = (row.get("domain") or "").strip().lower()
                address = (row.get("ip") or "").strip()
                if not domain or not address:
                    continue
                try:
                    passes = int(row.get("pass_count") or 0)
                    attempts = int(row.get("attempts") or 1)
                except ValueError:
                    continue
                result[(domain, address)][0] += passes
                result[(domain, address)][1] += attempts
        return result

    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("probe") != "matrix":
                continue
            domain = (record.get("domain") or "").strip().lower()
            address = (record.get("ip") or "").strip()
            if not domain or not address:
                continue
            attempts = int(record.get("attempts") or 1)
            passes = int(record.get("pass_count") or 0)
            result[(domain, address)][0] += passes
            result[(domain, address)][1] += attempts
    return result


def load_control(path: Optional[Path]) -> set:
    if not path or not Path(path).exists():
        return set()
    values = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            values.add(line)
    return values


def control_ratio(totals: Dict[Tuple[str, str], List[int]], control: set) -> Tuple[float, int]:
    """Доля успеха эталонных доменов в этих же прогонах: качество канала здесь и сейчас.

    Абсолютный порог на мобильном канале не работает: в замерах даже yandex.ru
    проходил 6–7 попыток из 10, и «разрешённый» домен выглядел заблокированным.
    Эталон задаёт масштаб: сколько сейчас теряет сам канал.
    """
    per_domain: Dict[str, List[int]] = defaultdict(lambda: [0, 0])
    for (domain, _), (done, total) in totals.items():
        if domain in control:
            per_domain[domain][0] += done
            per_domain[domain][1] += total
    if not per_domain:
        return 0.0, 0
    # Медиана по доменам, а не общая доля: если оператор закрыл один-два
    # эталонных сервиса, это не должно расшатывать порог для всех остальных.
    ratios = sorted(done / total for done, total in per_domain.values() if total)
    mid = ratios[len(ratios) // 2]
    return mid, sum(total for _, total in per_domain.values())


def effective_threshold(args: argparse.Namespace, control_rate: float) -> float:
    if control_rate <= 0:
        return args.min_ratio
    return min(args.min_ratio, args.control_factor * control_rate)


def address_verdict(passes: int, attempts: int, threshold: float,
                    min_attempts: int) -> str:
    if passes == 0:
        return ADR_BLOCKED
    if attempts < min_attempts:
        return ADR_UNSTABLE
    ratio = passes / attempts
    if ratio >= threshold:
        return ADR_ALLOWED
    return ADR_UNSTABLE


def build(runs: List[Path], http_files: List[Path],
          args: argparse.Namespace) -> Dict[str, Any]:
    totals: Dict[Tuple[str, str], List[int]] = defaultdict(lambda: [0, 0])
    for path in runs:
        for key, (passes, attempts) in load_run(path).items():
            totals[key][0] += passes
            totals[key][1] += attempts
    unresolved = load_unresolved(runs)

    control = load_control(Path(args.control_file) if args.control_file else CONTROL_FILE)
    control_rate, control_attempts = control_ratio(totals, control)
    threshold = effective_threshold(args, control_rate)
    if control_attempts:
        print(f"эталон ({len(control & {d for d, _ in totals})} доменов, "
              f"{control_attempts} попыток): доля успеха {control_rate:.2f} "
              f"→ порог адреса {threshold:.2f}")
    else:
        print(f"⚠️  эталон не найден в наблюдениях — порог {threshold:.2f} (абсолютный)")

    http_sets = [read_domains(path) for path in http_files]
    http_count: Dict[str, int] = defaultdict(int)
    for values in http_sets:
        for domain in values:
            http_count[domain] += 1
    # Знаменатель — прогоны, где HTTP-шаг действительно был, а не все прогоны
    # пар: иначе один прогон с --no-http делает 2/3 < 0.9 и весь список
    # уезжает в «содержимое не подтверждено».
    http_runs = len(http_files)
    if not http_runs:
        print("⚠️  HTTP-подтверждений нет: содержимое не проверялось, "
              "вердикт только по парам")

    by_domain: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for (domain, address), (passes, attempts) in totals.items():
        by_domain[domain].append({
            "ip": address,
            "passes": passes,
            "attempts": attempts,
            "ratio": round(passes / attempts, 3) if attempts else 0.0,
            "state": address_verdict(passes, attempts, threshold, args.min_attempts),
        })

    # адрес, на котором живёт больше одного домена, — общий (хостинг, CDN)
    hosts: Dict[str, int] = defaultdict(int)
    for domain, addresses in by_domain.items():
        for item in addresses:
            hosts[item["ip"]] += 1

    domains: Dict[str, Any] = {}
    for domain, addresses in by_domain.items():
        allowed = [item for item in addresses if item["state"] == ADR_ALLOWED]
        http_ratio = (http_count.get(domain, 0) / http_runs) if http_runs else None
        http_ok = True if http_ratio is None else http_ratio >= args.min_http

        if not any(item["passes"] for item in addresses):
            verdict = VERDICT_BLOCKED
        elif len(allowed) == len(addresses):
            # Все адреса проходят, но содержимое не подтвердилось: это парковка,
            # чужой сертификат или пустой ответ — не фильтрация оператора.
            verdict = VERDICT_ALLOWED if http_ok else VERDICT_CONTENT
        elif allowed:
            verdict = VERDICT_PARTIAL
        else:
            verdict = VERDICT_UNSTABLE

        shared = sorted({item["ip"] for item in allowed if hosts[item["ip"]] > 1})
        # Самая слабая доля среди разрешённых адресов: показывает, насколько
        # вердикт близок к границе.
        weakest = min((item["ratio"] for item in allowed), default=0.0)
        domains[domain] = {
            "verdict": verdict,
            "http": round(http_ratio, 2) if http_ratio is not None else None,
            "weakest_ratio": weakest,
            "addresses": sorted(addresses, key=lambda item: (-item["passes"], item["ip"])),
            "shared_ips": shared,
        }

    # Домены без единого адреса: измерять было нечего, но и терять их нельзя.
    for domain in sorted(unresolved - set(domains)):
        domains[domain] = {"verdict": VERDICT_UNKNOWN, "http": None,
                           "weakest_ratio": 0.0, "addresses": [], "shared_ips": []}
    return {"runs": [path.name for path in runs], "domains": domains,
            # На чём построены вердикты: по этим числам видно, можно ли им
            # доверять (один прогон или одна попытка на адрес — мало).
            "basis": {"runs": len(runs), "http_runs": http_runs,
                      "min_attempts": args.min_attempts,
                      "max_attempts": max((total for _, total in totals.values()),
                                          default=0)},
            "control": {"rate": round(control_rate, 3), "attempts": control_attempts,
                        "domains": sorted(control), "threshold": round(threshold, 3)}}


def write_outputs(data: Dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    domains = data["domains"]
    groups: Dict[str, List[str]] = defaultdict(list)
    for domain, info in domains.items():
        groups[info["verdict"]].append(domain)

    names = {
        VERDICT_ALLOWED: "allowed.txt",
        VERDICT_PARTIAL: "partial.txt",
        VERDICT_CONTENT: "content-unconfirmed.txt",
        VERDICT_BLOCKED: "blocked.txt",
        VERDICT_UNSTABLE: "unstable.txt",
        VERDICT_UNKNOWN: "not-measured.txt",
    }
    for verdict, filename in names.items():
        values = sorted(groups.get(verdict, []))
        plat.write_lines(out_dir / filename, values)
    (out_dir / "classify.json").write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    allowed_ips = sorted({item["ip"]
                          for verdict in (VERDICT_ALLOWED, VERDICT_PARTIAL)
                          for domain, info in domains.items() if info["verdict"] == verdict
                          for item in info["addresses"] if item["state"] == ADR_ALLOWED})
    (out_dir / "ips-allowed.txt").write_text(
        "\n".join(allowed_ips) + ("\n" if allowed_ips else ""), encoding="utf-8")

    control = data.get("control") or {}
    lines = ["# Вердикт по доменам", "",
             f"- прогонов: {len(data['runs'])}",
             f"- доменов: {len(domains)}", ""]
    basis = data.get("basis") or {}
    if basis:
        lines += [f"- попыток на адрес: до {basis.get('max_attempts')} "
                  f"(минимум для суждения — {basis.get('min_attempts')})",
                  f"- прогонов с HTTP-шагом: {basis.get('http_runs')}", ""]
        if (basis.get("runs") or 0) < 3:
            # Один-два прогона — это ещё не серия: фильтрация меняется в пределах
            # минут, и вердикт держится на единичных прохождениях.
            lines += [f"> ⚠️ Прогонов меньше трёх ({basis.get('runs')}): вердикт "
                      "держится на единичных прохождениях. Для устойчивой картины "
                      "нужна серия из трёх прогонов.", ""]
    if control.get("attempts"):
        lines += [f"- эталон (качество канала): доля успеха "
                  f"**{control['rate']:.2f}** на {control['attempts']} попытках",
                  f"- порог «разрешён»: **{control['threshold']:.2f}** "
                  f"(эталон × коэффициент, не выше абсолютного)",
                  ""]
    for verdict in (VERDICT_ALLOWED, VERDICT_PARTIAL, VERDICT_CONTENT,
                    VERDICT_BLOCKED, VERDICT_UNSTABLE, VERDICT_UNKNOWN):
        lines.append(f"- {verdict}: **{len(groups.get(verdict, []))}**")
    lines += ["", "## Прогоны", ""] + [f"- `{name}`" for name in data["runs"]]

    partial = sorted(groups.get(VERDICT_PARTIAL, []))
    if partial:
        lines += ["", "## Частично доступные", "",
                  "| Домен | Проходят адреса | Не проходят |", "|---|---|---|"]
        for domain in partial:
            info = domains[domain]
            ok = [item["ip"] for item in info["addresses"] if item["state"] == ADR_ALLOWED]
            bad = [item["ip"] for item in info["addresses"] if item["state"] != ADR_ALLOWED]
            lines.append(f"| `{domain}` | {', '.join(ok) or '—'} | {', '.join(bad) or '—'} |")

    content = sorted(groups.get(VERDICT_CONTENT, []))
    if content:
        lines += ["", f"## Содержимое не подтверждено ({len(content)})", "",
                  "Адрес проходит, но сервис отвечает не тем: парковка, чужой "
                  "сертификат, пустая страница. К фильтрации оператора отношения нет.", "",
                  ", ".join(f"`{domain}`" for domain in content[:60])]

    shared = sorted(domain for domain, info in domains.items()
                    if info["verdict"] == VERDICT_ALLOWED and info["shared_ips"])
    if shared:
        lines += ["", f"## Доступны через общий адрес ({len(shared)})", "",
                  "Адрес проходит, но на нём живут и другие домены: доступ держится "
                  "на соседстве и пропадёт, если сервис сменит адрес.", ""]
        for domain in shared[:40]:
            lines.append(f"- `{domain}` — {', '.join(domains[domain]['shared_ips'])}")

    fragile = sorted((domain for domain, info in domains.items()
                      if info["verdict"] in (VERDICT_ALLOWED, VERDICT_PARTIAL)
                      and info["weakest_ratio"] < 0.95),
                     key=lambda name: domains[name]["weakest_ratio"])
    if fragile:
        lines += ["", f"## На границе ({len(fragile)})", "",
                  "Адрес проходит, но не в каждой попытке: держать в поле зрения.", "",
                  "| Домен | Слабая доля | HTTP |", "|---|---|---|"]
        for domain in fragile[:60]:
            info = domains[domain]
            http_text = "—" if info["http"] is None else f"{info['http']:.2f}"
            lines.append(f"| `{domain}` | {info['weakest_ratio']:.2f} | {http_text} |")

    unstable = sorted(groups.get(VERDICT_UNSTABLE, []))
    if unstable:
        lines += ["", f"## Нестабильные ({len(unstable)})", "",
                  "Адрес проходит не всегда: нужен ещё прогон, чтобы решить.", "",
                  ", ".join(f"`{domain}`" for domain in unstable[:80])]
    (out_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_release(operator: str, data: Dict[str, Any], out_dir: Path) -> None:
    domains = data["domains"]
    # Только «разрешён»: у «частично» закрыта часть адресов, а клиент адрес
    # не выбирает — домен в списке работал бы через раз.
    allowed = sorted(domain for domain, info in domains.items()
                     if info["verdict"] == VERDICT_ALLOWED)
    ips = sorted({item["ip"] for domain in allowed
                  for item in domains[domain]["addresses"] if item["state"] == ADR_ALLOWED})
    RELEASE_DIR.mkdir(parents=True, exist_ok=True)
    plat.write_lines(RELEASE_DIR / f"whitelist-{operator}.txt", allowed)
    plat.write_lines(RELEASE_DIR / f"IP-whitelist-{operator}.txt", ips)
    print(f"💾 release/whitelist-{operator}.txt: {len(allowed)} доменов")
    print(f"💾 release/IP-whitelist-{operator}.txt: {len(ips)} адресов")


def main() -> None:
    plat.setup_console()
    args = parse_args()
    manifest = load_manifest(RELEASE_MANIFEST)
    operator = canonical_key(args.operator, manifest) or args.operator
    runs_dir = Path(args.runs_dir) if args.runs_dir else RUNS_DIR / operator / args.phase
    if not runs_dir.is_dir():
        raise SystemExit(f"❌ нет каталога наблюдений: {runs_dir}")

    runs, http_files = find_runs(runs_dir)
    if not runs:
        raise SystemExit(f"❌ в {runs_dir} нет наблюдений")

    print(f"{display(operator, manifest)} · фаза {args.phase} · "
          f"прогонов: {len(runs)} · HTTP-файлов: {len(http_files)}")
    data = build(runs, http_files, args)
    out_dir = Path(args.out_dir) if args.out_dir else ROOT / "build" / "classify" / f"{operator}-{args.phase}"
    write_outputs(data, out_dir)

    counts: Dict[str, int] = defaultdict(int)
    for info in data["domains"].values():
        counts[info["verdict"]] += 1
    print(f"\nдоменов: {len(data['domains'])}")
    for verdict in (VERDICT_ALLOWED, VERDICT_PARTIAL, VERDICT_CONTENT,
                    VERDICT_BLOCKED, VERDICT_UNSTABLE, VERDICT_UNKNOWN):
        print(f"   {verdict:26} {counts.get(verdict, 0)}")
    try:
        shown = out_dir.resolve().relative_to(ROOT)
    except ValueError:
        shown = out_dir
    print(f"\n💾 {shown}: classify.json, report.md, *.txt")

    if args.write_release:
        write_release(operator, data, out_dir)


if __name__ == "__main__":
    main()
