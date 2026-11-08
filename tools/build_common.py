#!/usr/bin/env python3
"""Один whitelist для всех операторов: строгое пересечение вердиктов.

Почему пересечение
------------------
Список нужен, чтобы пускать домен напрямую мимо туннеля. Цена ошибок
несимметрична: лишний домен в списке — трафик идёт напрямую, а оператор его
режет, и сервис не работает; пропущенный домен — трафик идёт через туннель и
работает, просто менее оптимально. Поэтому в общий список попадает только то,
что подтверждено у КАЖДОГО оператора, по которому есть замеры.

Правила
-------
- вердикт оператора берётся из build/classify/<оператор>-on/classify.json;
- домен включается, только если у всех операторов с данными вердикт «разрешён»
  (все адреса проходят, содержимое подтверждено);
- «частично», «нестабильно», «содержимое не подтверждено», «не разрешён»
  и отсутствие данных — домен не включается;
- домен, чей адрес делят другие домены итогового списка, помечается как
  «общий адрес»: доступ держится на соседстве с чужим сервисом и пропадёт
  при смене адреса. Такие домены включаются, но идут отдельной секцией.

Результат: release/whitelist-common.txt, release/IP-whitelist-common.txt,
release/whitelist-common.meta.json и отчёт build/common/report.md.
"""
import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

TOOLS_DIR = Path(__file__).resolve().parent
ROOT = TOOLS_DIR.parent
sys.path.insert(0, str(TOOLS_DIR))

import platform_support as plat  # noqa: E402

from operators import canonical_key, display, load_manifest  # noqa: E402

MANIFEST = ROOT / "configs" / "release.json"
CLASSIFY_DIR = ROOT / "build" / "classify"
RELEASE_DIR = ROOT / "release"
OUT_DIR = ROOT / "build" / "common"

VERDICT_ALLOWED = "разрешён"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Общий whitelist: пересечение вердиктов всех операторов с данными")
    parser.add_argument("--phase", default="on", help="Фаза прогонов (по умолчанию on)")
    parser.add_argument("--classify-dir", default=None,
                        help="Каталог с <оператор>-<фаза>/classify.json")
    parser.add_argument("--only", nargs="+", default=[],
                        help="Учитывать только этих операторов")
    parser.add_argument("--min-operators", type=int, default=1,
                        help="Сколько операторов с данными нужно, чтобы строить список")
    parser.add_argument("--out-dir", default=None, help="Куда положить отчёт")
    parser.add_argument("--write-release", action="store_true",
                        help="Записать списки в release/")
    return parser.parse_args()


def discover(classify_dir: Path, phase: str, manifest: Dict[str, Any],
             only: List[str]) -> Dict[str, Dict[str, Any]]:
    """Вердикты операторов, у которых есть результаты."""
    found: Dict[str, Dict[str, Any]] = {}
    suffix = f"-{phase}"
    # Имена приводятся к каноническим: --only Megafon не должен отбрасывать megafon.
    wanted = {canonical_key(value, manifest) or value for value in only} if only else set()
    for path in sorted(classify_dir.glob(f"*{suffix}/classify.json")):
        operator = canonical_key(path.parent.name[: -len(suffix)], manifest)
        if wanted and operator not in wanted:
            continue
        try:
            found[operator] = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"⚠️  {path} не прочитан: {exc}")
    return found


def collect(data: Dict[str, Dict[str, Any]]) -> Tuple[Set[str], Dict[str, Any]]:
    """Домены с вердиктом «разрешён» у каждого оператора с данными."""
    if not data:
        return set(), {}
    common: Set[str] = set.intersection(*[set(d["domains"]) for d in data.values()])
    details: Dict[str, Any] = {}
    for domain in common:
        verdicts = {op: d["domains"][domain]["verdict"] for op, d in data.items()}
        if all(verdict == VERDICT_ALLOWED for verdict in verdicts.values()):
            details[domain] = verdicts
    return common, details


def addresses(data: Dict[str, Dict[str, Any]], domain: str) -> List[str]:
    """Адреса домена, прошедшие у всех операторов."""
    per_operator = []
    for operator_data in data.values():
        info = operator_data["domains"].get(domain) or {}
        per_operator.append({a["ip"] for a in info.get("addresses", [])
                             if a["state"] == "разрешён"})
    if not per_operator:
        return []
    return sorted(set.intersection(*per_operator))


def shared_flags(chosen: List[str], data: Dict[str, Dict[str, Any]]) -> Dict[str, List[str]]:
    """Адреса домена, которые он делит с другими доменами итогового списка."""
    owners: Dict[str, Set[str]] = defaultdict(set)
    for domain in chosen:
        for ip in addresses(data, domain):
            owners[ip].add(domain)
    flags: Dict[str, List[str]] = {}
    for domain in chosen:
        shared = [ip for ip in addresses(data, domain) if len(owners[ip]) > 1]
        if shared:
            flags[domain] = sorted(shared)
    return flags


def only_some(data: Dict[str, Dict[str, Any]]) -> Dict[str, List[str]]:
    """Домены, разрешённые не у всех: кто пускает, а кто нет."""
    domains: Set[str] = set().union(*[set(d["domains"]) for d in data.values()])
    result: Dict[str, List[str]] = defaultdict(list)
    for domain in sorted(domains):
        verdicts = {op: d["domains"].get(domain, {}).get("verdict", "нет данных")
                    for op, d in data.items()}
        allowed = [op for op, v in verdicts.items() if v == VERDICT_ALLOWED]
        denied = [op for op, v in verdicts.items()
                  if v in ("не разрешён", "нестабильно", "содержимое не подтверждено")]
        if allowed and denied:
            result["|".join(allowed)].append(domain)
    return result


def main() -> None:
    plat.setup_console()
    args = parse_args()
    manifest = load_manifest(MANIFEST)
    classify_dir = Path(args.classify_dir) if args.classify_dir else CLASSIFY_DIR
    data = discover(classify_dir, args.phase, manifest, args.only)
    if len(data) < max(args.min_operators, 1):
        raise SystemExit(f"❌ операторов с данными: {len(data)} — строить нечего")

    names = ", ".join(display(op, manifest) for op in data)
    print(f"операторы с данными: {names}")

    common, details = collect(data)
    chosen = sorted(details)
    flags = shared_flags(chosen, data)
    ips: Set[str] = set()
    for domain in chosen:
        ips.update(addresses(data, domain))

    out_dir = Path(args.out_dir).resolve() if args.out_dir else OUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\nдоменов с вердиктами у всех: {len(common)}")
    print(f"разрешены у всех:            {len(chosen)}")
    print(f"  из них на общем адресе:    {len(flags)}")
    print(f"адресов:                     {len(ips)}")

    plat.write_lines(out_dir / "whitelist-common.txt", chosen)
    plat.write_lines(out_dir / "ips-common.txt", sorted(ips))
    (out_dir / "verdicts.json").write_text(
        json.dumps({"operators": list(data), "domains": details,
                    "shared_addresses": flags}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8")

    only = only_some(data)
    lines = ["# Общий whitelist (пересечение)", "",
             f"- построен: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
             f"- операторы с данными: {names}",
             f"- доменов с вердиктами у всех: {len(common)}",
             f"- **разрешены у всех: {len(chosen)}**",
             f"- из них на общем адресе: {len(flags)}",
             f"- адресов: {len(ips)}", "",
             "## Правило", "",
             "Домен попадает в список, только если у каждого оператора с замерами",
             "вердикт «разрешён»: проходят все адреса и содержимое подтверждено.",
             "«Частично», «нестабильно» и «содержимое не подтверждено» не включаются.",
             ""]
    if flags:
        lines += [f"## На общем адресе ({len(flags)})", "",
                  "Адрес делят другие домены списка: доступ держится на соседстве "
                  "с чужим сервисом и пропадёт, если сервис сменит адрес.", "",
                  "| Домен | Общие адреса |", "|---|---|"]
        for domain in sorted(flags)[:80]:
            lines.append(f"| `{domain}` | {', '.join(flags[domain])} |")
    if only:
        lines += ["", "## Разрешены не у всех", ""]
        for group, domains in sorted(only.items(), key=lambda kv: -len(kv[1])):
            lines.append(f"### пускают: {group} ({len(domains)})")
            lines.append("")
            lines.append(", ".join(f"`{d}`" for d in domains[:60]))
            lines.append("")
    (out_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    if args.write_release:
        RELEASE_DIR.mkdir(parents=True, exist_ok=True)
        plat.write_lines(RELEASE_DIR / "whitelist-common.txt", chosen)
        plat.write_lines(RELEASE_DIR / "IP-whitelist-common.txt", sorted(ips))
        plat.write_text(
            RELEASE_DIR / "whitelist-common.meta.json",
            json.dumps({
                "built_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%S%z"),
                "phase": args.phase,
                "operators": {op: display(op, manifest) for op in data},
                # Сколько прогонов лежит в основе каждого списка: по одному
                # прогону вердикт держится на единичных прохождениях, и это
                # должно быть видно прямо в метаданных.
                "runs": {op: (d.get("basis") or {}).get("runs", "?")
                         for op, d in data.items()},
                "domains": len(chosen),
                "addresses": len(ips),
                "shared_address_domains": len(flags),
            }, indent=2, ensure_ascii=False) + "\n")
        print(f"\n💾 release/whitelist-common.txt: {len(chosen)} доменов")
        print(f"💾 release/IP-whitelist-common.txt: {len(ips)} адресов")

    print(f"\n💾 {out_dir.relative_to(ROOT)}: whitelist-common.txt, ips-common.txt, "
          f"report.md, verdicts.json")


if __name__ == "__main__":
    main()
