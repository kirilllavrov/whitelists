#!/usr/bin/env python3
"""
Сборка release-списков по всем операторам из манифеста.

Операторы фильтруют по-разному и в разное время, поэтому общего списка
«для всех» не существует: у каждого свои `whitelist-<оператор>.txt` и
`IP-whitelist-<оператор>.txt`. Источники — накопленные наблюдения из
`runs/<оператор>/` (домены в .txt, прошедшие пары в pairs.tsv).

Пример:
    python3 tools/build_all_release.py
    python3 tools/build_all_release.py --only rostelecom --check
"""
import argparse
import csv
import glob
import json
import sys
from pathlib import Path
from typing import Any, Dict, Set

TOOLS_DIR = Path(__file__).resolve().parent
ROOT = TOOLS_DIR.parent
sys.path.insert(0, str(TOOLS_DIR))

import platform_support as plat  # noqa: E402

from build_release import aggregate, collect_ips, read_domains  # noqa: E402
from operators import canonical_key  # noqa: E402

MANIFEST = ROOT / "configs" / "release.json"
RELEASE_DIR = ROOT / "release"


def expand(patterns):
    paths = []
    for pattern in patterns:
        matched = sorted(glob.glob(str(ROOT / pattern)))
        if not matched:
            print(f"   ⚠️  нет файлов по маске {pattern}")
        paths.extend(matched)
    return paths


class NoSources(Exception):
    """Оператор объявлен в манифесте, но наблюдений по нему ещё нет."""


def operators_in(path: Path) -> Set[str]:
    """Значения поля operator в наблюдениях (TSV или JSONL)."""
    values: Set[str] = set()
    try:
        if path.suffix == ".tsv":
            with open(path, "r", encoding="utf-8") as f:
                for row in csv.DictReader(f, delimiter="\t"):
                    value = (row.get("operator") or "").strip()
                    if value:
                        values.add(value)
        else:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    value = str(record.get("operator") or "").strip()
                    if value:
                        values.add(value)
    except OSError:
        return values
    return values


def warn_operator_mismatch(path: Path, operator: str, manifest: Dict[str, Any]) -> None:
    """Наблюдения должны лежать в каталоге своего оператора.

    Файл в чужой папке молча портит release: домены одного оператора попадут
    в список другого. Переписывать наблюдения не будем — в них записано то,
    что было в момент прогона, поэтому только предупреждаем.
    """
    for value in sorted(operators_in(path)):
        key = canonical_key(value, manifest)
        if key and key != operator:
            print(f"   ⚠️  {path.name}: в наблюдениях оператор «{value}», "
                  f"а каталог — «{operator}»")


def build(operator, spec):
    """Считает домены оператора и возвращает (домены, число источников)."""
    sources = expand(spec.get("sources", []))
    if not sources:
        raise NoSources(operator)

    sets = {}
    for path in sources:
        sets[Path(path).name] = read_domains(Path(path))

    mode = spec.get("mode", "intersection")
    if mode == "intersection":
        result = set.intersection(*sets.values())
    elif mode == "union":
        result = set.union(*sets.values())
    else:
        required = spec.get("min_sources") or (len(sets) // 2 + 1)
        counts = {}
        for values in sets.values():
            for domain in values:
                counts[domain] = counts.get(domain, 0) + 1
        result = {d for d, c in counts.items() if c >= required}

    title = spec.get("title", operator)
    print(f"\n{title}  (режим: {mode}, источников: {len(sets)})")
    for name, values in sets.items():
        print(f"   {len(values):4} доменов — {name}")
    return sorted(result), len(sets)


def main():
    plat.setup_console()
    parser = argparse.ArgumentParser(description="Сборка release-списков по операторам")
    parser.add_argument("--config", default=str(MANIFEST), help="Манифест операторов")
    parser.add_argument("--only", action="append", default=[],
                        help="Собрать только указанных операторов (можно несколько раз)")
    parser.add_argument("--check", action="store_true",
                        help="Не писать файлы, только сверить с текущими в release/")
    args = parser.parse_args()

    manifest = json.loads(Path(args.config).read_text(encoding="utf-8"))
    if args.only:
        missing = [name for name in args.only if name not in manifest]
        if missing:
            raise SystemExit(f"❌ нет в манифесте: {', '.join(missing)}")

    failed = []
    for operator, spec in manifest.items():
        if args.only and operator not in args.only:
            continue
        try:
            domains, _ = build(operator, spec)
        except NoSources:
            print(f"\n{spec.get('title', operator)}: наблюдений пока нет — пропускаю")
            continue

        pairs = expand(spec.get("pairs", []))
        for pair_path in pairs:
            warn_operator_mismatch(Path(pair_path), operator, manifest)
        ips = collect_ips(pairs, domains) if pairs else []
        nets = aggregate(ips) if ips else []

        print(f"   → доменов: {len(domains)}, адресов: {len(ips)}, записей: {len(nets)}")

        outputs = {
            RELEASE_DIR / f"whitelist-{operator}.txt": domains,
            RELEASE_DIR / f"IP-whitelist-{operator}.txt": [str(n) for n in nets],
        }
        for path, values in outputs.items():
            content = "\n".join(values) + "\n" if values else ""
            if args.check:
                current = path.read_text(encoding="utf-8") if path.exists() else None
                if current != content:
                    print(f"   ⚠️  {path.name} расходится с runs/ — нужна пересборка")
                    failed.append(operator)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            plat.write_text(path, content)
            print(f"   💾 {path.relative_to(ROOT)}")

    if failed:
        raise SystemExit(f"❌ проблемы с операторами: {', '.join(sorted(set(failed)))}")
    print("\n✅ готово")


if __name__ == "__main__":
    main()
