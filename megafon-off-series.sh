#!/bin/bash
# Baseline Мегафона при выключенном режиме БС: три прогона с паузой.
cd /home/lavrov/Checloud/Проекты/Xray/Whitelists || exit 1
for i in 1 2 3; do
    echo "=== прогон $i из 3 · $(date '+%Y-%m-%d %H:%M:%S') ==="
    python3 tools/check.py -o Megafon --phase off --no-release
    echo "=== прогон $i завершён с кодом $? · $(date '+%H:%M:%S') ==="
    if [ "$i" -lt 3 ]; then
        sleep 180
    fi
done
echo "=== серия off завершена · $(date '+%Y-%m-%d %H:%M:%S') ==="
