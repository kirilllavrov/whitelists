#!/usr/bin/env python3
import glob
import re
import os
import math

def merge_whitelists_intermediate(directory_pattern: str, threshold_percent: float):
    """Считает встречаемость доменов и возвращает список, прошедший порог."""
    all_domains = {}
    file_count = 0

    for filename in glob.glob(directory_pattern):
        if re.search(r'whitelist-.*\.txt$', os.path.basename(filename)):
            print(f"📄 Обработка: {filename}")
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    unique_in_file = set()
                    for line in f:
                        domain = line.strip()
                        if domain:
                            unique_in_file.add(domain)
                    for domain in unique_in_file:
                        all_domains[domain] = all_domains.get(domain, 0) + 1
                file_count += 1
            except Exception as e:
                print(f"❌ Ошибка чтения {filename}: {e}")

    print(f"✅ Обработано файлов: {file_count}")
    if file_count == 0:
        print("⚠️  Нет подходящих файлов для анализа.")
        return [], threshold_percent, file_count, 0

    required = min(math.ceil(threshold_percent / 100.0 * file_count), file_count)
    print(f"📊 Порог: {threshold_percent}% → Домен должен быть в ≥ {required} из {file_count} файлов")

    filtered = [d for d, count in all_domains.items() if count >= required]
    return filtered, threshold_percent, file_count, required

def load_mandatory_domains(filepath: str) -> set:
    """Загружает обязательные домены, игнорируя комментарии и пустые строки."""
    mandatory = set()
    if not os.path.exists(filepath):
        print(f"⚠️  Файл обязательных доменов не найден: {filepath}")
        return mandatory
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    mandatory.add(line.lower())  # DNS регистронезависим
    except Exception as e:
        print(f"❌ Ошибка чтения {filepath}: {e}")
    return mandatory

if __name__ == "__main__":
    INPUT_PATTERN = "../build/domains_checked/*.txt"
    THRESHOLD_PERCENT = 75.0
    MANDATORY_FILE = "../configs/minimal-whitelist.list"

    # 1. Собираем домены по порогу
    merged_list, _, sources_found, required_count = merge_whitelists_intermediate(INPUT_PATTERN, THRESHOLD_PERCENT)

    # 2. Загружаем обязательные домены
    mandatory_domains = load_mandatory_domains(MANDATORY_FILE)

    # 3. Объединяем, убираем дубликаты, сортируем
    final_domains = sorted(set(merged_list) | mandatory_domains)

    print(f"\n➕ Обязательно добавлено: {len(mandatory_domains)}")
    print(f"📦 Прошли по порогу: {len(merged_list)}")
    print(f"✅ Итоговый список: {len(final_domains)} доменов")

    # 4. Сохранение
    output_dir = "../release/"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "whitelist.txt")

    print(f"💾 Сохранение в {output_file}...")
    with open(output_file, 'w', encoding='utf-8') as f:
        for domain in final_domains:
            f.write(domain + '\n')
    print("🎉 Готово!")
