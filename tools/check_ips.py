import subprocess
import sys
import os
import re
import ipaddress
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import time

# ================= КОНФИГУРАЦИЯ =================
INPUT_DIRECTORY = "../src/IPs"
RESULTS_DIR = "../build/IP_checked"
NUM_THREADS = 500                    # Потоки
MAX_QUEUE_SIZE = 10000               # Очередь задач (защита RAM)
PING_TIMEOUT = 3                     # Таймаут (лучше меньше для скорости)
MAX_IPS_PER_CIDR = 500000            # Лимит на один CIDR (защита от /8)
STATS_INTERVAL = 10                  # Секунды между выводом статистики
# ================================================

def generate_ips_from_cidr(cidr_str):
    """Генератор IP из CIDR с защитой от переполнения."""
    try:
        network = ipaddress.ip_network(cidr_str, strict=False)
        count = 0
        limit = MAX_IPS_PER_CIDR
        
        # Оптимизация: если сеть огромная, итерация может быть медленной на создание объектов
        # Но generators в Python достаточно быстрые.
        for host in network.hosts():
            if count >= limit:
                print(f"\n⚠️ Достигнут лимит {limit} IP для {cidr_str}. Остановка.")
                break
            yield str(host)
            count += 1
    except ValueError:
        print(f"⚠️ Невалидный CIDR: {cidr_str}")

def parse_cidrs_from_content(content):
    cidr_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b'
    cidrs = re.findall(cidr_pattern, content)
    valid = []
    for c in cidrs:
        try:
            ipaddress.ip_network(c, strict=False)
            valid.append(c)
        except ValueError:
            continue
    return valid

def ping_ip(ip):
    """Быстрый пинг."""
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT * 1000), ip]
        timeout_val = PING_TIMEOUT + 1
    else:
        cmd = ["ping", "-c", "1", "-W", str(PING_TIMEOUT), ip]
        timeout_val = PING_TIMEOUT + 1
    
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout_val)
        return ip, res.returncode == 0
    except (subprocess.TimeoutExpired, Exception):
        return ip, False

def consolidate_to_cidr(input_file):
    """Агрегация IP в CIDR."""
    print(f"\n🔄 Агрегация результатов в CIDR...")
    ips = []
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            for line in f:
                ip_str = line.strip()
                if ip_str:
                    try:
                        ips.append(ipaddress.ip_address(ip_str))
                    except ValueError:
                        pass
    except Exception as e:
        print(f"❌ Ошибка чтения: {e}")
        return

    if not ips:
        return

    print(f"📥 Загружено {len(ips)} адресов. Сортировка и сжатие...")
    ips.sort()
    
    try:
        collapsed = list(ipaddress.collapse_addresses(ips))
        print(f"✅ Сжато до {len(collapsed)} сетей.")
        
        with open(input_file, 'w', encoding='utf-8') as f:
            for net in collapsed:
                f.write(f"{net}\n")
        print(f"💾 Файл обновлен: {input_file}")
    except Exception as e:
        print(f"❌ Ошибка агрегации: {e}")

def process_stream(ip_generator, original_filename, results_dir):
    """
    Основной движок: непрерывный поток задач с контролем очереди.
    """
    base_name = os.path.splitext(os.path.basename(original_filename))[0]
    result_filename = f"available_ips_from_{base_name}.txt"
    result_path = os.path.join(results_dir, result_filename)
    temp_path = result_path + ".tmp"
    
    # Очищаем временный файл
    if os.path.exists(temp_path):
        os.remove(temp_path)

    print(f"🚀 Запуск потока проверки...")
    
    count_found = 0
    count_checked = 0
    last_stats_time = time.time()
    start_time = time.time()

    with open(temp_path, 'a', encoding='utf-8') as f_out:
        with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
            futures = {}
            ip_iter = iter(ip_generator)
            
            while True:
                # 1. Заполняем очередь до лимита
                while len(futures) < MAX_QUEUE_SIZE:
                    try:
                        ip = next(ip_iter)
                        fut = executor.submit(ping_ip, ip)
                        futures[fut] = ip
                    except StopIteration:
                        break
                
                if not futures:
                    break

                # 2. Ждем завершения хотя бы одной задачи (неблокирующий wait)
                done, _ = wait(futures.keys(), return_when=FIRST_COMPLETED)
                
                for fut in done:
                    ip, is_ok = fut.result()
                    count_checked += 1
                    
                    if is_ok:
                        f_out.write(ip + '\n')
                        # Важно: flush не делаем часто, ОС сама буферизирует, 
                        # но при крахе последние данные могут потеряться. 
                        # Для скорости лучше довериться ОС.
                        count_found += 1
                    
                    del futures[fut] # Освобождаем память!

                # 3. Вывод статистики без блокировки потока
                now = time.time()
                if now - last_stats_time >= STATS_INTERVAL:
                    elapsed = now - start_time
                    rate = count_checked / elapsed if elapsed > 0 else 0
                    print(f"📊 Найдено: {count_found} | Проверено: {count_checked} | Скорость: {rate:.1f} IP/сек")
                    last_stats_time = now

    elapsed_total = time.time() - start_time
    print(f"\n🏁 Готово за {elapsed_total:.1f} сек. Найдено: {count_found}, Проверено: {count_checked}")

    if count_found > 0:
        consolidate_to_cidr(temp_path)
        if os.path.exists(result_path):
            os.remove(result_path)
        os.rename(temp_path, result_path)
        print(f"📂 Итог: {result_path}")
    else:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        print("⚠️ Ничего не найдено.")

def process_cidr_file(filepath, results_dir):
    print(f"\n📄 Формат: CIDR -> {filepath}")
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    cidrs = parse_cidrs_from_content(content)
    if not cidrs:
        print("❌ Нет валидных CIDR.")
        return

    # Генератор всех IP из всех CIDR
    def all_ips():
        for cidr in cidrs:
            # print(f"   -> Разворачиваем {cidr}...") # Можно включить для отладки
            yield from generate_ips_from_cidr(cidr)

    process_stream(all_ips(), filepath, results_dir)

def process_ip_list_file(filepath, results_dir):
    print(f"\n📄 Формат: Список IP -> {filepath}")
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    def ip_gen():
        for line in content.splitlines():
            ip = line.strip()
            if ip:
                try:
                    ipaddress.ip_address(ip)
                    yield ip
                except ValueError:
                    pass
    
    process_stream(ip_gen(), filepath, results_dir)

def determine_file_type(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            sample = f.read(4096)
            if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b', sample):
                return "cidr"
            
            lines = sample.splitlines()[:50]
            valid_ips = 0
            for line in lines:
                try:
                    if line.strip():
                        ipaddress.ip_address(line.strip())
                        valid_ips += 1
                except: pass
            if valid_ips > 2:
                return "ip_list"
    except: pass
    return "unknown"

def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    print("="*50)
    print(f"🔍 IP SCANNER (Stream Mode)")
    print(f"⚙️ Настройки: потоки={NUM_THREADS}, очередь={MAX_QUEUE_SIZE}, таймаут={PING_TIMEOUT}с")
    print("="*50)
    print(f"📂 Директория результатов: {RESULTS_DIR}")
    print(f"🔎 Поиск файлов .txt в: {INPUT_DIRECTORY}")

    if not os.path.exists(INPUT_DIRECTORY):
        print(f"❌ Ошибка: Директория '{INPUT_DIRECTORY}' не существует.")
        return

    txt_files = [f for f in os.listdir(INPUT_DIRECTORY) if f.lower().endswith('.txt')]
    
    if not txt_files:
        print(f"⚠️ Файлы .txt не найдены.")
        return

    print(f"📑 Найдены файлы: {txt_files}\n")

    for filename in txt_files:
        full_path = os.path.join(INPUT_DIRECTORY, filename)
        file_type = determine_file_type(full_path)
        print(f"🧐 Анализ '{filename}': тип - {file_type.upper()}")

        try:
            if file_type == "cidr":
                # Исправлено: передаем только путь, настройки берутся из глобальных переменных
                process_cidr_file(full_path, RESULTS_DIR)
            elif file_type == "ip_list":
                # Исправлено: передаем только путь
                process_ip_list_file(full_path, RESULTS_DIR)
            else:
                print(f"⚠️ Тип файла '{filename}' не распознан. Пропуск.\n")
            
            print("-" * 50)
        except KeyboardInterrupt:
            print(f"\n⛔ Прервано пользователем при обработке {filename}")
            sys.exit(1)
        except Exception as e:
            print(f"💥 Критическая ошибка при обработке {filename}: {e}")
            import traceback
            traceback.print_exc()
            continue
    
    print("\n✨ Все операции завершены!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⛔ Работа скрипта прервана пользователем.")
        sys.exit(1)