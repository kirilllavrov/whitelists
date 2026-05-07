#!/usr/bin/env python3
"""
Сканер доступных IP (CIDR / список IP) с пингом.
Поддерживает тихий режим, логирование, безопасное прерывание и resume.
"""
import subprocess
import sys
import os
import re
import ipaddress
import json
import logging
import argparse
import signal
import itertools
import threading
import atexit
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
import time

# ================= КОНФИГУРАЦИЯ =================
INPUT_DIRECTORY = "../src/IPs"
RESULTS_DIR = "../build/IP_checked"
CHECKPOINT_FILE = "scan_checkpoint.json"
LOG_FILE = "scan.log"
NUM_THREADS = 200          # Снижено: 500 subprocess'ов вызывают троттлинг ядра
MAX_QUEUE_SIZE = 10000
PING_TIMEOUT = 3
MAX_IPS_PER_CIDR = 500000
STATS_INTERVAL = 10
CHECKPOINT_INTERVAL = 1000  # Сохранять чекпоинт каждые N проверенных IP
MAX_IPS_IN_MEMORY = 100000   # Максимум IP в памяти для агрегации
# =================================================

logger = logging.getLogger("ip_scanner")
logger.setLevel(logging.DEBUG)

SHUTDOWN_REQUESTED = threading.Event()
FILE_LOCK = threading.Lock()  # Для потокобезопасной записи в файл
CURRENT_STATE = {}  # Глобальное состояние для atexit

def setup_logging(quiet: bool = False):
    """Настройка логирования"""
    logger.handlers.clear()
    fmt = logging.Formatter('%(asctime)s | %(levelname)-7s | %(message)s', datefmt='%H:%M:%S')
    
    fh = logging.FileHandler(LOG_FILE, encoding='utf-8', mode='a')
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.WARNING if quiet else logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

def load_checkpoint() -> dict:
    """Загрузка чекпоинта из файла"""
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Валидация структуры
                if not isinstance(data.get("processed_files", []), list):
                    data["processed_files"] = []
                if not isinstance(data.get("file_offsets", {}), dict):
                    data["file_offsets"] = {}
                logger.info(f"📂 Найден чекпоинт: {data.get('current_file', 'unknown')} "
                           f"(смещение {data.get('ip_offset', 0)})")
                return data
        except Exception as e:
            logger.warning(f"⚠️ Ошибка чтения чекпоинта: {e}")
    return {
        "processed_files": [],
        "file_offsets": {},  # Словарь: имя файла -> offset
        "current_file": None,
        "ip_offset": 0
    }

def save_checkpoint(state: dict):
    """Атомарное сохранение чекпоинта"""
    if SHUTDOWN_REQUESTED.is_set():
        return
    
    try:
        tmp = f"{CHECKPOINT_FILE}.tmp"
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(state, f, indent=2, ensure_ascii=False)
        os.replace(tmp, CHECKPOINT_FILE)
        logger.debug(f"💾 Чекпоинт сохранен (offset: {state.get('ip_offset', 0)})")
    except Exception as e:
        logger.error(f"❌ Не удалось сохранить чекпоинт: {e}")

def save_checkpoint_on_exit():
    """Сохранить чекпоинт при любом завершении"""
    if CURRENT_STATE and not SHUTDOWN_REQUESTED.is_set():
        logger.info("💾 Сохраняю финальный чекпоинт...")
        save_checkpoint(CURRENT_STATE)

def signal_handler(signum, frame):
    """Обработчик сигналов прерывания с немедленным сохранением"""
    logger.info(f"\n⛔ Получен сигнал {signum}. Немедленное сохранение результатов...")
    
    # ✅ Принудительная агрегация текущих результатов
    if CURRENT_STATE and 'current_temp_file' in CURRENT_STATE:
        temp_file = CURRENT_STATE['current_temp_file']
        if os.path.exists(temp_file) and os.path.getsize(temp_file) > 0:
            result_file = temp_file.replace('.tmp', '_interrupted.txt')
            logger.info(f"💾 Сохраняю промежуточные результаты в {result_file}")
            try:
                # Просто копируем без агрегации для скорости
                import shutil
                shutil.copy2(temp_file, result_file)
            except:
                pass
    
    SHUTDOWN_REQUESTED.set()

# Регистрация обработчиков
signal.signal(signal.SIGINT, signal_handler)
if hasattr(signal, 'SIGTERM'):
    signal.signal(signal.SIGTERM, signal_handler)
atexit.register(save_checkpoint_on_exit)

def generate_ips_from_cidr(cidr_str, skip: int = 0):
    """Генератор IP из CIDR с возможностью пропуска"""
    try:
        network = ipaddress.ip_network(cidr_str, strict=False)
        host_gen = (str(h) for h in network.hosts())
        
        # Пропускаем указанное количество IP
        for _ in range(skip):
            try:
                next(host_gen)
            except StopIteration:
                break
        
        # Генерируем IP с лимитом
        count = 0
        for ip in host_gen:
            if SHUTDOWN_REQUESTED.is_set():
                break
            if count >= MAX_IPS_PER_CIDR:
                logger.warning(f"⚠️ Достигнут лимит IP для {cidr_str}: {MAX_IPS_PER_CIDR}")
                break
            yield ip
            count += 1
    except ValueError:
        logger.warning(f"⚠️ Невалидный CIDR: {cidr_str}")

def parse_cidrs_from_content(content):
    """Извлечение CIDR из текста"""
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
    """Пинг одного IP адреса"""
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT * 1000), ip]
        timeout_val = PING_TIMEOUT + 1
    else:
        cmd = ["ping", "-c", "1", "-W", str(PING_TIMEOUT), ip]
        timeout_val = PING_TIMEOUT + 1
    
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, 
                           stderr=subprocess.DEVNULL, timeout=timeout_val)
        return ip, res.returncode == 0
    except (subprocess.TimeoutExpired, Exception):
        return ip, False

def aggregate_ips_to_cidr(input_file, output_file):
    """Агрегация IP в CIDR с использованием временного файла"""
    ips = []
    total_ips = 0
    
    # Подсчет общего количества IP
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            total_ips = sum(1 for _ in f)
        
        if total_ips == 0:
            return False
        
        # Если IP слишком много, обрабатываем порциями
        if total_ips > MAX_IPS_IN_MEMORY:
            logger.warning(f"⚠️ Слишком много IP ({total_ips}), агрегация может быть медленной")
        
        # Загрузка IP в память
        with open(input_file, 'r', encoding='utf-8') as f:
            for line in f:
                ip_str = line.strip()
                if ip_str:
                    try:
                        ips.append(ipaddress.ip_address(ip_str))
                    except ValueError:
                        pass
        
        if not ips:
            return False
        
        logger.info(f"📥 Загружено {len(ips)} адресов. Сортировка и сжатие...")
        ips.sort()
        collapsed = list(ipaddress.collapse_addresses(ips))
        logger.info(f"✅ Сжато до {len(collapsed)} сетей.")
        
        # Запись результата
        with open(output_file, 'w', encoding='utf-8') as f:
            for net in collapsed:
                f.write(f"{net}\n")
        
        return True
    except MemoryError:
        logger.error(f"❌ Недостаточно памяти для агрегации {total_ips} IP")
        return False
    except Exception as e:
        logger.error(f"❌ Ошибка агрегации: {e}")
        return False

def process_stream(ip_generator, original_filename, results_dir, checkpoint_state: dict):
    """Основная обработка потока IP адресов"""
    base_name = os.path.splitext(os.path.basename(original_filename))[0]
    result_filename = f"available_ips_from_{base_name}.txt"
    result_path = os.path.join(results_dir, result_filename)
    temp_path = result_path + ".tmp"
    
    # ✅ НОВОЕ: Загружаем уже найденные IP при resume
    existing_ips = set()
    if os.path.exists(temp_path) and os.path.getsize(temp_path) > 0:
        logger.info(f"📝 Найден существующий файл результатов: {temp_path}")
        # Загружаем уже найденные IP, чтобы избежать дублей
        try:
            with open(temp_path, 'r', encoding='utf-8') as f:
                existing_ips = set(line.strip() for line in f if line.strip())
            logger.info(f"📊 Загружено {len(existing_ips)} уже найденных IP")
        except Exception as e:
            logger.warning(f"⚠️ Не удалось загрузить существующие IP: {e}")
    
    count_found = len(existing_ips)  # ✅ Учитываем уже найденные
    count_checked = 0
    last_stats_time = time.time()
    last_checkpoint_save = 0
    last_aggregation = 0
    start_time = time.time()
    AGGREGATION_INTERVAL = 10000  # ✅ Агрегировать каждые 10000 найденных IP
    
    # Открываем файл для добавления
    with open(temp_path, 'a', encoding='utf-8', buffering=1) as f_out:
        with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
            futures = {}
            ip_iter = iter(ip_generator)
            
            while not SHUTDOWN_REQUESTED.is_set():
                # Заполняем очередь задач
                while len(futures) < MAX_QUEUE_SIZE:
                    try:
                        ip = next(ip_iter)
                        # ✅ Пропускаем уже найденные IP
                        if ip in existing_ips:
                            count_checked += 1
                            continue
                        futures[executor.submit(ping_ip, ip)] = ip
                    except StopIteration:
                        break
                
                if not futures:
                    break
                
                # Обрабатываем завершенные задачи
                try:
                    for fut in as_completed(list(futures.keys()), timeout=0.5):
                        try:
                            ip, is_ok = fut.result()
                            count_checked += 1
                            
                            if is_ok and ip not in existing_ips:
                                with FILE_LOCK:
                                    if not f_out.closed:
                                        f_out.write(ip + '\n')
                                        f_out.flush()  # ✅ Принудительный сброс на диск
                                        count_found += 1
                                        existing_ips.add(ip)  # ✅ Запоминаем
                        except Exception as e:
                            logger.debug(f"Ошибка обработки результата: {e}")
                        finally:
                            del futures[fut]
                        
                        # ✅ Периодическая агрегация промежуточных результатов
                        if count_found - last_aggregation >= AGGREGATION_INTERVAL:
                            logger.info(f"🔄 Промежуточная агрегация ({count_found} IP)...")
                            temp_aggregated = temp_path + f".agg_{last_aggregation}"
                            if aggregate_ips_to_cidr(temp_path, temp_aggregated):
                                # Сохраняем агрегированный результат
                                if os.path.exists(result_path + ".partial"):
                                    os.remove(result_path + ".partial")
                                os.rename(temp_aggregated, result_path + ".partial")
                                logger.info(f"✅ Промежуточный результат сохранен")
                            last_aggregation = count_found
                        
                        # Периодическое сохранение чекпоинта
                        if count_checked - last_checkpoint_save >= CHECKPOINT_INTERVAL:
                            checkpoint_state["ip_offset"] = count_checked
                            checkpoint_state["found_count"] = count_found  # ✅ Сохраняем найденные
                            save_checkpoint(checkpoint_state)
                            last_checkpoint_save = count_checked
                        
                        if len(futures) < MAX_QUEUE_SIZE // 2:
                            break
                except FuturesTimeoutError:
                    pass
                
                # Статистика
                now = time.time()
                if now - last_stats_time >= STATS_INTERVAL:
                    elapsed = now - start_time
                    rate = count_checked / elapsed if elapsed > 0 else 0
                    logger.info(f"📊 Найдено: {count_found} | Проверено: {count_checked} | "
                               f"Скорость: {rate:.1f} IP/сек | Очередь: {len(futures)}")
                    last_stats_time = now
            
            # Финальное сохранение
            checkpoint_state["ip_offset"] = count_checked
            checkpoint_state["found_count"] = count_found
            save_checkpoint(checkpoint_state)
    
    # ✅ Финальная агрегация при завершении
    if count_found > 0:
        logger.info(f"🔄 Финальная агрегация {count_found} IP...")
        aggregated_path = temp_path + ".final"
        if aggregate_ips_to_cidr(temp_path, aggregated_path):
            # Сохраняем финальный результат
            if os.path.exists(result_path):
                # Создаем backup
                backup_path = result_path + ".backup"
                if os.path.exists(backup_path):
                    os.remove(backup_path)
                os.rename(result_path, backup_path)
            
            os.rename(aggregated_path, result_path)
            logger.info(f"📂 Финальный результат сохранен: {result_path}")
            
            # ✅ Удаляем промежуточные файлы
            for f in os.listdir(results_dir):
                if f.startswith(base_name) and (f.endswith('.tmp') or f.endswith('.partial')):
                    try:
                        os.remove(os.path.join(results_dir, f))
                    except:
                        pass
        else:
            logger.warning(f"⚠️ Агрегация не удалась, сохранен сырой список")
            if os.path.exists(result_path):
                os.remove(result_path)
            os.rename(temp_path, result_path)
    else:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        logger.info("⚠️ Работоспособных IP не найдено.")
    
    return count_found

def process_cidr_file(filepath, results_dir, checkpoint_state: dict):
    """Обработка файла с CIDR сетями"""
    logger.info(f"\n📄 Обработка CIDR файла: {os.path.basename(filepath)}")
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        logger.error(f"❌ Ошибка чтения файла: {e}")
        return 0
    
    cidrs = parse_cidrs_from_content(content)
    if not cidrs:
        logger.warning("❌ Нет валидных CIDR.")
        return 0
    
    logger.info(f"📋 Найдено CIDR сетей: {len(cidrs)}")
    
    total_found = 0
    for i, cidr in enumerate(cidrs):
        if SHUTDOWN_REQUESTED.is_set():
            break
        
        logger.info(f"🌐 Обработка CIDR {i+1}/{len(cidrs)}: {cidr}")
        
        # Получаем offset для текущего CIDR
        offset_key = f"{os.path.basename(filepath)}_cidr_{i}"
        current_offset = checkpoint_state.get("file_offsets", {}).get(offset_key, 0)
        
        if current_offset > 0:
            logger.info(f"⏭ Продолжаю с offset {current_offset}")
        
        checkpoint_state["current_file"] = os.path.basename(filepath)
        checkpoint_state["current_cidr_index"] = i
        checkpoint_state["ip_offset"] = current_offset
        
        def ip_gen():
            yield from generate_ips_from_cidr(cidr, skip=current_offset)
        
        found = process_stream(ip_gen(), filepath, results_dir, checkpoint_state)
        total_found += found
        
        # Сохраняем прогресс по этому CIDR
        if not SHUTDOWN_REQUESTED.is_set():
            if "file_offsets" not in checkpoint_state:
                checkpoint_state["file_offsets"] = {}
            checkpoint_state["file_offsets"][offset_key] = checkpoint_state.get("ip_offset", 0)
            save_checkpoint(checkpoint_state)
    
    return total_found

def process_ip_list_file(filepath, results_dir, checkpoint_state: dict):
    """Обработка файла со списком IP адресов"""
    logger.info(f"\n📄 Обработка списка IP: {os.path.basename(filepath)}")
    
    # Получаем offset для этого файла
    file_key = os.path.basename(filepath)
    current_offset = checkpoint_state.get("file_offsets", {}).get(file_key, 0)
    
    if current_offset > 0:
        logger.info(f"⏭ Продолжаю с offset {current_offset}")
    
    checkpoint_state["current_file"] = file_key
    checkpoint_state["ip_offset"] = current_offset
    
    # Потоковый генератор IP из файла
    def ip_gen():
        skipped = 0
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f):
                    if SHUTDOWN_REQUESTED.is_set():
                        break
                    
                    ip = line.strip()
                    if not ip:
                        continue
                    
                    # Пропускаем уже обработанные
                    if skipped < current_offset:
                        skipped += 1
                        continue
                    
                    # Валидация IP
                    try:
                        ipaddress.ip_address(ip)
                        yield ip
                    except ValueError:
                        logger.debug(f"Пропущен невалидный IP: {ip}")
        except Exception as e:
            logger.error(f"❌ Ошибка чтения файла IP: {e}")
    
    found = process_stream(ip_gen(), filepath, results_dir, checkpoint_state)
    
    # Сохраняем прогресс
    if not SHUTDOWN_REQUESTED.is_set():
        if "file_offsets" not in checkpoint_state:
            checkpoint_state["file_offsets"] = {}
        checkpoint_state["file_offsets"][file_key] = checkpoint_state.get("ip_offset", 0)
        save_checkpoint(checkpoint_state)
    
    return found

def determine_file_type(filepath):
    """Определение типа файла (CIDR или список IP)"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            # Читаем первые строки для анализа
            lines = []
            for _ in range(20):
                try:
                    lines.append(next(f))
                except StopIteration:
                    break
        
        content = ''.join(lines)
        
        # Ищем CIDR
        if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b', content):
            return "cidr"
        
        # Проверяем, являются ли строки IP адресами
        valid_ips = 0
        for line in lines:
            line = line.strip()
            if line and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
                valid_ips += 1
        
        return "ip_list" if valid_ips > 2 else "unknown"
    except Exception as e:
        logger.error(f"Ошибка определения типа файла {filepath}: {e}")
        return "unknown"

def main():
    """Основная функция"""
    parser = argparse.ArgumentParser(description='IP Scanner с поддержкой resume и логирования')
    parser.add_argument('-q', '--quiet', action='store_true', help='Тихий режим (вывод только в scan.log)')
    parser.add_argument('--resume', action='store_true', help='Продолжить сканирование с места обрыва')
    parser.add_argument('--reset', action='store_true', help='Сбросить чекпоинт и начать заново')
    args = parser.parse_args()
    
    setup_logging(quiet=args.quiet)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    # Сброс чекпоинта если нужно
    if args.reset and os.path.exists(CHECKPOINT_FILE):
        os.remove(CHECKPOINT_FILE)
        logger.info("🗑️ Чекпоинт сброшен")
    
    logger.info("="*60)
    logger.info(f"🔍 IP SCANNER (Stream Mode) v2.0")
    logger.info(f"⚙️ Настройки: потоки={NUM_THREADS}, очередь={MAX_QUEUE_SIZE}, "
               f"таймаут={PING_TIMEOUT}с, чекпоинт={CHECKPOINT_INTERVAL}")
    logger.info("="*60)
    
    if not os.path.exists(INPUT_DIRECTORY):
        logger.error(f"❌ Директория '{INPUT_DIRECTORY}' не существует.")
        return
    
    # Поиск всех .txt файлов
    all_files = [f for f in os.listdir(INPUT_DIRECTORY) if f.lower().endswith('.txt')]
    txt_files = []
    
    for f in all_files:
        full_path = os.path.join(INPUT_DIRECTORY, f)
        if os.path.isfile(full_path):
            txt_files.append(f)
    
    txt_files.sort()
    
    if not txt_files:
        logger.warning("⚠️ Файлы .txt не найдены.")
        return
    
    # Загрузка состояния
    state = load_checkpoint() if args.resume else {
        "processed_files": [],
        "file_offsets": {},
        "current_file": None,
        "ip_offset": 0
    }
    
    global CURRENT_STATE
    CURRENT_STATE = state
    
    if args.resume and state.get("processed_files"):
        logger.info(f"🔄 Режим RESUME. Пропускаю {len(state['processed_files'])} завершённых файлов.")
    
    logger.info(f"📑 Файлов для обработки: {len(txt_files)}")
    
    # Обработка файлов
    for filename in txt_files:
        if SHUTDOWN_REQUESTED.is_set():
            break
        
        if filename in state.get("processed_files", []):
            logger.info(f"⏭ Пропуск обработанного файла: {filename}")
            continue
        
        full_path = os.path.join(INPUT_DIRECTORY, filename)
        file_type = determine_file_type(full_path)
        logger.info(f"🧐 Анализ '{filename}': тип - {file_type.upper()}")
        
        try:
            if file_type == "cidr":
                process_cidr_file(full_path, RESULTS_DIR, state)
            elif file_type == "ip_list":
                process_ip_list_file(full_path, RESULTS_DIR, state)
            else:
                logger.warning(f"⚠️ Тип файла '{filename}' не распознан. Пропускаем.")
                continue
            
            # Отмечаем файл как обработанный
            if not SHUTDOWN_REQUESTED.is_set():
                if filename not in state["processed_files"]:
                    state["processed_files"].append(filename)
                # Очищаем оффсеты для этого файла
                for key in list(state.get("file_offsets", {}).keys()):
                    if key.startswith(filename) or key == filename:
                        del state["file_offsets"][key]
                state["current_file"] = None
                state["ip_offset"] = 0
                save_checkpoint(state)
                
        except Exception as e:
            logger.error(f"💥 Критическая ошибка при обработке {filename}: {e}")
            logger.exception("Детали ошибки:")
            continue
    
    # Завершение работы
    if SHUTDOWN_REQUESTED.is_set():
        logger.info("\n⏸️ Сканирование прервано пользователем")
        logger.info(f"💾 Прогресс сохранен в {CHECKPOINT_FILE}")
    else:
        logger.info("\n✨ Все операции успешно завершены!")
        if os.path.exists(CHECKPOINT_FILE):
            os.remove(CHECKPOINT_FILE)
            logger.info("🗑️ Чекпоинт удален")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\n⏹️ Принудительное завершение")
        sys.exit(0)
    except Exception as e:
        logger.error(f"❌ Необработанная ошибка: {e}")
        logger.exception("Stack trace:")
        sys.exit(1)