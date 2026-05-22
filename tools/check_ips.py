#!/usr/bin/env python3
"""
Сканер доступных IP (CIDR / список IP) с пингом.
Поддерживает тихий режим, логирование, безопасное прерывание и resume.

Режимы работы:
- Обычный режим: полная проверка всех IP в подсети
  Результат: build/IP_checked/IP-whitelist.txt
  
- Режим --cidr: проверка подсетей до первого живого IP (быстро, параллельно)
  Результат: build/IP_checked/CIDR-whitelist.txt

Конфигурация: configs/check_ips.json
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
import threading
import atexit
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
import time
from pathlib import Path

# ================= ЗАГРУЗКА КОНФИГУРАЦИИ =================
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
CONFIG_DIR = PROJECT_ROOT / "configs"
CONFIG_FILE = CONFIG_DIR / "check_ips.json"

CONFIG = None

def load_config() -> dict:
    """Загружает конфигурацию из JSON файла."""
    if not CONFIG_FILE.exists():
        print(f"❌ Файл конфигурации не найден: {CONFIG_FILE}")
        print(f"📁 Создайте файл configs/check_ips.json с необходимыми настройками")
        sys.exit(1)
    
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Ошибка загрузки конфига: {e}")
        sys.exit(1)

def get_config_value(*keys, default=None):
    """Безопасное получение значения из конфига."""
    current = CONFIG
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return default
        if current is None:
            return default
    return current

# Загружаем конфиг
CONFIG = load_config()

# ================= КОНФИГУРАЦИОННЫЕ ПЕРЕМЕННЫЕ =================
INPUT_DIRECTORY = get_config_value("paths", "input_directory")
RESULTS_DIR = get_config_value("paths", "results_directory")
CHECKPOINT_FILE = get_config_value("paths", "checkpoint_file")
LOG_FILE = get_config_value("paths", "log_file")

NUM_THREADS = get_config_value("network", "num_threads")
MAX_QUEUE_SIZE = get_config_value("network", "max_queue_size")
PING_TIMEOUT = get_config_value("network", "ping_timeout")
MAX_IPS_PER_CIDR = get_config_value("network", "max_ips_per_cidr")

STATS_INTERVAL = get_config_value("scan", "stats_interval")
CHECKPOINT_INTERVAL = get_config_value("scan", "checkpoint_interval")
MAX_IPS_IN_MEMORY = get_config_value("scan", "max_ips_in_memory")
CIDR_MAX_CHECKS = get_config_value("scan", "cidr_max_checks")

IP_WHITELIST_FILE = get_config_value("output", "ip_whitelist")
CIDR_WHITELIST_FILE = get_config_value("output", "cidr_whitelist")
# =================================================

# Проверка обязательных параметров
required_params = [
    INPUT_DIRECTORY, RESULTS_DIR, CHECKPOINT_FILE, LOG_FILE,
    NUM_THREADS, MAX_QUEUE_SIZE, PING_TIMEOUT, MAX_IPS_PER_CIDR,
    STATS_INTERVAL, CHECKPOINT_INTERVAL, MAX_IPS_IN_MEMORY, CIDR_MAX_CHECKS,
    IP_WHITELIST_FILE, CIDR_WHITELIST_FILE
]

if any(p is None for p in required_params):
    print("❌ Ошибка: отсутствуют обязательные параметры в конфигурационном файле")
    print("📁 Проверьте configs/check_ips.json")
    sys.exit(1)

logger = logging.getLogger("ip_scanner")
logger.setLevel(logging.DEBUG)

SHUTDOWN_REQUESTED = threading.Event()
FILE_LOCK = threading.Lock()
CURRENT_STATE = {}

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
                if not isinstance(data.get("processed_files", []), list):
                    data["processed_files"] = []
                if not isinstance(data.get("file_offsets", {}), dict):
                    data["file_offsets"] = {}
                if not isinstance(data.get("processed_cidrs", []), list):
                    data["processed_cidrs"] = []
                logger.info(f"📂 Найден чекпоинт: {data.get('current_file', 'unknown')} "
                           f"(смещение {data.get('ip_offset', 0)})")
                return data
        except Exception as e:
            logger.warning(f"⚠️ Ошибка чтения чекпоинта: {e}")
    return {
        "processed_files": [],
        "file_offsets": {},
        "processed_cidrs": [],
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
    SHUTDOWN_REQUESTED.set()

signal.signal(signal.SIGINT, signal_handler)
if hasattr(signal, 'SIGTERM'):
    signal.signal(signal.SIGTERM, signal_handler)
atexit.register(save_checkpoint_on_exit)

def generate_ips_from_cidr(cidr_str, skip: int = 0):
    """Генератор IP из CIDR с возможностью пропуска"""
    try:
        network = ipaddress.ip_network(cidr_str, strict=False)
        host_gen = (str(h) for h in network.hosts())
        
        for _ in range(skip):
            try:
                next(host_gen)
            except StopIteration:
                break
        
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
    """Агрегация IP в CIDR"""
    ips = []
    total_ips = 0
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            total_ips = sum(1 for _ in f)
        
        if total_ips == 0:
            return False
        
        if total_ips > MAX_IPS_IN_MEMORY:
            logger.warning(f"⚠️ Слишком много IP ({total_ips}), агрегация может быть медленной")
        
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

def process_stream(ip_generator, results_dir, checkpoint_state: dict):
    """Основная обработка потока IP адресов (для обычного режима)"""
    result_path = os.path.join(results_dir, IP_WHITELIST_FILE)
    temp_path = result_path + ".tmp"
    
    existing_ips = set()
    if os.path.exists(temp_path) and os.path.getsize(temp_path) > 0:
        logger.info(f"📝 Найден существующий файл результатов: {temp_path}")
        try:
            with open(temp_path, 'r', encoding='utf-8') as f:
                existing_ips = set(line.strip() for line in f if line.strip())
            logger.info(f"📊 Загружено {len(existing_ips)} уже найденных IP")
        except Exception as e:
            logger.warning(f"⚠️ Не удалось загрузить существующие IP: {e}")
    
    count_found = len(existing_ips)
    count_checked = 0
    last_stats_time = time.time()
    last_checkpoint_save = 0
    start_time = time.time()
    
    with open(temp_path, 'a', encoding='utf-8', buffering=1) as f_out:
        with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
            futures = {}
            ip_iter = iter(ip_generator)
            
            while not SHUTDOWN_REQUESTED.is_set():
                while len(futures) < MAX_QUEUE_SIZE:
                    try:
                        ip = next(ip_iter)
                        if ip in existing_ips:
                            count_checked += 1
                            continue
                        futures[executor.submit(ping_ip, ip)] = ip
                    except StopIteration:
                        break
                
                if not futures:
                    break
                
                try:
                    for fut in as_completed(list(futures.keys()), timeout=0.5):
                        try:
                            ip, is_ok = fut.result()
                            count_checked += 1
                            
                            if is_ok and ip not in existing_ips:
                                with FILE_LOCK:
                                    if not f_out.closed:
                                        f_out.write(ip + '\n')
                                        f_out.flush()
                                        count_found += 1
                                        existing_ips.add(ip)
                        except Exception as e:
                            logger.debug(f"Ошибка обработки результата: {e}")
                        finally:
                            del futures[fut]
                        
                        if count_checked - last_checkpoint_save >= CHECKPOINT_INTERVAL:
                            checkpoint_state["ip_offset"] = count_checked
                            checkpoint_state["found_count"] = count_found
                            save_checkpoint(checkpoint_state)
                            last_checkpoint_save = count_checked
                        
                        if len(futures) < MAX_QUEUE_SIZE // 2:
                            break
                except FuturesTimeoutError:
                    pass
                
                now = time.time()
                if now - last_stats_time >= STATS_INTERVAL:
                    elapsed = now - start_time
                    rate = count_checked / elapsed if elapsed > 0 else 0
                    logger.info(f"📊 Найдено: {count_found} | Проверено: {count_checked} | "
                               f"Скорость: {rate:.1f} IP/сек | Очередь: {len(futures)}")
                    last_stats_time = now
            
            checkpoint_state["ip_offset"] = count_checked
            checkpoint_state["found_count"] = count_found
            save_checkpoint(checkpoint_state)
    
    if count_found > 0:
        logger.info(f"🔄 Финальная агрегация {count_found} IP...")
        if aggregate_ips_to_cidr(temp_path, result_path):
            logger.info(f"📂 Финальный результат сохранен: {result_path}")
            try:
                os.remove(temp_path)
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
    """Обработка CIDR файла в обычном режиме (полная проверка всех IP)"""
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
        
        offset_key = f"{os.path.basename(filepath)}_cidr_{i}"
        current_offset = checkpoint_state.get("file_offsets", {}).get(offset_key, 0)
        
        if current_offset > 0:
            logger.info(f"⏭ Продолжаю с offset {current_offset}")
        
        checkpoint_state["current_file"] = os.path.basename(filepath)
        checkpoint_state["current_cidr_index"] = i
        checkpoint_state["ip_offset"] = current_offset
        
        def ip_gen():
            yield from generate_ips_from_cidr(cidr, skip=current_offset)
        
        found = process_stream(ip_gen(), results_dir, checkpoint_state)
        total_found += found
        
        if not SHUTDOWN_REQUESTED.is_set():
            if "file_offsets" not in checkpoint_state:
                checkpoint_state["file_offsets"] = {}
            checkpoint_state["file_offsets"][offset_key] = checkpoint_state.get("ip_offset", 0)
            save_checkpoint(checkpoint_state)
    
    return total_found

def check_cidr_parallel(cidr_str, max_checks, timeout=PING_TIMEOUT):
    """
    Быстрая параллельная проверка CIDR: проверяем первые N IP одновременно.
    
    Args:
        cidr_str: CIDR сеть (например, "2.26.8.0/24")
        max_checks: Количество первых IP для параллельной проверки
        timeout: Таймаут пинга
    
    Returns:
        tuple: (доступна_ли_сеть, первый_живой_IP_или_None)
    """
    try:
        network = ipaddress.ip_network(cidr_str, strict=False)
        hosts = list(network.hosts())
        
        if not hosts:
            return False, None
        
        check_count = min(max_checks, len(hosts))
        logger.info(f"   Проверка CIDR {cidr_str} (первые {check_count} из {len(hosts)} IP)")
        
        # Берём первые IP для параллельной проверки
        check_ips = [str(hosts[i]) for i in range(check_count)]
        
        # Параллельный пинг всех выбранных IP
        with ThreadPoolExecutor(max_workers=check_count) as executor:
            futures = {executor.submit(ping_ip, ip): ip for ip in check_ips}
            
            # Ждём первый успешный результат
            for future in as_completed(futures):
                if SHUTDOWN_REQUESTED.is_set():
                    return False, None
                ip, is_alive = future.result()
                if is_alive:
                    logger.info(f"   ✅ Найден живой IP: {ip}")
                    return True, ip
        
        logger.info(f"   ❌ Живых IP не найдено (первые {check_count})")
        return False, None
    except Exception as e:
        logger.error(f"Ошибка проверки CIDR {cidr_str}: {e}")
        return False, None

def process_cidr_file_fast(filepath, results_dir, checkpoint_state: dict, max_checks: int):
    """Быстрая обработка CIDR файла (параллельная проверка до первого живого IP)"""
    logger.info(f"\n📄 Быстрая обработка CIDR файла: {os.path.basename(filepath)}")
    
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
    
    # Единый файл для всех результатов в режиме --cidr
    result_path = os.path.join(results_dir, CIDR_WHITELIST_FILE)
    temp_path = result_path + ".tmp"
    
    # Загружаем уже обработанные CIDR (для resume)
    processed_cidrs = set(checkpoint_state.get("processed_cidrs", []))
    if processed_cidrs:
        logger.info(f"📊 Загружено {len(processed_cidrs)} уже обработанных CIDR")
    
    total_found = 0
    
    for i, cidr in enumerate(cidrs):
        if SHUTDOWN_REQUESTED.is_set():
            break
        
        # Пропускаем уже обработанные
        if cidr in processed_cidrs:
            logger.info(f"⏭ Пропуск обработанного CIDR: {cidr}")
            continue
        
        logger.info(f"\n🌐 Обработка CIDR {i+1}/{len(cidrs)}: {cidr}")
        
        # Проверяем подсеть параллельно
        is_available, alive_ip = check_cidr_parallel(cidr, max_checks)
        
        if is_available:
            with FILE_LOCK:
                with open(temp_path, 'a', encoding='utf-8') as f:
                    f.write(f"{cidr}\n")
                total_found += 1
                logger.info(f"   ✅ CIDR добавлен в список: {cidr} (живой IP: {alive_ip})")
        else:
            logger.info(f"   ❌ CIDR пропущен: {cidr}")
        
        # Сохраняем прогресс
        if not SHUTDOWN_REQUESTED.is_set():
            processed_cidrs.add(cidr)
            checkpoint_state["processed_cidrs"] = list(processed_cidrs)
            save_checkpoint(checkpoint_state)
    
    # Финальное сохранение
    if total_found > 0:
        import shutil
        shutil.copy2(temp_path, result_path)
        logger.info(f"\n📂 Результат сохранен: {result_path} ({total_found} подсетей)")
    else:
        logger.info("\n⚠️ Доступных подсетей не найдено")
    
    return total_found

def process_ip_list_file(filepath, results_dir, checkpoint_state: dict):
    """Обработка файла со списком IP адресов"""
    logger.info(f"\n📄 Обработка списка IP: {os.path.basename(filepath)}")
    
    file_key = os.path.basename(filepath)
    current_offset = checkpoint_state.get("file_offsets", {}).get(file_key, 0)
    
    if current_offset > 0:
        logger.info(f"⏭ Продолжаю с offset {current_offset}")
    
    checkpoint_state["current_file"] = file_key
    checkpoint_state["ip_offset"] = current_offset
    
    def ip_gen():
        skipped = 0
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if SHUTDOWN_REQUESTED.is_set():
                        break
                    
                    ip = line.strip()
                    if not ip:
                        continue
                    
                    if skipped < current_offset:
                        skipped += 1
                        continue
                    
                    try:
                        ipaddress.ip_address(ip)
                        yield ip
                    except ValueError:
                        logger.debug(f"Пропущен невалидный IP: {ip}")
        except Exception as e:
            logger.error(f"❌ Ошибка чтения файла IP: {e}")
    
    found = process_stream(ip_gen(), results_dir, checkpoint_state)
    
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
            lines = []
            for _ in range(20):
                try:
                    lines.append(next(f))
                except StopIteration:
                    break
        
        content = ''.join(lines)
        
        if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b', content):
            return "cidr"
        
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
    parser = argparse.ArgumentParser(description='IP Scanner с поддержкой resume и логирования')
    parser.add_argument('-q', '--quiet', action='store_true', help='Тихий режим (вывод только в scan.log)')
    parser.add_argument('--resume', action='store_true', help='Продолжить сканирование с места обрыва')
    parser.add_argument('--reset', action='store_true', help='Сбросить чекпоинт и начать заново')
    parser.add_argument('--cidr', action='store_true', 
                        help='Режим проверки подсетей (до первого живого IP, быстро)')
    parser.add_argument('--cidr-checks', type=int, default=CIDR_MAX_CHECKS,
                        help=f'Количество первых IP для проверки в режиме --cidr (по умолч. {CIDR_MAX_CHECKS})')
    parser.add_argument('--version', action='version', version='IP Scanner v2.0')
    args = parser.parse_args()
    
    setup_logging(quiet=args.quiet)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    if args.reset and os.path.exists(CHECKPOINT_FILE):
        os.remove(CHECKPOINT_FILE)
        logger.info("🗑️ Чекпоинт сброшен")
    
    logger.info("="*60)
    logger.info(f"🔍 IP SCANNER v2.0")
    logger.info(f"⚙️ Режим: {'CIDR (быстрый)' if args.cidr else 'Полный'}")
    if args.cidr:
        logger.info(f"⚙️ CIDR проверка: {args.cidr_checks} первых IP")
    logger.info(f"⚙️ Настройки: потоки={NUM_THREADS}, очередь={MAX_QUEUE_SIZE}, "
               f"таймаут={PING_TIMEOUT}с, чекпоинт={CHECKPOINT_INTERVAL}")
    logger.info(f"⚙️ Конфиг: {CONFIG_FILE}")
    logger.info("="*60)
    
    if not os.path.exists(INPUT_DIRECTORY):
        logger.error(f"❌ Директория '{INPUT_DIRECTORY}' не существует.")
        return
    
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
    
    state = load_checkpoint() if args.resume else {
        "processed_files": [],
        "file_offsets": {},
        "processed_cidrs": [],
        "current_file": None,
        "ip_offset": 0
    }
    
    global CURRENT_STATE
    CURRENT_STATE = state
    
    if args.resume and state.get("processed_files"):
        logger.info(f"🔄 Режим RESUME. Пропускаю {len(state['processed_files'])} завершённых файлов.")
    
    logger.info(f"📑 Файлов для обработки: {len(txt_files)}")
    
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
                if args.cidr:
                    process_cidr_file_fast(full_path, RESULTS_DIR, state, args.cidr_checks)
                else:
                    process_cidr_file(full_path, RESULTS_DIR, state)
            elif file_type == "ip_list":
                if args.cidr:
                    logger.warning(f"⚠️ Файл '{filename}' содержит IP, а не CIDR. Режим --cidr не применим. Пропускаем.")
                    continue
                process_ip_list_file(full_path, RESULTS_DIR, state)
            else:
                logger.warning(f"⚠️ Тип файла '{filename}' не распознан. Пропускаем.")
                continue
            
            if not SHUTDOWN_REQUESTED.is_set():
                if filename not in state["processed_files"]:
                    state["processed_files"].append(filename)
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