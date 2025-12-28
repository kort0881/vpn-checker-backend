import os
import re
import html
import socket
import ssl
import time
import json
import requests
import base64
import websocket
import shutil
from datetime import datetime
from urllib.parse import quote, unquote
from concurrent.futures import ThreadPoolExecutor

# ------------------ Настройки ------------------
BASE_DIR = "checked"

# Папки назначения
FOLDER_RU = os.path.join(BASE_DIR, "RU_Best")       # Сюда падают те 7 ссылок
FOLDER_EURO = os.path.join(BASE_DIR, "My_Euro")     # Сюда падает ваша 1 ссылка (только Европа)

# Создаем структуру заново (чистка)
if os.path.exists(BASE_DIR):
    # Очищаем содержимое checked, чтобы удалить старые папки (World_Mix и т.д.)
    # Но оставляем json файлы (историю), чтобы не терять кэш!
    for item in os.listdir(BASE_DIR):
        item_path = os.path.join(BASE_DIR, item)
        if item.endswith(".json"): continue # Не удаляем историю!
        if os.path.isdir(item_path): shutil.rmtree(item_path) # Удаляем папки
        else: os.remove(item_path) # Удаляем файлы

os.makedirs(FOLDER_RU, exist_ok=True)
os.makedirs(FOLDER_EURO, exist_ok=True)

TIMEOUT = 2
THREADS = 50
CACHE_HOURS = 12
CHUNK_LIMIT = 500

HISTORY_FILE = os.path.join(BASE_DIR, "history.json")
GEO_CACHE_FILE = os.path.join(BASE_DIR, "geo_cache.json")
MY_CHANNEL = "@vlesstrojan" 

# 1. Источники для RU_Best (проверяем на доступность)
URLS_RU = [
    "https://raw.githubusercontent.com/zieng2/wl/main/vless.txt",
    "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/vsevjik/OBSpiskov/refs/heads/main/wwh",
    "https://jsnegsukavsos.hb.ru-msk.vkcloud-storage.ru/love",
    "https://etoneya.a9fm.site/1",
    "https://s3c3.001.gpucloud.ru/vahe4xkwi/cjdr"
]

# 2. Ваши источники (только Европа)
URLS_MY = [
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/githubmirror/new/all_new.txt"
]

# Коды Европы
EURO_CODES = {"NL", "DE", "FI", "GB", "FR", "SE", "PL", "CZ", "AT", "CH", "IT", "ES", "NO", "DK", "BE", "IE", "LU", "EE", "LV", "LT"}

# ------------------ Функции ------------------

def load_json(path):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f: return json.load(f)
        except: pass
    return {}

def save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f: json.dump(data, f, ensure_ascii=False, indent=2)
    except: pass

geo_cache = load_json(GEO_CACHE_FILE)

def get_country(host):
    if host in geo_cache: return geo_cache[host]
    if host.endswith(".ru"): return "RU"
    if host.endswith(".de"): return "DE"
    if host.endswith(".nl"): return "NL"
    return "UNKNOWN"

def fetch_keys(urls, tag):
    out = []
    print(f"Загрузка {tag}...")
    for url in urls:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code != 200: continue
            content = r.text.strip()
            if "://" not in content:
                try: lines = base64.b64decode(content + "==").decode('utf-8', errors='ignore').splitlines()
                except: lines = content.splitlines()
            else: lines = content.splitlines()
            for l in lines:
                l = l.strip()
                if l.startswith(("vless://", "vmess://", "trojan://", "ss://")): out.append((l, tag))
        except: pass
    return out

def check_single_key(data):
    key, tag = data
    try:
        if "@" in key and ":" in key:
            part = key.split("@")[1].split("?")[0].split("#")[0]
            host, port = part.split(":")[0], int(part.split(":")[1])
        else: return None, None, None
        
        # Определяем страну (если нет в кэше - пробуем API, но редко)
        country = get_country(host)
        if country == "UNKNOWN" and host not in geo_cache and tag == "MY":
             # Делаем запрос только для "Ваших" ссылок, чтобы отделить Европу
             try:
                 # Лимит: не более 1 запроса в 1.5 сек в потоке (или полагаемся на удачу)
                 # Тут простая заглушка. В реале лучше использовать локальную MaxMind DB.
                 # Но попробуем рискнуть для новых IP:
                 r = requests.get(f"http://ip-api.com/json/{host}?fields=countryCode", timeout=2)
                 if r.status_code == 200:
                     country = r.json().get("countryCode", "UNKNOWN")
                     geo_cache[host] = country # Запоминаем
             except: pass

        # Проверка коннекта
        is_tls = 'security=tls' in key or 'security=reality' in key or 'trojan://' in key or 'vmess://' in key
        is_ws = 'type=ws' in key or 'net=ws' in key
        path = "/"
        match = re.search(r'path=([^&]+)', key)
        if match: path = unquote(match.group(1))

        start = time.time()
        if is_ws:
            protocol = "wss" if is_tls else "ws"
            ws_url = f"{protocol}://{host}:{port}{path}"
            ws = websocket.create_connection(ws_url, timeout=TIMEOUT, sslopt={"cert_reqs": ssl.CERT_NONE})
            ws.close()
        elif is_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=host): pass
        else:
            with socket.create_connection((host, port), timeout=TIMEOUT): pass
            
        latency = int((time.time() - start) * 1000)
        return latency, tag, country
    except: return None, None, None

def save_chunked(keys_list, folder, base_name):
    if not keys_list: return
    chunks = [keys_list[i:i + CHUNK_LIMIT] for i in range(0, len(keys_list), CHUNK_LIMIT)]
    for i, chunk in enumerate(chunks, 1):
        fname = f"{base_name}.txt" if len(chunks) == 1 else f"{base_name}_part{i}.txt"
        with open(os.path.join(folder, fname), "w", encoding="utf-8") as f: f.write("\n".join(chunk))

# ------------------ Main ------------------
if __name__ == "__main__":
    print(f"=== CHECKER FINAL (Ru / MyEuro) ===")
    
    history = load_json(HISTORY_FILE)
    tasks = fetch_keys(URLS_RU, "RU") + fetch_keys(URLS_MY, "MY")
    
    # Дедупликация
    unique_tasks = {k: tag for k, tag in tasks}.items() # k -> tag
    print(f"Всего ключей: {len(unique_tasks)}")
    
    current_time = time.time()
    to_check = []
    
    # Списки результатов
    res_ru = []
    res_euro = []
    
    # 1. КЭШ
    for k, tag in unique_tasks:
        k_id = k.split("#")[0]
        cached = history.get(k_id)
        if cached and (current_time - cached['time'] < CACHE_HOURS * 3600) and cached['alive']:
            latency = cached['latency']
            country = cached.get('country', 'UNKNOWN')
            
            # ФОРМИРОВАНИЕ СТРОКИ
            label = f"{latency}ms_{country}_{MY_CHANNEL}"
            final = f"{k_id}#{label}"
            
            if tag == "RU":
                res_ru.append(final)
            elif tag == "MY":
                # ФИЛЬТР ЕВРОПЫ
                if country in EURO_CODES:
                    res_euro.append(final)
        else:
            to_check.append((k, tag))

    print(f"На проверку: {len(to_check)}")

    # 2. ПРОВЕРКА
    if to_check:
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            future_to_item = {executor.submit(check_single_key, item): item for item in to_check}
            for i, future in enumerate(future_to_item):
                key, tag = future_to_item[future]
                latency, _, country = future.result()
                
                k_id = key.split("#")[0]
                history[k_id] = {'alive': latency is not None, 'latency': latency, 'time': current_time, 'country': country}
                
                if latency is not None:
                    label = f"{latency}ms_{country}_{MY_CHANNEL}"
                    final = f"{k_id}#{label}"
                    
                    if tag == "RU":
                        res_ru.append(final)
                    elif tag == "MY":
                        if country in EURO_CODES:
                            res_euro.append(final)
                
                if i % 100 == 0: print(f"Checked {i}...")

    # Сохраняем базы
    save_json(HISTORY_FILE, {k:v for k,v in history.items() if current_time - v['time'] < 259200})
    save_json(GEO_CACHE_FILE, geo_cache)

    print(f"RU Valid: {len(res_ru)}")
    print(f"Euro Valid: {len(res_euro)}")

    # Сортировка по пингу
    res_ru.sort(key=lambda x: int(x.split("_")[0].split("ms")[0].split("#")[-1]))
    res_euro.sort(key=lambda x: int(x.split("_")[0].split("ms")[0].split("#")[-1]))

    # Запись
    save_chunked(res_ru, FOLDER_RU, "ru_white")
    save_chunked(res_euro, FOLDER_EURO, "my_euro")

    # ССЫЛКИ ПОДПИСКИ
    GITHUB_USER_REPO = "kort0881/vpn-checker-backend"
    BRANCH = "main"
    BASE_URL = f"https://raw.githubusercontent.com/{GITHUB_USER_REPO}/{BRANCH}/{BASE_DIR}"
    
    subs = [
        "=== 🇷🇺 RUSSIA WHITELISTS (Verified) ===",
        f"{BASE_URL}/RU_Best/ru_white.txt",
        "\n=== 🇪🇺 MY EUROPE (Filtered) ===",
        f"{BASE_URL}/My_Euro/my_euro.txt"
    ]
    
    with open(os.path.join(BASE_DIR, "subscriptions_list.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(subs))

    print("=== DONE ===")














