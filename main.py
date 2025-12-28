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
from urllib.parse import quote, unquote
from concurrent.futures import ThreadPoolExecutor

# ------------------ Настройки ------------------
BASE_DIR = "checked"
FOLDER_RU = os.path.join(BASE_DIR, "RU_Best")
FOLDER_EURO = os.path.join(BASE_DIR, "My_Euro")

# Чистим старое, создаем новое
if os.path.exists(FOLDER_RU): shutil.rmtree(FOLDER_RU)
if os.path.exists(FOLDER_EURO): shutil.rmtree(FOLDER_EURO)
os.makedirs(FOLDER_RU, exist_ok=True)
os.makedirs(FOLDER_EURO, exist_ok=True)

TIMEOUT = 5 
socket.setdefaulttimeout(TIMEOUT)
THREADS = 40 
CACHE_HOURS = 12
CHUNK_LIMIT = 1000  # Разбивка по 1000 ключей
MAX_KEYS_TO_CHECK = 15000 

HISTORY_FILE = os.path.join(BASE_DIR, "history.json")
MY_CHANNEL = "@vlesstrojan" 

# === ТВОИ ССЫЛКИ ===
URLS_RU = [
    "https://raw.githubusercontent.com/zieng2/wl/main/vless.txt",
    "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/vsevjik/OBSpiskov/refs/heads/main/wwh",
    "https://jsnegsukavsos.hb.ru-msk.vkcloud-storage.ru/love",
    "https://etoneya.a9fm.site/1",
    "https://s3c3.001.gpucloud.ru/vahe4xkwi/cjdr"
]

URLS_MY = [
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/githubmirror/new/all_new.txt"
]

EURO_CODES = {"NL", "DE", "FI", "GB", "FR", "SE", "PL", "CZ", "AT", "CH", "IT", "ES", "NO", "DK", "BE", "IE", "LU", "EE", "LV", "LT"}
BAD_MARKERS = ["CN", "IR", "KR", "BR", "IN", "RELAY", "POOL", "🇨🇳", "🇮🇷", "🇰🇷"] 

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

def get_country_fast(host, key_name):
    try:
        host = host.lower()
        name = key_name.upper()
        if host.endswith(".ru"): return "RU"
        if host.endswith(".de"): return "DE"
        if host.endswith(".nl"): return "NL"
        if host.endswith(".uk") or host.endswith(".co.uk"): return "GB"
        if host.endswith(".fr"): return "FR"
        for code in EURO_CODES:
            if code in name: return code
    except: pass
    return "UNKNOWN"

def is_garbage_text(key_str):
    upper = key_str.upper()
    for m in BAD_MARKERS:
        if m in upper: return True
    if ".ir" in key_str or ".cn" in key_str or "127.0.0.1" in key_str: return True
    return False

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
                if len(l) > 2000: continue 
                if l.startswith(("vless://", "vmess://", "trojan://", "ss://")):
                    if tag == "MY":
                        if is_garbage_text(l): continue
                    out.append((l, tag))
        except: pass
    return out

def check_single_key(data):
    key, tag = data
    try:
        if "@" in key and ":" in key:
            part = key.split("@")[1].split("?")[0].split("#")[0]
            host, port = part.split(":")[0], int(part.split(":")[1])
        else: return None, None, None

        country = get_country_fast(host, key)
        if tag == "MY" and country != "UNKNOWN" and country not in EURO_CODES:
            return None, None, None

        is_tls = 'security=tls' in key or 'security=reality' in key or 'trojan://' in key or 'vmess://' in key
        is_ws = 'type=ws' in key or 'net=ws' in key
        path = "/"
        match = re.search(r'path=([^&]+)', key)
        if match: path = unquote(match.group(1))

        start = time.time()
        
        if is_ws:
            protocol = "wss" if is_tls else "ws"
            ws_url = f"{protocol}://{host}:{port}{path}"
            ws = websocket.create_connection(ws_url, timeout=TIMEOUT, sslopt={"cert_reqs": ssl.CERT_NONE}, sockopt=((socket.SOL_SOCKET, socket.SO_RCVTIMEO, TIMEOUT),))
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

def extract_ping(key_str):
    try:
        label = key_str.split("#")[-1]
        if "ms_" not in label: return None
        ping_part = label.split("ms_")[0]
        return int(ping_part)
    except: return None

# === ИСПРАВЛЕННАЯ ФУНКЦИЯ (BASE64 + ВОЗВРАТ ИМЕН ФАЙЛОВ) ===
def save_chunked(keys_list, folder, base_name):
    created_files = []
    
    # Убираем пустые
    valid_keys = [k.strip() for k in keys_list if k and k.strip()]

    # Если пусто, создаем пустой файл (чтобы не было 404)
    if not valid_keys:
        fname = f"{base_name}.txt"
        path = os.path.join(folder, fname)
        with open(path, "w", encoding="utf-8") as f:
            f.write("")
        created_files.append(fname)
        return created_files

    chunks = [valid_keys[i:i + CHUNK_LIMIT] for i in range(0, len(valid_keys), CHUNK_LIMIT)]
    
    for i, chunk in enumerate(chunks, 1):
        # Если часть одна - имя без цифры. Если много - с цифрой.
        if len(chunks) == 1:
            fname = f"{base_name}.txt"
        else:
            fname = f"{base_name}_part{i}.txt"
            
        # КОДИРУЕМ В BASE64 (Hiddify полюбит это)
        raw_content = "\n".join(chunk)
        b64_content = base64.b64encode(raw_content.encode('utf-8')).decode('utf-8')
        
        with open(os.path.join(folder, fname), "w", encoding="utf-8") as f:
            f.write(b64_content)
            
        created_files.append(fname)
        
    return created_files

if __name__ == "__main__":
    print(f"=== CHECKER v9.5 (BASE64 + DYNAMIC LINKS) ===")
    
    history = load_json(HISTORY_FILE)
    tasks = fetch_keys(URLS_RU, "RU") + fetch_keys(URLS_MY, "MY")
    
    unique_tasks = {k: tag for k, tag in tasks}.items()
    all_items = list(unique_tasks)
    if len(all_items) > MAX_KEYS_TO_CHECK:
        all_items = all_items[:MAX_KEYS_TO_CHECK]
    
    current_time = time.time()
    to_check = []
    res_ru = []
    res_euro = []
    
    for k, tag in all_items:
        k_id = k.split("#")[0]
        cached = history.get(k_id)
        if cached and (current_time - cached['time'] < CACHE_HOURS * 3600) and cached['alive']:
            latency = cached['latency']
            country = cached.get('country', 'UNKNOWN')
            label = f"{latency}ms_{country}_{MY_CHANNEL}"
            final = f"{k_id}#{label}"
            
            if tag == "RU": res_ru.append(final)
            elif tag == "MY":
                if country in EURO_CODES: res_euro.append(final)
        else:
            to_check.append((k, tag))

    if to_check:
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            future_to_item = {executor.submit(check_single_key, item): item for item in to_check}
            for i, future in enumerate(future_to_item):
                key, tag = future_to_item[future]
                res = future.result()
                if not res or res[0] is None: continue
                latency, tag, country = res
                k_id = key.split("#")[0]
                history[k_id] = {'alive': True, 'latency': latency, 'time': current_time, 'country': country}
                label = f"{latency}ms_{country}_{MY_CHANNEL}"
                final = f"{k_id}#{label}"
                
                if tag == "RU": res_ru.append(final)
                elif tag == "MY":
                    if country in EURO_CODES: res_euro.append(final)

    save_json(HISTORY_FILE, {k:v for k,v in history.items() if current_time - v['time'] < 259200})
    
    res_ru_clean = [k for k in res_ru if extract_ping(k) is not None]
    res_euro_clean = [k for k in res_euro if extract_ping(k) is not None]
    res_ru_clean.sort(key=extract_ping)
    res_euro_clean.sort(key=extract_ping)

    # === СОХРАНЯЕМ И ПОЛУЧАЕМ ИМЕНА ФАЙЛОВ ===
    # Функция теперь вернет список, например: ['ru_white_part1.txt', 'ru_white_part2.txt']
    ru_files = save_chunked(res_ru_clean, FOLDER_RU, "ru_white")
    euro_files = save_chunked(res_euro_clean, FOLDER_EURO, "my_euro")

    # === ГЕНЕРАЦИЯ СПИСКА ССЫЛОК ===
    # Обязательно замени kort0881 на свой ник, если делал форк!
    GITHUB_USER_REPO = "kort0881/vpn-checker-backend"
    BRANCH = "main"
    BASE_URL_RU = f"https://raw.githubusercontent.com/{GITHUB_USER_REPO}/{BRANCH}/{BASE_DIR}/RU_Best"
    BASE_URL_EURO = f"https://raw.githubusercontent.com/{GITHUB_USER_REPO}/{BRANCH}/{BASE_DIR}/My_Euro"
    
    subs_lines = ["=== 🇷🇺 RUSSIA (BASE64) ==="]
    for f in ru_files:
        subs_lines.append(f"{BASE_URL_RU}/{f} | Russia Best")
        
    subs_lines.append("\n=== 🇪🇺 EUROPE (BASE64) ===")
    for f in euro_files:
        subs_lines.append(f"{BASE_URL_EURO}/{f} | Europe Best")

    with open(os.path.join(BASE_DIR, "subscriptions_list.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(subs_lines))

    print("=== SUCCESS: LISTS GENERATED ===")
























