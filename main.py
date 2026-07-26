#!/usr/bin/env python3
import os
import re
import socket
import ssl
import time
import json
import requests
import base64
import websocket
import shutil
import threading
import urllib.parse
from datetime import datetime, timezone
from urllib.parse import unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# ------------------ Настройки ------------------
BASE_DIR = "checked"
FOLDER_RU = os.path.join(BASE_DIR, "RU_Best")
FOLDER_EURO = os.path.join(BASE_DIR, "My_Euro")

if os.path.exists(FOLDER_RU):
    shutil.rmtree(FOLDER_RU)
if os.path.exists(FOLDER_EURO):
    shutil.rmtree(FOLDER_EURO)
os.makedirs(FOLDER_RU, exist_ok=True)
os.makedirs(FOLDER_EURO, exist_ok=True)

TIMEOUT = 5
socket.setdefaulttimeout(TIMEOUT)
THREADS = 40

CACHE_HOURS = 6
CHUNK_LIMIT = 1000
EURO_CHUNK_LIMIT = 500
MAX_KEYS_TO_CHECK = 30000

MAX_PING_MS = 10000
FAST_LIMIT = 3000
MAX_HISTORY_AGE = 2 * 24 * 3600

# Дисковый кэш IP → страна
IP_CACHE_FILE = os.path.join(BASE_DIR, "ip_cache.json")
IP_CACHE_MAX_AGE_DAYS = 30

# ip-api: не более ~40 req/min — берём 38 для запаса
GEO_API_RATE_LIMIT = 38
GEO_API_WINDOW = 60.0

RU_FILES = ["ru_white_part1.txt", "ru_white_part2.txt", "ru_white_part3.txt", "ru_white_part4.txt"]
EURO_FILES = ["my_euro_part1.txt", "my_euro_part2.txt", "my_euro_part3.txt"]

HISTORY_FILE = os.path.join(BASE_DIR, "history.json")
MY_CHANNEL = "@vlesstrojan"

# ==================== ОБНОВЛЁННЫЙ СПИСОК URLS_RU ====================
URLS_RU = [
    # старые источники (сохраняем все, что были)
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Base64/BLACK_SS+All_RUS_base64.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Base64/BLACK_VLESS_RUS_base64.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Base64/BLACK_VLESS_RUS_mobile_base64.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Base64/Vless-Reality-White-Lists-Rus-Mobile-2-base64.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Base64/Vless-Reality-White-Lists-Rus-Mobile-base64.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Base64/WHITE-CIDR-RU-all-base64.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Base64/WHITE-CIDR-RU-checked-base64.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Base64/WHITE-SNI-RU-all-base64.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless.txt",
    "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/vsevjik/OBSpiskov/refs/heads/main/wwh",
    "https://jsnegsukavsos.hb.ru-msk.vkcloud-storage.ru/love",
    "https://etoneya.a9fm.site/1",
    "https://s3c3.001.gpucloud.ru/vahe4xkwi/cjdr",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_lite.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
    "https://key.zarazaex.xyz/sub",
    "https://rostunnel.vercel.app/mega.txt",
    "https://subrostunnel.vercel.app/wl.txt",
    "https://subrostunnel.vercel.app/gen.txt",
    "https://etoneya.su/whitelist",
    "https://raw.githubusercontent.com/Kirillo4ka/eavevpn-configs/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/Kirillo4ka/eavevpn-configs/refs/heads/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/Kirillo4ka/eavevpn-configs/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/Kirillo4ka/eavevpn-configs/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://gist.githubusercontent.com/DestroyST6767/50af50221ca1858ba2084efc0f524fbc/raw/1dc2f8edf8b2d7ab2a85ffd970208aa6fbb65a8e/Destroy_ST%2520%25D0%2591%25D0%25A1",
    "https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/selected.txt",
    "https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/wl.txt",
    "https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/merged.txt",
    "https://raw.githubusercontent.com/Alex999ooo/VPN-for-Russia-/refs/heads/main/VPN%20by%20Alex999ooo%20%F0%9F%8F%B3%EF%B8%8F",
    "https://raw.githubusercontent.com/prominbro/sub/refs/heads/main/212.txt",
    "https://raw.githubusercontent.com/dmitriistekolnikov/Free_vpns_for_Russ/refs/heads/main/Vrema.txt",
    "https://raw.githubusercontent.com/dmitriistekolnikov/Free_vpns_for_Russ/refs/heads/main/Vip.txt",
    "https://raw.githubusercontent.com/Temnuk/naabuzil/refs/heads/main/whitelist_full",
    "https://raw.githubusercontent.com/Temnuk/naabuzil/refs/heads/main/whitelist",
    "https://raw.githubusercontent.com/ksenkovsolo/HardVPN-bypass-WhiteLists-/refs/heads/main/vpn-lte/WHITELIST-ALL.txt",
    "https://raw.githubusercontent.com/ksenkovsolo/HardVPN-bypass-WhiteLists-/refs/heads/main/vpn-lte/subscriptions/1sub.txt",
    "https://raw.githubusercontent.com/ksenkovsolo/HardVPN-bypass-WhiteLists-/refs/heads/main/vpn-lte/subscriptions/2sub.txt",
    "https://raw.githubusercontent.com/ksenkovsolo/HardVPN-bypass-WhiteLists-/refs/heads/main/vpn-lte/subscriptions/3sub.txt",
    "https://raw.githubusercontent.com/ksenkovsolo/HardVPN-bypass-WhiteLists-/refs/heads/main/vpn-lte/subscriptions/4sub.txt",
    "https://raw.githubusercontent.com/ksenkovsolo/HardVPN-bypass-WhiteLists-/refs/heads/main/vpn-lte/subscriptions/5sub.txt",
    "https://raw.githubusercontent.com/ksenkovsolo/HardVPN-bypass-WhiteLists-/refs/heads/main/vpn-lte/best_keys.txt",
    "https://raw.githubusercontent.com/ksenkovsolo/HardVPN-bypass-WhiteLists-/refs/heads/main/vpn-lte/good_keys.txt",
    "https://raw.githubusercontent.com/AirLinkVPN1/AirLinkVPN/refs/heads/main/rkn_white_list",
    "https://raw.githubusercontent.com/Maskkost93/kizyak-vpn-4.0/refs/heads/main/kizyakbeta7.txt",
    "https://raw.githubusercontent.com/Maskkost93/kizyak-vpn-4.0/refs/heads/main/kizyakbeta6.txt",
    "https://raw.githubusercontent.com/Maskkost93/kizyak-vpn-4.0/refs/heads/main/kizyaktestru.txt",
    "https://obwl.vercel.app/configs/configs.txt",
    "https://obwl.vercel.app/configs/selected.txt",
    "https://tinyurl.com/AeryxVPNyandexua",
    "https://raw.githubusercontent.com/VOID-Anonymity/V.O.I.D-VPN_Bypass/refs/heads/main/url_work.txt",
    "https://raw.githubusercontent.com/dequar/deqwl/refs/heads/main/deray.txt",
    "https://tinyurl.com/scalavpnbot",
    "https://raw.githubusercontent.com/kama55726/KomaryServers/refs/heads/main/KomaryServ",
    "https://raw.githubusercontent.com/LimeHi/Old-Context-Menu/refs/heads/main/afg.txt",
    "https://raw.githubusercontent.com/nzea243/ikoV31tud_vpn/refs/heads/main/tri_228.txt",
    "https://raw.githubusercontent.com/mbelspb-gif/gdffgd/refs/heads/main/Swordware.net",
    "https://gist.githubusercontent.com/flaafix/c79a81037d15163360571c7a7331b153/raw/AetrisVPN.txt",
    "https://raw.githubusercontent.com/HalyavusVPNUS/halyava-vpn-lte/refs/heads/main/lte.txt",

    # ---------- НОВЫЕ ИСТОЧНИКИ (добавлены 09.07.2026) ----------
    "https://tinyurl.com/freesub-scalavpnrobot",
    "https://raw.githubusercontent.com/Ilyacom4ik/free-v2ray-2026/refs/heads/main/subscriptions/FreeCFGHub1.txt",
    "https://raw.githubusercontent.com/uretkavpn/Uretkavpn/refs/heads/main/UretkaVpn.txt",
    "https://gist.githubusercontent.com/FrizanGAME/dfd1f7ac36511593dc6d0faff14cc8bb/raw/frizanVPN.txt",
    "https://raw.githubusercontent.com/Ilyacom4ik/vpn-keys/refs/heads/main/allkeysFreeCFGHub.txt",
    "https://raw.githubusercontent.com/likzil/vless1/refs/heads/main/Treetcpvpn",
    "https://raw.githubusercontent.com/Ilyacom4ik/vpn-keys/refs/heads/main/FreeCFGHubSUB",
    "https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/whitelist.txt",
    "https://tinyurl.com/AeryxWiFiLTE",
    "https://tinyurl.com/5cnvrkmy",
    "https://tinyurl.com/3mzxa6k6",
    "https://tinyurl.com/Sub1EggAeryx",
    "https://raw.githubusercontent.com/Ghost-LInk-star/GhostL/refs/heads/main/dizzga.txt",
    "https://raw.githubusercontent.com/mbelspb-gif/bright/refs/heads/main/Kdlddl.sw",
    "https://raw.githubusercontent.com/Ghost-LInk-star/bambuk/refs/heads/main/vpn.txt",
    "https://gist.githubusercontent.com/nikitavalentinov90021-ai/b5f135a9547a559f8042cfc7c7cde32d/raw/3d454f959d5f4a2c37c47a5d4d9bd4c798506cea/LTE8464552823",
    "https://gist.githubusercontent.com/pidarasuebisov-afk/e220b44264242d1a97c0908aba091edd/raw/PKN%20cocnyL",
    "https://raw.githubusercontent.com/dmitriistekolnikov/Free_vpns_for_Russ/refs/heads/main/Vpn.txt",
    "https://gist.githubusercontent.com/nikitavalentinov90021-ai/a4de8e24121096a7714be35465849a0c/raw/995e0ee28983e89e3dab94d9e80834514bd212c1/ID6592823693.txt",
    "https://gist.githubusercontent.com/nikitavalentinov90021-ai/41901f30db6c78a6a4d0da27429f4fab/raw/6efae398be2ad0ab70ba257bab20a82053c36383/LTE.txt",
    "https://gist.githubusercontent.com/VSPBOOST/d84dcf89bf31012a96ee60a9eb73b852/raw/4f6af123b4a0251806b89958c845666268283c5a/gistfile1.txt",
    "https://gitverse.ru/api/repos/cid-uskoritel/cid-white/raw/branch/master/whitelist(beta).txt",
    "https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt",
    "https://raw.githubusercontent.com/RYZgames31/UWB/refs/heads/main/wcfg",
    "https://raw.githubusercontent.com/twinkalex1470-crypto/CatWhiteVPN/refs/heads/main/CaTWhiteVPN.txt",
    "https://raw.githubusercontent.com/DarkFirexs/Whitelist-bypass_VPN/refs/heads/main/Whitelist%20%7C%20VPN",
    "https://raw.githubusercontent.com/stanislavPLS/AuraChannel/refs/heads/main/ID%3D1%2Cdata%3D280427",
    "https://raw.githubusercontent.com/stanislavPLS/GMVPN-users/refs/heads/main/id%3D1%2Cdata%3D120527",
    "https://gitverse.ru/api/repos/cid-uskoritel/cid-white/raw/branch/master/whitelist.txt",
    "https://sub.obbhod.online/premium",
    "http://194.33.61.236:8080/premium",
    "https://raw.githubusercontent.com/Ilyacom4ik/free-v2ray-2026/refs/heads/main/subscriptions/whitelist-keys.txt",
    "http://144.31.165.198:8080/premium",
    "https://raw.githubusercontent.com/kama55726/KomaryServers/main/White-List-2"
]

# ==================== ОСТАЛЬНЫЕ URLS_MY (без изменений) ====================
# ==================== НОВЫЕ URLS_MY (свежие источники) ====================
URLS_MY = [
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/data/githubmirror/clean/hy2.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/data/githubmirror/clean/vless.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/data/githubmirror/clean/hysteria2.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/data/githubmirror/clean/ss.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/data/githubmirror/clean/trojan.txt",
]
EURO_CODES = {
    "NL", "DE", "FI", "GB", "FR", "SE", "PL", "CZ", "AT", "CH",
    "IT", "ES", "NO", "DK", "BE", "IE", "LU", "EE", "LV", "LT"
}
BAD_MARKERS = ["CN", "IR", "KR", "BR", "IN", "RELAY", "POOL", "🇨🇳", "🇮🇷", "🇰🇷"]

RU_MARKERS_STRICT = [
    ".ru", "moscow", "msk", "spb", "saint-peter", "russia",
    "россия", "москва", "питер", "ru-", "-ru.",
    "178.154.", "77.88.", "5.255.", "87.250.",
    "95.108.", "213.180.", "195.208.",
    "91.108.", "149.154.",
]

# ------------------ Страна → название + флаг ------------------

COUNTRY_NAMES_RU = {
    "RU": "Россия", "NL": "Нидерланды", "DE": "Германия", "FI": "Финляндия",
    "GB": "Великобритания", "FR": "Франция", "SE": "Швеция", "PL": "Польша",
    "CZ": "Чехия", "AT": "Австрия", "CH": "Швейцария", "IT": "Италия",
    "ES": "Испания", "NO": "Норвегия", "DK": "Дания", "BE": "Бельгия",
    "IE": "Ирландия", "LU": "Люксембург", "EE": "Эстония", "LV": "Латвия",
    "LT": "Литва",
}

COUNTRY_FLAGS = {
    "RU": "🇷🇺", "NL": "🇳🇱", "DE": "🇩🇪", "FI": "🇫🇮", "GB": "🇬🇧",
    "FR": "🇫🇷", "SE": "🇸🇪", "PL": "🇵🇱", "CZ": "🇨🇿", "AT": "🇦🇹",
    "CH": "🇨🇭", "IT": "🇮🇹", "ES": "🇪🇸", "NO": "🇳🇴", "DK": "🇩🇰",
    "BE": "🇧🇪", "IE": "🇮🇪", "LU": "🇱🇺", "EE": "🇪🇪", "LV": "🇱🇻",
    "LT": "🇱🇹",
}

def country_to_title_ru(code: str) -> str:
    return COUNTRY_NAMES_RU.get(code, code or "UNKNOWN")

def country_to_flag(code: str) -> str:
    return COUNTRY_FLAGS.get(code, "")

# ---------- FIX UNIVERSAL (исправляет type=xhttp -> http) ----------
def fix_universal(key: str) -> str:
    key = key.strip()
    if not key.startswith("vless://") or "type=xhttp" not in key:
        return key
    try:
        parsed = urllib.parse.urlparse(key)
        query = urllib.parse.parse_qs(parsed.query)
        if query.get("type", [""])[0].lower() == "xhttp":
            query["type"] = ["http"]
        new_query = urllib.parse.urlencode(query, doseq=True)
        return urllib.parse.urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            )
        )
    except Exception:
        return key

# ==================== GEO-API + КЭШИ ====================

_disk_ip_cache: dict = {}

def load_ip_cache():
    global _disk_ip_cache
    if os.path.exists(IP_CACHE_FILE):
        try:
            with open(IP_CACHE_FILE, "r", encoding="utf-8") as f:
                _disk_ip_cache = json.load(f)
        except Exception:
            _disk_ip_cache = {}
    cutoff = time.time() - IP_CACHE_MAX_AGE_DAYS * 86400
    _disk_ip_cache = {k: v for k, v in _disk_ip_cache.items() if v.get("time", 0) > cutoff}

def save_ip_cache():
    os.makedirs(BASE_DIR, exist_ok=True)
    try:
        with open(IP_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(_disk_ip_cache, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

_ip_cache_lock = threading.Lock()

_host_to_ip: dict = {}
_host_ip_lock = threading.Lock()

def resolve_host(host: str) -> str | None:
    with _host_ip_lock:
        if host in _host_to_ip:
            return _host_to_ip[host]
    try:
        ip = socket.gethostbyname(host)
        with _host_ip_lock:
            _host_to_ip[host] = ip
        return ip
    except Exception:
        with _host_ip_lock:
            _host_to_ip[host] = None
        return None

_geo_rate_lock = threading.Lock()
_geo_request_times: list = []
_ip_api_disabled = False
_geo_stats = defaultdict(int)
_geo_stats_lock = threading.Lock()

def _inc_geo_stat(key: str):
    with _geo_stats_lock:
        _geo_stats[key] += 1

def _geo_api_wait_slot() -> bool:
    global _ip_api_disabled
    if _ip_api_disabled:
        return False
    with _geo_rate_lock:
        now = time.time()
        cutoff = now - GEO_API_WINDOW
        while _geo_request_times and _geo_request_times[0] < cutoff:
            _geo_request_times.pop(0)
        if len(_geo_request_times) >= GEO_API_RATE_LIMIT:
            sleep_time = GEO_API_WINDOW - (now - _geo_request_times[0]) + 0.1
            if sleep_time > 0:
                time.sleep(sleep_time)
            now = time.time()
            cutoff = now - GEO_API_WINDOW
            while _geo_request_times and _geo_request_times[0] < cutoff:
                _geo_request_times.pop(0)
        _geo_request_times.append(time.time())
    return True

def detect_exit_country_via_http(proxy_host: str) -> str:
    global _ip_api_disabled
    ip = resolve_host(proxy_host)
    if not ip:
        return "UNKNOWN"
    with _ip_cache_lock:
        cached = _disk_ip_cache.get(ip)
    if cached:
        _inc_geo_stat("cache")
        return cached["country"]
    if _ip_api_disabled:
        return "UNKNOWN"
    if not _geo_api_wait_slot():
        return "UNKNOWN"
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=4)
        if r.status_code == 429:
            _ip_api_disabled = True
            print("⚠️  ip-api вернул 429 (rate limit) — geo-API отключён до конца запуска")
            return "UNKNOWN"
        if r.status_code == 200:
            code = r.json().get("countryCode", "UNKNOWN") or "UNKNOWN"
            with _ip_cache_lock:
                _disk_ip_cache[ip] = {"country": code, "time": time.time()}
            _inc_geo_stat("api")
            return code
    except Exception:
        pass
    return "UNKNOWN"

def get_country_fast(host: str, key_name: str) -> str:
    try:
        host_l = host.lower()
        name_u = key_name.upper()
        if host_l.endswith(".ru"):
            return "RU"
        if host_l.endswith(".de"):
            return "DE"
        if host_l.endswith(".nl"):
            return "NL"
        if host_l.endswith(".uk") or host_l.endswith(".co.uk"):
            return "GB"
        if host_l.endswith(".fr"):
            return "FR"
        for code in EURO_CODES:
            if code in name_u:
                return code
    except Exception:
        pass
    return "UNKNOWN"

def _has_many_ru_markers(host: str, key_str: str) -> bool:
    count = 0
    host_lower = host.lower()
    key_upper = key_str.upper()
    for marker in RU_MARKERS_STRICT:
        if marker.lower() in host_lower or marker.upper() in key_upper:
            count += 1
            if count >= 2:
                return True
    return False

def is_russian_exit(key_str: str, host: str, country: str) -> bool:
    if country == "RU":
        return True
    host_lower = host.lower()
    if host_lower.endswith(".ru"):
        return True
    for marker in RU_MARKERS_STRICT:
        if marker.lower() in host_lower:
            return True
    return False

def is_garbage_text(key_str: str) -> bool:
    upper = key_str.upper()
    for m in BAD_MARKERS:
        if m in upper:
            return True
    if ".ir" in key_str or ".cn" in key_str or "127.0.0.1" in key_str:
        return True
    return False

def fetch_keys(urls, tag):
    out = []
    print(f"Загрузка {tag}...")
    for url in urls:
        try:
            if "github.com" in url and "/blob/" in url:
                url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            r = requests.get(url, timeout=10)
            if r.status_code != 200:
                continue
            content = r.text.strip()
            if "://" not in content:
                try:
                    lines = base64.b64decode(content + "==").decode("utf-8", errors="ignore").splitlines()
                except Exception:
                    lines = content.splitlines()
            else:
                lines = content.splitlines()
            for l in lines:
                l = l.strip()
                if len(l) > 2000:
                    continue
                if l.startswith(("vless://", "vmess://", "trojan://", "ss://")):
                    if tag == "MY" and is_garbage_text(l):
                        continue
                    out.append((l, tag))
        except Exception:
            pass
    return out

ERR_TIMEOUT = "timeout"
ERR_TLS = "tls"
ERR_DNS = "dns"
ERR_OTHER = "other"

_err_stats = defaultdict(int)
_err_stats_lock = threading.Lock()

def _inc_err(kind: str):
    with _err_stats_lock:
        _err_stats[kind] += 1

def check_single_key(data):
    key, tag = data
    try:
        if "@" not in key or ":" not in key:
            return None, None, None, None, key, ERR_OTHER
        part = key.split("@")[1].split("?")[0].split("#")[0]
        host_port = part.split(":")
        host = host_port[0]
        port = int(host_port[1])
    except Exception:
        return None, None, None, None, key, ERR_OTHER

    if tag == "MY":
        fast_hint = get_country_fast(host, key)
        if fast_hint == "RU" and _has_many_ru_markers(host, key):
            return None, None, None, None, key, ERR_OTHER

    is_tls = (
        "security=tls" in key or
        "security=reality" in key or
        "trojan://" in key or
        "vmess://" in key
    )
    is_ws = "type=ws" in key or "net=ws" in key
    path = "/"
    match = re.search(r"path=([^&]+)", key)
    if match:
        path = unquote(match.group(1))

    start = time.time()

    try:
        if is_ws:
            protocol = "wss" if is_tls else "ws"
            ws_url = f"{protocol}://{host}:{port}{path}"
            ws = websocket.create_connection(
                ws_url,
                timeout=TIMEOUT,
                sslopt={"cert_reqs": ssl.CERT_NONE},
            )
            ws.close()
        elif is_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    pass
        else:
            with socket.create_connection((host, port), timeout=TIMEOUT):
                pass
    except socket.timeout:
        _inc_err(ERR_TIMEOUT)
        return None, None, None, None, key, ERR_TIMEOUT
    except ssl.SSLError:
        _inc_err(ERR_TLS)
        return None, None, None, None, key, ERR_TLS
    except socket.gaierror:
        _inc_err(ERR_DNS)
        return None, None, None, None, key, ERR_DNS
    except OSError as e:
        msg = str(e).lower()
        if "timed out" in msg or "timeout" in msg:
            _inc_err(ERR_TIMEOUT)
            return None, None, None, None, key, ERR_TIMEOUT
        _inc_err(ERR_OTHER)
        return None, None, None, None, key, ERR_OTHER
    except Exception:
        _inc_err(ERR_OTHER)
        return None, None, None, None, key, ERR_OTHER

    latency = int((time.time() - start) * 1000)
    country_exit = detect_exit_country_via_http(host)

    if country_exit == "UNKNOWN":
        country_exit = get_country_fast(host, key)
        if country_exit == "UNKNOWN":
            _inc_geo_stat("unknown")
        else:
            _inc_geo_stat("fast")

    return latency, tag, country_exit, host, key, None

def make_final_key(k_id, latency, country):
    title_ru = country_to_title_ru(country)
    flag = country_to_flag(country)
    title_full = f"{title_ru} {country}" if country and country != "UNKNOWN" else title_ru
    info_str = f"[{latency}ms {title_full} {flag} {MY_CHANNEL}]"
    raw = f"{k_id}#{info_str}"
    return fix_universal(raw)

def extract_ping(key_str):
    try:
        label = key_str.split("#")[-1]
        match = re.search(r"(\d+)ms", label)
        if match:
            return int(match.group(1))
        return None
    except Exception:
        return None

def save_exact(keys, folder, filename):
    path = os.path.join(folder, filename)
    with open(path, "w", encoding="utf-8") as f:
        cleaned = [fix_universal(k.strip()) for k in keys if k and k.strip()]
        f.write("\n".join(cleaned))
    return path

def save_fixed_chunks_ru(keys_list, folder):
    valid_keys = [k.strip() for k in keys_list if k and k.strip()]
    chunks = [
        valid_keys[i:i + CHUNK_LIMIT]
        for i in range(0, min(len(valid_keys), CHUNK_LIMIT * 4), CHUNK_LIMIT)
    ]
    while len(chunks) < 4:
        chunks.append([])
    file_names = []
    for i, filename in enumerate(RU_FILES):
        save_exact(chunks[i] if i < len(chunks) else [], folder, filename)
        count = len(chunks[i]) if i < len(chunks) else 0
        print(f"  {filename}: {count} ключей")
        file_names.append(filename)
    return file_names

def save_fixed_chunks_euro(keys_list, folder):
    valid_keys = [k.strip() for k in keys_list if k and k.strip()]
    chunks = [
        valid_keys[i:i + EURO_CHUNK_LIMIT]
        for i in range(0, min(len(valid_keys), EURO_CHUNK_LIMIT * 3), EURO_CHUNK_LIMIT)
    ]
    while len(chunks) < 3:
        chunks.append([])
    file_names = []
    for i, filename in enumerate(EURO_FILES):
        save_exact(chunks[i] if i < len(chunks) else [], folder, filename)
        count = len(chunks[i]) if i < len(chunks) else 0
        print(f"  {filename}: {count} ключей")
        file_names.append(filename)
    return file_names

def save_chunked(keys_list, folder, base_name, chunk_size=None):
    if chunk_size is None:
        chunk_size = CHUNK_LIMIT
    valid_keys = [k.strip() for k in keys_list if k and k.strip()]
    chunks = [valid_keys[i:i + chunk_size] for i in range(0, len(valid_keys), chunk_size)]
    file_names = []
    for idx, chunk in enumerate(chunks, start=1):
        filename = f"{base_name}_part{idx}.txt"
        save_exact(chunk, folder, filename)
        file_names.append(filename)
        print(f"  {filename}: {len(chunk)} ключей")
    return file_names

def load_json(path):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def generate_subscriptions_list(ru_fast_files, ru_all_files, euro_fast_files, euro_all_files):
    GITHUB_USER_REPO = "kort0881/vpn-checker-backend"
    BRANCH = "main"
    BASE_RAW = f"https://raw.githubusercontent.com/{GITHUB_USER_REPO}/{BRANCH}"
    subs_lines = []

    subs_lines.append(f"# Generated: {datetime.now(timezone.utc).isoformat()} UTC")
    subs_lines.append("")

    def nonempty_files(folder, filenames):
        out = []
        for fname in filenames:
            path = os.path.join(folder, fname)
            if os.path.exists(path) and os.path.getsize(path) > 0:
                out.append(fname)
        return out

    # RUSSIA FAST
    ru_fast_nonempty = nonempty_files(FOLDER_RU, ru_fast_files)
    if ru_fast_nonempty:
        subs_lines.append("=== 🇷🇺 RUSSIA (FAST) ===")
        for filename in ru_fast_nonempty:
            file_path = os.path.join(FOLDER_RU, filename)
            mtime = int(os.path.getmtime(file_path)) if os.path.exists(file_path) else ""
            subs_lines.append(f"{BASE_RAW}/checked/RU_Best/{filename}?ts={mtime}")
        subs_lines.append("")

    # RUSSIA ALL
    ru_all_nonempty = nonempty_files(FOLDER_RU, ru_all_files)
    if ru_all_nonempty:
        subs_lines.append("=== 🇷🇺 RUSSIA (ALL) ===")
        for fname in ru_all_nonempty:
            file_path = os.path.join(FOLDER_RU, fname)
            mtime = int(os.path.getmtime(file_path)) if os.path.exists(file_path) else ""
            subs_lines.append(f"{BASE_RAW}/checked/RU_Best/{fname}?ts={mtime}")
        subs_lines.append("")

    # EUROPE FAST
    euro_fast_nonempty = nonempty_files(FOLDER_EURO, euro_fast_files)
    if euro_fast_nonempty:
        subs_lines.append("=== 🇪🇺 EUROPE (FAST) ===")
        for filename in euro_fast_nonempty:
            file_path = os.path.join(FOLDER_EURO, filename)
            mtime = int(os.path.getmtime(file_path)) if os.path.exists(file_path) else ""
            subs_lines.append(f"{BASE_RAW}/checked/My_Euro/{filename}?ts={mtime}")
        subs_lines.append("")

    # EUROPE ALL
    euro_all_nonempty = nonempty_files(FOLDER_EURO, euro_all_files)
    if euro_all_nonempty:
        subs_lines.append("=== 🇪🇺 EUROPE (ALL) ===")
        for fname in euro_all_nonempty:
            file_path = os.path.join(FOLDER_EURO, fname)
            mtime = int(os.path.getmtime(file_path)) if os.path.exists(file_path) else ""
            subs_lines.append(f"{BASE_RAW}/checked/My_Euro/{fname}?ts={mtime}")
        subs_lines.append("")

    # WHITE RUSSIA
    ru_white_path = os.path.join(FOLDER_RU, "ru_white_all_WHITE.txt")
    if os.path.exists(ru_white_path) and os.path.getsize(ru_white_path) > 0:
        subs_lines.append("=== ✅ WHITE RUSSIA (ALL) ===")
        mtime = int(os.path.getmtime(ru_white_path))
        subs_lines.append(f"{BASE_RAW}/checked/RU_Best/ru_white_all_WHITE.txt?ts={mtime}")
        subs_lines.append("")

    # WHITE EUROPE
    euro_white_path = os.path.join(FOLDER_EURO, "my_euro_all_WHITE.txt")
    if os.path.exists(euro_white_path) and os.path.getsize(euro_white_path) > 0:
        subs_lines.append("=== ✅ WHITE EUROPE (ALL) ===")
        mtime = int(os.path.getmtime(euro_white_path))
        subs_lines.append(f"{BASE_RAW}/checked/My_Euro/my_euro_all_WHITE.txt?ts={mtime}")
        subs_lines.append("")

    # BLACK RUSSIA
    ru_black_path = os.path.join(FOLDER_RU, "ru_white_all_BLACK.txt")
    if os.path.exists(ru_black_path) and os.path.getsize(ru_black_path) > 0:
        subs_lines.append("=== ⚠️ BLACK RUSSIA (ALL) ===")
        mtime = int(os.path.getmtime(ru_black_path))
        subs_lines.append(f"{BASE_RAW}/checked/RU_Best/ru_white_all_BLACK.txt?ts={mtime}")
        subs_lines.append("")

    # BLACK EUROPE
    euro_black_path = os.path.join(FOLDER_EURO, "my_euro_all_BLACK.txt")
    if os.path.exists(euro_black_path) and os.path.getsize(euro_black_path) > 0:
        subs_lines.append("=== ⚠️ BLACK EUROPE (ALL) ===")
        mtime = int(os.path.getmtime(euro_black_path))
        subs_lines.append(f"{BASE_RAW}/checked/My_Euro/my_euro_all_BLACK.txt?ts={mtime}")

    subs_path = os.path.join(BASE_DIR, "subscriptions_list.txt")
    with open(subs_path, "w", encoding="utf-8") as f:
        f.write("\n".join(subs_lines))

    http_count = sum(1 for l in subs_lines if l.startswith("http"))
    print(f"\n📋 subscriptions_list.txt создан ({http_count} ссылок):")
    for line in subs_lines:
        if line:
            print(f"  {line}")
    return subs_path

# ==================== MAIN ====================

if __name__ == "__main__":
    print("=== CHECKER v6 (FAST/ALL + WHITE/BLACK + GEO-CACHE + THROTTLE) ===")
    print(f"Параметры: CACHE={CACHE_HOURS}h, MAX_PING={MAX_PING_MS}ms, FAST={FAST_LIMIT}, HISTORY={MAX_HISTORY_AGE // 3600}h")

    load_ip_cache()
    print(f"📂 Дисковый ip_cache загружен: {len(_disk_ip_cache)} записей")

    history = load_json(HISTORY_FILE)
    tasks = fetch_keys(URLS_RU, "RU") + fetch_keys(URLS_MY, "MY")

    unique_tasks = {k: tag for k, tag in tasks}
    all_items = list(unique_tasks.items())
    if len(all_items) > MAX_KEYS_TO_CHECK:
        all_items = all_items[:MAX_KEYS_TO_CHECK]

    current_time = time.time()
    to_check = []
    res_ru = []
    res_euro = []
    dead_ru = []
    dead_euro = []
    euro_filtered_ru = 0

    print(f"\n📊 Всего уникальных ключей: {len(all_items)}")

    for k, tag in all_items:
        k_id = k.split("#")[0]
        cached = history.get(k_id)
        if cached and (current_time - cached["time"] < CACHE_HOURS * 3600) and cached["alive"]:
            latency = cached["latency"]
            country = cached.get("country", "UNKNOWN")
            host = cached.get("host", "")
            final = make_final_key(k_id, latency, country)
            if tag == "RU":
                res_ru.append(final)
            elif tag == "MY":
                if is_russian_exit(k, host, country):
                    euro_filtered_ru += 1
                else:
                    res_euro.append(final)
        else:
            to_check.append((k, tag))

    print(f"✅ Из кэша: RU={len(res_ru)}, EURO={len(res_euro)}, EURO→RU filtered={euro_filtered_ru}")
    print(f"🔍 На проверку: {len(to_check)}")

    if to_check:
        checked_ok = 0
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            future_map = {executor.submit(check_single_key, item): item for item in to_check}
            for future in as_completed(future_map):
                key, tag = future_map[future]
                try:
                    latency, _, country, host, original_key, err_type = future.result()
                except Exception:
                    if tag == "RU":
                        dead_ru.append(key)
                    else:
                        dead_euro.append(key)
                    continue
                if latency is None:
                    if tag == "RU":
                        dead_ru.append(original_key)
                    elif tag == "MY":
                        dead_euro.append(original_key)
                    continue
                k_id = original_key.split("#")[0]
                history[k_id] = {
                    "alive": True,
                    "latency": latency,
                    "time": time.time(),
                    "country": country,
                    "host": host,
                }
                final = make_final_key(k_id, latency, country)
                if tag == "RU":
                    res_ru.append(final)
                elif tag == "MY":
                    if is_russian_exit(original_key, host, country):
                        euro_filtered_ru += 1
                        dead_euro.append(original_key)
                    else:
                        res_euro.append(final)
                checked_ok += 1
        print(f"✅ Проверено успешно: {checked_ok}")

    save_ip_cache()
    print(f"💾 ip_cache сохранён: {len(_disk_ip_cache)} записей")

    save_json(
        HISTORY_FILE,
        {k: v for k, v in history.items() if current_time - v["time"] < MAX_HISTORY_AGE}
    )

    res_ru_clean = [k for k in res_ru if extract_ping(k) is not None and extract_ping(k) <= MAX_PING_MS]
    res_euro_clean = [k for k in res_euro if extract_ping(k) is not None and extract_ping(k) <= MAX_PING_MS]

    res_ru_clean.sort(key=extract_ping)
    res_euro_clean.sort(key=extract_ping)

    print(f"\n📈 После фильтрации (≤ {MAX_PING_MS} ms) и сортировки:")
    print(f"  RU: {len(res_ru_clean)} ключей")
    print(f"  EURO: {len(res_euro_clean)} ключей")

    res_ru_fast = res_ru_clean[:FAST_LIMIT]
    res_euro_fast = res_euro_clean[:FAST_LIMIT]

    print(f"\n🚀 FAST слои (топ {FAST_LIMIT}):")
    print(f"  RU FAST: {len(res_ru_fast)}")
    print(f"  EURO FAST: {len(res_euro_fast)}")

    print(f"\n💾 Сохранение RU FAST → {FOLDER_RU}:")
    ru_fast_files = save_fixed_chunks_ru(res_ru_fast, FOLDER_RU)

    print(f"\n💾 Сохранение EURO FAST → {FOLDER_EURO} (по {EURO_CHUNK_LIMIT} ключей):")
    euro_fast_files = save_fixed_chunks_euro(res_euro_fast, FOLDER_EURO)

    print(f"\n💾 Сохранение RU ALL → {FOLDER_RU}:")
    ru_all_files = save_chunked(res_ru_clean, FOLDER_RU, "ru_white_all")

    print(f"\n💾 Сохранение EURO ALL → {FOLDER_EURO} (по {EURO_CHUNK_LIMIT} ключей):")
    euro_all_files = save_chunked(res_euro_clean, FOLDER_EURO, "my_euro_all", chunk_size=EURO_CHUNK_LIMIT)

    print(f"\n💾 WHITE/BLACK → {FOLDER_RU}:")
    save_exact(res_ru_clean, FOLDER_RU, "ru_white_all_WHITE.txt")
    save_exact(dead_ru, FOLDER_RU, "ru_white_all_BLACK.txt")

    print(f"\n💾 WHITE/BLACK → {FOLDER_EURO}:")
    save_exact(res_euro_clean, FOLDER_EURO, "my_euro_all_WHITE.txt")
    save_exact(dead_euro, FOLDER_EURO, "my_euro_all_BLACK.txt")

    # Принудительная генерация subscriptions_list.txt с диагностикой
    try:
        generate_subscriptions_list(ru_fast_files, ru_all_files, euro_fast_files, euro_all_files)
        print("✅ generate_subscriptions_list выполнен успешно")
    except Exception as e:
        print(f"❌ Ошибка при вызове generate_subscriptions_list: {e}")
        import traceback
        traceback.print_exc()

    # Проверяем, что файл действительно создан
    subs_path = os.path.join(BASE_DIR, "subscriptions_list.txt")
    if os.path.exists(subs_path):
        print(f"✅ Файл {subs_path} существует, размер {os.path.getsize(subs_path)} байт")
    else:
        print(f"❌ Файл {subs_path} НЕ СУЩЕСТВУЕТ! Создаём резервный...")
        # Создаём минимальный корректный файл, чтобы коммит прошёл
        with open(subs_path, "w", encoding="utf-8") as f:
            f.write("# Generated by fallback\n")
            f.write("=== 🇷🇺 RUSSIA (ALL) ===\n")
            for fname in ru_all_files:
                f.write(f"https://raw.githubusercontent.com/kort0881/vpn-checker-backend/main/checked/RU_Best/{fname}\n")
        print(f"✅ Создан резервный файл {subs_path}")

    print("\n" + "=" * 55)
    print("📊 ФИНАЛЬНЫЙ ОТЧЁТ")
    print("=" * 55)

    print(f"\n✅ Результат:")
    print(f"  RU FAST: {len(res_ru_fast)}, RU WHITE: {len(res_ru_clean)}, RU BLACK: {len(dead_ru)}")
    print(f"  EURO FAST: {len(res_euro_fast)}, EURO WHITE: {len(res_euro_clean)}, EURO BLACK: {len(dead_euro)}")
    print(f"  EURO ключей отфильтровано как RU-exit: {euro_filtered_ru}")

    print(f"\n🌍 Источник страны (geo-статистика):")
    with _geo_stats_lock:
        stats = dict(_geo_stats)
    total_geo = sum(stats.values()) or 1
    for src in ("api", "cache", "fast", "unknown"):
        n = stats.get(src, 0)
        print(f"  {src:8s}: {n:5d}  ({n * 100 // total_geo}%)")
    if _ip_api_disabled:
        print("  ⚠️  ip-api был отключён из-за 429 в процессе работы")

    print(f"\n❌ Ошибки соединения:")
    with _err_stats_lock:
        estats = dict(_err_stats)
    total_err = sum(estats.values()) or 1
    for kind in (ERR_TIMEOUT, ERR_TLS, ERR_DNS, ERR_OTHER):
        n = estats.get(kind, 0)
        print(f"  {kind:8s}: {n:5d}  ({n * 100 // total_err}%)")

    print("\n✅ SUCCESS: FAST/ALL + WHITE/BLACK GENERATED")























































































































































































































































































































































































































































































































