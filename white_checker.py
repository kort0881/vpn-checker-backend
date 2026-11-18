"""
white_checker.py — проверка ключа «по-настоящему»: запускаем собственный прокси
(xray для vless/vmess/trojan/ss, sing-box для hy2/hysteria2/tuic) и проверяем,
что через него открываются нужные пользователю сайты.

Статусы:
  WHITE   — открылось >= WHITE_THRESHOLD доменов из WHITE_TEST_DOMAINS
  BLACK   — прокси поднялся, но сайты не открылись (причина в white_reason)
  UNKNOWN — проверить нечем (нет бинаря / протокол не поддержан).
            Такие ключи НЕ считаются мёртвыми: TCP-проверка их уже пропустила.

Причины BLACK (white_reason):
  xray_not_started | singbox_not_started | proxy_error | http_fail | timeout
  unsupported_proto | parse_error
"""

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from base64 import b64decode
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Semaphore
from typing import Optional
from urllib.parse import unquote, parse_qs

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =============================================================================
# Публичные константы / конфигурация
# =============================================================================

WHITE_TEST_DOMAINS = [
    "www.youtube.com",
    "discord.com",
    "web.telegram.org",
    "www.google.com",
]
WHITE_THRESHOLD = 2  # минимум 2 из 4

HTTP_TIMEOUT = 5
XRAY_STARTUP_TIMEOUT = 5.0
XRAY_POLL_INTERVAL = 0.15
WHITE_CHECK_TIMEOUT = 22.0
WHITE_WORKERS = 5
WHITE_CACHE_HOURS = 24

BIN_DIR = os.path.dirname(os.path.abspath(__file__))
XRAY_BIN = os.environ.get("XRAY_BIN", os.path.join(BIN_DIR, "xray"))
SINGBOX_BIN = os.environ.get("SINGBOX_BIN", os.path.join(BIN_DIR, "sing-box"))

XRAY_PROTOS = ("vless://", "trojan://", "vmess://", "ss://")
SINGBOX_PROTOS = ("hy2://", "hysteria2://", "hysteria://", "tuic://")

# label -> Counter(reason -> count)
REASON_STATS: dict = {}

_sem = Semaphore(WHITE_WORKERS)

STATUS_WHITE = "white"
STATUS_BLACK = "black"
STATUS_UNKNOWN = "unknown"

# =============================================================================
# Поиск бинарей
# =============================================================================


def _find_binary(path: str, names: tuple) -> Optional[str]:
    if os.path.isfile(path) and os.access(path, os.X_OK):
        return path
    for name in names:
        cand = os.path.join(BIN_DIR, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def _xray_binary() -> Optional[str]:
    return _find_binary(
        XRAY_BIN, ("xray", "xray-linux-64", "xray-linux-arm64", "xray.exe")
    )


def _singbox_binary() -> Optional[str]:
    return _find_binary(
        SINGBOX_BIN, ("sing-box", "sing-box-linux-64", "sing-box.exe")
    )


def xray_available() -> bool:
    return _xray_binary() is not None


def singbox_available() -> bool:
    return _singbox_binary() is not None


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: float, proc=None) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            return False
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(XRAY_POLL_INTERVAL)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(XRAY_POLL_INTERVAL)
    return False


def _truthy(value: str) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes")


# =============================================================================
# Парсинг URI → outbound xray
# =============================================================================


def _p(params: dict, key: str, default: str = "") -> str:
    return params.get(key, [default])[0]


def _stream_settings(params: dict, net: str, security: str, host: str) -> dict:
    sni = _p(params, "sni", host)
    fp = _p(params, "fp", "chrome")
    pbk = _p(params, "pbk", "")
    sid = _p(params, "sid", "")
    path = unquote(_p(params, "path", "/"))
    h_header = unquote(_p(params, "host", host))
    alpn_raw = _p(params, "alpn", "")

    # xhttp/raw — транспорты Xray; для проверки трактуем как http/tcp
    if net == "xhttp":
        net = "http"
    elif net == "raw":
        net = "tcp"

    ss: dict = {"network": net}

    if security == "tls":
        tls_cfg: dict = {
            "allowInsecure": True,
            "serverName": sni,
            "fingerprint": fp or "chrome",
        }
        if alpn_raw:
            tls_cfg["alpn"] = [a.strip() for a in alpn_raw.split(",") if a.strip()]
        ss["security"] = "tls"
        ss["tlsSettings"] = tls_cfg
    elif security == "reality":
        ss["security"] = "reality"
        ss["realitySettings"] = {
            "serverName": sni,
            "fingerprint": fp or "chrome",
            "publicKey": pbk,
            "shortId": sid,
        }
    else:
        ss["security"] = "none"

    if net == "ws":
        ss["wsSettings"] = {"path": path, "headers": {"Host": h_header}}
    elif net == "grpc":
        ss["grpcSettings"] = {
            "serviceName": _p(params, "serviceName", ""),
            "multiMode": False,
        }
    elif net in ("h2", "http"):
        ss["httpSettings"] = {
            "path": path,
            "host": [h_header] if h_header else [],
        }
    elif net == "httpupgrade":
        ss["httpupgradeSettings"] = {"path": path, "host": h_header}

    return ss


def _split_host_port(host_port: str) -> tuple:
    host, port_s = host_port.rsplit(":", 1)
    host = host.strip("[]")
    return host, int(port_s)


def _parse_vless(uri: str) -> Optional[dict]:
    try:
        body = uri[len("vless://"):]
        user_id, rest = body.split("@", 1)
        qs = rest.split("?", 1)[1] if "?" in rest else ""
        qs = qs.split("#")[0]
        host_port = rest.split("?")[0]
        host, port = _split_host_port(host_port)
        params = parse_qs(qs)

        security = _p(params, "security", "none")
        net = _p(params, "type", "tcp")
        flow = _p(params, "flow", "")

        ss = _stream_settings(params, net, security, host)

        user: dict = {"id": user_id, "encryption": "none"}
        if flow and security == "reality":
            user["flow"] = flow

        return {
            "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
            "streamSettings": ss,
        }
    except Exception:
        return None


def _parse_trojan(uri: str) -> Optional[dict]:
    try:
        body = uri[len("trojan://"):]
        password, rest = body.split("@", 1)
        password = unquote(password)
        qs = rest.split("?", 1)[1] if "?" in rest else ""
        qs = qs.split("#")[0]
        host_port = rest.split("?")[0]
        host, port = _split_host_port(host_port)
        params = parse_qs(qs)

        security = _p(params, "security", "tls")
        net = _p(params, "type", "tcp")

        ss = _stream_settings(params, net, security, host)

        return {
            "protocol": "trojan",
            "settings": {"servers": [{"address": host, "port": port, "password": password}]},
            "streamSettings": ss,
        }
    except Exception:
        return None


def _parse_vmess(uri: str) -> Optional[dict]:
    try:
        enc = uri[len("vmess://"):]
        enc += "=" * (-len(enc) % 4)
        data = json.loads(b64decode(enc).decode("utf-8", errors="ignore"))

        host = str(data.get("add", ""))
        port = int(data.get("port", 443))
        uid = str(data.get("id", ""))
        aid = int(data.get("aid", 0))
        net = str(data.get("net", "tcp"))
        tls = str(data.get("tls", ""))
        sni = str(data.get("sni", host))
        path = str(data.get("path", "/"))
        h_host = str(data.get("host", host))
        fp = str(data.get("fp", "chrome"))
        alpn = str(data.get("alpn", ""))

        if net == "xhttp":
            net = "http"
        elif net == "raw":
            net = "tcp"

        ss: dict = {"network": net}
        if tls == "tls":
            tls_cfg: dict = {
                "allowInsecure": True,
                "serverName": sni,
                "fingerprint": fp or "chrome",
            }
            if alpn:
                tls_cfg["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
            ss["security"] = "tls"
            ss["tlsSettings"] = tls_cfg
        else:
            ss["security"] = "none"

        if net == "ws":
            ss["wsSettings"] = {"path": path, "headers": {"Host": h_host}}
        elif net == "grpc":
            ss["grpcSettings"] = {"serviceName": path, "multiMode": False}
        elif net in ("h2", "http"):
            ss["httpSettings"] = {"path": path, "host": [h_host] if h_host else []}

        return {
            "protocol": "vmess",
            "settings": {"vnext": [{
                "address": host,
                "port": port,
                "users": [{"id": uid, "alterId": aid, "security": "auto"}],
            }]},
            "streamSettings": ss,
        }
    except Exception:
        return None


def _parse_ss(uri: str) -> Optional[dict]:
    try:
        body = uri[len("ss://"):]
        body = body.split("#")[0].split("?")[0]

        if "@" in body:
            cred_part, host_port = body.rsplit("@", 1)
            try:
                pad = cred_part + "=" * (-len(cred_part) % 4)
                decoded_cred = b64decode(pad).decode("utf-8")
                if ":" in decoded_cred:
                    method, password = decoded_cred.split(":", 1)
                else:
                    method, password = cred_part, ""
            except Exception:
                if ":" in cred_part:
                    method, password = cred_part.split(":", 1)
                else:
                    return None
        else:
            pad = body + "=" * (-len(body) % 4)
            decoded = b64decode(pad).decode("utf-8")
            if "@" not in decoded:
                return None
            cred_part, host_port = decoded.rsplit("@", 1)
            if ":" not in cred_part:
                return None
            method, password = cred_part.split(":", 1)

        host, port = _split_host_port(host_port)

        return {
            "protocol": "shadowsocks",
            "settings": {"servers": [{
                "address": host,
                "port": port,
                "method": method,
                "password": password,
                "uot": False,
            }]},
            "streamSettings": {"network": "tcp", "security": "none"},
        }
    except Exception:
        return None


def _build_outbound(vpn_uri: str) -> Optional[dict]:
    """Xray-outbound (vless/vmess/trojan/ss). None — протокол не для xray."""
    uri = vpn_uri.split("#")[0].strip()
    if uri.startswith("vless://"):
        return _parse_vless(uri)
    if uri.startswith("trojan://"):
        return _parse_trojan(uri)
    if uri.startswith("vmess://"):
        return _parse_vmess(uri)
    if uri.startswith("ss://"):
        return _parse_ss(uri)
    return None


# =============================================================================
# Парсинг URI → outbound sing-box (hy2 / hysteria2 / hysteria / tuic)
# =============================================================================


def _tls_block(params: dict, default_sni: str, default_alpn: Optional[list] = None) -> dict:
    sni = _p(params, "sni") or _p(params, "peer") or default_sni
    raw_insecure = (
        _p(params, "insecure")
        or _p(params, "allow_insecure")
        or _p(params, "allowInsecure")
    )
    alpn_raw = _p(params, "alpn")
    if alpn_raw:
        alpn = [a.strip() for a in alpn_raw.split(",") if a.strip()]
    else:
        alpn = list(default_alpn or [])

    tls: dict = {
        "enabled": True,
        "server_name": sni or default_sni,
        # для проверки живого ключа MITM-сертификат не мешает
        "insecure": True if raw_insecure == "" else _truthy(raw_insecure),
    }
    if alpn:
        tls["alpn"] = alpn
    return tls


def _parse_hysteria2(uri: str) -> Optional[dict]:
    try:
        body = uri.split("://", 1)[1].split("#")[0]
        auth, rest = body.split("@", 1)
        auth = unquote(auth)
        password = auth.split(":", 1)[1] if ":" in auth and not auth.startswith(":") else auth
        host_port = rest.split("?", 1)[0]
        qs = rest.split("?", 1)[1] if "?" in rest else ""
        host, port = _split_host_port(host_port)
        params = parse_qs(qs)

        out: dict = {
            "type": "hysteria2",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "password": password,
            "tls": _tls_block(params, host),
        }
        obfs = _p(params, "obfs")
        if obfs and obfs.lower() != "none":
            obfs_pw = _p(params, "obfs-password") or _p(params, "obfs_password")
            out["obfs"] = {"type": obfs, "password": obfs_pw}
        return out
    except Exception:
        return None


def _parse_hysteria(uri: str) -> Optional[dict]:
    try:
        body = uri.split("://", 1)[1].split("#")[0]
        host_port = body.split("?", 1)[0]
        qs = body.split("?", 1)[1] if "?" in body else ""
        host, port = _split_host_port(host_port)
        params = parse_qs(qs)

        out: dict = {
            "type": "hysteria",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "up_mbps": int(_p(params, "upmbps", "50") or 50),
            "down_mbps": int(_p(params, "downmbps", "50") or 50),
            "tls": _tls_block(params, host),
        }
        auth = _p(params, "auth") or _p(params, "auth_str")
        if auth:
            out["auth_str"] = auth
        return out
    except Exception:
        return None


def _parse_tuic(uri: str) -> Optional[dict]:
    try:
        body = uri.split("://", 1)[1].split("#")[0]
        cred, rest = body.split("@", 1)
        cred = unquote(cred)
        if ":" in cred:
            uuid, password = cred.split(":", 1)
        else:
            uuid, password = cred, ""
        host_port = rest.split("?", 1)[0]
        qs = rest.split("?", 1)[1] if "?" in rest else ""
        host, port = _split_host_port(host_port)
        params = parse_qs(qs)

        return {
            "type": "tuic",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "uuid": uuid,
            "password": password,
            "congestion_control": _p(params, "congestion_control") or "bbr",
            "udp_relay_mode": _p(params, "udp_relay_mode") or "native",
            "tls": _tls_block(params, host, ["h3"]),
        }
    except Exception:
        return None


def _build_singbox_outbound(vpn_uri: str) -> Optional[dict]:
    uri = vpn_uri.split("#")[0].strip()
    if uri.startswith(("hy2://", "hysteria2://")):
        return _parse_hysteria2(uri)
    if uri.startswith("hysteria://"):
        return _parse_hysteria(uri)
    if uri.startswith("tuic://"):
        return _parse_tuic(uri)
    return None


# =============================================================================
# Конфиги движков
# =============================================================================


def _build_xray_config(outbound: dict, socks_port: int) -> dict:
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
            "sniffing": {"enabled": False},
        }],
        "outbounds": [
            {**outbound, "tag": "proxy"},
            {"protocol": "freedom", "settings": {}, "tag": "direct"},
            {"protocol": "blackhole", "settings": {}, "tag": "block"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "outboundTag": "proxy", "port": "0-65535"},
            ],
        },
    }


def _build_singbox_config(outbound: dict, socks_port: int) -> dict:
    return {
        "log": {"level": "error"},
        "inbounds": [{
            "type": "socks",
            "tag": "in",
            "listen": "127.0.0.1",
            "listen_port": socks_port,
        }],
        "outbounds": [outbound],
        "route": {"final": outbound.get("tag", "proxy")},
    }


# =============================================================================
# Основные функции
# =============================================================================


def classify_proto(vpn_uri: str) -> Optional[str]:
    """'xray' | 'singbox' | None."""
    uri = vpn_uri.split("#")[0].strip()
    if uri.startswith(XRAY_PROTOS):
        return "xray"
    if uri.startswith(SINGBOX_PROTOS):
        return "singbox"
    return None


def check_key(vpn_uri: str, timeout: float = WHITE_CHECK_TIMEOUT) -> tuple:
    """Возвращает (status, reason, detail). status: white|black|unknown."""
    with _sem:
        return _check_one(vpn_uri, timeout)


def is_white_key(vpn_uri: str, timeout: float = WHITE_CHECK_TIMEOUT) -> bool:
    """Совместимость: белый только при status == 'white'."""
    status, _, _ = check_key(vpn_uri, timeout)
    return status == STATUS_WHITE


def _check_one(vpn_uri: str, timeout: float) -> tuple:
    engine = classify_proto(vpn_uri)
    if engine is None:
        return STATUS_UNKNOWN, "unsupported_proto", "protocol"

    if engine == "xray":
        binary = _xray_binary()
        outbound = _build_outbound(vpn_uri)
        not_started = "xray_not_started"
    else:
        binary = _singbox_binary()
        outbound = _build_singbox_outbound(vpn_uri)
        not_started = "singbox_not_started"

    if binary is None:
        # нечем проверить — ключ не хороним, помечаем как непроверенный
        return STATUS_UNKNOWN, "unsupported_proto", f"no_{engine}_binary"
    if outbound is None:
        return STATUS_UNKNOWN, "parse_error", "outbound"

    socks_port = _free_port()
    config = (
        _build_xray_config(outbound, socks_port)
        if engine == "xray"
        else _build_singbox_config(outbound, socks_port)
    )

    proc: Optional[subprocess.Popen] = None
    tmp_cfg: Optional[str] = None
    t_start = time.monotonic()

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as tf:
            json.dump(config, tf)
            tmp_cfg = tf.name

        cmd = (
            [binary, "run", "-c", tmp_cfg]
            if engine == "singbox"
            else [binary, "run", "-config", tmp_cfg]
        )
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        if not _wait_for_port(socks_port, XRAY_STARTUP_TIMEOUT, proc):
            return STATUS_BLACK, not_started, "port"

        elapsed = time.monotonic() - t_start
        remaining = max(1.0, timeout - elapsed)
        per_req = min(HTTP_TIMEOUT, max(2.0, remaining / len(WHITE_TEST_DOMAINS)))

        proxies = {
            "http": f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,*/*",
        }

        success = 0
        got_http = 0
        proxy_err = 0
        timeouts = 0
        other_err = 0
        total = len(WHITE_TEST_DOMAINS)

        for idx, domain in enumerate(WHITE_TEST_DOMAINS):
            if success >= WHITE_THRESHOLD:
                break
            # даже если все оставшиеся пройдут — порога не набрать
            if success + (total - idx) < WHITE_THRESHOLD:
                break
            if time.monotonic() - t_start > timeout - 1:
                break
            try:
                resp = requests.get(
                    f"https://{domain}/",
                    proxies=proxies,
                    timeout=per_req,
                    allow_redirects=True,
                    verify=False,
                    headers=headers,
                )
                got_http += 1
                if resp.status_code < 600:
                    success += 1
            except requests.exceptions.ProxyError:
                proxy_err += 1
            except requests.exceptions.Timeout:
                timeouts += 1
            except Exception:
                other_err += 1

        if success >= WHITE_THRESHOLD:
            return STATUS_WHITE, "", f"{success}/{total}"

        if got_http > 0:
            return STATUS_BLACK, "http_fail", f"{success}/{total}"

        # ни одного HTTP-ответа: либо прокси не пропускает, либо сеть не отвечает
        if proxy_err > 0 or other_err > 0:
            return STATUS_BLACK, "proxy_error", f"succ={success}"
        if timeouts > 0:
            return STATUS_BLACK, "timeout", f"succ={success}"
        return STATUS_BLACK, "http_fail", "no_response"

    except Exception as e:
        return STATUS_BLACK, "http_fail", type(e).__name__

    finally:
        _kill_proc(proc)
        _rm_file(tmp_cfg)


def _kill_proc(proc: Optional[subprocess.Popen]) -> None:
    if proc is None:
        return
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
    except Exception:
        pass


def _rm_file(path: Optional[str]) -> None:
    if path and os.path.exists(path):
        try:
            os.unlink(path)
        except Exception:
            pass


# =============================================================================
# Пакетная проверка с прогрессом и кешем
# =============================================================================


def _cached_status(entry: dict) -> Optional[str]:
    """Достаёт закешированный статус, понимая и старый bool-формат."""
    w = entry.get("white")
    if isinstance(w, bool):
        return STATUS_WHITE if w else STATUS_BLACK
    if w in (STATUS_WHITE, STATUS_BLACK):
        return w
    return None


def batch_white_check(
    keys: list,
    history: dict,
    *,
    workers: int = WHITE_WORKERS,
    cache_hours: float = WHITE_CACHE_HOURS,
    label: str = "",
) -> tuple:
    """Проверяет ключи реальным трафиком.

    Возвращает (white, black, unknown).
    UNKNOWN — протокол не поддержан / нет бинаря: это НЕ мёртвые ключи.
    """
    now = time.time()
    white_keys: list = []
    black_keys: list = []
    unknown_keys: list = []
    stats = REASON_STATS.setdefault(label or "-", Counter())

    cached_white, cached_black, to_test = [], [], []
    for k in keys:
        k_id = k.split("#")[0]
        entry = history.get(k_id, {})
        status = _cached_status(entry)
        w_time = entry.get("white_time", 0)
        if status and (now - w_time) < cache_hours * 3600:
            (cached_white if status == STATUS_WHITE else cached_black).append(k)
        else:
            to_test.append(k)

    if cached_white or cached_black:
        print(
            f"  [{label}] Из кеша белого статуса: "
            f"WHITE={len(cached_white)} BLACK={len(cached_black)}"
        )

    white_keys.extend(cached_white)
    black_keys.extend(cached_black)
    stats["cached_white"] += len(cached_white)
    stats["cached_black"] += len(cached_black)

    if not to_test:
        return white_keys, black_keys, unknown_keys

    print(
        f"  [{label}] Белый чек: {len(to_test)} ключей | воркеры={workers} | "
        f"таймаут={WHITE_CHECK_TIMEOUT}с | домены={len(WHITE_TEST_DOMAINS)}, "
        f"порог={WHITE_THRESHOLD}"
    )

    completed = 0
    total = len(to_test)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_key = {
            executor.submit(check_key, k.split("#")[0]): k for k in to_test
        }
        for future in as_completed(future_to_key):
            k = future_to_key[future]
            k_id = k.split("#")[0]
            try:
                status, reason, detail = future.result()
            except Exception:
                status, reason, detail = STATUS_BLACK, "http_fail", "exception"

            entry = history.setdefault(k_id, {})
            if status == STATUS_UNKNOWN:
                # не кешируем: на следующем прогоне бинарь может появиться
                entry["white"] = None
                entry["white_reason"] = reason
                entry["white_time"] = 0
                entry["white_detail"] = detail
                unknown_keys.append(k)
            else:
                entry["white"] = status
                entry["white_reason"] = reason
                entry["white_detail"] = detail
                entry["white_time"] = time.time()
                if status == STATUS_WHITE:
                    white_keys.append(k)
                else:
                    black_keys.append(k)

            stats[reason or status] += 1

            completed += 1
            if completed % 10 == 0 or completed == total:
                pct = completed * 100 // total
                print(
                    f"  [{label}] {completed}/{total} ({pct}%) "
                    f"WHITE={len(white_keys)} BLACK={len(black_keys)} "
                    f"UNKNOWN={len(unknown_keys)}"
                )

    return white_keys, black_keys, unknown_keys


def reason_summary() -> dict:
    """label -> Counter причин (для финального отчёта)."""
    return {label: Counter(c) for label, c in REASON_STATS.items()}
